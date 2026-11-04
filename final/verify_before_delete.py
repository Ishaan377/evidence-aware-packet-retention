"""Prototype: repair EBR's losses before deleting the original capture.

    python final/verify_before_delete.py --run verify

Three conditions decide which detections may guide repair:

    all    every attack alert, the best case
    past   only rules published before the capture, the realistic case
    half   half the rule families, leaving the rest hidden as a stand-in for unknowns

Every round scans all reductions with one Suricata process. Results are not sealed,
because the outcomes on these captures were already known when this was written.
"""
import argparse
from concurrent.futures import ProcessPoolExecutor
import json
from itertools import compress
from pathlib import Path
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import forensic_test as harness  # noqa: E402
from ebr import forensic  # noqa: E402
from ebr.profile import build_profile  # noqa: E402
from ebr.retain import write_reduced  # noqa: E402
from ebr.value import score_flows  # noqa: E402
from ebr.verify import FlowIndex, hidden_family, is_later_rule, known_alerts, repaired_select  # noqa: E402

FORENSIC = ROOT / 'results' / 'forensic'
CAPS = (0.01, 0.02, 0.05, 0.10)
CONDITIONS = ('all', 'past', 'half')
LAST_ROUND = 2
REFERENCE_RUNS = {'dev': 'dev_final', 'test': 'test', 'sealed2': 'sealed2', 'sealed3': 'sealed3'}


def tag_of(cap, condition, round_number):
    return f'c{cap:g}_{condition}_r{round_number}' if round_number else f'c{cap:g}_first'


def reference(case, catalogue):
    run = FORENSIC / REFERENCE_RUNS[catalogue['cases'][case]['split']]
    return forensic.load_summaries(harness.full_summary_paths(run, case, harness.case_files(case, catalogue)))


def reduce_round(job):
    """Profile one case, then make every selection this round needs."""
    case, run_dir, round_number, state = job
    run_dir = Path(run_dir)
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    config = json.loads((ROOT / 'ebr_config.json').read_text(encoding='utf8'))
    profile = build_profile(harness.case_files(case, catalogue), config)
    scores = score_flows(profile.flows, config)
    full = reference(case, catalogue)
    flow_costs = None
    records = []
    plans = []
    if round_number == 0:
        plans = [(cap, None, set()) for cap in CAPS]
    else:
        pending = {tuple(key) for entry in state.values() if not entry['finished'] for key, _ in entry['repairs']}
        index = FlowIndex(profile.flows, [full['alerts'][key] for key in pending])
        for name, entry in state.items():
            if entry['finished']:
                continue
            cap, condition = float(entry['cap']), entry['condition']
            forced = set()
            for key, widen in entry['repairs']:
                sid, a, b = key
                forced |= index.targets(full['alerts'][(sid, a, b)], widen)
            plans.append((cap, condition, forced))
    for cap, condition, forced in plans:
        budget = int(profile.input_bytes * cap)
        began = time.time()
        mask, ledger, info = repaired_select(profile, budget, config, scores, forced)
        seconds = time.time() - began
        pcap_bytes = 24 * profile.headers + sum(compress(profile.sizes, mask))
        if pcap_bytes + len(ledger) > budget:
            raise RuntimeError(f'{case} exceeded its cap: {pcap_bytes + len(ledger)} > {budget}')
        tag = tag_of(cap, condition, round_number)
        write_reduced(profile, mask, run_dir / 'reduced' / case / tag)
        levels = info['levels']
        if flow_costs is None:
            flow_costs = [sum(f.cost) for f in profile.flows]
        repaired_bytes = sum(sum(f.cost[t] for t in range(5) if t <= levels[f.id]) for f in (profile.flows[i] for i in forced))
        records.append(dict(case=case, cap=cap, condition=condition, round=round_number, tag=tag, input_bytes=profile.input_bytes,
                            budget=budget, kept_bytes=pcap_bytes + len(ledger), forced_flows=len(forced), repaired_bytes=repaired_bytes,
                            selection_seconds=round(seconds, 2), full_flow_bytes_forced=sum(flow_costs[i] for i in forced)))
    return case, records


def score_view(full, view, capture_date, known):
    """Recall on what repair may see, on what it may not, and on rules nobody had yet."""
    attacks = {k: v for k, v in full['alerts'].items() if forensic.is_attack(v)}
    later = {k: v for k, v in attacks.items() if is_later_rule(v, capture_date)}
    hidden = {k: v for k, v in attacks.items() if hidden_family(v)}
    unseen = {k: v for k, v in attacks.items() if k not in known}

    def recall(group):
        return (sum(1 for k in group if k in view['alerts']) / len(group)) if group else None

    signatures = {v['sid'] for v in attacks.values()}
    found = {attacks[k]['sid'] for k in attacks if k in view['alerts']}
    invented = [k for k, v in view['alerts'].items() if k not in full['alerts'] and forensic.is_attack(v)]
    return dict(attack_refs=len(attacks), attack_recall=recall(attacks), attack_sig_recall=len(found) / len(signatures) if signatures else None,
                later_refs=len(later), later_recall=recall(later), hidden_refs=len(hidden), hidden_recall=recall(hidden),
                known_refs=len(known), known_recall=recall(known), unseen_refs=len(unseen), unseen_recall=recall(unseen), invented=len(invented))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', default='verify')
    parser.add_argument('--cases', nargs='*')
    parser.add_argument('--split', nargs='*', default=('test', 'sealed2'))
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    cases = args.cases or [c for c, s in catalogue['cases'].items() if s['split'] in args.split]
    run_dir = FORENSIC / args.run
    run_dir.mkdir(parents=True, exist_ok=True)
    states = {case: {} for case in cases}
    results = []
    for round_number in range(LAST_ROUND + 1):
        began = time.time()
        jobs = [(case, str(run_dir), round_number, states[case]) for case in cases if round_number == 0 or any(not e['finished'] for e in states[case].values())]
        if not jobs:
            break
        with ProcessPoolExecutor(args.workers) as pool:
            reduced = dict(pool.map(reduce_round, jobs))
        reduce_seconds = time.time() - began
        began = time.time()
        scans = []
        for case, records in reduced.items():
            for record in records:
                for name in (Path(f).name for f in harness.case_files(case, catalogue)):
                    scans.append((run_dir / 'reduced' / case / record['tag'] / name, run_dir / 'scans' / case / record['tag'] / (name + '.json')))
        forensic.scan_batch(scans, run_dir)
        scan_seconds = time.time() - began
        scanned_bytes = sum(Path(p).stat().st_size for p, _ in scans)
        print(f'round {round_number}: {len(scans)} scans of {scanned_bytes / 1e9:.2f} GB, reduce {reduce_seconds:.0f}s, scan {scan_seconds:.0f}s', flush=True)
        (run_dir / 'timing.jsonl').open('a', encoding='utf8').write(json.dumps(dict(round=round_number, scans=len(scans), scanned_bytes=scanned_bytes, reduce_seconds=reduce_seconds, scan_seconds=scan_seconds)) + '\n')
        for case, records in reduced.items():
            full = reference(case, catalogue)
            date = harness.capture_date(case, catalogue)
            names = [Path(f).name for f in harness.case_files(case, catalogue)]
            for record in records:
                view = forensic.load_summaries([run_dir / 'scans' / case / record['tag'] / (n + '.json') for n in names])
                for condition in (CONDITIONS if round_number == 0 else (record['condition'],)):
                    known = known_alerts(full, condition, date)
                    row = dict(record, condition=condition, **score_view(full, view, date, known))
                    results.append(row)
                    name = f'{record["cap"]:g}|{condition}'
                    entry = states[case].setdefault(name, dict(cap=record['cap'], condition=condition, repairs=[], finished=False))
                    lost = [k for k in known if k not in view['alerts']]
                    tried = {tuple(key) for key, _ in entry['repairs']}
                    entry['repairs'] = [[list(k), k in tried] for k in lost] + [[key, widen] for key, widen in entry['repairs'] if tuple(key) not in lost]
                    entry['finished'] = not lost or round_number == LAST_ROUND
        shutil.rmtree(run_dir / 'reduced', ignore_errors=True)
        (run_dir / 'results.json').write_text(json.dumps(results, indent=0), encoding='utf8')
    print('complete', run_dir, flush=True)


if __name__ == '__main__':
    main()
