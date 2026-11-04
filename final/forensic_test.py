"""Run the forensic comparison over the cases in forensic_cases.json.

    python final/forensic_test.py --split dev --run dev01

Stages are cached under final/results/forensic/<run>, so a rerun repeats only
what is missing. EBR never receives alerts or labels; the IDS-triggered
comparators do, because that is how those systems work.
"""
import argparse
from concurrent.futures import ProcessPoolExecutor
import csv
from datetime import datetime, timedelta
import gzip
from itertools import compress
import json
from pathlib import Path
import shutil
import socket
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ebr import baselines, forensic  # noqa: E402
from ebr.profile import build_profile  # noqa: E402
from ebr.retain import address, ebr_select, write_reduced  # noqa: E402
from ebr.value import score_flows  # noqa: E402

DATA = ROOT / 'data' / 'forensic'
BUDGETS = (0.01, 0.02, 0.05, 0.10)
RANDOM_SEEDS = (1, 2, 3)
POLICIES = ('random_packet', 'random_flow', 'flow_cutoff', 'rare_dest', 'ids_past', 'ids_past_fill', 'ebr')


def case_files(case, catalogue):
    """CIC captures are independent hosts; WRCCDC parts are one continuous tap and are joined."""
    folder = DATA / case
    spec = catalogue['cases'][case]
    if spec['source'] == 'local':
        return [ROOT / 'data' / 'downloads' / name for name in spec['files']]
    if spec['source'] == 'alias':
        return [DATA / spec['of'] / name for name in spec['files']]
    if spec['source'] != 'wrccdc':
        return sorted(folder.glob('*.pcap'))
    merged = folder / 'merged' / 'continuous.pcap'
    if not merged.exists():
        merged.parent.mkdir(exist_ok=True)
        parts = sorted(folder.glob('*.pcap'))
        temporary = merged.with_suffix('.part')
        with temporary.open('wb') as out:
            for number, part in enumerate(parts):
                with part.open('rb') as stream:
                    stream.seek(0 if number == 0 else 24)
                    shutil.copyfileobj(stream, out, 1 << 22)
        temporary.replace(merged)
    return [merged]


def load_truth(case):
    """Expand the published schedule into UTC minute windows for this case."""
    truth = json.loads((ROOT / 'forensic_truth.json').read_text(encoding='utf8'))
    offset = timedelta(hours=truth['schedule_to_utc_hours'])
    addresses = truth['address_groups']
    episodes = []
    alias = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))['cases'].get(case, {}).get('of')
    for episode in truth['episodes'].get(alias or case, []):
        start = datetime.strptime(episode['start'], '%Y-%m-%d %H:%M') + offset
        end = datetime.strptime(episode['end'], '%Y-%m-%d %H:%M') + offset
        expand = lambda names: [a for n in names for a in addresses.get(n, [n])]
        episodes.append(dict(episode, attackers=expand(episode['attackers']), victims=expand(episode['victims']),
                             start=start.strftime('%Y-%m-%dT%H:%M'), end=end.strftime('%Y-%m-%dT%H:%M'),
                             start_ns=int((start - datetime(1970, 1, 1)).total_seconds() * 1e9),
                             end_ns=int((end - datetime(1970, 1, 1)).total_seconds() * 1e9) + 60_000_000_000))
    return episodes


def capture_date(case, catalogue):
    spec = catalogue['cases'][case]
    if spec['source'] == 'alias':
        return capture_date(spec['of'], catalogue)
    if 'date' in spec:
        return spec['date']
    if spec['source'] == 'cic':
        day = spec['day'].split('-', 1)[1]
        return datetime.strptime(day, '%d-%m-%Y').strftime('%Y-%m-%d')
    return f'{spec["year"]}-08-15' if spec['source'] == 'local' else f'{spec["year"]}-03-24'


def past_alert_tuples(full, cutoff_date):
    """Alerts a sensor could have raised on capture day: rules that already existed then."""
    tuples = []
    for entry in full['alerts'].values():
        created = (entry.get('created') or '9999').replace('_', '-')
        if created < cutoff_date:
            tuples.append(entry['tuple'])
    return tuples


def packed(text):
    return socket.inet_pton(socket.AF_INET6 if ':' in text else socket.AF_INET, text)


def frozen_config():
    return json.loads((ROOT / 'ebr_config_frozen.json').read_text(encoding='utf8'))


def full_summary_paths(run_dir, case, files):
    return [run_dir / 'full' / case / (Path(f).name + '.json') for f in files]


def original_algorithm_mask(path, profile, budget, strategy):
    """The earlier in-memory implementation, feasible only on small captures."""
    from evidence_budget.features import build_features
    from evidence_budget.pcap import read_pcap
    from evidence_budget.selection import select
    settings = json.loads((ROOT / 'config.json').read_text(encoding='utf8'))
    capture = read_pcap(path)
    chosen, _ = select(capture.packets, build_features(capture.packets, settings), budget, strategy, 0, settings)
    mask = bytearray(profile.packets)
    for index in chosen:
        mask[index] = 1
    return mask


def ledger_accounting(ledger, flows, attackers):
    """Can the ledger alone state how many flows the attacker made, and when?"""
    rows = gzip.decompress(ledger).decode('ascii', 'replace').splitlines()
    actual = [f for f in flows if address(f.client) in attackers or address(f.server) in attackers]
    if not actual:
        return None
    counted, first, last = 0, None, None
    for line in rows[1:]:
        cells = line.split(',')
        if cells[0] == 'group' and cells[1] != 'client':
            if cells[1] in attackers:
                counted += int(cells[5])
                begin, end = int(cells[6]), int(cells[7])
            else:
                continue
        elif cells[0].isdigit() and (cells[3] in attackers or cells[5] in attackers):
            counted += 1
            begin, end = int(cells[0]), int(cells[0]) + int(float(cells[1]) * 1e9)
        else:
            continue
        first = begin if first is None else min(first, begin)
        last = end if last is None else max(last, end)
    true_first, true_last = min(f.first_ns for f in actual), max(f.last_ns for f in actual)
    return dict(true_flows=len(actual), ledger_flows=counted,
                first_error_seconds=abs(first - true_first) / 1e9 if first else None,
                last_error_seconds=abs(last - true_last) / 1e9 if last else None)


def reduce_case(args):
    case, run_name, budgets, policies, config_path = args
    run_dir = ROOT / 'results' / 'forensic' / run_name
    config = json.loads(Path(config_path).read_text(encoding='utf8'))
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    files = case_files(case, catalogue)
    began = time.time()
    profile = build_profile(files, config)
    profile_seconds = time.time() - began
    full = forensic.load_summaries(full_summary_paths(run_dir, case, files))
    began = time.time()
    scores = score_flows(profile.flows, config)
    score_seconds = time.time() - began
    index = baselines.CutoffIndex(profile)
    costs = baselines.flow_costs(profile)
    date = capture_date(case, catalogue)
    past = {(packed(src), sport, packed(dst), dport) for src, sport, dst, dport in past_alert_tuples(full, date)}
    flagged = baselines.alert_flow_ids(profile, past)
    records = []
    episodes = load_truth(case)
    labelled = {}
    for episode in episodes:
        actors, targets = set(episode['attackers']), set(episode['victims'])
        labelled[episode['id']] = {f.id for f in profile.flows
                                   if ((address(f.client) in actors and address(f.server) in targets)
                                       or (address(f.server) in actors and address(f.client) in targets))
                                   and f.first_ns <= episode['end_ns'] and f.last_ns >= episode['start_ns']}
    frozen_scores = {}
    attackers = {a for episode in episodes for a in episode['attackers']}
    ranking = [address(h) for h, _ in sorted(scores['hosts'].items(), key=lambda kv: -kv[1])]
    attacker_ranks = {a: ranking.index(a) + 1 for a in attackers if a in ranking}
    for fraction in budgets:
        budget = int(profile.input_bytes * fraction)
        for policy in policies:
            for seed in (RANDOM_SEEDS if policy.startswith('random') else (0,)):
                began = time.time()
                ledger_size, ledger = 0, None
                if policy == 'ebr':
                    mask, ledger, _ = ebr_select(profile, budget, config, scores)
                    ledger_size = len(ledger)
                elif policy == 'ebr_frozen':
                    # The first sealed version, kept so old and new meet on the same captures.
                    frozen = frozen_config()
                    if 'value' not in frozen_scores:
                        frozen_scores.update(score_flows(profile.flows, frozen))
                    mask, ledger, _ = ebr_select(profile, budget, frozen, frozen_scores)
                    ledger_size = len(ledger)
                elif policy == 'random_packet':
                    mask = baselines.random_packets(profile, budget, seed)
                elif policy == 'random_flow':
                    mask = baselines.random_flows(profile, budget, seed, costs)
                elif policy == 'flow_cutoff':
                    mask = baselines.flow_cutoff(profile, budget, index)
                elif policy == 'rare_dest':
                    mask = baselines.rare_destination(profile, budget, costs, index)
                elif policy in ('v1_evidence', 'v1_bundle'):
                    if len(files) != 1:
                        raise ValueError('The original implementation reads one capture at a time')
                    strategy = 'evidence' if policy == 'v1_evidence' else 'bundle_round_robin'
                    mask = original_algorithm_mask(files[0], profile, budget, strategy)
                elif policy == 'ids_past':
                    mask = baselines.ids_triggered(profile, budget, flagged, costs)
                elif policy == 'ids_past_fill':
                    mask = baselines.ids_triggered(profile, budget, flagged, costs, True, index)
                else:
                    raise ValueError(policy)
                seconds = time.time() - began
                pcap_bytes = 24 * profile.headers + sum(compress(profile.sizes, mask))
                if pcap_bytes + ledger_size > budget:
                    raise RuntimeError(f'{policy} exceeded the cap on {case}: {pcap_bytes + ledger_size} > {budget}')
                tag = f'{policy}_{fraction:g}_s{seed}'
                folder = run_dir / 'reduced' / case / tag
                write_reduced(profile, mask, folder)
                kept_flows = set(compress(profile.flow_of, mask))
                record = dict(case=case, policy=policy, fraction=fraction, seed=seed, budget=budget, input_bytes=profile.input_bytes,
                              pcap_bytes=pcap_bytes, ledger_bytes=ledger_size, select_seconds=round(seconds, 3),
                              packets_kept=sum(mask), packets=profile.packets, flows=len(profile.flows),
                              flows_kept=len(kept_flows), tag=tag)
                for episode in episodes:
                    members = labelled[episode['id']]
                    record[f'flows:{episode["id"]}'] = [len(members), len(members & kept_flows)]
                if ledger is not None and attackers:
                    record['ledger_accounting'] = ledger_accounting(ledger, profile.flows, attackers)
                records.append(record)
    meta = dict(case=case, packets=profile.packets, flows=len(profile.flows), input_bytes=profile.input_bytes,
                profile_seconds=round(profile_seconds, 2), score_seconds=round(score_seconds, 2),
                flagged_flows=len(flagged), files=[Path(f).name for f in files], hosts_ranked=len(ranking),
                hosts_total=len({f.client for f in profile.flows} | {f.server for f in profile.flows}),
                attacker_ranks=attacker_ranks,
                top_hosts=[(address(k), round(v, 2)) for k, v in sorted(scores['hosts'].items(), key=lambda kv: -kv[1])[:12]])
    (run_dir / 'reduced' / case).mkdir(parents=True, exist_ok=True)
    (run_dir / 'reduced' / case / 'records.json').write_text(json.dumps(dict(meta=meta, records=records)), encoding='utf8')
    return case, profile.packets, round(profile_seconds, 1)


def evaluate(run_dir, cases, catalogue):
    rows, campaign_rows = [], []
    for case in cases:
        files = case_files(case, catalogue)
        full = forensic.load_summaries(full_summary_paths(run_dir, case, files))
        date = capture_date(case, catalogue)
        store = json.loads((run_dir / 'reduced' / case / 'records.json').read_text(encoding='utf8'))
        episodes = load_truth(case)
        future = lambda e: (e.get('created') or '9999').replace('_', '-') >= date and forensic.is_attack(e)
        for record in store['records']:
            summaries = [run_dir / 'scans' / case / record['tag'] / (Path(f).name + '.json') for f in files]
            reduced = forensic.load_summaries(summaries)
            attack = forensic.alert_recall(full, reduced, forensic.is_attack)
            everything = forensic.alert_recall(full, reduced)
            later = forensic.alert_recall(full, reduced, future)
            invented = forensic.invented_alerts(full, reduced)
            rows.append(dict(case=case, policy=record['policy'], fraction=record['fraction'], seed=record['seed'],
                             input_mb=round(record['input_bytes'] / 1e6, 1), kept_mb=round((record['pcap_bytes'] + record['ledger_bytes']) / 1e6, 2),
                             ledger_mb=round(record['ledger_bytes'] / 1e6, 2), attack_refs=attack['reference'],
                             attack_recall=attack['instance'], attack_sig_refs=attack['signatures'], attack_sig_recall=attack['signature'],
                             all_refs=everything['reference'], all_recall=everything['instance'], all_sig_recall=everything['signature'],
                             future_refs=later['reference'], future_recall=later['instance'], invented=len(invented),
                             invented_attack=sum(1 for e in invented if forensic.is_attack(e))))
            for episode in episodes:
                truth = forensic.episode_outcome(episode, full)
                found = forensic.episode_outcome(episode, reduced)
                application = forensic.application_recall(episode, full, reduced)
                total, kept = record.get(f'flows:{episode["id"]}', (0, 0))
                campaign_rows.append(dict(case=case, episode=episode['id'], attack=episode['name'], policy=record['policy'],
                                          fraction=record['fraction'], seed=record['seed'], full_sids=len(truth), found_sids=len(set(found) & set(truth)),
                                          caught=int(bool(set(found) & set(truth))), detectable=int(bool(truth)), attack_flows=total, flows_kept=kept,
                                          app_events=application['events'], app_events_kept=application['events_kept'],
                                          urls=application['urls'], urls_kept=application['urls_kept']))
    return rows, campaign_rows


def write_csv(path, rows):
    if not rows:
        return
    with Path(path).open('w', newline='', encoding='utf8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--split', default='dev')
    parser.add_argument('--cases', nargs='*')
    parser.add_argument('--run', required=True)
    parser.add_argument('--budgets', nargs='*', type=float, default=BUDGETS)
    parser.add_argument('--policies', nargs='*', default=POLICIES)
    parser.add_argument('--config', default=str(ROOT / 'ebr_config.json'))
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--full-from', help='reuse full-capture scans from this run')
    parser.add_argument('--keep-reduced', action='store_true')
    args = parser.parse_args()
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    cases = args.cases or [c for c, s in catalogue['cases'].items() if s['split'] == args.split]
    run_dir = ROOT / 'results' / 'forensic' / args.run
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / 'config_used.json').write_text(Path(args.config).read_text(encoding='utf8'), encoding='utf8')

    # Stage 1: reference detections on the untouched captures.
    if args.full_from and not (run_dir / 'full').exists():
        shutil.copytree(ROOT / 'results' / 'forensic' / args.full_from / 'full', run_dir / 'full')
    jobs = []
    for case in cases:
        files = case_files(case, catalogue)
        jobs += list(zip(files, full_summary_paths(run_dir, case, files)))
    began = time.time()
    scanned = forensic.scan_batch(jobs, run_dir)
    print(f'full scans: {scanned} in {time.time() - began:.0f}s', flush=True)

    # Stage 2: every policy reduces every case under the same caps.
    began = time.time()
    with ProcessPoolExecutor(args.workers) as pool:
        tasks = [(c, args.run, tuple(args.budgets), tuple(args.policies), args.config) for c in cases
                 if not (run_dir / 'reduced' / c / 'records.json').exists()]
        for case, packets, seconds in pool.map(reduce_case, tasks):
            print(f'reduced {case}: {packets} packets, profile {seconds}s', flush=True)
    print(f'reduction stage {time.time() - began:.0f}s', flush=True)

    # Stage 3: scan each reduced capture exactly as the originals were scanned.
    jobs = []
    for case in cases:
        files = case_files(case, catalogue)
        store = json.loads((run_dir / 'reduced' / case / 'records.json').read_text(encoding='utf8'))
        for record in store['records']:
            for f in files:
                name = Path(f).name
                jobs.append((run_dir / 'reduced' / case / record['tag'] / name, run_dir / 'scans' / case / record['tag'] / (name + '.json')))
    began = time.time()
    scanned = forensic.scan_batch(jobs, run_dir)
    print(f'reduced scans: {scanned} in {time.time() - began:.0f}s', flush=True)

    # Stage 4: score.
    rows, campaign_rows = evaluate(run_dir, cases, catalogue)
    write_csv(run_dir / 'metrics.csv', rows)
    write_csv(run_dir / 'campaigns.csv', campaign_rows)
    if not args.keep_reduced:
        for case in cases:
            for folder in (run_dir / 'reduced' / case).iterdir():
                if folder.is_dir():
                    shutil.rmtree(folder)
    print('complete', run_dir, flush=True)


if __name__ == '__main__':
    main()
