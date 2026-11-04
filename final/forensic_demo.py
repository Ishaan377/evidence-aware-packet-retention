"""Live demonstration: compress real attack captures with EBR, then investigate the result.

    python final/forensic_demo.py                 11.3 GB with labelled attacks, 5 percent cap
    python final/forensic_demo.py --sealed        7 GB of captures kept sealed until the freeze
    python final/forensic_demo.py --cap 0.02      a harder cap
    python final/forensic_demo.py --quick         one 1.5 GB case, about a minute

The investigator's view uses only what survives: the reduced PCAPs and the flow
ledger. Suricata reference alerts on the untouched captures are reused from the
test runs, because rescanning the originals takes far longer than the demonstration.

The default cases have publisher labels, but they helped shape the second version.
The sealed cases did not, and they mostly lack labels, so the two runs answer
different questions: was each named attack caught, and how does it do on unseen data?
"""
import argparse
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime
import gzip
import hashlib
from itertools import compress
import json
from pathlib import Path
import sys
import time
import webbrowser

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import forensic_test as harness  # noqa: E402
from ebr import forensic  # noqa: E402
from ebr.profile import build_profile  # noqa: E402
from ebr.report import demo_report  # noqa: E402
from ebr.retain import address, ebr_select, sha256_file, write_reduced  # noqa: E402
from ebr.value import score_flows  # noqa: E402

QUICK_CASE = 'test_bot_mar02'


def reduce_one(args):
    case, cap, out, config = args
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    files = harness.case_files(case, catalogue)
    began = time.time()
    profile = build_profile(files, config)
    scores = score_flows(profile.flows, config)
    budget = int(profile.input_bytes * cap)
    mask, ledger, info = ebr_select(profile, budget, config, scores)
    folder = Path(out) / case
    written = write_reduced(profile, mask, folder)
    (folder / 'flow_ledger.csv.gz').write_bytes(ledger)
    seconds = time.time() - began
    ranking = sorted(scores['hosts'].items(), key=lambda kv: -kv[1])
    suspects = [dict(address=address(host), bits=round(bits, 1)) for host, bits in ranking[:10]]
    outputs = [dict(item, sha256=sha256_file(folder / item['file'])) for item in written]
    return dict(case=case, input_bytes=profile.input_bytes, output_bytes=sum(i['bytes'] for i in written) + len(ledger),
                ledger_bytes=len(ledger), packets=profile.packets, packets_kept=sum(mask), flows=len(profile.flows),
                flows_with_packets=len(set(compress(profile.flow_of, mask))), seconds=round(seconds, 1), budget=budget,
                suspects=suspects, outputs=outputs, files=[Path(f).name for f in files])


def ledger_view(path, attackers, window_start, window_end):
    """What the ledger alone says about these addresses during one attack window.

    Grouped rows hold totals for a behaviour, so a group that overlaps the window
    counts whole. The figure can therefore run high when a ledger is heavily folded.
    """
    flows, first, last, payload = 0, None, None, 0
    with gzip.open(path, 'rt', encoding='ascii') as stream:
        for line in stream:
            cells = line.rstrip('\n').split(',')
            if cells[0].isdigit() and (cells[3] in attackers or cells[5] in attackers):
                begin = int(cells[0])
                end = begin + int(float(cells[1]) * 1e9)
                count, bytes_moved = 1, int(cells[11]) + int(cells[12])
            elif cells[0] == 'group' and cells[1] in attackers:
                begin, end = int(cells[6]), int(cells[7])
                count, bytes_moved = int(cells[5]), int(cells[9]) + int(cells[10])
            else:
                continue
            if begin > window_end or end < window_start:
                continue
            flows += count
            payload += bytes_moved
            first = begin if first is None else min(first, begin)
            last = end if last is None else max(last, end)
    return dict(flows=flows, first_ns=first, last_ns=last, payload_bytes=payload)


def investigate(case, record, out, reference_run, catalogue):
    files = harness.case_files(case, catalogue)
    run_dir = ROOT / 'results' / 'forensic' / reference_run
    full = forensic.load_summaries(harness.full_summary_paths(run_dir, case, files))
    reduced = forensic.load_summaries([Path(out) / 'scans' / case / (Path(f).name + '.json') for f in files])
    attack = forensic.alert_recall(full, reduced, forensic.is_attack)
    findings = []
    ledger = Path(out) / case / 'flow_ledger.csv.gz'
    for episode in harness.load_truth(case):
        truth = forensic.episode_outcome(episode, full)
        found = forensic.episode_outcome(episode, reduced)
        names = {e['sid']: e['sig'] for e in reduced['alerts'].values()}
        suspects = [s['address'] for s in record['suspects']]
        ranks = [suspects.index(a) + 1 for a in episode['attackers'] if a in suspects]
        view = ledger_view(ledger, set(episode['attackers']), episode['start_ns'], episode['end_ns'])
        findings.append(dict(id=episode['id'], name=episode['name'], attackers=episode['attackers'], window=[episode['start'], episode['end']],
                             detectable=bool(truth), caught=bool(set(found) & set(truth)), signatures_full=len(truth),
                             signatures_kept=len(set(found) & set(truth)), examples=[names[s] for s in found[:3] if s in names],
                             suspect_rank=min(ranks) if ranks else None, ledger=view))
    invented = forensic.invented_alerts(full, reduced)
    return dict(attack_alerts_full=attack['reference'], attack_alerts_kept=attack['found'],
                attack_signatures_full=attack['signatures'], attack_signatures_kept=attack['signatures_found'],
                invented_attack_alerts=sum(1 for e in invented if forensic.is_attack(e)), findings=findings)


def line(text=''):
    print(text, flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cap', type=float, default=0.05)
    parser.add_argument('--cases', nargs='*')
    parser.add_argument('--quick', action='store_true')
    parser.add_argument('--sealed', action='store_true')
    parser.add_argument('--reference')
    parser.add_argument('--no-open', action='store_true')
    args = parser.parse_args()
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    split = 'sealed2' if args.sealed else 'test'
    args.reference = args.reference or ('sealed2' if args.sealed else 'test')
    cases = args.cases or ([QUICK_CASE] if args.quick else [c for c, s in catalogue['cases'].items() if s['split'] == split])
    config = json.loads((ROOT / 'ebr_config.json').read_text(encoding='utf8'))
    out = ROOT / 'results' / 'forensic_demo' / datetime.now().strftime('run_%Y%m%d_%H%M%S')
    out.mkdir(parents=True)
    total = sum(f.stat().st_size for case in cases for f in harness.case_files(case, catalogue))
    line(f'EVIDENCE: {len(cases)} cases, {total / 1e9:.2f} GB of packet captures. Storage allowed: {args.cap:.0%}.')

    line('\nSTEP 1  Compressing with Evidence-Based Retention (no signatures, no labels)')
    began = time.time()
    with ProcessPoolExecutor(min(6, len(cases))) as pool:
        records = list(pool.map(reduce_one, [(c, args.cap, str(out), config) for c in cases]))
    for r in records:
        line(f'  {r["case"]:<26}{r["input_bytes"] / 1e9:6.2f} GB -> {r["output_bytes"] / 1e6:8.1f} MB   '
             f'{r["packets_kept"]:>9,} of {r["packets"]:>10,} packets   {r["seconds"]:.0f}s')
    kept = sum(r['output_bytes'] for r in records)
    line(f'  TOTAL {total / 1e9:.2f} GB -> {kept / 1e6:.1f} MB, {100 * (1 - kept / total):.1f}% smaller, in {time.time() - began:.0f}s')

    # A clean checkout has no cached scans of the original captures.
    reference_dir = ROOT / 'results' / 'forensic' / args.reference
    reference_jobs = []
    for case in cases:
        files = harness.case_files(case, catalogue)
        reference_jobs.extend(zip(files, harness.full_summary_paths(reference_dir, case, files)))
    if any(not summary.exists() for _, summary in reference_jobs):
        line('\nSTEP 2  Scanning the original captures for reference alerts (first run only)')
        began = time.time()
        scanned = forensic.scan_batch(reference_jobs, out)
        line(f'  Scanned {scanned} original captures in {time.time() - began:.0f}s')

    line('\nSTEP 3  Running Suricata with 52,778 ET Open rules on the COMPRESSED evidence only')
    jobs = []
    for case in cases:
        for f in harness.case_files(case, catalogue):
            name = Path(f).name
            jobs.append((out / case / name, out / 'scans' / case / (name + '.json')))
    began = time.time()
    forensic.scan_batch(jobs, out)
    line(f'  Scanned {len(jobs)} reduced captures in {time.time() - began:.0f}s')

    line('\nSTEP 4  Verdict for each case and labelled attack')
    findings, caught, detectable = {}, 0, 0
    for record in records:
        result = investigate(record['case'], record, out, args.reference, catalogue)
        findings[record['case']] = result
        line(f'  {record["case"]}: {result["attack_signatures_kept"]} of {result["attack_signatures_full"]} attack signatures kept, '
             f'{result["attack_alerts_kept"]} of {result["attack_alerts_full"]} alert instances')
        for f in result['findings']:
            status = 'CAUGHT' if f['caught'] else ('MISSED' if f['detectable'] else 'no IDS rule, see ledger')
            caught += f['caught']
            detectable += f['detectable']
            rank = f'suspect #{f["suspect_rank"]}' if f['suspect_rank'] else 'not in top 10'
            line(f'  {f["name"]:<36}{status:<24}{f["signatures_kept"]:>3}/{f["signatures_full"]:<3} signatures   '
                 f'{f["ledger"]["flows"]:>8,} flows in ledger   {rank}')
    kept_signatures = sum(f['attack_signatures_kept'] for f in findings.values())
    all_signatures = sum(f['attack_signatures_full'] for f in findings.values())
    line(f'\nRESULT: {kept_signatures} of {all_signatures} attack signatures kept across the cases.')
    if detectable:
        line(f'RESULT: {caught} of {detectable} labelled attacks that Suricata can detect on the full evidence are still caught.')

    summary = dict(generated=datetime.now().isoformat(timespec='seconds'), cap=args.cap, reference_run=args.reference,
                   config_sha256=hashlib.sha256((ROOT / 'ebr_config.json').read_bytes()).hexdigest(),
                   input_bytes=total, output_bytes=kept, cases=records, findings=findings)
    (out / 'demo_summary.json').write_text(json.dumps(summary, indent=1), encoding='utf8')
    report = out / 'report.html'
    report.write_text(demo_report(summary), encoding='utf8')
    line(f'Report: {report}')
    if not args.no_open:
        webbrowser.open(report.as_uri())


if __name__ == '__main__':
    main()
