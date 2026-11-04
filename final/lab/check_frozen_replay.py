"""Prove the current code's frozen mode reproduces the first sealed test exactly.

Compares bytes kept, packets kept, flows kept and every recall figure against the
saved results, so an old-against-new comparison really does test the old version.
"""
import csv
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
FORENSIC = ROOT / 'results' / 'forensic'
RUN = 'frozen_replay'
CASES = ('test_web_feb23', 'test_dos_feb15', 'test_infiltration_mar01')


def records(run):
    found = {}
    for case in CASES:
        store = json.loads((FORENSIC / run / 'reduced' / case / 'records.json').read_text(encoding='utf8'))
        for record in store['records']:
            if record['policy'] in ('ebr', 'ebr_frozen'):
                found[(case, record['fraction'])] = (record['pcap_bytes'], record['ledger_bytes'], record['packets_kept'], record['flows_kept'])
    return found


def metrics(run, policy):
    with (FORENSIC / run / 'metrics.csv').open(encoding='utf8') as stream:
        rows = [r for r in csv.DictReader(stream) if r['policy'] == policy and r['case'] in CASES]
    return {(r['case'], r['fraction']): (r['attack_recall'], r['attack_sig_recall'], r['all_recall']) for r in rows}


def main():
    # A cached run would only compare old output with itself, so always execute afresh.
    shutil.rmtree(FORENSIC / RUN, ignore_errors=True)
    subprocess.run([sys.executable, '-B', str(ROOT / 'forensic_test.py'), '--cases', *CASES, '--run', RUN, '--policies', 'ebr_frozen',
                    '--full-from', 'test', '--workers', '3'], check=True, stdout=subprocess.DEVNULL)
    old, new = records('test'), records(RUN)
    selection_same = old == new
    scores_same = metrics('test', 'ebr') == metrics(RUN, 'ebr_frozen')
    result = dict(cases=CASES, comparisons=len(old), identical_selections=selection_same, identical_scores=scores_same)
    (FORENSIC / 'frozen_replay.json').write_text(json.dumps(result, indent=1), encoding='utf8')
    print(json.dumps(result))
    if not selection_same or not scores_same:
        for key in old:
            if old[key] != new.get(key):
                print('selection differs', key, old[key], new.get(key))
        raise SystemExit('Frozen mode does not reproduce the first sealed test')


if __name__ == '__main__':
    main()
