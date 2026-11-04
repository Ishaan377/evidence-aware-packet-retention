"""The third sealed study, following sealed3_plan.json.

    python final/run_sealed3.py

1. Verify the freeze.
2. Screen captures for scan storms from headers, before any detection runs.
3. Compare every policy on the sealed cases.
4. Run the verify-before-delete loop on the same cases.
5. Summarise, with gzip as a lossless reference.
"""
from concurrent.futures import ProcessPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
FORENSIC = ROOT / 'results' / 'forensic'
POLICIES = ('random_packet', 'random_flow', 'flow_cutoff', 'rare_dest', 'ids_past', 'ids_past_fill', 'ebr_frozen', 'ebr')


def step(name, *command):
    began = time.time()
    subprocess.run([sys.executable, '-B', *map(str, command)], check=True)
    print(f'-- {name} finished in {time.time() - began:.0f}s', flush=True)


def main():
    step('freeze check', ROOT / 'freeze.py', 'check', 'v3')
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    cases = [c for c, s in catalogue['cases'].items() if s['split'] == 'sealed3']
    step('screen', ROOT / 'lab' / 'check_cap_engaged.py', 'sealed3', *cases)
    step('comparison', ROOT / 'forensic_test.py', '--cases', *cases, '--run', 'sealed3', '--policies', *POLICIES, '--workers', '2')
    step('repair loop', ROOT / 'verify_before_delete.py', '--run', 'sealed3_verify', '--split', 'sealed3', '--workers', '2')
    step('summary', ROOT / 'verify_summary.py', 'sealed3_verify', 'sealed3')
    from run_frozen_test import gzip_size
    import forensic_test as harness
    files = [(case, f) for case in cases for f in harness.case_files(case, catalogue)]
    with ProcessPoolExecutor(6) as pool:
        sizes = list(pool.map(gzip_size, [f for _, f in files]))
    result = {}
    for (case, f), size in zip(files, sizes):
        entry = result.setdefault(case, dict(input_bytes=0, gzip_bytes=0))
        entry['input_bytes'] += Path(f).stat().st_size
        entry['gzip_bytes'] += size
    (FORENSIC / 'sealed3' / 'lossless.json').write_text(json.dumps(result, indent=1), encoding='utf8')
    print('THIRD SEALED TEST COMPLETE', flush=True)


if __name__ == '__main__':
    main()
