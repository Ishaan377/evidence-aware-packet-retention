"""The second sealed study: fixed EBR against the frozen version on captures neither has seen.

    python final/run_sealed2.py

1. Verify the second freeze.
2. Compare every policy, including the first frozen version, on the sealed cases.
3. Measure lossless gzip on the sealed captures.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
FORENSIC = ROOT / 'results' / 'forensic'
POLICIES = ('random_packet', 'random_flow', 'flow_cutoff', 'rare_dest', 'ids_past', 'ids_past_fill', 'ebr_frozen', 'ebr')


def run(*arguments):
    began = time.time()
    subprocess.run([sys.executable, '-B', str(ROOT / 'forensic_test.py'), *arguments], check=True)
    print(f'-- finished {arguments[:3]} in {time.time() - began:.0f}s', flush=True)


def main():
    subprocess.run([sys.executable, '-B', str(ROOT / 'freeze.py'), 'check', 'v2'], check=True)
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    sealed = [c for c, s in catalogue['cases'].items() if s['split'] == 'sealed2']
    run('--cases', *sealed, '--run', 'sealed2', '--policies', *POLICIES, '--workers', '4')
    from run_frozen_test import gzip_size
    import forensic_test as harness
    from concurrent.futures import ProcessPoolExecutor
    files = [(case, f) for case in sealed for f in harness.case_files(case, catalogue)]
    with ProcessPoolExecutor(6) as pool:
        sizes = list(pool.map(gzip_size, [f for _, f in files]))
    result = {}
    for (case, f), size in zip(files, sizes):
        entry = result.setdefault(case, dict(input_bytes=0, gzip_bytes=0))
        entry['input_bytes'] += Path(f).stat().st_size
        entry['gzip_bytes'] += size
    (FORENSIC / 'sealed2' / 'lossless.json').write_text(json.dumps(result, indent=1), encoding='utf8')
    print('SEALED TEST COMPLETE', flush=True)


if __name__ == '__main__':
    main()
