"""The held-out study: one recorded sequence, declared before any test capture is opened.

    python final/run_frozen_test.py

1. Verify the freeze.
2. Compare all policies on every test case at 1, 2, 5 and 10 percent.
3. Remove EBR's components one at a time (ablation).
4. Compare the original algorithm where it is able to run at all.
5. Measure Suricata's own run-to-run noise on a complete capture.
6. Record what lossless gzip achieves on the same captures.
"""
from concurrent.futures import ProcessPoolExecutor
import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
FORENSIC = ROOT / 'results' / 'forensic'
ABLATIONS = {
    'no_rarity': {'use_rarity': False},
    'no_automation': {'use_automation': False},
    'no_pivot': {'pivot_weight': 0, 'pivot_victim_weight': 0},
    'no_diminishing': {'repeat_power': 0, 'spread_power': 0},
    'no_turn_heads': {'turn_head_bytes': 0},
    'no_ledger': {'ledger_max_share': 0},
    'tiers_only': {'use_rarity': False, 'use_automation': False, 'pivot_weight': 0, 'pivot_victim_weight': 0,
                   'repeat_power': 0, 'spread_power': 0},
}


def run(*arguments):
    began = time.time()
    subprocess.run([sys.executable, '-B', str(ROOT / 'forensic_test.py'), *arguments], check=True)
    print(f'-- finished {arguments[:6]} in {time.time() - began:.0f}s', flush=True)


def gzip_size(path):
    """Bytes after lossless gzip at the default level, without keeping the output."""
    class Counter:
        size = 0

        def write(self, data):
            self.size += len(data)
            return len(data)

        def flush(self):
            pass

    sink = Counter()
    with Path(path).open('rb') as source, gzip.GzipFile(fileobj=sink, mode='wb', compresslevel=6, mtime=0) as packer:
        shutil.copyfileobj(source, packer, 1 << 20)
    return sink.size


def lossless(cases, catalogue):
    import forensic_test as harness
    files = [(case, f) for case in cases for f in harness.case_files(case, catalogue)]
    with ProcessPoolExecutor(6) as pool:
        sizes = list(pool.map(gzip_size, [f for _, f in files]))
    result = {}
    for (case, f), size in zip(files, sizes):
        entry = result.setdefault(case, dict(input_bytes=0, gzip_bytes=0))
        entry['input_bytes'] += Path(f).stat().st_size
        entry['gzip_bytes'] += size
    (FORENSIC / 'test' / 'lossless.json').write_text(json.dumps(result, indent=1), encoding='utf8')


def noise_floor(catalogue):
    """Scan one complete capture three more times and compare alert sets with the reference."""
    import forensic_test as harness
    from ebr import forensic
    case = 'test_web_feb23'
    files = harness.case_files(case, catalogue)
    results = []
    for repeat in range(3):
        folder = FORENSIC / 'test' / 'noise' / str(repeat)
        forensic.scan_batch([(f, folder / (Path(f).name + '.json')) for f in files], folder)
        first = forensic.load_summaries(harness.full_summary_paths(FORENSIC / 'test', case, files))
        again = forensic.load_summaries([folder / (Path(f).name + '.json') for f in files])
        results.append(forensic.alert_recall(first, again))
    (FORENSIC / 'test' / 'noise.json').write_text(json.dumps(results, indent=1), encoding='utf8')


def main():
    subprocess.run([sys.executable, '-B', str(ROOT / 'freeze.py'), 'check'], check=True)
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    cases = [c for c, s in catalogue['cases'].items() if s['split'] == 'test']
    run('--cases', *cases, '--run', 'test', '--workers', '4')
    base = json.loads((ROOT / 'ebr_config.json').read_text(encoding='utf8'))
    for name, change in ABLATIONS.items():
        path = FORENSIC / f'ablation_{name}.config.json'
        path.write_text(json.dumps({**base, **change}), encoding='utf8')
        run('--cases', *cases, '--run', f'test_ablation_{name}', '--policies', 'ebr', '--full-from', 'test',
            '--config', str(path), '--workers', '4')
    run('--cases', 'dev_ctu_neris', 'dev_ctu_donbot', 'dev_ctu_rbot', 'dev_web', 'v1_test_web', '--run', 'original_compare',
        '--policies', 'v1_evidence', 'v1_bundle', 'flow_cutoff', 'ebr', '--workers', '3')
    noise_floor(catalogue)
    lossless(cases, catalogue)
    print('FROZEN TEST COMPLETE', flush=True)


if __name__ == '__main__':
    main()
