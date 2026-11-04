"""Record what a held-out test will run, and refuse to run anything else.

    python final/freeze.py write v3     create FREEZE_v3.json after tuning on non-sealed data
    python final/freeze.py check v3     fail if any frozen file has changed

The frozen set is everything that can move a test result: the algorithm, its
configuration, the comparators, the scoring code, the ground truth and the rules.
Earlier freezes stay as records of their tests, and their exact code is kept in
archive/ebr_frozen_20261030.zip and archive/ebr_v2_20261030.zip.
"""
import hashlib
import json
from datetime import datetime
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
FROZEN = ['ebr/__init__.py', 'ebr/pcapstream.py', 'ebr/profile.py', 'ebr/value.py', 'ebr/allocate.py', 'ebr/retain.py',
          'ebr/baselines.py', 'ebr/forensic.py', 'ebr_config.json', 'forensic_test.py', 'forensic_cases.json',
          'forensic_truth.json', 'lab/scan_batch.sh', 'lab/summarize_eve.py', 'lab/setup_lab.sh', 'ebr_config_frozen.json',
          'ebr/verify.py', 'verify_before_delete.py', 'verify_summary.py', 'lab/check_cap_engaged.py', 'run_sealed3.py', 'sealed3_plan.json']
RULES_SHA256 = '87db9268528953f871e3734498ff5597de20be1fe97edfdabaea1ac4468f6109'


def digests():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FROZEN}


def main(action, version):
    RECORD = ROOT / f'FREEZE_{version}.json'
    if action == 'write':
        if RECORD.exists():
            raise SystemExit(f'{RECORD.name} already exists. A new freeze means a new, disclosed test.')
        RECORD.write_text(json.dumps(dict(frozen_at=datetime.now().isoformat(timespec='seconds'), rules_sha256=RULES_SHA256,
                                          note='Written before any sealed capture was opened; only their sizes and format headers were read.', files=digests()), indent=1), encoding='utf8')
        print('Frozen', len(FROZEN), 'files')
    else:
        record = json.loads(RECORD.read_text(encoding='utf8'))
        changed = [name for name, digest in digests().items() if record['files'].get(name) != digest]
        if changed:
            raise SystemExit(f'Frozen files changed: {changed}')
        print('Freeze verified:', record['frozen_at'])


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
