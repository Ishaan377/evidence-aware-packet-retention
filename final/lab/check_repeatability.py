"""Is a Suricata scan of a reduced capture repeatable, and which run mode makes it so?

Scans the same reduced captures several times in fresh processes under each mode.
Uses only captures whose results are already known.
"""
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import forensic_test as harness  # noqa: E402
from ebr import forensic  # noqa: E402
from ebr.profile import build_profile  # noqa: E402
from ebr.retain import ebr_select, write_reduced  # noqa: E402

SAMPLES = (('sealed2_ctu_mixed1', 0.10), ('sealed2_wrccdc2019', 0.05), ('sealed2_wrccdc2024', 0.05))
MODES = ('autofp', 'single')
REPEATS = 3


def scan(pcap, summary, mode):
    script = ('set -e; d=$(mktemp -d /var/tmp/ebrone.XXXXXX); export TZ=UTC; '
              f'suricata -c /opt/ebr/suricata.yaml -r "$1" -l "$d" -k none --runmode {mode} >/dev/null 2>&1; '
              'python3 /opt/ebr/bin/summarize_eve.py "$d/eve.json" "$2"; rm -rf "$d"')
    subprocess.run(['wsl.exe', '-d', 'ebr-lab', '-u', 'root', '--exec', '/bin/bash', '-c', script, '_',
                    forensic.to_wsl(pcap), forensic.to_wsl(summary)], check=True)


def keys(path):
    data = json.loads(Path(path).read_text(encoding='utf8'))
    return {(a['sid'], a['a'], a['b']) for a in data['alerts']}


def main():
    forensic.sync_lab_tools()
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    config = json.loads((ROOT / 'ebr_config.json').read_text(encoding='utf8'))
    out = ROOT / 'results' / 'forensic' / 'repeatability'
    report = []
    for case, cap in SAMPLES:
        files = harness.case_files(case, catalogue)
        profile = build_profile(files, config)
        mask, _, _ = ebr_select(profile, int(profile.input_bytes * cap), config)
        write_reduced(profile, mask, out / case)
        pcap = out / case / Path(files[0]).name
        for mode in MODES:
            sets, began = [], time.time()
            for repeat in range(REPEATS):
                summary = out / case / f'{mode}{repeat}.json'
                scan(pcap, summary, mode)
                sets.append(keys(summary))
            union, common = set().union(*sets), set.intersection(*sets)
            report.append(dict(case=case, cap=cap, mode=mode, alert_keys=sorted(len(s) for s in sets), differing_keys=len(union - common),
                               identical=len(union) == len(common), seconds_per_scan=round((time.time() - began) / REPEATS, 1), megabytes=round(pcap.stat().st_size / 1e6, 1)))
            print(report[-1], flush=True)
    (out.parent / 'repeatability.json').write_text(json.dumps(report, indent=1), encoding='utf8')


if __name__ == '__main__':
    main()
