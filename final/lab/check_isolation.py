"""Does one Suricata daemon give the same alerts as a fresh process for every capture?

Repeats captures inside one daemon, then scans each in its own process, and compares
the alert sets. Differences would mean state leaks between scans and bias later ones.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ebr import forensic  # noqa: E402


def alert_keys(path):
    data = json.loads(Path(path).read_text(encoding='utf8'))
    return {(a['sid'], a['a'], a['b']): a['n'] for a in data['alerts']}


def standalone(pcap, summary):
    script = ('set -e; d=$(mktemp -d /var/tmp/ebrone.XXXXXX); export TZ=UTC; '
              'suricata -c /opt/ebr/suricata.yaml -r "$1" -l "$d" -k none --runmode autofp >/dev/null 2>&1; '
              'python3 /opt/ebr/bin/summarize_eve.py "$d/eve.json" "$2"; rm -rf "$d"')
    subprocess.run(['wsl.exe', '-d', 'ebr-lab', '-u', 'root', '--exec', '/bin/bash', '-c', script, '_',
                    forensic.to_wsl(pcap), forensic.to_wsl(summary)], check=True)


def main(pcaps):
    with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parent) as folder:
        folder = Path(folder)
        order = [pcaps[0], pcaps[1], pcaps[0], pcaps[1], pcaps[0]]
        jobs = [(p, folder / f'daemon_{i}.json') for i, p in enumerate(order)]
        forensic.scan_batch(jobs, folder)
        for number, pcap in enumerate(pcaps):
            standalone(pcap, folder / f'alone_{number}.json')
        verdict = dict(identical=True, details=[])
        for i, pcap in enumerate(order):
            daemon = alert_keys(folder / f'daemon_{i}.json')
            alone = alert_keys(folder / f'alone_{pcaps.index(pcap)}.json')
            same_keys = set(daemon) == set(alone)
            same_counts = daemon == alone
            verdict['identical'] &= same_keys
            verdict['details'].append(dict(position=i, capture=Path(pcap).name, daemon=len(daemon), alone=len(alone),
                                           same_alert_set=same_keys, same_counts=same_counts,
                                           only_daemon=len(set(daemon) - set(alone)), only_alone=len(set(alone) - set(daemon))))
    print(json.dumps(verdict, indent=1))


if __name__ == '__main__':
    main(sys.argv[1:3])
