"""Forensic scoring. Suricata and ET Open are independent of everything EBR computes.

Three questions are asked of each reduced capture:

* Alert survival: which detections on the full capture still fire?
* Campaign survival: for a labelled attack, is the attacker still caught?
* Evidence survival: how much of the labelled attack can still be examined?
"""
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import subprocess

# Detection classes that describe an attack rather than ordinary or merely unusual traffic.
ATTACK_CATEGORIES = {
    'A Network Trojan was detected', 'Attempted Administrator Privilege Gain', 'Attempted User Privilege Gain',
    'Successful Administrator Privilege Gain', 'Successful User Privilege Gain', 'Web Application Attack',
    'Attempted Denial of Service', 'Denial of Service', 'Detection of a Denial of Service Attack',
    'Executable code was detected', 'A suspicious string was detected', 'Attempted Information Leak',
    'Information Leak', 'Large Scale Information Leak', 'Detection of a Network Scan', 'Network Scan',
    'Malware Command and Control Activity Detected', 'Exploit Kit Activity Detected', 'Misc Attack',
    'access to a potentially vulnerable web application', 'A Client was using an unusual port',
    'Domain Observed Used for C2 Detected', 'Device Retrieving External IP Address Detected',
    'Crypto Currency Mining Activity Detected', 'Targeted Malicious Activity was Detected', 'Possible Social Engineering Attempted',
    'Potentially Bad Traffic', 'Potential Corporate Privacy Violation'}


def to_wsl(path):
    resolved = Path(path).resolve()
    drive, rest = resolved.drive.rstrip(':').lower(), resolved.as_posix().split(':', 1)[1]
    return f'/mnt/{drive}{rest}'


def sync_lab_tools():
    """Copy the lab helpers into the distro through stdin, with Unix line endings."""
    lab = Path(__file__).resolve().parent.parent / 'lab'
    for name in ('scan_batch.sh', 'summarize_eve.py'):
        script = (lab / name).read_bytes().replace(b'\r\n', b'\n')
        subprocess.run(['wsl.exe', '-d', 'ebr-lab', '-u', 'root', '--exec', '/usr/bin/tee', f'/opt/ebr/bin/{name}'],
                       input=script, stdout=subprocess.DEVNULL, check=True)


def scan_batch(jobs, workspace):
    """Run Suricata over (pcap, summary) pairs that lack a summary. One daemon, rules loaded once."""
    pending = [(p, s) for p, s in jobs if not Path(s).exists()]
    if not pending:
        return 0
    sync_lab_tools()
    workspace = Path(workspace)
    workspace.mkdir(parents=True, exist_ok=True)
    batch = workspace / f'batch_{hashlib.md5(repr(pending).encode()).hexdigest()[:8]}.tsv'
    with batch.open('w', encoding='utf8', newline='\n') as stream:
        for pcap, summary in pending:
            Path(summary).parent.mkdir(parents=True, exist_ok=True)
            stream.write(f'{to_wsl(pcap)}\t{to_wsl(summary)}\n')
    subprocess.run(['wsl.exe', '-d', 'ebr-lab', '-u', 'root', '--exec', '/bin/bash', '/opt/ebr/bin/scan_batch.sh', to_wsl(batch)], check=True)
    batch.unlink()
    missing = [s for _, s in pending if not Path(s).exists()]
    if missing:
        raise RuntimeError(f'Suricata produced no summary for {len(missing)} captures, first {missing[0]}')
    return len(pending)


def load_summaries(paths):
    """Merge per-file summaries from one case into a single view."""
    alerts, pairs = {}, defaultdict(lambda: defaultdict(int))
    urls = defaultdict(set)
    for path in paths:
        data = json.loads(Path(path).read_text(encoding='utf8'))
        for entry in data['alerts']:
            key = (entry['sid'], entry['a'], entry['b'])
            current = alerts.get(key)
            if current is None:
                alerts[key] = dict(entry)
            else:
                current['n'] += entry['n']
                current['minutes'] = sorted(set(current['minutes']) | set(entry['minutes']))
        for pair, counts in data['pairs'].items():
            for kind in ('http', 'ssh', 'ftp', 'tls', 'smtp', 'dns'):
                pairs[pair][kind] += counts[kind]
            urls[pair].update(counts['urls'])
    return dict(alerts=alerts, pairs=pairs, urls=urls)


def is_attack(entry):
    return entry['cat'] in ATTACK_CATEGORIES


def alert_recall(full, reduced, keep=None):
    """Recall of alert instances, and of distinct signatures, within the `keep` subset."""
    reference = {k: v for k, v in full['alerts'].items() if keep is None or keep(v)}
    observed = reduced['alerts']
    hits = [k for k in reference if k in observed]
    sids = {v['sid'] for v in reference.values()}
    seen = {reference[k]['sid'] for k in hits}
    return dict(reference=len(reference), found=len(hits), instance=len(hits) / len(reference) if reference else None,
                signatures=len(sids), signatures_found=len(seen), signature=len(seen) / len(sids) if sids else None)


def invented_alerts(full, reduced):
    """Detections that exist only in the reduced capture."""
    return [v for k, v in reduced['alerts'].items() if k not in full['alerts']]


def episode_matches(entry, episode):
    """Does this alert connect an attacker to a victim during the labelled window?"""
    actors, targets = set(episode['attackers']), set(episode['victims'])
    linked = (entry['a'] in actors and entry['b'] in targets) or (entry['b'] in actors and entry['a'] in targets)
    if not linked:
        return False
    return any(episode['start'] <= minute <= episode['end'] for minute in entry['minutes'])


def episode_outcome(episode, view):
    """Which distinct signatures tie the labelled attacker to the victim in this view?"""
    return sorted({entry['sid'] for entry in view['alerts'].values() if episode_matches(entry, episode)})


def application_recall(episode, full, reduced):
    """Share of application events between labelled endpoints that survive, per protocol."""
    actors, targets = episode['attackers'], episode['victims']
    keys = ['|'.join(sorted((a, b))) for a in actors for b in targets]
    total, kept = 0, 0
    for key in keys:
        if key not in full['pairs']:
            continue
        for kind in ('http', 'ssh', 'ftp', 'tls', 'smtp'):
            reference = full['pairs'][key][kind]
            total += reference
            kept += min(reference, reduced['pairs'][key][kind] if key in reduced['pairs'] else 0)
    url_total = sum(len(full['urls'].get(k, ())) for k in keys)
    url_kept = sum(len(full['urls'].get(k, set()) & reduced['urls'].get(k, set())) for k in keys)
    return dict(events=total, events_kept=kept, urls=url_total, urls_kept=url_kept)
