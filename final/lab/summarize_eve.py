"""Reduce a Suricata eve.json to the facts a forensic comparison needs. Runs in the lab distro."""
import json
import sys
from collections import defaultdict

MAX_URLS = 4000


def main(eve_path, out_path):
    alerts, pairs = {}, defaultdict(lambda: dict(http=0, ssh=0, ftp=0, tls=0, smtp=0, dns=0, urls=set(), names=set()))
    for line in open(eve_path, 'rb'):
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get('event_type')
        src, dst = event.get('src_ip'), event.get('dest_ip')
        if not src or not dst:
            continue
        a, b = sorted((src, dst))
        if kind == 'alert':
            info = event['alert']
            key = f'{info["signature_id"]}|{a}|{b}'
            minute = event['timestamp'][:16]
            entry = alerts.get(key)
            if entry is None:
                created = (info.get('metadata') or {}).get('created_at', [None])
                entry = alerts[key] = dict(sid=info['signature_id'], sig=info['signature'], cat=info.get('category', ''),
                                           sev=info.get('severity', 3), a=a, b=b, n=0, minutes=[], src=src, dst=dst,
                                           tuple=[src, event.get('src_port', 0), dst, event.get('dest_port', 0)],
                                           created=created[0] if created else None)
            entry['n'] += 1
            if not entry['minutes'] or entry['minutes'][-1] != minute:
                if len(entry['minutes']) < 2000:
                    entry['minutes'].append(minute)
        elif kind in ('http', 'ssh', 'ftp', 'tls', 'smtp', 'dns'):
            pair = pairs[f'{a}|{b}']
            pair[kind] += 1
            if kind == 'http':
                http = event.get('http', {})
                if len(pair['urls']) < MAX_URLS:
                    pair['urls'].add(f'{http.get("http_method", "")} {http.get("hostname", "")}{http.get("url", "")}')
            elif kind == 'dns':
                name = event.get('dns', {}).get('rrname')
                if name and len(pair['names']) < MAX_URLS:
                    pair['names'].add(name)
    result = dict(alerts=list(alerts.values()),
                  pairs={k: dict(v, urls=sorted(v['urls']), names=sorted(v['names'])) for k, v in pairs.items()})
    with open(out_path, 'w') as stream:
        json.dump(result, stream, separators=(',', ':'))


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
