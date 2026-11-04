"""Apply a retention mask, write reduced captures and the charged flow ledger."""
import csv
import gzip
import hashlib
import io
from itertools import compress
from pathlib import Path
import socket

from .allocate import allocate
from .pcapstream import write_subset
from .value import score_flows

LEDGER_COLUMNS = ('start_ns', 'seconds', 'proto', 'client', 'cport', 'server', 'sport', 'app', 'state',
                  'pkts_c2s', 'pkts_s2c', 'bytes_c2s', 'bytes_s2c')
GROUP_COLUMNS = ('group', 'client', 'sport', 'app', 'state', 'flows', 'first_ns', 'last_ns', 'packets', 'bytes_c2s', 'bytes_s2c')


def address(raw):
    if len(raw) == 4:
        return socket.inet_ntoa(raw)
    if len(raw) == 16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    return raw.hex()


def _render_ledger(individual, grouped):
    text = io.StringIO()
    writer = csv.writer(text, lineterminator='\n')
    writer.writerow(LEDGER_COLUMNS)
    for f in individual:
        writer.writerow((f.first_ns, round((f.last_ns - f.first_ns) / 1e9, 3), f.proto, address(f.client), f.cport,
                         address(f.server), f.sport, f.app, f.state, f.packets[0], f.packets[1],
                         f.payload[0], f.payload[1]))
    if grouped:
        writer.writerow(GROUP_COLUMNS)
        for (client, sport, app, state), g in grouped.items():
            writer.writerow(('group', address(client) if client else '*', sport, app, state, g[0], g[1], g[2], g[3], g[4], g[5]))
    return gzip.compress(text.getvalue().encode('ascii', 'replace'), 6, mtime=0)


def _fold(flows, by_client=True):
    """Exact totals per behaviour for flows too cheap to deserve their own row."""
    groups = {}
    for f in flows:
        key = (f.client if by_client else None, f.sport, f.app, f.state)
        g = groups.get(key)
        if g is None:
            groups[key] = [1, f.first_ns, f.last_ns, f.packets[0] + f.packets[1], f.payload[0], f.payload[1]]
        else:
            g[0] += 1
            g[1] = min(g[1], f.first_ns)
            g[2] = max(g[2], f.last_ns)
            g[3] += f.packets[0] + f.packets[1]
            g[4] += f.payload[0]
            g[5] += f.payload[1]
    return groups


def ledger_bytes(flows, values=None, limit=None):
    """Gzip-compressed flow summary. Every flow is accounted for, individually or in a group."""
    complete = _render_ledger(flows, None)
    if limit is None or len(complete) <= limit:
        return complete
    ranked = sorted(flows, key=lambda f: -values[f.id])
    share = limit / len(complete)
    for attempt in range(8):
        count = int(len(flows) * share * 0.8 ** attempt)
        rest = ranked[count:]
        for by_client in (True, False):
            ledger = _render_ledger(ranked[:count], _fold(rest, by_client))
            if len(ledger) <= limit:
                return ledger
    return _render_ledger([], _fold(flows, False))


def ebr_select(profile, budget, config, scores=None):
    """Return (retention mask, ledger bytes, explanation) with the ledger charged to `budget`."""
    scores = scores or score_flows(profile.flows, config)
    share = config['ledger_max_share']
    ledger = ledger_bytes(profile.flows, scores['value'], int(budget * share)) if share else b''
    available = budget - 24 * profile.headers - len(ledger)
    if available <= 0:
        raise ValueError(f'Budget {budget} cannot fit the {len(ledger)}-byte ledger')
    levels, used = allocate(profile.flows, scores['value'], available, config)
    mask = bytearray(map(int.__le__, profile.tier, map(levels.__getitem__, profile.flow_of)))
    return mask, ledger, dict(levels=levels, scores=scores, pcap_bytes=used + 24 * profile.headers, ledger_bytes=len(ledger))


def write_reduced(profile, mask, folder):
    """Write one reduced capture per input, keeping every retained record byte-identical."""
    folder = Path(folder)
    results = []
    ends = profile.file_starts[1:] + [profile.packets]
    for path, begin, end in zip(profile.paths, profile.file_starts, ends):
        kept = compress(range(begin, end), memoryview(mask)[begin:end])
        target = folder / Path(path).name
        written = write_subset(path, kept, profile.offsets, profile.sizes, target)
        results.append(dict(file=target.name, bytes=written))
    return results


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()
