"""Comparators on the same streaming index. Each gets the same serialized-byte budget.

The flow cutoff adapts to every budget, which makes it stronger than the fixed
Time Machine setting it derives from. The IDS-triggered policies receive real
Suricata alerts, an advantage EBR never has.
"""
from bisect import bisect_right
from itertools import accumulate, compress
import random


def random_packets(profile, budget, seed):
    """Seeded uniform packet sampling, trimmed to the exact cap."""
    room = budget - 24 * profile.headers
    total = sum(profile.sizes)
    rate = min(1.0, room / total)
    rng = random.Random(seed)
    draw = rng.random
    mask = bytearray(draw() < rate for _ in range(profile.packets))
    used = sum(compress(profile.sizes, mask))
    if used > room:
        for i in compress(range(profile.packets - 1, -1, -1), reversed(mask)):
            mask[i] = 0
            used -= profile.sizes[i]
            if used <= room:
                break
    return mask


def flow_costs(profile):
    totals = [0] * len(profile.flows)
    for flow, size in zip(profile.flow_of, profile.sizes):
        totals[flow] += size
    return totals


def random_flows(profile, budget, seed, costs=None):
    """Keep complete flows in random order until the cap is reached."""
    costs = costs or flow_costs(profile)
    room = budget - 24 * profile.headers
    order = list(range(len(costs)))
    random.Random(seed).shuffle(order)
    chosen = bytearray(len(costs))
    for flow in order:
        if costs[flow] <= room:
            chosen[flow] = 1
            room -= costs[flow]
    return bytearray(map(chosen.__getitem__, profile.flow_of))


class CutoffIndex:
    """Sorted stream positions, so the cutoff for any budget is one binary search."""

    def __init__(self, profile):
        packed = sorted(map(lambda p, s: (p << 20) | s, profile.position, profile.sizes))
        self.positions = [v >> 20 for v in packed]
        self.running = list(accumulate(v & 0xFFFFF for v in packed))

    def cutoff(self, room):
        where = bisect_right(self.running, room)
        if where >= len(self.positions):
            return 1 << 62
        return self.positions[where]


def flow_cutoff(profile, budget, index):
    """Time Machine style: keep the first C bytes of each flow direction, with C fitted to the cap.

    Packets tied at exactly C are thinned evenly across the capture, so the whole
    budget is spent even when control packets alone exceed it.
    """
    room = budget - 24 * profile.headers
    limit = index.cutoff(room)
    mask = bytearray(map(limit.__gt__, profile.position))
    spare = room - sum(compress(profile.sizes, mask))
    tied = list(compress(range(profile.packets), map(limit.__eq__, profile.position)))
    tied_bytes = sum(profile.sizes[i] for i in tied)
    if tied_bytes:
        rate, credit = min(1.0, spare / tied_bytes), 0.0
        for i in tied:
            credit += rate
            if credit >= 1.0 and profile.sizes[i] <= spare:
                mask[i] = 1
                spare -= profile.sizes[i]
                credit -= 1.0
    return mask


def alert_flow_ids(profile, alerts):
    """Map Suricata alert five-tuples onto profiled flows."""
    wanted = set()
    for src, sport, dst, dport in alerts:
        wanted.add((src, sport, dst, dport))
        wanted.add((dst, dport, src, sport))
    ids = set()
    for flow in profile.flows:
        if (flow.client, flow.cport, flow.server, flow.sport) in wanted:
            ids.add(flow.id)
    return ids


def is_internal(ip):
    return len(ip) == 4 and (ip[0] == 10 or (ip[0] == 172 and 16 <= ip[1] < 32) or (ip[0] == 192 and ip[1] == 168))


def rare_destination(profile, budget, costs, index, threshold=2):
    """Priority for DNS and rarely contacted outsiders, then a prefix of everything else.

    Inspired by XNET (Papastergiou et al., 2026), not a reproduction: it has no
    external popularity feeds, runs offline, and is fitted to a byte budget here.
    """
    peers = {}
    for flow in profile.flows:
        outside = flow.client if is_internal(flow.server) and not is_internal(flow.client) else flow.server
        inside = flow.server if outside is flow.client else flow.client
        peers.setdefault(outside, set()).add(inside)
    dns, rare = [], []
    for flow in profile.flows:
        outside = flow.client if is_internal(flow.server) and not is_internal(flow.client) else flow.server
        if 53 in (flow.sport, flow.cport):
            dns.append(flow.id)
        elif len(peers[outside]) <= threshold:
            rare.append(flow.id)
    # Low-and-slow first: the policy exists to protect small flows from sampling.
    ordered = dns + sorted(rare, key=costs.__getitem__)
    return keep_then_cutoff(profile, budget, ordered, costs, index)


def ids_triggered(profile, budget, flagged, costs=None, fill=False, index=None):
    """Keep complete alerted flows in time order; optionally spend leftovers on a flow cutoff."""
    costs = costs or flow_costs(profile)
    ordered = sorted(flagged, key=lambda f: profile.flows[f].first_ns)
    return keep_then_cutoff(profile, budget, ordered, costs, index if fill else None)


def keep_then_cutoff(profile, budget, ordered, costs, index=None):
    """Keep flows whole in the given order, then fit one cutoff to the remaining room."""
    fill = index is not None
    room = budget - 24 * profile.headers
    chosen = bytearray(len(costs))
    for flow in ordered:
        if costs[flow] <= room:
            chosen[flow] = 1
            room -= costs[flow]
    mask = bytearray(map(chosen.__getitem__, profile.flow_of))
    if fill and room > 0:
        total = budget - 24 * profile.headers
        low, high = 0, min(index.cutoff(total), 1 << 31)
        while low + 1 < high:
            middle = (low + high) // 2
            trial = bytearray(map(int.__or__, mask, map(middle.__gt__, profile.position)))
            if sum(compress(profile.sizes, trial)) <= total:
                low = middle
            else:
                high = middle
        mask = bytearray(map(int.__or__, mask, map(low.__gt__, profile.position)))
    return mask
