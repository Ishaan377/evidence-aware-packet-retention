"""Forensic value of a flow, in bits of surprise under the capture's own baseline.

Nothing here uses signatures, labels or alerts. Value comes from three ideas:

1. Rarity: a flow is worth -log2 P(x) bits for each rarely seen trait x.
2. Automation: thousands of near-identical flows from one client are a behaviour
   worth log2(n) bits, even though each flow is individually common.
3. Pivoting: an investigator who distrusts a host looks at everything it touched,
   so suspicion spreads from a host to its flows and to what its victims did next.

Behaviour clusters then apply diminishing returns. The tenth thousandth identical
login failure adds almost nothing once exemplars and the ledger's exact count exist.
"""
from collections import Counter, defaultdict
from math import log2
from statistics import median, pstdev


def _bucket(value):
    return value.bit_length() if value else 0


def service_of(flow):
    port = flow.sport if flow.sport < 49152 else 'eph'
    return (flow.proto, port, flow.app)


def shape_of(flow):
    return (flow.app, flow.state, _bucket(flow.payload[0]), _bucket(flow.payload[1]))


def _surprisal(values, cap):
    """-log2 P(value), with Good-Turing's correction for values seen only a few times.

    A value seen once is only surprising when one-offs are rare. If most values are
    one-offs, as with spam-bot DNS names, then the next new value is entirely expected.
    """
    counts = Counter(values)
    total = len(values)
    novelty = sum(1 for n in counts.values() if n == 1) / total
    table = {k: min(cap, -log2(max(n / total, novelty / n))) for k, n in counts.items()}
    return [table[v] for v in values]


def _surprisal_within(flows, trait, cap):
    """Surprisal of a trait among flows of the same application, whose vocabularies differ."""
    groups = defaultdict(list)
    for i, f in enumerate(flows):
        groups[f.app].append(i)
    bits = [0.0] * len(flows)
    for members in groups.values():
        for i, value in zip(members, _surprisal([trait(flows[i]) for i in members], cap)):
            bits[i] = value
    return bits


def rarity_bits(flows, config):
    """Combine trait surprisal with noisy-max: the rarest trait dominates, the rest add a little."""
    cap = config['rarity_cap_bits']
    traits = [
        _surprisal([service_of(f) for f in flows], cap),
        _surprisal([shape_of(f) for f in flows], cap),
        _surprisal([(f.client, f.server) for f in flows], cap),
        _surprisal_within(flows, lambda f: f.client_fp or f.state, cap),
        _surprisal_within(flows, lambda f: f.content or f.state, cap),
    ]
    baseline = [median(column) for column in traits]
    bits = []
    for i in range(len(flows)):
        excess = sorted((max(0.0, traits[t][i] - baseline[t]) for t in range(len(traits))), reverse=True)
        bits.append(excess[0] + config['rarity_tail_weight'] * sum(excess[1:]))
    return bits


def automation_bits(flows, config):
    """log2(n) for groups of similar repeated flows, scaled by how machine-like they look."""
    groups = defaultdict(list)
    for f in flows:
        groups[(f.client, f.server, f.sport, f.proto)].append(f)
    bits = [0.0] * len(flows)
    position = {f.id: i for i, f in enumerate(flows)}
    for (client, server, port, proto), members in groups.items():
        n = len(members)
        if n < config['automation_min_flows']:
            continue
        sizes = [f.payload[0] + f.payload[1] for f in members]
        mean = sum(sizes) / n
        spread = pstdev(sizes) / mean if mean else 0.0
        failures = sum(1 for f in members if f.state in ('S0', 'REJ', 'RSTO')) / n
        starts = sorted(f.first_ns for f in members)
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        gap_mean = sum(gaps) / len(gaps) if gaps else 0
        regular = 1 - min(1.0, pstdev(gaps) / gap_mean) if gap_mean else 0.0
        likeness = max(1 - min(1.0, spread), regular, failures)
        score = log2(n) * likeness
        for f in members:
            bits[position[f.id]] = score
    # One client probing many endpoints is automation even when each endpoint sees one flow.
    probes = defaultdict(list)
    for f in flows:
        if f.state in ('S0', 'REJ', 'RSTO') and f.proto != 255:
            probes[f.client].append(f)
    for client, members in probes.items():
        distinct = len({(f.server, f.sport) for f in members})
        if distinct >= config['automation_min_flows']:
            score = log2(distinct)
            for f in members:
                i = position[f.id]
                bits[i] = max(bits[i], score)
    return bits


def host_suspicion(flows, bits, config):
    """A host is as suspicious as the mass of surprise it initiated, not its single oddest flow."""
    mass = defaultdict(float)
    for f, b in zip(flows, bits):
        if b >= config['pivot_seed_bits']:
            mass[f.client] += 2 ** min(b - config['pivot_seed_bits'], 12)
    scores = {host: log2(1 + total) for host, total in mass.items()}
    if not scores:
        return scores
    reference = median(scores.values()) if len(scores) > 2 else 0.0
    return {host: max(0.0, s - reference) for host, s in scores.items()}


def pivot_bits(flows, bits, config):
    """Spread suspicion to every flow of a suspicious host and to its victims' next moves."""
    hosts = host_suspicion(flows, bits, config)
    weight, window = config['pivot_weight'], int(config['pivot_window_seconds'] * 1e9)
    first_hit = {}
    for f, b in sorted(zip(flows, bits), key=lambda item: item[0].first_ns):
        if b >= config['pivot_seed_bits'] and hosts.get(f.client, 0) > 0 and f.server not in first_hit:
            first_hit[f.server] = (f.first_ns, hosts[f.client])
    uplift = []
    seen_peers = defaultdict(int)
    for f in flows:
        seen_peers[(f.client, f.server)] += 1
    for f in flows:
        lift = weight * max(hosts.get(f.client, 0.0), hosts.get(f.server, 0.0))
        hit = first_hit.get(f.client)
        if hit and 0 <= f.first_ns - hit[0] <= window and seen_peers[(f.client, f.server)] <= config['pivot_rare_peer_flows']:
            lift = max(lift, config['pivot_victim_weight'] * hit[1])
        uplift.append(lift)
    return uplift, hosts


def _cluster_multipliers(clusters, power, burst):
    """Rank members of each cluster; a burst stays whole, the rest are spread in bit-reversed order."""
    multipliers = {}
    for members in clusters.values():
        members.sort(key=lambda f: f.first_ns)
        n = len(members)
        order = list(range(min(burst, n)))
        if n > burst:
            rest = n - burst
            width = max(1, (rest - 1).bit_length())
            order += [burst + i for i in sorted(range(rest), key=lambda i: int(f'{i:0{width}b}'[::-1], 2))]
        for rank, where in enumerate(order, 1):
            effective = 1 if rank <= burst else rank - burst + 1
            multipliers[members[where].id] = effective ** -power
    return multipliers


def diminishing_multipliers(flows, config):
    """Apply diminishing returns to repetition, but not to new indicators.

    Repeating one message to one server adds little, so ranks within a client,
    server and content triple fall steeply. A new payload or a new endpoint is a
    new indicator of compromise even when the behaviour matches, so ranks across
    a behaviour fall gently. Measuring from both the client and the server side
    collapses one-to-many and many-to-one floods; leaving the port out of the
    client's view makes a thousand-port scan one behaviour.

    A short unbroken burst keeps rate-based detections working, and bit-reversed
    order means any prefix of a cluster covers its whole time span.
    """
    burst = config['exemplar_burst']
    pairs, clients, servers, silent = defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list)
    for f in flows:
        shape = (f.app, f.state, _bucket(f.payload[0] + f.payload[1]))
        service = f.sport if f.sport < 49152 else 'eph'
        pairs[(f.client, f.server, service, f.content, shape)].append(f)
        clients[(f.client, shape)].append(f)
        servers[(f.server, service, shape)].append(f)
        if not f.data_seen:
            # A payload-free flow holds nothing the ledger lacks, beyond proving the behaviour.
            silent[(f.client, shape)].append(f)
    repeat = _cluster_multipliers(pairs, config['repeat_power'], burst)
    across_clients = _cluster_multipliers(clients, config['spread_power'], burst)
    across_servers = _cluster_multipliers(servers, config['spread_power'], burst)
    probes = _cluster_multipliers(silent, config['repeat_power'], burst)
    return [repeat[f.id] * min(across_clients[f.id], across_servers[f.id], probes.get(f.id, 1.0)) for f in flows]


def score_flows(flows, config):
    """Return per-flow evidence value plus the components that explain it."""
    blank = [0.0] * len(flows)
    rarity = rarity_bits(flows, config) if config.get('use_rarity', True) else blank
    automation = automation_bits(flows, config) if config.get('use_automation', True) else blank
    own = [max(r, a) for r, a in zip(rarity, automation)]
    uplift, hosts = pivot_bits(flows, own, config)
    multiplier = diminishing_multipliers(flows, config)
    base = config['base_value_bits']
    values = [(base + o + u) * m for o, u, m in zip(own, uplift, multiplier)]
    return dict(value=values, rarity=rarity, automation=automation, pivot=uplift, multiplier=multiplier, hosts=hosts)
