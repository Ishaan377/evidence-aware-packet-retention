"""Whole-packet selection with shared serialized-byte accounting."""
from collections import Counter, defaultdict
import random
from src.evidence_scoring import candidates

def budget_bytes(original_size, fraction):
    if not 0 < fraction <= 1:
        raise ValueError("Budget fraction must be greater than zero and at most one.")
    cap = int(original_size * fraction)
    if cap < 24:
        raise ValueError("Budget cannot fit the mandatory 24-byte PCAP header.")
    return cap

def pack_order(packets, order, cap):
    remaining, selected = cap - 24, set()
    for i in order:
        if packets[i].cost <= remaining:
            selected.add(i)
            remaining -= packets[i].cost
    return selected

def select(packets, features, cap, strategy, seed, config, bundles=True):
    if 24 + sum(p.cost for p in packets) <= cap:
        return set(range(len(packets))), [{"reason": "All packets fit the byte cap"}]
    if strategy == "random":
        order = list(range(len(packets)))
        random.Random(seed).shuffle(order)
        return pack_order(packets, order, cap), [{"reason": "Seeded permutation; skip packets that do not fit"}]
    if strategy == "alert":
        order = [p.index for p in sorted(packets, key=lambda p: (p.timestamp_ns, p.index))
                 if p.flow in features["alerted_flows"]]
        return pack_order(packets, order, cap), [{"reason": "Chronological packing of rule-alerted flows"}]
    if strategy == "flow_prefix":
        spent, order = defaultdict(int), []
        for p in sorted(packets, key=lambda p: (p.timestamp_ns, p.index)):
            spent[p.flow] += len(p.data)
            if spent[p.flow] <= config["flow_prefix_bytes"]:
                order.append(p.index)
        return pack_order(packets, order, cap), [{"reason": "Whole packets within a per-flow prefix cutoff"}]
    if strategy != "evidence":
        raise ValueError("Unknown strategy: " + strategy)
    pool, _ = candidates(packets, features, config, bundles=bundles)
    selected, used, counts, decisions = set(), 24, Counter(), []
    # Recompute marginal cost after overlap; category gains diminish after use.
    # This is a heuristic, not an optimal knapsack solver or a guarantee.
    while True:
        best, best_ratio, best_new, best_cost = None, -1, None, 0
        for candidate in pool:
            new = candidate.indices - selected
            if not new:
                continue
            cost = sum(packets[i].cost for i in new)
            if used + cost > cap:
                continue
            scale = config["diminishing_scale"].get(candidate.kind, 1.0)
            gain = candidate.weight / (1 + counts[candidate.kind] / scale)
            ratio = gain / cost
            if ratio > best_ratio:
                best, best_ratio, best_new, best_cost = candidate, ratio, new, cost
        if best is None:
            break
        selected.update(best_new)
        used += best_cost
        counts[best.kind] += 1
        decisions.append({"kind": best.kind, "indices": sorted(best_new), "marginal_bytes": best_cost,
                          "gain_per_byte": best_ratio, "reason": best.reason})
    return selected, decisions
