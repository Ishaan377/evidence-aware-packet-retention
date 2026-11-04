"""Choose one fidelity level per flow to maximise evidence value under a byte budget.

This is a multiple-choice knapsack. Each flow's (cost, value) levels are reduced
to their upper concave hull; hull segments are then taken in order of value per
byte. Segments of one flow have falling efficiency, so the order is always
feasible, and the fractional optimum is reached to within the final segment.
The optional share for payload-free flows adds a second constraint, so with it
the result is a good heuristic rather than that optimum.
"""
from .profile import TIERS


def tier_weights(flow, config):
    """Marginal worth of each tier. Unreadable bulk is worth little beyond its head."""
    weights = config['tier_weights']
    if flow.plain or flow.app in config.get('readable_apps', ()):
        return weights
    return weights[:2] + [w * config['opaque_bulk_factor'] for w in weights[2:]]


def hull_segments(flow, value, config):
    """Return (efficiency, flow id, level reached, added bytes) along the upper hull."""
    weights = tier_weights(flow, config)
    levels = [(0, 0.0, -1)]
    cost, worth = 0, 0.0
    for tier in range(TIERS):
        # A flow earns value only for evidence it contains. A bare SYN has no head to keep,
        # so it cannot outbid a flow that carried a request merely by being cheap.
        if flow.cost[tier]:
            cost += flow.cost[tier]
            worth += value * weights[tier]
            levels.append((cost, worth, tier))
    hull = []
    for point in levels:
        while len(hull) >= 2:
            (x0, y0, _), (x1, y1, _) = hull[-2], hull[-1]
            if (y1 - y0) * (point[0] - x0) <= (point[1] - y0) * (x1 - x0):
                hull.pop()
            else:
                break
        hull.append(point)
    segments = []
    for (x0, y0, _), (x1, y1, level) in zip(hull, hull[1:]):
        if y1 > y0:
            # Levels above the highest occupied tier are empty, so the last vertex keeps everything.
            segments.append(((y1 - y0) / (x1 - x0), flow.id, TIERS if level == levels[-1][2] else level, x1 - x0))
    return segments


def allocate(flows, values, budget, config):
    """Return (levels by flow id, bytes used). Level -1 keeps the flow in the ledger only."""
    segments = []
    for flow, value in zip(flows, values):
        segments.extend(hull_segments(flow, value, config))
    segments.sort(key=lambda s: (-s[0], s[1], s[2]))
    levels, used = [-1] * len(flows), 0
    blocked = bytearray(len(flows))
    # Payload-free flows are cheap, so a scan storm could outbid real evidence on price alone.
    # They get a share of the budget first, and whatever content leaves unused afterwards.
    share = config.get('silent_budget_share')
    silent_room, deferred = (budget * share if share else None), []
    for segment in segments:
        _, fid, level, cost = segment
        if blocked[fid]:
            continue
        if silent_room is not None and not flows[fid].data_seen:
            if cost > silent_room:
                deferred.append(segment)
                continue
            silent_room -= cost
        if used + cost <= budget:
            used += cost
            levels[fid] = level
        else:
            # Later segments of this flow depend on the one that did not fit.
            blocked[fid] = 1
    for _, fid, level, cost in deferred:
        if used + cost <= budget:
            used += cost
            levels[fid] = level
    return levels, used
