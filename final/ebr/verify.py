"""Verify before delete: measure a reduction's losses while the original still exists.

Retention is usually a blind bet, but the complete capture is still on disk until
the moment it is deleted. So scan both copies, put back the flows behind any lost
detection, and try again. Repair runs inside the same byte budget: a repaired flow
outbids everything else, and the lowest-value evidence makes room for it.

Repair can only protect detections that already exist. What it reveals about
unknown threats comes from the reduction's losses before repair, because EBR
makes that first selection without seeing a single rule.
"""
from collections import defaultdict
from datetime import datetime, timezone
import hashlib

from .forensic import is_attack
from .retain import address, ebr_select

REPAIR_BOOST = 1000
NEIGHBOUR_LIMIT = 64


def family(entry):
    """Rule family from the signature's name, such as 'ET SCAN' or 'GPL WEB_SERVER'."""
    words = entry['sig'].split()
    return ' '.join(words[:2]) if len(words) > 1 else entry['sig']


def hidden_family(entry):
    """A stable coin flip per family, so the same families stay hidden in every case."""
    return int(hashlib.md5(family(entry).encode()).hexdigest(), 16) % 2 == 1


def is_later_rule(entry, capture_date):
    """Was this rule published on or after the capture date, so nothing could have used it then?"""
    return (entry.get('created') or '9999').replace('_', '-') >= capture_date


def known_alerts(full, condition, capture_date):
    """The detections a condition may use for repair, keyed as in the summaries."""
    attacks = {k: v for k, v in full['alerts'].items() if is_attack(v)}
    if condition == 'all':
        return attacks
    if condition == 'past':
        return {k: v for k, v in attacks.items() if not is_later_rule(v, capture_date)}
    if condition == 'half':
        return {k: v for k, v in attacks.items() if not hidden_family(v)}
    raise ValueError(condition)


def minute_ns(text):
    moment = datetime.strptime(text, '%Y-%m-%dT%H:%M').replace(tzinfo=timezone.utc)
    return int(moment.timestamp()) * 1_000_000_000


class FlowIndex:
    """Find the flows behind an alert, by five-tuple and by host pair.

    Scan storms hold millions of flows, so with `entries` given it indexes only
    the hosts those alerts involve.
    """

    def __init__(self, flows, entries=None):
        self.by_tuple, self.by_pair = defaultdict(list), defaultdict(list)
        hosts = None if entries is None else {a for e in entries for a in (e['a'], e['b'])}
        for f in flows:
            client, server = address(f.client), address(f.server)
            if hosts is not None and client not in hosts and server not in hosts:
                continue
            self.by_tuple[(client, f.cport, server, f.sport)].append(f)
            self.by_tuple[(server, f.sport, client, f.cport)].append(f)
            self.by_pair[tuple(sorted((client, server)))].append(f)

    def targets(self, entry, widen):
        """The flow that raised an alert; if that was not enough, its neighbours in time.

        Rate-based rules need several flows close together, so a second attempt
        adds the first flows between the same hosts inside the alert's minutes.
        """
        chosen = [f.id for f in self.by_tuple.get(tuple(entry['tuple']), ())]
        if widen and entry['minutes']:
            start, stop = minute_ns(entry['minutes'][0]), minute_ns(entry['minutes'][-1]) + 60_000_000_000
            nearby = [f for f in self.by_pair.get((entry['a'], entry['b']), ()) if f.first_ns <= stop and f.last_ns >= start]
            chosen += [f.id for f in sorted(nearby, key=lambda f: f.first_ns)[:NEIGHBOUR_LIMIT]]
        return set(chosen)


def repaired_select(profile, budget, config, scores, forced):
    """Select again with `forced` flows outbidding everything, so the cap still holds."""
    boosted = list(scores['value'])
    ceiling = max(boosted, default=1.0) * REPAIR_BOOST
    for flow in forced:
        boosted[flow] = ceiling
    return ebr_select(profile, budget, config, dict(scores, value=boosted))
