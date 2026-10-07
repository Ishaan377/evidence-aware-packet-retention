"""Build explainable candidate bundles from observable traffic.

Weights are design choices, not learned values or probabilities of malice.
The heuristic never reads the question catalogue or ground-truth manifest.
"""
from dataclasses import dataclass
from src.feature_extraction import is_internal

@dataclass(frozen=True)
class Candidate:
    indices: frozenset
    kind: str
    weight: float
    reason: str

def candidates(packets, features, config, bundles=True):
    result, scan_ids = [], set()
    weights = config["weights"]
    for members in features["scans"].values():
        ids = frozenset(p.index for p in members)
        scan_ids.update(ids)
        if bundles:
            result.append(Candidate(ids, "scan_complete", weights["scan_complete"],
                                    "All SYN witnesses for a detected fan-out bin"))
            result.append(Candidate(frozenset((members[0].index, members[-1].index)),
                                    "scan_boundary", weights["scan_boundary"],
                                    "First and last observed SYN in the fan-out bin"))
    priority = {}
    if bundles:
        for request, response, status in features["http"]:
            kind = "http_failure" if status == 401 else "http_success" if status == 200 else "http_other"
            result.append(Candidate(frozenset((request.index, response.index)), kind, weights[kind],
                                    "Matched HTTP request and response, including TCP acknowledgement"))
        for request, response, _, _ in features["dns"]:
            result.append(Candidate(frozenset((request.index, response.index)), "dns_exchange",
                                    weights["dns_exchange"], "Matched DNS transaction"))
        for syn, synack, ack in features["handshakes"]:
            if all(is_internal(a, config["internal_networks"]) for a in (syn.src, syn.dst)):
                result.append(Candidate(frozenset((syn.index, synack.index, ack.index)),
                                        "internal_handshake", weights["internal_handshake"],
                                        "Complete internal TCP three-way handshake"))
    for p in packets:
        if p.index in scan_ids:
            kind = "scan_syn"
        elif p.flow in features["alerted_flows"] and p.payload:
            kind = "alert_payload"
        elif p.protocol == "UDP" and 53 in (p.sport, p.dport):
            kind = "dns_packet"
        elif p.src and all(is_internal(a, config["internal_networks"]) for a in (p.src, p.dst)):
            kind = "internal_packet"
        elif p.syn or p.flags & 3:
            kind = "control_packet"
        else:
            kind = "background"
        priority[p.index] = kind
        result.append(Candidate(frozenset((p.index,)), kind, weights[kind],
                                "Packet feature category: " + kind))
    return result, priority
