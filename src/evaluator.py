"""Compute answers ONLY from retained packets, then compare to reference truth."""
from src.feature_extraction import extract

QUESTIONS = [
    ("Q1", "Preserve scan source and target with at least four distinct probed ports"),
    ("Q2", "Preserve the exact observed number of scan SYN attempts"),
    ("Q3", "Preserve both observed scan interval endpoints"),
    ("Q4", "Preserve at least three matched login requests and HTTP 401 responses"),
    ("Q5", "Preserve a matched login request and HTTP 200 response"),
    ("Q6", "Preserve the internal TCP three-way handshake"),
    ("Q7", "Preserve the queried domain and its returned IPv4 address"),
    ("Q8", "Demonstrate at least 65536 unique outbound TCP payload bytes on the nominated flow"),
]

def unique_payload_bytes(packets):
    """Union non-overlapping sequence intervals; retransmissions do not add bytes.

    Sequence wrap across 2**32 is outside this MVP's supported evaluator scope.
    """
    intervals = sorted((p.seq, p.seq + len(p.payload)) for p in packets if p.payload)
    total, end = 0, -1
    for start, stop in intervals:
        total += max(0, stop - max(start, end))
        end = max(end, stop)
    return total

def answer(packets, truth, config):
    features = extract(packets, config)
    scan = [p for p in packets if p.syn and p.src == truth["scan"]["src"]
            and p.dst == truth["scan"]["dst"] and p.dport in truth["scan"]["ports"]]
    scan.sort(key=lambda p: (p.timestamp_ns, p.index))
    # This query target identifies what is being investigated. Expected answers
    # and event labels are never provided to the selection strategy.
    identity = [[p.src, p.dst] for p in scan[:1]]
    count = len({(p.sport, p.dport, p.seq) for p in scan})
    interval = [scan[0].timestamp_ns, scan[-1].timestamp_ns] if scan else []
    transactions = [(q, r, s) for q, r, s in features["http"]
                    if q.src == truth["http"]["src"] and q.dst == truth["http"]["dst"]]
    failed = [(q, r) for q, r, s in transactions if s == 401]
    success = [(q, r) for q, r, s in transactions if s == 200]
    handshakes = [h for h in features["handshakes"] if h[0].src == truth["internal"]["src"]
                  and h[0].dst == truth["internal"]["dst"] and h[0].dport == truth["internal"]["port"]]
    dns = [(q, r, n, a) for q, r, n, a in features["dns"] if n == truth["dns"]["name"]
           and truth["dns"]["address"] in a]
    transfer = [p for p in packets if p.protocol == "TCP" and p.src == truth["bulk"]["src"]
                and p.dst == truth["bulk"]["dst"] and p.sport == truth["bulk"]["sport"]
                and p.dport == truth["bulk"]["dport"]]
    volume = unique_payload_bytes(transfer)
    criteria = [
        bool(identity) and len({p.dport for p in scan}) >= 4,
        count == truth["scan"]["count"],
        interval == truth["scan"]["interval_ns"],
        len({(q.flow, q.seq) for q, _ in failed}) >= 3,
        bool(success),
        bool(handshakes),
        bool(dns),
        volume >= truth["bulk"]["minimum_bytes"],
    ]
    observations = [identity, count, interval, len(failed), len(success), len(handshakes),
                    [{"name": n, "answers": a} for _, _, n, a in dns], volume]
    witnesses = [
        [p.index for p in scan], [p.index for p in scan], [p.index for p in scan[:1] + scan[-1:]],
        [p.index for pair in failed for p in pair], [p.index for pair in success for p in pair],
        [p.index for h in handshakes for p in h], [p.index for q, r, _, _ in dns for p in (q, r)],
        [p.index for p in transfer if p.payload],
    ]
    rows = [{"question": qid, "description": text, "answerable": bool(ok),
             "observed": obs, "retained_packet_indices": sorted(set(ids))}
            for (qid, text), ok, obs, ids in zip(QUESTIONS, criteria, observations, witnesses)]
    return {"coverage": sum(criteria) / len(criteria), "answered": sum(criteria),
            "questions": rows, "observed_unique_bulk_bytes": volume}
