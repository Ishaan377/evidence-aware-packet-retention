"""Generate synthetic packet records locally. This script never sends traffic."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import socket
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.packet_parser import read_pcap

BASE_NS = 1767225600 * 1_000_000_000  # 2026-01-01 UTC, artificial trace clock

def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def frame(src, dst, protocol, transport, packet_id):
    a, b = socket.inet_aton(src), socket.inet_aton(dst)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), packet_id % 65536,
                     0x4000, 64, protocol, 0, a, b)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    ethernet = bytes.fromhex("0200000000020200000000010800")
    return (ethernet + ip + transport).ljust(60, b"\0")

def tcp(src, dst, sport, dport, flags, seq, ack=0, payload=b"", packet_id=0):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 64240, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(header) + len(payload))
    header = header[:16] + struct.pack("!H", checksum(pseudo + header + payload)) + header[18:]
    return frame(src, dst, 6, header + payload, packet_id)

def udp(src, dst, sport, dport, payload, packet_id=0):
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, 8 + len(payload))
    value = checksum(pseudo + header + payload) or 0xFFFF
    return frame(src, dst, 17, header[:6] + struct.pack("!H", value) + payload, packet_id)

def name_bytes(name):
    return b"".join(bytes((len(x),)) + x.encode("ascii") for x in name.split(".")) + b"\0"

def generate(output, seed=2026, background_packets=800, scan_count=40, failures=12):
    if background_packets < 0 or not 10 <= scan_count <= 200 or not 3 <= failures <= 30:
        raise ValueError("Use nonnegative background, 10–200 scan probes, and 3–30 failures.")
    rng, records = random.Random(seed), []
    def add(seconds, data, event):
        timestamp = BASE_NS + int(round(seconds * 1_000_000)) * 1000
        records.append((timestamp, data, event))
    def handshake(t, src, dst, sport, dport, seq, server_seq, event):
        add(t, tcp(src, dst, sport, dport, 2, seq), event)
        add(t + .001, tcp(dst, src, dport, sport, 0x12, server_seq, seq + 1), event)
        add(t + .002, tcp(src, dst, sport, dport, 0x10, seq + 1, server_seq + 1), event)

    for i in range(background_packets):
        payload = rng.randbytes(rng.randint(400, 900))
        add(rng.uniform(0, 90), udp("10.0.0." + str(30 + i % 10), "198.51.100.20",
                                  30000 + i % 1000, 9001, payload, i), "background")
    scan_src, target = "192.0.2.10", "10.0.0.10"
    ports = list(range(1000, 1000 + scan_count))
    scan_start = 10.1
    for i, port in enumerate(ports):
        add(scan_start + i * .02, tcp(scan_src, target, 40000 + i, port, 2, 10000 + i), "scan")
    for i in range(failures + 1):
        t, sport, seq, server_seq = 20 + i * .6, 41000 + i, 20000 + i * 1000, 60000 + i * 1000
        handshake(t, scan_src, target, sport, 80, seq, server_seq, "http")
        body = b"user=student&token=synthetic-demo"
        request = (b"POST /login HTTP/1.1\r\nHost: lab.example\r\nContent-Length: "
                   + str(len(body)).encode() + b"\r\n\r\n" + body)
        status = b"401 Unauthorized" if i < failures else b"200 OK"
        response = b"HTTP/1.1 " + status + b"\r\nContent-Length: 0\r\n\r\n"
        add(t + .01, tcp(scan_src, target, sport, 80, 0x18, seq + 1, server_seq + 1, request), "http")
        add(t + .02, tcp(target, scan_src, 80, sport, 0x18, server_seq + 1,
                         seq + 1 + len(request), response), "http")
    handshake(45, "10.0.0.10", "10.0.0.20", 43000, 445, 50000, 80000, "internal")
    domain, address, transaction_id = "archive.example", "203.0.113.9", 4242
    question = name_bytes(domain) + struct.pack("!HH", 1, 1)
    query = struct.pack("!6H", transaction_id, 0x0100, 1, 0, 0, 0) + question
    response = (struct.pack("!6H", transaction_id, 0x8180, 1, 1, 0, 0) + question
                + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address))
    add(50, udp(target, "10.0.0.53", 44000, 53, query), "dns")
    add(50.005, udp("10.0.0.53", target, 53, 44000, response), "dns")
    handshake(60, "10.0.0.20", address, 45000, 9000, 90000, 100000, "bulk")
    bulk_bytes = 0
    for i in range(250):
        payload = rng.randbytes(1200)
        add(60.01 + i * .025, tcp("10.0.0.20", address, 45000, 9000, 0x18,
                                90001 + bulk_bytes, 100001, payload), "bulk")
        bulk_bytes += len(payload)
        add(60.012 + i * .025, tcp(address, "10.0.0.20", 9000, 45000, 0x10,
                                 100001, 90001 + bulk_bytes), "bulk")
    records.sort(key=lambda r: r[0])
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, data, _ in records:
            stream.write(struct.pack("<IIII", timestamp // 1_000_000_000,
                                     (timestamp % 1_000_000_000) // 1000, len(data), len(data)))
            stream.write(data)
    scan_times = [timestamp for timestamp, _, event in records if event == "scan"]
    truth = {
        "dataset_kind": "SYNTHETIC_FILE_ONLY", "generator_seed": seed,
        "description": "Fabricated protocol observations, not a captured attack or real incident.",
        "scan": {"src": scan_src, "dst": target, "ports": ports, "count": scan_count,
                 "interval_ns": [min(scan_times), max(scan_times)]},
        "http": {"src": scan_src, "dst": target, "failures_generated": failures},
        "internal": {"src": target, "dst": "10.0.0.20", "port": 445},
        "dns": {"name": domain, "address": address},
        "bulk": {"src": "10.0.0.20", "dst": address, "sport": 45000, "dport": 9000,
                 "unique_payload_bytes_generated": bulk_bytes, "minimum_bytes": 65536},
        "packet_count": len(records), "event_packet_counts": dict(Counter(r[2] for r in records)),
        "event_packet_indices": {event: [i for i, r in enumerate(records) if r[2] == event]
                                 for event in sorted({r[2] for r in records})},
        "pcap_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "parameters": {"background_packets": background_packets, "scan_count": scan_count, "failures": failures},
    }
    truth_path = output.with_suffix(".truth.json")
    truth_path.write_text(json.dumps(truth, indent=2) + "\n", encoding="utf-8")
    # IO integrity check; ground truth itself comes from generator records.
    parsed = read_pcap(output)
    assert len(parsed.packets) == truth["packet_count"]
    return truth

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "data/generated/demo.pcap")
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--background-packets", type=int, default=800)
    parser.add_argument("--scan-count", type=int, default=40)
    parser.add_argument("--failures", type=int, default=12)
    args = parser.parse_args()
    try:
        truth = generate(args.output, args.seed, args.background_packets, args.scan_count, args.failures)
    except (ValueError, OSError) as error:
        parser.exit(2, "Generation failed: " + str(error) + "\n")
    print("SYNTHETIC ONLY:", args.output)
    print("Packets:", truth["packet_count"], "Bytes:", args.output.stat().st_size)
    print("Ground truth:", args.output.with_suffix(".truth.json"))
    print("No packets were transmitted.")

if __name__ == "__main__":
    main()
