"""Independent classic-PCAP and protocol-field check using optional Scapy."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scapy.all import PcapReader, IP, TCP, UDP, DNS, Ether
import scapy
from src.packet_parser import read_pcap

input_path = ROOT / "data/generated/demo.pcap"
capture = read_pcap(input_path)
with PcapReader(str(input_path)) as reader:
    independent = list(reader)
assert len(independent) == 1413 == len(capture.packets)
tcp_count = udp_count = 0
for model, packet in zip(capture.packets, independent):
    assert bytes(packet) == model.data
    assert packet[IP].src == model.src and packet[IP].dst == model.dst
    assert abs(float(packet.time) - model.timestamp_ns/1e9) < 1e-6
    ip = packet[IP]
    if TCP in packet:
        tcp_count += 1
        transport = packet[TCP]
        assert (transport.sport, transport.dport, int(transport.flags), transport.seq, transport.ack) == (
            model.sport, model.dport, model.flags, model.seq, model.ack)
        assert ip.len - ip.ihl*4 - transport.dataofs*4 == len(model.payload)
    elif UDP in packet:
        udp_count += 1
        transport = packet[UDP]
        assert (transport.sport, transport.dport, transport.len-8) == (model.sport, model.dport, len(model.payload))
    rebuilt = packet.copy()
    del rebuilt[IP].chksum
    if TCP in rebuilt:
        del rebuilt[TCP].chksum
    elif UDP in rebuilt:
        del rebuilt[UDP].chksum
    recomputed = Ether(bytes(rebuilt))
    assert recomputed[IP].chksum == packet[IP].chksum
    if TCP in packet:
        assert recomputed[TCP].chksum == packet[TCP].chksum
    elif UDP in packet:
        assert recomputed[UDP].chksum == packet[UDP].chksum
assert sum(TCP in p and int(p[TCP].flags)==2 and p[TCP].dport in range(1000,1040) for p in independent) == 40
assert sum(TCP in p and bytes(p[TCP].payload).startswith(b"HTTP/1.1 401") for p in independent) == 12
assert sum(TCP in p and bytes(p[TCP].payload).startswith(b"HTTP/1.1 200") for p in independent) == 1
dns = [p for p in independent if DNS in p]
assert len(dns) == 2
assert dns[0][DNS].qd.qname == b"archive.example."
assert dns[1][DNS].an.rdata == "203.0.113.9"
manifest = json.loads((ROOT / "results/demo/manifest.json").read_text(encoding="utf-8"))
for info in manifest["subsets"].values():
    path = ROOT / info["path"]
    with PcapReader(str(path)) as reader:
        retained = list(reader)
    assert [bytes(p) for p in retained] == [bytes(independent[i]) for i in info["source_packet_indices"]]
    assert path.stat().st_size <= info["byte_cap"]
result = {"library": "Scapy", "version": scapy.__version__, "input_packets": len(independent),
          "tcp_packets": tcp_count, "udp_packets": udp_count, "verified_subsets": len(manifest["subsets"]),
          "checks": ["PCAP reading", "packet bytes", "timestamps", "IPv4/TCP/UDP fields",
                     "Scapy-recomputed IPv4/transport checksums", "40 scan SYNs", "12 HTTP 401s",
                     "one HTTP 200", "DNS query and A response", "all retained-subset raw bytes/caps"]}
(ROOT / "logs/scapy_verification.json").write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
print("SCAPY INDEPENDENT CHECK PASSED:", json.dumps(result))
