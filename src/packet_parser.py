"""Classic PCAP IO. Keep original record bytes rather than rebuilding packets."""
from dataclasses import dataclass
from pathlib import Path
import socket
import struct

MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

@dataclass
class Packet:
    index: int
    timestamp_ns: int
    data: bytes
    record: bytes
    original_length: int
    src: str = ""
    dst: str = ""
    sport: int = 0
    dport: int = 0
    protocol: str = "OTHER"
    flags: int = 0
    seq: int = 0
    ack: int = 0
    payload: bytes = b""
    truncated: bool = False

    @property
    def cost(self):
        return len(self.record)

    @property
    def flow(self):
        a, b = sorted(((self.src, self.sport), (self.dst, self.dport)))
        return (self.protocol, a, b)

    @property
    def syn(self):
        return self.protocol == "TCP" and bool(self.flags & 2) and not self.flags & 16

@dataclass
class Capture:
    header: bytes
    packets: list
    size: int
    endian: str
    resolution: int

def decode_packet(p):
    data = p.data
    if len(data) < 14:
        return
    kind = struct.unpack("!H", data[12:14])[0]
    offset = 14
    while kind in (0x8100, 0x88A8) and len(data) >= offset + 4:
        kind = struct.unpack("!H", data[offset + 2:offset + 4])[0]
        offset += 4
    if kind != 0x0800 or len(data) < offset + 20:
        return
    ip = data[offset:]
    ihl = (ip[0] & 15) * 4
    total = struct.unpack("!H", ip[2:4])[0]
    if ip[0] >> 4 != 4 or ihl < 20 or total < ihl or len(ip) < ihl:
        return
    p.src, p.dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
    if struct.unpack("!H", ip[6:8])[0] & 0x3FFF:  # no fragmented transport decoding
        p.protocol = "FRAGMENT"
        return
    transport = ip[ihl:min(total, len(ip))]
    p.truncated = p.truncated or len(ip) < total
    if ip[9] == 6 and len(transport) >= 20:
        p.protocol = "TCP"
        p.sport, p.dport, p.seq, p.ack = struct.unpack("!HHII", transport[:12])
        tcp_length = (transport[12] >> 4) * 4
        p.flags = transport[13]
        if 20 <= tcp_length <= len(transport):
            p.payload = transport[tcp_length:]
    elif ip[9] == 17 and len(transport) >= 8:
        p.protocol = "UDP"
        p.sport, p.dport, udp_length = struct.unpack("!HHH", transport[:6])
        if 8 <= udp_length <= len(transport):
            p.payload = transport[8:udp_length]
        else:
            p.truncated = True
    elif ip[9] == 1:
        p.protocol = "ICMP"
    # Truncated application bytes cannot establish an intact transaction.
    if p.truncated:
        p.payload = b""

def read_pcap(path):
    path = Path(path)
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) < 24:
            raise ValueError("File is too short for a classic PCAP header.")
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            raise ValueError("PCAPNG is unsupported. Convert with editcap -F pcap.")
        if header[:4] not in MAGICS:
            raise ValueError("Invalid or unsupported PCAP magic.")
        endian, resolution = MAGICS[header[:4]]
        major, minor, _, _, snaplen, link = struct.unpack(endian + "HHIIII", header[4:])
        if (major, minor) != (2, 4) or not snaplen:
            raise ValueError("Only PCAP version 2.4 with a valid snaplen is supported.")
        if link != 1:
            raise ValueError("Only Ethernet link type 1 is supported.")
        packets = []
        while True:
            record_header = stream.read(16)
            if not record_header:
                break
            if len(record_header) != 16:
                raise ValueError("Truncated PCAP record header.")
            seconds, fraction, included, original = struct.unpack(endian + "IIII", record_header)
            if fraction >= resolution or included > snaplen or included > original:
                raise ValueError("Invalid timestamp or packet lengths in PCAP record.")
            data = stream.read(included)
            if len(data) != included:
                raise ValueError("Truncated PCAP packet data.")
            p = Packet(len(packets), seconds * 1_000_000_000 + fraction * (1_000_000_000 // resolution),
                       data, record_header + data, original, truncated=included < original)
            decode_packet(p)
            packets.append(p)
    return Capture(header, packets, path.stat().st_size, endian, resolution)

def write_subset(capture, indices, path, byte_cap):
    indices = sorted(set(indices))
    if any(i < 0 or i >= len(capture.packets) for i in indices):
        raise ValueError("Packet index outside input capture.")
    expected = 24 + sum(capture.packets[i].cost for i in indices)
    if expected > byte_cap:
        raise ValueError("Selection exceeds serialized PCAP byte cap.")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        stream.write(capture.header)
        for i in indices:
            stream.write(capture.packets[i].record)
    if path.stat().st_size != expected:
        raise RuntimeError("Serialized size does not match budget accounting.")
    return expected
