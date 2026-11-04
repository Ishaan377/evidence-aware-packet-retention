"""Classic PCAP streaming and fast header decoding. Records are never rewritten."""
import mmap
from pathlib import Path
import struct

MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1_000),
    b'\xa1\xb2\xc3\xd4': ('>', 1_000),
    b'\x4d\x3c\xb2\xa1': ('<', 1),
    b'\xa1\xb2\x3c\x4d': ('>', 1),
}
LINK_ETHERNET, LINK_RAW, LINK_SLL, LINK_SLL2 = 1, 101, 113, 276
SUPPORTED_LINKS = (LINK_ETHERNET, LINK_RAW, LINK_SLL, LINK_SLL2)
FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16
TCP, UDP, ICMP = 6, 17, 1
HEADER_BYTES, RECORD_BYTES = 24, 16

_tcp = struct.Struct('!HHIIBB')
_udp = struct.Struct('!HHH')
_short = struct.Struct('!H')


def read_header(path):
    with Path(path).open('rb') as stream:
        header = stream.read(HEADER_BYTES)
    if len(header) < HEADER_BYTES or header[:4] not in MAGICS:
        raise ValueError(f'{path}: not a classic PCAP file')
    endian, scale = MAGICS[header[:4]]
    link = struct.unpack(endian + 'I', header[20:24])[0]
    if link not in SUPPORTED_LINKS:
        raise ValueError(f'{path}: unsupported link type {link}')
    return header, endian, scale, link


def iter_records(path):
    """Yield (offset, ts_ns, record_bytes, packet_bytes); a torn final record ends the stream."""
    _, endian, scale, _ = read_header(path)
    unpack = struct.Struct(endian + 'IIII').unpack
    offset = HEADER_BYTES
    with Path(path).open('rb', buffering=1 << 22) as stream:
        stream.seek(HEADER_BYTES)
        read = stream.read
        while True:
            head = read(RECORD_BYTES)
            if len(head) < RECORD_BYTES:
                return
            seconds, fraction, included, _ = unpack(head)
            data = read(included)
            if len(data) < included:
                return
            size = RECORD_BYTES + included
            yield offset, seconds * 1_000_000_000 + fraction * scale, size, data
            offset += size


def decode(data, link):
    """Return (src, dst, proto, sport, dport, flags, seq, payload_offset, payload_length) or None."""
    length = len(data)
    if link == LINK_ETHERNET:
        if length < 14:
            return None
        offset, kind = 14, (data[12] << 8) | data[13]
        while kind in (0x8100, 0x88A8) and length >= offset + 4:
            kind = (data[offset + 2] << 8) | data[offset + 3]
            offset += 4
    elif link == LINK_SLL:
        if length < 16:
            return None
        offset, kind = 16, (data[14] << 8) | data[15]
    elif link == LINK_SLL2:
        if length < 20:
            return None
        offset, kind = 20, (data[0] << 8) | data[1]
    else:
        if length < 1:
            return None
        offset, kind = 0, 0x0800 if data[0] >> 4 == 4 else 0x86DD
    if kind == 0x0800:
        if length < offset + 20 or data[offset] >> 4 != 4:
            return None
        ihl = (data[offset] & 15) * 4
        if ihl < 20:
            return None
        total = (data[offset + 2] << 8) | data[offset + 3]
        proto = data[offset + 9]
        src, dst = data[offset + 12:offset + 16], data[offset + 16:offset + 20]
        end = min(length, offset + total) if total else length
        if ((data[offset + 6] & 0x3F) << 8 | data[offset + 7]) != 0:
            return src, dst, 0, 0, 0, 0, 0, 0, 0  # non-initial or fragmented datagrams carry no ports
        transport = offset + ihl
    elif kind == 0x86DD:
        if length < offset + 40:
            return None
        proto = data[offset + 6]
        src, dst = data[offset + 8:offset + 24], data[offset + 24:offset + 40]
        end = min(length, offset + 40 + ((data[offset + 4] << 8) | data[offset + 5]))
        transport = offset + 40
    else:
        return None
    if proto == TCP:
        if end < transport + 20:
            return src, dst, 0, 0, 0, 0, 0, 0, 0
        sport, dport, seq, _, offset_byte, flags = _tcp.unpack_from(data, transport)
        start = transport + (offset_byte >> 4) * 4
        if start > end:
            return src, dst, 0, 0, 0, 0, 0, 0, 0
        return src, dst, TCP, sport, dport, flags, seq, start, end - start
    if proto == UDP:
        if end < transport + 8:
            return src, dst, 0, 0, 0, 0, 0, 0, 0
        sport, dport, _ = _udp.unpack_from(data, transport)
        return src, dst, UDP, sport, dport, 0, 0, transport + 8, end - transport - 8
    if proto in (ICMP, 58):
        return src, dst, ICMP, 0, 0, 0, 0, transport, max(0, end - transport)
    return src, dst, 0, 0, 0, 0, 0, transport, max(0, end - transport)


def write_subset(source, indices, offsets, sizes, target):
    """Copy selected original records byte for byte, in original order."""
    header, *_ = read_header(source)
    written = len(header)
    Path(target).parent.mkdir(parents=True, exist_ok=True)
    with Path(source).open('rb') as stream, Path(target).open('wb', buffering=1 << 22) as out:
        out.write(header)
        write = out.write
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as view:
            for i in indices:
                begin = offsets[i]
                write(view[begin:begin + sizes[i]])
                written += sizes[i]
    return written
