"""Convert PCAPNG to classic PCAP, keeping every packet's bytes, lengths and timestamp.

    python final/pcapng_to_pcap.py input.pcapng output.pcap

EBR reads classic PCAP. Output uses the nanosecond variant so no timestamp
precision is lost. Captures that mix link types cannot be represented and are refused.
"""
from pathlib import Path
import struct
import sys

SECTION_HEADER, INTERFACE, SIMPLE_PACKET, ENHANCED_PACKET = 0x0A0D0D0A, 1, 3, 6
OPTION_END, OPTION_RESOLUTION = 0, 9
BYTE_ORDER_LITTLE = b'\x4d\x3c\x2b\x1a'
SNAPLEN = 262144


def resolution_of(options, endian):
    """Ticks per second for an interface; the format defaults to microseconds."""
    p = 0
    while p + 4 <= len(options):
        code, length = struct.unpack_from(endian + 'HH', options, p)
        if code == OPTION_END:
            break
        if code == OPTION_RESOLUTION and length >= 1:
            value = options[p + 4]
            return 2 ** (value & 0x7F) if value & 0x80 else 10 ** value
        p += 4 + length + (-length % 4)
    return 1_000_000


def convert(source, target):
    interfaces, endian, link, packets, written = [], '<', None, 0, 0
    record = struct.Struct('<IIII')
    with Path(source).open('rb', buffering=1 << 22) as stream, Path(target).open('wb', buffering=1 << 22) as out:
        read = stream.read
        while True:
            head = read(8)
            if len(head) < 8:
                break
            if struct.unpack('<I', head[:4])[0] == SECTION_HEADER:
                order = read(4)
                endian = '<' if order == BYTE_ORDER_LITTLE else '>'
                total = struct.unpack(endian + 'I', head[4:])[0]
                read(total - 12)
                interfaces = []
                continue
            kind, total = struct.unpack(endian + 'II', head)
            body = read(total - 12)
            if len(body) < total - 12 or len(read(4)) < 4:
                break  # a torn final block is the normal end of an interrupted capture
            if kind == INTERFACE:
                interface_link = struct.unpack_from(endian + 'H', body)[0]
                if link is None:
                    link = interface_link
                    out.write(struct.pack('<IHHIIII', 0xA1B23C4D, 2, 4, 0, 0, SNAPLEN, link))
                elif interface_link != link:
                    raise ValueError(f'Mixed link types {link} and {interface_link}')
                interfaces.append(resolution_of(body[8:], endian))
            elif kind == ENHANCED_PACKET:
                interface, high, low, captured, original = struct.unpack_from(endian + 'IIIII', body)
                ticks = (high << 32) | low
                rate = interfaces[interface]
                seconds, remainder = divmod(ticks, rate)
                out.write(record.pack(seconds, remainder * 1_000_000_000 // rate, captured, original))
                out.write(body[20:20 + captured])
                packets += 1
                written += 16 + captured
            elif kind == SIMPLE_PACKET:
                raise ValueError('Simple packet blocks have no timestamps and cannot be converted faithfully')
    return dict(packets=packets, record_bytes=written, link=link)


if __name__ == '__main__':
    print(convert(sys.argv[1], sys.argv[2]))
