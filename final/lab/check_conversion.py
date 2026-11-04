"""Independently confirm a PCAPNG conversion with Scapy's readers, which share no code with EBR.

Compares every packet's bytes, wire length and timestamp, and records the outcome.
Prints only counts, so running it reveals nothing about a capture's content.
"""
from itertools import zip_longest
import json
from pathlib import Path
import sys

from scapy.all import RawPcapNgReader, RawPcapReader


def main(original, converted, record):
    compared, mismatches = 0, 0
    first, second = RawPcapNgReader(original), RawPcapReader(converted)
    missing = object()
    for left, right in zip_longest(first, second, fillvalue=missing):
        if left is missing or right is missing:
            raise SystemExit('Conversion check failed: packet counts differ')
        (data_a, meta_a), (data_b, meta_b) = left, right
        ticks = (meta_a.tshigh << 32) | meta_a.tslow
        nanoseconds = ticks * 1_000_000_000 // meta_a.tsresol
        compared += 1
        if data_a != data_b or meta_a.wirelen != meta_b.wirelen or nanoseconds != meta_b.sec * 1_000_000_000 + meta_b.usec:
            mismatches += 1
    result = dict(tool='scapy raw readers', packets_compared=compared, mismatches=mismatches,
                  original=Path(original).name, original_bytes=Path(original).stat().st_size,
                  converted=Path(converted).name, converted_bytes=Path(converted).stat().st_size)
    Path(record).write_text(json.dumps(result, indent=1), encoding='utf8')
    print(json.dumps(result))
    if mismatches:
        raise SystemExit('Conversion check failed: packet contents differ')


if __name__ == '__main__':
    main(*sys.argv[1:4])
