"""Fetch the forensic-test captures listed in forensic_cases.json.

CIC members are pulled out of each day's 40+ GB pcap.zip with HTTP range
requests, so only the listed captures are transferred. WRCCDC files are gzip
downloads. Every result records its SHA-256 in a per-case provenance file.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import zlib

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from ebr.pcapstream import iter_records  # noqa: E402
from pcapng_to_pcap import convert  # noqa: E402

CHUNK = 1 << 20
RETRIES = 6


def get_range(url, start, end):
    request = urllib.request.Request(url, headers={'Range': f'bytes={start}-{end}'})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def zip_index(url):
    """Map member name to (method, compressed, uncompressed, crc, local offset)."""
    head = urllib.request.Request(url, method='HEAD')
    with urllib.request.urlopen(head, timeout=120) as response:
        size = int(response.headers['Content-Length'])
    tail = get_range(url, max(0, size - 70000), size - 1)
    end = tail.rfind(b'PK\x05\x06')
    if end < 0:
        raise ValueError('ZIP end record not found')
    _, directory_size, directory_offset = struct.unpack('<HII', tail[end + 10:end + 20])
    locator = tail.rfind(b'PK\x06\x07')
    if locator >= 0:
        offset = struct.unpack('<Q', tail[locator + 8:locator + 16])[0]
        record = get_range(url, offset, offset + 55)
        _, _, directory_size, directory_offset = struct.unpack('<QQQQ', record[24:56])
    directory = get_range(url, directory_offset, directory_offset + directory_size - 1)
    members, p = {}, 0
    while p + 46 <= len(directory) and directory[p:p + 4] == b'PK\x01\x02':
        method = struct.unpack('<H', directory[p + 10:p + 12])[0]
        crc, compressed, uncompressed = struct.unpack('<III', directory[p + 16:p + 28])
        name_length, extra_length, comment_length = struct.unpack('<HHH', directory[p + 28:p + 34])
        local = struct.unpack('<I', directory[p + 42:p + 46])[0]
        name = directory[p + 46:p + 46 + name_length].decode('utf8', 'replace')
        extra = directory[p + 46 + name_length:p + 46 + name_length + extra_length]
        q = 0
        while q + 4 <= len(extra):
            tag, length = struct.unpack('<HH', extra[q:q + 4])
            if tag == 1:
                data, r = extra[q + 4:q + 4 + length], 0
                if uncompressed == 0xFFFFFFFF:
                    uncompressed = struct.unpack('<Q', data[r:r + 8])[0]
                    r += 8
                if compressed == 0xFFFFFFFF:
                    compressed = struct.unpack('<Q', data[r:r + 8])[0]
                    r += 8
                if local == 0xFFFFFFFF:
                    local = struct.unpack('<Q', data[r:r + 8])[0]
            q += 4 + length
        members[name] = (method, compressed, uncompressed, crc, local)
        p += 46 + name_length + extra_length + comment_length
    return members


def fetch_member(url, member, info, target):
    method, compressed, uncompressed, crc_expected, local = info
    if method != 8:
        raise ValueError(f'{member}: unsupported ZIP method {method}')
    local_header = get_range(url, local, local + 29)
    name_length, extra_length = struct.unpack('<HH', local_header[26:30])
    start = local + 30 + name_length + extra_length
    partial = target.with_suffix(target.suffix + '.part')
    for attempt in range(RETRIES):
        try:
            inflater, crc, written = zlib.decompressobj(-15), 0, 0
            request = urllib.request.Request(url, headers={'Range': f'bytes={start}-{start + compressed - 1}'})
            with urllib.request.urlopen(request, timeout=180) as response, partial.open('wb') as out:
                while True:
                    block = response.read(CHUNK)
                    if not block:
                        break
                    data = inflater.decompress(block)
                    crc = zlib.crc32(data, crc)
                    written += len(data)
                    out.write(data)
                data = inflater.flush()
                crc = zlib.crc32(data, crc)
                written += len(data)
                out.write(data)
            if written != uncompressed or crc != crc_expected:
                raise ValueError(f'{member}: size/CRC mismatch {written} != {uncompressed}')
            partial.replace(target)
            return
        except (OSError, ValueError, zlib.error) as error:
            print(f'retry {attempt + 1} {target.name}: {error}', flush=True)
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f'Could not fetch {member}')


def fetch_gzip(url, target):
    download = target.with_suffix(target.suffix + '.gz.part')
    for attempt in range(RETRIES):
        result = subprocess.run(['curl.exe', '-sS', '-L', '--fail', '-C', '-', '-o', str(download), url])
        if result.returncode == 0:
            break
        print(f'retry {attempt + 1} {target.name}: curl exit {result.returncode}', flush=True)
        time.sleep(5 * (attempt + 1))
    else:
        raise RuntimeError(f'Could not fetch {url}')
    partial = target.with_suffix(target.suffix + '.part')
    with gzip.open(download, 'rb') as source, partial.open('wb') as out:
        shutil.copyfileobj(source, out, CHUNK)
    partial.replace(target)
    download.unlink()


def fetch_direct(url, target, limit=None):
    """Download a capture, or only its first `limit` bytes, which is a fixed-size slice by rule."""
    partial = target.with_suffix(target.suffix + '.part')
    window = ['-r', f'0-{limit - 1}'] if limit else ['-C', '-']
    for attempt in range(RETRIES):
        if subprocess.run(['curl.exe', '-sS', '-L', '--fail', *window, '-o', str(partial), url]).returncode == 0:
            partial.replace(target)
            return
        time.sleep(5 * (attempt + 1))
    raise RuntimeError(f'Could not fetch {url}')


def trim_torn_tail(target):
    """Cut a byte-limited slice back to its last complete packet record."""
    end = 24
    for offset, _, size, _ in iter_records(target):
        end = offset + size
    with target.open('r+b') as stream:
        stream.truncate(end)


def normalise_format(target):
    """Convert PCAPNG to classic PCAP. Reads the format marker only, not the traffic."""
    with target.open('rb') as stream:
        if stream.read(4) != b'\x0a\x0d\x0d\x0a':
            return False
    converted = target.with_suffix(target.suffix + '.converted')
    convert(target, converted)
    converted.replace(target)
    return True


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(CHUNK), b''):
            digest.update(block)
    return digest.hexdigest()


def safe_name(member):
    return re.sub(r'[^A-Za-z0-9._-]+', '_', member.split('/')[-1].strip())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--split', choices=('dev', 'test', 'sealed2', 'sealed3', 'all'), default='all')
    parser.add_argument('--case', action='append', dest='cases', help='Fetch one named case; repeat for multiple cases')
    parser.add_argument('--workers', type=int, default=6)
    args = parser.parse_args()
    catalogue = json.loads((ROOT / 'forensic_cases.json').read_text(encoding='utf8'))
    unknown = set(args.cases or ()) - set(catalogue['cases'])
    if unknown:
        parser.error('unknown case: ' + ', '.join(sorted(unknown)))
    data_root = ROOT / 'data' / 'forensic'
    indexes, jobs, limits = {}, [], {}
    for case, spec in catalogue['cases'].items():
        if args.cases and case not in args.cases:
            continue
        if args.split not in ('all', spec['split']):
            continue
        folder = data_root / case
        folder.mkdir(parents=True, exist_ok=True)
        if spec['source'] == 'cic':
            url = urllib.parse.quote(catalogue['cic_base'] + spec['day'] + '/pcap.zip', safe=':/')
            indexes.setdefault(url, zip_index(url))
            for member in spec['members']:
                target = folder / (safe_name(member) + '.pcap').replace('.pcap.pcap', '.pcap')
                jobs.append((case, target, url, member))
        elif spec['source'] == 'direct':
            for url in spec['urls']:
                jobs.append((case, folder / url.rsplit('/', 1)[1], url, None))
                limits[url] = spec.get('max_bytes')
        elif spec['source'] == 'wrccdc':
            for name in spec['files']:
                target = folder / name.replace('.gz', '')
                jobs.append((case, target, catalogue['wrccdc_base'] + spec['year'] + '/' + name, None))

    def run(job):
        case, target, url, member = job
        if target.exists():
            return job
        began = time.time()
        if member:
            fetch_member(url, member, indexes[url][member], target)
        elif url.endswith('.gz'):
            fetch_gzip(url, target)
        else:
            fetch_direct(url, target, limits.get(url))
        if normalise_format(target):
            converted_files.add(target.name)
        elif limits.get(url):
            trim_torn_tail(target)
        print(f'done {case}/{target.name} {target.stat().st_size / 1e6:.1f} MB in {time.time() - began:.0f}s', flush=True)
        return job

    converted_files = set()
    with ThreadPoolExecutor(args.workers) as pool:
        for future in as_completed([pool.submit(run, job) for job in jobs]):
            future.result()
    provenance = {}
    for case, target, url, member in jobs:
        provenance.setdefault(case, []).append(dict(file=target.name, url=url, member=member, bytes=target.stat().st_size, sha256=sha256(target),
                                                    converted_from_pcapng=target.name in converted_files))
    for case, files in provenance.items():
        (data_root / case / 'provenance.json').write_text(json.dumps(files, indent=1), encoding='utf8')
    print('ALL COMPLETE', sum(f['bytes'] for files in provenance.values() for f in files) / 1e9, 'GB', flush=True)


if __name__ == '__main__':
    main()
