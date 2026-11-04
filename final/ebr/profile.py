"""First pass: stream the capture into flows, packet tiers and protocol fingerprints.

Each packet receives a fidelity tier from what it is, not from who sent it:

    0  skeleton   connection control, first and last packet of the flow
    1  head       the first bytes of each direction, where requests and banners live
    2  deep head  a longer contiguous prefix
    3  turn heads the start of every later message turn in a long-lived session
    4  bulk       everything else

Position comes from TCP sequence numbers, so retransmissions and reordering land
in the same tier as the bytes they carry. Pure ACKs follow the data they
acknowledge, which keeps retained streams inspectable by a reassembling IDS.
"""
from array import array
from dataclasses import dataclass
import hashlib
import re

from .pcapstream import ACK, FIN, RST, SYN, TCP, UDP, decode, iter_records, read_header

TIERS = 5
CLIENT_HEAD, SERVER_HEAD = 768, 256
WORDS = re.compile(r'[A-Za-z0-9_]+')


class Flow:
    __slots__ = ('id', 'proto', 'client', 'server', 'cport', 'sport', 'first_ns', 'last_ns', 'starts',
                 'packets', 'payload', 'cost', 'syn_seq', 'origin', 'position', 'data_seen', 'turn_side',
                 'turn_bytes', 'turns', 'gap_max', 'saw_synack', 'saw_fin', 'saw_rst', 'head', 'last_index',
                 'app', 'client_fp', 'server_fp', 'content', 'plain', 'state')

    def __init__(self, fid, proto, client, server, cport, sport, now):
        self.id, self.proto, self.client, self.server = fid, proto, client, server
        self.cport, self.sport, self.first_ns, self.last_ns = cport, sport, now, now
        self.packets, self.payload, self.cost = [0, 0], [0, 0], [0] * TIERS
        self.syn_seq, self.origin, self.position = None, [None, None], [0, 0]
        self.data_seen, self.turn_side, self.turn_bytes, self.turns = False, -1, 0, 0
        self.gap_max, self.saw_synack, self.saw_fin, self.saw_rst = 0, False, False, False
        self.head, self.last_index = [bytearray(), bytearray()], 0
        self.app, self.client_fp, self.server_fp, self.content = 'none', '', '', ''
        self.plain, self.state, self.starts = True, 'OTH', None


@dataclass
class Profile:
    paths: list
    flows: list
    flow_of: array
    tier: bytearray
    sizes: array
    offsets: array
    position: array
    file_starts: list
    input_bytes: int
    headers: int
    seconds: float = 0.0

    @property
    def packets(self):
        return len(self.tier)


def tier_of(position, turn_bytes, config):
    if position < config['head_bytes']:
        return 1
    if position < config['deep_head_bytes']:
        return 2
    if turn_bytes < config['turn_head_bytes']:
        return 3
    return 4


def ja3_like(data):
    """Hash a TLS ClientHello's cipher and extension lists, the client's implicit fingerprint."""
    try:
        if len(data) < 44 or data[0] != 0x16 or data[5] != 1:
            return ''
        p = 43
        p += 1 + data[p]
        cipher_length = (data[p] << 8) | data[p + 1]
        ciphers = data[p + 2:p + 2 + cipher_length]
        p += 2 + cipher_length
        p += 1 + data[p]
        total = (data[p] << 8) | data[p + 1]
        p += 2
        stop, types = min(len(data), p + total), []
        while p + 4 <= stop:
            types.append((data[p] << 8) | data[p + 1])
            p += 4 + ((data[p + 2] << 8) | data[p + 3])
        return hashlib.md5(bytes(ciphers) + repr(types).encode()).hexdigest()[:10]
    except IndexError:
        return ''


def dns_query_name(message):
    """Read the first question's name from a DNS message, or '' if it is not one."""
    labels, p = [], 12
    try:
        while True:
            length = message[p]
            if length == 0:
                return '.'.join(labels).lower()
            if length > 63 or len(labels) > 32:
                return ''
            labels.append(message[p + 1:p + 1 + length].decode('ascii'))
            p += 1 + length
    except (IndexError, UnicodeDecodeError):
        return ''


def identify(flow):
    """Name the application and summarise the client and server without any signatures."""
    client, server = bytes(flow.head[0]), bytes(flow.head[1])
    sample = client or server
    if not sample:
        return
    readable = sum(1 for b in sample[:256] if 32 <= b < 127 or b in (9, 10, 13)) / min(len(sample), 256)
    spread = len(set(sample[:256])) / min(len(sample), 256)
    flow.plain = readable > 0.7
    word = client[:8]
    if word[:4] in (b'GET ', b'POST', b'HEAD', b'PUT ') or word[:7] in (b'OPTIONS', b'CONNECT') or word[:6] == b'DELETE':
        flow.app = 'http'
        lines = client.split(b'\r\n')
        first = lines[0].split(b' ')
        names, agent = [], b''
        for line in lines[1:]:
            if b':' in line:
                name, _, value = line.partition(b':')
                names.append(name.strip().lower())
                if name.strip().lower() == b'user-agent':
                    agent = bytes(c if not 48 <= c <= 57 else 35 for c in value.strip().lower())[:48]
        order = hashlib.md5(b','.join(names)).hexdigest()[:6]
        flow.client_fp = f'http|{first[0].decode("latin1")}|{agent.decode("latin1")}|{order}'
        # The URL's punctuation is its structure: payloads differ here while values do not.
        target = first[1].decode('latin1')[:120] if len(first) > 1 else ''
        flow.content = first[0].decode('latin1') + ' ' + WORDS.sub('a', target)
    elif client[:1] == b'\x16' and client[1:2] == b'\x03':
        flow.app, flow.plain = 'tls', False
        flow.client_fp = 'tls|' + ja3_like(client)
    elif client[:4] == b'SSH-' or server[:4] == b'SSH-':
        flow.app, flow.plain = 'ssh', False
        flow.client_fp = 'ssh|' + client.split(b'\r\n')[0][:40].decode('latin1')
    elif server[:4] in (b'220 ', b'220-') or client[:5] in (b'USER ', b'EHLO ', b'HELO '):
        flow.app = 'ftp_smtp'
        flow.client_fp = 'cmd|' + client[:4].decode('latin1')
    elif client[:4] in (b'NICK', b'PASS', b'JOIN') or b'PRIVMSG' in client[:64]:
        flow.app = 'irc'
        flow.client_fp = 'irc'
    elif client[4:8] in (b'\xffSMB', b'\xfeSMB'):
        flow.app, flow.plain = 'smb', False
        flow.client_fp = 'smb|' + client[4:5].hex()
    elif flow.proto == UDP and 53 in (flow.sport, flow.cport):
        flow.app = 'dns'
        name = dns_query_name(client or server)
        parts = name.split('.')
        flow.client_fp = 'dns|' + parts[-1]
        flow.content = '.'.join(parts[-2:])
        if len(server) > 3 and server[3] & 15 == 3:
            flow.server_fp = 'nxdomain'
    elif client[:2] == b'\x03\x00':
        flow.app, flow.plain = 'rdp', False
        flow.client_fp = 'rdp'
    elif flow.plain:
        flow.app = 'text'
        flow.client_fp = 'text|' + ''.join(chr(c) if 65 <= c <= 90 else ('a' if 97 <= c <= 122 else '.') for c in client[:6])
    else:
        flow.app = 'binary'
        flow.plain = spread < 0.42
        flow.client_fp = 'bin|' + client[:2].hex() + f'|{min(len(client), 512) // 64}'
    if server and not flow.server_fp:
        flow.server_fp = server[:12].decode('latin1').split('\r')[0]
    flow.content = flow.content or flow.client_fp


def finish(flow):
    identify(flow)
    if flow.proto == TCP:
        answered = flow.saw_synack or flow.packets[1] > 0
        if flow.saw_rst and not flow.data_seen:
            flow.state = 'REJ' if flow.saw_synack or flow.packets[1] else 'RSTO'
        elif not answered:
            flow.state = 'S0'
        elif flow.saw_rst:
            flow.state = 'RST'
        elif flow.saw_fin:
            flow.state = 'SF'
        else:
            flow.state = 'OPEN'
    else:
        flow.state = 'UNI' if not flow.packets[1] else 'NX' if flow.server_fp == 'nxdomain' else 'BI'
    flow.head = None


def build_profile(paths, config):
    """Stream `paths` once. Output arrays are parallel across every record in file order."""
    flows, table = [], {}
    flow_of, tiers, sizes, offsets, positions = array('I'), bytearray(), array('I'), array('Q'), array('I')
    file_starts, input_bytes, headers = [], 0, 0
    tcp_idle = int(config['tcp_idle_seconds'] * 1e9)
    udp_idle = int(config['udp_idle_seconds'] * 1e9)
    head_keep = (CLIENT_HEAD, SERVER_HEAD)
    udp_tier = config['udp_tier_packets']
    add_flow, add_tier, add_size, add_offset, add_position = flow_of.append, tiers.append, sizes.append, offsets.append, positions.append
    for path in paths:
        link = read_header(path)[3]
        file_starts.append(len(tiers))
        headers += 1
        input_bytes += 24
        for offset, now, size, data in iter_records(path):
            index = len(tiers)
            input_bytes += size
            decoded = decode(data, link)
            if decoded is None:
                # Non-IP traffic is one flow per frame type and source MAC.
                src, dst, proto = data[6:12], data[0:6], 255
                sport, dport, flags, seq, start, length = 0, (data[12] << 8 | data[13]) if len(data) > 13 else 0, 0, 0, 0, 0
            else:
                src, dst, proto, sport, dport, flags, seq, start, length = decoded
            key = (src, sport, dst, dport, proto)
            found = table.get(key)
            if found is not None:
                flow, side = found
                idle = now - flow.last_ns > (tcp_idle if proto == TCP else udp_idle)
                restart = proto == TCP and flags & SYN and not flags & ACK and flow.syn_seq is not None and seq != flow.syn_seq
                if idle or restart:
                    finish(flow)
                    found = None
            if found is None:
                # A SYN-ACK seen first still names the real client.
                flip = proto == TCP and flags & SYN and flags & ACK
                if not flip and proto == TCP and not flags & SYN and sport < dport and sport < 1024:
                    flip = True
                if flip:
                    flow = Flow(len(flows), proto, dst, src, dport, sport, now)
                    side = 1
                else:
                    flow = Flow(len(flows), proto, src, dst, sport, dport, now)
                    side = 0
                flows.append(flow)
                table[key] = (flow, side)
                table[(dst, dport, src, sport, proto)] = (flow, 1 - side)
            first_packet = flow.packets[0] + flow.packets[1] == 0
            flow.packets[side] += 1
            gap = now - flow.last_ns
            if gap > flow.gap_max:
                flow.gap_max = gap
            flow.last_ns = now
            flow.last_index = index
            position = 0
            if proto == TCP:
                if flags & SYN:
                    if not flags & ACK and flow.syn_seq is None:
                        flow.syn_seq = seq
                    if flags & ACK:
                        flow.saw_synack = True
                    tier = 0
                    flow.origin[side] = (seq + 1) & 0xFFFFFFFF
                elif flags & RST:
                    flow.saw_rst = True
                    tier = 0
                else:
                    if flags & FIN:
                        flow.saw_fin = True
                    if flow.origin[side] is None:
                        flow.origin[side] = seq
                    if length:
                        relative = (seq - flow.origin[side]) & 0xFFFFFFFF
                        position = 0 if relative > 0x7FFFFFFF else relative
                        fresh = position + length - flow.position[side]
                        if fresh > 0:
                            flow.payload[side] += fresh
                            flow.position[side] = position + length
                        if side != flow.turn_side:
                            flow.turn_side, flow.turn_bytes = side, 0
                            flow.turns += 1
                        tier = tier_of(position, flow.turn_bytes, config)
                        flow.turn_bytes += length
                        flow.data_seen = True
                        room = head_keep[side] - len(flow.head[side]) if flow.head is not None else 0
                        if room > 0 and position < head_keep[side]:
                            flow.head[side] += data[start:start + min(length, room)]
                    elif flags & FIN:
                        tier = 0
                    elif flow.packets[0] + flow.packets[1] <= 3 and not flow.data_seen:
                        tier = 0
                    else:
                        tier = tier_of(flow.position[1 - side], flow.turn_bytes if flow.turn_side != side else 0, config)
                        position = flow.position[1 - side]
            else:
                ordinal = flow.packets[side] - 1
                tier = 0 if ordinal == 0 else 1 if ordinal < udp_tier[0] else 2 if ordinal < udp_tier[1] else 4
                position = flow.position[side]
                flow.position[side] += size
                if length:
                    flow.payload[side] += length
                    flow.data_seen = True
                    if ordinal == 0 and flow.head is not None and data:
                        flow.head[side] += data[start:start + min(length, head_keep[side])]
            if first_packet:
                tier = 0
            flow.cost[tier] += size
            add_flow(flow.id)
            add_tier(tier)
            add_size(size)
            add_offset(offset)
            add_position(min(position, 0xFFFFFFFF))
    for flow in flows:
        if flow.head is not None:
            finish(flow)
        # The closing packet bounds the flow in time and costs almost nothing.
        last = tiers[flow.last_index]
        if last:
            flow.cost[last] -= sizes[flow.last_index]
            flow.cost[0] += sizes[flow.last_index]
            tiers[flow.last_index] = 0
    return Profile(list(paths), flows, flow_of, tiers, sizes, offsets, positions, file_starts, input_bytes, headers)
