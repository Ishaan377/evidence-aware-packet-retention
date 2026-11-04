"""Unit tests for Evidence-Based Retention, using small hand-built captures."""
import gzip
from itertools import compress
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pcapng_to_pcap import convert  # noqa: E402
from ebr import baselines  # noqa: E402
from ebr.allocate import allocate, hull_segments  # noqa: E402
from ebr.pcapstream import FIN, ACK, PSH, RST, SYN, decode, iter_records  # noqa: E402
from ebr.profile import build_profile, dns_query_name  # noqa: E402
from ebr.retain import ebr_select, ledger_bytes, write_reduced  # noqa: E402
from ebr.value import _surprisal, diminishing_multipliers, score_flows  # noqa: E402
from ebr.verify import FlowIndex, family, hidden_family, known_alerts, repaired_select  # noqa: E402

CONFIG = json.loads((Path(__file__).resolve().parent.parent / 'ebr_config.json').read_text(encoding='utf8'))
CLIENT, SERVER = bytes((10, 0, 0, 1)), bytes((10, 0, 0, 2))


def tcp_frame(src, dst, sport, dport, flags, seq, ack=0, payload=b''):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, src, dst)
    return b'\x02' * 6 + b'\x04' * 6 + b'\x08\x00' + ip + tcp


def udp_frame(src, dst, sport, dport, payload):
    udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, src, dst)
    return b'\x02' * 6 + b'\x04' * 6 + b'\x08\x00' + ip + udp


def write_pcap(path, frames):
    with open(path, 'wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            stream.write(struct.pack('<IIII', 1000 + i, 0, len(frame), len(frame)) + frame)


def conversation(sport=4000, request=b'GET /index.html HTTP/1.1\r\nHost: a\r\n\r\n', body=b'x' * 40000, client=CLIENT):
    """A complete TCP exchange: handshake, one request, a long response, a close."""
    frames = [tcp_frame(client, SERVER, sport, 80, SYN, 100),
              tcp_frame(SERVER, client, 80, sport, SYN | ACK, 500, 101),
              tcp_frame(client, SERVER, sport, 80, ACK, 101, 501),
              tcp_frame(client, SERVER, sport, 80, ACK | PSH, 101, 501, request)]
    position = 501
    for start in range(0, len(body), 1400):
        chunk = body[start:start + 1400]
        frames.append(tcp_frame(SERVER, client, 80, sport, ACK, position, 101 + len(request), chunk))
        frames.append(tcp_frame(client, SERVER, sport, 80, ACK, 101 + len(request), position + len(chunk)))
        position += len(chunk)
    frames.append(tcp_frame(client, SERVER, sport, 80, FIN | ACK, 101 + len(request), position))
    return frames


class Harness(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)

    def capture(self, frames, name='input.pcap'):
        path = self.root / name
        write_pcap(path, frames)
        return path

    def profile(self, frames):
        return build_profile([self.capture(frames)], CONFIG)


class Decoding(Harness):
    def test_decoder_reads_tcp_fields_and_payload(self):
        frame = tcp_frame(CLIENT, SERVER, 1234, 80, ACK, 77, 5, b'hello')
        src, dst, proto, sport, dport, flags, seq, start, length = decode(frame, 1)
        self.assertEqual((src, dst, proto, sport, dport, flags, seq), (CLIENT, SERVER, 6, 1234, 80, ACK, 77))
        self.assertEqual(frame[start:start + length], b'hello')

    def test_linux_cooked_v2_frames_decode_like_ethernet(self):
        ethernet = tcp_frame(CLIENT, SERVER, 1234, 80, ACK, 77, 5, b'hello')
        cooked = b'\x08\x00\x00\x00' + b'\0' * 4 + b'\x00\x01\x00\x06' + b'\0' * 8 + ethernet[14:]
        expected = decode(ethernet, 1)
        found = decode(cooked, 276)
        self.assertEqual(found[:7], expected[:7])
        self.assertEqual(cooked[found[7]:found[7] + found[8]], b'hello')

    def test_torn_final_record_ends_the_stream_cleanly(self):
        path = self.capture(conversation(body=b'y' * 100))
        with open(path, 'ab') as stream:
            stream.write(struct.pack('<IIII', 2000, 0, 500, 500) + b'short')
        self.assertEqual(len(list(iter_records(path))), len(conversation(body=b'y' * 100)))

    def test_pcapng_is_refused(self):
        path = self.root / 'x.pcapng'
        path.write_bytes(b'\x0a\x0d\x0d\x0a' + b'\0' * 40)
        with self.assertRaises(ValueError):
            build_profile([path], CONFIG)

    def test_dns_name(self):
        message = b'\0' * 12 + b'\x03www\x07example\x03com\x00\x00\x01\x00\x01'
        self.assertEqual(dns_query_name(message), 'www.example.com')


class Conversion(Harness):
    def pcapng(self, frames, resolution=None):
        """Build a small PCAPNG: section header, one Ethernet interface, enhanced packets."""
        options = struct.pack('<HHBBBB', 9, 1, resolution, 0, 0, 0) + struct.pack('<HH', 0, 0) if resolution is not None else b''
        section = struct.pack('<IIIHHq', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1) + struct.pack('<I', 28)
        length = 20 + len(options)
        interface = struct.pack('<IIHHI', 1, length, 1, 0, 65535) + options + struct.pack('<I', length)
        blocks = [section, interface]
        for i, frame in enumerate(frames):
            pad = -len(frame) % 4
            size = 32 + len(frame) + pad
            ticks = (1000 + i) * (10 ** resolution if resolution is not None else 1_000_000) + 7
            blocks.append(struct.pack('<IIIIIII', 6, size, 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame) + 4)
                          + frame + b'\0' * pad + struct.pack('<I', size))
        path = self.root / 'input.pcapng'
        path.write_bytes(b''.join(blocks))
        return path

    def test_packets_lengths_and_times_survive_conversion(self):
        frames = conversation(body=b'c' * 2000)
        target = self.root / 'converted.pcap'
        result = convert(self.pcapng(frames), target)
        self.assertEqual(result['packets'], len(frames))
        records = list(iter_records(target))
        self.assertEqual([r[3] for r in records], frames)
        self.assertEqual(records[0][1], 1000 * 1_000_000_000 + 7000)
        self.assertEqual(struct.unpack_from('<I', target.read_bytes(), 24 + 12)[0], len(frames[0]) + 4)

    def test_nanosecond_interfaces_keep_full_precision(self):
        target = self.root / 'converted.pcap'
        convert(self.pcapng(conversation(body=b'c' * 100), 9), target)
        self.assertEqual(next(iter_records(target))[1], 1000 * 1_000_000_000 + 7)

    def test_converted_capture_is_accepted_by_the_profiler(self):
        target = self.root / 'converted.pcap'
        convert(self.pcapng(conversation(body=b'c' * 2000)), target)
        self.assertEqual(len(build_profile([target], CONFIG).flows), 1)


class Tiers(Harness):
    def test_costs_partition_all_bytes(self):
        profile = self.profile(conversation() + conversation(sport=4001))
        self.assertEqual(sum(sum(f.cost) for f in profile.flows), sum(profile.sizes))

    def test_control_and_request_stay_in_low_tiers_and_bulk_goes_high(self):
        frames = conversation()
        profile = self.profile(frames)
        self.assertEqual(profile.tier[0], 0)
        self.assertEqual(profile.tier[3], 1)
        self.assertEqual(max(profile.tier), 4)
        self.assertEqual(profile.tier[len(frames) - 1], 0)

    def test_retransmission_shares_the_tier_of_the_original(self):
        frames = conversation(body=b'z' * 30000)
        late = next(i for i, t in enumerate(self.profile(frames).tier) if t == 4)
        # A trailing packet keeps the copy from being the flow's closing packet, which is always kept.
        profile = self.profile(frames + [frames[late], frames[-1]])
        self.assertEqual(profile.tier[len(frames)], profile.tier[late])

    def test_later_turn_of_a_long_session_gets_a_turn_head(self):
        first = conversation(body=b'a' * 30000)[:-1]
        sequence = 101 + len(b'GET /index.html HTTP/1.1\r\nHost: a\r\n\r\n')
        second = tcp_frame(CLIENT, SERVER, 4000, 80, ACK | PSH, sequence, 30501, b'GET /admin?cmd=1 HTTP/1.1\r\n\r\n')
        profile = self.profile(first + [second, tcp_frame(CLIENT, SERVER, 4000, 80, FIN | ACK, sequence + 29, 30501)])
        self.assertEqual(profile.tier[len(first)], 1)
        deep = tcp_frame(CLIENT, SERVER, 4000, 80, ACK | PSH, sequence + 20000, 30501, b'POST /x HTTP/1.1\r\n\r\n')
        answer = tcp_frame(SERVER, CLIENT, 80, 4000, ACK | PSH, 30501, sequence + 20000, b'HTTP/1.1 200 OK\r\n\r\n')
        profile = self.profile(first + [deep, answer, deep[:-1] + b'\n', tcp_frame(CLIENT, SERVER, 4000, 80, FIN | ACK, sequence + 20021, 30521)])
        self.assertEqual(profile.tier[len(first)], 3)

    def test_server_first_midstream_flow_keeps_the_real_client(self):
        profile = self.profile([tcp_frame(SERVER, CLIENT, 80, 4000, ACK, 500, 100, b'data')])
        self.assertEqual((profile.flows[0].client, profile.flows[0].sport), (CLIENT, 80))

    def test_new_syn_with_new_sequence_starts_a_new_flow(self):
        frames = [tcp_frame(CLIENT, SERVER, 5, 80, SYN, 1), tcp_frame(CLIENT, SERVER, 5, 80, SYN, 9000)]
        self.assertEqual(len(self.profile(frames).flows), 2)

    def test_identical_syn_retransmission_stays_one_flow(self):
        frames = [tcp_frame(CLIENT, SERVER, 5, 80, SYN, 1), tcp_frame(CLIENT, SERVER, 5, 80, SYN, 1)]
        self.assertEqual(len(self.profile(frames).flows), 1)


class Value(Harness):
    def test_good_turing_discounts_one_offs_when_they_are_common(self):
        all_unique = _surprisal([f'name{i}' for i in range(1000)], 16)
        mostly_common = _surprisal(['common'] * 999 + ['rare'], 16)
        self.assertLess(all_unique[0], 0.01)
        self.assertGreater(mostly_common[-1], 9)

    def test_repeating_one_message_diminishes_but_new_content_does_not_collapse(self):
        repeats = [f for i in range(100) for f in conversation(sport=1000 + i, body=b'r' * 200)]
        distinct = [f for i in range(100) for f in conversation(sport=3000 + i, body=b'r' * 200, request=f'GET /p{"/" * (i % 40)}?{"%" * (i // 40)} HTTP/1.1\r\n\r\n'.encode())]
        repeated = diminishing_multipliers(self.profile(repeats).flows, CONFIG)
        varied = diminishing_multipliers(self.profile(distinct).flows, CONFIG)
        self.assertLess(min(repeated), min(varied))

    def test_burst_of_exemplars_keeps_full_value(self):
        frames = [f for i in range(80) for f in conversation(sport=1000 + i, body=b'r' * 200)]
        multipliers = diminishing_multipliers(self.profile(frames).flows, CONFIG)
        self.assertEqual(sum(1 for m in multipliers if m == 1.0), CONFIG['exemplar_burst'])

    def test_readable_apps_keep_full_value_for_deep_bytes(self):
        flow = self.profile(conversation(request=b'\x00\x00\x00\x2f\xfeSMB' + b'\x00' * 200, body=b'\x90' * 30000)).flows[0]
        self.assertEqual(flow.app, 'smb')
        opaque = sum(s[0] * s[3] for s in hull_segments(flow, 10.0, dict(CONFIG, readable_apps=[])))
        readable = sum(s[0] * s[3] for s in hull_segments(flow, 10.0, CONFIG))
        self.assertLess(opaque, readable)

    def test_automated_scanner_outranks_normal_clients(self):
        scanner = bytes((10, 9, 9, 9))
        frames = [f for i in range(40) for f in conversation(sport=2000 + i, body=b'n' * (300 + i * 500))]
        frames += [tcp_frame(scanner, SERVER, 40000 + p, p, SYN, 1) for p in range(1, 600)]
        scores = score_flows(self.profile(frames).flows, CONFIG)
        self.assertEqual(max(scores['hosts'], key=scores['hosts'].get), scanner)


class Allocation(Harness):
    def test_budget_is_never_exceeded(self):
        frames = [f for i in range(50) for f in conversation(sport=1000 + i)]
        profile = self.profile(frames)
        for budget in (2000, 20000, 200000):
            mask, ledger, _ = ebr_select(profile, budget, CONFIG)
            self.assertLessEqual(24 + sum(compress(profile.sizes, mask)) + len(ledger), budget)

    def test_full_budget_keeps_everything(self):
        profile = self.profile(conversation())
        mask, _, _ = ebr_select(profile, profile.input_bytes * 2, CONFIG)
        self.assertEqual(sum(mask), profile.packets)

    def test_empty_tiers_earn_no_value(self):
        bare = self.profile([tcp_frame(CLIENT, SERVER, 1, 80, SYN, 1)]).flows[0]
        segments = hull_segments(bare, 10.0, CONFIG)
        self.assertEqual(len(segments), 1)
        self.assertAlmostEqual(segments[0][0] * segments[0][3], 10.0 * CONFIG['tier_weights'][0])

    def test_hull_efficiency_falls_within_a_flow(self):
        flow = self.profile(conversation()).flows[0]
        efficiencies = [s[0] for s in hull_segments(flow, 10.0, CONFIG)]
        self.assertEqual(efficiencies, sorted(efficiencies, reverse=True))

    def scan_storm(self):
        frames = [tcp_frame(CLIENT, SERVER, 40000 + p, p, SYN, 1) for p in range(1, 400)]
        return frames + conversation(sport=7, body=b'q' * 3000)

    def test_silent_share_limits_scan_flows_when_content_needs_the_room(self):
        profile = self.profile(self.scan_storm())
        room = 3000
        talker = next(f for f in profile.flows if f.data_seen)
        tight, _ = allocate(profile.flows, [0.001 if f is talker else 50.0 for f in profile.flows], room, dict(CONFIG, silent_budget_share=None))
        capped, used = allocate(profile.flows, [0.001 if f is talker else 50.0 for f in profile.flows], room, dict(CONFIG, silent_budget_share=0.2))
        self.assertLess(tight[talker.id], capped[talker.id])
        self.assertLessEqual(used, room)

    def test_silent_share_returns_unused_budget_to_scan_flows(self):
        profile = self.profile(self.scan_storm())
        room = sum(sum(f.cost) for f in profile.flows)
        levels, _ = allocate(profile.flows, [5.0] * len(profile.flows), room, dict(CONFIG, silent_budget_share=0.05))
        self.assertTrue(all(level >= 0 for level in levels))

    def test_higher_value_flow_wins_a_tight_budget(self):
        profile = self.profile(conversation(sport=1, body=b'q' * 100) + conversation(sport=2, body=b'q' * 100))
        need = sum(profile.flows[0].cost)
        levels, used = allocate(profile.flows, [1.0, 50.0], need, CONFIG)
        self.assertEqual(levels[0], -1)
        self.assertGreaterEqual(levels[1], 0)
        self.assertLessEqual(used, need)


class Output(Harness):
    def test_reduced_records_are_byte_identical_to_the_source(self):
        frames = [f for i in range(5) for f in conversation(sport=1000 + i)]
        profile = self.profile(frames)
        mask, _, _ = ebr_select(profile, 20000, CONFIG)
        write_reduced(profile, mask, self.root / 'out')
        source = {data for _, _, _, data in iter_records(self.root / 'input.pcap')}
        kept = list(iter_records(self.root / 'out' / 'input.pcap'))
        self.assertEqual(len(kept), sum(mask))
        self.assertTrue(all(data in source for _, _, _, data in kept))

    def test_ledger_accounts_for_every_flow_even_when_folded(self):
        frames = [f for i in range(300) for f in conversation(sport=1000 + i, body=b'r' * 100)]
        profile = self.profile(frames)
        scores = score_flows(profile.flows, CONFIG)
        folded = gzip.decompress(ledger_bytes(profile.flows, scores['value'], 500)).decode()
        rows = folded.splitlines()
        individual = [r for r in rows[1:] if not r.startswith(('group', 'start'))]
        groups = [r.split(',') for r in rows if r.startswith('group,') and not r.startswith('group,client')]
        self.assertEqual(len(individual) + sum(int(g[5]) for g in groups), len(profile.flows))

    def test_ledger_respects_its_limit(self):
        frames = [f for i in range(300) for f in conversation(sport=1000 + i, body=b'r' * 100)]
        profile = self.profile(frames)
        scores = score_flows(profile.flows, CONFIG)
        self.assertLessEqual(len(ledger_bytes(profile.flows, scores['value'], 1000)), 1000)


class VerifyBeforeDelete(Harness):
    def alert(self, sport=1001, minutes=('1970-01-01T00:16',)):
        return dict(sid=1, sig='ET SCAN example', cat='Network Scan', a='10.0.0.1', b='10.0.0.2', minutes=list(minutes),
                    tuple=['10.0.0.1', sport, '10.0.0.2', 80], created='2015_01_01')

    def test_repaired_flow_is_kept_whole_inside_the_same_cap(self):
        profile = self.profile([f for i in range(30) for f in conversation(sport=1000 + i, body=b'q' * 6000)])
        scores = score_flows(profile.flows, CONFIG)
        budget = profile.input_bytes // 8
        chosen = min(profile.flows, key=lambda f: scores['value'][f.id]).id
        mask, ledger, info = repaired_select(profile, budget, CONFIG, scores, {chosen})
        kept = sum(compress(profile.sizes, map(chosen.__eq__, profile.flow_of)))
        self.assertEqual(sum(compress(profile.sizes, (m and f == chosen for m, f in zip(mask, profile.flow_of)))), kept)
        self.assertLessEqual(24 + sum(compress(profile.sizes, mask)) + len(ledger), budget)

    def test_exact_flow_comes_first_and_neighbours_only_when_widened(self):
        frames = [f for i in range(5) for f in conversation(sport=1000 + i, body=b'q' * 100)]
        index = FlowIndex(self.profile(frames).flows)
        entry = self.alert(minutes=('1970-01-01T00:16', '1970-01-01T00:17'))
        self.assertEqual(len(index.targets(entry, False)), 1)
        self.assertEqual(len(index.targets(entry, True)), 5)

    def test_index_can_be_limited_to_the_hosts_in_question(self):
        frames = conversation(sport=1001, body=b'q' * 100) + conversation(sport=1002, body=b'q' * 100, client=bytes((10, 0, 0, 3)))
        flows = self.profile(frames).flows
        limited = FlowIndex(flows, [dict(self.alert(), a='10.0.0.1', b='10.0.0.2')])
        self.assertEqual(len(limited.by_pair), 2)
        unrelated = FlowIndex(flows, [dict(self.alert(), a='10.0.0.8', b='10.0.0.9')])
        self.assertEqual(len(unrelated.by_pair), 0)

    def test_alert_known_from_either_direction(self):
        index = FlowIndex(self.profile(conversation(sport=1001, body=b'q' * 100)).flows)
        reverse = dict(self.alert(), tuple=['10.0.0.2', 80, '10.0.0.1', 1001])
        self.assertEqual(len(index.targets(reverse, False)), 1)

    def test_rules_newer_than_the_capture_are_not_known(self):
        older, newer = self.alert(), dict(self.alert(), created='2020_01_01', sid=2)
        full = dict(alerts={(1, 'a', 'b'): older, (2, 'a', 'b'): newer})
        self.assertEqual(set(known_alerts(full, 'past', '2018-01-01')), {(1, 'a', 'b')})
        self.assertEqual(len(known_alerts(full, 'all', '2018-01-01')), 2)

    def test_hidden_condition_excludes_whole_families(self):
        entries = [dict(self.alert(), sig=f'ET {name} example', sid=i) for i, name in enumerate(('SCAN', 'MALWARE', 'EXPLOIT', 'POLICY', 'INFO', 'DOS'))]
        full = dict(alerts={(e['sid'], 'a', 'b'): e for e in entries})
        known = known_alerts(full, 'half', '2018-01-01')
        self.assertTrue(all(not hidden_family(v) for v in known.values()))
        self.assertEqual(family(entries[0]), 'ET SCAN')


class Comparators(Harness):
    def setUp(self):
        super().setUp()
        frames = [f for i in range(40) for f in conversation(sport=1000 + i, body=b'b' * (500 + i * 900))]
        frames += [udp_frame(CLIENT, SERVER, 5000 + i, 53, b'\0' * 12 + b'\x01a\x00\x00\x01\x00\x01') for i in range(30)]
        self.prepared = self.profile(frames)
        self.budget = self.prepared.input_bytes // 10

    def within(self, mask):
        used = 24 + sum(compress(self.prepared.sizes, mask))
        self.assertLessEqual(used, self.budget)
        return used

    def test_random_packets_respect_the_cap(self):
        self.within(baselines.random_packets(self.prepared, self.budget, 1))

    def test_random_packets_are_reproducible(self):
        self.assertEqual(baselines.random_packets(self.prepared, self.budget, 7), baselines.random_packets(self.prepared, self.budget, 7))

    def test_random_flows_keep_flows_whole(self):
        mask = baselines.random_flows(self.prepared, self.budget, 1)
        self.within(mask)
        kept = set(compress(self.prepared.flow_of, mask))
        for flow, packet in zip(self.prepared.flow_of, mask):
            self.assertEqual(flow in kept, bool(packet))

    def test_flow_cutoff_spends_its_budget(self):
        used = self.within(baselines.flow_cutoff(self.prepared, self.budget, baselines.CutoffIndex(self.prepared)))
        self.assertGreater(used, self.budget * 0.9)

    def test_flow_cutoff_handles_budget_below_all_control_packets(self):
        index = baselines.CutoffIndex(self.prepared)
        tiny = 2000
        mask = baselines.flow_cutoff(self.prepared, tiny, index)
        self.assertLessEqual(24 + sum(compress(self.prepared.sizes, mask)), tiny)
        self.assertGreater(sum(mask), 0)

    def test_rare_destination_prefers_dns_and_respects_the_cap(self):
        costs = baselines.flow_costs(self.prepared)
        index = baselines.CutoffIndex(self.prepared)
        mask = baselines.rare_destination(self.prepared, self.budget, costs, index)
        self.within(mask)
        kept = set(compress(self.prepared.flow_of, mask))
        self.assertTrue({f.id for f in self.prepared.flows if f.sport == 53} <= kept)

    def test_internal_address_ranges(self):
        self.assertTrue(baselines.is_internal(bytes((172, 31, 69, 25))))
        self.assertFalse(baselines.is_internal(bytes((18, 218, 115, 60))))

    def test_ids_triggered_keeps_only_alerted_flows(self):
        mask = baselines.ids_triggered(self.prepared, self.budget, {0})
        self.within(mask)
        self.assertEqual(set(compress(self.prepared.flow_of, mask)), {0})

    def test_ids_fill_spends_leftover_budget(self):
        index = baselines.CutoffIndex(self.prepared)
        plain = self.within(baselines.ids_triggered(self.prepared, self.budget, {0}))
        filled = self.within(baselines.ids_triggered(self.prepared, self.budget, {0}, None, True, index))
        self.assertGreater(filled, plain)


if __name__ == '__main__':
    unittest.main()
