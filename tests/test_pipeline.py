"""Correctness tests for evidence loss, byte accounting, and capture IO."""
import copy
import json
from pathlib import Path
import struct
import tempfile
import unittest

from demo.generate_demo_pcap import generate, checksum
from src.packet_parser import read_pcap, write_subset
from src.feature_extraction import extract
from src.selectors import select, budget_bytes
from src.evaluator import answer, unique_payload_bytes

ROOT = Path(__file__).resolve().parents[1]

class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        cls.folder = Path(cls.temp.name)
        cls.path = cls.folder / "fixture.pcap"
        cls.truth = generate(cls.path, background_packets=20)
        cls.capture = read_pcap(cls.path)
        cls.config = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
        cls.features = extract(cls.capture.packets, cls.config)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def question(self, packets, qid):
        return next(q["answerable"] for q in answer(packets, self.truth, self.config)["questions"] if q["question"] == qid)

    def test_full_capture_answers_all_questions(self):
        self.assertEqual(answer(self.capture.packets, self.truth, self.config)["answered"], 8)

    def test_generator_known_counts_and_bytes(self):
        self.assertEqual(self.truth["scan"]["count"], 40)
        self.assertEqual(self.truth["http"]["failures_generated"], 12)
        self.assertEqual(self.truth["bulk"]["unique_payload_bytes_generated"], 300000)
        self.assertEqual(len(self.capture.packets), self.truth["packet_count"])
        self.assertEqual(len(self.features["http"]), 13)
        self.assertEqual(len(self.features["dns"]), 1)

    def test_generated_network_checksums(self):
        for p in self.capture.packets:
            ip = p.data[14:]
            ihl = (ip[0] & 15) * 4
            total = struct.unpack("!H", ip[2:4])[0]
            self.assertEqual(checksum(ip[:ihl]), 0)
            transport = ip[ihl:total]
            pseudo = ip[12:20] + struct.pack("!BBH", 0, ip[9], len(transport))
            self.assertEqual(checksum(pseudo + transport), 0)

    def test_all_strategies_respect_cap_and_keep_record_bytes(self):
        for strategy in ("random", "alert", "evidence", "flow_prefix"):
            for fraction in (.01, .05, .1, .2, 1):
                cap = budget_bytes(self.capture.size, fraction)
                selected, _ = select(self.capture.packets, self.features, cap, strategy, 17, self.config)
                path = self.folder / f"{strategy}_{fraction}.pcap"
                size = write_subset(self.capture, selected, path, cap)
                retained = read_pcap(path)
                self.assertLessEqual(size, cap)
                self.assertEqual(size, 24 + sum(p.cost for p in retained.packets))
                self.assertEqual([p.record for p in retained.packets],
                                 [self.capture.packets[i].record for i in sorted(selected)])
                self.assertEqual(retained.header, self.capture.header)

    def test_random_seed_is_reproducible_and_changes_selection(self):
        cap = budget_bytes(self.capture.size, .1)
        a = select(self.capture.packets, self.features, cap, "random", 4, self.config)[0]
        b = select(self.capture.packets, self.features, cap, "random", 4, self.config)[0]
        c = select(self.capture.packets, self.features, cap, "random", 5, self.config)[0]
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_empty_subset_has_no_answers(self):
        self.assertEqual(answer([], self.truth, self.config)["answered"], 0)

    def test_dns_response_loss_breaks_mapping_question(self):
        response = self.features["dns"][0][1]
        retained = [p for p in self.capture.packets if p.index != response.index]
        self.assertFalse(self.question(retained, "Q7"))

    def test_missing_handshake_ack_breaks_sequence_question(self):
        handshake = next(h for h in self.features["handshakes"]
                         if h[0].src == self.truth["internal"]["src"]
                         and h[0].dst == self.truth["internal"]["dst"])
        retained = [p for p in self.capture.packets if p.index != handshake[2].index]
        self.assertFalse(self.question(retained, "Q6"))

    def test_http_request_loss_breaks_success_question(self):
        request = next(q for q, _, status in self.features["http"] if status == 200)
        retained = [p for p in self.capture.packets if p.index != request.index]
        self.assertFalse(self.question(retained, "Q5"))

    def test_scan_boundary_loss_breaks_exact_count_and_interval(self):
        missing = min(p.index for p in self.capture.packets if p.syn and p.dport == 1000)
        retained = [p for p in self.capture.packets if p.index != missing]
        self.assertFalse(self.question(retained, "Q2"))
        self.assertFalse(self.question(retained, "Q3"))
        self.assertTrue(self.question(retained, "Q1"))

    def test_duplicate_payload_does_not_inflate_bulk_volume(self):
        p = next(p for p in self.capture.packets if p.src == self.truth["bulk"]["src"]
                 and p.dst == self.truth["bulk"]["dst"] and p.payload)
        self.assertEqual(unique_payload_bytes([p, p, p]), 1200)

    def test_too_small_budget_and_overrun_rejected(self):
        for fraction in (0, -1, 1.1):
            with self.assertRaises(ValueError):
                budget_bytes(self.capture.size, fraction)
        with self.assertRaises(ValueError):
            budget_bytes(24, .01)
        with self.assertRaises(ValueError):
            write_subset(self.capture, [0], self.folder / "overrun.pcap", 24)

    def test_big_endian_nanosecond_round_trip(self):
        p = self.capture.packets[0]
        path = self.folder / "nanos.pcap"
        secs, nanos = divmod(p.timestamp_ns + 123, 1_000_000_000)
        path.write_bytes(struct.pack(">IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
                         + struct.pack(">IIII", secs, nanos, len(p.data), p.original_length) + p.data)
        capture = read_pcap(path)
        self.assertEqual(capture.packets[0].timestamp_ns, p.timestamp_ns + 123)
        out = self.folder / "nanos_out.pcap"
        write_subset(capture, [0], out, capture.size)
        self.assertEqual(path.read_bytes(), out.read_bytes())

    def test_invalid_inputs_fail_explicitly(self):
        header = self.capture.header
        fixtures = [b"", b"\x0a\x0d\x0d\x0a" + b"\0"*20, header + b"\0"*3,
                    header + struct.pack("<IIII", 1, 0, 50, 50) + b"\0"*4,
                    header[:20] + struct.pack("<I", 101)]
        for i, data in enumerate(fixtures):
            path = self.folder / f"invalid_{i}.pcap"
            path.write_bytes(data)
            with self.assertRaises(ValueError):
                read_pcap(path)

    def test_truth_labels_are_not_selector_inputs(self):
        # Different evaluator reference answers cannot affect packet selection.
        cap = budget_bytes(self.capture.size, .05)
        original = select(self.capture.packets, self.features, cap, "evidence", 0, self.config)[0]
        truth = copy.deepcopy(self.truth)
        truth["scan"]["count"] = 999
        self.assertFalse(next(q["answerable"] for q in answer(self.capture.packets, truth, self.config)["questions"]
                              if q["question"] == "Q2"))
        self.assertEqual(original, select(self.capture.packets, self.features, cap, "evidence", 0, self.config)[0])

if __name__ == "__main__":
    unittest.main()
