import unittest

from app.services.packet_analysis import PacketValidationError, analyze_packet


class PacketAnalysisTests(unittest.TestCase):
    def test_detects_high_rate_syn_scan(self):
        result = analyze_packet({
            "src_ip": "203.0.113.10",
            "dst_ip": "10.0.0.8",
            "dst_port": 3389,
            "protocol": "tcp",
            "tcp_flags": "SYN",
            "packets": 120,
            "bytes_out": 600,
            "duration_ms": 500,
        })
        self.assertEqual(result.threat_type, "network_attack")
        self.assertEqual(result.severity, "critical")
        self.assertGreaterEqual(result.score, 0.8)
        self.assertIn("high_rate_flow", result.indicators)

    def test_rejects_payload_and_invalid_ip(self):
        with self.assertRaises(PacketValidationError):
            analyze_packet({"src_ip": "not-an-ip", "payload": "secret"})

    def test_benign_flow_has_no_threat_score(self):
        result = analyze_packet({
            "src_ip": "203.0.113.10",
            "dst_ip": "198.51.100.8",
            "dst_port": 443,
            "protocol": "tcp",
            "packets": 2,
            "bytes_out": 1000,
            "duration_ms": 5000,
        })
        self.assertEqual(result.threat_type, "benign")
        self.assertEqual(result.score, 0.0)


if __name__ == "__main__":
    unittest.main()
