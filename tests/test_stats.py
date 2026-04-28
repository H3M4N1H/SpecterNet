import unittest

from core.stats import TrafficStats


class TrafficStatsTest(unittest.TestCase):
    def test_record_and_summary(self):
        stats = TrafficStats(window=60)
        stats.record({"length": 100, "proto": "TCP"})
        stats.record({"length": 200, "proto": "HTTP"})

        summary = stats.get_summary()
        self.assertEqual(summary["total_packets"], 2)
        self.assertEqual(summary["total_bytes"], 300)
        self.assertEqual(summary["proto_totals"]["TCP"], 100)
        self.assertEqual(summary["proto_totals"]["HTTP"], 200)


if __name__ == "__main__":
    unittest.main()

