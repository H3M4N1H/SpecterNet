import unittest
import time

from utils.helpers import format_bytes, format_timestamp, PROTO_COLORS, SERVICE_PORTS


class HelpersTest(unittest.TestCase):
    def test_format_bytes(self):
        self.assertEqual(format_bytes(0), "0 B")
        self.assertEqual(format_bytes(1024), "1.0 KB")
        self.assertEqual(format_bytes(1536), "1.5 KB")

    def test_format_timestamp(self):
        self.assertEqual(
            format_timestamp(0),
            time.strftime("%H:%M:%S", time.localtime(0))
        )
        self.assertEqual(format_timestamp(None), "")

    def test_collections(self):
        self.assertIn("HTTP", PROTO_COLORS)
        self.assertEqual(SERVICE_PORTS[80], "HTTP")


if __name__ == "__main__":
    unittest.main()
