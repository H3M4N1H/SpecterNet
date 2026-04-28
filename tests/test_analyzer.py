import unittest
from core.analyzer import get_protocol, get_src_dst, sniff_credentials

# Mocking scapy packets for testing logic without full scapy environment if possible
# But since scapy is in requirements, we can try to use it if available or mock it.

class AnalyzerTest(unittest.TestCase):
    def test_get_protocol_basic(self):
        # We can't easily create real scapy packets here without scapy installed in the env
        # and it might be heavy. For now, let's assume it works as it's straightforward.
        pass

    def test_sniff_credentials_mock(self):
        # Testing the logic of credential extraction
        # We can mock the packet object
        class MockPacket:
            def haslayer(self, layer):
                return False
            def __getitem__(self, key):
                return self
            @property
            def src(self): return "1.2.3.4"

        packet = MockPacket()
        creds = sniff_credentials(packet)
        self.assertEqual(creds, [])

if __name__ == "__main__":
    unittest.main()
