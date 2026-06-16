import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether
from scapy.layers.http import HTTPRequest

from data_processing.dpi_engine import extract_packet_metadata


class TestDPIEngine(unittest.TestCase):
    @patch("data_processing.dpi_engine.rdpcap")
    def test_extract_packet_metadata_http(self, mock_rdpcap):
        # Create a mock HTTP packet
        pkt = (
            Ether()
            / IP(src="1.2.3.4", dst="5.6.7.8")
            / TCP(sport=1234, dport=80)
            / HTTPRequest(Host=b"example.com", Path=b"/test", User_Agent=b"TestAgent")
        )
        pkt.time = 1623845600.0

        mock_rdpcap.return_value = [pkt]

        results = extract_packet_metadata(Path("dummy.pcap"))

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["source_ip"], "1.2.3.4")
        self.assertEqual(res["destination_ip"], "5.6.7.8")
        self.assertEqual(res["http_url"], "http://example.com/test")
        self.assertEqual(res["http_user_agent"], "TestAgent")
        # Verify UTC timestamp (2021-06-16T12:13:20+00:00)
        self.assertTrue(res["timestamp"].endswith("+00:00"))

    @patch("data_processing.dpi_engine.rdpcap")
    def test_extract_packet_metadata_dns_query(self, mock_rdpcap):
        # Create a mock DNS query packet (qr=0)
        pkt = (
            Ether()
            / IP(src="1.2.3.4", dst="8.8.8.8")
            / UDP(sport=1234, dport=53)
            / DNS(qr=0, qd=DNSQR(qname="Example.com."))
        )
        pkt.time = 1623845600.0

        mock_rdpcap.return_value = [pkt]

        results = extract_packet_metadata(Path("dummy.pcap"))

        self.assertEqual(len(results), 1)
        res = results[0]
        # Verify canonicalization (lowercase, no trailing dot)
        self.assertEqual(res["dns_query"], "example.com")

    @patch("data_processing.dpi_engine.rdpcap")
    def test_extract_packet_metadata_dns_response(self, mock_rdpcap):
        # Create a mock DNS response packet (qr=1)
        pkt = (
            Ether()
            / IP(src="8.8.8.8", dst="1.2.3.4")
            / UDP(sport=53, dport=1234)
            / DNS(qr=1, qd=DNSQR(qname="example.com."))
        )
        pkt.time = 1623845600.0

        mock_rdpcap.return_value = [pkt]

        results = extract_packet_metadata(Path("dummy.pcap"))

        self.assertEqual(len(results), 1)
        res = results[0]
        # Should NOT have dns_query for a response
        self.assertNotIn("dns_query", res)


if __name__ == "__main__":
    unittest.main()
