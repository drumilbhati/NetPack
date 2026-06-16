import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw
from scapy.layers.http import HTTPRequest

from data_processing.dpi_engine import extract_packet_metadata


class TestDPIEngine(unittest.TestCase):
    def test_extract_packet_metadata_http(self):
        # Create a mock HTTP packet
        pkt = (
            Ether()
            / IP(src="1.2.3.4", dst="5.6.7.8")
            / TCP(sport=1234, dport=80)
            / HTTPRequest(Host=b"example.com", Path=b"/test", User_Agent=b"TestAgent")
        )
        pkt.time = 1623845600.0

        results = extract_packet_metadata([pkt])

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["source_ip"], "1.2.3.4")
        self.assertEqual(res["destination_ip"], "5.6.7.8")
        self.assertEqual(res["http_url"], "http://example.com/test")
        self.assertEqual(res["http_user_agent"], "TestAgent")
        self.assertEqual(res["protocol"], "HTTP")

    def test_extract_packet_metadata_dns(self):
        pkt = (
            Ether()
            / IP(src="1.2.3.4", dst="8.8.8.8")
            / UDP(sport=1234, dport=53)
            / DNS(qr=0, qd=DNSQR(qname="Example.com."))
        )
        pkt.time = 1623845600.0

        results = extract_packet_metadata([pkt])

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["dns_query"], "example.com")
        self.assertEqual(res["protocol"], "DNS")

    def test_extract_packet_metadata_ftp(self):
        pkt = (
            Ether()
            / IP(src="1.2.3.4", dst="5.6.7.8")
            / TCP(sport=1234, dport=21)
            / Raw(load=b"USER anonymous\r\n")
        )
        pkt.time = 1623845600.0

        results = extract_packet_metadata([pkt])

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["protocol"], "FTP")
        self.assertEqual(res["ftp_command"], "USER anonymous")

    def test_extract_packet_metadata_smtp(self):
        pkt = (
            Ether()
            / IP(src="1.2.3.4", dst="5.6.7.8")
            / TCP(sport=1234, dport=25)
            / Raw(load=b"MAIL FROM:<test@example.com>\r\n")
        )
        pkt.time = 1623845600.0

        results = extract_packet_metadata([pkt])

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["protocol"], "SMTP")
        self.assertEqual(res["smtp_command"], "MAIL FROM:<test@example.com>")

    def test_extract_packet_metadata_smb(self):
        pkt = Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=445)
        pkt.time = 1623845600.0

        results = extract_packet_metadata([pkt])

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertEqual(res["protocol"], "SMB")

    def test_payload_signature_matching(self):
        pkt = (
            Ether()
            / IP(src="1.2.3.4", dst="5.6.7.8")
            / TCP(sport=1234, dport=80)
            / Raw(
                load=b"POST /login HTTP/1.1\r\nHost: example.com\r\n\r\npassword=supersecret"
            )
        )
        pkt.time = 1623845600.0

        results = extract_packet_metadata([pkt])

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertIn("payload_signatures", res)
        self.assertIn("password_exposure", res["payload_signatures"])

    def test_sql_injection_signature(self):
        pkt = (
            Ether()
            / IP(src="1.2.3.4", dst="5.6.7.8")
            / TCP(sport=1234, dport=80)
            / Raw(load=b"GET /search?id=1' union select null,null-- HTTP/1.1\r\n")
        )
        pkt.time = 1623845600.0

        results = extract_packet_metadata([pkt])

        self.assertEqual(len(results), 1)
        res = results[0]
        self.assertIn("sql_injection_attempt", res["payload_signatures"])

    def test_extract_tcp_streams(self):
        from data_processing.dpi_engine import extract_tcp_streams

        pkts = [
            Ether()
            / IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=1000, dport=80, seq=100)
            / Raw(load=b"GET / HTTP/1.1\r\n"),
            Ether()
            / IP(src="2.2.2.2", dst="1.1.1.1")
            / TCP(sport=80, dport=1000, seq=500)
            / Raw(load=b"HTTP/1.1 200 OK\r\n"),
            Ether()
            / IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=1000, dport=80, seq=116)
            / Raw(load=b"Host: example.com\r\n\r\n"),
        ]
        # Set timestamps
        for i, p in enumerate(pkts):
            p.time = 1623845600.0 + i

        streams = extract_tcp_streams(pkts)
        self.assertEqual(len(streams), 1)

        # Check bidirectional content
        stream_id = "1.1.1.1:1000 <-> 2.2.2.2:80"
        self.assertIn(stream_id, streams)
        directions = streams[stream_id]["directions"]

        self.assertIn("1.1.1.1:1000 -> 2.2.2.2:80", directions)
        self.assertIn("2.2.2.2:80 -> 1.1.1.1:1000", directions)

        self.assertEqual(
            directions["1.1.1.1:1000 -> 2.2.2.2:80"],
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        self.assertEqual(
            directions["2.2.2.2:80 -> 1.1.1.1:1000"], "HTTP/1.1 200 OK\r\n"
        )


if __name__ == "__main__":
    unittest.main()
