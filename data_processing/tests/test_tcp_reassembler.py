import unittest

from scapy.all import IP, TCP, Ether, Raw

from data_processing.tcp_reassembler import TCPReassembler


def ipv4(*octets: int) -> str:
    return ".".join(str(octet) for octet in octets)


SRC_IP = ipv4(1, 1, 1, 1)
DST_IP = ipv4(2, 2, 2, 2)


class TestTCPReassembler(unittest.TestCase):
    def test_reassembly_ordered(self):
        reassembler = TCPReassembler()

        pkts = [
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(sport=1000, dport=80, seq=100)
            / Raw(load=b"Hello "),
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(sport=1000, dport=80, seq=106)
            / Raw(load=b"World"),
        ]

        reassembler.process_packets(pkts)
        streams = reassembler.get_all_streams()

        self.assertEqual(len(streams), 1)
        self.assertEqual(list(streams.values())[0], b"Hello World")

    def test_reassembly_out_of_order(self):
        reassembler = TCPReassembler()

        pkts = [
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(sport=1000, dport=80, seq=106)
            / Raw(load=b"World"),
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(sport=1000, dport=80, seq=100)
            / Raw(load=b"Hello "),
        ]

        reassembler.process_packets(pkts)
        streams = reassembler.get_all_streams()

        self.assertEqual(len(streams), 1)
        self.assertEqual(list(streams.values())[0], b"Hello World")

    def test_reassembly_overlap(self):
        reassembler = TCPReassembler()

        pkts = [
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(sport=1000, dport=80, seq=100)
            / Raw(load=b"Hello "),
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(sport=1000, dport=80, seq=103)
            / Raw(load=b"lo World"),
        ]

        reassembler.process_packets(pkts)
        streams = reassembler.get_all_streams()

        self.assertEqual(len(streams), 1)
        # "Hel" + "lo World" = "Hello World"
        self.assertEqual(list(streams.values())[0], b"Hello World")

    def test_reassembly_gap(self):
        reassembler = TCPReassembler()

        pkts = [
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(sport=1000, dport=80, seq=100)
            / Raw(load=b"Hello "),
            IP(src=SRC_IP, dst=DST_IP)
            / TCP(sport=1000, dport=80, seq=110)
            / Raw(load=b"World"),
        ]

        reassembler.process_packets(pkts)
        streams = reassembler.get_all_streams()

        payload = list(streams.values())[0]
        self.assertIn(b"Hello", payload)
        self.assertIn(b"World", payload)
        self.assertIn(b"GAP:4BYTES", payload)


if __name__ == "__main__":
    unittest.main()
