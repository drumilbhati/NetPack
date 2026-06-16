import unittest

from scapy.all import IP, TCP, Ether, Raw

from data_processing.tcp_reassembler import TCPReassembler


class TestTCPReassembler(unittest.TestCase):
    def test_reassembly_ordered(self):
        reassembler = TCPReassembler()

        pkts = [
            IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=1000, dport=80, seq=100)
            / Raw(load=b"Hello "),
            IP(src="1.1.1.1", dst="2.2.2.2")
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
            IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=1000, dport=80, seq=106)
            / Raw(load=b"World"),
            IP(src="1.1.1.1", dst="2.2.2.2")
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
            IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=1000, dport=80, seq=100)
            / Raw(load=b"Hello "),
            IP(src="1.1.1.1", dst="2.2.2.2")
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
            IP(src="1.1.1.1", dst="2.2.2.2")
            / TCP(sport=1000, dport=80, seq=100)
            / Raw(load=b"Hello "),
            IP(src="1.1.1.1", dst="2.2.2.2")
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
