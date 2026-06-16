import collections
import logging
from typing import Any, Dict, List, Tuple

from scapy.all import IP, TCP, Raw

logger = logging.getLogger(__name__)


class TCPStream:
    """Represents a single TCP stream (one direction)."""

    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.segments = {}  # seq -> payload
        self.first_seq = None
        self.last_seq = None

    def add_segment(self, seq: int, payload: bytes):
        if not payload:
            return

        # Simple overlap handling: if we already have this exact seq, ignore or overwrite
        # A more robust reassembler would handle partial overlaps
        if seq not in self.segments or len(payload) > len(self.segments[seq]):
            self.segments[seq] = payload

        if self.first_seq is None or seq < self.first_seq:
            self.first_seq = seq

    def get_reassembled_payload(self) -> bytes:
        if not self.segments:
            return b""

        sorted_seqs = sorted(self.segments.keys())
        reassembled = b""
        current_seq = self.first_seq

        for seq in sorted_seqs:
            payload = self.segments[seq]
            if seq < current_seq:
                # Overlap: skip the part we already have
                overlap = current_seq - seq
                if overlap < len(payload):
                    reassembled += payload[overlap:]
                    current_seq = seq + len(payload)
            elif seq == current_seq:
                reassembled += payload
                current_seq = seq + len(payload)
            else:
                # Gap in sequence numbers
                gap_size = seq - current_seq
                # For forensics, we might want to represent gaps with placeholders
                reassembled += b" [GAP:" + str(gap_size).encode() + b"BYTES] "
                reassembled += payload
                current_seq = seq + len(payload)

        return reassembled


class TCPReassembler:
    """Reassembles TCP segments from a list of packets into bidirectional streams."""

    def __init__(self):
        self.streams = {}  # (src_ip, dst_ip, src_port, dst_port) -> TCPStream

    def process_packets(self, packets: List[Any]):
        for pkt in packets:
            if IP in pkt and TCP in pkt and Raw in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                seq = pkt[TCP].seq
                payload = pkt[Raw].load

                stream_key = (src_ip, dst_ip, src_port, dst_port)
                if stream_key not in self.streams:
                    self.streams[stream_key] = TCPStream(
                        src_ip, dst_ip, src_port, dst_port
                    )

                self.streams[stream_key].add_segment(seq, payload)

    def get_all_streams(self) -> Dict[Tuple[str, str, int, int], bytes]:
        return {
            key: stream.get_reassembled_payload()
            for key, stream in self.streams.items()
        }

    def get_bidirectional_streams(
        self,
    ) -> Dict[Tuple[frozenset, frozenset], Dict[str, bytes]]:
        """Groups one-way streams into bidirectional conversations."""
        bidi = collections.defaultdict(dict)
        for (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        ), payload in self.get_all_streams().items():
            # Create a stable key for both directions
            # Using tuple of sorted tuples to be hashable
            key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))

            direction = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            bidi[key][direction] = payload

        return dict(bidi)
