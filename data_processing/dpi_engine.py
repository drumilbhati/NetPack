import datetime
import json
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, PcapReader, Raw
from scapy.layers.http import HTTPRequest

from .tcp_reassembler import TCPReassembler


class SignatureManager:
    """
    Manages loading and matching of payload signatures from external JSON rules.
    """

    def __init__(self, rules_path: Optional[str] = None):
        self.signatures: List[Dict[str, Any]] = []
        if rules_path is None:
            rules_path = os.path.join(
                os.path.dirname(__file__), "rules", "signatures.json"
            )

        self.load_rules(rules_path)

    def load_rules(self, path: str):
        if not os.path.exists(path):
            print(f"Warning: Signature rules file not found at {path}")
            return

        try:
            with open(path, "r") as f:
                rules = json.load(f)
                for rule in rules:
                    rule["regex"] = re.compile(rule["pattern"].encode(), re.IGNORECASE)
                    self.signatures.append(rule)
            print(f"Loaded {len(self.signatures)} payload signatures from {path}")
        except Exception as e:
            print(f"Error loading signatures from {path}: {e}")

    def match(self, payload: bytes) -> List[str]:
        matched = []
        for sig in self.signatures:
            if sig["regex"].search(payload):
                matched.append(sig["name"])
        return matched


def calculate_entropy(data: str) -> float:
    """
    Calculate Shannon entropy of a string (used for DNS tunneling detection).
    """
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy


SIGNATURE_MANAGER = SignatureManager()


def extract_packet_metadata(packets: Iterable[Any]) -> List[Dict[str, Any]]:
    """
    Extract metadata from Scapy packets (iterator-based).
    Decodes HTTP, DNS, FTP, SMTP, SMB, ICMP and matches payload signatures.
    """
    results = []

    for pkt in packets:
        if IP not in pkt:
            continue

        res = {
            "timestamp": datetime.datetime.fromtimestamp(
                float(pkt.time), datetime.timezone.utc
            ).isoformat(),
            "source_ip": pkt[IP].src,
            "destination_ip": pkt[IP].dst,
            "protocol": "IP",
            "size": len(pkt),
        }

        # 1. TCP Analysis
        if TCP in pkt:
            res["source_port"] = pkt[TCP].sport
            res["destination_port"] = pkt[TCP].dport
            res["protocol"] = "TCP"

            # HTTP
            if pkt.haslayer(HTTPRequest):
                host = (
                    pkt[HTTPRequest].Host.decode(errors="replace")
                    if pkt[HTTPRequest].Host
                    else ""
                )
                path = (
                    pkt[HTTPRequest].Path.decode(errors="replace")
                    if pkt[HTTPRequest].Path
                    else ""
                )
                res["http_url"] = f"http://{host}{path}"
                res["http_user_agent"] = (
                    pkt[HTTPRequest].User_Agent.decode(errors="replace")
                    if pkt[HTTPRequest].User_Agent
                    else ""
                )
                res["protocol"] = "HTTP"

            # FTP (Control Port 21)
            elif res["source_port"] == 21 or res["destination_port"] == 21:
                payload = bytes(pkt[TCP].payload)
                if payload:
                    msg = payload.decode(errors="replace").strip()
                    if any(
                        cmd in msg
                        for cmd in ["USER", "PASS", "RETR", "STOR", "CWD", "LIST"]
                    ):
                        res["ftp_command"] = msg
                        res["protocol"] = "FTP"

            # SMTP (Ports 25, 587, 465)
            elif res["destination_port"] in [25, 587, 465]:
                payload = bytes(pkt[TCP].payload)
                if payload:
                    msg = payload.decode(errors="replace").strip()
                    if any(
                        cmd in msg
                        for cmd in ["HELO", "EHLO", "MAIL FROM", "RCPT TO", "DATA"]
                    ):
                        res["smtp_command"] = msg
                        res["protocol"] = "SMTP"

            # SMB (Port 445)
            elif res["destination_port"] == 445 or res["source_port"] == 445:
                res["protocol"] = "SMB"
                # Check for SMB2 Header
                try:
                    from scapy.layers.smb import SMB2_Header

                    if pkt.haslayer(SMB2_Header):
                        res["protocol"] = "SMB2"
                        res["smb_command"] = pkt[SMB2_Header].Command
                except ImportError:
                    pass

            # Payload Signature Matching
            if Raw in pkt:
                payload_data = pkt[Raw].load
                matched = SIGNATURE_MANAGER.match(payload_data)
                if matched:
                    res["payload_signatures"] = matched

        # 2. UDP Analysis
        elif UDP in pkt:
            res["source_port"] = pkt[UDP].sport
            res["destination_port"] = pkt[UDP].dport
            res["protocol"] = "UDP"

            # DNS
            if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                qname = (
                    pkt[DNSQR].qname.decode(errors="replace")
                    if pkt[DNSQR].qname
                    else ""
                )
                query = qname.lower().rstrip(".")
                res["dns_query"] = query
                res["dns_entropy"] = calculate_entropy(query)
                res["protocol"] = "DNS"

        # 3. ICMP Analysis (Tunneling Detection)
        elif ICMP in pkt:
            res["protocol"] = "ICMP"
            res["icmp_type"] = pkt[ICMP].type
            res["icmp_code"] = pkt[ICMP].code
            if Raw in pkt:
                payload_data = pkt[Raw].load
                res["payload_size"] = len(payload_data)
                # Check for large ICMP payloads (often indicative of tunneling)
                if len(payload_data) > 64:
                    res["suspicious_icmp"] = True

        results.append(res)

    return results


def extract_flow_metadata(packets: Iterable[Any]) -> List[Dict[str, Any]]:
    """
    Extract flow-level metadata from Scapy packets (iterator-based).
    Aggregates packets into flows based on (src_ip, dst_ip, sport, dport, protocol).
    """
    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        # Determine 5-tuple and direction
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = "IP"
        sport = 0
        dport = 0

        if TCP in pkt:
            proto = "TCP"
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif UDP in pkt:
            proto = "UDP"
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"

        # Canonical flow key (directional)
        flow_key = (src_ip, dst_ip, sport, dport, proto)
        reverse_key = (dst_ip, src_ip, dport, sport, proto)

        timestamp = float(pkt.time)
        pkt_len = len(pkt)

        if flow_key not in flows:
            # Check if it's the reverse of an existing flow
            if reverse_key in flows:
                f = flows[reverse_key]
                f["bytes_received"] += pkt_len
                f["packet_count"] += 1
                f["end_time"] = max(f["end_time"], timestamp)
                f["start_time"] = min(f["start_time"], timestamp)
            else:
                flows[flow_key] = {
                    "source_ip": src_ip,
                    "destination_ip": dst_ip,
                    "source_port": sport,
                    "destination_port": dport,
                    "protocol": proto,
                    "bytes_sent": pkt_len,
                    "bytes_received": 0,
                    "packet_count": 1,
                    "start_time": timestamp,
                    "end_time": timestamp,
                }
        else:
            f = flows[flow_key]
            f["bytes_sent"] += pkt_len
            f["packet_count"] += 1
            f["end_time"] = max(f["end_time"], timestamp)
            f["start_time"] = min(f["start_time"], timestamp)

    results = []
    for f in flows.values():
        f["duration"] = f["end_time"] - f["start_time"]
        f["timestamp"] = datetime.datetime.fromtimestamp(
            f["start_time"], datetime.timezone.utc
        ).isoformat()
        results.append(f)

    return results


def process_pcap_iterator(file_path: str) -> Iterable[Any]:
    """
    Returns a PcapReader iterator for a given PCAP file.
    """
    return PcapReader(file_path)


def extract_tcp_streams(packets: Iterable[Any]) -> Dict[str, Any]:
    """
    Reassemble TCP streams from packets and return as a dictionary.
    Keys are string representations of the 5-tuple.
    """
    reassembler = TCPReassembler()
    reassembler.process_packets(packets)

    bidi_streams = reassembler.get_bidirectional_streams()

    results = {}
    for key, directions in bidi_streams.items():
        # key is ((ip1, port1), (ip2, port2))
        stream_id = f"{key[0][0]}:{key[0][1]} <-> {key[1][0]}:{key[1][1]}"
        results[stream_id] = {
            "directions": {
                dir_name: payload.decode(errors="replace")
                for dir_name, payload in directions.items()
            },
            "total_size": sum(len(p) for p in directions.values()),
        }

    return results
