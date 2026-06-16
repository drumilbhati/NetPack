import datetime
import re
from pathlib import Path
from typing import Any, Dict, List

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Raw, rdpcap
from scapy.layers.http import HTTPRequest

from .tcp_reassembler import TCPReassembler

# Payload Signatures for sensitive data and common attack patterns
PAYLOAD_SIGNATURES = {
    "password_exposure": re.compile(
        rb"(password|passwd|pwd|secret)\s*[:=]\s*(\w+)", re.IGNORECASE
    ),
    "sql_injection_attempt": re.compile(
        rb"union\s+select|drop\s+table|select\s+.*\s+from\s+information_schema",
        re.IGNORECASE,
    ),
    "private_key_exposure": re.compile(
        rb"-----BEGIN (RSA|EC|DSA|OPENSSH)? PRIVATE KEY-----"
    ),
    "zip_archive_header": re.compile(rb"PK\x03\x04"),
    "executable_header": re.compile(rb"MZ\x90\x00"),  # Windows PE
    "elf_header": re.compile(rb"\x7fELF"),
}


def extract_packet_metadata(packets: List[Any]) -> List[Dict[str, Any]]:
    """
    Extract metadata from Scapy packets.
    Decodes HTTP, DNS, FTP, SMTP, SMB and matches payload signatures.
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
                matched = []
                for sig_name, pattern in PAYLOAD_SIGNATURES.items():
                    if pattern.search(payload_data):
                        matched.append(sig_name)
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
                res["dns_query"] = qname.lower().rstrip(".")
                res["protocol"] = "DNS"

        results.append(res)

    return results


def extract_flow_metadata(packets: List[Any]) -> List[Dict[str, Any]]:
    """
    Extract flow-level metadata from Scapy packets.
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


def extract_tcp_streams(packets: List[Any]) -> Dict[str, Any]:
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
