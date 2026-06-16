import datetime
from pathlib import Path
from typing import Any, Dict, List

from scapy.all import DNS, DNSQR, IP, TCP, UDP, rdpcap
from scapy.layers.http import HTTPRequest


def extract_packet_metadata(packets: List[Any]) -> List[Dict[str, Any]]:
    """
    Extract metadata from Scapy packets.
    Decodes HTTP requests (URL, User-Agent) and DNS queries.
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

        if TCP in pkt:
            res["source_port"] = pkt[TCP].sport
            res["destination_port"] = pkt[TCP].dport
            res["protocol"] = "TCP"

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

        elif UDP in pkt:
            res["source_port"] = pkt[UDP].sport
            res["destination_port"] = pkt[UDP].dport
            res["protocol"] = "UDP"

            if pkt.haslayer(DNSQR) and pkt.haslayer(DNS) and pkt[DNS].qr == 0:
                qname = (
                    pkt[DNSQR].qname.decode(errors="replace")
                    if pkt[DNSQR].qname
                    else ""
                )
                res["dns_query"] = qname.lower().rstrip(".")

        results.append(res)

    return results


def extract_flow_metadata(packets: List[Any]) -> List[Dict[str, Any]]:
    """
    Extract flow-level metadata from Scapy packets.
    Aggregates packets into flows based on (src_ip, dst_ip, src_port, dst_port, protocol).
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
