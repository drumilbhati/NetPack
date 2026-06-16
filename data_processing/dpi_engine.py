import datetime
from pathlib import Path
from typing import Any, Dict, List

from scapy.all import DNS, DNSQR, IP, TCP, UDP, rdpcap
from scapy.layers.http import HTTPRequest


def extract_packet_metadata(pcap_path: Path) -> List[Dict[str, Any]]:
    """
    Extract metadata from a PCAP file using Scapy.
    Decodes HTTP requests (URL, User-Agent) and DNS queries.
    """
    packets = rdpcap(str(pcap_path))
    results = []

    for pkt in packets:
        if not IP in pkt:
            continue

        res = {
            "timestamp": datetime.datetime.fromtimestamp(
                float(pkt.time), datetime.timezone.utc
            ).isoformat(),
            "source_ip": pkt[IP].src,
            "destination_ip": pkt[IP].dst,
            "protocol": "IP",
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
