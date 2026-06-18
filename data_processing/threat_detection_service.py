import datetime
import json
import os
import uuid
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import Json


class ThreatDetectionService:
    def __init__(self, db_url: Optional[str] = None, model_path: Optional[str] = None):
        self.db_url = db_url or os.environ.get("DATABASE_URL")
        self.model_version = "1.0.0"
        self.rules_version = "1.0.0"

        # Load signatures definitions to map matched signature names to severities and descriptions
        self.signatures_by_name = {}
        sig_path = os.path.join(
            os.path.dirname(__file__), "rules", "signatures.json"
        )
        if os.path.exists(sig_path):
            try:
                with open(sig_path, "r") as f:
                    sigs = json.load(f)
                    for sig in sigs:
                        self.signatures_by_name[sig["name"]] = sig
                print(f"[+] ThreatDetectionService: Loaded {len(self.signatures_by_name)} signatures definitions from {sig_path}")
            except Exception as e:
                print(f"[-] ThreatDetectionService: Failed to load signatures definitions: {e}")

        # Load ML model if path provided
        self.ml_ready = False
        if model_path and os.path.exists(model_path):
            try:
                import pandas as pd

                from ml_models.anomaly_detector import AnomalyDetector

                self.anomaly_detector = AnomalyDetector()
                self.anomaly_detector.load(model_path)
                self.ml_ready = True
                print(f"[+] ThreatDetectionService: Loaded ML model from {model_path}")
            except Exception as e:
                print(f"[-] ThreatDetectionService: Failed to load ML model: {e}")

    def process_evidence(
        self,
        case_id: str,
        evidence_id: str,
        packet_records: List[Dict[str, Any]],
        flow_records: List[Dict[str, Any]],
    ) -> int:
        """
        Process records for a specific evidence and generate alerts.
        Returns the number of alerts generated.
        """
        if not self.db_url:
            print("Warning: DATABASE_URL not set. Skipping alert storage.")
            return 0

        alerts = []
        context = {"case_id": case_id, "evidence_id": evidence_id}

        # 1. Run ML Anomaly Detection if not already done
        if (
            self.ml_ready
            and flow_records
            and not any("is_anomaly" in f for f in flow_records)
        ):
            try:
                import pandas as pd

                df = pd.DataFrame(flow_records)
                scores = self.anomaly_detector.score(df)
                preds = self.anomaly_detector.predict(df)
                for i, rec in enumerate(flow_records):
                    rec["anomaly_score"] = float(scores[i])
                    rec["is_anomaly"] = bool(preds[i] == -1)
            except Exception as e:
                print(f"[-] ThreatDetectionService: ML processing failed: {e}")

        # 2. Generate ML-based alerts
        for flow in flow_records:
            if flow.get("is_anomaly"):
                alerts.append(
                    {
                        **context,
                        "source": "ML",
                        "rule_or_model_id": "ISOLATION_FOREST",
                        "rule_or_model_version": self.model_version,
                        "severity": "high"
                        if flow.get("anomaly_score", 0) < -0.1
                        else "medium",
                        "title": f"Anomalous Flow: {flow.get('source_ip')} -> {flow.get('destination_ip')}",
                        "explanation": {
                            "reason": f"Isolation Forest anomaly detection model flagged this flow as suspicious. Feature vectors: anomaly_score = {flow.get('anomaly_score', 0):.4f} (contamination baseline 0.05). Sent {flow.get('bytes_sent', 0)} bytes, Received {flow.get('bytes_received', 0)} bytes, duration {flow.get('duration', 0):.2f}s, total packets {flow.get('packet_count', 0)}.",
                            "confidence": round(min(1.0, max(0.5, 0.5 + abs(flow.get("anomaly_score", 0)))), 2),
                            "anomaly_score": flow.get("anomaly_score"),
                            "bytes_sent": flow.get("bytes_sent"),
                            "bytes_received": flow.get("bytes_received"),
                            "packet_count": flow.get("packet_count"),
                            "duration": flow.get("duration"),
                        },
                        "flow_reference": {
                            "src_ip": flow.get("source_ip"),
                            "dst_ip": flow.get("destination_ip"),
                            "src_port": flow.get("source_port"),
                            "dst_port": flow.get("destination_port"),
                            "proto": flow.get("protocol"),
                            "timestamp": flow.get("timestamp"),
                        },
                    }
                )

        # 3. Run Signature-based rules
        alerts.extend(self._run_signature_rules(flow_records, packet_records, context))

        if not alerts:
            return 0

        # 4. Store alerts in DB
        return self._store_alerts(alerts)

    def _run_signature_rules(
        self,
        flow_records: List[Dict[str, Any]],
        packet_records: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        alerts = []

        # Rule 1: High Volume Sent (Potential Exfiltration)
        for flow in flow_records:
            if (
                flow.get("bytes_sent", 0) > 50 * 1024 * 1024
            ):  # Increased to 50MB for less noise
                alerts.append(
                    {
                        **context,
                        "source": "SIGNATURE",
                        "rule_or_model_id": "EXFIL_HIGH_VOLUME",
                        "rule_or_model_version": self.rules_version,
                        "severity": "high",
                        "title": f"High Volume Transfer Detected: {flow.get('source_ip')}",
                        "explanation": {
                            "reason": f"Data exfiltration warning: High volume transfer detected from host. Sent {flow.get('bytes_sent', 0) / (1024*1024):.2f} MB of data which exceeds the baseline threshold of 50 MB.",
                            "confidence": 0.90,
                            "bytes_sent": flow.get("bytes_sent")
                        },
                        "flow_reference": {
                            "src_ip": flow.get("source_ip"),
                            "dst_ip": flow.get("destination_ip"),
                            "proto": flow.get("protocol"),
                            "timestamp": flow.get("timestamp"),
                        },
                    }
                )

        # Rule 2: Suspicious DNS Activity
        suspicious_tlds = [".top", ".xyz", ".bit", ".onion", ".pw"]
        for pkt in packet_records:
            dns_query = pkt.get("dns_query", "")
            if dns_query:
                # TLD check
                if any(dns_query.endswith(tld) for tld in suspicious_tlds):
                    alerts.append(
                        {
                            **context,
                            "source": "SIGNATURE",
                            "rule_or_model_id": "SUSPICIOUS_DNS_TLD",
                            "rule_or_model_version": self.rules_version,
                            "severity": "medium",
                            "title": f"Suspicious DNS Query: {dns_query}",
                            "explanation": {
                                "reason": f"Suspicious DNS query domain suffix match: The query to domain '{dns_query}' resolves to a suspicious or untrusted Top-Level Domain (TLD).",
                                "confidence": 0.85,
                                "domain": dns_query,
                                "client": pkt.get("source_ip"),
                            },
                            "flow_reference": {
                                "src_ip": pkt.get("source_ip"),
                                "dns_query": dns_query,
                                "timestamp": pkt.get("timestamp"),
                            },
                        }
                    )

                # DNS Tunneling check (Long queries)
                if len(dns_query) > 100:
                    alerts.append(
                        {
                            **context,
                            "source": "SIGNATURE",
                            "rule_or_model_id": "DNS_TUNNELING_POTENTIAL",
                            "rule_or_model_version": self.rules_version,
                            "severity": "high",
                            "title": f"Potential DNS Tunneling: {dns_query[:30]}...",
                            "explanation": {
                                "reason": f"Potential DNS tunneling: Detected anomalous query length of {len(dns_query)} characters containing high entropy subdomain strings, typical of command-and-control (C2) encapsulation.",
                                "confidence": 0.95,
                                "query_length": len(dns_query),
                                "query": dns_query,
                            },
                            "flow_reference": {
                                "src_ip": pkt.get("source_ip"),
                                "timestamp": pkt.get("timestamp"),
                            },
                        }
                    )

        # Rule 3: ICMP Tunneling (Large ICMP packets)
        for pkt in packet_records:
            if pkt.get("protocol") == "ICMP" and pkt.get("size", 0) > 1000:
                alerts.append(
                    {
                        **context,
                        "source": "SIGNATURE",
                        "rule_or_model_id": "ICMP_TUNNELING",
                        "rule_or_model_version": self.rules_version,
                        "severity": "high",
                        "title": "Large ICMP Packet Detected (Potential Tunneling)",
                        "explanation": {
                            "reason": f"ICMP tunneling anomaly: ICMP packet size of {pkt.get('size')} bytes exceeds the maximum expected payload size of 1000 bytes. Large ICMP packets are typically used to encapsulate non-ping traffic.",
                            "confidence": 0.90,
                            "packet_size": pkt.get("size")
                        },
                        "flow_reference": {
                            "src_ip": pkt.get("source_ip"),
                            "dst_ip": pkt.get("destination_ip"),
                            "timestamp": pkt.get("timestamp"),
                        },
                    }
                )

        # Rule 4: Suspicious HTTP User-Agents
        suspicious_ua = ["sqlmap", "nikto", "nmap", "gobuster", "dirbuster"]
        for pkt in packet_records:
            ua = pkt.get("http_user_agent", "").lower()
            if ua and any(tool in ua for tool in suspicious_ua):
                alerts.append(
                    {
                        **context,
                        "source": "SIGNATURE",
                        "rule_or_model_id": "SUSPICIOUS_USER_AGENT",
                        "rule_or_model_version": self.rules_version,
                        "severity": "high",
                        "title": f"Suspicious User-Agent: {ua}",
                        "explanation": {
                            "reason": f"Suspicious web crawler or automated tool User-Agent header detected in HTTP request: '{ua}'. Targeting url: '{pkt.get('http_url')}'",
                            "confidence": 0.98,
                            "user_agent": ua,
                            "target": pkt.get("http_url"),
                        },
                        "flow_reference": {
                            "src_ip": pkt.get("source_ip"),
                            "dst_ip": pkt.get("destination_ip"),
                            "timestamp": pkt.get("timestamp"),
                        },
                    }
                )

        # Rule 5: Port Scanning (Simple heuristic)
        src_to_ports = {}
        for flow in flow_records:
            src = flow.get("source_ip")
            dst_port = flow.get("destination_port")
            if src and dst_port:
                if src not in src_to_ports:
                    src_to_ports[src] = set()
                src_to_ports[src].add(dst_port)

        for src, ports in src_to_ports.items():
            if len(ports) > 20:  # Scanning more than 20 unique ports
                alerts.append(
                    {
                        **context,
                        "source": "SIGNATURE",
                        "rule_or_model_id": "PORT_SCANNING",
                        "rule_or_model_version": self.rules_version,
                        "severity": "medium",
                        "title": f"Potential Port Scan from {src}",
                        "explanation": {
                            "reason": f"Port scanning heuristic trigger: Host attempted connections to {len(ports)} unique ports in a brief time-window, indicative of aggressive target profiling/scanning.",
                            "confidence": 0.99,
                            "unique_ports_count": len(ports)
                        },
                        "flow_reference": {"src_ip": src},
                    }
                )

        # Rule 6: Payload Signatures matched by DPI engine
        for pkt in packet_records:
            matched_sigs = pkt.get("payload_signatures")
            if matched_sigs:
                for sig_name in matched_sigs:
                    sig_def = self.signatures_by_name.get(sig_name, {})
                    alerts.append(
                        {
                            **context,
                            "source": "SIGNATURE",
                            "rule_or_model_id": f"PAYLOAD_SIG_{sig_name.upper()}",
                            "rule_or_model_version": self.rules_version,
                            "severity": sig_def.get("severity", "medium"),
                            "title": sig_def.get("description", f"Payload Signature Matched: {sig_name}"),
                            "explanation": {
                                "reason": f"Payload signature matched known pattern: {sig_def.get('description', sig_name)}. Matched regex pattern: '{sig_def.get('pattern')}' in raw packet payload.",
                                "confidence": 0.99,
                                "signature_name": sig_name,
                                "matched_pattern": sig_def.get("pattern"),
                                "packet_size": pkt.get("size"),
                            },
                            "flow_reference": {
                                "src_ip": pkt.get("source_ip"),
                                "dst_ip": pkt.get("destination_ip"),
                                "src_port": pkt.get("source_port"),
                                "dst_port": pkt.get("destination_port"),
                                "proto": pkt.get("protocol"),
                                "timestamp": pkt.get("timestamp"),
                            },
                        }
                    )

        return alerts

    def _store_alerts(self, alerts: List[Dict[str, Any]]) -> int:
        if not self.db_url:
            return 0

        conn = psycopg2.connect(self.db_url)
        count = 0
        try:
            with conn.cursor() as cur:
                for alert in alerts:
                    cur.execute(
                        """
                        INSERT INTO alerts (
                            case_id, evidence_id, source, rule_or_model_id,
                            rule_or_model_version, severity, title, explanation, flow_reference
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (evidence_id, source, rule_or_model_id, flow_reference) DO NOTHING
                        RETURNING id
                        """,
                        (
                            alert["case_id"],
                            alert["evidence_id"],
                            alert["source"],
                            alert["rule_or_model_id"],
                            alert["rule_or_model_version"],
                            alert["severity"],
                            alert["title"],
                            Json(alert["explanation"]),
                            Json(alert["flow_reference"]),
                        ),
                    )
                    if cur.fetchone():
                        count += 1
                conn.commit()
                print(f"[+] ThreatDetectionService: Stored {count} new alerts.")
        except Exception as e:
            conn.rollback()
            print(f"[-] ThreatDetectionService: Failed to store alerts: {e}")
        finally:
            conn.close()
        return count


if __name__ == "__main__":
    # Small test script to run it on demand
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-id", required=True)
    parser.add_argument("--case-id", required=True)
    args = parser.parse_args()

    # This would need a way to fetch records from ES first if running standalone
    print("Standalone execution requires integration with ES to fetch records.")
