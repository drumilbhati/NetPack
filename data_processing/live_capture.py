import argparse
import base64
import os
import sys
import time
from pathlib import Path
from typing import Optional

from scapy.all import sniff

# Add parent directory to sys.path to allow relative imports
sys.path.append(str(Path(__file__).parent.parent))

from data_processing.kafka_utils import get_kafka_producer, produce_message


class LiveCaptureService:
    def __init__(
        self,
        interface: str,
        case_id: str,
        batch_size: int = 100,
        user_id: Optional[str] = None,
    ):
        self.interface = interface
        self.case_id = case_id
        self.batch_size = batch_size
        self.user_id = user_id
        self.packet_buffer = []
        self.is_running = False
        self.producer = get_kafka_producer()

    def packet_handler(self, packet):
        # Serialize packet to raw bytes and then base64 for JSON compatibility
        raw_pkt = bytes(packet)
        pkt_data = {
            "case_id": self.case_id,
            "interface": self.interface,
            "user_id": self.user_id,
            "timestamp": float(packet.time),
            "data": base64.b64encode(raw_pkt).decode("utf-8"),
        }
        
        self.packet_buffer.append(pkt_data)

        if len(self.packet_buffer) >= self.batch_size:
            self.flush_to_kafka()

    def flush_to_kafka(self):
        if not self.packet_buffer:
            return

        print(f"[*] Streaming {len(self.packet_buffer)} packets to Kafka topic 'raw-capture-chunks'...")

        try:
            payload = {
                "case_id": self.case_id,
                "user_id": self.user_id,
                "packets": self.packet_buffer
            }
            produce_message(self.producer, "raw-capture-chunks", self.case_id, payload)
            self.packet_buffer = []
        except Exception as e:
            print(f"[-] Error streaming to Kafka: {e}")

    def start(self, count: int = 0):
        """
        Start sniffing. 
        count=0 means sniff indefinitely.
        """
        self.is_running = True
        print(f"[*] Starting LIVE STREAMING capture on interface: {self.interface}")
        print(f"[*] Target Case ID: {self.case_id}")
        print(f"[*] Batch Size: {self.batch_size} packets")
        
        try:
            sniff(
                iface=self.interface, 
                prn=self.packet_handler, 
                store=0, 
                count=count
            )
        except KeyboardInterrupt:
            print("\n[*] Live capture stopped by user.")
        except Exception as e:
            print(f"[-] Fatal error during sniffing: {e}")
        finally:
            self.is_running = False
            # Final flush
            if self.packet_buffer:
                self.flush_to_kafka()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live network interface capture for NetPack.")
    parser.add_argument("--interface", "-i", required=True, help="Network interface to sniff (e.g., eth0, en0)")
    parser.add_argument("--case-id", "-c", required=True, help="Case UUID to associate with the capture")
    parser.add_argument("--batch-size", "-b", type=int, default=100, help="Number of packets to batch before sending to Kafka")
    parser.add_argument("--user-id", "-u", help="User UUID performing the capture")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")

    args = parser.parse_args()

    # Load environment variables
    try:
        from dotenv import load_dotenv
        env_path = Path(__file__).parent.parent / "infra" / ".env"
        if env_path.exists():
            load_dotenv(env_path)
    except ImportError:
        pass

    service = LiveCaptureService(
        interface=args.interface,
        case_id=args.case_id,
        batch_size=args.batch_size,
        user_id=args.user_id
    )
    
    service.start(count=args.count)
