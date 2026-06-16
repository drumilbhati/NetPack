import argparse
import os
import sys
import time
from pathlib import Path
from typing import Optional

from scapy.all import sniff, wrpcap

# Add parent directory to sys.path to allow relative imports
sys.path.append(str(Path(__file__).parent.parent))

from data_processing.ingestor import EvidenceIngestor


class LiveCaptureService:
    def __init__(
        self,
        interface: str,
        case_id: str,
        interval: int = 60,
        user_id: Optional[str] = None,
    ):
        self.interface = interface
        self.case_id = case_id
        self.interval = interval
        self.user_id = user_id
        self.ingestor = EvidenceIngestor()
        self.packet_buffer = []
        self.last_flush = time.time()
        self.is_running = False

    def packet_handler(self, packet):
        self.packet_buffer.append(packet)
        current_time = time.time()

        if current_time - self.last_flush >= self.interval:
            self.flush_to_ingestor()
            self.last_flush = current_time

    def flush_to_ingestor(self):
        if not self.packet_buffer:
            return

        print(f"[*] Flushing {len(self.packet_buffer)} packets to ingestor...")

        temp_dir = Path("temp_captures")
        temp_dir.mkdir(exist_ok=True)

        timestamp = int(time.time())
        filename = f"live_{self.interface.replace('/', '_')}_{timestamp}.pcap"
        file_path = temp_dir / filename

        try:
            # Save packets to temporary PCAP
            wrpcap(str(file_path), self.packet_buffer)
            self.packet_buffer = []

            # Ingest into the main pipeline
            evidence_id = self.ingestor.ingest(self.case_id, file_path, self.user_id)
            print(f"[+] Successfully ingested live capture chunk as {evidence_id}")
        except Exception as e:
            print(f"[-] Error during live capture ingestion: {e}")
        finally:
            if file_path.exists():
                file_path.unlink()

    def start(self, count: int = 0):
        """
        Start sniffing. 
        count=0 means sniff indefinitely.
        """
        self.is_running = True
        print(f"[*] Starting live capture on interface: {self.interface}")
        print(f"[*] Target Case ID: {self.case_id}")
        print(f"[*] Rotation Interval: {self.interval} seconds")
        
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
                self.flush_to_ingestor()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Live network interface capture for NetPack.")
    parser.add_argument("--interface", "-i", required=True, help="Network interface to sniff (e.g., eth0, en0)")
    parser.add_argument("--case-id", "-c", required=True, help="Case UUID to associate with the capture")
    parser.add_argument("--interval", "-t", type=int, default=60, help="Rotation interval in seconds (default: 60)")
    parser.add_argument("--user-id", "-u", help="User UUID performing the capture")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (0 for infinite)")

    args = parser.parse_args()

    # Load environment variables for ingestor
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
        interval=args.interval,
        user_id=args.user_id
    )
    
    service.start(count=args.count)
