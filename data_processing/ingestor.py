import json
import hashlib
import os
import sys
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read file in chunks to handle large PCAPs
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def extract_metadata(pcap_path):
    """Extract basic flow metadata from a PCAP file."""
    packets = rdpcap(pcap_path)
    metadata = []

    for pkt in packets:
        entry = {
            "timestamp": float(pkt.time),
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": None,
            "length": len(pkt)
        }

        # IP Layer
        if IP in pkt:
            entry["src_ip"] = pkt[IP].src
            entry["dst_ip"] = pkt[IP].dst
            entry["protocol"] = pkt[IP].proto
        elif IPv6 in pkt:
            entry["src_ip"] = pkt[IPv6].src
            entry["dst_ip"] = pkt[IPv6].dst
            entry["protocol"] = pkt[IPv6].nh

        # Transport Layer
        if TCP in pkt:
            entry["src_port"] = pkt[TCP].sport
            entry["dst_port"] = pkt[TCP].dport
            entry["protocol_name"] = "TCP"
        elif UDP in pkt:
            entry["src_port"] = pkt[UDP].sport
            entry["dst_port"] = pkt[UDP].dport
            entry["protocol_name"] = "UDP"
        
        # If we found IP data, add to list
        if entry["src_ip"]:
            metadata.append(entry)

    return metadata

def main():
    if len(sys.argv) < 2:
        print("Usage: python ingestor.py <pcap_file> [output_json]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "metadata.json"

    if not os.path.exists(pcap_path):
        print(f"Error: File {pcap_path} not found.")
        sys.exit(1)

    print(f"Processing {pcap_path}...")
    
    # Calculate Hash
    file_hash = calculate_sha256(pcap_path)
    print(f"SHA-256: {file_hash}")

    # Extract Metadata
    try:
        metadata = extract_metadata(pcap_path)
        
        output_data = {
            "file_info": {
                "file_name": os.path.basename(pcap_path),
                "sha256": file_hash,
                "total_packets": len(metadata)
            },
            "flows": metadata
        }

        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=4)
        
        print(f"Successfully extracted metadata to {output_path}")

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
