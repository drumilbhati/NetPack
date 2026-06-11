import json
import hashlib
import os
import sys
from scapy.all import PcapReader, IP, IPv6, TCP, UDP

def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        # Read file in chunks to handle large PCAPs
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def is_pcap(file_path):
    """Check for PCAP/PCAPNG magic numbers."""
    magic_numbers = [
        b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', 
        b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d',
        b'\x0a\x0d\x0d\x0a'
    ]
    try:
        with open(file_path, 'rb') as f:
            header = f.read(4)
            return header in magic_numbers
    except Exception:
        return False

def is_safe_path(path):
    """Validate output path for security."""
    if os.path.isabs(path):
        return False
    if ".." in os.path.normpath(path):
        return False
    # Enforce current directory or subdirectories
    return True

def extract_metadata(pcap_path):
    """Extract basic flow metadata from a PCAP file using streaming."""
    metadata = []
    total_count = 0
    
    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            total_count += 1
            entry = {
                "timestamp": float(pkt.time),
                "src_ip": None,
                "dst_ip": None,
                "src_port": None,
                "dst_port": None,
                "protocol": None,
                "protocol_name": None,
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

    return metadata, total_count

def main():
    if len(sys.argv) < 2:
        print("Usage: python ingestor.py <pcap_file> [output_json]")
        sys.exit(1)

    pcap_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else "metadata.json"

    # Validation
    if not os.path.exists(pcap_path):
        print(f"Error: File {pcap_path} not found.")
        sys.exit(1)

    if not is_pcap(pcap_path):
        print(f"Error: {pcap_path} is not a valid PCAP/PCAPNG file.")
        sys.exit(1)

    if not is_safe_path(output_path):
        print(f"Error: Dangerous output path detected: {output_path}")
        sys.exit(1)

    if os.path.exists(output_path):
        print(f"Error: Output file {output_path} already exists. Refusing to overwrite.")
        sys.exit(1)

    try:
        print(f"Processing {pcap_path}...")
        
        # Calculate Hash inside try block
        file_hash = calculate_sha256(pcap_path)
        print(f"SHA-256: {file_hash}")

        # Extract Metadata using streaming
        metadata, total_packets = extract_metadata(pcap_path)
        
        output_data = {
            "file_info": {
                "file_name": os.path.basename(pcap_path),
                "sha256": file_hash,
                "total_packets_read": total_packets,
                "ip_packets_extracted": len(metadata)
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
