import json
import hashlib
import os
import sys
import tempfile
from pathlib import Path
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
    except OSError:
        return False

def is_safe_path(resolved_path):
    """Validate resolved output path is within current working directory tree."""
    try:
        cwd = Path.cwd().resolve()
        # Path must be a descendant of CWD or CWD itself
        return cwd in resolved_path.parents or resolved_path == cwd
    except Exception:
        return False

def extract_metadata(pcap_path):
    """Yield basic flow metadata from a PCAP file using streaming."""
    total_count = 0
    with PcapReader(str(pcap_path)) as reader:
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
            
            # If we found IP data, yield the entry and current total count
            if entry["src_ip"]:
                yield entry, total_count
        
        # Yield a final sentinel with the final count if needed
        yield None, total_count

def main():
    if len(sys.argv) < 2:
        print("Usage: python ingestor.py <pcap_file> [output_json]")
        sys.exit(1)

    pcap_path = Path(sys.argv[1])
    output_arg = sys.argv[2] if len(sys.argv) > 2 else "metadata.json"

    # Resolve and validate output path
    resolved_output = Path(output_arg).resolve()

    # Validation
    if not pcap_path.exists():
        print(f"Error: File {pcap_path} not found.")
        sys.exit(1)

    if not is_pcap(pcap_path):
        print(f"Error: {pcap_path} is not a valid PCAP/PCAPNG file.")
        sys.exit(1)

    if not is_safe_path(resolved_output):
        print(f"Error: Dangerous output path detected: {resolved_output}")
        sys.exit(1)

    if resolved_output.exists():
        print(f"Error: Output file {resolved_output} already exists. Refusing to overwrite.")
        sys.exit(1)

    try:
        print(f"Processing {pcap_path}...")
        
        # Calculate Hash inside try block
        file_hash = calculate_sha256(pcap_path)
        print(f"SHA-256: {file_hash}")

        # Atomic streaming write to temporary file
        temp_fd, temp_path = tempfile.mkstemp(dir=resolved_output.parent, text=True)
        try:
            with os.fdopen(temp_fd, 'w') as tf:
                tf.write('{\n  "flows": [\n')
                
                ip_count = 0
                total_packets = 0
                first = True
                
                # Stream metadata to disk to keep memory footprint minimal
                for entry, count in extract_metadata(pcap_path):
                    total_packets = count
                    if entry:
                        if not first:
                            tf.write(',\n')
                        tf.write('    ')
                        json.dump(entry, tf)
                        ip_count += 1
                        first = False
                
                tf.write('\n  ],\n')
                tf.write('  "file_info": {\n')
                tf.write(f'    "file_name": "{pcap_path.name}",\n')
                tf.write(f'    "sha256": "{file_hash}",\n')
                tf.write(f'    "total_packets_read": {total_packets},\n')
                tf.write(f'    "ip_packets_extracted": {ip_count}\n')
                tf.write('  }\n}')
                tf.flush()
                os.fsync(tf.fileno())

            # Atomic move into final location
            os.replace(temp_path, resolved_output)
            print(f"Successfully extracted metadata to {resolved_output}")

        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise e

    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
