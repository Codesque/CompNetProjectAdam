"""
File Receiver Module
--------------------
Listens for incoming IP packets, reassembles file fragments, and verifies integrity.
"""


from scapy.all import sniff, IP
from encryption import decrypt_file, sha256_hash
from collections import defaultdict
import time

RECEIVER_IP = "192.168.1.1"
OUTPUT_FILE = "received.txt"  # Output path for the reconstructed file

buffer = defaultdict(bytes)  # Stores fragments indexed by their ID
total_fragments = None  # Total number of fragments expected
recv_timestamps = {} # Tracks the timestamp of each received fragment
received_hash = None  # Expected hash of the final file

#  Callback function for each captured packet.
def packet_callback(packet):
    global total_fragments, received_hash

    if IP in packet and packet[IP].dst == RECEIVER_IP:
        payload = bytes(packet[IP].payload)
        try:
            # Split the payload using the first two pipes only
            parts = payload.split(b'|', 2)
            if len(parts) < 3:
                print("x--Malformed packet: missing delimiters.")
                return

            frag_info = parts[0].decode()
            received_hash_candidate = parts[1].decode()
            fragment_data = parts[2]

            # Parse fragment index and total count
            try:
                frag_id, total = map(int, frag_info.split('/'))
            except ValueError:
                print("x--Invalid fragment info:", frag_info)
                return

            # Accept the hash only once
            if received_hash is None:
                received_hash = received_hash_candidate
                total_fragments = total
                print(f"*Receiving {total} fragments...")

            buffer[frag_id] = fragment_data
            recv_timestamps[frag_id] = time.time()

            print(f"Received fragment {frag_id+1}/{total}")

            if len(buffer) == total_fragments:
                assemble_file()

        except Exception as e:
            print("Error parsing packet:", e)


def assemble_file():
    
    # Reassemble fragments in order
    ordered = [buffer[i] for i in sorted(buffer)]
    encrypted_data = b''.join(ordered)

    # Decrypt and verify file integrity
    decrypted = decrypt_file(encrypted_data)
    actual_hash = sha256_hash(decrypted)

    print(f"---All fragments received. Verifying...")

    if actual_hash == received_hash:
        with open(OUTPUT_FILE, "wb") as f:
            f.write(decrypted)
        print("---File successfully reconstructed and verified.")
    else:
        print("---Hash mismatch. File corrupted.")

    # Calculate and display latency between first and last received fragment
    first_recv = min(recv_timestamps.values())
    last_recv = max(recv_timestamps.values())
    print(f"---Latency (first-to-last fragment): {last_recv - first_recv:.2f} seconds")
    exit(0)

def main():
    print("*Receiver listening...")
    sniff(filter=f"ip dst {RECEIVER_IP}", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()
