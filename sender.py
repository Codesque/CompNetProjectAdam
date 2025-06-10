import time
from scapy.all import IP, send
from encryption import encrypt_file, sha256_hash
import random

RECEIVER_IP = "192.168.1.1"  # this must be same with the receiver.py
MTU = 1400  # Max payload per packet
FILE_PATH = "data.txt"

# in order to prevent multiple packages conflicting each other , use random ip for packets each time the script is executed
session_id = random.randint(0, 65535) 


def main():

    # read data.txt
    with open(FILE_PATH, "rb") as f:
        data = f.read()

    # encrypt data using AES encryption and SHA-256 Hashing
    print("*Encrypting data...")
    encrypted = encrypt_file(data)
    hash_val = sha256_hash(data)

    # divide the encrypted data to fragments by "MTU" sized chunks
    fragments = [encrypted[i:i+MTU] for i in range(0, len(encrypted), MTU)]
    total_fragments = len(fragments)

    print(f"*Sending {total_fragments} fragments...")

    full_start = time.time() # store the first time the fragment is sent
    for i, fragment in enumerate(fragments):
        start_time = time.time() # store the time before package manipulation

        ip_pkt = IP(dst=RECEIVER_IP, id=session_id, ttl=64)
        ip_pkt.flags = "MF" if i < total_fragments - 1 else 0
        ip_pkt.frag = i * (MTU // 8)

        # i = fragment offset
        # create header for payload and bury it in package with the fragment itself.
        payload = f"{i}/{total_fragments}|{hash_val}|".encode() + fragment
        ip_pkt = ip_pkt / payload
        send(ip_pkt, verbose=False) #  send the ip package 
        elapsed = time.time() - start_time # elapsed time is end_of_package_man - start_of_package_man 
        print(f"Fragment {i+1}/{total_fragments} sent in {elapsed:.4f} seconds")

    total_time = time.time() - full_start # calculate total elapsed time 
    print(f"---Transfer complete. Total time: {total_time:.2f} seconds")

if __name__ == "__main__":
    main()
