#!/usr/bin/env python3
import socket
import argparse
import ipaddress

# RDP Negotiation Request (seguro, padrão)
RDP_NEGOTIATION_REQUEST = bytes.fromhex(
    "030000130ee000000000000100080003000000"
)

def check_rdp_handshake(ip, port=3389, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        s.sendall(RDP_NEGOTIATION_REQUEST)
        response = s.recv(1024)
        s.close()

        if response.startswith(b"\x03\x00"):
            print(f"[+] {ip}:{port} RDP handshake OK")
            return True
        else:
            print(f"[-] {ip}:{port} Unexpected response")
            return False

    except socket.timeout:
        print(f"[!] {ip}:{port} Timeout (filtered?)")
    except ConnectionRefusedError:
        print(f"[-] {ip}:{port} Connection refused")
    except Exception as e:
        print(f"[!] {ip}:{port} Error: {e}")

    return False

def main():
    parser = argparse.ArgumentParser(description="RDP 0-day detection PoC (safe)")
    parser.add_argument("--ip-range", required=True)
    parser.add_argument("--port", type=int, default=3389)
    args = parser.parse_args()

    network = ipaddress.ip_network(args.ip_range, strict=False)

    print(f"[i] Scanning RDP handshake on {network}\n")

    for ip in network.hosts():
        check_rdp_handshake(str(ip), args.port)

if __name__ == "__main__":
    main()
