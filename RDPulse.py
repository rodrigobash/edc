#!/usr/bin/env python3
"""
RDP Pre-Authentication Behavioral Scan
CVE-2026-21533 Assessment Methodology

Created by: Rodrigo Bash
Contact: rodrigo@bashsecurity.com.br


OVERVIEW
--------
This tool performs a non-exploit, pre-authentication behavioral assessment
against Remote Desktop Protocol (RDP) services exposed on TCP port 3389.

The objective is NOT to exploit a vulnerability. Instead, the script evaluates
how the RDP service handles malformed negotiation packets during the
pre-authentication phase.

The assessment is based on comparative protocol behavior using:

    1. A minimally valid RDP negotiation packet (baseline)
    2. A malformed negotiation packet with anomalous flags
    3. A truncated negotiation packet

No authentication, brute-force attempts, or payload delivery are performed.


PURPOSE
-------
The scan aims to:

    - Identify exposed RDP services
    - Evaluate strictness of protocol parsing
    - Detect tolerant pre-authentication behavior
    - Support risk-based prioritization
    - Provide defensible technical evidence for investigation

Hosts are classified as:

    NOT ASSESSABLE
        No observable response to baseline negotiation.

    EXPOSED BUT STRICT
        Responds to valid negotiation but rejects malformed input.

    POTENTIALLY AFFECTED
        Responds consistently to valid and malformed negotiation packets,
        indicating tolerant pre-authentication parsing behavior.


IMPORTANT LIMITATIONS
---------------------
This tool DOES NOT:

    - Confirm exploitability
    - Authenticate to the service
    - Perform credential attacks
    - Execute code
    - Trigger memory corruption
    - Verify patch level or RDP version

Behavioral tolerance does NOT equal confirmed vulnerability.

Results may be influenced by:

    - Firewalls or IPS
    - Load balancers
    - RDP gateways
    - Network segmentation
    - Timing controls or rate limiting


INTENDED USE
------------
This script is intended for authorized security assessments,
red team reconnaissance (non-invasive phase), and defensive validation.

Use only in environments where proper authorization has been granted.


CONCLUSION
----------
This PoC provides a structured, measurable, and non-destructive method
to assess RDP pre-authentication behavior potentially associated with
CVE-2026-21533.

While it does not confirm exploitability, it identifies hosts that
demonstrate protocol tolerance and may warrant deeper investigation.
"""

import socket
import ipaddress
import time
import sys

if len(sys.argv) < 2:
    print("RDPULSE - RDP Exposure Scanner\n")
    print("Passive-style detection of exposed RDP services across a given network range.\n")
    print("By Rodrigo Bash")
    print("Usage:")
    print("  python3 RDPulse.py <NET/MASK>\n")
    print("Example:")
    print("  python3 RDPulse.py 192.168.0.0/24\n")
    sys.exit(1)

main(sys.argv[1])

TIMEOUT = 3

RDP_BASELINE = bytes.fromhex(
    "030000130ee000000000000100080003000000"
)

RDP_MALFORMED = bytes.fromhex(
    "030000130ee000000000ffff080003000000"
)

RDP_TRUNCATED = bytes.fromhex(
    "0300000b0ee000"
)

def test_payload(ip, payload):
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        s.connect((str(ip), 3389))
        s.send(payload)
        data = s.recv(16)
        s.close()
        return "response" if data else "no-data"
    except socket.timeout:
        return "timeout"
    except ConnectionResetError:
        return "reset"
    except Exception:
        return "error"

def analyze(ip):
    baseline = test_payload(ip, RDP_BASELINE)

    if baseline != "response":
        return None  # NOT ASSESSABLE

    malformed = test_payload(ip, RDP_MALFORMED)
    truncated = test_payload(ip, RDP_TRUNCATED)

    return {
        "baseline": baseline,
        "malformed": malformed,
        "truncated": truncated
    }

def classify(result):
    if not result:
        return "NOT ASSESSABLE"

    if (
        result["baseline"] == "response"
        and result["malformed"] == "response"
        and result["truncated"] == "response"
    ):
        return "POTENTIALLY AFFECTED"

    return "EXPOSED BUT STRICT"

def main(cidr):
    net = ipaddress.ip_network(cidr, strict=False)

    for ip in net:
        print(f"[>] {ip}:3389")
        res = analyze(ip)

        if not res:
            print("    CVE-2026-21533  : NOT ASSESSABLE\n")
            continue

        for k, v in res.items():
            print(f"    {k:<15}: {v}")

        print(f"    CVE-2026-21533  : {classify(res)}\n")

if __name__ == "__main__":
    import sys
    main(sys.argv[1])
