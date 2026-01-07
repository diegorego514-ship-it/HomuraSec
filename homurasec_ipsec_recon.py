#!/usr/bin/env python3
"""
HomuraSec IPSec Recon Engine
Async • Accurate • No false positives
"""

import argparse
import asyncio
import socket
import struct
import os
import ipaddress
import json

# ================= CONFIG =================

IKE_PORT = 500
NATT_PORT = 4500

DEFAULT_TIMEOUT = 1.5
DEFAULT_RETRIES = 2
MAX_CONCURRENCY = 300

STATE_CLOSED = 0
STATE_NO_RESPONSE = 1
STATE_IKE_CONFIRMED = 2

# ================= UTILS =================

def state_str(s):
    return {
        STATE_CLOSED: "Closed",
        STATE_NO_RESPONSE: "No Response",
        STATE_IKE_CONFIRMED: "IKE Confirmed",
    }.get(s, "Unknown")

# ================= IKE PACKETS =================

def ikev2_probe():
    return struct.pack(
        "!8s8sBBBBII",
        os.urandom(8),
        b"\x00" * 8,
        33,
        0x20,
        34,
        0x08,
        0,
        28
    )

def natt_probe():
    return b"\x00\x00\x00\x00" + ikev2_probe()

# ================= SYNC PROBE =================

def udp_probe_sync(ip, port, family, timeout, retries):
    try:
        addrinfo = socket.getaddrinfo(ip, port, family, socket.SOCK_DGRAM)
    except socket.gaierror:
        return STATE_CLOSED

    probe = ikev2_probe() if port == IKE_PORT else natt_probe()

    for af, socktype, proto, _, sa in addrinfo:
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            sock.connect(sa)
        except Exception:
            continue

        for _ in range(retries):
            try:
                sock.send(probe)
                data = sock.recv(512)

                if len(data) >= 28 and data[17] == 0x20:
                    sock.close()
                    return STATE_IKE_CONFIRMED

            except socket.timeout:
                continue
            except ConnectionRefusedError:
                sock.close()
                return STATE_CLOSED
            except Exception:
                break

        sock.close()

    return STATE_NO_RESPONSE

# ================= ASYNC LAYER =================

async def udp_probe(ip, port, family, timeout, retries, sem):
    loop = asyncio.get_running_loop()
    async with sem:
        return await loop.run_in_executor(
            None,
            udp_probe_sync,
            ip, port, family, timeout, retries
        )

async def scan_target(ip, family, timeout, retries, sem):
    s500, s4500 = await asyncio.gather(
        udp_probe(ip, IKE_PORT, family, timeout, retries, sem),
        udp_probe(ip, NATT_PORT, family, timeout, retries, sem)
    )

    confirmed = (s500 == STATE_IKE_CONFIRMED or s4500 == STATE_IKE_CONFIRMED)

    service = "IPSec/IKE" if confirmed else "None"

    return {
        "ip": ip,
        "ike_500": state_str(s500),
        "natt_4500": state_str(s4500),
        "service": service
    }

# ================= TARGET EXPANSION =================

def expand_targets(items):
    out = []
    for t in items:
        try:
            net = ipaddress.ip_network(t, strict=False)
            out.extend(str(ip) for ip in net.hosts())
        except ValueError:
            out.append(t)
    return out

# ================= ASYNC RUNNER =================

async def run_async(args):
    family = socket.AF_UNSPEC
    if args.ipv4:
        family = socket.AF_INET
    if args.ipv6:
        family = socket.AF_INET6

    raw_targets = []

    if args.target:
        raw_targets.append(args.target)

    if args.file:
        if not os.path.exists(args.file):
            print(f"[!] File not found: {args.file}")
            return
        with open(args.file) as f:
            raw_targets.extend(l.strip() for l in f if l.strip())

    targets = expand_targets(raw_targets)
    sem = asyncio.Semaphore(MAX_CONCURRENCY)

    results = []

    tasks = [
        scan_target(ip, family, args.timeout, args.retries, sem)
        for ip in targets
    ]

    for coro in asyncio.as_completed(tasks):
        res = await coro
        results.append(res)

        print(
            f"{res['ip']:39} | "
            f"{res['service']:10} | "
            f"IKE(500): {res['ike_500']:12} | "
            f"NAT-T: {res['natt_4500']}"
        )

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)

# ================= MAIN =================

def main():
    parser = argparse.ArgumentParser(description="HomuraSec IPSec Recon")
    parser.add_argument("target", nargs="?", help="IP or CIDR")
    parser.add_argument("-f", "--file", help="Targets file")
    parser.add_argument("--ipv4", action="store_true")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES)
    parser.add_argument("--json", help="Write JSON output")

    args = parser.parse_args()

    if not args.target and not args.file:
        parser.print_help()
        return

    asyncio.run(run_async(args))

if __name__ == "__main__":
    main()
