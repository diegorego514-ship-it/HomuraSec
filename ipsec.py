import asyncio
import socket
import struct
import os

IKE_PORT = 500
NATT_PORT = 4500

STATE_CLOSED = "Closed"
STATE_NO_RESPONSE = "No Response"
STATE_IKE_CONFIRMED = "IKE Confirmed"

# ---------------- IKE PACKETS ----------------

def ikev2_probe():
    return struct.pack(
        "!8s8sBBBBII",
        os.urandom(8),
        b"\x00" * 8,
        33, 0x20, 34, 0x08, 0, 28
    )

def natt_probe():
    return b"\x00\x00\x00\x00" + ikev2_probe()

# ---------------- SYNC PROBE ----------------

def _udp_probe_sync(ip, port, family, timeout, retries):
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

# ---------------- ASYNC API ----------------

async def scan_ip(ip, family, timeout, retries, semaphore):
    loop = asyncio.get_running_loop()
    async with semaphore:
        s500, s4500 = await asyncio.gather(
            loop.run_in_executor(None, _udp_probe_sync, ip, IKE_PORT, family, timeout, retries),
            loop.run_in_executor(None, _udp_probe_sync, ip, NATT_PORT, family, timeout, retries),
        )

    confirmed = (s500 == STATE_IKE_CONFIRMED or s4500 == STATE_IKE_CONFIRMED)

    return {
        "ip": ip,
        "module": "ipsec",
        "ike_500": s500,
        "natt_4500": s4500,
        "service": "IPSec/IKE" if confirmed else "None"
    }
