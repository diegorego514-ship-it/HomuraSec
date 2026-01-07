import argparse
import asyncio
import json

from homurasec.core.engine import run_module
from homurasec.core.target import expand_targets
from homurasec.modules.ipsec.ipsec import scan_ip

def main():
    parser = argparse.ArgumentParser(prog="homurasec")
    parser.add_argument("module", choices=["ipsec"])
    parser.add_argument("target", nargs="+")
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=300)
    parser.add_argument("--ipv4", action="store_true")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--json", help="Output JSON")
    args = parser.parse_args()

    targets = expand_targets(args.target)

    if args.module == "ipsec":
        results = asyncio.run(run_module(scan_ip, targets, args))

    for r in results:
        print(
            f"{r['ip']:39} | "
            f"{r['service']:10} | "
            f"IKE(500): {r['ike_500']:12} | "
            f"NAT-T: {r['natt_4500']}"
        )

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)

if __name__ == "__main__":
    main()
