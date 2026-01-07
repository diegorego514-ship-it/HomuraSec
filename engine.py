import asyncio
import socket

async def run_module(module_scan_fn, targets, args):
    family = socket.AF_UNSPEC
    if args.ipv4:
        family = socket.AF_INET
    if args.ipv6:
        family = socket.AF_INET6
    
    semaphore = asyncio.Semaphore(args.concurrency)

    tasks = [
        module_scan_fn(
            ip,
            family,
            args.timeout,
            semaphore
        )
        for ip in targets
    ]

    results = []
    for coro in asyncio.as_completed(tasks):
        results.append(await coro)
    
    return results
