# report.py
import json
from typing import Any, Iterable

def save_text(results: Iterable[Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in results:
            if isinstance(r, (list, tuple)) and len(r) >= 4:
                ip, s500, s4500, service = r[0], r[1], r[2], r[3]
                f.write(f"Target: {ip:39} | IKE(500): {s500:14} | NAT-T(4500): {s4500:14} | Service: {service}\n")
            else:
                f.write(f"{r}\n")

def save_json(results: Any, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)