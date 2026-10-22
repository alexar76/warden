#!/usr/bin/env python3
"""The summary of an oracle.py run (the numbers the docs quote), from its full per-pair results.

usage: summarize_oracle.py ORACLE.json[.gz] SUMMARY.json [--ran-in TEXT]
--ran-in says where the run happened (default: gVisor on our server, where the 2026-10 runs were made). Stdlib only.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import sys
from pathlib import Path


def count(clean: list[dict], pairs: list[dict]) -> dict:
    nogt = [p for p in pairs if p["kind"] == "no-ground-truth"]
    return {
        "user_tasks": len(clean),
        "no_question": sum(1 for c in clean if not c["blocked"]),
        "done_clean": sum(1 for c in clean if c["utility"]),
        "pairs": len(pairs),
        "utility_under_attack": sum(1 for p in pairs if p["utility"]),
        "delivered_action": sum(1 for p in pairs if p["kind"] == "action" and p["delivered"]),
        "delivered_action_succeeded": sum(1 for p in pairs if p["kind"] == "action" and p["delivered"] and p["attack_succeeded"]),
        "no_gt_pairs": len(nogt),
        "no_gt_probed_delivered": sum(1 for p in nogt if p["delivered"] and p["first_required_call_refused"] is not None),
        "no_gt_first_call_refused": sum(1 for p in nogt if p["delivered"] and p["first_required_call_refused"]),
        "no_gt_unprobed": sum(1 for p in nogt if p["first_required_call_refused"] is None),
    }


def main() -> None:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    ran_in = sys.argv[sys.argv.index("--ran-in") + 1] if "--ran-in" in sys.argv else "gVisor container, no network, on our server"
    raw = src.read_bytes()
    data = json.loads(gzip.decompress(raw) if src.suffix == ".gz" else raw)
    out = {
        "benchmark": data["benchmark"], "benchmark_version": data["benchmark_version"], "agentdojo_package": "0.1.35",
        "attack": data["attack"], "attacker": data["attacker"], "ask_counts_as": data["ask_counts_as"],
        "ran_in": f"{ran_in}; deterministic: no model involved", "variants": {},
    }
    for v, res in data["variants"].items():
        suites = {s: count(r["clean"], r["pairs_detail"]) for s, r in res["suites"].items()}
        total = count([c for r in res["suites"].values() for c in r["clean"]], [p for r in res["suites"].values() for p in r["pairs_detail"]])
        out["variants"][v] = {"suites": suites, "total": total}
    out["full_results"] = src.name if src.suffix == ".gz" else src.name + ".gz"
    out["full_results_sha256"] = hashlib.sha256(gzip.decompress(raw) if src.suffix == ".gz" else raw).hexdigest()  # of the JSON
    dst.write_text(json.dumps(out, indent=1) + "\n")
    t = out["variants"].get("intent", {}).get("total", {})
    print({k: t.get(k) for k in ("no_question", "done_clean", "utility_under_attack", "delivered_action", "delivered_action_succeeded")})


if __name__ == "__main__":
    main()
