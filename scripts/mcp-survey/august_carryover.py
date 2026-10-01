"""Targets for re-asking the servers the 2026-08-24 run blocked, by the URL that run recorded.

The registry is paged in name order, so a fixed page cap selects a different alphabetical slice
as the registry grows; most of August's blocked servers are not in a later run's first 80 pages.
This writes them out as harvest targets so their current definitions can be collected directly:

    python3 august_carryover.py                       # -> august_targets.json
    python3 harvest_tools.py august_targets.json august_tools_raw.jsonl

The four substantiated servers are withheld by name in the August dataset and are not included.
"""
import json, os
DATA=os.path.join(os.path.dirname(os.path.abspath(__file__)),"..","..","docs","data","mcp-survey-2026-08-24.json")
aug=json.load(open(DATA))
targets={b["server"]:{"remotes":[{"type":"streamable-http","url":b["url"]}]}
         for b in aug["blocked_servers"] if b.get("url") and "withheld" not in b["server"]}
json.dump(targets, open("august_targets.json","w"), indent=2)
print("targets",len(targets),"of",len(aug["blocked_servers"]),"blocked in August")
