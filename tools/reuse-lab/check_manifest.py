#!/usr/bin/env python3
"""Validate the pinned reuse-lab inputs; no third-party code is loaded."""
import json
import pathlib
import re

path = pathlib.Path(__file__).with_name("candidates.json")
data = json.loads(path.read_text(encoding="utf-8"))
assert data.get("schema_version") == 1
required = {"cloudflare", "php2shell-doctor", "p2selfcheck", "bashclub"}
assert set(data["candidates"]) == required
for key, entry in data["candidates"].items():
    assert re.fullmatch(r"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+", entry["repository"]), key
    assert re.fullmatch(r"[0-9a-f]{40}", entry["sha"]), key
    assert entry["license"] in {"MIT", "Apache-2.0"}, key
    assert re.fullmatch(r"[a-z0-9.-]+:[a-zA-Z0-9._-]+", entry["image"]), key
    assert len(entry["check"]) > 6
print("PASS: 4 allowlisted, commit-pinned candidate definitions")
