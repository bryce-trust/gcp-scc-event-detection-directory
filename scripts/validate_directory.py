#!/usr/bin/env python3
import json
import sys

INPUT_FILE = "event_threat_detection_finding_types.json"
REQUIRED_ITEM_FIELDS = ["namespace", "id", "display_name", "detection_service"]

def fail(msg: str):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

def main():
    try:
        with open(INPUT_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except FileNotFoundError:
        fail(f"Missing {INPUT_FILE}. Run scripts/sync_threat_findings.py first.")
    except json.JSONDecodeError as e:
        fail(f"Invalid JSON in {INPUT_FILE}: {e}")

    if "items" not in payload or not isinstance(payload["items"], list):
        fail("Payload missing 'items' list")

    seen = set()
    for i, item in enumerate(payload["items"]):
        if not isinstance(item, dict):
            fail(f"Item {i} is not an object")

        for field in REQUIRED_ITEM_FIELDS:
            if field not in item or not item[field]:
                fail(f"Item {i} missing required field '{field}'")

        key = (item["namespace"], item["id"])
        if key in seen:
            fail(f"Duplicate (namespace,id) found: {key}")
        seen.add(key)

    print(f"OK: {len(payload['items'])} items validated; required fields present; no duplicates.")

if __name__ == "__main__":
    main()
