"""Import normalized lab NDJSON via verified TLS; never execute event content."""
from __future__ import annotations

import argparse
import base64
import getpass
import json
from pathlib import Path
import re
import ssl
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


def build_bulk(lines: list[str], index: str) -> tuple[bytes, int]:
    if not re.fullmatch(r"remcos-lab-[a-z0-9][a-z0-9-]*", index):
        raise ValueError("Use an explicitly named remcos-lab-* index")
    output = []
    seen = set()
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        item = json.loads(line)
        identity = item.get("event", {}).get("id")
        if not identity or not item.get("@timestamp") or not item.get("labels", {}).get("evidence_type"):
            raise ValueError(f"Line {number} is not a normalized, labeled lab event")
        if identity in seen:
            raise ValueError(f"Line {number} duplicates an event ID in this batch")
        seen.add(identity)
        output.append(json.dumps({"index": {"_index": index, "_id": identity}}))
        output.append(json.dumps(item, ensure_ascii=False))
    return (("\n".join(output) + "\n").encode("utf-8"), len(seen)) if seen else (b"", 0)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--url", default="https://localhost:9200")
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--username", default="elastic")
    parser.add_argument("--index", default="remcos-lab-events")
    args = parser.parse_args()
    try:
        parsed = urlsplit(args.url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("Use a credential-free https://host:port URL")
        context = ssl.create_default_context(cafile=str(args.ca))
        # Validate the whole small lab input before requesting credentials or sending a batch.
        lines = args.input.read_text(encoding="utf-8-sig").splitlines()
        payload, count = build_bulk(lines, args.index)
        if not count:
            raise ValueError("Input contains no events")
        if len(payload) > 20 * 1024 * 1024:
            raise ValueError("Split this capture into batches below 20 MiB before importing")
        password = getpass.getpass(f"Password for {args.username}: ")
        authorization = base64.b64encode(f"{args.username}:{password}".encode()).decode()
        auth_header = {"Authorization": "Basic " + authorization}
        index_url = args.url.rstrip("/") + "/" + args.index
        try:
            with urlopen(Request(index_url, headers=auth_header, method="HEAD"), context=context, timeout=30):
                pass
        except HTTPError as error:
            if error.code != 404:
                raise
            mapping_path = Path(__file__).resolve().parents[1] / "configs/elastic/offline-index.json"
            create_request = Request(index_url, data=mapping_path.read_bytes(),
                                     headers={**auth_header, "Content-Type": "application/json"}, method="PUT")
            with urlopen(create_request, context=context, timeout=30) as response:
                created = json.load(response)
            if not created.get("acknowledged"):
                raise ValueError("Index creation was not acknowledged")
        request = Request(args.url.rstrip("/") + "/_bulk?refresh=wait_for", data=payload,
                          headers={"Authorization": "Basic " + authorization,
                                   "Content-Type": "application/x-ndjson"}, method="POST")
        with urlopen(request, context=context, timeout=60) as response:
            result = json.load(response)
        failures = [item["index"] for item in result.get("items", []) if item["index"].get("status", 500) >= 300]
        if result.get("errors") or failures or len(result.get("items", [])) != count:
            print(json.dumps({"status": "failed", "expected": count, "item_failures": failures[:5]}), file=sys.stderr)
            return 1
        print(json.dumps({"status": "imported", "events": count, "index": args.index,
                          "note": "Upserted by stable event ID; not a detection result."}))
        return 0
    except (OSError, ValueError, HTTPError, URLError, KeyError, TypeError) as error:
        print(f"Import failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
