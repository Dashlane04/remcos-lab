"""Normalize standard Windows Event XML without executing its contents.

ETW payloads differ by provider. Unknown payload fields are retained as winlog.event_data.
Only Sysmon's provider-specific payload receives the convenience ECS-like mappings.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

EVIDENCE_TYPES = ("synthetic", "benign-background", "benign-emulation", "actual-malware")
SPLITS = ("development", "validation", "holdout")
SYSMON = "Microsoft-Windows-Sysmon"


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def children(node: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in node if local_name(child.tag) == name]


def child(node: ET.Element, name: str) -> ET.Element | None:
    return next(iter(children(node, name)), None)


def text_of(node: ET.Element, name: str) -> str:
    found = child(node, name)
    return "" if found is None else (found.text or "")


def utc_timestamp(raw: str) -> str:
    if not raw:
        raise ValueError("Event has no System/TimeCreated/@SystemTime")
    parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must contain a timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def integer(value: object) -> int | None:
    try:
        return int(str(value))
    except (ValueError, TypeError):
        return None


def convert(xml_bytes: bytes, *, case_id: str, evidence_type: str, split: str,
            dataset: str | None = None) -> list[dict]:
    if evidence_type not in EVIDENCE_TYPES or split not in SPLITS:
        raise ValueError("Invalid evidence type or split")
    if not case_id.strip():
        raise ValueError("A nonempty case ID is required")
    # Reject DTD/entity declarations rather than expanding untrusted XML definitions.
    declarations = xml_bytes.replace(b"\x00", b"").upper()
    if b"<!DOCTYPE" in declarations or b"<!ENTITY" in declarations:
        raise ValueError("DTD/entity declarations are not supported")
    root = ET.fromstring(xml_bytes)
    if local_name(root.tag) == "Event":
        events = [root]
    elif local_name(root.tag) == "Events":
        events = children(root, "Event")
    else:
        raise ValueError("Expected an Event or Events XML envelope; provider-specific exports need an adapter")
    source_hash = hashlib.sha256(xml_bytes).hexdigest()
    output = []
    for event in events:
        system = child(event, "System")
        if system is None:
            raise ValueError("An Event is missing its System header")
        provider_node = child(system, "Provider")
        provider = "" if provider_node is None else provider_node.get("Name", provider_node.get("Guid", ""))
        time_node = child(system, "TimeCreated")
        timestamp = utc_timestamp("" if time_node is None else time_node.get("SystemTime", ""))
        code = text_of(system, "EventID")
        if not code or not provider:
            raise ValueError("An Event is missing its provider or event ID")
        if dataset == "windows.sysmon_operational" and provider != SYSMON:
            raise ValueError("A non-Sysmon provider cannot be relabeled as Sysmon")
        payload: dict[str, object] = {}
        event_data = child(event, "EventData")
        if event_data is not None:
            for item in event_data:
                name = item.get("Name", local_name(item.tag))
                value = "".join(item.itertext())
                if name in payload:
                    previous = payload[name]
                    payload[name] = previous + [value] if isinstance(previous, list) else [previous, value]
                else:
                    payload[name] = value
        detected_dataset = "windows.sysmon_operational" if provider == SYSMON else "windows.eventlog"
        record = {
            "@timestamp": timestamp,
            "event": {
                "id": hashlib.sha256(case_id.encode() + b"\x00" + ET.tostring(event)).hexdigest(),
                "kind": "event", "module": "windows", "code": code,
                "dataset": dataset or detected_dataset,
            },
            "host": {"name": text_of(system, "Computer") or "unknown"},
            "winlog": {
                "provider_name": provider, "channel": text_of(system, "Channel"),
                "time_created_raw": "" if time_node is None else time_node.get("SystemTime", ""),
                "record_id": text_of(system, "EventRecordID"), "event_data": payload,
            },
            "labels": {"case_id": case_id, "evidence_type": evidence_type, "split": split,
                       "source_sha256": source_hash},
        }
        user_data = child(event, "UserData")
        if user_data is not None:
            record["winlog"]["user_data_xml"] = ET.tostring(user_data, encoding="unicode")
        execution = child(system, "Execution")
        if execution is not None:
            emitter_pid = integer(execution.get("ProcessID"))
            if emitter_pid is not None:
                record["winlog"]["process"] = {"pid": emitter_pid}
        if provider == SYSMON:
            process = {}
            for source, target in (("Image", "executable"), ("CommandLine", "command_line"),
                                   ("ProcessGuid", "entity_id")):
                if isinstance(payload.get(source), str):
                    process[target] = payload[source]
            pid = integer(payload.get("ProcessId"))
            if pid is not None:
                process["pid"] = pid
            if payload.get("ParentImage"):
                process["parent"] = {"executable": payload["ParentImage"]}
            if process:
                record["process"] = process
            if isinstance(payload.get("TargetObject"), str):
                record["registry"] = {"path": payload["TargetObject"]}
            if payload.get("DestinationIp"):
                try:
                    dest_ip = str(ipaddress.ip_address(str(payload["DestinationIp"])))
                    record["destination"] = {"ip": dest_ip}
                    port = integer(payload.get("DestinationPort"))
                    if port is not None and 0 <= port <= 65535:
                        record["destination"]["port"] = port
                except ValueError:
                    pass  # Keep original payload even when a typed convenience field is invalid.
        output.append(record)
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--evidence-type", choices=EVIDENCE_TYPES, required=True)
    parser.add_argument("--split", choices=SPLITS, required=True)
    parser.add_argument("--dataset", help="For compatible tracerpt XML use lab.etw")
    args = parser.parse_args()
    try:
        records = convert(args.input.read_bytes(), case_id=args.case_id,
                          evidence_type=args.evidence_type, split=args.split, dataset=args.dataset)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # Avoid silently replacing a preserved normalized case.
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            for record in records:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(json.dumps({"records": len(records), "output": str(args.output),
                          "evidence_type": args.evidence_type}))
        return 0
    except (OSError, ValueError, ET.ParseError) as error:
        print(f"Conversion failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
