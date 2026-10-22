from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from normalize_events import convert, utc_timestamp
from import_elastic import build_bulk


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.xml = (ROOT / "fixtures/synthetic-sysmon.xml").read_bytes()
        self.options = dict(case_id="SYN-001", evidence_type="synthetic", split="development")

    def test_fixture_identity_and_original_timestamp(self):
        records = convert(self.xml, **self.options)
        self.assertEqual([r["event"]["code"] for r in records], ["1", "13", "3", "13"])
        self.assertEqual(records[0]["@timestamp"], "2026-10-22T03:00:00.123Z")
        self.assertEqual(records[0]["winlog"]["time_created_raw"], "2026-10-22T03:00:00.1234567Z")
        self.assertEqual(records[0]["host"]["name"], "SYNTHETIC-WIN")
        self.assertEqual(records[0]["labels"]["evidence_type"], "synthetic")
        self.assertEqual(records[0]["winlog"]["record_id"], "1001")
        self.assertEqual(len(records[0]["labels"]["source_sha256"]), 64)

    def test_stable_identity_and_case_separation(self):
        one = convert(self.xml, **self.options)
        two = convert(self.xml, **self.options)
        other = convert(self.xml, **{**self.options, "case_id": "SYN-002"})
        self.assertEqual(one[0]["event"]["id"], two[0]["event"]["id"])
        self.assertNotEqual(one[0]["event"]["id"], other[0]["event"]["id"])

    def test_xml_decoding_and_typed_fields(self):
        records = convert(self.xml, **self.options)
        self.assertIn('"not executed"', records[0]["process"]["command_line"])
        self.assertEqual(records[2]["destination"], {"ip": "192.0.2.10", "port": 443})
        self.assertEqual(records[0]["process"]["pid"], 4242)
        self.assertEqual(records[0]["winlog"]["process"]["pid"], 4)

    def test_wrong_provider_is_not_sysmon(self):
        changed = self.xml.replace(b"Microsoft-Windows-Sysmon", b"Microsoft-Windows-Kernel-Process")
        records = convert(changed, **self.options, dataset="lab.etw")
        self.assertEqual(records[0]["event"]["dataset"], "lab.etw")
        self.assertNotIn("process", records[0])
        self.assertNotIn("registry", records[1])
        with self.assertRaises(ValueError):
            convert(changed, **self.options, dataset="windows.sysmon_operational")

    def test_missing_time_and_naive_time_fail(self):
        with self.assertRaises(ValueError):
            convert(self.xml.replace(b'SystemTime="2026-10-22T03:00:00.1234567Z"', b''), **self.options)
        with self.assertRaises(ValueError):
            utc_timestamp("2026-10-22T03:00:00")

    def test_offset_is_converted_to_utc(self):
        self.assertEqual(utc_timestamp("2026-10-22T10:00:00+07:00"), "2026-10-22T03:00:00.000Z")

    def test_unsupported_envelope_and_entity_definitions_fail(self):
        with self.assertRaises(ValueError):
            convert(b"<trace><record/></trace>", **self.options)
        document = '<!DOCTYPE Events [<!ENTITY x "example">]><Events/>'
        for encoding in ("utf-8", "utf-16"):
            with self.assertRaises(ValueError):
                convert(document.encode(encoding), **self.options)

    def test_empty_standard_export_is_explicitly_empty(self):
        self.assertEqual(convert(b"<Events/>", **self.options), [])

    def test_bulk_has_stable_ids_and_terminal_newline(self):
        records = convert(self.xml, **self.options)
        payload, count = build_bulk([json.dumps(r) for r in records], "remcos-lab-events")
        self.assertEqual(count, 4)
        self.assertTrue(payload.endswith(b"\n"))
        actions = payload.decode().splitlines()
        self.assertEqual(len(actions), 8)
        self.assertEqual(json.loads(actions[0])["index"]["_id"], records[0]["event"]["id"])

    def test_bulk_rejects_unlabeled_or_duplicate_events_and_nonlab_index(self):
        record = convert(self.xml, **self.options)[0]
        line = json.dumps(record)
        with self.assertRaises(ValueError):
            build_bulk([line, line], "remcos-lab-events")
        with self.assertRaises(ValueError):
            build_bulk([line], ".security")
        record.pop("labels")
        with self.assertRaises(ValueError):
            build_bulk([json.dumps(record)], "remcos-lab-events")

    def test_hunt_catalog_and_mapping_parse(self):
        hunts = json.loads((ROOT / "detections/elastic/hunts.json").read_text())
        self.assertEqual([h["id"] for h in hunts["hunts"]], ["R1", "R2", "R3"])
        self.assertEqual(hunts["hunts"][2]["language"], "eql")
        mapping = json.loads((ROOT / "configs/elastic/offline-index.json").read_text())
        self.assertEqual(mapping["mappings"]["properties"]["@timestamp"]["type"], "date")

    def test_splunk_macro_is_invoked_not_a_comment(self):
        for query in (ROOT / "detections/splunk").glob("*.spl"):
            self.assertEqual(query.read_text().splitlines()[0], "`remcos_sysmon`")


if __name__ == "__main__":
    unittest.main()
