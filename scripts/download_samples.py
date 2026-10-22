"""Fetch only the two reference samples as encrypted MalwareBazaar ZIPs.

Uses the documented authenticated API. Never extracts or executes archive contents.
No external Python dependencies. Run interactively so getpass can hide the Auth-Key.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
import warnings
import zipfile


API_URL = "https://mb-api.abuse.ch/api/v1/"
MAX_DOWNLOAD = 20 * 1024 * 1024
SAMPLES = {
    "4.9.3": "0af76f2897158bf752b5ee258053215a6de198e8910458c02282c2d4d284add5",
    "7.0.4": "94ca3beeb0dfd3f02fe14de2e6fb0d26e29beb426aee911422b08465afbd2faa",
}
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "data/raw/sample-archives"


class AcquisitionError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Do not forward a personal Auth-Key to another endpoint.
        return None


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def api_post(fields, auth_key, max_bytes):
    request = urllib.request.Request(
        API_URL, data=urllib.parse.urlencode(fields).encode("ascii"), method="POST",
        headers={"Auth-Key": auth_key, "User-Agent": "RemcosResearchLab/1.0",
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=45) as response:
            chunks = []
            total = 0
            while True:
                chunk = response.read(min(65536, max_bytes - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise AcquisitionError("API response exceeded the configured size limit")
                chunks.append(chunk)
            return b"".join(chunks)
    except urllib.error.HTTPError as error:
        raise AcquisitionError(f"API HTTP {error.code}; check account access and download limits") from None
    except (urllib.error.URLError, OSError, TimeoutError):
        raise AcquisitionError("API network/TLS request failed; no archive was saved") from None


def status_text(value):
    return value if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", value) else "invalid_response"


def verify_metadata(raw, expected_sha256):
    try:
        reply = json.loads(raw)
    except (ValueError, UnicodeError):
        raise AcquisitionError("Metadata response was not valid JSON") from None
    if not isinstance(reply, dict):
        raise AcquisitionError("Unexpected metadata response structure")
    if reply.get("query_status") != "ok":
        raise AcquisitionError("Metadata lookup: " + status_text(reply.get("query_status")))
    records = reply.get("data")
    if not isinstance(records, list):
        raise AcquisitionError("Metadata response has no sample records")
    matching = [entry for entry in records if isinstance(entry, dict)
                and str(entry.get("sha256_hash", "")).lower() == expected_sha256]
    if len(matching) != 1:
        raise AcquisitionError("Metadata did not identify exactly the requested SHA-256")
    return {key: matching[0].get(key) for key in
            ("sha256_hash", "file_name", "file_size", "file_type", "signature", "first_seen")}


def inspect_archive(raw):
    if not raw.startswith(b"PK\x03\x04"):
        try:
            reply = json.loads(raw)
            status = status_text(reply.get("query_status")) if isinstance(reply, dict) else "invalid_response"
        except (ValueError, UnicodeError):
            status = "not_a_zip"
        raise AcquisitionError("Download was not a ZIP: " + status)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            files = [item for item in archive.infolist() if not item.is_dir()]
            if not files or len(files) > 10:
                raise AcquisitionError("Unexpected archive member count")
            if any(not item.flag_bits & 1 for item in files):
                raise AcquisitionError("Refusing an archive with unencrypted file contents")
            if sum(item.file_size for item in files) > MAX_DOWNLOAD:
                raise AcquisitionError("Unexpected declared uncompressed size")
            return [{"name": item.filename, "encrypted": True,
                     "declared_size": item.file_size, "compression_method": item.compress_type}
                    for item in files]
    except (zipfile.BadZipFile, OSError, ValueError):
        raise AcquisitionError("Archive structure could not be read") from None


def acquire_one(version, output, auth_key, check_only=False):
    expected = SAMPLES[version]
    destination = output / f"remcos-{version}-pro-{expected}.zip"
    if destination.exists() and not check_only:
        raise AcquisitionError("Destination already exists; choose a new output directory")
    metadata = verify_metadata(api_post({"query": "get_info", "hash": expected}, auth_key, 2 * 1024 * 1024), expected)
    result = {"reported_version": version + " Pro", "expected_payload_sha256": expected,
              "repository_metadata": metadata, "payload_hash_verified_locally": False}
    if check_only:
        return {**result, "status": "metadata_found_only"}
    raw = api_post({"query": "get_file", "sha256_hash": expected}, auth_key, MAX_DOWNLOAD)
    members = inspect_archive(raw)
    # Write only after ZIP checks; exclusive creation preserves any previous archive.
    with destination.open("xb") as stream:
        stream.write(raw)
    return {**result, "status": "encrypted_archive_saved", "archive_path": str(destination.resolve()),
            "archive_sha256": hashlib.sha256(raw).hexdigest(), "archive_bytes": len(raw),
            "archive_members": members, "acquired_utc": utc_now(),
            "verification_note": "ZIP structure/encryption flags checked only; decrypt and hash payload inside VM."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--versions", choices=tuple(SAMPLES), nargs="+", default=list(SAMPLES))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check-only", action="store_true", help="Query metadata without downloading samples")
    args = parser.parse_args(argv)
    if not sys.stdin.isatty():
        parser.error("Run in an interactive terminal; the Auth-Key is entered through a hidden prompt")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            auth_key = getpass.getpass("MalwareBazaar Auth-Key (hidden; not saved): ").strip()
    except getpass.GetPassWarning:
        parser.error("Secure input is unavailable in this terminal; refusing an echoed Auth-Key prompt")
    except (EOFError, KeyboardInterrupt):
        return 1
    if not auth_key or any(character in auth_key for character in "\r\n"):
        parser.error("A nonempty Auth-Key without line breaks is required")
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"source_api": API_URL, "started_utc": utc_now(), "check_only": args.check_only,
              "archive_password": "infected", "extracted_or_executed": False, "results": []}
    failed = False
    try:
        for version in dict.fromkeys(args.versions):
            try:
                result = acquire_one(version, args.output, auth_key, args.check_only)
                report["results"].append(result)
                print(f"{version} Pro: {result['status']}")
            except AcquisitionError as error:
                failed = True
                report["results"].append({"reported_version": version + " Pro",
                    "expected_payload_sha256": SAMPLES[version], "status": "failed", "reason": str(error)})
                print(f"{version} Pro: {error}", file=sys.stderr)
                if "HTTP 401" in str(error) or "HTTP 403" in str(error):
                    break
    finally:
        auth_key = None  # No credential is included in the report or written to disk.
        report["finished_utc"] = utc_now()
        report_path = args.output / ("acquisition-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                                     + "-" + uuid.uuid4().hex[:8] + ".json")
        with report_path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
        print(f"Acquisition report: {report_path.resolve()}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
