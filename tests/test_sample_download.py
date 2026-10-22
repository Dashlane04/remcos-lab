"""Acquisition guards tested with inert in-memory fixtures; no network or malware."""
from __future__ import annotations

import io
import contextlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import download_samples as download


class DownloadTests(unittest.TestCase):
    def test_insecure_key_prompt_fails_before_any_request_or_file_write(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "not-created"
            with patch.object(download.sys.stdin, "isatty", return_value=True), \
                    patch.object(download.getpass, "getpass", side_effect=download.getpass.GetPassWarning), \
                    patch.object(download, "api_post") as request, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    download.main(["--output", str(destination)])
                self.assertEqual(error.exception.code, 2)
                request.assert_not_called()
            self.assertFalse(destination.exists())

    def metadata(self, sha=None):
        return json.dumps({"query_status": "ok", "data": [{"sha256_hash": sha or download.SAMPLES["4.9.3"],
                                                          "file_name": "inert-test.txt"}]}).encode()

    def archive(self, encrypted_flag=False):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("inert-test.txt", "not malware; no executable")
        raw = bytearray(buffer.getvalue())
        if encrypted_flag:
            # Structural test only: set both ZIP flags; data stays inert and is never extracted.
            raw[6] |= 1
            central = raw.index(b"PK\x01\x02")
            raw[central + 8] |= 1
        return bytes(raw)

    def test_metadata_rejects_wrong_hash_and_missing_sample(self):
        with self.assertRaises(download.AcquisitionError):
            download.verify_metadata(self.metadata("0" * 64), download.SAMPLES["4.9.3"])
        with self.assertRaises(download.AcquisitionError):
            download.verify_metadata(b'{"query_status":"hash_not_found"}', download.SAMPLES["4.9.3"])

    def test_json_and_unencrypted_archives_are_not_saved(self):
        for raw in (b'{"query_status":"file_not_found"}', self.archive(), b"not a zip"):
            with self.subTest(raw=raw[:12]), tempfile.TemporaryDirectory() as directory:
                with patch.object(download, "api_post", side_effect=[self.metadata(), raw]):
                    with self.assertRaises(download.AcquisitionError):
                        download.acquire_one("4.9.3", Path(directory), "inert-test-key")
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_check_only_does_not_download_or_write_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(download, "api_post", return_value=self.metadata()) as request:
                result = download.acquire_one("4.9.3", Path(directory), "inert-test-key", check_only=True)
            self.assertEqual(request.call_count, 1)
            self.assertEqual(result["status"], "metadata_found_only")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_archive_record_distinguishes_archive_and_payload_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(download, "api_post", side_effect=[self.metadata(), self.archive(True)]):
                result = download.acquire_one("4.9.3", Path(directory), "inert-test-key")
            self.assertEqual(len(list(Path(directory).glob("*.zip"))), 1)
            self.assertEqual(len(result["archive_sha256"]), 64)
            self.assertFalse(result["payload_hash_verified_locally"])
            self.assertNotIn("inert-test-key", json.dumps(result))
            with patch.object(download, "api_post") as request:
                with self.assertRaises(download.AcquisitionError):
                    download.acquire_one("4.9.3", Path(directory), "inert-test-key")
                request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
