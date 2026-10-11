"""Offline sanity tests for the credential scan used by CI."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "credential_scan", Path(__file__).resolve().parents[1] / "scripts" / "security_guard.py"
)
assert spec is not None and spec.loader is not None
scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanner)

class ScannerTests(unittest.TestCase):
    def test_github_token(self):
        self.assertIn("github-classic-pat", scanner.scan_bytes(b"ghp_" + b"A" * 40))
    def test_private_key_marker(self):
        self.assertIn("private-key-block", scanner.scan_bytes(b"-----BEGIN PRIVATE KEY-----"))
    def test_benign_placeholder(self):
        self.assertEqual([], scanner.scan_bytes(b"API_KEY=YOUR_KEY_HERE"))

if __name__ == "__main__":
    unittest.main()
