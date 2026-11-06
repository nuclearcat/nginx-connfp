#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Classifier fixtures below are synthetic and never part of the sample corpus."""
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import osdb

SYN = "syn1:4:64:1:64240:1460:7:2-4-8-1-3"


def fixture(family="linux", syn=SYN, initial_ttl=64, **overrides):
    """Construct test data, not an empirical signature or an OS assertion."""
    fields = {"family": family, "os_name": "Synthetic test fixture", "os_version": "test",
              "kernel": "test", "syn": syn, "tlsfp": None, "initial_ttl": initial_ttl,
              "captured_at": "2026-01-01T00:00:00+00:00",
              "provenance": {"method": "operator_capture", "network": "lan",
                             "label_source": "Synthetic test fixture, not capture evidence",
                             "application": "test", "notes": "Never add this fixture to the distributed corpus",
                             "ttl_source": "Synthetic initial TTL" if initial_ttl is not None else None}}
    fields.update(overrides)
    return osdb.make_sample(**fields)


def database(*samples):
    return osdb.Database({"schema_version": 1, "database_version": "0.1.0",
                         "license": "BSD-2-Clause", "samples": list(samples)})


class DatabaseTests(unittest.TestCase):
    def test_single_family_is_tentative_never_calibrated(self):
        sample = fixture()
        result = database(sample).match(SYN)
        self.assertEqual(result["os_family"], "linux")
        self.assertEqual(result["status"], "tentative")
        self.assertEqual(result["confidence"], "unvalidated")
        self.assertEqual(result["sample_ids"], [sample["id"]])

    def test_mss_changes_do_not_change_lookup(self):
        db = database(fixture())
        self.assertEqual(db.match(SYN), db.match(SYN.replace(":1460:", ":1380:")))
        self.assertEqual(db.match(SYN.replace(":64240:", ":65535:"))["status"], "unknown")
        self.assertEqual(db.match(SYN.replace(":7:", ":8:"))["status"], "unknown")

    def test_linux_android_collision_is_ambiguous_independent_of_order(self):
        linux, android = fixture(), fixture("android", syn=SYN.replace(":1460:", ":1380:"))
        first = database(linux, android).match(SYN)
        second = database(android, linux).match(SYN)
        for result in (first, second):
            self.assertEqual(result["status"], "ambiguous")
            self.assertEqual(result["os_family"], "unknown")
            self.assertEqual(result["candidates"], ["android", "linux"])
        self.assertEqual(first["sample_ids"], second["sample_ids"])

    def test_ttl_window_and_missing_ground_truth(self):
        db = database(fixture())
        for ttl in (32, 54, 64):
            self.assertEqual(db.match(SYN.replace(":64:", f":{ttl}:"))["status"], "tentative")
        for ttl in (31, 65, 128):
            self.assertEqual(db.match(SYN.replace(":64:", f":{ttl}:"))["status"], "unknown")
        self.assertEqual(db.match(SYN.replace(":64:", ":63:"), max_hops=0)["status"], "unknown")
        unknown_ttl = database(fixture(initial_ttl=None))
        self.assertEqual(unknown_ttl.match(SYN)["status"], "tentative")
        self.assertEqual(unknown_ttl.match(SYN.replace(":64:", ":63:"))["status"], "unknown")

    def test_overlapping_ttl_ranges_do_not_hide_candidates(self):
        linux = fixture()
        android = fixture("android", SYN.replace(":64:", ":32:"), 32)
        db = database(linux, android)
        self.assertEqual(db.match(SYN.replace(":64:", ":32:"))["status"], "ambiguous")
        self.assertEqual(db.match(SYN)["candidates"], ["linux"])

    def test_empty_and_unavailable(self):
        for fingerprint in (SYN, "", "-"):
            result = database().match(fingerprint)
            self.assertEqual(result["status"], "unknown")
            self.assertEqual(result["confidence"], "none")

    def test_parser_and_invalid_input(self):
        osdb.Syn.parse("syn1:6:64:-:65535:-:-:-")
        osdb.Syn.parse("syn1:4:64:1:65535:0:255:2-3-0")
        for bad in ("", "syn2:4:64:1:64240:1460:7:2-4-8-1-3", SYN + ":0",
                    SYN.replace(":64:", ":0:"), SYN.replace(":64:", ":256:"),
                    SYN.replace(":1460:", ":65536:"), SYN.replace(":1460:", ":01460:"),
                    SYN.replace(":1460:", ":-:"), SYN.replace(":7:", ":-:"),
                    SYN.replace("syn1:4:", "syn1:6:"), SYN.replace(":7:", ":256:"),
                    SYN.replace("2-4-8-1-3", "2-0-3"), SYN.replace("2-4-8-1-3", "2-2-3")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                osdb.Syn.parse(bad)
        with self.assertRaises(ValueError):
            database(fixture()).match(SYN, max_hops=True)

    def test_database_rejects_missing_provenance_tampering_and_duplicates(self):
        sample = fixture()
        for path, value in (("family", "linux; include /tmp/evil;"), ("captured_at", "2026-01-01"),
                            ("initial_ttl", True), ("tlsfp", "forged")):
            modified = copy.deepcopy(sample)
            modified[path] = value
            modified["id"] = "sample-" + osdb.checksum({k: v for k, v in modified.items() if k != "id"})[:16]
            with self.subTest(path=path), self.assertRaises(ValueError):
                database(modified)
        modified = copy.deepcopy(sample)
        del modified["provenance"]["label_source"]
        with self.assertRaises(ValueError):
            database(modified)
        with self.assertRaises(ValueError):
            database(sample, sample)
        modified = copy.deepcopy(sample)
        modified["family"] = "android"
        with self.assertRaises(ValueError):
            database(modified)

    def test_maps_and_matcher_agree_for_every_ttl(self):
        db = database(fixture(), fixture("android", SYN.replace(":64:", ":32:"), 32),
                      fixture("macos", "syn1:6:64:-:65535:-:-:-", initial_ttl=None))
        rules = osdb.nginx_rules(db)
        for ttl in range(1, 256):
            for mss in (0, 1, 1380, 1460, 65535):
                fingerprint = SYN.replace(":64:", f":{ttl}:").replace(":1460:", f":{mss}:")
                matches = [rule for rule in rules if re.fullmatch(rule["pattern"], fingerprint)]
                result = db.match(fingerprint)
                self.assertLessEqual(len(matches), 1, "map order must never decide between OS candidates")
                if result["status"] == "unknown":
                    self.assertFalse(matches)
                else:
                    self.assertEqual(matches[0]["candidates"], result["candidates"])
                    self.assertEqual(matches[0]["status"], result["status"])
        for bad_mss in ("65536", "99999", "01460", "-", "forged"):
            self.assertFalse(any(re.fullmatch(rule["pattern"], SYN.replace(":1460:", f":{bad_mss}:")) for rule in rules))
        for ttl in (63, 64, 65):
            fingerprint = f"syn1:6:{ttl}:-:65535:-:-:-"
            matches = [rule for rule in rules if re.fullmatch(rule["pattern"], fingerprint)]
            self.assertEqual(bool(matches), ttl == 64)
        self.assertEqual(osdb.nginx_include(db), osdb.nginx_include(db))

    def test_cli_record_merge_validate_and_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = root / "capture.json"
            sample = root / "sample.json"
            output = root / "database.json"
            capture.write_text(json.dumps({"tcp_syn": SYN, "time": "2026-01-01T00:00:00Z", "user_agent": "Android"}))
            command = [sys.executable, str(ROOT / "tools/osdb.py")]
            subprocess.run(command + ["record", "--input", str(capture), "--family", "linux",
                                     "--os-name", "Synthetic fixture", "--os-version", "test", "--kernel", "test",
                                     "--label-source", "Synthetic test only", "--application", "test", "--notes", "test",
                                     "--network", "lan", "--output", str(sample)], check=True)
            self.assertEqual(json.loads(sample.read_text())["family"], "linux")
            empty = root / "empty.json"
            osdb.write_json(database().data, empty)
            subprocess.run(command + ["merge", "--database", str(empty), str(sample), "--version", "0.1.1",
                                     "--output", str(output)], check=True)
            result = json.loads(subprocess.check_output(command + ["match", "--database", str(output), SYN], text=True))
            self.assertEqual(result["os_family"], "linux")
            self.assertEqual(result["database_version"], "0.1.1")
            malformed = root / "duplicate.json"
            malformed.write_text('{"samples":[],"samples":[]}')
            with self.assertRaises(ValueError):
                osdb.read_json(malformed)

    def test_distributed_corpus_has_original_observations(self):
        db = osdb.Database.load(osdb.DEFAULT_DATABASE)
        for sample in db.data["samples"]:
            self.assertNotIn("synthetic", sample["provenance"]["label_source"].lower())
            self.assertNotEqual(sample["kernel"], "test")


if __name__ == "__main__":
    unittest.main()
