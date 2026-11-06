#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Compare generated nginx maps with Python classification on real SYNs.

The Android labels used to test collisions here are synthetic fixtures, not
capture evidence. They never enter database/os-signatures.json.
"""
import copy
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import capture_local
import osdb


def main():
    nginx = sys.argv[1]
    module = sys.argv[2] if len(sys.argv) > 2 else None
    observations = capture_local.capture(nginx, module, count=1)
    samples = capture_local.samples_from_local(observations, notes="Integration fixture; not corpus evidence")
    base = {"schema_version": 1, "database_version": "0.0.0", "license": "BSD-2-Clause", "samples": samples}
    for mode in ("corpus", "tentative", "ambiguous", "unknown"):
        data = copy.deepcopy(base)
        if mode == "ambiguous":
            for sample in samples:
                # Deliberately collide a different label with the same measured
                # features to check that nginx never silently picks one family.
                android = {k: v for k, v in sample.items() if k != "id"}
                android["family"] = "android"
                android["provenance"] = {**android["provenance"], "label_source": "Synthetic collision fixture only"}
                data["samples"].append(osdb.make_sample(**android))
        if mode == "unknown":
            data["samples"] = []
        database = osdb.Database.load(osdb.DEFAULT_DATABASE) if mode == "corpus" else osdb.Database(data)
        rows = capture_local.capture(nginx, module, count=2, maps=osdb.nginx_include(database))
        for row in rows:
            expected = database.match(row["syn"])
            if mode != "corpus":
                assert row["status"] == mode, row
            for key in ("os_family", "status", "confidence"):
                assert row[key] == expected[key], (row, expected)
            assert row["candidates"] == (",".join(expected["candidates"]) or "none"), row
            assert (row["rule"] == "none") == (expected["status"] == "unknown"), row
    print("PASS: generated nginx maps agree with Python on real IPv4/IPv6 SYNs; distributed corpus, tentative, Linux/Android collision, and unknown results")


if __name__ == "__main__":
    main()
