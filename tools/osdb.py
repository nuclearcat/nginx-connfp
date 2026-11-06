#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Experimental SYN database, conservative matching and nginx map generation.

No external signature data or classifier implementation is incorporated here.
"""
import argparse
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

DEFAULT_DATABASE = Path(__file__).resolve().parents[1] / "database/os-signatures.json"
FAMILIES = ("linux", "android", "windows", "macos", "ios", "freebsd", "openbsd", "netbsd", "other")
PROVENANCE_FIELDS = {"method", "network", "label_source", "application", "notes", "ttl_source"}
SAMPLE_FIELDS = {"id", "family", "os_name", "os_version", "kernel", "syn", "tlsfp",
                 "initial_ttl", "captured_at", "provenance"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def checksum(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value


def text(value, name):
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise ValueError(f"{name} must be a nonempty string of at most 2048 characters")


def number(value, low, high, name):
    if not re.fullmatch(r"0|[1-9][0-9]{0,4}", value):
        raise ValueError(f"invalid {name} in SYN fingerprint")
    return integer(int(value), low, high, name)


@dataclass(frozen=True)
class Syn:
    ip: int
    ttl: int
    df: str
    window: int
    mss: int | None
    scale: int | None
    options: str

    @classmethod
    def parse(cls, value):
        if not isinstance(value, str) or len(value) > 255:
            raise ValueError("SYN fingerprint must be a string of at most 255 characters")
        parts = value.split(":")
        if len(parts) != 8 or parts[0] != "syn1":
            raise ValueError("expected syn1:ip:ttl:df:window:mss:scale:options")
        _, ip, ttl, df, window, mss, scale, options = parts
        if ip not in ("4", "6") or df not in (("0", "1") if ip == "4" else ("-",)):
            raise ValueError("invalid IP version or DF field")
        parsed_mss = None if mss == "-" else number(mss, 0, 65535, "MSS")
        parsed_scale = None if scale == "-" else number(scale, 0, 255, "window scale")
        kinds = [] if options == "-" else [number(v, 0, 255, "option kind") for v in options.split("-")]
        if len(kinds) > 40 or 0 in kinds[:-1]:
            raise ValueError("invalid TCP option layout")
        for kind, present in ((2, parsed_mss is not None), (3, parsed_scale is not None)):
            if kinds.count(kind) != int(present):
                raise ValueError("TCP option layout disagrees with MSS or window scale")
        return cls(int(ip), number(ttl, 1, 255, "TTL"), df,
                   number(window, 0, 65535, "window"), parsed_mss, parsed_scale, options)

    @property
    def shape(self):
        # MSS is network-sensitive. Keep it in the observation, but not the
        # lookup key. Window remains exact; no inferred window/MSS formulas.
        return self.ip, self.df, self.window, self.scale, self.options


def validate_sample(sample):
    if not isinstance(sample, dict) or set(sample) != SAMPLE_FIELDS:
        raise ValueError(f"sample must have exactly these fields: {sorted(SAMPLE_FIELDS)}")
    if not re.fullmatch(r"sample-[0-9a-f]{16}", sample["id"] if isinstance(sample["id"], str) else ""):
        raise ValueError("invalid sample id")
    expected = "sample-" + checksum({k: v for k, v in sample.items() if k != "id"})[:16]
    if sample["id"] != expected:
        raise ValueError("sample id does not match its content")
    if sample["family"] not in FAMILIES:
        raise ValueError(f"family must be one of {', '.join(FAMILIES)}")
    for name in ("os_name", "os_version", "kernel", "captured_at"):
        text(sample[name], name)
    try:
        captured = datetime.fromisoformat(sample["captured_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("captured_at must be an ISO 8601 timestamp") from error
    if captured.tzinfo is None:
        raise ValueError("captured_at must include a timezone")
    syn = Syn.parse(sample["syn"])
    if sample["initial_ttl"] is not None:
        integer(sample["initial_ttl"], syn.ttl, 255, "initial_ttl")
    tlsfp = sample["tlsfp"]
    if tlsfp is not None and (not isinstance(tlsfp, str) or not re.fullmatch(
            r"t[0-9a-z]{2}[di][0-9]{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}_(?:[0-9a-f]{12})?", tlsfp)):
        raise ValueError("invalid TLSFP observation")
    provenance = sample["provenance"]
    if not isinstance(provenance, dict) or set(provenance) != PROVENANCE_FIELDS:
        raise ValueError(f"provenance must have exactly these fields: {sorted(PROVENANCE_FIELDS)}")
    if provenance["method"] not in ("local_capture", "operator_capture"):
        raise ValueError("only original local or operator-labeled captures are accepted")
    if provenance["network"] not in ("loopback", "lan", "wifi", "cellular", "vpn", "other"):
        raise ValueError("invalid capture network")
    for name in ("label_source", "application", "notes"):
        text(provenance[name], f"provenance.{name}")
    if sample["initial_ttl"] is None:
        if provenance["ttl_source"] is not None:
            raise ValueError("ttl_source requires a measured initial_ttl")
    else:
        text(provenance["ttl_source"], "provenance.ttl_source")
    return syn


def make_sample(**fields):
    sample = {"id": "sample-" + checksum(fields)[:16], **fields}
    validate_sample(sample)
    return sample


class Database:
    def __init__(self, data):
        if not isinstance(data, dict) or set(data) != {"schema_version", "database_version", "license", "samples"}:
            raise ValueError("invalid database fields")
        if type(data["schema_version"]) is not int or data["schema_version"] != 1:
            raise ValueError("unsupported database schema")
        if not isinstance(data["database_version"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", data["database_version"]):
            raise ValueError("database_version must have three numeric components")
        if data["license"] != "BSD-2-Clause":
            raise ValueError("this corpus requires original samples under BSD-2-Clause")
        if not isinstance(data["samples"], list) or len(data["samples"]) > 10000:
            raise ValueError("samples must be a list of at most 10000 observations")
        self.data = data
        self.digest = checksum(data)
        self.index = defaultdict(list)
        ids = set()
        for sample in data["samples"]:
            syn = validate_sample(sample)
            if sample["id"] in ids:
                raise ValueError("duplicate sample id")
            ids.add(sample["id"])
            self.index[syn.shape].append((sample, syn))

    @classmethod
    def load(cls, path):
        return cls(read_json(path))

    def candidates(self, shape, ttl, max_hops):
        result = []
        for sample, observed in self.index.get(shape, []):
            initial = sample["initial_ttl"]
            if (initial is None and ttl == observed.ttl) or (
                    initial is not None and 0 <= initial - ttl <= max_hops):
                result.append(sample)
        return sorted(result, key=lambda sample: sample["id"])

    def match(self, fingerprint, max_hops=32):
        integer(max_hops, 0, 64, "max_hops")
        candidates = []
        if fingerprint not in ("", "-"):
            syn = Syn.parse(fingerprint)
            candidates = self.candidates(syn.shape, syn.ttl, max_hops)
        result = summarize(candidates)
        return {**result, "sample_ids": [s["id"] for s in candidates],
                "database_version": self.data["database_version"], "database_sha256": self.digest,
                "max_hops": max_hops}


def summarize(samples):
    families = sorted({sample["family"] for sample in samples})
    return {"status": "unknown" if not families else "tentative" if len(families) == 1 else "ambiguous",
            "os_family": families[0] if len(families) == 1 else "unknown",
            "confidence": "unvalidated" if families else "none", "candidates": families}


def nginx_rules(database, max_hops=32):
    """Partition TTLs before emitting regexes, so file order never picks an OS."""
    integer(max_hops, 0, 64, "max_hops")
    rules = []
    for shape in sorted(database.index, key=str):
        groups = defaultdict(list)
        evidence = {}
        for ttl in range(1, 256):
            samples = database.candidates(shape, ttl, max_hops)
            if not samples:
                continue
            ids = tuple(sample["id"] for sample in samples)
            groups[ids].append(ttl)
            evidence[ids] = samples
        ip, df, window, scale, options = shape
        for ids, ttls in sorted(groups.items()):
            ttl_pattern = "(?:" + "|".join(map(str, ttls)) + ")"
            scale_pattern = "-" if scale is None else str(scale)
            # Accept only canonical uint16 decimal MSS values. When the MSS
            # option is absent, the corresponding field must remain '-'.
            has_mss = "2" in options.split("-")
            mss = r"(?:0|[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])" if has_mss else "-"
            pattern = f"^syn1:{ip}:{ttl_pattern}:{df}:{window}:{mss}:{scale_pattern}:{options}$"
            rule = "rule-" + checksum([shape, ttls, ids])[:16]
            rules.append({"id": rule, "pattern": pattern, "sample_ids": list(ids),
                          **summarize(evidence[ids])})
    return rules


def nginx_include(database, max_hops=32):
    rules = nginx_rules(database, max_hops)
    lines = ["# Generated by tools/osdb.py; include inside http {}.",
             "# Experimental OS hints; confidence is unvalidated, never a probability.",
             f"# database_version={database.data['database_version']} sha256={database.digest}",
             f"# max_hops={max_hops}; MSS ignored; window/scale/options remain exact.",
             "map $connfp_syn $connfp_os_rule {", "    default none;"]
    for rule in rules:
        lines.append(f'    "~{rule["pattern"]}" {rule["id"]};')
    lines.append("}")
    for variable, field, default in (("family", "os_family", "unknown"), ("status", "status", "unknown"),
                                     ("confidence", "confidence", "none"), ("candidates", "candidates", "none")):
        lines.extend((f"map $connfp_os_rule $connfp_os_{variable} {{", f"    default {default};"))
        for rule in rules:
            value = ",".join(rule[field]) if isinstance(rule[field], list) else rule[field]
            lines.append(f"    {rule['id']} {value};")
        lines.append("}")
    return "\n".join(lines) + "\n"


def read_json(path):
    if str(path) == "-":
        raw = sys.stdin.read(2_000_001)
    else:
        with Path(path).open() as stream:
            raw = stream.read(2_000_001)
    if len(raw) > 2_000_000:
        raise ValueError("JSON input is larger than 2 MB")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def write_json(value, path=None):
    content = json.dumps(value, indent=2, ensure_ascii=True) + "\n"
    if path:
        Path(path).write_text(content)
    else:
        sys.stdout.write(content)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "match", "nginx", "merge"):
        sub = commands.add_parser(name)
        sub.add_argument("--database", type=Path, default=DEFAULT_DATABASE)
        if name in ("match", "nginx"):
            sub.add_argument("--max-hops", type=int, default=32)
        if name == "match":
            sub.add_argument("fingerprint")
        if name in ("nginx", "merge"):
            sub.add_argument("--output", type=Path)
        if name == "merge":
            sub.add_argument("samples", nargs="+", type=Path)
            sub.add_argument("--version", required=True, help="new database version, e.g. 0.1.1")
    sub = commands.add_parser("record", help="label a capture from a known device; never infer labels from User-Agent")
    sub.add_argument("--input", required=True, help="capture JSON or one dashboard JSON log record; '-' reads stdin")
    sub.add_argument("--family", choices=FAMILIES, required=True)
    for name in ("os-name", "os-version", "kernel", "label-source", "application", "notes"):
        sub.add_argument("--" + name, required=True)
    sub.add_argument("--network", choices=("loopback", "lan", "wifi", "cellular", "vpn", "other"), required=True)
    sub.add_argument("--initial-ttl", type=int)
    sub.add_argument("--ttl-source")
    sub.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "record":
            observation = read_json(args.input)
            if not isinstance(observation, dict):
                raise ValueError("capture must be a JSON object")
            if "syn" in observation and "tcp_syn" in observation and observation["syn"] != observation["tcp_syn"]:
                raise ValueError("conflicting SYN observations")
            sample = make_sample(family=args.family, os_name=args.os_name, os_version=args.os_version,
                                 kernel=args.kernel, syn=observation.get("syn", observation.get("tcp_syn")),
                                 tlsfp=observation.get("tlsfp") or None, initial_ttl=args.initial_ttl,
                                 captured_at=observation.get("captured_at", observation.get("time")),
                                 provenance={"method": "operator_capture", "network": args.network,
                                             "label_source": args.label_source, "application": args.application,
                                             "notes": args.notes, "ttl_source": args.ttl_source})
            write_json(sample, args.output)
            return
        database = Database.load(args.database)
        if args.command == "validate":
            write_json({"database_version": database.data["database_version"], "database_sha256": database.digest,
                        "samples": len(database.data["samples"]),
                        "families": sorted({s["family"] for s in database.data["samples"]}),
                        "confidence": "unvalidated"})
        elif args.command == "match":
            write_json(database.match(args.fingerprint, args.max_hops))
        elif args.command == "nginx":
            content = nginx_include(database, args.max_hops)
            if args.output:
                args.output.write_text(content)
            else:
                sys.stdout.write(content)
        elif args.command == "merge":
            samples = {s["id"]: s for s in database.data["samples"]}
            for path in args.samples:
                incoming = read_json(path)
                for sample in incoming if isinstance(incoming, list) else [incoming]:
                    validate_sample(sample)
                    samples[sample["id"]] = sample
            updated = {**database.data, "database_version": args.version,
                       "samples": sorted(samples.values(), key=lambda s: s["id"])}
            Database(updated)
            write_json(updated, args.output)
    except (ValueError, OSError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
