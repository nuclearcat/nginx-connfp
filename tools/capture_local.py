#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""Collect original loopback SYN samples through a local nginx-connfp build."""
import argparse
import http.client
import json
from pathlib import Path
import platform
import signal
import socket
import subprocess
import sys
import tempfile
import time

import osdb


def quote_path(path):
    return '"' + str(Path(path).resolve()).replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def capture(nginx, module=None, *, ip_versions=(4, 6), count=3, maps=None):
    """Return connection-derived observations; never obtain an OS label remotely.

    maps is used by integration tests to exercise generated nginx maps on the
    actual saved SYN. No maps are installed by the collection CLI.
    """
    osdb.integer(count, 1, 100, "count")
    with tempfile.TemporaryDirectory(prefix="connfp-osdb-") as directory:
        root = Path(directory)
        addresses = []
        for version in ip_versions:
            if version not in (4, 6):
                raise ValueError("ip_versions must contain 4 or 6")
            host = "127.0.0.1" if version == 4 else "::1"
            with socket.socket(socket.AF_INET if version == 4 else socket.AF_INET6) as sock:
                sock.bind((host, 0))
                port = sock.getsockname()[1]
            addresses.append((host, port))
        listens = "\n".join(f"listen {host if ':' not in host else '[' + host + ']'}:{port};" for host, port in addresses)
        fields = ('{"syn":"$connfp_syn","tlsfp":"$connfp_tls",'
                  '"captured_at":"$time_iso8601"')
        if maps is not None:
            fields += (',"os_family":"$connfp_os_family","status":"$connfp_os_status",'
                       '"confidence":"$connfp_os_confidence","candidates":"$connfp_os_candidates",'
                       '"rule":"$connfp_os_rule"')
        fields += "}"
        config = root / "nginx.conf"
        load = f"load_module {quote_path(module)};" if module else ""
        config.write_text(f"""{load}
daemon off;
master_process off;
pid {quote_path(root / 'nginx.pid')};
error_log {quote_path(root / 'error.log')} notice;
events {{ worker_connections 128; }}
http {{
    access_log off;
    {maps or ''}
    server {{
        {listens}
        tcp_save_syn on;
        default_type application/json;
        location = /sample {{ return 200 '{fields}'; }}
    }}
}}
""")
        process = subprocess.Popen([str(Path(nginx).resolve()), "-p", str(root), "-c", str(config)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    details = (root / "error.log").read_text() if (root / "error.log").exists() else ""
                    raise RuntimeError(process.stderr.read().decode() + details)
                try:
                    with socket.create_connection(addresses[0], timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError("capture nginx did not start within 5 seconds")
            observations = []
            for host, port in addresses:
                for _ in range(count):
                    connection = http.client.HTTPConnection(host, port, timeout=5)
                    try:
                        connection.request("GET", "/sample")
                        response = connection.getresponse()
                        body = response.read()
                        if response.status != 200:
                            raise RuntimeError(f"capture returned HTTP {response.status}")
                        observation = json.loads(body)
                        osdb.Syn.parse(observation["syn"])
                        observations.append(observation)
                    finally:
                        connection.close()
            return observations
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGQUIT)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stderr.close()


def local_identity():
    system = platform.system()
    if system == "Android" or hasattr(sys, "getandroidapilevel") or Path("/system/bin/getprop").is_file():
        return "android", "Android", "unknown"
    if system == "Linux":
        family = "linux"
    else:
        family = {"Windows": "windows", "Darwin": "macos", "FreeBSD": "freebsd",
                  "OpenBSD": "openbsd", "NetBSD": "netbsd", "iOS": "ios"}.get(system, "other")
    try:
        release = platform.freedesktop_os_release()
    except (OSError, AttributeError):
        release = {}
    return family, release.get("NAME", system), release.get("VERSION_ID", platform.release())


def samples_from_local(observations, *, notes):
    family, name, version = local_identity()
    samples = {}
    for observation in observations:
        syn = osdb.Syn.parse(observation["syn"])
        ttl_path = Path("/proc/sys/net/ipv4/ip_default_ttl" if syn.ip == 4 else "/proc/sys/net/ipv6/conf/lo/hop_limit")
        try:
            initial_ttl = int(ttl_path.read_text().strip())
            ttl_source = f"Local read of {ttl_path} during loopback collection"
        except (OSError, ValueError):
            initial_ttl = ttl_source = None
        sample = osdb.make_sample(
            family=family, os_name=name, os_version=version, kernel=platform.release(),
            syn=observation["syn"], tlsfp=observation.get("tlsfp") or None,
            initial_ttl=initial_ttl, captured_at=observation["captured_at"],
            provenance={"method": "local_capture", "network": "loopback",
                        "label_source": "Local platform identity and /etc/os-release; TCP kernel identified by platform.release()",
                        "application": f"CPython {platform.python_version()} http.client, default socket options",
                        "notes": notes, "ttl_source": ttl_source})
        samples[sample["id"]] = sample
    return sorted(samples.values(), key=lambda sample: sample["id"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nginx", type=Path)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--ip", choices=("4", "6", "both"), default="both")
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--notes", required=True, help="describe the controlled environment and any virtualization")
    parser.add_argument("--output", type=Path, required=True, help="new file containing labeled samples")
    args = parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError("output already exists; choose a new sample file")
        versions = (4, 6) if args.ip == "both" else (int(args.ip),)
        observations = capture(args.nginx, args.module, ip_versions=versions, count=args.count)
        osdb.write_json(samples_from_local(observations, notes=args.notes), args.output)
    except (ValueError, OSError, RuntimeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
