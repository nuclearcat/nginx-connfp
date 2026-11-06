#!/usr/bin/env python3
"""Run real TLS/TCP connections against a built nginx; no root or packages needed."""
import http.client
import json
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

from test_vectors import reference_wire

NGINX = str(Path(sys.argv[1]).resolve())
MODULE = f'load_module "{Path(sys.argv[2]).resolve()}";' if len(sys.argv) > 2 else ""
UA = 'connfp "quotes" \\ escapes'


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def context(version=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    if version:
        ctx.minimum_version = ctx.maximum_version = version
    return ctx


def request(conn, path):
    conn.request("GET", path, headers={"User-Agent": UA, "SSL-JA4": "forged",
                 "SSL-JA4T": "forged", "Connfp-Tls": "forged", "Connfp-Syn": "forged"})
    response = conn.getresponse()
    assert response.status == 200 and response.read() == b"ok\n"


def bio_request(port, path, *, ctx=None, session=None, fragmented=False, expect_retry=False):
    """Capture the exact original ClientHello and compare it to nginx's log.

    MemoryBIO also permits splitting a ClientHello across TLS records and
    receiving a session ticket for a real TLS 1.3 resumption attempt.
    """
    ctx = ctx or context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = ctx.wrap_bio(incoming, outgoing, server_side=False,
                          server_hostname="localhost", session=session)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        try:
            client.do_handshake()
        except ssl.SSLWantReadError:
            pass
        wire = outgoing.read()
        assert wire[0] == 22 and wire[5] == 1
        length = int.from_bytes(wire[3:5], "big")
        first_hello = wire[5:5 + length]
        if fragmented:
            split = 37
            # Send distinct records and TCP writes, not just split TCP packets.
            for part in (first_hello[:split], first_hello[split:]):
                sock.sendall(wire[:3] + len(part).to_bytes(2, "big") + part)
            sock.sendall(wire[5 + length:])
        else:
            sock.sendall(wire)
        server_wire = b""
        while True:
            try:
                client.do_handshake()
                sock.sendall(outgoing.read())
                break
            except ssl.SSLWantReadError:
                sock.sendall(outgoing.read())
                received = sock.recv(65536)
                assert received, "EOF during TLS handshake"
                server_wire += received
                incoming.write(received)
        if expect_retry:
            assert bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c") in server_wire, "No HelloRetryRequest observed"
        reused = client.session_reused
        client.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
        sock.sendall(outgoing.read())
        response = b""
        while not response.endswith(b"ok\n"):
            try:
                response += client.read(65536)
            except ssl.SSLWantReadError:
                received = sock.recv(65536)
                assert received, response
                incoming.write(received)
        assert response.startswith(b"HTTP/1.1 200 "), response
        return reference_wire(first_hello), client.session, reused


def main():
    with tempfile.TemporaryDirectory(prefix="nginx-connfp-") as temp:
        root = Path(temp)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"),
                        "-days", "1", "-subj", "/CN=localhost"], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        plain, tls, off, shared, retry, ipv6 = [free_port() for _ in range(6)]
        # Port allocation is inherently racy; fail startup visibly if occupied.
        assert len({plain, tls, off, shared, retry, ipv6}) == 6
        certificate = f'ssl_certificate "{root}/cert.pem"; ssl_certificate_key "{root}/key.pem";'
        log_format = ('log_format fp escape=json \'{"request":"$request","tls":"$connfp_tls",'
                      '"syn":"$connfp_syn","old_tls":"$http_ssl_ja4","old_syn":"$http_ssl_ja4t",'
                      '"registry":"$connfp_registry","connection":"$connection",'
                      '"requests":"$connection_requests","ua":"$http_user_agent",'
                      '"protocol":"$ssl_protocol"}\';')

        def config(capture=True):
            return f"""{MODULE}
daemon off;
pid {root}/nginx.pid;
error_log {root}/error.log debug;
events {{ worker_connections 128; }}
http {{
    {log_format}
    access_log {root}/access.log fp;
    tcp_save_syn {'on' if capture else 'off'};
    server {{ listen 127.0.0.1:{plain}; return 200 'ok\\n'; }}
    server {{ listen 127.0.0.1:{tls} ssl; listen [::1]:{ipv6} ssl;
        {certificate} http2 on; ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_cache shared:SSL:1m; ssl_session_tickets on;
        return 200 'ok\\n'; }}
    server {{ listen 127.0.0.1:{off}; tcp_save_syn off; return 200 'ok\\n'; }}
    server {{ listen 127.0.0.1:{shared} default_server; tcp_save_syn off; return 200 'ok\\n'; }}
    server {{ listen 127.0.0.1:{shared}; server_name named.test;
        tcp_save_syn {'on' if capture else 'off'}; return 200 'ok\\n'; }}
    server {{ listen 127.0.0.1:{retry} ssl; {certificate}
        ssl_protocols TLSv1.3; ssl_ecdh_curve secp384r1; return 200 'ok\\n'; }}
}}
"""

        conf = root / "nginx.conf"
        conf.write_text(config())
        process = subprocess.Popen([NGINX, "-p", str(root), "-c", str(conf)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read().decode())
                try:
                    with socket.create_connection(("127.0.0.1", plain), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise AssertionError("nginx failed to start")

            for p, path in ((plain, "/plain"), (off, "/off"), (shared, "/shared")):
                conn = http.client.HTTPConnection("127.0.0.1", p, timeout=5)
                request(conn, path)
                conn.close()
            for version, label in ((ssl.TLSVersion.TLSv1_2, "12"), (ssl.TLSVersion.TLSv1_3, "13")):
                conn = http.client.HTTPSConnection("localhost", tls, context=context(version), timeout=5)
                request(conn, f"/tls{label}")
                request(conn, f"/reuse{label}")
                conn.close()
            conn = http.client.HTTPSConnection("::1", ipv6, context=context(), timeout=5)
            request(conn, "/ipv6")
            conn.close()
            subprocess.run(["curl", "-fsSk", "--http2", "--noproxy", "*", "--max-time", "5",
                            f"https://localhost:{tls}/http2", f"https://localhost:{tls}/http2-reuse"],
                           check=True, stdout=subprocess.DEVNULL)
            expected = {}
            expected["/fragmented"], _, _ = bio_request(tls, "/fragmented", fragmented=True)
            expected["/retry"], _, _ = bio_request(retry, "/retry", expect_retry=True)
            ctx = context(ssl.TLSVersion.TLSv1_3)
            expected["/full"], session, reused = bio_request(tls, "/full", ctx=ctx)
            assert not reused and session.has_ticket
            expected["/resumed"], _, reused = bio_request(tls, "/resumed", ctx=ctx, session=session)
            assert reused, "TLS 1.3 session did not resume"
            assert expected["/full"] == expected["/resumed"], expected

            def rows():
                return {row["request"].split()[1]: row for line in (root / "access.log").read_text().splitlines()
                        if (row := json.loads(line))["request"]}

            for _ in range(100):
                found = rows()
                if "/resumed" in found:
                    break
                time.sleep(.02)
            for path, row in found.items():
                assert row["registry"] == "1", row
                assert row["tls"] == row["old_tls"] and row["syn"] == row["old_syn"], row
                assert "forged" not in row["tls"] + row["syn"], row
                if path == "/off":
                    assert not row["syn"], row
                else:
                    assert row["syn"].startswith("syn1:"), row
                if path in ("/plain", "/off", "/shared"):
                    assert not row["tls"], row
                if path in expected:
                    assert row["tls"] == expected[path], (row, expected[path])
            for label in ("12", "13"):
                first, second = found[f"/tls{label}"], found[f"/reuse{label}"]
                assert first["tls"].startswith(f"t{label}d") and len(first["tls"]) == 49, first
                assert first["ua"] == UA and second["ua"] == UA
                assert first["requests"] == "1" and second["requests"] == "2"
                for field in ("tls", "syn", "connection"):
                    assert first[field] == second[field], (first, second)
            assert found["/http2"]["request"] == "GET /http2 HTTP/2.0"
            assert found["/http2-reuse"]["request"] == "GET /http2-reuse HTTP/2.0"
            for field in ("tls", "syn", "connection"):
                assert found["/http2"][field] == found["/http2-reuse"][field]
            assert found["/ipv6"]["syn"].startswith("syn1:6:"), found["/ipv6"]

            # Turning off capture must reset the kernel option on inherited sockets.
            conf.write_text(config(False))
            process.send_signal(signal.SIGHUP)
            for i in range(100):
                conn = http.client.HTTPConnection("127.0.0.1", plain, timeout=5)
                request(conn, f"/reload{i}")
                conn.close()
                found = rows()
                if f"/reload{i}" in found and not found[f"/reload{i}"]["syn"]:
                    break
                time.sleep(.05)
            else:
                raise AssertionError("TCP_SAVE_SYN remained enabled after reload")
            print(json.dumps({p: found[p] for p in ("/plain", "/tls13", "/ipv6", "/resumed")}, indent=2))
            print("PASS: real IPv4/IPv6 SYN, TLS 1.2/1.3, HTTP/2, keepalive, header spoofing, JSON escaping, "
                  "fragmented ClientHello, retry, TLS resumption, shared listeners, disabled capture and reload")
        finally:
            process.send_signal(signal.SIGQUIT) if process.poll() is None else None
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.returncode:
                print((root / "error.log").read_text() if (root / "error.log").exists() else "", file=sys.stderr)
                assert process.returncode == 0, process.stderr.read().decode()


if __name__ == "__main__":
    main()
