# nginx-connfp

TLSFP and TCP SYN fingerprinting for nginx. BSD-2-Clause, built against stock
nginx with OpenSSL. No nginx core patches, packet-capture privileges, eBPF
programs or external fingerprint service are needed.

The module observes the connection that reaches nginx. It exposes values for
logging, `map` rules and upstream headers. It does not change request policy.

## Build

Tested with nginx 1.30.6 and OpenSSL 3.5.5. Build with the same source version,
compiler options and dependencies as your nginx binary.

```sh
cd /path/to/nginx-source
./configure --with-http_ssl_module --with-http_v2_module \
    --add-module=/path/to/nginx-connfp
make -j4
```

For a dynamic module, use `--with-compat --add-dynamic-module=...` instead of
`--add-module=...`, run `make modules`, and load `ngx_http_connfp_module.so`
with `load_module`. OpenSSL is required. Other TLS implementations are untested.

nginx-connfp uses OpenSSL's message callback to observe complete, reassembled
ClientHellos. nginx's own ClientHello callback continues to select virtual
servers and certificates. Another module installing an OpenSSL message callback
on the same SSL context conflicts with this module; use only one such observer.

## Configuration

```nginx
http {
    log_format connfp escape=json
        '{"peer":"$remote_addr","request":"$request",'
        '"tlsfp":"$connfp_tls","syn":"$connfp_syn",'
        '"tlsfp_registry":"$connfp_registry"}';

    server {
        listen 443 ssl;
        ssl_certificate /etc/nginx/ssl/fullchain.pem;
        ssl_certificate_key /etc/nginx/ssl/privkey.pem;
        tcp_save_syn on;
        access_log /var/log/nginx/access.log connfp;
    }
}
```

| Variable | Value |
| --- | --- |
| `$connfp_tls` | ntop TLSFP, four fields, up to 49 characters |
| `$connfp_syn` | Versioned `syn1:` format described below |
| `$connfp_registry` | `1`, the TLSFP ephemeral extension registry version |
| `$http_ssl_ja4` | Compatibility alias for `$connfp_tls` |
| `$http_ssl_ja4t` | Compatibility alias for `$connfp_syn` |

Aliases preserve the two variable names used by KernelCI dashboard PR #2219.
They return the new formats. Existing JA4/JA4T allowlists, parsers and expected
values need migration. The other FoxIO suite variables, including JA4H,
JA4one and unhashed `_string` variants, are outside this module's scope.
Do not load both modules into the same nginx configuration.

`tcp_save_syn on|off` is accepted at `http` and `server` scope and defaults to
`off`. On Linux, it sets `TCP_SAVE_SYN` on the listening socket before workers
accept connections, and obtains the original packet with `TCP_SAVED_SYN`.
Enabling it in any virtual server sharing a socket enables collection for that
socket. Separate listeners isolate capture and its memory cost. Disabling it
on reload resets inherited sockets; existing connections retain cached values.
During a graceful reload, the new setting also affects accepts in old workers
that still share the socket.

SYN capture is unavailable on unsupported builds/kernels, with SYN cookies,
Unix sockets or QUIC. Socket-option failures produce a warning when enabling
capture. Unavailable fingerprints are empty strings. The module caches results
in the connection's pool, including empty results, so keepalive and HTTP/2
requests reuse the original values. Client-supplied HTTP headers cannot set
any of these variables.

## TLSFP

This follows the [ntop TLSFP draft 0.1, Registry v1](https://github.com/ntop/nDPI/blob/a01ea9463125b24dcf7b37d71274291dc4a95753/fingerprint/nDPI_TLS_Fingerprint.md).
See [NOTICE](NOTICE) for attribution. The first ClientHello is retained across
TLS 1.3 HelloRetryRequest and session reuse. It includes the offered maximum
TLS version, SNI presence, filtered cipher/extension counts, ALPN, and truncated
SHA-256 hashes of sorted cipher suites, sanitized extensions with advertised
signature algorithms, and sorted supported groups. Duplicate list values are
retained and displayed counts are capped at 99 without truncating hash inputs.

Registry v1 excludes extension IDs 21, 35, 41, 42, 44 and 45. GREASE ciphers,
extensions, groups and supported versions are filtered. Signature algorithms
remain in advertised order as specified in section 6.6. Plain HTTP has no TLSFP.
Only TLS over TCP is supported; there is no QUIC or DTLS fingerprinting.

The draft contains inconsistencies. This implementation follows section 6's
calculation rules and Appendix B's registry rather than its illustrative
fingerprints. Appendix A lists ephemeral extension IDs in its sanitized list,
and the cipher hash printed there does not match its listed ciphers. The
GREASE test requires equal bytes as in RFC 8701; the draft's purported bitmask
equivalence would incorrectly filter values such as `0x1a2a`. Non-alphanumeric
ALPN endpoint bytes become `0` to preserve the field alphabet. An absent or
fully GREASE-filtered supported-groups list yields a trailing empty fourth field.
Malformed or unavailable ClientHellos yield an empty fingerprint, with a
diagnostic in nginx's debug log. No partial fingerprint is used for matching.

## SYN format v1

```text
syn1:ip_version:ttl_or_hop_limit:df:window:mss:window_scale:option_kinds
syn1:4:64:1:64240:1460:7:2-4-8-1-3
```

Numeric fields are decimal. `df` is the IPv4 Don't Fragment bit or `-` for
IPv6. Missing MSS, window scale or options use `-`. TCP option kinds retain
wire order, including NOP and the first EOL, but omit option payloads such as
timestamps. Window scale is the advertised byte, before any kernel clamping.
IPv4 options and IPv6 hop-by-hop, routing, destination and AH headers are
skipped to find TCP. Fragmented packets, malformed options and saved headers
larger than 4096 bytes yield an empty value. This is this project's own format.
It does not emit JA4T values or infer an operating-system name.

TTL reflects routing distance. A TCP or TLS terminating proxy supplies its own
handshake, so capture belongs at the public edge. Forwarded headers cannot
restore the original handshake. Fingerprints are shared and can be imitated;
use them as one signal alongside request behavior.

## Tests

The parser tests need Python 3, a C compiler and OpenSSL development headers:

```sh
python3 tests/test_vectors.py
```

The integration test needs a built nginx, Linux with SYN capture, Python 3,
OpenSSL CLI, IPv6 loopback and curl with HTTP/2 support. It uses temporary
files, ephemeral loopback ports and a self-signed certificate, and stops its
nginx process on exit. It compares captured ClientHellos with an independent
Python implementation of the calculation rules.

```sh
python3 tests/integration.py /path/to/nginx/objs/nginx
# For a dynamically built module and an otherwise unmodified nginx binary:
python3 tests/integration.py /path/to/nginx /path/to/ngx_http_connfp_module.so
```

Coverage includes TLS 1.2/1.3, resumption, HelloRetryRequest, fragmented
ClientHellos, HTTP/2, IPv4/IPv6 SYN, keepalive, forged headers, JSON escaping,
shared listeners, capture disabled and configuration reloads.
