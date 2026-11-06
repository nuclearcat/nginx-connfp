# nginx-connfp

TLSFP and TCP SYN fingerprinting for nginx. BSD-2-Clause, built against stock
nginx with OpenSSL. No nginx core patches, packet-capture privileges, eBPF
programs or external fingerprint service are needed.

The module observes the connection that reaches nginx. It exposes values for
logging, `map` rules and upstream headers. It does not change request policy.

## Source provenance

The C parsers, nginx integration, build configuration and tests were written for
this project. No FoxIO or nDPI implementation source, nginx core patches,
third-party fingerprint library or generated third-party source is vendored.
nginx module descriptors and API names follow nginx's public module interface.

TLSFP's algorithm and numeric reference data come from ntop's published
specification, credited in [NOTICE](NOTICE) under its CC BY 4.0 terms. The
independent C implementation and Python test implementation use the calculation
rules; they are not ports of nDPI's C code. The `syn1:` format is defined here.

BSD-2-Clause covers this project's code. External dependencies retain their
own licenses: [nginx](https://nginx.org/LICENSE) and
[OpenSSL 3.x](https://openssl-library.org/source/license/), along with the
libraries selected by your nginx build. Binary distributions must retain the
applicable dependency notices as well as this project's LICENSE and NOTICE.

Contributions must be written for this project using specifications and API
documentation. Do not submit copied or translated implementation code from
other projects. Disclose external references and dependency changes for review.

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
It does not emit JA4T values. OS hints are available through the opt-in
experimental database below.

TTL reflects routing distance. A TCP or TLS terminating proxy supplies its own
handshake, so capture belongs at the public edge. Forwarded headers cannot
restore the original handshake. Fingerprints are shared and can be imitated;
use them as one signal alongside request behavior.

## Experimental OS database

`database/os-signatures.json` contains independently collected observations
under BSD-2-Clause. Each sample records its raw SYN, known OS label, kernel,
application, network, timestamp and how the label and initial TTL were obtained.
Content-derived sample IDs detect accidental edits to that provenance. The
initial corpus contains Linux IPv4/IPv6 loopback observations from one host.
It contains no Android samples and has no measured classification accuracy.

The Python 3.10+ tools match existing observations and generate nginx maps.
They do not change the C module or existing variables. Classification is
opt-in. Every single-family match has status `tentative` and confidence
`unvalidated`. A matching Linux entry does not exclude Android or other systems
absent from the corpus. Overlapping families return `ambiguous` with all
candidates; no match returns `unknown`. OS version is never predicted.

Matching uses exact IP version, DF, window, window scale and TCP option order.
MSS is retained as evidence but ignored for matching because it can change
with network conditions. Window size remains exact; no window/MSS relationship
is inferred. A measured initial TTL permits up to 32 routed hops by default,
configurable from 0 to 64. Without a measured initial TTL, only the sample's
exact observed TTL matches. No common initial TTL is silently guessed.
These rules are experimental and require validation on independent devices
and network paths. Contributors' labels are operator assertions, not
cryptographically verified device identities. HTTP headers never supply labels.

```sh
python3 tools/osdb.py validate
python3 tools/osdb.py match 'syn1:4:64:1:65495:65495:10:2-4-8-1-3'
python3 tools/osdb.py nginx --output /tmp/connfp-osdb.conf
```

Include the generated file inside nginx's `http {}` block. It creates these
variables using `$connfp_syn` as the input, with no request-time service calls
or database-file reads:

| Variable | Value |
| --- | --- |
| `$connfp_os_family` | One tentative family, or `unknown` |
| `$connfp_os_candidates` | Comma-separated candidate families, or `none` |
| `$connfp_os_status` | `tentative`, `ambiguous` or `unknown` |
| `$connfp_os_confidence` | `unvalidated` or `none`, never a probability |
| `$connfp_os_rule` | Generated rule ID, or `none` |

The include records the database version and canonical SHA-256. Regenerate it
after reviewing a database update, then run `nginx -t` and reload nginx.
The generator combines overlapping TTL ranges before producing regexes, so
the first regex in a file cannot silently select one of several OS families.
Regex lookup cost grows with the corpus; the initial dataset is small.

For example, after installing the generated include at the path below, add
these directives inside `http {}` and select `connfp_os` in `access_log`:

```nginx
include /etc/nginx/connfp-osdb.conf;
log_format connfp_os escape=json
    '{"syn":"$connfp_syn","os_family":"$connfp_os_family",'
    '"candidates":"$connfp_os_candidates","status":"$connfp_os_status",'
    '"confidence":"$connfp_os_confidence","rule":"$connfp_os_rule"}';
```

### Collecting original samples

For the local machine, a helper starts a temporary nginx bound to loopback,
collects IPv4/IPv6 connections and records local OS/kernel metadata:

```sh
python3 tools/capture_local.py /path/to/nginx/objs/nginx \
    --notes 'Known Linux VM; direct loopback; describe virtualization here' \
    --output /tmp/local-samples.json
# Add --module /path/to/ngx_http_connfp_module.so for a dynamic build.
```

Use `--ip 4` on a host without IPv6 loopback. Samples with identical content
are deduplicated. Multiple connections from one machine do not establish
cross-device accuracy. On systems where automatic OS identity is uncertain,
use the operator-labeled collection flow instead.

For Android or another known device, enable `tcp_save_syn on;` on a controlled
edge server and include `examples/capture-location.conf` inside its server
block. Request `/__connfp_sample` from the labeled device, using a direct TCP
connection to that edge, and save the returned JSON. The request must originate
on the device being labeled. TLS-terminating proxies or cached responses would
invalidate the sample. The location sends `Cache-Control: no-store` and can be
removed after collection. Then label the saved JSON on your workstation:

```sh
python3 tools/osdb.py record --input /tmp/android-capture.json \
    --family android --os-name Android --os-version 'measured device version' \
    --kernel 'uname -r from the device' \
    --label-source 'Known handset; OS settings and device kernel inspection' \
    --application 'Browser or HTTP client and its measured version' \
    --network wifi --notes 'Device model, capture method and network details' \
    --output /tmp/android-sample.json
python3 tools/osdb.py merge /tmp/android-sample.json --version 0.1.1 \
    --output /tmp/proposed-os-signatures.json
python3 tools/osdb.py validate --database /tmp/proposed-os-signatures.json
```

`record` also accepts one dashboard JSON access-log record with `tcp_syn` and
`time` fields. If the sender's initial TTL was measured, provide
`--initial-ttl NUMBER --ttl-source 'how it was measured'`. Otherwise omit both.
Keep unknown OS versions or kernels explicitly labeled `unknown`.

Review proposed samples and their provenance before replacing the corpus.
Collect from controlled devices, VMs or contributor-owned systems; imported
signature databases and labels derived solely from User-Agent are outside this
corpus's contribution policy. Keep synthetic classifier fixtures in tests.
Before claiming Linux/Android separation, collect both populations across
devices, kernel versions and paths and measure errors on held-out devices.

## Tests

The tests need Python 3.10+, a C compiler and OpenSSL development headers:

```sh
python3 tests/test_vectors.py
python3 tests/test_osdb.py
```

The integration tests need a built nginx, Linux with SYN capture, Python 3.10+,
OpenSSL CLI, IPv6 loopback and curl with HTTP/2 support. It uses temporary
files, ephemeral loopback ports and a self-signed certificate, and stops its
nginx process on exit. It compares captured ClientHellos with an independent
Python implementation of the calculation rules.

```sh
python3 tests/integration.py /path/to/nginx/objs/nginx
python3 tests/integration_osdb.py /path/to/nginx/objs/nginx
# For a dynamically built module and an otherwise unmodified nginx binary:
python3 tests/integration.py /path/to/nginx /path/to/ngx_http_connfp_module.so
python3 tests/integration_osdb.py /path/to/nginx /path/to/ngx_http_connfp_module.so
```

Coverage includes TLS 1.2/1.3, resumption, HelloRetryRequest, fragmented
ClientHellos, HTTP/2, IPv4/IPv6 SYN, keepalive, forged headers, JSON escaping,
shared listeners, capture disabled and configuration reloads.
