#!/usr/bin/env python3
"""Independent byte-level vectors and invariants; Python stdlib + C compiler."""
import ctypes
import hashlib
import os
from pathlib import Path
import random
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def word(n):
    return struct.pack("!H", n)


def vector(data, width=2):
    return len(data).to_bytes(width, "big") + data


def words(values):
    return b"".join(map(word, values))


def extension(kind, payload):
    return word(kind) + vector(payload)


def hello(ciphers, extensions, version=0x0303):
    body = word(version) + bytes(32) + b"\0" + vector(words(ciphers)) + b"\1\0"
    if extensions is not None:
        body += vector(b"".join(extension(k, v) for k, v in extensions))
    return b"\1" + len(body).to_bytes(3, "big") + body


def is_grease(v):
    return v >> 8 == v & 255 and v & 15 == 10


def hash_codes(values):
    return ",".join(f"{v:04x}" for v in values)


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def reference(ciphers, extensions, legacy=0x0303):
    """The draft's §6 calculation rules, independent of the C implementation."""
    extensions = extensions or []
    data = dict(extensions)
    ciphers = sorted(v for v in ciphers if not is_grease(v))
    ids = [k for k, _ in extensions if not is_grease(k) and k not in (21, 35, 41, 42, 44, 45)]
    unpack = lambda b: list(struct.unpack(f"!{len(b) // 2}H", b))
    versions = [v for v in unpack(data[43][1:]) if not is_grease(v)] if 43 in data else [legacy]
    version = {0x300: "s3", 0x301: "10", 0x302: "11", 0x303: "12", 0x304: "13"}.get(max(versions, default=0), "00")
    alpn = "00"
    if 16 in data and len(data[16]) > 3 and data[16][2]:
        protocol = data[16][3:3 + data[16][2]]
        # Draft §6.4 specifies lowercase first/last bytes. Non-alphanumeric
        # bytes map to 0 to keep the draft's field alphabet.
        alpn = "".join(chr(v).lower() if chr(v).isascii() and chr(v).isalnum() else "0"
                       for v in (protocol[0], protocol[-1]))
    a = f"t{version}{'d' if 0 in ids else 'i'}{min(len(ciphers), 99):02}{min(len(ids), 99):02}{alpn}"
    signatures = unpack(data[13][2:]) if 13 in data else []
    groups = sorted(v for v in unpack(data[10][2:]) if not is_grease(v)) if 10 in data else []
    return "_".join((a, digest(hash_codes(ciphers)),
                     digest(hash_codes(sorted(k for k in ids if k not in (0, 16))) + "_" + hash_codes(signatures)),
                     digest(hash_codes(groups)) if groups else ""))


def reference_wire(data):
    """Decode a well-formed captured ClientHello for integration comparison."""
    body = memoryview(data)[4:]
    legacy = int.from_bytes(body[:2], "big")
    pos = 35 + body[34]
    size = int.from_bytes(body[pos:pos + 2], "big")
    ciphers = list(struct.unpack(f"!{size // 2}H", body[pos + 2:pos + 2 + size]))
    pos += 2 + size
    pos += 1 + body[pos]
    extensions = []
    if pos < len(body):
        pos += 2
        while pos < len(body):
            kind, size = struct.unpack("!HH", body[pos:pos + 4])
            extensions.append((kind, bytes(body[pos + 4:pos + 4 + size])))
            pos += 4 + size
    return reference(ciphers, extensions, legacy)


def main():
    with tempfile.TemporaryDirectory() as tmp:
        libpath = str(Path(tmp) / "connfp.so")
        subprocess.run([os.environ.get("CC", "cc"), "-std=c99", "-Wall", "-Wextra", "-Werror",
                        "-shared", "-fPIC", "-g", str(ROOT / "src/connfp.c"), "-lcrypto", "-o", libpath], check=True)
        lib = ctypes.CDLL(libpath)
        for name in ("connfp_tls", "connfp_syn"):
            function = getattr(lib, name)
            function.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
            function.restype = ctypes.c_int

        def tls(data):
            out = ctypes.create_string_buffer(50)
            ok = lib.connfp_tls(data, len(data), out)
            return out.value.decode() if ok else None

        def syn(data):
            out = ctypes.create_string_buffer(256)
            ok = lib.connfp_syn(data, len(data), out)
            return out.value.decode() if ok else None

        ciphers = [0x1301, 0x1303, 0x1302, 0xc02f]
        ext = [(0, b""), (10, vector(words([29, 23, 24]))),
               (13, vector(words([0x804, 0x403]))),
               (16, vector(vector(b"h2", 1))), (43, vector(words([0x304, 0x303]), 1))]
        base = tls(hello(ciphers, ext))
        assert base == reference(ciphers, ext), base
        assert len(base) == 49
        # Registry v1: every ephemeral extension, not merely padding/PSK.
        for kind in (21, 35, 41, 42, 44, 45):
            assert tls(hello(ciphers, ext + [(kind, b"\0" * 7)])) == base
        for grease in range(0x0a0a, 0x10000, 0x1010):
            assert tls(hello(ciphers + [grease], ext + [(grease, b"")])) == base
        assert tls(hello(ciphers + [0x1a2a], ext)) != base  # not GREASE
        reordered = list(reversed(ext))
        reordered[3] = (10, vector(words([24, 29, 23, 0x1a1a])))
        assert tls(hello(list(reversed(ciphers)), reordered)) == base
        changed_groups = [(k, vector(words([29, 23, 25])) if k == 10 else v) for k, v in ext]
        assert tls(hello(ciphers, changed_groups)).split("_")[:3] == base.split("_")[:3]
        assert tls(hello(ciphers, changed_groups)).split("_")[3] != base.split("_")[3]
        changed_sigs = [(k, vector(words([0x403, 0x804])) if k == 13 else v) for k, v in ext]
        assert tls(hello(ciphers, changed_sigs)) != base
        for no_groups in ([], [(10, vector(words([0x0a0a])))], None):
            actual = tls(hello(ciphers, no_groups))
            assert actual == reference(ciphers, no_groups) and actual.endswith("_"), actual
        many = [0x1301] * 110
        many_ext = [(500, b"")] * 110
        assert tls(hello(many, many_ext)) == reference(many, many_ext)
        assert "99" in tls(hello(many, many_ext))[:10]
        assert digest("0017,0018,0019,001d,001e") == "0a47a2b05960"
        # Appendix A's cipher hash does not match its listed ciphers under §6.5.
        appendix_ciphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                            0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
        assert digest(hash_codes(sorted(appendix_ciphers))) == "8daaf6152771"
        original = hello(ciphers, ext)
        for end in range(len(original)):
            assert tls(original[:end]) is None
        for malformed in (
            hello([1], [(10, b"\0\3\0\1\2")]),
            hello([1], [(43, b"\3\3\4\3")]),
            hello([1], [(16, b"\0\4\5h2")]),
            hello([1], [(13, b"\0\2\4")]),
        ):
            assert tls(malformed) is None

        tcp = bytearray(20)
        tcp[12:16] = b"\xa0\x02\xfa\xf0"
        opts = bytes.fromhex("020405b40402080a000000010000000001030307")
        ipv4 = bytearray(20)
        ipv4[0], ipv4[6], ipv4[8], ipv4[9] = 0x45, 0x40, 64, 6
        packet = bytes(ipv4 + tcp) + opts
        assert syn(packet) == "syn1:4:64:1:64240:1460:7:2-4-8-1-3", syn(packet)
        ipv6 = bytearray(40)
        ipv6[0], ipv6[6], ipv6[7] = 0x60, 6, 128
        assert syn(bytes(ipv6 + tcp) + opts) == "syn1:6:128:-:64240:1460:7:2-4-8-1-3"
        ipv6[6] = 0
        assert syn(bytes(ipv6) + b"\6\0" + bytes(6) + bytes(tcp) + opts).startswith("syn1:6:")
        for end in range(len(packet)):
            assert syn(packet[:end]) is None
        broken = bytearray(packet)
        broken[41] = 0
        assert syn(bytes(broken)) is None
        broken = bytearray(packet)
        broken[33] = 0x12
        assert syn(bytes(broken)) is None
        randomizer = random.Random(1729)
        for _ in range(10000):
            data = randomizer.randbytes(randomizer.randrange(512))
            tls(data)
            syn(data)
        print("PASS: TLSFP reference vectors, sanitization, GREASE, sorting, groups, counts, malformed input; IPv4/IPv6 SYN; 10,000 random inputs")


if __name__ == "__main__":
    main()
