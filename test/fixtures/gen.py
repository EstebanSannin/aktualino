#!/usr/bin/env python3
"""
gen.py — Uptane fixture generator for the host unit tests (WORKPLAN T1.3).

Mints a fresh Ed25519 key (via the openssl CLI — no Python crypto deps needed),
emits a root.json `signed` object + a Director targets envelope signed over
canonical(signed), plus tampered / expired / threshold variants, and a
canonical-JSON cross-check pair. Everything is written as C string literals into
a generated header so the C tests are self-contained.

CRUCIAL PROPERTY: this file's canonical-JSON implementation must agree
byte-for-byte with the C `akt_canonical_json` (SPEC Appendix A). The test
`test_canonical` asserts exactly that on CANON_CROSSCHECK_*, and every signature
fixture is signed over *this* canonical output — so if the two disagree, the C
signature verification fails. That cross-check is itself a deliverable.

Usage: gen.py <output_header_path>
"""
import sys, os, json, hashlib, subprocess, tempfile, base64

# --- canonical JSON: recursive key-sort, arrays preserved, minified, ints ---
def canonical_bytes(obj) -> bytes:
    # json.dumps with sort_keys sorts by Unicode code point == bytewise for
    # ASCII == circe's UTF-16 sortBy for ASCII keys. separators minify; Python
    # ints render without ".0"; ensure_ascii=False passes UTF-8 through, matching
    # circe noSpaces / the C serializer.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")

# --- openssl-backed Ed25519 -------------------------------------------------
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")

def gen_ed25519(workdir, name):
    priv = os.path.join(workdir, f"{name}.pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", priv],
                   check=True, capture_output=True)
    der = subprocess.run(["openssl", "pkey", "-in", priv, "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    pub = der[-32:]
    keyid = hashlib.sha256(ED25519_SPKI_PREFIX + pub).hexdigest()
    return {"priv": priv, "pub": pub, "pub_hex": pub.hex(), "keyid": keyid}

def sign(priv_path, msg: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as mf:
        mf.write(msg); msg_path = mf.name
    sig_path = msg_path + ".sig"
    try:
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", priv_path,
                        "-rawin", "-in", msg_path, "-out", sig_path],
                       check=True, capture_output=True)
        with open(sig_path, "rb") as f:
            sig = f.read()
    finally:
        os.unlink(msg_path)
        if os.path.exists(sig_path): os.unlink(sig_path)
    assert len(sig) == 64, f"expected 64-byte ed25519 sig, got {len(sig)}"
    return sig

def tuf_key(pub_hex):
    return {"keytype": "ED25519", "keyval": {"public": pub_hex}}

def make_envelope(signed_obj, keyid, priv_path, tamper=False):
    sig = sign(priv_path, canonical_bytes(signed_obj))
    if tamper:
        sig = sig[:-1] + bytes([sig[-1] ^ 0xFF])
    return {
        "signatures": [{"keyid": keyid, "method": "ed25519",
                        "sig": base64.b64encode(sig).decode()}],
        "signed": signed_obj,
    }

# --- C literal emitter (octal escapes: unambiguous, no hex-run problem) ------
def c_str(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    out = ['"']
    for b in data:
        if b == 0x22:   out.append('\\"')
        elif b == 0x5c: out.append('\\\\')
        elif 0x20 <= b <= 0x7e: out.append(chr(b))
        else:           out.append('\\%03o' % b)
    out.append('"')
    return "".join(out)

def emit_json(name, obj):
    return f"static const char {name}[] =\n    {c_str(json.dumps(obj, ensure_ascii=True))};\n"

def emit_bytes_str(name, data):
    return f"static const char {name}[] =\n    {c_str(data)};\n"

# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) != 2:
        print("usage: gen.py <output_header>", file=sys.stderr); sys.exit(2)
    out_path = sys.argv[1]

    HWID = "aktualino-esp32"
    OTHER_HWID = "other-board-imx8"
    TARGET_PATH = "aktualino/1.0.2/aktualino-app.bin"
    TARGET_LEN = 1048576
    TARGET_VER = 2
    TARGET_SHA = hashlib.sha256(b"pretend-firmware-image-v2").hexdigest()

    with tempfile.TemporaryDirectory() as wd:
        k1 = gen_ed25519(wd, "k1")
        k2 = gen_ed25519(wd, "k2")  # second key, for the threshold-2 fixture

        # ---- root.json signed (threshold 1) ----
        def root_signed(targets_keyids, targets_threshold, keys):
            return {
                "_type": "Root",
                "version": 1,
                "expires": "2099-12-31T00:00:00Z",
                "consistent_snapshot": False,
                "keys": {k: tuf_key(v) for k, v in keys.items()},
                "roles": {
                    "root":      {"keyids": [k1["keyid"]], "threshold": 1},
                    "snapshot":  {"keyids": [k1["keyid"]], "threshold": 1},
                    "targets":   {"keyids": targets_keyids, "threshold": targets_threshold},
                    "timestamp": {"keyids": [k1["keyid"]], "threshold": 1},
                },
            }

        root_t1 = root_signed([k1["keyid"]], 1, {k1["keyid"]: k1["pub_hex"]})
        root_t2 = root_signed([k1["keyid"], k2["keyid"]], 2,
                              {k1["keyid"]: k1["pub_hex"], k2["keyid"]: k2["pub_hex"]})

        # ---- Director targets signed ----
        def targets_signed(expires):
            return {
                "_type": "Targets",
                "version": 5,
                "expires": expires,
                "targets": {
                    TARGET_PATH: {
                        "length": TARGET_LEN,
                        "hashes": {"sha256": TARGET_SHA},
                        "custom": {"hardwareIdentifier": HWID,
                                   "version": TARGET_VER,
                                   "targetFormat": "BINARY"},
                    },
                    "other/board/img.bin": {
                        "length": 4096,
                        "hashes": {"sha256": hashlib.sha256(b"other").hexdigest()},
                        "custom": {"hardwareIdentifier": OTHER_HWID, "version": 9},
                    },
                },
            }

        good = targets_signed("2099-12-31T00:00:00Z")
        expired = targets_signed("2000-01-01T00:00:00Z")

        env_good     = make_envelope(good,    k1["keyid"], k1["priv"])
        env_tampered = make_envelope(good,    k1["keyid"], k1["priv"], tamper=True)
        env_expired  = make_envelope(expired, k1["keyid"], k1["priv"])

        # ---- canonical JSON cross-check (nesting, order, ints, escaping, UTF-8) ----
        crosscheck = {
            "zeta": 1,
            "alpha": {"z": [3, 2, 1], "a": "he said \"hi\"\n\tok", "m": True},
            "beta": [{"b": 2, "a": 1}, {"d": 4, "c": 3}],
            "num": 1048576,
            "neg": -7,
            "unicode": "café ☃",
            "empty_obj": {},
            "empty_arr": [],
            "nullv": None,
        }
        crosscheck_canon = canonical_bytes(crosscheck)

        # ---- write header ----
        lines = []
        lines.append("/* GENERATED by test/fixtures/gen.py — DO NOT EDIT. */\n")
        lines.append("#pragma once\n\n")
        lines.append(f"#define FIXTURE_NOW 1800000000L /* ~2027-01, after expired(2000) & before good(2099) */\n")
        lines.append(f"#define FIXTURE_HWID {c_str(HWID)}\n")
        lines.append(f"#define FIXTURE_OTHER_HWID {c_str(OTHER_HWID)}\n")
        lines.append(f"#define FIXTURE_TARGET_PATH {c_str(TARGET_PATH)}\n")
        lines.append(f"#define FIXTURE_TARGET_LEN {TARGET_LEN}L\n")
        lines.append(f"#define FIXTURE_TARGET_VERSION {TARGET_VER}L\n")
        lines.append(f"#define FIXTURE_TARGET_SHA256_HEX {c_str(TARGET_SHA)}\n")
        lines.append(f"#define FIXTURE_TARGETS_VERSION 5L\n\n")
        lines.append(emit_json("FIXTURE_ROOT_SIGNED", root_t1))
        lines.append(emit_json("FIXTURE_ROOT_SIGNED_THRESHOLD2", root_t2))
        lines.append(emit_json("FIXTURE_TARGETS_ENVELOPE_GOOD", env_good))
        lines.append(emit_json("FIXTURE_TARGETS_ENVELOPE_TAMPERED", env_tampered))
        lines.append(emit_json("FIXTURE_TARGETS_ENVELOPE_EXPIRED", env_expired))
        lines.append(emit_json("FIXTURE_TARGETS_SIGNED_GOOD", good))
        lines.append("\n/* canonical-JSON cross-check: parse INPUT, canonicalize, compare EXPECTED */\n")
        lines.append(emit_json("FIXTURE_CANON_INPUT", crosscheck))
        lines.append(emit_bytes_str("FIXTURE_CANON_EXPECTED", crosscheck_canon))

        with open(out_path, "w") as f:
            f.write("".join(lines))

    print(f"gen.py: wrote {out_path}", file=sys.stderr)

if __name__ == "__main__":
    main()
