#!/usr/bin/env python3
"""
make_synthetic_torizon.py — generate SYNTHETIC, Torizon-Cloud-shaped two-repo
Uptane/TUF metadata for the host tests and the firmware trust anchors.

This publishes NO real account data. It mints throwaway RSA-2048 keys (one per
repo, via the openssl CLI — no Python crypto deps) and emits minimal Director +
Image repo metadata signed with RSASSA-PSS-SHA256, exactly the primitive Torizon
Cloud uses. The output exercises the same on-device verification core the real
metadata did: RSA-PSS signature verification, byte-exact canonical JSON (the
signature is over canonical(signed)), and the Image-repo meta-hash chain over the
raw served envelope bytes.

Outputs (all synthetic, safe to commit):
  test/fixtures/torizon/*.json   — the 10 role/anchor files the header is built from
  main/embed/director_root.json  — firmware Director trust anchor (== director root)
  main/embed/image_root.json     — firmware Image trust anchor (== image root)

Run this to (re)generate the fixtures; the C header is produced from these files
at test-build time by gen_torizon.py. Keys are regenerated on each run — the
committed files are the canonical synthetic set.
"""
import os, sys, json, base64, hashlib, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
OUT  = os.path.join(HERE, "torizon")
EMBED = os.path.join(REPO, "main", "embed")

# The single synthetic target both repos sign (drives the cross-repo match test).
TARGET_FP  = "aktualino-esp32-1.0.0"
TARGET_LEN = 1048576
TARGET_SHA = hashlib.sha256(b"aktualino-esp32-1.0.0 synthetic firmware image").hexdigest()

# Validity windows: valid at the tests' "now" (2026), image roles expire before
# the tests' 2030 expiry probe.
EXP_DIR = "2035-01-01T00:00:00Z"
EXP_IMG = "2028-01-01T00:00:00Z"


def canonical_bytes(obj) -> bytes:
    # Must match components/aktualino_crypto/akt_canonical.c byte-for-byte:
    # recursive key sort, minified, integers without ".0", UTF-8 passthrough.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def env_bytes(env) -> bytes:
    # The RAW served bytes the device hashes for the meta-hash chain. Stable,
    # compact serialization; the device re-canonicalizes `signed` for signature
    # checks, so the envelope's own key order is irrelevant to verification.
    return json.dumps(env, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def gen_rsa(path):
    subprocess.run(["openssl", "genrsa", "-out", path, "2048"],
                   check=True, capture_output=True)


def pub_pem(path) -> str:
    return subprocess.run(["openssl", "rsa", "-in", path, "-pubout"],
                          check=True, capture_output=True, text=True).stdout


def keyid_of(pem: str) -> str:
    # Any stable id works: the device matches signatures[].keyid to the keys map
    # by string, it does not recompute the id. sha256(SPKI PEM) is deterministic.
    return hashlib.sha256(pem.encode("utf-8")).hexdigest()


def pss_sign(keypath, msg: bytes) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as mf:
        mf.write(msg); msg_path = mf.name
    sig_path = msg_path + ".sig"
    try:
        subprocess.run(["openssl", "dgst", "-sha256", "-sign", keypath,
                        "-sigopt", "rsa_padding_mode:pss",
                        "-sigopt", "rsa_pss_saltlen:digest",
                        "-out", sig_path, msg_path],
                       check=True, capture_output=True)
        return open(sig_path, "rb").read()
    finally:
        os.unlink(msg_path)
        if os.path.exists(sig_path): os.unlink(sig_path)


def rsa_key(pem: str) -> dict:
    return {"keytype": "RSA", "keyval": {"public": pem}}


def sign_env(signed, keyid, keypath) -> dict:
    sig = pss_sign(keypath, canonical_bytes(signed))
    return {"signatures": [{"keyid": keyid, "method": "rsassa-pss-sha256",
                            "sig": base64.b64encode(sig).decode()}],
            "signed": signed}


def root_signed(keyid, pem, version, expires):
    return {
        "_type": "Root",
        "version": version,
        "expires": expires,
        "consistent_snapshot": False,
        "keys": {keyid: rsa_key(pem)},
        "roles": {r: {"keyids": [keyid], "threshold": 1}
                  for r in ("root", "snapshot", "targets", "timestamp")},
    }


def meta_entry(raw: bytes, version):
    return {"hashes": {"sha256": hashlib.sha256(raw).hexdigest()},
            "length": len(raw), "version": version}


def build_repo(keypath, keyid, pem, root_ver, tgt_ver, snap_ver, ts_ver,
               expires, targets_obj):
    """Return {name: raw_bytes} for root/targets/snapshot/timestamp with a valid
    meta-hash chain (timestamp->snapshot->{root,targets})."""
    root_env = sign_env(root_signed(keyid, pem, root_ver, expires), keyid, keypath)
    root_raw = env_bytes(root_env)

    targets_env = sign_env({"_type": "Targets", "version": tgt_ver,
                            "expires": expires, "targets": targets_obj},
                           keyid, keypath)
    targets_raw = env_bytes(targets_env)

    snap_env = sign_env({"_type": "Snapshot", "version": snap_ver,
                         "expires": expires,
                         "meta": {"root.json":    meta_entry(root_raw, root_ver),
                                  "targets.json": meta_entry(targets_raw, tgt_ver)}},
                        keyid, keypath)
    snap_raw = env_bytes(snap_env)

    ts_env = sign_env({"_type": "Timestamp", "version": ts_ver,
                       "expires": expires,
                       "meta": {"snapshot.json": meta_entry(snap_raw, snap_ver)}},
                      keyid, keypath)
    return {"root": root_raw, "targets": targets_raw,
            "snapshot": snap_raw, "timestamp": env_bytes(ts_env)}


def main():
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(EMBED, exist_ok=True)

    with tempfile.TemporaryDirectory() as wd:
        dk = os.path.join(wd, "director.key"); gen_rsa(dk)
        ik = os.path.join(wd, "image.key");    gen_rsa(ik)
        d_pem, i_pem = pub_pem(dk), pub_pem(ik)
        d_kid, i_kid = keyid_of(d_pem), keyid_of(i_pem)

        target = {TARGET_FP: {"length": TARGET_LEN,
                              "hashes": {"sha256": TARGET_SHA},
                              "custom": {"hardwareIdentifier": "aktualino-esp32",
                                         "version": 1, "targetFormat": "BINARY"}}}

        director = build_repo(dk, d_kid, d_pem, 1, 1, 1, 1, EXP_DIR, target)
        image    = build_repo(ik, i_kid, i_pem, 2, 3, 4, 5, EXP_IMG, target)

        files = {
            "anchor_director_root.json": director["root"],
            "director_root.json":        director["root"],
            "director_timestamp.json":   director["timestamp"],
            "director_snapshot.json":    director["snapshot"],
            "director_targets.json":     director["targets"],
            "anchor_image_root.json":    image["root"],
            "repo_root.json":            image["root"],
            "repo_timestamp.json":       image["timestamp"],
            "repo_snapshot.json":        image["snapshot"],
            "repo_targets.json":         image["targets"],
        }
        for name, raw in files.items():
            with open(os.path.join(OUT, name), "wb") as f:
                f.write(raw)

        # Firmware trust anchors == the repo root.json files.
        with open(os.path.join(EMBED, "director_root.json"), "wb") as f:
            f.write(director["root"])
        with open(os.path.join(EMBED, "image_root.json"), "wb") as f:
            f.write(image["root"])

    print("wrote %d synthetic fixtures to %s + 2 embed roots" % (len(files), OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
