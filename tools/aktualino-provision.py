#!/usr/bin/env python3
"""
aktualino-provision.py — build an NVS image that pre-provisions an ESP32 for
Torizon Cloud (SPEC §6.1 injector; docs/torizon-cloud-validation.md Approach A).

--torizon mode (this file's focus)
==================================
Given a Torizon Cloud `credentials.zip` (and, optionally, an already-minted
per-device `device.zip`), emit an NVS partition image carrying:

  namespace akt_id   (device identity — read by aktualino_store):
    uuid    = device UUID (client-cert CN)
    gw_url  = https://dgw.torizon.io   (from device.zip/gateway.url)
    cert    = client.pem  (mTLS client cert, per-device)
    pkey    = pkey.pem     (mTLS client key, EC P-256)  [SECRET]
    cacert  = root.crt     (server CA to pin for the gateway)
    ecu_ser = generated primary ECU serial (alphabetic, ValidEcuIdentifier)

  namespace akt_tuf  (TUF trust store — read by aktualino_core trust anchor):
    director_root = credentials.zip/director.root.json  (Director RSA root)
    image_root    = credentials.zip/root.json           (Image RSA root)
    ver_root      = director root version   (anti-rollback baseline)
    ver_img_root  = image root version

Because aktualino_core.trust_anchor_init prefers a persisted NVS root over the
firmware-embedded root, seeding director_root/image_root pins the device to this
account's Torizon RSA anchors; a device flashed WITHOUT this image falls back to
the firmware-embedded roots.

The device is left UN-provisioned (no `prov` flag): on first boot it finds the
injected creds and self-registers its ECU + first manifest against
dgw.torizon.io (aktualino_prov_run).

If no device.zip is supplied, the tool mints one: OAuth2 client_credentials from
provision.json -> POST https://app.torizon.io/api/accounts/devices -> device.zip.
(A device is usually already registered; pass --device-zip to reuse it and avoid
creating duplicates.)

Output: <out>/nvs.csv, <out>/files/*, and <out>/torizon-nvs.bin (when an
nvs_partition_gen.py is reachable via --idf-path or $IDF_PATH; otherwise the
exact generate command is printed for container-side execution).

NEVER commit anything this writes: pkey.pem is a device secret.
"""
import argparse
import io
import json
import os
import random
import shutil
import subprocess
import sys
import zipfile


def log(msg):
    print("[aktualino-provision] %s" % msg, file=sys.stderr)


def die(msg):
    print("[aktualino-provision] ERROR: %s" % msg, file=sys.stderr)
    sys.exit(1)


def read_zip_member(zf, name):
    try:
        return zf.read(name)
    except KeyError:
        return None


def gen_ecu_serial(rng):
    """Alphabetic ECU serial (ValidEcuIdentifier: alphabetic, length 10-64).

    "aktualino" + 24 lowercase a-p letters = 33 chars. The random tail keeps it
    unique so a re-provisioned board never collides with a stale ECU record."""
    tail = "".join(chr(ord("a") + rng.randrange(16)) for _ in range(24))
    return "aktualino" + tail


def mint_device_zip(cred_zip_bytes, device_id, device_name):
    """OAuth2 client_credentials -> POST /api/accounts/devices -> device.zip."""
    import urllib.request
    import urllib.parse

    with zipfile.ZipFile(io.BytesIO(cred_zip_bytes)) as zf:
        prov = json.loads(read_zip_member(zf, "provision.json"))
    client_id = prov["client_id"]
    client_secret = prov["secret"]
    token_endpoint = prov["token_endpoint"]

    # 1. token
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }).encode()
    req = urllib.request.Request(token_endpoint, data=data,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as r:
        tok = json.loads(r.read())["access_token"]
    log("minted OAuth2 access token")

    # 2. register device -> device.zip (binary)
    body = json.dumps({"device_id": device_id, "device_name": device_name}).encode()
    req = urllib.request.Request("https://app.torizon.io/api/accounts/devices",
                                 data=body,
                                 headers={"Authorization": "Bearer " + tok,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        zbytes = r.read()
    log("registered device %s -> device.zip (%d bytes)" % (device_id, len(zbytes)))
    return zbytes


def csv_field(v):
    """Quote a CSV value that may contain commas (paths won't, but be safe)."""
    if "," in v or '"' in v:
        return '"' + v.replace('"', '""') + '"'
    return v


def main():
    ap = argparse.ArgumentParser(description="Build a pre-provisioning NVS image.")
    ap.add_argument("--torizon", action="store_true", required=True,
                    help="Torizon Cloud mode (the only mode implemented here).")
    ap.add_argument("--credentials", required=True,
                    help="Path to Torizon Cloud credentials.zip.")
    ap.add_argument("--device-zip", default=None,
                    help="Existing per-device device.zip to REUSE (recommended).")
    ap.add_argument("--hwid", default="aktualino-esp32",
                    help="Hardware id for the ECU (default aktualino-esp32).")
    ap.add_argument("--device-id", default=None,
                    help="device_id when minting a new device.zip (no reuse).")
    ap.add_argument("--out", required=True, help="Output directory.")
    ap.add_argument("--nvs-size", default="0x6000",
                    help="NVS partition size (must match partitions.csv; default 0x6000).")
    ap.add_argument("--idf-path", default=os.environ.get("IDF_PATH"),
                    help="ESP-IDF path (to locate nvs_partition_gen.py).")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed for the ECU serial (reproducible builds).")
    args = ap.parse_args()

    rng = random.Random(args.seed)

    with open(args.credentials, "rb") as f:
        cred_bytes = f.read()
    with zipfile.ZipFile(io.BytesIO(cred_bytes)) as zf:
        director_root = read_zip_member(zf, "director.root.json")
        image_root = read_zip_member(zf, "root.json")
    if not director_root or not image_root:
        die("credentials.zip missing director.root.json or root.json")

    # ---- per-device creds: reuse or mint ----
    if args.device_zip:
        with open(args.device_zip, "rb") as f:
            dev_bytes = f.read()
        log("reusing device.zip %s" % args.device_zip)
    else:
        dev_id = args.device_id or ("aktualino-esp32-%06x" % rng.randrange(1 << 24))
        dev_bytes = mint_device_zip(cred_bytes, dev_id, dev_id)

    with zipfile.ZipFile(io.BytesIO(dev_bytes)) as zf:
        client_pem = read_zip_member(zf, "client.pem")
        pkey_pem = read_zip_member(zf, "pkey.pem")
        root_crt = read_zip_member(zf, "root.crt")
        gateway_url = read_zip_member(zf, "gateway.url")
        info = read_zip_member(zf, "info.json")
    for nm, val in [("client.pem", client_pem), ("pkey.pem", pkey_pem),
                    ("root.crt", root_crt), ("gateway.url", gateway_url),
                    ("info.json", info)]:
        if not val:
            die("device.zip missing %s" % nm)

    uuid = json.loads(info)["deviceUuid"]
    gw = gateway_url.decode().strip()
    ecu_serial = gen_ecu_serial(rng)

    # root versions (for the anti-rollback baseline).
    dir_root_v = json.loads(director_root)["signed"]["version"]
    img_root_v = json.loads(image_root)["signed"]["version"]

    # ---- stage files + CSV ----
    out = os.path.abspath(args.out)
    files = os.path.join(out, "files")
    os.makedirs(files, exist_ok=True)

    def stage(name, data):
        p = os.path.join(files, name)
        with open(p, "wb") as f:
            f.write(data)
        return os.path.join("files", name)  # CSV-relative (run gen from <out>)

    p_cert = stage("client.pem", client_pem)
    p_pkey = stage("pkey.pem", pkey_pem)
    p_ca = stage("root.crt", root_crt)
    p_dir_root = stage("director_root.json", director_root)
    p_img_root = stage("image_root.json", image_root)

    # nvs_partition_gen CSV. `file`+`string` NUL-terminates (fits nvs_get_str);
    # roots are `file`+`binary` blobs (director root is 4754 B > the ~4000-byte
    # NVS string cap, and aktualino_core reads them by explicit length).
    rows = [
        "key,type,encoding,value",
        "akt_id,namespace,,",
        "uuid,data,string,%s" % csv_field(uuid),
        "gw_url,data,string,%s" % csv_field(gw),
        "cert,file,string,%s" % csv_field(p_cert),
        "pkey,file,string,%s" % csv_field(p_pkey),
        "cacert,file,string,%s" % csv_field(p_ca),
        "ecu_ser,data,string,%s" % csv_field(ecu_serial),
        "akt_tuf,namespace,,",
        "director_root,file,binary,%s" % csv_field(p_dir_root),
        "image_root,file,binary,%s" % csv_field(p_img_root),
        "ver_root,data,i32,%d" % dir_root_v,
        "ver_img_root,data,i32,%d" % img_root_v,
    ]
    csv_path = os.path.join(out, "nvs.csv")
    with open(csv_path, "w") as f:
        f.write("\n".join(rows) + "\n")

    log("device uuid   : %s" % uuid)
    log("gateway       : %s" % gw)
    log("ecu serial    : %s" % ecu_serial)
    log("hardware id   : %s" % args.hwid)
    log("anchors       : director root v%d, image root v%d" % (dir_root_v, img_root_v))
    log("wrote CSV     : %s" % csv_path)

    # ---- generate the .bin if nvs_partition_gen.py is reachable ----
    gen = None
    if args.idf_path:
        cand = os.path.join(args.idf_path, "components", "nvs_flash",
                            "nvs_partition_generator", "nvs_partition_gen.py")
        if os.path.isfile(cand):
            gen = cand
    bin_path = os.path.join(out, "torizon-nvs.bin")
    if gen:
        cmd = [sys.executable, gen, "generate", "nvs.csv",
               "torizon-nvs.bin", args.nvs_size]
        log("running nvs_partition_gen: %s" % " ".join(cmd))
        subprocess.check_call(cmd, cwd=out)
        log("wrote NVS image: %s" % bin_path)
    else:
        log("nvs_partition_gen.py not found (pass --idf-path or set IDF_PATH).")
        log("Generate the image (from %s) with:" % out)
        log("  python $IDF_PATH/components/nvs_flash/nvs_partition_generator/"
            "nvs_partition_gen.py generate nvs.csv torizon-nvs.bin %s" % args.nvs_size)

    print(json.dumps({
        "uuid": uuid, "gateway": gw, "ecu_serial": ecu_serial,
        "hwid": args.hwid, "director_root_version": dir_root_v,
        "image_root_version": img_root_v, "csv": csv_path,
        "bin": bin_path if gen else None, "nvs_size": args.nvs_size,
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
