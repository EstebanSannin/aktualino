#!/usr/bin/env python3
"""
aktualino-bundle.py — publish + assign a Berry script bundle to Torizon Cloud.

A bundle is delivered to the device's Berry script secondary (hardware id
`aktualino-lua`) as an ordinary Uptane target: publish it to the Image repo, then
assign it to your device. The device two-repo-verifies, downloads, runs, and
reports it (see docs/bundles.md).

Credentials (from your Torizon `credentials.zip`, kept in secrets/ — never
commit): the `garage-tools` client (treehub.json) publishes targets; a user-scoped
Platform API v2 client (api-client.json) assigns updates. Point --secrets at your
own if they live elsewhere.

Examples:
  # one-shot: publish blink.be as aktualino-lua v1.1.0 and assign to a device
  tools/aktualino-bundle.py deploy examples/bundles/blink.be \\
      --name aktualino-lua --version 1.1.0 --device <device-uuid>

  # or in two steps
  tools/aktualino-bundle.py publish examples/bundles/blink.be --version 1.1.0
  tools/aktualino-bundle.py assign --package aktualino-lua-1.1.0 --device <uuid>
  tools/aktualino-bundle.py status --device <uuid>
"""
import argparse, hashlib, json, os, sys, urllib.parse, urllib.request, urllib.error

DEFAULT_SECRETS = os.environ.get("AKT_TORIZON_SECRETS", "secrets/torizon")
HWID = "aktualino-lua"
PLATFORM = "https://app.torizon.io"


def _oauth(token_url, client_id, secret):
    data = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id, "client_secret": secret,
    }).encode()
    with urllib.request.urlopen(urllib.request.Request(token_url, data=data)) as r:
        return json.load(r)["access_token"]


def _req(method, url, token, body=None, ctype=None):
    h = {"Authorization": "Bearer " + token}
    if ctype:
        h["Content-Type"] = ctype
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def _repo_token(secrets):
    th = json.load(open(os.path.join(secrets, "extracted", "treehub.json")))
    o = th["oauth2"]
    return _oauth(o["server"] + "/token", o["client_id"], o["client_secret"])


def _platform_token(secrets):
    ac = json.load(open(os.path.join(secrets, "api-client.json")))
    return _oauth(ac["token_endpoint"], ac["client_id"], ac["secret"])


def _repo_base(secrets):
    return open(os.path.join(secrets, "extracted", "tufrepo.url")).read().strip()


def _default_device(secrets):
    p = os.path.join(secrets, "dev_extracted", "info.json")
    return json.load(open(p))["deviceUuid"] if os.path.exists(p) else None


def do_publish(a):
    data = open(a.file, "rb").read()
    pkg = "%s-%s" % (a.name, a.version)
    print("bundle %s: %d bytes, sha256=%s" % (a.file, len(data), hashlib.sha256(data).hexdigest()))
    tok = _repo_token(a.secrets)
    q = urllib.parse.urlencode({"name": a.name, "version": a.version,
                                "hardwareIds": a.hwid, "targetFormat": "BINARY"})
    url = "%s/api/v1/user_repo/targets/%s?%s" % (_repo_base(a.secrets), urllib.parse.quote(pkg), q)
    st, body = _req("PUT", url, tok, body=data, ctype="application/octet-stream")
    print("publish %s -> HTTP %d %s" % (pkg, st, body[:200]))
    if st not in (200, 204):
        sys.exit(1)
    print("published package: %s (hwid %s)" % (pkg, a.hwid))
    return pkg


def do_assign(a):
    dev = a.device or _default_device(a.secrets)
    if not dev:
        sys.exit("no --device and no secrets/.../info.json to default from")
    tok = _platform_token(a.secrets)
    body = json.dumps({"packageIds": [a.package], "devices": [dev]}).encode()
    st, resp = _req("POST", PLATFORM + "/api/v2beta/updates", tok, body=body, ctype="application/json")
    print("assign %s -> device %s: HTTP %d\n  %s" % (a.package, dev, st, resp[:400]))
    if st not in (200, 201):
        sys.exit(1)


def do_status(a):
    dev = a.device or _default_device(a.secrets)
    tok = _platform_token(a.secrets)
    st, resp = _req("GET", PLATFORM + "/api/v2beta/updates/devices/%s" % dev, tok)
    if st != 200:
        sys.exit("status HTTP %d: %s" % (st, resp[:300]))
    j = json.loads(resp)
    vals = j.get("values", j) if isinstance(j, dict) else j
    for u in (vals if isinstance(vals, list) else []):
        if a.package and a.package not in json.dumps(u.get("packages", {})):
            continue
        print(json.dumps({k: u.get(k) for k in
              ("updateId", "status", "completedAt", "deviceResult", "packages")}, indent=1))
        if a.package:
            return


def do_deploy(a):
    a.package = do_publish(a)
    do_assign(a)


def main():
    ap = argparse.ArgumentParser(description="Publish + assign a Berry bundle to Torizon Cloud.")
    ap.add_argument("--secrets", default=DEFAULT_SECRETS, help="Torizon secrets dir (default %(default)s)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_pub(p):
        p.add_argument("file", help="the .be bundle to publish")
        p.add_argument("--name", default=HWID, help="package name (default %(default)s)")
        p.add_argument("--version", required=True, help="package version, e.g. 1.1.0")
        p.add_argument("--hwid", default=HWID, help="hardware id (default %(default)s)")

    p = sub.add_parser("publish", help="publish a bundle as an Image-repo target"); add_pub(p)
    p = sub.add_parser("assign", help="assign a package to a device")
    p.add_argument("--package", required=True); p.add_argument("--device")
    p = sub.add_parser("status", help="show update status for a device")
    p.add_argument("--device"); p.add_argument("--package")
    p = sub.add_parser("deploy", help="publish + assign in one step"); add_pub(p)
    p.add_argument("--device")

    a = ap.parse_args()
    {"publish": do_publish, "assign": do_assign, "status": do_status, "deploy": do_deploy}[a.cmd](a)


if __name__ == "__main__":
    main()
