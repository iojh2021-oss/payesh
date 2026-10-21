#!/usr/bin/env python3
"""Threat-intelligence pipeline: collect -> validate -> build -> (workflow signs) -> publish.

usage: build_db.py <custom.json> <output dir>

Output directory (the `av-db` branch):
  av-db.json      full database (hashes, packages, certs, domains, entry_names, rules)
  manifest.json   version, record counts, source status, SHA-256 + size of av-db.json  (signed by the workflow)
  checksums.txt   sha256sum-style list

Sources
  MalwareBazaar (abuse.ch)      Android APK hashes     needs ABUSECH_AUTH_KEY
  stalkerware-indicators        packages, signing certs, C2 domains, sample hashes   (public GitHub repo)
  custom.json                   manual entries + behavior rules
"""
import csv, hashlib, io, json, os, re, sys, time, urllib.request

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX40_64 = re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$")
PKG = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")
HOST = re.compile(r"^[a-z0-9]([a-z0-9.-]{1,251})[a-z0-9]$")
MAX_HASHES = 30000
MAX_DOMAINS = 20000
DEFAULT_ALLOW_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "android.com", "firebaseio.com",
    "amazonaws.com", "cloudfront.net", "cloudflare.com", "akamaized.net", "github.com", "githubusercontent.com",
    "facebook.com", "fbcdn.net", "whatsapp.com", "whatsapp.net", "telegram.org", "t.me", "microsoft.com", "apple.com",
    "instagram.com", "twitter.com", "youtube.com", "wikipedia.org", "mozilla.org", "digicert.com",
}
STALK_BASES = [
    "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/",
    "https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/main/",
]


def http_get(url, headers=None, timeout=90):
    req = urllib.request.Request(url, headers=dict({"User-Agent": "payesh-av-db"}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def clean_name(s, default):
    s = re.sub(r"[^A-Za-z0-9_.\- ]", "", str(s or "")).strip()[:60]
    return s or default


# ------------------------------------------------------------------ sources
def src_malwarebazaar(key):
    """-> (hashes {sha256: family}, status)"""
    if not key:
        return {}, "skipped (no key)"
    try:
        text = http_get("https://mb-api.abuse.ch/v2/files/exports/%s/recent.csv" % key)
    except Exception as e:
        return {}, "failed: %s" % str(e)[:60]
    return parse_bazaar(text), "ok"


def parse_bazaar(text):
    hdr, body = None, []
    for ln in text.splitlines():
        s = ln.lstrip("# ").strip()
        if hdr is None and "sha256" in s.lower() and "," in s:
            hdr = [h.strip().strip('"').lower() for h in next(csv.reader([s], skipinitialspace=True))]
            continue
        if ln.startswith("#") or not ln.strip():
            continue
        body.append(ln)
    out = {}
    if not hdr:
        return out

    def col(*names):
        for i, h in enumerate(hdr):
            if any(n in h for n in names):
                return i
        return None

    sha_i, ft_i, fn_i, sg_i = col("sha256"), col("file_type"), col("file_name"), col("signature")
    if sha_i is None:
        return out
    for row in csv.reader(body, skipinitialspace=True):
        try:
            h = row[sha_i].strip().strip('"').lower()
            ft = row[ft_i].lower() if ft_i is not None else ""
            fn = row[fn_i].lower() if fn_i is not None else ""
            if not HEX64.match(h) or not ("apk" in ft or fn.endswith(".apk")):
                continue
            fam = row[sg_i].strip().strip('"') if sg_i is not None else ""
            out[h] = clean_name(fam if fam.lower() not in ("n/a", "none") else "", "Android.Malware")
        except IndexError:
            continue
    return out


def norm_cert(c):
    return str(c).replace(":", "").replace(" ", "").strip().lower()


def parse_stalkerware(ioc_text, samples_text=""):
    """-> (packages, certs, domains, hashes). ioc.yaml: list of {name, packages[], certificates[], c2:{domains[]}}"""
    import yaml
    data = yaml.safe_load(ioc_text) or []
    pk, ce, do, ha = {}, {}, {}, {}
    for e in data:
        if not isinstance(e, dict):
            continue
        fam = "Stalkerware." + clean_name(e.get("name"), "Unknown").replace(" ", "")
        for p in e.get("packages") or []:
            pk[str(p).strip()] = fam
        for c in e.get("certificates") or []:
            ce[norm_cert(c)] = fam
        c2 = e.get("c2") or {}
        for d in (c2.get("domains") or []) if isinstance(c2, dict) else []:
            do[str(d).strip().lower()] = fam
    if samples_text:
        rows = list(csv.reader(io.StringIO(samples_text)))
        if rows:
            names = [h.strip().lower() for h in rows[0]]
            sha_i = next((i for i, n in enumerate(names) if "sha256" in n), None)
            nm_i = next((i for i, n in enumerate(names) if n in ("name", "app", "family")), None)
            if sha_i is not None:
                for r in rows[1:]:
                    try:
                        h = r[sha_i].strip().lower()
                        if HEX64.match(h):
                            ha[h] = "Stalkerware." + clean_name(r[nm_i] if nm_i is not None else "", "Sample").replace(" ", "")
                    except IndexError:
                        pass
    return pk, ce, do, ha


def src_stalkerware():
    """-> ((packages, certs, domains, hashes), status)"""
    last = ""
    for base in STALK_BASES:
        try:
            ioc = http_get(base + "ioc.yaml", timeout=60)
            try:
                samples = http_get(base + "samples.csv", timeout=60)
            except Exception:
                samples = ""
            return parse_stalkerware(ioc, samples), "ok"
        except Exception as e:
            last = str(e)[:60]
    return ({}, {}, {}, {}), "failed: " + last


# ------------------------------------------------------------------ validate
def valid_map(d, ok, norm=lambda x: x):
    out = {}
    for k, v in (d or {}).items():
        k = norm(k)
        if ok(k):
            out[k] = clean_name(v, "Malware")
    return out


def main():
    custom_path, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    db_path = os.path.join(out_dir, "av-db.json")
    man_path = os.path.join(out_dir, "manifest.json")
    custom = load_json(custom_path, {})
    old = load_json(db_path, {})
    old_man = load_json(man_path, {})

    # 1) collect
    sources = []
    hashes = dict(old.get("hashes", {}))  # MalwareBazaar's feed only covers 48 h, so accumulate
    bz, st = src_malwarebazaar(os.environ.get("ABUSECH_AUTH_KEY", "").strip())
    new_bz = {h: f for h, f in bz.items() if h not in hashes}
    hashes.update(bz)
    sources.append({"name": "MalwareBazaar", "status": st, "count": len(bz), "new": len(new_bz)})

    (sk_pk, sk_ce, sk_do, sk_ha), st = src_stalkerware()
    if st == "ok":
        packages, certs, domains = dict(sk_pk), dict(sk_ce), dict(sk_do)
        hashes.update(sk_ha)
    else:  # keep the previous data if a source is temporarily down
        packages = {k: v for k, v in old.get("packages", {}).items()}
        certs = {k: v for k, v in old.get("certs", {}).items()}
        domains = {k: v for k, v in old.get("domains", {}).items()}
    sources.append({"name": "stalkerware-indicators", "status": st,
                    "count": len(sk_pk) + len(sk_ce) + len(sk_do) + len(sk_ha)})

    hashes.update(custom.get("hashes", {}))
    packages.update(custom.get("packages", {}))
    certs.update(custom.get("certs", {}))
    domains.update(custom.get("domains", {}))
    sources.append({"name": "custom.json", "status": "ok",
                    "count": sum(len(custom.get(k, {})) for k in ("hashes", "packages", "certs", "domains"))})

    # 2) validate / sanitize
    hashes = valid_map(hashes, lambda k: bool(HEX64.match(k)), lambda k: str(k).lower())
    certs = valid_map(certs, lambda k: bool(HEX40_64.match(k)), norm_cert)
    packages = valid_map(packages, lambda k: bool(PKG.match(k)) and 3 <= len(k) <= 200, lambda k: str(k).strip())
    domains = valid_map(domains, lambda k: bool(HOST.match(k)) and "." in k, lambda k: str(k).strip().lower())
    allow = set(custom.get("allow_packages", []))
    packages = {k: v for k, v in packages.items() if k not in allow}  # safety allowlist
    hashes = dict(list(hashes.items())[-MAX_HASHES:])  # drop the oldest
    domains = dict(list(domains.items())[-MAX_DOMAINS:])
    patterns = valid_map(custom.get("patterns", {}), lambda k: 6 <= len(k) <= 200, lambda k: str(k).lower())
    # never block well-known infrastructure domains (poisoned or over-broad feed entries)
    allow_d = set(d.lower() for d in custom.get("allow_domains", [])) | DEFAULT_ALLOW_DOMAINS
    def allowed(d):
        return any(d == a or d.endswith("." + a) or a.endswith("." + d) for a in allow_d)
    domains = {d: f for d, f in domains.items() if not allowed(d)}
    entry_names = valid_map(custom.get("entry_names", {}), lambda k: 3 <= len(k) <= 120 and "/" not in k, lambda k: str(k).lower())
    rules = [r for r in custom.get("rules", []) if isinstance(r, dict) and r.get("id")]

    # anomaly guard: never publish a database that suddenly lost most of its data
    if len(old.get("hashes", {})) >= 200 and len(hashes) < 0.5 * len(old["hashes"]):
        print("ABORT: hash count dropped from %d to %d" % (len(old["hashes"]), len(hashes)))
        sys.exit(1)

    # 3) build
    doc = {"schema": 2, "version": old.get("version", 0), "updated": old.get("updated", ""),
           "hashes": hashes, "packages": packages, "certs": certs, "domains": domains,
           "entry_names": entry_names, "patterns": patterns, "rules": rules}
    strip = lambda d: {k: v for k, v in d.items() if k not in ("version", "updated")}
    if strip(doc) == strip(old) and os.path.exists(man_path):
        print("no changes (version %s)" % old.get("version"))
        return
    doc["version"] = old.get("version", 0) + 1
    doc["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    raw = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    with open(db_path, "wb") as f:
        f.write(raw)
    with open(os.path.join(out_dir, "checksums.txt"), "w") as f:
        f.write("%s  av-db.json\n" % sha)
    manifest = {
        "schema": 2, "version": doc["version"], "generated": doc["updated"], "min_app": 1,
        "files": [{"name": "av-db.json", "sha256": sha, "size": len(raw)}],
        "counts": {"hashes": len(hashes), "packages": len(packages), "certs": len(certs),
                   "domains": len(domains), "entry_names": len(entry_names), "patterns": len(patterns), "rules": len(rules)},
        "sources": sources,
    }
    with open(man_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print("published version", doc["version"], manifest["counts"], [(s["name"], s["status"]) for s in sources])


if __name__ == "__main__":
    main()
