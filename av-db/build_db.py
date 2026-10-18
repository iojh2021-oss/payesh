#!/usr/bin/env python3
"""Builds the over-the-air threat database consumed by the app.

usage: build_db.py <custom.json> <out av-db.json>

- hand-maintained entries/rules come from custom.json
- Android malware hashes are collected from abuse.ch MalwareBazaar when the
  ABUSECH_AUTH_KEY environment variable is set (free key: https://auth.abuse.ch)
  and accumulated over time (the feed only covers the last 48 hours)
"""
import csv, json, os, re, sys, time, urllib.request

HEX = re.compile(r"^[0-9a-f]{64}$")
MAX_HASHES = 30000


def load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def fetch_bazaar(key):
    url = "https://mb-api.abuse.ch/v2/files/exports/%s/recent.csv" % key
    req = urllib.request.Request(url, headers={"User-Agent": "payesh-av-db"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read().decode("utf-8", "replace")


def parse_bazaar(text):
    """Returns {sha256: family} for APK samples. Columns are located by header name."""
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
            if not HEX.match(h) or not ("apk" in ft or fn.endswith(".apk")):
                continue
            fam = row[sg_i].strip().strip('"') if sg_i is not None else ""
            out[h] = fam if fam and fam.lower() not in ("n/a", "none") else "Android.Malware"
        except IndexError:
            continue
    return out


def main():
    custom_path, out_path = sys.argv[1], sys.argv[2]
    custom = load(custom_path, {})
    old = load(out_path, {})
    hashes = dict(old.get("hashes", {}))

    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if key:
        try:
            new = parse_bazaar(fetch_bazaar(key))
            added = 0
            for h, fam in new.items():
                if h not in hashes:
                    added += 1
                hashes[h] = fam
            print("MalwareBazaar: %d Android samples in feed, %d new" % (len(new), added))
        except Exception as e:  # keep what we already have
            print("MalwareBazaar fetch failed:", e)
    else:
        print("ABUSECH_AUTH_KEY not set: skipping MalwareBazaar feed")

    for h, fam in custom.get("hashes", {}).items():
        if HEX.match(h.lower()):
            hashes[h.lower()] = fam
    hashes = dict(list(hashes.items())[-MAX_HASHES:])  # drop the oldest entries

    doc = {
        "schema": 1,
        "version": old.get("version", 0),
        "updated": old.get("updated", ""),
        "hashes": hashes,
        "packages": custom.get("packages", {}),
        "certs": custom.get("certs", {}),
        "rules": custom.get("rules", []),
    }
    strip = lambda d: {k: v for k, v in d.items() if k not in ("version", "updated")}
    if strip(doc) != strip(old):
        doc["version"] = old.get("version", 0) + 1
        doc["updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        print("database changed -> version", doc["version"])
    else:
        print("no changes")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, separators=(",", ":"))


if __name__ == "__main__":
    main()
