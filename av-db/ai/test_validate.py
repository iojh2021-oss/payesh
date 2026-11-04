#!/usr/bin/env python3
"""Offline tests for the validator (no network, fake LLM). Run: python3 av-db/ai/test_validate.py"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ai_intel as A

H1 = "a" * 63 + "1"
H_FAKE = "b" * 64
REPORT = ("New Android banker 'Hydrax' abuses Accessibility. Sample SHA-256: %s . It contacts evil-c2[.]xyz and drops "
          "com.fake.banker. Legit services such as google.com and securelist.com are also mentioned. " % H1) + "x" * 200

def item(i, host, trusted, text=REPORT):
    return {"id": i, "url": "https://%s/p" % host, "src": host, "host": host, "trusted": trusted, "text": text}

def fake(rules=None):
    def llm(system, user):
        return json.dumps({"android_related": True, "iocs": [
            {"type": "sha256", "value": H1, "family": "Hydrax", "evidence": "Sample SHA-256: %s" % H1},
            {"type": "sha256", "value": H_FAKE, "family": "Hydrax", "evidence": "Sample SHA-256: %s" % H_FAKE},      # hallucinated
            {"type": "domain", "value": "evil-c2.xyz", "family": "Hydrax", "evidence": "It contacts evil-c2.xyz and drops"},
            {"type": "domain", "value": "google.com", "family": "Hydrax", "evidence": "Legit services such as google.com"},
            {"type": "domain", "value": "securelist.com", "family": "X", "evidence": "and securelist.com are also"},
            {"type": "package", "value": "com.fake.banker", "family": "Hydrax", "evidence": "drops com.fake.banker."},
            {"type": "package", "value": "com.google.android.gms", "family": "X", "evidence": "drops com.fake.banker."},
            {"type": "sha256", "value": H1, "family": "Hydrax", "evidence": "this quote is not in the report at all"},
        ], "proposed_rules": rules or []})
    return llm

def run(items, llm):
    custom = {"rules": [{"id": "banker.overlay", "all": ["overlay_on", "a11y_on"], "any": ["sms_any"]}]}
    ctx = A.Ctx(custom, ["securelist.com", "other.org"])
    meta, appr, prop = {}, {"hashes": {}, "packages": {}, "certs": {}, "domains": {}}, []
    stats = A.process_items(items, meta, appr, prop, ctx, llm, log=lambda *a: None)
    return stats, meta, appr, prop

# 1) single trusted source
s, m, a, p = run([item("1", "securelist.com", True)], fake())
assert H1 in a["hashes"] and a["hashes"][H1] == "AI.Hydrax", a
assert H_FAKE not in a["hashes"], "hallucinated hash accepted!"
assert "com.fake.banker" in a["packages"]
assert "com.google.android.gms" not in a["packages"], "protected package accepted!"
assert not a["domains"], "domain must wait for a second source: %s" % a["domains"]
assert "domain:evil-c2.xyz" in m["pending"]
assert "google.com" not in a["domains"] and "securelist.com" not in a["domains"]

# 2) untrusted single source -> hash only pending
s, m, a, p = run([item("2", "blog.example.net", False)], fake())
assert not a["hashes"] and not a["packages"] and not a["domains"], a

# 3) two independent sources -> domain accepted
s, m, a, p = run([item("3", "securelist.com", True), item("4", "welivesecurity.com", True)], fake())
assert "evil-c2.xyz" in a["domains"], a

# 4) rules: valid accepted, unknown token / bad id / empty rejected, score capped
good = {"id": "banker.hydrax", "name": "x", "score": 99, "all": ["overlay_on", "a11y_on"], "any": ["perm:READ_SMS"], "no": []}
bad1 = {"id": "evil.rule", "all": ["rm_rf_token"]}
bad2 = {"id": "Bad Id!", "all": ["overlay_on"]}
bad3 = {"id": "empty.rule", "all": [], "any": []}
s, m, a, p = run([item("5", "securelist.com", True)], fake([good, bad1, bad2, bad3]))
assert [r["id"] for r in p] == ["ai.banker.hydrax"] and p[0]["score"] == 15, p

# 5) the same item is never processed twice
custom = {"rules": []}
ctx = A.Ctx(custom, [])
meta = {"processed": {"1": "x"}}
st = A.process_items([item("1", "securelist.com", True)], meta, {"hashes": {}}, [], ctx, fake(), log=lambda *a: None)
assert st["skipped"] == 1 and st["items"] == 0

# 6) refang + json parsing robustness
assert A.refang("hxxps://evil[.]com/a(.)b") == "https://evil.com/a.b"
assert A.parse_json("```json\n{\"a\": 1}\n```") == {"a": 1}
assert A.parse_json("sorry, no") is None
print("ALL VALIDATOR TESTS PASSED")
