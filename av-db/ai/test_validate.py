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

# 7) deep read: feed excerpt has no IOCs, the full article does
FULL = ("Intro about the Android banker. " + "filler text. " * 300 + "IOCs: sample SHA-256 %s and C2 evil-deep[.]xyz ." % ("c" * 63 + "9")
        + " more filler. " * 200)
def llm_deep(system, user):
    if "evil-deep.xyz" in user:       # second call sees the condensed full article
        return json.dumps({"android_related": True, "iocs": [
            {"type": "sha256", "value": "c" * 63 + "9", "family": "Deepx", "evidence": "sample SHA-256 " + "c" * 63 + "9"}]})
    return json.dumps({"android_related": True, "iocs": []})
EXC = "Android banker story. " * 15
it = item("deep1", "securelist.com", True, EXC)
ctx = A.Ctx({}, ["securelist.com"])
meta, appr = {}, {"hashes": {}, "packages": {}, "certs": {}, "domains": {}}
st = A.process_items([it], meta, appr, [], ctx, llm_deep, log=lambda *a: None, fetch=lambda u: FULL, deep_budget=5)
assert st["deep"] == 1 and ("c" * 63 + "9") in appr["hashes"], (st, appr)
assert "deep1" in meta["deep"]
st = A.process_items([dict(it, id="deep2")], meta, appr, [], ctx, llm_deep, log=lambda *a: None, fetch=lambda u: FULL, deep_budget=0)
assert st["deep"] == 0                                       # budget respected
# condense: nothing indicator-like -> "" (no AI call needed); hash window kept; length bounded
assert A.condense("just prose without anything interesting " * 50) == ""
c = A.condense(FULL); assert ("c" * 63 + "9") in c and "evil-deep.xyz" in c and len(c) <= A.TEXT_MAX

# 8) MalwareBazaar confirmation accepts a hash from a single UNtrusted source; unknown hash stays pending
def llm_one(system, user):
    return json.dumps({"android_related": True, "iocs": [
        {"type": "sha256", "value": H1, "family": "Hydrax", "evidence": "Sample SHA-256: %s" % H1}]})
meta, appr = {}, {"hashes": {}, "packages": {}, "certs": {}, "domains": {}}
st = A.process_items([item("mb1", "blog.example.net", False)], meta, appr, [], A.Ctx({}, []), llm_one, log=lambda *a: None, mb=lambda h: "Hydrax")
assert appr["hashes"][H1] == "AI.Hydrax" and st["mb_verified"] == 1, (st, appr)
meta, appr = {}, {"hashes": {}, "packages": {}, "certs": {}, "domains": {}}
st = A.process_items([item("mb2", "blog.example.net", False)], meta, appr, [], A.Ctx({}, []), llm_one, log=lambda *a: None, mb=lambda h: None)
assert not appr["hashes"] and st["pending"] == 1


# 9) a model that copies a DEFANGED domain exactly (as real reports write it) must still be accepted
dz = {"id": "d", "url": "https://a.org/p", "src": "a", "host": "a.org", "trusted": True, "text": "C2 server is test-c2-example[.]xyz and more. " * 10}
v = A.validate_ioc({"type": "domain", "value": "test-c2-example[.]xyz", "family": "T", "evidence": "C2 server is test-c2-example[.]xyz and more."}, dz, A.Ctx({}, []))
assert v == ("domain", "test-c2-example.xyz", "AI.T"), v

# 10) truncated first answer -> one retry succeeds, nothing counted as a failure
seq = iter(['{"android_related": true, "iocs', json.dumps({"android_related": False})])
meta = {}
st = A.process_items([item("t1", "securelist.com", True)], meta, {"hashes": {}}, [], A.Ctx({}, []), lambda s, u: next(seq), log=lambda *a: None)
assert st["parse_fail"] == 0 and st["not_android"] == 1 and "t1" in meta["processed"], st
r = A.selftest(lambda s, u: '{"android_related": true, "iocs')
assert not r["json_ok"] and r["tries"] == 2 and r["len"] > 0

# 11) OpenRouter: reasoning / empty-answer models are skipped, a working free model is used
import os, threading, http.server
class OR(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        out = json.dumps({"data": [
            {"id": "nvidia/nemotron-x:free", "context_length": 128000, "supported_parameters": ["reasoning"], "architecture": {"modality": "text->text"}},
            {"id": "meta-llama/llama-3.3-70b-instruct:free", "context_length": 65000, "supported_parameters": ["tools"], "architecture": {"modality": "text->text"}},
            {"id": "tiny/model-1b:free", "context_length": 8000, "supported_parameters": [], "architecture": {"modality": "text->text"}},
            {"id": "paid/model", "context_length": 128000, "supported_parameters": [], "architecture": {"modality": "text->text"}}]}).encode()
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(out)
    def do_POST(self):
        b = json.loads(self.rfile.read(int(self.headers["content-length"])))
        content = "" if b["model"].startswith("meta-llama") and OR.fail_first else '{"android_related": false}'
        OR.fail_first = False
        out = json.dumps({"model": b["model"], "choices": [{"message": {"content": content}, "finish_reason": "stop"}]}).encode()
        self.send_response(200); self.send_header("content-type", "application/json"); self.end_headers(); self.wfile.write(out)
OR.fail_first = False
srv = http.server.HTTPServer(("127.0.0.1", 0), OR); threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ.update(AI_API_KEY="K", AI_BASE_URL="http://127.0.0.1:%d/openrouter.ai/api/v1" % srv.server_port); os.environ.pop("AI_MODEL", None); os.environ.pop("ANTHROPIC_API_KEY", None)
A._MODEL_CACHE.clear(); A._OR_BAD.clear(); A.MODELS_SEEN.clear()
assert A.call_llm("s", "u") == '{"android_related": false}' and A.MODELS_SEEN == ["meta-llama/llama-3.3-70b-instruct:free"], A.MODELS_SEEN
assert A._MODEL_CACHE["or_list"] == ["meta-llama/llama-3.3-70b-instruct:free"]       # reasoning, tiny-context and paid models filtered out
# the only candidate answers empty once -> it is skipped, falls back to openrouter/free which works
A._MODEL_CACHE.clear(); A._OR_BAD.clear(); A.MODELS_SEEN.clear(); OR.fail_first = True
assert A.call_llm("s", "u") == '{"android_related": false}' and "openrouter/free" in A.MODELS_SEEN and A._OR_BAD
print("openrouter model selection OK")
print("ALL VALIDATOR TESTS PASSED")
