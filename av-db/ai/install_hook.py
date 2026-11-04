#!/usr/bin/env python3
"""One-time, idempotent: makes av-db/build_db.py also read av-db/ai-approved.json. Run from the repo root."""
import pathlib, sys
p = pathlib.Path("av-db/build_db.py")
s = p.read_text(encoding="utf-8")
if "ai-approved.json" in s:
    print("already installed"); sys.exit(0)
a1 = "    custom = load_json(custom_path, {})\n"
a2 = '    sources.append({"name": "custom.json", "status": "ok",\n'
if a1 not in s or a2 not in s:
    print("anchors not found: build_db.py changed, patch it by hand"); sys.exit(1)
hook = a1 + '''    # AI-validated indicators (written by av-db/ai/ai_intel.py); entries in custom.json always win
    ai = load_json(os.path.join(os.path.dirname(os.path.abspath(custom_path)), "ai-approved.json"), {})
    ai_count = 0
    for _k in ("hashes", "packages", "certs", "domains"):
        _m = ai.get(_k, {}) if isinstance(ai.get(_k, {}), dict) else {}
        ai_count += len(_m)
        custom[_k] = dict(_m, **custom.get(_k, {}))
'''
s = s.replace(a1, hook, 1)
s = s.replace(a2, '    sources.append({"name": "ai-intel", "status": "ok" if ai_count else "empty", "count": ai_count})\n' + a2, 1)
p.write_text(s, encoding="utf-8")
print("installed")
