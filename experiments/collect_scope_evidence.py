#!/usr/bin/env python3
from __future__ import annotations
import csv, json, os, re, urllib.request, urllib.parse
from pathlib import Path

INV=Path("experiments/inventory/pair-inventory.csv")
OUT=Path("experiments/inventory/scope-evidence-v0.json")
TOKEN=os.environ["GITHUB_TOKEN"]
GHSA_RE=re.compile(r"(GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4})")
FIX_RE=re.compile(r"https://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{40})",re.I)
KW=re.compile(r"(subprocess|os\.system|popen|spawn|exec\(|execve|shell\s*=|eval\(|yaml\.load|jinja|template|browser|url|hg\s|git\s|command|cmd|shlex|system\(|deserialize|pickle|facts|nmap|wget)",re.I)

def get_json(url, auth=False):
    h={"User-Agent":"security-triage-scope-review/1.0","Accept":"application/json"}
    if auth:
        h["Authorization"]=f"Bearer {TOKEN}"
        h["X-GitHub-Api-Version"]="2022-11-28"
    with urllib.request.urlopen(urllib.request.Request(url,headers=h),timeout=45) as r:
        return json.load(r)

def get_text(url):
    with urllib.request.urlopen(urllib.request.Request(url,headers={"User-Agent":"security-triage-scope-review/1.0"}),timeout=45) as r:
        return r.read().decode()

def csv_rows():
    with INV.open(newline="",encoding="utf-8") as f:
        return list(csv.DictReader(f))

def slim_patch(files):
    out=[]
    for f in files or []:
        patch=f.get("patch") or ""
        hits=[x for x in patch.splitlines() if KW.search(x)]
        if hits:
            out.append({"file":f.get("filename"),"hits":hits[:40]})
    return out

def commit_evidence(repo,sha):
    j=get_json(f"https://api.github.com/repos/{repo}/commits/{sha}",True)
    if j.get("message")=="Moved Permanently" and j.get("url"):
        j=get_json(j["url"],True)
    return {
      "url":j.get("html_url"),
      "message":((j.get("commit") or {}).get("message") or "")[:1800],
      "files":slim_patch(j.get("files")),
      "all_files":[f.get("filename") for f in (j.get("files") or [])][:80],
    }

def secbench_meta(row):
    ref=(row.get("reference_provenance") or "").split("|")[0]
    m=re.search(r"github\.com/cristianstaicu/SecBench\.js/blob/([^/]+)/(.+)$",ref)
    if not m:return {}
    return json.loads(get_text(f"https://raw.githubusercontent.com/cristianstaicu/SecBench.js/{m.group(1)}/{m.group(2)}"))

rows=csv_rows()
out={"generated_for":"scope-review-v0","secbench":[],"pyvul":[]}
for row in rows:
    if row["split"]=="excluded":
        continue
    if row["dataset"]=="SecBench.js":
        meta=secbench_meta(row)
        ids=[]
        for src in ((row.get("cwe_provenance") or "")+"|"+(row.get("reference_provenance") or "")).split("|"):
            ids += GHSA_RE.findall(src)
        advisory=None
        if ids:
            try:
                advisory=get_json(f"https://api.github.com/advisories/{ids[0]}",True)
            except Exception as e:
                advisory={"error":str(e)}
        fix=None
        fm=FIX_RE.search(str(meta.get("fixCommit") or row.get("fix_commit") or ""))
        if fm:
            try: fix=commit_evidence(fm.group(1),fm.group(2))
            except Exception as e: fix={"error":str(e)}
        out["secbench"].append({
          "group_id":row["group_id"],"pair_id":row["pair_id"],"split":row["split"],
          "cwe":row["adjudicated_cwe"],"vulnerability_id":row["vulnerability_id"],
          "sink":meta.get("sink"),"source":meta.get("source"),
          "ghsa_id":ids[0] if ids else None,
          "ghsa_summary":(advisory or {}).get("summary") if isinstance(advisory,dict) else None,
          "ghsa_description":((advisory or {}).get("description") or "")[:1800] if isinstance(advisory,dict) else "",
          "ghsa_source_code_location":(advisory or {}).get("source_code_location") if isinstance(advisory,dict) else None,
          "fix":fix,
        })
    else:
        try: ce=commit_evidence(row["repository"],row["fix_commit"])
        except Exception as e: ce={"error":str(e)}
        out["pyvul"].append({
          "group_id":row["group_id"],"pair_id":row["pair_id"],"split":row["split"],
          "cwe":row["adjudicated_cwe"],"repository":row["repository"],"fix_commit":row["fix_commit"],
          "commit":ce,
        })
OUT.write_text(json.dumps(out,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
print(json.dumps({"secbench":len(out["secbench"]),"pyvul":len(out["pyvul"])}))
