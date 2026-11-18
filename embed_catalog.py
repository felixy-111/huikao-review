# 把 index.html 裡 CATALOGS 列出的每個章節表複製進內嵌備份（直接雙擊開檔、或某個檔抓不到時用）。
# 改了章節表、或在 CATALOGS 加了新科目就跑一次：python3 embed_catalog.py
import json, re, pathlib
here = pathlib.Path(__file__).parent
html = (here / "index.html").read_text(encoding="utf-8")
m = re.search(r"const CATALOGS = \[(.*?)\];", html)
assert m, "找不到 CATALOGS"
paths = re.findall(r"'([^']+)'", m.group(1))
cats = [json.loads((here / p).read_text(encoding="utf-8")) for p in paths]
blob = json.dumps(cats, ensure_ascii=False, separators=(",", ":"))
pat = r'(<script id="catalog-embed" type="application/json">)(.*?)(</script>)'
new, n = re.subn(pat, lambda m: m.group(1) + blob + m.group(3), html, count=1, flags=re.S)
assert n == 1, "找不到內嵌區塊"
(here / "index.html").write_text(new, encoding="utf-8")
for p, c in zip(paths, cats):
    print("已內嵌", p, len(c["units"]), "節")
