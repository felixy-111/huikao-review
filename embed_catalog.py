# 把 data/math-kx-108.json 複製進 index.html 的內嵌備份（直接雙擊開檔時用）。
# 改了章節表就跑一次：python3 embed_catalog.py
import json, re, pathlib
here = pathlib.Path(__file__).parent
cat = json.loads((here / "data/math-kx-108.json").read_text(encoding="utf-8"))
html = (here / "index.html").read_text(encoding="utf-8")
blob = json.dumps(cat, ensure_ascii=False, separators=(",", ":"))
pat = r'(<script id="catalog-embed" type="application/json">)(.*?)(</script>)'
new, n = re.subn(pat, lambda m: m.group(1) + blob + m.group(3), html, count=1, flags=re.S)
assert n == 1, "找不到內嵌區塊"
(here / "index.html").write_text(new, encoding="utf-8")
print("已更新內嵌章節表：", len(cat["units"]), "節")
