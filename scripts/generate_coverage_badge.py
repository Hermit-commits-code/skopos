#!/usr/bin/env python3
"""Generate a simple coverage badge SVG from coverage.xml.

Writes `docs/coverage-badge.svg` with basic text showing the percent.
"""
import xml.etree.ElementTree as ET
from pathlib import Path

OUT = Path("docs")
OUT.mkdir(exist_ok=True)

cov_file = Path("coverage.xml")
if not cov_file.exists():
    print("coverage.xml not found; run pytest --cov to generate it")
    raise SystemExit(1)

root = ET.parse(cov_file).getroot()
metrics = root.find("coverage") if root.tag != "coverage" else root
# older/lxml structures: look for packages/lines
percent = None
if root.tag == "coverage":
    attr = root.attrib
    if "line-rate" in attr:
        try:
            percent = float(attr["line-rate"]) * 100
        except Exception:
            percent = None
# fallback: compute from counters
if percent is None:
    lines = root.findall("./packages/package/classes/class/lines/line")
    if lines:
        total = sum(1 for _ in lines)
        covered = sum(1 for l in lines if l.get("hits") and int(l.get("hits")) > 0)
        percent = (covered / total) * 100 if total else 0.0

if percent is None:
    print("Could not determine coverage percent from coverage.xml")
    raise SystemExit(2)

p = int(round(percent))
svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="120" height="20">
  <rect width="120" height="20" fill="#555" />
  <rect x="70" width="50" height="20" fill="#4c1" />
  <text x="35" y="14" fill="#fff" font-family="Verdana" font-size="11">coverage</text>
  <text x="90" y="14" fill="#fff" font-family="Verdana" font-size="11">{p}%</text>
</svg>'''

(OUT / "coverage-badge.svg").write_text(svg)
print(f"Wrote {OUT / 'coverage-badge.svg'}")
