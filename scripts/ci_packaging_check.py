#!/usr/bin/env python3
"""CI helper: validate sdist contents don't include demo/sample files and include README/LICENSE."""
import sys
import tarfile
from pathlib import Path


def main():
    dist = list(Path("dist").glob("*.tar.gz"))
    if not dist:
        print("no sdist found")
        return 2
    names = tarfile.open(dist[0]).getnames()
    if not any("README.md" in n for n in names):
        print("README.md missing from sdist")
        return 3
    if not any("LICENSE" in n for n in names):
        print("LICENSE missing from sdist")
        return 4
    if any("scripts/demo_offline_snyk.sh" in n for n in names):
        print("demo script leaked into sdist")
        return 5
    if any("etc/snyk_offline_sample.json" in n for n in names):
        print("offline sample leaked into sdist")
        return 6
    print("packaging assertions passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
