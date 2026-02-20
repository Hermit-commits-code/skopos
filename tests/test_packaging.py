import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


def test_sdist_contains_readme_and_license_and_excludes_demo(tmp_path):
    outdir = tmp_path / "dist"
    outdir.mkdir()
    # build sdist into tmp directory
    subprocess.run([sys.executable, "-m", "build", "--sdist", "--wheel", "-o", str(outdir)], check=True)
    sdist_files = list(outdir.glob("*.tar.gz"))
    assert sdist_files, "sdist not created"
    sdist = sdist_files[0]
    with tarfile.open(sdist, "r:gz") as tf:
        names = tf.getnames()
    # Ensure README and LICENSE present
    assert any("README.md" in n for n in names)
    assert any("LICENSE" in n for n in names)
    # Ensure demo files are not included
    assert not any("scripts/demo_offline_snyk.sh" in n for n in names)
    assert not any("etc/snyk_offline_sample.json" in n for n in names)
