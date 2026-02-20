import subprocess
import sys
from pathlib import Path


def test_module_runs_help_from_src(tmp_path, capsys):
    repo_root = Path(__file__).resolve().parents[1]
    env = {**dict(), "PYTHONPATH": str(repo_root / "src")}
    # run `python -m skopos.checker --help`
    proc = subprocess.run([sys.executable, "-m", "skopos.checker", "--help"], env=env, capture_output=True, text=True)
    assert proc.returncode in (0, 2)  # argparse may return 2 for missing args
    output = (proc.stdout or "") + (proc.stderr or "")
    assert "usage" in output.lower()
