#!/usr/bin/env bash
set -euo pipefail

# Demo script: register the sample offline Snyk feed and show enrichment for evil-package
# Usage: ./scripts/demo_offline_snyk.sh

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/.. 
REPO_ROOT=$(cd "$SCRIPT_ROOT" && pwd)

# Use python -m to run the CLI from source in this repo
python -m skopos.checker integrations load-snyk "$REPO_ROOT/etc/snyk_offline_sample.json"
# Enable the integration in the user's config (non-destructive append if needed)
python - <<PY
from pathlib import Path
p=Path.home()/'.skopos'/'config.toml'
s=p.read_text()
if '[integrations.snyk]' in s and 'enabled' in s.split('[integrations.snyk]')[-1]:
    s=s.replace('[integrations.snyk]\nenabled = false','[integrations.snyk]\nenabled = true')
else:
    s += '\n[integrations.snyk]\nenabled = true\napi_key = ""\noffline_file = "{0}/etc/snyk_offline_sample.json"\n'.format('$REPO_ROOT')
p.write_text(s)
print('Configured offline Snyk feed in',p)
PY

# Run demo command which prints enrichment without contacting PyPI
python -m skopos.checker integrations demo-snyk evil-package

echo "Demo complete."
