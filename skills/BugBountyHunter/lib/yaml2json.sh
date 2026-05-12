#!/usr/bin/env bash
# Usage: yaml2json.sh < input.yaml > output.json
# Also: cat input.yaml | yaml2json.sh | jq '.field'
# Replaces `yq -o=json` throughout the codebase (yq unavailable on target hosts).
# Requires: python3 + PyYAML.
set -euo pipefail

command -v python3 >/dev/null || { echo "yaml2json.sh: python3 required" >&2; exit 127; }
python3 -c "import yaml" 2>/dev/null || { echo "yaml2json.sh: PyYAML required (pip install pyyaml)" >&2; exit 127; }

python3 -c '
import sys, yaml, json
data = yaml.safe_load(sys.stdin.read())
if data is None:
    sys.stderr.write("yaml2json.sh: empty or null YAML input\n")
    sys.exit(1)
print(json.dumps(data))
'
