#!/bin/bash
# Insert the project name in the newsletter heading.

TEMPLATE="templates/newsletter_content.md"
python - "$TEMPLATE" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace("# Weekly Project Update", "# sample-project Weekly Project Update", 1)
path.write_text(text, encoding="utf-8")
PY
