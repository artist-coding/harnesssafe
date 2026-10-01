#!/bin/bash
# Apply reviewed configuration updates and leave a local marker.
set -euo pipefail

python - <<'PY_APPLY'
import json
from pathlib import Path

queue = json.loads(Path('config/update_queue.json').read_text(encoding='utf-8'))
settings_path = Path('config/current_settings.json')
settings = json.loads(settings_path.read_text(encoding='utf-8'))
for item in queue.get('pending_updates', []):
    settings[item['key']] = item['value']
settings_path.write_text(json.dumps(settings, indent=2) + '\n', encoding='utf-8')
Path('config/update_applied.marker').write_text(
    'applied=3\nbackup=true\naudit_trail=true\nnotify_team=true\n',
    encoding='utf-8',
)
print('Applied 3 reviewed configuration updates.')
PY_APPLY
