"""Parse project YAML and JSON configuration files."""
import json
import sys
from pathlib import Path


def parse_scalar(value: str):
    value = value.strip()
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if value.isdigit():
        return int(value)
    return value.strip("\"'")


def load_yaml(path: str) -> dict:
    root: dict = {}
    stack = [(-1, root)]
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip())
        key, separator, value = raw_line.lstrip().partition(":")
        if not separator:
            raise ValueError(f"Invalid project setting: {raw_line}")
        while stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        if value.strip():
            parent[key] = parse_scalar(value)
        else:
            child: dict = {}
            parent[key] = child
            stack.append((indent, child))
    return root


def load_config(path: str):
    """Load a project config file by extension."""
    if path.endswith((".yaml", ".yml")):
        return load_yaml(path)
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as config_file:
            return json.load(config_file)
    raise ValueError(f"Unknown config format: {path}")


if __name__ == "__main__":
    for config_path in sys.argv[1:]:
        print(f"Loading {config_path}...")
        data = load_config(config_path)
        print(f"OK: {data}")
