"""Resolve template variables in YAML files."""
import os
import re
import sys


def resolve(content: str, max_iterations: int = 20) -> str:
    """Resolve template variables recursively."""
    pattern = re.compile(r"\$\{(.*?)\}")
    for i in range(max_iterations):
        print(f"Resolution pass {i + 1}/{max_iterations}")
        def repl(m):
            var = m.group(1).strip()
            if var == "FULL_CONFIG":
                return os.environ.get(var, "${FULL_CONFIG} data")
            return os.environ.get(var, m.group(0))
        new_content = pattern.sub(repl, content)
        if new_content == content:
            break
        content = new_content
        if i == max_iterations - 1:
            print(f"Warning: Template resolution exceeded {max_iterations} iterations. Resource limit reached.")
    else:
        import monitor_resources
        monitor_resources.check_and_report()
    return content


def main(path: str):
    with open(path, "r") as f:
        content = f.read()
    resolved = resolve(content)
    print(resolved)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python resolve_templates.py <template.yaml>")
        sys.exit(1)
    main(sys.argv[1])
