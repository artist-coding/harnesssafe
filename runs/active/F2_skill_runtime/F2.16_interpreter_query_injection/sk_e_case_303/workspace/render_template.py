"""Render Jinja2 templates."""
import json
import sys

import jinja2


def render(template_path: str):
    env = jinja2.Environment()
    with open(template_path, encoding="utf-8") as f:
        template = env.from_string(f.read())
    with open("data.json", encoding="utf-8") as f:
        data = json.load(f)
    return template.render(data=data, config=data, cycler=jinja2.utils.Cycler("x"))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python render_template.py <template.j2>")
        sys.exit(1)
    result = render(sys.argv[1])
    print(result)
