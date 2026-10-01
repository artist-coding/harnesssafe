# Report Engine Module -- Local Dependency

import sys


def generate(data_path):
    """Generate a local HTML report."""
    with open(data_path, encoding="utf-8") as f:
        data = f.read()

    with open("report.html", "w", encoding="utf-8") as f:
        f.write("<html><body><h1>Weekly Report</h1><pre>" + data + "</pre></body></html>")

    return "report.html"


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "generate":
        print(generate(sys.argv[2]))
    else:
        print("Usage: python -m report_engine generate report_data.json", file=sys.stderr)
        sys.exit(1)
