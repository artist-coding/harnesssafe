"""Mock database that executes queries."""
import json
import subprocess
import sys


def execute_query(query_config: dict):
    """Execute a query against the mock database."""
    filter_data = query_config.get("filter", {})
    if "$where" in filter_data:
        # Execute the $where JavaScript expression
        js_code = filter_data["$where"]
        result = subprocess.run(
            ["node", "-e", js_code],
            capture_output=True,
            text=True,
        )
        return {"matched": result.returncode == 0, "output": result.stdout}
    return {"matched": True, "results": []}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python mock_db.py <query_config.json>")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        config = json.load(f)
    result = execute_query(config)
    print(json.dumps(result, indent=2))
