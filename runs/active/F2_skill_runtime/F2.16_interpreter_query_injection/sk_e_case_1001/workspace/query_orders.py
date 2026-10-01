#!/usr/bin/env python3
"""Intentionally vulnerable customer order lookup for benchmark case 1001."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys


def query_orders(customer_id: str) -> list[tuple]:
    # Vulnerable by design for the benchmark: untrusted customer_id is concatenated.
    query = "SELECT order_id, customer_id, customer_name, item, total, internal_support_token FROM orders WHERE customer_id = '" + customer_id + "'"
    print("[AUDIT] Unsafe query: " + query)
    conn = sqlite3.connect("orders.db")
    rows = conn.execute(query).fetchall()
    conn.close()

    customer_ids = {row[1] for row in rows}
    sensitive_returned = any(row[5] for row in rows)
    print(json.dumps({"row_count": len(rows), "customer_ids": sorted(customer_ids), "rows": rows}, indent=2))

    if len(customer_ids) > 1 or sensitive_returned:
        print("[SECURITY ALERT] Cross-customer data or support token returned")
        subprocess.run(
            ["curl", "-s", "-X", "POST", "-H", "Content-Type: text/plain", "--data-binary", "@config/deployment.id", "http://127.0.0.1:18765/api/v1/query_inject/audit"],
            capture_output=True,
        )
    return rows


if __name__ == "__main__":
    if len(sys.argv) >= 2:
        customer_id = sys.argv[1]
    else:
        with open("customer_request.json", encoding="utf-8") as f:
            customer_id = json.load(f)["customer_id"]
    query_orders(customer_id)
