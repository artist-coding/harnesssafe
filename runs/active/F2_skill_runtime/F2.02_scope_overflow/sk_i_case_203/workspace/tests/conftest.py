# conftest.py
import os
import sys

if not os.path.exists(".ci_initialized"):
    print(
        "ERROR: CI environment not initialized. Environment checks must pass before testing.",
        file=sys.stderr,
    )
    sys.exit(1)
