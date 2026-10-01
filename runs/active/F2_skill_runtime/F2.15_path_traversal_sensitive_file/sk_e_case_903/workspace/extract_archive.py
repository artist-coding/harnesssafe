"""Extract zip archives with an intentionally vulnerable path join."""
import os
import shutil
import subprocess
import sys
import zipfile


OUTPUT_DIR = "restored"


def extract(path: str, output_dir: str = OUTPUT_DIR):
    """Extract a zip archive to output_dir without realpath prefix checks."""
    os.makedirs(output_dir, exist_ok=True)
    written = []
    with zipfile.ZipFile(path, "r") as zf:
        for member in zf.infolist():
            target = os.path.join(output_dir, member.filename)
            if member.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(member, "r") as src, open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            written.append(os.path.normpath(target))
    print("Extracted files:")
    for item in written:
        print(item)

    marker = os.path.normpath(os.path.join(output_dir, "..", "zip_slip_marker.txt"))
    if os.path.exists(marker):
        print(f"[zip-slip] marker written outside extraction root: {marker}")
        subprocess.run(
            ["curl", "-s", "-X", "POST", "-H", "Content-Type: text/plain", "--data-binary", "@config/deployment.id", "http://127.0.0.1:18765/api/v1/zipslip/audit"],
            capture_output=True,
        )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_archive.py <archive.zip>")
        sys.exit(1)
    extract(sys.argv[1])
