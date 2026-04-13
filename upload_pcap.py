#!/usr/bin/env python3

import shutil
import subprocess
import time
from pathlib import Path

# ================= CONFIG =================
LOCAL_DIR = Path.home() / "Downloads/data/pcap"
REMOTE = "datapcap:Thai_ERAB/datapcapremote"
MIN_AGE_SECONDS = 6 * 60      # 6 minutes
SLEEP_INTERVAL = 60           # check every 60 sec
STATE_FILE = LOCAL_DIR / ".uploaded_files.txt"
# ==========================================


def ensure_rclone():
    if shutil.which("rclone") is None:
        raise RuntimeError("rclone not found in PATH. Install it first.")


def load_uploaded():
    if not STATE_FILE.exists():
        return set()
    return set(STATE_FILE.read_text(encoding="utf-8").splitlines())


def save_uploaded(uploaded_set):
    STATE_FILE.write_text("\n".join(sorted(uploaded_set)), encoding="utf-8")


def is_old_enough(file_path: Path) -> bool:
    file_age = time.time() - file_path.stat().st_mtime
    return file_age > MIN_AGE_SECONDS


def iter_candidate_files():
    # Match .pcap, .pcap00, .pcap01, etc.
    for file_path in sorted(LOCAL_DIR.iterdir()):
        if file_path.is_file() and ".pcap" in file_path.name and not file_path.name.startswith("."):
            yield file_path


def upload_file(file_path: Path) -> bool:
    print(f"[UPLOAD] {file_path}")

    cmd = [
        "rclone",
        "copy",
        str(file_path),
        REMOTE,
        "-P",
    ]

    result = subprocess.run(cmd)

    if result.returncode == 0:
        print(f"[SUCCESS] {file_path}")
        return True
    else:
        print(f"[FAILED] {file_path}")
        return False


def main():
    ensure_rclone()

    if not LOCAL_DIR.exists():
        raise RuntimeError(f"Local directory does not exist: {LOCAL_DIR}")

    print("Starting PCAP auto-upload service...")
    print(f"Monitoring: {LOCAL_DIR}")
    print(f"Remote: {REMOTE}")
    print(f"Min age: {MIN_AGE_SECONDS} seconds")
    print()

    uploaded = load_uploaded()

    while True:
        try:
            found_any = False

            for file_path in iter_candidate_files():
                found_any = True
                file_key = str(file_path.resolve())

                if file_key in uploaded:
                    continue

                if not is_old_enough(file_path):
                    print(f"[SKIP] Still active/new: {file_path.name}")
                    continue

                success = upload_file(file_path)

                if success:
                    uploaded.add(file_key)
                    save_uploaded(uploaded)

            if not found_any:
                print("[INFO] No PCAP files found.")

            time.sleep(SLEEP_INTERVAL)

        except KeyboardInterrupt:
            print("\nStopping...")
            break

        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(10)


if __name__ == "__main__":
    main()
