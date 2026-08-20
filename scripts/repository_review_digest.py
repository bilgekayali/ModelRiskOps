from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess

EXCLUDED_PATHS = {"security-review/v1.0-review.json"}


def tracked_paths() -> tuple[str, ...]:
    output = subprocess.check_output(["git", "ls-files", "-z"])
    paths = [item.decode("utf-8") for item in output.split(b"\0") if item]
    return tuple(sorted(path for path in paths if path not in EXCLUDED_PATHS))


def repository_review_digest() -> str:
    digest = hashlib.sha256()
    for relative in tracked_paths():
        path = Path(relative)
        if not path.is_file():
            raise SystemExit(f"tracked path is not a regular file: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


if __name__ == "__main__":
    print(repository_review_digest())
