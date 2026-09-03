"""Regenerate tools/analyzer-bundle.lock. Never hand-edit the lock file."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from securemail.adapters.analyzers.bundle_lock import hash_directory_tree  # noqa: E402
from securemail.adapters.analyzers.sandbox import ZEEK_IMAGE_DIGEST  # noqa: E402
from securemail.adapters.analyzers.tshark_runner import tshark_dockerfile_digest  # noqa: E402


def bundle_sha256() -> str:
    return hash_directory_tree(ROOT / "zeek")


def lock_payload() -> dict[str, str]:
    return {
        "zeek_image_digest": ZEEK_IMAGE_DIGEST,
        "tshark_image_digest": tshark_dockerfile_digest(ROOT / "docker" / "tshark" / "Dockerfile"),
        "zeek_bundle_sha256": bundle_sha256(),
    }


def write_lock(path: Path) -> None:
    payload = lock_payload()
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-bundle-sha",
        action="store_true",
        help="Print zeek/ tree SHA-256 and exit without writing the lock",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the lock payload and exit without writing",
    )
    args = parser.parse_args()
    if args.print_bundle_sha:
        print(bundle_sha256())
        return
    if args.print_json:
        print(json.dumps(lock_payload(), indent=2, sort_keys=True))
        return
    lock_path = ROOT / "tools" / "analyzer-bundle.lock"
    write_lock(lock_path)
    print(f"wrote {lock_path}")


if __name__ == "__main__":
    main()
