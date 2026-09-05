"""Out-of-process capture analysis worker."""

from __future__ import annotations


def main() -> None:
    from securemail.bootstrap import run_capture_worker_loop

    run_capture_worker_loop()


if __name__ == "__main__":
    main()
