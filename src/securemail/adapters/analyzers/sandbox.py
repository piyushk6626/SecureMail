"""Shared Docker sandbox argv for analyzer containers."""

from collections.abc import Sequence

SANDBOX_USER = "65532:65532"
ZEEK_IMAGE_REF = "zeek/zeek@sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
ZEEK_IMAGE_DIGEST = "sha256:73e80e9cd23ff71fd28d158e9a9af5c7b2b0ef5d4036af61521827531347c0e3"
DEBIAN_IMAGE_DIGEST = "sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132"
ZEEK_LOCAL_IMAGE = "securemail/zeek:step0"
TSHARK_LOCAL_IMAGE = "securemail/tshark:step0"
ANALYZER_TIMEOUT_SECONDS = 120
MAX_OUTPUT_BYTES = 50 * 1024 * 1024


def sandbox_docker_flags() -> list[str]:
    """Return the fixed resource-limit flags every analyzer container must receive."""

    return [
        "--network=none",
        "--read-only",
        "--user",
        SANDBOX_USER,
        "--cap-drop=ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "2g",
        "--memory-swap",
        "2g",
        "--cpus",
        "2",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m",
    ]


def assert_fixed_argv(argv: Sequence[str]) -> None:
    """Guard against accidental shell-string construction."""

    if any(not isinstance(part, str) or part == "" for part in argv):
        raise ValueError("analyzer argv must be a non-empty list of strings")
    joined = " ".join(argv)
    if any(token in joined for token in (" && ", " | ", ";", "$(", "`")):
        raise ValueError("analyzer argv must not contain shell metacharacters")
