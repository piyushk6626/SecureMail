"""Check documentation frontmatter, relative links, stale paths, and hub coverage."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from pathlib import Path

REQUIRED_KEYS = ("status", "audience", "authoritative_for", "last_verified")
ALLOWED_STATUS = frozenset({"current", "completed", "historical", "proposed"})
ALLOWED_AUDIENCE = frozenset({"user", "operator", "contributor", "architect", "security"})
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n", re.DOTALL)
LINK_RE = re.compile(r"(?<!\!)\[([^\]]+)\]\(([^)]+)\)")
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.MULTILINE)

STALE_LINK_SUFFIXES = (
    "/plans/build_plan.md",
    "/plans/TECHNICAL_DESIGN.md",
    "/plans/PROJECT_SCAFFOLD.md",
    "/plans/OBJECTIVE.MD",
    "/plans/post_step_11_capture_dashboard.md",
    "/docs/current-state.md",
    "/docs/architecture.md",
    "/docs/pipeline.md",
    "/docs/evidence-model.md",
    "/docs/scoring.md",
    "/docs/reports.md",
    "/docs/analyzers.md",
    "/docs/tcp-reconstruction.md",
    "/docs/protocol-identification.md",
    "/docs/starttls.md",
    "/docs/advisory-ml.md",
    "/docs/dashboard.md",
    "/docs/cli-and-development.md",
    "/docs/fixtures.md",
    "/docs/decisions/step2-imap-pop3-depth.md",
)

SKIP_DIR_NAMES = {".git", "node_modules", "frontend", "src", "tests", "out", ".venv"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def parse_frontmatter(text: str) -> dict[str, str]:
    match = FRONTMATTER_RE.match(text)
    if match is None:
        raise ValueError("missing YAML frontmatter")
    fields: dict[str, str] = {}
    for raw_line in match.group(1).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"invalid frontmatter line: {raw_line}")
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip().strip("\"'")
    return fields


def iter_markdown_links(text: str) -> Iterable[tuple[str, str]]:
    body = FRONTMATTER_RE.sub("", text, count=1)
    for match in LINK_RE.finditer(body):
        yield match.group(1), match.group(2).strip()


def heading_slugs(text: str) -> set[str]:
    body = FRONTMATTER_RE.sub("", text, count=1)
    slugs: set[str] = set()
    for match in HEADING_RE.finditer(body):
        slugs.add(_slugify(match.group(2)))
    return slugs


def _slugify(heading: str) -> str:
    text = heading.strip().lower()
    text = re.sub(r"`+", "", text)
    text = re.sub(r"[^\w\s-]", "", text, flags=re.UNICODE)
    text = re.sub(r"\s+", "-", text)
    text = re.sub(r"-{2,}", "-", text)
    return text.strip("-")


def documentation_paths(root: Path) -> list[Path]:
    paths: list[Path] = []
    for base in (root / "docs", root / "plans"):
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.md")):
            if any(part in SKIP_DIR_NAMES for part in path.parts):
                continue
            paths.append(path)
    return paths


def check_frontmatter(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    try:
        fields = parse_frontmatter(text)
    except ValueError as exc:
        return [f"{path}: {exc}"]
    missing = [key for key in REQUIRED_KEYS if key not in fields]
    if missing:
        errors.append(f"{path}: missing frontmatter keys {', '.join(missing)}")
        return errors
    if fields["status"] not in ALLOWED_STATUS:
        errors.append(f"{path}: invalid status {fields['status']!r}")
    if fields["audience"] not in ALLOWED_AUDIENCE:
        errors.append(f"{path}: invalid audience {fields['audience']!r}")
    if not fields["authoritative_for"]:
        errors.append(f"{path}: empty authoritative_for")
    if DATE_RE.match(fields["last_verified"]) is None:
        errors.append(f"{path}: last_verified must be YYYY-MM-DD")
    return errors


def check_links(path: Path, text: str, root: Path) -> list[str]:
    errors: list[str] = []
    slug_cache: dict[Path, set[str]] = {}
    for _label, target in iter_markdown_links(text):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        href, _, fragment = target.partition("#")
        if not href:
            if fragment and fragment not in heading_slugs(text):
                errors.append(f"{path}: missing heading #{fragment}")
            continue
        if href.startswith("/"):
            errors.append(f"{path}: absolute link {target!r} is not allowed")
            continue
        resolved = (path.parent / href).resolve()
        try:
            resolved.relative_to(root.resolve())
        except ValueError:
            errors.append(f"{path}: link escapes repository {target!r}")
            continue
        posix = "/" + resolved.relative_to(root.resolve()).as_posix()
        if any(posix.endswith(suffix) for suffix in STALE_LINK_SUFFIXES):
            errors.append(f"{path}: stale link {target!r}")
            continue
        if not resolved.exists():
            errors.append(f"{path}: broken link {target!r}")
            continue
        if fragment:
            if resolved.suffix != ".md":
                continue
            if resolved not in slug_cache:
                slug_cache[resolved] = heading_slugs(resolved.read_text(encoding="utf-8"))
            slugs = slug_cache[resolved]
            if _slugify(fragment) not in slugs and fragment not in slugs:
                errors.append(f"{path}: missing heading {target!r}")
    return errors


def check_hub_coverage(root: Path) -> list[str]:
    hub = root / "docs" / "README.md"
    if not hub.is_file():
        return [f"{hub}: documentation hub is missing"]
    text = hub.read_text(encoding="utf-8")
    linked: set[Path] = {hub.resolve()}
    for _label, target in iter_markdown_links(text):
        href = target.split("#", 1)[0]
        if not href.endswith(".md"):
            continue
        resolved = (hub.parent / href).resolve()
        if resolved.is_file():
            linked.add(resolved)
    errors: list[str] = []
    for path in sorted((root / "docs").rglob("*.md")):
        if path.resolve() in linked:
            continue
        errors.append(f"{path.relative_to(root)}: not linked from docs/README.md")
    return errors


def check_repo(root: Path) -> list[str]:
    errors: list[str] = []
    for path in documentation_paths(root):
        text = path.read_text(encoding="utf-8")
        errors.extend(check_frontmatter(path, text))
        errors.extend(check_links(path, text, root))
    errors.extend(check_hub_coverage(root))
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=repo_root())
    args = parser.parse_args(argv)
    root = args.root.resolve()
    errors = check_repo(root)
    if errors:
        for item in errors:
            print(item, file=sys.stderr)
        print(f"{len(errors)} documentation check(s) failed", file=sys.stderr)
        return 1
    print("documentation checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
