"""Documentation checker behavior."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "check_docs.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_docs", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check_docs = _load()


def test_parse_frontmatter_and_slug() -> None:
    text = """---
status: current
audience: user
authoritative_for: example
last_verified: 2026-09-06
---

# Hello World

See [x](other.md).
"""
    fields = check_docs.parse_frontmatter(text)
    assert fields["status"] == "current"
    assert "hello-world" in check_docs.heading_slugs(text)
    links = list(check_docs.iter_markdown_links(text))
    assert links == [("x", "other.md")]


def test_check_repo_reports_broken_and_stale_links(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    plans = tmp_path / "plans"
    docs.mkdir()
    plans.mkdir()
    (docs / "README.md").write_text(
        """---
status: current
audience: user
authoritative_for: hub
last_verified: 2026-09-06
---

# Hub

- [ok](ok.md)
- [missing](missing.md)
- [stale](../plans/build_plan.md)
"""
    )
    (docs / "ok.md").write_text(
        """---
status: current
audience: user
authoritative_for: ok
last_verified: 2026-09-06
---

# Ok
"""
    )
    (docs / "orphan.md").write_text(
        """---
status: current
audience: user
authoritative_for: orphan
last_verified: 2026-09-06
---

# Orphan
"""
    )
    errors = check_docs.check_repo(tmp_path)
    joined = "\n".join(errors)
    assert "broken link" in joined
    assert "stale link" in joined
    assert "not linked from docs/README.md" in joined


def test_live_repository_documentation() -> None:
    errors = check_docs.check_repo(ROOT)
    assert errors == []
