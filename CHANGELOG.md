# Changelog

This project is version `0.0.0` in `pyproject.toml`. There is no package
publication, container publication, or automated release pipeline. This file
records user-visible repository changes.

## Unreleased

### Documentation

- Replaced the flat `docs/` tree with audience-oriented folders (getting
  started, user guide, architecture, forensics, operations, reference,
  development, security, status, future, decisions).
- Classified `plans/` into requirements, completed contracts, history, and an
  empty proposals folder. Markdown is canonical; HTML copies are frozen
  exports.
- Documented as-built architecture, OS install, CLI/API/worker operation,
  known limitations, and a clearly non-implemented future reference
  architecture.
- Added `make docs-check` (`tools/check_docs.py`) for Markdown links,
  frontmatter, and stale plan paths.

### Notes

- Live product behavior is unchanged by this documentation work.
- No license file is present; adding one is a project-owner decision.
