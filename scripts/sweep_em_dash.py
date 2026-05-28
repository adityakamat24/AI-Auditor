"""One-shot sweep: replace U+2014 (em dash) with a plain hyphen in every project text file.

Byte-level replacement (UTF-8 em dash is the three bytes 0xE2 0x80 0x94) so we don't accidentally
re-encode files or normalize line endings. Skips vendored dirs (venv, node_modules, caches, .git).

Usage:
    python scripts/sweep_em_dash.py
"""

from __future__ import annotations

from pathlib import Path

EXTS = {
    ".py", ".ts", ".tsx", ".js", ".md", ".bat", ".ps1", ".sh",
    ".css", ".html", ".json", ".yml", ".yaml", ".toml", ".rego",
    ".proto", ".sql", ".ini", ".cfg",
}
EXCLUDE = {
    ".venv", "node_modules", ".git", "dist", "__pycache__",
    ".pytest_cache", ".ruff_cache", ".mypy_cache", ".run",
    "target",
}
EXTRA_FILES = {".env.example", ".gitignore", ".gitattributes", ".dockerignore", "Makefile"}

EM = b"\xe2\x80\x94"
REPL = b"-"


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    changed: list[Path] = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in EXCLUDE for part in path.parts):
            continue
        if path.suffix not in EXTS and path.name not in EXTRA_FILES:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if EM not in data:
            continue
        path.write_bytes(data.replace(EM, REPL))
        changed.append(path.relative_to(root))

    print(f"patched {len(changed)} files")
    for c in changed:
        print(f"  {c}")


if __name__ == "__main__":
    main()
