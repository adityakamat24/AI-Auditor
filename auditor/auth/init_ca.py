"""Private CA bootstrap CLI (PRD §11.1/§11.4): mint the mTLS root CA.

Usage: ``python -m auditor.auth.init_ca``. Idempotent - does nothing if the CA already exists. Per-run
leaf certs are minted at run start by the auditor (see :func:`auditor.auth.ca.mint_leaf_to_files`).
"""

from __future__ import annotations

from auditor.auth.ca import init_ca
from auditor.config import get_settings


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    ca_cert, _ca_key = init_ca(settings.data_dir)
    print(f"CA ready: {ca_cert}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
