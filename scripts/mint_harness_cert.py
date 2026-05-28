"""Mint a harness mTLS client cert for the demo, printing env assignments the demo scripts capture.

Uses the shared CA under ``<data_dir>/certs`` (created by ``python -m auditor.auth.init_ca`` or the
auditor at startup). Output lines: HARNESS_CERT, HARNESS_KEY, HARNESS_CA, HARNESS_RUN_ID, HARNESS_TENANT_ID.
"""

from __future__ import annotations

from auditor.auth.ca import init_ca, mint_leaf_to_files
from auditor.config import get_settings
from auditor.ids import uuid7

DEMO_TENANT = "00000000-0000-0000-0000-000000000001"


def main() -> int:
    settings = get_settings()
    init_ca(settings.data_dir)
    run_id = str(uuid7())
    cert, key, ca = mint_leaf_to_files(
        settings.data_dir, role="harness", run_id=run_id, tenant_id=DEMO_TENANT, hostname="harness.local"
    )
    print(f"HARNESS_CERT={cert}")
    print(f"HARNESS_KEY={key}")
    print(f"HARNESS_CA={ca}")
    print(f"HARNESS_RUN_ID={run_id}")
    print(f"HARNESS_TENANT_ID={DEMO_TENANT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
