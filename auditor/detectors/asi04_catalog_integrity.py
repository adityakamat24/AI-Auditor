"""ASI04 Catalog-Integrity startup check (PRD §9.7.4 / §15 Phase-4 acceptance item ASI04).

This module implements the **startup** half of ASI04: tool *implementation-file* integrity.

At catalog-publish time the orchestrator calls :func:`publish_catalog` to capture a sha256
fingerprint of every tool implementation file.  Those fingerprints are persisted alongside the
catalog (e.g. in run metadata or a side-car manifest).  At run-start time the orchestrator calls
:func:`verify_catalog_integrity` to re-hash the current files and compare them against the
published manifest.  Any discrepancy - a modified file, a tool removed after publish, or a tool
added that was not present at publish - produces a CRITICAL :class:`~auditor.verdicts.schemas.Verdict`
and must fail the run.

This is a standalone startup check.  It is NOT registered in the detector registry; the per-event
supply-chain detector (:mod:`auditor.detectors.asi04_supply_chain`) handles the runtime
``schema_hash`` check separately.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import UUID

from auditor.verdicts.schemas import Evidence, Severity, Verdict, VerdictResult

# ---------------------------------------------------------------------------
# Core hashing helpers
# ---------------------------------------------------------------------------


def hash_tool_file(path: str | Path) -> str:
    """Return the sha256 hex-digest of *path*'s raw bytes.

    Raises :class:`FileNotFoundError` if *path* does not exist, and
    :class:`OSError` for other I/O problems - callers should handle these
    appropriately (a missing file that *was* present at publish time is a
    CRITICAL integrity violation).
    """
    p = Path(path)
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    return digest


# ---------------------------------------------------------------------------
# Catalog publish / verify API
# ---------------------------------------------------------------------------


def publish_catalog(tool_files: dict[str, str | Path]) -> dict[str, str]:
    """Hash every implementation file and return a ``tool_name -> sha256`` manifest.

    Call this once when publishing the tool catalog.  Persist the returned
    mapping alongside the catalog so :func:`verify_catalog_integrity` can
    compare it at run-start.

    Args:
        tool_files: Mapping of ``tool_name`` to the path of its implementation
            file.  All paths must exist at publish time.

    Returns:
        A new ``dict[str, str]`` where each value is the sha256 hex-digest of
        the corresponding implementation file's bytes.

    Raises:
        FileNotFoundError: if any path in *tool_files* does not exist.
    """
    return {name: hash_tool_file(path) for name, path in tool_files.items()}


def verify_catalog_integrity(
    published: dict[str, str],
    current_files: dict[str, str | Path],
    *,
    run_id: UUID,
    tenant_id: UUID,
) -> list[Verdict]:
    """Compare current implementation-file hashes against the *published* manifest.

    For each discrepancy a CRITICAL VIOLATION :class:`Verdict` is produced.
    Discrepancy cases:

    - **Modified**: a tool present in *published* whose file hash now differs.
    - **Removed**: a tool present in *published* whose path no longer exists
      (or is absent from *current_files*).
    - **Added**: a tool present in *current_files* that was not in *published*
      (new, un-audited tool injected after catalog publish).

    Returns an empty list (with a single OK verdict) when all hashes match and
    no tools were added or removed - matching the style of
    :mod:`auditor.detectors.asi04_supply_chain`.

    Args:
        published: The manifest returned by :func:`publish_catalog`.
        current_files: Current ``tool_name -> path`` mapping, as it stands at
            run-start.
        run_id: The run UUID (passed through to each :class:`Verdict`).
        tenant_id: The tenant UUID (passed through to each :class:`Verdict`).

    Returns:
        A list of :class:`Verdict` objects - one OK verdict if everything
        matches, or one CRITICAL VIOLATION verdict per discrepancy found.
    """
    evidence: list[Evidence] = []

    published_tools = set(published.keys())
    current_tools = set(current_files.keys())

    # --- 1. Modified or removed tools (present at publish) ---
    for tool_name in published_tools:
        if tool_name not in current_tools:
            # Tool present at publish but absent from the current file map.
            evidence.append(
                Evidence(
                    reason=(
                        f"[{Severity.CRITICAL}] tool {tool_name!r} was present at catalog publish "
                        "but is missing from the current tool-file map (removed or unregistered)"
                    )
                )
            )
            continue

        path = current_files[tool_name]
        try:
            current_hash = hash_tool_file(path)
        except FileNotFoundError:
            evidence.append(
                Evidence(
                    reason=(
                        f"[{Severity.CRITICAL}] tool {tool_name!r} implementation file "
                        f"{str(path)!r} no longer exists (file removed after catalog publish)"
                    )
                )
            )
            continue
        except OSError as exc:
            evidence.append(
                Evidence(
                    reason=(
                        f"[{Severity.CRITICAL}] tool {tool_name!r} implementation file "
                        f"{str(path)!r} could not be read: {exc}"
                    )
                )
            )
            continue

        expected_hash = published[tool_name]
        if current_hash != expected_hash:
            evidence.append(
                Evidence(
                    reason=(
                        f"[{Severity.CRITICAL}] tool {tool_name!r} implementation file modified: "
                        f"published hash {expected_hash[:12]}.. != current {current_hash[:12]}.."
                    )
                )
            )

    # --- 2. Added tools (present now but not at publish) ---
    for tool_name in current_tools - published_tools:
        evidence.append(
            Evidence(
                reason=(
                    f"[{Severity.CRITICAL}] tool {tool_name!r} was not present at catalog publish "
                    "but exists in the current tool-file map (tool injected after publish)"
                )
            )
        )

    # --- Build verdict(s) ---
    if not evidence:
        return [
            Verdict(
                run_id=run_id,
                tenant_id=tenant_id,
                detector="asi04_catalog_integrity",
                asi_category="ASI04",
                result=VerdictResult.OK,
                confidence=1.0,
                evidence=[
                    Evidence(
                        reason=(
                            f"all {len(published_tools)} tool implementation file hashes "
                            "match the published catalog"
                        )
                    )
                ],
            )
        ]

    # One VIOLATION verdict per piece of evidence keeps the aggregator / flag
    # table clean; the PRD does not mandate batching, and separate verdicts give
    # a clearer audit trail.
    verdicts: list[Verdict] = []
    for ev in evidence:
        verdicts.append(
            Verdict(
                run_id=run_id,
                tenant_id=tenant_id,
                detector="asi04_catalog_integrity",
                asi_category="ASI04",
                result=VerdictResult.VIOLATION,
                confidence=0.99,
                evidence=[ev],
                rubric_scores={"severity": "critical"},
            )
        )
    return verdicts


# ---------------------------------------------------------------------------
# Optional convenience wrapper
# ---------------------------------------------------------------------------


class CatalogIntegrityCheck:
    """Thin stateful wrapper around :func:`publish_catalog` and :func:`verify_catalog_integrity`.

    Usage::

        check = CatalogIntegrityCheck()
        check.publish(tool_files)          # at catalog-publish time
        verdicts = check.verify(tool_files, run_id=..., tenant_id=...)  # at run-start
    """

    def __init__(self) -> None:
        self._manifest: dict[str, str] = {}

    def publish(self, tool_files: dict[str, str | Path]) -> dict[str, str]:
        """Hash *tool_files* and store the manifest internally.  Returns the manifest."""
        self._manifest = publish_catalog(tool_files)
        return self._manifest

    @property
    def manifest(self) -> dict[str, str]:
        """The manifest produced by the last :meth:`publish` call."""
        return dict(self._manifest)

    def verify(
        self,
        current_files: dict[str, str | Path],
        *,
        run_id: UUID,
        tenant_id: UUID,
    ) -> list[Verdict]:
        """Verify *current_files* against the stored manifest and return verdicts."""
        return verify_catalog_integrity(
            self._manifest,
            current_files,
            run_id=run_id,
            tenant_id=tenant_id,
        )


__all__ = [
    "hash_tool_file",
    "publish_catalog",
    "verify_catalog_integrity",
    "CatalogIntegrityCheck",
]
