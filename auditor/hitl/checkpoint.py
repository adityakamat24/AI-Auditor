"""HITL checkpoint (PRD §9.10.2) — snapshot run state and upload to MinIO.

:class:`CheckpointCapture` builds an in-memory ``tar.gz`` archive containing
the agent's recent LLM context (last ≤50 turns), the in-flight tool state,
and best-effort process-state information.  The archive is then uploaded to
MinIO at ``audit/{tenant_id}/checkpoints/{run_id}_{ts}.tar.gz``.

If MinIO is unreachable the capture degrades gracefully: logs a warning and
returns ``None`` so callers can continue without crashing.
"""

from __future__ import annotations

import asyncio
import io
import json
import tarfile
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from auditor.logging import get_logger

log = get_logger("auditor.hitl.checkpoint")

_OBJECT_PREFIX = "audit"


class CheckpointCapture:
    """Build and upload run checkpoints to MinIO.

    Parameters
    ----------
    minio_client:
        A pre-built ``minio.Minio`` instance.  If ``None``, one is constructed
        from ``settings`` on first capture.
    enforcer:
        The platform enforcer (used for best-effort quarantine/dump info).
        If ``None``, process-state capture records that it is unavailable.
    """

    def __init__(
        self,
        minio_client: object | None = None,
        enforcer: object | None = None,
    ) -> None:
        self._minio = minio_client
        self._enforcer = enforcer

    def _get_minio(self) -> object:
        if self._minio is None:
            from minio import Minio

            from auditor.config import get_settings

            s = get_settings()
            self._minio = Minio(
                s.minio_endpoint,
                access_key=s.minio_access_key,
                secret_key=s.minio_secret_key,
                secure=s.minio_secure,
            )
        return self._minio

    def _get_bucket(self) -> str:
        from auditor.config import get_settings

        s = get_settings()
        return s.minio_bucket_audit

    def _build_archive(
        self,
        run_id: UUID | str,
        tenant_id: UUID | str,
        *,
        llm_context: list[dict[str, Any]] | None,
        in_flight_tool: dict[str, Any] | None,
        process_state_info: dict[str, Any],
    ) -> bytes:
        """Build an in-memory tar.gz and return the raw bytes."""
        buf = io.BytesIO()

        def _add(tar: tarfile.TarFile, name: str, data: str | bytes) -> None:
            if isinstance(data, str):
                data = data.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            # 1. LLM context — last ≤50 turns.
            ctx_turns = (llm_context or [])[-50:]
            _add(tar, "llm_context.json", json.dumps(ctx_turns, default=str, indent=2))

            # 2. In-flight tool state.
            _add(
                tar,
                "in_flight_tool.json",
                json.dumps(in_flight_tool or {}, default=str, indent=2),
            )

            # 3. Process state (best-effort).
            _add(
                tar,
                "process_state.json",
                json.dumps(process_state_info, default=str, indent=2),
            )

            # 4. Manifest.
            manifest = {
                "run_id": str(run_id),
                "tenant_id": str(tenant_id),
                "captured_at": datetime.now(tz=UTC).isoformat(),
                "llm_context_turns": len(ctx_turns),
                "has_in_flight_tool": in_flight_tool is not None,
            }
            _add(tar, "manifest.json", json.dumps(manifest, default=str, indent=2))

        return buf.getvalue()

    def _collect_process_state(self, run_id: UUID | str) -> dict[str, Any]:
        """Best-effort process-state info from the enforcer."""
        info: dict[str, Any] = {"enforcer_available": self._enforcer is not None}

        if self._enforcer is None:
            info["note"] = "no enforcer injected; process state unavailable"
            return info

        # Record enforcer type.
        info["enforcer_type"] = type(self._enforcer).__name__

        # If the enforcer exposes a registered PID use it.
        try:
            pid = self._enforcer._pid(run_id)  # type: ignore[attr-defined]
            info["pid"] = pid
            if pid is not None:
                import psutil

                proc = psutil.Process(pid)
                info["proc_status"] = proc.status()
                info["proc_memory_mb"] = round(proc.memory_info().rss / 1024 / 1024, 2)
        except Exception as exc:  # noqa: BLE001
            info["pid_error"] = str(exc)

        # Note quarantine capability (the actual dump is the enforcer's job; we record availability).
        info["quarantine_capable"] = hasattr(self._enforcer, "quarantine")

        return info

    def _upload(self, bucket: str, object_name: str, data: bytes) -> None:
        """Synchronous upload — run via asyncio.to_thread."""
        minio = self._get_minio()
        # Ensure bucket exists.
        try:
            if not minio.bucket_exists(bucket):  # type: ignore[union-attr]
                minio.make_bucket(bucket)  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001
            log.debug("hitl.checkpoint.bucket_check_failed", bucket=bucket, error=str(exc))

        minio.put_object(  # type: ignore[union-attr]
            bucket,
            object_name,
            data=io.BytesIO(data),
            length=len(data),
            content_type="application/gzip",
        )

    async def capture(
        self,
        run_id: UUID | str,
        tenant_id: UUID | str,
        *,
        llm_context: list[dict[str, Any]] | None = None,
        in_flight_tool: dict[str, Any] | None = None,
    ) -> str | None:
        """Build and upload a checkpoint archive.

        Returns the MinIO URI (``minio://{bucket}/{object}``) on success, or
        ``None`` if MinIO is unreachable or any error occurs.
        """
        ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        object_name = f"{_OBJECT_PREFIX}/{tenant_id}/checkpoints/{run_id}_{ts}.tar.gz"
        bucket = self._get_bucket()

        # Collect process state (best-effort, sync — cheap).
        process_state = self._collect_process_state(run_id)

        # Build archive bytes in a thread to avoid blocking the event loop.
        try:
            archive_bytes: bytes = await asyncio.to_thread(
                self._build_archive,
                run_id,
                tenant_id,
                llm_context=llm_context,
                in_flight_tool=in_flight_tool,
                process_state_info=process_state,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("hitl.checkpoint.build_failed", run_id=str(run_id), error=str(exc))
            return None

        # Upload in a thread.
        try:
            await asyncio.to_thread(self._upload, bucket, object_name, archive_bytes)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "hitl.checkpoint.upload_failed",
                run_id=str(run_id),
                object_name=object_name,
                error=str(exc),
            )
            return None

        uri = f"minio://{bucket}/{object_name}"
        log.info(
            "hitl.checkpoint.captured",
            run_id=str(run_id),
            tenant_id=str(tenant_id),
            uri=uri,
            size_bytes=len(archive_bytes),
        )
        return uri


__all__ = ["CheckpointCapture"]
