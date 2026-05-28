"""HITL review queue (PRD §9.10) — Redis-backed pending-flag store.

Each enqueued flag is stored as a compact JSON record in a Redis hash keyed by
``hitl:queue:{tenant_id}:{flag_id}``.  A per-tenant index set
``hitl:index:{tenant_id}`` tracks which flag_ids exist for that tenant so
:meth:`list_pending` can enumerate them without a SCAN.

TTL is applied via EXPIREAT on the individual hash key so each flag ages out
independently.  Acknowledgement removes both the hash and the index entry.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from auditor.logging import get_logger

if TYPE_CHECKING:
    from auditor.verdicts.aggregator import Flag

log = get_logger("auditor.hitl.queue")

_HASH_PREFIX = "hitl:queue"
_INDEX_PREFIX = "hitl:index"


def _hash_key(tenant_id: UUID | str, flag_id: UUID | str) -> str:
    return f"{_HASH_PREFIX}:{tenant_id}:{flag_id}"


def _index_key(tenant_id: UUID | str) -> str:
    return f"{_INDEX_PREFIX}:{tenant_id}"


def _digest_key(tenant_id: UUID | str, date: str) -> str:
    """Daily-digest list key for MEDIUM flags."""
    return f"hitl:digest:{tenant_id}:{date}"


class HitlQueue:
    """Redis-backed queue for flags awaiting human review.

    Parameters
    ----------
    redis_client:
        An ``redis.asyncio`` client.  If ``None``, one is created from
        ``settings.redis_url`` on first use.
    """

    def __init__(self, redis_client: object | None = None) -> None:
        self._client = redis_client

    async def _get_client(self) -> object:
        if self._client is None:
            import redis.asyncio as aioredis

            from auditor.config import get_settings

            settings = get_settings()
            self._client = aioredis.from_url(
                settings.redis_url,
                decode_responses=True,
            )
        return self._client

    async def enqueue(self, flag: Flag, ttl_s: int) -> None:
        """Store *flag* in Redis with the given TTL (seconds)."""
        client = await self._get_client()
        record = {
            "flag_id": str(flag.flag_id),
            "run_id": str(flag.run_id),
            "tenant_id": str(flag.tenant_id),
            "severity": str(flag.severity),
            "asi_categories": json.dumps(flag.asi_categories),
            "confidence": str(flag.confidence),
            "status": flag.status,
            "enqueued_at": datetime.now(tz=UTC).isoformat(),
        }
        hkey = _hash_key(flag.tenant_id, flag.flag_id)
        ikey = _index_key(flag.tenant_id)

        # Use a pipeline for atomic set + expire + index add.
        pipe = client.pipeline()  # type: ignore[union-attr]
        pipe.hset(hkey, mapping=record)
        pipe.expire(hkey, ttl_s)
        pipe.sadd(ikey, str(flag.flag_id))
        await pipe.execute()

        log.info(
            "hitl.queue.enqueued",
            flag_id=str(flag.flag_id),
            tenant_id=str(flag.tenant_id),
            ttl_s=ttl_s,
        )

    async def append_digest(self, flag: Flag) -> None:
        """Append a compact digest entry for a MEDIUM flag (daily list per tenant)."""
        client = await self._get_client()
        date_str = datetime.now(tz=UTC).strftime("%Y-%m-%d")
        dkey = _digest_key(flag.tenant_id, date_str)
        entry = json.dumps({
            "flag_id": str(flag.flag_id),
            "run_id": str(flag.run_id),
            "severity": str(flag.severity),
            "asi_categories": flag.asi_categories,
            "ts": datetime.now(tz=UTC).isoformat(),
        })
        await client.rpush(dkey, entry)  # type: ignore[union-attr]
        # Keep the digest list for 48 h so daily reports can look back one day.
        await client.expire(dkey, 48 * 3600)  # type: ignore[union-attr]
        log.debug(
            "hitl.queue.digest_appended",
            flag_id=str(flag.flag_id),
            tenant_id=str(flag.tenant_id),
            date=date_str,
        )

    async def list_pending(self, tenant_id: UUID | str) -> list[dict]:
        """Return all pending flag records for *tenant_id*."""
        client = await self._get_client()
        ikey = _index_key(tenant_id)
        flag_ids: set[str] = await client.smembers(ikey)  # type: ignore[union-attr]
        if not flag_ids:
            return []

        results: list[dict] = []
        for fid in flag_ids:
            hkey = _hash_key(tenant_id, fid)
            record: dict = await client.hgetall(hkey)  # type: ignore[union-attr]
            if record:  # key may have already expired
                results.append(record)
            else:
                # Clean up stale index entry.
                await client.srem(ikey, fid)  # type: ignore[union-attr]

        return results

    async def ack(self, tenant_id: UUID | str, flag_id: UUID | str) -> bool:
        """Acknowledge (remove) a flag from the queue.  Returns True if it existed."""
        client = await self._get_client()
        hkey = _hash_key(tenant_id, flag_id)
        ikey = _index_key(tenant_id)

        pipe = client.pipeline()  # type: ignore[union-attr]
        pipe.delete(hkey)
        pipe.srem(ikey, str(flag_id))
        results = await pipe.execute()
        deleted = bool(results[0])

        log.info(
            "hitl.queue.acked",
            flag_id=str(flag_id),
            tenant_id=str(tenant_id),
            existed=deleted,
        )
        return deleted


__all__ = ["HitlQueue"]
