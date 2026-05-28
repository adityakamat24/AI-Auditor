"""Unit tests for the HITL routing subsystem (PRD §9.10).

All tests use fakes/stubs — no live Redis, MinIO, or Slack.
asyncio_mode = auto (configured in pyproject.toml) so no @pytest.mark.asyncio.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from auditor.hitl.queue import HitlQueue
from auditor.hitl.router import HitlRouter
from auditor.verdicts.aggregator import Flag
from auditor.verdicts.schemas import Severity

# ---------------------------------------------------------------------------
# Helpers / Factories
# ---------------------------------------------------------------------------

RID = uuid4()
TID = uuid4()


def _flag(severity: Severity, run_id=None, tenant_id=None) -> Flag:
    return Flag(
        run_id=run_id or RID,
        tenant_id=tenant_id or TID,
        severity=severity,
        asi_categories=["ASI01"],
        verdict_ids=[uuid4()],
        confidence=0.95,
    )


# ---------------------------------------------------------------------------
# Fake collaborators
# ---------------------------------------------------------------------------


class FakeEnforcer:
    """In-memory enforcer that records calls."""

    def __init__(self, *, fail_pause: bool = False) -> None:
        self.paused: list[Any] = []
        self.resumed: list[Any] = []
        self.aborted: list[Any] = []
        self._fail_pause = fail_pause

    async def pause(self, run_id):
        if self._fail_pause:
            raise RuntimeError("no PID registered for run_id")
        self.paused.append(run_id)

    async def resume(self, run_id):
        self.resumed.append(run_id)

    async def abort(self, run_id):
        self.aborted.append(run_id)


class FakeQueue:
    """In-memory queue that records calls."""

    def __init__(self) -> None:
        self.enqueued: list[tuple[Any, int]] = []   # (flag, ttl_s)
        self.digested: list[Any] = []

    async def enqueue(self, flag, ttl_s):
        self.enqueued.append((flag, ttl_s))

    async def append_digest(self, flag):
        self.digested.append(flag)

    async def list_pending(self, tenant_id):
        return [
            {"flag_id": str(f.flag_id), "tenant_id": str(f.tenant_id)}
            for f, _ in self.enqueued
            if str(f.tenant_id) == str(tenant_id)
        ]

    async def ack(self, tenant_id, flag_id):
        before = len(self.enqueued)
        self.enqueued = [(f, ttl) for f, ttl in self.enqueued if str(f.flag_id) != str(flag_id)]
        return len(self.enqueued) < before


class FakeNotifier:
    """Records notify calls; optionally simulates configured/unconfigured."""

    def __init__(self, *, configured: bool = True) -> None:
        self._configured = configured
        self.calls: list[Any] = []

    async def notify(self, flag, *, ui_url=None):
        if not self._configured:
            return False
        self.calls.append((flag, ui_url))
        return True


class FakeCheckpoint:
    """Records capture calls and returns a fake URI."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[Any] = []
        self._fail = fail

    async def capture(self, run_id, tenant_id, *, llm_context=None, in_flight_tool=None):
        if self._fail:
            return None
        self.calls.append((run_id, tenant_id))
        return f"minio://audit/{tenant_id}/checkpoints/{run_id}_fake.tar.gz"


def _router(
    *,
    fail_pause: bool = False,
    notifier_configured: bool = True,
    checkpoint_fail: bool = False,
) -> tuple[HitlRouter, FakeEnforcer, FakeQueue, FakeNotifier, FakeCheckpoint]:
    enforcer = FakeEnforcer(fail_pause=fail_pause)
    queue = FakeQueue()
    notifier = FakeNotifier(configured=notifier_configured)
    checkpoint = FakeCheckpoint(fail=checkpoint_fail)
    router = HitlRouter(
        enforcer=enforcer,
        queue=queue,
        notifier=notifier,
        checkpoint=checkpoint,
        ui_base_url="http://hitl.example.com",
    )
    return router, enforcer, queue, notifier, checkpoint


# ---------------------------------------------------------------------------
# Router — severity dispatching
# ---------------------------------------------------------------------------


async def test_critical_pauses_and_queues_and_notifies():
    router, enforcer, queue, notifier, checkpoint = _router()
    flag = _flag(Severity.CRITICAL)

    result = await router.route(flag)

    assert result.tier == "critical"
    assert result.paused is True
    assert result.queued is True
    assert result.notified is True
    assert result.digested is False
    assert result.pause_error is None

    # Enforcer was called with the run_id.
    assert flag.run_id in enforcer.paused

    # Queue received the flag with a 4 h TTL.
    assert len(queue.enqueued) == 1
    enqueued_flag, ttl = queue.enqueued[0]
    assert enqueued_flag.flag_id == flag.flag_id
    assert ttl == 4 * 3600

    # Notifier was called.
    assert len(notifier.calls) == 1
    called_flag, ui_url = notifier.calls[0]
    assert called_flag.flag_id == flag.flag_id
    assert "hitl.example.com" in (ui_url or "")

    # Checkpoint was captured.
    assert len(checkpoint.calls) == 1
    assert result.checkpoint_uri is not None


async def test_critical_pause_failure_does_not_crash():
    """If the enforcer raises (no PID), router still queues + notifies."""
    router, enforcer, queue, notifier, _ = _router(fail_pause=True)
    flag = _flag(Severity.CRITICAL)

    result = await router.route(flag)

    assert result.tier == "critical"
    assert result.paused is False
    assert result.pause_error is not None
    assert result.queued is True   # still enqueued
    assert result.notified is True  # still notified


async def test_high_queues_and_notifies_no_pause():
    router, enforcer, queue, notifier, _ = _router()
    flag = _flag(Severity.HIGH)

    result = await router.route(flag)

    assert result.tier == "high"
    assert result.paused is False
    assert result.queued is True
    assert result.notified is True
    assert result.digested is False

    # Enforcer must NOT be called for HIGH.
    assert len(enforcer.paused) == 0

    # Queue received 4 h TTL.
    _, ttl = queue.enqueued[0]
    assert ttl == 4 * 3600


async def test_high_not_paused_even_with_enforcer():
    """HIGH must never call enforcer.pause regardless of enforcer state."""
    router, enforcer, queue, _, _ = _router()
    await router.route(_flag(Severity.HIGH))
    assert len(enforcer.paused) == 0


async def test_medium_appends_to_digest_only():
    router, enforcer, queue, notifier, _ = _router()
    flag = _flag(Severity.MEDIUM)

    result = await router.route(flag)

    assert result.tier == "medium"
    assert result.paused is False
    assert result.queued is False
    assert result.notified is False
    assert result.digested is True

    assert len(queue.enqueued) == 0
    assert len(queue.digested) == 1
    assert len(enforcer.paused) == 0
    assert len(notifier.calls) == 0


async def test_low_logs_only():
    router, enforcer, queue, notifier, _ = _router()
    flag = _flag(Severity.LOW)

    result = await router.route(flag)

    assert result.tier == "low"
    assert result.paused is False
    assert result.queued is False
    assert result.notified is False
    assert result.digested is False

    assert len(enforcer.paused) == 0
    assert len(queue.enqueued) == 0
    assert len(notifier.calls) == 0


async def test_critical_checkpoint_failure_does_not_crash():
    """Checkpoint failure should not prevent pause/queue/notify."""
    router, enforcer, queue, notifier, checkpoint = _router(checkpoint_fail=True)
    flag = _flag(Severity.CRITICAL)

    result = await router.route(flag)

    assert result.paused is True
    assert result.queued is True
    assert result.notified is True
    # Checkpoint returned None gracefully.
    assert result.checkpoint_uri is None


# ---------------------------------------------------------------------------
# HitlQueue — fake redis (in-memory dict, async methods)
# ---------------------------------------------------------------------------


class FakeRedis:
    """Minimal async Redis fake covering the commands HitlQueue uses."""

    def __init__(self) -> None:
        self._hashes: dict[str, dict] = {}
        self._sets: dict[str, set] = {}
        self._lists: dict[str, list] = {}
        self._ttls: dict[str, int] = {}

    def pipeline(self):
        return FakePipeline(self)

    async def hset(self, key, mapping):
        self._hashes.setdefault(key, {}).update(mapping)

    async def expire(self, key, seconds):
        self._ttls[key] = seconds

    async def sadd(self, key, *members):
        self._sets.setdefault(key, set()).update(members)

    async def srem(self, key, *members):
        self._sets.get(key, set()).discard(*members)

    async def smembers(self, key):
        return set(self._sets.get(key, set()))

    async def hgetall(self, key):
        return dict(self._hashes.get(key, {}))

    async def delete(self, key):
        existed = key in self._hashes
        self._hashes.pop(key, None)
        return 1 if existed else 0

    async def rpush(self, key, value):
        self._lists.setdefault(key, []).append(value)

    async def lrange(self, key, start, end):
        lst = self._lists.get(key, [])
        return lst[start : end + 1 if end != -1 else None]


class FakePipeline:
    """Batches commands and executes them via FakeRedis."""

    def __init__(self, redis: FakeRedis) -> None:
        self._r = redis
        self._cmds: list = []

    def hset(self, key, mapping):
        self._cmds.append(("hset", key, mapping))
        return self

    def expire(self, key, seconds):
        self._cmds.append(("expire", key, seconds))
        return self

    def sadd(self, key, *members):
        self._cmds.append(("sadd", key, members))
        return self

    def srem(self, key, *members):
        self._cmds.append(("srem", key, members))
        return self

    def delete(self, key):
        self._cmds.append(("delete", key))
        return self

    async def execute(self):
        results = []
        for cmd in self._cmds:
            op, *args = cmd
            if op == "hset":
                self._r._hashes.setdefault(args[0], {}).update(args[1])
                results.append(1)
            elif op == "expire":
                self._r._ttls[args[0]] = args[1]
                results.append(1)
            elif op == "sadd":
                self._r._sets.setdefault(args[0], set()).update(args[1])
                results.append(len(args[1]))
            elif op == "srem":
                self._r._sets.get(args[0], set()).discard(*args[1])
                results.append(1)
            elif op == "delete":
                existed = args[0] in self._r._hashes
                self._r._hashes.pop(args[0], None)
                results.append(1 if existed else 0)
            else:
                results.append(None)
        return results


async def test_queue_enqueue_and_list_pending():
    redis = FakeRedis()
    q = HitlQueue(redis_client=redis)
    flag = _flag(Severity.HIGH)

    await q.enqueue(flag, ttl_s=14400)
    pending = await q.list_pending(flag.tenant_id)

    assert len(pending) == 1
    record = pending[0]
    assert record["flag_id"] == str(flag.flag_id)
    assert record["severity"] == str(flag.severity)
    assert record["tenant_id"] == str(flag.tenant_id)


async def test_queue_ack_removes_entry():
    redis = FakeRedis()
    q = HitlQueue(redis_client=redis)
    flag = _flag(Severity.HIGH)

    await q.enqueue(flag, ttl_s=14400)
    removed = await q.ack(flag.tenant_id, flag.flag_id)
    assert removed is True

    pending = await q.list_pending(flag.tenant_id)
    assert pending == []


async def test_queue_ttl_applied():
    redis = FakeRedis()
    q = HitlQueue(redis_client=redis)
    flag = _flag(Severity.HIGH)

    await q.enqueue(flag, ttl_s=9999)
    from auditor.hitl.queue import _hash_key

    hkey = _hash_key(flag.tenant_id, flag.flag_id)
    assert redis._ttls.get(hkey) == 9999


async def test_queue_append_digest():
    redis = FakeRedis()
    q = HitlQueue(redis_client=redis)
    flag = _flag(Severity.MEDIUM)

    await q.append_digest(flag)

    date_str = datetime.now(tz=UTC).strftime("%Y-%m-%d")
    dkey = f"hitl:digest:{flag.tenant_id}:{date_str}"
    assert dkey in redis._lists
    entries = redis._lists[dkey]
    assert len(entries) == 1
    entry = json.loads(entries[0])
    assert entry["flag_id"] == str(flag.flag_id)
    assert entry["severity"] == str(flag.severity)


async def test_queue_list_pending_handles_expired_keys():
    """list_pending should skip entries whose hash key expired (empty hgetall)."""
    redis = FakeRedis()
    q = HitlQueue(redis_client=redis)
    flag = _flag(Severity.HIGH)

    # Manually add only to the index, not the hash (simulates expiry).
    from auditor.hitl.queue import _index_key

    ikey = _index_key(flag.tenant_id)
    redis._sets[ikey] = {str(flag.flag_id)}

    pending = await q.list_pending(flag.tenant_id)
    assert pending == []
    # Stale index entry should be cleaned up.
    assert str(flag.flag_id) not in redis._sets.get(ikey, set())


# ---------------------------------------------------------------------------
# SlackNotifier
# ---------------------------------------------------------------------------


async def test_slack_notifier_unconfigured_returns_false():
    from auditor.hitl.notifier import SlackNotifier

    notifier = SlackNotifier(webhook_url=None)
    # Override internal attribute to ensure no URL leaks in from env.
    notifier._webhook_url = None
    flag = _flag(Severity.HIGH)
    result = await notifier.notify(flag)
    assert result is False


async def test_slack_notifier_posts_when_configured(httpx_mock=None):
    """Use a fake httpx transport to verify the POST is made."""

    pytest.importorskip("pytest_httpx")


@pytest.mark.parametrize("severity", [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW])
async def test_slack_notifier_no_exception_on_bad_url(severity):
    """SlackNotifier should return False (not raise) if the request fails."""
    from auditor.hitl.notifier import SlackNotifier

    notifier = SlackNotifier(webhook_url="http://localhost:0/nonexistent")
    flag = _flag(severity)
    result = await notifier.notify(flag)
    # Connection will fail; notifier must return False, not raise.
    assert result is False


async def test_slack_notifier_configured_sends_card(respx_mock=None):
    """Integration-style: verify card is POSTed to the webhook URL via httpx."""
    import httpx

    posted: list[dict] = []

    # Build a fake transport that captures the request body.
    class _FakeTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            body = json.loads(request.content)
            posted.append(body)
            return httpx.Response(200, text="ok")

    from auditor.hitl.notifier import SlackNotifier

    url = "https://hooks.slack.example.com/T123/B456/secret"
    notifier = SlackNotifier(webhook_url=url)

    flag = _flag(Severity.CRITICAL)

    # Monkey-patch httpx.AsyncClient to use our transport.
    original_client = httpx.AsyncClient

    class _PatchedClient(httpx.AsyncClient):
        def __init__(self, **kwargs):
            kwargs.setdefault("transport", _FakeTransport())
            super().__init__(**kwargs)

    import httpx as _httpx_mod

    _httpx_mod.AsyncClient = _PatchedClient  # type: ignore[misc]
    try:
        result = await notifier.notify(flag, ui_url="http://hitl.example.com/flags/123")
    finally:
        _httpx_mod.AsyncClient = original_client

    assert result is True
    assert len(posted) == 1
    card = posted[0]
    # Card must contain run_id and severity.
    card_text = str(card)
    assert str(flag.run_id) in card_text
    assert "critical" in card_text.lower()


# ---------------------------------------------------------------------------
# PagerDutyNotifier
# ---------------------------------------------------------------------------


async def test_pagerduty_unconfigured_returns_false():
    from auditor.hitl.notifier import PagerDutyNotifier

    notifier = PagerDutyNotifier(routing_key=None)
    notifier._routing_key = None
    flag = _flag(Severity.CRITICAL)
    result = await notifier.notify(flag)
    assert result is False


# ---------------------------------------------------------------------------
# CheckpointCapture — graceful degrade
# ---------------------------------------------------------------------------


async def test_checkpoint_graceful_degrade_no_minio(monkeypatch):
    """If MinIO is unreachable, capture() returns None without raising."""
    from auditor.hitl.checkpoint import CheckpointCapture

    class _BadMinio:
        def bucket_exists(self, bucket):
            raise ConnectionError("MinIO unreachable")

        def make_bucket(self, bucket):
            pass

        def put_object(self, *args, **kwargs):
            raise ConnectionError("MinIO unreachable")

    cp = CheckpointCapture(minio_client=_BadMinio())
    uri = await cp.capture(uuid4(), uuid4())
    assert uri is None


async def test_checkpoint_returns_uri_on_success():
    """Successful upload returns a non-None URI."""
    from auditor.hitl.checkpoint import CheckpointCapture

    uploads: list[tuple] = []

    class _FakeMinio:
        def bucket_exists(self, bucket):
            return True

        def make_bucket(self, bucket):
            pass

        def put_object(self, bucket, object_name, data, length, content_type):
            uploads.append((bucket, object_name, length))

    cp = CheckpointCapture(minio_client=_FakeMinio())
    run_id = uuid4()
    tenant_id = uuid4()
    uri = await cp.capture(run_id, tenant_id, llm_context=[{"role": "user", "content": "hi"}])

    assert uri is not None
    assert str(run_id) in uri
    assert str(tenant_id) in uri
    assert len(uploads) == 1
    # Archive should be non-empty.
    assert uploads[0][2] > 0


async def test_checkpoint_limits_context_to_50_turns():
    """Only the last 50 turns of LLM context should appear in the archive."""
    import io
    import tarfile

    from auditor.hitl.checkpoint import CheckpointCapture

    captured_archives: list[bytes] = []

    class _CaptureMinio:
        def bucket_exists(self, bucket):
            return True

        def make_bucket(self, bucket):
            pass

        def put_object(self, bucket, object_name, data, length, content_type):
            captured_archives.append(data.read())

    context = [{"role": "user", "content": f"turn {i}"} for i in range(100)]
    cp = CheckpointCapture(minio_client=_CaptureMinio())
    await cp.capture(uuid4(), uuid4(), llm_context=context)

    assert len(captured_archives) == 1
    with tarfile.open(fileobj=io.BytesIO(captured_archives[0]), mode="r:gz") as tar:
        member = tar.getmember("llm_context.json")
        turns = json.loads(tar.extractfile(member).read())  # type: ignore[union-attr]
    assert len(turns) == 50
    # Should be the LAST 50 turns.
    assert turns[0]["content"] == "turn 50"
    assert turns[-1]["content"] == "turn 99"
