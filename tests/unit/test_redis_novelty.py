"""RedisNoveltyIndex over a fake sync redis client; matches the in-memory novelty semantics."""

from __future__ import annotations

from uuid import uuid4

from auditor.async_pipeline.sampler import InMemoryNoveltyIndex, RedisNoveltyIndex

TENANT = uuid4()


class _FakeRedis:
    """Minimal sync redis stand-in: just the set ops RedisNoveltyIndex uses."""

    def __init__(self) -> None:
        self.sets: dict[str, set[str]] = {}

    def sismember(self, key: str, member: str) -> bool:
        return member in self.sets.get(key, set())

    def sadd(self, key: str, *members: str) -> None:
        self.sets.setdefault(key, set()).update(members)


def test_first_sight_is_novel_then_seen() -> None:
    idx = RedisNoveltyIndex(_FakeRedis())
    assert idx.is_novel(TENANT, frozenset({"http_get"}), frozenset()) is True
    assert idx.is_novel(TENANT, frozenset({"http_get"}), frozenset()) is False  # now seen


def test_new_tool_or_egress_retriggers_novelty() -> None:
    idx = RedisNoveltyIndex(_FakeRedis())
    idx.is_novel(TENANT, frozenset({"http_get"}), frozenset({"a.com"}))
    assert idx.is_novel(TENANT, frozenset({"http_get"}), frozenset({"a.com"})) is False
    assert idx.is_novel(TENANT, frozenset({"exec_shell"}), frozenset()) is True  # new tool
    assert idx.is_novel(TENANT, frozenset(), frozenset({"b.com"})) is True  # new egress


def test_matches_in_memory_semantics() -> None:
    mem = InMemoryNoveltyIndex()
    red = RedisNoveltyIndex(_FakeRedis())
    calls = [
        (frozenset({"t1"}), frozenset()),
        (frozenset({"t1"}), frozenset()),
        (frozenset({"t1", "t2"}), frozenset({"x.com"})),
        (frozenset({"t2"}), frozenset({"x.com"})),
    ]
    for tools, egress in calls:
        assert mem.is_novel(TENANT, tools, egress) == red.is_novel(TENANT, tools, egress)
