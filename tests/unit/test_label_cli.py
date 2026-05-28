"""Unit tests for auditor.calibration.label (manual-labeling CLI).

All database access is replaced by monkeypatching ``auditor.calibration.label.get_sessionmaker``
with a fake async session factory — no live DB required.

Covers:
  - ``--add`` with valid args returns 0 and inserts a row.
  - ``--add`` with invalid category returns 2.
  - ``--add`` with invalid label returns 2.
  - ``--add`` missing --run-id returns 2.
  - ``--add`` missing --label returns 2.
  - ``--add`` missing --category returns 2.
  - ``--list`` returns 0.
  - ``--list --category ASI06`` returns 0.
  - ``--list`` with invalid category returns 2.
  - ``_add_ground_truth`` inserts a GroundTruth-compatible object.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from unittest.mock import patch

import auditor.calibration.label as label_mod
import pytest
from auditor.calibration.label import _add_ground_truth, _list_ground_truth, main

# ------------------------------------------------------------------------------- fake session + factory


class _FakeSession:
    """Minimal async session stub compatible with the label CLI helpers."""

    def __init__(self, existing_rows: list[Any] | None = None) -> None:
        self._rows: list[Any] = list(existing_rows or [])
        self.added: list[Any] = []
        self.flushed: bool = False

    async def execute(self, stmt, *args, **kwargs):  # noqa: ARG002
        class _Result:
            def __init__(self, rows: list[Any]) -> None:
                self._rows = rows

            def scalars(self) -> _Result:
                return self

            def all(self) -> list[Any]:
                return self._rows

        return _Result(self._rows)

    def add(self, obj: Any) -> None:
        self.added.append(obj)
        # Simulate the ORM making the row available after add.
        self._rows.append(obj)

    async def flush(self) -> None:
        self.flushed = True

    async def commit(self) -> None:
        pass

    def begin(self) -> _FakeSession:
        return self

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass


class _FakeSessionMaker:
    """Fake async_sessionmaker: calling it returns a _FakeSession context manager."""

    def __init__(self, session: _FakeSession) -> None:
        self._session = session

    def __call__(self) -> _FakeSession:
        return self._session


def _make_fake_sm(session: _FakeSession | None = None) -> _FakeSessionMaker:
    return _FakeSessionMaker(session or _FakeSession())


# ------------------------------------------------------------------------------- helper: patch get_sessionmaker


def _patch_sm(sm: _FakeSessionMaker):
    """Context manager that replaces label_mod.get_sessionmaker with *sm*."""
    return patch.object(label_mod, "get_sessionmaker", return_value=sm)


# ------------------------------------------------------------------------------- tests: _add_ground_truth


class TestAddGroundTruth:
    def test_inserts_row_with_correct_fields(self):
        session = _FakeSession()
        run_id = str(uuid.uuid4())

        async def _run():
            return await _add_ground_truth(
                session,
                trace_uri=run_id,
                asi_category="ASI06",
                label="VIOLATION",
                source="manual",
            )

        row = asyncio.run(_run())
        assert len(session.added) == 1
        assert row is session.added[0]
        assert row.asi_category == "ASI06"
        assert row.label == "VIOLATION"
        assert row.trace_uri == run_id
        assert row.source == "manual"
        assert session.flushed

    def test_inserts_ok_label(self):
        session = _FakeSession()

        async def _run():
            return await _add_ground_truth(
                session,
                trace_uri="uri://test",
                asi_category="ASI01",
                label="OK",
                source="adversarial",
            )

        row = asyncio.run(_run())
        assert row.label == "OK"
        assert row.asi_category == "ASI01"


# ------------------------------------------------------------------------------- tests: _list_ground_truth


class TestListGroundTruth:
    def _make_row(self, category: str = "ASI06") -> Any:
        class _Row:
            pass

        r = _Row()
        r.gt_id = uuid.uuid4()
        r.asi_category = category
        r.label = "VIOLATION"
        r.trace_uri = str(uuid.uuid4())
        r.source = "manual"
        from datetime import UTC, datetime

        r.created_at = datetime(2026, 1, 1, tzinfo=UTC)
        return r

    def test_returns_all_rows_when_no_filter(self):
        rows = [self._make_row("ASI01"), self._make_row("ASI06")]
        session = _FakeSession(existing_rows=rows)

        async def _run():
            return await _list_ground_truth(session, category=None)

        result = asyncio.run(_run())
        # The fake session returns whatever is in _rows; our add() also appends to _rows,
        # but here we seeded directly, so result length == 2.
        assert len(result) == 2

    def test_category_filter_applied(self):
        """_list_ground_truth passes the category to the WHERE clause; the fake returns all rows
        because the stmt_str inspection is not done here — we test that the helper builds the
        query without error and returns whatever the session gives back."""
        session = _FakeSession(existing_rows=[self._make_row("ASI06")])

        async def _run():
            return await _list_ground_truth(session, category="ASI06")

        result = asyncio.run(_run())
        assert isinstance(result, list)


# ------------------------------------------------------------------------------- tests: main() -- --add


class TestMainAdd:
    def test_valid_add_returns_0(self, capsys):
        session = _FakeSession()
        sm = _make_fake_sm(session)
        run_id = str(uuid.uuid4())
        with _patch_sm(sm):
            rc = main(["--add", "--run-id", run_id, "--category", "ASI06", "--label", "VIOLATION"])
        assert rc == 0
        assert len(session.added) == 1
        assert session.added[0].label == "VIOLATION"
        assert session.added[0].asi_category == "ASI06"

    def test_add_with_source_flag(self):
        session = _FakeSession()
        sm = _make_fake_sm(session)
        run_id = str(uuid.uuid4())
        with _patch_sm(sm):
            rc = main([
                "--add", "--run-id", run_id,
                "--category", "ASI01",
                "--label", "OK",
                "--source", "adversarial",
            ])
        assert rc == 0
        assert session.added[0].source == "adversarial"

    def test_invalid_category_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--add", "--run-id", "some-uri", "--category", "ASI99", "--label", "VIOLATION"])
        assert exc_info.value.code == 2

    def test_invalid_label_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--add", "--run-id", "some-uri", "--category", "ASI06", "--label", "BAD"])
        assert exc_info.value.code == 2

    def test_missing_run_id_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--add", "--category", "ASI06", "--label", "VIOLATION"])
        assert exc_info.value.code == 2

    def test_missing_label_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--add", "--run-id", "some-uri", "--category", "ASI06"])
        assert exc_info.value.code == 2

    def test_missing_category_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--add", "--run-id", "some-uri", "--label", "VIOLATION"])
        assert exc_info.value.code == 2

    def test_all_asi_categories_accepted(self):
        for i in range(1, 11):
            cat = f"ASI{i:02d}"
            session = _FakeSession()
            sm = _make_fake_sm(session)
            with _patch_sm(sm):
                rc = main(["--add", "--run-id", "uri://x", "--category", cat, "--label", "OK"])
            assert rc == 0, f"category {cat} should be accepted"


# ------------------------------------------------------------------------------- tests: main() -- --list


class TestMainList:
    def test_list_returns_0_empty(self, capsys):
        session = _FakeSession()
        sm = _make_fake_sm(session)
        with _patch_sm(sm):
            rc = main(["--list"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "no ground truth rows found" in out

    def test_list_with_category_filter_returns_0(self):
        session = _FakeSession()
        sm = _make_fake_sm(session)
        with _patch_sm(sm):
            rc = main(["--list", "--category", "ASI06"])
        assert rc == 0

    def test_list_invalid_category_exits_2(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--list", "--category", "BADCAT"])
        assert exc_info.value.code == 2

    def test_list_prints_rows(self, capsys):
        class _Row:
            pass

        r = _Row()
        r.gt_id = uuid.uuid4()
        r.asi_category = "ASI03"
        r.label = "OK"
        r.trace_uri = "uri://trace"
        r.source = "manual"
        from datetime import UTC, datetime

        r.created_at = datetime(2026, 1, 2, tzinfo=UTC)

        session = _FakeSession(existing_rows=[r])
        sm = _make_fake_sm(session)
        with _patch_sm(sm):
            rc = main(["--list"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "ASI03" in out
        assert "OK" in out


# ------------------------------------------------------------------------------- tests: mutually exclusive flags


class TestCliMutualExclusion:
    def test_no_mode_flag_exits_nonzero(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--run-id", "some-uri"])
        assert exc_info.value.code != 0

    def test_add_and_list_together_exits_nonzero(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--add", "--list", "--run-id", "x", "--category", "ASI01", "--label", "OK"])
        assert exc_info.value.code != 0
