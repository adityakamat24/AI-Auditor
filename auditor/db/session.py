"""Async SQLAlchemy engine + session factory.

The engine is created lazily so importing this module never opens a connection (keeps unit tests and
app import side-effect-free). Use :func:`get_sessionmaker` for sessions and :func:`dispose_engine`
on shutdown.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from auditor.config import Settings, get_settings

_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine(settings: Settings | None = None) -> AsyncEngine:
    global _engine
    if _engine is None:
        settings = settings or get_settings()
        _engine = create_async_engine(
            settings.postgres_dsn,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_pre_ping=True,
        )
    return _engine


def get_sessionmaker(settings: Settings | None = None) -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            get_engine(settings), expire_on_commit=False, class_=AsyncSession
        )
    return _sessionmaker


async def dispose_engine() -> None:
    """Dispose the engine/pool (call on shutdown). Resets the lazy singletons."""
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
