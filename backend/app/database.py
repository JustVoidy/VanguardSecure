import os
import redis as _redis_lib

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# ── SQLAlchemy (User model / auth only) ──────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./netshield.db")
_kwargs = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ── Redis (event store) ───────────────────────────────────────────────────────
_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


def _make_redis():
    try:
        c = _redis_lib.from_url(_REDIS_URL, decode_responses=True)
        c.ping()
        print(f"[database] Redis connected: {_REDIS_URL}")
        return c
    except Exception as e:
        print(f"[database] Redis unavailable: {e}")
        return None


redis_client: _redis_lib.Redis | None = _make_redis()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
