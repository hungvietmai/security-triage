from collections.abc import Generator
from typing import Annotated, Any

from fastapi import Depends
from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import get_settings
from app.core.exceptions import NotFoundError

# Deterministic names for unnamed constraints, identical to PostgreSQL's defaults
# (so existing migrations match). Check and unique constraints are always named
# explicitly (ck_…, uq_…) and therefore have no template here.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "fk": "%(table_name)s_%(column_0_name)s_fkey",
    "pk": "%(table_name)s_pkey",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


engine = create_engine(get_settings().database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_session() -> Generator[Session]:
    with SessionLocal() as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


def get_or_raise[M](
    session: Session, model: type[M], ident: Any, error: type[NotFoundError] = NotFoundError
) -> M:
    """Load `model` by primary key or raise `error` (a feature's own 404)."""
    instance = session.get(model, ident)
    if instance is None:
        raise error()
    return instance
