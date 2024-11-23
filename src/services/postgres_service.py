import logging
from typing import Any, Generic, Type, TypeVar
from psycopg2.errors import UniqueViolation, GeneratedAlways
from sqlalchemy import create_engine, update
from sqlalchemy.orm import scoped_session, sessionmaker, Query

from contextlib import contextmanager
from sqlalchemy.exc import IntegrityError, ProgrammingError
from src.services.exceptions import (
    IdGeneratedAlways,
)
from src.services.config import PostgresServiceConfig
from src.services.exceptions import ObjectAlreadyExists, ObjectNotFound
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

T = TypeVar("T", bound=Any)

logger = logging.getLogger(__name__)


class SingletonService(object):
    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, "instance"):
            cls.instance = super(SingletonService, cls).__new__(cls)
        return cls.instance


class PostgresService(Generic[T]):
    def __init__(
        self,
        url: str,
        base: Any,
        model: Type[T],
        pool_size=PostgresServiceConfig.pool_size,
    ) -> None:
        self.engine = create_engine(
            url, echo=True, pool_size=pool_size, max_overflow=pool_size * 3
        )
        self.base = base
        self.model = model
        self.session = self.create_session()

    def create_session(self) -> "Session":
        session = scoped_session(
            sessionmaker(autoflush=False, bind=self.engine, expire_on_commit=False)
        )

        return session()

    @contextmanager
    def transaction(self):
        with self.session.begin():
            yield self.session

    def get(self, id: Any, nested=False) -> T | None:
        with self.session.begin(nested=nested):
            obj = self.session.get(self.model, id)

        return obj

    def add(self, obj: T, nested=False) -> T:
        try:
            with self.session.begin(nested=nested):
                self.session.add(obj)

            with self.session.begin(nested=nested):
                self.session.refresh(obj)

            return obj

        except IntegrityError as e:
            if isinstance(e.orig, UniqueViolation):
                raise ObjectAlreadyExists()
            raise e
        except ProgrammingError as e:
            if isinstance(e.orig, GeneratedAlways):
                raise IdGeneratedAlways()
            raise e

    def update(self, id: Any, changes: dict[str, Any], nested=False) -> None:
        with self.session.begin(nested=nested):
            self.session.execute(update(self.model).filter_by(id=id).values(**changes))

    def query(self) -> Query[T]:
        """Return a query object for the model. Usage requires a transaction context."""
        return self.session.query(self.model)

    def delete(self, id: Any, nested=False) -> None:
        with self.session.begin(nested=nested):
            data = self.session.get(self.model, id)
            if data:
                self.session.delete(data)
            else:
                raise ObjectNotFound()

    def close_session(self):
        self.session.close()
