from src.gateway.v1.models.filters import BoilerplateFilter
from src.gateway.v1.models.queries import BoilerplateCreate, BoilerplateUpdate
from src.gateway.v1.models.responses import Boilerplate

from src.services.boilerplate.db_models import Base, BoilerplateModel
from src.services.exceptions import FailedToRetrieveObject
from src.services.postgres_service import PostgresService

from src.settings import APP_SETTINGS


class BoilerplateService:
    def __init__(
        self,
        url: str = APP_SETTINGS.backend_url,
        service: PostgresService[BoilerplateModel] | None = None,
    ):
        self.postgres_service = service or PostgresService(
            url=url, model=BoilerplateModel, base=Base
        )

    def get(self, id: int) -> Boilerplate | None:
        result = self.postgres_service.get(id)

        return Boilerplate.model_validate(result) if result is not None else None

    def _build_filter_options(
        self,
        filter: BoilerplateFilter,
    ) -> list:
        filters = []

        filters += filter.get_datetime_filters(
            BoilerplateModel.created_at, BoilerplateModel.updated_at
        )

        return filters

    def query_count(
        self,
        filter: BoilerplateFilter,
    ) -> int:
        filters = self._build_filter_options(filter)

        with self.postgres_service.transaction():
            return self.postgres_service.query().filter(*filters).count()

    def query(
        self,
        filter: BoilerplateFilter,
        limit: int,
        skip: int = 0,
    ) -> list[Boilerplate]:

        filters = self._build_filter_options(filter)

        with self.postgres_service.transaction():
            results = (
                self.postgres_service.query()
                .filter(*filters)
                .order_by(BoilerplateModel.id)
                .limit(limit)
                .offset(skip)
                .all()
            )

        return [Boilerplate.model_validate(r) for r in results]

    def add(self, msg: BoilerplateCreate) -> Boilerplate:

        inserted_obj = self.postgres_service.add(BoilerplateModel(**msg.model_dump()))

        return Boilerplate.model_validate(inserted_obj)

    def update(self, id: int, msg: BoilerplateUpdate) -> Boilerplate:

        with self.postgres_service.transaction():
            changes = msg.model_dump(exclude_unset=True)

            self.postgres_service.update(id, changes, nested=True)

            updated = self.postgres_service.get(id, nested=True)

            if updated is None:
                raise FailedToRetrieveObject()

        return Boilerplate.model_validate(updated)

    def delete(self, id: int) -> None:
        self.postgres_service.delete(id)
