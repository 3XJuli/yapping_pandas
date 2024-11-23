from functools import lru_cache
import logging

from fastapi import APIRouter, Depends, status
from src.gateway.v1.models.filters import BoilerplateFilter
from src.gateway.v1.models.queries import BoilerplateCreate, BoilerplateUpdate

from src.gateway.v1.models.responses import Boilerplate
from src.services.boilerplate.boilerplate_service import BoilerplateService
from src.services.exceptions import ObjectNotFound


logger = logging.getLogger()


@lru_cache
def boilerplate_service():
    return BoilerplateService()


router = APIRouter(
    prefix="/boilerplate",
    tags=["boilerplate"],
)


@router.get("/")
async def read_boilerplates(
    skip: int = 0,
    limit: int = 100,
    service: BoilerplateService = Depends(boilerplate_service),
) -> list[Boilerplate]:
    boilerplates = service.query(filter=BoilerplateFilter(), limit=limit, skip=skip)

    return boilerplates


@router.post("/count")
async def count_boilerplates(
    filter: BoilerplateFilter = BoilerplateFilter(),
    service: BoilerplateService = Depends(boilerplate_service),
) -> int:
    return service.query_count(filter=filter)


@router.get("/{boilerplate_id}")
async def read_boilerplate(
    boilerplate_id: int,
    service: BoilerplateService = Depends(boilerplate_service),
) -> Boilerplate:
    msg = service.get(boilerplate_id)
    if msg is None:
        raise ObjectNotFound()

    return msg


@router.post("/")
async def add_boilerplate(
    boilerplate: BoilerplateCreate,
    service: BoilerplateService = Depends(boilerplate_service),
) -> Boilerplate:

    added = service.add(boilerplate)

    return added


@router.patch("/{boilerplate_id}")
async def update_boilerplate(
    boilerplate_id: int,
    update: BoilerplateUpdate,
    service: BoilerplateService = Depends(boilerplate_service),
) -> Boilerplate:
    updated = service.update(boilerplate_id, update)

    return updated


@router.delete("/{boilerplate_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_boilerplate(
    boilerplate_id: int,
    service: BoilerplateService = Depends(boilerplate_service),
):
    service.delete(boilerplate_id)
