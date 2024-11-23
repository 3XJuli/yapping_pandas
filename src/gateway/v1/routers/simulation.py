from functools import lru_cache
import logging

from fastapi import APIRouter, Depends, status
from src.gateway.v1.models.queries import SimulationParameters
from src.services.simulation.simulation_service import SimulationService
from src.services.exceptions import ObjectNotFound


logger = logging.getLogger()


@lru_cache
def simulation_service():
    return SimulationService()


router = APIRouter(
    prefix="/simulation",
    tags=["simulation"],
)


@router.post("/start_simulation/", status_code=status.HTTP_204_NO_CONTENT)
async def delete_boilerplate(
    simulation_params: SimulationParameters,
    service: SimulationService = Depends(simulation_service),
):
    service.run_simulation(simulation_params)
