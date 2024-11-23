from src.gateway.v1.routers.vulnerability import router as simulation_router
from fastapi import APIRouter

router = APIRouter(prefix="/v1")
router.include_router(simulation_router)
