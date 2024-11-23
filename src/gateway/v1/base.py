from src.gateway.v1.routers.boilerplate import router as boilerplate_router
from src.gateway.v1.routers.simulation import router as simulation_router
from fastapi import APIRouter

router = APIRouter(prefix="/v1")
router.include_router(boilerplate_router)
router.include_router(simulation_router)
