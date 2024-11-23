from src.gateway.v1.routers.boilerplate import router as boilerplate_router

from fastapi import APIRouter

router = APIRouter(prefix="/v1")
router.include_router(boilerplate_router)
