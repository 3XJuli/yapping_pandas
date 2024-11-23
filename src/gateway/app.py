from fastapi import FastAPI

from src.gateway.v1.base import router as v1_router

app = FastAPI()

app.include_router(v1_router)
