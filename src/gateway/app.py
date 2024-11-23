from fastapi import Depends, FastAPI
from src.gateway.auth import check_x_token_is_master_key

from src.gateway.v1.base import router as v1_router

app = FastAPI(dependencies=[Depends(check_x_token_is_master_key)])

app.include_router(v1_router)
