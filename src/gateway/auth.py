from fastapi import HTTPException, Security
import secrets
from src import settings

from fastapi.security.api_key import APIKeyHeader

_x_token = APIKeyHeader(name="X-Token", auto_error=False)
_authorization_token = APIKeyHeader(name="Authorization", auto_error=False)


async def check_x_token_is_master_key(
    x_token: str = Security(_x_token),
    authorization_token: str = Security(_authorization_token),
):
    token = x_token or ""
    if authorization_token and "MasterKey" in authorization_token:
        token = authorization_token.split("MasterKey ")[-1]

    if not secrets.compare_digest(token, settings.APP_SETTINGS.master_key):
        raise HTTPException(status_code=403, detail="X-Token header invalid")
