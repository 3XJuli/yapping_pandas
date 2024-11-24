import logging

import uvicorn
from src.gateway.app import app

logging.basicConfig(level=logging.DEBUG)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
