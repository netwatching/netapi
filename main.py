
import asyncio

from src.api import app
from hypercorn.config import Config
from hypercorn.asyncio import serve

if __name__ == "__main__":
    cfg = Config()
    cfg.bind = ["0.0.0.0:8443"]
    cfg.insecure_bind = ["0.0.0.0:8080"]
    cfg.keyfile = "./ssl/palguin.htl-vil.local+3-key.pem"
    cfg.certfile = "./ssl/palguin.htl-vil.local+3.pem"

    asyncio.run(serve(app, cfg))
