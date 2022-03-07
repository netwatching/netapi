import asyncio

from src.api import app, mongo
from src.mongoDBIO import MongoDBIO
from hypercorn.config import Config
from hypercorn.asyncio import serve


async def main(config):
    await asyncio.gather(serve(app, cfg), MongoDBIO.thread_insertIntoDatabase(mongo))


if __name__ == "__main__":
    cfg = Config()
    cfg.bind = ["0.0.0.0:8443"]
    cfg.insecure_bind = ["0.0.0.0:8080"]
    cfg.keyfile = "./ssl/palguin.htl-vil.local+3-key.pem"
    cfg.certfile = "./ssl/palguin.htl-vil.local+3.pem"
    cfg.worker_class = 'asyncio'
    cfg.accesslog = "-"
    cfg.loglevel = "DEBUG"

    while True:
        try:
            asyncio.run(main(cfg))
        except Exception:
            continue
