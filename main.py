import asyncio
import ssl

import pymongo.errors

from src.api import app, mongo
from src.mongoDBIO import MongoDBIO
from hypercorn.config import Config
from hypercorn.asyncio import serve


async def main(config):
    await asyncio.gather(serve(app, config), MongoDBIO.thread_insertIntoDatabase(mongo))

def run():
    cfg = Config()
    cfg.bind = ["0.0.0.0:8443"]
    cfg.insecure_bind = ["0.0.0.0:8080"]
    cfg.keyfile = "./ssl/palguin.htl-vil.local+3-key.pem"
    cfg.certfile = "./ssl/palguin.htl-vil.local+3.pem"
    cfg.worker_class = 'asyncio'
    cfg.accesslog = "-"
    cfg.loglevel = "DEBUG"

    asyncio.run(main(cfg))

if __name__ == "__main__":
    while True:
        try:
            run()
        except (pymongo.errors.ServerSelectionTimeoutError, TimeoutError, asyncio.exceptions.CancelledError, ssl.SSLError, OSError):
            print("Lost connection to DB! Restarting")
