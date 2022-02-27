
import asyncio
import threading
from datetime import datetime

import sqlalchemy
from sqlalchemy.dialects.mysql import pymysql
import pymongo

from src.api import app, db
from src.dbio import DBIO
from hypercorn.config import Config
from hypercorn.asyncio import serve
async def main(config):
    await asyncio.gather(serve(app, cfg), DBIO.thread_insertIntoDatabase(db))

if __name__ == "__main__":
    cfg = Config()
    cfg.bind = ["0.0.0.0:8443"]
    cfg.insecure_bind = ["0.0.0.0:8080"]
    cfg.keyfile = "./ssl/palguin.htl-vil.local+3-key.pem"
    cfg.certfile = "./ssl/palguin.htl-vil.local+3.pem"
    cfg.worker_class = 'asyncio'
    cfg.accesslog = "-"
    cfg.loglevel = "DEBUG"

    asyncio.run(main(cfg))
