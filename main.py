import asyncio
import ssl
import os
import signal
from typing import Any

import pymongo.errors

from src.api import app, mongo
from src.mongoDBIO import MongoDBIO
from hypercorn.config import Config
from hypercorn.asyncio import serve


cfg = Config()
cfg.bind = ["0.0.0.0:8443"]
cfg.insecure_bind = ["0.0.0.0:8080"]
cfg.keyfile = "./ssl/palguin.htl-vil.local+3-key.pem"
cfg.certfile = "./ssl/palguin.htl-vil.local+3.pem"
cfg.worker_class = 'asyncio'
cfg.accesslog = "-"
cfg.loglevel = "DEBUG"


def main(config):
    loop = asyncio.new_event_loop()

    shutdown_event = asyncio.Event()
    def _signal_handler(*_: Any) -> None:
        shutdown_event.set()
    loop.add_signal_handler(signal.SIGTERM, _signal_handler)
    loop.add_signal_handler(signal.SIGINT, _signal_handler)

    while True:
        try:
            loop.run_until_complete(serve(app, config, shutdown_trigger=shutdown_event.wait))
            if shutdown_event.is_set():
                os._exit(-1)
            #await asyncio.gather(serve(app, config), MongoDBIO.thread_insertIntoDatabase(mongo), MongoDBIO.keep_connections(mongo), return_exceptions=True)
        except (pymongo.errors.ServerSelectionTimeoutError, TimeoutError, asyncio.exceptions.CancelledError, ssl.SSLError, OSError):
            print("Lost connection to DB! Restarting")

def run():
    asyncio.run(main(cfg))

if __name__ == "__main__":
    main(cfg)
