from fastapi import HTTPException
from pymodm import connection
from pymongo import DESCENDING

from src.models.event import Event
from src.models.aggregator import Aggregator
from src.models.module import Type, Module
from src.models.device import Device, Category

import asyncio
import datetime


# noinspection PyMethodMayBeStatic
class MongoDBIO:
    def __init__(self, details):
        self.details = details
        connection.connect(details)
        self.redis_indices = ["in_bytes", "in_unicast_packets", "in_non_unicast_packets",
                              "in_discards", "in_errors", "in_unknown_protocols",
                              "out_bytes", "out_unicast_packets", "out_non_unicast_packets",
                              "out_discards", "out_errors"]

    def get_modules(self):
        modules = list(Module.objects.order_by([['type', DESCENDING]]).all())
        return modules

    def add_category(self, category: str):
        try:
            category = Category(category=category).save()
            return category
        except Category.DuplicateKeyError:
            return False

    def add_device(self, hostname: str, category: Category, ip: str = None):
        try:
            device = Device(
                hostname=hostname,
                ip=ip,
                category=category).save()
            return device
        except Device.DuplicateKeyError:
            return False

    def check_token(self, token: str):
        try:
            ag = Aggregator.objects.get({'token': token})
            return ag
        except Aggregator.DoesNotExist:
            return False
        except Aggregator.MultipleObjectsReturned:
            return -1

    def add_aggregator(self, token: str):
        try:
            ag = Aggregator(token=token).save()
            return ag
        except Aggregator.DuplicateKeyError:
            return False

    # https://stackoverflow.com/questions/46366398/how-to-convert-pymodm-objects-to-json
    def get_aggregator_devices(self, id: str):
        print(id)
        try:
            ag = Aggregator.objects.get({'_id': id})
            return ag.devices
        except Aggregator.DoesNotExist:
            return False
        except Aggregator.MultipleObjectsReturned:
            return -1

    def get_device_by_id(self, id: str):
        try:
            device = Device.objects.get({'_id': id})
            return device
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1


# --- Redis --- #

    def redis_insert_live_data(self, data):
        hostname = data["device"]

        for interface_index in data["data"]:
            database_index = self.redis_indices.index(interface_index)

            if database_index != -1:
                self.redis_insert(hostname, data["data"][interface_index], database_index)

    def redis_insert(self, hostname: str, values: list, database_index: int):
        pool = redis.ConnectionPool(host="palguin.htl-vil.local", port="6379",
                                    password="WVFz.S9U:q4Y`]DGq5;2%7[H/t/WRymGR[r)@uA2mfq=ULvfcssHy5ef9HV",
                                    username="default",
                                    db=database_index)
        r = redis.Redis(connection_pool=pool)
        r.zadd(hostname, values)
        pool.connection_class()

    async def thread_insertIntoDatabase(self):
        while True:
            await asyncio.sleep(30 * 60)
            # Run all 30 minutes

            for i in range(0, len(self.redis_indices)):
                pool = redis.ConnectionPool(host="palguin.htl-vil.local", port="6379",
                                            password="WVFz.S9U:q4Y`]DGq5;2%7[H/t/WRymGR[r)@uA2mfq=ULvfcssHy5ef9HV",
                                            username="default",
                                            db=i)
                r = redis.Redis(connection_pool=pool)

                for key in r.scan_iter():
                    key = str(key, "utf-8")
                    # Get all live-data entries currently stored
                    scores = r.zrange(key, 0, -1, withscores=True)
                    # Delete all entries of current database so already created events which have occurred in this set are
                    # not inserted again. This also increases performance
                    r.flushdb()

                    with self.session.begin() as session:
                        device_id = session.query(func.netdb.insDevByCat(key, 3)).all()

                        device_id = device_id[0][0]
                        feature = self.redis_indices[i]
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                        avg_score = 0
                        for score in scores:
                            avg_score += score[1]
                            # This values will be changed in the future since currently we can not differentiate between
                            # normal values and anomalies. Furthermore, it is extremely likely that some values
                            # might get their own threshold values since every value is differently important. If this is
                            # the case, the alert-message and severity will be changed accordingly too.
                            if score[1] >= 1000000:
                                query = f"Call insAleWithTimestampAndSeverityAndProblemByDevHostnameOrIp(" \
                                        f"\"{timestamp}\", 3, \"A high level of {feature} has been detected\", \"{key}\", \"null\");"
                                session.execute(query)
                        if len(scores) > 0:
                            avg_score /= len(scores)

                        query = f"Call insValnByFeaNameAndDev({device_id}, \"{feature}\", \"{timestamp}\", {avg_score})"
                        session.execute(query)
