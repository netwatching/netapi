from datetime import datetime
import json

import redis
from decouple import config
from fastapi import HTTPException
from pymodm import connection
from pymongo import DESCENDING

from src.models.event import Event
from src.models.aggregator import Aggregator
from src.models.module import Type, Module
from src.models.device import Device, Category, Data

from src.crypt import Crypt

import asyncio


# noinspection PyMethodMayBeStatic
class MongoDBIO:
    def __init__(self, details):
        self.details = details
        connection.connect(details)
        self.redis_indices = ["in_bytes", "in_unicast_packets", "in_non_unicast_packets",
                              "in_discards", "in_errors", "in_unknown_protocols",
                              "out_bytes", "out_unicast_packets", "out_non_unicast_packets",
                              "out_discards", "out_errors"]
        self.crypt = Crypt()

    def get_modules(self):
        modules = list(Module.objects.order_by([['type', DESCENDING]]).all())
        return modules

    def add_category(self, category: str):
        try:
            category = Category(category=category).save()
            return category
        except Category.DuplicateKeyError:
            return False

    def get_category_by_category(self, category: str):
        try:
            return Category.objects.get({"category": category})
        except Category.DuplicateKeyError:
            return False

    def add_event(self, device: Device, severity: int, event: str,
                  timestamp: datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')):
        try:
            if severity < 0 or severity > 10:
                return False

            event = Event(device=device, severity=severity, event=event, timestamp=timestamp)
            if self.check_if_event_exists(event) is False:
                event.save()

            return event
        except Event.DuplicateKeyError:
            return False

    def add_device(self, hostname: str, category: Category, ip: str = None):
        try:
            if ip is not None:
                device = Device(
                    hostname=hostname,
                    ip=ip,
                    category=category).save()
            else:
                device = Device(
                    hostname=hostname,
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

    def get_device_by_hostname(self, hostname: str):
        try:
            device = Device.objects.get({'hostname': hostname})
            return device
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1

    def check_if_event_exists(self, event: Event):
        count = 0
        count = Event.objects.raw({"event": event.event, "timestamp": event.timestamp, "device": event.Device}).count()
        if count == 0:
            return False
        else:
            return True


    def get_device_by_category(self, category: str = None, page: int = None, amount: int = None):
        cat = None
        try:
            if category is not None:
                cat = Category.objects.get({'category': category})
        except Category.DoesNotExist:
            return False
        except Category.MultipleObjectsReturned:
            return -1

        out = {}
        if cat is not None:
            total = Device.objects.raw({'category': cat.pk}).count()
        else:
            total = Device.objects.all().count()
        out["page"] = page
        out["amount"] = amount
        out["total"] = total

        if (page is not None and amount is not None) and (page > 0 and amount > 0):
            if cat is not None:
                devices = list(Device.objects \
                               .raw({'category': cat.pk}) \
                               .order_by([('_id', DESCENDING)]) \
                               .skip((page - 1) * amount) \
                               .limit(amount))
            else:
                devices = list(Device.objects \
                               .order_by([('_id', DESCENDING)]) \
                               .skip((page - 1) * amount) \
                               .limit(amount))

        elif (page is None or page <= 0) and amount is None:
            if cat is not None:
                devices = list(Device.objects \
                               .raw({'category': cat.pk}) \
                               .order_by([('_id', DESCENDING)]))
            else:
                devices = list(Device.objects \
                               .order_by([('_id', DESCENDING)]) \
                               .all())
        else:
            return -1

        out["devices"] = devices
        return out

    def add_data_for_devices(self, devices: str, external_events: str):
        try:
            devices = json.loads(devices)
            external_events = json.loads(external_events)
        except ValueError:
            return False

        category = self.get_category_by_category("New")

        for device in devices:
            allowed = True
            dev = self.get_device_by_hostname(hostname=device["name"])
            if dev is None or (isinstance(dev, int) and dev == -1):
                allowed = False

            if isinstance(dev, bool) and dev is False:
                ip = None
                if "ip" in device:
                    ip = device["ip"]
                dev = self.add_device(hostname=device["name"], category=category, ip=ip)
            else:
                allowed = False

            if allowed is True:
                static_data = device["static_data"]
                for static_key in static_data:
                    self.__handle_static_data__(device=dev, key=static_key, input=static_data[static_key])

                live_data = device["live_data"]
                for live_key in live_data:
                    self.__handle_live_data__(device=dev, key=live_key, input=live_data[live_key])

                events = device["events"]
                self.__handle_events__(device=dev, events=events)

        for hostname in external_events:
            allowed = True
            dev = self.get_device_by_hostname(hostname=hostname)
            if dev is None or (isinstance(dev, int) and dev == -1):
                allowed = False

            if isinstance(dev, bool) and dev is False:
                dev = self.add_device(hostname=device["name"], category=category, ip=ip)
            else:
                allowed = False

            if allowed is True:
                self.__handle_events__(device=dev, events=external_events[hostname])

        

    def __handle_static_data__(self, device: Device, key, input):
        for data in device.static:
            if data.key == key:
                data.data = input
                data.save()
                return

        data = Data(key=key, data=input).save()
        data_list = device.static
        data_list.append(data)
        device.static = data_list
        device.save()

    def __handle_live_data__(self, device: Device, key, input):
        for data in device.live:
            if data.key == key:
                new_data = input
                old_data = data.data

                updated_data = old_data | new_data
                data.data = updated_data

                data.save()
                return

        data = Data(key=key, data=input).save()
        data_list = device.live
        data_list.append(data)
        device.live = data_list
        device.save()

    def __handle_events__(self, device: Device, events: list[{str, str}]):
        for event_dict in events:
            self.add_event(event=event_dict["information"], severity=event_dict["severity"], timestamp=event_dict["timestamp"], device=device)

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
            await asyncio.sleep(60 * 30)

            for i in range(0, len(self.redis_indices)):
                pool = redis.ConnectionPool(host="palguin.htl-vil.local", port="6379",
                                            password="WVFz.S9U:q4Y`]DGq5;2%7[H/t/WRymGR[r)@uA2mfq=ULvfcssHy5ef9HV",
                                            username="default",
                                            db=i)
                r = redis.Redis(connection_pool=pool)

                for key in r.scan_iter():
                    hostname = str(key, "utf-8")
                    scores = r.zrange(hostname, 0, -1, withscores=True)

                    device = self.get_device_by_hostname(hostname)
                    if isinstance(device, bool) and device is False:
                        category = self.get_category_by_category("New")
                        device = self.add_device(hostname=hostname, category=category)

                    type = self.redis_indices[i]

                    avg_score = 0
                    for score in scores:
                        avg_score += score[1]
                        if score[1] >= 80000:
                            timestamp = datetime.strptime(str(score[0], "utf-8"), '%Y-%m-%d %H:%M:%S')
                            event = f"Unusual high amount of {type}: {score[1]}"
                            self.add_event(device=device, event=event, severity=3, timestamp=timestamp)

                    if len(scores) > 0:
                        avg_score /= len(scores)

                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    data = {timestamp: avg_score}
                    self.__handle_live_data__(device=device, key=type, input=data)
                    #print(f"Inserted {device.hostname} for {type}")
                r.flushdb()
                #print(f"Flushed {str(i)}")

    def set_aggregator_version(self, id: str, ver: str):
        try:
            aggregator = Aggregator.objects.get({'_id': id})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1

        aggregator.version = ver
        return aggregator.save()

    def insert_aggregator_modules(self, modules, id):
        try:
            aggregator = Aggregator.objects.get({'_id': id})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1

        types = []
        for t in modules:
            type = Type(type=t["id"], signature=t["config_signature"], config=self.crypt.encrypt(t["config_fields"], config("cryptokey"))).save()
            types.append(type)

        aggregator.types = types
        return(aggregator.save())



