from datetime import datetime
import json

import pymodm
import redis
from decouple import config
from fastapi import HTTPException
from pymodm import connection
from pymongo import DESCENDING

from bson import ObjectId

from src.models.event import Event
from src.models.aggregator import Aggregator
from src.models.module import Type, Module
from src.models.device import Device, Category, Data
from src.models.node import Link, Node, LinkJson, NodeJson, TreeJson, Connection

from src.crypt import Crypt

from bson import ObjectId

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

    def get_types(self):
        types = Type.objects.order_by([['type', DESCENDING]]).all()
        typesDict = []

        for t in types:
            t = t.to_son().to_dict()
            t.pop("_id")
            t["config"] = json.loads(self.crypt.decrypt(t["config"], config("cryptokey")))
            typesDict.append(t)
        print(typesDict)
        return typesDict

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

        if self.__is_float__(num=str(timestamp)) is True:
            timestamp = datetime.utcfromtimestamp(float(str(timestamp))).strftime('%Y-%m-%d %H:%M:%S')

        if severity < 0 or severity > 10:
            return False

        event = Event(device=device, severity=severity, event=event, timestamp=timestamp)
        if self.check_if_event_exists(event) is False:
            event.save()

        return event

    def __is_float__(self, num: str):
        try:
            float(num)
            return True
        except ValueError:
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

    def get_aggregator_devices(self, id):
        try:
            id = ObjectId(id)
            ag = Aggregator.objects.get({'_id': id})
            return ag
        except Aggregator.DoesNotExist:
            return False
        except Aggregator.MultipleObjectsReturned:
            return -1

    def get_device_by_id(self, id: str):
        try:
            id = ObjectId(id)
            device = Device.objects.get({'_id': id})
            static = []
            live = []
            modules = []

            category = device.category.category

            for s in device.static:
                r = s.to_son().to_dict()
                r.pop('_id')
                static.append(r)

            for l in device.live:
                r = l.to_son().to_dict()
                r.pop('_id')
                live.append(r)

            for m in device.modules:
                r = m.to_son().to_dict()
                r.pop('_id')
                modules.append(r)

            d = device.to_son().to_dict()
            d["category"] = category
            d["static"] = static
            d["live"] = live
            d["modules"] = modules

            d.pop("_id")
            return d
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
        count = Event.objects.raw(
            {"event": event.event, "device": event.device.pk, "timestamp": event.timestamp}).count()
        if count == 0:
            return False
        else:
            return True

    def check_if_device_exsits(self, hostname: str):
        count = Device.objects.raw({"hostname": hostname}).count()
        if count == 0:
            return False
        else:
            return True

    def get_category_by_id(self, id: str):
        try:
            id = ObjectId(id)
            category = Category.objects.get({'_id': id})
            return category
        except Category.DoesNotExist:
            return False
        except Category.MultipleObjectsReturned:
            return -1

    def get_device_by_category_full(self, category: str = "", page: int = None, amount: int = None):
        cat = None
        try:
            if category != "":
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

        devs = []
        static = []
        live = []
        modules = []
        for d in devices:
            category = d.category.category

            for s in d.static:
                r = s.to_son().to_dict()
                r.pop('_id')
                static.append(r)

            for l in d.live:
                r = l.to_son().to_dict()
                r.pop('_id')
                live.append(r)

            for m in d.modules:
                r = m.to_son().to_dict()
                r.pop('_id')
                modules.append(r)

            d = d.to_son().to_dict()
            d["category"] = category
            d["static"] = static
            d["live"] = live
            d["modules"] = modules

            d.pop("_id")
            devs.append(d)

        out["devices"] = devs
        print(out)
        return out

    def get_device_by_category(self, category: str = "", page: int = None, amount: int = None):
        cat = None
        try:
            if category != "":
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
                               .limit(amount)
                               .values())
            else:
                devices = list(Device.objects \
                               .order_by([('_id', DESCENDING)]) \
                               .skip((page - 1) * amount) \
                               .limit(amount)
                               .values())

        elif (page is None or page <= 0) and amount is None:
            if cat is not None:
                devices = list(Device.objects \
                               .raw({'category': cat.pk}) \
                               .order_by([('_id', DESCENDING)])
                               .values())
            else:
                devices = list(Device.objects \
                               .order_by([('_id', DESCENDING)]) \
                               .all()
                               .values())
        else:
            return -1

        devs = []
        for d in devices:

            category = self.get_category_by_id(d["category"])
            category = category.category

            d["id"] = str(d.pop("_id"))
            if "_cls" in d:
                d.pop("_cls")
            d["category"] = category
            if "static" in d:
                d.pop("static")
            if "live" in d:
                d.pop("live")
            if "modules" in d:
                d.pop("modules")

            devs.append(d)

        out["devices"] = devs
        return out

    def add_data_for_devices(self, devices: list, external_events: dict):
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

            if allowed is True:
                static_data = device["static_data"]
                for static_key in static_data:
                    self.__handle_static_data__(device=dev, key=static_key,
                                                input=self.__clean_dictionary__(static_data[static_key]))

                live_data = device["live_data"]
                self.redis_insert_live_data(device=dev, live_data=live_data)

                events = device["events"]
                self.__handle_events__(device=dev, events=events)

        for hostname in external_events:
            allowed = True
            dev = self.get_device_by_hostname(hostname=hostname)
            if dev is None or (isinstance(dev, int) and dev == -1):
                allowed = False

            if isinstance(dev, bool) and dev is False:
                dev = self.add_device(hostname=hostname, category=category)

            if allowed is True:
                self.__handle_events__(device=dev, events=external_events[hostname])
        return True

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
            self.add_event(event=event_dict["information"], severity=event_dict["severity"],
                           timestamp=event_dict["timestamp"], device=device)

    def __clean_dictionary__(self, dict: dict):
        new_dict = {}
        for key in dict:
            if isinstance(key, str):
                new_key = key.replace("__", ".")
                new_dict[new_key.replace(".", "__")] = dict[key]
        return new_dict

    def __normalize_dictionary__(self, dict: dict):
        new_dict = {}
        for key in dict:
            if isinstance(key, str):
                new_key = key.replace("__", ".")
                new_dict[new_key] = dict[key]
        return new_dict

    def set_aggregator_version(self, id, ver):
        try:
            id = ObjectId(id)
            aggregator = Aggregator.objects.get({'_id': id})
        except Aggregator.DoesNotExist:
            return False
        except Aggregator.MultipleObjectsReturned:
            return -1

        aggregator.version = ver
        return aggregator.save()

    def insert_aggregator_modules(self, modules, id):
        try:
            id = ObjectId(id)
            aggregator = Aggregator.objects.get({'_id': id})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1

        types = []
        for t in modules:
            type = Type(type=t.id, signature=t.config_signature,
                        config=self.crypt.encrypt(json.dumps(t.config_fields), config("cryptokey"))).save()
            types.append(type)

        aggregator.types = types
        return (aggregator.save())

    def add_device_web(self, device, category, ip="1.1.1.1"):
        try:
            cat = Category.objects.get({'category': category})
        except Category.DoesNotExist:
            return False
        except Category.MultipleObjectsReturned:
            return -1

        if not self.check_if_device_exsits(device):
            return Device(hostname=device, category=cat.pk, ip=ip).save()
        return False

    def get_device_config(self, id):
        try:
            dev = Device.objects.get({'_id', id})
            ag = Aggregator.objects.get({'devices': id})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1
        except Aggregator.DoesNotExist:
            return False
        except Aggregator.MultipleObjectsReturned:
            return -1

        config = []

        for t in ag.types:
            for m in dev.modules:
                if t.type == m.type:
                    t.type.config = json.loads(self.crypt.decrypt(t.type.config, config("cryptokey"))).update(json.loads(self.crypt.decrypt(m.type.config, config("7C1aGDU8ym9UudJXfNI01exYvfriT6RD"))))
            config.append(t.type)

        return config

    def set_device_config(self, id, config):
        try:
            dev = Device.objects.get({'_id', id})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1

        modules = []

        for c in config:
            m = Module(type=c.type, config=self.crypt.decrypt(json.dumps(c.config), config("cryptokey"))).save
            modules.append(m)
        dev.modules = modules
        dev.save()
        return


        return config

    def get_categories(self):
        categories = list(Category.objects.order_by([('_id', DESCENDING)]).all())

        out = []
        for c in categories:
            pk = str(c.pk)
            c = c.to_son().to_dict()
            c["_id"] = pk
            out.append(c)

        return out

    def get_event_by_id(self, event_id):
        try:
            event_id = ObjectId(event_id)
            event = Event.objects.get({'_id': event_id})

            host = event.device.hostname

            event = event.to_son().to_dict()
            event["device"] = host
            event.pop("_id")

            print(event)

            return event
        except Category.DoesNotExist:
            return False
        except Category.MultipleObjectsReturned:
            return -1

    def get_event_count(self, device_id: str = None):
        if device_id is not None:
            device_id = ObjectId(device_id)
            total = Event.objects.raw({'device': device_id}).count()
        else:
            total = Event.objects.all().count()
        return total

    def get_events(self, amount: int = None, page: int = None, severity: int = None, min_severity: int = None,
                   device_id: str = None):
        if device_id is not None:
            device_id = ObjectId(device_id)

        if (amount is not None and amount <= 0) or (page is not None and page < 0) or (
                severity is not None and severity < 0) or (min_severity is not None and min_severity < 0):
            return False

        if severity is not None and min_severity is not None:
            severity = None

        if severity is not None and severity > 10:
            return False

        if min_severity is not None and min_severity > 10:
            return False

        if amount is not None and page is not None:
            if min_severity is not None:
                if device_id is not None:
                    events = list(
                        Event.objects
                            .raw({'device': device_id, "severity": {"$gte": min_severity}})
                            .order_by([('_id', DESCENDING)])
                            .skip((page - 1) * amount)
                            .limit(amount)
                            .values()
                    )
                else:
                    events = list(
                        Event.objects
                            .raw({"severity": {"$gte": min_severity}})
                            .order_by([('_id', DESCENDING)])
                            .skip((page - 1) * amount)
                            .limit(amount)
                            .values()
                    )
            elif severity is not None:
                if device_id is not None:
                    events = list(
                        Event.objects
                            .raw({'device': device_id, "severity": severity})
                            .order_by([('_id', DESCENDING)])
                            .skip((page - 1) * amount)
                            .limit(amount)
                            .values()
                    )
                else:
                    events = list(
                        Event.objects
                            .raw({"severity": severity})
                            .order_by([('_id', DESCENDING)])
                            .skip((page - 1) * amount)
                            .limit(amount)
                            .values()
                    )
            elif device_id is not None:
                events = list(
                    Event.objects
                        .raw({'device': device_id})
                        .order_by([('_id', DESCENDING)])
                        .skip((page - 1) * amount)
                        .limit(amount)
                        .values()
                )
            else:
                events = list(
                    Event.objects
                        .order_by([('_id', DESCENDING)])
                        .skip((page - 1) * amount)
                        .limit(amount)
                        .values()
                )
        else:
            if min_severity is not None:
                if device_id is not None:
                    events = list(
                        Event.objects
                            .raw({'device': device_id, "severity": {"$gte": min_severity}})
                            .order_by([('_id', DESCENDING)])
                            .values()
                    )
                else:
                    events = list(
                        Event.objects
                            .raw({"severity": {"$gte": min_severity}})
                            .order_by([('_id', DESCENDING)])
                            .values()
                    )
            elif severity is not None:
                if device_id is not None:
                    events = list(
                        Event.objects
                            .raw({'device': device_id, "severity": severity})
                            .order_by([('_id', DESCENDING)])
                            .values()
                    )
                else:
                    events = list(
                        Event.objects
                            .raw({"severity": severity})
                            .order_by([('_id', DESCENDING)])
                            .values()
                    )
            elif device_id is not None:
                events = list(
                    Event.objects
                        .raw({'device': device_id})
                        .order_by([('_id', DESCENDING)])
                        .values()
                )
            else:
                events = list(
                    Event.objects
                        .order_by([('_id', DESCENDING)])
                        .all()
                        .values()
                )

        events_cleansed = []
        for event in events:

            event["id"] = str(event.pop("_id"))
            if "_cls" in event:
                event.pop("_cls")
            event["timestamp"] = str(event["timestamp"])
            event["device_id"] = str(event.pop("device"))

            events_cleansed.append(event)

        return events_cleansed

    def checkInt(self, input: str):
        try:
            int(input)
            return True
        except ValueError:
            return False

    def __check_if_connection_exists__(self, connection: Connection):
        connection = connection.to_son().to_dict()
        count = Connection.objects.raw(
            {
                "$or": [
                    {
                        "source": ObjectId(connection["source"]),
                        "target": ObjectId(connection["target"])
                    },
                    {
                        "source": ObjectId(connection["target"]),
                        "target": ObjectId(connection["source"])
                    }
                ]
            }
        ).count()

        if count >= 1:
            return True
        return False

    def __create_connection__(self, source: Link, target: Link):
        if source.mac == target.remote_mac and source.remote_mac == target.mac:
            connection = Connection(source=source, target=target)
            if self.__check_if_connection_exists__(connection=connection) is False:
                connection = connection.save()
                return connection
        return None

    def get_tree(self):
        connections = Connection.objects.all()

        links = []
        nodes = []
        for connection in connections:
            source_node = connection.source.node
            target_node = connection.target.node

            links.append(LinkJson(source=source_node.hostname, target=target_node.hostname))
            nodes.append(NodeJson(id=source_node.hostname))
            nodes.append(NodeJson(id=target_node.hostname))

        tree = TreeJson(links=links, nodes=nodes)
        return tree

    # --- Redis --- #

    def redis_insert_live_data(self, device: Device, live_data: dict):
        hostname = device.hostname

        for key in live_data:
            database_index = self.redis_indices.index(key)

            if database_index != -1:
                self.redis_insert(hostname, live_data[key], database_index)

    def redis_insert(self, hostname: str, values: dict, database_index: int):
        pool = redis.ConnectionPool(host=str(config("rDBurl")),
                                    port=str(config("rDBport")),
                                    password=str(config("rDBpassword")),
                                    username=str(config("rDBusername")),
                                    db=database_index)
        r = redis.Redis(connection_pool=pool)
        r.zadd(hostname, values)
        pool.connection_class()

    async def thread_insertIntoDatabase(self):
        while True:
            await asyncio.sleep(30 * 60)

            for i in range(0, len(self.redis_indices)):
                pool = redis.ConnectionPool(host=str(config("rDBurl")),
                                            port=str(config("rDBport")),
                                            password=str(config("rDBpassword")),
                                            username=str(config("rDBusername")),
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

                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            event_time = str(score[0], "utf-8")
                            if self.__is_float__(num=event_time) is True:
                                timestamp = datetime.fromtimestamp(float(event_time))
                            elif isinstance(event_time, str):
                                timestamp = datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S')

                            event = f"Unusual high amount of {type}: {str(score[1])}"
                            self.add_event(device=device, event=event, severity=3, timestamp=timestamp)

                    if len(scores) > 0:
                        avg_score /= len(scores)

                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    data = {timestamp: avg_score}
                    print(data)
                    self.__handle_live_data__(device=device, key=type, input=data)
                r.flushdb()
            print("Redis thread successful")
