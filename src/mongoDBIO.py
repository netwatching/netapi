from datetime import datetime
import json

import pymongo.errors
import redis
from decouple import config as dconfig
from pymodm import connection
from pymongo import DESCENDING

from bson import ObjectId

from src.models.event import Event
from src.models.aggregator import Aggregator
from src.models.module import Type, Module
from src.models.device import Device, Category, Data, Filter
from src.models.node import Link, LinkJson, NodeJson, TreeJson, Connection, Node

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

    def get_aggregators(self):
        ags = list(Aggregator.objects.only("identifier").only("_id").only("version").all().values())
        for ag in ags:
            ag["id"] = str(ag.pop("_id"))
        return ags

    def get_types(self):
        types = Type.objects.order_by([['type', DESCENDING]]).all()
        typesDict = []

        for t in types:
            t = t.to_son().to_dict()
            t.pop("_id")
            t["config"] = json.loads(self.crypt.decrypt(t["config"], dconfig("cryptokey")))
            typesDict.append(t)
        return typesDict

    def set_aggregator_device(self, ag, dev):
        try:
            ag = Aggregator.objects.get({"identifier": ag})
        except Aggregator.DoesNotExist:
            return False
        except Aggregator.MultipleObjectsReturned:
            return -1

        try:
            dev = Device.objects.get({"hostname": dev})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1

        devices = ag.devices
        devices.append(dev)
        ag.devices = devices
        ag.save()

        return ag

    def add_category(self, category: str):
        try:
            category = Category(category=category).save()
            return category
        except Category.DuplicateKeyError:
            return False

    def delete_category(self, category_id: str):
        try:
            category = Category.objects.get({"_id": ObjectId(category_id)})
            category.delete()
            return True
        except Category.DoesNotExist:
            return False
        except Category.MultipleObjectsReturned:
            return False

    def delete_module(self, module_id: str, device_id: str):
        try:
            device = Device.objects.get({'_id': ObjectId(device_id)})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return False

        if device:
            if hasattr(device, "modules") and device.modules:
                modules = device.modules

                if len(modules) == 1:
                    Device.objects.raw({'_id': ObjectId(device_id)}).update({"$set": {"modules": []}})
                    modules[0].delete()
                    return True
                elif len(modules) == 0:
                    return False

                new_modules = []

                if modules:
                    for module in modules:
                        if module and hasattr(module, "pk"):
                            if module.pk != ObjectId(module_id):
                                new_modules.append(module)
                            else:
                                module.delete()

                device.modules = new_modules
                device.save()
        return True


    def get_category_by_category(self, category: str):
        try:
            return Category.objects.get({"category": category})
        except Category.DoesNotExist:
            return None
        except Category.MultipleObjectsReturned:
            return None

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

    def add_aggregator(self, token: str, identifier):
        try:
            ag = Aggregator(token=token, identifier=identifier).save()
            return ag
        except Aggregator.DuplicateKeyError:
            return None

    def get_aggregator_devices(self, id):
        try:
            id = ObjectId(id)
            ag = Aggregator.objects.get({'_id': id})
            return ag
        except Aggregator.DoesNotExist:
            return False
        except Aggregator.MultipleObjectsReturned:
            return -1

    def get_hostname_from_device_id(self, id: str):
        device = list(Device.objects.raw({"_id": ObjectId(id)}).only("hostname").all().values())
        if len(device) == 1:
            return device[0]["hostname"]
        return None

    def get_device_by_id(self, id: str):
        try:
            id = ObjectId(id)
            device = Device.objects.get({'_id': id})
            static = []
            live = []
            modules = []

            if hasattr(device, "category"):
                category = device.category.category

            if hasattr(device, "static"):
                for s in device.static:
                    r = s.to_son().to_dict()
                    r.pop('_id')
                    static.append(r)

            if hasattr(device, "live"):
                for l in device.live:
                    r = l.to_son().to_dict()
                    r.pop('_id')
                    live.append(r)

            if hasattr(device, "modules"):
                for m in device.modules:
                    t = m.type.type
                    r = m.to_son().to_dict()
                    r["type"] = t
                    r.pop('_id')
                    modules.append(r)

            d = device.to_son().to_dict()
            if "category" in d:
                d["category"] = category
            if "static" in d:
                d["static"] = static
            else:
                d["static"] = []
            if "live" in d:
                d["live"] = live
            else:
                d["live"] = []
            if "modules" in d:
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
            return None
        except Category.MultipleObjectsReturned:
            return None

    def get_aggregator_by_identifier(self, identifier: str):
        try:
            aggregator = Aggregator.objects.get({'identifier': identifier})
            return aggregator
        except Aggregator.DoesNotExist:
            return None
        except Aggregator.MultipleObjectsReturned:
            return None

    def get_device_by_category_full(self, categories: list = None, page: int = None, amount: int = None):
        out = {}
        if categories:
            total = Device.objects.raw({'category': {"$in": categories}}).count()
        else:
            total = Device.objects.all().count()
        out["page"] = page
        out["amount"] = amount
        out["total"] = total

        if (page is not None and amount is not None) and (page > 0 and amount > 0):
            if categories:
                devices = list(Device.objects \
                               .raw({'category': {"$in": categories}}) \
                               .order_by([('_id', DESCENDING)]) \
                               .skip((page - 1) * amount) \
                               .limit(amount))
            else:
                devices = list(Device.objects \
                               .order_by([('_id', DESCENDING)]) \
                               .skip((page - 1) * amount) \
                               .limit(amount))

        elif (page is None or page <= 0) and amount is None:
            if categories:
                devices = list(Device.objects \
                               .raw({'category': {"$in": categories}}) \
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
            if hasattr(d, "category"):
                category = d.category.category

            if hasattr(d, "static"):
                for s in d.static:
                    r = s.to_son().to_dict()
                    r.pop('_id')
                    static.append(r)

            if hasattr(d, "live"):
                for l in d.live:
                    r = l.to_son().to_dict()
                    r.pop('_id')
                    live.append(r)

            if hasattr(d, "modules"):
                for m in d.modules:
                    type = m.type.type
                    r = m.to_son().to_dict()
                    r.pop('_id')
                    r["type"] = type
                    modules.append(r)

            d = d.to_son().to_dict()
            if "category" in d:
                d["category"] = category
            if "static" in d:
                d["static"] = static
            if "live" in d:
                d["live"] = live
            if "modules" in d:
                d["modules"] = modules

            d.pop("_id")
            devs.append(d)

        out["devices"] = devs
        return out

    def get_device_by_category(self, categories: list = None, page: int = None, amount: int = None):
        out = {}
        if categories:
            total = Device.objects.raw({'category': {"$in": categories}}).count()
        else:
            total = Device.objects.all().count()
        out["page"] = page
        out["amount"] = amount
        out["total"] = total


        if (page is not None and amount is not None) and (page > 0 and amount > 0):
            if categories:
                devices = list(Device.objects \
                               .raw({'category': {"$in": categories}}) \
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
            if categories:
                devices = list(Device.objects \
                               .raw({'category': {"$in": categories}}) \
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

            if "category" in d:
                category = self.get_category_by_id(d["category"])
                if hasattr(category, "category"):
                    category = category.category
                    d["category"] = category
                else:
                    d.pop("category")

            d["id"] = str(d.pop("_id"))
            if "_cls" in d:
                d.pop("_cls")
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

        if category is None:
            category = self.add_category(category="New")

        for device in devices:
            if "name" not in device:
                continue

            allowed = True
            dev = self.get_device_by_hostname(hostname=device["name"])
            if dev is None or (isinstance(dev, int) and dev == -1):
                allowed = False

            if isinstance(dev, bool) and dev is False:
                if "ip" in device:
                    ip = device["ip"]
                    dev = self.add_device(hostname=device["name"], category=category, ip=ip)
                else:
                    dev = self.add_device(hostname=device["name"], category=category)

            if allowed is True:
                live_data_types = {}
                for index in self.redis_indices:
                    live_data_types[index] = []

                if "static_data" in device:
                    static_data = device["static_data"]
                    for static_key in static_data:
                        if static_key == "neighbors":
                            interfaces = None
                            if "vlan" in static_data:
                                interfaces = static_data["vlan"]
                            self.__handle_lldp_data__(links=static_data[static_key], device=device,
                                                      interfaces=interfaces)
                        elif isinstance(static_data[static_key], dict):
                            self.__handle_static_data__(device=dev, key=static_key,
                                                        input=self.__clean_dictionary__(static_data[static_key]))

                if "live_data" in device:
                    live_data = device["live_data"]
                    self.redis_insert_live_data(device=dev, live_data=live_data)

                if "events" in device:
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
        if hasattr(device, "live"):
            data_list = device.live
        else:
            data_list = []
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
            if isinstance(key, str) and "." in key:
                new_key = key.replace(".", "___")
                new_dict[new_key] = dict[key]
            else:
                new_dict[key] = dict[key]
        return new_dict

    def __normalize_dictionary__(self, dict: dict):
        new_dict = {}
        for key in dict:
            if isinstance(key, str) and "___" in key:
                new_key = key.replace("___", ".")
                new_dict[new_key] = dict[key]
            else:
                new_dict[key] = dict[key]
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

    def update_device(self, id: str, hostname: str = None, ip: str = None, category: str = None):
        if self.check_if_device_exists_by_id(id) is False:
            return False
        id = ObjectId(id)
        update = {}
        if hostname:
            if self.check_if_device_exsits(hostname=hostname):
                return False
            update["hostname"] = hostname
        if ip:
            update["ip"] = ip
        if category:
            if self.check_if_category_exists(category_id=category) is False:
                return False
            update["category"] = ObjectId(category)

        Device.objects.raw({"_id": id}).update({"$set": update})
        return True

    def update_category(self, id: str, category: str):
        if self.check_if_category_exists(category_id=id) is False:
            return False

        if self.check_if_category_exists_by_name(category=category):
            return False

        update = {"category": category}
        id = ObjectId(id)
        Category.objects.raw({"_id": id}).update({"$set": update})
        return True

    def check_if_category_exists(self, category_id: str):
        count = Category.objects.raw({"_id": ObjectId(category_id)}).count()
        if count == 0:
            return False
        else:
            return True

    def check_if_category_exists_by_name(self, category: str):
        count = Category.objects.raw({"category": category}).count()
        if count == 0:
            return False
        else:
            return True

    def check_if_device_exists_by_id(self, id: str):
        count = Device.objects.raw({"_id": ObjectId(id)}).count()
        if count == 0:
            return False
        else:
            return True

    def insert_aggregator_modules(self, modules, id):
        try:
            id = ObjectId(id)
            aggregator = Aggregator.objects.get({'_id': id})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1

        types = []
        if hasattr(aggregator, "types"):
            types = aggregator.types
            # type = Type(type=t.id, signature=t.config_signature,
            #             config=self.crypt.encrypt(json.dumps(t.config_fields), dconfig("cryptokey"))).save()

        types_to_add = []
        already_inserted = []
        for type in types:
            is_obsolete = True
            for new_type in modules:
                if new_type.id == type.type:
                    type.signature = new_type.config_signature
                    type.config = self.crypt.encrypt(json.dumps(new_type.config_fields), dconfig("cryptokey"))
                    type.save()
                    is_obsolete = False
                    already_inserted.append(new_type.id)
                    break
            if is_obsolete is False:
                types_to_add.append(type)

        new_types = []

        for new_type in modules:
            if new_type.id not in already_inserted:
                type = Type(type=new_type.id, signature=new_type.config_signature,
                            config=self.crypt.encrypt(json.dumps(new_type.config_fields), dconfig("cryptokey"))).save()
                new_types.append(type)

        types_to_add.extend(new_types)
        if types_to_add:
            aggregator.types = types_to_add
        aggregator.save()


        for type in types:
            is_obsolete = True
            for new_type in types_to_add:
                if type.pk == new_type.pk:
                    is_obsolete = False
                    break
            if is_obsolete:
                type.delete()

        return True


    def add_device_web(self, hostname, category, ip="1.1.1.1"):
        try:
            cat = Category.objects.get({'category': category})
        except Category.DoesNotExist:
            return False
        except Category.MultipleObjectsReturned:
            return -1

        if self.check_if_device_exsits(hostname) is False:
            device = Device(hostname=hostname, category=cat.pk, ip=ip).save()

            if dconfig("single_aggregator_mode", cast=bool, default=False):
                identifier = dconfig("single_aggregator_identifier", default=None)
                if identifier:
                    aggregator = self.get_aggregator_by_identifier(identifier=identifier)
                    if aggregator:
                        devices = aggregator.devices
                        devices.append(device.pk)
                        aggregator.devices = devices
                        aggregator.save()
                    else:
                        token = dconfig("single_aggregator_token", cast=str, default=None)
                        if token:
                            aggregator = self.add_aggregator(token=token, identifier=identifier)
                            if aggregator:
                                devices = []
                                devices.append(device.pk)
                                aggregator.devices = devices
                                aggregator.save()

            return device
        return False

    def delete_device_web(self, id):
        try:
            dev = Device.objects.get({'_id': id})
            dev.delete()
            return True
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1

    def get_device_config(self, id):
        try:
            dev = Device.objects.get({'_id': id})
            ag = Aggregator.objects.get({'devices': id})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1
        except Aggregator.DoesNotExist:
            return False
        except Aggregator.MultipleObjectsReturned:
            return -1

        config_out = []


        for t in ag.types:
            if hasattr(dev, "modules") and dev.modules:
                for m in dev.modules:
                    decrypted = json.loads(self.crypt.decrypt(t.config, dconfig("cryptokey")))
                    if t.type == m.type.type:
                        if m.config is not None:
                            dv = self.crypt.decrypt(m.config, dconfig("cryptokey"))
                            dv = dv.replace("'", '"')
                            value = json.loads(dv)
                            decrypted = decrypted | value
                            m.config = decrypted
                        config_out.append(m)

        return config_out

    def set_device_config(self, id, reqconfig):
        try:
            dev = Device.objects.get({'_id': id})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1

        modules = []
        if hasattr(dev, "modules") and dev.modules and isinstance(dev.modules, list):
            modules = dev.modules

        for c in reqconfig:
            try:
                type = Type.objects.get({'type': c.type.id})
            except Type.DoesNotExist:
                continue

            if c.config:
                dc = self.crypt.encrypt(str(c.config), dconfig("cryptokey"))
                m = Module(type=type, config=dc).save()
            else:
                m = Module(type=type).save()

            replaced = False
            index = 0
            for module in modules:
                if module.type.pk == type.pk:
                    replaced = True
                    break
                index += 1

            if replaced is False:
                modules.append(m)
            else:
                modules[index] = m

        if modules:
            dev.modules = modules
            dev.save()
        return True

    def delete_device_config(self, id, type):
        try:
            dev = Device.objects.get({'_id': id})
        except Device.DoesNotExist:
            return False
        except Device.MultipleObjectsReturned:
            return -1

        for m in dev.modules:
            if m.type.type == type:
                m.delete()
                return True
        return False

    def get_categories(self):
        categories = list(Category.objects.order_by([('_id', DESCENDING)]).all().values())

        out = []
        for category in categories:
            category["id"] = str(category.pop("_id"))
            category.pop("_cls")
            out.append(category)

        return out


    def get_event_by_id(self, event_id):
        try:
            event_id = ObjectId(event_id)
            event = Event.objects.get({'_id': event_id})

            device = event.device
            hostname = device.hostname

            event = event.to_son().to_dict()
            event["device_id"] = str(device.pk)
            event["device"] = hostname
            event["id"] = str(event.pop("_id"))
            event.pop("_cls")

            return event
        except Event.DoesNotExist:
            return False
        except Event.MultipleObjectsReturned:
            return -1
        except pymongo.errors.InvalidId:
            return False

    def get_event_count(self, device_id: str = None, severities: list = None, min_severity: int = None):
        if min_severity:
            severities = None

        if device_id is not None:
            device_id = ObjectId(device_id)
            if severities:
                total = Event.objects.raw({'device': device_id, "severity": {"$in": severities}}).count()
            elif min_severity:
                total = Event.objects.raw({'device': device_id, "severity": {"$gte": min_severity}}).count()
            else:
                total = Event.objects.raw({'device': device_id}).count()
        else:
            if severities:
                total = Event.objects.raw({"severity": {"$in": severities}}).count()
            elif min_severity:
                total = Event.objects.raw({"severity": {"$gte": min_severity}}).count()
            else:
                total = Event.objects.all().count()
        return total

    def get_events(self, amount: int = None, page: int = None, severities: list = None, min_severity: int = None,
                   device_id: str = None):
        if device_id is not None:
            device_id = ObjectId(device_id)

        if (amount is not None and amount <= 0) or (page is not None and page < 0) or (min_severity is not None and min_severity < 0):
            return False

        if min_severity is not None:
            severity = None

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
            elif severities is not None:
                if device_id is not None:
                    events = list(
                        Event.objects
                            .raw({'device': device_id, "severity": {"$in": severities}})
                            .order_by([('_id', DESCENDING)])
                            .skip((page - 1) * amount)
                            .limit(amount)
                            .values()
                    )
                else:
                    events = list(
                        Event.objects
                            .raw({"severity": {"$in": severities}})
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
            elif severities is not None:
                if device_id is not None:
                    events = list(
                        Event.objects
                            .raw({'device': device_id, "severity": {"$in": severities}})
                            .order_by([('_id', DESCENDING)])
                            .values()
                    )
                else:
                    events = list(
                        Event.objects
                            .raw({"severity": {"$in": severities}})
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

            event["device"] = str(self.get_hostname_from_device_id(event["device_id"]))

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

    async def keep_connections(self):
        while True:
            await asyncio.sleep(10)
            print("Connections thread started")

            links = list(Link.objects.order_by([['mac', DESCENDING]]).all())

            for source in links:
                try:
                    query = {
                        "mac": f"{source.remote_mac}",
                        "remote_mac": f"{source.mac}"
                    }
                    target = Link.objects.get(query)
                except Link.DoesNotExist:
                    continue
                except Link.MultipleObjectsReturned:
                    continue

                print("Connection found")
                connection = Connection(source=source, target=target)
                if self.__check_if_connection_exists__(connection=connection) is False:
                    connection.save()



    def __create_connections__(self, source: Link):
        try:
            query = {
                "mac": f"{source.remote_mac}",
                "remote_mac": f"{source.mac}"
            }
            target = Link.objects.get(query)
        except Link.DoesNotExist:
            return
        except Link.MultipleObjectsReturned:
            return

        connection = Connection(source=source, target=target)
        if self.__check_if_connection_exists__(connection=connection) is False:
            connection.save()

    def get_device_id_from_hostname(self, hostname: str):
        device = list(Device.objects.raw({"hostname": hostname}).only("_id").all().values())
        if len(device) == 1:
            return ObjectId(device[0]["_id"])
        return None

    def get_connection_by_source(self, source_id: ObjectId):
        try:
            connection = Connection.objects.get({"source": source_id})
            return connection
        except Connection.DoesNotExist:
            return None
        except Connection.MultipleObjectsReturned:
            return None

    def get_connection_by_target(self, target_id: ObjectId):
        try:
            connection = Connection.objects.get({"target": target_id})
            return connection
        except Connection.DoesNotExist:
            return None
        except Connection.MultipleObjectsReturned:
            return None

    def get_tree(self, vlan_id: int = None):
        connections = []
        if vlan_id:
            valid_links = []
            links = list(Link.objects.only("_id").only("vlans").values())
            for link in links:
                if "vlans" in link:
                    for vlan in link["vlans"]:
                        if isinstance(vlan, dict) is False:
                            try:
                                vlan = json.loads(vlan)
                            finally:
                                continue

                        if "id" in vlan and vlan["id"] == vlan_id:
                            valid_links.append(link)

            for link in valid_links:
                connection = self.get_connection_by_source(source_id=link["_id"])
                if connection is None:
                    connection = self.get_connection_by_target(target_id=link["_id"])

                if connection:
                    connections.append(connection)

        else:
            connections = Connection.objects.all()

        links = []
        nodes = []
        for connection in connections:
            source_link = connection.source
            source_node = source_link.node
            target_link = connection.target
            target_node = target_link.node
            source_device_id = self.get_device_id_from_hostname(source_node.hostname)
            target_device_id = self.get_device_id_from_hostname(target_node.hostname)

            links.append(
                LinkJson(
                    source=source_node.hostname,
                    target=target_node.hostname,
                )
            )

            nodes.append(
                NodeJson(
                    id=source_node.hostname,
                    device_id=str(source_device_id)
                )
            )
            nodes.append(
                NodeJson(
                    id=target_node.hostname,
                    device_id=str(target_device_id)
                )
            )

        tree = TreeJson(links=links, nodes=nodes)
        return tree

    def __get_node__(self, ip: str = None, hostname: str = None):
        if ip and hostname:
            query = {
                "$or": [
                    {
                        "ip": ip
                    },
                    {
                        "hostname": hostname
                    }
                ]
            }
        elif ip is None:
            query = {"hostname": hostname}
        else:
            return

        try:
            node = Node.objects.get(query)
            return node
        except Node.DoesNotExist:
            return None
        except Node.MultipleObjectsReturned:
            return None

    def __is_int__(self, input):
        try:
            int(input)
            return True
        except ValueError:
            return False

    def __handle_lldp_data__(self, links: dict, device: dict, interfaces: list):
        hostname = device["name"]
        ip = None
        if "ip" in device:
            ip = device["ip"]

        node = self.__get_node__(ip=ip, hostname=hostname)

        if node is None:
            if ip is None and hostname:
                node = Node(hostname=hostname).save()
            else:
                node = Node(hostname=hostname, ip=ip).save()
        else:
            Link.objects.raw(
                {
                    "node": node.pk
                }
            ).delete()

        new_links = []
        for link_key in links:
            link = links[link_key][0]
            if "local_mac" in link:
                mac = link["local_mac"].lower()
            else:
                continue

            vlans = []
            is_trunk = False
            if "local_port" in link:
                description = link["local_port"]

                if interfaces:
                    for interface in interfaces:
                        if "port" in interface and description == interface["port"]:
                            if "is_trunk" in interface and isinstance(interface["is_trunk"], bool):
                                is_trunk = interface["is_trunk"]

                            if "vlans" in interface and isinstance(interface["vlans"], list) and len(interface["vlans"]) > 1:
                                is_trunk = True

                            if "vlans" in interface and isinstance(interface["vlans"], list):

                                for vlan in interface["vlans"]:
                                    if "id" in vlan and "name" in vlan:
                                        vlan_id = vlan["id"]
                                        vlan_name = vlan["name"]
                                        vlans.append({"id": vlan_id, "name": vlan_name})

            else:
                continue

            remote_mac = None
            if "remote_chassis_id" in link:
                remote_mac = link["remote_chassis_id"].lower()

            if remote_mac:
                new_link = Link(mac=mac, description=description, remote_mac=remote_mac, node=node)
            else:
                new_link = Link(mac=mac, description=description, node=node)

            if vlans:
                new_link.vlans = vlans
                new_link.is_trunk = is_trunk

            new_link = self.__save_link__(new_link)
            if new_link:
                new_links.append(new_link)

        # for new_link in new_links:
        #     self.__create_connections__(new_link)

    def __save_link__(self, link: Link):
        try:
            link = link.save()
            return link
        except pymongo.errors.DuplicateKeyError:
            return None

    # --- Redis --- #

    def redis_insert_live_data(self, device: Device, live_data: dict):
        hostname = device.hostname
        print(live_data)

        for port in live_data:
            if isinstance(live_data[port], dict) is False:
                continue

            port_data = live_data[port]
            for key in port_data:
                if isinstance(key, str) is False:
                    continue

                if key in self.redis_indices is False:
                    continue

                try:
                    database_index = self.redis_indices.index(key)
                except ValueError:
                    continue

                if database_index != -1:
                    self.redis_insert(hostname=f"{hostname}--//--{port}", values=port_data[key],
                                      database_index=database_index)

    def redis_insert(self, hostname: str, values: dict, database_index: int):
        pool = redis.ConnectionPool(host=str(dconfig("rDBurl")),
                                    port=str(dconfig("rDBport")),
                                    password=str(dconfig("rDBpassword")),
                                    username=str(dconfig("rDBusername")),
                                    db=database_index)
        r = redis.Redis(connection_pool=pool)
        r.zadd(hostname, values)
        pool.connection_class()

    async def thread_insertIntoDatabase(self):
        while True:
            await asyncio.sleep(30 * 60)

            for i in range(0, len(self.redis_indices)):
                pool = redis.ConnectionPool(host=str(dconfig("rDBurl")),
                                            port=str(dconfig("rDBport")),
                                            password=str(dconfig("rDBpassword")),
                                            username=str(dconfig("rDBusername")),
                                            db=i)
                r = redis.Redis(connection_pool=pool)

                for key in r.scan_iter():
                    keys = str(key, "utf-8").split("--//--")
                    if isinstance(keys, list):
                        hostname = keys[0]
                        port = keys[1]

                    scores = r.zrange(key, 0, -1, withscores=True)

                    device = self.get_device_by_hostname(hostname)
                    if isinstance(device, bool) and device is False:
                        category = self.get_category_by_category("New")

                        if category is None:
                            category = self.add_category(category="New")

                        device = self.add_device(hostname=hostname, category=category)

                    type = self.redis_indices[i]

                    avg_score = 0
                    for score in scores:
                        avg_score += score[1]
                        #if score[1] >= 10:
                        if False:

                            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                            event_time = str(score[0], "utf-8")
                            if self.__is_float__(num=event_time) is True:
                                timestamp = datetime.fromtimestamp(float(event_time))
                            elif isinstance(event_time, str):
                                timestamp = datetime.strptime(event_time, '%Y-%m-%d %H:%M:%S')

                            event = f"Unusual high amount of {type} at {port}: {str(score[1])}"
                            self.add_event(device=device, event=event, severity=3, timestamp=timestamp)

                    if len(scores) > 0:
                        avg_score /= len(scores)

                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    data = {timestamp: avg_score}
                    self.__handle_live_data__(device=device, key=type, input=data)
                r.flushdb()

    # --- Filter --- #

    def filter_devices(self, key: str, value: str, page: int = None, amount: int = None, category_id: str = None):
        self.__handle_filter__(key, value)

        if page and page <= 0:
            page = None

        if amount and amount <= 0:
            amount = None

        is_page = False
        if page and amount:
            is_page = True

        if is_page:
            cursor_page = Data.objects.aggregate(
                {
                    "$addFields": {
                        "UnknownKeys": {
                            "$objectToArray": "$data"
                        }
                    }
                },
                {
                    "$match": {
                        f"UnknownKeys.v.{key}": {
                            "$regex": f"{value}", "$options": "i"
                        }
                    }
                },
                {
                    "$project": {"_id": 1},
                },
                {
                    "$skip": (page - 1) * amount
                },
                {
                    "$limit": amount
                }
            )

        cursor_total = Data.objects.aggregate(
            {
                "$addFields": {
                    "UnknownKeys": {
                        "$objectToArray": "$data"
                    }
                }
            },
            {
                "$match": {
                    f"UnknownKeys.v.{key}": {
                        "$regex": f"{value}", "$options": "i"
                    }
                }
            },
            {
                "$project": {"_id": 1},
            }
        )

        if is_page:
            page_ids = []
            for id in list(cursor_page):
                page_ids.append(id["_id"])

        total_ids = []
        for id in list(cursor_total):
            total_ids.append(id["_id"])

        if category_id:
            devices_raw = Device.objects.raw({"category": ObjectId(category_id)}).all()
        else:
            devices_raw = Device.objects.all()

        if is_page:
            devices = list(
                devices_raw.aggregate(
                    {
                        "$match": {
                            "static": {
                                "$in": page_ids
                            }
                        }
                    },
                    {
                        "$project": {
                            "_id": 1,
                            "hostname": 1,
                            "ip": 1,
                            "category": 1
                        },
                    }
                )
            )
        else:
            devices = list(
                devices_raw.aggregate({"$match": {
                    "static": {"$in": total_ids}}},
                    {
                        "$project": {"_id": 1, "hostname": 1, "ip": 1, "category": 1},
                    })
            )

        if is_page:
            total = len(list(
                devices_raw.aggregate({"$match": {
                    "static": {"$in": total_ids}}},
                    {
                        "$project": {"_id": 1, "hostname": 1, "ip": 1, "category": 1},
                    })
            ))
        else:
            total = len(devices)

        devs = []
        for d in devices:
            if "category" in d:
                category = self.get_category_by_id(d["category"])
                if category and isinstance(category, Category) and hasattr(category, "category"):
                    category = category.category
                    d["category"] = category
                else:
                    d.pop("category")

            d["id"] = str(d.pop("_id"))

            devs.append(d)

        return {
            "page": page,
            "amout": amount,
            "total": total,
            "devices": devs
        }

    def __handle_filter__(self, key: str, value: str):
        try:
            filter = Filter(key=key, value=value)
            filter.save()
            return True
        except pymongo.errors.DuplicateKeyError:
            return False

    def get_filter(self):
        filters = []
        for filter in list(Filter.objects.all().values()):
            filter["id"] = str(filter.pop("_id"))
            filter.pop("_cls")

            filters.append(filter)

        return filters

    def first_start(self):
        category_switch = self.get_category_by_category("Switch")
        if category_switch is None:
            self.add_category(category="Switch")

        category_zabbix = self.get_category_by_category("Zabbix")
        if category_zabbix is None:
            self.add_category(category="Zabbix")
