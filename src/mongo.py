import json
from datetime import datetime

from pymodm import connection
from pymongo import DESCENDING
import pymongo.errors

from src.models.event import Event
from src.models.aggregator import Aggregator
from src.models.module import Type, Module
from src.models.device import Device


class Mongo:
    def __init__(self, details):
        self.details = details
        connection.connect(self.details)

    def test(self):
        try:
            connection.connect(self.details)
            # Try if DICT is convertable to and from JSON
            data = {"test_key": "test_value", "test_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            data = json.dumps(data)
            data = json.loads(data)

            # Creating and saving a new device
            device = Device(
                hostname="localhost",
                ip="192.169.0.1",
                category="testing",
                static=[data, data],
                live=[data, data]).save()

            # Creating and saving two new events
            event00 = Event(event="This is a test", severity=5, device=device).save()
            event01 = Event(event="This is a test for insy", severity=1, device=device).save()

            # Retrieving and updating an event
            event = Event.objects.get({'event': "This is a test for insy"})
            event.event = "This test has been updated"
            event = event.save()

            # Retrieving a list of events
            events = list(Event.objects.raw({'event': {'$regex': 'test', '$options': 'gm'}}))

            # Deleting an event and a device
            event.delete()
            device.delete()

        except pymongo.errors.DuplicateKeyError as e:
            print(e)

    def get_modules(self):
        try:
            modules = list(Module.objects.order_by([['type', DESCENDING]]).all())
            return modules
        except Exception as e:
            print(e)

    def add_device(self, hostname: str, category: str, ip: str = None):
        try:
            device = Device(
                hostname=hostname,
                ip=ip,
                category=category).save()
            return device
        except Exception as e:
            print(e)


mongo = Mongo(
    details="mongodb://netwatch:jfMCDp9dzZrTxytB6zSrtEjkqXcrmvPKrnXttTFj383u8UFmN3AqY9XdPw7H@palguin.htl-vil.local:27017/netdb?authSource=admin")
# mongo.test()

modules = mongo.get_modules()
print(modules)

time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
device = mongo.add_device(hostname=f'test.{time}', category='test', ip='192.126.12.1')
print(device.pk)
