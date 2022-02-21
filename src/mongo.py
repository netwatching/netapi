import json
from datetime import datetime

from pymodm import connection
from pymongo import DESCENDING
import pymongo.errors

from src.models.event import Event
from src.models.aggregator import Type, Module, Aggregator
from src.models.device import Device


class Mongo:
    # def __init__(self, details):
    #    self.client = pymodm.connection.connect(details)
    connection.connect(
        "mongodb://netwatch:jfMCDp9dzZrTxytB6zSrtEjkqXcrmvPKrnXttTFj383u8UFmN3AqY9XdPw7H@palguin.htl-vil.local:27017/netdb?authSource=admin&readPreference=primary&appname=MongoDB%20Compass&ssl=false")

    if __name__ == "__main__":
        try:
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
        except Exception as e:
            print(e)

    def get_modules(self):
        return list(Module.objects.order_by(['type', DESCENDING]).all())
