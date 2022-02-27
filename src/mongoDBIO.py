import json
from datetime import datetime

from pymodm import connection
from pymongo import DESCENDING
import pymongo.errors

from src.models.event import Event
from src.models.aggregator import Aggregator
from src.models.module import Type, Module
from src.models.device import Device, Category


class MongoDBIO:
    def __init__(self, details):
        self.details = details
        connection.connect(details)

    def get_modules(self):
        try:
            modules = list(Module.objects.order_by([['type', DESCENDING]]).all())
            return modules
        except Exception as e:
            print(e)

    def add_category(self, category: str):
        try:
            category = Category(category=category).save()
            return category
        except Exception as e:
            print(e)

    def add_device(self, hostname: str, category: Category, ip: str = None):
        try:
            device = Device(
                hostname=hostname,
                ip=ip,
                category=category).save()
            return device
        except Exception as e:
            print(e)
