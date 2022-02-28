import datetime

from decouple import config
from fastapi import HTTPException
from pymodm import connection
from pymongo import DESCENDING

from src.models.event import Event
from src.models.aggregator import Aggregator
from src.models.module import Type, Module
from src.models.device import Device, Category


# noinspection PyMethodMayBeStatic
class MongoDBIO:
    def __init__(self, details):
        self.details = details
        connection.connect(details)

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
                devices =  list(Device.objects \
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


timestamp = datetime.datetime.now().strftime("%m/%d/%Y, %H:%M:%S")

mongo = MongoDBIO(details=f'mongodb://'
                          f'{config("mDBuser")}:{config("mDBpassword")}@'
                          f'{config("mDBurl")}:{config("mDBport")}/'
                          f'{config("mDBdatabase")}?authSource=admin')

category = mongo.add_category(category=f"category.{timestamp}")
device = mongo.add_device(hostname=f"hostname.{timestamp}", ip=f"ip.{timestamp}", category=category)

devices = mongo.get_device_by_category(category=f"category.{timestamp}", page=1, amount=10)
devices = mongo.get_device_by_category(page=2, amount=10)
devices = mongo.get_device_by_category(category=f"category.{timestamp}")
devices = mongo.get_device_by_category()



