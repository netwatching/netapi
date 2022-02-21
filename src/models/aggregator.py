from pymodm import MongoModel, fields, GenericIPAddressField, ReferenceField
from pymongo import IndexModel, DESCENDING

from src.models.device import Device

class Aggregator(MongoModel):
    identifier = fields.CharField(required=True)
    version = fields.CharField(required=True)
    ip = fields.GenericIPAddressField(protocol=GenericIPAddressField.IPV4)
    devices = fields.ListField(fields.ReferenceField(Device, on_delete=ReferenceField.DENY))

    class Meta:
        indexes = [
            IndexModel([('identifier', DESCENDING)], unique=True)
        ]
