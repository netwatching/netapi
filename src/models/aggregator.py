from pymodm import MongoModel, fields, ReferenceField
from pymongo import IndexModel, DESCENDING

from src.models.device import Device

class Aggregator(MongoModel):
    token = fields.CharField(required=True)
    version = fields.CharField(required=False)
    identifier = fields.CharField(required=True)
    devices = fields.ListField(fields.ReferenceField(Device, on_delete=ReferenceField.DENY))

    class Meta:
        indexes = [
            IndexModel([('token', DESCENDING)], unique=True),
            IndexModel([('identifier', DESCENDING)], unique=True)
        ]
