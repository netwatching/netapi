from pymodm import MongoModel, fields, ReferenceField
from pymongo import IndexModel, DESCENDING

from src.models.device import Device
from src.models.module import Type

class Aggregator(MongoModel):
    token = fields.CharField(required=True)
    version = fields.CharField(required=False)
    identifier = fields.CharField(required=False)
    devices = fields.ListField(fields.ReferenceField(Device, on_delete=ReferenceField.NULLIFY))
    types = fields.ListField(fields.ReferenceField(Type, on_delete=ReferenceField.NULLIFY))

    class Meta:
        indexes = [
            IndexModel([('token', DESCENDING)], unique=True),
            IndexModel([('identifier', DESCENDING)], unique=True)
        ]
