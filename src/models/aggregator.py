from pymodm import MongoModel, fields, GenericIPAddressField, ReferenceField
from pymongo import IndexModel, DESCENDING
from src.models.device import Device


class Type(MongoModel):
    type = fields.CharField(required=True)
    config = fields.CharField(required=True)


class Module(MongoModel):
    config = fields.CharField(required=False)
    type = fields.ReferenceField(Type, on_delete=ReferenceField.DENY)
    devices = fields.ListField(ReferenceField(Device, on_delete=ReferenceField.DENY))


class Aggregator(MongoModel):
    identifier = fields.CharField(required=True)
    version = fields.CharField(required=True)
    ip = fields.GenericIPAddressField(protocol=GenericIPAddressField.IPV4)
    modules = fields.ListField(fields.ReferenceField(Module, on_delete=ReferenceField.NULLIFY))

    class Meta:
        indexes = [
            IndexModel([('identifier', DESCENDING)], unique=True)
        ]
