from pymongo import IndexModel, DESCENDING

from pymodm import MongoModel, fields, GenericIPAddressField, ReferenceField
from src.models.aggregator import Module


class Device(MongoModel):
    hostname = fields.CharField(required=True)
    ip = fields.GenericIPAddressField(required=True, protocol=GenericIPAddressField.IPV4)
    category = fields.CharField(required=True)
    static = fields.ListField(fields.CharField())
    live = fields.ListField(fields.CharField())
    modules = fields.ListField(ReferenceField(Module, on_delete=ReferenceField.DENY), required=False)

    class Meta:
        indexes = [
            IndexModel([('hostname', DESCENDING)], unique=True),
            IndexModel([('category', DESCENDING)])
        ]
