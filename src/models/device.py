from pymongo import IndexModel, DESCENDING

from pymodm import MongoModel, fields, GenericIPAddressField, ReferenceField
from src.models.module import Module


class Device(MongoModel):
    hostname = fields.CharField(required=True)
    ip = fields.GenericIPAddressField(required=False, protocol=GenericIPAddressField.IPV4)
    category = fields.CharField(required=True)
    static = fields.ListField(fields.CharField())
    live = fields.ListField(fields.CharField())
    modules = fields.ListField(fields.ReferenceField(Module, on_delete=ReferenceField.CASCADE), required=False)

    class Meta:
        indexes = [
            IndexModel([('hostname', DESCENDING)], unique=True),
            IndexModel([('category', DESCENDING)])
        ]
