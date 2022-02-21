from pymongo import IndexModel, DESCENDING

from pymodm import MongoModel, fields, GenericIPAddressField


class Device(MongoModel):
    hostname = fields.CharField(required=True)
    ip = fields.GenericIPAddressField(required=True, protocol=GenericIPAddressField.IPV4)
    category = fields.CharField(required=True)
    static = fields.ListField(fields.CharField())
    live = fields.ListField(fields.CharField())

    class Meta:
        indexes = [
            IndexModel([('hostname', DESCENDING)], unique=True),
            IndexModel([('category', DESCENDING)])
        ]
