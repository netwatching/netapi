from pymongo import IndexModel, DESCENDING

from pymodm import MongoModel, fields, ReferenceField
from src.models.module import Module


class Category(MongoModel):
    category = fields.CharField(required=True)

    class Meta:
        indexes = [
            IndexModel([('category', DESCENDING)], unique=True)
        ]


class Data(MongoModel):
    key = fields.CharField(required=True)
    data = fields.DictField(required=True)


class Device(MongoModel):
    hostname = fields.CharField(required=True)
    ip = fields.CharField(required=False)
    category = fields.ReferenceField(Category, required=False, on_delete=ReferenceField.NULLIFY)
    static = fields.ListField(fields.ReferenceField(Data, on_delete=ReferenceField.NULLIFY))
    live = fields.ListField(fields.ReferenceField(Data, on_delete=ReferenceField.NULLIFY))
    modules = fields.ListField(fields.ReferenceField(Module, on_delete=ReferenceField.NULLIFY), required=False)

    class Meta:
        indexes = [
            IndexModel([('hostname', DESCENDING)], unique=True)
        ]



