from pymodm import MongoModel, fields, ReferenceField
from pymongo import IndexModel, DESCENDING


class Type(MongoModel):
    type = fields.CharField(required=True)
    config = fields.CharField(required=True)
    signature = fields.CharField(required=True)

    class Meta:
        indexes = [
            IndexModel([('type', DESCENDING)], unique=True)
        ]


class Module(MongoModel):
    config = fields.CharField(required=False)
    type = fields.ReferenceField(Type, on_delete=ReferenceField.CASCADE)