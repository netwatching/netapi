from pymodm import MongoModel, fields, ReferenceField


class Type(MongoModel):
    type = fields.CharField(required=True)
    config = fields.CharField(required=False)
    signature = fields.CharField(required=True)


class Module(MongoModel):
    config = fields.CharField(required=False)
    type = fields.ReferenceField(Type, on_delete=ReferenceField.CASCADE)