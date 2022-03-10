from pymodm import MongoModel, fields


class Interface(MongoModel):
    mac = fields.CharField(required=True)
    port = fields.CharField(required=True)
    vlan = fields.IntegerField(default=1)
    is_trunk = fields.BooleanField(default=False)


class Node(MongoModel):
    hostname = fields.CharField(required=True)
    ip = fields.CharField(required=False)
    interfaces = fields.ListField(fields)
