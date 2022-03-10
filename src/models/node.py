from pydantic import BaseModel
from pymodm import MongoModel, fields
from pymongo import IndexModel, DESCENDING


class Node(MongoModel):
    hostname = fields.CharField(required=True)
    ip = fields.CharField(required=False)

    class Meta:
        indexes = [
            IndexModel([('hostname', DESCENDING)], unique=True)
        ]


class Link(MongoModel):
    mac = fields.CharField(required=True)
    remote_mac = fields.CharField(required=False)
    description = fields.CharField(required=True)
    vlan = fields.IntegerField(default=1)
    is_trunk = fields.BooleanField(default=False)
    node = fields.ReferenceField(Node, required=True)

    class Meta:
        indexes = [
            IndexModel([('mac', DESCENDING)], unique=True),
            IndexModel([('remote_mac', DESCENDING)], unique=True),
            IndexModel([('description', DESCENDING), ("node", DESCENDING)], unique=True)
        ]


class Connection(MongoModel):
    source = fields.ReferenceField(Link, required=True)
    target = fields.ReferenceField(Link, required=True)

    indexes = [
        IndexModel([('source', DESCENDING), ("target", DESCENDING)], unique=True)
    ]


class LinkJson(BaseModel):
    source: str
    target: str
    value: int = 50


class NodeJson(BaseModel):
    id: str
    group: int = 0


class TreeJson(BaseModel):
    links: list[LinkJson]
    nodes: list[NodeJson]
