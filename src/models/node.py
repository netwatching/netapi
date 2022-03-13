from typing import Optional

from pydantic import BaseModel
from pymodm import MongoModel, fields, ReferenceField
from pymongo import IndexModel, DESCENDING


class Node(MongoModel):
    hostname = fields.CharField(required=True)
    ip = fields.CharField(required=False)

    class Meta:
        indexes = [
            IndexModel([('ip', DESCENDING)], unique=True),
            IndexModel([('hostname', DESCENDING)], unique=True),
        ]


class Link(MongoModel):
    mac = fields.CharField(required=True)
    remote_mac = fields.CharField(required=False)
    description = fields.CharField(required=True)
    vlan_id = fields.IntegerField(default=1)
    vlan_name = fields.CharField(default="Default")
    is_trunk = fields.BooleanField(default=False)
    node = fields.ReferenceField(Node, required=True, on_delete=ReferenceField.CASCADE)

    class Meta:
        indexes = [
            IndexModel([('description', DESCENDING), ("node", DESCENDING)], unique=True),
            IndexModel([('description', DESCENDING), ("node", DESCENDING), ("remote_mac", DESCENDING)], unique=True)
        ]


class Connection(MongoModel):
    source = fields.ReferenceField(Link, required=True, on_delete=ReferenceField.CASCADE)
    target = fields.ReferenceField(Link, required=True, on_delete=ReferenceField.CASCADE)

    indexes = [
        IndexModel([('source', DESCENDING), ("target", DESCENDING)], unique=True)
    ]


class LinkJson(BaseModel):
    source: str
    target: str
    value: int = 50

    # Additional data
    # source_mac: str
    # source_description: str
    # target_mac: str
    # target_description: str


class NodeJson(BaseModel):
    id: str
    group: int = 1

    # Additional data
    # ip: Optional[str]


class TreeJson(BaseModel):
    links: list[LinkJson]
    nodes: list[NodeJson]
