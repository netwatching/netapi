from datetime import datetime

from pymodm import MongoModel, fields, ReferenceField
from pymongo import IndexModel, DESCENDING

from src.models.device import Device


class Event(MongoModel):
    timestamp = fields.DateTimeField(default=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    event = fields.CharField(required=True)
    severity = fields.IntegerField(required=True, min_value=0, max_value=10)
    device = fields.ReferenceField(Device, ReferenceField.CASCADE)

    class Meta:
        indexes = [
            IndexModel(
                [
                    ('event', DESCENDING),
                    ('timestamp', DESCENDING),
                    ('device', DESCENDING)
                ], unique=True)
        ]

