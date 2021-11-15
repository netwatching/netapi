from pydantic import BaseModel
from typing import Optional
from decouple import config

# only for test
from random import randint

class User(BaseModel):
    id: int


class Settings(BaseModel):
    authjwt_secret_key: str = config("secret")


class Device(BaseModel):
    id: Optional[str] = None
    name: str
    ip: str
    type: str
    aggregator_id: int
    timeout: int

    def get_id(self):
        # gets id from db after adding device to it
        return randint(0, 1000)

    def serialize(self):
        out = {
            "id": self.id,
            "name": self.name,
            "ip": self.ip,
            "type": self.type,
            "aggregator_id": self.aggregator_id,
            "timeout": self.timeout
        }
        return out

    def serialize_without_id(self):
        out = {
            "name": self.name,
            "ip": self.ip,
            "type": self.type,
            "aggregator_id": self.aggregator_id,
            "timeout": self.timeout
        }
        return out
