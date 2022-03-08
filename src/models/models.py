import datetime
import json

from pydantic import BaseModel, Field
from typing import Optional
from decouple import config
from sqlalchemy import Numeric, ForeignKey, Column, String, JSON, Integer, TIMESTAMP
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy_repr as repr
from datetime import datetime

# only for test
from random import randint

Base = declarative_base(cls=repr.RepresentableBase)


class APIStatus(BaseModel):
    message: str = "OrderService is up and running"
    version: str
    uptime: str


class User(BaseModel):
    id: int


class Settings(BaseModel):
    authjwt_secret_key: str = config("secret")


class Category(BaseModel):
    category: str = "Drucka"


class Type(BaseModel):
    id: str = "SoSoHo"
    config_signature: dict
    config_fields: dict


class Module(BaseModel):
    config: str = "JSON Static Config Override"
    type: list[Type]


class Device(BaseModel):
    hostname: str = "device.local"
    ip: str = "1.2.3.4"
    category: list[Category]
    static: str = "JSON Static Data"
    live: str = "JSON Live Data"
    modules: list[Module]


class Event(BaseModel):
    information: str = "event has happend"
    timestamp: datetime = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    severity: int = 2
    device_id: str = "621bcca84763b786518e2a4f"


class ExternalEvents(BaseModel):
    external_event: dict


class AddDataForDevices(BaseModel):
    devices: list
    external_events: dict


class ServiceLoginOut(BaseModel):
    access_token: str
    refresh_token: str


class ServiceAggregatorLoginOut(BaseModel):
    aggregator_id: str
    access_token: str
    refresh_token: str


class ServiceLogin(BaseModel):
    password: str = "TYlZfng0wwuEOaxcyyoJ2N5otTPS0g4X6fXq9s777yJxwtcpHsRQC1F5Ao5PI3MT42xlMeBOP4jN7fUAA5a5vEtM7WWIMYvQPDebr5Lcgz9Ri1yEQiwmObINIHyI8pMw"
    id: int = 1
    name: str = "Hons"


class ServiceAggregatorLogin(BaseModel):
    token: str = "token"


class AddAggregatorIn(BaseModel):
    token: str = "token"


class AddAggregatorOut(BaseModel):
    detail: str = "Created"


class DeviceByIdIn(BaseModel):
    id: str = "621bcca84763b786518e2a4f"


class DeviceByIdOut(BaseModel):
    device: Device


class AggregatorByID(BaseModel):
    version: str = "0.0.0.0"
    ip: str = "1.2.3.4"
    devices: list[Device]


class GetDevicesByAggregator(BaseModel):
    id: str = "621bcca84763b786518e2a4f"


class GetAllDevicesOut(BaseModel):
    devices: list[Device]


class AggregatorVersionIn(BaseModel):
    version: str = "1.0.0"


class AggregatorVersionOut(BaseModel):
    detail: str = "Updated"


class AggregatorModulesIn(BaseModel):
    modules: list[Type]


class AggregatorModulesOut(BaseModel):
    detail: str = "Inserted"


class AddDeviceIn(BaseModel):
    device: str = "name"
    ip: Optional[str] = "testDevice.local or 0.0.0.0"
    category: str = "category"


class AddDeviceOut(BaseModel):
    detail: str = "Success"


class AddCategoryIn(BaseModel):
    category: str = "category"


class AddCategoryOut(BaseModel):
    detail: str = "Success"


class GetAlertByIdOut(BaseModel):
    event: Event



# --- Old Models for old DB --- #

class oldDevice(BaseModel):  # old device model, should be deleted
    id: Optional[str] = None
    name: str
    ip: str
    type: str
    aggregator_id: int
    timeout: int
    module_name: list

    def get_id(self):
        # gets id from db after adding device to it
        return randint(0, 1000)

    def serialize(self):
        modules = []
        for m in self.module_name:
            modules.append({"name": m, "config": {}})
        out = {
            "id": self.id,
            "name": self.name,
            "timeout": self.timeout,
            "ip": self.ip,
            "type": self.type,
            "modules": modules
        }
        return out

    def serialize_without_id(self):
        modules = []
        for m in self.module_name:
            modules.append({"name": m, "config": {}})
        out = {
            "name": self.name,
            "timeout": self.timeout,
            "ip": self.ip,
            "type": self.type,
            "modules": modules
        }
        return out


class Category(Base):
    __tablename__ = "Category"
    id = Column(Integer, primary_key=True, autoincrement=True)
    category = Column(String)
    devices = relationship('Device', back_populates="category", lazy='joined')

    def __init__(self, category):
        self.category = category


class Device(Base):
    __tablename__ = "Device"
    id = Column(Integer, primary_key=True)
    device = Column(String)
    features = relationship('Feature', back_populates="device", lazy='joined')
    category_id = Column(Integer, ForeignKey('Category.id'))
    category = relationship('Category', back_populates="devices")
    ip = Column(String)

    def __init__(self, device, category, ip):
        self.device = device
        self.category = category
        self.ip = ip


class Feature(Base):
    __tablename__ = "Feature"
    id = Column(Integer, primary_key=True)
    feature = Column(String)
    value_numerics = relationship('Value_Numeric', back_populates="feature", lazy='joined')
    value_strings = relationship('Value_String', back_populates="feature", lazy='joined')
    device_id = Column(Integer, ForeignKey('Device.id'))
    device = relationship('Device', back_populates="features")

    def __init__(self, feature, device):
        self.feature = feature
        self.device = device


class Value_Numeric(Base):
    __tablename__ = "Value_Numeric"
    id = Column(Integer, primary_key=True)
    key = Column(String)
    value = Column(Numeric)
    feature_id = Column(Integer, ForeignKey('Feature.id'))
    feature = relationship('Feature', back_populates="value_numerics")

    def __init__(self, key, value, feature):
        self.key = key
        self.value = value
        self.feature = feature


class Value_String(Base):
    __tablename__ = "Value_String"
    id = Column(Integer, primary_key=True)
    key = Column(String)
    value = Column(String)
    feature_id = Column(Integer, ForeignKey('Feature.id'))
    feature = relationship('Feature', back_populates="value_strings")

    def __init__(self, key, value, feature):
        self.key = key
        self.value = value
        self.feature = feature


class Alert(Base):
    __tablename__ = "Alert"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(TIMESTAMP)
    problem = Column(String)
    severity = Column(Integer)
    device_id = Column(Integer, ForeignKey('Device.id'))


class Aggregator(Base):
    __tablename__ = "Aggregator"
    id = Column(Integer, primary_key=True, autoincrement=True)
    version = Column(String)
    token = Column(String)

    def __init__(self, version, token):
        self.version = version
        self.token = token


class Module(Base):
    __tablename__ = "Module"
    id = Column(Integer, primary_key=True, autoincrement=True)
    config_fields = Column(JSON)
    device_id = Column(Integer, ForeignKey('Device.id'))


class Type(Base):
    __tablename__ = "Type"
    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String, unique=True)
    config_signature = Column(JSON)
    config_fields = Column(JSON)


class Aggregator_To_Type(Base):
    __tablename__ = "Aggregator_To_Type"
    id = Column(Integer, primary_key=True, autoincrement=True)
    type_id = Column(Integer, ForeignKey('Type.id'))
    aggregator_id = Column(Integer, ForeignKey('Aggregator.id'))
