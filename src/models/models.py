from pydantic import BaseModel
from typing import Optional
from decouple import config
from sqlalchemy import Numeric, ForeignKey, Column, String, JSON, Integer, TIMESTAMP
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
import sqlalchemy_repr as repr

# only for test
from random import randint


Base = declarative_base(cls=repr.RepresentableBase)


class User(BaseModel):
    id: int


class Settings(BaseModel):
    #authjwt_secret_key: str = config("secret")
    authjwt_secret_key: str = "secret"


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