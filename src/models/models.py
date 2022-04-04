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
    message: str = "NetAPI is up and running"
    version: str
    uptime: str


class User(BaseModel):
    id: int


class Settings(BaseModel):
    authjwt_secret_key: str = config("secret")


class Category(BaseModel):
    category: str = "Drucka"
    id: str = "0101010"

class UpdateDevice(BaseModel):
    hostname: Optional[str]
    category: Optional[str]
    ip: Optional[str]


class AggregatorSmall(BaseModel):
    version: str = "1.0"
    identifier: str = "identifier"
    id: str = "622cf4f1af250c8c7f1ad1bc"


class Type(BaseModel):
    id: str = "ssh"
    config_signature: dict
    config_fields: dict

class TypeID(BaseModel):
    id: str = "ssh"

class Module(BaseModel):
    config: Optional[dict] = {"timeout": 5}
    type: TypeID


class CoreTypeOut(BaseModel):
    config: str =  ""
    id: str = "6241fd6191ddffb865978d87"
    name: str = "ssh"
    type : dict


class DeviceConfigOut(BaseModel):
    configs: list[CoreTypeOut]


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
    identifier: str = "myAggregator"


class AddAggregatorOut(BaseModel):
    detail: str = "Created"


class DeviceByIdIn(BaseModel):
    id: str = "621bcca84763b786518e2a4f"


class DeviceByIdOut(BaseModel):
    device: dict


class AggregatorByID(BaseModel):
    version: str = "0.0.0.0"
    ip: str = "1.2.3.4"
    devices: list


class LinkAgDeviceIN(BaseModel):
    aggregator: str = "Aggregator Identifier"
    device: str = "Device Hostname"


class GetCategoriesOut(BaseModel):
    categories: list[Category]


class AggregatorDeviceLinkOut(BaseModel):
    detail: str = "updated"


class GetDevicesByAggregator(BaseModel):
    id: str = "621bcca84763b786518e2a4f"


class GetAllDevicesOut(BaseModel):
    page: int = None
    amount: int = None
    total: int = 123
    devices: list


class GetAllAlertsOut(BaseModel):
    page: int = None
    amount: int = None
    total: int = 123
    alerts: list


class AggregatorVersionIn(BaseModel):
    version: str = "1.0.0"


class AggregatorVersionOut(BaseModel):
    detail: str = "Updated"


class AggregatorModulesIn(BaseModel):
    modules: list[Type]


class AggregatorModulesOut(BaseModel):
    detail: str = "Inserted"


class AddDeviceIn(BaseModel):
    hostname: str = "device.local"
    ip: Optional[str] = "0.0.0.0"
    category: str = "category"


class AddDeviceOut(BaseModel):
    detail: str = "Success"


class AddCategoryIn(BaseModel):
    category: str = "category"


class AddCategoryOut(BaseModel):
    detail: str = "Success"


class AddDataForDeviceOut(BaseModel):
    detail: str = "Success"


class GetAlertByIdOut(BaseModel):
    event: dict


class GetAlertsByIdIn(BaseModel):
    device_id: str
    min_severity: Optional[int] = 0
    severity: Optional[int] = None
    page: Optional[int] = None
    amount: Optional[int] = None


class SetConfig(BaseModel):
    config: list[Module]


class DeleteConfig(BaseModel):
    module: str = "ssh"


class AggregatorsOut(BaseModel):
    aggregators: list[AggregatorSmall]


class DevicesFilterOut(BaseModel):
    page: int = None
    amount: int = None
    total: int = None
    devices: list


class FilterOut(BaseModel):
    key: str
    value: str