from fastapi import FastAPI, Request
from pydantic import BaseModel
from typing import Optional

# only for test
from random import randint
import time

app = FastAPI()


class Device(BaseModel):
    id: Optional[int] = None
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


@app.post("/api/aggregator-login")
async def aggregator_login(token: str):
    """
    /aggregator-login - POST - aggregator sends token, gets token and aggregator-id returned
    """
    token = "ghjklfdsjhjdfshgjks"
    aggregator_id = 1

    return {"token": token, "id": aggregator_id}


@app.get("/api/aggregator/{id}")
async def aggregator(id: int):
    """
    /aggregator/{id} - GET - returns devices belonging to the aggregator
    """
    out = []
    if id > 0:
        for i in range(1, 6):
            d = Device(id=i, name=f'device{i}', ip=f'10.10.10.{i}', type='Cisco' if i % 2 else 'Ubiquiti', aggregator_id=id, timeout=10)
            out.append(d.serialize())
    return {"device": out}


@app.get("/api/devices")
async def devices():
    """
    /devices - GET - returns all devices
    """
    out = []
    for i in range(1, 10):
        d = Device(id=i, name=f'device{i}', ip=f'10.10.10.{i}', type='Cisco' if i % 2 else 'Ubiquiti', aggregator_id=1 if i < 6 else 2, timeout=10)
        out.append(d.serialize())
    return {"devices": out}


@app.post("/api/devices")
async def add_devices(device: Device):
    """
    /devices - POST - add a new device and return device
    """
    device.id = device.get_id()
    return {"devices": device.serialize()}


@app.get("/api/devices/{id}")
async def devices_id(id: int):
    """
    /devices/{id} - GET - returns devices with id
    """
    d = Device(id=id, name=f'device{id}', ip=f'10.10.10.{id}', type='Cisco' if id % 2 else 'Ubiquiti', aggregator_id=1 if id < 6 else 2, timeout=10)
    return {"device": d.serialize()}


@app.get("/api/devices/{id}/data/{senor}")
async def devices_id_sensor(id: int, sensor: str):
    """
    /devices/{id}/data/{senor} - GET -  returns data from sensor and device
    """
    out = {}
    d = Device(id=id, name=f'device{id}', ip=f'10.10.10.{id}', type='Cisco' if id % 2 else 'Ubiquiti', aggregator_id=1 if id < 6 else 2, timeout=10)
    out["device"] = d.serialize()
    data = {}
    t = time.time()
    for i in range(100):
        data[(t+i)] = randint(10, 20)
    out[sensor] = data
    return out


@app.post("/api/devices/data")
async def devices_data(request: Request):
    """
    /devices/data - POST - aggregator sends JSON to API
    """
    try:
        data = await request.json()
        print(data)
        out = 'success'
    except:
        out = 'failed'
    return {"data": out}
