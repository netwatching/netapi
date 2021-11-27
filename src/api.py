from fastapi import FastAPI, Depends, Request, HTTPException
from starlette.middleware.cors import CORSMiddleware
from src.models import Device, User, Settings
from fastapi_jwt_auth import AuthJWT
from decouple import config
import pymongo
import json

# only for test
from random import randint
import time

app = FastAPI()
db = pymongo.MongoClient("mongodb://root:testPassword1234@palguin.htl-vil.local:27017")

origins = [
    "http://localhost:4200",
    "http://palguin.htl-vil.local",
    "0.0.0.0",
    "localhost"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@AuthJWT.load_config
def get_config():
    return Settings()

@app.get("/")
async def root() -> dict:
    """
    / - GET - for API testing purposes only
    """
    return {"NetAPI": "hello"}


# --- LOGIN AND REFRESH---

@app.post('/api/login')
async def login(req: Request, authorize: AuthJWT = Depends()):
    """
    /login - POST - authenticates frontend User and returns JWT
    """
#    try:
    json_body = await req.json()
    if json_body['pw'] != config("pw") :
        raise HTTPException(status_code=401,detail="Unauthorized")
    access_token = authorize.create_access_token(subject=json_body['id'], headers={"name": json_body['name']})
    refresh_token = authorize.create_refresh_token(subject=json_body['id'], expires_time=9999999999)
    return {"access_token": access_token, "refresh_token": refresh_token}
#    except Exception as ex:
#        raise HTTPException(status_code=400, detail=ex)


@app.post('/api/refresh')
async def refresh(authorize: AuthJWT = Depends()):
    try:
        authorize.jwt_refresh_token_required()
    except authorize.exceptions.InvalidHeaderError:
        raise HTTPException(status_code=403, detail="Refresh missing")
    current_user = authorize.get_jwt_subject()
    new_access_token = authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}


@app.post("/api/aggregator-login")
async def aggregator_login(request: Request, authorize: AuthJWT = Depends()):
    """
    /aggregator-login - POST - aggregator sends token, gets token and aggregator-id returned
    """
    json_body = await request.json()
    token = json_body['token']
    if token == config("token"):
        aggregator_id = 1
        access_token = authorize.create_access_token(subject=aggregator_id)
        refresh_token = authorize.create_refresh_token(subject=aggregator_id)
        return {"token": access_token, "refresh_token": refresh_token, "aggregator_id": aggregator_id}
    return {""}


# --- AGGREGATOR ---
@app.get("/api/aggregator/{id}")
async def aggregator(id: int, authorize: AuthJWT = Depends()):
    """
    /aggregator/{id} - GET - returns devices belonging to the aggregator
    """

    out = []
    if id > 0:
        d = Device(id=1, name=f'zabbixServer', ip=f'zabbix.htl-vil.local', type='Zabbix', aggregator_id=id, timeout=10)
        out.append(d.serialize())
        d = Device(id=2, name=f'schulSwitch', ip=f'172.31.37.95', type='Ubiquiti', aggregator_id=id, timeout=10)
        out.append(d.serialize())
        d = Device(id=3, name=f'CISCO_HTL-R154-PoE-Access', ip=f'172.31.8.81', type='Cisco', aggregator_id=id, timeout=10)
        out.append(d.serialize())
    print(f'------------- {out}')
    return {"devices": out}


@app.post("/api/aggregator/{id}/version")
async def aggregator(id: int, request: Request, authorize: AuthJWT = Depends()):
    authorize.jwt_required()
    """
    /api/aggregator/{id}/version - POST - version of the aggregator
    """
    if id > 0:
        try:
            jsondata = await request.json()
            print(jsondata)
            out = {
                "data": "success",
                "data_sent": {json.dumps(jsondata)}
            }
        except BaseException as e:
            print(e)
            out = {"data": "failed"}
    else:
        out = {"data": "failed"}
    return out


@app.post("/api/aggregator/{id}/modules")
async def aggregator_modules(id: int, request: Request, authorize: AuthJWT = Depends()):
    """
    /aggregator/{id}/modules - POST - aggregator sends all known modules
    """

    if id > 0:
        try:
            jsondata = await request.json()
            print(jsondata)
            out = {
                "data": "success",
                "data_sent": {json.dumps(jsondata)}
            }
        except BaseException as e:
            print(e)
            out = {"data": "failed"}
    else:
        out = {"data": "failed"}
    return out


# --- DEVICES ---
@app.get("/api/devices")
async def get_all_devices(authorize: AuthJWT = Depends()):
    """
    /devices - GET - get all devices for the frontend
    """
    try:
        authorize.jwt_required()
    except:
        raise HTTPException(status_code=401, detail="Unauthorized")

    db_col = db["netdb"]["zabix"]
    devices = []

    for x in db_col.find({}, {"_id": 1, "name": 1, "timestamp": 1}):
        devices.append(x)

    return devices


@app.get("/api/devices/problems")
async def get_all_problems(authorize: AuthJWT = Depends()):
    """
    /devices/problems - GET - get all problems of the devices for the frontend
    """
    try:
        authorize.jwt_required()
    except:
        raise HTTPException(status_code=401, detail="Unauthorized")

    db_col = db["netdb"]["zabix"]
    devices = []

    for x in db_col.find({}, {"_id": 1, "problem": 1,}):
        x["device_id"] = x.pop('_id')
        devices.append(x)

    return devices


@app.post("/api/devices")
async def add_devices(device: Device, authorize: AuthJWT = Depends()):
    authorize.jwt_required()
    """
    /devices - POST - add a new device and return device
    """

    device.id = device.get_id()
    return {"devices": device.serialize()}


@app.get("/api/devices/{id}")
async def devices_id(id: int, authorize: AuthJWT = Depends()):
    authorize.jwt_required()
    """
    /devices/{id} - GET - returns devices with id
    """
    if id == 1:
        d = Device(id=1, name=f'zabbixServer', ip=f'zabbix.htl-vil.local', type='Zabbix', aggregator_id=id, timeout=10)
    elif id == 2:
        d = Device(id=2, name=f'schulSwitch', ip=f'172.31.37.95', type='Ubiquiti', aggregator_id=id, timeout=10)
    else:
        d = Device(id=id, name=f'demo', ip=f'10.10.10.10', type='Cisco', aggregator_id=id, timeout=10)

    return {"device": d.serialize()}


@app.get("/api/devices/{id}/data/{senor}")
async def devices_id_sensor(id: int, sensor: str, authorize: AuthJWT = Depends()):
    authorize.jwt_required()
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
async def devices_data(request: Request, authorize: AuthJWT = Depends()):
    authorize.jwt_required()
    """
    /devices/data - POST - aggregator sends JSON to API
    """
    try:
        jsondata = await request.json()
        data = jsondata['devices']
        for e in data:
            if e['type'] == "Zabbix":
                db_col = db["netdb"]["zabix"]
                for v in e['data'][0]['value']:
                    col = v
                    if 'id' in col:
                        col['_id'] = col['id']
                        col.pop("id")
                    if db_col.find({'_id': col['_id']}).count() > 0:
                        db_col.update_one({'_id': col['_id']}, {"$set": col})
                    else:
                        db_col.insert_one(col)

        out = {"data": "success"}
    except BaseException as e:
        print(e)
        out = {"data": "failed"}
    return out


