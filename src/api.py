from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi_jwt_auth.exceptions import AuthJWTException
from starlette.middleware.cors import CORSMiddleware
from src.models import oldDevice, User, Settings
from fastapi_jwt_auth import AuthJWT
from decouple import config
import json
import datetime

from src.dbio import DBIO

# only for test
from random import randint
import time

app = FastAPI()
db = DBIO(db_path='mysql+pymysql://netdb:NPlyaVeGq5rse715JvD6@palguin.htl-vil.local:3306/netdb')

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


# --- AUTHENTICATION--- #

@app.post('/api/login')
async def login(req: Request, authorize: AuthJWT = Depends()):
    """
    /login - POST - authenticates frontend User and returns JWT
    """
    json_body = await req.json()
    if json_body['pw'] != config("pw"):
        raise HTTPException(status_code=401, detail="Unauthorized")

    expires = datetime.timedelta(days=1)
    access_token = authorize.create_access_token(
        subject=json_body['id'],
        headers={"name": json_body['name']},
        expires_time=expires
    )
    refresh_token = authorize.create_refresh_token(subject=json_body['id'], expires_time=False)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }


@app.post('/api/refresh')
async def refresh(authorize: AuthJWT = Depends()):
    """
    /refresh - POST - expired access token can be renewed
    """
    authorize.jwt_refresh_token_required()

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


# --- AGGREGATOR --- #

@app.get("/api/aggregator/{id}")
async def aggregator(id: int, authorize: AuthJWT = Depends()):
    """
    /aggregator/{id} - GET - returns devices belonging to the aggregator
    """
    authorize.jwt_required()
    out = []
    if id > 0:
        d = oldDevice(id=1, name=f'Zabbi', ip=f'zabbix.htl-vil.local', type='Zabbi', aggregator_id=id, timeout=10, module_name=['problems', 'events'])
        out.append(d.serialize())
        d = oldDevice(id=2, name=f'Ubi', ip=f'172.31.37.95', type='Ubiquiti', aggregator_id=id, timeout=10, module_name=['snmp'])
        out.append(d.serialize())
    return out


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
    authorize.jwt_required()
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


# --- DEVICES --- #

@app.get("/api/devices/full")
async def get_all_devices(authorize: AuthJWT = Depends()):
    """
    /devices - GET - get all devices and what belongs to it for the frontend
    """
    authorize.jwt_required()

    return db.get_full_devices()


@app.get("/api/devices")
async def get_all_devices(authorize: AuthJWT = Depends()):
    """
    /devices - GET - get all devices in a base version for the frontend
    """
    authorize.jwt_required()

    return db.get_devices()


@app.get("/api/devices/{id}")
async def device_by_id(id: int, authorize: AuthJWT = Depends()):
    """
    /devices/{id} - GET - returns devices with specified id
    """
    authorize.jwt_required()

    if id is not None:
        device = db.get_device_by_id(id)

    return device[0]


@app.get("/api/devices/{id}/features")
async def device_features_by_id(id: int, authorize: AuthJWT = Depends()):
    """
    /devices/{id} - GET - returns devices with id
    """
    authorize.jwt_required()

    if id is not None:
        out = {}
        dic = {}
        ifs = []
        ips = []
        features = db.get_device_features_by_id(id)

        for f in features:
            for val_s in f.value_strings:
                dic[val_s.key] = val_s.value
            for val_n in f.value_numerics:
                dic[val_n.key] = val_n.value

            if "interfaces;" in f.feature:
                ifs.append(dic)
            elif "ipAddresses;" in f.feature:
                ips.append(dic)
            else:
                out[f.feature] = dic
            dic = {}

        out["interfaces"] = ifs
        out["ipAddresses"] = ips

    return out


@app.post("/api/devices")
async def add_devices(device: oldDevice, authorize: AuthJWT = Depends()):
    authorize.jwt_required()
    """
    /devices - POST - add a new device and return device
    """

    device.id = device.get_id()
    return {"devices": device.serialize()}


@app.get("/api/devices/{id}/data/{senor}")
async def devices_id_sensor(id: int, sensor: str, authorize: AuthJWT = Depends()):
    authorize.jwt_required()
    """
    /devices/{id}/data/{senor} - GET -  returns data from sensor and device
    """

    out = {}
    d = oldDevice(id=id, name=f'device{id}', ip=f'10.10.10.{id}', type='Cisco' if id % 2 else 'Ubiquiti',
                  aggregator_id=1 if id < 6 else 2, timeout=10)
    out["device"] = d.serialize()
    data = {}
    t = time.time()
    for i in range(100):
        data[(t + i)] = randint(10, 20)
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
        cursor = db.connection.cursor()

        for item in jsondata['devices']:
            id = item['id']
            name = item['name']
            for sd in item['static_data']:
                identifier = f";{sd['identifier']}" if sd['identifier'] is not None else ''
                feature = f"{sd['key']}{identifier}"
                values = sd['value']
                for key in values:
                    value = values[key]
                    if isinstance(value, str):
                        db.add_value_string(cursor=cursor, device_id=id, feature_name=feature, key=key, value=value)
                    else:
                        db.add_value_numeric(cursor=cursor, device_id=id, feature_name=feature, key=key, value=value)
            for event_host in jsondata['external_events']:
                event_values = jsondata['external_events'][event_host][0]
                event_timestamp = datetime.datetime.fromtimestamp(int(event_values['timestamp'])).strftime("%Y-%m-%d %H:%M:%S")
                event_severity = event_values['severity']
                event_problem = event_values['problem']
                db.add_event(cursor=cursor, timestamp=event_timestamp, severity=event_severity, problem=event_problem, hostname=event_host)

            cursor.close()
            db.connection.commit()
        out = {"data": "success"}
    except BaseException as e:
        print(e)
        out = {"data": "failed"}
    return out


# --- Features --- #

@app.get("/api/features")
async def get_all_features(authorize: AuthJWT = Depends()):
    """
    /features - GET - get all available features
    """
    authorize.jwt_required()

    features = db.get_features()
    json = []
    out = []

    for f in features:
        json.append({"id": f.id, "feature": f.feature, "device_id": f.device_id})

    for o in json:
        if ";" in o["feature"]:
            x = o["feature"].split(";")
            o["feature"] = x[0]
            o["number"] = x[1]
            out.append(o)
        else:
            out.append(o)

    return out


# --- Category --- #

@app.get("/api/categories")
async def get_all_categories(authorize: AuthJWT = Depends()):
    """
    /categories - GET - get all available categories
    """
    authorize.jwt_required()

    return db.get_categories()


# --- Alerts --- #

@app.get("/api/alerts")
async def get_all_alerts(authorize: AuthJWT = Depends()):
    """
    /categories - GET - get all alerts
    """
    authorize.jwt_required()

    return db.get_alerts()


@app.get("/api/alerts/{did}")
async def get_all_categories(did: int, authorize: AuthJWT = Depends()):
    """
    /categories - GET - get all alerts by device id
    """
    authorize.jwt_required()

    return db.get_alerts_by_id(did)


# --- Exception Handling --- #

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )
