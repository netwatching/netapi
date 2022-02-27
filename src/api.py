import os
import sys

import mysql
import json
import sqlalchemy.exc
import inspect
import re
from fastapi.routing import APIRoute
import uvicorn as uvicorn
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi_jwt_auth.exceptions import AuthJWTException
from starlette.middleware.cors import CORSMiddleware
from src.models.models import oldDevice, User, Settings, ServiceLoginOut, ServiceAggregatorLoginOut, ServiceLogin, \
    ServiceAggregatorLogin, AddAggregatorIn, AddAggregatorOut
from fastapi_jwt_auth import AuthJWT
from decouple import config
from typing import Optional
import datetime
from fastapi_route_logger_middleware import RouteLoggerMiddleware
import pymongo.errors

from src.dbio import DBIO
from src.mongoDBIO import MongoDBIO

# only for test
from random import randint
import time

BAD_PARAM = "Bad Parameter"

app = FastAPI()
try:
    db = DBIO(
        db_path=f'mysql+pymysql://{config("DBuser")}:{config("DBpassword")}@{config("DBurl")}:{config("DBport")}/{config("DBdatabase")}')
except mysql.connector.errors.DatabaseError:
    sys.exit("No Database Connection...\nexiting...")

# Note: Better logging if needed
# logging.config.fileConfig('loggingx.conf', disable_existing_loggers=False)
# app.add_middleware(RouteLoggerMiddleware)
mongo = MongoDBIO(
    details="mongodb://netwatch:jfMCDp9dzZrTxytB6zSrtEjkqXcrmvPKrnXttTFj383u8UFmN3AqY9XdPw7H@palguin.htl-vil.local:27017/netdb?authSource=admin")

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


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="OrderService",
        version="DEV",
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }

    cookie_security_schemes = {
        "AccessToken": {
            "type": "http",
            "scheme": "bearer",
            "in": "header",
            "name": "Authorization"
        },
        "RefreshToken": {
            "type": "http",
            "scheme": "bearer",
            "in": "header",
            "name": "Authorization"
        }
    }

    if "components" in openapi_schema:
        openapi_schema["components"].update({"securitySchemes": cookie_security_schemes})
    else:
        openapi_schema["components"] = {"securitySchemes": cookie_security_schemes}

    api_router = [route for route in app.routes if isinstance(route, APIRoute)]

    for route in api_router:
        path = getattr(route, "path")
        endpoint = getattr(route, "endpoint")
        methods = [method.lower() for method in getattr(route, "methods")]

        for method in methods:
            # access_token
            if (
                    re.search("jwt_required", inspect.getsource(endpoint)) or
                    re.search("fresh_jwt_required", inspect.getsource(endpoint)) or
                    re.search("jwt_optional", inspect.getsource(endpoint))
            ):
                openapi_schema["paths"][path][method].update({
                    'security': [{"AccessToken": []}]
                })

            # refresh_token
            if re.search("jwt_refresh_token_required", inspect.getsource(endpoint)):
                openapi_schema["paths"][path][method].update({
                    'security': [{"RefreshToken": []}]
                })

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


@AuthJWT.load_config
def get_config():
    return Settings()


@app.get("/")
async def test() -> dict:
    """
    / - GET - Testing Endpoint to verify API connectivity
    """
    return {"NetAPI": "hello"}


# --- AUTHENTICATION--- #

@app.post('/api/login')
async def login(req: ServiceLogin, authorize: AuthJWT = Depends()):
    """
    /login - POST - authenticates frontend User and returns JWT
    """
    try:
        pw = req.password
        uid = req.id
        name = req.name
    except KeyError:
        raise HTTPException(status_code=400, detail=BAD_PARAM)

    if pw != config("pw"):
        raise HTTPException(status_code=401, detail="Unauthorized")
    else:
        expires = datetime.timedelta(minutes=10)
        access_token = authorize.create_access_token(
            subject=uid,
            headers={"name": name},
            expires_time=expires
        )
        expires = datetime.timedelta(minutes=20)
        refresh_token = authorize.create_refresh_token(subject=uid, expires_time=expires)
        return ServiceLoginOut(access_token=access_token, refresh_token=refresh_token)


@app.post('/api/refresh')
async def refresh(authorize: AuthJWT = Depends()):
    """
    /refresh - POST - renew expired access token
    """
    authorize.jwt_refresh_token_required()

    current_user = authorize.get_jwt_subject()
    expires = datetime.timedelta(minutes=10)
    access_token = authorize.create_access_token(
        subject=current_user,
        # headers={"name": name},
        expires_time=expires
    )
    expires = datetime.timedelta(minutes=20)
    refresh_token = authorize.create_refresh_token(subject=current_user, expires_time=expires)
    return ServiceLoginOut(access_token=access_token, refresh_token=refresh_token)


@app.post("/api/aggregator-login")
async def aggregator_login(request: ServiceAggregatorLogin, authorize: AuthJWT = Depends()):
    """
    /aggregator-login - POST - aggregator login with token
    """
    try:
        token = request.token
    except KeyError:
        raise HTTPException(status_code=400, detail=BAD_PARAM)

    exists = db.check_token(token)

    if exists:
        aggregator_id = exists.pk
        expires = datetime.timedelta(minutes=10)
        access_token = authorize.create_access_token(subject=aggregator_id, expires_time=expires)
        expires = datetime.timedelta(minutes=20)
        refresh_token = authorize.create_refresh_token(subject=aggregator_id, expires_time=expires)
        return ServiceAggregatorLoginOut(
            aggregator_id=aggregator_id,
            access_token=access_token,
            refresh_token=refresh_token
        )
    raise HTTPException(status_code=401, detail="Unauthorized")


# --- AGGREGATOR --- #
@app.post("/api/aggregator", status_code=201, response_model=AddAggregatorOut)
async def add_aggregator(request: AddAggregatorIn, authorize: AuthJWT = Depends()):
    """
        /aggregator - POST - webinterface can add a new token for a new aggregator
        """
    authorize.jwt_required()

    try:
        token = request.token
    except KeyError:
        raise HTTPException(status_code=400, detail=BAD_PARAM)

    try:
        mongo.add_aggregator(token)
    except pymongo.errors.DuplicateKeyError:
        raise HTTPException(status_code=400, detail="Already exists")

    return JSONResponse(status_code=201, content={"detail": "Created"})


@app.get("/api/aggregator/{id}") # TODO: rewrite
async def get_aggregator_by_id(id: str = "", authorize: AuthJWT = Depends()):
    """
    /aggregator/{id} - GET - returns devices belonging to the aggregator
    """
    authorize.jwt_required()

    if id == "":
        raise HTTPException(status_code=400, detail=BAD_PARAM)

    db = mongo.get_aggregator_devices(id)
    json_string = json.dumps(db)
    return json_string


@app.post("/api/aggregator/{id}/version") # TODO: rewrite
async def get_aggregator_version_by_id(id: int, request: Request, authorize: AuthJWT = Depends()):
    """
    /aggregator/{id}/version - POST - set version of the aggregator
    """
    authorize.jwt_required()
    if id:
        jsondata = await request.json()
        try:
            ver = jsondata['version']
        except KeyError:
            raise HTTPException(status_code=400, detail=BAD_PARAM)

        db.set_aggregator_version(id, ver)
        return {"detail": "updated"}
    raise HTTPException(status_code=400, detail=BAD_PARAM)


@app.post("/api/aggregator/{id}/modules") # TODO: rewrite
async def aggregator_modules(id: int, request: Request, authorize: AuthJWT = Depends()):
    """
    /aggregator/{id}/modules - POST - aggregator sends all known modules
    """
    authorize.jwt_required()

    if id:
        jsondata = await request.json()

        db.insert_aggregator_modules(jsondata, id)
        return JSONResponse(
            status_code=200,
            content={"detail": "Inserted"}
        )
    raise HTTPException(status_code=400, detail=BAD_PARAM)


# --- DEVICES --- #
@app.get("/api/devices") # TODO: rewrite
async def get_all_devices(
        category: Optional[str] = None,
        page: Optional[int] = None,
        amount: Optional[int] = None,
        authorize: AuthJWT = Depends()):
    """
    /devices - GET - get all devices in a base version for the frontend
    """
    authorize.jwt_required()

    out = {}

    out["page"] = page
    out["amount"] = amount

    if category:
        cats = category.split('_')
        data = db.get_devices_by_categories(cats, page, amount)
    else:
        data = db.get_devices(page, amount)

    out["total"] = data[1]
    out["devices"] = data[0]
    return out


@app.get("/api/devices/{id}") # TODO: rewrite
async def device_by_id(id: int, authorize: AuthJWT = Depends()):
    """
    /devices/{id} - GET - returns device infos with specified id
    """
    authorize.jwt_required()

    if id is not None:
        device = db.get_device_by_id(id)

    return device[0]


# ------------------- DISCARD ----------------------
# @app.get("/api/devices/{id}/features")
# async def device_features_by_id(id: int, authorize: AuthJWT = Depends()):
#     """
#     /devices/{id} - GET - returns device features with id
#     """
#     authorize.jwt_required()
#
#     if id is not None:
#         out = {}
#         dic = {}
#         ifs = []
#         ips = []
#         features = db.get_device_features_by_id(id)
#
#         for f in features:
#             for val_s in f.value_strings:
#                 if val_s is not None:
#                     dic[val_s.key] = val_s.value
#             for val_n in f.value_numerics:
#                 if val_n is not None:
#                     dic[val_n.key] = val_n.value
#
#             if "interfaces;" in f.feature:
#                 ifs.append(dic)
#             elif "ipAddresses;" in f.feature:
#                 ips.append(dic)
#             else:
#                 out[f.feature] = dic
#             dic = {}
#
#         out["interfaces"] = ifs
#         out["ipAddresses"] = ips
#
#     return out

@app.post("/api/devices/data") # TODO: rewrite
async def devices_data(request: Request, authorize: AuthJWT = Depends()):
    """
    /devices/data - POST - aggregator sends data which is saved in the Database
    """
    global cursor
    authorize.jwt_required()
    try:
        jsondata = await request.json()
        cursor = db.connection.cursor()
        try:
            devices = jsondata['devices']
            events = jsondata['external_events']
        except KeyError:
            raise HTTPException(status_code=400, detail=BAD_PARAM)

        for item in devices:
            device_id = item['id']
            for sd in item['static_data']:
                identifier = f";{sd['identifier']}" if sd['identifier'] is not None else ''
                feature = f"{sd['key']}{identifier}"
                values = sd['value']
                for key in values:
                    value = values[key]
                    if isinstance(value, str):
                        db.add_value_string(cursor=cursor, device_id=device_id, feature_name=feature, key=key,
                                            value=value)
                    else:
                        db.add_value_numeric(cursor=cursor, device_id=device_id, feature_name=feature, key=key,
                                             value=value)
        for event_host in events:
            event_values = events[event_host]
            for event in event_values:
                event_timestamp = datetime \
                    .datetime \
                    .fromtimestamp(int(event['timestamp'])) \
                    .strftime("%Y-%m-%d %H:%M:%S")
                event_severity = event['severity']
                event_problem = event['data']
                db.add_event(cursor=cursor,
                             timestamp=event_timestamp,
                             severity=event_severity,
                             problem=event_problem,
                             hostname=event_host)
        db.connection.commit()
        out = JSONResponse(status_code=200, content={"detail": "success"})
    except BaseException as e:
        print(e)
        out = JSONResponse(status_code=200, content={"detail": "failed"})
    cursor.close()
    return out


@app.get("/api/devices/{did}/alerts") # TODO: rewrite
async def get_alerts_by_device(
        did: int,
        minSeverity: Optional[int] = 0,
        severity: Optional[str] = None,
        page: Optional[int] = None,
        amount: Optional[int] = None,
        authorize: AuthJWT = Depends()
):
    """
    /devices/{did}/alerts - GET - get all alerts by device id
    """
    authorize.jwt_required()

    out = {}

    out["page"] = page
    out["amount"] = amount

    if severity:
        sevs = severity.split('_')
        data = db.get_alerts_by_device_id_and_severity_time(did, sevs, page, amount)
    else:
        data = db.get_alerts_by_device_id(did, minSeverity, page, amount)

    out["total"] = data[1]
    out["alerts"] = data[0]
    return out


@app.post("/api/devices") # TODO: rewrite
async def add_device(request: Request, authorize: AuthJWT = Depends()):
    """
    /devices/add - GET - adds a new device to the DB
    """
    authorize.jwt_required()

    data = await request.json()

    if data.get('device') is not None and data.get('category') is not None:
        try:
            db.add_device(data['device'], data['category'], data['ip'])
        except sqlalchemy.exc.IntegrityError:
            raise HTTPException(status_code=400, detail="already exists")
        return {"status": "success"}

    raise HTTPException(status_code=400, detail=BAD_PARAM)


# --- Features --- #
# ------------------- DISCARD ----------------------
# @app.get("/api/features")
# async def get_all_features(authorize: AuthJWT = Depends()):
#     """
#     /features - GET - get all available features
#     """
#     authorize.jwt_required()
#
#     features = db.get_features()
#     json = []
#     out = []
#
#     for f in features:
#         json.append({"id": f.id, "feature": f.feature, "device_id": f.device_id})
#
#     for o in json:
#         if ";" in o["feature"]:
#             x = o["feature"].split(";")
#             o["feature"] = x[0]
#             o["number"] = x[1]
#             out.append(o)
#         else:
#             out.append(o)
#
#     return out


# --- Category --- #
@app.get("/api/categories") # TODO: rewrite
async def get_all_categories(authorize: AuthJWT = Depends()):
    """
    /categories - GET - get all available categories
    """
    authorize.jwt_required()

    return db.get_categories()


@app.post("/api/categories") # TODO: rewrite
async def add_categories(request: Request, authorize: AuthJWT = Depends()):
    """
    /categories - POST - add a new Category to the DB
    """
    authorize.jwt_required()

    data = await request.json()

    if data.get('category') is not None:
        try:
            db.add_category(data['category'])
        except sqlalchemy.exc.IntegrityError:
            raise HTTPException(status_code=400, detail="already exists")
        return {"status": "success"}

    raise HTTPException(status_code=400, detail=BAD_PARAM)


# --- Alerts --- #
@app.get("/api/alerts") # TODO: rewrite
async def get_all_alerts(
        minSeverity: Optional[int] = 0,
        severity: Optional[str] = None,
        page: Optional[int] = None,
        amount: Optional[int] = None,
        authorize: AuthJWT = Depends()
):
    """
    /alerts - GET - get all alerts
    """
    authorize.jwt_required()

    out = {}

    out["page"] = page
    out["amount"] = amount

    if severity:
        sevs = severity.split('_')
        data = db.get_alerts_by_severity_type(sevs, page, amount)
    else:
        data = db.get_alerts_by_severity(minSeverity, page, amount)

    out["total"] = data[1]
    out["alerts"] = data[0]
    return out


@app.get("/api/alerts/{aid}") # TODO: rewrite
async def get_alert_by_id(aid: int, authorize: AuthJWT = Depends()):
    """
    /alerts/{aid} - GET - get specific alert by id
    """
    authorize.jwt_required()

    return db.get_alerts_by_id(aid)


# --- Modules --- #
@app.get("/api/modules") # TODO: rewrite
async def get_all_modules(authorize: AuthJWT = Depends()):
    """
    /modules - GET - get all modules
    """
    authorize.jwt_required()

    return db.get_modules()


# --- Redis --- #
@app.post("/api/redis") # TODO: rewrite @Tobi
# async def redis(request: Request):
async def redis(request: Request, authorize: AuthJWT = Depends()):
    """
    /redis - POST - aggregator sends all live-data variables
    """
    authorize.jwt_required()

    jsondata = await request.json()

    db.redis_insert_live_data(jsondata)
    return JSONResponse(
        status_code=200,
        content={"detail": "Inserted"}
    )

    # {
    #     "device": "TESTING",
    #     "data": {
    #         "in_bytes": {
    #             "2022-01-23 21:00:00": "2000"
    #         }
    #     }
    # }


# --- Exception Handling --- #
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )
