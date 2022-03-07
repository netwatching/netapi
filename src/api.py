import os
import sys

import json
import sqlalchemy.exc
import inspect
import re
from fastapi.routing import APIRoute
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi_jwt_auth.exceptions import AuthJWTException
from starlette.middleware.cors import CORSMiddleware
from src.models.models import oldDevice, User, Settings, ServiceLoginOut, ServiceAggregatorLoginOut, ServiceLogin, \
    ServiceAggregatorLogin, AddAggregatorIn, AddAggregatorOut, APIStatus, DeviceById, GetAllDevices, AggregatorByID, \
    AddDataForDevices, RedisData, AggregatorVersionIn, AggregatorVersionOut, AggregatorModulesIn, AggregatorModulesOut
from fastapi_jwt_auth import AuthJWT
from decouple import config
from typing import Optional
import datetime
import humanize
import pymongo.errors
from bson import ObjectId

from src.dbio import DBIO
from src.mongoDBIO import MongoDBIO

# only for test
from random import randint
import time

BAD_PARAM = "Bad Parameter"

start_time = datetime.datetime.now()
version = "DEV"

app = FastAPI()
#try:
#    db = DBIO(
#        db_path=f'mysql+pymysql://{config("DBuser")}:{config("DBpassword")}@{config("DBurl")}:{config("DBport")}/{config("DBdatabase")}')
#except mysql.connector.errors.DatabaseError:
#    sys.exit("No Database Connection...\nexiting...")

# Note: Better logging if needed
# logging.config.fileConfig('loggingx.conf', disable_existing_loggers=False)
# app.add_middleware(RouteLoggerMiddleware)

mongo = MongoDBIO(
    details=f'mongodb://{config("mDBuser")}:{config("mDBpassword")}@{config("mDBurl")}:{config("mDBport")}/{config("mDBdatabase")}?authSource=admin')

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
        title="NetAPI",
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

            if (
                    re.search("jwt_required", inspect.getsource(endpoint)) or
                    re.search("fresh_jwt_required", inspect.getsource(endpoint)) or
                    re.search("jwt_optional", inspect.getsource(endpoint))
            ):
                openapi_schema["paths"][path][method].update({
                    'security': [{"AccessToken": []}]
                })

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


@app.get("/",
         summary="Check service status",
         response_model=APIStatus)
async def root() -> APIStatus:
    time_delta = datetime.datetime.now() - start_time
    output_time = humanize.naturaldelta(time_delta)
    return APIStatus(version=version, uptime=output_time)


# --- AUTHENTICATION--- #

@app.post('/api/login', response_model=ServiceLoginOut)
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
        refresh_token = authorize.create_refresh_token(subject=uid, headers={"name": name}, expires_time=expires)
        return ServiceLoginOut(access_token=access_token, refresh_token=refresh_token)


@app.post('/api/refresh', response_model=ServiceLoginOut)
async def refresh(authorize: AuthJWT = Depends()):
    """
    /refresh - POST - renew expired access token
    """
    authorize.jwt_refresh_token_required()
    name = authorize.get_unverified_jwt_headers()["name"]

    current_user = authorize.get_jwt_subject()
    expires = datetime.timedelta(minutes=10)
    access_token = authorize.create_access_token(
        subject=current_user,
        headers={"name": name},
        expires_time=expires
    )
    expires = datetime.timedelta(minutes=20)
    refresh_token = authorize.create_refresh_token(subject=current_user, headers={"name": name}, expires_time=expires)
    return ServiceLoginOut(access_token=access_token, refresh_token=refresh_token)


@app.post("/api/aggregator-login", response_model=ServiceAggregatorLoginOut)
async def aggregator_login(request: ServiceAggregatorLogin, authorize: AuthJWT = Depends()):
    """
    /aggregator-login - POST - aggregator login with token
    """
    try:
        token = request.token
    except KeyError:
        raise HTTPException(status_code=400, detail=BAD_PARAM)

    exists = mongo.check_token(token)

    if exists:
        aggregator_id = str(exists.pk)

        expires = datetime.timedelta(minutes=10)
        access_token = authorize.create_access_token(subject=aggregator_id, expires_time=expires)
        expires = datetime.timedelta(hours=1)
        refresh_token = authorize.create_refresh_token(subject=aggregator_id, expires_time=expires)
        return ServiceAggregatorLoginOut(
            aggregator_id=aggregator_id,
            access_token=access_token,
            refresh_token=refresh_token
        )
    raise HTTPException(status_code=401, detail="Unauthorized")

@app.post("/api/aggregator-refresh", response_model=ServiceLoginOut)
async def aggregator_login(authorize: AuthJWT = Depends()):
    """
    /aggregator-login - POST - aggregator login with token
    """
    authorize.jwt_refresh_token_required()

    current_user = authorize.get_jwt_subject()
    expires = datetime.timedelta(minutes=10)
    access_token = authorize.create_access_token(
        subject=current_user,
        expires_time=expires
    )
    expires = datetime.timedelta(hours=1)
    refresh_token = authorize.create_refresh_token(subject=current_user, expires_time=expires)
    return ServiceLoginOut(access_token=access_token, refresh_token=refresh_token)

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


@app.get("/api/aggregator/{id}", response_model=AggregatorByID)
async def get_aggregator_by_id(id: str = "", authorize: AuthJWT = Depends()):
    """
    /aggregator/{id} - GET - returns devices belonging to the aggregator
    """
    authorize.jwt_required()

    if id == "":
        raise HTTPException(status_code=400, detail=BAD_PARAM)

    id = ObjectId(id)

    db_result = mongo.get_aggregator_devices(id)
    return db_result


@app.post("/api/aggregator/{id}/version", response_model=AggregatorVersionOut)
async def get_aggregator_version_by_id(request: AggregatorVersionIn, id: str = "", authorize: AuthJWT = Depends()):
    """
    /aggregator/{id}/version - POST - set version of the aggregator
    """
    authorize.jwt_required()
    if id != "":
        try:
            ver = request.version
        except KeyError:
            raise HTTPException(status_code=400, detail=BAD_PARAM)

        mongo.set_aggregator_version(id, ver)
        return AggregatorVersionOut(detail="Updated")
    raise HTTPException(status_code=400, detail=BAD_PARAM)


@app.post("/api/aggregator/{id}/modules", response_model=AggregatorModulesOut)
async def aggregator_modules(request: AggregatorModulesIn, id: str = "", authorize: AuthJWT = Depends()):
    """
    /aggregator/{id}/modules - POST - aggregator sends all known modules
    """
    authorize.jwt_required()

    if id != "":
        try:
            modules = request.modules
        except KeyError:
            raise HTTPException(status_code=400, detail="Bad Parameter")
        mongo.insert_aggregator_modules(modules, id)
        return AggregatorModulesOut(detail="Inserted")
    raise HTTPException(status_code=400, detail=BAD_PARAM)


# --- DEVICES --- #
@app.get("/api/devices")
async def get_all_devices(request: GetAllDevices, authorize: AuthJWT = Depends()):
    """
    /devices - GET - get all devices in a base version for the frontend
    """

    authorize.jwt_required()

    category = request.category
    page = request.page
    amount = request.amount

    devices = mongo.get_device_by_category(category=category, page=page, amount=amount)
    if devices == -1 or devices is False:
        raise HTTPException(status_code=400, detail="Error occurred")

    return JSONResponse(status_code=200, content=json.dumps(devices))


@app.get("/api/devices/{id}")  # TODO: rewrite
async def device_by_id(request: DeviceById, authorize: AuthJWT = Depends()):
    """
    /devices/{id} - GET - returns device infos with specified id
    """
    authorize.jwt_required()

    device = mongo.get_device_by_id(DeviceById.id)
    return JSONResponse(status_code=200, content=json.dumps(device))


@app.post("/api/devices/data")  # TODO: rewrite
async def devices_data(request: AddDataForDevices, authorize: AuthJWT = Depends()):
    """
    /devices/data - POST - aggregator sends data which is saved in the Database
    """
    authorize.jwt_required()

    success = mongo.add_data_for_devices(data=request.data)
    if (isinstance(success, bool) is False and success is False) or (isinstance(success, int) and success == -1):
        raise HTTPException(status_code=400, detail="Error occurred")

@app.get("/api/devices/{did}/alerts")  # TODO: rewrite
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


@app.post("/api/devices")  # TODO: rewrite
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


# --- Category --- #
@app.get("/api/categories")  # TODO: rewrite
async def get_all_categories(authorize: AuthJWT = Depends()):
    """
    /categories - GET - get all available categories
    """
    authorize.jwt_required()

    return db.get_categories()


@app.post("/api/categories")  # TODO: rewrite
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
@app.get("/api/alerts")  # TODO: rewrite
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


@app.get("/api/alerts/{aid}")  # TODO: rewrite
async def get_alert_by_id(aid: int, authorize: AuthJWT = Depends()):
    """
    /alerts/{aid} - GET - get specific alert by id
    """
    authorize.jwt_required()

    return db.get_alerts_by_id(aid)


# --- Modules --- #
@app.get("/api/modules")  # TODO: rewrite
async def get_all_modules(authorize: AuthJWT = Depends()):
    """
    /modules - GET - get all modules
    """
    authorize.jwt_required()

    return db.get_modules()


# --- Redis --- #
@app.post("/api/redis")  # TODO: rewrite @Tobi
# async def redis(request: Request):
async def redis(request: RedisData, authorize: AuthJWT = Depends()):
    """
    /redis - POST - aggregator sends all live-data variables
    """
    authorize.jwt_required()

    mongo.redis_insert_live_data(request)
    return JSONResponse(
        status_code=200,
        content={"detail": "Inserted"}
    )

# --- Exception Handling --- #
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )
