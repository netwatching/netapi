from fastapi import FastAPI, Body, Depends, Request
import json
from app.models import Device
from app.auth.auth_bearer import JWTBearer
from app.auth.auth_handler import sign_jwt
from decouple import config
import pymongo


app = FastAPI()
db = pymongo.MongoClient("mongodb://root:testPassword1234@palguin.htl-vil.local:27017")


@app.get("/", dependencies=[Depends(JWTBearer())])
async def read_root() -> dict:
    """
    / - GET - for API testing purposes only
    """
    return {"message": "Welcome to Auth."}


@app.post("/api/frontend/login")
async def login_user(req: Request):
    """
    /login - POST - authenticates frontend User and returns JWT
    """
    json_body = await req.json()
    json_body['pw'] = config("pw")
    return sign_jwt(json_body['id'])


@app.get("/api/frontend/devices", dependencies=[Depends(JWTBearer())])
async def get_all_devices():
    """
    /devices - GET - get all devices for the frontend
    """
    db_col = db["zabix"]["devices"]
    devices = []

    for x in db_col.find({}, {"_id": 1, "name": 1, "timestamp": 1}):
        devices.append(x)

    return devices

@app.get("/api/frontend/devices/problems", dependencies=[Depends(JWTBearer())])
async def get_all_problems():
    """
    /devices/problems - GET - get all problems of the devices for the frontend
    """
    db_col = db["zabix"]["devices"]
    devices = []

    for x in db_col.find({}, {"_id": 1, "problem": 1,}):
        x["device_id"] = x.pop('_id')
        devices.append(x)

    return devices

