from fastapi import FastAPI, Body, Depends, Request
import json
from models import Device
from app.auth.auth_bearer import JWTBearer
from app.auth.auth_handler import sign_jwt
from decouple import config


app = FastAPI()


@app.get("/", dependencies=[Depends(JWTBearer())])
async def read_root() -> dict:
    return {"message": "Welcome to Auth."}


@app.post("/login")
async def login_user(req: Request):
    json_body = await req.json()
    json_body['pw'] = config("pw")
    return sign_jwt(json_body['id'])


@app.get("/api/frontend/devices", dependencies=[Depends(JWTBearer())])
async def get_all_devices():
    """
    /devices - GET - get all devices for the frontend
    """
    devices = []
    for i in range(1, 10):
        d = Device(
            id=i,
            name=f'demoDevice{i}',
            ip=f'1.1.1.{i}',
            type='Cisco' if i % 2 else 'Ubi',
            aggregator_id=i,
            timeout=i)
        devices.append(d.serialize())
    return {"devices": devices}

