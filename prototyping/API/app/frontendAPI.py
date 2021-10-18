from fastapi import FastAPI, Body, Depends, Request
import json
from app.model import PostSchema
from app.auth.auth_bearer import JWTBearer
from app.auth.auth_handler import sign_jwt


app = FastAPI()


@app.get("/", dependencies=[Depends(JWTBearer())])
async def read_root() -> dict:
    return {"message": "Welcome to Auth."}

@app.post("/login")
async def login_user(req: Request):
    json_body = await req.json()
    return sign_jwt(json_body['id'])