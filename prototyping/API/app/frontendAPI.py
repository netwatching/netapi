from fastapi import FastAPI, Body

from app.model import PostSchema
from app.auth.auth_handler import signJWT

app = FastAPI()


@app.get("/", tags=["root"])
async def read_root() -> dict:
    return {"message": "Welcome to Auth."}