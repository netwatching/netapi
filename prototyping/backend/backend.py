from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class Heartbeat(BaseModel):
    timestamp: str


@app.post('/heartbeat')
async def heartbeat(heartbeat: Heartbeat):
    out = {
        'timestamp': heartbeat.timestamp
    }
    return out


@app.get('/devices')
async def devices():
    out = {
        'id-1': {
            'ip': '10.10.10.10',
            'name': 'test_switch_1',
            'type': 'switch'
        },
        'id-2': {
            'ip': '10.10.10.23',
            'name': 'test_switch_2',
            'type': 'switch'
        },
        'id-3': {
            'ip': '10.10.12.56',
            'name': 'test_pc_1',
            'type': 'pc'
        },
        'id-4': {
            'ip': '10.10.1.1',
            'name': 'test_router_1',
            'type': 'router'
        },

    }
    return out


@app.get("/devices/{id}")
async def devices_agr(id):
    out = {
        'id-1': {
            'ip': '10.10.10.10',
            'name': 'test_switch_1',
            'type': 'switch'
        },
        'id-2': {
            'ip': '10.10.10.23',
            'name': 'test_switch_2',
            'type': 'switch'
        },
        "id": id
    }
    return out
