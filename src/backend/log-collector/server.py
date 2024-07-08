from fastapi import FastAPI
import time

log = FastAPI()

@log.get('/log')
async def add_log():
    time.sleep(15)
    return {"hello": "world"}
