import logging
import os
import sys
from time import sleep

import redis as r
import uvicorn
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response

import vars
from models import Creds, Arbor
from processors import ProcessError, ProcessHook, ProcessProxy, ProcessUpdate, ProcessDDoS
from utils import load_datafiles

app = FastAPI(title="Arbor Webhooks Listener")
redis = r.Redis(host='webhooks-redis', port=6379)

logging.basicConfig(level=vars.LOG_LEVEL)

parentDir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
creds = Creds.parse_file(f'{parentDir}/app/{vars.DATA_DIR}/{vars.CREDS_FILENAME}')
kwargs = load_datafiles(parentDir)


# Exception handler for RequestValidationError
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_, exc: RequestValidationError) -> Response:
    await ProcessError(exc, creds)
    return Response(status_code=202)


@app.post("/arbors/{arborType}/webhooks")
async def HookProcessor(arborType: str, hook: Arbor.Response, request: Request, background_tasks: BackgroundTasks) -> Response:
    hook.arborType = arborType

    match hook.arborType:
        case 'ix' | 'ipt':
            hook.response = await request.json()
            background_tasks.add_task(ProcessHook, hook, creds, redis)
            return Response(status_code=200)
        case _:
            return Response(status_code=403)


@app.post("/device42")
async def UpdateProcessor(_: Request, background_tasks: BackgroundTasks) -> Response:
    background_tasks.add_task(ProcessUpdate, 'd42', creds, redis)
    return Response(status_code=200)


@app.post("/arbors/{arborType}/update_db")
async def UpdateProcessor(arborType: str | None, request: Request, background_tasks: BackgroundTasks) -> Response:
    match request.client.host:
        case '192.168.240.2':
            background_tasks.add_task(ProcessUpdate, arborType, creds, redis)
            return Response(status_code=200)
        case _:
            return Response(status_code=403)


@app.post("/arbors/{arborType}/proxy")
async def ProxyProcessor(arborType: str, hook: Arbor.Response, request: Request, background_tasks: BackgroundTasks) -> Response:
    match request.client.host:
        case '192.168.240.2':
            hook.arborType = arborType
            hook.response = await request.json()
            match hook.arborType:
                case 'ix' | 'ipt':
                    background_tasks.add_task(ProcessProxy, hook, creds)
                    return Response(status_code=200)
                case _:
                    return Response(status_code=403)
        case _:
            return Response(status_code=403)


@app.post("/arbors/{arborType}/ddos")
async def DDoSProcessor(arborType: str, hook: Arbor.Response, request: Request, background_tasks: BackgroundTasks) -> Response:
    match request.client.host:
        case '192.168.240.2':
            hook.arborType = arborType
            match hook.arborType:
                case 'ix' | 'ipt':
                    background_tasks.add_task(ProcessDDoS, hook, creds, redis, logging, **kwargs)
                    return Response(status_code=200)
                case _:
                    return Response(status_code=403)
        case _:
            return Response(status_code=403)


if __name__ == "__main__":

    if not any(flag in sys.argv for flag in ['-d', '--debug']):
        logging.info(f'Waiting for the container with the Redis to start, as well as the redis.service itself')
        sleep(20)

        logging.info(f'Adding bots and chats data to the Redis database')
        for botName, bot in creds.tg.items():
            redis.delete(f'bots.{botName}.users')
            redis.delete(f'bots.{botName}.groups')

            redis.sadd(f'bots.{botName}.users', *bot.users)
            redis.sadd(f'bots.{botName}.groups', *bot.groups)

            for groupName, groupID in bot.groups.items():
                redis.set(f'bots.{botName}.groups.{abs(groupID)}.name', groupName)
                redis.set(f'bots.{botName}.groups.{abs(groupID)}.id', groupID)

        for updType in ['d42', 'ix', 'ipt']:
            logging.info(f'Adding data to the Redis database by {updType}')
            ProcessUpdate(updType, creds, redis)

    # External communications
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=443 if not any(flag in sys.argv for flag in ['-d', '--debug']) else 64270,
        reload=False if not any(flag in sys.argv for flag in ['-d', '--debug']) else True,
        log_level="info" if not any(flag in sys.argv for flag in ['-d', '--debug']) else "debug",
        ssl_keyfile='certs/ssl_keyfile.key',
        ssl_certfile='certs/ssl_certfile.crt',
        workers=4
        )
