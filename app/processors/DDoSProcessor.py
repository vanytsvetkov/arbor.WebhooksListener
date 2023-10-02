from asyncio import sleep
from datetime import timedelta

import redis as r

import vars
from models import (
    Arbor,
    Creds
)
from utils import msg, gen_report, gen_email


async def ProcessDDoS(hook: Arbor.Response, creds: Creds, redis: r.client.Redis, logger, **kwargs):

    blob = Arbor.Blob(id=hook.data.relationships.managed_object.data.id)
    blob.tenant.id = redis.get(f'{hook.arborType}|blobs.{blob.id}.tenant.id')

    if not hook.bypass:

        redis.set(f'd42|customers.{blob.tenant.id}.notified', 1)
        redis.expire(f'd42|customers.{blob.tenant.id}.notified', timedelta(hours=72))

        iter_stage = redis.get(f'{hook.arborType}|iter_stage')
        iter_stage = int(iter_stage) if iter_stage and iter_stage.isdigit() else 0

        redis.set(f'{hook.arborType}|iter_stage.{iter_stage}', hook.data.id)
        redis.expire(f'{hook.arborType}|iter_stage.{iter_stage}', timedelta(hours=24))

        # Waiting for Arbor to analyze the alert and be able to return the analytics via the API.
        await sleep(5*60)

    blob.tenant.manager = redis.get(f'd42|customers.{blob.tenant.id}.contact_info')
    blob.tenant.emails = redis.smembers(f'd42|customers.{blob.tenant.id}.emails')
    # blob.tenant.services = redis.smembers(f'd42|customers.{blob.tenant.id}.services')
    blob.tenant.services = redis.smembers(f'{hook.arborType}|blobs.{blob.id}.tenant.services')

    blob.tenant.tags = redis.smembers(f'd42|customers.{blob.tenant.id}.tags')
    blob.tenant.ott = redis.get(f'd42|customers.{blob.tenant.id}.ott')

    report = gen_report(hook, creds, blob, **kwargs)

    report.content = kwargs.get('template').render(report)

    if not hook.bypass:

        await msg(
            data={"filename": f"{hook.data.id}.eml", "data": gen_email(report, blob)},
            token=creds.tg[vars.BOT_NAME].token,
            chat_id=creds.tg[vars.BOT_NAME].groups[f'[GBL-DoS] Proxy']
            )
        return

    # # # # #
    # Debug part below
    # # # # #

    logger.warning(f'{report=}')

    await msg(
        data={"filename": f"{hook.data.id}.html", "data": report.content},
        token=creds.tg[vars.BOT_NAME].token,
        chat_id=creds.tg[vars.BOT_NAME].groups[vars.BOT_DFT_CHAT]
        )

    await msg(
        data={"filename": f"{hook.data.id}.eml", "data": gen_email(report, blob)},
        token=creds.tg[vars.BOT_NAME].token,
        chat_id=creds.tg[vars.BOT_NAME].groups[vars.BOT_DFT_CHAT]
        )

    # # # # #
