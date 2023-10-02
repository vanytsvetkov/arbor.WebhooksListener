from fastapi.exceptions import RequestValidationError

import vars
from models import Creds
from utils import msg


async def ProcessError(exc: RequestValidationError, creds: Creds) -> None:
    await msg(
            data={"filename": f"processError.json", "data": str(exc.body) + f"\n\n{exc.errors()}"},
            token=creds.tg[vars.BOT_NAME].token,
            chat_id=creds.tg[vars.BOT_NAME].groups[vars.BOT_DFT_CHAT]
            )
