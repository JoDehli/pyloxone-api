"""
A quick test of the pyloxone_api module

From the command line, run:

> python -m pyloxone_api username password host port

where username, password host and port are your Loxone login credentials

"""
from pyloxone_api import LoxApp, LoxWs
import asyncio
import logging
import sys

_LOGGER = logging.getLogger(__name__)
_LOGGER.setLevel(logging.DEBUG)
_LOGGER.addHandler(logging.StreamHandler())


async def main():
    try:
        app = LoxApp()
        app.lox_user = sys.argv[1]
        app.lox_pass = sys.argv[2]
        app.host = sys.argv[3]
        app.port = sys.argv[4]
        request_code = await app.getJson()

        if request_code == 200 or request_code == "200":

            api = LoxWs(
                user=app.lox_user,
                password=app.lox_pass,
                host=app.host,
                port=app.port,
                loxconfig=app.json,
                loxone_url=app.url,
            )

            res = await api.async_init()
            if not res or res == -1:
                _LOGGER.error("Error connecting to loxone miniserver #1")
                return False

        else:
            if request_code in [401, "401"]:
                _LOGGER.error(
                    "401 - Unauthorized: the requesting user was not authorized "
                    "(invalid username/password)-Processing an encrypted request failed"
                )

            else:
                _LOGGER.error(
                    f"Error connecting to loxone miniserver #2 Code ({request_code})"
                )
            return False

    except ConnectionError:
        _LOGGER.error("Error connecting to loxone miniserver  #3")
        return False

    await api.start()
    return


if __name__ == "__main__":

    r = asyncio.run(main())
