"""
A quick test of the pyloxone_api module

From the command line, run:

> python -m pyloxone_api username password host port

where username, password host and port are your Loxone login credentials

"""
import asyncio
import logging
import sys

from pyloxone_api import LoxAPI

_LOGGER = logging.getLogger("pyloxone_api")
_LOGGER.setLevel(logging.DEBUG)
_LOGGER.addHandler(logging.StreamHandler())
# If you want to see what is going on at the websocket level, uncomment the following
# lines

# _LOGGER2 = logging.getLogger("websockets")
# _LOGGER2.setLevel(logging.DEBUG)
# _LOGGER2.addHandler(logging.StreamHandler())


async def main() -> None:

    api = LoxAPI(
        user=sys.argv[1], password=sys.argv[2], host=sys.argv[3], port=int(sys.argv[4])
    )

    await api.getJson()
    await api.async_init()
    await api.start()


if __name__ == "__main__":
    try:
        r = asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit()
