"""
Loxone constants

For more details about this component, please refer to the documentation at
https://github.com/JoDehli/pyloxone-api
"""
# Loxone constants


TIMEOUT = 10
KEEP_ALIVE_PERIOD = 240

IV_BYTES = 16
AES_KEY_SIZE = 32

SALT_BYTES = 16
SALT_MAX_AGE_SECONDS = 60 * 60
SALT_MAX_USE_COUNT = 30

TOKEN_PERMISSION = 4  # 2=web, 4=app
TOKEN_REFRESH_RETRY_COUNT = 5
# token will be refreshed 1 day before its expiration date
TOKEN_REFRESH_SECONDS_BEFORE_EXPIRY = 24 * 60 * 60  # 1 day
#  if can't determine token expiration date, it will be refreshed after 2 days
TOKEN_REFRESH_DEFAULT_SECONDS = 2 * 24 * 60 * 60  # 2 days

LOXAPPPATH = "/data/LoxAPP3.json"

CMD_GET_PUBLIC_KEY = "jdev/sys/getPublicKey"
CMD_KEY_EXCHANGE = "jdev/sys/keyexchange/"
CMD_GET_KEY_AND_SALT = "jdev/sys/getkey2/"
CMD_REQUEST_TOKEN = "jdev/sys/gettoken/"
CMD_REQUEST_TOKEN_JSON_WEB = "jdev/sys/getjwt/"
CMD_GET_KEY = "jdev/sys/getkey"
CMD_AUTH_WITH_TOKEN = "authwithtoken/"
CMD_REFRESH_TOKEN = "jdev/sys/refreshtoken/"
CMD_REFRESH_TOKEN_JSON_WEB = "jdev/sys/refreshjwt/"
CMD_ENCRYPT_CMD = "jdev/sys/enc/"
CMD_ENABLE_UPDATES = "jdev/sps/enablebinstatusupdate"
CMD_GET_VISUAL_PASSWD = "jdev/sys/getvisusalt/"

DEFAULT_TOKEN_PERSIST_NAME = "lox_token.cfg"
ERROR_VALUE = -1
LOX_CONFIG = "loxconfig"
