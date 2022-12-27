""" Loxone exceptions"""


class LoxoneException(Exception):
    """Base class for all Loxone Exceptions"""


class LoxoneHTTPStatusError(LoxoneException):
    """An exception indicating an unusual http response from the miniserver"""


class LoxoneRequestError(LoxoneException):
    """An exception raised during an http request"""


class LoxoneTokenError(LoxoneException):
    """An exception indicating a problem loading or saving a token"""
