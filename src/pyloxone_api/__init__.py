"""Low-level async client for the Loxone Miniserver WebSocket API.

Public API: :class:`LoxoneConnection` (and its base class) plus the
exceptions below. Everything else is internal and may change between
releases.
"""

from .connection import LoxoneBaseConnection, LoxoneConnection
from .exceptions import (
    ConnectionFailure,
    HttpApiError,
    LoxoneAuthEscalatedError,
    LoxoneCommandError,
    LoxoneConnectionClosedOk,
    LoxoneConnectionError,
    LoxoneException,
    LoxoneHTTPStatusError,
    LoxoneMaxNumOfConnectionsError,
    LoxoneOutOfServiceException,
    LoxoneRequestError,
    LoxoneServiceUnAvailableError,
    LoxoneTimeOutError,
    LoxoneTokenError,
    LoxoneUnauthorisedError,
    LoxoneUnrecognizedCommandError,
    MessageError,
    ResponseError,
    UnauthorizedError,
)

__version__ = "0.3.0"

__all__ = [
    "ConnectionFailure",
    "HttpApiError",
    "LoxoneAuthEscalatedError",
    "LoxoneBaseConnection",
    "LoxoneCommandError",
    "LoxoneConnection",
    "LoxoneConnectionClosedOk",
    "LoxoneConnectionError",
    "LoxoneException",
    "LoxoneHTTPStatusError",
    "LoxoneMaxNumOfConnectionsError",
    "LoxoneOutOfServiceException",
    "LoxoneRequestError",
    "LoxoneServiceUnAvailableError",
    "LoxoneTimeOutError",
    "LoxoneTokenError",
    "LoxoneUnauthorisedError",
    "LoxoneUnrecognizedCommandError",
    "MessageError",
    "ResponseError",
    "UnauthorizedError",
    "__version__",
]
