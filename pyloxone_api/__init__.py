"""
Component to create an interface to the Loxone Miniserver.

For more details about this component, please refer to the documentation at
https://github.com/JoDehli/PyLoxone
"""


import logging
from .api import LoxWs, LoxApp

_LOGGER = logging.getLogger(__name__)