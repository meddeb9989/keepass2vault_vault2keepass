# Initialize Global imports

import os as OS
import re as RE
import sys as SYS
import logging as LOGGING
import requests as REQUESTS
import argparse as ARG_PARSER
from datetime import datetime as DATE_TIME
import requests.packages.urllib3 as URLLIB3_PACKAGES

# Initialize Global Vars

RED_TERMINAL_COLOR = "\033[31m"
YELLOW_TERMINAL_COLOR = "\033[33m"
TERMINAL_COLOR = "\033[1;37m"
BLUE_TERMINAL_COLOR = "\033[1;34m"
GREEN_TERMINAL_COLOR = "\033[32m"

KEEPASS_DIRECTORY_FILES = 'keepassfiles'
KEEPASS_DEFAULT_PASSWORD = '123456789'

ENTRIES_EXPORTED = 0
DELETE_ITERATION = 0
DELETE_EXISTING_REPOSITORY = False

KEEPASS_DB = None
PASSWORD = None
KEYFILE = None
TOKEN = None

KEEPASS_BASEFILE = None
KEEPASS_FILE = None

GROUPS_SECRETS_ADDED = []
GROUPS_ADDED = 0
SECRETS_ADDED = []

LOGGING.basicConfig(level=LOGGING.DEBUG)
LOGGER = LOGGING.getLogger(__name__)


# Disable logging for requests, urllib3 and pykeepass

LOGGING.getLogger('requests').setLevel(LOGGING.CRITICAL)
LOGGING.getLogger('urllib3').setLevel(LOGGING.CRITICAL)
LOGGING.getLogger('pykeepass').setLevel(LOGGING.CRITICAL)
URLLIB3_PACKAGES.disable_warnings(
    URLLIB3_PACKAGES.exceptions.InsecureRequestWarning
)


# Initialize Global Functions

def excepthook(_type, value, _traceback):
    """
    Raise Errors without Treceback.
    """
    print(value)