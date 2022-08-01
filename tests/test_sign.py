from hashlib import sha256
import json
from pathlib import Path
from typing import Tuple, List, Dict, Any
import pytest

from ecdsa.curves import SECP256k1
from ecdsa.keys import VerifyingKey
from ecdsa.util import sigdecode_der

from bitcoin_client.hwi.serialization import CTransaction
from bitcoin_client.exception import ConditionOfUseNotSatisfiedError
from utils import automation


@automation("automations/accept.json")





