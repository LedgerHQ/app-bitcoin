from contextlib import contextmanager
import json
import sys
import os
from typing import Union

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from ledger_bitcoin import TransportClient
from speculos.client import SpeculosClient


@contextmanager
def automation(client: Union[TransportClient, SpeculosClient], file_or_automation: Union[str, dict]):
    if not isinstance(client, SpeculosClient):
        # not speculos, ignore automation rules
        yield
    else:
        if isinstance(file_or_automation, str):
            aut_obj = json.load(open(file_or_automation))
            if not isinstance(aut_obj, dict):
                raise ValueError("Invalid automation file")
        else:
            aut_obj = file_or_automation

        client.set_automation_rules(aut_obj)

        yield

        # clear automation rules
        client.set_automation_rules({"version": 1, "rules": []})
