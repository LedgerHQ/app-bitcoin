import pytest
from pathlib import Path

from ragger.conftest import configuration
from ragger.backend.interface import BackendInterface
from ragger_bitcoin import createRaggerClient, RaggerClient

###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

MNEMONIC = "glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"
configuration.OPTIONAL.CUSTOM_SEED = MNEMONIC
configuration.OPTIONAL.BACKEND_SCOPE = "function"


#########################
### CONFIGURATION END ###
#########################
TESTS_ROOT_DIR = Path(__file__).parent

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )


@pytest.fixture
def client(backend: BackendInterface) -> RaggerClient:
    return createRaggerClient(backend, screenshot_dir=TESTS_ROOT_DIR)
