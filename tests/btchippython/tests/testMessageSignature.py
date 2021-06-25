"""
*******************************************************************************    
*   BTChip Bitcoin Hardware Wallet Python API
*   (c) 2014 BTChip - 1BTChip7VfTnrPra5jqci7ejnMguuHogTn
*   
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*   Unless required by applicable law or agreed to in writing, software
*   distributed under the License is distributed on an "AS IS" BASIS,
*   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*   limitations under the License.
********************************************************************************
"""

from btchip.btchip import *
from btchip.btchipUtils import *

# Run on non configured dongle or dongle configured with test seed below

SEED = bytearray("1762F9A3007DBC825D0DD9958B04880284E88F10C57CF569BB3DADF7B1027F2D".decode('hex'))

MESSAGE = "Campagne de Sarkozy : une double comptabilite chez Bygmalion"

SECONDFACTOR_1 = "Powercycle then confirm signature of .Campagne de Sarkozy : une double comptabilite chez Bygmalion. for address 17JusYNVXLPm3hBPzzRQkARYDMUBgRUMVc with PIN"
SIGNATURE = bytearray("30450221009a0d28391c0535aec1077bbb86614c8f3c384a3e9aa1a124bfb9ce9649196b7e02200efa1adc010a7bdde4784ee98441e402f93b3c50a2760cb09dda07501e02c81f".decode('hex'))

# Optional setup
dongle = getDongle(True)
app = btchip(dongle)
try:
	app.setup(btchip.OPERATION_MODE_WALLET, btchip.FEATURE_RFC6979, 0x00, 0x05, "1234", None, btchip.QWERTY_KEYMAP, SEED)
except Exception:
	pass
# Authenticate
app.verifyPin("1234")
# Start signing
app.signMessagePrepare("0'/0/0", MESSAGE)
dongle.close()
# Wait for the second factor confirmation
# Done on the same application for test purposes, this is typically done in another window
# or another computer for bigger transactions
response = raw_input("Powercycle the dongle to get the second factor and powercycle again : ")
if not response.startswith(SECONDFACTOR_1):
	raise BTChipException("Invalid second factor")
# Get a reference to the dongle again, as it was disconnected
dongle = getDongle(True)
app = btchip(dongle)
# Compute the signature
signature = app.signMessageSign(response[len(response) - 4:])
if signature <> SIGNATURE:
	raise BTChipException("Invalid signature")
