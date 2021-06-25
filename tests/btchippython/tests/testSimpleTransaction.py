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

UTX = bytearray("01000000014ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71010000008a47304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f57c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdebffffffff0281b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88aca0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac00000000".decode('hex'))
UTXO_INDEX = 1
ADDRESS = "1BTChipvU14XH6JdRiK9CaenpJ2kJR9RnC"
AMOUNT = "0.0009"
FEES = "0.0001"

SECONDFACTOR_1 = "Powercycle then confirm transfer of 0.0009 BTC to 1BTChipvU14XH6JdRiK9CaenpJ2kJR9RnC fees 0.0001 BTC change 0 BTC with PIN"
SIGNATURE = bytearray("3045022100ea6df031b47629590daf5598b6f0680ad0132d8953b401577f01e8cc46393fe602202201b7a19d706a0213dcfeb7033719b92c6fd58a2d1d53411de71c4d8353154b01".decode('hex'))
TRANSACTION = bytearray("0100000001c773da236484dae8f0fdba3d7e0ba1d05070d1a34fc44943e638441262a04f10010000006b483045022100ea6df031b47629590daf5598b6f0680ad0132d8953b401577f01e8cc46393fe602202201b7a19d706a0213dcfeb7033719b92c6fd58a2d1d53411de71c4d8353154b01210348bb1fade0adde1bf202726e6db5eacd2063fce7ecf8bbfd17377f09218d5814ffffffff01905f0100000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac00000000".decode('hex'))

# Optional setup
dongle = getDongle(True)
app = btchip(dongle)
try:
	app.setup(btchip.OPERATION_MODE_WALLET, btchip.FEATURE_RFC6979, 0x00, 0x05, "1234", None, btchip.QWERTY_KEYMAP, SEED)
except Exception:
	pass
# Authenticate
app.verifyPin("1234")
# Get the public key and compress it
publicKey = compress_public_key(app.getWalletPublicKey("0'/0/0")['publicKey'])
# Get the trusted input associated to the UTXO
transaction = bitcoinTransaction(UTX)
outputScript = transaction.outputs[UTXO_INDEX].script
trustedInput = app.getTrustedInput(transaction, UTXO_INDEX)
# Start composing the transaction
app.startUntrustedTransaction(True, 0, [trustedInput], outputScript)
outputData = app.finalizeInput(ADDRESS, AMOUNT, FEES, "0'/1/0")
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
# Replay the transaction, this time continue it since the second factor is ready
app.startUntrustedTransaction(False, 0, [trustedInput], outputScript)
app.finalizeInput(ADDRESS, "0.0009", "0.0001", "0'/1/0")
# Provide the second factor to finalize the signature
signature = app.untrustedHashSign("0'/0/0", response[len(response) - 4:])
if signature <> SIGNATURE:
	raise BTChipException("Invalid signature")
# Finalize the transaction - build the redeem script and put everything together
inputScript = get_regular_input_script(signature, publicKey)
transaction = format_transaction(outputData['outputData'], [ [ trustedInput['value'], inputScript] ])
print "Generated transaction : " + str(transaction).encode('hex')
if transaction <> TRANSACTION:
	raise BTChipException("Invalid transaction")
# The transaction is ready to be broadcast, enjoy
