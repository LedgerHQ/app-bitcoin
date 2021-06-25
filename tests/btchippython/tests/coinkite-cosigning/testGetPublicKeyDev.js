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

# Coinkite co-signer provisioning
# To be run with the dongle in developer mode, PIN verified

import hashlib
from btchip.btchip import *
from btchip.btchipUtils import *
from base64 import b64encode

# Replace with your own seed (preferably import it and store it), key path, and Testnet flag
SEED = bytearray("fe721b95503a18a14d93914e02ff153f924737c336b01f98f2ff39395f630187".decode('hex'))
KEYPATH = "0'/2/0"
TESTNET = True

# From Electrum

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
    """ encode v, which is a string of bytes, to base58."""

    long_value = 0L
    for (i, c) in enumerate(v[::-1]):
        long_value += (256**i) * ord(c)

    result = ''
    while long_value >= __b58base:
        div, mod = divmod(long_value, __b58base)
        result = __b58chars[mod] + result
        long_value = div
    result = __b58chars[long_value] + result

    # Bitcoin does a little leading-zero-compression:
    # leading 0-bytes in the input become leading-1s
    nPad = 0
    for c in v:
        if c == '\0': nPad += 1
        else: break

    return (__b58chars[0]*nPad) + result

def EncodeBase58Check(vchIn):
    hash = Hash(vchIn)
    return b58encode(vchIn + hash[0:4])

def sha256(x):
    return hashlib.sha256(x).digest()


def Hash(x):
    if type(x) is unicode: x=x.encode('utf-8')
    return sha256(sha256(x))

def i4b(self, x):
    return pack('>I', x)


# /from Electrum

def getXpub(publicKeyData, testnet=False):
    header = ("043587CF" if testnet else "0488B21E")
    result = header.decode('hex') + chr(publicKeyData['depth']) + str(publicKeyData['parentFingerprint']) + str(publicKeyData['childNumber']) + str(publicKeyData['chainCode']) + str(compress_public_key(publicKeyData['publicKey']))
    return EncodeBase58Check(result)

def signMessage(encodedPrivateKey, data):
    messageData = bytearray("\x18Bitcoin Signed Message:\n")
    writeVarint(len(data), messageData)
    messageData.extend(data)
    messageHash = Hash(messageData)
    signature = app.signImmediate(encodedPrivateKey, messageHash)
    
    # Parse the ASN.1 signature

    rLength = signature[3]
    r = signature[4 : 4 + rLength]
    sLength = signature[4 + rLength + 1]
    s = signature[4 + rLength + 2:]
    if rLength == 33:
        r = r[1:]
    if sLength == 33:
        s = s[1:]
    r = str(r)
    s = str(s)

    # And convert it

    return b64encode(chr(27 + 4 + (signature[0] & 0x01)) + r + s)
         
dongle = getDongle(True)
app = btchip(dongle)
seed = app.importPrivateKey(SEED, TESTNET)
privateKey = app.deriveBip32Key(seed, KEYPATH)
publicKeyData = app.getPublicKey(privateKey)
print getXpub(publicKeyData, TESTNET)
print signMessage(privateKey, "Coinkite")
dongle.close()
