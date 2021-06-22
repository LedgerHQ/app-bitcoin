import re
import base64
import hashlib
from bitcoin_client.bitcoin_base_cmd import AddrType

def test_sign_message(cmd):
    message_og = 'Test'
    path_og = "m/44'/175'/0'/0/0"

    # From https://github.com/LedgerHQ/btchip-python/blob/master/btchip/btchip.py

    # Prepare signing

    def writeUint32BE(value, buffer):
        buffer.append((value >> 24) & 0xff)
        buffer.append((value >> 16) & 0xff)
        buffer.append((value >> 8) & 0xff)
        buffer.append(value & 0xff)
        return buffer

    def parse_bip32_path(path):
        if len(path) == 0:
            return bytearray([ 0 ])
        result = []
        elements = path.split('/')
        if len(elements) > 10:
            raise Exception("Path too long")
        for pathElement in elements:
            element = re.split('\'|h|H', pathElement)
            if len(element) == 1:
                writeUint32BE(int(element[0]), result)
            else:
                writeUint32BE(0x80000000 | int(element[0]), result)
        return bytearray([ len(elements) ] + result)

    path = parse_bip32_path(path_og[2:])
    message = message_og.encode('utf8')

    result = {}
    offset = 0
    encryptedOutputData = b""
    while (offset < len(message)):
        params = [];
        if offset == 0:
            params.extend(path)
            params.append((len(message) >> 8) & 0xff)
            params.append(len(message) & 0xff)
            p2 = 0x01
        else:
            p2 = 0x80
        blockLength = 255 - len(params)
        if ((offset + blockLength) < len(message)):
            dataLength = blockLength
        else:
            dataLength = len(message) - offset
        params.extend(bytearray(message[offset : offset + dataLength]))
        apdu = [ 0xe0, 0x4e, 0x00, p2 ]
        apdu.append(len(params))
        apdu.extend(params)
        _, response = cmd.transport.exchange_raw(bytearray(apdu))
        encryptedOutputData = encryptedOutputData + response[1 : 1 + response[0]]
        offset += blockLength
    result['confirmationNeeded'] = response[1 + response[0]] != 0x00
    result['confirmationType'] = response[1 + response[0]]
    if result['confirmationType'] == 0x03:
        offset = 1 + response[0] + 1
        result['secureScreenData'] = response[offset:]
        result['encryptedOutputData'] = encryptedOutputData

    # Sign

    print('Message Hash')
    print(hashlib.sha256(message).hexdigest().upper())

    apdu = [ 0xe0, 0x4e, 0x80, 0x00 ]
    params = []
    params.append(0x00)
    apdu.append(len(params))
    apdu.extend(params)
    _, signature = cmd.transport.exchange_raw(bytearray(apdu))

    # Parse the ASN.1 signature
    rLength = signature[3]
    r = signature[4: 4 + rLength]
    sLength = signature[4 + rLength + 1]
    s = signature[4 + rLength + 2:]
    if rLength == 33:
        r = r[1:]
    if sLength == 33:
        s = s[1:]
    # And convert it

    # Pad r and s points with 0x00 bytes when the point is small to get valid signature.
    r_padded = bytes([0x00]) * (32 - len(r)) + r
    s_padded = bytes([0x00]) * (32 - len(s)) + s

    p = bytes([27 + 4 + (signature[0] & 0x01)]) + r_padded + s_padded
    pub_key, addr, bip32_chain_code = cmd.get_public_key(
        addr_type=AddrType.Legacy,
        bip32_path=path_og,
        display=False
    )
    readable_sig = base64.b64encode(p).decode('ascii')
    print(addr)
    print(message_og)
    print(readable_sig)

    assert 'INyo6gzuMMY9wNvT71+amLPG+zBnL4PO8leCdYvSZGuLaVpvHrFcDFf3Q9Gt0ReRuwIxUSaKa+SGFJoxc8b32Zo='==\
        readable_sig
