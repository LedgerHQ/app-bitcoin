from btchippython.btchip.bitcoinTransaction import bitcoinTransaction
from btchippython.btchip.btchip import btchip
from electrum_clone.electrumravencoin.electrum.transaction import Transaction
from electrum_clone.electrumravencoin.electrum.util import bfh
from electrum_clone.electrumravencoin.electrum.ravencoin import int_to_hex, var_int

def sign_transaction(cmd, tx, pubkeys, inputsPaths, changePath):
    inputs = []
    chipInputs = []
    redeemScripts = []
    output = None
    p2shTransaction = False
    segwitTransaction = False
    pin = ""

    print("SIGNING")

    # Fetch inputs of the transaction to sign
    for i, txin in enumerate(tx.inputs()):
        redeemScript = Transaction.get_preimage_script(txin)
        txin_prev_tx = txin.utxo
        txin_prev_tx_raw = txin_prev_tx.serialize() if txin_prev_tx else None
        print((txin_prev_tx_raw,
              txin.prevout.out_idx,
              redeemScript,
              txin.prevout.txid.hex(),
              pubkeys[i],
              txin.nsequence,
              txin.value_sats()))
        inputs.append([txin_prev_tx_raw,
                       txin.prevout.out_idx,
                       redeemScript,
                       txin.prevout.txid.hex(),
                       pubkeys[i],
                       txin.nsequence,
                       txin.value_sats()])

    txOutput = var_int(len(tx.outputs()))
    for o in tx.outputs():
        txOutput += int_to_hex(0 if o.asset else o.value.value, 8)
        script = o.scriptpubkey.hex()
        txOutput += var_int(len(script) // 2)
        txOutput += script
    txOutput = bfh(txOutput)

    for utxo in inputs:

        sequence = int_to_hex(utxo[5], 4)

        txtmp = bitcoinTransaction(bfh(utxo[0]))
        trustedInput = btchip.getTrustedInput(cmd, txtmp, utxo[1])
        trustedInput['sequence'] = sequence
        if segwitTransaction:
            trustedInput['witness'] = True
        chipInputs.append(trustedInput)
        redeemScripts.append(txtmp.outputs[utxo[1]].script)

    # Sign all inputs
    firstTransaction = True
    inputIndex = 0
    rawTx = tx.serialize_to_network()

    btchip.enableAlternate2fa(cmd, False)

    while inputIndex < len(inputs):
        btchip.startUntrustedTransaction(cmd, firstTransaction, inputIndex,
                                                chipInputs, redeemScripts[inputIndex], version=tx.version)
        # we don't set meaningful outputAddress, amount and fees
        # as we only care about the alternateEncoding==True branch
        outputData = btchip.finalizeInput(cmd, b'', 0, 0, changePath, bfh(rawTx))
        outputData['outputData'] = txOutput
        if outputData['confirmationNeeded']:
            outputData['address'] = output
        else:
            # Sign input with the provided PIN
            inputSignature = btchip.untrustedHashSign(cmd, inputsPaths[inputIndex], pin,
                                                             lockTime=tx.locktime)
            inputSignature[0] = 0x30  # force for 1.4.9+
            my_pubkey = inputs[inputIndex][4]
            tx.add_signature_to_txin(txin_idx=inputIndex,
                                     signing_pubkey=my_pubkey.hex(),
                                     sig=inputSignature.hex())
            inputIndex = inputIndex + 1
        firstTransaction = False