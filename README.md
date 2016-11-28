# blue-app-btc
Bitcoin wallet application for Ledger Blue and Nano S

This follows the beta specification at https://ledgerhq.github.io/btchip-doc/bitcoin-technical-beta.html - with the regular set of APDUs for standard wallet operations enabled.

Can be tested quickly tested with the Python API at https://github.com/LedgerHQ/btchip-python and Electrum (force noPin = True in getClient in plugins/ledger/ledger.py) 

This application is compatible with the Ledger Bitcoin Wallet Chrome Application available on Github at https://github.com/LedgerHQ/blue-app-btc and on Chrome Web Store at https://chrome.google.com/webstore/detail/ledger-wallet-bitcoin/kkdpmhnladdopljabkgpacgpliggeeaf  

## Using the beta high level communication API (1.1.2+)

The high level communication API provides a set of functions to directly sign transactions in Chrome, Opera or Firefox with the U2F extension with no Chrome app installed.

To use this API, make sure that "Browser Mode" is activated in the Settings of the Nano S application. This setting is not compatible with the former communication API, and needs to be disabled to use the Ledger Wallet Chrome application

## Usage 

Include the necessary headers (copied from the js/ directory) in your web page

```html
<head>
  <script src="thirdparty/q.js"></script>
  <script src="thirdparty/async.min.js"></script>
  <script src="thirdparty/u2f-api.js"></script>
  <script src="dist/ledger-btc.js"></script>
</head>
```

Create a communication object 

```javascript
var dongle = new LedgerBtc(20);
```

For each UTXO included in your transaction, create a transaction object from the raw serialized version of the transaction used in this UTXO

```javascript
var tx1 = dongle.splitTransaction("01000000014ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71010000008a47304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f57c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdebffffffff0281b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88aca0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac00000000");

var tx2 = dongle.splitTransaction("...")
```

Call createPaymentTransactionNew_async with the folowing parameters 

 - `inputs` is an array of [ transaction, output_index, optional redeem script, optional sequence ] where
   - transaction is the previously computed transaction object for this UTXO
   - output_index is the output in the transaction used as input for this UTXO (counting from 0)
   - redeem script is the redeem script to use when consuming a P2SH input, or non present when consuming a P2PKH input
   - sequence is the sequence number to use for this input (when using RBF), or non present
 - `associatedKeysets` is an array of BIP 32 paths pointing to the path to the private key used for each UTXO  
 - `changePath` is an optional BIP 32 path pointing to the path to the public key used to compute the change address
 - `outputScript` is the hexadecimal serialized outputs of the transaction to sign  
 - `lockTime` is the optional lockTime of the transaction to sign, or default (0)
 - `sigHashType` is the hash type of the transaction to sign, or default (all) 

This method returns the signed transaction ready to be broadcast 

```javascript
dongle.createPaymentTransactionNew_async(
   [ [tx, 1] ], 
   ["0'/0/0"], 
   undefined, 
   "01905f0100000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac").then(
     function(result) { console.log(result);}).fail(
     function(error) { console.log(error); });
);
```

