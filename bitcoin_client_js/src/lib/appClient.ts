import { DescriptorsFactory } from '@bitcoinerlab/descriptors';
import * as secp256k1 from '@bitcoinerlab/secp256k1';
const { Output } = DescriptorsFactory(secp256k1);
import Transport from '@ledgerhq/hw-transport';
import { networks } from 'bitcoinjs-lib';

import { pathElementsToBuffer, pathStringToArray } from './bip32';
import { ClientCommandInterpreter } from './clientCommands';
import { MerkelizedPsbt } from './merkelizedPsbt';
import { hashLeaf, Merkle } from './merkle';
import { WalletPolicy } from './policy';
import { PsbtV2 } from './psbtv2';
import { createVarint, parseVarint } from './varint';

const CLA_BTC = 0xe1;
const CLA_FRAMEWORK = 0xf8;

const CURRENT_PROTOCOL_VERSION = 1; // supported from version 2.1.0 of the app

enum BitcoinIns {
  GET_PUBKEY = 0x00,
  REGISTER_WALLET = 0x02,
  GET_WALLET_ADDRESS = 0x03,
  SIGN_PSBT = 0x04,
  GET_MASTER_FINGERPRINT = 0x05,
  SIGN_MESSAGE = 0x10,
}

enum FrameworkIns {
  CONTINUE_INTERRUPTED = 0x01,
}

/**
 * This class represents a partial signature produced by the app during signing.
 * It always contains the `signature` and the corresponding `pubkey` whose private key
 * was used for signing; in the case of taproot script paths, it also contains the
 * tapleaf hash.
 */
export class PartialSignature {
  readonly pubkey: Buffer;
  readonly signature: Buffer;
  readonly tapleafHash?: Buffer;

  constructor(pubkey: Buffer, signature: Buffer, tapleafHash?: Buffer) {
    this.pubkey = pubkey;
    this.signature = signature;
    this.tapleafHash = tapleafHash;
  }
}

/**
 * Creates an instance of `PartialSignature` from the returned raw augmented pubkey and signature.
 * @param pubkeyAugm the public key, concatenated with the tapleaf hash in the case of taproot script path spend.
 * @param signature the signature
 * @returns an instance of `PartialSignature`.
 */
function makePartialSignature(pubkeyAugm: Buffer, signature: Buffer): PartialSignature {
  if (pubkeyAugm.length == 64) {
    // tapscript spend: concatenation of 32-bytes x-only pubkey and 32-bytes tapleaf_hash
    return new PartialSignature(pubkeyAugm.slice(0, 32), signature, pubkeyAugm.slice(32, 64));
  } else if (pubkeyAugm.length == 32 || pubkeyAugm.length == 33) {
    // legacy, segwit or taproot keypath spend: pubkeyAugm is just the pubkey
    return new PartialSignature(pubkeyAugm, signature);
  } else {
    throw new Error(`Invalid length for pubkeyAugm: ${pubkeyAugm.length} bytes.`);
  }
}

/**
 * This class encapsulates the APDU protocol documented at
 * https://github.com/LedgerHQ/app-bitcoin/blob/master/doc/bitcoin.md
 */
export class AppClient {
  readonly transport: Transport;

  constructor(transport: Transport) {
    this.transport = transport;
  }

  private async makeRequest(
    ins: BitcoinIns,
    data: Buffer,
    cci?: ClientCommandInterpreter
  ): Promise<Buffer> {
    let response: Buffer = await this.transport.send(
      CLA_BTC,
      ins,
      0,
      CURRENT_PROTOCOL_VERSION,
      data,
      [0x9000, 0xe000]
    );
    while (response.readUInt16BE(response.length - 2) === 0xe000) {
      if (!cci) {
        throw new Error('Unexpected SW_INTERRUPTED_EXECUTION');
      }

      const hwRequest = response.slice(0, -2);
      const commandResponse = cci.execute(hwRequest);

      response = await this.transport.send(
        CLA_FRAMEWORK,
        FrameworkIns.CONTINUE_INTERRUPTED,
        0,
        CURRENT_PROTOCOL_VERSION,
        commandResponse,
        [0x9000, 0xe000]
      );
    }
    return response.slice(0, -2); // drop the status word (can only be 0x9000 at this point)
  }

  /**
   * Returns an object containing the currently running app's name, version and the device status flags.
   *
   * @returns an object with app name, version and device status flags.
   */
  public async getAppAndVersion(): Promise<{
    name: string;
    version: string;
    flags: number | Buffer;
  }> {
    const r = await this.transport.send(0xb0, 0x01, 0x00, 0x00);
    let i = 0;
    const format = r[i++];
    if (format !== 1) throw new Error("Unexpected response")

    const nameLength = r[i++];
    const name = r.slice(i, (i += nameLength)).toString("ascii");
    const versionLength = r[i++];
    const version = r.slice(i, (i += versionLength)).toString("ascii");
    const flagLength = r[i++];
    const flags = r.slice(i, (i += flagLength));
    return {
      name,
      version,
      flags,
    };
  };

  /**
   * Requests the BIP-32 extended pubkey to the hardware wallet.
   * If `display` is `false`, only standard paths will be accepted; an error is returned if an unusual path is
   * requested.
   * If `display` is `true`, the requested path is shown on screen for user verification; unusual paths can be
   * requested, and a warning is shown to the user in that case.
   *
   * @param path the requested BIP-32 path as a string
   * @param display `false` to silently retrieve a pubkey for a standard path, `true` to display the path on screen
   * @returns the base58-encoded serialized extended pubkey (xpub)
   */
  async getExtendedPubkey(
    path: string,
    display: boolean = false
  ): Promise<string> {
    const pathElements = pathStringToArray(path);
    if (pathElements.length > 6) {
      throw new Error('Path too long. At most 6 levels allowed.');
    }
    const response = await this.makeRequest(
      BitcoinIns.GET_PUBKEY,
      Buffer.concat([
        Buffer.from(display ? [1] : [0]),
        pathElementsToBuffer(pathElements),
      ])
    );
    return response.toString('ascii');
  }

  /**
   * Registers a `WalletPolicy`, after interactive verification from the user.
   * On success, after user's approval, this function returns the id (which is the same that can be computed with
   * `walletPolicy.getid()`), followed by the 32-byte hmac. The client should store the hmac to use it for future
   * requests to `getWalletAddress` or `signPsbt` using this `WalletPolicy`.
   *
   * @param walletPolicy the `WalletPolicy` to register
   * @returns a pair of two 32-byte arrays: the id of the Wallet Policy, followed by the policy hmac
   */
  async registerWallet(
    walletPolicy: WalletPolicy
  ): Promise<readonly [Buffer, Buffer]> {

    const clientInterpreter = new ClientCommandInterpreter();

    clientInterpreter.addKnownWalletPolicy(walletPolicy);

    const serializedWalletPolicy = walletPolicy.serialize();
    const response = await this.makeRequest(
      BitcoinIns.REGISTER_WALLET,
      Buffer.concat([
        createVarint(serializedWalletPolicy.length),
        serializedWalletPolicy,
      ]),
      clientInterpreter
    );

    if (response.length != 64) {
      throw Error(
        `Invalid response length. Expected 64 bytes, got ${response.length}`
      );
    }
    const walletId = response.subarray(0, 32);
    const walletHMAC = response.subarray(32);

    // sanity check: derive and validate the first address with a 3rd party
    const firstAddrDevice = await this.getWalletAddress(
      walletPolicy,
      walletHMAC,
      0,
      0,
      false
    );
    await this.validateAddress(firstAddrDevice, walletPolicy, 0, 0);

    return [walletId, walletHMAC];
  }

  /**
   * Returns the address of `walletPolicy` for the given `change` and `addressIndex`.
   *
   * @param walletPolicy the `WalletPolicy` to use
   * @param walletHMAC the 32-byte hmac returned during wallet registration for a registered policy; otherwise
   * `null` for a standard policy
   * @param change `0` for a normal receive address, `1` for a change address
   * @param addressIndex the address index to retrieve
   * @param display `True` to show the address on screen, `False` to retrieve it silently
   * @returns the address, as an ascii string.
   */
  async getWalletAddress(
    walletPolicy: WalletPolicy,
    walletHMAC: Buffer | null,
    change: number,
    addressIndex: number,
    display: boolean
  ): Promise<string> {
    if (change !== 0 && change !== 1)
      throw new Error('Change can only be 0 or 1');
    if (addressIndex < 0 || !Number.isInteger(addressIndex))
      throw new Error('Invalid address index');

    if (walletHMAC != null && walletHMAC.length != 32) {
      throw new Error('Invalid HMAC length');
    }

    const clientInterpreter = new ClientCommandInterpreter();

    clientInterpreter.addKnownWalletPolicy(walletPolicy);

    const addressIndexBuffer = Buffer.alloc(4);
    addressIndexBuffer.writeUInt32BE(addressIndex, 0);

    const response = await this.makeRequest(
      BitcoinIns.GET_WALLET_ADDRESS,
      Buffer.concat([
        Buffer.from(display ? [1] : [0]),
        walletPolicy.getId(),
        walletHMAC || Buffer.alloc(32, 0),
        Buffer.from([change]),
        addressIndexBuffer,
      ]),
      clientInterpreter
    );

    const address = response.toString('ascii');
    await this.validateAddress(address, walletPolicy, change, addressIndex);
    return address;
  }

  /**
   * Signs a psbt using a (standard or registered) `WalletPolicy`. This is an interactive command, as user validation
   * is necessary using the device's secure screen.
   * On success, a map of input indexes and signatures is returned.
   * @param psbt a base64-encoded string, or a psbt in a binary Buffer. Using the `PsbtV2` type is deprecated.
   * @param walletPolicy the `WalletPolicy` to use for signing
   * @param walletHMAC the 32-byte hmac obtained during wallet policy registration, or `null` for a standard policy
   * @param progressCallback optionally, a callback that will be called every time a signature is produced during
   * the signing process. The callback does not receive any argument, but can be used to track progress.
   * @returns an array of of tuples with 2 elements containing:
   *    - the index of the input being signed;
   *    - an instance of PartialSignature
   */
  async signPsbt(
    psbt: PsbtV2 | string | Buffer,
    walletPolicy: WalletPolicy,
    walletHMAC: Buffer | null,
    progressCallback?: () => void
  ): Promise<[number, PartialSignature][]> {

    if (typeof psbt === 'string') {
      psbt = Buffer.from(psbt, "base64");
    }

    if (Buffer.isBuffer(psbt)) {
      const psbtObj = new PsbtV2()
      psbtObj.deserialize(psbt);
      psbt = psbtObj;
    }

    const merkelizedPsbt = new MerkelizedPsbt(psbt);

    if (walletHMAC != null && walletHMAC.length != 32) {
      throw new Error('Invalid HMAC length');
    }

    const clientInterpreter = new ClientCommandInterpreter(progressCallback);

    // prepare ClientCommandInterpreter
    clientInterpreter.addKnownWalletPolicy(walletPolicy);

    clientInterpreter.addKnownMapping(merkelizedPsbt.globalMerkleMap);
    for (const map of merkelizedPsbt.inputMerkleMaps) {
      clientInterpreter.addKnownMapping(map);
    }
    for (const map of merkelizedPsbt.outputMerkleMaps) {
      clientInterpreter.addKnownMapping(map);
    }

    clientInterpreter.addKnownList(merkelizedPsbt.inputMapCommitments);
    const inputMapsRoot = new Merkle(
      merkelizedPsbt.inputMapCommitments.map((m) => hashLeaf(m))
    ).getRoot();
    clientInterpreter.addKnownList(merkelizedPsbt.outputMapCommitments);
    const outputMapsRoot = new Merkle(
      merkelizedPsbt.outputMapCommitments.map((m) => hashLeaf(m))
    ).getRoot();

    await this.makeRequest(
      BitcoinIns.SIGN_PSBT,
      Buffer.concat([
        merkelizedPsbt.getGlobalKeysValuesRoot(),
        createVarint(merkelizedPsbt.getGlobalInputCount()),
        inputMapsRoot,
        createVarint(merkelizedPsbt.getGlobalOutputCount()),
        outputMapsRoot,
        walletPolicy.getId(),
        walletHMAC || Buffer.alloc(32, 0),
      ]),
      clientInterpreter
    );

    const yielded = clientInterpreter.getYielded();

    const ret: [number, PartialSignature][] = [];
    for (const inputAndSig of yielded) {
      // inputAndSig contains:
      // <inputIndex : varint> <pubkeyLen : 1 byte> <pubkey : pubkeyLen bytes (32 or 33)> <signature : variable length>
      const [inputIndex, inputIndexLen] = parseVarint(inputAndSig, 0);
      const pubkeyAugmLen = inputAndSig[inputIndexLen];
      const pubkeyAugm = inputAndSig.subarray(inputIndexLen + 1, inputIndexLen + 1 + pubkeyAugmLen);
      const signature = inputAndSig.subarray(inputIndexLen + 1 + pubkeyAugmLen)

      const partialSig = makePartialSignature(pubkeyAugm, signature);

      ret.push([Number(inputIndex), partialSig]);
    }
    return ret;
  }

  /**
   * Returns the fingerprint of the master public key, as per BIP-32 standard.
   * @returns the master key fingerprint as a string of 8 hexadecimal digits.
   */
  async getMasterFingerprint(): Promise<string> {
    const fpr = await this.makeRequest(BitcoinIns.GET_MASTER_FINGERPRINT, Buffer.from([]));
    return fpr.toString("hex");
  }

  /**
   * Signs a message using the legacy Bitcoin Message Signing standard. The signed message is
   * the double-sha256 hash of the concatenation of:
   * - "\x18Bitcoin Signed Message:\n";
   * - the length of `message`, encoded as a Bitcoin-style variable length integer;
   * - `message`.
   *
   * @param message the serialized message to sign
   * @param path the BIP-32 path of the key used to sign the message
   * @returns base64-encoded signature of the message.
   */
  async signMessage(
    message: Buffer,
    path: string
  ): Promise<string> {
    const pathElements = pathStringToArray(path);

    const clientInterpreter = new ClientCommandInterpreter();

    // prepare ClientCommandInterpreter
    const nChunks = Math.ceil(message.length / 64);
    const chunks: Buffer[] = [];
    for (let i = 0; i < nChunks; i++) {
      chunks.push(message.subarray(64 * i, 64 * i + 64));
    }

    clientInterpreter.addKnownList(chunks);
    const chunksRoot = new Merkle(chunks.map((m) => hashLeaf(m))).getRoot();

    const result = await this.makeRequest(
      BitcoinIns.SIGN_MESSAGE,
      Buffer.concat([
        pathElementsToBuffer(pathElements),
        createVarint(message.length),
        chunksRoot,
      ]),
      clientInterpreter
    );

    return result.toString('base64');
  }

  /* Performs any additional check on the generated address before returning it.*/
  private async validateAddress(
    address: string,
    walletPolicy: WalletPolicy,
    change: number,
    addressIndex: number
  ) {
    if (change !== 0 && change !== 1)
      throw new Error('Change can only be 0 or 1');
    const isChange: boolean = change === 1;
    if (addressIndex < 0 || !Number.isInteger(addressIndex))
      throw new Error('Invalid address index');
    const appAndVer = await this.getAppAndVersion();
    let network;
    if (appAndVer.name === 'Bitcoin Test') {
      network = networks.testnet;
    } else if (appAndVer.name === 'Bitcoin' || appAndVer.name === 'Bitcoin Recovery') {
      network = networks.bitcoin;
    } else {
      throw new Error(
        `Invalid network: ${appAndVer.name}. Expected 'Bitcoin Test', 'Bitcoin' or 'Bitcoin Recovery'.`
      );
    }
    let expression = walletPolicy.descriptorTemplate;
    // Replace change:
    expression = expression.replace(/\/\*\*/g, `/<0;1>/*`);
    const regExpMN = new RegExp(`/<(\\d+);(\\d+)>`, 'g');
    let matchMN;
    while ((matchMN = regExpMN.exec(expression)) !== null) {
      const [M, N] = [parseInt(matchMN[1], 10), parseInt(matchMN[2], 10)];
      expression = expression.replace(`/<${M};${N}>`, `/${isChange ? N : M}`);
    }
    // Replace index:
    expression = expression.replace(/\/\*/g, `/${addressIndex}`);
    // Replace origin in reverse order to prevent
    // misreplacements, e.g., @10 being mistaken for @1 and leaving a 0.
    for (let i = walletPolicy.keys.length - 1; i >= 0; i--)
      expression = expression.replace(
        new RegExp(`@${i}`, 'g'),
        walletPolicy.keys[i]
      );
    let thirdPartyValidationApplicable = true;
    let thirdPartyGeneratedAddress: string;
    try {
      thirdPartyGeneratedAddress = new Output({
        descriptor: expression,
        network,
      }).getAddress();
    } catch (err) {
      // If this descriptor cannot be interpreted by @bitcoinerlab/descriptors,
      // third-party validation is not applicable.
      console.warn(`Third-party address validation unavailable for this descriptor. Address: ${address}`, err);
      thirdPartyValidationApplicable = false;
    }
    if (
      thirdPartyValidationApplicable &&
      address !== thirdPartyGeneratedAddress
    )
      throw new Error(
        `Third party address validation mismatch: ${address} != ${thirdPartyGeneratedAddress}`
      );
  }
}

export default AppClient;
