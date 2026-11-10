import Transport from '@ledgerhq/hw-transport';

import { WalletPolicy } from './policy';
import { Apdu, Operation } from './wasm/ledger_bitcoin_wasm';

const SW_OK = 0x9000;
const SW_INTERRUPTED_EXECUTION = 0xe000;

const WALLET_POLICY_V2 = 2;

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
 * A MuSig2 public nonce produced by the app during the first round of a MuSig2 signing session.
 * `participantPubkey` is the 33-byte compressed key of this participant, `aggregatePubkey` the
 * 33-byte compressed (tweaked) aggregate key; `tapleafHash` is set when signing for a tapscript.
 */
export class MusigPubNonce {
  constructor(
    readonly participantPubkey: Buffer,
    readonly aggregatePubkey: Buffer,
    readonly pubnonce: Buffer,
    readonly tapleafHash?: Buffer
  ) {}
}

/**
 * A MuSig2 partial signature produced by the app during the second round of a MuSig2 signing
 * session. Not to be confused with `PartialSignature`, which is a regular signature.
 */
export class MusigPartialSignature {
  constructor(
    readonly participantPubkey: Buffer,
    readonly aggregatePubkey: Buffer,
    readonly partialSignature: Buffer,
    readonly tapleafHash?: Buffer
  ) {}
}

/**
 * An object yielded by the app with a tag unknown to this version of the client; `data` is the
 * opaque payload that follows the input index.
 */
export class UnknownSignPsbtYieldedObject {
  constructor(readonly tag: bigint, readonly data: Buffer) {}
}

export type SignPsbtYieldedObject =
  | PartialSignature
  | MusigPubNonce
  | MusigPartialSignature
  | UnknownSignPsbtYieldedObject;

/**
 * A PSBT of version 0 or 2: base64-encoded, serialized, or an object that serializes it, like
 * the `Psbt` class of bitcoinjs-lib (`toBuffer()`). Its fields are sent to the device exactly as
 * serialized.
 */
export type PsbtInput =
  | string
  | Uint8Array
  | { toBuffer(): Uint8Array }
  | { serialize(): Uint8Array | string };

function psbtBytes(psbt: PsbtInput): Uint8Array {
  if (typeof psbt === 'string') {
    return Buffer.from(psbt, 'base64');
  }
  if (psbt instanceof Uint8Array) {
    return psbt;
  }
  if ('toBuffer' in psbt && typeof psbt.toBuffer === 'function') {
    return psbt.toBuffer();
  }
  if ('serialize' in psbt && typeof psbt.serialize === 'function') {
    const serialized = psbt.serialize();
    return typeof serialized === 'string'
      ? Buffer.from(serialized, 'base64')
      : serialized;
  }
  throw new Error('Unsupported PSBT type');
}

function optionalBuffer(data?: Uint8Array): Buffer | undefined {
  return data === undefined ? undefined : Buffer.from(data);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function yieldedObject(object: any): SignPsbtYieldedObject {
  switch (object.kind) {
    case 'partialSignature':
      return new PartialSignature(
        Buffer.from(object.pubkey),
        Buffer.from(object.signature),
        optionalBuffer(object.tapleafHash)
      );
    case 'musigPubNonce':
      return new MusigPubNonce(
        Buffer.from(object.participantPubkey),
        Buffer.from(object.aggregatePubkey),
        Buffer.from(object.pubnonce),
        optionalBuffer(object.tapleafHash)
      );
    case 'musigPartialSignature':
      return new MusigPartialSignature(
        Buffer.from(object.participantPubkey),
        Buffer.from(object.aggregatePubkey),
        Buffer.from(object.partialSignature),
        optionalBuffer(object.tapleafHash)
      );
    default:
      return new UnknownSignPsbtYieldedObject(
        object.tag,
        Buffer.from(object.data)
      );
  }
}

function walletArgs(
  walletPolicy: WalletPolicy
): [string, string, string[], number] {
  return [
    walletPolicy.name,
    walletPolicy.descriptorTemplate,
    [...walletPolicy.keys],
    WALLET_POLICY_V2,
  ];
}

/**
 * Client for the Ledger Bitcoin application, version 2.1.0 or later.
 *
 * The protocol documented at
 * https://github.com/LedgerHQ/app-bitcoin/blob/master/doc/bitcoin.md
 * is implemented by the Rust client of the app, compiled to WebAssembly; this class owns the
 * transport and runs the exchanges.
 */
export class AppClient {
  readonly transport: Transport;

  constructor(transport: Transport) {
    this.transport = transport;
  }

  /**
   * Runs the exchanges of an operation, and returns its output. `onYield` is called once per
   * object yielded by the device.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private async run(operation: Operation, onYield?: () => void): Promise<any> {
    try {
      let apdu: Apdu | undefined = operation.nextApdu();
      let yielded = 0;
      while (apdu !== undefined) {
        const { cla, ins, p1, p2, data } = apdu;
        apdu.free();
        // any other status word makes the transport throw a TransportStatusError
        const response = await this.transport.send(
          cla,
          ins,
          p1,
          p2,
          Buffer.from(data),
          [SW_OK, SW_INTERRUPTED_EXECUTION]
        );
        const sw = response.readUInt16BE(response.length - 2);
        apdu = operation.step(sw, response.subarray(0, response.length - 2));
        for (
          const count = operation.yieldedCount();
          yielded < count;
          yielded++
        ) {
          onYield?.();
        }
      }
      return operation.output();
    } finally {
      operation.free();
    }
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
    const { name, version, flags } = await this.run(Operation.getVersion());
    return { name, version, flags: Buffer.from(flags) };
  }

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
  async getExtendedPubkey(path: string, display = false): Promise<string> {
    return await this.run(Operation.getExtendedPubkey(path, display));
  }

  /**
   * Registers a `WalletPolicy`, after interactive verification from the user.
   * On success, after user's approval, this function returns the id (which is the same that can be computed with
   * `walletPolicy.getid()`), followed by the 32-byte hmac. The client should store the hmac to use it for future
   * requests to `getWalletAddress` or `signPsbt` using this `WalletPolicy`.
   *
   * Before returning, the first receive address of the wallet is requested from the device, and verified
   * independently.
   *
   * @param walletPolicy the `WalletPolicy` to register
   * @returns a pair of two 32-byte arrays: the id of the Wallet Policy, followed by the policy hmac
   */
  async registerWallet(
    walletPolicy: WalletPolicy
  ): Promise<readonly [Buffer, Buffer]> {
    const { id, hmac } = await this.run(
      Operation.registerWallet(...walletArgs(walletPolicy))
    );
    return [Buffer.from(id), Buffer.from(hmac)] as const;
  }

  /**
   * Returns the address of `walletPolicy` for the given `change` and `addressIndex`, after
   * verifying it independently.
   *
   * @param walletPolicy the `WalletPolicy` to use
   * @param walletHMAC the 32-byte hmac returned during wallet registration for a registered policy; otherwise
   * `null` for a standard policy
   * @param change `0` for a normal receive address, `1` for a change address
   * @param addressIndex the address index to retrieve
   * @param display `True` to show the address on screen, `False` to retrieve it silently
   * @returns the address, as a string
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
    if (
      !Number.isInteger(addressIndex) ||
      addressIndex < 0 ||
      addressIndex >= 0x80000000
    )
      throw new Error('Invalid address index');

    return await this.run(
      Operation.getWalletAddress(
        ...walletArgs(walletPolicy),
        walletHMAC,
        change,
        addressIndex,
        display
      )
    );
  }

  /**
   * Signs a psbt using a (standard or registered) `WalletPolicy`. This is an interactive command, as user validation
   * is necessary using the device's secure screen.
   * On success, a list of the objects yielded by the device is returned: the index of the input, and either a
   * `PartialSignature`, or, for MuSig2, a `MusigPubNonce` or a `MusigPartialSignature`.
   *
   * @param psbt a PSBT of version 0 or 2, as a base64 string, as its serialization, or as an object that
   * serializes it, like the `Psbt` class of bitcoinjs-lib
   * @param walletPolicy the `WalletPolicy` to use for signing
   * @param walletHMAC the 32-byte hmac obtained during wallet policy registration, or `null` for a standard policy
   * @param progressCallback optionally, a callback that will be called every time a signature is produced during
   * the signing process. The callback does not receive any argument, but can be used to track progress.
   * @returns an array of of tuples with 2 elements containing:
   *    - the index of the input being signed;
   *    - the yielded object.
   */
  async signPsbt(
    psbt: PsbtInput,
    walletPolicy: WalletPolicy,
    walletHMAC: Buffer | null,
    progressCallback?: () => void
  ): Promise<[number, SignPsbtYieldedObject][]> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const results: [number, any][] = await this.run(
      Operation.signPsbt(
        psbtBytes(psbt),
        ...walletArgs(walletPolicy),
        walletHMAC
      ),
      progressCallback
    );
    return results.map(([index, object]) => [index, yieldedObject(object)]);
  }

  /**
   * Returns the fingerprint of the master public key, as per BIP-32 standard.
   * @returns the master key fingerprint as a string of 8 hexadecimal digits.
   */
  async getMasterFingerprint(): Promise<string> {
    const fingerprint = await this.run(Operation.getMasterFingerprint());
    return Buffer.from(fingerprint).toString('hex');
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
  async signMessage(message: Buffer, path: string): Promise<string> {
    const signature = await this.run(Operation.signMessage(message, path));
    return Buffer.from(signature).toString('base64');
  }
}

export default AppClient;
