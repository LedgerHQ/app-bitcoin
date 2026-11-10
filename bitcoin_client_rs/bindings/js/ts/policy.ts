import {
  walletPolicyId,
  walletPolicySerialize,
} from './wasm/ledger_bitcoin_wasm';

const WALLET_POLICY_V2 = 2;

/**
 * The Bitcon hardware app uses a descriptors-like thing to describe
 * how to construct output scripts from keys. A "Wallet Policy" consists
 * of a "Descriptor Template" and a list of "keys". A key is basically
 * a serialized BIP32 extended public key with some added derivation path
 * information. This is documented at
 * https://github.com/LedgerHQ/app-bitcoin/blob/master/doc/wallet.md
 */
export class WalletPolicy {
  readonly name: string;
  readonly descriptorTemplate: string;
  readonly keys: readonly string[];
  /**
   * Creates and instance of a wallet policy.
   * @param name an ascii string, up to 16 bytes long; it must be an empty string for default wallet policies
   * @param descriptorTemplate the wallet policy template
   * @param keys and array of the keys, with the key derivation information
   */
  constructor(
    name: string,
    descriptorTemplate: string,
    keys: readonly string[]
  ) {
    this.name = name;
    this.descriptorTemplate = descriptorTemplate;
    this.keys = keys;
  }

  /**
   * Returns the unique 32-bytes id of this wallet policy.
   */
  getId(): Buffer {
    return Buffer.from(
      walletPolicyId(
        this.name,
        this.descriptorTemplate,
        [...this.keys],
        WALLET_POLICY_V2
      )
    );
  }

  /**
   * Serializes the wallet policy for transmission via the hardware wallet protocol.
   * @returns the serialized wallet policy
   */
  serialize(): Buffer {
    return Buffer.from(
      walletPolicySerialize(
        this.name,
        this.descriptorTemplate,
        [...this.keys],
        WALLET_POLICY_V2
      )
    );
  }
}

export type DefaultDescriptorTemplate =
  | 'pkh(@0/**)'
  | 'sh(wpkh(@0/**))'
  | 'wpkh(@0/**)'
  | 'tr(@0/**)';

/**
 * Simplified class to handle default wallet policies that can be used without policy registration.
 */
export class DefaultWalletPolicy extends WalletPolicy {
  constructor(descriptorTemplate: DefaultDescriptorTemplate, key: string) {
    super('', descriptorTemplate, [key]);
  }
}
