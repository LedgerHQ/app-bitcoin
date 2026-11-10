/*
Runs the client against the recorded device transcripts of the Rust client
(bitcoin_client_rs/tests/data), through a transport that replays them.
*/
import fs from 'fs';
import path from 'path';

import Transport from '@ledgerhq/hw-transport';

import {
  AppClient,
  DefaultWalletPolicy,
  MusigPartialSignature,
  MusigPubNonce,
  PartialSignature,
  UnknownSignPsbtYieldedObject,
  WalletPolicy,
} from '..';

const DATA_DIR = path.resolve(__dirname, '../../../../tests/data');

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function load(name: string): any[] {
  return JSON.parse(fs.readFileSync(path.join(DATA_DIR, name)).toString());
}

type Exchange = { apdu: Buffer; response: Buffer };

function parseExchanges(entries: string[]): Exchange[] {
  const result: Exchange[] = [];
  let apdu = Buffer.alloc(0);
  for (const raw of entries) {
    const entry = raw.replace(/ /g, '');
    if (entry.startsWith('=>')) {
      apdu = Buffer.from(entry.slice(2), 'hex');
    } else if (entry.startsWith('<=')) {
      result.push({ apdu, response: Buffer.from(entry.slice(2), 'hex') });
    }
  }
  return result;
}

/** Checks each APDU against the transcript, and replays its response. */
class ReplayTransport {
  constructor(readonly exchanges: Exchange[]) {}

  async send(
    cla: number,
    ins: number,
    p1: number,
    p2: number,
    data: Buffer = Buffer.alloc(0),
    statusList: number[] = [0x9000]
  ): Promise<Buffer> {
    const exchange = this.exchanges.shift();
    if (exchange === undefined) throw new Error('unexpected APDU');
    expect(
      Buffer.concat([Buffer.from([cla, ins, p1, p2, data.length]), data])
    ).toEqual(exchange.apdu);
    const sw = exchange.response.readUInt16BE(exchange.response.length - 2);
    if (!statusList.includes(sw)) {
      const error = new Error(`status ${sw.toString(16)}`);
      Object.assign(error, { statusCode: sw });
      throw error;
    }
    return exchange.response;
  }
}

function client(exchanges: Exchange[]): AppClient {
  return new AppClient(new ReplayTransport(exchanges) as unknown as Transport);
}

describe('replayed transcripts', () => {
  it('registers wallets, checking the first address', async () => {
    // the JS client only supports V2 wallet policies
    for (const c of load('register_wallet.json').filter(
      (c) => c.version === 2
    )) {
      const exchanges = parseExchanges([
        ...c.exchanges,
        ...c.address_exchanges,
      ]);
      const policy = new WalletPolicy(c.name, c.policy, c.keys);
      const [id, hmac] = await client(exchanges).registerWallet(policy);
      expect(exchanges).toHaveLength(0);
      expect(id).toEqual(policy.getId());
      expect(hmac.toString('hex')).toEqual(c.hmac);
    }
  });

  it('gets wallet addresses', async () => {
    for (const c of load('get_wallet_address.json')) {
      const exchanges = parseExchanges(c.exchanges);
      const address = await client(exchanges).getWalletAddress(
        new WalletPolicy(c.name, c.policy, c.keys),
        c.hmac ? Buffer.from(c.hmac, 'hex') : null,
        c.change ? 1 : 0,
        c.address_index,
        c.display
      );
      expect(exchanges).toHaveLength(0);
      expect(address).toEqual(c.address);
    }
  });

  it('gets extended pubkeys', async () => {
    for (const c of load('get_extended_pubkey.json')) {
      const exchanges = parseExchanges(c.exchanges);
      const xpub = await client(exchanges).getExtendedPubkey(
        c.derivation_path,
        c.display
      );
      expect(exchanges).toHaveLength(0);
      expect(xpub).toEqual(c.result);
    }
  });

  it('signs psbts, reporting progress', async () => {
    for (const c of load('sign_psbt.json')) {
      for (const psbt of [
        c.psbt,
        Buffer.from(c.psbt, 'base64'),
        { toBuffer: () => Buffer.from(c.psbt, 'base64') },
      ]) {
        const exchanges = parseExchanges(c.exchanges);
        let progress = 0;
        const results = await client(exchanges).signPsbt(
          psbt,
          new WalletPolicy(c.name, c.policy, c.keys),
          c.hmac ? Buffer.from(c.hmac, 'hex') : null,
          () => progress++
        );
        expect(exchanges).toHaveLength(0);
        expect(progress).toEqual(results.length);

        const sigs = c.sigs || [];
        const nonces = c.musig_pub_nonces || [];
        const musigSigs = c.musig_partial_signatures || [];
        expect(results).toHaveLength(
          sigs.length + nonces.length + musigSigs.length
        );
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        sigs.forEach((sig: any, i: number) => {
          const result = results[i][1] as PartialSignature;
          expect(result).toBeInstanceOf(PartialSignature);
          expect(result.pubkey.toString('hex')).toEqual(sig.key);
          expect(result.signature.toString('hex')).toEqual(sig.sig);
          expect(result.tapleafHash?.toString('hex')).toEqual(
            sig.tapleaf_hash
          );
        });
        for (const [, result] of results.slice(sigs.length)) {
          expect(
            result instanceof MusigPubNonce ||
              result instanceof MusigPartialSignature
          ).toBe(true);
        }
      }
    }
  });
});

describe('simple requests and errors', () => {
  const fingerprintApdu = Buffer.from('e105000100', 'hex');

  it('gets the master fingerprint and the version', async () => {
    expect(
      await client([
        { apdu: fingerprintApdu, response: Buffer.from('f5acc2fd9000', 'hex') },
      ]).getMasterFingerprint()
    ).toEqual('f5acc2fd');

    const version = Buffer.concat([
      Buffer.from([1, 12]),
      Buffer.from('Bitcoin Test'),
      Buffer.from([5]),
      Buffer.from('2.1.0'),
      Buffer.from([1, 2, 0x90, 0x00]),
    ]);
    expect(
      await client([
        { apdu: Buffer.from('b001000000', 'hex'), response: version },
      ]).getAppAndVersion()
    ).toEqual({
      name: 'Bitcoin Test',
      version: '2.1.0',
      flags: Buffer.from([2]),
    });
  });

  it('lets the transport report device errors', async () => {
    await expect(
      client([
        { apdu: fingerprintApdu, response: Buffer.from('6985', 'hex') },
      ]).getMasterFingerprint()
    ).rejects.toMatchObject({ statusCode: 0x6985 });
  });

  it('rejects invalid arguments before any exchange', async () => {
    const policy = new DefaultWalletPolicy(
      'tr(@0/**)',
      "[f5acc2fd/86'/1'/0']tpubDDKYE6BREvDsSWMazgHoyQWiJwYaDDYPbCFjYxN3HFXJP5fokeiK4hwK5tTLBNEDBwrDXn8cQ4v9b2xdW62Xr5yxoQdMu1v6c7UDXYVH27U"
    );
    const app = client([]);
    await expect(app.getWalletAddress(policy, null, 2, 0, false)).rejects.toThrow(
      'Change can only be 0 or 1'
    );
    await expect(app.getWalletAddress(policy, null, 0, -1, false)).rejects.toThrow(
      'Invalid address index'
    );
    await expect(
      app.getWalletAddress(policy, Buffer.alloc(31), 0, 0, false)
    ).rejects.toMatchObject({ code: 'InvalidArgument' });
    await expect(app.getExtendedPubkey('m/x')).rejects.toMatchObject({
      code: 'InvalidArgument',
    });
    await expect(
      app.signPsbt(Buffer.from('not a psbt'), policy, null)
    ).rejects.toMatchObject({ code: 'InvalidArgument' });
    expect(() => new WalletPolicy('', 'tr(@0/**)', ['not a key']).getId()).toThrow();
  });

  it('keeps the tag of unknown yields', async () => {
    const c = load('sign_psbt.json')[0];
    const first = parseExchanges(c.exchanges)[0];
    const yielded = Buffer.from('10fe0100008003090807e000', 'hex');
    const results = await client([
      { apdu: first.apdu, response: yielded },
      { apdu: Buffer.from('f801000100', 'hex'), response: Buffer.from('9000', 'hex') },
    ]).signPsbt(
      c.psbt,
      new WalletPolicy(c.name, c.policy, c.keys),
      c.hmac ? Buffer.from(c.hmac, 'hex') : null
    );
    expect(results).toEqual([
      [3, new UnknownSignPsbtYieldedObject(BigInt(0x80000001), Buffer.from([9, 8, 7]))],
    ]);
  });
});

describe('WalletPolicy', () => {
  it('serializes like the device', () => {
    const policy = new WalletPolicy(
      'Cold storage',
      'wsh(sortedmulti(2,@0/**,@1/**))',
      [
        "[76223a6e/48'/1'/0'/2']tpubDE7NQymr4AFtewpAsWtnreyq9ghkzQBXpCZjWLFVRAvnbf7vya2eMTvT2fPapNqL8SuVvLQdbUbMfWLVDCZKnsEBqp6UK93QEzL8Ck23AwF",
        "[f5acc2fd/48'/1'/0'/2']tpubDFAqEGNyad35aBCKUAXbQGDjdVhNueno5ZZVEn3sQbW5ci457gLR7HyTmHBg93oourBssgUxuWz1jX5uhc1qaqFo9VsybY1J5FuedLfm4dK",
      ]
    );
    expect(policy.serialize().toString('hex')).toEqual(
      '020c436f6c642073746f726167651fb56c3d5542fa09b3956834a9ff6a1df5c36a38e5b02c63c54b41a9a04403b82602516d2c50a89476ecffeec658057f0110674bbfafc18797dc480c7ed53802f3fb'
    );
    expect(policy.getId()).toHaveLength(32);
  });
});
