import {
  BIP32DerivationType,
  fromSeed,
  harden,
  KeyContext,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { Dhkem, XCryptoKey, type DhkemPrimitives } from "@hpke/common";
import { CipherSuite, HkdfSha256, KemId } from "@hpke/core";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";

type BIP32Path = {
  purpose: number,
  coinType: number,
  account: number,
  change: number,
  index: number
}

/**
 * Generate the BIP32 path for 20_000' / 0' / account' / 0 / index
 * @param account The account number
 * @param index The index number
 * @returns The BIP32 path
 */
export function getPath(account: number, index: number): BIP32Path & { array: [number, number, number, number, number] } {
  const path = {
    purpose: harden(20_000), // we're using 20_000 as purpose since satoshi labs reserves up to 19_999
    coinType: harden(0),
    account: harden(account),
    change: 0,
    index: index,
  };

  return { ...path, array: [path.purpose, path.coinType, path.account, path.change, path.index] };
}
export type PrivateXHDKey = CryptoKey & {
  type: "private";
  rootKey: Uint8Array;
  derivation: BIP32DerivationType;
} & BIP32Path;

export type XHDKeyPair = {
  publicKey: XCryptoKey;
  privateKey: PrivateXHDKey;
};

function buf(arr: Uint8Array): Buffer {
  return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength);
}

export class xHdX25519 implements DhkemPrimitives {
  private _xhd: XHDWalletAPI;
  private _derivationType: BIP32DerivationType;
  private _generatedPath: BIP32Path;

  constructor(options: { derivationType?: BIP32DerivationType, generatedPath?: BIP32Path } = {}) {
    this._xhd = new XHDWalletAPI();
    this._derivationType = options.derivationType ?? BIP32DerivationType.Peikert;
    this._generatedPath = options.generatedPath ?? getPath(0, 0);
  }

  async serializePublicKey(key: XCryptoKey): Promise<ArrayBuffer> {
    console.debug({ key })
    const pk = key.key.buffer.slice(
      key.key.byteOffset,
      key.key.byteOffset + key.key.byteLength,
    );

    console.debug("Serialized Public Key:", Buffer.from(pk).toString("hex"));

    return pk;
  }

  async deserializePublicKey(key: ArrayBuffer): Promise<XCryptoKey> {
    return {
      type: "public",
      key: new Uint8Array(key),
      algorithm: { name: "X25519" },
      extractable: true,
      usages: [],
    };
  }

  async serializePrivateKey(key: PrivateXHDKey): Promise<ArrayBuffer> {
    const sk = await this._xhd.deriveKey(
      key.rootKey,
      [key.purpose, key.coinType, key.account, key.change, key.index],
      true,
      this._derivationType,
    );

    return sk.buffer;
  }

  async deserializePrivateKey(key: ArrayBuffer): Promise<CryptoKey> {
    throw new Error("deserializePrivateKey not implemented.");
  }

  async importKey(
    format: "raw" | "jwk",
    key: ArrayBuffer | JsonWebKey,
    isPublic: boolean,
  ): Promise<CryptoKey> {
    throw new Error("importKey not implemented.");
  }

  async generateKeyPair(): Promise<XHDKeyPair> {
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    const rootKey = fromSeed(buf(seed));

    const privateKey: PrivateXHDKey = {
      ...this._generatedPath,
      derivation: this._derivationType,
      type: "private",
      rootKey: rootKey,
      algorithm: { name: "xHD" },
      extractable: false,
      usages: ["deriveBits"],
    };

    const pubkeyEd25519 = (await this._xhd.deriveKey(
      rootKey,
      [
        this._generatedPath.purpose,
        this._generatedPath.coinType,
        this._generatedPath.account,
        this._generatedPath.change,
        this._generatedPath.index,
      ],
      false,
      this._derivationType,
    )).slice(0, 32);

    const pubkeyX25519 = ed25519.utils.toMontgomery(pubkeyEd25519);

    const publicKey = new XCryptoKey("X25519", pubkeyX25519, "public")

    return {
      publicKey: publicKey,
      privateKey: privateKey,
    };
  }

  async deriveKeyPair(ikm: ArrayBuffer): Promise<CryptoKeyPair> {
    throw new Error("deriveKeyPair not implemented.");
  }

  /**
   * Derives the public key from the given private key.
   * @param key The private key.
   * @returns The derived public key.
   */
  async derivePublicKey(key: PrivateXHDKey): Promise<XCryptoKey> {
    const ed25519Pub = (await this._xhd.deriveKey(
      key.rootKey,
      [key.purpose, key.coinType, key.account, key.change, key.index],
      false,
      this._derivationType,
    )).slice(0, 32);

    const pubX25519 = ed25519.utils.toMontgomery(ed25519Pub);

    return {
      type: "public",
      key: pubX25519,
      algorithm: { name: "X25519" },
      extractable: true,
      usages: [],
    };
  }

  async dh(sk: PrivateXHDKey, pk: XCryptoKey): Promise<ArrayBuffer> {
    const childSecret = await this._xhd.deriveKey(sk.rootKey, [sk.purpose, sk.coinType, sk.account, sk.change, sk.index], true, this._derivationType);
    const scalar = childSecret.slice(0, 32);

    return x25519.getSharedSecret(scalar, pk.key);
  }
}

export class DhkemXhdX25519HkdfSha256 extends Dhkem {
  override id: KemId = KemId.DhkemX25519HkdfSha256;
  /** 32 */
  override secretSize: number = 32;
  /** 32 */
  override encSize: number = 32;
  /** 32 */
  override publicKeySize: number = 32;
  /** 32 */
  override privateKeySize: number = 32;

  constructor() {
    const kdf = new HkdfSha256();
    super(KemId.DhkemX25519HkdfSha256, new xHdX25519(), kdf);
  }
}

export async function encryptWithXhdHpke(
  plaintext: Uint8Array,
  receiverCurve25519Pubkey: Uint8Array,
): Promise<{ ciphertext: Uint8Array; enc: Uint8Array }> {
  const suite = new CipherSuite({
    kem: new DhkemXhdX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });

  console.debug("Receiver Curve25519 Pubkey:", Buffer.from(receiverCurve25519Pubkey).toString("hex"));

  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(
      receiverCurve25519Pubkey,
    ),
  });

  return {
    ciphertext: new Uint8Array(await sender.seal(plaintext)),
    enc: new Uint8Array(sender.enc),
  };
}

export async function decryptWithXhdHpke({
  ciphertext,
  enc,
  rootKey,
  account,
  index,
}: {
  ciphertext: Uint8Array;
  enc: Uint8Array;
  rootKey: Uint8Array;
  account: number;
  index: number;
}): Promise<Uint8Array> {
  const suite = new CipherSuite({
    kem: new DhkemXhdX25519HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Chacha20Poly1305(),
  });

  const recipient = await suite.createRecipientContext({
    recipientKey: {
      type: "private",
      ...getPath(account, index),
      derivation: BIP32DerivationType.Peikert,
      rootKey: rootKey,
      algorithm: { name: "xHD" },
      extractable: false,
      usages: [],
    } as PrivateXHDKey,
    enc: buf(enc),
  });

  return new Uint8Array(await recipient.open(buf(ciphertext)));
}
