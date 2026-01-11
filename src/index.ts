import {
  BIP32DerivationType,
  fromSeed,
  harden,
  KeyContext,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { Dhkem, type DhkemPrimitives, type KdfInterface } from "@hpke/common";
import { HkdfSha256, KemId } from "@hpke/core";
import { ed25519 } from "@noble/curves/ed25519.js";

export type PublicXHDKey = CryptoKey & {
  type: "public";
  publicKey: Uint8Array;
};
export type PrivateXHDKey = CryptoKey & {
  type: "private";
  rootKey: Uint8Array;
  account: number;
  index: number;
};
export type XHDKeyPair = {
  publicKey: PublicXHDKey;
  privateKey: PrivateXHDKey;
};

export class xHdECDH implements DhkemPrimitives {
  private _xhd: XHDWalletAPI;

  constructor(hkdf: KdfInterface) {
    this._xhd = new XHDWalletAPI();
  }

  async serializePublicKey(key: PublicXHDKey): Promise<ArrayBuffer> {
    return key.publicKey.buffer.slice(
      key.publicKey.byteOffset,
      key.publicKey.byteOffset + key.publicKey.byteLength,
    );
  }

  async deserializePublicKey(key: ArrayBuffer): Promise<PublicXHDKey> {
    return {
      type: "public",
      publicKey: new Uint8Array(key),
      algorithm: { name: "xHD" },
      extractable: true,
      usages: [],
    };
  }

  async serializePrivateKey(key: PrivateXHDKey): Promise<ArrayBuffer> {
    const sk = await this._xhd.deriveKey(
      key.rootKey,
      [harden(44), harden(283), harden(key.account), 0, key.index],
      true,
      BIP32DerivationType.Peikert,
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
    const rootKey = fromSeed(seed);

    const publicKey = await this._xhd.keyGen(
      rootKey,
      KeyContext.Address,
      0,
      0,
      BIP32DerivationType.Peikert,
    );

    const privateKey: PrivateXHDKey = {
      type: "private",
      rootKey: rootKey,
      account: 0,
      index: 0,
      algorithm: { name: "xHD" },
      extractable: false,
      usages: ["deriveBits"],
    };

    const publicXHDKey: PublicXHDKey = {
      type: "public",
      publicKey: publicKey,
      algorithm: { name: "xHD" },
      extractable: true,
      usages: [],
    };

    return {
      publicKey: publicXHDKey,
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
  async derivePublicKey(key: PrivateXHDKey): Promise<PublicXHDKey> {
    const pub = await this._xhd.keyGen(
      key.rootKey,
      KeyContext.Address,
      key.account,
      key.index,
      BIP32DerivationType.Peikert,
    );

    return {
      type: "public",
      publicKey: pub,
      algorithm: { name: "xHD" },
      extractable: true,
      usages: [],
    };
  }

  async dh(sk: PrivateXHDKey, pk: PublicXHDKey): Promise<ArrayBuffer> {
    const secret = await this._xhd.ECDHRaw(
      sk.rootKey,
      KeyContext.Address,
      sk.account,
      sk.index,
      ed25519.utils.toMontgomery(pk.publicKey),
    );

    return secret;
  }
}

export class DhkemPeikertXhdHkdfSha256 extends Dhkem {
  /** TODO: figure out what I should use as KemId. Does it matter? */
  override id: KemId = 1337 as KemId;
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
    super(1337 as KemId, new xHdECDH(kdf), kdf);
  }
}
