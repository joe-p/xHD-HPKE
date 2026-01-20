import {
  BIP32DerivationType,
  fromSeed,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { Dhkem, XCryptoKey, type DhkemPrimitives, type RecipientContextParams } from "@hpke/common";
import { CipherSuite, HkdfSha256, KemId } from "@hpke/core";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { getPath, PrivateXHDKey, type BIP32Path, type XHDKeyPair } from ".";
import { buf } from "./utils";
import { bytesToNumberLE } from "@noble/curves/utils.js";
import { mod } from "@noble/curves/abstract/modular.js";

const xhd = new XHDWalletAPI();

async function getPublicX25519Key(sk: PrivateXHDKey): Promise<XCryptoKey> {
  const scalar = bytesToNumberLE(sk.key.slice(0, 32));
  const clearedTopBitScalar = scalar & ((1n << 255n) - 1n);
  const reducedScalar = mod(clearedTopBitScalar, ed25519.Point.Fn.ORDER);

  const ed25519Pub = ed25519.Point.BASE.multiply(reducedScalar);
  const pubX25519 = ed25519.utils.toMontgomery(ed25519Pub.toBytes());

  return new XCryptoKey("X25519", pubX25519, "public");
}

export async function deriveX25519Keypair(rootKey: Uint8Array, account: number, index: number, derivationType: BIP32DerivationType = BIP32DerivationType.Peikert): Promise<XHDKeyPair> {
  const privateKeyBytes = await xhd.deriveKey(
    rootKey,
    getPath(account, index).array,
    true,
    derivationType,
  );

  const privateKey = new PrivateXHDKey(privateKeyBytes)

  return {
    publicKey: await getPublicX25519Key(privateKey),
    privateKey,
  };
}

export class xHdX25519 implements DhkemPrimitives {
  private _derivationType: BIP32DerivationType;
  private _generatedPath: BIP32Path;

  constructor(options: { derivationType?: BIP32DerivationType, account?: number, index?: number } = {}) {
    this._derivationType = options.derivationType ?? BIP32DerivationType.Peikert;
    this._generatedPath = getPath(options.account ?? 0, options.index ?? 0);
  }

  async serializePublicKey(key: XCryptoKey): Promise<ArrayBuffer> {
    return key.key.buffer.slice(
      key.key.byteOffset,
      key.key.byteOffset + key.key.byteLength,
    );
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
    return key.key;
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

    const privateKeyBytes = await xhd.deriveKey(
      rootKey,
      [
        this._generatedPath.purpose,
        this._generatedPath.coinType,
        this._generatedPath.account,
        this._generatedPath.change,
        this._generatedPath.index,
      ],
      true,
      this._derivationType,
    );

    const privateKey = new PrivateXHDKey(privateKeyBytes)

    return {
      publicKey: await getPublicX25519Key(privateKey),
      privateKey,
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
    return getPublicX25519Key(key);
  }

  async dh(sk: PrivateXHDKey, pk: XCryptoKey): Promise<ArrayBuffer> {
    const scalar = sk.key.slice(0, 32);
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

export async function encrypt(
  suite: CipherSuite,
  plaintext: Uint8Array,
  receiverCurve25519Pubkey: Uint8Array,
  senderAuthKeypair?: XHDKeyPair,
): Promise<{ ciphertext: Uint8Array; enc: Uint8Array }> {
  const sender = await suite.createSenderContext({
    recipientPublicKey: await suite.kem.deserializePublicKey(
      receiverCurve25519Pubkey,
    ),
    senderKey: senderAuthKeypair,
  });

  return {
    ciphertext: new Uint8Array(await sender.seal(plaintext)),
    enc: new Uint8Array(sender.enc),
  };
}

export async function decrypt({
  suite,
  ciphertext,
  enc,
  rootKey,
  account,
  index,
  sender
}: {
  suite: CipherSuite;
  ciphertext: Uint8Array;
  enc: Uint8Array;
  rootKey: Uint8Array;
  account: number;
  index: number;
  sender?: Uint8Array
}): Promise<Uint8Array> {
  const path = getPath(account, index);
  const privateKeyBytes = await xhd.deriveKey(
    rootKey,
    path.array,
    true,
    BIP32DerivationType.Peikert,
  );

  const context: RecipientContextParams = {
    recipientKey: new PrivateXHDKey(privateKeyBytes),
    enc: buf(enc),
  }

  if (sender) {
    context.senderPublicKey = await suite.kem.deserializePublicKey(buf(sender));
  }

  const recipient = await suite.createRecipientContext(context);

  return new Uint8Array(await recipient.open(buf(ciphertext)));
}

