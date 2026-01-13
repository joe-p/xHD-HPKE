import {
  BIP32DerivationType,
  fromSeed,
  KeyContext,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, HkdfSha512 } from "@hpke/core";
import {
  decryptWithXhdHpke,
  DhkemXhdX25519HkdfSha256,
  encryptWithXhdHpke,
  getPath,
  type PrivateXHDKey,
} from "../src";
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";

function buf(arr: Uint8Array): Buffer {
  return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength);
}

describe("xHD HPKE", () => {
  it("should encrypt and decrypt a message using HPKE with xHD keys", async () => {
    const xhd = new XHDWalletAPI();

    const suite = new CipherSuite({
      kem: new DhkemXhdX25519HkdfSha256(),
      kdf: new HkdfSha512(),
      aead: new Chacha20Poly1305(),
    });

    const receiverSeed = new Uint8Array(32);
    crypto.getRandomValues(receiverSeed);
    const receiverRoot = fromSeed(buf(receiverSeed));
    const receiverEd25519 = (await xhd.deriveKey(receiverRoot, getPath(0, 0).array, false, BIP32DerivationType.Peikert)).slice(0, 32);
    const receiverX25519 = ed25519.utils.toMontgomery(receiverEd25519);

    // A sender encrypts a message with the recipient public key.
    const sender = await suite.createSenderContext({
      recipientPublicKey: await suite.kem.deserializePublicKey(receiverX25519),
    });

    const ct = await sender.seal(
      new TextEncoder().encode("Hello world!").buffer,
    );

    // The recipient decrypts it.
    const recipient = await suite.createRecipientContext({
      recipientKey: {
        rootKey: receiverRoot,
        type: "private",
        derivation: BIP32DerivationType.Peikert,
        algorithm: { name: "xHD" },
        extractable: false,
        usages: [],
        ...getPath(0, 0),
      } as PrivateXHDKey,
      enc: sender.enc,
    });
    const pt = await recipient.open(ct);

    // Hello world!
    expect(new TextDecoder().decode(pt)).toBe("Hello world!");
  });

  it("encrypt/decrypt functions", async () => {
    const xhd = new XHDWalletAPI();

    const receiverSeed = new Uint8Array(32);
    crypto.getRandomValues(receiverSeed);
    const receiverRoot = fromSeed(buf(receiverSeed));
    const receiverPublicEd25519 = (await xhd.deriveKey(receiverRoot, getPath(0, 0).array, false, BIP32DerivationType.Peikert)).slice(0, 32);

    const { ciphertext, enc } = await encryptWithXhdHpke(
      new TextEncoder().encode("Hello HPKE!"),
      ed25519.utils.toMontgomery(receiverPublicEd25519),
    );

    const plaintext = await decryptWithXhdHpke({
      ciphertext,
      enc,
      rootKey: receiverRoot,
      account: 0,
      index: 0,
    });

    expect(new TextDecoder().decode(plaintext)).toBe("Hello HPKE!");
  });
});
