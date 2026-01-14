import {
  BIP32DerivationType,
  fromSeed,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, HkdfSha512 } from "@hpke/core";
import {
  decrypt,
  deriveX25519Keypair,
  DhkemXhdX25519HkdfSha256,
  encrypt,
} from "../src/xhd_x25519";
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { getPath } from "../src";

function buf(arr: Uint8Array): Buffer {
  return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength);
}

describe("xHD HPKE", () => {
  it("should encrypt and decrypt a message using HPKE with xHD keys", async () => {
    const suite = new CipherSuite({
      kem: new DhkemXhdX25519HkdfSha256(),
      kdf: new HkdfSha512(),
      aead: new Chacha20Poly1305(),
    });

    const receiverSeed = new Uint8Array(32);
    crypto.getRandomValues(receiverSeed);
    const receiverRoot = fromSeed(buf(receiverSeed));
    const receiverKeypair = await deriveX25519Keypair(receiverRoot, 0, 0);

    // A sender encrypts a message with the recipient public key.
    const sender = await suite.createSenderContext({
      recipientPublicKey: receiverKeypair.publicKey,
    });

    const ct = await sender.seal(
      new TextEncoder().encode("Hello world!").buffer,
    );

    // The recipient decrypts it.
    const recipient = await suite.createRecipientContext({
      recipientKey: receiverKeypair.privateKey,
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
    const receiverKeypair = await deriveX25519Keypair(receiverRoot, 0, 0);

    const { ciphertext, enc } = await encrypt(
      new TextEncoder().encode("Hello HPKE!"),
      receiverKeypair.publicKey.key
    );

    const plaintext = await decrypt({
      ciphertext,
      enc,
      rootKey: receiverRoot,
      account: 0,
      index: 0,
    });

    expect(new TextDecoder().decode(plaintext)).toBe("Hello HPKE!");
  });

  it("encrypt/decrypt functions with auth", async () => {
    const senderSeed = new Uint8Array(32);
    crypto.getRandomValues(senderSeed);
    const senderRoot = fromSeed(buf(senderSeed));
    const senderKeypair = await deriveX25519Keypair(senderRoot, 0, 0);

    const receiverSeed = new Uint8Array(32);
    crypto.getRandomValues(receiverSeed);
    const receiverRoot = fromSeed(buf(receiverSeed));
    const receiverKeypair = await deriveX25519Keypair(receiverRoot, 0, 0);

    const { ciphertext, enc } = await encrypt(
      new TextEncoder().encode("Hello HPKE!"),
      receiverKeypair.publicKey.key,
      senderKeypair
    );

    const plaintext = await decrypt({
      sender: senderKeypair.publicKey.key,
      ciphertext,
      enc,
      rootKey: receiverRoot,
      account: 0,
      index: 0,
    });

    expect(new TextDecoder().decode(plaintext)).toBe("Hello HPKE!");
  });
});
