import {
  fromSeed,
} from "@algorandfoundation/xhd-wallet-api";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
import {
  decrypt,
  deriveX25519Keypair,
  encrypt,
} from "../src/xhd_x25519";
import { describe, expect, it } from "vitest";

function buf(arr: Uint8Array): Buffer {
  return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength);
}

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

describe("xHD HPKE", () => {
  it("encrypt/decrypt functions", async () => {
    const receiverSeed = new Uint8Array(32);
    crypto.getRandomValues(receiverSeed);
    const receiverRoot = fromSeed(buf(receiverSeed));
    const receiverKeypair = await deriveX25519Keypair(receiverRoot, 0, 0);

    const { ciphertext, enc } = await encrypt(
      suite,
      new TextEncoder().encode("Hello HPKE!"),
      receiverKeypair.publicKey
    );

    const plaintext = await decrypt({
      suite,
      ciphertext,
      enc,
      recipientPrivateKey: receiverKeypair.privateKey,
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
      suite,
      new TextEncoder().encode("Hello HPKE!"),
      receiverKeypair.publicKey,
      senderKeypair
    );

    const plaintext = await decrypt({
      suite,
      sender: senderKeypair.publicKey,
      ciphertext,
      enc,
      recipientPrivateKey: receiverKeypair.privateKey,
    });

    expect(new TextDecoder().decode(plaintext)).toBe("Hello HPKE!");
  });

  it("non-xhd encrypt with xhd decrypt with auth", async () => {
    const senderKeypair = await suite.kem.generateKeyPair();

    const receiverSeed = new Uint8Array(32);
    crypto.getRandomValues(receiverSeed);
    const receiverRoot = fromSeed(buf(receiverSeed));
    const receiverKeypair = await deriveX25519Keypair(receiverRoot, 0, 0);
    const senderPub = senderKeypair.publicKey

    const sender = await suite.createSenderContext({
      recipientPublicKey: receiverKeypair.publicKey,

      senderKey: senderKeypair,
    })

    const ciphertext = await sender.seal(
      new TextEncoder().encode("Hello HPKE!").buffer,
    );

    const plaintext = await decrypt({
      suite,
      sender: senderPub,
      ciphertext: new Uint8Array(ciphertext),
      enc: new Uint8Array(sender.enc),
      recipientPrivateKey: receiverKeypair.privateKey,
    });

    expect(new TextDecoder().decode(plaintext)).toBe("Hello HPKE!");
  });

  it("xhd encrypt with non-xhd decrypt with auth", async () => {
    const senderSeed = new Uint8Array(32);
    crypto.getRandomValues(senderSeed);
    const senderRoot = fromSeed(buf(senderSeed));
    const senderKeypair = await deriveX25519Keypair(senderRoot, 0, 0);

    const receiverKeypair = await suite.kem.generateKeyPair();
    const receiverPub = receiverKeypair.publicKey;

    const { ciphertext, enc } = await encrypt(
      suite,
      new TextEncoder().encode("Hello HPKE!"),
      receiverPub,
      senderKeypair
    );

    const recipient = await suite.createRecipientContext({
      recipientKey: receiverKeypair.privateKey,
      enc,
      senderPublicKey: senderKeypair.publicKey,
    });

    const plaintext = await recipient.open(ciphertext);

    expect(new TextDecoder().decode(plaintext)).toBe("Hello HPKE!");
  });
});
