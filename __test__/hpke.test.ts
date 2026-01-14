import {
  fromSeed,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, DhkemX25519HkdfSha256, HkdfSha256, HkdfSha512 } from "@hpke/core";
import {
  decrypt,
  deriveX25519Keypair,
  DhkemXhdX25519HkdfSha256,
  encrypt,
} from "../src/xhd_x25519";
import { describe, expect, it } from "vitest";

function buf(arr: Uint8Array): Buffer {
  return Buffer.from(arr.buffer, arr.byteOffset, arr.byteLength);
}

const xHDSuite = new CipherSuite({
  kem: new DhkemXhdX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

const nonXhdSuite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

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
      xHDSuite,
      new TextEncoder().encode("Hello HPKE!"),
      receiverKeypair.publicKey.key
    );

    const plaintext = await decrypt({
      suite: xHDSuite,
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
      xHDSuite,
      new TextEncoder().encode("Hello HPKE!"),
      receiverKeypair.publicKey.key,
      senderKeypair
    );

    const plaintext = await decrypt({
      suite: xHDSuite,
      sender: senderKeypair.publicKey.key,
      ciphertext,
      enc,
      rootKey: receiverRoot,
      account: 0,
      index: 0,
    });

    expect(new TextDecoder().decode(plaintext)).toBe("Hello HPKE!");
  });

  it("non-xhd encrypt with xhd decrypt with auth", async () => {
    const senderKeypair = await nonXhdSuite.kem.generateKeyPair();

    const receiverSeed = new Uint8Array(32);
    crypto.getRandomValues(receiverSeed);
    const receiverRoot = fromSeed(buf(receiverSeed));
    const receiverKeypair = await deriveX25519Keypair(receiverRoot, 0, 0);
    const senderPub = await nonXhdSuite.kem.serializePublicKey(senderKeypair.publicKey)

    const sender = await nonXhdSuite.createSenderContext({
      recipientPublicKey: await nonXhdSuite.kem.deserializePublicKey(
        receiverKeypair.publicKey.key,
      ),
      senderKey: senderKeypair,
    })

    const ciphertext = await sender.seal(
      new TextEncoder().encode("Hello HPKE!").buffer,
    );

    const plaintext = await decrypt({
      suite: xHDSuite,
      sender: new Uint8Array(senderPub),
      ciphertext: new Uint8Array(ciphertext),
      enc: new Uint8Array(sender.enc),
      rootKey: receiverRoot,
      account: 0,
      index: 0,
    });

    expect(new TextDecoder().decode(plaintext)).toBe("Hello HPKE!");
  });

  it("xhd encrypt with non-xhd decrypt with auth", async () => {
    const senderSeed = new Uint8Array(32);
    crypto.getRandomValues(senderSeed);
    const senderRoot = fromSeed(buf(senderSeed));
    const senderKeypair = await deriveX25519Keypair(senderRoot, 0, 0);

    const receiverKeypair = await nonXhdSuite.kem.generateKeyPair();
    const receiverPub = await nonXhdSuite.kem.serializePublicKey(receiverKeypair.publicKey);

    const { ciphertext, enc } = await encrypt(
      xHDSuite,
      new TextEncoder().encode("Hello HPKE!"),
      new Uint8Array(receiverPub),
      senderKeypair
    );

    const recipient = await nonXhdSuite.createRecipientContext({
      recipientKey: receiverKeypair.privateKey,
      enc,
      senderPublicKey: await nonXhdSuite.kem.deserializePublicKey(
        senderKeypair.publicKey.key
      ),
    });

    const plaintext = await recipient.open(ciphertext);

    expect(new TextDecoder().decode(plaintext)).toBe("Hello HPKE!");
  });
});
