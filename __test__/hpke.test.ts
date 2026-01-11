import {
  BIP32DerivationType,
  fromSeed,
  KeyContext,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";
import { CipherSuite, HkdfSha512 } from "@hpke/core";
import { DhkemPeikertXhdHkdfSha256, type PrivateXHDKey } from "../src";
import { describe, expect, it } from "vitest";

describe("xHD HPKE", () => {
  it("should encrypt and decrypt a message using HPKE with xHD keys", async () => {
    const xhd = new XHDWalletAPI();

    const suite = new CipherSuite({
      kem: new DhkemPeikertXhdHkdfSha256(),
      kdf: new HkdfSha512(),
      aead: new Chacha20Poly1305(),
    });

    const receiverSeed = new Uint8Array(32);
    crypto.getRandomValues(receiverSeed);
    const receiverRoot = fromSeed(receiverSeed);
    const receiverEd25519 = await xhd.keyGen(
      receiverRoot,
      KeyContext.Address,
      0,
      0,
      BIP32DerivationType.Peikert,
    );

    // A sender encrypts a message with the recipient public key.
    const sender = await suite.createSenderContext({
      recipientPublicKey: await suite.kem.deserializePublicKey(receiverEd25519),
    });
    const ct = await sender.seal(
      new TextEncoder().encode("Hello world!").buffer,
    );

    // The recipient decrypts it.
    const recipient = await suite.createRecipientContext({
      recipientKey: {
        rootKey: receiverRoot,
        account: 0,
        index: 0,
      } as PrivateXHDKey,
      enc: sender.enc,
    });
    const pt = await recipient.open(ct);

    // Hello world!
    expect(new TextDecoder().decode(pt)).toBe("Hello world!");
  });
});
