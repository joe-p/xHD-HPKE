import {
  BIP32DerivationType,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { type RecipientContextParams } from "@hpke/common";
import { CipherSuite, DhkemX25519HkdfSha256 } from "@hpke/core";
import { x25519 } from "@noble/curves/ed25519.js";
import { getPath } from ".";
import { buf } from "./utils";

const xhd = new XHDWalletAPI();
let kem: DhkemX25519HkdfSha256;

function getKem(): DhkemX25519HkdfSha256 {
  if (!kem) {
    kem = new DhkemX25519HkdfSha256();
  }
  return kem;
}

export async function deriveX25519Keypair(
  rootKey: Uint8Array,
  account: number,
  index: number,
  derivationType: BIP32DerivationType = BIP32DerivationType.Peikert
): Promise<CryptoKeyPair> {
  const xHdPrivateKeyBytes = await xhd.deriveKey(
    rootKey,
    getPath(account, index).array,
    true,
    derivationType,
  );

  const scalar = xHdPrivateKeyBytes.slice(0, 32);

  const kem = getKem();

  return {
    publicKey: await kem.deserializePublicKey(
      x25519.getPublicKey(scalar),
    ),
    privateKey: await kem.deserializePrivateKey(scalar),
  };
}

export async function encrypt(
  suite: CipherSuite,
  plaintext: Uint8Array,
  receiverCurve25519Pubkey: CryptoKey,
  senderAuthKeypair?: CryptoKeyPair,
): Promise<{ ciphertext: Uint8Array; enc: Uint8Array }> {
  const sender = await suite.createSenderContext({
    recipientPublicKey: receiverCurve25519Pubkey,
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
  sender?: CryptoKey
}): Promise<Uint8Array> {
  const keyPair = await deriveX25519Keypair(
    rootKey,
    account,
    index,
  )

  const context: RecipientContextParams = {
    recipientKey: keyPair.privateKey,
    enc: buf(enc),
    senderPublicKey: sender
  }

  const recipient = await suite.createRecipientContext(context);

  return new Uint8Array(await recipient.open(buf(ciphertext)));
}

