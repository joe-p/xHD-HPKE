import {
  BIP32DerivationType,
  harden,
  XHDWalletAPI,
} from "@algorandfoundation/xhd-wallet-api";
import { type RecipientContextParams } from "@hpke/common";
import { CipherSuite, DhkemX25519HkdfSha256 } from "@hpke/core";
import { x25519 } from "@noble/curves/ed25519.js";
import { buf } from "./utils";

const xhd = new XHDWalletAPI();
let kem: DhkemX25519HkdfSha256;

function getKem(): DhkemX25519HkdfSha256 {
  if (!kem) {
    kem = new DhkemX25519HkdfSha256();
  }
  return kem;
}

/**
 * Derives an X25519 keypair from the given root key and account index. It should be noted that no soft-derivatins
 * are done to ensure the scalar is clamped for X25519 usage.
 * @param rootKey - The root key (master private key) as a Uint8Array.
 * @param account - The account index for derivation.
 * @param derivationType - The BIP32 derivation type (default is Peikert).
 * @returns A Promise that resolves to a CryptoKeyPair containing the derived X25519 public and private keys.
 */
export async function deriveX25519Keypair(
  rootKey: Uint8Array,
  account: number,
  derivationType: BIP32DerivationType = BIP32DerivationType.Peikert
): Promise<CryptoKeyPair> {
  const xHdPrivateKeyBytes = await xhd.deriveKey(
    rootKey,
    [
      harden(20_000), // we're using 20_000 as purpose since satoshi labs reserves up to 19_999
      harden(account), // hardened derivation for the account
    ],
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
  recipientPrivateKey,
  sender
}: {
  suite: CipherSuite;
  ciphertext: Uint8Array;
  enc: Uint8Array;
  recipientPrivateKey: CryptoKey;
  sender?: CryptoKey
}): Promise<Uint8Array> {
  const context: RecipientContextParams = {
    recipientKey: recipientPrivateKey,
    enc: buf(enc),
    senderPublicKey: sender
  }

  const recipient = await suite.createRecipientContext(context);

  return new Uint8Array(await recipient.open(buf(ciphertext)));
}

