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

export type BIP32Path = {
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


