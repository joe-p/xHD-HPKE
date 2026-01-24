import {
  harden,
} from "@algorandfoundation/xhd-wallet-api";
import { XCryptoKey } from "@hpke/common";

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



