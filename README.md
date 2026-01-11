# xHD-HPKE

This repo contains an DH KEM (Diffie-Hellman Key Encapsulation Mechanism) that uses Algorand's xHD key derivation scheme. It is intended for use with hpke-js.

## Disclaimer

This is a very early prototype and should not be used in production. It has not been audited for security.

## Example

In addition to the lower-level KEM implementation, there are high-level functions for making encryption and decryption easier:

To encrypt a with just the receiver's public key:

```ts
const { ciphertext, enc } = await encryptWithXhdHpke(
  new TextEncoder().encode("Hello HPKE!"),
  receiverPublicEd25519,
);
```

Then to decrypt it with the receiver's secret root key and derivation account/index:

```ts
const plaintext = await decryptWithXhdHpke({
  ciphertext,
  enc,
  rootKey: receiverRoot,
  account: 0,
  index: 0,
});

console.log(new TextDecoder().decode(plaintext)); // Hello HPKE!
```
