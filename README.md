# xHD-HPKE

This repo contains an X25519 DH KEM (Diffie-Hellman Key Encapsulation Mechanism) implementation that uses Algorand's xHD key derivation scheme for key derivation. It is intended for use with hpke-js. This implementation supports xHD key derivation, but otherwise is standard X25119 DH KEM. This means this module is interoperable with any HPKE protocol that uses X25519 KEM, regardless of whether they use xHD key derivation or not.

For the HPKE specification, see [RFC 9180](https://datatracker.ietf.org/doc/rfc9180/).

For a non-normative introduction to HPKE, see [this blog post](https://blog.cloudflare.com/hybrid-public-key-encryption/).

For a list of standard HPKE suites, see [HPKE's IANA page](https://www.iana.org/assignments/hpke/hpke.xhtml).

## Disclaimer

This is a very early prototype and should not be used in production. It has not been audited for security.

## Example

In addition to the lower-level KEM implementation, there are high-level functions for making encryption and decryption easier:

To encrypt a with just the receiver's public key:

```ts
const { ciphertext, enc } = await encrypt(
  new TextEncoder().encode("Hello HPKE!"),
  receiverPublicX25519,
);
```

Then to decrypt it with the receiver's secret root key and derivation account/index:

```ts
const plaintext = await decrypt({
  ciphertext,
  enc,
  rootKey: receiverRoot,
  account: 0,
  index: 0,
});

console.log(new TextDecoder().decode(plaintext)); // Hello HPKE!
```
