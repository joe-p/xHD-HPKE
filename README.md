# xHD-HPKE

This repo contains an X25519 DH KEM (Diffie-Hellman Key Encapsulation Mechanism) implementation that uses Algorand's xHD key derivation scheme for key derivation. It is intended for use with hpke-js. This implementation supports xHD key derivation, but otherwise is a standard X25119 DH KEM. This means this module is interoperable with any HPKE protocol that uses X25519 KEM, regardless of whether they use xHD key derivation or not.

For the HPKE specification, see [RFC 9180](https://datatracker.ietf.org/doc/rfc9180/).

For a non-normative introduction to HPKE, see [this blog post](https://blog.cloudflare.com/hybrid-public-key-encryption/).

For a list of standard HPKE suites, see [HPKE's IANA page](https://www.iana.org/assignments/hpke/hpke.xhtml).

## Disclaimer

This is a very early prototype and should not be used in production. It has not been audited for security.

## Example

In addition to the lower-level KEM implementation, there are high-level functions for making encryption and decryption easier:

To encrypt a with just the receiver's public key:

```ts
const suite = new CipherSuite({
  kem: new DhkemXhdX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

const { ciphertext, enc } = await encrypt(
  suite,
  new TextEncoder().encode("Hello HPKE!"),
  receiverPublicX25519,
);
```

Then to decrypt it with the receiver's secret root key and derivation account/index:

```ts
const plaintext = await decrypt({
  suite
  ciphertext,
  enc,
  rootKey: receiverRoot,
  account: 0,
  index: 0,
});

console.log(new TextDecoder().decode(plaintext)); // Hello HPKE!
```

### Auth Mode

This implementation also supports auth mode. To encrypt with auth mode, provide the sender's keypair to the `encrypt` function. On the decryption side, provide the sender's public key to the `decrypt` function.

```ts
const suite = new CipherSuite({
  kem: new DhkemXhdX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

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
  receiverKeypair.publicKey.key,
  senderKeypair
);

const plaintext = await decrypt({
  suite,
  sender: senderKeypair.publicKey.key,
  ciphertext,
  enc,
  rootKey: receiverRoot,
  account: 0,
  index: 0,
});

expect(new TextDecoder().decode(plaintext)).toBe("Hello HPKE!");
```
