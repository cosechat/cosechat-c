# cosechat

Post-quantum mesh chat protocol for microcontrollers and desktop. Inspired by [Reticulum](https://reticulum.network/) / LXMF.

Wire format is CBOR. Crypto is COSE. No dynamic allocation — safe for ESP32.

## Features

- **Addresses** — 16-byte, derived from ML-DSA-44 signing public key (`SHA-256(sign_pub)[0:16]`)
- **Announces** — signed with ML-DSA-44 (COSE_Sign1), carry name + opaque metadata + KEM pubkey
- **Chat** — encrypted with ML-KEM-512 key encapsulation + AES-256-GCM (COSE_Encrypt0), sender address authenticated inside ciphertext
- **Spam resistance** — SHA-256 proof-of-work on every packet, configurable difficulty (`CC_POW_DIFFICULTY`)
- **Routing** — inspect type, hops, and recipient address without decrypting; increment hops in-place
- **Embedded-safe** — large structs (`cc_key_t`, `cc_announce_t`) use static/global storage, no heap

## Message types

| Type | Value | Description |
|------|-------|-------------|
| `CC_MSG_ANNOUNCE` | 0 | Node identity broadcast |
| `CC_MSG_CHAT` | 1 | Encrypted directed message |

## Wire format

```
Announce: [type=0, hops, pow_nonce, COSE_Sign1]
  payload: [sign_pub(1312B), kem_pub(800B), name, meta]

Chat: [type=1, hops, recipient_addr(16B), kem_ct(768B), pow_nonce, COSE_Encrypt0]
  plaintext: [sender_addr(16B), message]
  key: HKDF-SHA256(ML-KEM-512 shared secret, info="cosechat")
```

## Dependencies

- [wolfSSL](https://www.wolfssl.com/) ≥ 5.0.0 — ML-DSA-44, ML-KEM-512, AES-GCM, HKDF, SHA-256
- [wolfCOSE](https://github.com/aidangarske/wolfCOSE) — COSE_Sign1, COSE_Encrypt0, CBOR

## Build (desktop)

```sh
make configure
make build
make test
```

## PlatformIO

Add to `platformio.ini`:

```ini
lib_deps =
  wolfssl
  https://github.com/aidangarske/wolfCOSE
  https://github.com/cosechat/cosechat-c
```

Required build flags (see `library.json`):

```
-DHAVE_DILITHIUM -DWOLFSSL_DILITHIUM_FIPS_204
-DWOLFSSL_HAVE_KYBER -DWOLFSSL_KYBER512
-DHAVE_AESGCM -DHAVE_HKDF -DWOLFSSL_SHA256 -DWOLFSSL_KEY_GEN
```

Targets: `espressif32` (Arduino, ESP-IDF).

## Embedded notes

`cc_key_t` is ~13 KB. `cc_announce_t` is ~2.5 KB. Declare both **static or global** on ESP32 — never as stack locals. See examples for the pattern.

## Examples & tests

- [`examples/keygen.c`](examples/keygen.c) — generate and export keys
- [`examples/announce.c`](examples/announce.c) — build, parse, and route an announce
- [`examples/chat.c`](examples/chat.c) — full Alice→Bob encrypted chat with hop routing
- [`test/test_cosechat.c`](test/test_cosechat.c) — full test suite

## Error codes

| Code | Value | Meaning |
|------|-------|---------|
| `CC_OK` | 0 | Success |
| `CC_E_ARG` | -1 | Bad argument |
| `CC_E_BUF` | -2 | Buffer too small |
| `CC_E_CRYPTO` | -3 | Crypto operation failed |
| `CC_E_FORMAT` | -4 | Malformed packet |
| `CC_E_SIG` | -5 | Signature verification failed |
| `CC_E_POW` | -6 | Proof-of-work check failed |
| `CC_E_DECRYPT` | -7 | Decryption failed |

## License

MIT
