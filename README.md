# cosechat

Post-quantum mesh chat protocol for microcontrollers and desktop. Inspired by [Reticulum](https://reticulum.network/) / LXMF.

Wire format is CBOR. Crypto is COSE. No dynamic allocation — safe for ESP32.

## Features

- **Addresses** — 16-byte, derived from ML-DSA-44 signing public key (`SHA-256(sign_pub)[0:16]`)
- **Announces** — signed with ML-DSA-44 (COSE_Sign1), carry name + opaque metadata + KEM pubkey
- **Chat** — encrypted with ML-KEM-512 key encapsulation + AES-256-GCM (COSE_Encrypt0), sender address authenticated inside ciphertext
- **Spam resistance** — SHA-256 proof-of-work on every packet, configurable difficulty (`CC_POW_DIFFICULTY`)
- **Routing** — inspect type, hops, and recipient address without decrypting; increment hops in-place
- **Roads** — pluggable transports (`road_lora`, `road_wifi`, `road_ble`, `road_80211`) that hand the application whole packets
- **Embedded-safe** — large structs (`cc_key_t`, `cc_announce_t`) use static/global storage, no heap

## Message types

| Type | Value | Description |
|------|-------|-------------|
| `CC_MSG_ANNOUNCE` | 0 | Node identity broadcast |
| `CC_MSG_CHAT` | 1 | Encrypted directed message |
| `CC_MSG_PRESENCE` | 2 | Periodic unsigned heartbeat |
| `CC_MSG_KEY_REQ` | 3 | Ask a node to re-send its full announce |

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

**wolfSSL ≥ 5.8 is required** (`wolfssl/wolfcrypt/wc_mlkem.h` landed in 5.8).
The PlatformIO registry package tops out at 5.7.2, so a registry-only
`lib_deps = wolfssl` cannot provide ML-KEM — point at a wolfSSL ≥ 5.8 source
(see [`examples/cardputer/fetch-wolfssl.sh`](examples/cardputer/fetch-wolfssl.sh)).

## Roads (transports)

A *road* moves whole cosechat packets between nodes. It owns framing, and
fragmentation where the medium needs it, so the application only ever sees
complete packets:

```c
extern cc_road_t* road;

road->send(road, pkt, len);

uint8_t buf[CC_ROAD_PKT_BUF_SZ];
size_t len;
while (road->recv(road, buf, sizeof(buf), &len) == CC_ROAD_OK) {
  /* cc_msg_type() / cc_announce_parse() / cc_chat_parse() ... */
}
```

| Road | Medium | Header | Source |
|------|--------|--------|--------|
| `road_lora` | SX1262 LoRa via [RadioLib](https://github.com/jgromes/RadioLib) | `include/road_lora.h` | `src/road_lora.cpp` |
| `road_wifi` | WiFi + UDP (ESP32 Arduino) | `include/road_wifi.h` | `src/road_wifi.cpp` |
| `road_ble` | Anonymous BLE 5 extended advertising via [NimBLE-Arduino](https://github.com/h2zero/NimBLE-Arduino) | `include/road_ble.h` | `src/road_ble.cpp` |
| `road_80211` | Unauthenticated 802.11 management frames (ESP32) | `include/road_80211.h` | `src/road_80211.cpp` |

All four share the framing in `include/road.h`: `[magic=0xCC, msg_id, frag_idx,
frag_total, payload]`, sized for the SX1262's 252-byte packet limit. A road
with a smaller MTU passes its own fragment payload to the `*_n` helpers —
`road_ble` uses 243 bytes so each fragment fits one extended advertisement.
Each road is compiled only when its dependency is available (`__has_include`),
so the library stays buildable without RadioLib, NimBLE or the WiFi stack.

### Opportunistic roads

`road_ble` and `road_80211` piggyback on radios a device already has, without
joining anything:

- **`road_ble`** carries each fragment as manufacturer-specific data in a
  non-connectable, non-scannable, *anonymous* BLE 5 extended advertisement (no
  advertiser address, no scan response, no connection). RX is a continuous
  passive scan. One advertisement holds 251 bytes of data, minus the AD header,
  company id and road header — 243 payload bytes, so an announce is ~22
  advertisements. `send()` blocks while each fragment advertises
  (`cfg.adv_ms`); the NimBLE host task does RX.
- **`road_80211`** carries each fragment in a vendor-specific action frame
  (category 127) sent to the broadcast MAC — a plain management frame that
  needs no association, authentication or ACK. The source address is a random
  locally-administered MAC. RX is promiscuous-mode capture, so both ends must
  sit on the same channel (`cfg.channel`). The promiscuous callback runs in the
  WiFi task and reassembles there.

Both are lossy and unacknowledged, like any broadcast medium: announces are
the expensive case (many fragments) and presence/chat are cheap.

```c
static cc_road_lora_t lora;          /* ~16 KB — static/global */
cc_road_lora_cfg_t cfg;
cc_road_lora_defaults(&cfg);         /* CardputerADV + LoRa Cap 1262 */
cfg.spi_mux = bus_mutex;             /* SD card shares the SPI bus */
cfg.antenna = antenna_switch;        /* cap RF switch, if any */
cc_road_lora_init(&lora, &cfg);
cc_road_t* road = &lora.road;

static cc_road_wifi_t wifi;
cc_road_wifi_cfg_t wifi_cfg;
cc_road_wifi_defaults(&wifi_cfg);    /* port 4242, broadcast */
wifi_cfg.ssid = "my-ssid";
wifi_cfg.pass = "my-pass";
cc_road_wifi_init(&wifi, &wifi_cfg);

static cc_road_ble_t ble;
cc_road_ble_cfg_t ble_cfg;
cc_road_ble_defaults(&ble_cfg);      /* 0 dBm, 20 ms interval, 120 ms/frag */
cc_road_ble_init(&ble, &ble_cfg);

static cc_road_80211_t raw;
cc_road_80211_cfg_t raw_cfg;
cc_road_80211_defaults(&raw_cfg);    /* channel 1 */
cc_road_80211_init(&raw, &raw_cfg);
```

`road_lora` runs its own FreeRTOS task (RX except during TX); `road_wifi` has
no task and drains the socket inside `recv()`; `road_ble` and `road_80211`
reassemble inside the NimBLE / WiFi task and hand `recv()` a queue.

## Embedded notes

`cc_key_t` is ~13 KB. `cc_announce_t` is ~2.5 KB, road structs ~16 KB. Declare
all of them **static or global** on ESP32 — never as stack locals. See examples
for the pattern.

## Examples & tests

- [`examples/keygen.c`](examples/keygen.c) — generate and export keys
- [`examples/announce.c`](examples/announce.c) — build, parse, and route an announce
- [`examples/chat.c`](examples/chat.c) — full Alice→Bob encrypted chat with hop routing
- [`examples/cardputer`](examples/cardputer) — node firmware for CardputerADV (LoRa cap, WiFi/UDP, anonymous BLE, or raw 802.11)
- [`test/test_cosechat.c`](test/test_cosechat.c) — protocol test suite
- [`test/test_road.c`](test/test_road.c) — road framing (fragmentation/reassembly) tests

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

[Zlib](https://opensource.org/license/ZLIB)
