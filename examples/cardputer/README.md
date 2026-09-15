# cardputer

cosechat node firmware for [CardputerADV](https://docs.m5stack.com/en/core/Cardputer-Adv).
It is a mesh chat peer on a *road* (transport): pick LoRa, WiFi/UDP, anonymous
BLE or raw 802.11 at build time; the node code is identical either way.

```sh
# LoRa: M5 LoRa Cap 1262
pio run -e lora --target upload --target monitor

# WiFi + UDP: set WIFI_SSID/WIFI_PASS in platformio.ini first
pio run -e wifi --target upload --target monitor

# Anonymous BLE 5 extended advertising (no connection, no address)
pio run -e ble --target upload --target monitor

# Unauthenticated 802.11 management frames (vendor-specific action frames)
pio run -e dot11 --target upload --target monitor
```

All four paths need a different radio, and BLE 5 extended advertising needs an
ESP32-S3 (or C3/C6); the cardputer is an S3. BLE and WiFi share the radio, so
run one road at a time.

Two nodes only hear each other on the same medium: both on channel 1 for
`dot11`, and both within BLE advertising range for `ble`. Neither road
acknowledges anything, so `announce` (which is ~5 KB, i.e. ~22 fragments on
BLE) is the lossy part; presence and chat are a handful of fragments.

## Controls

| Key | Action |
|-----|--------|
| letters | type a message |
| Tab | cycle peers (received via announce) |
| Enter | send the message to the selected peer |
| Del | backspace |

The log line shows `ANN`/`PRE` (announce/presence received), `TX`, and `RX`
(decrypted chat, prefixed with the sender's address).

## How it works

- On boot the node generates (or loads from SD) an ML-DSA-44 + ML-KEM-512
  keypair, broadcasts a signed **announce**, then sends an unsigned
  **presence** heartbeat every 60 s.
- A presence from an unknown address triggers a **key_req**; the target
  answers by re-sending its announce.
- Announcements are cached on SD as `/cc/peers/<addr_hex>.bin`; only the
  selected peer is loaded into RAM to encrypt a chat.

## SD card layout

```
/cc/key.bin            sign_priv | sign_pub | kem_priv
/cc/peers/<hex>.bin    raw cc_announce_t
```

No SD card works too: the key is regenerated each boot and peers are kept in
RAM only.

## Roads

`road_lora` runs its own FreeRTOS task (RX except while transmitting) and
fragments packets to the SX1262 252-byte limit. `road_wifi` joins WiFi and
broadcasts the same fragments as UDP datagrams on port 4242, draining the
socket from the main loop.

`road_ble` sends each fragment as anonymous BLE 5 extended advertising data and
listens with a continuous passive scan; it needs no peer to connect to and
exposes no address. `road_80211` sends each fragment in a vendor-specific
action frame to the broadcast MAC and listens in promiscuous mode — no
association, no authentication, no ACK. Both reassemble received fragments in
the radio's own task and hand `recv()` complete packets, so nothing changes in
`main.cpp` but the road `#include` and the init call.

`road_lora` needs a mutex for the SPI bus it shares with the SD card; the demo
creates one and passes it as `spi_mux`. `road_ble` is the only road whose
`send()` blocks: the advertisement data is swapped per fragment, so an
announce takes `fragments × adv_ms` (≈ 2.5 s by default).

The `ble` env pulls `NimBLE-Arduino` and turns on extended advertising with
`-DCONFIG_BT_NIMBLE_EXT_ADV=1`; the `dot11` env uses only the WiFi stack that
ships with the framework.

## Dependencies

`m5stack/M5Cardputer`, the local `lib/wolfssl`, `wolfCOSE`, and — for the `ble`
env — `NimBLE-Arduino ^1.4.3`.

`wolfCOSE` ships no PlatformIO manifest, so PlatformIO never puts its
`include/` directory on the search path for the cosechat library's own
sources (the sketch compiles fine, `src/cosechat.c` does not). `[env]` adds it
explicitly:

```ini
-I${PROJECT_LIBDEPS_DIR}/${PIOENV}/wolfCOSE/include
```

## wolfSSL

The build needs **wolfSSL ≥ 5.8** for ML-KEM (`wolfssl/wolfcrypt/wc_mlkem.h`).
The PlatformIO registry package stops at 5.7.2, so a plain `lib_deps = wolfssl`
will not compile. `fetch-wolfssl.sh` fetches upstream v5.9.0-stable into
`lib/wolfssl/` (a gitignored local PlatformIO library compiled from the
wolfcrypt sources only) and pins `user_settings.h` next to it:

```sh
./fetch-wolfssl.sh
```

Re-run it after editing `include/user_settings.h`, since the library's own
sources cannot see the sketch's `include/` directory.

`user_settings.h` opts in to the experimental ML-DSA/ML-KEM code and `#undef`s
`WOLFSSL_ESPIDF`: PlatformIO defines `PLATFORMIO` and Arduino-ESP32 defines
`ESP_PLATFORM`, which makes wolfSSL's `settings.h` set `WOLFSSL_ESPIDF` even
for this Arduino build, and wolfSSL then rejects `ARDUINO` + `ESPIDF`.
