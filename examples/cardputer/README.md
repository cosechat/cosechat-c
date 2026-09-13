# cardputer

cosechat node firmware for [CardputerADV](https://docs.m5stack.com/en/core/Cardputer-Adv).
It is a mesh chat peer on a *road* (transport): pick LoRa or WiFi/UDP at build
time; the node code is identical either way.

```sh
# LoRa: M5 LoRa Cap 1262
pio run -e lora --target upload --target monitor

# WiFi + UDP: set WIFI_SSID/WIFI_PASS in platformio.ini first
pio run -e wifi --target upload --target monitor
```

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

Both need a mutex for the SPI bus they share with the SD card; the demo creates
one and passes it to the LoRa road as `spi_mux`.

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
