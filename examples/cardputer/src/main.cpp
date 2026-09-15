// cosechat demo node — CardputerADV, on a road (`road_lora`, `road_wifi`,
// `road_ble` or `road_80211`).
//
// Default road is LoRa (M5 LoRa Cap 1262); build one of the other PlatformIO
// envs (wifi/ble/dot11) for a different road. The rest of the node is
// identical because the road hides framing and fragmentation.
//
//   Tab   = cycle peers        Enter = send chat to selected peer
//
// Key stored on SD at /cc/key.bin (sign_priv + sign_pub + kem_priv).
// Peers stored at /cc/peers/<addr_hex>.bin (raw cc_announce_t).
// Only the selected peer is loaded into RAM; the rest stay on SD.
//
// The SD card and the SX1262 share one SPI bus, so the demo creates a mutex
// and hands it to the LoRa road as `spi_mux`.

#include <Arduino.h>
#include <SD.h>
#include <SPI.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

#include "M5Cardputer.h"
#include "utility/PI4IOE5V6408_Class.hpp"

extern "C" {
#include "cosechat.h"
#include "road.h"
#if defined(CC_ROAD_BLE)
#include "road_ble.h"
#elif defined(CC_ROAD_80211)
#include "road_80211.h"
#elif defined(CC_ROAD_WIFI)
#include "road_wifi.h"
#else
#include "road_lora.h"
#endif
#include <wolfssl/wolfcrypt/random.h>
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
#define ANN_BUF_SZ 6144
#define CHAT_BUF_SZ 2048
#define PRES_BUF_SZ 128
#define KEY_REQ_BUF_SZ 32

#define SD_CS 12
#define KEY_FILE "/cc/key.bin"
#define PEER_DIR "/cc/peers"

#define SPI_SCK 40
#define SPI_MISO 39
#define SPI_MOSI 14
#define SPI_CS 5 /* LoRa cap NSS; also the bus default CS */

#define MAX_PEERS 16
#define STATUS_H 16
#define ANNOUNCE_MS 60000UL

// Client-side hop limit. The protocol does not enforce this; each node decides
// independently. Packets above this hop count are silently dropped rather than
// forwarded, preventing indefinite circulation in routing loops.
#define CC_MAX_HOPS 15

#if defined(CC_ROAD_BLE)
static const char NODE_NAME[] = "cc-ble";
#elif defined(CC_ROAD_80211)
static const char NODE_NAME[] = "cc-raw";
#elif defined(CC_ROAD_WIFI)
static const char NODE_NAME[] = "cc-wifi";

#ifndef WIFI_SSID
#define WIFI_SSID ""
#endif
#ifndef WIFI_PASS
#define WIFI_PASS ""
#endif
#else
static const char NODE_NAME[] = "cc-node";
#endif

// ---------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------
m5::PI4IOE5V6408_Class ioe(0x43, 400000, &m5::In_I2C);
M5Canvas canvas(&M5Cardputer.Display);

// ---------------------------------------------------------------------------
// Road
// ---------------------------------------------------------------------------
#if defined(CC_ROAD_BLE)
static cc_road_ble_t roadImpl;
#elif defined(CC_ROAD_80211)
static cc_road_80211_t roadImpl;
#elif defined(CC_ROAD_WIFI)
static cc_road_wifi_t roadImpl;
#else
static cc_road_lora_t roadImpl;
#endif
static cc_road_t* road = &roadImpl.road;

static SemaphoreHandle_t spiMux;
static uint8_t rxPkt[CC_ROAD_PKT_BUF_SZ];

// ---------------------------------------------------------------------------
// Crypto / keys
// ---------------------------------------------------------------------------
static WC_RNG rng;
static cc_key_t myKey; /* ~13KB — static to stay off stack */
static cc_chat_t tmpChat;
static cc_announce_t tmpAnn; /* scratch for RX parse and SD load */

static uint8_t myAddr[CC_ADDR_SZ];

// ---------------------------------------------------------------------------
// Wire buffers
// ---------------------------------------------------------------------------
static uint8_t annBuf[ANN_BUF_SZ];
static uint8_t chatBuf[CHAT_BUF_SZ];
static uint8_t presBuf[PRES_BUF_SZ];
static uint8_t keyReqBuf[KEY_REQ_BUF_SZ];

// ---------------------------------------------------------------------------
// Peer cache (addrs + names in RAM; full announce on SD)
// ---------------------------------------------------------------------------
static uint8_t peerAddrs[MAX_PEERS][CC_ADDR_SZ];
static char peerNames[MAX_PEERS][CC_MAX_NAME_LEN + 1];
static int peerCount = 0;
static int peerSel = -1;

// ---------------------------------------------------------------------------
// UI state
// ---------------------------------------------------------------------------
static String inputBuf;
static uint32_t lastAnn = 0;
static bool sdReady = false;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static const char HEXDIGITS[] = "0123456789abcdef";

static void toHex(const uint8_t* b, int n, char* out) {
  for (int i = 0; i < n; i++) {
    out[i * 2] = HEXDIGITS[b[i] >> 4];
    out[i * 2 + 1] = HEXDIGITS[b[i] & 0xf];
  }
  out[n * 2] = '\0';
}

static void logMsg(const char* who, const char* msg, uint16_t col = YELLOW) {
  canvas.setTextColor(col);
  canvas.print(who);
  canvas.setTextColor(WHITE);
  canvas.print(": ");
  canvas.println(msg);
  canvas.pushSprite(8, STATUS_H + 4);
  Serial.printf("%s: %s\n", who, msg);
}

static void drawStatus() {
  char hex[9];
  toHex(myAddr, 4, hex);  // first 4 bytes = 8 chars

  auto& D = M5Cardputer.Display;
  D.fillRect(0, 0, D.width(), STATUS_H, NAVY);
  D.setTextSize(1);
  D.setCursor(2, 4);
  D.setTextColor(CYAN);
  D.print(hex);
  D.setTextColor(DARKGREY);
  D.print(" ");
  D.print(road->name);
  D.setTextColor(WHITE);
  D.print(" -> ");
#ifdef CC_ROAD_WIFI
  const char* ip = cc_road_wifi_ip(&roadImpl);
  if (ip) {
    D.setTextColor(GREEN);
    D.print(ip);
  } else {
    D.setTextColor(RED);
    D.print("no wifi");
  }
  D.print(" ");
#endif
  if (peerSel >= 0 && peerSel < peerCount) {
    D.setTextColor(GREEN);
    D.print(peerNames[peerSel]);
    D.setTextColor(DARKGREY);
    char buf[16];
    snprintf(buf, sizeof(buf), " (%d/%d)", peerSel + 1, peerCount);
    D.print(buf);
  } else {
    D.setTextColor(DARKGREY);
    D.print("(no peer - Tab to scan)");
  }
}

static void drawInput() {
  auto& D = M5Cardputer.Display;
  int y = D.height() - 14;
  D.fillRect(0, y, D.width(), 14, BLACK);
  D.setCursor(2, y + 3);
  D.setTextColor(WHITE);
  D.print("> ");
  D.print(inputBuf.c_str());
}

static bool roadSend(const uint8_t* pkt, size_t len) {
  return road->send(road, pkt, len) == CC_ROAD_OK;
}

// ---------------------------------------------------------------------------
// SD helpers (all calls hold spiMux)
// ---------------------------------------------------------------------------
static bool sdInit() {
  if (sdReady)
    return true;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  sdReady = SD.begin(SD_CS, SPI, 25000000);
  if (sdReady) {
    SD.mkdir("/cc");
    SD.mkdir(PEER_DIR);
  }
  xSemaphoreGive(spiMux);
  return sdReady;
}

static bool keyLoad() {
  if (!sdInit())
    return false;
  static uint8_t sp[CC_SIGN_PRIVKEY_SZ], sb[CC_SIGN_PUBKEY_SZ],
      kp[CC_KEM_PRIVKEY_SZ];
  xSemaphoreTake(spiMux, portMAX_DELAY);
  File f = SD.open(KEY_FILE, FILE_READ);
  bool ok = false;
  if (f && (size_t)f.size() ==
               CC_SIGN_PRIVKEY_SZ + CC_SIGN_PUBKEY_SZ + CC_KEM_PRIVKEY_SZ) {
    f.read(sp, CC_SIGN_PRIVKEY_SZ);
    f.read(sb, CC_SIGN_PUBKEY_SZ);
    f.read(kp, CC_KEM_PRIVKEY_SZ);
    ok = true;
  }
  if (f)
    f.close();
  xSemaphoreGive(spiMux);
  return ok && cc_key_import(&myKey, sp, sb, kp) == CC_OK;
}

static bool keySave() {
  static uint8_t sp[CC_SIGN_PRIVKEY_SZ], kp[CC_KEM_PRIVKEY_SZ];
  static uint8_t sb[CC_SIGN_PUBKEY_SZ], kb[CC_KEM_PUBKEY_SZ];
  if (cc_key_export_private(&myKey, sp, kp) != CC_OK)
    return false;
  if (cc_key_export_public(&myKey, sb, kb) != CC_OK)
    return false;
  if (!sdInit())
    return false;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  File f = SD.open(KEY_FILE, FILE_WRITE);
  bool ok = false;
  if (f) {
    f.write(sp, CC_SIGN_PRIVKEY_SZ);
    f.write(sb, CC_SIGN_PUBKEY_SZ);
    f.write(kp, CC_KEM_PRIVKEY_SZ);
    f.close();
    ok = true;
  }
  xSemaphoreGive(spiMux);
  return ok;
}

static void peerSave(const cc_announce_t* ann) {
  if (!sdInit())
    return;
  char hex[CC_ADDR_SZ * 2 + 1];
  toHex(ann->addr, CC_ADDR_SZ, hex);
  char path[64];
  snprintf(path, sizeof(path), PEER_DIR "/%s.bin", hex);
  xSemaphoreTake(spiMux, portMAX_DELAY);
  File f = SD.open(path, FILE_WRITE);
  if (f) {
    f.write((const uint8_t*)ann, sizeof(cc_announce_t));
    f.close();
  }
  xSemaphoreGive(spiMux);
}

static bool peerLoad(int idx, cc_announce_t* out) {
  if (idx < 0 || idx >= peerCount || !sdInit())
    return false;
  char hex[CC_ADDR_SZ * 2 + 1];
  toHex(peerAddrs[idx], CC_ADDR_SZ, hex);
  char path[64];
  snprintf(path, sizeof(path), PEER_DIR "/%s.bin", hex);
  xSemaphoreTake(spiMux, portMAX_DELAY);
  File f = SD.open(path, FILE_READ);
  bool ok = false;
  if (f && (size_t)f.size() >= sizeof(cc_announce_t)) {
    f.read((uint8_t*)out, sizeof(cc_announce_t));
    f.close();
    ok = true;
  } else if (f) {
    f.close();
  }
  xSemaphoreGive(spiMux);
  return ok;
}

static void peersFromSD() {
  if (!sdInit())
    return;
  peerCount = 0;
  xSemaphoreTake(spiMux, portMAX_DELAY);
  File dir = SD.open(PEER_DIR);
  while (dir && peerCount < MAX_PEERS) {
    File e = dir.openNextFile();
    if (!e)
      break;
    if (!e.isDirectory() && (size_t)e.size() >= sizeof(cc_announce_t)) {
      cc_announce_t tmp;
      e.read((uint8_t*)&tmp, sizeof(cc_announce_t));
      memcpy(peerAddrs[peerCount], tmp.addr, CC_ADDR_SZ);
      strncpy(peerNames[peerCount], tmp.name, CC_MAX_NAME_LEN);
      peerNames[peerCount][CC_MAX_NAME_LEN] = '\0';
      peerCount++;
    }
    e.close();
  }
  if (dir)
    dir.close();
  xSemaphoreGive(spiMux);
}

static void peerAddOrUpdate(const cc_announce_t* ann) {
  for (int i = 0; i < peerCount; i++) {
    if (memcmp(peerAddrs[i], ann->addr, CC_ADDR_SZ) == 0) {
      strncpy(peerNames[i], ann->name, CC_MAX_NAME_LEN);
      peerNames[i][CC_MAX_NAME_LEN] = '\0';
      peerSave(ann);
      return;
    }
  }
  if (peerCount < MAX_PEERS) {
    memcpy(peerAddrs[peerCount], ann->addr, CC_ADDR_SZ);
    strncpy(peerNames[peerCount], ann->name, CC_MAX_NAME_LEN);
    peerNames[peerCount][CC_MAX_NAME_LEN] = '\0';
    if (peerSel < 0)
      peerSel = peerCount;
    peerCount++;
    peerSave(ann);
  }
}

// ---------------------------------------------------------------------------
// Announce / presence broadcast
// ---------------------------------------------------------------------------
static void broadcastAnnounce() {
  // A cosechat announce is ~5 KB and must be sent as ~21 fragments. If two
  // nodes transmit simultaneously their fragments interleave by msg_id,
  // causing both reassemblies to fail. A random pre-transmit delay (0-5 s)
  // spreads simultaneous boots and periodic re-announces across time so
  // collisions are rare. For a production mesh you would replace this with
  // proper TDMA slot assignment or carrier-sense backoff.
#if !defined(CC_ROAD_BLE) && !defined(CC_ROAD_80211) && !defined(CC_ROAD_WIFI)
  delay(random(0, 5000));
#endif

  size_t len = 0;
  int ret = cc_announce_build(&myKey, NODE_NAME, strlen(NODE_NAME), nullptr, 0,
                              annBuf, sizeof(annBuf), &len, &rng);
  if (ret == CC_OK && len > 0 && roadSend(annBuf, len)) {
    logMsg("TX", "announce", CYAN);
  } else {
    char buf[40];
    snprintf(buf, sizeof(buf), "announce failed (%d)", ret);
    logMsg("Sys", buf, RED);
  }
}

static void broadcastPresence() {
  size_t len = 0;
  int ret = cc_presence_build(&myKey, NODE_NAME, strlen(NODE_NAME), presBuf,
                              sizeof(presBuf), &len, &rng);
  if (ret == CC_OK && len > 0 && roadSend(presBuf, len)) {
    logMsg("TX", "presence", CYAN);
  }
}

// ---------------------------------------------------------------------------
// Process a fully received cosechat packet
// ---------------------------------------------------------------------------
static void processPkt(const uint8_t* pkt, size_t len) {
  uint8_t type = 0;
  if (cc_msg_type(pkt, len, &type) != CC_OK)
    return;
  uint8_t hops = 0;
  cc_msg_hops(pkt, len, &hops);
  if (hops > CC_MAX_HOPS)
    return;  // drop; don't forward stale packets

  float rssi = road->last_rssi;

  if (type == CC_MSG_ANNOUNCE) {
    if (cc_announce_parse(pkt, len, &tmpAnn) == CC_OK) {
      if (memcmp(tmpAnn.addr, myAddr, CC_ADDR_SZ) == 0)
        return;
      peerAddOrUpdate(&tmpAnn);
      char buf[CC_MAX_NAME_LEN + 24];
      snprintf(buf, sizeof(buf), "'%s' %.0fdBm (key)", tmpAnn.name, rssi);
      logMsg("ANN", buf, GREEN);
      drawStatus();
    }

  } else if (type == CC_MSG_PRESENCE) {
    cc_presence_t pres;
    if (cc_presence_parse(pkt, len, &pres) != CC_OK)
      return;
    if (memcmp(pres.addr, myAddr, CC_ADDR_SZ) == 0)
      return;

    char buf[CC_MAX_NAME_LEN + 24];
    snprintf(buf, sizeof(buf), "'%s' %.0fdBm", pres.name, rssi);
    logMsg("PRE", buf, ORANGE);

    // Unknown peer? request their full announce
    bool known = false;
    for (int i = 0; i < peerCount; i++) {
      if (memcmp(peerAddrs[i], pres.addr, CC_ADDR_SZ) == 0) {
        known = true;
        break;
      }
    }
    if (!known) {
      size_t rlen = 0;
      if (cc_key_req_build(pres.addr, keyReqBuf, sizeof(keyReqBuf), &rlen) ==
              CC_OK &&
          roadSend(keyReqBuf, rlen)) {
        logMsg("TX", "key_req", CYAN);
      }
    }

  } else if (type == CC_MSG_KEY_REQ) {
    uint8_t reqAddr[CC_ADDR_SZ];
    if (cc_key_req_parse(pkt, len, reqAddr) != CC_OK)
      return;
    if (memcmp(reqAddr, myAddr, CC_ADDR_SZ) != 0)
      return;
    logMsg("RX", "key_req (sending announce)", ORANGE);
    broadcastAnnounce();

  } else if (type == CC_MSG_CHAT) {
    uint8_t recip[CC_ADDR_SZ];
    if (cc_msg_recipient(pkt, len, recip) != CC_OK)
      return;
    if (memcmp(recip, myAddr, CC_ADDR_SZ) != 0)
      return;
    if (cc_chat_parse(&myKey, pkt, len, &tmpChat) == CC_OK) {
      char sender[9];
      toHex(tmpChat.sender_addr, 4, sender);
      char buf[CC_MAX_MSG_SZ + 16];
      snprintf(buf, sizeof(buf), "[%s] %.*s", sender, (int)tmpChat.msg_len,
               (const char*)tmpChat.msg);
      logMsg("RX", buf, YELLOW);
    }
  }
}

// ---------------------------------------------------------------------------
// Drain the road — whole packets only, framing is the road's business
// ---------------------------------------------------------------------------
static void pumpRoad() {
  size_t len;
  while (road->recv(road, rxPkt, sizeof(rxPkt), &len) == CC_ROAD_OK) {
    processPkt(rxPkt, len);
  }
}

// ---------------------------------------------------------------------------
// Keyboard
// ---------------------------------------------------------------------------
static void handleKeyboard() {
  if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed())
    return;
  auto ks = M5Cardputer.Keyboard.keysState();

  bool tabPressed = false;
  for (auto k : ks.word) {
    if (k == '\t')
      tabPressed = true;
    else
      inputBuf += k;
  }

  if (ks.del && inputBuf.length() > 0) {
    inputBuf.remove(inputBuf.length() - 1);
  }

  // Tab: cycle peers
  if (tabPressed) {
    if (peerCount > 0) {
      peerSel = (peerSel + 1) % peerCount;
      drawStatus();
    }
    return;
  }

  if (ks.enter) {
    String msg = inputBuf;
    msg.trim();
    inputBuf = "";
    drawInput();

    if (msg.isEmpty())
      return;

    if (peerSel < 0 || peerSel >= peerCount) {
      logMsg("Sys", "no peer selected (Tab)", RED);
      return;
    }

    // Load peer from SD to get KEM pubkey
    if (!peerLoad(peerSel, &tmpAnn)) {
      logMsg("Sys", "peer load failed", RED);
      return;
    }

    size_t len = 0;
    int ret = cc_chat_build(&myKey, tmpAnn.addr, tmpAnn.kem_pubkey,
                            (const uint8_t*)msg.c_str(), msg.length(), chatBuf,
                            sizeof(chatBuf), &len, &rng);
    if (ret == CC_OK && len > 0 && roadSend(chatBuf, len)) {
      char disp[CC_MAX_MSG_SZ + 8];
      snprintf(disp, sizeof(disp), "-> %s", msg.c_str());
      logMsg("TX", disp, CYAN);
    } else {
      char buf[40];
      snprintf(buf, sizeof(buf), "chat failed (%d)", ret);
      logMsg("Sys", buf, RED);
    }
    return;
  }

  drawInput();
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------
void setup() {
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Display.setRotation(1);
  Serial.begin(115200);

  // Shared SPI bus: SD card and LoRa cap both hang off it.
  SPI.begin(SPI_SCK, SPI_MISO, SPI_MOSI, SPI_CS);
  spiMux = xSemaphoreCreateMutex();

  // Display
  auto& D = M5Cardputer.Display;
  D.fillScreen(BLACK);
  D.setTextSize(1);

  // Crypto RNG
  wc_InitRng(&rng);

  // Canvas for scrolling log
  int canvasH = D.height() - STATUS_H - 6 - 14;
  canvas.createSprite(D.width() - 8, canvasH);
  canvas.setTextScroll(true);
  canvas.fillSprite(BLACK);
  canvas.setTextSize(1);

  // Road
#if defined(CC_ROAD_BLE)
  cc_road_ble_cfg_t bleCfg;
  cc_road_ble_defaults(&bleCfg);
  int ret = cc_road_ble_init(&roadImpl, &bleCfg);
#elif defined(CC_ROAD_80211)
  cc_road_80211_cfg_t rawCfg;
  cc_road_80211_defaults(&rawCfg);
  int ret = cc_road_80211_init(&roadImpl, &rawCfg);
#elif defined(CC_ROAD_WIFI)
  cc_road_wifi_cfg_t wifiCfg;
  cc_road_wifi_defaults(&wifiCfg);
  wifiCfg.ssid = WIFI_SSID;
  wifiCfg.pass = WIFI_PASS;
  int ret = cc_road_wifi_init(&roadImpl, &wifiCfg);
#else
  // I2C for the port expander that drives the cap's antenna switch
  m5::In_I2C.begin(I2C_NUM_0, 8, 9);
  if (ioe.begin()) {
    ioe.setDirection(0, true);
    ioe.setHighImpedance(0, false);
    ioe.digitalWrite(0, true);  // antenna enable
    ioe.setDirection(7, true);
    ioe.setHighImpedance(7, false);
    ioe.digitalWrite(7, true);  // RX mode
  }

  cc_road_lora_cfg_t loraCfg;
  cc_road_lora_defaults(&loraCfg);
  loraCfg.pin_sck = -1;  // bus already begun above
  loraCfg.spi_mux = spiMux;
  loraCfg.antenna = [](int rx) {
    ioe.digitalWrite(7, rx);
    delay(2);
  };
  int ret = cc_road_lora_init(&roadImpl, &loraCfg);
#endif

  if (ret != CC_ROAD_OK) {
    logMsg("Sys", "road init FAILED", RED);
    char buf[32];
    snprintf(buf, sizeof(buf), "err %d", ret);
    logMsg("Sys", buf, RED);
    while (true) delay(1000);
  }

  // SD + key
  if (!keyLoad()) {
    logMsg("Sys", "generating key...", ORANGE);
    if (cc_key_generate(&myKey, &rng) != CC_OK) {
      logMsg("Sys", "keygen FAILED", RED);
      while (true) delay(1000);
    }
    keySave();
    logMsg("Sys", "key saved", ORANGE);
  } else {
    logMsg("Sys", "key loaded", ORANGE);
  }

  cc_addr_from_key(&myKey, myAddr);

  // Load known peers from SD
  peersFromSD();
  {
    char buf[32];
    snprintf(buf, sizeof(buf), "%d peers from SD", peerCount);
    logMsg("Sys", buf, ORANGE);
  }
  if (peerCount > 0)
    peerSel = 0;

  drawStatus();
  drawInput();

  // Announce at boot (proves identity); presence sent periodically after
  broadcastAnnounce();
  lastAnn = millis();
}

// ---------------------------------------------------------------------------
// loop
// ---------------------------------------------------------------------------
void loop() {
  M5Cardputer.update();
  handleKeyboard();
  pumpRoad();

  if (millis() - lastAnn >= ANNOUNCE_MS) {
    broadcastPresence();
    lastAnn = millis();
    drawStatus();
  }

  delay(5);
}
