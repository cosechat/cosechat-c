// cosechat LoRa node — CardputerADV + M5 LoRa Cap 1262
//
// Key stored on SD at /cc/key.bin (sign_priv + sign_pub + kem_priv).
// Peers stored at /cc/peers/<addr_hex>.bin (raw cc_announce_t).
// Only selected peer loaded into RAM; rest stay on SD.
//
// Fragmentation: SX1262 max 252 bytes. Header = [0xCC, msg_id, frag_idx,
// frag_total]. Payload = 248 bytes/frag. Announce ~21 frags, chat ~9 frags.
//
// Tab = cycle peers. Enter = send chat to selected peer.

#include <Arduino.h>
#include "M5Cardputer.h"
#include <RadioLib.h>
#include "utility/PI4IOE5V6408_Class.hpp"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <SD.h>
#include <SPI.h>

extern "C" {
#include "cosechat.h"
#include <wolfssl/wolfcrypt/random.h>
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
#define LORA_FREQ         915.0
#define LORA_BW           125.0f
#define LORA_SF           7
#define LORA_CR           5
#define LORA_SYNC_WORD    0x12
#define LORA_TX_POWER     0
#define LORA_PREAMBLE_LEN 6

#define FRAG_MAGIC   0xCC
#define LORA_MAX_PKT 252
#define FRAG_HDR     4              // magic + msg_id + frag_idx + frag_total
#define FRAG_PAYLOAD (LORA_MAX_PKT - FRAG_HDR)  // 248

#define ANN_BUF_SZ   6144
#define CHAT_BUF_SZ  2048
#define PRES_BUF_SZ  128
#define KEY_REQ_BUF_SZ 32

#define SD_CS        12
#define KEY_FILE     "/cc/key.bin"
#define PEER_DIR     "/cc/peers"

#define MAX_PEERS    16
#define STATUS_H     16
#define ANNOUNCE_MS  60000UL

// ---------------------------------------------------------------------------
// Hardware
// ---------------------------------------------------------------------------
SX1262 radio = new Module(GPIO_NUM_5, GPIO_NUM_4, GPIO_NUM_3, GPIO_NUM_6);
m5::PI4IOE5V6408_Class ioe(0x43, 400000, &m5::In_I2C);
M5Canvas canvas(&M5Cardputer.Display);

// ---------------------------------------------------------------------------
// FreeRTOS types
// ---------------------------------------------------------------------------
struct TxJob  { uint8_t data[LORA_MAX_PKT]; uint8_t len; };
struct RxFrag { uint8_t data[LORA_MAX_PKT]; uint8_t len; float rssi; float snr; };

static QueueHandle_t     txQ;
static QueueHandle_t     rxQ;
static SemaphoreHandle_t spiMux;

// ---------------------------------------------------------------------------
// Crypto / keys
// ---------------------------------------------------------------------------
static WC_RNG      rng;
static cc_key_t    myKey;     // ~13KB — static to stay off stack
static cc_chat_t   tmpChat;
static cc_announce_t tmpAnn;  // scratch for RX parse and SD load

static uint8_t myAddr[CC_ADDR_SZ];

// ---------------------------------------------------------------------------
// Wire buffers
// ---------------------------------------------------------------------------
static uint8_t annBuf[ANN_BUF_SZ];
static uint8_t chatBuf[CHAT_BUF_SZ];
static uint8_t presBuf[PRES_BUF_SZ];
static uint8_t keyReqBuf[KEY_REQ_BUF_SZ];

// ---------------------------------------------------------------------------
// Fragment reassembly (single slot — only one message being assembled)
// ---------------------------------------------------------------------------
static struct {
    uint8_t  id;
    uint8_t  total;
    uint32_t mask;
    size_t   last_sz;       // payload size of last (highest-idx) fragment
    uint8_t  buf[ANN_BUF_SZ];
    bool     active;
} frag;
static size_t fragPktLen;

// ---------------------------------------------------------------------------
// Peer cache (addrs + names in RAM; full announce on SD)
// ---------------------------------------------------------------------------
static uint8_t peerAddrs[MAX_PEERS][CC_ADDR_SZ];
static char    peerNames[MAX_PEERS][CC_MAX_NAME_LEN + 1];
static int     peerCount = 0;
static int     peerSel   = -1;

// ---------------------------------------------------------------------------
// UI state
// ---------------------------------------------------------------------------
static String   inputBuf;
static uint8_t  txMsgId  = 0;
static uint32_t lastAnn  = 0;
static bool     sdReady  = false;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static const char HEX[] = "0123456789abcdef";

static void toHex(const uint8_t* b, int n, char* out) {
    for (int i = 0; i < n; i++) {
        out[i * 2]     = HEX[b[i] >> 4];
        out[i * 2 + 1] = HEX[b[i] & 0xf];
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
    D.setTextColor(WHITE);
    D.print(" -> ");
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

// ---------------------------------------------------------------------------
// SD helpers (all calls hold spiMux)
// ---------------------------------------------------------------------------
static bool sdInit() {
    if (sdReady) return true;
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
    if (!sdInit()) return false;
    static uint8_t sp[CC_SIGN_PRIVKEY_SZ], sb[CC_SIGN_PUBKEY_SZ], kp[CC_KEM_PRIVKEY_SZ];
    xSemaphoreTake(spiMux, portMAX_DELAY);
    File f = SD.open(KEY_FILE, FILE_READ);
    bool ok = false;
    if (f && (size_t)f.size() == CC_SIGN_PRIVKEY_SZ + CC_SIGN_PUBKEY_SZ + CC_KEM_PRIVKEY_SZ) {
        f.read(sp, CC_SIGN_PRIVKEY_SZ);
        f.read(sb, CC_SIGN_PUBKEY_SZ);
        f.read(kp, CC_KEM_PRIVKEY_SZ);
        ok = true;
    }
    if (f) f.close();
    xSemaphoreGive(spiMux);
    return ok && cc_key_import(&myKey, sp, sb, kp) == CC_OK;
}

static bool keySave() {
    static uint8_t sp[CC_SIGN_PRIVKEY_SZ], kp[CC_KEM_PRIVKEY_SZ];
    static uint8_t sb[CC_SIGN_PUBKEY_SZ],  kb[CC_KEM_PUBKEY_SZ];
    if (cc_key_export_private(&myKey, sp, kp) != CC_OK) return false;
    if (cc_key_export_public(&myKey, sb, kb)  != CC_OK) return false;
    if (!sdInit()) return false;
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
    if (!sdInit()) return;
    char hex[CC_ADDR_SZ * 2 + 1];
    toHex(ann->addr, CC_ADDR_SZ, hex);
    char path[64];
    snprintf(path, sizeof(path), PEER_DIR "/%s.bin", hex);
    xSemaphoreTake(spiMux, portMAX_DELAY);
    File f = SD.open(path, FILE_WRITE);
    if (f) { f.write((const uint8_t*)ann, sizeof(cc_announce_t)); f.close(); }
    xSemaphoreGive(spiMux);
}

static bool peerLoad(int idx, cc_announce_t* out) {
    if (idx < 0 || idx >= peerCount || !sdInit()) return false;
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
    } else if (f) f.close();
    xSemaphoreGive(spiMux);
    return ok;
}

static void peersFromSD() {
    if (!sdInit()) return;
    peerCount = 0;
    xSemaphoreTake(spiMux, portMAX_DELAY);
    File dir = SD.open(PEER_DIR);
    while (dir && peerCount < MAX_PEERS) {
        File e = dir.openNextFile();
        if (!e) break;
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
    if (dir) dir.close();
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
        if (peerSel < 0) peerSel = peerCount;
        peerCount++;
        peerSave(ann);
    }
}

// ---------------------------------------------------------------------------
// Fragmentation TX
// ---------------------------------------------------------------------------
static void enqueuePkt(const uint8_t* pkt, size_t len) {
    uint8_t total = (uint8_t)((len + FRAG_PAYLOAD - 1) / FRAG_PAYLOAD);
    if (total == 0 || total > 32) return;  // >32 frags = >7936 bytes, shouldn't happen
    uint8_t id = txMsgId++;
    for (uint8_t i = 0; i < total; i++) {
        TxJob job;
        size_t off = (size_t)i * FRAG_PAYLOAD;
        size_t psz = (off + FRAG_PAYLOAD <= len) ? (size_t)FRAG_PAYLOAD : (len - off);
        job.data[0] = FRAG_MAGIC;
        job.data[1] = id;
        job.data[2] = i;
        job.data[3] = total;
        memcpy(job.data + FRAG_HDR, pkt + off, psz);
        job.len = (uint8_t)(FRAG_HDR + psz);
        xQueueSend(txQ, &job, pdMS_TO_TICKS(5000));
    }
}

// ---------------------------------------------------------------------------
// Fragment reassembly — returns true when packet is complete in frag.buf
// ---------------------------------------------------------------------------
static bool fragFeed(const uint8_t* data, uint8_t len) {
    if (len < FRAG_HDR + 1 || data[0] != FRAG_MAGIC) return false;
    uint8_t id    = data[1];
    uint8_t idx   = data[2];
    uint8_t total = data[3];
    size_t  plen  = (size_t)(len - FRAG_HDR);

    if (total == 0 || idx >= total || total > 32) return false;

    if (!frag.active || frag.id != id) {
        memset(&frag, 0, sizeof(frag));
        frag.id     = id;
        frag.total  = total;
        frag.active = true;
    }

    size_t off = (size_t)idx * FRAG_PAYLOAD;
    if (off + plen > sizeof(frag.buf)) return false;
    memcpy(frag.buf + off, data + FRAG_HDR, plen);
    frag.mask |= (1u << idx);
    if (idx == total - 1) frag.last_sz = plen;

    uint32_t full = (total == 32) ? 0xFFFFFFFFu : ((1u << total) - 1);
    if ((frag.mask & full) == full) {
        frag.active = false;
        fragPktLen  = (size_t)(total - 1) * FRAG_PAYLOAD + frag.last_sz;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Announce broadcast
// ---------------------------------------------------------------------------
static void broadcastAnnounce() {
    // A cosechat announce is ~5 KB and must be sent as ~21 LoRa fragments.
    // If two nodes transmit simultaneously their fragments interleave by msg_id,
    // causing both reassemblies to fail. A random pre-transmit delay (0–5 s)
    // spreads simultaneous boots and periodic re-announces across time so
    // collisions are rare. For a production mesh you would replace this with
    // proper TDMA slot assignment or carrier-sense backoff.
    vTaskDelay(pdMS_TO_TICKS(random(0, 5000)));

    size_t len = 0;
    // cc_announce_build blocks ~50ms (PoW difficulty=1 on ESP32)
    int ret = cc_announce_build(&myKey, "cc-node", 7, nullptr, 0,
                                annBuf, sizeof(annBuf), &len, &rng);
    if (ret == CC_OK && len > 0) {
        enqueuePkt(annBuf, len);
        logMsg("TX", "announce", CYAN);
    } else {
        char buf[32];
        snprintf(buf, sizeof(buf), "ann build err %d", ret);
        logMsg("Sys", buf, RED);
    }
}

// ---------------------------------------------------------------------------
// Broadcast presence (periodic heartbeat, ~1 LoRa fragment)
// ---------------------------------------------------------------------------
static void broadcastPresence() {
    size_t len = 0;
    int ret = cc_presence_build(&myKey, "cc-node", 7,
                                presBuf, sizeof(presBuf), &len, &rng);
    if (ret == CC_OK && len > 0) {
        TxJob job;
        memcpy(job.data, presBuf, len);
        job.len = (uint8_t)len;
        xQueueSend(txQ, &job, pdMS_TO_TICKS(1000));
        logMsg("TX", "presence", CYAN);
    }
}

// ---------------------------------------------------------------------------
// Process a fully reassembled cosechat packet
// ---------------------------------------------------------------------------
static void processPkt(const uint8_t* pkt, size_t len, float rssi, float snr) {
    uint8_t type = 0;
    if (cc_msg_type(pkt, len, &type) != CC_OK) return;

    if (type == CC_MSG_ANNOUNCE) {
        if (cc_announce_parse(pkt, len, &tmpAnn) == CC_OK) {
            if (memcmp(tmpAnn.addr, myAddr, CC_ADDR_SZ) == 0) return;
            peerAddOrUpdate(&tmpAnn);
            char buf[CC_MAX_NAME_LEN + 24];
            snprintf(buf, sizeof(buf), "'%s' %.0fdBm (key)", tmpAnn.name, rssi);
            logMsg("ANN", buf, GREEN);
            drawStatus();
        }

    } else if (type == CC_MSG_PRESENCE) {
        cc_presence_t pres;
        if (cc_presence_parse(pkt, len, &pres) != CC_OK) return;
        if (memcmp(pres.addr, myAddr, CC_ADDR_SZ) == 0) return;

        char buf[CC_MAX_NAME_LEN + 24];
        snprintf(buf, sizeof(buf), "'%s' %.0fdBm", pres.name, rssi);
        logMsg("PRE", buf, ORANGE);

        // Unknown peer? request their full announce
        bool known = false;
        for (int i = 0; i < peerCount; i++) {
            if (memcmp(peerAddrs[i], pres.addr, CC_ADDR_SZ) == 0) {
                known = true; break;
            }
        }
        if (!known) {
            size_t rlen = 0;
            if (cc_key_req_build(pres.addr, keyReqBuf, sizeof(keyReqBuf), &rlen) == CC_OK) {
                TxJob job;
                memcpy(job.data, keyReqBuf, rlen);
                job.len = (uint8_t)rlen;
                xQueueSend(txQ, &job, pdMS_TO_TICKS(1000));
                logMsg("TX", "key_req", CYAN);
            }
        }

    } else if (type == CC_MSG_KEY_REQ) {
        uint8_t reqAddr[CC_ADDR_SZ];
        if (cc_key_req_parse(pkt, len, reqAddr) != CC_OK) return;
        if (memcmp(reqAddr, myAddr, CC_ADDR_SZ) != 0) return;
        logMsg("RX", "key_req (sending announce)", ORANGE);
        broadcastAnnounce();

    } else if (type == CC_MSG_CHAT) {
        uint8_t recip[CC_ADDR_SZ];
        if (cc_msg_recipient(pkt, len, recip) != CC_OK) return;
        if (memcmp(recip, myAddr, CC_ADDR_SZ) != 0) return;
        if (cc_chat_parse(&myKey, pkt, len, &tmpChat) == CC_OK) {
            char sender[9];
            toHex(tmpChat.sender_addr, 4, sender);
            char buf[CC_MAX_MSG_SZ + 16];
            snprintf(buf, sizeof(buf), "[%s] %.*s", sender,
                     (int)tmpChat.msg_len, (const char*)tmpChat.msg);
            logMsg("RX", buf, YELLOW);
        }
    }
}

// ---------------------------------------------------------------------------
// Antenna switch
// ---------------------------------------------------------------------------
static void setAntenna(bool rx) {
    ioe.digitalWrite(7, rx);
    delay(2);
}

// ---------------------------------------------------------------------------
// Radio task
// ---------------------------------------------------------------------------
static void radioTask(void* arg) {
    xSemaphoreTake(spiMux, portMAX_DELAY);
    setAntenna(true);
    radio.startReceive();
    xSemaphoreGive(spiMux);

    for (;;) {
        // TX has priority
        TxJob job;
        if (xQueueReceive(txQ, &job, 0) == pdPASS) {
            xSemaphoreTake(spiMux, portMAX_DELAY);
            radio.standby();
            xSemaphoreGive(spiMux);

            setAntenna(false);
            xSemaphoreTake(spiMux, portMAX_DELAY);
            radio.transmit(job.data, job.len);
            radio.clearIrqFlags(RADIOLIB_SX126X_IRQ_ALL);
            xSemaphoreGive(spiMux);

            setAntenna(true);
            xSemaphoreTake(spiMux, portMAX_DELAY);
            radio.startReceive();
            xSemaphoreGive(spiMux);

            // Small inter-fragment gap to let receivers process
            vTaskDelay(pdMS_TO_TICKS(20));
            continue;
        }

        // Poll RX
        xSemaphoreTake(spiMux, portMAX_DELAY);
        uint16_t irq = radio.getIrqFlags();
        xSemaphoreGive(spiMux);

        if (irq & RADIOLIB_SX126X_IRQ_RX_DONE) {
            xSemaphoreTake(spiMux, portMAX_DELAY);
            int pktLen = radio.getPacketLength();
            RxFrag evt = {};
            if (pktLen > 0 && pktLen <= LORA_MAX_PKT) {
                int state = radio.readData(evt.data, pktLen);
                if (state == RADIOLIB_ERR_NONE) {
                    evt.len  = (uint8_t)pktLen;
                    evt.rssi = radio.getRSSI();
                    evt.snr  = radio.getSNR();
                }
            }
            radio.clearIrqFlags(RADIOLIB_SX126X_IRQ_RX_DONE |
                                 RADIOLIB_SX126X_IRQ_HEADER_ERR |
                                 RADIOLIB_SX126X_IRQ_CRC_ERR);
            radio.startReceive();
            xSemaphoreGive(spiMux);

            if (evt.len > 0) xQueueSend(rxQ, &evt, 0);

        } else if (irq & RADIOLIB_SX126X_IRQ_TIMEOUT) {
            xSemaphoreTake(spiMux, portMAX_DELAY);
            radio.clearIrqFlags(RADIOLIB_SX126X_IRQ_TIMEOUT);
            radio.startReceive();
            xSemaphoreGive(spiMux);
        }

        vTaskDelay(pdMS_TO_TICKS(5));
    }
}

// ---------------------------------------------------------------------------
// Keyboard
// ---------------------------------------------------------------------------
static void handleKeyboard() {
    if (!M5Cardputer.Keyboard.isChange() || !M5Cardputer.Keyboard.isPressed()) return;
    auto ks = M5Cardputer.Keyboard.keysState();

    bool tabPressed = false;
    for (auto k : ks.word) {
        if (k == '\t') tabPressed = true;
        else inputBuf += k;
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

        if (msg.isEmpty()) return;

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
        int ret = cc_chat_build(&myKey,
                                tmpAnn.addr, tmpAnn.kem_pubkey,
                                (const uint8_t*)msg.c_str(), msg.length(),
                                chatBuf, sizeof(chatBuf), &len, &rng);
        if (ret == CC_OK && len > 0) {
            enqueuePkt(chatBuf, len);
            char disp[CC_MAX_MSG_SZ + 8];
            snprintf(disp, sizeof(disp), "-> %s", msg.c_str());
            logMsg("TX", disp, CYAN);
        } else {
            char buf[32];
            snprintf(buf, sizeof(buf), "chat build err %d", ret);
            logMsg("Sys", buf, RED);
        }
        return;
    }

    drawInput();
}

// ---------------------------------------------------------------------------
// Pump RX events — reassemble fragments, process complete packets
// ---------------------------------------------------------------------------
static void pumpRx() {
    RxFrag evt;
    while (xQueueReceive(rxQ, &evt, 0) == pdPASS) {
        if (fragFeed(evt.data, evt.len)) {
            processPkt(frag.buf, fragPktLen, evt.rssi, evt.snr);
        }
    }
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------
void setup() {
    auto cfg = M5.config();
    M5Cardputer.begin(cfg, true);
    M5Cardputer.Display.setRotation(1);
    Serial.begin(115200);

    // I2C for port expander (antenna switch)
    m5::In_I2C.begin(I2C_NUM_0, 8, 9);
    if (ioe.begin()) {
        ioe.setDirection(0, true);
        ioe.setHighImpedance(0, false);
        ioe.digitalWrite(0, true);   // antenna enable
        ioe.setDirection(7, true);
        ioe.setHighImpedance(7, false);
        ioe.digitalWrite(7, true);   // RX mode
    }

    SPI.begin(40, 39, 14, 5);

    // Init display
    auto& D = M5Cardputer.Display;
    D.fillScreen(BLACK);
    D.setTextSize(1);

    spiMux = xSemaphoreCreateMutex();
    txQ    = xQueueCreate(64, sizeof(TxJob));   // 64 frags = ~2 full announces
    rxQ    = xQueueCreate(32, sizeof(RxFrag));

    // Radio
    int state = radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR,
                            LORA_SYNC_WORD, LORA_TX_POWER, LORA_PREAMBLE_LEN,
                            3.0, true);
    if (state != RADIOLIB_ERR_NONE) {
        D.setTextColor(RED);
        D.setCursor(4, 4);
        D.printf("Radio init failed: %d", state);
        while (true) delay(1000);
    }
    radio.setCurrentLimit(140);
    radio.setDio2AsRfSwitch(false);

    // Crypto RNG
    wc_InitRng(&rng);

    // Canvas for scrolling log
    int canvasH = D.height() - STATUS_H - 6 - 14;
    canvas.createSprite(D.width() - 8, canvasH);
    canvas.setTextScroll(true);
    canvas.fillSprite(BLACK);
    canvas.setTextSize(1);

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
    if (peerCount > 0) peerSel = 0;

    // Start radio task
    xTaskCreate(radioTask, "LoRa", 4096, nullptr, 1, nullptr);

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
    pumpRx();

    if (millis() - lastAnn >= ANNOUNCE_MS) {
        broadcastPresence();
        lastAnn = millis();
    }

    delay(5);
}
