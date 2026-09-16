/*
 * road_ble — anonymous BLE extended-advertising road (NimBLE).
 *
 * Compiled only when NimBLE-Arduino is available; otherwise this is an empty
 * TU, so the library still builds for LoRa/WiFi-only targets.
 */

#if __has_include(<Arduino.h>) && __has_include(<NimBLEDevice.h>)

#include "road_ble.h"

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <string.h>

static cc_road_ble_t* impl_of(cc_road_t* road) {
  return (cc_road_ble_t*)road->ctx;
}

/* Marks the end of one fragment's advertising window. */
class CcAdvCallbacks : public NimBLEExtAdvertisingCallbacks {
 public:
  volatile bool done = false;
  void onStopped(NimBLEExtAdvertising*, int, uint8_t) override { done = true; }
};

class CcScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
 public:
  cc_road_ble_t* r = nullptr;
  void onResult(NimBLEAdvertisedDevice* dev) override;
};

void CcScanCallbacks::onResult(NimBLEAdvertisedDevice* dev) {
  if (!r)
    return;
  std::string mfg = dev->getManufacturerData();
  if (mfg.size() <= 2)
    return;
  uint16_t cid = (uint8_t)mfg[0] | ((uint16_t)(uint8_t)mfg[1] << 8);
  if (cid != CC_ROAD_BLE_COMPANY_ID)
    return;

  const uint8_t* frag = (const uint8_t*)mfg.data() + 2;
  size_t flen = mfg.size() - 2;
  /* The slot holds one packet for recv(): a completion it has not collected
   * yet drops the new packet instead of being overwritten. No source: an
   * anonymous advertisement carries no advertiser address, so this road cannot
   * say who sent the packet (road->last_src_len stays 0). */
  int done = cc_road_rx_frag(&r->frag, frag, flen, CC_ROAD_BLE_FRAG_PAYLOAD,
                             NULL, 0, &r->pkt);
  if (done == CC_ROAD_RX_BAD) {
    r->stats.rxDrop++;
  } else if (done != CC_ROAD_RX_MORE) {
    r->stats.rxFrag++;
    r->road.last_rssi = (float)dev->getRSSI();
    if (done == CC_ROAD_RX_BUSY)
      r->stats.rxDrop++;
  }
}

void cc_road_ble_defaults(cc_road_ble_cfg_t* cfg) {
  if (!cfg)
    return;
  cfg->instance = 0;
  cfg->tx_power = 0;
  cfg->adv_interval = 32;
  cfg->adv_ms = 120;
  cfg->scan_interval_ms = 100;
  cfg->scan_window_ms = 100;
}

/* Emit one fragment as one anonymous extended advertisement, and wait out its
 * advertising window before the next fragment replaces it. */
static size_t ble_emit(void* ctx, const uint8_t* frag, size_t len) {
  cc_road_ble_t* r = (cc_road_ble_t*)ctx;
  NimBLEExtAdvertising* adv = (NimBLEExtAdvertising*)r->adv;
  CcAdvCallbacks* done = (CcAdvCallbacks*)r->adv_cb;
  std::string mfg;

  mfg.reserve(len + 2);
  mfg.push_back((char)(CC_ROAD_BLE_COMPANY_ID & 0xff));
  mfg.push_back((char)((CC_ROAD_BLE_COMPANY_ID >> 8) & 0xff));
  mfg.append((const char*)frag, len);

  NimBLEExtAdvertisement ad(BLE_HCI_LE_PHY_1M, BLE_HCI_LE_PHY_1M);
  ad.setLegacyAdvertising(false);
  ad.setConnectable(false);
  ad.setScannable(false);
  ad.setAnonymous(true);
  ad.setMinInterval(r->cfg.adv_interval);
  ad.setMaxInterval(r->cfg.adv_interval);
  ad.setTxPower(r->cfg.tx_power);
  ad.setManufacturerData(mfg);

  if (adv->isActive(r->cfg.instance))
    adv->stop(r->cfg.instance);
  if (!adv->setInstanceData(r->cfg.instance, ad)) {
    r->stats.txFail++;
    return 0;
  }
  done->done = false;
  if (!adv->start(r->cfg.instance, r->cfg.adv_ms, 0)) {
    r->stats.txFail++;
    return 0;
  }

  /* The controller repeats the advertisement until the window elapses. */
  uint32_t start = millis();
  while (!done->done &&
         (uint32_t)(millis() - start) < (uint32_t)r->cfg.adv_ms + 250) {
    delay(5);
  }
  r->stats.txFrag++;
  return len;
}

static int ble_send(cc_road_t* road, const uint8_t* pkt, size_t len) {
  cc_road_ble_t* r = impl_of(road);

  if (!r->ready)
    return CC_ROAD_ERR;
  return cc_road_send_pkt(pkt, len, r->tx_id++, CC_ROAD_BLE_FRAG_PAYLOAD,
                          ble_emit, r);
}

static int ble_recv(cc_road_t* road, uint8_t* buf, size_t buf_sz,
                    size_t* len_out) {
  cc_road_ble_t* r = impl_of(road);
  int ret;

  if (!buf || !len_out)
    return CC_ROAD_ERR;
  if (r->pkt.len == 0)
    return CC_ROAD_EMPTY;
  ret = cc_road_pkt_get(&r->pkt, buf, buf_sz, len_out);
  r->pkt.len = 0; /* release the slot */
  return ret;
}

int cc_road_ble_init(cc_road_ble_t* r, const cc_road_ble_cfg_t* cfg) {
  if (!r)
    return CC_ROAD_ERR;
  memset(r, 0, sizeof(*r));
  cc_road_ble_defaults(&r->cfg);
  if (cfg)
    r->cfg = *cfg;
  cc_road_frag_init(&r->frag);

  /* msg_id is the only sender identity on the wire and increments per send, so
   * start it somewhere neither an attacker nor a peer that booted at the same
   * moment can predict. */
  r->tx_id = (uint8_t)(random(0, 256) ^ millis());

  NimBLEDevice::init("");
  r->adv = NimBLEDevice::getAdvertising();
  r->scan = NimBLEDevice::getScan();
  CcScanCallbacks* scanCb = new CcScanCallbacks();
  CcAdvCallbacks* advCb = new CcAdvCallbacks();
  if (!r->adv || !r->scan || !scanCb || !advCb)
    return CC_ROAD_ERR;
  scanCb->r = r;
  r->scan_cb = scanCb;
  r->adv_cb = advCb;
  ((NimBLEExtAdvertising*)r->adv)->setCallbacks(advCb, false);

  r->road.name = "ble";
  r->road.ctx = r;
  r->road.send = ble_send;
  r->road.recv = ble_recv;
  r->road.last_rssi = 0;
  r->road.last_snr = 0;
  r->ready = 1;

  NimBLEScan* scan = (NimBLEScan*)r->scan;
  scan->setAdvertisedDeviceCallbacks(scanCb, true /* wantDuplicates */);
  scan->setActiveScan(false);
  scan->setInterval(r->cfg.scan_interval_ms);
  scan->setWindow(r->cfg.scan_window_ms);
  /* Callbacks only: storing results would grow without bound in a mesh. */
  scan->setMaxResults(0);
  if (!scan->start(0, nullptr, false)) {
    r->ready = 0;
    return CC_ROAD_ERR;
  }
  return CC_ROAD_OK;
}

void cc_road_ble_shutdown(cc_road_ble_t* r) {
  if (!r || !r->ready)
    return;
  r->ready = 0;
  if (r->scan)
    ((NimBLEScan*)r->scan)->stop();
  NimBLEExtAdvertising* adv = (NimBLEExtAdvertising*)r->adv;
  if (adv) {
    if (adv->isActive(r->cfg.instance))
      adv->stop(r->cfg.instance);
    /* Drop our callback before deinit() frees the advertising object. */
    adv->setCallbacks(nullptr, false);
  }
  NimBLEDevice::deinit(true);
  delete (CcScanCallbacks*)r->scan_cb;
  delete (CcAdvCallbacks*)r->adv_cb;
  r->scan_cb = NULL;
  r->adv_cb = NULL;
}

#endif /* __has_include(<Arduino.h>) && __has_include(<NimBLEDevice.h>) */
