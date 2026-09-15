/*
 * road_ble — anonymous BLE extended-advertising road (NimBLE).
 *
 * Compiled only when NimBLE-Arduino is available; otherwise this is an empty
 * TU, so the library still builds for LoRa/WiFi-only targets.
 */

#include <Arduino.h>

#if __has_include(<NimBLEDevice.h>)

#include <NimBLEDevice.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <string.h>

#include "road_ble.h"

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

/* Hand the completed packet to recv(). The slot semaphore is held until recv()
 * has copied pktbuf, so a new packet never overwrites one being read. */
static void ble_push(cc_road_ble_t* r) {
  if (xSemaphoreTake((SemaphoreHandle_t)r->slot, 0) != pdPASS) {
    r->stats.rxDrop++;
    return;
  }
  memcpy(r->pktbuf, r->frag.buf, r->frag.len);
  size_t len = r->frag.len;
  if (xQueueSend((QueueHandle_t)r->rx_q, &len, 0) != pdPASS) {
    xSemaphoreGive((SemaphoreHandle_t)r->slot);
    r->stats.rxDrop++;
  }
}

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
  int done = cc_road_frag_feed_n(&r->frag, frag, flen,
                                 CC_ROAD_BLE_FRAG_PAYLOAD);
  if (done < 0) {
    r->stats.rxDrop++;
  } else if (done == 1) {
    r->stats.rxFrag++;
    r->road.last_rssi = (float)dev->getRSSI();
    ble_push(r);
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

static int ble_send(cc_road_t* road, const uint8_t* pkt, size_t len) {
  cc_road_ble_t* r = impl_of(road);
  NimBLEExtAdvertising* adv = (NimBLEExtAdvertising*)r->adv;
  CcAdvCallbacks* done = (CcAdvCallbacks*)r->adv_cb;
  uint8_t frag[CC_ROAD_FRAG_HDR + CC_ROAD_BLE_FRAG_PAYLOAD];
  size_t total, i;
  uint8_t id;

  if (!r->ready)
    return CC_ROAD_ERR;
  total = cc_road_frag_count_n(len, CC_ROAD_BLE_FRAG_PAYLOAD);
  if (total == 0)
    return CC_ROAD_ERR;

  id = r->tx_id++;
  for (i = 0; i < total; i++) {
    size_t n = cc_road_frag_encode_n(pkt, len, id, (uint8_t)i, (uint8_t)total,
                                     CC_ROAD_BLE_FRAG_PAYLOAD, frag);
    if (n == 0)
      return CC_ROAD_ERR;

    std::string mfg;
    mfg.reserve(n + 2);
    mfg.push_back((char)(CC_ROAD_BLE_COMPANY_ID & 0xff));
    mfg.push_back((char)((CC_ROAD_BLE_COMPANY_ID >> 8) & 0xff));
    mfg.append((const char*)frag, n);

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
      return CC_ROAD_ERR;
    }
    done->done = false;
    if (!adv->start(r->cfg.instance, r->cfg.adv_ms, 0)) {
      r->stats.txFail++;
      return CC_ROAD_ERR;
    }

    /* The controller repeats the advertisement until the window elapses. */
    uint32_t start = millis();
    while (!done->done &&
           (uint32_t)(millis() - start) < (uint32_t)r->cfg.adv_ms + 250) {
      delay(5);
    }
    r->stats.txFrag++;
  }
  return CC_ROAD_OK;
}

static int ble_recv(cc_road_t* road, uint8_t* buf, size_t buf_sz,
                    size_t* len_out) {
  cc_road_ble_t* r = impl_of(road);
  size_t len;
  int ret = CC_ROAD_OK;

  if (!buf || !len_out)
    return CC_ROAD_ERR;
  if (xQueueReceive((QueueHandle_t)r->rx_q, &len, 0) != pdPASS)
    return CC_ROAD_EMPTY;
  if (len <= buf_sz) {
    memcpy(buf, r->pktbuf, len);
    *len_out = len;
  } else {
    ret = CC_ROAD_ERR;
  }
  xSemaphoreGive((SemaphoreHandle_t)r->slot);
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

  r->rx_q = xQueueCreate(4, sizeof(size_t));
  r->slot = xSemaphoreCreateBinary();
  if (!r->rx_q || !r->slot)
    return CC_ROAD_ERR;
  xSemaphoreGive((SemaphoreHandle_t)r->slot);

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
  if (r->rx_q) {
    vQueueDelete((QueueHandle_t)r->rx_q);
    r->rx_q = NULL;
  }
  if (r->slot) {
    vSemaphoreDelete((SemaphoreHandle_t)r->slot);
    r->slot = NULL;
  }
}

#endif /* __has_include(<NimBLEDevice.h>) */
