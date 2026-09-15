/*
 * road_80211 — unauthenticated 802.11 management-frame road.
 *
 * Compiled only where the ESP32 WiFi stack is available; otherwise this is an
 * empty TU.
 */

#include <Arduino.h>

#if __has_include(<esp_wifi.h>)

#include <esp_event.h>
#include <esp_netif.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <string.h>

#include "road_80211.h"

/* No real vendor owns this OUI; it only has to be ours on both ends. */
static const uint8_t k_oui[3] = {0xCC, 0x0C, 0x05};
static const uint8_t k_bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* The promiscuous callback takes no context argument. */
static cc_road_80211_t* g_road;

static cc_road_80211_t* impl_of(cc_road_t* road) {
  return (cc_road_80211_t*)road->ctx;
}

/* Hand the completed packet to recv(). The slot semaphore is held until recv()
 * has copied pktbuf, so a new packet never overwrites one being read. */
static void pkt_push(cc_road_80211_t* r) {
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

static void cc_80211_rx(void* buf, wifi_promiscuous_pkt_type_t type) {
  cc_road_80211_t* r = g_road;
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  const uint8_t* f;
  const uint8_t* frag;
  int len;
  size_t flen;
  int done;

  if (!r || type != WIFI_PKT_MGMT)
    return;

  len = (int)pkt->rx_ctrl.sig_len;
  if (len <= 4)
    return;
  /* The driver reports management frames with the 4-byte FCS included. */
  len -= 4;
  if (len < CC_ROAD_80211_HDR + CC_ROAD_80211_ACTION)
    return;

  f = pkt->payload;
  if ((f[0] & 0xfc) != 0xd0) /* management, action */
    return;
  if (memcmp(f + 4, k_bcast, 6) != 0) /* to broadcast */
    return;
  if (memcmp(f + 10, r->src, 6) == 0) /* our own frame, echoed */
    return;
  if (f[CC_ROAD_80211_HDR] != CC_ROAD_80211_CATEGORY)
    return;
  if (memcmp(f + CC_ROAD_80211_HDR + 1, k_oui, 3) != 0)
    return;

  frag = f + CC_ROAD_80211_HDR + CC_ROAD_80211_ACTION;
  flen = (size_t)(len - CC_ROAD_80211_HDR - CC_ROAD_80211_ACTION);
  done = cc_road_frag_feed(&r->frag, frag, flen);
  if (done < 0) {
    r->stats.rxDrop++;
  } else if (done == 1) {
    r->stats.rxFrag++;
    r->road.last_rssi = (float)pkt->rx_ctrl.rssi;
    pkt_push(r);
  }
}

void cc_road_80211_defaults(cc_road_80211_cfg_t* cfg) {
  if (!cfg)
    return;
  cfg->channel = 1;
}

static int cc_80211_send(cc_road_t* road, const uint8_t* pkt, size_t len) {
  cc_road_80211_t* r = impl_of(road);
  uint8_t frame[CC_ROAD_80211_FRAME_MAX];
  size_t total, i, off;
  uint8_t id;

  if (!r->ready)
    return CC_ROAD_ERR;
  total = cc_road_frag_count(len);
  if (total == 0)
    return CC_ROAD_ERR;

  off = CC_ROAD_80211_HDR + CC_ROAD_80211_ACTION;
  memset(frame, 0, off);
  frame[0] = 0xd0; /* management, action */
  memcpy(frame + 4, k_bcast, 6);  /* addr1: destination */
  memcpy(frame + 10, r->src, 6);  /* addr2: source */
  memcpy(frame + 16, k_bcast, 6); /* addr3: BSSID (none) */
  frame[CC_ROAD_80211_HDR] = CC_ROAD_80211_CATEGORY;
  memcpy(frame + CC_ROAD_80211_HDR + 1, k_oui, 3);

  id = r->tx_id++;
  for (i = 0; i < total; i++) {
    size_t n =
        cc_road_frag_encode(pkt, len, id, (uint8_t)i, (uint8_t)total,
                            frame + off);
    if (n == 0)
      return CC_ROAD_ERR;
    if (esp_wifi_80211_tx(WIFI_IF_STA, frame, (int)(off + n), true) != ESP_OK) {
      r->stats.txFail++;
      return CC_ROAD_ERR;
    }
    r->stats.txFrag++;
    delay(2);
  }
  return CC_ROAD_OK;
}

static int cc_80211_recv(cc_road_t* road, uint8_t* buf, size_t buf_sz,
                         size_t* len_out) {
  cc_road_80211_t* r = impl_of(road);
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

int cc_road_80211_init(cc_road_80211_t* r, const cc_road_80211_cfg_t* cfg) {
  wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
  wifi_promiscuous_filter_t filt = {};

  if (!r)
    return CC_ROAD_ERR;
  memset(r, 0, sizeof(*r));
  cc_road_80211_defaults(&r->cfg);
  if (cfg)
    r->cfg = *cfg;
  cc_road_frag_init(&r->frag);

  r->rx_q = xQueueCreate(4, sizeof(size_t));
  r->slot = xSemaphoreCreateBinary();
  if (!r->rx_q || !r->slot)
    return CC_ROAD_ERR;
  xSemaphoreGive((SemaphoreHandle_t)r->slot);

  /* Random locally-administered unicast address: nothing identifies the node. */
  r->src[0] = (uint8_t)((esp_random() & 0xfc) | 0x02);
  for (int i = 1; i < 6; i++)
    r->src[i] = (uint8_t)esp_random();

  /* Arduino may already have brought these up; failure here is fine. */
  esp_netif_init();
  esp_event_loop_create_default();

  if (esp_wifi_init(&wcfg) != ESP_OK)
    return CC_ROAD_ERR;
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  if (esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK)
    return CC_ROAD_ERR;
  if (esp_wifi_start() != ESP_OK)
    return CC_ROAD_ERR;

  g_road = r;
  filt.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT;
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&cc_80211_rx);
  if (esp_wifi_set_promiscuous(true) != ESP_OK)
    return CC_ROAD_ERR;
  esp_wifi_set_ps(WIFI_PS_NONE);
  if (esp_wifi_set_channel(r->cfg.channel, WIFI_SECOND_CHAN_NONE) != ESP_OK)
    return CC_ROAD_ERR;

  r->road.name = "80211";
  r->road.ctx = r;
  r->road.send = cc_80211_send;
  r->road.recv = cc_80211_recv;
  r->road.last_rssi = 0;
  r->road.last_snr = 0;
  r->ready = 1;
  return CC_ROAD_OK;
}

void cc_road_80211_shutdown(cc_road_80211_t* r) {
  if (!r || !r->ready)
    return;
  r->ready = 0;
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_deinit();
  g_road = NULL;
  if (r->rx_q) {
    vQueueDelete((QueueHandle_t)r->rx_q);
    r->rx_q = NULL;
  }
  if (r->slot) {
    vSemaphoreDelete((SemaphoreHandle_t)r->slot);
    r->slot = NULL;
  }
}

#endif /* __has_include(<esp_wifi.h>) */
