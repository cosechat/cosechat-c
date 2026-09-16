/*
 * road_80211 — unauthenticated 802.11 management-frame road.
 *
 * Pure ESP-IDF: this road needs neither Arduino nor any C++ runtime, so it
 * builds under the arduino and espidf frameworks alike, and is an empty TU
 * wherever the WiFi stack is absent.
 */

#if __has_include(<esp_wifi.h>)

#include "road_80211.h"

#include <esp_event.h>
#include <esp_netif.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <string.h>

/* No real vendor owns this OUI; it only has to be ours on both ends. */
static const uint8_t k_oui[3] = {0xCC, 0x0C, 0x05};
static const uint8_t k_bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/* The promiscuous callback takes no context argument. */
static cc_road_80211_t* g_road;

static cc_road_80211_t* impl_of(cc_road_t* road) {
  return (cc_road_80211_t*)road->ctx;
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
  /* The slot holds one packet for recv(): a completion it has not collected
   * yet drops the new packet instead of being overwritten. The frame's
   * transmitter address (addr2) is what this packet is attributed to. */
  done = cc_road_rx_frag(&r->frag, frag, flen, CC_ROAD_FRAG_PAYLOAD, f + 10,
                         CC_ROAD_SRC_SZ, &r->pkt);
  if (done == CC_ROAD_RX_BAD) {
    r->stats.rxDrop++;
  } else if (done != CC_ROAD_RX_MORE) {
    r->stats.rxFrag++;
    r->road.last_rssi = (float)pkt->rx_ctrl.rssi;
    if (done == CC_ROAD_RX_BUSY)
      r->stats.rxDrop++;
  }
}

void cc_road_80211_defaults(cc_road_80211_cfg_t* cfg) {
  if (!cfg)
    return;
  cfg->channel = 1;
}

/* The action-frame header is built once per packet; each fragment is appended
 * to it. */
typedef struct {
  cc_road_80211_t* r;
  uint8_t* frame;
  size_t off;
} TxFrame;

static size_t cc_80211_emit(void* ctx, const uint8_t* frag, size_t len) {
  TxFrame* tx = (TxFrame*)ctx;
  cc_road_80211_t* r = tx->r;

  if (len == 0 || tx->off + len > CC_ROAD_80211_FRAME_MAX)
    return 0;
  memcpy(tx->frame + tx->off, frag, len);
  if (esp_wifi_80211_tx(WIFI_IF_STA, tx->frame, (int)(tx->off + len), true) !=
      ESP_OK) {
    r->stats.txFail++;
    return 0;
  }
  r->stats.txFrag++;
  vTaskDelay(pdMS_TO_TICKS(2));
  return len;
}

static int cc_80211_send(cc_road_t* road, const uint8_t* pkt, size_t len) {
  cc_road_80211_t* r = impl_of(road);
  uint8_t frame[CC_ROAD_80211_FRAME_MAX];
  TxFrame tx;

  if (!r->ready)
    return CC_ROAD_ERR;

  tx.r = r;
  tx.frame = frame;
  tx.off = CC_ROAD_80211_HDR + CC_ROAD_80211_ACTION;
  memset(frame, 0, tx.off);
  frame[0] = 0xd0;                /* management, action */
  memcpy(frame + 4, k_bcast, 6);  /* addr1: destination */
  memcpy(frame + 10, r->src, 6);  /* addr2: source */
  memcpy(frame + 16, k_bcast, 6); /* addr3: BSSID (none) */
  frame[CC_ROAD_80211_HDR] = CC_ROAD_80211_CATEGORY;
  memcpy(frame + CC_ROAD_80211_HDR + 1, k_oui, 3);

  return cc_road_send_pkt(pkt, len, r->tx_id++, CC_ROAD_FRAG_PAYLOAD,
                          cc_80211_emit, &tx);
}

static int cc_80211_recv(cc_road_t* road, uint8_t* buf, size_t buf_sz,
                         size_t* len_out) {
  cc_road_80211_t* r = impl_of(road);
  int ret;

  if (!buf || !len_out)
    return CC_ROAD_ERR;
  if (r->pkt.len == 0)
    return CC_ROAD_EMPTY;
  ret = cc_road_pkt_get(&r->pkt, buf, buf_sz, len_out);
  if (ret == CC_ROAD_OK)
    cc_road_src_take(&r->pkt, &r->road); /* who this packet came from */
  r->pkt.len = 0;                        /* release the slot */
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

  /* msg_id is the only sender identity on the wire and increments per send, so
   * start it somewhere neither an attacker nor a peer that booted at the same
   * moment can predict. */
  r->tx_id = (uint8_t)esp_random();

  /* Random locally-administered unicast address: nothing identifies the node.
   */
  r->src[0] = (uint8_t)((esp_random() & 0xfc) | 0x02);
  for (int i = 1; i < 6; i++) r->src[i] = (uint8_t)esp_random();

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
}

#endif /* __has_include(<esp_wifi.h>) */
