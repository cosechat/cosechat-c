/*
 * road_wifi — WiFi + UDP road (ESP32 Arduino).
 *
 * Compiled only when the Arduino WiFi stack is available; otherwise this is
 * an empty TU.
 */

#if __has_include(<Arduino.h>) && __has_include(<WiFiUdp.h>)

#include "road_wifi.h"

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <string.h>

#define CC_WIFI_DGRAM_MAX (CC_ROAD_FRAG_PAYLOAD + CC_ROAD_FRAG_HDR)

static char ip_str[16];

static cc_road_wifi_t* impl_of(cc_road_t* road) {
  return (cc_road_wifi_t*)road->ctx;
}

void cc_road_wifi_defaults(cc_road_wifi_cfg_t* cfg) {
  if (!cfg)
    return;
  cfg->ssid = NULL;
  cfg->pass = NULL;
  cfg->port = 4242;
  cfg->dst[0] = 255;
  cfg->dst[1] = 255;
  cfg->dst[2] = 255;
  cfg->dst[3] = 255;
  cfg->join_timeout_ms = 15000;
}

/* Emit one fragment as a UDP datagram to the configured peer. */
static size_t wifi_emit(void* ctx, const uint8_t* frag, size_t len) {
  cc_road_wifi_t* r = (cc_road_wifi_t*)ctx;
  WiFiUDP* udp = (WiFiUDP*)r->udp;
  IPAddress dst(r->cfg.dst[0], r->cfg.dst[1], r->cfg.dst[2], r->cfg.dst[3]);

  if (!udp->beginPacket(dst, r->cfg.port) || udp->write(frag, len) != len ||
      !udp->endPacket()) {
    r->stats.txFail++;
    return 0;
  }
  r->stats.txFrag++;
  /* Don't flood the socket buffer: a full announce is ~19-20 datagrams at 248
   * bytes of payload each. */
  delay(1);
  return len;
}

static int wifi_send(cc_road_t* road, const uint8_t* pkt, size_t len) {
  cc_road_wifi_t* r = impl_of(road);

  if (!r->ready)
    return CC_ROAD_ERR;
  return cc_road_send_pkt(pkt, len, r->tx_id++, CC_ROAD_FRAG_PAYLOAD, wifi_emit,
                          r);
}

static int wifi_recv(cc_road_t* road, uint8_t* buf, size_t buf_sz,
                     size_t* len_out) {
  cc_road_wifi_t* r = impl_of(road);
  WiFiUDP* udp = (WiFiUDP*)r->udp;
  uint8_t dgram[CC_WIFI_DGRAM_MAX];

  if (!r->ready || !buf || !len_out)
    return CC_ROAD_ERR;

  while (udp->parsePacket() > 0) {
    /* The datagram's sender, read from the socket rather than from the bytes:
     * IPv4 address then UDP source port. */
    IPAddress peer = udp->remoteIP();
    uint16_t peer_port = udp->remotePort();
    uint8_t src[CC_ROAD_SRC_SZ] = {peer[0],
                                   peer[1],
                                   peer[2],
                                   peer[3],
                                   (uint8_t)(peer_port >> 8),
                                   (uint8_t)(peer_port & 0xff)};
    int n = udp->read(dgram, sizeof(dgram));
    if (n <= CC_ROAD_FRAG_HDR) {
      r->stats.rxDrop++;
      continue;
    }
    /* recv() empties the slot before it returns, so it is never busy here. */
    int done = cc_road_rx_frag(&r->frag, dgram, (size_t)n, CC_ROAD_FRAG_PAYLOAD,
                               src, sizeof(src), &r->pkt);
    if (done == CC_ROAD_RX_BAD) {
      r->stats.rxDrop++;
    } else if (done == CC_ROAD_RX_READY) {
      r->stats.rxFrag++;
      int ret = cc_road_pkt_get(&r->pkt, buf, buf_sz, len_out);
      if (ret == CC_ROAD_OK)
        cc_road_src_take(&r->pkt, &r->road);
      r->pkt.len = 0; /* release the slot */
      return ret;
    }
  }
  return CC_ROAD_EMPTY;
}

int cc_road_wifi_init(cc_road_wifi_t* r, const cc_road_wifi_cfg_t* cfg) {
  if (!r)
    return CC_ROAD_ERR;
  memset(r, 0, sizeof(*r));
  cc_road_wifi_defaults(&r->cfg);
  if (cfg)
    r->cfg = *cfg;
  cc_road_frag_init(&r->frag);

  /* msg_id is the only sender identity on the wire and increments per send, so
   * start it somewhere neither an attacker nor a peer that booted at the same
   * moment can predict. */
  r->tx_id = (uint8_t)(random(0, 256) ^ millis());

  if (r->cfg.ssid) {
    WiFi.mode(WIFI_STA);
    WiFi.begin(r->cfg.ssid, r->cfg.pass);
    uint32_t start = millis();
    while (WiFi.status() != WL_CONNECTED) {
      if (r->cfg.join_timeout_ms == 0 ||
          millis() - start >= r->cfg.join_timeout_ms) {
        break;
      }
      delay(100);
    }
    if (WiFi.status() != WL_CONNECTED)
      return CC_ROAD_ERR;
  } else if (WiFi.status() != WL_CONNECTED) {
    /* No credentials: caller joined WiFi itself. */
    return CC_ROAD_ERR;
  }

  WiFiUDP* udp = new WiFiUDP();
  if (!udp)
    return CC_ROAD_ERR;
  if (!udp->begin(r->cfg.port)) {
    delete udp;
    return CC_ROAD_ERR;
  }
  r->udp = udp;

  r->road.name = "wifi";
  r->road.ctx = r;
  r->road.send = wifi_send;
  r->road.recv = wifi_recv;
  r->road.last_rssi = 0;
  r->road.last_snr = 0;
  r->ready = 1;
  return CC_ROAD_OK;
}

int cc_road_wifi_connected(const cc_road_wifi_t* r) {
  return (r && r->ready && WiFi.status() == WL_CONNECTED) ? 1 : 0;
}

const char* cc_road_wifi_ip(const cc_road_wifi_t* r) {
  if (!cc_road_wifi_connected(r))
    return NULL;
  IPAddress ip = WiFi.localIP();
  snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
  return ip_str;
}

void cc_road_wifi_shutdown(cc_road_wifi_t* r) {
  if (!r || !r->ready)
    return;
  if (r->udp) {
    ((WiFiUDP*)r->udp)->stop();
    delete (WiFiUDP*)r->udp;
    r->udp = NULL;
  }
  r->ready = 0;
}

#endif /* __has_include(<Arduino.h>) && __has_include(<WiFiUdp.h>) */
