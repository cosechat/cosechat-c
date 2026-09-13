/*
 * road_wifi — WiFi + UDP road (ESP32 Arduino).
 *
 * Compiled only when the Arduino WiFi stack is available; otherwise this is
 * an empty TU.
 */

#include <Arduino.h>

#if __has_include(<WiFiUdp.h>)

#include <WiFi.h>
#include <WiFiUdp.h>
#include <string.h>

#include "road_wifi.h"

#define CC_WIFI_DGRAM_MAX (CC_ROAD_FRAG_MAX_PAYLOAD + CC_ROAD_FRAG_HDR)

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

static int wifi_send(cc_road_t* road, const uint8_t* pkt, size_t len) {
  cc_road_wifi_t* r = impl_of(road);
  WiFiUDP* udp = (WiFiUDP*)r->udp;
  IPAddress dst(r->cfg.dst[0], r->cfg.dst[1], r->cfg.dst[2], r->cfg.dst[3]);
  size_t total, i;
  uint8_t id;
  uint8_t frag[CC_WIFI_DGRAM_MAX];

  if (!r->ready)
    return CC_ROAD_ERR;
  total = cc_road_frag_count(len);
  if (total == 0)
    return CC_ROAD_ERR;

  id = r->tx_id++;
  for (i = 0; i < total; i++) {
    size_t n =
        cc_road_frag_encode(pkt, len, id, (uint8_t)i, (uint8_t)total, frag);
    if (n == 0)
      return CC_ROAD_ERR;
    if (!udp->beginPacket(dst, r->cfg.port) || udp->write(frag, n) != n ||
        !udp->endPacket()) {
      r->stats.txFail++;
      return CC_ROAD_ERR;
    }
    r->stats.txFrag++;
    /* Don't flood the socket buffer: a 5 KB announce is ~21 datagrams. */
    delay(1);
  }
  return CC_ROAD_OK;
}

static int wifi_recv(cc_road_t* road, uint8_t* buf, size_t buf_sz,
                     size_t* len_out) {
  cc_road_wifi_t* r = impl_of(road);
  WiFiUDP* udp = (WiFiUDP*)r->udp;
  uint8_t dgram[CC_WIFI_DGRAM_MAX];
  int ret = CC_ROAD_EMPTY;

  if (!r->ready || !buf || !len_out)
    return CC_ROAD_ERR;

  while (udp->parsePacket() > 0) {
    int n = udp->read(dgram, sizeof(dgram));
    if (n <= CC_ROAD_FRAG_HDR) {
      r->stats.rxDrop++;
      continue;
    }
    int done = cc_road_frag_feed(&r->frag, dgram, (size_t)n);
    if (done < 0) {
      r->stats.rxDrop++;
    } else if (done == 1) {
      r->stats.rxFrag++;
      if (r->frag.len > buf_sz) {
        ret = CC_ROAD_ERR;
        continue;
      }
      memcpy(buf, r->frag.buf, r->frag.len);
      *len_out = r->frag.len;
      return CC_ROAD_OK;
    }
  }
  return ret;
}

int cc_road_wifi_init(cc_road_wifi_t* r, const cc_road_wifi_cfg_t* cfg) {
  if (!r)
    return CC_ROAD_ERR;
  memset(r, 0, sizeof(*r));
  cc_road_wifi_defaults(&r->cfg);
  if (cfg)
    r->cfg = *cfg;
  cc_road_frag_init(&r->frag);

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

#endif /* __has_include(<WiFiUdp.h>) */
