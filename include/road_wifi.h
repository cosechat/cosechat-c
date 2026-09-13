#ifndef CC_ROAD_WIFI_H
#define CC_ROAD_WIFI_H

/*
 * road_wifi — WiFi + UDP road (ESP32 Arduino).
 *
 * Joins a WiFi network and exchanges fragmented cosechat packets over UDP,
 * broadcast by default so every node on the LAN sees announces without any
 * peer configuration. Datagrams are the shared road framing (road.h), so the
 * same fragmentation/reassembly code serves both roads.
 *
 * There is no background task: recv() drains the socket, so call it from your
 * main loop.
 *
 * The struct embeds ~16 KB of buffers — declare it static/global.
 */

#include "road.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  const char* ssid;
  const char* pass;
  uint16_t port;  /* 4242 */
  uint8_t dst[4]; /* destination IP; default 255.255.255.255 (broadcast) */
  uint32_t join_timeout_ms; /* 15000; 0 = don't wait */
} cc_road_wifi_cfg_t;

typedef struct {
  uint32_t rxFrag;
  uint32_t rxDrop;
  uint32_t txFrag;
  uint32_t txFail;
} cc_road_wifi_stats_t;

typedef struct cc_road_wifi {
  cc_road_t road;
  cc_road_wifi_cfg_t cfg;

  void* udp; /* WiFiUDP* */
  uint8_t tx_id;
  int ready;
  cc_road_frag_t frag;
  uint8_t pktbuf[CC_ROAD_PKT_BUF_SZ];
  cc_road_wifi_stats_t stats;
} cc_road_wifi_t;

/* Apply defaults (port 4242, broadcast) to cfg. */
void cc_road_wifi_defaults(cc_road_wifi_cfg_t* cfg);

/* Join WiFi and bind the UDP port. cfg may be NULL for defaults (broadcast). */
int cc_road_wifi_init(cc_road_wifi_t* r, const cc_road_wifi_cfg_t* cfg);

/* 1 when the station has an IP. */
int cc_road_wifi_connected(const cc_road_wifi_t* r);

/* Local IPv4 address as a string, or NULL when not joined. */
const char* cc_road_wifi_ip(const cc_road_wifi_t* r);

void cc_road_wifi_shutdown(cc_road_wifi_t* r);

#ifdef __cplusplus
}
#endif

#endif /* CC_ROAD_WIFI_H */
