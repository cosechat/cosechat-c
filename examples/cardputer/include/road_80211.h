#ifndef CC_ROAD_80211_H
#define CC_ROAD_80211_H

/*
 * road_80211 — unauthenticated 802.11 management-frame road (ESP32).
 *
 * Packets ride vendor-specific action frames (category 127) addressed to the
 * broadcast MAC. An action frame is a plain management frame: it needs no
 * association, no authentication and no ACK, so this road never joins a
 * network and leaves no association state behind. The source address is a
 * random locally-administered MAC. Receiving is promiscuous-mode capture;
 * both ends must sit on the same channel (cfg.channel).
 *
 * The frame body is [category=127, OUI(3), fragment...], so one frame carries
 * CC_ROAD_FRAG_PAYLOAD fragment bytes and packets are split with the shared
 * road framing (cosechat_road.h).
 *
 * The promiscuous callback runs in the WiFi task and reassembles received
 * fragments there; recv() only reads the completed-packet slot and never
 * blocks.
 *
 * recv() attributes each packet: road->last_src / last_src_len are the
 * transmitter address (addr2) of the frame the packet arrived in — the
 * medium's own addressing, never a claim from inside the packet. Frames here
 * are unauthenticated, so a transmitter chooses the address it sends from; the
 * field says which link address a packet came in on, not who owns that
 * address.
 *
 * The struct embeds ~16 KB of buffers — declare it static/global.
 */

#include "cosechat_road.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CC_ROAD_80211_HDR 24       /* management frame header */
#define CC_ROAD_80211_ACTION 4     /* category byte + 3-byte OUI */
#define CC_ROAD_80211_CATEGORY 127 /* vendor-specific */
#define CC_ROAD_80211_FRAME_MAX                                  \
  (CC_ROAD_80211_HDR + CC_ROAD_80211_ACTION + CC_ROAD_FRAG_HDR + \
   CC_ROAD_FRAG_PAYLOAD) /* 280 */

typedef struct {
  uint8_t channel; /* 1; both ends must use the same channel */
} cc_road_80211_cfg_t;

typedef struct {
  uint32_t rxFrag; /* fragments reassembled into packets */
  uint32_t rxDrop; /* fragments/packets dropped (bad or busy) */
  uint32_t txFrag; /* frames transmitted */
  uint32_t txFail;
} cc_road_80211_stats_t;

typedef struct cc_road_80211 {
  cc_road_t road;
  cc_road_80211_cfg_t cfg;

  uint8_t src[6]; /* random locally-administered source MAC */
  uint8_t tx_id;
  int ready;
  cc_road_frag_t frag;
  cc_road_pkt_t pkt; /* completed packet waiting for recv() */
  cc_road_80211_stats_t stats;
} cc_road_80211_t;

/* Apply defaults (channel 1). */
void cc_road_80211_defaults(cc_road_80211_cfg_t* cfg);

/* Start WiFi in station mode, enable promiscuous capture on cfg.channel. */
int cc_road_80211_init(cc_road_80211_t* r, const cc_road_80211_cfg_t* cfg);

void cc_road_80211_shutdown(cc_road_80211_t* r);

#ifdef __cplusplus
}
#endif

#endif /* CC_ROAD_80211_H */
