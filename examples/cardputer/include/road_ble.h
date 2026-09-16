#ifndef CC_ROAD_BLE_H
#define CC_ROAD_BLE_H

/*
 * road_ble — anonymous BLE extended-advertising road (ESP32-S3/C3, NimBLE).
 *
 * Every cosechat fragment rides one BLE 5 extended advertisement as
 * manufacturer-specific data (company id 0xFFFF). Advertisements are
 * non-connectable, non-scannable and anonymous — the controller omits the
 * advertiser address — so a node reveals nothing but the packet bytes: no
 * connection, no bonding, no GAP address, no scan response. Receiving is a
 * continuous passive scan; any BLE 5 scanner in range sees the same bytes.
 *
 * Anonymous by design means unattributable by design: with no advertiser
 * address and no scan response there is nothing to record, so recv() always
 * reports road->last_src_len == 0. A caller must treat that as "sender
 * unknown" and must not fall back to the address the packet announces (see the
 * contract on cc_road_t.last_src).
 *
 * One advertisement carries at most CC_ROAD_BLE_FRAG_PAYLOAD fragment bytes
 * (the 251-byte extended-advertising data limit minus the AD and road
 * headers), so packets are split with the shared road framing
 * (cosechat_road.h). A full announce (name and metadata at their limits) is 21
 * advertisements.
 *
 * send() blocks while each fragment advertises (cfg.adv_ms) because the
 * advertisement data must be swapped per fragment. The NimBLE host task does
 * RX and reassembly, so recv() only reads the completed-packet slot and never
 * blocks.
 *
 * Requires NimBLE-Arduino >= 1.4 with extended advertising enabled:
 *
 *     -DCONFIG_BT_NIMBLE_EXT_ADV=1
 *     -DCONFIG_BT_NIMBLE_MAX_EXT_ADV_INSTANCES=1
 *     -DCONFIG_BT_NIMBLE_MAX_EXT_ADV_DATA_LEN=251
 *
 * The struct embeds ~16 KB of buffers — declare it static/global.
 */

#include "cosechat_road.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Extended-advertising data limit, and what is left of it for our packet. */
#define CC_ROAD_BLE_ADV_MAX 251
#define CC_ROAD_BLE_COMPANY_ID 0xFFFF /* reserved for testing */
/* AD header (len+type) + company id + road fragment header. */
#define CC_ROAD_BLE_FRAG_PAYLOAD \
  (CC_ROAD_BLE_ADV_MAX - 2 - 2 - CC_ROAD_FRAG_HDR) /* 243 */

typedef struct {
  uint8_t instance;          /* 0; extended-advertising instance id */
  int8_t tx_power;           /* 0 dBm; controller range is -27..18 on S3 */
  uint16_t adv_interval;     /* 32 = 20 ms, in 0.625 ms units */
  uint16_t adv_ms;           /* 120; how long each fragment is advertised */
  uint16_t scan_interval_ms; /* 100 */
  uint16_t scan_window_ms;   /* 100 */
} cc_road_ble_cfg_t;

typedef struct {
  uint32_t rxFrag; /* fragments reassembled into packets */
  uint32_t rxDrop; /* fragments/packets dropped (bad or busy) */
  uint32_t txFrag; /* fragments advertised */
  uint32_t txFail;
} cc_road_ble_stats_t;

typedef struct cc_road_ble {
  cc_road_t road;
  cc_road_ble_cfg_t cfg;

  void* adv;     /* NimBLEExtAdvertising* */
  void* scan;    /* NimBLEScan* */
  void* adv_cb;  /* advertisement-stopped callback */
  void* scan_cb; /* scan-result callback */
  uint8_t tx_id;
  int ready;
  cc_road_frag_t frag;
  cc_road_pkt_t pkt; /* completed packet waiting for recv() */
  cc_road_ble_stats_t stats;
} cc_road_ble_t;

/* Apply defaults (instance 0, 0 dBm, 20 ms interval, 120 ms per fragment). */
void cc_road_ble_defaults(cc_road_ble_cfg_t* cfg);

/* Bring up NimBLE, start advertising and a continuous passive scan. */
int cc_road_ble_init(cc_road_ble_t* r, const cc_road_ble_cfg_t* cfg);

void cc_road_ble_shutdown(cc_road_ble_t* r);

#ifdef __cplusplus
}
#endif

#endif /* CC_ROAD_BLE_H */
