#ifndef CC_ROAD_LORA_H
#define CC_ROAD_LORA_H

/*
 * road_lora — SX1262 LoRa road (RadioLib).
 *
 * Owns a FreeRTOS radio task that keeps the radio in RX except while
 * transmitting. Packets are fragmented to fit the SX1262 252-byte limit and
 * reassembled before being handed back as whole cosechat packets.
 *
 * A radio frame carries payload and nothing else, so recv() is UNABLE to
 * attribute a packet: road->last_src_len is always 0. A caller must treat that
 * as "sender unknown" and must not fall back to the address the packet
 * announces (see the contract on cc_road_t.last_src).
 *
 * Defaults match the M5Stack LoRa Cap 1262 on a CardputerADV (SX1262 on the
 * shared SPI bus, antenna switch controlled by the caller via `antenna`).
 *
 * The struct embeds ~16 KB of buffers — declare it static/global.
 */

#include "cosechat_road.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  /* Radio */
  float freq;           /* 915.0 */
  float bw;             /* 125.0 */
  uint8_t sf;           /* 7 */
  uint8_t cr;           /* 5 */
  uint8_t sync_word;    /* 0x12 */
  int8_t power;         /* 0 dBm */
  uint8_t preamble;     /* 6 */
  float tcxo_voltage;   /* 3.0; <0 = no TCXO */
  int8_t current_limit; /* 140 mA */
  int dio2_rf_switch;   /* 0 = external RF switch */

  /* Pins (CardputerADV + LoRa Cap 1262) */
  int8_t pin_cs;   /* 5 */
  int8_t pin_irq;  /* 4 */
  int8_t pin_rst;  /* 3 */
  int8_t pin_busy; /* 6 */
  /* SPI pins; pass -1 to leave the bus alone (already begun by caller) */
  int8_t pin_sck;  /* 40 */
  int8_t pin_miso; /* 39 */
  int8_t pin_mosi; /* 14 */

  /* Optional RF switch control: called with true before RX, false before TX */
  void (*antenna)(int rx);
  /* Optional SPI mutex (SemaphoreHandle_t) shared with other bus users (SD) */
  void* spi_mux;
  /* Radio task */
  uint32_t task_stack; /* 4096 */
  uint32_t task_prio;  /* 1 */
} cc_road_lora_cfg_t;

typedef struct {
  uint32_t rxFrag; /* fragments reassembled into packets */
  uint32_t rxDrop; /* fragments/packets dropped (bad or busy) */
  uint32_t txFrag; /* fragments transmitted */
  uint32_t txFail;
} cc_road_lora_stats_t;

typedef struct cc_road_lora {
  cc_road_t road; /* base interface (ctx points back at this struct) */
  cc_road_lora_cfg_t cfg;

  void* radio; /* RadioLib SX1262* */
  void* tx_q;  /* QueueHandle_t of TxJob */
  void* mux;   /* SemaphoreHandle_t (borrowed if cfg.spi_mux set) */
  void* task;
  int own_mux;
  int ready;

  uint8_t tx_id;
  cc_road_frag_t frag __attribute__((aligned(4)));
  cc_road_pkt_t pkt; /* completed packet waiting for recv() */
  cc_road_lora_stats_t stats;
} cc_road_lora_t;

/* Apply defaults (CardputerADV + LoRa Cap 1262) to cfg. */
void cc_road_lora_defaults(cc_road_lora_cfg_t* cfg);

/* Init radio + start task. cfg may be NULL for defaults. */
int cc_road_lora_init(cc_road_lora_t* r, const cc_road_lora_cfg_t* cfg);

/* Stop the radio task and put the radio to sleep. */
void cc_road_lora_shutdown(cc_road_lora_t* r);

#ifdef __cplusplus
}
#endif

#endif /* CC_ROAD_LORA_H */
