/*
 * road_lora — SX1262 LoRa road (RadioLib).
 *
 * A dedicated FreeRTOS task owns the radio: it drains the TX queue (each job
 * is one fragment) and otherwise keeps the SX1262 in RX. Received fragments
 * are reassembled into whole cosechat packets and left in the road's slot for
 * recv().
 *
 * The SX1262 packet limit is 252 bytes, so every cosechat packet is split by
 * the shared road framing (see cosechat_road.h).
 *
 * Compiled only when RadioLib is available; otherwise this is an empty TU.
 */

#if __has_include(<Arduino.h>) && __has_include(<RadioLib.h>)

#include "road_lora.h"

#include <Arduino.h>
#include <RadioLib.h>
#include <SPI.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <string.h>

#define CC_LORA_MAX_PKT (CC_ROAD_FRAG_PAYLOAD + CC_ROAD_FRAG_HDR) /* 252 */

typedef struct {
  uint8_t data[CC_LORA_MAX_PKT];
  uint8_t len;
} TxJob;

typedef struct {
  uint8_t data[CC_LORA_MAX_PKT];
  uint8_t len;
  float rssi;
  float snr;
} RxFrag;

static cc_road_lora_t* impl_of(cc_road_t* road) {
  return (cc_road_lora_t*)road->ctx;
}

static inline void bus_lock(cc_road_lora_t* r) {
  xSemaphoreTake((SemaphoreHandle_t)r->mux, portMAX_DELAY);
}

static inline void bus_unlock(cc_road_lora_t* r) {
  xSemaphoreGive((SemaphoreHandle_t)r->mux);
}

static void set_antenna(cc_road_lora_t* r, int rx) {
  if (r->cfg.antenna)
    r->cfg.antenna(rx);
}

void cc_road_lora_defaults(cc_road_lora_cfg_t* cfg) {
  if (!cfg)
    return;
  cfg->freq = 915.0;
  cfg->bw = 125.0;
  cfg->sf = 7;
  cfg->cr = 5;
  cfg->sync_word = 0x12;
  cfg->power = 0;
  cfg->preamble = 6;
  cfg->tcxo_voltage = 3.0;
  cfg->current_limit = 140;
  cfg->dio2_rf_switch = 0;
  cfg->pin_cs = 5;
  cfg->pin_irq = 4;
  cfg->pin_rst = 3;
  cfg->pin_busy = 6;
  cfg->pin_sck = 40;
  cfg->pin_miso = 39;
  cfg->pin_mosi = 14;
  cfg->antenna = NULL;
  cfg->spi_mux = NULL;
  cfg->task_stack = 4096;
  cfg->task_prio = 1;
}

static void radio_task(void* arg) {
  cc_road_lora_t* r = (cc_road_lora_t*)arg;
  SX1262* radio = (SX1262*)r->radio;
  QueueHandle_t txq = (QueueHandle_t)r->tx_q;

  bus_lock(r);
  set_antenna(r, 1);
  radio->startReceive();
  bus_unlock(r);

  for (;;) {
    TxJob job;
    if (xQueueReceive(txq, &job, 0) == pdPASS) {
      bus_lock(r);
      radio->standby();
      bus_unlock(r);

      set_antenna(r, 0);
      bus_lock(r);
      int state = radio->transmit(job.data, job.len);
      radio->clearIrqFlags(RADIOLIB_SX126X_IRQ_ALL);
      bus_unlock(r);
      if (state == RADIOLIB_ERR_NONE) {
        r->stats.txFrag++;
      } else {
        r->stats.txFail++;
      }

      set_antenna(r, 1);
      bus_lock(r);
      radio->startReceive();
      bus_unlock(r);

      /* Let receivers drain this fragment before the next one lands. */
      vTaskDelay(pdMS_TO_TICKS(20));
      continue;
    }

    bus_lock(r);
    uint16_t irq = radio->getIrqFlags();
    bus_unlock(r);

    if (irq & RADIOLIB_SX126X_IRQ_RX_DONE) {
      RxFrag evt;
      memset(&evt, 0, sizeof(evt));
      bus_lock(r);
      int pkt_len = radio->getPacketLength();
      if (pkt_len > 0 && pkt_len <= CC_LORA_MAX_PKT) {
        int state = radio->readData(evt.data, pkt_len);
        if (state == RADIOLIB_ERR_NONE) {
          evt.len = (uint8_t)pkt_len;
          evt.rssi = radio->getRSSI();
          evt.snr = radio->getSNR();
        }
      }
      radio->clearIrqFlags(RADIOLIB_SX126X_IRQ_RX_DONE |
                           RADIOLIB_SX126X_IRQ_HEADER_ERR |
                           RADIOLIB_SX126X_IRQ_CRC_ERR);
      radio->startReceive();
      bus_unlock(r);

      if (evt.len == 0) {
        r->stats.rxDrop++;
      } else {
        int done;
        bus_lock(r);
        /* No source: an SX1262 frame carries no sender field, so this road
         * cannot say who sent the packet (road->last_src_len stays 0). */
        done = cc_road_rx_frag(&r->frag, evt.data, evt.len,
                               CC_ROAD_FRAG_PAYLOAD, NULL, 0, &r->pkt);
        bus_unlock(r);
        if (done == CC_ROAD_RX_BAD) {
          r->stats.rxDrop++;
        } else if (done != CC_ROAD_RX_MORE) {
          /* complete: handed to the slot, or dropped because recv() had not
           * collected the previous packet yet. */
          r->stats.rxFrag++;
          r->road.last_rssi = evt.rssi;
          r->road.last_snr = evt.snr;
          if (done == CC_ROAD_RX_BUSY)
            r->stats.rxDrop++;
        }
      }
    } else if (irq & RADIOLIB_SX126X_IRQ_TIMEOUT) {
      bus_lock(r);
      radio->clearIrqFlags(RADIOLIB_SX126X_IRQ_TIMEOUT);
      radio->startReceive();
      bus_unlock(r);
    }

    vTaskDelay(pdMS_TO_TICKS(5));
  }
}

/* Emit one fragment: hand it to the radio task, which counts what the radio
 * actually transmitted. */
static size_t lora_emit(void* ctx, const uint8_t* frag, size_t len) {
  cc_road_lora_t* r = (cc_road_lora_t*)ctx;
  TxJob job;

  if (len == 0 || len > sizeof(job.data))
    return 0;
  memcpy(job.data, frag, len);
  job.len = (uint8_t)len;
  if (xQueueSend((QueueHandle_t)r->tx_q, &job, pdMS_TO_TICKS(5000)) != pdPASS)
    return 0;
  return len;
}

static int lora_send(cc_road_t* road, const uint8_t* pkt, size_t len) {
  cc_road_lora_t* r = impl_of(road);

  if (!r->ready)
    return CC_ROAD_ERR;
  return cc_road_send_pkt(pkt, len, r->tx_id++, CC_ROAD_FRAG_PAYLOAD, lora_emit,
                          r);
}

static int lora_recv(cc_road_t* road, uint8_t* buf, size_t buf_sz,
                     size_t* len_out) {
  cc_road_lora_t* r = impl_of(road);
  int ret;

  if (!buf || !len_out)
    return CC_ROAD_ERR;
  if (r->pkt.len == 0)
    return CC_ROAD_EMPTY;
  bus_lock(r);
  ret = cc_road_pkt_get(&r->pkt, buf, buf_sz, len_out);
  if (ret == CC_ROAD_OK)
    cc_road_src_take(&r->pkt, &r->road); /* always "unknown" on this road */
  r->pkt.len = 0;                        /* release the slot */
  bus_unlock(r);
  return ret;
}

int cc_road_lora_init(cc_road_lora_t* r, const cc_road_lora_cfg_t* cfg) {
  if (!r)
    return CC_ROAD_ERR;
  memset(r, 0, sizeof(*r));
  cc_road_lora_defaults(&r->cfg);
  if (cfg)
    r->cfg = *cfg;
  cc_road_frag_init(&r->frag);

  /* msg_id is the only sender identity on the wire and increments per send, so
   * start it somewhere neither an attacker nor a peer that booted at the same
   * moment can predict. */
  r->tx_id = (uint8_t)(random(0, 256) ^ millis());

  if (r->cfg.task_stack == 0)
    r->cfg.task_stack = 4096;
  if (r->cfg.task_prio == 0)
    r->cfg.task_prio = 1;

  if (r->cfg.spi_mux) {
    r->mux = r->cfg.spi_mux;
    r->own_mux = 0;
  } else {
    r->mux = xSemaphoreCreateMutex();
    r->own_mux = 1;
    if (!r->mux)
      return CC_ROAD_ERR;
  }

  if (r->cfg.pin_sck >= 0) {
    SPI.begin(r->cfg.pin_sck, r->cfg.pin_miso, r->cfg.pin_mosi, r->cfg.pin_cs);
  }

  Module* mod = new Module(r->cfg.pin_cs, r->cfg.pin_irq, r->cfg.pin_rst,
                           r->cfg.pin_busy, SPI);
  if (!mod)
    return CC_ROAD_ERR;
  SX1262* radio = new SX1262(mod);
  if (!radio)
    return CC_ROAD_ERR;
  r->radio = radio;

  int state = radio->begin(r->cfg.freq, r->cfg.bw, r->cfg.sf, r->cfg.cr,
                           r->cfg.sync_word, r->cfg.power, r->cfg.preamble,
                           r->cfg.tcxo_voltage, true);
  if (state != RADIOLIB_ERR_NONE)
    return state;

  radio->setCurrentLimit(r->cfg.current_limit);
  radio->setDio2AsRfSwitch(r->cfg.dio2_rf_switch != 0);

  r->tx_q = xQueueCreate(64, sizeof(TxJob));
  if (!r->tx_q)
    return CC_ROAD_ERR;

  r->road.name = "lora";
  r->road.ctx = r;
  r->road.send = lora_send;
  r->road.recv = lora_recv;
  r->road.last_rssi = 0;
  r->road.last_snr = 0;
  r->ready = 1;

  if (xTaskCreate(radio_task, "ccLora", r->cfg.task_stack, r, r->cfg.task_prio,
                  (TaskHandle_t*)&r->task) != pdPASS) {
    r->ready = 0;
    return CC_ROAD_ERR;
  }
  return CC_ROAD_OK;
}

void cc_road_lora_shutdown(cc_road_lora_t* r) {
  if (!r || !r->ready)
    return;
  if (r->task) {
    vTaskDelete((TaskHandle_t)r->task);
    r->task = NULL;
  }
  bus_lock(r);
  ((SX1262*)r->radio)->sleep();
  bus_unlock(r);
  r->ready = 0;
  if (r->own_mux && r->mux) {
    vSemaphoreDelete((SemaphoreHandle_t)r->mux);
    r->mux = NULL;
  }
  if (r->tx_q) {
    vQueueDelete((QueueHandle_t)r->tx_q);
    r->tx_q = NULL;
  }
}

#endif /* __has_include(<Arduino.h>) && __has_include(<RadioLib.h>) */
