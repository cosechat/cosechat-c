/*
 * road_lora — SX1262 LoRa road (RadioLib).
 *
 * A dedicated FreeRTOS task owns the radio: it drains the TX queue (each job
 * is one fragment) and otherwise keeps the SX1262 in RX. Received fragments
 * are reassembled into whole cosechat packets and queued for recv().
 *
 * The SX1262 packet limit is 252 bytes, so every cosechat packet is split by
 * the shared road framing (see road.h).
 *
 * Compiled only when RadioLib is available; otherwise this is an empty TU.
 */

#include <Arduino.h>

#if __has_include(<RadioLib.h>)

#include <RadioLib.h>
#include <SPI.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <string.h>

#include "road_lora.h"

#define CC_LORA_MAX_PKT (CC_ROAD_FRAG_MAX_PAYLOAD + CC_ROAD_FRAG_HDR) /* 252 \
                                                                       */

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
  QueueHandle_t rxq = (QueueHandle_t)r->rx_q;

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
        int done = cc_road_frag_feed(&r->frag, evt.data, evt.len);
        if (done < 0) {
          r->stats.rxDrop++;
        } else if (done == 1) {
          r->stats.rxFrag++;
          r->road.last_rssi = evt.rssi;
          r->road.last_snr = evt.snr;
          /* Keep one completed packet at a time: pktbuf is a single slot. */
          bus_lock(r);
          bool busy = uxQueueMessagesWaiting(rxq) > 0;
          if (!busy) {
            memcpy(r->pktbuf, r->frag.buf, r->frag.len);
            size_t len = r->frag.len;
            bus_unlock(r);
            xQueueSend(rxq, &len, 0);
          } else {
            bus_unlock(r);
            r->stats.rxDrop++;
          }
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

static int lora_send(cc_road_t* road, const uint8_t* pkt, size_t len) {
  cc_road_lora_t* r = impl_of(road);
  QueueHandle_t txq = (QueueHandle_t)r->tx_q;
  size_t total, i;
  uint8_t id;
  int sent = 0;

  if (!r->ready)
    return CC_ROAD_ERR;
  total = cc_road_frag_count(len);
  if (total == 0)
    return CC_ROAD_ERR;

  id = r->tx_id++;
  for (i = 0; i < total; i++) {
    TxJob job;
    size_t n =
        cc_road_frag_encode(pkt, len, id, (uint8_t)i, (uint8_t)total, job.data);
    if (n == 0)
      return CC_ROAD_ERR;
    job.len = (uint8_t)n;
    if (xQueueSend(txq, &job, pdMS_TO_TICKS(5000)) != pdPASS)
      return CC_ROAD_ERR;
    sent++;
  }
  return CC_ROAD_OK;
}

static int lora_recv(cc_road_t* road, uint8_t* buf, size_t buf_sz,
                     size_t* len_out) {
  cc_road_lora_t* r = impl_of(road);
  size_t len;
  int ret = CC_ROAD_OK;

  if (!buf || !len_out)
    return CC_ROAD_ERR;
  if (xQueueReceive((QueueHandle_t)r->rx_q, &len, 0) != pdPASS) {
    return CC_ROAD_EMPTY;
  }
  bus_lock(r);
  if (len <= buf_sz) {
    memcpy(buf, r->pktbuf, len);
    *len_out = len;
  } else {
    ret = CC_ROAD_ERR;
  }
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
  r->rx_q = xQueueCreate(4, sizeof(size_t));
  if (!r->tx_q || !r->rx_q)
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
  if (r->rx_q) {
    vQueueDelete((QueueHandle_t)r->rx_q);
    r->rx_q = NULL;
  }
}

#endif /* __has_include(<RadioLib.h>) */
