#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#include "cosechat.h"

/* Wire buffer sizes for PQ key sizes */
#define ANN_BUF_SZ  6144
#define CHAT_BUF_SZ 2048
#define PRES_BUF_SZ 128
#define KEY_REQ_BUF_SZ 32

static int g_passed = 0, g_failed = 0;

#define T(name, cond)               \
  do {                              \
    if (cond) {                     \
      printf("  pass: %s\n", name); \
      g_passed++;                   \
    } else {                        \
      printf("  FAIL: %s\n", name); \
      g_failed++;                   \
    }                               \
  } while (0)

static void test_keys(WC_RNG* rng) {
  /* static: cc_key_t ~13KB, too large for embedded stack */
  static cc_key_t key, imported;
  uint8_t sign_priv[CC_SIGN_PRIVKEY_SZ];
  uint8_t kem_priv[CC_KEM_PRIVKEY_SZ];
  uint8_t sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t addr[CC_ADDR_SZ], addr2[CC_ADDR_SZ], addr3[CC_ADDR_SZ];
  printf("keys:\n");

  T("generate", cc_key_generate(&key, rng) == CC_OK);
  T("export_private", cc_key_export_private(&key, sign_priv, kem_priv) == CC_OK);
  T("export_public", cc_key_export_public(&key, sign_pub, kem_pub) == CC_OK);
  T("addr_from_key", cc_addr_from_key(&key, addr) == CC_OK);
  T("addr_from_sign_pubkey", cc_addr_from_sign_pubkey(sign_pub, addr2) == CC_OK);
  T("addr_consistent", memcmp(addr, addr2, CC_ADDR_SZ) == 0);
  T("import", cc_key_import(&imported, sign_priv, sign_pub, kem_priv) == CC_OK);
  cc_addr_from_key(&imported, addr3);
  T("import_addr_match", memcmp(addr, addr3, CC_ADDR_SZ) == 0);
  T("null_arg", cc_key_generate(NULL, rng) == CC_E_ARG);

  cc_key_free(&key);
  cc_key_free(&imported);
}

static void test_announce(WC_RNG* rng) {
  static cc_key_t key;
  static cc_announce_t ann, ann2, ann3;
  static uint8_t pkt[ANN_BUF_SZ], pkt2[ANN_BUF_SZ], pkt3[ANN_BUF_SZ];
  size_t pkt_len = 0, pkt2_len = 0, pkt3_len = 0;
  uint8_t expected_addr[CC_ADDR_SZ];
  uint8_t corrupt[ANN_BUF_SZ];
  uint8_t type, hops;
  printf("announce:\n");

  cc_key_generate(&key, rng);

  T("build", cc_announce_build(&key, "Alice", 5, NULL, 0, pkt, sizeof(pkt), &pkt_len, rng) == CC_OK);
  T("pkt_nonempty", pkt_len > 0);

  cc_msg_type(pkt, pkt_len, &type);
  T("msg_type", type == CC_MSG_ANNOUNCE);

  T("parse", cc_announce_parse(pkt, pkt_len, &ann) == CC_OK);
  T("name", ann.name_len == 5 && memcmp(ann.name, "Alice", 5) == 0);
  T("hops_zero", ann.hops == 0);

  cc_addr_from_key(&key, expected_addr);
  T("addr_match", memcmp(ann.addr, expected_addr, CC_ADDR_SZ) == 0);

  T("pow_ok", cc_pow_verify(pkt, pkt_len) == CC_OK);

  /* Hop increment */
  T("hops_inc",
    cc_hops_increment(pkt, pkt_len, pkt2, sizeof(pkt2), &pkt2_len) == CC_OK);
  cc_msg_hops(pkt2, pkt2_len, &hops);
  T("hops_value", hops == 1);
  T("parse_after_hop", cc_announce_parse(pkt2, pkt2_len, &ann2) == CC_OK);
  T("hops_after_hop", ann2.hops == 1);

  /* Metadata */
  uint8_t meta_buf[] = {0xa1, 0x01, 0x02}; /* CBOR {1: 2} */
  cc_announce_build(&key, "Bob", 3, meta_buf, sizeof(meta_buf), pkt3,
                    sizeof(pkt3), &pkt3_len, rng);
  T("meta_parse", cc_announce_parse(pkt3, pkt3_len, &ann3) == CC_OK);
  T("meta_len", ann3.meta_len == sizeof(meta_buf));
  T("meta_content", memcmp(ann3.meta, meta_buf, sizeof(meta_buf)) == 0);

  /* Corrupted signature rejected */
  memcpy(corrupt, pkt, pkt_len);
  corrupt[pkt_len - 10] ^= 0xFF;
  T("bad_sig_rejected", cc_announce_parse(corrupt, pkt_len, &ann) != CC_OK);

  cc_key_free(&key);
}

static void test_chat(WC_RNG* rng) {
  static cc_key_t alice, bob;
  static cc_announce_t bob_ann;
  static cc_chat_t chat, chat2, chat3;
  static uint8_t ann_pkt[ANN_BUF_SZ];
  static uint8_t chat_pkt[CHAT_BUF_SZ], routed[CHAT_BUF_SZ];
  size_t ann_len = 0, chat_len = 0, routed_len = 0;
  uint8_t alice_addr[CC_ADDR_SZ], recip[CC_ADDR_SZ];
  uint8_t type, hops;
  static const char msg[] = "Hello Bob!";
  int ret;
  printf("chat:\n");

  cc_key_generate(&alice, rng);
  cc_key_generate(&bob, rng);

  cc_announce_build(&bob, "Bob", 3, NULL, 0, ann_pkt, sizeof(ann_pkt), &ann_len,
                    rng);
  cc_announce_parse(ann_pkt, ann_len, &bob_ann);

  T("build",
    cc_chat_build(&alice, bob_ann.addr, bob_ann.kem_pubkey,
                  (const uint8_t*)msg, strlen(msg),
                  chat_pkt, sizeof(chat_pkt), &chat_len, rng) == CC_OK);
  T("pkt_nonempty", chat_len > 0);

  cc_msg_type(chat_pkt, chat_len, &type);
  T("msg_type", type == CC_MSG_CHAT);

  cc_msg_recipient(chat_pkt, chat_len, recip);
  T("recipient_addr", memcmp(recip, bob_ann.addr, CC_ADDR_SZ) == 0);

  T("pow_ok", cc_pow_verify(chat_pkt, chat_len) == CC_OK);

  ret = cc_chat_parse(&bob, chat_pkt, chat_len, &chat);
  if (ret != CC_OK) printf("  bob parse ret=%d\n", ret);
  T("bob_decrypt", ret == CC_OK);
  T("msg_match", ret == CC_OK && chat.msg_len == strlen(msg) &&
                     memcmp(chat.msg, msg, chat.msg_len) == 0);

  cc_addr_from_key(&alice, alice_addr);
  T("sender_addr",
    ret == CC_OK && memcmp(chat.sender_addr, alice_addr, CC_ADDR_SZ) == 0);

  /* Wrong key rejected */
  T("wrong_key", cc_chat_parse(&alice, chat_pkt, chat_len, &chat2) != CC_OK);

  /* Hops routing preserves decryptability */
  cc_hops_increment(chat_pkt, chat_len, routed, sizeof(routed), &routed_len);
  cc_msg_hops(routed, routed_len, &hops);
  T("hops_inc", hops == 1);

  ret = cc_chat_parse(&bob, routed, routed_len, &chat3);
  T("decrypt_after_hop", ret == CC_OK);
  T("msg_after_hop", ret == CC_OK && chat3.msg_len == strlen(msg) &&
                         memcmp(chat3.msg, msg, chat3.msg_len) == 0);

  cc_key_free(&alice);
  cc_key_free(&bob);
}

static void test_presence(WC_RNG* rng) {
  static cc_key_t key;
  cc_presence_t p, p2;
  static uint8_t pkt[PRES_BUF_SZ], pkt2[PRES_BUF_SZ];
  size_t pkt_len = 0, pkt2_len = 0;
  uint8_t expected_addr[CC_ADDR_SZ];
  uint8_t type, hops;
  printf("presence:\n");

  cc_key_generate(&key, rng);
  T("build",  cc_presence_build(&key, "Alice", 5, pkt, sizeof(pkt), &pkt_len, rng) == CC_OK);
  T("nonempty", pkt_len > 0 && pkt_len <= PRES_BUF_SZ);
  cc_msg_type(pkt, pkt_len, &type);
  T("msg_type", type == CC_MSG_PRESENCE);
  T("parse",  cc_presence_parse(pkt, pkt_len, &p) == CC_OK);
  T("name",   p.name_len == 5 && memcmp(p.name, "Alice", 5) == 0);
  T("hops_zero", p.hops == 0);
  cc_addr_from_key(&key, expected_addr);
  T("addr_match", memcmp(p.addr, expected_addr, CC_ADDR_SZ) == 0);
  T("pow_ok", cc_pow_verify(pkt, pkt_len) == CC_OK);

  T("hops_inc", cc_hops_increment(pkt, pkt_len, pkt2, sizeof(pkt2), &pkt2_len) == CC_OK);
  cc_msg_hops(pkt2, pkt2_len, &hops);
  T("hops_value", hops == 1);
  T("parse_after_hop", cc_presence_parse(pkt2, pkt2_len, &p2) == CC_OK);
  T("addr_after_hop",  memcmp(p2.addr, expected_addr, CC_ADDR_SZ) == 0);
  T("pow_after_hop",   cc_pow_verify(pkt2, pkt2_len) == CC_OK);

  /* Corrupt → rejected */
  pkt[pkt_len - 3] ^= 0xFF;
  T("corrupt_rejected", cc_presence_parse(pkt, pkt_len, &p) != CC_OK);

  cc_key_free(&key);
}

static void test_key_req(void) {
  static cc_key_t key;
  uint8_t addr[CC_ADDR_SZ], parsed_addr[CC_ADDR_SZ];
  static uint8_t pkt[KEY_REQ_BUF_SZ], pkt2[KEY_REQ_BUF_SZ];
  size_t pkt_len = 0, pkt2_len = 0;
  uint8_t type, hops;
  WC_RNG rng;
  wc_InitRng(&rng);
  cc_key_generate(&key, &rng);
  wc_FreeRng(&rng);
  cc_addr_from_key(&key, addr);
  printf("key_req:\n");

  T("build",    cc_key_req_build(addr, pkt, sizeof(pkt), &pkt_len) == CC_OK);
  T("nonempty", pkt_len > 0 && pkt_len <= KEY_REQ_BUF_SZ);
  cc_msg_type(pkt, pkt_len, &type);
  T("msg_type", type == CC_MSG_KEY_REQ);
  T("parse",    cc_key_req_parse(pkt, pkt_len, parsed_addr) == CC_OK);
  T("addr_match", memcmp(addr, parsed_addr, CC_ADDR_SZ) == 0);
  T("pow_ok",   cc_pow_verify(pkt, pkt_len) == CC_OK);

  T("hops_inc", cc_hops_increment(pkt, pkt_len, pkt2, sizeof(pkt2), &pkt2_len) == CC_OK);
  cc_msg_hops(pkt2, pkt2_len, &hops);
  T("hops_value", hops == 1);
  T("parse_after_hop", cc_key_req_parse(pkt2, pkt2_len, parsed_addr) == CC_OK);
  T("addr_after_hop",  memcmp(addr, parsed_addr, CC_ADDR_SZ) == 0);
  T("pow_after_hop",   cc_pow_verify(pkt2, pkt2_len) == CC_OK);

  /* Corrupt nonce → PoW fails */
  pkt[pkt_len - 1] ^= 0xFF;
  T("corrupt_rejected", cc_key_req_parse(pkt, pkt_len, parsed_addr) != CC_OK);

  T("null_arg", cc_key_req_build(NULL, pkt, sizeof(pkt), &pkt_len) == CC_E_ARG);
  cc_key_free(&key);
}

int main(void) {
  WC_RNG rng;
  wc_InitRng(&rng);

  printf("cosechat v%s  (POW_DIFFICULTY=%d)\n\n", CC_VERSION,
         CC_POW_DIFFICULTY);

  test_keys(&rng);
  printf("\n");
  test_announce(&rng);
  printf("\n");
  test_chat(&rng);
  printf("\n");
  test_presence(&rng);
  printf("\n");
  test_key_req();

  wc_FreeRng(&rng);
  printf("\n%d passed, %d failed\n", g_passed, g_failed);
  return g_failed > 0 ? 1 : 0;
}
