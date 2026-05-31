#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#include "cosechat.h"

int main(void) {
  WC_RNG rng;
  cc_key_t alice, bob;
  uint8_t ann_pkt[1024];
  size_t ann_len = 0;
  uint8_t chat_pkt[1024];
  size_t chat_len = 0;
  uint8_t routed[1024];
  size_t routed_len = 0;
  cc_announce_t bob_ann;
  cc_chat_t chat;
  uint8_t recip_addr[CC_ADDR_SZ];
  uint8_t alice_addr[CC_ADDR_SZ];
  uint8_t hops;
  int i, ret;
  static const char msg[] = "Hello Bob!";

  wc_InitRng(&rng);
  cc_key_generate(&alice, &rng);
  cc_key_generate(&bob, &rng);

  /* Bob announces himself */
  cc_announce_build(&bob, "Bob", 3, NULL, 0, ann_pkt, sizeof(ann_pkt), &ann_len,
                    &rng);

  /* Alice receives Bob's announce and parses it */
  ret = cc_announce_parse(ann_pkt, ann_len, &bob_ann);
  if (ret != CC_OK) {
    printf("announce parse error: %d\n", ret);
    return 1;
  }

  printf("bob addr: ");
  for (i = 0; i < CC_ADDR_SZ; i++) printf("%02x", bob_ann.addr[i]);
  printf("\n");

  /* Alice sends chat using Bob's pubkey from the announce */
  ret = cc_chat_build(&alice, bob_ann.pubkey, (const uint8_t*)msg, strlen(msg),
                      chat_pkt, sizeof(chat_pkt), &chat_len, &rng);
  if (ret != CC_OK) {
    printf("chat build error: %d\n", ret);
    return 1;
  }
  printf("chat pkt: %zu bytes\n", chat_len);

  /* Routing: check recipient address without decrypting */
  cc_msg_recipient(chat_pkt, chat_len, recip_addr);
  printf("recipient matches bob: %s\n",
         memcmp(recip_addr, bob_ann.addr, CC_ADDR_SZ) == 0 ? "yes" : "no");

  /* Bob decrypts */
  ret = cc_chat_parse(&bob, chat_pkt, chat_len, &chat);
  if (ret != CC_OK) {
    printf("chat parse error: %d\n", ret);
    return 1;
  }

  printf("message: %.*s\n", (int)chat.msg_len, (char*)chat.msg);

  /* Verify sender address matches Alice */
  cc_addr_from_key(&alice, alice_addr);
  printf("sender is alice: %s\n",
         memcmp(chat.sender_addr, alice_addr, CC_ADDR_SZ) == 0 ? "yes" : "no");

  /* Wrong key cannot decrypt */
  cc_chat_t chat2;
  ret = cc_chat_parse(&alice, chat_pkt, chat_len, &chat2);
  printf("wrong key rejected: %s\n", ret != CC_OK ? "yes" : "no");

  /* Router increments hops; Bob can still decrypt */
  cc_hops_increment(chat_pkt, chat_len, routed, sizeof(routed), &routed_len);
  cc_msg_hops(routed, routed_len, &hops);
  printf("hops after route: %d\n", hops);

  cc_chat_t chat3;
  ret = cc_chat_parse(&bob, routed, routed_len, &chat3);
  printf("decrypt after hop: %s\n", ret == CC_OK ? "ok" : "FAILED");

  cc_key_free(&alice);
  cc_key_free(&bob);
  wc_FreeRng(&rng);
  return 0;
}
