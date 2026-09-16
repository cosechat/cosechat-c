/* chat.c — end-to-end flow using the announce/presence split, plus the
 * properties the v9 wire revision adds: replay rejection, a signature that
 * binds the claimed sender, receiver-published admission pricing, and the link
 * (session) path with forward secrecy.
 *
 *   1. Bob builds a full announce (boot).
 *   2. Bob later sends a presence (periodic heartbeat), with a seq.
 *   3. Alice receives Bob's presence for an unknown addr → sends key_req.
 *   4. Bob receives the key_req for his addr → re-sends his announce.
 *   5. Alice parses the announce and now has Bob's keys.
 *   6. Alice reads the price Bob's announce asks senders to mine for chat.
 *   7. Alice sends a signed chat to Bob (counter + detached ML-DSA sig).
 *   8. Bob decrypts and verifies the sender addr.
 *   9. Bob feeds the same packet to cc_chat_parse(&w, ...) again → replay
 *      rejected.
 *  10. Alice forges a chat that claims another sender → Bob rejects the
 *      signature (CC_E_SIG), or asks for an announce (CC_E_NOKEY) when the
 *      claimed sender's key is unknown.
 *  11. Alice opens a link, sends data both ways (one fragment per message),
 *      identifies herself, closes it.
 */
#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#include "cosechat.h"

/* Chat layout: [ver, type, hops, sender, recipient, kem_ct, counter, nonce,
   encrypt0, sig]. Indexes below follow the sequence in include/cosechat.h. */
#define CHAT_ELEMS 10
#define CHAT_SENDER 3
#define CHAT_NONCE 7

/* Spans (offset and length) of the outer CBOR array's elements. Small and
 * local: enough for the demo's adversarial step, no library access needed. */
static int chat_spans(const uint8_t* pkt, size_t len, size_t* off, size_t* elen,
                      size_t* count) {
  size_t pos = 1, i;
  uint8_t ai, major;
  uint64_t v;

  if (len < 2 || (pkt[0] >> 5) != 4 || (pkt[0] & 0x1F) > 23)
    return -1;
  *count = (size_t)(pkt[0] & 0x1F);
  for (i = 0; i < *count; i++) {
    size_t start = pos;
    if (pos >= len)
      return -1;
    major = (uint8_t)(pkt[pos] >> 5);
    ai = (uint8_t)(pkt[pos] & 0x1F);
    pos += 1;
    if (ai < 24) {
      v = ai;
    } else if (ai == 24) {
      if (pos + 1 > len)
        return -1;
      v = pkt[pos];
      pos += 1;
    } else if (ai == 25) {
      if (pos + 2 > len)
        return -1;
      v = ((uint64_t)pkt[pos] << 8) | pkt[pos + 1];
      pos += 2;
    } else if (ai == 26) {
      if (pos + 4 > len)
        return -1;
      v = ((uint64_t)pkt[pos] << 24) | ((uint64_t)pkt[pos + 1] << 16) |
          ((uint64_t)pkt[pos + 2] << 8) | pkt[pos + 3];
      pos += 4;
    } else {
      return -1;
    }
    if (major == 2 || major == 3)
      pos += (size_t)v;
    else if (major != 0)
      return -1;
    if (pos > len)
      return -1;
    off[i] = start;
    elen[i] = pos - start;
  }
  return 0;
}

/* Re-mine the PoW after patching, using cc_pow_verify() as the oracle so the
 * demo does not need to know the configured difficulty. The nonce element is
 * widened to a 5-byte encoding so any candidate fits in place. */
static int chat_remine(uint8_t* pkt, size_t* len) {
  static const uint8_t five[5] = {0x1a, 0, 0, 0, 0};
  static uint8_t padded[CC_CHAT_BUF_SZ + 8];
  size_t off[CHAT_ELEMS], elen[CHAT_ELEMS], n = 0, i, o = 0, padded_len;
  uint32_t cand;

  if (chat_spans(pkt, *len, off, elen, &n) != 0 || n != CHAT_ELEMS)
    return -1;

  padded[o++] = pkt[0];
  for (i = 0; i < n; i++) {
    if (i == CHAT_NONCE) {
      memcpy(padded + o, five, sizeof(five));
      o += sizeof(five);
    } else {
      memcpy(padded + o, pkt + off[i], elen[i]);
      o += elen[i];
    }
  }
  padded_len = o;
  memcpy(pkt, padded, padded_len);
  *len = padded_len;

  if (chat_spans(pkt, padded_len, off, elen, &n) != 0)
    return -1;
  for (cand = 0; cand < 0xFFFFFF00U; cand++) {
    for (i = 0; i < 4; i++)
      pkt[off[CHAT_NONCE] + 1 + i] = (uint8_t)(cand >> (8 * i));
    if (cc_pow_verify(pkt, *len) == CC_OK)
      return 0;
  }
  return -1;
}

int main(void) {
  /* The library keeps no state of its own: this is the per-caller
     working memory (static here, as it must be on an MCU). */
  static cc_work_t w;
  WC_RNG rng;
  static cc_key_t alice, bob, mallory;
  static cc_announce_t bob_ann;
  static cc_chat_t chat;
  cc_presence_t bob_pres;
  cc_replay_t bob_from_alice, bob_from_mallory;
  static uint8_t ann_pkt[CC_ANN_BUF_SZ];
  static uint8_t chat_pkt[CC_CHAT_BUF_SZ];
  static uint8_t forged[CC_CHAT_BUF_SZ + 8];
  uint8_t pres_pkt[CC_PRES_BUF_SZ];
  uint8_t req_pkt[CC_KEY_REQ_BUF_SZ];
  uint8_t alice_sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t alice_kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t mallory_sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t mallory_kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t req_addr[CC_ADDR_SZ];
  uint8_t bob_addr[CC_ADDR_SZ], alice_addr[CC_ADDR_SZ];
  uint8_t mallory_addr[CC_ADDR_SZ], recip[CC_ADDR_SZ], claimed[CC_ADDR_SZ];
  size_t ann_len = 0, chat_len = 0, forged_len = 0, pres_len = 0, req_len = 0;
  uint32_t req_counter = 0;
  uint8_t price = 0, lprice = 0; /* what Bob asks senders to mine */
  static const char msg[] = "Hello Bob!";
  int i, ret;

  wc_InitRng(&rng);
  cc_key_generate(&alice, &rng);
  cc_key_generate(&bob, &rng);
  cc_key_generate(&mallory, &rng);
  cc_addr_from_key(&bob, bob_addr);
  cc_addr_from_key(&alice, alice_addr);
  cc_addr_from_key(&mallory, mallory_addr);
  cc_key_export_public(&alice, alice_sign_pub, alice_kem_pub);
  cc_key_export_public(&mallory, mallory_sign_pub, mallory_kem_pub);

  printf("bob addr:     ");
  for (i = 0; i < CC_ADDR_SZ; i++) printf("%02x", bob_addr[i]);
  printf("\nalice addr:   ");
  for (i = 0; i < CC_ADDR_SZ; i++) printf("%02x", alice_addr[i]);
  printf("\nmallory addr: ");
  for (i = 0; i < CC_ADDR_SZ; i++) printf("%02x", mallory_addr[i]);
  printf("\n\n");

  /* 1. Bob announces at boot (~27 LoRa fragments) */
  ret = cc_announce_build(&w, &bob, "Bob", 3, NULL, 0, NULL, 1, 0, ann_pkt,
                          sizeof(ann_pkt), &ann_len, &rng);
  printf("1. bob announce: %s (%zu bytes, ~%zu frags)\n",
         ret == CC_OK ? "ok" : "FAILED", ann_len, (ann_len + 247) / 248);

  /* 2. Bob sends periodic presence (counter 1; a real node persists it) */
  ret = cc_presence_build(&w, &bob, "Bob", 3, 1, pres_pkt, sizeof(pres_pkt),
                          &pres_len, &rng);
  printf("2. bob presence: %s (%zu bytes, 1 frag, counter=1)\n",
         ret == CC_OK ? "ok" : "FAILED", pres_len);

  /* 3. Alice receives presence for unknown addr → builds key_req */
  ret = cc_presence_parse(&w, pres_pkt, pres_len, &bob_pres);
  printf("3. alice parses presence: %s (addr + name_hash only, seq=%u)\n",
         ret == CC_OK ? "ok" : "FAILED", ret == CC_OK ? bob_pres.seq : 0);

  ret = cc_key_req_build(&w, bob_pres.addr, 2, 0, req_pkt, sizeof(req_pkt),
                         &req_len);
  printf("   alice sends key_req: %s (%zu bytes, counter=2)\n",
         ret == CC_OK ? "ok" : "FAILED", req_len);

  /* 4. Bob receives key_req for his addr → re-sends announce */
  ret = cc_key_req_parse(&w, req_pkt, req_len, req_addr, &req_counter);
  printf("4. bob parses key_req: %s, for_me=%s, counter=%u\n",
         ret == CC_OK ? "ok" : "FAILED",
         memcmp(req_addr, bob_addr, CC_ADDR_SZ) == 0 ? "yes" : "no",
         req_counter);
  /* Bob re-sends his announce (already built above, would retransmit ann_pkt)
   */

  /* 5. Alice parses bob's announce, now has his keys */
  ret = cc_announce_parse(&w, ann_pkt, ann_len, &bob_ann);
  printf("5. alice parses announce: %s\n", ret == CC_OK ? "ok" : "FAILED");

  /* 6. Bob's announce publishes what he asks senders to mine for chat. The
     rule is max(what he asked for, what this build requires), and
     cc_admit_for() is where that rule lives. */
  ret = cc_admit_for(&bob_ann, CC_MSG_CHAT, &price);
  printf("6. bob's chat price: %s (declared %u, mined %u)\n",
         ret == CC_OK ? "ok" : "FAILED", bob_ann.admit[CC_ADMIT_CHAT], price);

  /* 7. Alice sends a signed chat to Bob using addr + KEM pubkey from announce
   */
  ret = cc_chat_build(&w, &alice, bob_ann.addr, bob_ann.kem_pubkey, 1,
                      (const uint8_t*)msg, strlen(msg), price, chat_pkt,
                      sizeof(chat_pkt), &chat_len, &rng);
  printf("7. alice sends signed chat: %s (%zu bytes, counter=1)\n",
         ret == CC_OK ? "ok" : "FAILED", chat_len);

  cc_msg_recipient(chat_pkt, chat_len, recip);
  cc_chat_sender(chat_pkt, chat_len, claimed);
  printf("   recipient matches bob: %s, claimed sender is alice: %s\n",
         memcmp(recip, bob_addr, CC_ADDR_SZ) == 0 ? "yes" : "no",
         memcmp(claimed, alice_addr, CC_ADDR_SZ) == 0 ? "yes" : "no");
  printf(
      "   signed chat cost: %zu bytes = %zu LoRa frags (248 B) / %zu BLE "
      "adverts (243 B)\n",
      chat_len, (chat_len + 247) / 248, (chat_len + 242) / 243);

  /* 8. Bob decrypts; the claimed sender's key is Alice's, and the AUTHED
   *    replay window is keyed on her addr */
  cc_replay_init(&bob_from_alice, alice_addr, CC_REPLAY_AUTHED);
  ret = cc_chat_parse(&w, &bob, alice_sign_pub, &bob_from_alice, chat_pkt,
                      chat_len, &chat);
  printf("8. bob decrypts: %s\n", ret == CC_OK ? "ok" : "FAILED");
  if (ret == CC_OK) {
    printf("   message: %.*s\n", (int)chat.msg_len, (char*)chat.msg);
    printf(
        "   sender is alice: %s\n",
        memcmp(chat.sender_addr, alice_addr, CC_ADDR_SZ) == 0 ? "yes" : "no");
  }

  /* 9. The same packet again: the counter was already accepted */
  ret = cc_chat_parse(&w, &bob, alice_sign_pub, &bob_from_alice, chat_pkt,
                      chat_len, &chat);
  printf(
      "9. bob re-parses the same packet: rejected as replay (rc=%d, "
      "CC_E_REPLAY=%d): %s\n",
      ret, CC_E_REPLAY, ret == CC_E_REPLAY ? "yes" : "no");

  /* 10. A forgery: patch the claimed sender to Mallory and re-mine the PoW —
   *    the detached signature still belongs to Alice, so it cannot pass. */
  memcpy(forged, chat_pkt, chat_len);
  forged_len = chat_len;
  {
    size_t off[CHAT_ELEMS], elen[CHAT_ELEMS], n = 0;
    chat_spans(forged, forged_len, off, elen, &n);
    memcpy(forged + off[CHAT_SENDER] + 1, mallory_addr, CC_ADDR_SZ);
  }
  int remined = chat_remine(forged, &forged_len);
  cc_chat_sender(forged, forged_len, claimed);
  printf("10. alice forges a chat claiming mallory: re-mined=%s, PoW ok=%s\n",
         remined == 0 ? "yes" : "no",
         cc_pow_verify(forged, forged_len) == CC_OK ? "yes" : "no");

  /* Claimed sender's key unknown → caller is told to ask for an announce */
  cc_replay_init(&bob_from_mallory, mallory_addr, CC_REPLAY_AUTHED);
  ret = cc_chat_parse(&w, &bob, NULL, &bob_from_mallory, forged, forged_len,
                      &chat);
  printf(
      "   bob, no announce for the claimed sender: rc=%d (CC_E_NOKEY=%d): "
      "%s\n",
      ret, CC_E_NOKEY, ret == CC_E_NOKEY ? "yes" : "no");

  /* Mallory's real key matches the claimed address, so only the signature
   * can reject it: it is Alice's, not Mallory's. */
  cc_replay_init(&bob_from_mallory, mallory_addr, CC_REPLAY_AUTHED);
  ret = cc_chat_parse(&w, &bob, mallory_sign_pub, &bob_from_mallory, forged,
                      forged_len, &chat);
  printf("   bob, with mallory's announce: rc=%d (CC_E_SIG=%d): %s\n", ret,
         CC_E_SIG, ret == CC_E_SIG ? "yes" : "no");

  /* 11. The link path (the default for conversations): one handshake, then
   *     one fragment per message, with forward secrecy. */
  {
    static cc_link_t li, lr;
    static uint8_t req[CC_LINK_REQ_BUF_SZ], proof[CC_LINK_PROOF_BUF_SZ];
    static uint8_t d1[CC_LINK_DATA_BUF_SZ], d2[CC_LINK_DATA_BUF_SZ];
    static uint8_t idp[CC_LINK_IDENTIFY_BUF_SZ];
    size_t rl = 0, pl = 0, dl1 = 0, dl2 = 0, lplen = 0;
    uint8_t kind = 0, link_payload[CC_MAX_MSG_SZ];
    uint32_t now = 0;

    if (cc_admit_for(&bob_ann, CC_MSG_LINK_REQ, &lprice) != CC_OK)
      lprice = 0;
    ret = cc_link_start(&w, &li, bob_ann.addr, bob_ann.kem_pubkey, ++now, 300,
                        lprice, req, sizeof(req), &rl, &rng);
    printf(
        "11. alice starts a link: %s (link_req %zu bytes = %zu frags, "
        "suite %u)\n",
        ret == CC_OK ? "ok" : "FAILED", rl, (rl + 247) / 248, cc_suite());
    ret = cc_link_accept(&w, &lr, &bob, ++now, 300, req, rl, proof,
                         sizeof(proof), &pl, &rng);
    printf(
        "    bob accepts and proves identity: %s (link_proof %zu bytes = "
        "%zu frags)\n",
        ret == CC_OK ? "ok" : "FAILED", pl, (pl + 247) / 248);
    ret =
        cc_link_confirm(&w, &li, bob_ann.addr, bob_ann.sign_pubkey, proof, pl);
    printf("    alice verifies the proof: %s (both sides open: %s)\n",
           ret == CC_OK ? "ok" : "FAILED",
           cc_link_active(&li, now) && cc_link_active(&lr, now) ? "yes" : "no");
    printf(
        "    handshake cost: %zu frags total, then one fragment per "
        "message\n",
        (rl + 247) / 248 + (pl + 247) / 248);

    ret = cc_link_send(&w, &li, CC_LINK_KIND_DATA, (const uint8_t*)msg,
                       strlen(msg), ++now, d1, sizeof(d1), &dl1);
    printf(
        "    alice -> bob data: %s (%zu bytes = %zu frags: no signature, "
        "no PoW)\n",
        ret == CC_OK ? "ok" : "FAILED", dl1, (dl1 + 247) / 248);
    ret = cc_link_recv(&w, &lr, d1, dl1, ++now, &kind, link_payload,
                       sizeof(link_payload), &lplen);
    printf("    bob decrypts: %s (\"%.*s\")\n", ret == CC_OK ? "ok" : "FAILED",
           (int)lplen, (char*)link_payload);

    ret = cc_link_send(&w, &lr, CC_LINK_KIND_DATA, (const uint8_t*)"Hi Alice!",
                       9, ++now, d2, sizeof(d2), &dl2);
    ret = cc_link_recv(&w, &li, d2, dl2, ++now, &kind, link_payload,
                       sizeof(link_payload), &lplen);
    printf("    bob -> alice: %s (\"%.*s\", separate direction key)\n",
           ret == CC_OK ? "ok" : "FAILED", (int)lplen, (char*)link_payload);

    ret = cc_link_recv(&w, &lr, d1, dl1, ++now, &kind, link_payload,
                       sizeof(link_payload), &lplen);
    printf("    alice's data replayed to bob: rc=%d (CC_E_REPLAY=%d): %s\n",
           ret, CC_E_REPLAY, ret == CC_E_REPLAY ? "yes" : "no");

    {
      static uint8_t id_payload[CC_ADDR_SZ + CC_SIGN_SIG_SZ];
      size_t il = 0, ibody = 0;
      uint8_t who[CC_ADDR_SZ];
      ret =
          cc_link_identify(&w, &li, &alice, ++now, idp, sizeof(idp), &il, &rng);
      printf("    alice identifies herself inside the link: %s (%zu bytes)\n",
             ret == CC_OK ? "ok" : "FAILED", il);
      ret = cc_link_recv(&w, &lr, idp, il, ++now, &kind, id_payload,
                         sizeof(id_payload), &ibody);
      printf(
          "      bob receives it: rc=%d, kind=%d (CC_LINK_KIND_IDENTIFY=%d)\n",
          ret, kind, CC_LINK_KIND_IDENTIFY);
      ret = cc_identify_verify(&w, &lr, id_payload, ibody, alice_sign_pub, who);
      printf("      checked against alice's announce: %s, addr matches: %s\n",
             ret == CC_OK ? "ok" : "FAILED",
             ret == CC_OK && memcmp(who, alice_addr, CC_ADDR_SZ) == 0 ? "yes"
                                                                      : "no");
    }

    ret = cc_link_close(&w, &li, ++now, d2, sizeof(d2), &dl2);
    ret = cc_link_recv(&w, &lr, d2, dl2, ++now, &kind, link_payload,
                       sizeof(link_payload), &lplen);
    printf(
        "    alice closes: rc=%d, record kind=%d (CC_LINK_KIND_CLOSE=%d), "
        "bob's link now active=%s\n",
        ret, kind, CC_LINK_KIND_CLOSE, cc_link_active(&lr, now) ? "yes" : "no");
  }

  cc_key_free(&alice);
  cc_key_free(&bob);
  cc_key_free(&mallory);
  wc_FreeRng(&rng);
  return 0;
}
