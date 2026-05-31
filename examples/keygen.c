#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#include "cosechat.h"

int main(void) {
  WC_RNG rng;
  /* Large structs — static to avoid stack overflow on ESP32 */
  static cc_key_t key, imported;
  uint8_t sign_priv[CC_SIGN_PRIVKEY_SZ];
  uint8_t kem_priv[CC_KEM_PRIVKEY_SZ];
  uint8_t sign_pub[CC_SIGN_PUBKEY_SZ];
  uint8_t kem_pub[CC_KEM_PUBKEY_SZ];
  uint8_t addr[CC_ADDR_SZ], addr2[CC_ADDR_SZ];
  int i, ret;

  wc_InitRng(&rng);

  /* Generate new key */
  ret = cc_key_generate(&key, &rng);
  if (ret != CC_OK) {
    printf("generate failed: %d\n", ret);
    return 1;
  }

  cc_key_export_private(&key, sign_priv, kem_priv);
  cc_key_export_public(&key, sign_pub, kem_pub);
  cc_addr_from_key(&key, addr);

  printf("sign_priv (first 32 bytes): ");
  for (i = 0; i < 32; i++) printf("%02x", sign_priv[i]);
  printf("... (%d total)\n", CC_SIGN_PRIVKEY_SZ);

  printf("kem_priv  (first 32 bytes): ");
  for (i = 0; i < 32; i++) printf("%02x", kem_priv[i]);
  printf("... (%d total)\n", CC_KEM_PRIVKEY_SZ);

  printf("address: ");
  for (i = 0; i < CC_ADDR_SZ; i++) printf("%02x", addr[i]);
  printf("\n");

  /* Import from raw private + public bytes */
  ret = cc_key_import(&imported, sign_priv, sign_pub, kem_priv);
  if (ret != CC_OK) {
    printf("import failed: %d\n", ret);
    return 1;
  }

  cc_addr_from_key(&imported, addr2);
  printf("import:  %s\n",
         memcmp(addr, addr2, CC_ADDR_SZ) == 0 ? "ok" : "MISMATCH");

  cc_key_free(&key);
  cc_key_free(&imported);
  wc_FreeRng(&rng);
  return 0;
}
