#include <stdio.h>
#include <string.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/random.h>

#include "cosechat.h"

int main(void) {
  WC_RNG rng;
  cc_key_t key, imported;
  uint8_t priv[32], pub[CC_PUBKEY_SZ], addr[CC_ADDR_SZ], addr2[CC_ADDR_SZ];
  int i, ret;

  wc_InitRng(&rng);

  /* Generate new key */
  ret = cc_key_generate(&key, &rng);
  if (ret != CC_OK) {
    printf("generate failed: %d\n", ret);
    return 1;
  }

  cc_key_export_private(&key, priv);
  cc_key_export_public(&key, pub);
  cc_addr_from_key(&key, addr);

  printf("private: ");
  for (i = 0; i < 32; i++) printf("%02x", priv[i]);
  printf("\n");

  printf("public:  ");
  for (i = 0; i < CC_PUBKEY_SZ; i++) printf("%02x", pub[i]);
  printf("\n");

  printf("address: ");
  for (i = 0; i < CC_ADDR_SZ; i++) printf("%02x", addr[i]);
  printf("\n");

  /* Import from raw private bytes */
  ret = cc_key_import(&imported, priv);
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
