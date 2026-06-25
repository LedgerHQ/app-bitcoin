/* Smoke test for the bip388-c staticlib.
 *
 * Build (from the crate dir):
 *   cargo build --release
 *   cc tests/smoke.c target/release/libbip388_c.a -o /tmp/bip388_smoke
 *   /tmp/bip388_smoke
 */
#include "../include/bip388.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int check_one(const char *tmpl) {
  size_t tlen = strlen(tmpl);
  size_t need = 0;
  int rc = bip388_min_arena_size((const uint8_t *)tmpl, tlen, &need);
  if (rc != BIP388_OK) {
    printf("FAIL min_arena_size(%s) = %d\n", tmpl, rc);
    return 1;
  }

  uint8_t arena[16384];
  if (need > sizeof arena) {
    printf("FAIL arena too small for %s: need %zu\n", tmpl, need);
    return 1;
  }

  uint64_t score = 0;
  rc = bip388_confusion_score((const uint8_t *)tmpl, tlen, arena, sizeof arena,
                              &score);
  if (rc != BIP388_OK) {
    printf("FAIL confusion_score(%s) = %d\n", tmpl, rc);
    return 1;
  }

  uint8_t out[2048];
  Bip388Line lines[32];
  size_t n = 0;
  bool hct = false;
  rc = bip388_to_cleartext((const uint8_t *)tmpl, tlen, arena, sizeof arena, out,
                           sizeof out, lines, 32, &n, &hct);
  if (rc != BIP388_OK) {
    printf("FAIL to_cleartext(%s) = %d\n", tmpl, rc);
    return 1;
  }

  printf("%s\n  min_arena=%zu  confusion_score=%llu  has_cleartext=%d\n", tmpl,
         need, (unsigned long long)score, (int)hct);
  for (size_t i = 0; i < n; i++) {
    printf("  [%zu] %.*s\n", i, (int)lines[i].len, lines[i].ptr);
  }
  if (n == 0) {
    printf("FAIL: no cleartext lines\n");
    return 1;
  }
  return 0;
}

int main(void) {
  int failures = 0;
  failures += check_one("wsh(multi(2,@0/**,@1/**,@2/**))");
  failures += check_one("tr(@0/**,{pk(@1/**),and_v(v:pk(@2/**),older(144))})");
  failures += check_one("pkh(@0/**)");
  if (failures) {
    printf("SMOKE TEST FAILED (%d)\n", failures);
    return 1;
  }
  printf("SMOKE TEST OK\n");
  return 0;
}
