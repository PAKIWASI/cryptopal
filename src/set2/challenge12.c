#include "random_single.h"
#include "set1.h"
#include "set2.h"
#include "views_single.h"



int challenge12_run(void)
{
    WC_Pcg32 rng = PCG32_INITIALIZER;
    pcg32_rand_seed_os(&rng);

    const char* pt  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const char* key = "wasi ullah satti"; // 16bits

    String cypher = String_create(WC_LIBC);

    encryption_oracle(&rng, StrView_over_cstr(pt), StrView_over_cstr(key), &cypher);

    String hex = String_with_cap(WC_LIBC, String_len(&cypher) * 2);
    hex_encode(StrView_over_String(&cypher), &hex);

    HashMap set = HashMap_create(WC_LIBC, sizeof(StrView), 0, wc_strview_hash, wc_strview_cmp, NULL, NULL);

    if (is_aes_ecb(StrView_over_String(&cypher), &set, 16)) {
        String_print(&hex);
    }

    HashMap_destroy(&set);
    String_destroy(&hex);
    String_destroy(&cypher);
    return 0;
}
