#include "random_single.h"
#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <assert.h>
#include <stdio.h>



void generate_random_aes_128_key(u8 k[16])
{
    wc_get_os_entropy(k, 16);
}

static wc_always_inline void append_rand_bytes(String* s, u8 num)
{
    wc_get_os_entropy(String_data_ptr_unsafe(s) + String_len(s), num);
    s->size += num;
}


bool encryption_oracle(WC_Pcg32* rng, StrView plaintext, String* cypher, StrView key)
{
    // find out how many random bytes (5-10) to add before and after the plaintext
    u8 prepend_num  = (u8)pcg32_rand_range(rng, 5, 11);
    u8 postpend_num = (u8)pcg32_rand_range(rng, 5, 11);

    String_clear(cypher);
    String pt = String_with_cap(WC_LIBC, plaintext.len + prepend_num + postpend_num);

    // prepend random bytes
    append_rand_bytes(&pt, prepend_num);

    // append the entire plaintext
    String_append_multi(&pt, plaintext.data, plaintext.len);

    // postpend random bytes
    append_rand_bytes(&pt, postpend_num);

    bool is_cbc = (bool)pcg32_rand_bounded(rng, 2); //  0 or 1

    if (is_cbc) { // encrypt using cbc
        u8 iv[16];
        generate_random_aes_128_key(iv);
        encrypt_aes_128_cbc(StrView_over_String(&pt), key, StrView_over_buf((char*)iv, 16), cypher);
    } else { // encrypt using ecb
        String_reserve(cypher, String_len(&pt) + 16);
        u64 n = encrypt_aes_128_ecb(StrView_over_buf(String_data_ptr_unsafe(&pt), String_len(&pt)), key,
                                    (u8*)String_data_ptr_unsafe(cypher), String_capacity(cypher), true);

        cypher->size = n; // set the length
    }

    String_destroy(&pt);
    return is_cbc;
}

bool detect_rand_block_cypher_mode(StrView cypher, HashMap* set)
{
    return (!is_aes_ecb(cypher, set, 16)) != 0;
}



int challenge11_run(void)
{
    WC_Pcg32 rng = PCG32_INITIALIZER;
    pcg32_rand_seed_os(&rng);

    const char* pt = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    u8 key[16];
    generate_random_aes_128_key(key);
    String cypher = String_create(WC_LIBC);

    HashMap set = HashMap_create(WC_LIBC, sizeof(StrView), 0, wc_strview_hash, wc_strview_cmp, NULL, NULL);

    u64 wrong = 0;

    for (u64 i = 0; i < 100; i++) {
        bool is_cbc = encryption_oracle(&rng, StrView_over_cstr(pt), &cypher, StrView_over_buf((char*)key, 16));
        bool is_cbc_detected = detect_rand_block_cypher_mode(StrView_over_String(&cypher), &set);
        if (is_cbc != is_cbc_detected) {
            wrong++;
        }

        String_print(&cypher);
        putchar('\n');
    }

    printf("Wrong answers: %lu\n", wrong);

    HashMap_destroy(&set);
    String_destroy(&cypher);
    return 0;
}
