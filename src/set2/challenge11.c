#include "random_single.h"
#include "set2.h"
#include "views_single.h"
#include <assert.h>
#include <stdio.h>



void generate_random_aes_128_key(WC_Pcg32* rng, u8 k[16])
{
    ((u32*)k)[0] = pcg32_rand(rng); // bytes 0-3
    ((u32*)k)[1] = pcg32_rand(rng); // 4-7
    ((u32*)k)[2] = pcg32_rand(rng); // 8-11
    ((u32*)k)[3] = pcg32_rand(rng); // 12-15
}

void encryption_oracle(WC_Pcg32* rng, StrView plaintext, String* cypher)
{
    // gen 128-bit key
    u8 key[16];
    generate_random_aes_128_key(rng, key);

    // find out how many random bytes (5-10) to add before and after the plaintext
    u8 prepend_num  = (u8)pcg32_rand_range(rng, 5, 11);
    u8 postpend_num = (u8)pcg32_rand_range(rng, 5, 11);

    String_clear(cypher);
    String pt = String_with_cap(WC_LIBC, plaintext.len + prepend_num + postpend_num);

    // prepend random bytes
    for (u8 i = 0; i < prepend_num;) {
        u32 r = pcg32_rand(rng);
        if (i + 3 < prepend_num) {
            String_append_multi(&pt, (const char*)&r, 4);
            i += 4;
        } else if (i + 2 < prepend_num) {
            String_append_multi(&pt, (const char*)&r, 3);
            i += 3;
        } else if (i + 1 < prepend_num) {
            String_append_multi(&pt, (const char*)&r, 2);
            i += 2;
        } else {
            String_append_multi(&pt, (const char*)&r, 1);
            i += 1;
        }
    }

    // append the entire plaintext
    String_append_multi(&pt, plaintext.data, plaintext.len);

    // postpend random bytes
    for (u8 i = 0; i < postpend_num;) {
        u32 r = pcg32_rand(rng);
        if (i + 3 < postpend_num) {
            String_append_multi(&pt, (const char*)&r, 4);
            i += 4;
        } else if (i + 2 < postpend_num) {
            String_append_multi(&pt, (const char*)&r, 3);
            i += 3;
        } else if (i + 1 < postpend_num) {
            String_append_multi(&pt, (const char*)&r, 2);
            i += 2;
        } else {
            String_append_multi(&pt, (const char*)&r, 1);
            i += 1;
        }
    }

    bool is_cbc = (bool)pcg32_rand_bounded(rng, 2); //  0 or 1

    // TODO: i think the challenge wants me to choose b/w cbc and ecb for each BLOCK,
    // not the entire plaintext...

    if (is_cbc) { // encrypt using cbc
        u8 iv[16];
        generate_random_aes_128_key(rng, iv);
        encrypt_aes_128_cbc(StrView_over_String(&pt), StrView_over_buf(key, 16), StrView_over_buf(iv, 16), cypher);

    } else { // encrypt using ecb
        String_reserve(cypher, String_len(&pt));
        encrypt_aes_128_ecb(StrView_over_buf(String_data_ptr_unsafe(&pt), String_len(&pt)), StrView_over_buf(key, 16),
                            String_data_ptr_unsafe(cypher), String_capacity(cypher), true);
    }

    String_destroy(&pt);
}


int challenge11_run(void)
{
    WC_Pcg32 rng = PCG32_INITIALIZER;
    pcg32_rand_seed_time(&rng);

    const char* pt = "hello im wasi ullah satti";

    String cypher = String_create(WC_LIBC);
    encryption_oracle(&rng, StrView_over_cstr(pt), &cypher);
    String_print(&cypher);
    putchar('\n');


    String_destroy(&cypher);
    return 0;
}
