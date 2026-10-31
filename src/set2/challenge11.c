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


bool encryption_oracle(WC_Pcg32* rng, StrView plaintext, StrView key, String* cypher)
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

    bool is_ecb = (bool)pcg32_rand_bounded(rng, 2); //  0 or 1

    if (is_ecb) { // encrypt using ecb
        String_reserve(cypher, String_len(&pt) + 16);
        u64 n        = encrypt_aes_128_ecb(StrView_over_buf(String_data_ptr_unsafe(&pt), String_len(&pt)), key,
                                           (u8*)String_data_ptr_unsafe(cypher), String_capacity(cypher), true);
        cypher->size = n; // set the length

    } else { // encrypt using cbc
        u8 iv[16];
        generate_random_aes_128_key(iv);
        encrypt_aes_128_cbc(StrView_over_String(&pt), key, StrView_over_buf((char*)iv, 16), cypher);
    }

    String_destroy(&pt);
    return is_ecb;
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
        bool is_ecb = encryption_oracle(&rng, StrView_over_cstr(pt), StrView_over_buf((char*)key, 16), &cypher);
        bool is_ecb_detected = is_aes_ecb(StrView_over_String(&cypher), &set, 16);
        if (is_ecb != is_ecb_detected) {
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

/*

10c5d1a2bc6a3d65105fc4a71713c8b2    // 32 bytes HEX (16 byte BIN, one AES block), repeated 3x. supposed to represent 64 bytes of plaintext?

*/

/* Example outputs:

92814b88eeb2e3ee119b00032821cf0d10c5d1a2bc6a3d65105fc4a71713c8b210c5d1a2bc6a3d65105fc4a71713c8b210c5d1a2bc6a3d65105fc4a71713c8b20d494214759112f1acd724cca8fe6a190b453c7416636a1586f2dbb440e5f50c

bb7104ce5c5dbcebf23ec22cb34bc37810c5d1a2bc6a3d65105fc4a71713c8b210c5d1a2bc6a3d65105fc4a71713c8b210c5d1a2bc6a3d65105fc4a71713c8b298d8b2e03c0955c4e494d1ecaf3d1eb5

cec70e772fc4649a97006e4b1175ae2b10c5d1a2bc6a3d65105fc4a71713c8b210c5d1a2bc6a3d65105fc4a71713c8b210c5d1a2bc6a3d65105fc4a71713c8b2b56e0598ad94d6549b44f61d654d8a5da37f57f07ed63c11386ad875f061a335

0414f3a031055ab096badfded125169010c5d1a2bc6a3d65105fc4a71713c8b210c5d1a2bc6a3d65105fc4a71713c8b210c5d1a2bc6a3d65105fc4a71713c8b2f3be79de8f147c0f181b9cc6eeedcc0f
*/

/* as we are prepending and postpending 5-10 bytes and each block for AES is 16 bytes

block 0: [p random bytes][16-p A's]   <- differs
block 1: AAAAAAAAAAAAAAAA             <- identical
block 2: AAAAAAAAAAAAAAAA             <- identical
block 3: AAAAAAAAAAAAAAAA             <- identical
block 4: [p A's][suffix][padding]     <- differs

*/

/*
static int play(void)
{
    WC_Pcg32 rng = PCG32_INITIALIZER;
    pcg32_rand_seed_os(&rng);

    const char* pt = "AAAAAAAAAAAAAAAA"
                     "AAAAAAAAAAAAAAAA"
                     "AAAAAAAAAAAAAAAA"
                     "AAAAAAAAAAAAAAAA"; // 64 bytes (4 AES-128 blocks)

    const char* key = "wasi ullah satti"; // 16 bytes (1 AES-128 block)

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
*/
