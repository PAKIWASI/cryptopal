#include "random_single.h"
#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <stdalign.h>
#include <stddef.h>
#include <string.h>



void fixed_key_oracle_2(StrView plaintext, Oracle_2* oracle, String* cypher)
{
    String_clear(cypher);
    String_reserve(cypher, oracle->prepend.len + plaintext.len + oracle->secret.len + 16);

    // random prepend
    String temp = StrView_to_String(WC_LIBC, oracle->prepend);
    // user controlled text
    String_append_multi(&temp, plaintext.data, plaintext.len);
    // secret message
    String_append_multi(&temp, oracle->secret.data, oracle->secret.len);

    u64 n        = encrypt_aes_128_ecb(      //
        StrView_over_String(&temp),          //
        oracle->key,                         //
        (u8*)String_data_ptr_unsafe(cypher), //
        String_capacity(cypher), true        //
    );
    cypher->size = n;

    String_destroy(&temp);
}

static u64 find_padding(Oracle_2* oracle)
{
    String input = String_create(WC_LIBC);
    String_reserve_char(&input, (u64)(4 * 16), 'A'); // forth block is supplied 0-15

    String cypher = String_with_cap(WC_LIBC, input.size);

    for (u64 i = 0; i < 16; i++) {
        fixed_key_oracle_2(StrView_over_String_ex(&input, 0, (u64)(3 * 16) + i), oracle, &cypher);
        // if we find 3 blocks of encrypted A's, then we have the padding
        is_oracle_ecb(HashMap *map, Oracle *oracle, u64 block_size);
    }

    String_destroy(&input);
    String_destroy(&input);
}


int challenge14_run(void)
{
    WC_Pcg32 rng = PCG32_INITIALIZER;
    pcg32_rand_seed_os(&rng);

    // random key
    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);

    // random bytes to prepend to the user input (count can't be used for decryption, only oracle)
    u32   rand_count = pcg32_rand_range(&rng, 1, 160);
    char* rand_bytes = wc_alloc(WC_LIBC, rand_count, alignof(char));
    for (u32 i = 0; i < rand_count; i++) {
        rand_bytes[i] = (char)pcg32_rand(&rng);
    }

    // user input
    String input = String_create(WC_LIBC);

    // the secret we wanna find out (base64)
    const char* secret_b64 =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzd"
        "GFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    // decode base64
    String secret = String_with_cap(WC_LIBC, strlen(secret_b64));
    base64_decode(StrView_over_cstr(secret_b64), &secret);

    Oracle_2 oracle = {
        .prepend = StrView_over_buf(rand_bytes, rand_count),
        .key     = StrView_over_buf((char*)rand_key, 16),
        .secret  = StrView_over_String(&secret),
    };

    String cypher = String_create(WC_LIBC);

    /*
        adding random-looking junk in front of the data doesn’t protect ECB.
        The weakness is still that ECB encrypts identical blocks identically, and that we control part of the input

        how much can our input be mangeled? 1-15 bytes rand chars + remaining input for a block
        16 random bytes - 0 + 16 x 3 input A's
        15 random bytes - 1 + 16 x 3 input A's
        14 random bytes - 2 + 16 x 3 input A's
        13 random bytes - 3 + 16 x 3 input A's
        ...
        1 random bytes - 15 + 16 x 3 input A's

        we supply all the possible inputs of A's and see when we get consecutive 3 blocks of cyphertext that's the same
        that means that's the number of A's we need to complete the block. then, using the last block of A's from the input,
        we can do the normal supply one less so secret's first byte is the blocks last byte etc etc
    */


    String_destroy(&cypher);
    String_destroy(&secret);
    String_destroy(&input);
    wc_free(WC_LIBC, rand_bytes, rand_count, alignof(char));
    return 0;
}
