#include "random_single.h"
#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <stdalign.h>
#include <string.h>





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

    // prepend
    String_insert_multi(&input, 0, rand_bytes, rand_count);

    // the secret we wanna find out (base64)
    const char* secret_b64 =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzd"
        "GFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    // decode base64
    String secret = String_with_cap(WC_LIBC, strlen(secret_b64));
    base64_decode(StrView_over_cstr(secret_b64), &secret);

    Oracle oracle = {
        .key    = StrView_over_buf((char*)rand_key, 16),
        .secret = StrView_over_String(&secret),
    };

    String cypher = String_create(WC_LIBC);

    // oracle (only thing we use to decypher)
    fixed_key_oracle(StrView_over_String(&input), &oracle, &cypher);

    /*
        adding random-looking junk in front of the data doesn’t protect ECB.
        The weakness is still that ECB encrypts identical blocks identically, and that we control part of the input

        how much can our input be mangeled? 1-15 bytes rand chars + remaining input for a block

    */




    String_destroy(&cypher);
    String_destroy(&secret);
    String_destroy(&input);
    wc_free(WC_LIBC, rand_bytes, rand_count, alignof(char));
    return 0;
}
