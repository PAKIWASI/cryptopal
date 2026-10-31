#include "random_single.h"
#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <stdio.h>



/*

1. Block size: call the oracle with 0, 1, 2, … As. The first time the ciphertext length grows, the jump is the block size (16). Say it first jumps at i bytes from base length base: then secret_len = base - i.
2. Confirm ECB: feed 3 * bs copies of A and check that block 0 equals block 1. Compare at step = bs (aligned blocks). Your is_aes_ecb slides one byte at a time. That works, but it does 16x more hashing and only aligned matches are meaningful.
3. Recover each byte k.

*/

/*
The math for block size comes from how PKCS#7 padding rounds the ciphertext length up to the next multiple of the block size.

The setup

Let S be the secret length and i the number of As you prepend. The plaintext is i + S bytes, and with padding the ciphertext length is:

C(i) = (floor((i + S) / bs) + 1) * bs

The + 1 is because PKCS#7 always adds at least one padding byte. If the plaintext is already block-aligned, a whole extra block of padding is added.

So the ciphertext length only changes when i + S crosses a multiple of bs.

Finding the jump

Let base = C(0), the ciphertext length with no input. Increase i one at a time. The first i where C(i) > base is the point where i + S first hits a multiple of bs, because that’s when padding needs a whole new block.

At that point:

i + S = base      (the plaintext now fills `base` bytes exactly, plus one full block of padding)

Check this: at i + S = base, the plaintext is block-aligned, so padding adds a full block and the length becomes base + bs. One byte earlier (i - 1), i - 1 + S = base - 1, which pads with exactly one byte and gives length base. So the jump happens exactly at the i where i + S = base.

Therefore:

secret_len S = base - i
block_size   = C(i) - base

*/



int challenge12_run(void)
{
    WC_Pcg32 rng = PCG32_INITIALIZER;
    pcg32_rand_seed_os(&rng);

    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);

    String final_pt = String_from_cstr(WC_LIBC, "AAAAAAAAAAAAAAAA"
                                                "AAAAAAAAAAAAAAAA"
                                                "AAAAAAAAAAAAAAAA"
                                                "AAAAAAAAAAAAAAAA");
    // secret to append to plaintext
    const char* secret =
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IH"
        "dhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    base64_decode(StrView_over_cstr(secret), &final_pt);

    String cypher = String_with_cap(WC_LIBC, String_len(&final_pt) + 16);

    u64 n = encrypt_aes_128_ecb(StrView_over_String(&final_pt), StrView_over_buf((char*)rand_key, 16),
                                (u8*)String_data_ptr_unsafe(&cypher), String_capacity(&cypher), true);
    cypher.size += n;

    String hex = String_with_cap(WC_LIBC, String_len(&cypher) * 2);
    hex_encode(StrView_over_String(&cypher), &hex);
    String_print(&hex);
    putchar('\n');

    HashMap set = HashMap_create(WC_LIBC, sizeof(StrView), 0, wc_strview_hash, wc_strview_cmp, NULL, NULL);

    WC_ASSERT(is_aes_ecb(StrView_over_String(&final_pt), &set, 16), );


    HashMap_destroy(&set);
    String_destroy(&hex);
    String_destroy(&cypher);
    String_destroy(&final_pt);
    return 0;
}
