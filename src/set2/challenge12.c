#include "random_single.h"
#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <stdio.h>


void fixed_key_oracle(StrView plaintext, StrView key, String* cypher)
{
    String_clear(cypher);
    String_reserve(cypher, plaintext.len + 16);
    u64 n = encrypt_aes_128_ecb(plaintext, key, (u8*)String_data_ptr_unsafe(cypher), String_capacity(cypher), true);
    cypher->size = n;
}

u64 find_oracle_block_size(StrView key)
{
    String As     = String_create(WC_LIBC);
    String cypher = String_create(WC_LIBC);

    u64 base_len   = 0;
    u64 block_size = 0;

    for (;; String_append_char(&As, 'A')) {
        fixed_key_oracle(StrView_over_String(&As), key, &cypher);
        if (base_len == 0) {
            base_len = cypher.size;
        } else if (cypher.size > base_len) {
            block_size = cypher.size - base_len;
            break;
        }
    }

    String_destroy(&cypher);
    String_destroy(&As);

    return block_size;
}

bool is_oracle_ecb(HashMap* map, StrView key, u64 block_size)
{
    String As     = String_with_cap(WC_LIBC, 3 * block_size);
    String cypher = String_with_cap(WC_LIBC, 3 * block_size);

    String_reserve_char(&As, 3 * block_size, 'A');
    fixed_key_oracle(StrView_over_String(&As), key, &cypher);

    bool is_ecb = is_aes_ecb(StrView_over_String(&cypher), map, block_size);

    String_destroy(&cypher);
    String_destroy(&As);

    return is_ecb;
}

static void find_byte_cypher_mapping(char map[256], StrView key, u64 block_size)
{
    String crafted = String_with_cap(WC_LIBC, block_size);
    // craft input [A...0], [A...1], ..., [A...A], [A...B], ...,[A...a], etc
    // go through all the values of one byte
    String_reserve_char(&crafted, block_size, 'A');

    String cypher = String_with_cap(WC_LIBC, block_size);

    for (u16 i = 0; i < 256; i++) {
        String_set_char(&crafted, block_size - 1, (char)i);
        fixed_key_oracle(StrView_over_String(&crafted), key, &cypher);
        // input is block size aligned, we will get block_size of padding
        WC_ASSERT(String_len(&cypher) == block_size * 2, );
        char e = String_char_at_unsafe(&cypher, block_size - 1);
        // we have to map encrypted -> decrypted
        map[(u8)e] = (char)i;
    }

    String_destroy(&cypher);
    String_destroy(&crafted);
}

int challenge12_run(void)
{
    WC_Pcg32 rng = PCG32_INITIALIZER;
    pcg32_rand_seed_os(&rng);

    // single random key for all shit
    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);
    StrView rkey = StrView_over_buf((char*)rand_key, 16);

    // find the block size
    u64 block_size = find_oracle_block_size(rkey);
    printf("Block Size: %lu\n", block_size);

    // for whatever the fuck
    HashMap set = HashMap_create(WC_LIBC, sizeof(StrView), 0, wc_strview_hash, wc_strview_cmp, NULL, NULL);
    WC_ASSERT(is_oracle_ecb(&set, rkey, block_size), "oracle no ecb");

    // the secret we wanna find out (base64)
    String secret_b64 = String_from_cstr(
        WC_LIBC, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzd"
                 "GFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    // decode base64
    String secret = String_with_cap(WC_LIBC, String_len(&secret_b64));
    base64_decode(StrView_over_String(&secret_b64), &secret);

    /* crafted input text: A's with block - 1 len
        If we supply a 15 byte input to a oracle that has block size 16, then due to 16 byte block alignment
        the last byte will be filled with the first byte of the secret, as our plaintext is crafted_text || secret.
        As we already know 15/16 bytes, we can figure out the last block (256 possiblities)
    */
    String plaintext = String_with_cap(WC_LIBC, block_size);
    String_reserve_char(&plaintext, block_size, 'A'); // last char will be replaced

    // byte to it's cypher representation under the rand_key
    // obtained by repeated calls to oracle using crafted inputs: [A...A], [A...B], [A...C] etc
    // this maps encrypted -> decrypted
    char byte_cypher_map[256];
    find_byte_cypher_mapping(byte_cypher_map, rkey, block_size);

    // cypher output storage
    String cypher = String_with_cap(WC_LIBC, block_size);

    // decoded secret accumilation
    String decyphered = String_with_cap(WC_LIBC, String_len(&secret));

    // loop until we find all the bytes of the secret
    // append ith char of secret at the block_size-th position in plaintext
    for (u64 i = 0; i < String_len(&secret); i++) {
        // replace the block_size - 1 char with the secret's byte
        String_set_char(&plaintext, block_size - 1, String_char_at_unsafe(&secret, i));
        // encrypt the thing
        fixed_key_oracle(StrView_over_String(&plaintext), rkey, &cypher);
        // input is block size aligned, we will get block_size of padding
        WC_ASSERT(String_len(&cypher) == block_size * 2, );
        // decode and store the block_size - 1 char
        String_append_char(&decyphered, byte_cypher_map[(u8)String_char_at_unsafe(&cypher, block_size - 1)]);
    }

    String_print(&decyphered);


    String_destroy(&decyphered);
    String_destroy(&cypher);
    String_destroy(&plaintext);
    String_destroy(&secret);
    String_destroy(&secret_b64);
    HashMap_destroy(&set);
    return 0;
}


/*
1. Block size: call the oracle with 0, 1, 2, … As. The first time the ciphertext length grows, the jump is the block size (16). Say it first jumps at i bytes from base length base: then secret_len = base - i.
2. Confirm ECB: feed 3 * bs copies of A and check that block 0 equals block 1. Compare at step = bs (aligned blocks)
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
