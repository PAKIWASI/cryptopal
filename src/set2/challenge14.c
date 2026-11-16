#include "random_single.h"
#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <stdalign.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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

static bool has_3_repeated_blks(StrView cypher)
{
    HashMap sv_count =
        HashMap_create(WC_LIBC, sizeof(StrView), sizeof(u64), wc_strview_hash, wc_strview_cmp, NULL, NULL);

    for (u64 i = 0; i + 16 < cypher.len; i += 16) {
        StrView blk = StrView_slice(cypher, i, 16);
        if (HashMap_has(&sv_count, &blk)) {
            u64* count = (u64*)HashMap_get_ptr(&sv_count, &blk);
            if (++(*count) >= 3) {
                HashMap_destroy(&sv_count);
                return true;
            }
        } else {
            u64 count = 1;
            HashMap_put(&sv_count, &blk, &count);
        }
    }

    HashMap_destroy(&sv_count);
    return false;
}

static u64 find_padding(Oracle_2* oracle)
{
    String input = String_create(WC_LIBC);
    String_reserve_char(&input, (u64)(4 * 16), 'A'); // forth block is supplied 0-15

    String cypher = String_with_cap(WC_LIBC, input.size);

    for (u64 i = 0; i < 16; i++) {
        fixed_key_oracle_2(StrView_over_String_ex(&input, 0, (u64)(3 * 16) + i), oracle, &cypher);
        // if we find 3 blocks of encrypted A's, then we have the padding
        if (has_3_repeated_blks(StrView_over_String(&cypher))) {
            String_destroy(&cypher);
            String_destroy(&input);
            return i;
        }
    }

    String_destroy(&cypher);
    String_destroy(&input);
    return WC_NOT_FOUND;
}


int challenge14_run(void)
{
    WC_Pcg32 rng = PCG32_INITIALIZER;
    pcg32_rand_seed_os(&rng);

    // random key
    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);

    // random bytes to prepend to the user input (count can't be used for decryption, only oracle)
    u32 rand_count = pcg32_rand_range(&rng, 1, 160);
    printf("RAND COUNT: %u\n", rand_count);

    char* rand_bytes = malloc(rand_count);
    for (u32 i = 0; i < rand_count; i++) {
        rand_bytes[i] = (char)pcg32_rand(&rng);
    }

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

    Oracle_2 oracle_2 = {
        .prepend = StrView_over_buf(rand_bytes, rand_count),
        .key     = StrView_over_buf((char*)rand_key, 16),
        .secret  = StrView_over_String(&secret),
    };

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

    u64 pad = find_padding(&oracle_2);
    WC_ASSERT(pad != WC_NOT_FOUND, );
    printf("PADDING: %lu\n", pad);


    // now the normal byte at a time decryption from challenge 12
    u64 block_size = 16;

    StringStore store;
    StringStore_create(&store, WC_LIBC, nKB(1), true); // interned
    HashMap block_map =
        HashMap_create(WC_LIBC, sizeof(StrView), sizeof(char), wc_strview_hash, wc_strview_cmp, NULL, NULL);

    // contains the bytes as we decypher them. starts of with pad (to align the user input) and one less than block size
    String known = String_with_cap(WC_LIBC, 256);
    String_reserve_char(&known, pad + block_size - 1, 'A');
    // oracle output storage
    String cypher = String_with_cap(WC_LIBC, block_size);
    // plaintext set for caching blocks
    HashMap ptset = HashMap_create(WC_LIBC, sizeof(StrView), 0, wc_strview_hash, wc_strview_cmp, NULL, NULL);


    // we offset by pad as it's just to align the next block for byte at a time decryption
    for (u64 off = pad;; off++) {
        // pad only view for the oracle to align blocks
        u64     pad_len = block_size - 1 - (off % block_size);        // 15...0 to 15...0 and so on
        StrView p       = StrView_over_String_ex(&known, 0, pad_len); // include the pad for random

        fixed_key_oracle_2(p, &oracle_2, &cypher);

        // off has to be rounded down to a multiple of the block size
        u64     blk = (off / block_size) * block_size;
        StrView ct  = StrView_over_String_ex(&cypher, blk, block_size);

        /*
        dictionary maps encrypt(P) to a byte, where P is exactly one 16-byte plaintext block.
        For a lookup to hit, the slice you read from the target ciphertext has to be one whole encrypted block,
        which means it must start at a multiple of 16.

        Which block you read: blk = (off / bs) * bs. This only moves forward every 16 decoded bytes.
        Where the secret byte sits inside that block is controlled by the pad length, bs - 1 - (off % bs).
        It slides the secret left one byte at a time, so the byte you want is always the last byte of the block you read.
        */

        // last block_size - 1 bytes and every candidate byte for the dictionary
        StrView prefix = StrView_over_String_ex(&known, known.size - (block_size - 1), block_size - 1);

        find_byte_cypher_mapping(&store, &block_map, &ptset, &oracle, prefix);

        char c;
        if (!HashMap_get(&block_map, &ct, &c)) {
            break;
        }
        String_append_char(&known, c);
    }

    String_print(&known);


    HashMap_destroy(&ptset);
    String_destroy(&cypher);
    String_destroy(&known);
    HashMap_destroy(&block_map);
    StringStore_destroy(&store);
    String_destroy(&secret);
    wc_free(WC_LIBC, rand_bytes, rand_count, alignof(char));
    return 0;
}
