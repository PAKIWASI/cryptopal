#include "random_single.h"
#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <stdio.h>




void fixed_key_oracle(StrView plaintext, Oracle* oracle, String* cypher)
{
    String_clear(cypher);
    String_reserve(cypher, plaintext.len + oracle->secret.len + 16);
    // oracle appends the secret to user supplied plaintext
    String pt_secret = StrView_to_String(WC_LIBC, plaintext);
    String_append_multi(&pt_secret, oracle->secret.data, oracle->secret.len);

    u64 n        = encrypt_aes_128_ecb(      //
        StrView_over_String(&pt_secret),     //
        oracle->key,                         //
        (u8*)String_data_ptr_unsafe(cypher), //
        String_capacity(cypher), true        //
    );
    cypher->size = n;

    String_destroy(&pt_secret);
}

u64 find_oracle_block_size(Oracle* oracle)
{
    String As     = String_create(WC_LIBC);
    String cypher = String_create(WC_LIBC);

    u64 base_len   = 0;
    u64 block_size = 0;

    for (;; String_append_char(&As, 'A')) {
        fixed_key_oracle(StrView_over_String(&As), oracle, &cypher);
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

bool is_oracle_ecb(HashMap* map, Oracle* oracle, u64 block_size)
{
    String As     = String_with_cap(WC_LIBC, 3 * block_size);
    String cypher = String_with_cap(WC_LIBC, 3 * block_size);

    String_reserve_char(&As, 3 * block_size, 'A');
    fixed_key_oracle(StrView_over_String(&As), oracle, &cypher);
    bool is_ecb = is_aes_ecb(StrView_over_String(&cypher), map, block_size);

    String_destroy(&cypher);
    String_destroy(&As);

    return is_ecb;
}

// TODO:
// we need to append the each decoded char back to the plaintext and slide the window forward
// this function is not what we need
// we need a function that gives us all the possible mappings for any plaintext that has some char appended to it's end
// that way, when we feed it the sliding window of 15 known chars, we want to know the possible cypherblock mappings
// with the last char included.
// This will be called once per iteration in the main decoding loop, for each char we need to decode
// we should also cache plaintext blocks to avoid redundent calls to oracle, also use interned string store
static void find_byte_cypher_mapping(StringStore* ss, HashMap* ctmap, HashMap* ptset, Oracle* oracle, StrView plaintext)
{
    u64 block_size = plaintext.len + 1;
    // appended plaintext storage
    String crafted = String_with_cap(WC_LIBC, block_size);
    String_append_multi(&crafted, plaintext.data, block_size - 1);
    String_append_char(&crafted, 'A'); // temp fil in to set size to block_size
    // cypher output storage
    String cypher = String_with_cap(WC_LIBC, block_size * 2); // plaintext.len == block_size - 1

    // one byte will be appended to plaintext and we need to brute force all possible combinations of plaintext
    // then we store the cypherblock -> last char mapping for later decoding

    // whole ascii range
    for (u8 i = 0; i < 128; i++) {
        // set the (block_size - 1)th char
        String_set_char(&crafted, block_size - 1, (char)i);
        StrView pt = StringStore_str(ss, &crafted); // storage for ptset
        // if we have seen this plaintext block before, dont do anything
        if (HashMap_has(ptset, &pt)) {
            continue;
        } // else we put this plaintext block in the set
        HashMap_put(ptset, &pt, NULL);

        fixed_key_oracle(StrView_over_String(&crafted), oracle, &cypher);

        // BUG:
        // oracle encryptes crafted || secret. but we only need the first block
        StrView ct = StringStore_sv(ss, StrView_over_String_ex(&cypher, 0, block_size));
        if (!HashMap_has(ctmap, &ct)) {
            // cypher block -> last char of crafted block (variable)
            HashMap_put(ctmap, &ct, &i);
        } // else we already have that cypher -> char mapping
    }

    String_destroy(&crafted);
    String_destroy(&cypher);
}


int challenge12_run(void)
{
    WC_Pcg32 rng = PCG32_INITIALIZER;
    pcg32_rand_seed_os(&rng);

    // single random key for all shit
    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);

    // the secret we wanna find out (base64)
    String secret_b64 = String_from_cstr(
        WC_LIBC, "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzd"
                 "GFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
    // decode base64
    String secret = String_with_cap(WC_LIBC, String_len(&secret_b64));
    base64_decode(StrView_over_String(&secret_b64), &secret);

    Oracle oracle = {
        .key    = StrView_over_buf((char*)rand_key, 16),
        .secret = StrView_over_String(&secret),
    };

    // find the block size
    u64 block_size = find_oracle_block_size(&oracle);
    printf("Block Size: %lu\n", block_size);

    // for whatever the fuck
    HashMap set = HashMap_create(WC_LIBC, sizeof(StrView), 0, wc_strview_hash, wc_strview_cmp, NULL, NULL);
    WC_ASSERT(is_oracle_ecb(&set, &oracle, block_size), "oracle no ecb");

    /*
        AES ECB encrypts the whole `block_size` block as `block_size` cyphertext (as a whole, NOT individual chars)
        the same plaintext produces the same cyphertext. so we will map crafted plaintext block [A...A], [A...B] etc
        to their cypher under the random key. we will store cypher block -> char for all possible 1 byte values
        we dont need to store the entire plaintext as a value we it's the crafted input, so we know the char that made that plaintext
    */
    StringStore store;
    StringStore_create(&store, WC_LIBC, nKB(1), true); // interned
    HashMap block_map =
        HashMap_create(WC_LIBC, sizeof(StrView), sizeof(char), wc_strview_hash, wc_strview_cmp, NULL, NULL);

    /*
        the starting plaintext is A's, with len block_size - 1, so when oracle appends the secret, it's first
        byte aligns with our A block. we find all the possible cypher blocks for the final char, then supply the 
        oracle with plaintext (where block alignment will be with secret's first byte). we decode the char with the mapping
        and append it to the plaintext. now we slide the window forward and repeat
    */

    // plaintext accumulator
    String ptpad = String_with_cap(WC_LIBC, block_size - 1);
    String_reserve_char(&ptpad, block_size - 1, 'A');
    // oracle output storage
    String cypher = String_with_cap(WC_LIBC, block_size);
    // final decoded secret storage
    String plaintext = String_with_cap(WC_LIBC, block_size);
    // plaintext set for caching blocks
    HashMap ptset = HashMap_create(WC_LIBC, sizeof(StrView), sizeof(char), wc_strview_hash, wc_strview_cmp, NULL, NULL);

    u64 off = 0; // window offset

    while (true) {
        // out cypher input ranges from 15 A's to 1 A and again we wrap around to 15 A's
        // 15 A's makes it so secret's first char is the last char of the block
        // after we decode it, we want to make it so the second secret char is also in the first block,
        // hence we decrease our input by one. when we have the whole first block decoded, we move the
        // the next one, so we will need 15 A's again, so second block's last char is the next secret char
        StrView pt = StrView_over_String_ex(&ptpad, 0,
                                            block_size - 1 - (off % (block_size - 1))); // goes from 15...1...15...1 etc

        find_byte_cypher_mapping(&store, &block_map, &ptset, &oracle, pt);
        // TODO: pt only has the pad, we need to add cypher decoded chars to it as well

        fixed_key_oracle(StrView_over_String(&ptpad), &oracle, &cypher);

        StrView ct = StrView_over_String_ex(&cypher, off, block_size); // get the WHOLE block
        char    c;
        // get the char that mapped this cypher block
        if (!HashMap_get(&block_map, &ct, &c)) {
            break; //
        }

        // append that char to the plaintext
        String_append_char(&plaintext, c);
        off++; // slide window
    }

    String_print(&plaintext);


    HashMap_destroy(&ptset);
    String_destroy(&plaintext);
    String_destroy(&cypher);
    String_destroy(&ptpad);
    HashMap_destroy(&block_map);
    StringStore_destroy(&store);
    HashMap_destroy(&set);
    String_destroy(&secret);
    String_destroy(&secret_b64);
    return 0;
}
