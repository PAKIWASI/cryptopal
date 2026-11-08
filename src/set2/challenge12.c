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

static void find_byte_cypher_mapping(StringStore* ss, HashMap* cyphermap, StrView key, u64 block_size)
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
        // store the key and val
        StrView cy = StringStore_str(ss, &cypher);
        // we have to map the entire cypher block to the entire plaintext block
        // cypher -> plaintext's char for later lookup
        char c = (char)i;
        HashMap_put(cyphermap, &cy, &c);
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

    /*
        AES ECB encrypts the whole `block_size` block as `block_size` cyphertext (as a whole, NOT individual chars)
        the same plaintext produces the same cyphertext. so we will map crafted plaintext block [A...A], [A...B] etc
        to their cypher under the random key. we will store cypher block -> char for all possible 1 byte values
        we dont need to store the entire plaintext as a value we it's the crafted input, so we know the char that made that plaintext
    */
    StringStore store;
    StringStore_create(&store, WC_LIBC, nKB(1), false);
    HashMap block_map =
        HashMap_create(WC_LIBC, sizeof(StrView), sizeof(char), wc_strview_hash, wc_strview_cmp, NULL, NULL);

    find_byte_cypher_mapping(&store, &block_map, rkey, block_size);
    HashMap_print(&block_map, wc_strview_print, wc_print_char);

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
        // map the cypher to the known cyper maps and decode the char
        StrView cy = StrView_over_String(&cypher);
        String_append_char(&decyphered, *(char*)HashMap_get_key_ptr(&block_map, &cy));
    }

    putchar('\n');
    String_print(&decyphered);
    putchar('\n');


    String_destroy(&decyphered);
    String_destroy(&cypher);
    HashMap_destroy(&block_map);
    StringStore_destroy(&store);
    String_destroy(&plaintext);
    String_destroy(&secret);
    String_destroy(&secret_b64);
    HashMap_destroy(&set);
    return 0;
}


/*
Because the attack is about recovering something you can't see, and right now your code uses the secret as an input to recover the secret.

## The scenario

The challenge models a service you can talk to but not look inside:

```
oracle(your_input) = AES-128-ECB(your_input || secret, key)
```

- You control `your_input`.
- You see the ciphertext.
- You don't know `key` or `secret`.

The goal is to recover `secret`. The secret is appended **by the oracle**, not by you. That is the whole point: your input and the secret end up in the same plaintext, so they share blocks.

## Why that matters: a small example

Use a block size of 4 and the secret `HELLO` (which you don't know).

You send 3 bytes, `AAA`. The oracle encrypts `AAAHELLO` plus padding:

```
plaintext blocks:  [A A A H] [E L L O] [pad...]
```

The first ciphertext block is `E(AAAH)`. You know three of its four plaintext bytes, and the fourth is the first byte of the secret.

Now ask the oracle about each candidate yourself: send `AAAA`, `AAAB`, `AAAC`, ..., and look at the first ciphertext block each time. ECB is deterministic, so identical plaintext blocks produce identical ciphertext blocks. When you send `AAAH`, the first block equals the target block from before. A match means the unknown byte is `H`.

For the next byte, send 2 bytes, `AA`:

```
[A A H E] [L L O pad]
```

You now know `H`, so you try `AAH` + each candidate and match against the first block. You get `E`. Shrinking the prefix slides the secret left, one byte at a time, so there is always exactly one unknown byte in the block you're attacking. That is why the secret has to be appended: your prefix length controls where the secret's bytes land relative to block boundaries.

## What your code does instead

```c
String_set_char(&plaintext, block_size - 1, String_char_at_unsafe(&secret, i));
```

The attack loop reads `secret[i]` directly and puts it into the plaintext. Then it encrypts, looks the ciphertext up in a table of all 256 candidates, and gets back... `secret[i]`. It's a round trip through AES that returns the byte you started with.

It would "work" with any deterministic function in the middle, even a broken one, because the answer is never hidden from the attack code. The cryptography isn't being broken, since there's nothing secret left to break.

## What changes

The secret lives inside the oracle function, and the attack code never touches it. The only thing the attack code can do is call `oracle(prefix)` and look at the output. The attack then has to infer `secret[i]` using only the ciphertext matching trick above.

A side effect is that the ciphertext length also leaks the secret's length. Since padding adds up to a block, the first prefix length that makes the output jump by one block tells you `len(secret)` mod `block_size`, and you can work out the rest from there. This is the same trick your `find_oracle_block_size` already uses.

*/
