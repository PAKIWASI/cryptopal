#include "set1.h"
#include "views_single.h"

#include <stdio.h>
#include <stdlib.h>


// input: base64 char
// output: 6 bit (2^6=64) value as a u8 (lower bits set)
// derived from challenge1: to_base64_char
static wc_always_inline u8 base64_to_ascii(char c)
{
    if (c >= 'a' && c <= 'z') {
        return (u8)(c - 'a');
    }
    if (c >= 'A' && c <= 'Z') {
        return (u8)(c - 'A' + 26);
    }
    if (c >= '0' && c <= '9') {
        return (u8)(c - '0' + 52);
    }
    if (c == '+') {
        return 62;
    }
    return 63; // '/'
}

// 4 base64 chars = 4 * 6 = 24 bytes = 8 + 8 + 8 bytes decoded
// each 4 base64 chars of 6 bits each make up 3 8 bit ascii chars
void base64_decode(StrView base64, String* bytes)
{
    u64 i = 0;
    while (i + 3 < base64.len) { // 0th, 1st, 2nd and 3rd are in range
        // process 4 chars at once
        u8 b1 = base64_to_ascii(base64.data[i]);
        u8 b2 = base64_to_ascii(base64.data[i + 1]);
        u8 b3 = base64_to_ascii(base64.data[i + 2]);
        u8 b4 = base64_to_ascii(base64.data[i + 3]);

        u8 out[3] = {0}; // the three 8 byte acii outputs for these 4 base64 chars

        out[0] = (u8)(b1 << 2);  // set top 6 bits with b1
        out[0] |= (u8)(b2 >> 4); // get bottom 2 from b2 (b2 has 4 left)

        out[1] = (u8)(b2 << 4);  // set top 4 bits with remainign b2
        out[1] |= (u8)(b3 >> 2); // set bottom 4 from b3 (b3 has 2 remaining)

        out[2] = (u8)(b3 << 6); // set top 4 from b3's remaining 2
        out[2] |= b4;           // set bottom 6 bits from b4

        String_append_multi(bytes, (const char*)out, 3);

        i += 4;
    }
}

// counts the number of set bits
static wc_always_inline u8 popcount(u8 byte)
{
    u8 count = 0;
    while (byte) {
        count += byte & 0x01; // check the lowest bit
        byte >>= 1;           // shift right: 2nd bit becomes lowest
    }
    return count;
}

float bitwise_edit_distance(StrView s1, StrView s2)
{
    WC_ASSERT(s1.len == s2.len, "unequal strings");

    float distance = 0;
    for (u64 i = 0; i < s1.len; i++) {
        distance += (float)popcount((u8)(s1.data[i] ^ s2.data[i]));
    }
    return distance;
}

// take 4 keysized blocks from text, find bitwise_edit_distance for each
// consecative 2 blocks, then average and normalise them
float avg_bitwise_edit_distance(StrView text, u32 keysize)
{
    WC_ASSERT(text.len >= (u64)4 * keysize, "text is not long enough");

    float avg_edis = 0;
    for (int i = 0; i < 3; i++) {
        StrView sv1 = StrView_slice(text, (u64)i * keysize, keysize);
        StrView sv2 = StrView_slice(text, (u64)(i + 1) * keysize, keysize);
        avg_edis += bitwise_edit_distance(sv1, sv2);
    }

    return avg_edis / (float)keysize;
}

#define MAX_KEY_SIZE 64
#define MAX_KEYS     4

static void find_keysize(StrView text, float best_eds[MAX_KEYS], u8 best_keys[MAX_KEYS])
{
    u8 num = 0;

    // all keysizes between 1 and MAX_KEY_SIZE
    for (u8 k = 1; k <= MAX_KEY_SIZE; k++) {
        float ed_dis = avg_bitwise_edit_distance(text, k);
        if (num < MAX_KEYS) {
            best_keys[num] = k;
            best_eds[num]  = ed_dis;
            num++;
        } else {
            for (u8 i = 0; i < MAX_KEYS; i++) {
                if (best_eds[i] > ed_dis) {
                    best_eds[i]  = ed_dis;
                    best_keys[i] = k;
                    break;
                }
            }
        }
    }

    printf("Best Edit Distances:\t");
    for (u8 i = 0; i < MAX_KEYS; i++) {
        printf("%f\t", best_eds[i]);
    }
    putchar('\n');
    printf("Best Key Size:\t");
    for (u8 i = 0; i < MAX_KEYS; i++) {
        printf("%u\t", best_keys[i]);
    }
    putchar('\n');
}

// cleanup and free needed
static String* transform_blocks(StrView text, u8 keysize)
{
    /*
        (text chunks) |---|---|---|---|---| (5 blocks, len 3)
            after transform:
        (string blocks) |-----|-----|-----| (3 blocks, len 5)
    */

    u64 text_chunks = text.len / keysize; // remaining incomplete block is ignored
    // init array of blocks, numbering keysize
    String* blocks = malloc(sizeof(String) * keysize);
    for (u8 i = 0; i < keysize; i++) {
        blocks[i] = String_with_cap(WC_LIBC, text_chunks);
    }

    // for each keysized text chunk
    for (u64 i = 0; i < text.len; i += keysize) {
        // for each char in the chunk, place the first char of each chunk into the first block,
        // the second char into the second block and so on
        for (u8 k = 0; k < keysize; k++) {
            String_append_char(&blocks[k], text.data[i + k]);
        }
    }

    return blocks;
}


int challenge6_run(void)
{
    FILE* f = fopen("data/challenge6.txt", "r");
    FATAL_IF(!f, "could not open challenge6.txt");

    // get file size
    fseek(f, 0, SEEK_END);
    u64 size = (u64)ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("File Size: %lu\n", size);

    // make a string to store all the text and read in the entire file
    String text_base64 = String_with_cap(WC_LIBC, size);
    // BUG: reading into String_data_ptr is a segmentation fault
    fread(text_base64.heap, 1, size, f);
    text_base64.size = size;
    String_print(&text_base64);
    putchar('\n');

    // decode base64
    String text_bytes = String_with_cap(WC_LIBC, size);
    base64_decode(StrView_over_String(&text_base64), &text_bytes);
    StrView text = StrView_over_String(&text_bytes);

    // find the top MAX_KEYS of potential keys. discard multiples
    // I set max keys to 2 since more than 2 are multiples
    float best_eds[MAX_KEYS];
    u8    best_keys[MAX_KEYS];
    find_keysize(text, best_eds, best_keys);
    u8 keysize = best_keys[0];
    for (u8 i = 0; i < MAX_KEYS; i++) {
        if (best_keys[i] < keysize) {
            keysize = best_keys[i];
        }
    }

    String* blocks = transform_blocks(text, keysize); // cleanup and free needed

    // break each block as a single char xor dechiper (each blocks is encripted with one char of the key)
    // deciphered char from blocks[i] is the ith char if the key
    String key = String_with_cap(WC_LIBC, keysize);
    String d   = String_with_cap(WC_LIBC, keysize); // not needed here but decript_char_xor requires it for temp work

    // find each key char of the key from each block
    for (u8 i = 0; i < keysize; i++) {
        char k = (char)decript_char_xor(StrView_over_String(&blocks[i]), &d);
        String_append_char(&key, k);
    }

    String base64_key = String_with_cap(WC_LIBC, keysize);
    base64_encode(StrView_over_String(&key), &base64_key);

    printf("FOUND THE KEY: ");
    String_print(&base64_key);
    putchar('\n');

    String decoded = String_with_cap(WC_LIBC, size);
    encript_repeated_xor(text, StrView_over_String(&key), &decoded);

    String base64_decoded = String_with_cap(WC_LIBC, keysize);
    base64_encode(StrView_over_String(&key), &base64_decoded);

    String_print(&base64_decoded);


    String_destroy(&decoded);
    String_destroy(&base64_key);
    String_destroy(&d);
    String_destroy(&key);
    for (u8 i = 0; i < keysize; i++) {
        String_destroy(&blocks[i]);
    }
    free(blocks);
    String_destroy(&text_bytes);
    String_destroy(&text_base64);
    fclose(f);
    return 0;
}
