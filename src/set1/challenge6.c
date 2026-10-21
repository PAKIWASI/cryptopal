#include "set1.h"
#include "views_single.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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

// static int edit_distance_test(void)
// {
//     const char* c1 = "this is a test";
//     const char* c2 = "wokka wokka!!!";
//
//     // should be 37
//     printf("Edit Distance: %f\n", bitwise_edit_distance(StrView_over_cstr(c1), StrView_over_cstr(c2)));
//
//     return 0;
// }

#define MAX_KEY_SIZE 64

static u8 find_key_size(StrView text)
{
    WC_ASSERT(text.len >= (u64)2 * MAX_KEY_SIZE, "text not long enough: %lu", text.len);

    // the key size with the smallest edit distance is PROBABLY the key
    float smallest_edit_dis = 100000.0F;
    u8    smallest_key_size = 255;

    char bytes1[MAX_KEY_SIZE] = {0};
    char bytes2[MAX_KEY_SIZE] = {0};

    // check key sizes from 1 to 64 bytes
    for (u8 keysize = 1; keysize <= MAX_KEY_SIZE; keysize++) {

        memcpy(bytes1, text.data, keysize);
        memcpy(bytes2, text.data + keysize, keysize);

        float edit_dis = bitwise_edit_distance(StrView_over_buf(bytes1, keysize), StrView_over_buf(bytes2, keysize));
        edit_dis /= (float)keysize; // normalise

        if (edit_dis < smallest_edit_dis) {
            smallest_edit_dis = edit_dis;
            smallest_key_size = keysize;
        }
    }

    printf("Smallest Edit Distance: %f\n", smallest_edit_dis);
    printf("Smallest Key Size: %u\n", smallest_key_size);

    return smallest_key_size;
}



typedef struct {
    String* strings;
    u64     size;
} StringArr;

static StringArr StringArr_create(u64 size)
{
    String* strings = malloc(sizeof(String) * size);
    for (u64 i = 0; i < size; i++) {
        strings[i] = String_create(WC_LIBC);
    }
    return (StringArr){.strings = strings, .size = size};
}

static void StringArr_destroy(StringArr* sarr)
{
    for (u64 i = 0; i < sarr->size; i++) {
        String_destroy(&sarr->strings[i]);
    }
}


// find the best single char xor key for line. found by scoring text
void find_best_key(StrView line, float* best_score, u8* best_key)
{
    *best_score = 10000.0F;
    *best_key   = 0;

    for (int k = 0; k < 256; k++) {
        float score = score_with_key(line, (u8)k, NULL);
        if (score < *best_score) {
            *best_score = score;
            *best_key   = (u8)k;
        }
    }
}


int challenge6_run(void)
{
    FILE* f = fopen("data/challenge6.txt", "r");
    FATAL_IF(!f, "file not found");

    // get file size
    fseek(f, 0, SEEK_END);
    u64 size = (u64)ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("size: %lu\n", size);

    // store whole file in a string
    String text = String_with_cap(WC_LIBC, size);
    // fread(String_data_ptr(&text), size, 1, f); // BUG: segfault
    fread(text.heap, size, 1, f);
    text.size = size;
    String_print(&text);
    putchar('\n');

    // the text is base64, decript it first
    String bytes = String_with_cap(WC_LIBC, size);
    base64_decode(StrView_over_String(&text), &bytes);
    String_print(&bytes);
    putchar('\n');

    // find the keysize using bitwise edit distance
    u8 keysize = find_key_size(StrView_over_String(&text));

    // divide whole text into keysized blocks
    // keysize/text.size = n (number of blocks)
    u64       n      = (text.size / keysize); // + 1; // final block may not be complete
    StringArr blocks = StringArr_create(keysize);

    // each block is a string, so we can transform it
    for (u64 i = 0; i < n; i += keysize) {  // keysize'd strides
        for (u64 j = 0; j < keysize; j++) { // for each char in a block
            // for each string in StringArr, the first one contains all the first chars of each block
            // then the next string contains the second chars of each block and so on
            String_append_char(&blocks.strings[j], text.heap[j + i]);
        }
    }

    String decoded = String_with_cap(WC_LIBC, keysize);

    String key = String_with_cap(WC_LIBC, keysize);
    for (u64 i = 0; i < blocks.size; i++) {
        float score;
        u8 k;
        find_best_key(StrView_over_String(&blocks.strings[i]), &score, &k);
        String_append_char(&key, (char)k);
    }

    printf("\n\nFOUND IT\n\n");
    String_print(&key);
    printf("\n\nFOUND IT\n\n");


    String_destroy(&key);
    String_destroy(&decoded);
    StringArr_destroy(&blocks);
    String_destroy(&bytes);
    String_destroy(&text);
    fclose(f);
    return 0;
}
