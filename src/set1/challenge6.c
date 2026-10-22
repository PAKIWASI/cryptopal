#include "set1.h"
#include "views_single.h"

#include <stdio.h>
#include <stdlib.h>


static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1; // newline, '=', anything else
}

void base64_decode(StrView base64, String* bytes)
{
    u32 acc  = 0;
    int bits = 0;
    for (u64 i = 0; i < base64.len; i++) {
        if (base64.data[i] == '=') {
            break;
        }
        int v = b64_val(base64.data[i]);
        if (v < 0) {
            continue; // skip whitespace
        }
        acc = (acc << 6) | (u32)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            String_append_char(bytes, (char)((acc >> bits) & 0xFF));
            acc &= (1u << bits) - 1; // drop consumed bits
        }
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


//use every consecutive block pair in the ciphertext
float avg_bitwise_edit_distance(StrView text, u32 keysize)
{
    u64 nblocks = text.len / keysize;
    WC_ASSERT(nblocks >= 2, "text is not long enough");

    u64   pairs = nblocks - 1;
    float total = 0;
    for (u64 i = 0; i < pairs; i++) {
        StrView a = StrView_slice(text, i * keysize, keysize);
        StrView b = StrView_slice(text, (i + 1) * keysize, keysize);
        total += bitwise_edit_distance(a, b);
    }
    return total / ((float)pairs * (float)keysize);
}

#define MAX_KEY_SIZE 64
#define MAX_KEYS     4

// returns how many candidates were found
static u8 find_keysize(StrView text, float best_eds[MAX_KEYS], u8 best_keys[MAX_KEYS])
{
    WC_ASSERT(text.len >= (u64)2 * MAX_KEY_SIZE, "text too short");

    u8 num = 0;

    for (u8 k = 1; k <= MAX_KEY_SIZE; k++) {
        float d = avg_bitwise_edit_distance(text, k);

        // full and not better than the current worst: skip
        if (num == MAX_KEYS && d >= best_eds[MAX_KEYS - 1]) {
            continue;
        }
        // slot to fill: a new one, or overwrite the worst (last)
        u8 i = (num < MAX_KEYS) ? num++ : MAX_KEYS - 1;
        // shift worse entries down to keep the array sorted ascending
        while (i > 0 && best_eds[i - 1] > d) {
            best_eds[i]  = best_eds[i - 1];
            best_keys[i] = best_keys[i - 1];
            i--;
        }
        best_eds[i]  = d;
        best_keys[i] = k;
    }

    printf("Best Key Size:\t\t");
    for (u8 i = 0; i < num; i++) {
        printf("%u\t", best_keys[i]);
    }
    printf("\nBest Edit Distances:\t");
    for (u8 i = 0; i < num; i++) {
        printf("%f\t", best_eds[i]);
    }
    putchar('\n');

    return num;
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
    for (u64 c = 0; c < text_chunks; c++) {
        // for each char in the chunk, place the first char of each chunk into the first block,
        // the second char into the second block and so on
        for (u8 k = 0; k < keysize; k++) {
            String_append_char(&blocks[k], text.data[(c * keysize) + k]);
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
    u8    num     = find_keysize(text, best_eds, best_keys);
    u8    keysize = best_keys[0]; // best score (requires the sorted version of find_keysize)
    for (u8 i = 1; i < num; i++) {
        // a smaller candidate that divides the current pick is the real key length
        if (best_keys[i] < keysize && keysize % best_keys[i] == 0) {
            keysize = best_keys[i];
        }
    }

    printf("KEYSIZE: %u\n", keysize);

    // transform chunks into blocks

    String* blocks = transform_blocks(text, keysize); // cleanup and free needed

    // break each block as a single char xor dechiper (each blocks is encripted with one char of the key)
    // deciphered char from blocks[i] is the ith char of the key
    String key = String_with_cap(WC_LIBC, keysize);
    String d   = String_with_cap(WC_LIBC, keysize); // not needed here but decript_char_xor requires it for temp work

    // find each key char of the key from each block
    for (u8 i = 0; i < keysize; i++) {
        char k = (char)decript_char_xor(StrView_over_String(&blocks[i]), &d);
        String_append_char(&key, k);
    }

    printf("\nFOUND THE KEY: ");
    String_print(&key);
    putchar('\n');

    // do repeated key xor again on the text
    // this undoes the original xor encription and leaves plain text
    String decoded = String_with_cap(WC_LIBC, size);
    encript_repeated_xor(text, StrView_over_String(&key), &decoded);
    printf("\n\n DECODED TEXT\n\n");
    String_print(&decoded);
    printf("\n\n");


    String_destroy(&decoded);
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
