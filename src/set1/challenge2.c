#include "set1.h"
#include "views_single.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>



static const char digits[] = "0123456789abcdef";


void hex_encode(StrView bytes, String* hex)
{
    String_clear(hex);
    for (u64 i = 0; i < bytes.len; i++) {
        u8 b = (u8)bytes.data[i];
        String_append_char(hex, digits[b >> 4]);
        String_append_char(hex, digits[b & 0x0F]);
    }
}


// do 64 bit xor at a time
void fixed_xor(StrView bytes1, StrView bytes2, u8* xored, u64 xlen)
{
    WC_ASSERT(bytes1.len == bytes2.len, );
    WC_ASSERT(xlen >= bytes1.len, );
    // String_clear(xored);

    u64 i = 0;
    for (; i + 7 < bytes1.len; i += 8) {
        u64 b1, b2;
        memcpy(&b1, bytes1.data + i, 8);
        memcpy(&b2, bytes2.data + i, 8);
        u64 x = b1 ^ b2; // store 8 bytes at once
        // String_append_multi(xored, (const char*)&x, sizeof(x));
        memcpy(xored + i, &x, sizeof(x));
    }
    // process remaining
    for (; i < bytes1.len; i++) {
        // String_append_char(xored, (char)(bytes1.data[i] ^ bytes2.data[i]));
        xored[i] = (u8)(bytes1.data[i] ^ bytes2.data[i]);
    }
}



int challenge2_run(void)
{
    String input1 = String_from_cstr(WC_LIBC, "1c0111001f010100061a024b53535009181c");
    String_print(&input1);
    putchar('\n');
    String input2 = String_from_cstr(WC_LIBC, "686974207468652062756c6c277320657965");
    String_print(&input2);
    putchar('\n');

    String raw1 = String_with_cap(WC_LIBC, String_len(&input1) / 2);
    hex_decode(StrView_over_String(&input1), &raw1);
    String_print(&raw1);
    putchar('\n');
    String raw2 = String_with_cap(WC_LIBC, String_len(&input2) / 2);
    hex_decode(StrView_over_String(&input2), &raw2);
    String_print(&raw2);
    putchar('\n');

    u64 xlen = String_len(&raw1);
    u8* xored = malloc(xlen);
    fixed_xor(StrView_over_String(&raw1), StrView_over_String(&raw2), xored, xlen);
    StrView_print(StrView_over_buf((const char*)xored, xlen));
    putchar('\n');

    String hex = String_with_cap(WC_LIBC, xlen * 2);
    hex_encode(StrView_over_buf((const char*)xored, xlen), &hex);
    String_print(&hex);
    putchar('\n');

    String_destroy(&input1);
    String_destroy(&input2);
    String_destroy(&raw1);
    String_destroy(&raw2);
    free(xored);
    String_destroy(&hex);
    return 0;
}
