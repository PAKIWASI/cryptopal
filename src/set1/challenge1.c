#include "set1.h"
#include "views_single.h"

#include <stdio.h>


static wc_always_inline u8 hex_to_byte(char h1) // 0-9, a-f
{
    switch (h1) {
    case '0':
        return 0x00;
    case '1':
        return 0x01;
    case '2':
        return 0x02;
    case '3':
        return 0x03;
    case '4':
        return 0x04;
    case '5':
        return 0x05;
    case '6':
        return 0x06;
    case '7':
        return 0x07;
    case '8':
        return 0x08;
    case '9':
        return 0x09;
    case 'a':
    case 'A':
        return 0x0A;
    case 'b':
    case 'B':
        return 0x0B;
    case 'c':
    case 'C':
        return 0x0C;
    case 'd':
    case 'D':
        return 0x0D;
    case 'e':
    case 'E':
        return 0x0E;
    case 'f':
    case 'F':
        return 0x0F;
    default:
        WC_ASSERT(false, "non hex char");
    }
}


void hex_decode(StrView hex, String* bytes)
{
    String_clear(bytes);
    u64 i = 0;
    while (i + 1 < hex.len) { // we process 2 hex chars at once
        String_append_char(bytes, (char)((hex_to_byte(hex.data[i]) << 4) | hex_to_byte(hex.data[i + 1])));
        i += 2;
    }
    if (i < hex.len) { // one char remains
        String_append_char(bytes, (char)hex_to_byte(hex.data[i]));
    }
}


/* Base64
    6-bit encoding. 2^6 = 64.

    Representation:
        a-z, A-Z, 0-9, +, /
        26 + 26 + 10 + 1 + 1 = 64
        a is 0th and / is 63th letter

    However, in ascii representation, a is not 0, it's 43
    and the order of appreance in ascii is not the same as well
*/

// val must be 0..63
static wc_always_inline char to_base64_char(u8 val)
{
    if (val < 26) {
        return (char)('A' + val);
    }
    if (val < 52) {
        return (char)('a' + (val - 26));
    }
    if (val < 62) {
        return (char)('0' + (val - 52));
    }
    return val == 62 ? '+' : '/';
}

/*
    0xF1 = 0b1111_0001 ...
    base64 = 111100 (one digit)  01
    base64 = 01 1111 (one digit) 0001
    base64 = 0001 11 (one digit) 11 0001 (another one)

    4 base 64 digits from 8x3 = 24 = 6 + 6 + 6 + 6

    so we can process 3 u8s each iteration
*/

void base64_encode(StrView bytes, String* base64)
{
    u64 i = 0;
    while (i + 2 < bytes.len) { // next 0th, 1st and 2nd are in range

        u8 c1 = (u8)bytes.data[i];
        u8 c2 = (u8)bytes.data[i + 1];
        u8 c3 = (u8)bytes.data[i + 2];

        // first 6 bits. move them 2 slots down so highest 2 bits are 0 and we have a valid 6-bit number
        String_append_char(base64, to_base64_char((c1 & 0xFC) >> 2));
        // low 2 bits remain in c1, move them up to 3rd and 4th bit, leave space for 4 bits, high 4 bits from c2 go there
        String_append_char(base64, to_base64_char((u8)((c1 & 0x03) << 4) | ((c2 & 0xF0) >> 4)));
        // low 4 bits of c2 and top 2 bits of c3
        String_append_char(base64, to_base64_char((u8)((c2 & 0x0F) << 2) | ((c3 & 0xC0) >> 6)));
        // we have 6 bits remaining in c3
        String_append_char(base64, to_base64_char(c3 & 0x3F));

        i += 3; // we processed 3 u8s
    }

    // we might have one or 2 chars remaining to process
    // 1 byte remaining, 2 digits and == padding
    // 2 bytes remaining, 3 digits and = paddin
    if (i < bytes.len) {
        u8 c1 = (u8)bytes.data[i];
        String_append_char(base64, to_base64_char(c1 >> 2));

        if (i + 1 < bytes.len) { // we have 2 left
            u8 c2 = (u8)bytes.data[i + 1];

            String_append_char(base64, to_base64_char((u8)((c1 & 0x03) << 4) | (c2 >> 4)));
            String_append_char(base64, to_base64_char((c2 & 0x0F) << 2));
            String_append_char(base64, '='); // pad with =
        } else {                             // we have one left
            String_append_char(base64, to_base64_char((c1 & 0x03) << 4));
            String_append_char(base64, '=');
            String_append_char(base64, '=');
        }
    }
}

int challenge1_run(void)
{
    // original hex string. each char is a hex digit, each digit represents 4 bits, 2 hexes combine to form one byte
    String hex = String_from_cstr(
        WC_LIBC, "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    String_print(&hex);
    putchar('\n');

    // decoded hex into raw bytes
    String bytes = String_with_cap(WC_LIBC, String_len(&hex));
    hex_decode(StrView_over_String(&hex), &bytes);
    String_print(&bytes);
    putchar('\n');

    // give the raw bytes stream to encode into base64
    String base64 = String_with_cap(WC_LIBC, String_len(&hex));
    base64_encode(StrView_over_String(&bytes), &base64);
    String_print(&base64);
    putchar('\n');

    String_destroy(&hex);
    String_destroy(&bytes);
    String_destroy(&base64);
    return 0;
}
