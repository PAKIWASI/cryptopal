#include "set1.h"
#include "views_single.h"

#include <stdio.h>

int main(void)
{
    // original hex string. each char is a hex digit, each digit represents 4 bits, 2 hexes combine to form one byte
    String hex = String_from_cstr(
        WC_LIBC, "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    String_print(&hex);
    putchar('\n');

    // decoded hex into raw bytes (used char for convinence)
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
