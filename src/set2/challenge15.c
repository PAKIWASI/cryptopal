#include "random_single.h"
#include "set2.h"
#include "views_single.h"
#include <stdio.h>


/*
pkcs#7 padding can be from 1 to 16, depending on how many bytes are unused
1-15 if we have 1-15 bytes unused and 16 if we have an entire padding block
so we can have the whole last block as padding or some of it.
*/
StrView strip_pkcs7(StrView plaintext)
{
    WC_ASSERT(plaintext.len >= 16, "plaintext does not have valid block size");

    // whatever the value of the last byte is, i need that many bytes of that value before it as well
    u8 pad_char = (u8)plaintext.data[plaintext.len - 1];
    if (pad_char < 1 || pad_char > 16) { // valid pad range
        return SV_NULL;
    }
    u64 base = plaintext.len - 16; // start index of last block

    // depending on pad_char, we know how many bytes of the final block we need to verify
    for (u8 i = 16 - pad_char; i < 16; i++) {
        if ((u8)plaintext.data[base + i] != pad_char) {
            return SV_NULL;
        }
    }

    return StrView_slice(plaintext, 0, plaintext.len - pad_char);
}


int challenge15_run(void)
{
    const char* t1 = "ICE ICE BABY\x04\x04\x04\x04";
    const char* t2 = "ICE ICE BABY\x05\x05\x05\x05";

    StrView a1 = strip_pkcs7(StrView_over_cstr(t1));
    StrView_print(a1);
    putchar('\n');

    StrView a2 = strip_pkcs7(StrView_over_cstr(t2));
    StrView_print(a2);

    return 0;
}


