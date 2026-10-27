#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <stdio.h>



void pad_pkcs7(String* block, u8 block_len)
{
    WC_ASSERT(block_len != 0, "invalid block_len");

    u8 mod_len = (u8)(String_len(block) % block_len);

    // block's len is a multiple of block_len
    // add an entire block_len as padding
    // else, just add padding as needed
    u8 to_pad = (mod_len == 0) ? block_len : block_len - mod_len;

    // append `to_pad` number of bytes to block, all with value `to_pad`
    String_reserve_char(block, String_len(block) + to_pad, (char)to_pad);
}


int challenge9_run(void)
{
    String key = String_from_cstr(WC_LIBC, "YELLOW SUBMARINE");
    String_print(&key);
    putchar('\n');

    pad_pkcs7(&key, 20);

    String key_hex = String_with_cap(WC_LIBC, String_len(&key));
    hex_encode(StrView_over_String(&key), &key_hex);
    String_print(&key_hex);
    putchar('\n');

    String_destroy(&key_hex);
    String_destroy(&key);
    return 0;
}
