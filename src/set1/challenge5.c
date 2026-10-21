#include "set1.h"
#include "views_single.h"
#include <stdio.h>
#include <string.h>



void encript_repeated_xor(StrView text, StrView key, String* encripted)
{
    for (u64 i = 0, k = 0; i < text.len; i++, k = (k + 1) % key.len) {
        String_append_char(encripted, (char)(text.data[i] ^ key.data[k]));
    }
}


int challenge5_run(void)
{
    const char* text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const char* key  = "ICE";

    String encrpted = String_with_cap(WC_LIBC, strlen(text));
    encript_repeated_xor(StrView_over_cstr(text), StrView_over_cstr(key), &encrpted);

    String hex = String_with_cap(WC_LIBC, String_capacity(&encrpted));
    hex_encode(StrView_over_String(&encrpted), &hex);

    printf("text:\n%s\n", text);
    printf("key: %s\n", key);
    putchar('\n');
    printf("Hexed: ");
    String_print(&hex);
    putchar('\n');

    String_destroy(&hex);
    String_destroy(&encrpted);
    return 0;
}
