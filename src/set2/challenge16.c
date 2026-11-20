#include "random_single.h"
#include "set2.h"
#include "views_single.h"

#include <stdio.h>
#include <string.h>



void first_function(StrView input, StrView key, StrView iv, String* cypher)
{
    static const char* pre  = "comment1=cooking%20MCs;userdata=";
    static const char* post = ";comment2=%20like%20a%20pound%20of%20bacon";

    String temp = String_with_cap(WC_LIBC, input.len + strlen(pre) + strlen(post));

    String_append_cstr(&temp, pre);
    String_append_multi(&temp, input.data, input.len); // user input
    String_append_cstr(&temp, post);

    // quote out the ';' and '='. This way, there is no way user input can set ;admin=true;
    // im just gonna replace both with a space for now
    for (u64 i = 0; i < String_len(&temp); i++) {
        char c = String_char_at(&temp, i);
        if (c == ';' || c == '=') {
            String_set_char(&temp, i, ' ');
        }
    }

    // encrypt the whole thing
    encrypt_aes_128_cbc(StrView_over_String(&temp), key, iv, cypher);

    String_destroy(&temp);
}

bool second_function(StrView cypher, StrView key, StrView iv, String* plaintext)
{
    decrypt_aes_128_cbc(cypher, key, iv, plaintext);

    // look for ;admin=true;
    u64 idx = StrView_find(StrView_over_String(plaintext), StrView_over_cstr(";admin=true;"));

    return idx != WC_NOT_FOUND; // true if we found it
}


int challenge16_run(void)
{
    // random key
    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);
    StrView rkey = StrView_over_buf((char*)rand_key, 16);
    // iv of all zeros
    u8      ivec[16] = {0};
    StrView iv       = StrView_over_buf((char*)ivec, 16);
    // user controlled input
    const char* user_input_1 = ";admin=true;AAA";

    String cypher = String_create(WC_LIBC);
    first_function(StrView_over_cstr(user_input_1), rkey, iv, &cypher);
    print_hex(cypher.heap, cypher.size, 16);


    // modify cyphertext to place admin=true
    /*
        the decypher is:
            Pi = D_k(Ci) ^ Ci-1
        The ith plaintext block depends on the xor of the decyphered of ith cypherblock and the i-1th cypherblock
        We modify the i-1th cypherblock such that the xor with the decypher output gives desired modifications in the ith plaintext
        This completely scrambles the i-1th plaintext block (not important tho, we can pad using user input)
        When someone actually decypheres the altered cypher without any integrity checks, they take the decypher at face value,
        even though we modified it.
    */
    /*
        the 3rd block has our user input. we can flip bits by modifying the bits of 2nd cypherblock
        the bit flip scrambles 2nd plaintext but produces the same bit flip in the 3rd block
        say 2nd block's first byte is 0 and we want to edit it so 3rd block's plaintext goes from ' ' to ';'
        ' ' is ascii 32 and ';' is 59
        ' ' ^ x = ';' -> 32 ^ x = 59 -> 32 ^x ^x = 59 ^x -> 32 ^ 59 = x = 27
    */

    cypher.heap[16] = 27; // first byte of 2nd block

    String pt    = String_create(WC_LIBC);
    bool   found = second_function(StrView_over_String(&cypher), rkey, iv, &pt);
    String_print(&pt);
    WC_ASSERT(found, "didn't find admin=true");



    String_destroy(&pt);
    String_destroy(&cypher);
    return 0;
}
