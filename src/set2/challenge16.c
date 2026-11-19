#include "random_single.h"
#include "set2.h"
#include "views_single.h"

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
    const char* user_input = "hello;admin=true;";

    String cypher = String_create(WC_LIBC);
    first_function(StrView_over_cstr(user_input), rkey, iv, &cypher);

    // modify cyphertext to place admin=true
    /*
        Let's say I modify the first byte of the cypher. In the decrypt function, Reg is loaded with IV and
        we get garbage output for the first block decypher as internally it uses ecb and ecb encrypts identical
        plaintext block to identical cyphertext block. I changed one byte so it'll be different.
        Then that CYPHERTEXT block is loaded into the register where IV was for block one. That block is ONE BYTE off.
        The first byte. So the second block is also all wrong again and we load the next
    */

    String pt = String_create(WC_LIBC);
    WC_ASSERT(second_function(StrView_over_String(&cypher), rkey, iv, &pt), "didn't find admin=true");

    String_destroy(&pt);
    String_destroy(&cypher);
    return 0;
}



