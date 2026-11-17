#include "random_single.h"
#include "set2.h"
#include "views_single.h"
#include <string.h>



void first_function(StrView input, StrView key, String* cypher)
{
    static const char* pre  = "comment1=cooking%20MCs;userdata=";
    static const char* post = ";comment2=%20like%20a%20pound%20of%20bacon";

    String temp = String_with_cap(WC_LIBC, input.len + strlen(pre) + strlen(post));

    String_append_cstr(&temp, pre);
    String_append_multi(&temp, input.data, input.len);
    String_append_cstr(&temp, post);

    

    String_destroy(&temp);
}

int challenge16_run(void)
{
    // random key
    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);



    return 0;
}
