#include "random_single.h"
#include "set2.h"
#include "set3.h"
#include "views_single.h"



static const char* strs[10] = {
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
};


void encrypt_cbc_rand_str(WC_Pcg32* rng, StrView key, StrView iv, String* cypher)
{
    u32 idx = pcg32_rand_range(rng, 0, 10);
    encrypt_aes_128_cbc(StrView_over_cstr(strs[idx]), key, iv, cypher);
}

bool decrypt_cbc_check_padding(StrView cypher, StrView key, StrView iv, String* plaintext)
{
    // the plaintext is padded before encryption
    // this function decrypts with padding off. so we should have the plaintext padded
    decrypt_aes_128_cbc(cypher, key, iv, plaintext);
    return StrView_is_valid(
        strip_pkcs7(StrView_over_String(plaintext)) // strip_pkcs7 returns a valid strview if padding was valid
    );
}



int challenge17_run(void)
{
    // rng
    WC_Pcg32 rng = PCG32_INITIALIZER;
    pcg32_rand_seed_os(&rng);

    // random key
    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);
    StrView rkey = StrView_over_buf((char*)rand_key, 16);
    // iv of all zeros
    u8      ivec[16] = {0};
    StrView iv       = StrView_over_buf((char*)ivec, 16);


    String cypher = String_create(WC_LIBC);
    encrypt_cbc_rand_str(&rng, rkey, iv, &cypher);


    String pt = String_create(WC_LIBC);
    WC_ASSERT(decrypt_cbc_check_padding(StrView_over_String(&cypher), rkey, iv, &pt), );



    String_destroy(&pt);
    String_destroy(&cypher);
    return 0;
}
