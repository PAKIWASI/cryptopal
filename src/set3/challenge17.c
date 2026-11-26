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

bool decrypt_cbc_check_padding(StrView cypher, StrView key, StrView iv)
{
    String plaintext = String_create(WC_LIBC);
    // the plaintext is padded before encryption
    // this function decrypts with padding off. so we should have the plaintext padded
    decrypt_aes_128_cbc(cypher, key, iv, &plaintext);
    return StrView_is_valid(
        strip_pkcs7(StrView_over_String(&plaintext)) // strip_pkcs7 returns a valid strview if padding was valid
    );

    String_destroy(&plaintext);
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


    /*
        The "server" (the decrypt function), does Pi = D_k(Ci) ^ Ci-1
        It then tries to strip padding, and returns true if the padding is valid and strips it.

        To decypher Ci, we supply the "previous" block, a block we craft, as [000...x], where x our testing value 0-255
        crafted:[000000000000000x]
        cypher: [cccccccccccccccc]
        decyper:[iiiiiiiiiiiiiiii] intermediate result from D_k(Ci)
        xor:    [ppppppppppppppp1] -> valid padding, returns true

        as x ^ i = 0x01 => i = x ^ 0x01, we have the last byte
        TODO: for x = 0-16, when oracle returns true, we need to check the byte before the one we are looking for
        it might be 0x02 when x = 0x02, so its valid padding

        [000000000000000x]
        [cccccccccccccccc]
        [iiiiiiiiiiiiiiij]
        [pppppppppppppp22]

        i = 0 ^ 0x02 = 0x02
        j = x ^ 0x02

        now insert 0x02 in its position, and the next iternation will look for valid padding 0x02 0x02

    */
    String crafted = String_with_cap(WC_LIBC, 32);

    // for each block of cyphertext
    for (u64 i = 0; i < String_len(&cypher) - 16; i += 16) {
        String_clear(&crafted);
        String_append_multi(&crafted, (char*)ivec, 16);                  // all zeros
        String_append_multi(&crafted, String_data_ptr(&cypher) + i, 16); // append the block we want to decrypt

        // for each byte in the block, starting from the end
        for (u8 j = 15; j >= 0; j--) {

            // test every possible value for the byte
            for (u8 k = 0; k < 255; k++) {
                *(String_data_ptr(&crafted) + j) = (char)k;

                if (decrypt_cbc_check_padding(StrView_over_String(&crafted), rkey, iv)) {
                    u8 expeced_pad = 16 - j;

                    u8 decoded = k ^ expeced_pad;

                    if (k < 17) { // check 0-16 for edge case
                    }
                }
            }
        }
    }



    String_destroy(&crafted);
    String_destroy(&cypher);
    return 0;
}





