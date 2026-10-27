#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

u64 encrypt_aes_128_ecb(StrView plaintext, StrView key, u8* cypher, u64 len, bool padding)
{
    WC_ASSERT(key.len == 16, "wrong key len for AES 128");
    if (padding) {
        WC_ASSERT(len >= plaintext.len + 16, ); // 16 bytes (128 bits)
    }

    // create and init the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    EVP_CIPHER_CTX_set_padding(ctx, (int)padding);

    // Initialize the decryption operation with the key and IV
    // we are doing AES with 128 bit block size in ECB mode
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (u8*)key.data, NULL) != 1) {
        handleErrors();
    }

    int out_len = 0;

    // privide the ciphertext to be decrypted
    if (EVP_EncryptUpdate(ctx, cypher, &out_len, (u8*)plaintext.data, (int)plaintext.len) != 1) {
        handleErrors();
    }

    int final_len = 0;

    // finalize the decryption (handles padding)
    if (EVP_EncryptFinal_ex(ctx, cypher + out_len, &final_len) != 1) {
        handleErrors();
    }

    // cleanup
    EVP_CIPHER_CTX_free(ctx);

    return (u64)out_len + (u64)final_len;
}

// static void test_encript_decript(void)
// {
//     const char* plaintext = "hello im wasi ullah satti!";
//     const char* key       = "wus";
//
//     u8 cypher[nKB(4)];
//     u64 write     = encript_aes_128_ecb( //
//         StrView_over_cstr(plaintext),    //
//         StrView_over_cstr(key),          //
//         cypher, nKB(4)                   //
//     );
//     cypher[write] = '\0';
//     printf("\n\n CYPHER: %s", cypher);
//
//     u8  plain_2[nKB(4)];
//     u64 read = decrypt_aes_128_ecb(             //
//         StrView_over_cstr((const char*)cypher), //
//         StrView_over_cstr(key),                 //
//         plain_2, nKB(4), true                   //
//     );
//     plain_2[read] = '\0';
//     printf("\n\n PLAINTEXT: %s", plain_2);
// }


/*
The top register should be loaded with the n-bit Initialization Vector (IV).

XOR the data value in the top register with the n-bit plaintext block.

Use key K to encrypt the output of the XOR operation using the underlying block cipher.

Continue the process until all plaintext blocks have been processed by feeding the ciphertext block into the top register.

IV data is XORed with the first decrypted ciphertext block in order to decrypt it. In order to decrypt the next ciphertext block, the previous ciphertext block is added as well into the register that replaces IV.
*/
void encrypt_aes_128_cbc(StrView plaintext, StrView key, StrView iv, String* cypher)
{
    WC_ASSERT(key.len == 16, "wrong key length for AES-128");
    WC_ASSERT(iv.len == 16, "wrong IV length for AES-128");
    String_clear(cypher);

    // register that holds the last encrypted block to be xored with the next one before encryption
    u8 reg[16];
    memcpy(reg, iv.data, 16); // it initially holds iv
    StrView reg_sv = StrView_over_buf((const char*)reg, 16);

    // fixed xor output: reg ^ plaintext block
    u8 xored[16];

    // ecb encryption output
    u8 c[16];

    // Number of full 16-byte blocks. The tail is always 0..15 bytes.
    u64 full = plaintext.len - (plaintext.len % 16);

    for (u64 i = 0; i < full; i += 16) {
        // first we xor the prev cyphered block (the value in reg) with the plaintext block
        fixed_xor(reg_sv, StrView_slice(plaintext, i, 16), xored, 16);
        // encrypt that xored output
        u64 w = encrypt_aes_128_ecb(StrView_over_buf((const char*)xored, 16), key, c, sizeof c, false);
        WC_ASSERT(w == 16, "ECB with padding off must emit 16B");
        // add the encrypted block to the cypher output
        String_append_multi(cypher, (const char*)c, 16);
        // update the register with this encrypted block
        memcpy(reg, c, 16);
    }

    // Final block: build the padded 16-byte block, XOR with reg, encrypt no-pad.
    u64    left = plaintext.len - full;
    String tail = String_with_cap(WC_LIBC, 16);
    if (left) {
        String_append_multi(&tail, plaintext.data + full, left);
    }
    // pad the rest (pkcs7).
    pad_pkcs7(&tail, 16);
    WC_ASSERT(String_len(&tail) == 16, ); // we should always get 16 length as left is b/w 0..15

    fixed_xor(reg_sv, StrView_over_String(&tail), xored, 16);

    u64 w = encrypt_aes_128_ecb(StrView_over_buf((const char*)xored, 16), key, c, sizeof c, false);
    WC_ASSERT(w == 16, "final CBC block must be exactly 16B");

    String_append_multi(cypher, (const char*)c, 16);

    String_destroy(&tail);
}


void decrypt_aes_128_cbc(StrView cypher, StrView key, StrView iv, String* plaintext)
{
    WC_ASSERT(key.len == 16, "wrong key length for AES-128");
    WC_ASSERT(iv.len == 16, "wrong IV length for AES-128");
    String_clear(plaintext);

    // register that holds the last encrypted block to be xored with the next one before encryption
    u8 reg[16];
    memcpy(reg, iv.data, 16); // it initially holds iv
    StrView reg_sv = StrView_over_buf((const char*)reg, 16);

    // fixed xor output: reg ^ plaintext block
    u8 xored[16];

    // ecb decryption output
    u8 p[16];

    // cypher len should be a multiple of the block size 16
    WC_ASSERT(cypher.len % 16 == 0, "cbc encrypted text not a multiple of block len");

}


int challenge10_run(void)
{
    const char* text   = "YELLOW SUBMARINE YELLOW SUBMARINE"; // 33 bytes
    const char* key    = "YELLOW SUBMARINE";
    const char  iv[16] = {0}; // all ascii zeros

    String cypher = String_with_cap(WC_LIBC, 64);
    encrypt_aes_128_cbc(StrView_over_cstr(text), StrView_over_cstr(key), StrView_over_buf(iv, 16), &cypher);
    String_print(&cypher);
    putchar('\n');



    String_destroy(&cypher);
    return 0;
}
