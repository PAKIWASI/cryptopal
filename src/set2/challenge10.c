#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdlib.h>

static inline void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

u64 encript_aes_128_ecb(StrView plaintext, StrView key, u8* cypher, u64 len)
{
    if (len < plaintext.len + 128) {
        handleErrors();
    }

    // create and init the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

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
//         plain_2, nKB(4)                         //
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



int challenge10_run(void)
{

    return 0;
}



