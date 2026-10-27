#include "set1.h"
#include "views_single.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
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

int challenge8_run(void)
{
    FILE* f = fopen("data/challenge7.txt", "r");
    FATAL_IF(!f, "could not open challenge7.txt");

    // get file size
    fseek(f, 0, SEEK_END);
    u64 size = (u64)ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("File Size: %lu\n", size);

    // make a string to store all the text and read in the entire file
    String cypher_b64 = String_with_cap(WC_LIBC, size);
    u64    riyal      = fread(String_data_ptr_unsafe(&cypher_b64), 1, size, f);
    cypher_b64.size   = riyal;
    String_print(&cypher_b64);
    putchar('\n');

    String cypher_bin = String_with_cap(WC_LIBC, size);
    base64_decode(StrView_over_String(&cypher_b64), &cypher_bin);
    StrView cypher = StrView_over_String(&cypher_bin);


    String_destroy(&cypher_bin);
    String_destroy(&cypher_b64);
    fclose(f);
    return 0;
}
