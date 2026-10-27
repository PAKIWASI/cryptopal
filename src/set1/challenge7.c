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

// decrypt cipher using key and iv, store result in plaintext
// - key MUST be NUL terminated
// - plaintext must be atleast ciphertext len + block size (128)
u64 decrypt_aes_128_ecb(StrView cypher, StrView key, u8* plaintext, u64 len, bool padding)
{
    WC_ASSERT(key.len == 16, "wrong key len for AES 128");
    if (padding) {
        WC_ASSERT(len >= cypher.len + 16, );
    }

    // create and init the context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleErrors();
    }

    EVP_CIPHER_CTX_set_padding(ctx, (int)padding);

    // Initialize the decryption operation with the key and IV
    // we are doing AES with 128 bit block size in ECB mode
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, (u8*)key.data, NULL) != 1) {
        handleErrors();
    }

    int out_len = 0;

    // privide the ciphertext to be decrypted
    if (EVP_DecryptUpdate(ctx, plaintext, &out_len, (u8*)cypher.data, (int)cypher.len) != 1) {
        handleErrors();
    }

    int final_len = 0;

    // finalize the decryption (handles padding)
    if (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &final_len) != 1) {
        handleErrors();
    }

    // cleanup
    EVP_CIPHER_CTX_free(ctx);

    return (u64)out_len + (u64)final_len;
}


int challenge7_run(void)
{
    FILE* f = fopen("data/challenge7.txt", "r");
    FATAL_IF(!f, "could not open challenge7.txt");

    // get file size
    fseek(f, 0, SEEK_END);
    u64 size = (u64)ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("File Size: %lu\n", size);

    // make a string to store all the text and read in the entire file
    String cyper_b64 = String_with_cap(WC_LIBC, size);
    u64    riyal     = fread(String_data_ptr_unsafe(&cyper_b64), 1, size, f);
    cyper_b64.size   = riyal;
    String_print(&cyper_b64);
    putchar('\n');

    // decode base64
    String cypher_bin = String_with_cap(WC_LIBC, size);
    base64_decode(StrView_over_String(&cyper_b64), &cypher_bin);
    StrView cypher = StrView_over_String(&cypher_bin);

    // define the key
    const char* key = "YELLOW SUBMARINE";
    // output buffer
    u8 plaintext[nKB(4)];

    // use libcrypto to decript ecb
    u64 read = decrypt_aes_128_ecb(cypher, StrView_over_cstr(key), plaintext, nKB(4), true);
    WC_ASSERT(read < sizeof plaintext, "invalid read");
    plaintext[read] = '\0';

    // output
    printf("\n%s\n", plaintext);

    String_destroy(&cypher_bin);
    String_destroy(&cyper_b64);
    fclose(f);
    return 0;
}
