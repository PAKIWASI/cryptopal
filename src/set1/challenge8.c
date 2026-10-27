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


/*
    We need to look for repeated windows in the cyphertext. I'm gonna look for 16-bit windows
    using HashSet
*/
bool is_line_aes_ecb(StrView cypherline, HashMap* map, u64 window_len)
{
    HashMap_clear(map);

    for (u64 i = 0; i < cypherline.len - window_len; i++) {
        StrView win = StrView_slice(cypherline, i, window_len);

        if (HashMap_put(map, &win, NULL)) { // we have seen this window before: a repetition
            return true;
        }
    }

    return false;
}


int challenge8_run(void)
{
    FILE* f = fopen("data/challenge8.txt", "r");
    FATAL_IF(!f, "could not open challenge7.txt");

    // get file size
    fseek(f, 0, SEEK_END);
    u64 size = (u64)ftell(f);
    fseek(f, 0, SEEK_SET);
    printf("File Size: %lu\n", size);


    // hashset init
    HashMap set = HashMap_create(WC_LIBC, sizeof(StrView), 0, wc_strview_hash, wc_strview_cmp, NULL, NULL);

    String bytes = String_with_cap(WC_LIBC, 512);
    char   line[512];
    u64    line_no = 0;

    while (fgets(line, sizeof(line), f)) {
        line_no++;

        // strip trailing newline(s)
        u64 n = 0;
        while (line[n] != '\0') {
            n++;
        }
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
            line[--n] = '\0';
        }
        if (n == 0) {
            continue;
        }

        // hex decode
        hex_decode(StrView_over_cstr(line), &bytes);

        // check if line is aes-ecb
        if (is_line_aes_ecb(StrView_over_String(&bytes), &set, 16)) {
            printf("\n\nFOUND THE AES ECB ENCRIPTED LINE AT: %lu\n%s\n", line_no, line);
            break;
        }
    }


    String_destroy(&bytes);
    HashMap_destroy(&set);
    fclose(f);
    return 0;
}
