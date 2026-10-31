#include "random_single.h"
#include "set1.h"
#include "views_single.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>



/*
    We need to look for repeated windows in the cyphertext. I'm gonna look for 16-bit windows
    using HashSet
*/
bool is_aes_ecb(StrView cypherline, HashMap* map, u64 window_len)
{
    WC_ASSERT(cypherline.len >= window_len, );
    HashMap_clear(map);

    // TODO: check i += window_len
    for (u64 i = 0; i <= cypherline.len - window_len; i += window_len) {
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
        if (is_aes_ecb(StrView_over_String(&bytes), &set, 16)) {
            printf("\n\nFOUND THE AES ECB ENCRIPTED LINE AT: %lu\n%s\n", line_no, line);
            break;
        }
    }


    String_destroy(&bytes);
    HashMap_destroy(&set);
    fclose(f);
    return 0;
}
