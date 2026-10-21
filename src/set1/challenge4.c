#include "set1.h"
#include "views_single.h"

#include <stdio.h>


float score_with_key(StrView line, u8 key, String* out)
{
    float freq[256] = {0};
    if (out) {
        String_clear(out);
    }

    for (u64 i = 0; i < line.len; i++) {
        u8 b = (u8)(line.data[i] ^ key);
        freq[b]++;
        if (out) {
            String_append_char(out, (char)b);
        }
    }
    return score_eng_text(freq, line.len);
}


int challenge4_run(void)
{
    FILE* f = fopen("data/challenge4.txt", "r");
    FATAL_IF(!f, "file open failed");

    float  best_score   = 100000.0F;
    u8     best_key     = 0;
    u64    best_line_no = 0; // 1-based
    String best_hex     = String_with_cap(WC_LIBC, 256);
    String best_plain   = String_with_cap(WC_LIBC, 256);

    char   line[256];
    String bytes   = String_with_cap(WC_LIBC, 128);
    String decoded = String_with_cap(WC_LIBC, 128);

    u64 line_no = 0;
    while (fgets(line, sizeof(line), f)) {
        line_no++;

        // 1. strip trailing newline(s)
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

        // 2. hex-decode this line
        hex_decode(StrView_over_cstr(line), &bytes);

        // 3. try every key, XOR the whole line
        for (int k = 0; k < 256; k++) {
            float score = score_with_key(StrView_over_String(&bytes), (u8)k, &decoded);
            if (score < best_score) {
                best_score   = score;
                best_key     = (u8)k;
                best_line_no = line_no;
                String_clear(&best_hex);
                String_append_cstr(&best_hex, line);
                String_clear(&best_plain);
                String_append_String(&best_plain, &decoded);
            }
        }
    }

    printf("FOUND AT LINE %lu, KEY 0x%02x ('%c'), SCORE %.6f\n", best_line_no, best_key,
           (best_key >= 32 && best_key < 127) ? best_key : '?', best_score);
    printf("HEX:      ");
    String_print(&best_hex);
    putchar('\n');
    printf("PLAINTEXT: ");
    String_print(&best_plain);
    putchar('\n');

    String_destroy(&best_hex);
    String_destroy(&best_plain);
    String_destroy(&bytes);
    String_destroy(&decoded);
    fclose(f);
    return 0;
}


