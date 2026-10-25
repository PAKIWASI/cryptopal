#include "set1.h"
#include "views_single.h"
#include <stdio.h>





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
    String cyper_hex = String_with_cap(WC_LIBC, size);
    u64    riyal     = fread(String_data_ptr_unsafe(&cyper_hex), 1, size, f);
    cyper_hex.size   = riyal;
    String_print(&cyper_hex);
    putchar('\n');

    // decode hex
    String cypher_bin = String_with_cap(WC_LIBC, size);
    hex_decode(StrView_over_String(&cyper_hex), &cypher_bin);
    StrView cypher = StrView_over_String(&cypher_bin);





    String_destroy(&cypher_bin);
    String_destroy(&cyper_hex);
    fclose(f);
    return 0;
}
