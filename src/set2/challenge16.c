#include "random_single.h"
#include "set2.h"
#include "views_single.h"

#include <stdio.h>
#include <string.h>



void first_function(StrView input, StrView key, StrView iv, String* cypher)
{
    static const char* pre  = "comment1=cooking%20MCs;userdata=";
    static const char* post = ";comment2=%20like%20a%20pound%20of%20bacon";

    String temp = String_with_cap(WC_LIBC, input.len + strlen(pre) + strlen(post));

    String_append_cstr(&temp, pre);
    String_append_multi(&temp, input.data, input.len); // user input
    String_append_cstr(&temp, post);

    // quote out the ';' and '='. This way, there is no way user input can set ;admin=true;
    // im just gonna replace both with a space for now
    for (u64 i = 0; i < String_len(&temp); i++) {
        char c = String_char_at(&temp, i);
        if (c == ';' || c == '=') {
            String_set_char(&temp, i, ' ');
        }
    }

    // encrypt the whole thing
    encrypt_aes_128_cbc(StrView_over_String(&temp), key, iv, cypher);

    String_destroy(&temp);
}

bool second_function(StrView cypher, StrView key, StrView iv, String* plaintext)
{
    decrypt_aes_128_cbc(cypher, key, iv, plaintext);

    // look for ;admin=true;
    u64 idx = StrView_find(StrView_over_String(plaintext), StrView_over_cstr(";admin=true;"));

    return idx != WC_NOT_FOUND; // true if we found it
}


int challenge16_run(void)
{
    // random key
    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);
    StrView rkey = StrView_over_buf((char*)rand_key, 16);
    // iv of all zeros
    u8      ivec[16] = {0};
    StrView iv       = StrView_over_buf((char*)ivec, 16);
    // user controlled input
    const char* user_input_1 = ";admin=true;AAAA";

    String cypher = String_create(WC_LIBC);
    first_function(StrView_over_cstr(user_input_1), rkey, iv, &cypher);
    print_hex(cypher.heap, cypher.size, 16);

    // modify cyphertext to place admin=true
    /*
        AES-CBC decryption, block by block, is:

            P[i] = D_K(C[i]) ^ C[i-1]

        where D_K is AES decryption, C[i] is the i-th ciphertext block,
        C[i-1] is the previous ciphertext block, and ^ is XOR.
        (For i = 0, C[-1] is the IV.)

        The attacker controls every byte of the ciphertext, so the attacker
        controls C[i-1] directly. The attacker does NOT know D_K(C[i]);
        that is a pseudorandom byte produced by AES.

        If we replace C[i-1] with (C[i-1] ^ delta), then:

            P'[i] = D_K(C[i]) ^ (C[i-1] ^ delta)
                  = (D_K(C[i]) ^ C[i-1]) ^ delta
                  = P[i] ^ delta

        The unknown D_K(C[i]) cancels out against the existing C[i-1], and
        the plaintext byte changes by exactly delta, regardless of what
        the original ciphertext byte or the decrypted byte were. This is
        why the flip MUST be applied with ^= (XOR), not with = (assign):

            C[i-1] ^= delta;   // correct:  P'[i] = P[i] ^ delta
            C[i-1]  = delta;   // wrong:    P'[i] = D_K(C[i]) ^ delta

        The assignment version only lands on the desired plaintext byte if
        the decrypted byte D_K(C[i]) happens to equal the old plaintext
        byte (i.e. if the original C[i-1] was 0). That is a 1/256 event
        per flipped byte, so assignment is effectively broken.

        Layout produced by first_function():

            "comment1=cooking%20MCs;userdata="  (32 bytes, 2 blocks: 0, 1)
            "<user input>"                      (block 2)
            ";comment2=%20like%20a%20pound%20of%20bacon"

        The prefix is exactly 32 bytes, so the user input begins on a
        block boundary at plaintext block 2. Therefore:

          - plaintext block 1 depends on ciphertext block 0 (unchanged)
          - plaintext block 2 depends on ciphertext block 1 (we flip this)
          - flipping a byte in ciphertext block 1 also scrambles
            plaintext block 1 (garbage, but harmless: it is the fixed
            prefix, and second_function only searches for ";admin=true;")

        The user input we send is ";admin=true;AAAA". first_function
        replaces ';' and '=' with ' ', so plaintext block 2 becomes:

            " admin true AAAA"
             0123456789...

        We want to flip the three spaces at offsets 0, 6, 11 back into
        ';', '=', ';'. Deltas are computed from the plaintext bytes:

            ' ' = 0x20,  ';' = 0x3b,  '=' = 0x3d

            delta[0]  = ' ' ^ ';' = 0x20 ^ 0x3b = 0x1b = 27
            delta[6]  = ' ' ^ '=' = 0x20 ^ 0x3d = 0x1d = 29
            delta[11] = ' ' ^ ';' = 0x20 ^ 0x3b = 0x1b = 27

        Those deltas go into ciphertext block 1 (bytes 16..31), at the
        offsets matching the plaintext positions inside block 2:
        
            ciphertext byte 16 + 0  -> plaintext block 2 byte 0
            ciphertext byte 16 + 6  -> plaintext block 2 byte 6
            ciphertext byte 16 + 11 -> plaintext block 2 byte 11
        
        After the flips, block 2 decrypts to ";admin=true;AAAA".
        No integrity check is present, so second_function accepts it.
     */

    printf("%c\n", 32 ^ 27);
    printf("%c\n", 32 ^ 29);

    cypher.heap[16] ^= 27; // 0th byte of 2nd block. ' ' ^ 27 = ';'
    cypher.heap[22] ^= 29; // 6th byte of 2nd block. ' ' ^ = '='
    cypher.heap[27] ^= 27; // 11th byte of 2nd block. ' ' ^ 27 = ';'

    String pt    = String_create(WC_LIBC);
    bool   found = second_function(StrView_over_String(&cypher), rkey, iv, &pt);
    WC_ASSERT(found, "didn't find admin=true");
    String_print(&pt);


    String_destroy(&pt);
    String_destroy(&cypher);
    return 0;
}
