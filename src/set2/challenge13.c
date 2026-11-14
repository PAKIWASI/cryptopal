#include "random_single.h"
#include "set1.h"
#include "set2.h"
#include "views_single.h"

#include <stdio.h>



void parse_kv(StrView kvs, StringStore* ss, HashMap* out)
{
    WC_ASSERT(kvs.len >= 3, "kvs not valid"); // a=b

    String builder = String_create(WC_LIBC);
    String key     = String_create(WC_LIBC);

    for (u64 i = 0; i < kvs.len; i++) {
        char c = kvs.data[i];

        switch (c) {
        case '=': { // key has ended: write it to key buffer string
            String_append_String(&key, &builder);
            String_clear(&builder);
            break;
        }
        case '&': { // val has ended, write the whole
            // val is in builder, the key string has the key
            // first store them in persistant storage
            StrView k = StringStore_str(ss, &key);
            StrView v = StringStore_str(ss, &builder);
            // add key/val to hashmap
            HashMap_put(out, &k, &v);
            // clear builder and key strings for next kv
            String_clear(&key);
            String_clear(&builder);
            break;
        }

        default:
            String_append_char(&builder, c);
        }
    }

    // for the last pair, we will write it if key/builder string is not empty
    // this ensures a valid key/val pair and we dont write anything extra
    // if the loop did process the last pair
    if (String_len(&key) != 0 && String_len(&builder) != 0) {
        StrView k = StringStore_str(ss, &key);
        StrView v = StringStore_str(ss, &builder);
        HashMap_put(out, &k, &v);
    }

    String_destroy(&key);
    String_destroy(&builder);
}


static inline bool is_alnum(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) != 0;
}

static inline bool is_local_special(char c)
{
    return (c == '_' || c == '%' || c == '+' || c == '-') != 0;
}

bool validate_email(StrView email)
{
    u64  at            = WC_NOT_FOUND;
    bool dot_in_domain = false;

    for (u64 i = 0; i < email.len; i++) {
        char c = email.data[i];

        if (is_alnum(c)) {
            continue;
        }
        // domain part starts after this
        if (c == '@') {
            if (at != WC_NOT_FOUND || i == 0 || email.data[i - 1] == '.') {
                return false; // second @ or  // empty local part or "a.@b" etc
            }
            at = i;
            continue;
        }
        // dot can appear in both name and domain part
        if (c == '.') {
            if (i == 0 || i == email.len - 1) {
                return false; // leading/trailing dot
            }
            char prev = email.data[i - 1];
            if (prev == '.' || prev == '@') {
                return false; // "..", "@."
            }
            // we already have an @: we are in the domain part
            if (at != WC_NOT_FOUND) {
                dot_in_domain = true;
            }
            continue;
        }

        // '-' allowed in both parts, the other specials only before the @
        if (c == '-' || (at == WC_NOT_FOUND && is_local_special(c))) {
            continue;
        }

        return false; // invalid char
    }

    if (at == WC_NOT_FOUND || !dot_in_domain) {
        return false;
    }
    return true;
}

StrView extract_email(StrView email)
{
    u64 start = WC_NOT_FOUND;
    u64 end   = WC_NOT_FOUND;

    // find the start
    for (u64 i = 0; i < email.len; i++) {
        char c = email.data[i];

        if (is_alnum(c) || is_local_special(c)) { // these are valid chars for email start
            start = i;
            break;
        }
    }
    if (start == WC_NOT_FOUND) {
        return SV_NULL;
    }

    // find the end index
    for (u64 i = email.len - 1; i >= start; i--) {
        char c = email.data[i];

        if (is_alnum(c)) { // only these accepted after @, at the end
            end = i;
            break;
        }
    }
    if (end == WC_NOT_FOUND) {
        return SV_NULL;
    }

    StrView sl = StrView_slice(email, start, end - start + 1);
    return validate_email(sl) ? sl : SV_NULL;
}



void profile_for(StrView email, String* out)
{
    StrView valid_mail = extract_email(email);

    static u16 uid = 100;
    char       printable[8];
    snprintf(printable, 8, "%hu", uid);
    uid++;

    String_append_cstr(out, "email=");
    String_append_multi(out, valid_mail.data, valid_mail.len);
    String_append_cstr(out, "&uid=");
    String_append_cstr(out, printable);
    String_append_cstr(out, "&role=user");
}

void encrypt_aes_ecb_string(StrView str, StrView key, String* cypher)
{
    String_clear(cypher);
    String_reserve(cypher, str.len + 16);
    u64 n        = encrypt_aes_128_ecb(str, key, (u8*)String_data_ptr_unsafe(cypher), String_capacity(cypher), true);
    cypher->size = n;
}

void decrypt_aes_ecb_string(StrView str, StrView key, String* plaintext)
{
    String_clear(plaintext);
    String_reserve(plaintext, str.len + 16);
    u64 n = decrypt_aes_128_ecb(str, key, (u8*)String_data_ptr_unsafe(plaintext), String_capacity(plaintext), true);
    plaintext->size = n;
}

int challenge13_run(void)
{
    StringStore store;
    StringStore_create(&store, WC_LIBC, nKB(1), false);

    // map for storing parsed key value pairs from the profiles
    HashMap pairs =
        HashMap_create(WC_LIBC, sizeof(StrView), sizeof(StrView), wc_strview_hash, wc_strview_cmp, NULL, NULL);

    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);
    StrView rkey = StrView_over_buf((char*)rand_key, 16);

    /*
        craft email A to isolate the role= field
        Push the substring role= to the end of a block. This ensures the next block starts with the role value
        Feed the oracle emails of varying lengths (e.g., "A"*n). For each, check the ciphertext length.
        The moment the ciphertext length increases by one block (16 bytes), you have filled a block completely.
        Adjust the email length by a few more characters (e.g., +3 or +4) to push "user" into its own, new block.
    */
    const char* email     = "AAAAAAAAAwasisatti@gmail.com";
    String      profile_A = String_create(WC_LIBC);
    String      cypher_A  = String_create(WC_LIBC);
    profile_for(StrView_over_cstr(email), &profile_A);
    String_print(&profile_A); putchar('\n');
    // find index of role=user
    u64 user_i = StrView_find(StrView_over_String(&profile_A), StrView_over_cstr("role=user"));
    WC_ASSERT(user_i != WC_NOT_FOUND, );
    user_i += 5;                                                          // +5 to skip role=
    WC_ASSERT(user_i % 16 == 0, "must be a mulitple of 16: %lu", user_i); // it must be a multiple of 16
    encrypt_aes_ecb_string(StrView_over_String(&profile_A), rkey, &cypher_A);
    WC_ASSERT(cypher_A.size == user_i + 16, );
    // the final block has "user" and some padding encrypted


    /*
        craft email B to isolate the admin string. Since the total length of "admin" is 5 bytes,
        it will be padded with 11 bytes of PKCS#7 padding. this block has only admin plus padding
    */
    String profile_B = String_from_cstr(WC_LIBC, "admin");
    String cypher_B  = String_create(WC_LIBC);
    encrypt_aes_ecb_string(StrView_over_String(&profile_B), rkey, &cypher_B);
    WC_ASSERT(cypher_B.size == 16, );

    
    // remove the last block from A (containing user + padding) and replace it with B (containing admin + padding)
    String_remove_range(&cypher_A, String_len(&cypher_A) - 16 - 1, 16);
    String_append_String(&cypher_A, &cypher_B);

    // decrypt
    String pt = String_create(WC_LIBC);
    decrypt_aes_ecb_string(StrView_over_String(&cypher_A), rkey, &pt);

    // parse the key value pairs
    parse_kv(StrView_over_String(&pt), &store, &pairs);

    HashMap_print(&pairs, wc_strview_print, wc_strview_print);


    String_destroy(&pt);
    String_destroy(&cypher_B);
    String_destroy(&profile_B);
    String_destroy(&cypher_A);
    String_destroy(&profile_A);
    HashMap_destroy(&pairs);
    StringStore_destroy(&store);
    return 0;
}
