#include "random_single.h"
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

static bool validate_email_strict(StrView email)
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

StrView validate_email(StrView email)
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
    return validate_email_strict(sl) ? sl : SV_NULL;
}



void profile_for(StrView email, String* out)
{
    StrView valid_mail = validate_email(email);

    static u16 uid = 0;
    char       printable[8];
    snprintf(printable, 8, "%hu", uid);
    uid++;

    String_append_cstr(out, "email=");
    String_append_multi(out, valid_mail.data, valid_mail.len);
    String_append_cstr(out, "&uid=");
    String_append_cstr(out, printable);
    String_append_cstr(out, "&role=user");
}


int challenge13_run(void)
{
    const char* kvs = "foo=bar&baz=qux&zap=zazzle&hello=";

    StringStore store;
    StringStore_create(&store, WC_LIBC, nKB(1), false);

    HashMap pairs =
        HashMap_create(WC_LIBC, sizeof(StrView), sizeof(StrView), wc_strview_hash, wc_strview_cmp, NULL, NULL);


    parse_kv(StrView_over_cstr(kvs), &store, &pairs);
    HashMap_print(&pairs, wc_strview_print, wc_strview_print);


    const char* email   = "* =wasi@gmail.com   &";
    String      profile = String_create(WC_LIBC);
    profile_for(StrView_over_cstr(email), &profile);
    String_print(&profile);
    putchar('\n');

    u8 rand_key[16];
    generate_random_aes_128_key(rand_key);





    String_destroy(&profile);
    HashMap_destroy(&pairs);
    StringStore_destroy(&store);
    return 0;
}
