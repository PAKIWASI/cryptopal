#include "random_single.h"
#include "set2.h"
#include "views_single.h"



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


StrView validate_email(StrView email)
{
    bool seen_at  = false;
    bool seen_dot = false;
    u64  start    = WC_NOT_FOUND;
    u64  end      = WC_NOT_FOUND;

    for (u64 i = 0; i < email.len; i++) {
        char c = email.data[i];
        // all valid chars for an email
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            // this is where the valid email starts
            if (start == WC_NOT_FOUND) {
                start = i;
            }
            continue;
        }
        // the dreded @
        if (c == '@') {
            seen_at = ((!seen_at) != 0); // flip
            if (!seen_at) {              // we saw a second @
                break;
            }
            continue;
        }
        // the dot
        if (c == '.') {
            seen_dot = ((!seen_dot) != 0); // flip
            if (!seen_dot) {               // we saw a second .
                break;
            }
            continue;
        }
        // anything else it's invalid, the previous char was the last valid one
        // if we had seen an @ before
        if (end == WC_NOT_FOUND && seen_at && seen_dot && i != 0) {
            end = i - 1;
        }
        break; // we break if we hit an invalid char
    }

    // email is valid if we have a valid start and end
    if (start != WC_NOT_FOUND && end != WC_NOT_FOUND && start < end) {
        return StrView_slice(email, start, end - start + 1); // email
    }
    return SV_NULL;
}


void profile_for(StrView email, String* out)
{
    //
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

    const char* email = "wasi@gmail.com";
    StrView v = validate_email(StrView_over_cstr(email));
    StrView_print(v);
    WC_ASSERT(StrView_is_valid(v), );

    HashMap_destroy(&pairs);
    StringStore_destroy(&store);
    return 0;
}
