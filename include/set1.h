#include "views_single.h"


// run whole set
int set1_run(void);


// challenge 1
/*
Convert hex to base64

The string:

49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

So go ahead and make that happen. You'll need to use this code for the rest of the exercises.
*/

void hex_decode(StrView hex, String* bytes);
void base64_encode(StrView bytes, String* base64);
int  challenge1_run(void);


// challenge 2
/*
Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c

... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965

... should produce:

746865206b696420646f6e277420706c6179
*/
void hex_encode(StrView bytes, String* hex);
void fixed_xor(StrView bytes1, StrView bytes2, String* xored);
int  challenge2_run(void);


// challenge 3
/*
Single-byte XOR cipher

The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score. 
*/

float score_eng_text(float freq[256], u64 total_chars);
u8    decript_char_xor(StrView bytes, String* decoded);
int   challenge3_run(void);


// challenge 4
/*
 One of the 60-character strings in data/challenge4.txt has been encrypted by single-character XOR

Find it.

(Your code from #3 should help.)
*/

float score_with_key(StrView line, u8 key, String* out);
int   challenge4_run(void);


// challenge 5
/*
Implement repeating-key XOR

Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal

Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

*/

void encript_repeated_xor(StrView text, StrView key, String* encripted);
int  challenge5_run(void);


// challenge 6
/*
There's a file here (data/challenge6.txt). It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

    Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
    Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:

    this is a test

    and

    wokka wokka!!!

    is 37. Make sure your code agrees before you proceed.
    For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
    The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
    Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
    Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    Solve each block as if it was single-character XOR. You already have code to do this.
    For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.

This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important. 
*/

void  base64_decode(StrView base64, String* bytes);
float bitwise_edit_distance(StrView s1, StrView s2);
float avg_bitwise_edit_distance(StrView text, u32 keysize);
int   challenge6_run(void);


// challenge 7
/*
AES in ECB mode

The Base64-encoded content in this file (data/challenge7.txt)has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".

(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher. 
*/

u64 decrypt_aes_128_ecb(StrView cypher, StrView key, u8* plaintext, u64 len);
int challenge7_run(void);


// challenge 8
/*
Detect AES in ECB mode

In this file(data/challenge8.txt) are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext. 
*/

u64 encript_aes_128_ecb(StrView plaintext, StrView key, u8* cypher, u64 len);
bool is_line_aes_ecb(StrView cypherline, HashMap* map, u64 window_len);
int challenge8_run(void);

