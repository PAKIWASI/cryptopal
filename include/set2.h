#include "random_single.h"
#include "views_single.h"


// run whole set
int set2_run(void);


// challenge 9
/*
Implement PKCS#7 padding

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

"YELLOW SUBMARINE"

... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
*/

void pad_pkcs7(String* block, u8 block_len);
int  challenge9_run(void);


// challenge 10
/*
Implement CBC mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)
*/

u64  encrypt_aes_128_ecb(StrView plaintext, StrView key, u8* cypher, u64 len, bool padding);
void encrypt_aes_128_cbc(StrView plaintext, StrView key, StrView iv, String* cypher); // 128 BITS = 16 byte window
void decrypt_aes_128_cbc(StrView cypher, StrView key, StrView iv, String* plaintext);
int  challenge10_run(void);


// challenge 11
/*
An ECB/CBC detection oracle

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
*/

wc_always_inline void generate_random_aes_128_key(u8 k[16]);
// returns true if cbc is used, false if ecb
bool encryption_oracle(WC_Pcg32* rng, StrView plaintext, String* cypher, StrView key);
// returns true if cbc is used, false if ecb
bool detect_rand_block_cypher_mode(StrView cypher, HashMap* set);
int  challenge11_run(void);
