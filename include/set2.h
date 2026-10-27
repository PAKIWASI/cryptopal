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

u64 encript_aes_128_ecb(StrView plaintext, StrView key, u8* cypher, u64 len);
// TODO:
void encrypt_aes_128_cbc(StrView plaintext, StrView key, StrView iv, String* cypher);
void decrypt_aes_128_cbc(StrView cypher, StrView key, StrView iv, String* plaintext);

int challenge10_run(void);
