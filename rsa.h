#ifndef __RSA_H__
#define __RSA_H__

#include <stdint.h>

// This is the header file for the library librsaencrypt.a

// It can encrpyt / decrypt data smaller than 2^32 - 1 bytes, or about 4 GB.


// Change this line to the file you'd like to use as a source of primes.
// The format of the file should be one prime per line.
char *PRIME_SOURCE_FILE = "primes.txt";


struct public_key_class{
  int64_t modulus;
  int64_t exponent;
};

struct private_key_class{
  int64_t modulus;
  int64_t exponent;
};

// This function generates public and private keys, then stores them in the structures you
// provide pointers to. The 3rd argument should be the text PRIME_SOURCE_FILE to have it use
// the location specified above in this header.
void rsa_gen_keys(struct public_key_class *pub, struct private_key_class *priv, const char *PRIME_SOURCE_FILE);

// This function will encrypt the data pointed to by message. It returns a pointer to a heap
// array containing the encrypted data, or NULL upon failure. This pointer should be freed when 
// you are finished. The encrypted data will be 8 times as large as the original data.
int64_t *rsa_encrypt(const char *message, const unsigned long message_size, const struct public_key_class *pub);

// This function will decrypt the data pointed to by message. It returns a pointer to a heap
// array containing the decrypted data, or NULL upon failure. This pointer should be freed when 
// you are finished. The variable message_size is the size in bytes of the encrypted message. 
// The decrypted data will be 1/8th the size of the encrypted data.
char *rsa_decrypt(const int64_t *message, const unsigned long message_size, const struct private_key_class *pub);

#endif
