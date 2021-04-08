#ifndef __RSA_H__
#define __RSA_H__

#include <stdint.h>

// This is the header file for the library librsaencrypt.a

// Change this line to the file you'd like to use as a source of primes.
// The format of the file should be one prime per line.
char *PRIME_SOURCE_FILE = "primes.txt";


struct public_key_class{
  long long modulus;
  long long exponent;
};

struct private_key_class{
  long long modulus;
  long long exponent;
};

// This function generates public and private keys, then stores them in the structures you
// provide pointers to. The 3rd argument should be the text PRIME_SOURCE_FILE to have it use
// the location specified above in this header.
void rsa_gen_keys(struct public_key_class *pub, struct private_key_class *priv, const char *PRIME_SOURCE_FILE);

// This function will encrypt the data pointed to by message. It returns a pointer to a heap
// array containing the encrypted data, or NULL upon failure. This pointer should be freed when
// you are finished. The encrypted data will be 8 times as large as the original data.
long long *rsa_encrypt(const char *message, const unsigned long message_size, const struct public_key_class *pub);

// This function will decrypt the data pointed to by message. It returns a pointer to a heap
// array containing the decrypted data, or NULL upon failure. This pointer should be freed when
// you are finished. The variable message_size is the size in bytes of the encrypted message.
// The decrypted data will be 1/8th the size of the encrypted data.
char *rsa_decrypt(const long long *message, const unsigned long message_size, const struct private_key_class *pub);


/*
These functions work much in the same way to their simpler counterparts declared above, with some important caveats.
Sticking with the style of rsa_encrypt and rsa_decrypt, rsa_oaep_encrypt and rsa_oaep_decrypt return a pointer to a heap array
that should be freed when it is no longer needed. For ease of use the value pointed to by message_size will refer to the size of that buffer,
which depends on the keys. A rough estimate is: rsa_oaep_encrypt of a buffer of size m will produce a buffer of size 5*(m +k1 +k2) and, in a similar way,
rsa_oaep_decrypt of a buffer of size m with k1 and k2 will produce a buffer of size (m - k1 - k2)/5.
I have included an explanation of the encryption scheme at the appropriate place in the .c file, but wikipedia has an excellent explanation.
*/
char* rsa_oaep_encrypt(const char* message, unsigned long *message_size, const struct public_key_class *pub, const unsigned long k1, const unsigned long k2);
char* rsa_oaep_decrypt(const char* message, unsigned long *message_size, const struct private_key_class *priv, const unsigned long k1, const unsigned long k2);

#endif
