
#ifndef __RSA_H__
#define __RSA_H__

#include <stdint.h>

struct public_key_class{
  int64_t modulus;
  int64_t exponent;
};

struct private_key_class{
  int64_t modulus;
  int64_t exponent;
};

// Change this line to the file you'd like to use as a source of primes.
// The format of the file should be one prime per line.
char *PRIME_SOURCE_FILE = "primes.txt";

void gen_keys(struct public_key_class *pub, struct private_key_class *priv, char *PRIME_SOURCE_FILE);

#endif
