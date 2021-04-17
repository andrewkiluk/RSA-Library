#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include "sha-256.h"

char buffer[1024];
const int MAX_DIGITS = 50;
int i,j = 0;

struct public_key_class{
  long long modulus;
  long long exponent;
};

struct private_key_class{
  long long modulus;
  long long exponent;
};
/*
This file has been augmented to include OAEP functions that scramble input messages in a predictable way before encrypting them,
thus maken chosen or known plaintext attacks much more challenging.
No important information should ever be encoded without them.
*/
//this little function is necessary, because the original rsa implementation expects signed chars and the sha implementation outputs unsigned chars
//maybe this can be replaced
static char cabsc(uint8_t in){
      return in >= 128 ? in >> 1: in;
}
//necessary forward declarations to place all of the OAEP stuff at the top
long long *rsa_encrypt(const void *message, const unsigned long message_size, const struct public_key_class *pub);
uint8_t *rsa_decrypt(const long long *message, const unsigned long message_size, const struct private_key_class *pub);
/*
This function is described very well on wikipedia, but the short version is:
for every group of 32 bytes that is requested, apply sha256 to seed || counter (where || means concatenate; this is done while applying byte swapping)
*/
static uint8_t* mgf1(const void* seed, const unsigned long seed_length, const unsigned long outlength){
      uint8_t* r = (uint8_t*)malloc(outlength);
      if (!r){
            fprintf(stderr, "MALLOC error in mgf1 with params seed_length %lu and outlength %lu", seed_length, outlength);
            return NULL;
      }
      uint8_t* processed_seed = (uint8_t*)malloc(seed_length +4);
      memcpy(processed_seed, seed, seed_length);
      int64_t processed = outlength;
      int copy, i, j;
      int counter = 0;
      uint8_t* counterc =(uint8_t*) &counter;
      while (processed>0){
            uint8_t hash[32];
            j = seed_length;
            for (i=3; i>=0; i--){
                  processed_seed[j++]=counterc[i];
            }
            calc_sha_256(hash, processed_seed, (size_t) seed_length+4);
            copy = processed > 32 ? 32: processed;
            j = counter *32;
            for (i=0; i<copy; i++){
                  r[j++] = hash[i];    //cabsc(hash[i]);
            }
            counter++;
            processed -= copy;
      }
      free(processed_seed);
      return r;
}
static uint8_t* ill2osp(const long long* message, const unsigned long  message_size, const unsigned long num_octets){
      //test for endianess
      unsigned short testshort = 0x01;
      uint8_t* charpointer = (uint8_t*)&testshort;
      if (*charpointer == 0x01){
            if (num_octets > 7){
                  fprintf(stderr, "Invalid num_octets: %lu\n", num_octets);
                  return NULL;
            }
            int i, j, k;
            uint8_t* r = (uint8_t*)malloc(num_octets*message_size);
            if (!r){
                  fprintf(stderr, "MALLOC error in ill2osp with params message_size: %lu, num_octets: %lu\n", message_size, num_octets);
                  return NULL;
            }
            k=0;
            //reverse byte order ignoring all data beyond num_octets
            for (i=0; i<message_size; i++){
                  charpointer = (uint8_t*)&message[i];
                  for (j=num_octets-1; j>=0; j--){
                        r[k++]=charpointer[j];
                  }
            }
            return r;
      }
      else {
            fprintf(stderr, "Machine is BIG-ENDIAN\n");
            return NULL;
      }
}
static long long * osp2ill(void* message, const unsigned long message_size, const unsigned long num_octets){
      //test for endianess
      unsigned short testshort = 0x01;
      uint8_t* charpointer = (uint8_t*)&testshort;
      if (*charpointer == 0x01){
            if (message_size % num_octets != 0){
                  fprintf(stderr, "osp2ill error: Expected message size to be integer multiple of num octets.\nInstead found message_size: %lu and num_octets: %lu\n", message_size, num_octets);
                  return NULL;
            }
            int i, j, k, l;
            long long* r = (long long*)malloc(sizeof(long long)*message_size);
            k=0;
            charpointer = (uint8_t*) r;
            uint8_t* messagepointer;
            //reverse byte order adding zero padding for bytes not represented by num_octets
            for (i=0; i<message_size/num_octets; i++){
                  messagepointer = &message[i*num_octets];
                  l = num_octets;
                  for (j=7; j >= 0; j--){
                        if (j <= 7 - num_octets)
                              charpointer[k++] = 0x00;
                              else
                              charpointer[k++] = messagepointer[--l];
                  }
            }
            return r;
      }
      else {
            fprintf(stderr, "Machine is BIG-ENDIAN\n");
            return NULL;
      }
}
static unsigned long getnumoctets(void* pub){
      struct public_key_class* key = (struct public_key_class*) pub;
      //one octet can store 256 values, so num_octets must be log_256(modulus)
      long long modulus = key->modulus;
      unsigned long num_octets = 0;
      while (modulus>0){
            modulus /=256;
            num_octets++;
      }
      return num_octets;
}
/*
Explanation of the encoding scheme used in the OAEP functions.

|| refers to concatenation; ^ is bitwise XOR

M is the message (length m), A is a string of length k1 consisting of zeros, and B is a random string of length k2

MGF1 is a function, declared above, that takes in a string and produces a random but reproduceable string of a certain length

M = M || A
M = M^MGF1(B, m+k1)
B = B^MGF1(M, k2)
M = M || B

First, the string of zeros is added to M.
Then, M is xor'd with a string generated from B.
Then, B is xor'd with a string generated from resultant A.
Then, B is concatenated to A.

We then proceed to encrypt / decrypt M as usual using RSA. The security benefit stems from the fact that an attacker has to decrypt
all of M to reverse the process described above (since any small change at the input of MGF1 will produce a completely different output).


*/
void* rsa_oaep_encrypt(const void* message, unsigned long *message_size, const struct public_key_class *pub, const unsigned long k1, const unsigned long k2){
      //create random string of length k2
      char nonce[32];
      memset(nonce, '\0', 32);
      snprintf(nonce, 32, "%d", rand());
      uint8_t* padding = mgf1((void*)nonce, strlen(nonce), k2);
      //expand padding to length k+1 message_size
      uint8_t* rand_padding = mgf1(padding, k2, *message_size + k1);
      //place message in new buffer and pad with zeros
      uint8_t* r = (uint8_t*)malloc(*message_size + k1 +k2);
      memset(r, '0', *message_size + k1);
      memcpy(r, message, *message_size);
      //xor message (+padding) with random string
      int i, mylength = *message_size + k1;
      for (i=0; i<mylength; i++){
            r[i] ^= rand_padding[i];
      }
      //compress scrambled message to k2 length and xor padding with that scramble
      uint8_t* last_scramble = mgf1(r, mylength, k2);
      for (i=0; i<k2; i++){
            padding[i]^= last_scramble[i];
      }
      int j = *message_size + k1;
      for (i=0; i<k2; i++){
            r[j++]=padding[i];
      }
      *message_size = *message_size + k1 + k2;
      long long *encrypted = rsa_encrypt((void*)r, *message_size, pub);
      //this gets the minimum number of octets required to represent every encoded number
      unsigned long num_octets = getnumoctets((void*)pub);
      //this produces a new buffer with the compressed, scramble encrypted buffer
      uint8_t* osp = ill2osp(encrypted, *message_size, num_octets);
      *message_size = (*message_size) * num_octets;
      free(last_scramble);
      free(rand_padding);
      free(padding);
      free(encrypted);
      free(r);
      return (void*)osp;
}
void* rsa_oaep_decrypt(void* message, unsigned long *message_size, const struct private_key_class *priv, const unsigned long k1, const unsigned long k2){
      //get the number of octets required to represent the encrypted data and translate that data into an array of long longs (as expected by rsa_decrypt)
      unsigned long num_octets = getnumoctets((void*)priv);
      long long *encrypted = osp2ill(message, *message_size, num_octets);
      if (!encrypted)
            return NULL;
      /*encoded message has size:
      (message + k1 + k2) * num_octets = message_size
      */
      unsigned long mymessage_size = *message_size / num_octets;
      uint8_t* decrypted = rsa_decrypt(encrypted, mymessage_size*sizeof(long long), priv);
      //recover padding (the last k2 octets of the decrypted message)
      uint8_t* padding = (uint8_t*)malloc(k2);
      int i, j=mymessage_size-k2;
      for (i=0; i<k2; i++){
            padding[i]=decrypted[j++];
      }
      //padding is xored with mgf1(padded message)
      uint8_t* last_scramble = mgf1(decrypted, mymessage_size-k2, k2);
      for (i=0; i<k2; i++){
            padding[i]^=last_scramble[i];
      }
      //message is xored with mgf1(padding)
      uint8_t* rand_padding = mgf1(padding, k2, mymessage_size-k2);
      for (i=0; i<mymessage_size-k2; i++){
            decrypted[i]^=rand_padding[i];
      }
      //padding is removed from message and null terminator is added so message can be read as string
      *message_size = mymessage_size - k1 -k2;
      decrypted[*message_size] = '\0';
      free(rand_padding);
      free(last_scramble);
      free(padding);
      free(encrypted);
      return (void*)decrypted;
}
// This should totally be in the math library.
static long long gcd(long long a, long long b)
{
  long long c;
  while ( a != 0 ) {
    c = a; a = b%a;  b = c;
  }
  return b;
}


static long long ExtEuclid(long long a, long long b)
{
 int64_t x = 0, y = 1, u = 1, v = 0, gcd = b, m, n, q, r;
 while (a!=0) {
   q = gcd/a; r = gcd % a;
   m = x-u*q; n = y-v*q;
   gcd = a; a = r; x = u; y = v; u = m; v = n;
   }
   return y;
}
static long long modmult(long long a,long long b,long long mod);
static long long rsa_mymodExp(long long b, long long e, long long m)
{
      if (b<0)
            b = -b;
      long long product;
      product = 1;
      b = b % m;
      while ( e > 0){
            if (e & 1){
                  product = modmult(product, b, m);
            }
            b = modmult(b, b, m);
            e >>= 1;
      }
      return product;
}
static long long modmult(long long a,long long b,long long mod)
{
    if (b<0)
      b = -b;
    if (a == 0 || b < mod / a)
        return (a*b)%mod;
    long long sum;
    sum = 0;
    while(b>0)
    {
        if(b&1)
            sum = (sum + a) % mod;
        a = (2*a) % mod;
        b>>=1;
    }
    return sum;
}
/// @deprecated: this is unsafe
/*
long long rsa_modExp(long long b, long long e, long long m)
{
  if (b < 0 || e < 0 || m <= 0){
    exit(1);
  }
  b = b % m;
  if(e == 0) return 1;
  if(e == 1) return b;
  if( e % 2 == 0){
    return ( rsa_modExp(b * b % m, e/2, m) % m );
  }
  if( e % 2 == 1){
    return ( b * rsa_modExp(b, (e-1), m) % m );
  }

}
*/
// Calling this function will generate a public and private key and store them in the pointers
// it is given.
void rsa_gen_keys(struct public_key_class *pub, struct private_key_class *priv, const char *PRIME_SOURCE_FILE)
{
  FILE *primes_list;
  if(!(primes_list = fopen(PRIME_SOURCE_FILE, "r"))){
    fprintf(stderr, "Problem reading %s\n", PRIME_SOURCE_FILE);
    exit(1);
  }

  // count number of primes in the list
  long long prime_count = 0;
  do{
    int bytes_read = fread(buffer,1,sizeof(buffer)-1, primes_list);
    buffer[bytes_read] = '\0';
    for (i=0 ; buffer[i]; i++){
      if (buffer[i] == '\n'){
	prime_count++;
      }
    }
  }
  while(feof(primes_list) == 0);


  // choose random primes from the list, store them as p,q

  long long p = 0;
  long long q = 0;

  long long e = (2 << 16) + 1;//powl(2, 8) + 1;
  long long d = 0;
  char prime_buffer[MAX_DIGITS];
  long long max = 0;
  long long phi_max = 0;

  srand(time(NULL));

  do{
    // a and b are the positions of p and q in the list
    int a =  (double)rand() * (prime_count+1) / (RAND_MAX+1.0);
    int b =  (double)rand() * (prime_count+1) / (RAND_MAX+1.0);

    // here we find the prime at position a, store it as p
    rewind(primes_list);
    for(i=0; i < a + 1; i++){
    //  for(j=0; j < MAX_DIGITS; j++){
    //	prime_buffer[j] = 0;
    //  }
      fgets(prime_buffer,sizeof(prime_buffer)-1, primes_list);
    }
    p = atol(prime_buffer);

    // here we find the prime at position b, store it as q
    rewind(primes_list);
    for(i=0; i < b + 1; i++){
      for(j=0; j < MAX_DIGITS; j++){
	prime_buffer[j] = 0;
      }
      fgets(prime_buffer,sizeof(prime_buffer)-1, primes_list);
    }
    q = atol(prime_buffer);

    max = p*q;
    phi_max = (p-1)*(q-1);
  }
  while(!(p && q) || (p == q) || (gcd(phi_max, e) != 1));

  // Next, we need to choose a,b, so that a*max+b*e = gcd(max,e). We actually only need b
  // here, and in keeping with the usual notation of RSA we'll call it d. We'd also like
  // to make sure we get a representation of d as positive, hence the while loop.
  d = ExtEuclid(phi_max,e);
  while(d < 0){
    d = d+phi_max;
}

  //printf("primes are %lld and %lld\n",(long long)p, (long long )q);
  // We now store the public / private keys in the appropriate structs
  pub->modulus = max;
  pub->exponent = e;

  priv->modulus = max;
  priv->exponent = d;
}


long long *rsa_encrypt(const void *message, const unsigned long message_size,
                     const struct public_key_class *pub)
{
  long long *encrypted = malloc(sizeof(long long)*message_size);
  if(encrypted == NULL){
    fprintf(stderr,
     "Error: Heap allocation failed.\n");
    return NULL;
  }
  unsigned long i = 0;
  unsigned char *message_converted = (unsigned char *)message;
  for(i=0; i < message_size; i++){
    /*if (message[i]>=pub->modulus || message[i] < 0){
          printf("message out of range\n");
   }*/
    if ((encrypted[i] = rsa_modExp(message_converted[i], pub->exponent, pub->modulus)) == -1)
    return NULL;
  }
  return encrypted;
}

uint8_t *rsa_decrypt(const long long *message,
                  const unsigned long message_size,
                  const struct private_key_class *priv)
{
  if(message_size % sizeof(long long) != 0){
    fprintf(stderr,
     "Error: message_size is not divisible by %d, so cannot be output of rsa_encrypt\n", (int)sizeof(long long));
     return NULL;
  }
  // We allocate space for the output as a char array
  uint8_t *decrypted = malloc(message_size/sizeof(long long));
  if(decrypted == NULL){
    fprintf(stderr,
     "Error: Heap allocation failed.\n");
    return NULL;
  }
  // Now we go through each 8-byte chunk and decrypt it.
  long long i = 0;
  for(i=0; i < message_size/8; i++){
        decrypted[i] = rsa_modExp(message[i], priv->exponent, priv->modulus);
  }
  // The result should be a number in the char range, which gives back the original byte.
  return decrypted;
}
