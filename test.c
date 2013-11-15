#include <stdio.h>
#include "rsa.h"

int main(int argc, char **argv)
{
  struct public_key_class pub[1];
  struct private_key_class priv[1];
  rsa_gen_keys(pub, priv, PRIME_SOURCE_FILE);
  printf("Private Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)priv->modulus, (long long) priv->exponent);
  printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->modulus, (long long) pub->exponent);
  char message[] = "abc123";
 
  int64_t *encrypted = rsa_encrypt(message, sizeof(message), pub);
  char *decrypted = rsa_decrypt(encrypted, sizeof(encrypted), priv);
  
  int i;
  for(i=0; i < sizeof(message); i++){
    printf("%d\n", decrypted[i]);
  }  
  printf("\n");
  return 0;
}
