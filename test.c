#include <stdio.h>
#include "rsa.h"
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  struct public_key_class pub[1];
  struct private_key_class priv[1];
  //rsa_gen_keys(pub, priv, PRIME_SOURCE_FILE);

  pub->modulus = priv->modulus = 91;
  pub->exponent = 5;
  priv->exponent = 29;


  printf("Private Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)priv->modulus, (long long) priv->exponent);
  printf("Public Key:\n Modulus: %lld\n Exponent: %lld\n", (long long)pub->modulus, (long long) pub->exponent);
//  char message[] = "123abc";
  char message[] = "CLOUD";
 
  long long *encrypted = rsa_encrypt(message, sizeof(message), pub);
  char *decrypted = rsa_decrypt(encrypted, 8*sizeof(message), priv);
  printf("testing\n");
  printf("%lld\n", (long long)rsa_modExp(67, 5, 91));
  
  int i;
  printf("Original:\n");
  for(i=0; i < strlen(message); i++){
    printf("%lld\n", (long long)message[i]);
  }  
  printf("Encrypted:\n");
  for(i=0; i < strlen(message); i++){
    printf("%lld\n", (long long)encrypted[i]);
  }  
  printf("Decrypted:\n");
  for(i=0; i < strlen(message); i++){
    printf("%lld\n", (long long)decrypted[i]);
  }  
  printf("\n");
  free(encrypted);
  free(decrypted);
  return 0;
}
