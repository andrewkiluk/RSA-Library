#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>

char buffer[1024];
const int MAX_DIGITS = 50;
int i,j = 0;

struct public_key_class{
  int64_t modulus;
  int64_t exponent;
};

struct private_key_class{
  int64_t modulus;
  int64_t exponent;
};


// This should totally be in the math library.
int64_t gcd(int64_t a, int64_t b)
{
  int64_t c;
  while ( a != 0 ) {
    c = a; a = b%a;  b = c;
  }
  return b;
}

// This computes the multiplicative inverse of a modulo b.
/*int mod_inv(int a, int b)
{
  int64_t b0 = b, t, q;
  int64_t x0 = 0, x1 = 1;
  if (b == 1) return 1;
  while (a > 1) {
    	q = a / b;
		t = b, b = a % b, a = t;
			t = x0, x0 = x1 - q * x0, x1 = t;
  }
  if (x1 < 0) x1 += b0;
  return x1;
}*/

int64_t ExtEuclid(int64_t a, int64_t b)
{
 int64_t x = 0, y = 1, u = 1, v = 0, gcd = b, m, n, q, r;
 while (a!=0) {
   q = gcd/a; r = gcd % a;
   m = x-u*q; n = y-v*q;
   gcd = a; a = r; x = u; y = v; u = m; v = n;
   }
   printf("(%ld, %ld)\n", (long)x,(long)y);
   return y;
}



// Calling this function will generate a public and private key and store them in the pointers
// it is given. 
void gen_keys(struct public_key_class *pub, struct private_key_class *priv, char *PRIME_SOURCE_FILE)
{
  FILE *primes_list;
  if(!(primes_list = fopen(PRIME_SOURCE_FILE, "r"))){
    fprintf(stderr, "Problem reading %s\n", PRIME_SOURCE_FILE);
    exit(1);
  }

  // count number of primes in the list
  int64_t prime_count = 0;
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
  srand(time(NULL));

  int64_t p = 0;
  int64_t q = 0;

  int64_t e = powl(2, 8) + 1;
  int64_t d = 0;
  char prime_buffer[MAX_DIGITS];
  int64_t max = 0;
  int64_t phi_max = 0;
  do{
    // a and b are the positions of p and q in the list
    int a =  (double)rand() * (prime_count+1) / (RAND_MAX+1.0);
    int b =  (double)rand() * (prime_count+1) / (RAND_MAX+1.0);
    
    // here we find the prime at position a, store it as p
    rewind(primes_list);
    for(i=0; i < a + 1; i++){
      for(j=0; j < MAX_DIGITS; j++){
	prime_buffer[j] = 0;
      }
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
  while(gcd(phi_max, e) != 1);
 
  // Next, we need to choose a,b, so that a*max+b*e = gcd(max,e). We actually only need b
  // here, and in keeping with the usual notation of RSA we'll call it d.
  d = ExtEuclid(phi_max,e);

  printf("%lld\n%lld\n", (long long)ExtEuclid(3,5), (long long)ExtEuclid(3, 7));
  printf("d               : %lld\ne               : %lld\nphi(max)        : %lld\nd*e mod phi(max): %lld\n",
    (long long)d,(long long)e, (long long)phi_max, (long long)((d*e) % phi_max));

}
  
