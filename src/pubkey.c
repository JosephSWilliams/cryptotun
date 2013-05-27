#define USAGE "Usage: pubkey /path/to/seckey\n"
#include <nacl/crypto_scalarmult_curve25519.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv) {
 if (argc>1) {
  unsigned char pk[32];
  unsigned char sk[32];
  int n;
  if (((n=open(argv[1],0))<0)||(read(n,sk,32)<32)||(close(n)<0)) return 64;
  crypto_scalarmult_curve25519_base(pk,sk);
  memset(sk,0,32);
  printf("pubkey: ");
  for (n=0;n<32;++n) printf("%02x",pk[n]);
  printf("\n");
  return 0;
 }
 write(2,USAGE,strlen(USAGE));
 return 64;
}
