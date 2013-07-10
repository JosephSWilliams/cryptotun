#define USAGE "Usage: pubkey /path/to/seckey\n"
#include <nacl/crypto_scalarmult_curve25519.h>
#include <string.h>
#include "base16.h"

int main(int argc, char **argv) {
 if (argc>1) {
  unsigned char pk[64];
  unsigned char sk[32];
  int n;
  if (((n=open(argv[1],0))<0)||(read(n,sk,32)<32)||(close(n)<0)) return 64;
  crypto_scalarmult_curve25519_base(pk,sk);
  memcpy(sk,pk,32);
  if (base16_encode(pk,sk,32)!=64) return 255;
  if (write(1,"pubkey: ",8)!=8) return 255;
  if (write(1,pk,64)!=64) return 255;
  if (write(1,"\n",1)-1) return 255;
  return 0;
 }
 write(2,USAGE,strlen(USAGE));
 return 64;
}
