#define USAGE "Usage: pubkey /path/to/seckey\n"
#include <nacl/crypto_scalarmult_curve25519.h>
main(int argc, char **argv){
if (argc>1){
  int i;
  i = open(argv[1],0);
  if (i<0) exit(64);
  unsigned char pk[32], sk[32];
  if (read(i,sk,32)<32) exit(64);
  close(i);
  crypto_scalarmult_curve25519_base(pk,sk);
  printf("pubkey: ");
  for (i=0;i<32;++i) printf("%02x",pk[i]);
  printf("\n");
  exit(0);}
write(2,USAGE,strlen(USAGE));
exit(64);}
