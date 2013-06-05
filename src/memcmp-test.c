#include <stdlib.h>
#include <string.h>
#include <taia.h>

main() {

 unsigned char taia0[16]={0};
 unsigned char taia1[16]={0};

 taia_now(taia0);
 taia_now(taia1);
 taia_pack(taia0,taia0);
 taia_pack(taia1,taia1);

 exit(
  (memcmp(taia0,taia0,16))
 |(memcmp(taia1,taia1,16))
 |(memcmp(taia0,taia1,16)>0)
 |(memcmp(taia1,taia0,16)<1));

}
