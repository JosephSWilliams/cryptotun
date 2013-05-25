#include <stdlib.h>
#include <string.h>
main() {
 exit((memcmp("\0\0","\0\0",1)) | (memcmp("\1\0","\0\0",1)<1) |(memcmp("\0\0","\1\0",1)>0));
}
