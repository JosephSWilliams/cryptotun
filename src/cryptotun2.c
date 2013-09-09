#include <nacl/crypto_scalarmult_curve25519.h>
#include <nacl/crypto_verify_32.h>
#include <nacl/crypto_verify_16.h>
#include <nacl/crypto_box.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <strings.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include "base16.h"
#include <errno.h>
#include <taia.h>
#include <poll.h>
#include <pwd.h>

#define USAGE "\
cryptotun2: usage:\n\
cryptotun2:  local addr\n\
cryptotun2:  local port\n\
cryptotun2:  remote addr\n\
cryptotun2:  remote port\n\
cryptotun2:  path/seckey\n\
cryptotun2:  remote pubkey\n\
cryptotun2:  ifr_name\n\
cryptotun2:  path/root\n\
"

int envnum(char *a) { return (getenv(a)) ? atoi(getenv(a)) : 0; }

main(int argc, char **argv) {

if (argc<8) exit(write(2,USAGE,strlen(USAGE))&255);

struct timeval now;
struct sockaddr_in sock4={0};
struct sockaddr_in6 sock6={0};
struct sockaddr_storage socka={0};
struct sockaddr_storage sockb={0};
socklen_t sockaddr_len=sizeof(socka);
struct sockaddr_storage recvaddr={0};
struct timezone *utc=(struct timezone*)0;

unsigned char taia0[16];
unsigned char taia1[16];
unsigned char longtermsk[32];
unsigned char longtermpk[32];
unsigned char shorttermpk[32];
unsigned char shorttermsk[32];
unsigned char buffer16[2048]={0};
unsigned char buffer32[2048]={0};
unsigned char localnonce[24]={0};
unsigned char remotenonce[24]={0};
unsigned char taiacache[2048]={0};
unsigned char longtermsharedk[32];
unsigned char remotelongtermpk[32];
unsigned char remoteshorttermpk[32];
unsigned char shorttermsharedk0[32];
unsigned char shorttermsharedk1[32];

int i;
int n;
int tunfd;
int sockfd;
int updatetaia=0;
int devurandomfd;
int usepadding=(!envnum("USE_PADDING")) ? 0 : 1;
int remotefloat=(!envnum("REMOTE_FLOAT")) ? 0 : 1;
int maxpadlen=(!(n=envnum("MAX_PAD_LEN"))) ? 255 : n&255;

void zeroexit(int signum) {
 bzero(&buffer16,2048);
 bzero(&buffer32,2048);
 bzero(&longtermsk,32);
 bzero(&shorttermsk,32);
 bzero(&longtermsharedk,32);
 bzero(&shorttermsharedk0,32);
 bzero(&shorttermsharedk1,32);
 exit(signum);
}
signal(SIGINT,zeroexit);
signal(SIGHUP,zeroexit);
signal(SIGTERM,zeroexit);

if (!inet_pton(AF_INET,argv[1],&sock4.sin_addr)) {
 if ((sockfd=socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP))<0) exit(128+errno&255);
 if (!inet_pton(AF_INET6,argv[1],&sock6.sin6_addr)) exit(128+errno&255);
 if (!(sock6.sin6_port=htons(atoi(argv[2])))) exit(128+errno&255);
 sock6.sin6_family=AF_INET6;
 memcpy(&socka,&sock6,sizeof(sock6));
} else {
 if ((sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))<0) exit(128+errno&255);
 if (!(sock4.sin_port=htons(atoi(argv[2])))) exit(128+errno&255);
 sock4.sin_family=AF_INET;
 memcpy(&socka,&sock4,sizeof(sock4));
}
if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(int[]){1},sizeof(int))) exit(128+errno&255);
if (bind(sockfd,(struct sockaddr*)&socka,sizeof(socka))<0) exit(128+errno&255);

if (!inet_pton(AF_INET,argv[3],&sock4.sin_addr)) {
 if (!inet_pton(AF_INET6,argv[3],&sock6.sin6_addr)) exit(128+errno&255);
 if (!(sock6.sin6_port=htons(atoi(argv[4])))) exit(128+errno&255);
 sock6.sin6_family=AF_INET6;
 memcpy(&recvaddr,&sock6,sizeof(sock6));
} else {
 if (!(sock4.sin_port=htons(atoi(argv[4])))) exit(128+errno&255);
 sock4.sin_family=AF_INET;
 memcpy(&recvaddr,&sock4,sizeof(sock4));
}
memcpy(&socka,&recvaddr,sockaddr_len);
memcpy(&sockb,&recvaddr,sockaddr_len);

if (((n=open(argv[5],0))<0)||(read(n,longtermsk,32)!=32)||(close(n)<0)) zeroexit(128+errno&255);
if ((strlen(argv[6])!=64)||(base16_decode(remotelongtermpk,argv[6],64)!=32)) zeroexit(128+errno&255);
if (crypto_box_beforenm(longtermsharedk,remotelongtermpk,longtermsk)) zeroexit(128+errno&255);
crypto_scalarmult_curve25519_base(longtermpk,longtermsk);
if (!crypto_verify_32(longtermpk,remotelongtermpk)) zeroexit(128+errno&255);
memcpy(remotenonce+16,remotelongtermpk,8);

if ((!strlen(argv[7]))||(strlen(argv[7])>=16)) zeroexit(128+errno&255);
#ifdef linux
 #include <linux/if_tun.h>
 #include <linux/if_ether.h>
 tunfd=open("/dev/net/tun",O_RDWR);
 if (tunfd<0) tunfd = open("/dev/tun",O_RDWR); /* #ifdef android ? */
 if (tunfd<0) zeroexit(128+errno&255);
 struct ifreq ifr;
 bzero(&ifr,sizeof(ifr));
 strcpy(ifr.ifr_name,argv[7]);
 ifr.ifr_flags=(!envnum("IFF_TAP")) ? IFF_TUN : IFF_TAP;
 ifr.ifr_flags|=(!envnum("USE_PI")) ? IFF_NO_PI : 0;
 if (ioctl(tunfd,TUNSETIFF,(void*)&ifr)) zeroexit(128+errno&255);
#else
 #include <net/if_tun.h>
 char ifr_name[5+16]={0};
 memcpy(&ifr_name,"/dev/",5);
 memcpy(&ifr_name[5],argv[7],strlen(argv[7]));
 if ((tunfd=open(ifr_name,O_RDWR))<0) zeroexit(128+errno&255);
 int ifr_flag=IFF_POINTOPOINT|IFF_MULTICAST;
 if (ioctl(tunfd,TUNSIFMODE,&ifr_flag)) zeroexit(128+errno&255);
 ifr_flag=(!envnum("USE_PI")) ? 0 : 1;
 if (ioctl(tunfd,TUNSLMODE,&ifr_flag)) zeroexit(128+errno&255);
 if (ioctl(tunfd,TUNSIFHEAD,&ifr_flag)) zeroexit(128+errno&255);
#endif

if ((devurandomfd=open("/dev/urandom",O_RDONLY))<0) zeroexit(128+errno&255);
if (argc>8) {
 struct passwd *cryptotun = getpwnam("cryptotun");
 if ((!cryptotun)||(chdir(argv[8]))||((chroot(argv[8]))||(setgid(cryptotun->pw_gid))||(setuid(cryptotun->pw_uid)))) zeroexit(128+errno&255);
}

struct pollfd fds[2];
fds[0].events=POLLIN;
fds[1].events=POLLIN;
fds[0].fd=sockfd;
fds[1].fd=tunfd;

taia_now(taia0);
taia_pack(taia1,taia0);
taia_pack(taia0,taia0);

gettimeofday(&now,utc);
int mobile=0;
int jitter=now.tv_sec;
int update=now.tv_sec-16;
int expiry=now.tv_sec-512;

while (1) {

gettimeofday(&now,utc);

if (now.tv_sec-expiry>=512) {
 if (read(devurandomfd,shorttermsk,32)<32) zeroexit(128+errno&255);
 crypto_scalarmult_curve25519_base(shorttermpk,shorttermsk);
 if (crypto_box_beforenm(shorttermsharedk0,remoteshorttermpk,shorttermsk)) zeroexit(128+errno&255);
 expiry=now.tv_sec;
 goto sendupdate;
}

if (now.tv_sec-update>=16) {
sendupdate:
 memcpy(buffer32+32,shorttermpk,32);
 taia_now(localnonce);
 taia_pack(localnonce,localnonce);
 memcpy(localnonce+16,longtermpk,8);
 if (crypto_box_afternm(buffer16,buffer32,32+32,localnonce,longtermsharedk)) zeroexit(128+errno&255);
 memcpy(buffer32+32,localnonce,16);
 memcpy(buffer32+32+16,buffer16+16,32+16);
 sendto(sockfd,buffer32+32,16+32+16,0,(struct sockaddr*)&socka,sockaddr_len);
 if ((remotefloat)&&(mobile)) sendto(sockfd,buffer32+32,16+32+16,0,(struct sockaddr*)&sockb,sockaddr_len);
 update=now.tv_sec;
 goto devread;
}

devwrite:
if (fds[0].revents) {
 if ((n=recvfrom(sockfd,buffer16+16,16+32+1500+255+1+16+16,0,(struct sockaddr*)&recvaddr,&sockaddr_len))<0) zeroexit(128+errno&255);
 if (n<16+32+16) goto devread;

 memcpy(remotenonce,buffer16+16,16);
 for (i=0;i<16;++i) {
  if (remotenonce[i]>taia0[i]) break;
  if (remotenonce[i]<taia0[i]) goto devread;
 }
 for (i=2048-16;i>-16;i-=16) if (!crypto_verify_16(taiacache+i,remotenonce)) goto devread;

 memcpy(buffer16+16,buffer16+16+16,-16+n);
 if (crypto_box_open_afternm(buffer32,buffer16,16-16+n,remotenonce,longtermsharedk)<0) goto devread;
 if (remotefloat) {
  if ((memcmp(&socka,&recvaddr,sockaddr_len))&&(memcmp(&sockb,&recvaddr,sockaddr_len))) {
    memcpy(&socka,&recvaddr,sockaddr_len);
    mobile=now.tv_sec;
  } else if ((mobile)&&(now.tv_sec-mobile>=64)) {
   memcpy(&sockb,&socka,sockaddr_len);
   mobile=0;
  }
 }
 if (updatetaia==32) {
  memcpy(taia0,taia1,16);
  taia_now(taia1);
  taia_pack(taia1,taia1);
  updatetaia=0;
 }

 for (i=0;i<16;++i) {
  if (taiacache[i]<taia0[i]) break;
  if (taiacache[i]>taia0[i]) { memcpy(taia0,taiacache,16); break; }
 }
 memcpy(taiacache,taiacache+16,2048-16);
 memcpy(taiacache+2048-16,remotenonce,16);
 ++updatetaia;

 if (crypto_verify_32(remoteshorttermpk,buffer32+32)) {
  jitter=now.tv_sec;
  memcpy(remoteshorttermpk,buffer32+32,32);
  if (crypto_box_beforenm(shorttermsharedk0,remoteshorttermpk,shorttermsk)<0) zeroexit(128+errno&255);
 } else if ((jitter)&&(now.tv_sec-jitter>=64)) {
  memcpy(shorttermsharedk1,shorttermsharedk0,32);
  jitter=0;
 }

 if (n<16+32+16+16) goto devread;
 memcpy(buffer16+16,buffer32+32+32,-16-32+n-16);
 if (crypto_box_open_afternm(buffer32,buffer16,16-16-32+n-16,remotenonce,shorttermsharedk0)<0) {
  jitter=now.tv_sec;
  bzero(&remoteshorttermpk,32);
  memcpy(shorttermsharedk0,shorttermsharedk1,32);
  if (crypto_box_open_afternm(buffer32,buffer16,16-16-32+n-16,remotenonce,shorttermsharedk1)<0) goto sendupdate;
  if (usepadding) n-=buffer32[32-16-32+n-16-16-1]+1;
  if ((-16-32+n-16-16>0)&&(write(tunfd,buffer32+32,-16-32+n-16-16)<0)) zeroexit(128+errno&255);
  goto sendupdate;
 }

 if (usepadding) n-=buffer32[32-16-32+n-16-16-1]+1;
 if ((-16-32+n-16-16>0)&&(write(tunfd,buffer32+32,-16-32+n-16-16)<0)) zeroexit(128+errno&255);
 update=now.tv_sec;
}

devread:
if (fds[1].revents) {
 if ((n=read(tunfd,buffer32+32,1500))<0) zeroexit(128+errno&255);
 taia_now(localnonce);
 taia_pack(localnonce,localnonce);
 memcpy(localnonce+16,longtermpk,8);
 if (usepadding) {
  i=maxpadlen-n%maxpadlen;
  if (read(devurandomfd,buffer32+32+n,i)<i) zeroexit(128+errno&255);
  buffer32[32+n+i]=i;
  n+=i+1;
 }
 if (crypto_box_afternm(buffer16,buffer32,32+n,localnonce,shorttermsharedk0)<0) zeroexit(128+errno&255);
 memcpy(buffer32+32,shorttermpk,32);
 memcpy(buffer32+32+32,buffer16+16,n+16);
 if (crypto_box_afternm(buffer16,buffer32,32+32+n+16,localnonce,longtermsharedk)<0) zeroexit(128+errno&255);
 memcpy(buffer32+32,localnonce,16);
 memcpy(buffer32+32+16,buffer16+16,32+n+16+16);
 if (sendto(sockfd,buffer32+32,16+32+n+16+16,0,(struct sockaddr*)&socka,sockaddr_len)==16+32+n+16+16) update=now.tv_sec;
 if ((remotefloat)&&(mobile)&&(sendto(sockfd,buffer32+32,16+32+n+16+16,0,(struct sockaddr*)&sockb,sockaddr_len)==16+32+n+16+16)) update=now.tv_sec;
}

poll(fds,2,16384);
}}
