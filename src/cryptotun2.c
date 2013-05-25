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
#include <taia.h>
#include <poll.h>

#include "base16.h"

#define USAGE "\
cryptotun2: usage:\n\
cryptotun2:  local addr\n\
cryptotun2:  local port\n\
cryptotun2:  remote addr\n\
cryptotun2:  remote port\n\
cryptotun2:  path/seckey\n\
cryptotun2:  remote pubkey\n\
cryptotun2:  ifr_name\n\
"

main(int argc, char **argv) {

if (argc<8) exit(write(2,USAGE,strlen(USAGE))&255);

struct timeval now;
struct sockaddr_in sock;
struct sockaddr_in recvaddr;
struct sockaddr_in remoteaddr;
struct timezone *utc = (struct timezone*)0;
socklen_t recvaddr_len = sizeof(struct sockaddr_in);

unsigned char taia0[16];
unsigned char taia1[16];
unsigned char nonce[24]={0};
unsigned char longtermsk[32];
unsigned char shorttermpk[32];
unsigned char shorttermsk[32];
unsigned char buffer16[2048]={0};
unsigned char buffer32[2048]={0};
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
int updatetaia = 0;

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

bzero(&sock,sizeof(sock));
if (!inet_pton(AF_INET,argv[1],&sock.sin_addr.s_addr)) {
 if (!inet_pton(AF_INET6,argv[1],&sock.sin_addr.s_addr)) exit(64);
 else sock.sin_family = AF_INET6;
} else sock.sin_family = AF_INET;
if ((!(sock.sin_port=htons(atoi(argv[2]))))
|| ((sockfd=socket(sock.sin_family,SOCK_DGRAM,IPPROTO_UDP))<0)
|| (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(int[]){1},sizeof(int)))
|| (bind(sockfd,(struct sockaddr*)&sock,sizeof(sock))<0))
exit(64);

bzero(&remoteaddr,sizeof(remoteaddr));
if (!inet_pton(AF_INET,argv[3],&remoteaddr.sin_addr.s_addr)) {
 if (!inet_pton(AF_INET6,argv[3],&remoteaddr.sin_addr.s_addr)) exit(64);
 else remoteaddr.sin_family = AF_INET6;
} else remoteaddr.sin_family = AF_INET;
if (!(remoteaddr.sin_port=htons(atoi(argv[4])))) exit(64);

if (((n=open(argv[5],0))<0)||(read(n,longtermsk,32)!=32)) zeroexit(64);
close(n);
if ((strlen(argv[6])!=64)||(base16_decode(remotelongtermpk,argv[6],64)!=32)) zeroexit(64);
if (crypto_box_beforenm(longtermsharedk,remotelongtermpk,longtermsk)) zeroexit(255);
if ((!strlen(argv[7]))||(strlen(argv[7])>=16)) zeroexit(64);

#ifdef linux
 #include <linux/if_tun.h>
 #include <linux/if_ether.h>
 tunfd = open("/dev/net/tun",O_RDWR);
 if (tunfd<0) tunfd = open("/dev/tun",O_RDWR); /* #ifdef android ? */
 if (tunfd<0) zeroexit(255);
 struct ifreq ifr;
 bzero(&ifr,sizeof(ifr));
 strcpy(ifr.ifr_name,argv[7]);
 ifr.ifr_flags = (!getenv("IFF_TAP")) ? IFF_TUN : IFF_TAP;
 ifr.ifr_flags |= (!getenv("USE_PI")) ? IFF_NO_PI : 0;
 if (ioctl(tunfd,TUNSETIFF,(void*)&ifr)) zeroexit(255);

#else
 #include <net/if_tun.h>
 char ifr_name[5+16]={0};
 memcpy(&ifr_name,"/dev/",5);
 memcpy(&ifr_name[5],argv[7],strlen(argv[7]));
 if ((tunfd=open(ifr_name,O_RDWR))<0) zeroexit(255);
 int ifr_flag = IFF_POINTOPOINT | IFF_MULTICAST;
 if (ioctl(tunfd,TUNSIFMODE,&ifr_flag)) zeroexit(255);
 ifr_flag = (!getenv("USE_PI")) ? 0 : 1;
 if (ioctl(tunfd,TUNSLMODE,&ifr_flag)) zeroexit(255);
 if (ioctl(tunfd,TUNSIFHEAD,&ifr_flag)) zeroexit(255);

#endif

struct pollfd fds[2];
fds[0].events = POLLIN;
fds[1].events = POLLIN;
fds[0].fd = sockfd;
fds[1].fd = tunfd;

taia_now(taia0);
taia_pack(taia1,taia0);
taia_pack(taia0,taia0);

gettimeofday(&now,utc);
int jitter = now.tv_sec;
int update = now.tv_sec - 16;
int expiry = now.tv_sec - 512;

while (1) {

gettimeofday(&now,utc);

if (now.tv_sec-expiry>=512) {
 if (crypto_box_keypair(shorttermpk,shorttermsk)) zeroexit(255);
 if (crypto_box_beforenm(shorttermsharedk0,remoteshorttermpk,shorttermsk)) zeroexit(255);
 expiry = now.tv_sec;
 goto sendupdate;
}

if (now.tv_sec-update>=16) {
sendupdate:
 memcpy(buffer32+32,shorttermpk,32);
 taia_now(nonce);
 taia_pack(nonce,nonce);
 if (crypto_box_afternm(buffer16,buffer32,32+32,nonce,longtermsharedk)) zeroexit(255);
 memcpy(buffer32+32,nonce,16);
 memcpy(buffer32+32+16,buffer16+16,32+16);
 sendto(sockfd,buffer32+32,16+32+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr));
 update = now.tv_sec;
 goto devread;
}

devwrite:
if (fds[0].revents) {
 if ((n=recvfrom(sockfd,buffer16+16,1500,0,(struct sockaddr*)&recvaddr,&recvaddr_len))<0) zeroexit(255);
 if (n<16+32+16) goto devread;
 memcpy(nonce,buffer16+16,16);
 if (memcmp(nonce,taia0,16)<1) goto devread;
 for (i=2048-16;i>-16;i-=16) if (!crypto_verify_16(taiacache+i,nonce)) goto devread;
 memcpy(buffer16+16,buffer16+16+16,-16+n);
 if (crypto_box_open_afternm(buffer32,buffer16,16-16+n,nonce,longtermsharedk)<0) goto devread;

 remoteaddr.sin_addr = recvaddr.sin_addr;
 remoteaddr.sin_port = recvaddr.sin_port;

 if (updatetaia==32) {
  memcpy(taia0,taia1,16);
  taia_now(taia1);
  taia_pack(taia1,taia1);
  updatetaia = 0;
 }

 if (memcmp(taia0,taiacache,16)<0) memcpy(taia0,taiacache,16);
 memcpy(taiacache,taiacache+16,2048-16);
 memcpy(taiacache+2048-16,nonce,16);
 ++updatetaia;

 if (crypto_verify_32(remoteshorttermpk,buffer32+32)) {
  jitter = now.tv_sec;
  memcpy(remoteshorttermpk,buffer32+32,32);
  if (crypto_box_beforenm(shorttermsharedk0,remoteshorttermpk,shorttermsk)<0) zeroexit(255);
 } else if ((jitter)&&(now.tv_sec-jitter>=64)) {
  memcpy(shorttermsharedk1,shorttermsharedk0,32);
  jitter = 0;
 }

 if (n<16+32+16+16) goto devread;
 memcpy(buffer16+16,buffer32+32+32,-16-32+n-16);

 if (crypto_box_open_afternm(buffer32,buffer16,16-16-32+n-16,nonce,shorttermsharedk0)<0) {
  jitter = now.tv_sec;
  bzero(&remoteshorttermpk,32);
  memcpy(shorttermsharedk0,shorttermsharedk1,32);
  if (crypto_box_open_afternm(buffer32,buffer16,16-16-32+n-16,nonce,shorttermsharedk1)<0) goto sendupdate;
  if (write(tunfd,buffer32+32,-16-32+n-16-16)<0) zeroexit(255);
  goto sendupdate;
 }

 if (write(tunfd,buffer32+32,-16-32+n-16-16)<0) zeroexit(255);
 update = now.tv_sec;
}

devread:
if (fds[1].revents) {
 if ((n=read(tunfd,buffer32+32,1500))<0) zeroexit(255);
 taia_now(nonce);
 taia_pack(nonce,nonce);
 if (crypto_box_afternm(buffer16,buffer32,32+n,nonce,shorttermsharedk0)<0) zeroexit(255);
 memcpy(buffer32+32,shorttermpk,32);
 memcpy(buffer32+32+32,buffer16+16,n+16);
 if (crypto_box_afternm(buffer16,buffer32,32+32+n+16,nonce,longtermsharedk)<0) zeroexit(255);
 memcpy(buffer32+32,nonce,16);
 memcpy(buffer32+32+16,buffer16+16,32+n+16+16);
 if (sendto(sockfd,buffer32+32,16+32+n+16+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr))==16+32+n+16+16) update = now.tv_sec;
}

poll(fds,2,16384);

}}
