#include <nacl/randombytes.h>
#include <nacl/crypto_box.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <stdio.h>
#include <taia.h>
#include <poll.h>

#ifdef linux
  #include <linux/if_ether.h>
  #include <linux/if_tun.h>
#else
  #include <net/if_tun.h>
#endif

#define USAGE "\
cryptotun: usage:\n\
cryptotun:   local addr\n\
cryptotun:   local port\n\
cryptotun:   remote addr\n\
cryptotun:   remote port\n\
cryptotun:   path/seckey\n\
cryptotun:   pubkey\n\
cryptotun:   ifr_name\n\
"

main(int argc, char **argv)
{

  if (argc<8)
  {
    fprintf(stderr,USAGE);
    exit(64);
  }

  int i, l, n=1;
  struct sockaddr_in sock, remoteaddr, recvaddr;
  socklen_t recvaddr_len = sizeof(struct sockaddr_in);

  if (socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)!=3)
  {
    fprintf(stderr,"cryptotun: fatal error: failed socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP) != fd3\n");
    exit(64);
  }

  if (setsockopt(3,SOL_SOCKET,SO_REUSEADDR,&n,sizeof(n))<0)
  {
    fprintf(stderr,"cryptotun: fatal error: failed setsockopt(3,SOL_SOCKET,SO_REUSEADDR,&n,sizeof(n))\n");
    exit(64);
  }

  memset(&sock,0,sizeof(sock));
  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = inet_addr(argv[1]);
  sock.sin_port = htons(atoi(argv[2]));

  if (bind(3,(struct sockaddr*)&sock,sizeof(sock))<0)
  {
    fprintf(stderr,"cryptotun: fatal error: failed bind(3,(struct sockaddr*)&sock,sizeof(sock))\n");
    exit(64);
  }

  memset(&remoteaddr,0,sizeof(remoteaddr));
  remoteaddr.sin_family = AF_INET;
  remoteaddr.sin_addr.s_addr = inet_addr(argv[3]);
  remoteaddr.sin_port = htons(atoi(argv[4]));

  unsigned char nonce[24];
  unsigned char longtermsk[32];
  unsigned char shorttermpk[32];
  unsigned char shorttermsk[32];
  unsigned char longtermsharedk[32];
  unsigned char remotelongtermpk[32];
  unsigned char remoteshorttermpk[32];
  unsigned char shorttermsharedk0[32];
  unsigned char shorttermsharedk1[32];

  struct timeval now;
  struct timezone *utc = (struct timezone *)0;
  gettimeofday(&now,utc);
  int sessionexpiry = now.tv_sec - 512;
  int update = now.tv_sec - 16;

  int updatetaia = 0;
  unsigned char taia[16];
  unsigned char taiacache[2048] = {0};
  taia_now(taia); taia_pack(taia,taia);

  unsigned char buffer0[2048];
  unsigned char buffer1[2048];

  void zeroexit(int signum)
  {
    memset(buffer0,0,2048); memset(buffer1,0,2048);
    memset(longtermsk,0,32); memset(shorttermsk,0,32);
    memset(longtermsharedk,0,32); memset(shorttermsharedk0,0,32); memset(shorttermsharedk1,0,32);
    exit(signum);
  } signal(SIGINT,zeroexit); signal(SIGHUP,zeroexit); signal(SIGTERM,zeroexit);

  if ((open(argv[5],0)!=4)||(read(4,longtermsk,32)<32))
  {
    fprintf(stderr,"cryptotun: fatal error: failed read(4,%s,32)\n",argv[5]);
    zeroexit(64);
  } close(4);

  if (strlen(argv[6])<64)
  {
    fprintf(stderr,"cryptotun: fatal error: invalid remotelongtermpk\n");
    zeroexit(64);
  }

  l=0; for (i=0;i<64;++i)
  {
    if (((unsigned char)argv[6][i]>47)&&((unsigned char)argv[6][i]<58)) remotelongtermpk[l] = (unsigned char)argv[6][i] - 48 << 4;
    else { if (((unsigned char)argv[6][i]>64)&&((unsigned char)argv[6][i]<71)) remotelongtermpk[l] = (unsigned char)argv[6][i] - 55 << 4;
    else { if (((unsigned char)argv[6][i]>96)&&((unsigned char)argv[6][i]<103)) remotelongtermpk[l] = (unsigned char)argv[6][i] - 87 << 4;
    else { fprintf(stderr,"cryptotun: fatal error: invalid remotelongtermpk\n"); zeroexit(64);
    }}} ++i;
    if (((unsigned char)argv[6][i]>47)&&((unsigned char)argv[6][i]<58)) remotelongtermpk[l] += (unsigned char)argv[6][i] - 48;
    else { if (((unsigned char)argv[6][i]>64)&&((unsigned char)argv[6][i]<71)) remotelongtermpk[l] += (unsigned char)argv[6][i] - 55;
    else { if (((unsigned char)argv[6][i]>96)&&((unsigned char)argv[6][i]<103)) remotelongtermpk[l] += (unsigned char)argv[6][i] - 87;
    else { fprintf(stderr,"cryptotun: fatal error: invalid remotelongtermpk\n"); zeroexit(64);
    }}} ++l;
  }

  if (crypto_box_beforenm(longtermsharedk,remotelongtermpk,longtermsk)<0)
  {
    fprintf(stderr,"cryptotun: fatal error: failed crypto_box_beforenm(longtermsharedk,remotelongtermpk,longtermsk)\n");
    zeroexit(255);
  }

  if ((!strlen(argv[7]))||(strlen(argv[7])>=16))
  {
    fprintf(stderr,"cryptotun: fatal error: invalid ifr_name %s\n",argv[7]);
    zeroexit(64);
  }

  #ifdef linux

    if (open("/dev/net/tun",O_RDWR)!=4)
    {
      fprintf(stderr,"cryptotun: fatal error: open(\"/dev/net/tun\",O_RDWR) != fd4\n");
      zeroexit(255);
    }

    struct ifreq ifr;
    memset(&ifr,0,sizeof(ifr));
    strcpy(ifr.ifr_name,argv[7]);

    if (!getenv("IFF_TAP"))
    {
      ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    } else ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    if (ioctl(4,TUNSETIFF,(void *)&ifr)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(4,TUNSETIFF,(void *)&ifr)\n");
      zeroexit(255);
    }

  #else

    char ifr_name[5+16]={0};
    memmove(&ifr_name,"/dev/",5);
    memmove(&ifr_name[5],argv[7],strlen(argv[7]));

    if (open(ifr_name,O_RDWR)!=4)
    {
      fprintf(stderr,"cryptotun: fatal error: open(ifr_name,O_RDWR) != fd4\n");
      zeroexit(255);
    }

    int ifr_flag = IFF_POINTOPOINT | IFF_MULTICAST;
    if (ioctl(4,TUNSIFMODE,&ifr_flag)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(4,TUNSIFMODE,&ifr_flag)\n");
      zeroexit(255);
    }

    ifr_flag = 0;
    if (ioctl(4,TUNSLMODE,&ifr_flag)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(4,TUNSLMODE,&ifr_flag)\n");
      zeroexit(255);
    }

    ifr_flag = 0;
    if (ioctl(4,TUNSIFHEAD,&ifr_flag)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(4,TUNSIFHEAD,&ifr_flag)\n");
      zeroexit(255);
    }

  #endif

  struct pollfd fds[2];
  fds[0].fd = 3;
  fds[0].events = POLLIN;
  fds[1].fd = 4;
  fds[1].events = POLLIN;

  while (1)
  {

    gettimeofday(&now,utc);

    if (now.tv_sec - sessionexpiry >= 512)
    {

      if (crypto_box_keypair(shorttermpk,shorttermsk)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: failed crypto_box_keypair(shorttermpk,shorttermsk)\n");
        zeroexit(255);
      }

      if (crypto_box_beforenm(shorttermsharedk0,remoteshorttermpk,shorttermsk)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: failed crypto_box_beforenm(shorttermsharedk0,remoteshorttermpk,shorttermsk)\n");
        zeroexit(255);
      }

      sessionexpiry = now.tv_sec;
      goto sendupdate;

    }

    if (now.tv_sec - update >= 16){ sendupdate:

      memset(buffer0,0,16);
      memset(buffer1,0,32);
      memmove(buffer1+32,shorttermpk,32);

      taia_now(nonce);
      taia_pack(nonce,nonce);
      randombytes(nonce+16,8);

      if (crypto_box_afternm(buffer0,buffer1,32+32,nonce,longtermsharedk)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: crypto_box_afternm(buffer0,buffer1,32+32,nonce,longtermsharedk)\n");
        zeroexit(255);
      }

      memmove(buffer1,nonce,24);
      memmove(buffer1+24,buffer0+16,32+16);

      if (sendto(3,buffer1,24+32+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr))<0)
      {
        fprintf(stderr,"cryptotun: error: sendto(3,buffer1,24+32+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr))\n");
      }

      update = now.tv_sec;
      goto devread;

    }

    devwrite: if (fds[0].revents)
    {

      n = recvfrom(3,buffer0,1500,0,(struct sockaddr *)&recvaddr,&recvaddr_len);

      if (n<0)
      {
        fprintf(stderr,"cryptotun: fatal error: recvfrom(3,buffer0,1500,0,(struct sockaddr *)&recvaddr,&recvaddr_len)\n");
        zeroexit(255);
      } if (n<24+32+16) goto devread;

      memmove(nonce,buffer0,24);

      l=0; for (i=0;i<16;++i)
      {
        if (nonce[i] > taia[i]){ ++l; break; }
        if (nonce[i] < taia[i]) goto devread;
      } if (!l) goto devread;

      for (i=2048-16;i>0;i-=16) if (!memcmp(taiacache+i,nonce,16)) goto devread;

      memset(buffer1,0,16);
      memmove(buffer1+16,buffer0+24,-24+n);
      memset(buffer0,0,32);

      if (crypto_box_open_afternm(buffer0,buffer1,16+-24+n,nonce,longtermsharedk)<0) goto devread;

      remoteaddr.sin_addr = recvaddr.sin_addr;
      remoteaddr.sin_port = recvaddr.sin_port;

      if (updatetaia==128)
      {

        memmove(taia,nonce,16);
        updatetaia = 0;
        goto cachetaia;

      } else { cachetaia:

        memmove(taiacache,taiacache+16,2048-16);
        memmove(taiacache+2048-16,nonce,16);
        ++updatetaia;

      }

      if (memcmp(remoteshorttermpk,buffer0+32,32))
      {

        memmove(remoteshorttermpk,buffer0+32,32);

        if (crypto_box_beforenm(shorttermsharedk0,remoteshorttermpk,shorttermsk)<0)
        {
          fprintf(stderr,"cryptotun: fatal error: failed crypto_box_beforenm(shorttermsharedk0,remoteshorttermpk,shorttermsk)\n");
          zeroexit(255);
        }

      } if (n<=24+32+24+16+16) goto devread;

      memset(buffer1,0,16);
      memmove(nonce,buffer0+32+32,24);
      memmove(buffer1+16,buffer0+32+32+24,-24-32-24+n-16);
      memset(buffer0,0,32);

      if (crypto_box_open_afternm(buffer0,buffer1,16+-24-32-24+n-16,nonce,shorttermsharedk0)<0)
      {

        if (crypto_box_open_afternm(buffer0,buffer1,16+-24-32-24+n-16,nonce,shorttermsharedk1)<0) goto sendupdate;

        if (write(4,buffer0+32,-24-32-24+n-16-16)<0)
        {
          fprintf(stderr,"cryptotun: fatal error: write(4,buffer0+32,-24-32-24+n-16-16)\n");
          zeroexit(255);
        } goto sendupdate;

      } if (memcmp(shorttermsharedk1,shorttermsharedk0,32)) memmove(shorttermsharedk1,shorttermsharedk0,32);

      if (write(4,buffer0+32,-24-32-24+n-16-16)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: write(4,buffer0+32,-24-32-24+n-16-16)\n");
        zeroexit(255);
      }

    }

    devread: if (fds[1].revents)
    {

      memset(buffer1,0,32);

      n = read(4,buffer1+32,1500);

      if (n<0)
      {
        fprintf(stderr,"cryptotun: fatal error: read(4,buffer1+32,1500)\n");
        zeroexit(255);
      }

      memset(buffer0,0,16);
      randombytes(nonce,24);

      if (crypto_box_afternm(buffer0,buffer1,32+n,nonce,shorttermsharedk0)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: crypto_box_afternm(buffer0,buffer1,32+n,nonce,shorttermsharedk0)\n");
        zeroexit(255);
      }

      memset(buffer1,0,32);
      memmove(buffer1+32,shorttermpk,32);
      memmove(buffer1+32+32,nonce,24);
      memmove(buffer1+32+32+24,buffer0+16,n+16);
      memset(buffer0,0,16);

      taia_now(nonce);
      taia_pack(nonce,nonce);
      randombytes(nonce+16,8);

      if (crypto_box_afternm(buffer0,buffer1,32+32+24+n+16,nonce,longtermsharedk)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: crypto_box_afternm(buffer0,buffer1,32+32+24+n+16,nonce,longtermsharedk)\n");
        zeroexit(255);
      }

      memmove(buffer1,nonce,24);
      memmove(buffer1+24,buffer0+16,32+24+n+16+16);

      if (sendto(3,buffer1,24+32+24+n+16+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr))<0)
      {
        fprintf(stderr,"cryptotun: error: sendto(3,buffer1,24+32+24+n+16+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr))\n");
      } else update = now.tv_sec;

    }

    poll(fds,2,16384);

  }

}
