#include <nacl/crypto_verify_32.h>
#include <nacl/crypto_verify_16.h>
#include <nacl/randombytes.h>
#include <nacl/crypto_box.h>
#include <sys/socket.h>
#include <netinet/in.h>
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
#include <stdio.h>
#include <errno.h>
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
cryptotun:   remote pubkey\n\
cryptotun:   ifr_name\n\
"

main(int argc, char **argv)
{

  if (argc<8)
  {
    fprintf(stderr,USAGE);
    exit(64);
  }

  int i;
  int l;
  int n = 1;
  int sockfd;
  struct sockaddr_in sock, remoteaddr, recvaddr;
  socklen_t recvaddr_len = sizeof(struct sockaddr_in);

  if ((sockfd=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP))<0)
  {
    fprintf(stderr,"cryptotun: fatal error: failed socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)\n");
    exit(64);
  }

  if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&n,sizeof(n))<0)
  {
    fprintf(stderr,"cryptotun: fatal error: failed setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&n,sizeof(n))\n");
    exit(64);
  }

  bzero(&sock,sizeof(sock));
  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = inet_addr(argv[1]);
  sock.sin_port = htons(atoi(argv[2]));

  if (bind(sockfd,(struct sockaddr*)&sock,sizeof(sock))<0)
  {
    fprintf(stderr,"cryptotun: fatal error: failed bind(sockfd,(struct sockaddr*)&sock,sizeof(sock))\n");
    exit(64);
  }

  bzero(&remoteaddr,sizeof(remoteaddr));
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
  struct timezone *utc = (struct timezone*)0;
  gettimeofday(&now,utc);
  int sessionexpiry = now.tv_sec - 512;
  int update = now.tv_sec - 16;
  int jitter = now.tv_sec;

  int updatetaia = 0;
  unsigned char taia0[16], taia1[16];
  unsigned char taiacache[2048] = {0};

  taia_now(taia0);
  taia_pack(taia0,taia0);
  memcpy(taia1,taia0,16);

  unsigned char buffer0[2048];
  unsigned char buffer1[2048];

  void zeroexit(int signum)
  {
    bzero(buffer0,2048); bzero(buffer1,2048);
    bzero(longtermsk,32); bzero(shorttermsk,32);
    bzero(longtermsharedk,32); bzero(shorttermsharedk0,32); bzero(shorttermsharedk1,32);
    exit(signum);
  } signal(SIGINT,zeroexit); signal(SIGHUP,zeroexit); signal(SIGTERM,zeroexit);

  if (((n=open(argv[5],0))<0)||(read(n,longtermsk,32)<32))
  {
    fprintf(stderr,"cryptotun: fatal error: failed read(n,%s,32)\n",argv[5]);
    zeroexit(64);
  } close(n);

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


  int tunfd;

  #ifdef linux

    if ((tunfd=open("/dev/net/tun",O_RDWR))<0)
    {

      if ((errno == ENOENT) && ((tunfd=open("/dev/tun",O_RDWR))<0))
      {
        fprintf(stderr,"cryptotun: fatal error: open(\"/dev/tun\",O_RDWR)\n");
        zeroexit(255);
      }

      fprintf(stderr,"cryptotun: fatal error: open(\"/dev/net/tun\",O_RDWR)\n");
      zeroexit(255);

    }

    struct ifreq ifr;
    bzero(&ifr,sizeof(ifr));
    strcpy(ifr.ifr_name,argv[7]);

    if (!getenv("IFF_TAP"))
    {
      ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    } else {
      ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    }

    if (ioctl(tunfd,TUNSETIFF,(void*)&ifr)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(tunfd,TUNSETIFF,(void*)&ifr)\n");
      zeroexit(255);
    }

  #else

    char ifr_name[5+16]={0};
    memcpy(&ifr_name,"/dev/",5);
    memcpy(&ifr_name[5],argv[7],strlen(argv[7]));

    if ((tunfd=open(ifr_name,O_RDWR))<0)
    {
      fprintf(stderr,"cryptotun: fatal error: open(ifr_name,O_RDWR)\n");
      zeroexit(255);
    }

    n = IFF_POINTOPOINT | IFF_MULTICAST;

    if (ioctl(tunfd,TUNSIFMODE,&n)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(tunfd,TUNSIFMODE,&n)\n");
      zeroexit(255);
    } n = 0;

    if (ioctl(tunfd,TUNSLMODE,&n)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(tunfd,TUNSLMODE,&n)\n");
      zeroexit(255);
    }

    if (ioctl(tunfd,TUNSIFHEAD,&n)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(tunfd,TUNSIFHEAD,&n)\n");
      zeroexit(255);
    }

  #endif

  struct pollfd fds[2];
  fds[0].fd = sockfd;
  fds[0].events = POLLIN;
  fds[1].fd = tunfd;
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

      bzero(buffer0,16);
      bzero(buffer1,32);
      memcpy(buffer1+32,shorttermpk,32);

      taia_now(nonce);
      taia_pack(nonce,nonce);
      randombytes(nonce+16,8);

      if (crypto_box_afternm(buffer0,buffer1,32+32,nonce,longtermsharedk)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: crypto_box_afternm(buffer0,buffer1,32+32,nonce,longtermsharedk)\n");
        zeroexit(255);
      }

      memcpy(buffer1,nonce,24);
      memcpy(buffer1+24,buffer0+16,32+16);

      if (sendto(sockfd,buffer1,24+32+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr))<0)
      {
        fprintf(stderr,"cryptotun: error: sendto(sockfd,buffer1,24+32+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr))\n");
      }

      update = now.tv_sec;
      goto devread;

    }

    devwrite: if (fds[0].revents)
    {

      n = recvfrom(sockfd,buffer0,1500,0,(struct sockaddr*)&recvaddr,&recvaddr_len);

      if (n<0)
      {
        fprintf(stderr,"cryptotun: fatal error: recvfrom(sockfd,buffer0,1500,0,(struct sockaddr*)&recvaddr,&recvaddr_len)\n");
        zeroexit(255);
      } if (n<24+32+16) goto devread;

      memcpy(nonce,buffer0,24);

      l=0; for (i=0;i<16;++i)
      {
        if (nonce[i] > taia0[i]){ ++l; break; }
        if (nonce[i] < taia0[i]) goto devread;
      } if (!l) goto devread;

      for (i=2048-16;i>-16;i-=16) if (!crypto_verify_16(taiacache+i,nonce)) goto devread;

      bzero(buffer1,16);
      memcpy(buffer1+16,buffer0+24,-24+n);
      bzero(buffer0,32);

      if (crypto_box_open_afternm(buffer0,buffer1,16+-24+n,nonce,longtermsharedk)<0) goto devread;

      remoteaddr.sin_addr = recvaddr.sin_addr;
      remoteaddr.sin_port = recvaddr.sin_port;

      if (updatetaia == 32)
      {

        memcpy(taia0,taia1,16);
        taia_now(taia1);
        taia_pack(taia1,taia1);
        updatetaia = 0;
        goto cachetaia;

      } else { cachetaia:

        for (i=0;i<16;++i)
        {
          if (taia0[i] > taiacache[i]) break;
          if (taia0[i] < taiacache[i]){ memcpy(taia0,taiacache,16); break; }
        }

        memcpy(taiacache,taiacache+16,2048-16);
        memcpy(taiacache+2048-16,nonce,16);
        ++updatetaia;

      }

      if (crypto_verify_32(remoteshorttermpk,buffer0+32))
      {

        jitter = now.tv_sec;
        memcpy(remoteshorttermpk,buffer0+32,32);

        if (crypto_box_beforenm(shorttermsharedk0,remoteshorttermpk,shorttermsk)<0)
        {
          fprintf(stderr,"cryptotun: fatal error: failed crypto_box_beforenm(shorttermsharedk0,remoteshorttermpk,shorttermsk)\n");
          zeroexit(255);
        }

      } else if ((jitter) && (now.tv_sec - jitter >= 64)) {

        memcpy(shorttermsharedk1,shorttermsharedk0,32);
        jitter = 0;

      } if (n<=24+32+24+16+16) goto devread;

      bzero(buffer1,16);
      memcpy(nonce,buffer0+32+32,24);
      memcpy(buffer1+16,buffer0+32+32+24,-24-32-24+n-16);
      bzero(buffer0,32);

      if (crypto_box_open_afternm(buffer0,buffer1,16+-24-32-24+n-16,nonce,shorttermsharedk0)<0)
      {

        jitter = now.tv_sec;
        bzero(remoteshorttermpk,32);
        memcpy(shorttermsharedk0,shorttermsharedk1,32);

        if (crypto_box_open_afternm(buffer0,buffer1,16+-24-32-24+n-16,nonce,shorttermsharedk1)<0) goto sendupdate;

        if (write(tunfd,buffer0+32,-24-32-24+n-16-16)<0)
        {
          fprintf(stderr,"cryptotun: fatal error: write(tunfd,buffer0+32,-24-32-24+n-16-16)\n");
          zeroexit(255);
        } goto sendupdate;

      }

      if (write(tunfd,buffer0+32,-24-32-24+n-16-16)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: write(tunfd,buffer0+32,-24-32-24+n-16-16)\n");
        zeroexit(255);
      } update = now.tv_sec;

    }

    devread: if (fds[1].revents)
    {

      bzero(buffer1,32);

      n = read(tunfd,buffer1+32,1500);

      if (n<0)
      {
        fprintf(stderr,"cryptotun: fatal error: read(tunfd,buffer1+32,1500)\n");
        zeroexit(255);
      }

      bzero(buffer0,16);
      randombytes(nonce,24);

      if (crypto_box_afternm(buffer0,buffer1,32+n,nonce,shorttermsharedk0)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: crypto_box_afternm(buffer0,buffer1,32+n,nonce,shorttermsharedk0)\n");
        zeroexit(255);
      }

      memcpy(buffer1+32,shorttermpk,32);
      memcpy(buffer1+32+32,nonce,24);
      memcpy(buffer1+32+32+24,buffer0+16,n+16);

      taia_now(nonce);
      taia_pack(nonce,nonce);
      randombytes(nonce+16,8);

      if (crypto_box_afternm(buffer0,buffer1,32+32+24+n+16,nonce,longtermsharedk)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: crypto_box_afternm(buffer0,buffer1,32+32+24+n+16,nonce,longtermsharedk)\n");
        zeroexit(255);
      }

      memcpy(buffer1,nonce,24);
      memcpy(buffer1+24,buffer0+16,32+24+n+16+16);

      if (sendto(sockfd,buffer1,24+32+24+n+16+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr))<0)
      {
        fprintf(stderr,"cryptotun: error: sendto(sockfd,buffer1,24+32+24+n+16+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr))\n");
      } else update = now.tv_sec;

    }

    poll(fds,2,16384);

  }

}
