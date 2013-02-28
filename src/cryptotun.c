#include <nacl/crypto_scalarmult_curve25519.h>
#include <nacl/randombytes.h>
#include <nacl/crypto_box.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <poll.h>

#ifdef linux
  #include <linux/if_ether.h>
  #include <linux/if_tun.h>
#endif
#include <sys/ioctl.h>
#include <net/if.h>

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

  if (argc<7)
  {
    fprintf(stderr,USAGE);
    exit(64);
  }

  int optval=1;
  struct sockaddr_in sock, remoteaddr, recvaddr;
  socklen_t recvaddr_len = sizeof(struct sockaddr_in);

  if (socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP)!=3)
  {
    fprintf(stderr,"cryptotun: fatal error: failed socket()\n");
    exit(64);
  }

  if (setsockopt(3,SOL_SOCKET,SO_REUSEADDR,&optval,sizeof(optval))<0)
  {
    fprintf(stderr,"cryptotun: fatal error: failed setsockopt()\n");
    exit(64);
  }

  bzero(&sock,sizeof(sock));
  sock.sin_family = AF_INET;
  sock.sin_addr.s_addr = inet_addr(argv[1]);
  sock.sin_port = htons(atoi(argv[2]));

  if (bind(3,(struct sockaddr*)&sock,sizeof(sock))<0)
  {
    fprintf(stderr,"cryptotun: fatal error: failed bind()\n");
    exit(64);
  }

  bzero(&remoteaddr,sizeof(remoteaddr));
  remoteaddr.sin_family = AF_INET;
  remoteaddr.sin_addr.s_addr = inet_addr(argv[3]);
  remoteaddr.sin_port = htons(atoi(argv[4]));

  /*
  if (connect(3,(struct sockaddr*)&sock,sizeof(sock))<0)
  {
    fprintf(stderr,"cryptotun: fatal error: failed connect()\n");
    exit(64);
  }
  */

  unsigned char nonce[24];

  unsigned char longtermpk[32];
  unsigned char longtermsk[32];

  unsigned char shorttermpk[32];
  unsigned char shorttermsk[32];

  unsigned char remotelongtermpk[32];
  unsigned char remoteshorttermpk[32];

  unsigned char longtermsharedk[32];
  unsigned char shorttermsharedk[32];

  struct timeval now;
  unsigned long atto;
  unsigned long nano;
  unsigned long now_usec;
  unsigned long long sec;
  unsigned long long now_sec;
  unsigned char taia[16] = {0};

  struct timezone *utc = (struct timezone *)0;
  gettimeofday(&now,utc);
  int sessionexpiry = now.tv_sec - 512;
  int ping = now.tv_sec - 16;

  int i, n, l;
  unsigned char buffer0[2048];
  unsigned char buffer1[2048];

  if ((open(argv[5],0)!=4)||(read(4,longtermsk,32)<32))
  {
    fprintf(stderr,"cryptotun: fatal error: failed read(4,%s,32)\n",argv[5]);
    exit(64);
  }
  close(4);

  crypto_scalarmult_curve25519_base(longtermpk,longtermsk);

  /*
  if (crypto_scalarmult_curve25519_base(longtermpk,longtermsk)<0);
  {
    fprintf(stderr,"cryptotun: fatal error: failed crypto_scalarmult_curve25519_base(longtermpk,longtermsk)\n",argv[5]);
    exit(64);
  }
  */

  if (crypto_box_beforenm(longtermsharedk,remotelongtermpk,longtermsk)<0)
  {
    fprintf(stderr,"cryptotun: fatal error: failed crypto_box_beforenm(longtermsharedk,remotelongtermpk,longtermsk)\n");
    exit(255);
  }

  if (strlen(argv[6])<64)
  {
    fprintf(stderr,"cryptotun: fatal error: invalid remotelongtermpk\n");
    exit(64);
  }
  l=0; for (i=0;i<64;++i)
  {
    if (((unsigned char)argv[6][i]>47)&&((unsigned char)argv[6][i]<58)) remotelongtermpk[l] = (unsigned char)argv[6][i] - 48 << 4;
    else { if (((unsigned char)argv[6][i]>64)&&((unsigned char)argv[6][i]<71)) remotelongtermpk[l] = (unsigned char)argv[6][i] - 55 << 4;
    else { if (((unsigned char)argv[6][i]>96)&&((unsigned char)argv[6][i]<103)) remotelongtermpk[l] = (unsigned char)argv[6][i] - 87 << 4;
    else { fprintf(stderr,"cryptotun: fatal error: invalid remotelongtermpk\n"); exit(64);
    }}} ++i;
    if (((unsigned char)argv[6][i]>47)&&((unsigned char)argv[6][i]<58)) remotelongtermpk[l] += (unsigned char)argv[6][i] - 48;
    else { if (((unsigned char)argv[6][i]>64)&&((unsigned char)argv[6][i]<71)) remotelongtermpk[l] += (unsigned char)argv[6][i] - 55;
    else { if (((unsigned char)argv[6][i]>96)&&((unsigned char)argv[6][i]<103)) remotelongtermpk[l] += (unsigned char)argv[6][i] - 87;
    else { fprintf(stderr,"cryptotun: fatal error: invalid remotelongtermpk\n"); exit(64);
    }}} ++l;
  }

  if ((!strlen(argv[7]))||(strlen(argv[7])>16))
  {
    fprintf(stderr,"cryptotun: fatal error: invalid ifr_name %s\n",argv[7]);
    exit(64);
  }


  #ifdef linux

    if (open("/dev/net/tun",2)!=4)
    {
      fprintf(stderr,"cryptotun: fatal error: open(\"/dev/net/tun\",2) != fd4\n");
      exit(255);
    }

    struct ifreq ifr;
    memset(&ifr,0,sizeof(ifr));
    strcpy(ifr.ifr_name,argv[7]);

    ifr.ifr_flags = IFF_TUN /* | IFF_NO_PI */;

    if (ioctl(4,TUNSETIFF,(void *)&ifr)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(4,TUNSETIFF,(void *)&ifr)\n");
      exit(255);
    }

  #else

    char ifr_name[5+16];
    memmove(&ifr_name,"/dev/",5);
    memmove(&ifr_name[5],argv[7],strlen(argv[7]));

    if (open(ifr_name,2)!=4)
    {
      fprintf(stderr,"cryptotun: fatal error: open(ifr_name,2) != fd4\n");
      exit(255);
    }

    /*
    int ifr_flag = IFF_POINTOPOINT | IFF_MULTICAST;

    if (ioctl(4,TUNSIFMODE,&ifr_flag)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(4,TUNSIFMODE,&ifr_flag)\n");
      exit(255);
    }

    ifr_flag=0;
    if (ioctl(4,TUNSLMODE,&ifr_flag)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(4,TUNSLMODE,&ifr_flag)\n");
      exit(255);
    }

    ifr_flag=0;
    if (ioctl(4,TUNSIFHEAD,&ifr_flag)<0)
    {
      fprintf(stderr,"cryptotun: fatal error: ioctl(4,TUNSIFHEAD,&ifr_flag)\n");
      exit(255);
    }
    */

  #endif

  struct pollfd fds[2];
  fds[0].fd = 3;
  fds[0].events = POLLIN | POLLPRI;
  fds[0].revents = 3;
  fds[1].fd = 4;
  fds[1].events = POLLIN | POLLPRI;
  fds[1].revents = 3;

  while (1)
  {

    gettimeofday(&now,utc);

    if (now.tv_sec - sessionexpiry >= 512)
    {

      if (crypto_box_keypair(shorttermpk,shorttermsk)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: failed crypto_box_keypair()\n");
        exit(255);
      }

      if (crypto_box_beforenm(shorttermsharedk,remoteshorttermpk,shorttermsk)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: failed crypto_box_beforenm(shorttermsharedk,remoteshorttermpk,shorttermsk)\n");
        exit(255);
      }

      sessionexpiry = now.tv_sec;

    }

    if (poll(&fds[0],1,512)>0)
    {

      bzero(buffer0,2048);
      n = recvfrom(3,buffer0,1500,0,(struct sockaddr *)&recvaddr,&recvaddr_len);
      remoteaddr = recvaddr;/*
      if (n<0)
      {
        fprintf(stderr,"cryptotun: fatal error: recvfrom(3,&buffer0[32],1024,0,(struct sockaddr *)&recvaddr,&recvaddr_len)\n");
        exit(255);
      }

      memmove(nonce,buffer0,24);

      l=0; for (i=0;i<16;++i)
      {
        if (nonce[i] > taia[i]){ l = 1; break; }
        if (nonce[i] < taia[i]){ l = 0; break; }
      } if (!l) continue;

      now_sec = 4611686018427387914ULL + (unsigned long long)now.tv_sec;
      sec = 0ULL;
      l = 8; for (i=0;i<8;++i) sec += (unsigned long long)nonce[i] << (unsigned long long)(8 * --l);
      if ((sec > now_sec )&&(sec - now_sec > 128ULL)) continue;
      else if (now_sec - sec > 128ULL) continue;

      bzero(buffer1,2048);
      memmove(buffer1+16,buffer0+24,n-24);
      bzero(buffer0,2048);

      if (crypto_box_open_afternm(buffer0,buffer1,16+n-24,nonce,longtermsharedk)<0) continue;

      remoteaddr = recvaddr;

      memmove(taia,nonce,16);

      if (write(4,buffer0+32,n-24-16)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: write(4,buffer0+32,n-24-16)\n");
        exit(255);
      }*/write(4,buffer0,n);

    }

    if (poll(&fds[1],1,512)>0)
    {

      for (i=0;i<2048;++i)
      {
        buffer0[i] = 0;
        buffer1[i] = 0;
      }

      /*n = read(4,buffer1+32,1500);*/n = read(4,buffer1,1500);

      if (n<0)
      {
        fprintf(stderr,"cryptotun: fatal error: read(4,&buffer1[16],864)\n");
        exit(255);
      }
      /*
      bzero(nonce,24);
      now_sec = 4611686018427387914ULL + (unsigned long long)now.tv_sec;
      now_usec = 1000 * now.tv_usec + 500;
      l = 8; for (i=0;i<8;++i) nonce[i] = now_sec >> (unsigned long long)(8 * --l);
      l = 8; for (i=8;i<12;++i) nonce[i] = now_usec >> (unsigned long)(8 * --l);
      for (i=12;i<16;++i) nonce[i] = 0;

      if (crypto_box_afternm(buffer0,buffer1,32+n,nonce,longtermsharedk)<0)
      {
        fprintf(stderr,"cryptotun: fatal error: crypto_box_afternm(buffer0,buffer1,32+n,nonce,longtermsharedk)\n");
        exit(255);
      }

      bzero(buffer1,2048);
      memmove(buffer1,nonce,24);
      memmove(buffer1+24,buffer0+16,n+16);

      n = sendto(3,buffer1,24+n+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr));
      */n = sendto(3,buffer1,n,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr));
      if (n<0);
      {
        fprintf(stderr,"cryptotun: error: sendto(3,buffer1,24+n+16,0,(struct sockaddr*)&remoteaddr,sizeof(remoteaddr))\n");
      }

    }

  }
}
