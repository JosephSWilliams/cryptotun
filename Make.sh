#!/bin/sh -ve

[ -e /usr/lib/libnacl.so ] && \
  echo 'mv /usr/lib/libnacl.so /usr/lib/breaksBC.so' 1>&2 && \
  exit 64

[ `uname -s` == OpenBSD ] && CFLAGS=-DPOSIX_SOURCE
[ `uname -s` == FreeBSD ] && CFLAGS=-DPOSIX_SOURCE

gcc `cat conf-cc` $CFLAGS src/memcmp-test.c -o memcmp-test -l tai
./memcmp-test || exit 255

gcc `cat conf-cc` $CFLAGS src/ignchld.c -o ignchld
gcc `cat conf-cc` $CFLAGS src/pubkey.c -o pubkey -l nacl
gcc `cat conf-cc` $CFLAGS src/cryptotun.c -o cryptotun -l tai -l nacl /usr/lib/randombytes.o
gcc `cat conf-cc` $CFLAGS src/cryptotun2.c -o cryptotun2 -l tai -l nacl /usr/lib/randombytes.o
