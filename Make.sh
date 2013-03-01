#!/bin/sh -e

[ -e /usr/lib/libnacl.so ] && \
  echo 'mv /usr/lib/libnacl.so /usr/lib/breaksBC.so' 1>&2 && \
  exit 64

gcc -O3 src/pubkey.c -o pubkey -l nacl
gcc -O3 src/cryptotun.c -o cryptotun -l tai -l nacl /usr/lib/randombytes.o
