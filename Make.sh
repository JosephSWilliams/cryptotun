#!/bin/sh -e

[ -e /usr/lib/libnacl.so ] && \
  echo 'mv /usr/lib/libnacl.so /usr/lib/breaksBC.so' 1>&2 && \
  exit 64

gcc src/pubkey.c -o pubkey -l nacl
gcc src/cryptotun.c -o cryptotun -l tai -l nacl /usr/lib/randombytes.o
