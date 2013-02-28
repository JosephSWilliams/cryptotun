#!/bin/sh -e

[ -e /usr/lib/libnacl.so ] && \
  echo 'mv /usr/lib/libnacl.so /usr/lib/breaksBC.so' 1>&2 && \
  exit 64

gcc src/cryptotun.c -o cryptotun -l nacl /usr/lib/randombytes.o
