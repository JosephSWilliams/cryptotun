CryptoTUN:
	gcc -O3 src/cryptotun.c -o cryptotun -l nacl /usr/lib/randombytes.o
