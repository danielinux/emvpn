CC:=gcc
CFLAGS= -Wall -I posix/lib/libevquick -I.
SYSTEM?=posix
CRYPTO?=none

ifeq ($(SYSTEM),posix)
   OBJ+=sys_posix.o
endif

ifeq ($(SYSTEM),picotcp)
   OBJ+=sys_picotcp.o
endif

ifeq ($(CRYPTO),cyassl)
   OBJ+=crypto_cyassl.o
endif

ifeq ($(CRYPTO),openssl)
   OBJ+=crypto_openssl.o
endif

ifeq ($(CRYPTO),none)
	OBJ+=crypto_none.o
endif

all: posix

posix: vpn


crypto_none.o: crypto/lib/crypto_none.c
	gcc -c -o $@ $^ $(CFLAGS)

sys_posix.o: posix/lib/sys_posix.c
	gcc -c -o $@ $^ $(CFLAGS)

vpn: vpn.o linux_main.o libevquick.o $(OBJ)

libevquick.o: posix/lib/libevquick/libevquick.c
	gcc -c -o $@ $^ $(CFLAGS)


clean:
	rm -f *.o vpn 
