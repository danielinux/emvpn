CC:=gcc
CFLAGS= -Wall -I lib/libevquick -I. -ggdb
SYSTEM?=posix
CRYPTO?=none
SERVER?=n


ifeq ($(SYSTEM),posix)
   OBJ+=sys_posix.o
   SERVER=y
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

ifeq ($(SERVER),y)
  CFLAGS+=-DVPN_SERVER
endif

all: posix

posix: vpn_client vpn_server

crypto_none.o: crypto/crypto_none.c
	gcc -c -o $@ $^ $(CFLAGS)

sys_posix.o: sys/sys_posix.c
	gcc -c -o $@ $^ $(CFLAGS)

vpn_client: vpn.o linux_main.o libevquick.o $(OBJ) 
	gcc -o $@ $^

vpn_server: vpn.o linux_main.o libevquick.o $(OBJ) 
	gcc -o $@ $^

libevquick.o: lib/libevquick/libevquick.c
	gcc -c -o $@ $^ $(CFLAGS)


clean:
	rm -f *.o vpn_server vpn_client
