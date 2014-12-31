CC:=gcc
CFLAGS= -Wall -I lib/libevquick -I. -ggdb
SYSTEM?=posix
CRYPTO?=none
SERVER?=n


ifeq ($(SYSTEM),posix)
   OBJ+=sys_posix.o drv_tap.o
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

posix: emvpn_client emvpn_server

crypto_none.o: crypto/crypto_none.c
	gcc -c -o $@ $^ $(CFLAGS)

sys_posix.o: sys/sys_posix.c
	gcc -c -o $@ $^ $(CFLAGS)

drv_tap.o: sys/drv_tap.c
	gcc -c -o $@ $^ $(CFLAGS)

emvpn_client: emvpn.o linux_main.o libevquick.o $(OBJ) 
	gcc -o $@ $^

emvpn_server: emvpn.o linux_main.o libevquick.o $(OBJ) 
	gcc -o $@ $^

libevquick.o: lib/libevquick/libevquick.c
	gcc -c -o $@ $^ $(CFLAGS)


clean:
	rm -f *.o emvpn_server emvpn_client
