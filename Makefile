CC:=gcc
CFLAGS= -Wall -I lib/libevquick -I. -ggdb
SYSTEM?=posix
CRYPTO?=openssl
SERVER?=n
ADDRESS_SANITIZER=n
DRIVER?=stdio

ifeq ($(ADDRESS_SANITIZER),y)
  CFLAGS+=-fsanitize=address -fno-omit-frame-pointer -m32
  LDFLAGS+=-fsanitize=address -fno-omit-frame-pointer -m32
endif


ifeq ($(SYSTEM),posix)
   SERVER=y
   OBJ+=sys_posix.o
   ifeq ($(DRIVER),tap)
   	 OBJ+=drv_tap.o
	 CFLAGS+=-DDRV_TAP
   endif
   ifeq ($(DRIVER),stdio)
	OBJ+=drv_stdio.o
	 CFLAGS+=-DDRV_STDIO
   endif
endif

ifeq ($(SYSTEM),picotcp)
   OBJ+=lib/picotcp/build/lib/libpicotcp.a sys_picotcp.o
   CFLAGS+=-Ilib/picotcp/build/include
   SERVER=y
endif


ifeq ($(CRYPTO),cyassl)
   OBJ+=crypto_ctaocrypt.o
   LDFLAGS+=-lcyassl
   CFLAGS+=-DCRYPTO_CTAOCRYPT
endif

ifeq ($(CRYPTO),openssl)
   OBJ+=crypto_openssl.o
   CFLAGS+=-DCRYPTO_OPENSSL
   LDFLAGS+=-lcrypto
endif

ifeq ($(CRYPTO),none)
	OBJ+=crypto_none.o
   CFLAGS+=-DCRYPTO_NONE
endif

ifeq ($(SERVER),y)
  CFLAGS+=-DVPN_SERVER
endif

all: posix

posix: emvpn_client emvpn_server

pico: emvpn_client_pico emvpn_server_pico

crypto_none.o: crypto/crypto_none.c
	gcc -c -o $@ $^ $(CFLAGS)

emvpn.o: emvpn.c
	gcc -c -o $@ $^ $(CFLAGS)

crypto_openssl.o: crypto/crypto_openssl.c
	gcc -c -o $@ $^ $(CFLAGS)

crypto_ctaocrypt.o: crypto/crypto_ctaocrypt.c
	gcc -c -o $@ $^ $(CFLAGS)

sys_posix.o: sys/sys_posix.c
	gcc -c -o $@ $^ $(CFLAGS)

sys_picotcp.o: sys/sys_picotcp.c
	gcc -c -o $@ $^ $(CFLAGS)


lib/picotcp/build/lib/libpicotcp.a: lib/picotcp
	make -C lib/picotcp

drv_tap.o: sys/drv_tap.c
	gcc -c -o $@ $^ $(CFLAGS)

drv_stdio.o: sys/drv_stdio.c
	gcc -c -o $@ $^ $(CFLAGS)

emvpn_client: emvpn.o linux_main.o libevquick.o $(OBJ) 
	gcc -o $@ $^ $(LDFLAGS)

emvpn_server: emvpn.o linux_main.o libevquick.o $(OBJ) 
	gcc -o $@ $^ $(LDFLAGS)

emvpn_client_pico: emvpn.o picotcp_main.o $(OBJ) 
	gcc -o $@ $^ $(LDFLAGS)

emvpn_server_pico: emvpn.o picotcp_main.o $(OBJ) 
	gcc -o $@ $^ $(LDFLAGS)

libevquick.o: lib/libevquick/libevquick.c
	gcc -c -o $@ $^ $(CFLAGS)


clean:
	rm -f *.o emvpn_server emvpn_client
	make -C lib/picotcp clean
