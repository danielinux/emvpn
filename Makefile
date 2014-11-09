CC:=gcc
CFLAGS= #-Wall

all: posix

posix: vpn

vpn: vpn.o linux_main.o


clean:
	rm -f *.o vpn 
