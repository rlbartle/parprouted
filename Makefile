ifdef DEBUG
CFLAGS		?= -g -DDEBUG -Wall -Wno-address-of-packed-member
else
CFLAGS 		?= -O3 -Wall -Wno-address-of-packed-member
LDFLAGS		?= -flto
endif

PREFIX		?= $(DESTDIR)/usr
CC		?= gcc
SBINDIR		?= ${DESTDIR}${PREFIX}/sbin
MANDIR		?= ${DESTDIR}${PREFIX}/share/man/man8

OBJS = parprouted.o arp.o
LIBS = -pthread

all: parprouted parprouted.8

install: all
	install parprouted $(SBINDIR)
	install parprouted.8 $(MANDIR)

clean:
	rm -f $(OBJS) parprouted core

parprouted: ${OBJS}
	${CC} -g -o parprouted ${OBJS} ${CFLAGS} ${LDFLAGS} ${LIBS}

parprouted.8: parprouted.pod
	pod2man --section=8 --center="Proxy ARP Bridging Daemon" parprouted.pod --release "parprouted" --date "`date '+%B %Y'`" > parprouted.8

parprouted.o: parprouted.c parprouted.h

arp.o: arp.c parprouted.h
