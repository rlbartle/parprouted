ifdef DEBUG
CFLAGS  	?= -g -DDEBUG
else
CFLAGS  	?= -Os -flto -DNDEBUG
LDFLAGS 	?= -s -w
endif

PREFIX		?= $(DESTDIR)/usr
CC		?= gcc
SBINDIR		?= ${DESTDIR}${PREFIX}/sbin
MANDIR		?= ${DESTDIR}${PREFIX}/share/man/man8

CFLAGS := ${CFLAGS} -Werror -Wall -Wextra

OBJS = parprouted.o arp.o
LIBS = -pthread

all: parprouted parprouted.8

install: all
	install parprouted $(SBINDIR)
	install parprouted.8 $(MANDIR)

clean:
	rm -f $(OBJS) parprouted core

parprouted: ${OBJS}
	${CC} -o parprouted ${LDFLAGS} ${OBJS} ${LIBS}

parprouted.8: parprouted.pod
	pod2man --section=8 --center="Proxy ARP Bridging Daemon" parprouted.pod --release "parprouted" --date "`date '+%B %Y'`" > parprouted.8

%.o: %.c
	${CC} -c ${CPPFLAGS} $(CFLAGS) -o $@ $<
