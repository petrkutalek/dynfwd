CC ?= gcc
CFLAGS += -std=c99 -pedantic \
	-pedantic -frecord-gcc-switches \
	-O3 -ftree-vectorize -ftree-slp-vectorize \
	-D_XOPEN_SOURCE=700 \
	-D_FILE_OFFSET_BITS=64
LDFLAGS += -pie -lzmq -lmsgpackc -lipset

CFLAGS += -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fno-semantic-interposition
CFLAGS += -Wformat -Wformat-security -Werror=format-security
LDFLAGS += -Wl,-z,now -Wl,-z,relro

DEBUG ?= 1
ifeq (DEBUG, 1)
	CFLAGS += -g3 -gdwarf2 -DDEBUG
else
	CFLAGS=-DNDEBUG
endif

GIT_VERSION := $(shell git --no-pager describe --tags --always)
ifeq ($(strip $(GIT_VERSION)),)
	GIT_VERSION = 0.0.0
endif
ifneq ($(strip $(shell git status --porcelain 2> /dev/null)),)
	GIT_VERSION := $(GIT_VERSION)-DEV
endif
CFLAGS += -DGIT_VERSION=\"$(GIT_VERSION)\"

DESTDIR ?= /usr

SRCS = main.c
OBJS = $(SRCS:.c=.o)
DEPS = $(SRCS:.c=.d)

.PHONY: all
all: dynfwd

.PHONY: clean
clean:
	@-rm -f $(OBJS) $(DEPS) dynfwd dynfw-proxy

dynfwd: $(OBJS)
	@printf "%-16s%s\n" LD $@
	@$(CC) $^ $(LDFLAGS) -o $@

%.o: %.c
	@printf "%-16s%s\n" CC $@
	@$(CC) -x c -c $(CFLAGS) -o $@ $<

%.d: %.c
	@printf "%-16s%s\n" MM $@
	@$(CC) -x c $(CFLAGS) -MMD -o $@ $<

dynfw-proxy: proxy.o
	@printf "%-16s%s\n" LD $@
	@$(CC) $^ $(LDFLAGS) -o $@

install : all
	install -m755 -Z -D -s -t $(DESTDIR)/bin/ dynfwd
	#sudo setcap cap_net_admin+ep $(DESTDIR)/bin/dynfwd
	install -m644 -Z -D -t $(DESTDIR)/lib/systemd/system/ ../install/dynfwd.service
	install -m644 -Z -D -t $(DESTDIR)/share/doc/dynfwd/ ../README.md
	install -m644 -Z -D -t $(DESTDIR)/share/licenses/dynfwd/ ../LICENSE
	#install -m644 -Z -D -t $(DESTDIR)/share/man/man1/ dynfwd.1.gz
	#install -m644 -Z -D -t $(DESTDIR)/share/bash-completion/completions/ dynfwd.complete

uninstall :
	rm -f $(DESTDIR)/bin/dynfwd
	rm -f $(DESTDIR)/lib/systemd/system/dynfwd.service
	rm -fr $(DESTDIR)/share/doc/dynfwd
	rm -fr $(DESTDIR)/share/licenses/dynfwd
	#rm -f $(DESTDIR)/share/man/man1/dynfwd.1.gz
	#rm -f $(DESTDIR)/share/bash-completion/completions/dynfwd.complete
