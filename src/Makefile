# /**************************************
#  SixXSd - SixXS PoP Daemon
#  by Jeroen Massar <jeroen@sixxs.net>
# ***************************************
# $Author: jeroen $
# $Id: Makefile,v 1.8 2008-01-17 01:19:24 jeroen Exp $
# $Date: 2008-01-17 01:19:24 $
# **************************************/
#
# Source Makefile for SixXSd - Jeroen Massar <jeroen@sixxs.net>
#
# PROJECT_VERSION and PROJECT_OPTIONS need to be defined, gets done by toplevel Makefile
#
# One should make this using the main Makefile (thus one dir up)

ifndef PROJECT_VERSION
$(error Run this make from the root, aka one level up))
endif

SIXXSD_VERSION = ${PROJECT_VERSION}
SIXXSD_OPTIONS = ${PROJECT_OPTIONS}

BINS	= ../bin/sixxsd
SRCS	= sixxsd.c common/common.c common/md5.c common/sha1.c thread.c interface.c prefix.c cfg.c hb.c ayiya.c traffic.c latency.c
INCS	= sixxsd.h common/common.h common/md5.h common/sha1.h
OBJS	= sixxsd.o common/common.o common/md5.o common/sha1.o thread.o interface.o prefix.o cfg.o hb.o ayiya.o traffic.o latency.o
DEPS    := ../Makefile Makefile
CFLAGS	+= -D_GNU_SOURCE -D'SIXXSD_VERSION="$(SIXXSD_VERSION)"' $(SIXXSD_OPTIONS)
LDFLAGS	= -lpthread -lrrd
CC      = gcc
RM      = rm

COMPILE = @echo "* Compiling to $@"; $(CC) -c $(CFLAGS)
LINK    = @echo "* Linking $@"; $(CC) $(CFLAGS)
RM      = @echo "* Removing $@"; rm

# Our very *bliep* set of options to make sure that these things can't cause any issues
CFLAGS += -W -Wall -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Waggregate-return -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Wnested-externs -Winline -Wbad-function-cast -fshort-enums -fstrict-aliasing -fno-common -Wno-packed -Wpadded -pedantic -Wall -Wmissing-include-dirs -Wswitch-default -Wformat=2 -Wformat-security -Wformat -Wmissing-format-attribute -D_REENTRANT -D_THREAD_SAFE -pipe -combine -Wunused -Winit-self -Wextra -Wno-long-long

# Linux
ifeq ($(shell uname | grep -c "Linux"),1)
CFLAGS += -D_LINUX -Wno-variadic-macros
SRCS += os_linux.c
OBJS += os_linux.o
endif

# FreeBSD
ifeq ($(shell uname | grep -c "FreeBSD"),1)
CFLAGS += -D_FREEBSD -D_BSD -I/usr/local/include/
LDFLAGS += -L/usr/local/lib/
SRCS += os_bsd.c
OBJS += os_bsd.o
endif

# OpenBSD
ifeq ($(shell uname | grep -c "OpenBSD"),1)
CFLAGS += -D_OPENBSD -D_BSD -I/usr/local/include/
LDFLAGS += -L/usr/local/lib/
SRCS += os_bsd.c
OBJS += os_bsd.o
endif

# Darwin
ifeq ($(shell uname | grep -c "Darwin"),1)
CFLAGS += -D_DARWIN -D_BSD
SRCS += os_bsd.c
OBJS += os_bsd.o
endif

# AIX
ifeq ($(shell uname | grep -c "AIX"),1)
CFLAGS += -DAIX
#error No AIX configuration method (yet)
endif

# Add symbols for debugmode, but optimize fully otherwise
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "DEBUG"),1)
CFLAGS += -g
else
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "PROFILE"),0)
CFLAGS += -O3
endif
endif

ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "PROFILE"),1)
CFLAGS += -pg -g
# -fprofile-arcs
endif

all: ${BINS}

../bin/sixxsd: $(OBJS) $(INCS) $(DEPS)
	$(LINK) -o $@ $(OBJS) $(LDFLAGS)
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "DEBUG"),0)
	strip $@;
endif

$(OBJS): %.o: %.c $(DEPS) ${INCS}
	$(COMPILE) $< -o $@

clean:
	$(RM) -f $(OBJS) $(BINS)

# Mark targets as phony
.PHONY : all clean
