# /**************************************
#  SixXSd - SixXS POP Daemon
#  by Jeroen Massar <jeroen@sixxs.net>
# ***************************************
# $Author: jeroen $
# $Id: Makefile,v 1.1 2004-08-30 19:33:45 jeroen Exp $
# $Date: 2004-08-30 19:33:45 $
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
SRCS	= sixxsd.c common/common.c common/md5.c common/sha1.c thread.c interface.c prefix.c cfg.c hb.c ayiya.c traffic.c
INCS	= sixxsd.h common/common.h common/md5.h common/sha1.h
OBJS	= sixxsd.o common/common.o common/md5.o common/sha1.o thread.o interface.o prefix.o cfg.o hb.o ayiya.o traffic.o
DEPS    = ../Makefile Makefile
CFLAGS	= -W -Wall -Wno-unused -D_GNU_SOURCE -D'SIXXSD_VERSION="$(SIXXSD_VERSION)"' $(SIXXSD_OPTIONS)
LDFLAGS	= -lpthread
CC      = gcc
RM      = rm

# Did the user want ARCH_LINUX support?
ifeq ($(shell echo "${SIXXSD_OPTIONS}" | grep -c "ARCH_LINUX"),1)
SRCS += os_linux.c
OBJS += os_linux.o
endif

# Did the user want ARCH_FREEBSD support?
ifeq ($(shell echo "${SIXXSD_OPTIONS}" | grep -c "ARCH_FREEBSD"),1)
SRCS += os_freebsd.c
OBJS += os_freebsd.o
endif

all: ${BINS}

../bin/sixxsd: $(OBJS) $(INCS) $(DEPS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
ifeq ($(shell echo "${SIXXSD_OPTIONS}" | grep -c "DEBUG"),0)
	strip $@;
endif

clean:
	$(RM) -f $(OBJS) $(BINS)

# Mark targets as phony
.PHONY : all clean
