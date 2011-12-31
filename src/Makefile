# /*********************************************************
#  SixXSd - The Daemon of SixXS
#  by Jeroen Massar <jeroen@sixxs.net>
#  (C) Copyright SixXS 2000-2008 All Rights Reserved
# *********************************************************/
#
# Source Makefile for SixXSd - Jeroen Massar <jeroen@sixxs.net>
#
# SIXXSD_VERSION and SIXXSD_RELEASE and SIXXSD_OPTIONS need to be defined, gets done by toplevel Makefile
#
# One should make this using the main Makefile (thus one dir up)

ifndef SIXXSD_VERSION
$(error Run this make from the root, aka one level up)
endif

EXED = sixxsd_$(OS_BITS)

BINS		= ../bin/${EXED}${EXT}

# Core Modules
OBJS		=	sixxsd.o 							\
			ayiya.o								\
			checksum.o common.o common_extra.o config.o context.o 		\
			decode.o							\
			hash_md5.o hash_sha1.o						\
			hb.o								\
			iface.o								\
			pop.o								\
			proto41.o							\
			rwl.o								\
			subnet.o							\
			thread.o tunnel.o

INCS		=	sixxsd.h 							\
			ayiya.h								\
			checksum.h common.h common_extra.h config.h context.h		\
			hash_md5.h hash_sha1.h hb.h					\
			iface.h								\
			list.h								\
			platform.h proto41.h						\
			rwl.h								\
			sixxsd.h stats.h subnet.h					\
			thread.h tunnel.h

# http://www.gnu.org/software/libc/manual/html_node/Feature-Test-Macros.html
# Describes the various standard toggles (_LARGEFILE_SOURCE, _LARGEFILE64_SOURCE, _FILE_OFFSET_BITS=64)
# See also http://www.suse.de/~aj/linux_lfs.html for Long File Support (LFS) / 64bit support documentation
DEPS		:=	../Makefile Makefile
CFLAGS		+=	-D_XOPEN_SOURCE=600 -D_BSD_SOURCE
CFLAGS		+=	-D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
CFLAGS		+=	-D_REENTRANT -D_THREAD_SAFE
CFLAGS		+=	-D'SIXXSD_RELEASE="$(SIXXSD_RELEASE)"' -D'SIXXSD_VERSION="$(SIXXSD_VERSION)"'
CFLAGS		+=	-D'SIXXSD_DESC=$(SIXXSD_DESC)' -D'SIXXSD_COPYRIGHT=$(SIXXSD_COPYRIGHT)'
CFLAGS		+=	$(SIXXSD_OPTIONS) -D'SIXXSD_OPTIONS="$(SIXXSD_OPTS)"'
CFLAGS		+=	-DOS_BITS=$(OS_BITS)
COMPILE		=	@echo "* Compiling to $@"; $(CC) -c $(CFLAGS)
LINK		=	@echo "* Linking $@"; $(CC) $(CFLAGS)
RM		=	@echo "* Removing $@"; rm

# The part of the Makefile which actually builds SixXSd

all: ${BINS}

../bin/${EXED}${EXT}: ${OBJS} ${INCS} ${DEPS}
	$(LINK) -o $@ $(OBJS) $(LDFLAGS)
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "SYMBOLS"),0)
	@echo [STRIP] $@; strip $@;
endif

../bin/${EXEW}${EXT}: ${OBJSW} ${INCSW} ${DEPS}
	$(LINK) -o $@ $(OBJSW) $(LDFLAGSW)
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "SYMBOLS"),0)
	@echo [STRIP] $@; strip $@;
endif

$(OBJS): %.o: %.c $(DEPS) ${INCS}
	$(COMPILE) $< -o $@

clean:
	$(RM) -f $(OBJS) *.o $(BINS)

# Mark targets as phony
.PHONY : all clean

