# /*********************************************************
#  SixXSd - SixXS Daemon
#  by Jeroen Massar <jeroen@sixxs.net>
#  (C) Copyright SixXS 2000-2013 All Rights Reserved
# *********************************************************/
#
# Toplevel Makefile allowing easy distribution.
# Use this makefile for doing almost anything
# 'make help' shows the possibilities

# The name of the application
SIXXSD_NAME:=SixXSd
SIXXSD_DESC:="SixXSd - SixXS Daemon"
SIXXSD_COPYRIGHT:="(C) Copyright SixXS 2000-2013 All Rights Reserved"

# The version of SixXSd
SIXXSD_VERSION=4.0

# The version of SixXSd
SIXXSD_RELEASE:=2013.03.11

# Enable extra debugging operation + enables symbols (don't distribute with it enabled!)
#SIXXSD_OPTIONS+=-DDEBUG
#SIXXSD_OPTIONS+=-DSYMBOLS
# Debug Stack (Stackdump functions)
#SIXXSD_OPTIONS+=-DDEBUG_STACK

# Enable profiling?
#SIXXSD_OPTIONS+=-DPROFILE
#SIXXSD_OPTIONS+=-DCALLGRIND

#####################################################################
# No more settings to change any more below this block
#####################################################################
# HAS_IFHEAD  -> Tunnel Device produces packets with a tun_pi in the front
# NEED_IFHEAD -> Tunnel Device produces packets with a tun_pi in the front,
#                but it is not active per default
#####################################################################

ifeq ($(OS_NAME),)
OS_NAME=$(shell uname -s)
endif

ifeq ($(OS_RELEASE),)
OS_RELEASE=$(shell uname -r)
endif

ifeq ($(OS_BITS),)
OS_BITS=64
OS_PROC=x86_64
else
ifeq ($(OS_PROC),)
ifeq ($(OS_BITS),64)
OS_BITS=64
OS_PROC=x86_64
else
OS_BITS=32
OS_PROC=i586
endif
endif
endif

ifeq ($(OS_PROC),unknown)
OS_PROC=$(shell uname -m)
endif

# Try to get the Compiler version (currently we assume gcc)
CC_VERSION=$(shell $(CC) -v 2>&1 | grep "gcc version" | cut -f3 -d' ')

ifeq ($(CC_VERSION),)
error "We don't have a compiler?"
endif

CC_VER=$(shell echo $(CC_VERSION) | cut -c1)

# Misc bins, making it easy to quiet/change them :)
RM=@rm -f
MV=@mv
MAKE:=${MAKE}
CP=@echo [Copy]; cp
RPMBUILD=@echo [RPMBUILD]; rpmbuild
RPMBUILD_SILENCE=>/dev/null 2>/dev/null

# Alias the Project Options, so we can show it without our own ugly
# internal Makefile addons ;)
SIXXSD_OPTS:=$(SIXXSD_OPTIONS)

# Our very *bliep* set of options to make sure that these things can't cause any issues
CFLAGS += -ansi -pedantic -std=c99
CFLAGS += -W -Wall -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Waggregate-return
CFLAGS += -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls
CFLAGS += -Wnested-externs -Winline -Wbad-function-cast
CFLAGS += -fshort-enums -fstrict-aliasing -fno-common
CFLAGS += -Wno-packed -Wpadded -Wswitch-default -Wno-variadic-macros
CFLAGS += -Wformat=2 -Wformat-security -Wmissing-format-attribute
CFLAGS += -D_REENTRANT -D_THREAD_SAFE
CFLAGS += -pipe
CFLAGS += -Wunused -Winit-self -Wextra -Wno-long-long -Wmissing-include-dirs

# For a rainy day, get rid of all warnings caused by:
#CFLAGS += -Wconversion

# Compile 'sixxsd' (which resides in 'src')
TARGETS+=src

LDFLAGS+=-lrt

# http://www.gnu.org/software/libc/manual/html_node/Feature-Test-Macros.html
# Describes the various standard toggles (_LARGEFILE_SOURCE, _LARGEFILE64_SOURCE, _FILE_OFFSET_BITS=64)
# See also http://www.suse.de/~aj/linux_lfs.html for Long File Support (LFS) / 64bit support documentation
ifeq ($(OS_NAME),Linux)
	LDFLAGS += -lpthread -lm
	CFLAGS += -DHAS_IFHEAD=1
	CFLAGS += -D_XOPEN_SOURCE=600 -D_BSD_SOURCE
	CFLAGS += -D_LINUX -pthread -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
endif

ifeq ($(OS_NAME),FreeBSD)
LDFLAGS += -lpthread -lm
CFLAGS += -DNEED_IFHEAD=1
CFLAGS += -D_FREEBSD -pthread
endif

ifeq ($(OS_BITS),64)
CFLAGS += -D_64BIT
SIXXSD_OPTIONS += -m64
else
SIXXSD_OPTIONS += -m32
endif

# When not debugging and not profiling: Optimize even more
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "DEBUG"),0)
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "PROFILE"),0)
	CFLAGS += -O3 -fno-trapping-math
	ifeq ($(OS_BITS),64)
	CFLAGS += -fprefetch-loop-arrays
	endif
	CFLAGS += -ftracer -ffast-math -DNDEBUG
	CFLAGS += -maccumulate-outgoing-args -minline-all-stringops

	# Note that this was optimized
	SIXXSD_OPTIONS += -DOPTIMIZE
	SIXXSD_OPTS += -DOPTIMIZE
endif
endif

# Add profiling information
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "PROFILE"),1)
	CFLAGS += -pg
endif

# Not optimizing? -> Add symbols
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "OPTIMIZE"),0)
	# Make sure that we keep symbols (don't strip)
	ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "SYMBOLS"),0)
		SIXXSD_OPTIONS += -DSYMBOLS
	endif
endif

# Add symbols?
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "SYMBOLS"),1)
CFLAGS += -g -ggdb3
ifeq ($(OS_NAME),Linux)
CFLAGS += -rdynamic
endif
endif

ifeq ($(shell uname | grep -c "Linux"),1)
HOSTNAME:=$(shell hostname -f 2>/dev/null)
else
HOSTNAME:=$(shell hostname)
endif

# Pass the buildinfo so we can show that in the executable
SIXXSD_OPTIONS+=-D'BUILDINFO="$(SIXXSD_NAME) $(SIXXSD_VERSION) $(SIXXSD_RELEASE)/r$(shell svnversion -n) ($(shell id | cut -f2 -d'(' | cut -f1 -d')')@$(HOSTNAME) ($(shell $(CC) -v 2>&1 | grep "gcc version" | tr -d \')) \#1 $(shell date)"'

# Do not print "Entering directory ..."
MAKEFLAGS += --no-print-directory

# Tag it with debug when it is run with debug set
ifeq ($(shell echo $(SIXXSD_OPTIONS) | grep -c "DEBUG"),1)
SIXXSD_RELEASE:=$(SIXXSD_RELEASE)-debug
else
ifeq ($(shell echo $(SIXXSD_OPTIONS) | grep -c "SYMBOLS"),1)
SIXXSD_RELEASE:=$(SIXXSD_RELEASE)-symbols
endif
endif

# Change this if you want to install into another dirtree
# Required for eg the Debian Package builder
DESTDIR=

# Configure a default RPMDIR
ifeq ($(shell echo "${RPMDIR}/" | grep -c "/"),1)
RPMDIR=/usr/src/redhat/
endif

# Get the source dir, needed for eg debsrc
SOURCEDIR := $(shell pwd)
SOURCEDIRNAME := $(shell basename "`pwd`")

# Destination Paths (relative to DESTDIR)
dirsbin=/usr/sbin/
dirbin=/usr/bin/
diretc=/etc/
dirdoc=/usr/share/doc/${SIXXSD_NAME}/

# Make sure the lower makefile also knows these
export SIXXSD_NAME
export SIXXSD_DESC
export SIXXSD_OPTIONS
export SIXXSD_OPTS
export SIXXSD_VERSION
export SIXXSD_RELEASE
export SIXXSD_COPYRIGHT
export DESTDIR
export SOURCEDIR
export MAKEFLAGS
export CFLAGS
export LDFLAGS
export RM
export MV
export CC
export CC_VERSION
export CP
export MAKE
export dirsbin
export dirbin
export diretc
export dirdoc
export OS_NAME
export OS_PROC
export OS_BITS

#####################################################################
# The Targets
#####################################################################
all:	Makefile $(TARGETS)
	@echo "==== "$(SIXXSD_DESC)" ===="
	@echo "Building  : "$(SIXXSD_NAME)
	@echo "Copyright : "$(SIXXSD_COPYRIGHT)
	@echo "Version   : "$(SIXXSD_VERSION)
	@echo "Release   : "$(SIXXSD_RELEASE)
	@echo "Options   : "$(SIXXSD_OPTS)
	@echo "OS        : "$(OS_NAME) $(OS_BITS)-bit
	@echo "Compiler  : $(CC) $(CC_VERSION)"
	@echo "CFLAGS    : $(CFLAGS)" >/dev/null

ifeq ($(CC_VERSION),)
	echo "NO COMPILER VERSION!?"
	exit
endif

	@for dir in $(TARGETS); do $(MAKE) -C $${dir} all; done
	@echo "Building done"
ifeq ($(OS_BITS),32)
ifeq ($(OS_NAME),Linux)
	@echo "Note: We only build popstatd for 64bits platform which noc.sixxs.net is (use OS_BITS=64)"
endif
endif

help:
	@echo "$(SIXXSD_NAME) - $(SIXXSD_DESC)"
	@echo
	@echo "Makefile targets:"
	@echo "all                  : Build everything"
	@echo "help                 : This little text"
	@echo "clean                : Clean the dirs to be pristine in bondage"
	@echo ""
	@echo "OS_BITS=32 clean all  : build 32bit binary"
	@echo "OS_BITS=64 clean all  : build 64bit binary"
	@echo ""
	@echo "Note that gcc-multilib is needed for cross-compiles on 64bit to 32bit Debian hosts"

depend:
	@${MAKE} -C src depend

clean:
	@${MAKE} -C src clean

# Mark targets as phony
.PHONY: all help clean depend

