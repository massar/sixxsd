# /*********************************************************
#  SixXSd - The Daemon of SixXS
#  by Jeroen Massar <jeroen@sixxs.net>
#  (C) Copyright SixXS 2000-2013 All Rights Reserved
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

# The binaries we want build
BINS		=

# The modules sixxsd consists of
SD_EXE		=	../bin/sixxsd_$(OS_BITS)
BINS		+=	$(SD_EXE)
SD_OBJS		=	sixxsd.o 							\
			ayiya.o								\
			checksum.o common.o common_extra.o config.o context.o 		\
			decode.o							\
			hash_md5.o hash_sha1.o						\
			hb.o								\
			icmpv4.o							\
			iface.o								\
			pop.o								\
			proto4.o							\
			proto41.o							\
			rwl.o								\
			subnet.o							\
			thread.o tunnel.o
SD_LIBS		=

PS_EXE		=	../../../sbin/popstatd
ifeq ($(OS_BITS),64)
ifeq ($(OS_NAME),Linux)
# Only build popstat for 64bits platform as that is what our backends are
BINS		+=	$(PS_EXE)
endif
endif
PS_OBJS		=	popstatd.o common.o
PS_LIBS		=	-l rrd -l mysqlclient

DEPS		:=	../Makefile Makefile
CFLAGS		+=	-D'SIXXSD_RELEASE="$(SIXXSD_RELEASE)"' -D'SIXXSD_VERSION="$(SIXXSD_VERSION)"'
CFLAGS		+=	-D'SIXXSD_DESC=$(SIXXSD_DESC)' -D'SIXXSD_COPYRIGHT=$(SIXXSD_COPYRIGHT)'
CFLAGS		+=	$(SIXXSD_OPTIONS) -D'SIXXSD_OPTIONS="$(SIXXSD_OPTS)"'
CFLAGS		+=	-DOS_BITS=$(OS_BITS)
COMPILE		=	@echo "* Compiling to $@"; $(CC) -c $(CFLAGS)
LINK		=	@echo "* Linking $@"; $(CC) $(CFLAGS)
RM		=	@echo "* Removing $@"; rm

# All the objects in this project nicely in alpha order
OBJS	:= $(shell echo $(SD_OBJS) $(PS_OBJS) | sed 's/ /\n/g' | sort | uniq | tr '\n' ' ')

# The part of the Makefile which actually builds SixXSd

# The final targets we want to produce
all: ${BINS}
	@echo "* All Done"

${SD_EXE}: $(DEPS) $(SD_OBJS)
	$(LINK) -o $@ $(SD_OBJS) $(LDFLAGS) $(LDLIBS) $(SD_LIBS)
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "SYMBOLS"),0)
	@echo [STRIP] $@; strip $@;
endif

${PS_EXE}: $(DEPS) $(PS_OBJS)
	$(LINK) -o $@ $(PS_OBJS) $(LDFLAGS) $(LDLIBS) $(PS_LIBS)
ifeq ($(shell echo ${SIXXSD_OPTIONS} | grep -c "SYMBOLS"),0)
	@echo [STRIP] $@; strip $@;
endif

clean:
	$(RM) -f $(OBJS) *.o $(BINS)

# Include all the dependencies
-include $(OBJS:.o=.d)

depend: clean
	@echo "* Making dependencies"
	@$(MAKE) -s $(OBJS)
	@echo "* Making dependencies - done"

%.o: %.c $(DEPS)
	@echo "* Compiling $@";
	@$(CC) -c $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) $*.c > $*.d
	@cp -f $*.d $*.d.tmp
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
	  sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

# Mark targets as phony
.PHONY : all clean

