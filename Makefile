# /******************************************
#  SixXSd - The SixXS PoP Daemon
#  by Jeroen Massar <jeroen@sixxs.net>
# *******************************************
# $Author: jeroen $
# $Id: Makefile,v 1.5 2006-02-20 09:25:16 jeroen Exp $
# $Date: 2006-02-20 09:25:16 $
# ******************************************/
#
# Toplevel Makefile allowing easy distribution.
# Use this makefile for doing almost anything
# 'make help' shows the possibilities
#

# Make these variables generic
PROJECT:=sixxsd
PROJECT_DESC:="SixXS PoP Daemon"
PROJECT_VERSION:=2006.02.20-cvs
PROJECT_COPYRIGHT:="(C) Copyright SixXS. 2001-2006 All Rights Reserved"

# Compile Time Options
# Append one of the following option on wish to
# include certain features
#
# Enable Debugging	: -DDEBUG
# Lock Debugging        : -DDEBUG_LOCKS
#
# Make these variables generic
PROJECT_OPTIONS=-DDEBUG

#PROJECT_OPTIONS+=-DDEBUG_LOCKS

######################################################################
# No settings below here
######################################################################

# Tag it with debug when it is run with debug set
ifeq ($(shell echo $(PROJECT_OPTIONS) | grep -c "DEBUG"),1)
PROJECT_VERSION:=$(PROJECT_VERSION)-debug
endif

# Get the hostname this is compiled on
HOSTNAME:=$(shell hostname -f 2>/dev/null)
ifeq ($(HOSTNAME),)
HOSTNAME:=$(shell hostname)
endif

# Pass the buildinfo so we can show that in the executable
PROJECT_OPTIONS+=-D'BUILDINFO="$(PROJECT) version $(PROJECT_VERSION) ($(shell whoami)@$(HOSTNAME) ($(shell $(CC) -v 2>&1 | grep version)) \#1 $(shell date)"'

# Do not print "Entering directory ..."
MAKEFLAGS += --no-print-directory

# Export the variables for lower levels
export PROJECT
export PROJECT_DESC
export PROJECT_VERSION
export PROJECT_OPTIONS

# Change this if you want to install into another dirtree
# Required for eg the Debian Package builder
DESTDIR=

# Get the source dir, needed for eg debsrc
SOURCEDIR := $(shell pwd)

# Misc bins
RM=rm -f

# Paths
sbindir=/usr/sbin/
srcdir=src/

all:	Makefile ${srcdir}
	$(MAKE) -C src all

help:
	@echo "${PROJECT} - ${PROJECT_DESC}"
	@echo
	@echo "Makefile targets:"
	@echo "all      : Build everything"
	@echo "help     : This little text"
	@echo "install  : Build & Install"
	@echo "clean    : Clean the dirs to be pristine in bondage"
	@echo
	@echo "Distribution targets:"
	@echo "dist     : Make all distribution targets"
	@echo "tar      : Make source tarball (tar.gz)"
	@echo "bz2      : Make source tarball (tar.bz2)"
	@echo "deb      : Make Debian binary package (.deb)"
	@echo "debsrc   : Make Debian source packages"
	@echo "rpm      : Make RPM package (.rpm)"
	@echo "rpmsrc   : Make RPM source packages"

install: all
	mkdir -p ${DESTDIR}${sbindir}
	cp bin/${PROJECT} ${DESTDIR}${sbindir}

# Clean all the output files etc
distclean: clean

clean: debclean
	${MAKE} -C src clean

# Generate Distribution files
dist:	tar bz2 deb debsrc rpm rpmsrc

# tar.gz
tar:	clean
	-${RM} ../${PROJECT}_${PROJECT_VERSION}.tar.gz
	tar -zclof ../${PROJECT}_${PROJECT_VERSION}.tar.gz *

# tar.bz2
bz2:	clean
	-${RM} ../${PROJECT}_${PROJECT_VERSION}.tar.bz2
	tar -jclof ../${PROJECT}_${PROJECT_VERSION}.tar.bz2 *

# .deb
deb:	clean
	# Copy the changelog
	cp doc/changelog debian/changelog
	debian/rules binary
	${MAKE} clean

# Source .deb
debsrc: clean
	# Copy the changelog
	cp doc/changelog debian/changelog
	cd ..; dpkg-source -b ${SOURCEDIR}; cd ${SOURCEDIR}
	${MAKE} clean

# Cleanup after debian
debclean:
	-rm -rf build-stamp configure-stamp debian/changelog debian/${PROJECT}/ debian/${PROJECT}.postinst.debhelper debian/${PROJECT}.postrm.debhelper debian/${PROJECT}.prerm.debhelper debian/${PROJECT}.substvars debian/files

# RPM
rpm:	clean
	# TODO ;)
	${MAKE} clean

rpmsrc:	clean
	# TODO ;)

# Mark targets as phony
.PHONY : all install help clean dist tar bz2 deb debsrc debclean rpm rpmsrc
