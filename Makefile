# /******************************************
#  SixXSd - The SixXS POP Daemon
#  by Jeroen Massar <jeroen@sixxs.net>
# *******************************************
# $Author: jeroen $
# $Id: Makefile,v 1.2 2005-01-31 17:05:36 jeroen Exp $
# $Date: 2005-01-31 17:05:36 $
# ******************************************/
#
# Toplevel Makefile allowing easy distribution.
# Use this makefile for doing almost anything
# 'make help' shows the possibilities
#

# Make these variables generic
PROJECT_NAME=sixxsd
PROJECT_DESC="SixXS POP Daemon"
PROJECT_VERSION=2005.01.31-cvs

# Compile Time Options
# Append one of the following option on wish to
# include certain features
#
# Optimize		: -O3
# Enable Debugging	: -DDEBUG
#
# Linux			: -DARCH_LINUX
# FreeBSD		: -DARCH_FREEBSD
#
# Make these variables generic
PROJECT_OPTIONS=-DDEBUG -DARCH_LINUX

# Export the variables for lower levels
export PROJECT_NAME
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
	@echo "${PROJECT_NAME} - ${PROJECT_DESC}"
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
	cp bin/${PROJECT_NAME} ${DESTDIR}${sbindir}

# Clean all the output files etc
distclean: clean

clean: debclean
	${MAKE} -C src clean

# Generate Distribution files
dist:	tar bz2 deb debsrc rpm rpmsrc

# tar.gz
tar:	clean
	-${RM} ../${PROJECT_NAME}_${PROJECT_VERSION}.tar.gz
	tar -zclof ../${PROJECT_NAME}_${PROJECT_VERSION}.tar.gz *

# tar.bz2
bz2:	clean
	-${RM} ../${PROJECT_NAME}_${PROJECT_VERSION}.tar.bz2
	tar -jclof ../${PROJECT_NAME}_${PROJECT_VERSION}.tar.bz2 *

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
	-rm -rf build-stamp configure-stamp debian/changelog debian/${PROJECT_NAME}/ debian/${PROJECT_NAME}.postinst.debhelper debian/${PROJECT_NAME}.postrm.debhelper debian/${PROJECT_NAME}.prerm.debhelper debian/${PROJECT_NAME}.substvars debian/files

# RPM
rpm:	clean
	# TODO ;)
	${MAKE} clean

rpmsrc:	clean
	# TODO ;)

# Mark targets as phony
.PHONY : all install help clean dist tar bz2 deb debsrc debclean rpm rpmsrc
