# Generated automatically from Makefile.in by configure.
# Makefile.in generated automatically by automake 1.4-p4 from Makefile.am

# Copyright (C) 1994, 1995-8, 1999 Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.

# Makefile.am
# Automake file for Wiretap
#
# $Id: Makefile,v 1.13 2002/05/09 23:50:34 gram Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@zing.org>
# Copyright 1998 Gerald Combs
#
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.


SHELL = /bin/sh

srcdir = .
top_srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datadir = ${prefix}/share
sysconfdir = ${prefix}/etc
sharedstatedir = ${prefix}/com
localstatedir = ${prefix}/var
libdir = ${exec_prefix}/lib
infodir = ${prefix}/info
mandir = ${prefix}/man
includedir = ${prefix}/include
oldincludedir = /usr/include

DESTDIR =

pkgdatadir = $(datadir)/libwtap.a
pkglibdir = $(libdir)/libwtap.a
pkgincludedir = $(includedir)/libwtap.a

top_builddir = .

ACLOCAL = aclocal
AUTOCONF = autoconf
AUTOMAKE = automake
AUTOHEADER = autoheader

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL} $(AM_INSTALL_PROGRAM_FLAGS)
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}
transform = s,x,x,

NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
host_alias = i686-pc-linux-gnu
host_triplet = i686-pc-linux-gnu
CC = gcc
CPP = gcc -E
FLEX_PATH = 
GLIB_CFLAGS = -I/usr/include/glib-1.2 -I/usr/lib/glib/include
GLIB_CONFIG = /usr/bin/glib-config
GLIB_LIBS = -L/usr/lib -lglib
LEX = /usr/bin/flex
MAKEINFO = makeinfo
PACKAGE = libwtap.a
RANLIB = ranlib
VERSION = 0.0.0
YACC = bison -y

ACLOCAL_AMFLAGS = `../aclocal-flags`

noinst_LIBRARIES = libwiretap.a

#EXTRA_LIBRARIES = libwiretap.a

CLEANFILES =  	libwiretap.a			*~


libwiretap_a_SOURCES =  	ascend-grammar.y		ascend-scanner.l		ascend.c			ascend.h			ascend-int.h			atm.c				atm.h				buffer.c			buffer.h			csids.c				csids.h				dbs-etherwatch.c		dbs-etherwatch.h		etherpeek.c             	etherpeek.h             	file.c				file_wrappers.c			file_wrappers.h			i4btrace.c			i4btrace.h			i4b_trace.h			iptrace.c			iptrace.h			lanalyzer.c			lanalyzer.h			libpcap.c			libpcap.h			netmon.c			netmon.h			nettl.c				nettl.h				netxray.c			netxray.h			ngsniffer.c			ngsniffer.h			pppdump.c			pppdump.h			radcom.c			radcom.h			snoop.c				snoop.h				toshiba.c			toshiba.h			visual.c			visual.h			vms.c				vms.h				wtap.c				wtap.h				wtap-int.h


EXTRA_DIST =  	ascend-grammar.c		ascend-grammar.h		ascend-scanner.c		config.h.win32			Makefile.nmake			wtap.def


# Any POSIX-compatible YACC should honor the -p flag
YFLAGS = -d -p ascend
ACLOCAL_M4 = $(top_srcdir)/aclocal.m4
mkinstalldirs = $(SHELL) $(top_srcdir)/../mkinstalldirs
CONFIG_HEADER = config.h
CONFIG_CLEAN_FILES = 
LIBRARIES =  $(noinst_LIBRARIES)


DEFS = -DHAVE_CONFIG_H -I. -I$(srcdir) -I.
CPPFLAGS =  -I/usr/local/include
LDFLAGS =  -L/usr/local/lib
LIBS = -lz  -L/usr/lib -lglib
libwiretap_a_LIBADD = 
libwiretap_a_OBJECTS =  ascend-grammar.o ascend-scanner.o ascend.o atm.o \
buffer.o csids.o dbs-etherwatch.o etherpeek.o file.o file_wrappers.o \
i4btrace.o iptrace.o lanalyzer.o libpcap.o netmon.o nettl.o netxray.o \
ngsniffer.o pppdump.o radcom.o snoop.o toshiba.o visual.o vms.o wtap.o
AR = ar
LEX_OUTPUT_ROOT = lex.yy
LEXLIB = -lfl
CFLAGS = -D_U_="__attribute__((unused))" -Wall -W -g -O2 -I/usr/include/glib-1.2 -I/usr/lib/glib/include -I/usr/local/include
COMPILE = $(CC) $(DEFS) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(LDFLAGS) -o $@
DIST_COMMON =  README ./stamp-h.in AUTHORS COPYING ChangeLog INSTALL \
Makefile.am Makefile.in NEWS acconfig.h acinclude.m4 aclocal.m4 \
ascend-grammar.c ascend-scanner.c config.h.in configure configure.in


DISTFILES = $(DIST_COMMON) $(SOURCES) $(HEADERS) $(TEXINFOS) $(EXTRA_DIST)

TAR = tar
GZIP_ENV = --best
DEP_FILES =  .deps/ascend-grammar.P .deps/ascend-scanner.P \
.deps/ascend.P .deps/atm.P .deps/buffer.P .deps/csids.P \
.deps/dbs-etherwatch.P .deps/etherpeek.P .deps/file.P \
.deps/file_wrappers.P .deps/i4btrace.P .deps/iptrace.P \
.deps/lanalyzer.P .deps/libpcap.P .deps/netmon.P .deps/nettl.P \
.deps/netxray.P .deps/ngsniffer.P .deps/pppdump.P .deps/radcom.P \
.deps/snoop.P .deps/toshiba.P .deps/visual.P .deps/vms.P .deps/wtap.P
SOURCES = $(libwiretap_a_SOURCES)
OBJECTS = $(libwiretap_a_OBJECTS)

all: all-redirect
.SUFFIXES:
.SUFFIXES: .S .c .l .o .s .y
$(srcdir)/Makefile.in: Makefile.am $(top_srcdir)/configure.in $(ACLOCAL_M4) 
	cd $(top_srcdir) && $(AUTOMAKE) --gnu Makefile

Makefile: $(srcdir)/Makefile.in  $(top_builddir)/config.status $(BUILT_SOURCES)
	cd $(top_builddir) \
	  && CONFIG_FILES=$@ CONFIG_HEADERS= $(SHELL) ./config.status

$(ACLOCAL_M4):  configure.in  acinclude.m4
	cd $(srcdir) && $(ACLOCAL) $(ACLOCAL_AMFLAGS)

config.status: $(srcdir)/configure.in $(CONFIG_STATUS_DEPENDENCIES)
	$(SHELL) ./config.status --recheck
$(srcdir)/configure: $(srcdir)/configure.in $(ACLOCAL_M4) $(CONFIGURE_DEPENDENCIES)
	cd $(srcdir) && $(AUTOCONF)

config.h: stamp-h
	@if test ! -f $@; then \
		rm -f stamp-h; \
		$(MAKE) stamp-h; \
	else :; fi
stamp-h: $(srcdir)/config.h.in $(top_builddir)/config.status
	cd $(top_builddir) \
	  && CONFIG_FILES= CONFIG_HEADERS=config.h \
	     $(SHELL) ./config.status
	@echo timestamp > stamp-h 2> /dev/null
$(srcdir)/config.h.in: $(srcdir)/stamp-h.in
	@if test ! -f $@; then \
		rm -f $(srcdir)/stamp-h.in; \
		$(MAKE) $(srcdir)/stamp-h.in; \
	else :; fi
$(srcdir)/stamp-h.in: $(top_srcdir)/configure.in $(ACLOCAL_M4) acconfig.h
	cd $(top_srcdir) && $(AUTOHEADER)
	@echo timestamp > $(srcdir)/stamp-h.in 2> /dev/null

mostlyclean-hdr:

clean-hdr:

distclean-hdr:
	-rm -f config.h

maintainer-clean-hdr:

mostlyclean-noinstLIBRARIES:

clean-noinstLIBRARIES:
	-test -z "$(noinst_LIBRARIES)" || rm -f $(noinst_LIBRARIES)

distclean-noinstLIBRARIES:

maintainer-clean-noinstLIBRARIES:

.s.o:
	$(COMPILE) -c $<

.S.o:
	$(COMPILE) -c $<

mostlyclean-compile:
	-rm -f *.o core *.core

clean-compile:

distclean-compile:
	-rm -f *.tab.c

maintainer-clean-compile:

libwiretap.a: $(libwiretap_a_OBJECTS) $(libwiretap_a_DEPENDENCIES)
	-rm -f libwiretap.a
	$(AR) cru libwiretap.a $(libwiretap_a_OBJECTS) $(libwiretap_a_LIBADD)
	$(RANLIB) libwiretap.a
.l.c:
	$(LEX) $(AM_LFLAGS) $(LFLAGS) $< && mv $(LEX_OUTPUT_ROOT).c $@
.y.c:
	$(YACC) $(AM_YFLAGS) $(YFLAGS) $< && mv y.tab.c $*.c
	if test -f y.tab.h; then \
	if cmp -s y.tab.h $*.h; then rm -f y.tab.h; else mv y.tab.h $*.h; fi; \
	else :; fi
ascend-grammar.h: ascend-grammar.c


tags: TAGS

ID: $(HEADERS) $(SOURCES) $(LISP)
	list='$(SOURCES) $(HEADERS)'; \
	unique=`for i in $$list; do echo $$i; done | \
	  awk '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	here=`pwd` && cd $(srcdir) \
	  && mkid -f$$here/ID $$unique $(LISP)

TAGS:  $(HEADERS) $(SOURCES) config.h.in $(TAGS_DEPENDENCIES) $(LISP)
	tags=; \
	here=`pwd`; \
	list='$(SOURCES) $(HEADERS)'; \
	unique=`for i in $$list; do echo $$i; done | \
	  awk '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	test -z "$(ETAGS_ARGS)config.h.in$$unique$(LISP)$$tags" \
	  || (cd $(srcdir) && etags $(ETAGS_ARGS) $$tags config.h.in $$unique $(LISP) -o $$here/TAGS)

mostlyclean-tags:

clean-tags:

distclean-tags:
	-rm -f TAGS ID

maintainer-clean-tags:

distdir = $(PACKAGE)-$(VERSION)
top_distdir = $(distdir)

# This target untars the dist file and tries a VPATH configuration.  Then
# it guarantees that the distribution is self-contained by making another
# tarfile.
distcheck: dist
	-rm -rf $(distdir)
	GZIP=$(GZIP_ENV) $(TAR) zxf $(distdir).tar.gz
	mkdir $(distdir)/=build
	mkdir $(distdir)/=inst
	dc_install_base=`cd $(distdir)/=inst && pwd`; \
	cd $(distdir)/=build \
	  && ../configure --srcdir=.. --prefix=$$dc_install_base \
	  && $(MAKE) $(AM_MAKEFLAGS) \
	  && $(MAKE) $(AM_MAKEFLAGS) dvi \
	  && $(MAKE) $(AM_MAKEFLAGS) check \
	  && $(MAKE) $(AM_MAKEFLAGS) install \
	  && $(MAKE) $(AM_MAKEFLAGS) installcheck \
	  && $(MAKE) $(AM_MAKEFLAGS) dist
	-rm -rf $(distdir)
	@banner="$(distdir).tar.gz is ready for distribution"; \
	dashes=`echo "$$banner" | sed s/./=/g`; \
	echo "$$dashes"; \
	echo "$$banner"; \
	echo "$$dashes"
dist: distdir
	-chmod -R a+r $(distdir)
	GZIP=$(GZIP_ENV) $(TAR) chozf $(distdir).tar.gz $(distdir)
	-rm -rf $(distdir)
dist-all: distdir
	-chmod -R a+r $(distdir)
	GZIP=$(GZIP_ENV) $(TAR) chozf $(distdir).tar.gz $(distdir)
	-rm -rf $(distdir)
distdir: $(DISTFILES)
	-rm -rf $(distdir)
	mkdir $(distdir)
	-chmod 777 $(distdir)
	here=`cd $(top_builddir) && pwd`; \
	top_distdir=`cd $(distdir) && pwd`; \
	distdir=`cd $(distdir) && pwd`; \
	cd $(top_srcdir) \
	  && $(AUTOMAKE) --include-deps --build-dir=$$here --srcdir-name=$(top_srcdir) --output-dir=$$top_distdir --gnu Makefile
	@for file in $(DISTFILES); do \
	  d=$(srcdir); \
	  if test -d $$d/$$file; then \
	    cp -pr $$d/$$file $(distdir)/$$file; \
	  else \
	    test -f $(distdir)/$$file \
	    || ln $$d/$$file $(distdir)/$$file 2> /dev/null \
	    || cp -p $$d/$$file $(distdir)/$$file || :; \
	  fi; \
	done

DEPS_MAGIC := $(shell mkdir .deps > /dev/null 2>&1 || :)

-include $(DEP_FILES)

mostlyclean-depend:

clean-depend:

distclean-depend:
	-rm -rf .deps

maintainer-clean-depend:

%.o: %.c
	@echo '$(COMPILE) -c $<'; \
	$(COMPILE) -Wp,-MD,.deps/$(*F).pp -c $<
	@-cp .deps/$(*F).pp .deps/$(*F).P; \
	tr ' ' '\012' < .deps/$(*F).pp \
	  | sed -e 's/^\\$$//' -e '/^$$/ d' -e '/:$$/ d' -e 's/$$/ :/' \
	    >> .deps/$(*F).P; \
	rm .deps/$(*F).pp

%.lo: %.c
	@echo '$(LTCOMPILE) -c $<'; \
	$(LTCOMPILE) -Wp,-MD,.deps/$(*F).pp -c $<
	@-sed -e 's/^\([^:]*\)\.o[ 	]*:/\1.lo \1.o :/' \
	  < .deps/$(*F).pp > .deps/$(*F).P; \
	tr ' ' '\012' < .deps/$(*F).pp \
	  | sed -e 's/^\\$$//' -e '/^$$/ d' -e '/:$$/ d' -e 's/$$/ :/' \
	    >> .deps/$(*F).P; \
	rm -f .deps/$(*F).pp
info-am:
info: info-am
dvi-am:
dvi: dvi-am
check-am: all-am
check: check-am
installcheck-am:
installcheck: installcheck-am
all-recursive-am: config.h
	$(MAKE) $(AM_MAKEFLAGS) all-recursive

install-exec-am:
install-exec: install-exec-am

install-data-am:
install-data: install-data-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am
install: install-am
uninstall-am:
uninstall: uninstall-am
all-am: Makefile $(LIBRARIES) config.h
all-redirect: all-am
install-strip:
	$(MAKE) $(AM_MAKEFLAGS) AM_INSTALL_PROGRAM_FLAGS=-s install
installdirs:


mostlyclean-generic:

clean-generic:
	-test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean-generic:
	-rm -f Makefile $(CONFIG_CLEAN_FILES)
	-rm -f config.cache config.log stamp-h stamp-h[0-9]*

maintainer-clean-generic:
	-test -z "ascend-scannerlascend-grammarhascend-grammarc" || rm -f ascend-scannerl ascend-grammarh ascend-grammarc
mostlyclean-am:  mostlyclean-hdr mostlyclean-noinstLIBRARIES \
		mostlyclean-compile mostlyclean-tags mostlyclean-depend \
		mostlyclean-generic

mostlyclean: mostlyclean-am

clean-am:  clean-hdr clean-noinstLIBRARIES clean-compile clean-tags \
		clean-depend clean-generic mostlyclean-am

clean: clean-am

distclean-am:  distclean-hdr distclean-noinstLIBRARIES distclean-compile \
		distclean-tags distclean-depend distclean-generic \
		clean-am

distclean: distclean-am
	-rm -f config.status

maintainer-clean-am:  maintainer-clean-hdr \
		maintainer-clean-noinstLIBRARIES \
		maintainer-clean-compile maintainer-clean-tags \
		maintainer-clean-depend maintainer-clean-generic \
		distclean-am
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."

maintainer-clean: maintainer-clean-am
	-rm -f config.status

.PHONY: mostlyclean-hdr distclean-hdr clean-hdr maintainer-clean-hdr \
mostlyclean-noinstLIBRARIES distclean-noinstLIBRARIES \
clean-noinstLIBRARIES maintainer-clean-noinstLIBRARIES \
mostlyclean-compile distclean-compile clean-compile \
maintainer-clean-compile tags mostlyclean-tags distclean-tags \
clean-tags maintainer-clean-tags distdir mostlyclean-depend \
distclean-depend clean-depend maintainer-clean-depend info-am info \
dvi-am dvi check check-am installcheck-am installcheck all-recursive-am \
install-exec-am install-exec install-data-am install-data install-am \
install uninstall-am uninstall all-redirect all-am all installdirs \
mostlyclean-generic distclean-generic clean-generic \
maintainer-clean-generic clean mostlyclean distclean maintainer-clean


ascend-scanner.c : ascend-scanner.l
	$(LEX) -Pascend -oascend-scanner.c $(srcdir)/ascend-scanner.l

# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
