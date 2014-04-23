# Makefile.am
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2004 Gerald Combs
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

noinst_LTLIBRARIES = libdirtydissectors.la libfiledissectors.la libdissectors.la

AM_CPPFLAGS = -I$(srcdir)/../.. -I$(srcdir)/.. \
	$(LIBGNUTLS_CFLAGS) $(LIBGCRYPT_CFLAGS)

include Makefile.common

libdirtydissectors_la_SOURCES = \
	$(DIRTY_DISSECTOR_SRC)		\
	$(DIRTY_ASN1_DISSECTOR_SRC)	\
	$(DIRTY_PIDL_DISSECTOR_SRC)

if HAVE_WARNINGS_AS_ERRORS
AM_CLEAN_CFLAGS = -Werror
endif

libfiledissectors_la_SOURCES = \
	$(FILE_DISSECTOR_SRC)

libdissectors_la_SOURCES = \
	$(DISSECTOR_SRC) \
	$(ASN1_DISSECTOR_SRC) \
	$(PIDL_DISSECTOR_SRC) \
	$(DISSECTOR_SUPPORT_SRC)
libdissectors_la_CFLAGS = $(AM_CLEAN_CFLAGS)

# include dceprc and pidl in the source tarball. But nothing to build...
DIST_SUBDIRS = dcerpc pidl

EXTRA_DIST = \
	Custom.common		\
	Makefile.common		\
	Makefile.nmake		\
	packet-ncp2222.inc	\
	README.X11		\
	x11-fields

packet-ncp2222.c : $(top_srcdir)/tools/ncp2222.py
	$(PYTHON) $< -o $@

# Target to rebuild the X11 dissector header files.
# See README.X11 before using this--it requires the xcb and mesa source.
x11-dissector: $(top_srcdir)/tools/process-x11-fields.pl x11-fields $(top_srcdir)/tools/process-x11-xcb.pl
	$(PERL) $(top_srcdir)/tools/process-x11-fields.pl < x11-fields
	$(PERL) $(top_srcdir)/tools/process-x11-xcb.pl

#
# Build register.c, which contains a function register_all_protocols()
# that calls the register routines for all protocols and a function
# register_all_protocol_handoffs() that calls the handoff registration
# routines for all protocols.
#
# We do this by scanning through sources. If that turns out to be too slow,
# maybe we could just require every .o file to have an register routine
# of a given name (packet-aarp.o -> proto_register_aarp, etc.).
#
# Formatting conventions: The name of the proto_register_* routines an
# proto_reg_handoff_* routines must start in column zero, or must be
# preceded only by "void " starting in column zero, and must not be
# inside #if.
#
# ALL_DISSECTORS_SRC is assumed to have all the files that need to be scanned.
#
# For some unknown reason, having a big "for" loop in the Makefile
# to scan all the files doesn't work with some "make"s; they seem to
# pass only the first few names in the list to the shell, for some
# reason.
#
# Therefore, we have a script to generate the register.c file.
# The shell script runs slowly, as multiple greps and seds are run
# for each input file; this is especially slow on Windows. Therefore,
# if Python is present (as indicated by PYTHON being defined), we run
# a faster Python script to do that work instead.
#
# The first argument is the directory in which the source files live.
# The second argument is "dissectors", to indicate that we should build
# a register.c file for libwireshark.
# All subsequent arguments are the files to scan.
#
register.c: $(plugin_src) $(ALL_DISSECTORS_SRC) Makefile.common Custom.common $(top_srcdir)/tools/make-dissector-reg \
    $(top_srcdir)/tools/make-dissector-reg.py
	@if test -n "$(PYTHON)"; then \
		echo Making register.c with python ; \
		$(PYTHON) $(top_srcdir)/tools/make-dissector-reg.py $(srcdir) \
		    dissectors $(ALL_DISSECTORS_SRC) ; \
	else \
		echo Making register.c with shell script ; \
		$(top_srcdir)/tools/make-dissector-reg $(srcdir) \
		   dissectors $(plugin_src) $(ALL_DISSECTORS_SRC) ; \
	fi
#
# Currently register.c can be included in the distribution because
# we always build all protocol dissectors. We used to have to check
# whether or not to build the snmp dissector. If we again need to
# variably build something, making register.c non-portable, uncomment
# the dist-hook line below.
#
# Oh, yuk. We don't want to include "register.c" in the distribution, as
# its contents depend on the configuration, and therefore we want it
# to be built when the first "make" is done; however, Automake insists
# on putting *all* source into the distribution.
#
# We work around this by having a "dist-hook" rule that deletes
# "register.c", so that "dist" won't pick it up.
#
#dist-hook:
#	@rm -f $(distdir)/register.c

# XXX - We may want to add register-cache.pkl to the distribution at
# some point. It should be portable across architectures.
CLEANFILES = \
	libdissectors.a			\
	libdissectors.la		\
	libdirtydissectors.a		\
	libdirtydissectors.la		\
	register.c-tmp			\
	register-cache.pkl		\
	$(GENERATED_HEADER_FILES)	\
	*~

MAINTAINERCLEANFILES =	\
	$(GENERATED_FILES)	\
	Makefile.in

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -g abort -g termoutput -build \
	-sourcedir=$(srcdir) \
	$(ALL_DISSECTORS_SRC) $(DISSECTOR_INCLUDES) $(DISSECTOR_SUPPORT_SRC)
