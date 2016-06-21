# Makefile.am
# Automake file for the TShark taps
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
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

include $(top_srcdir)/Makefile.am.inc

AM_CPPFLAGS = $(INCLUDEDIRS) $(WS_CPPFLAGS) $(GLIB_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) $(LIBGNUTLS_CFLAGS) $(PORTAUDIO_INCLUDES)

noinst_LIBRARIES = libcliui.a

# Generated header files that we want in the distribution.
GENERATED_HEADER_FILES =

# Generated C source files that we want in the distribution.
GENERATED_C_FILES = \
	tshark-tap-register.c

# All the generated files.
GENERATED_FILES = \
	$(GENERATED_HEADER_FILES) \
	$(GENERATED_C_FILES)

# Files that generate compileable files
GENERATOR_FILES =

# sources for TShark taps
TSHARK_TAP_SRC = \
	tap-camelsrt.c		\
	tap-comparestat.c	\
	tap-diameter-avp.c	\
	tap-endpoints.c		\
	tap-expert.c		\
	tap-follow.c		\
	tap-funnel.c		\
	tap-gsm_astat.c		\
	tap-hosts.c		\
	tap-httpstat.c		\
	tap-icmpstat.c		\
	tap-icmpv6stat.c	\
	tap-iostat.c		\
	tap-iousers.c		\
	tap-macltestat.c	\
	tap-protocolinfo.c	\
	tap-protohierstat.c	\
	tap-rlcltestat.c	\
	tap-rpcprogs.c		\
	tap-rtd.c		\
	tap-rtp.c		\
	tap-rtspstat.c		\
	tap-sctpchunkstat.c	\
	tap-simple_stattable.c	\
	tap-sipstat.c		\
	tap-smbsids.c		\
	tap-srt.c		\
	tap-stats_tree.c	\
	tap-sv.c		\
	tap-wspstat.c

noinst_HEADERS = \
	tshark-tap.h

# All sources that should be put in the source distribution tarball
libcliui_a_SOURCES = \
	$(TSHARK_TAP_SRC) \
	$(noinst_HEADERS) \
	$(GENERATED_HEADER_FILES) \
	$(GENERATED_C_FILES)

libcliui_a_DEPENDENCIES =

EXTRA_DIST = \
	.editorconfig		\
	$(GENERATOR_FILES)

CLEANFILES = \
	libcliui.a			\
	tshark-tap-register.c-tmp	\
	tshark-tap-register-cache.pkl	\
	*~

MAINTAINERCLEANFILES = \
	$(GENERATED_FILES)	\
	Makefile.in

#
# Build "tshark-tap-register.c", which contains a function
# "register_all_tap_listeners()"
# that calls the register routines for all tshark tap listeners.
#
# We do this by grepping through sources.
#
# Formatting conventions:  The name of the tap_listener_register_*
# routines must start in column zero, or must be preceded only by
# "void " starting in column zero, and must not be inside #if.
#
# The first argument is the directory in which the source files live.
# All subsequent arguments are the files to scan.
#
tshark-tap-register.c: $(TSHARK_TAP_SRC) $(top_srcdir)/tools/make-tap-reg.py
	@echo Making tshark-tap-register.c
	@$(PYTHON) $(top_srcdir)/tools/make-tap-reg.py $(srcdir) tshark-taps $(TSHARK_TAP_SRC)

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -build \
	-sourcedir=$(srcdir) $(TSHARK_TAP_SRC)
