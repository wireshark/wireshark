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

# Generated files not in the distribution.
NODIST_GENERATED_FILES = \
	tshark-tap-register.c

# sources for TShark taps
TSHARK_TAP_SRC = \
	tap-camelsrt.c		\
	tap-comparestat.c	\
	tap-diameter-avp.c	\
	tap-endpoints.c		\
	tap-endpoints.c		\
	tap-expert.c		\
	tap-exportobject.c	\
	tap-flow.c			\
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
	tap-exportobject.h 	\
	tshark-tap.h

# All sources that should be put in the source distribution tarball
libcliui_a_SOURCES = \
	$(TSHARK_TAP_SRC)

nodist_libcliui_a_SOURCES = \
	$(NODIST_GENERATED_FILES)

EXTRA_DIST = \
	.editorconfig

DISTCLEANFILES = \
	$(NODIST_GENERATED_FILES)

tshark-tap-register.c: $(TSHARK_TAP_SRC) ../make-taps
	$(AM_V_GEN)../make-taps $@ $(filter %.c,$^)

doxygen:
if HAVE_DOXYGEN
	$(DOXYGEN) doxygen.cfg
endif		# HAVE_DOXYGEN

checkapi:
	$(PERL) $(top_srcdir)/tools/checkAPIs.pl -build \
	-sourcedir=$(srcdir) $(TSHARK_TAP_SRC)
