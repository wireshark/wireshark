# Makefile.am
# Automake file for listen_rtp Ethereal plugin
#
# $Id$
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@ethereal.com>
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#

INCLUDES = -I$(top_srcdir) @PORTAUDIO_INCLUDES@

plugindir = @plugindir@

plugin_LTLIBRARIES = listen_rtp.la

listen_rtp_la_SOURCES = \
	listen_rtp_plugin.c \
	main_listen_rtp.c \
	main_listen_rtp.h \
	codecs/G711a/G711adecode.c codecs/G711a/G711adecode.h \
	codecs/G711u/G711udecode.c codecs/G711u/G711udecode.h
	
listen_rtp_la_LDFLAGS = -module -avoid-version
listen_rtp_la_LIBADD = @PLUGIN_LIBS@ @PORTAUDIO_LIBS@

# Libs must be cleared, or else libtool won't create a shared module.
# If your module needs to be linked against any particular libraries,
# add them here.
LIBS = 

CLEANFILES = \
	listen_rtp \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	Makefile.nmake
