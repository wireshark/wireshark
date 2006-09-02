# Makefile.am
# Automake file for the codecs for Wireshark
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@xxxxxxxxxxxxx>
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


noinst_LIBRARIES = libcodec.a

CLEANFILES = \
       libcodec.a	\
       *~

MAINTAINERCLEANFILES =	\
       Makefile.in

libcodec_a_SOURCES = \
       G711a/G711adecode.c G711a/G711adecode.h G711a/G711atable.h	\
       G711u/G711udecode.c G711u/G711udecode.h G711u/G711utable.h 

libcodec_a_DEPENDENCIES = 

EXTRA_DIST = \
       Makefile.nmake 

