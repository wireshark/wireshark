# Makefile.am
# Automake file for the airpdcap for Wireshark
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


noinst_LIBRARIES = airpdcap.a

CLEANFILES = \
       airpdcap.a	\
       *~

MAINTAINERCLEANFILES =	\
       Makefile.in

airpdcap_a_SOURCES = \
       airpdcap.c \
       airpdcap_ccmp.c airpdcap_ccmp.h	\
       airpdcap_debug.c airpdcap_debug.h	\
       airpdcap_md5.c airpdcap_md5.h	\
       airpdcap_rijndael.c airpdcap_rijndael.h	\ 
       airpdcap_sha1.c airpdcap_sha1.h	\
       airpdcap_tkip.c airpdcap_tkip.h	\
       airpdcap_wep.c airpdcap_wep.h   \
       airpdcap_interop.h \
       airpdcap_ws.h \
       airpdcap_types.h	\
       airpdcap_user.h \
       airpdcap_system.h

airpdcap_a_DEPENDENCIES = 

EXTRA_DIST = \
       Makefile.nmake 
