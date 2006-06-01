# Makefile.am
# Automake file for Wireshark
#
# $Id$
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

SUBDIRS = lemon

PIDL_FILES= \
	pidl/MANIFEST					\
	pidl/Makefile.PL				\
	pidl/README					\
	pidl/TODO					\
	pidl/idl.yp					\
	pidl/lib/Parse/Pidl.pm				\
	pidl/lib/Parse/Pidl/Compat.pm			\
	pidl/lib/Parse/Pidl/Dump.pm			\
	pidl/lib/Parse/Pidl/Wireshark/Conformance.pm	\
	pidl/lib/Parse/Pidl/Wireshark/NDR.pm		\
	pidl/lib/Parse/Pidl/IDL.pm			\
	pidl/lib/Parse/Pidl/NDR.pm			\
	pidl/lib/Parse/Pidl/ODL.pm			\
	pidl/lib/Parse/Pidl/Samba4/COM/Header.pm	\
	pidl/lib/Parse/Pidl/Samba4/COM/Proxy.pm		\
	pidl/lib/Parse/Pidl/Samba4/COM/Stub.pm		\
	pidl/lib/Parse/Pidl/Samba4/EJS.pm		\
	pidl/lib/Parse/Pidl/Samba4/Header.pm		\
	pidl/lib/Parse/Pidl/Samba4/NDR/Client.pm	\
	pidl/lib/Parse/Pidl/Samba4/NDR/Parser.pm	\
	pidl/lib/Parse/Pidl/Samba4/NDR/Server.pm	\
	pidl/lib/Parse/Pidl/Samba4/SWIG.pm		\
	pidl/lib/Parse/Pidl/Samba4/TDR.pm		\
	pidl/lib/Parse/Pidl/Samba4/Template.pm		\
	pidl/lib/Parse/Pidl/Typelist.pm			\
	pidl/lib/Parse/Pidl/Util.pm			\
	pidl/pidl					\
	pidl/ref_notes.txt				\
	pidl/smb_interfaces.pm				\
	pidl/smb_interfaces.yp				\
	pidl/tests/Util.pm				\
	pidl/tests/ndr_align.pl				\
	pidl/tests/ndr_alloc.pl				\
	pidl/tests/ndr_array.pl				\
	pidl/tests/ndr_refptr.pl			\
	pidl/tests/ndr_simple.pl			\
	pidl/tests/ndr_string.pl			\
	pidl/tests/parse_idl.pl

EXTRA_DIST = \
	$(PIDL_FILES)					\
	WiresharkXML.py					\
	Makefile.nmake					\
	asn2wrs.py					\
	cvsdiff-fix.py					\
	dfilter-test.py 				\
	fuzz-test.sh					\
	idl2wrs.sh					\
	lex.py						\
	make-dissector-reg				\
	make-dissector-reg.py				\
	msnchat						\
	netscreen2dump.py				\
	pkt-from-core.py				\
	unix2dos.pl					\
	win32-setup.sh					\
	wireshark_be.py					\
	wireshark_gen.py				\
	yacc.py

MAINTAINERCLEANFILES = \
	Makefile.in

