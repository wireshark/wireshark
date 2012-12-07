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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

SUBDIRS = lemon

PIDL_FILES= \
	pidl/MANIFEST					\
	pidl/META.yml					\
	pidl/Makefile.PL				\
	pidl/README					\
	pidl/TODO					\
	pidl/expr.yp					\
	pidl/idl.yp					\
	pidl/lib/Parse/Pidl.pm				\
	pidl/lib/Parse/Pidl/CUtil.pm			\
	pidl/lib/Parse/Pidl/Compat.pm			\
	pidl/lib/Parse/Pidl/Dump.pm			\
	pidl/lib/Parse/Pidl/Expr.pm			\
	pidl/lib/Parse/Pidl/IDL.pm			\
	pidl/lib/Parse/Pidl/NDR.pm			\
	pidl/lib/Parse/Pidl/ODL.pm			\
	pidl/lib/Parse/Pidl/Samba3/ClientNDR.pm		\
	pidl/lib/Parse/Pidl/Samba3/ServerNDR.pm		\
	pidl/lib/Parse/Pidl/Samba4.pm			\
	pidl/lib/Parse/Pidl/Samba4/COM/Header.pm	\
	pidl/lib/Parse/Pidl/Samba4/COM/Proxy.pm		\
	pidl/lib/Parse/Pidl/Samba4/COM/Stub.pm		\
	pidl/lib/Parse/Pidl/Samba4/Header.pm		\
	pidl/lib/Parse/Pidl/Samba4/NDR/Client.pm	\
	pidl/lib/Parse/Pidl/Samba4/NDR/Parser.pm	\
	pidl/lib/Parse/Pidl/Samba4/NDR/Server.pm	\
	pidl/lib/Parse/Pidl/Samba4/Python.pm		\
	pidl/lib/Parse/Pidl/Samba4/TDR.pm		\
	pidl/lib/Parse/Pidl/Samba4/Template.pm		\
	pidl/lib/Parse/Pidl/Typelist.pm			\
	pidl/lib/Parse/Pidl/Util.pm			\
	pidl/lib/Parse/Pidl/Wireshark/Conformance.pm	\
	pidl/lib/Parse/Pidl/Wireshark/NDR.pm		\
	pidl/lib/Parse/Yapp/Driver.pm			\
	pidl/pidl					\
	pidl/tests/Util.pm				\
	pidl/tests/cutil.pl				\
	pidl/tests/dump.pl				\
	pidl/tests/header.pl				\
	pidl/tests/ndr.pl				\
	pidl/tests/ndr_align.pl				\
	pidl/tests/ndr_alloc.pl				\
	pidl/tests/ndr_array.pl				\
	pidl/tests/ndr_compat.pl			\
	pidl/tests/ndr_deprecations.pl			\
	pidl/tests/ndr_fullptr.pl			\
	pidl/tests/ndr_refptr.pl			\
	pidl/tests/ndr_represent.pl			\
	pidl/tests/ndr_simple.pl			\
	pidl/tests/ndr_string.pl			\
	pidl/tests/ndr_tagtype.pl			\
	pidl/tests/parse_idl.pl				\
	pidl/tests/samba-ndr.pl				\
	pidl/tests/samba3-cli.pl			\
	pidl/tests/samba3-srv.pl			\
	pidl/tests/tdr.pl				\
	pidl/tests/test_util.pl				\
	pidl/tests/typelist.pl				\
	pidl/tests/util.pl				\
	pidl/tests/wireshark-conf.pl			\
	pidl/tests/wireshark-ndr.pl

EXTRA_DIST = \
	$(PIDL_FILES)					\
	asn2wrs.py					\
	checkhf.pl					\
	colorfilters2js.pl				\
	compare-abis.sh					\
	checkAPIs.pl					\
	cppcheck/cppcheck.sh				\
	cppcheck/includes				\
	cppcheck/suppressions				\
	dfilter-test.py 				\
	extract_asn1_from_spec.pl			\
	fix-encoding-args.pl				\
	fixhf.pl					\
	ftsanity.py					\
	fuzz-test.sh					\
	html2text.py					\
	idl2wrs						\
	indexcap.py					\
	lex.py						\
	list_protos_in_cap.sh				\
	Makefile.nmake					\
	make-dissector-reg				\
	make-dissector-reg.py				\
	make-manuf					\
	make-sminmpec.pl 				\
	make-services.pl 				\
	make-tapreg-dotc				\
	make-tap-reg.py					\
	msnchat						\
	native-nmake.cmd				\
	ncp2222.py					\
	netscreen2dump.py				\
	pkt-from-core.py				\
	process-x11-fields.pl				\
	process-x11-xcb.pl				\
	randpkt-test.sh					\
	rdps.py						\
	runlex.sh					\
	setuid-root.pl.in				\
	test-common.sh					\
	test-fuzzed-cap.sh				\
	textify.sh 					\
	valgrind-wireshark.sh				\
	win32-setup.sh					\
	win64-setup.sh					\
	win-setup.sh					\
	wireshark_be.py					\
	wireshark_gen.py				\
	WiresharkXML.py					\
	ws-coding-style.cfg				\
	yacc.py

noinst_SCRIPTS = setuid-root.pl
setuid-root.pl: setuid-root.pl.in Makefile
	sed \
		-e 's,@BIN_PREFIX\@,$(bindir),' \
		-e 's,@TSHARK_BIN\@,$(tshark_bin)$(EEXT),' \
		-e 's,@DUMPCAP_BIN\@,$(dumpcap_bin)$(EEXT),' \
		< $(srcdir)/setuid-root.pl.in > setuid-root.pl
	chmod +x setuid-root.pl

CLEANFILES = \
	*.pyc

DISTCLEANFILES = \
	setuid-root.pl

MAINTAINERCLEANFILES = \
	Makefile.in
