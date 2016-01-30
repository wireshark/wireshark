# Makefile.am
# Automake file for Wireshark
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
	pidl/lib/wscript_build				\
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
	pidl/tests/wireshark-ndr.pl			\
	pidl/wscript

EXTRA_DIST = \
	$(PIDL_FILES)					\
	asn2deb						\
	asn2wrs.py					\
	checkfiltername.pl				\
	checkhf.pl					\
	checklicenses.py				\
	colorfilters2js.pl				\
	commit-msg					\
	compare-abis.sh					\
	checkAPIs.pl					\
	convert-proto-tree-new.awk			\
	convert_expert_add_info_format.pl		\
	convert_proto_tree_add_text.pl			\
	cppcheck/cppcheck.sh				\
	cppcheck/includes				\
	cppcheck/suppressions				\
	debian-setup.sh					\
	dfilter-test.py					\
	dftestfiles/arp.pcap				\
	dftestfiles/http.pcap				\
	dftestfiles/ipv6.pcap				\
	dftestfiles/ipx_rip.pcap			\
	dftestfiles/nfs.pcap				\
	dftestfiles/ntp.pcap				\
	dftestfiles/tftp.pcap				\
	dftestlib/__init__.py				\
	dftestlib/bytes_ether.py			\
	dftestlib/bytes_ipv6.py				\
	dftestlib/bytes_type.py				\
	dftestlib/dftest.py				\
	dftestlib/double.py				\
	dftestlib/integer.py				\
	dftestlib/integer_1byte.py			\
	dftestlib/ipv4.py				\
	dftestlib/range_method.py			\
	dftestlib/scanner.py				\
	dftestlib/string_type.py			\
	dftestlib/stringz.py				\
	dftestlib/time_relative.py			\
	dftestlib/time_type.py				\
	dftestlib/tvb.py				\
	dftestlib/uint64.py				\
	dftestlib/util.py				\
	extract_asn1_from_spec.pl			\
	fix-encoding-args.pl				\
	fixhf.pl					\
	ftsanity.py					\
	fuzz-test.sh					\
	gen-bugnote					\
	generate-bacnet-vendors.py			\
	generate-sysdig-event.py			\
	Get-HardenFlags.ps1				\
	git-compare-abis.sh				\
	git-export-release.sh				\
	html2text.py					\
	idl2deb						\
	idl2wrs						\
	indexcap.py					\
	install_rpms_for_devel.sh			\
	lex.py						\
	list_protos_in_cap.sh				\
	Makefile.nmake					\
	make-dissector-reg.py				\
	make-manuf					\
	make-sminmpec.pl				\
	make-services.pl				\
	make-services.py				\
	make-tap-reg.py					\
	make-usb.py					\
	make_charset_table.c				\
	msnchat						\
	native-nmake.cmd				\
	ncp2222.py					\
	netscreen2dump.py				\
	npl/ast.h					\
	npl/npl.c					\
	npl/parser.l					\
	npl/xmem.h					\
	parse_xml2skinny_dissector.py			\
	pkt-from-core.py				\
	pre-commit					\
	pre-commit-ignore.conf				\
	pre-commit-ignore.py				\
	process-x11-fields.pl				\
	process-x11-xcb.pl				\
	randpkt-test.sh					\
	rdps.py						\
	runa2x.sh					\
	runlex.sh					\
	setuid-root.pl.in				\
	test-common.sh					\
	test-captures.sh				\
	textify.ps1					\
	tpg/Makefile.am					\
	tpg/Makefile.nmake				\
	tpg/V2P.pm					\
	tpg/tpg.pl					\
	tpg/tpg.yp					\
	usb-ptp-extract-models.pl			\
	usb-ptp-extract-models.txt			\
	valgrind-wireshark.sh				\
	vg-suppressions					\
	win-setup.ps1					\
	win-setup.sh					\
	wireshark_be.py					\
	wireshark_gen.py				\
	WiresharkXML.py					\
	ws-coding-style.cfg				\
	yacc.py

noinst_SCRIPTS = setuid-root.pl

setuid-root.pl: setuid-root.pl.in Makefile
	$(AM_V_SED)$(SED) \
		-e 's,@BIN_PREFIX\@,$(bindir),' \
		-e 's,@TSHARK_BIN\@,$(tshark_bin)$(EEXT),' \
		-e 's,@DUMPCAP_BIN\@,$(dumpcap_bin)$(EEXT),' \
		< $(srcdir)/setuid-root.pl.in > setuid-root.pl; \
	chmod +x setuid-root.pl

CLEANFILES = \
	*.pyc

DISTCLEANFILES = \
	setuid-root.pl

MAINTAINERCLEANFILES = \
	Makefile.in
