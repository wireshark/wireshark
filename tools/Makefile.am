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

EXTRA_DIST = \
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
	cppcheck					\
	debian-setup.sh					\
	dfilter-test.py					\
	dftestfiles					\
	dftestlib					\
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
	make-dissector-reg.py				\
	make-manuf					\
	make-sminmpec.pl				\
	make-services.pl				\
	make-services.py				\
	make-tap-reg.py					\
	make-usb.py					\
	make_charset_table.c				\
	msnchat						\
	ncp2222.py					\
	netscreen2dump.py				\
	npl						\
	parse_xml2skinny_dissector.py			\
	pidl						\
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
	tpg						\
	usb-ptp-extract-models.pl			\
	usb-ptp-extract-models.txt			\
	valgrind-wireshark.sh				\
	vg-suppressions					\
	win-setup.ps1					\
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
