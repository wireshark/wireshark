# Makefile.am
# Automake file for Wireshark documentation
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

# We include dependencies on ../config.h in order to
# capture when $(VERSION) changes.

#
# This is a hideous hack.
#
# Automake needs to know into which sections to install various man
# pages; if the names in "man_MANS" have suffixes, it can infer the
# sections from the name (e.g., "hello.1" goes in section 1), but if
# they don't have suffixes, it can't tell what sections to put them, and
# it just gives up and doesn't create any rules to install them (and it
# gives up silently, so you have no clue what's wrong).
#
# Therefore, we can't just set "man_MANS" to a list of variables to be
# filled in by the configure script, as those variables don't have man
# page section numbers.
#
# It turns out (although this is not documented anywhere I could find
# in the automake Info file) that if you define, instead, variables with
# names like "man{section}_MANS", automake will infer that the names in
# those variables are the names of man pages to be installed in section
# "{section}".
#
# So we define "man1_MANS" to contain all the section 1 man pages and
# man4_MANS for the (one) section 4 man page.
#
# *However*, if "man_MANS" isn't defined at all, automake concludes that
# there are no man pages, the fact that, say, "man1_MANS" is defined
# nonwithstanding!  (I suspect this is the result of a mistaken attempt
# to get people to fix their automake files not to use "MANS"; if "MANS"
# is defined, it prints a warning and sets the exit status, but doesn't
# exit, and then it just gives up if "man_MANS" isn't defined,
# presumably on the theory that the only reason it wouldn't be defined
# is because the automake file uses the obsolete "MANS" variable instead
# of the shiny new "man_MANS" variable.)
#
# So we also define "man_MANS", but don't define it as anything;
# automake will arrange that the Makefile define it as the union of all
# the "man{section}_MANS" variables.
#
man1_MANS = \
	@wireshark_man@		\
	@tshark_man@		\
	@text2pcap_man@		\
	@mergecap_man@		\
	@reordercap_man@	\
	@capinfos_man@		\
	@editcap_man@		\
	@dumpcap_man@		\
	@rawshark_man@		\
	@dftest_man@		\
	@randpkt_man@		\
	@androiddump_man@	\
	@sshdump_man@		\
	@randpktdump_man@

man4_MANS = \
	@extcap_man@		\
	@wiresharkfilter_man@
man_MANS =

# Build these in case a developer wants to read them and for the Debian
# development package.
# (The former arguably should be in noinst_MANS but it didn't work for me.)
noinst_DATA = asn2deb.1 asn2deb.html idl2deb.1 idl2deb.html idl2wrs.1 idl2wrs.html

pkgdata_DATA = AUTHORS-SHORT $(top_srcdir)/docbook/ws.css wireshark.html \
	tshark.html wireshark-filter.html capinfos.html ciscodump.html editcap.html \
	mergecap.html reordercap.html text2pcap.html dumpcap.html androiddump.html \
	sshdump.html randpktdump.html rawshark.html dftest.html randpkt.html \
	extcap.html

#
# Build the short version of the authors file for the about dialog
# Put a copy in the top-level directory so Help->About, when run from the
# build directory, can find it.
#
AUTHORS-SHORT: $(top_srcdir)/AUTHORS $(srcdir)/make-authors-short.pl
	$(AM_V_GEN)$(PERL) $(srcdir)/perlnoutf.pl $(srcdir)/make-authors-short.pl \
		< $(top_srcdir)/AUTHORS > AUTHORS-SHORT && \
		cp $@ $(top_builddir)

#
# Build the short version of the authors file with formatting codes for the
# man page
#
AUTHORS-SHORT-FORMAT: AUTHORS-SHORT $(srcdir)/make-authors-format.pl
	$(AM_V_GEN)$(PERL) $(srcdir)/perlnoutf.pl $(srcdir)/make-authors-format.pl \
		< AUTHORS-SHORT > AUTHORS-SHORT-FORMAT

wireshark.pod: $(srcdir)/wireshark.pod.template AUTHORS-SHORT-FORMAT
	$(AM_V_GEN)cat $(srcdir)/wireshark.pod.template AUTHORS-SHORT-FORMAT > wireshark.pod

AM_V_POD2MAN = $(am__v_POD2MAN_@AM_V@)
am__v_POD2MAN_ = $(am__v_POD2MAN_@AM_DEFAULT_V@)
am__v_POD2MAN_0 = @echo "  POD2MAN " $@;

AM_V_POD2HTML = $(am__v_POD2HTML_@AM_V@)
am__v_POD2HTML_ = $(am__v_POD2HTML_@AM_DEFAULT_V@)
am__v_POD2HTML_0 = @echo "  POD2HTML" $@;

POD_CSS_URL ?= $(top_srcdir)/docbook/ws.css

.pod.1: ../config.h
	$(AM_V_POD2MAN)$(POD2MAN)                       \
	--center="The Wireshark Network Analyzer"       \
	--release=$(VERSION)                            \
	$< > $@

.pod.html: ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)                             \
	--title="The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)					\
	--noindex						\
	$< > $@

# These rules need to stay separate because of the --section option.
wireshark-filter.4: wireshark-filter.pod ../config.h
	$(AM_V_POD2MAN)$(POD2MAN)			\
	--section=4					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/wireshark-filter.pod > wireshark-filter.4

extcap.4: extcap.pod ../config.h
	$(AM_V_POD2MAN)$(POD2MAN)			\
	--section=4					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/extcap.pod > extcap.4

# These rules need to stay separate because each man page has a separate
# title.  Using GNU make's pattern rules would allow these to be removed
# but at the cost of portability.
tshark.html: tshark.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)					\
	--title="tshark - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/tshark.pod > tshark.html

wireshark-filter.html: wireshark-filter.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)						\
	--title="wireshark-filter - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)							\
	--noindex								\
	$(srcdir)/wireshark-filter.pod > wireshark-filter.html

extcap.html: extcap.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)						\
	--title="extcap - The Wireshark Network Analyzer $(VERSION)"		\
	--css=$(POD_CSS_URL)							\
	--noindex								\
	$(srcdir)/extcap.pod > extcap.html

capinfos.html: capinfos.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)					\
	--title="capinfos - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/capinfos.pod > capinfos.html

editcap.html: editcap.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)					\
	--title="editcap - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/editcap.pod > editcap.html

idl2wrs.html: idl2wrs.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)					\
	--title="idl2wrs - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/idl2wrs.pod > idl2wrs.html

mergecap.html: mergecap.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)					\
	--title="mergecap - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/mergecap.pod > mergecap.html

reordercap.html: reordercap.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)					\
	--title="reordercap - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/reordercap.pod > reordercap.html

text2pcap.html: text2pcap.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)                     \
	--title="text2pcap - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/text2pcap.pod > text2pcap.html

dumpcap.html: dumpcap.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)                     \
	--title="dumpcap - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/dumpcap.pod > dumpcap.html

androiddump.html: androiddump.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)                     \
	--title="androiddump - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/androiddump.pod > androiddump.html

sshdump.html: sshdump.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)                     \
	--title="sshdump - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/sshdump.pod > sshdump.html

ciscodump.html: ciscodump.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)                     \
	--title="ciscodump - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/ciscodump.pod > ciscodump.html

randpktdump.html: randpktdump.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)                     \
	--title="randpktdump - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/randpktdump.pod > randpktdump.html

rawshark.html: rawshark.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)                     \
	--title="rawshark - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/rawshark.pod > rawshark.html

dftest.html: dftest.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)                     \
	--title="dftest - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/dftest.pod > dftest.html

randpkt.html: randpkt.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(AM_V_POD2HTML)$(POD2HTML)                     \
	--title="randpkt - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(POD_CSS_URL)						\
	--noindex							\
	$(srcdir)/randpkt.pod > randpkt.html

CLEANFILES =		\
	wireshark.pod	\
	*.1		\
	*.4		\
	*.html

DISTCLEANFILES =		\
	pod2htmi.tmp		\
	pod2htmd.tmp		\
	AUTHORS-SHORT		\
	../AUTHORS-SHORT	\
	AUTHORS-SHORT-FORMAT	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST =				\
	README.capture			\
	README.design			\
	README.developer		\
	README.display_filter		\
	README.dissector		\
	README.epan_child		\
	README.extcap			\
	README.heuristic		\
	README.idl2wrs			\
	README.packaging		\
	README.plugins			\
	README.qt			\
	README.regression   		\
	README.request_response_tracking\
	README.stats_tree		\
	README.tapping			\
	README.wmem			\
	README.wslua			\
	README.xml-output		\
	androiddump.pod			\
	asn2deb.pod			\
	capinfos.pod			\
	captype.pod			\
	ciscodump.pod			\
	dfilter2pod.pl			\
	dftest.pod			\
	dumpcap.pod			\
	editcap.pod			\
	extcap.pod			\
	eproto2sgml			\
	idl2deb.pod			\
	idl2wrs.pod			\
	make-authors-format.pl		\
	make-authors-short.pl		\
	mergecap.pod			\
	packet-PROTOABBREV.c		\
	perlnoutf.pl			\
	randpkt.pod			\
	randpkt.txt			\
	randpktdump.pod			\
	rawshark.pod			\
	reordercap.pod			\
	sgml.doc.template		\
	sshdump.pod			\
	text2pcap.pod			\
	tshark.pod			\
	wireshark-filter.pod    	\
	wireshark.pod.template		\
	CMakeLists.txt

