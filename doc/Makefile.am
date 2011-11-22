# Makefile.am
# Automake file for Wireshark documentation
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
	@wireshark_man@	\
	@tshark_man@	\
	@text2pcap_man@	\
	@mergecap_man@	\
	@capinfos_man@	\
	@editcap_man@	\
	@dumpcap_man@	\
	idl2wrs.1	\
	@rawshark_man@	\
	@dftest_man@	\
	@randpkt_man@
man4_MANS = @wiresharkfilter_man@
man_MANS =

pkgdata_DATA = AUTHORS-SHORT $(top_srcdir)/docbook/ws.css wireshark.html \
	tshark.html wireshark-filter.html capinfos.html editcap.html \
	idl2wrs.html mergecap.html text2pcap.html dumpcap.html rawshark.html \
	dftest.html randpkt.html

#
# Build the short version of the authors file for the about dialog
#
AUTHORS-SHORT: $(top_srcdir)/AUTHORS $(srcdir)/make-authors-short.pl
	$(PERL) $(srcdir)/perlnoutf.pl $(srcdir)/make-authors-short.pl < $(top_srcdir)/AUTHORS > AUTHORS-SHORT

# Put a copy in the top-level directory so Help->About, when run from the
# build directory, can find it.
../AUTHORS-SHORT: AUTHORS-SHORT
	cp AUTHORS-SHORT ..

#
# Build the short version of the authors file with formatting codes for the
# man page
# (Depending on ../AUTHORS-SHORT is a bit of a hack to get the file copied
# down there.)
#
AUTHORS-SHORT-FORMAT: ../AUTHORS-SHORT $(srcdir)/make-authors-format.pl
	$(PERL) $(srcdir)/perlnoutf.pl $(srcdir)/make-authors-format.pl < AUTHORS-SHORT > AUTHORS-SHORT-FORMAT

wireshark.pod: $(srcdir)/wireshark.pod.template AUTHORS-SHORT-FORMAT
	cat $(srcdir)/wireshark.pod.template AUTHORS-SHORT-FORMAT > wireshark.pod

wireshark.1: wireshark.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	wireshark.pod  > wireshark.1

wireshark.html: wireshark.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)						\
	--title="The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css			\
	--noindex						\
	wireshark.pod > wireshark.html

tshark.1: tshark.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/tshark.pod > tshark.1

tshark.html: tshark.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)							\
	--title="tshark - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css				\
	--noindex							\
	$(srcdir)/tshark.pod > tshark.html

wireshark-filter.4: wireshark-filter.pod ../config.h
	$(POD2MAN)					\
	--section=4					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/wireshark-filter.pod > wireshark-filter.4

wireshark-filter.html: wireshark-filter.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)								\
	--title="wireshark-filter - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css					\
	--noindex								\
	$(srcdir)/wireshark-filter.pod > wireshark-filter.html

capinfos.1: capinfos.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/capinfos.pod > capinfos.1

capinfos.html: capinfos.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)							\
	--title="capinfos - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css				\
	--noindex							\
	$(srcdir)/capinfos.pod > capinfos.html

editcap.1: editcap.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/editcap.pod > editcap.1

editcap.html: editcap.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)							\
	--title="editcap - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css				\
	--noindex							\
	$(srcdir)/editcap.pod > editcap.html

idl2wrs.1: idl2wrs.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/idl2wrs.pod > idl2wrs.1

idl2wrs.html: idl2wrs.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)							\
	--title="idl2wrs - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css				\
	--noindex							\
	$(srcdir)/idl2wrs.pod > idl2wrs.html

mergecap.1: mergecap.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/mergecap.pod > mergecap.1

mergecap.html: mergecap.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)							\
	--title="mergecap - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css				\
	--noindex							\
	$(srcdir)/mergecap.pod > mergecap.html

text2pcap.1: text2pcap.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/text2pcap.pod > text2pcap.1

text2pcap.html: text2pcap.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)                     \
	--title="text2pcap - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css				\
	--noindex							\
	$(srcdir)/text2pcap.pod > text2pcap.html

dumpcap.1: dumpcap.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/dumpcap.pod > dumpcap.1

dumpcap.html: dumpcap.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)                     \
	--title="dumpcap - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css				\
	--noindex							\
	$(srcdir)/dumpcap.pod > dumpcap.html

rawshark.1: rawshark.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/rawshark.pod > rawshark.1

rawshark.html: rawshark.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)                     \
	--title="rawshark - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css				\
	--noindex							\
	$(srcdir)/rawshark.pod > rawshark.html

dftest.1: dftest.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/dftest.pod > dftest.1

dftest.html: dftest.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)                     \
	--title="dftest - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css				\
	--noindex							\
	$(srcdir)/dftest.pod > dftest.html

randpkt.1: randpkt.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/randpkt.pod > randpkt.1

randpkt.html: randpkt.pod ../config.h $(top_srcdir)/docbook/ws.css
	$(POD2HTML)                     \
	--title="randpkt - The Wireshark Network Analyzer $(VERSION)"	\
	--css=$(top_srcdir)/docbook/ws.css				\
	--noindex							\
	$(srcdir)/randpkt.pod > randpkt.html

CLEANFILES =		\
	wireshark.pod \
	wireshark-filter.4 \
	wireshark-filter.html \
	wireshark.1	\
	wireshark.html	\
	capinfos.1	\
	capinfos.html	\
	dftest.1	\
	dftest.html	\
	dumpcap.1	\
	dumpcap.html	\
	editcap.1	\
	editcap.html	\
	idl2wrs.1	\
	idl2wrs.html	\
	mergecap.1	\
	mergecap.html	\
	randpkt.1	\
	randpkt.html	\
	rawshark.1	\
	rawshark.html	\
	text2pcap.1	\
	text2pcap.html	\
	tshark.1	\
	tshark.html

DISTCLEANFILES =		\
	pod2htmi.tmp		\
	pod2htmd.tmp		\
	AUTHORS-SHORT		\
	../AUTHORS-SHORT	\
	AUTHORS-SHORT-FORMAT	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

EXTRA_DIST = \
	Makefile.nmake	\
	README.binarytrees	\
	README.capture	\
	README.design	\
	README.developer	\
	README.display_filter	\
	README.heuristic	\
	README.idl2wrs	\
	README.malloc	\
	README.packaging	\
	README.plugins	\
	README.python \
	README.regression   \
	README.request_response_tracking	\
	README.stats_tree	\
	README.tapping	\
	README.xml-output	\
	doc.vcproj		\
	make-authors-format.pl	\
	make-authors-short.pl	\
	perlnoutf.pl		\
	capinfos.pod		\
	dfilter2pod.pl		\
	dftest.pod		\
	dumpcap.pod		\
	editcap.pod		\
	eproto2sgml		\
	idl2wrs.pod		\
	mergecap.pod		\
	randpkt.pod		\
	randpkt.txt		\
	rawshark.pod		\
	sgml.doc.template	\
	text2pcap.pod		\
	tshark.pod		\
	wireshark-filter.pod    \
	wireshark.pod.template

