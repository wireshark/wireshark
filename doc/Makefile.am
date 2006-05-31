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

ethereal-tmp.pod: $(srcdir)/ethereal.pod $(top_builddir)/AUTHORS-SHORT-FORMAT
	cat $(srcdir)/ethereal.pod $(top_builddir)/AUTHORS-SHORT-FORMAT > ethereal-tmp.pod

../ethereal.1: ethereal-tmp.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	ethereal-tmp.pod | sed 's/ETHEREAL-TMP/ETHEREAL/' > ../ethereal.1

../ethereal.html: ethereal-tmp.pod ../config.h
	$(POD2HTML)						\
	--title="The Wireshark Network Analyzer $(VERSION)"	\
	--noindex						\
	ethereal-tmp.pod > ../ethereal.html

../tshark.1: tshark.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/tshark.pod > ../tshark.1

../tshark.html: tshark.pod ../config.h
	$(POD2HTML)							\
	--title="tshark - The Wireshark Network Analyzer $(VERSION)"	\
	--noindex							\
	$(srcdir)/tshark.pod > ../tshark.html

../ethereal-filter.4: ethereal-filter.pod ../config.h
	$(POD2MAN)					\
	--section=4					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	ethereal-filter.pod > ../ethereal-filter.4

../ethereal-filter.html: ethereal-filter.pod ../config.h
	$(POD2HTML)								\
	--title="ethereal-filter - The Wireshark Network Analyzer $(VERSION)"	\
	--noindex								\
	ethereal-filter.pod > ../ethereal-filter.html

ethereal-filter.pod: ethereal-filter.pod.template  ../tshark
	../tshark -G fields | $(PERL) $(srcdir)/dfilter2pod.pl $(srcdir)/ethereal-filter.pod.template > ethereal-filter.pod

../capinfos.1: capinfos.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/capinfos.pod > ../capinfos.1

../capinfos.html: capinfos.pod ../config.h
	$(POD2HTML)							\
	--title="capinfos - The Wireshark Network Analyzer $(VERSION)"	\
	--noindex							\
	$(srcdir)/capinfos.pod > ../capinfos.html

../editcap.1: editcap.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/editcap.pod > ../editcap.1

../editcap.html: editcap.pod ../config.h
	$(POD2HTML)							\
	--title="editcap - The Wireshark Network Analyzer $(VERSION)"	\
	--noindex							\
	$(srcdir)/editcap.pod > ../editcap.html

../idl2wrs.1: idl2wrs.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/idl2wrs.pod > ../idl2wrs.1

../idl2wrs.html: idl2wrs.pod ../config.h
	$(POD2HTML)							\
	--title="idl2wrs - The Wireshark Network Analyzer $(VERSION)"	\
	--noindex							\
	$(srcdir)/idl2wrs.pod > ../idl2wrs.html

../mergecap.1: mergecap.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/mergecap.pod > ../mergecap.1

../mergecap.html: mergecap.pod ../config.h
	$(POD2HTML)							\
	--title="mergecap - The Wireshark Network Analyzer $(VERSION)"	\
	--noindex							\
	$(srcdir)/mergecap.pod > ../mergecap.html

../text2pcap.1: text2pcap.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/text2pcap.pod > ../text2pcap.1

../text2pcap.html: text2pcap.pod ../config.h
	$(POD2HTML)                     \
	--title="text2pcap - The Wireshark Network Analyzer $(VERSION)"	\
	--noindex							\
	$(srcdir)/text2pcap.pod > ../text2pcap.html

../dumpcap.1: dumpcap.pod ../config.h
	$(POD2MAN)					\
	--center="The Wireshark Network Analyzer"	\
	--release=$(VERSION)				\
	$(srcdir)/dumpcap.pod > ../dumpcap.1

../dumpcap.html: dumpcap.pod ../config.h
	$(POD2HTML)                     \
	--title="dumpcap - The Wireshark Network Analyzer $(VERSION)"	\
	--noindex							\
	$(srcdir)/dumpcap.pod > ../dumpcap.html

CLEANFILES =		\
	ethereal-filter.pod \
	ethereal-tmp.pod \
	../ethereal-filter.4 \
	../ethereal-filter.html \
	../ethereal.1	\
	../ethereal.html	\
	../capinfos.1	\
	../capinfos.html	\
	../editcap.1	\
	../editcap.html	\
	../mergecap.1	\
	../mergecap.html	\
	../tshark.1	\
	../tshark.html	\
	../text2pcap.1	\
	../text2pcap.html	\
	../dumpcap.1	\
	../dumpcap.html	\
	../idl2wrs.1	\
	../idl2wrs.html

DISTCLEANFILES =	\
	pod2htmi.tmp	\
	pod2htmd.tmp	\
	*~

MAINTAINERCLEANFILES = \
	Makefile.in

