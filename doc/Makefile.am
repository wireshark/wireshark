# Makefile.am
# Automake file for Ethereal documentation
#
# $Id: Makefile.am,v 1.13 2002/02/05 18:39:06 gram Exp $
#
# Ethereal - Network traffic analyzer
# By Gerald Combs <gerald@zing.org>
# Copyright 1998 Gerald Combs
#
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

../ethereal.1: ethereal.pod ../config.h
	$(POD2MAN) ethereal.pod                     \
	--center="The Ethereal Network Analyzer" \
	--release=$(VERSION)			 \
	> ../ethereal.1

ethereal.pod: ethereal.pod.template  ../ethereal
	../ethereal -G | $(PERL) $(srcdir)/dfilter2pod.pl $(srcdir)/ethereal.pod.template > ethereal.pod

../tethereal.1: tethereal.pod ../config.h
	$(POD2MAN) tethereal.pod                     \
	--center="The Ethereal Network Analyzer" \
	--release=$(VERSION)			 \
	> ../tethereal.1

tethereal.pod: tethereal.pod.template  ../tethereal
	../tethereal -G | $(PERL) $(srcdir)/dfilter2pod.pl $(srcdir)/tethereal.pod.template > tethereal.pod

../editcap.1: editcap.pod ../config.h
	$(POD2MAN) $(srcdir)/editcap.pod                     \
	--center="The Ethereal Network Analyzer" \
	--release=$(VERSION)			 \
	> ../editcap.1

../idl2eth.1: idl2eth.pod ../config.h
	$(POD2MAN) $(srcdir)/idl2eth.pod                     \
	--center="The Ethereal Network Analyzer" \
	--release=$(VERSION)			 \
	> ../idl2eth.1

../mergecap.1: mergecap.pod ../config.h
	$(POD2MAN) $(srcdir)/mergecap.pod                     \
	--center="The Ethereal Network Analyzer" \
	--release=$(VERSION)			 \
	> ../mergecap.1

../text2pcap.1: text2pcap.pod ../config.h
	$(POD2MAN) $(srcdir)/text2pcap.pod                     \
	--center="The Ethereal Network Analyzer" \
	--release=$(VERSION)			 \
	> ../text2pcap.1
