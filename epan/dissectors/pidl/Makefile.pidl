# Makefile
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 2004 Gerald Combs
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

PIDL = ../../../../tools/pidl/pidl --ws-parser

pidl_out = --outputdir ../..
pidl_inc = --includedir ..

SUBDIRS = \
	atsvc		\
	dfs		\
	dnsserver	\
	dssetup		\
	efs		\
	eventlog	\
	frsrpc		\
	frstrans	\
	initshutdown	\
	lsa		\
	mapi		\
	mdssvc		\
	misc		\
	nspi		\
	rfr		\
	samr		\
	winreg		\
	witness		\
	wzcsvc

DONT_BUILD_SUBDIRS = \
	srvsvc	\
	wkssvc

all: $(SUBDIRS)

.PHONY: $(SUBDIRS) $(DONT_BUILD_SUBDIRS)

$(SUBDIRS) $(DONT_BUILD_SUBDIRS): %: ../packet-dcerpc-%.c ../packet-dcerpc-%.h

../packet-dcerpc-atsvc.c \
../packet-dcerpc-atsvc.h: atsvc/atsvc.idl atsvc/atsvc.cnf
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-dfs.c \
../packet-dcerpc-dfs.h: dfs/dfs.idl dfs/dfs.cnf
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-dnsserver.c \
../packet-dcerpc-dnsserver.h: dnsserver/dnsserver.idl dnsserver/dnsserver.cnf
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-dssetup.c \
../packet-dcerpc-dssetup.h: dssetup/dssetup.idl misc/misc.idl
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-efs.c \
../packet-dcerpc-efs.h: efs/efs.idl efs/efs.cnf
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-eventlog.c \
../packet-dcerpc-eventlog.h: eventlog/eventlog.idl eventlog/eventlog.cnf \
				idl_types.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-frsrpc.c \
../packet-dcerpc-frsrpc.h: frsrpc/frsrpc.idl frsrpc/frsrpc.cnf \
				misc/misc.idl idl_types.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-frstrans.c \
../packet-dcerpc-frstrans.h: frstrans/frstrans.idl frstrans/frstrans.cnf \
				misc/misc.idl idl_types.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-initshutdown.c \
../packet-dcerpc-initshutdown.h: initshutdown/initshutdown.idl \
					initshutdown/initshutdown.cnf \
					lsa/lsa.idl idl_types.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-lsa.c \
../packet-dcerpc-lsa.h: lsa/lsa.idl lsa/lsa.cnf idl_types.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-mapi.c \
../packet-dcerpc-mapi.h: mapi/mapi.idl mapi/mapi.cnf \
				mapi/request.cnf.c mapi/response.cnf.c \
				idl_types.h mapicodes_enum.h mapitags_enum.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-mdssvc.c \
../packet-dcerpc-mdssvc.h: mdssvc/mdssvc.idl mdssvc/mdssvc.cnf \
				misc/misc.idl
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-misc.c \
../packet-dcerpc-misc.h: misc/misc.idl misc/misc.cnf idl_types.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-nspi.c \
../packet-dcerpc-nspi.h: nspi/nspi.idl nspi/nspi.cnf \
				idl_types.h mapicodes_enum.h mapitags_enum.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-rfr.c \
../packet-dcerpc-rfr.h: rfr/rfr.idl rfr/rfr.cnf \
				idl_types.h  mapicodes_enum.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-samr.c \
../packet-dcerpc-samr.h: samr/samr.idl samr/samr.cnf idl_types.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-srvsvc.c \
../packet-dcerpc-srvsvc.h: srvsvc/srvsvc.idl srvsvc/srvsvc.cnf idl_types.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-winreg.c \
../packet-dcerpc-winreg.h: winreg/winreg.idl winreg/winreg.cnf \
				misc/misc.idl
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-witness.c \
../packet-dcerpc-witness.h: witness/witness.idl witness/witness.cnf \
				misc/misc.idl  idl_types.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-wkssvc.c \
../packet-dcerpc-wkssvc.h: wkssvc/wkssvc.idl wkssvc/wkssvc.cnf \
				lsa/lsa.idl srvsvc/srvsvc.idl \
				idl_types.h
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)

../packet-dcerpc-wzcsvc.c \
../packet-dcerpc-wzcsvc.h: wzcsvc/wzcsvc.idl wzcsvc/wzcsvc.cnf
	cd $(<D) && $(PIDL) $(pidl_out) $(pidl_inc) -- $(<F)
