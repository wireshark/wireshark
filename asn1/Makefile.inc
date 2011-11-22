# To be included into the asn1 Makefiles
#
# $Id$
#
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

DISSECTOR = $(top_srcdir)/epan/dissectors/packet-$(PROTOCOL_NAME).c
# This header file need not exist/get generated.  It is only used when cleaning.
DISSECTOR_HEADER=$(top_srcdir)/epan/dissectors/packet-$(PROTOCOL_NAME).h

all: generate_export $(DISSECTOR)

generate_export: $(EXPORT_FILES)

PROTO_OPT ?= -p $(PROTOCOL_NAME)

$(DISSECTOR): $(top_srcdir)/tools/asn2wrs.py $(SRC_FILES) $(EXTRA_CNF)
	$(PYTHON) $(top_srcdir)/tools/asn2wrs.py \
		$(A2W_FLAGS) \
		$(PROTO_OPT) \
		-c $(srcdir)/$(PROTOCOL_NAME).cnf \
		-s $(srcdir)/packet-$(PROTOCOL_NAME)-template \
		-D $(srcdir) \
		-O $(top_srcdir)/epan/dissectors \
		$(EXT_ASN_FILE_LIST) $(ASN_FILE_LIST) $(EXT_ASN_FILE_LIST_LATE)

$(EXPORT_FILES): $(top_srcdir)/tools/asn2wrs.py $(SRC_FILES)
	$(PYTHON) $(top_srcdir)/tools/asn2wrs.py \
		-E $(A2W_FLAGS) \
		$(PROTO_OPT) \
		-c $(srcdir)/$(PROTOCOL_NAME).cnf \
		-D $(srcdir) \
		$(EXT_ASN_FILE_LIST) $(ASN_FILE_LIST) $(EXT_ASN_FILE_LIST_LATE)

# Don't clean these up until/unless we start building them...
#$(DISSECTOR) \
#$(DISSECTOR_HEADER)
CLEANFILES = \
	parsetab.py \
	parsetab.pyc \
	*-exp.cnf \
	packet-*-{dis-tab,ettarr,ett,exp,fn,hfarr,hf,table*,val}.[hc]

MAINTAINERCLEANFILES = \
	Makefile.in
