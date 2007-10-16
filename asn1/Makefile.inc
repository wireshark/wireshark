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

generate_dissector: $(DISSECTOR_FILES)

generate_export: $(EXPORT_FILES)

PROTO_OPT ?= -p $(PROTOCOL_NAME)

$(DISSECTOR_FILES): $(top_srcdir)/tools/asn2wrs.py $(SRC_FILES) $(EXTRA_CNF)
	python $(top_srcdir)/tools/asn2wrs.py \
		$(A2W_FLAGS) \
		$(PROTO_OPT) \
		-c $(srcdir)/$(PROTOCOL_NAME).cnf \
		-s $(srcdir)/packet-$(PROTOCOL_NAME)-template \
		-D $(srcdir) \
		$(EXT_ASN_FILE_LIST) $(ASN_FILE_LIST) $(EXT_ASN_FILE_LIST_LATE)

$(EXPORT_FILES): $(top_srcdir)/tools/asn2wrs.py $(SRC_FILES)
	python $(top_srcdir)/tools/asn2wrs.py \
		-E $(A2W_FLAGS) \
		$(PROTO_OPT) \
		-c $(srcdir)/$(PROTOCOL_NAME).cnf \
		-D $(srcdir) \
		$(EXT_ASN_FILE_LIST) $(ASN_FILE_LIST) $(EXT_ASN_FILE_LIST_LATE)

copy_files: generate_dissector
	cp $(DISSECTOR_FILES) $(top_srcdir)/epan/dissectors/

CLEANFILES = \
	parsetab.py \
	parsetab.pyc \
	$(DISSECTOR_FILES) \
	*-exp.cnf \
	packet-*-{dis-tab,ettarr,ett,fn,hfarr,hf,table*,val,exp}.[hc]

