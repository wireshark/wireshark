# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME=gprscdr

EXPORT_FILES = \
	$(PROTOCOL_NAME)-exp.cnf

ASN_FILE_LIST = \
	GenericChargingDataTypes.asn \
	GPRSChargingDataTypesV641.asn \
	GPRSChargingDataTypes.asn

# The packet-$(PROTOCOL_NAME)-template.h and $(PROTOCOL_NAME).asn
# files do not exist for all protocols: Please add/remove as required.
EXTRA_DIST = \
	$(EXTRA_DIST_COMMON) \
	$(ASN_FILE_LIST) \
	$(INCLUDED_ASN_FILE_LIST) \
	packet-$(PROTOCOL_NAME)-template.c \
	packet-$(PROTOCOL_NAME)-template.h \
	$(PROTOCOL_NAME).cnf

SRC_FILES = \
	$(EXTRA_DIST) \
	$(EXT_ASN_FILE_LIST)

A2W_FLAGS= -b

EXTRA_CNF=$(builddir)/../gsm_map/gsm_map-exp.cnf

$(builddir)/../gsm_map/gsm_map-exp.cnf:
	(cd $(builddir)/../gsm_map && $(MAKE_CNF_EXPORT))
