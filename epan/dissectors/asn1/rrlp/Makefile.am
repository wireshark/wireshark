# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME = rrlp

EXT_ASN_FILE_LIST = \
	../gsm_map/MAP-ExtensionDataTypes.asn	\
	../gsm_map/MAP-LCS-DataTypes.asn

ASN_FILE_LIST = \
	RRLP-Messages.asn	\
	RRLP-Components.asn

EXTRA_DIST = \
	$(EXTRA_DIST_COMMON) \
	$(ASN_FILE_LIST) \
	packet-$(PROTOCOL_NAME)-template.c \
	$(PROTOCOL_NAME).cnf

SRC_FILES = \
	$(EXTRA_DIST) \
	$(EXT_ASN_FILE_LIST)

A2W_FLAGS =

EXTRA_CNF =
