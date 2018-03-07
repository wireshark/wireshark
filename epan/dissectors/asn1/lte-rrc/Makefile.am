# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME = lte-rrc

EXPORT_FILES = $(PROTOCOL_NAME)-exp.cnf

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	EUTRA-InterNodeDefinitions.asn \
	EUTRA-RRC-Definitions.asn \
	EUTRA-Sidelink-Preconf.asn \
	EUTRA-UE-Variables.asn \
	PC5-RRC-Definitions.asn \
	NBIOT-InterNodeDefinitions.asn \
	NBIOT-RRC-Definitions.asn \
	NBIOT-UE-Variables.asn

EXTRA_DIST = \
	$(EXTRA_DIST_COMMON) \
	$(ASN_FILE_LIST) \
	packet-$(PROTOCOL_NAME)-template.c \
	packet-$(PROTOCOL_NAME)-template.h \
	$(PROTOCOL_NAME).cnf

SRC_FILES = \
	$(EXTRA_DIST) \
	$(EXT_ASN_FILE_LIST)

A2W_FLAGS = -L

EXTRA_CNF =
