# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME = isdn-sup

EXPORT_FILES = $(PROTOCOL_NAME)-exp.cnf

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	Addressing-Data-Elements.asn \
	Basic-Service-Elements.asn \
	Embedded-Q931-Types.asn \
	General-Errors.asn \
	Advice-of-Charge-Operations.asn \
	Closed-User-Group-Service-Operations.asn \
	Conference-Add-On-Operations.asn \
	Diversion-Operations.asn \
	MCID-Operations.asn \
	User-To-User-Signalling-Operations.asn \
	Freephone-Operations.asn \
	MLPP-Operations-And-Errors.asn

INCLUDED_ASN_FILE_LIST = \
	CCBS-Operations-and-Errors.asn \
	CCBS-private-networks-Operations-and-Errors.asn \
	Explicit-Call-Transfer-Operations-and-Errors.asn \
	MWI-Operations-and-Errors.asn \
	Outgoing-Call-Barring-Operations-and-Errors.asn \
	Set-Operations-and-Errors.asn \
	Three-Party-Operations.asn

# The packet-$(PROTOCOL_NAME)-template.h and $(PROTOCOL_NAME).asn
# files do not exist for all protocols: Please add/remove as required.
EXTRA_DIST = \
	$(EXTRA_DIST_COMMON) \
	$(ASN_FILE_LIST) \
	$(INCLUDED_ASN_FILE_LIST) \
	packet-$(PROTOCOL_NAME)-template.c \
	$(PROTOCOL_NAME).cnf

SRC_FILES = \
	$(EXTRA_DIST) \
	$(EXT_ASN_FILE_LIST)

A2W_FLAGS= -b

EXTRA_CNF =
