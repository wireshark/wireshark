# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME=lcsap

#DISSECTOR_FILES=packet-$(PROTOCOL_NAME).c

EXPORT_FILES = $(PROTOCOL_NAME)-exp.cnf

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
    LCS-AP-CommonDataTypes.asn\
    LCS-AP-Constants.asn\
    LCS-AP-Containers.asn\
    LCS-AP-IEs.asn\
    LCS-AP-PDU-Contents.asn\
    LCS-AP-PDU-Descriptions.asn

# The packet-$(PROTOCOL_NAME)-template.h and $(PROTOCOL_NAME).asn
# files do not exist for all protocols: Please add/remove as required.
EXTRA_DIST = \
	$(EXTRA_DIST_COMMON) \
	$(ASN_FILE_LIST) \
	packet-$(PROTOCOL_NAME)-template.c \
	packet-$(PROTOCOL_NAME)-template.h \
	$(PROTOCOL_NAME).cnf

SRC_FILES = \
	$(EXTRA_DIST) \
	$(EXT_ASN_FILE_LIST)

A2W_FLAGS=

EXTRA_CNF= \
	$(builddir)/../x509if/x509if-exp.cnf

$(builddir)/../x509if/x509if-exp.cnf:
	(cd ../x509if && $(MAKE_CNF_EXPORT))
