# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME=x509af

EXPORT_FILES = $(PROTOCOL_NAME)-exp.cnf

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	AuthenticationFramework.asn

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

A2W_FLAGS= -b

EXTRA_CNF= \
	$(builddir)/../x509ce/x509ce-exp.cnf \
	$(builddir)/../x509if/x509if-exp.cnf \
	$(builddir)/../x509sat/x509sat-exp.cnf

$(builddir)/../x509ce/x509ce-exp.cnf:
	(cd $(builddir)/../x509ce && $(MAKE_CNF_EXPORT))

$(builddir)/../x509if/x509if-exp.cnf:
	(cd $(builddir)/../x509if && $(MAKE_CNF_EXPORT))

$(builddir)/../x509sat/x509sat-exp.cnf:
	(cd $(builddir)/../x509sat && $(MAKE_CNF_EXPORT))
