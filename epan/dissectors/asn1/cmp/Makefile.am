# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME=cmp

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	CMP.asn

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
	$(builddir)/../pkix1explicit/pkix1explicit_exp.cnf \
	$(builddir)/../pkix1implicit/pkix1implicit_exp.cnf \
	$(builddir)/../crmf/crmf-exp.cnf

$(builddir)/../crmf/crmf-exp.cnf:
	(cd $(builddir)/../crmf && $(MAKE_CNF_EXPORT))
