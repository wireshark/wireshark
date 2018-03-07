# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME = h225

EXPORT_FILES = \
	$(PROTOCOL_NAME)-exp.cnf

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	H323-MESSAGES.asn

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

EXTRA_CNF = \
	$(builddir)/../h235/h235-exp.cnf \
	$(builddir)/../h245/h245-exp.cnf

$(builddir)/../h235/h235-exp.cnf:
	(cd $(builddir)/../h235 && $(MAKE_CNF_EXPORT))

$(builddir)/../h245/h245-exp.cnf:
	(cd $(builddir)/../h245 && $(MAKE_CNF_EXPORT))
