# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME = h323

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	RAS-PROTOCOL-TUNNEL.asn	\
	ROBUSTNESS-DATA.asn

EXTRA_DIST = \
	$(EXTRA_DIST_COMMON) \
	$(ASN_FILE_LIST) \
	packet-$(PROTOCOL_NAME)-template.c \
	packet-$(PROTOCOL_NAME)-template.h \
	$(PROTOCOL_NAME).cnf

SRC_FILES = \
	$(EXTRA_DIST) \
	$(EXT_ASN_FILE_LIST)

A2W_FLAGS =

EXTRA_CNF = \
	$(builddir)/../h225/h225-exp.cnf

$(builddir)/../h225/h225-exp.cnf:
	(cd $(builddir)/../h225 && $(MAKE_CNF_EXPORT))
