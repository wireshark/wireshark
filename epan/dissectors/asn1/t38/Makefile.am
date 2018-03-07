# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME = t38

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	T38_2002.asn

INCLUDED_ASN_FILE_LIST = \
	T38_1998.asn

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

A2W_FLAGS =

EXTRA_CNF =
