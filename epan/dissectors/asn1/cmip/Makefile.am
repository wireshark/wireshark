# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME=cmip

EXPORT_FILES = \
	$(PROTOCOL_NAME)-exp.cnf

EXT_ASN_FILE_LIST_LATE = \
	../x721/Attribute-ASN1Module.asn \
	../ros/Remote-Operations-Information-Objects.asn \
	../ros/Remote-Operations-Generic-ROS-PDUs.asn

ASN_FILE_LIST = \
	CMIP-1.asn \
	CMIP-A-ABORT-Information.asn \
	CMIP-A-ASSOCIATE-Information.asn

INCLUDED_ASN_FILE_LIST = \
	CMIP.asn

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

EXTRA_CNF= \
	$(builddir)/../acse/acse-exp.cnf

$(builddir)/../acse/acse-exp.cnf:
	(cd $(builddir)/../acse && $(MAKE_CNF_EXPORT))
