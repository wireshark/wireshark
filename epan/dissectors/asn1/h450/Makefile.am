# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME=h450

# need empty -p <proto> option, default is -p $(PROTOCOL_NAME)
PROTO_OPT =

EXT_ASN_FILE_LIST =

H450_ASN = \
	H4501-Supplementary-ServiceAPDU-Structure.asn \
	Addressing-Data-Elements.asn \
	H225-generic-parameters-definition.asn \
	Manufacturer-specific-service-extension-definition.asn \
	H4501-General-Error-List.asn

H450_OP_ASN = \
	Call-Transfer-Operations.asn \
	Call-Diversion-Operations.asn \
	Call-Hold-Operations.asn \
	Call-Park-Pickup-Operations.asn \
	Call-Waiting-Operations.asn \
	Message-Waiting-Indication-Operations.asn \
	Name-Operations.asn \
	Call-Completion-Operations.asn \
	Call-Offer-Operations.asn \
	Call-Intrusion-Operations.asn \
	Common-Information-Operations.asn

ASN_FILE_LIST = \
	$(H450_ASN) \
	$(H450_OP_ASN)

# The packet-$(PROTOCOL_NAME)-template.h and $(PROTOCOL_NAME).asn
# files do not exist for all protocols: Please add/remove as required.
EXTRA_DIST = \
	$(EXTRA_DIST_COMMON) \
	$(ASN_FILE_LIST) \
	packet-$(PROTOCOL_NAME)-template.c \
	$(PROTOCOL_NAME).cnf

SRC_FILES = \
	$(EXTRA_DIST) \
	$(EXT_ASN_FILE_LIST)

A2W_FLAGS=

EXTRA_CNF = \
	$(builddir)/../h225/h225-exp.cnf	\
	$(builddir)/../h450-ros/h450-ros-exp.cnf

$(builddir)/../h225/h225-exp.cnf:
	(cd $(builddir)/../h225 && $(MAKE_CNF_EXPORT))

$(builddir)/../h450-ros/h450-ros-exp.cnf:
	(cd $(builddir)/../h450-ros && $(MAKE_CNF_EXPORT))
