# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME=p22

EXPORT_FILES = $(PROTOCOL_NAME)-exp.cnf

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	IPMSInformationObjects.asn \
	IPMSHeadingExtensions.asn \
	IPMSExtendedBodyPartTypes2.asn \
	IPMSFileTransferBodyPartType.asn \
	IPMSExtendedVoiceBodyPartType.asn \
	IPMSForwardedContentBodyPartType.asn \
	IPMSMessageStoreAttributes.asn \
	IPMSSecurityExtensions.asn \
	IPMSObjectIdentifiers.asn \
	IPMSUpperBounds.asn

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

A2W_FLAGS = -b -C

EXTRA_CNF = \
	$(builddir)/../acse/acse-exp.cnf \
	$(builddir)/../ftam/ftam-exp.cnf \
	$(builddir)/../p7/p7-exp.cnf \
	$(builddir)/../p1/p1-exp.cnf \
	$(builddir)/../x509af/x509af-exp.cnf \
	$(builddir)/../x509ce/x509ce-exp.cnf

EXPORT_DEPENDS = \
	$(builddir)/../p1/p1-exp.cnf

$(builddir)/../acse/acse-exp.cnf:
	(cd $(builddir)/../acse && $(MAKE_CNF_EXPORT))

$(builddir)/../ftam/ftam-exp.cnf:
	(cd $(builddir)/../ftam && $(MAKE_CNF_EXPORT))

$(builddir)/../p7/p7-exp.cnf:
	(cd $(builddir)/../p7 && $(MAKE_CNF_EXPORT))

$(builddir)/../p1/p1-exp.cnf:
	(cd $(builddir)/../p1 && $(MAKE_CNF_EXPORT))

$(builddir)/../x509af/x509af-exp.cnf:
	(cd $(builddir)/../x509af && $(MAKE_CNF_EXPORT))

$(builddir)/../x509ce/x509ce-exp.cnf:
	(cd $(builddir)/../x509ce && $(MAKE_CNF_EXPORT))
