# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME = h460

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	NUMBER-PORTABILITY.asn	\
	CIRCUIT-STATUS-MAP.asn	\
	CALL-PRIORITY.asn	\
	QOS-MONITORING-REPORT.asn	\
	QOS-MONITORING-EXTENDED-VOIP-REPORT.asn	\
	CALL-PARTY-CATEGORY.asn \
	MLPP.asn	\
	SIGNALLING-CHANNEL-SUSPEND-REDIRECT.asn	\
	SIGNALLING-TRAVERSAL.asn	\
	MEDIA-TRAVERSAL.asn	\
	MESSAGE-BROADCAST.asn

EXTRA_DIST = \
	$(EXTRA_DIST_COMMON) \
	$(ASN_FILE_LIST) \
	packet-$(PROTOCOL_NAME)-template.c \
	$(PROTOCOL_NAME).cnf

SRC_FILES = \
	$(EXTRA_DIST) \
	$(EXT_ASN_FILE_LIST)

# need empty -p <proto> option, default is -p $(PROTOCOL_NAME)
PROTO_OPT =
A2W_FLAGS =

EXTRA_CNF = \
	$(builddir)/../h225/h225-exp.cnf	\
	$(builddir)/../h235/h235-exp.cnf	\
	$(builddir)/../h245/h245-exp.cnf

$(builddir)/../h225/h225-exp.cnf:
	(cd $(builddir)/../h225 && $(MAKE_CNF_EXPORT))

$(builddir)/../h235/h235-exp.cnf:
	(cd $(builddir)/../h235 && $(MAKE_CNF_EXPORT))

$(builddir)/../h245/h245-exp.cnf:
	(cd $(builddir)/../h245 && $(MAKE_CNF_EXPORT))
