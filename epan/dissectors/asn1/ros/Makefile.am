# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

include ../Makefile.inc

PROTOCOL_NAME=ros

EXPORT_FILES = $(PROTOCOL_NAME)-exp.cnf

EXT_ASN_FILE_LIST =

ASN_FILE_LIST = \
	$(PROTOCOL_NAME).asn \
	Remote-Operations-Information-Objects.asn

INCLUDED_ASN_FILE_LIST = \
	Remote-Operations-Generic-ROS-PDUs.asn \
	Remote-Operations-Information-Objects.asn \
	Remote-Operations-Useful-Definitions.asn \
	ros-err.cnf \
	ros-inv.cnf \
	ros-rej.cnf \
	ros-res.cnf

# The packet-$(PROTOCOL_NAME)-template.h and $(PROTOCOL_NAME).asn
# files do not exist # for all protocols: Please add/remove as required.
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

EXTRA_CNF=
