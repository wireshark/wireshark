# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

include ../Makefile.inc

PROTOCOL_NAME=gprscdr

EXPORT_FILES = \
	$(PROTOCOL_NAME)-exp.cnf

ASN_FILE_LIST = \
	GenericChargingDataTypesV1250.asn \
	GPRSChargingDataTypesV641.asn \
	GPRSChargingDataTypesV1260.asn

INCLUDED_ASN_FILE_LIST = \
	3GPPGenericChargingDataTypes.asn \
	GPRSChargingDataTypes.asn \
	GPRSChargingDataTypesV8e0.asn \
	GPRSChargingDataTypesV9f0.asn \
	GPRSChargingDataTypesV1171.asn \
	GenericChargingDataTypes.asn \
	GenericChargingDataTypesV641.asn \
	GenericChargingDataTypesV8e0.asn \
	GenericChargingDataTypesV9f0.asn

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

EXTRA_CNF=$(builddir)/../gsm_map/gsm_map-exp.cnf

$(builddir)/../gsm_map/gsm_map-exp.cnf:
	(cd $(builddir)/../gsm_map && $(MAKE_CNF_EXPORT))
