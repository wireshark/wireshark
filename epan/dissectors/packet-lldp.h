/* packet-lldp.h
 * Routines for LLDP dissection
 * By Juan Gonzalez <juan.gonzalez@pikatech.com>
 * Copyright 2005 MITEL
 *
 * July 2005
 * Modified by: Brian Bogora <brian_bogora@mitel.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#ifndef PACKET_LLDP_H__
#define PACKET_LLDP_H__

static const value_string tlv_oui_subtype_vals[] = {
	{ OUI_IEEE_802_1,		"IEEE 802.1" },
	{ OUI_IEEE_802_3,		"IEEE 802.3" },
	{ OUI_MEDIA_ENDPOINT,	"TIA" },
	{ OUI_PROFINET,         "PROFINET" },
	{ OUI_CISCO_2,          "Cisco" },
	{ OUI_IEEE_802_1QBG,	"IEEE 802.1Qbg" },
	{ 0, NULL }
};

/* TLV Types */
#define END_OF_LLDPDU_TLV_TYPE			0x00	/* Mandatory */
#define CHASSIS_ID_TLV_TYPE				0x01	/* Mandatory */
#define PORT_ID_TLV_TYPE				0x02	/* Mandatory */
#define TIME_TO_LIVE_TLV_TYPE			0x03	/* Mandatory */
#define PORT_DESCRIPTION_TLV_TYPE		0x04
#define SYSTEM_NAME_TLV_TYPE			0x05
#define SYSTEM_DESCRIPTION_TLV_TYPE		0x06
#define SYSTEM_CAPABILITIES_TLV_TYPE	0x07
#define MANAGEMENT_ADDR_TLV_TYPE		0x08
#define ORGANIZATION_SPECIFIC_TLV_TYPE	0x7F

/* Masks */
#define TLV_TYPE_MASK		0xFE00
#define TLV_TYPE(value)		(((value) & TLV_TYPE_MASK) >> 9)
#define TLV_INFO_LEN_MASK	0x01FF
#define TLV_INFO_LEN(value)	((value) & TLV_INFO_LEN_MASK)

/* IEEE 802.1Qbg Subtypes */
static const value_string ieee_802_1qbg_subtypes[] = {
	{ 0x00,	"EVB" },
	{ 0x01,	"CDCP" },
	{ 0x02,	"VDP" },
	{ 0, NULL }
};

gint32 dissect_lldp_end_of_lldpdu(tvbuff_t *, packet_info *, proto_tree *, guint32);

#endif /* PACKET_LLDP_H__ */
