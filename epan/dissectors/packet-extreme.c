/* packet-extreme.c
 * Routines for the disassembly of Extreme Networks specific
 * protocols (EDP/ESRP/EAPS)
 *
 * $Id$
 *
 * Copyright 2005 Joerg Mayer (see AUTHORS file)
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
  TODO:
   EAPS v2 is not supported (no spec)
   Some stuff in the EDP Info field (no spec)
   Flags in the EDP Vlan field
   Meaning of speical MAC adresses:
	ExtremeN:00:00:01
	ExtremeN:00:00:06
   TLV type 0x0e (XOS only?)
   TLV type 0x15 (XOS only?)
   EAPS type 0x10

Specs:

EAPS v1 is specified in RFC3619

The following information is taken from the Extreme knowledge base
(login required). Search for ESRP.
Note: The information seems to be incorrect in at least one place
      (position of Vlan ID).

================================ snip ================================

ESRP Packet Format:
-------------------

 0                               1
 0 1 2 3 4 5 6 7 8 9 A B C D E F 0 1 2 3 4 5 6 7 8 9 A B C D E F
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 0000
|                       SOURCE MAC ADDRESS                      |
+-------------------------------+-------------------------------+ 0004
|   SOURCE MAC ADDRESS (CONT)   |        DEST MAC ADDRESS       |
+-------------------------------+-------------------------------+ 0008
|                    DEST MAC ADDRESS (CONT)                    |
+-------------------------------+---------------+---------------+ 000C
|            LENGTH             |  DSAP = AA    |  SSAP = AA    |
+---------------+---------------+---------------+---------------+ 0010
| LLC TYPE = UI |                  UID = 00E02B                 |
+---------------+---------------+---------------+---------------+ 0014
|         SNAP TYPE = 00BB      |   EDP VERSION |   RESERVED    |
+-------------------------------+---------------+---------------+ 0018
|            LENGTH             |           CHECKSUM            |
+-------------------------------+-------------------------------+ 001C
|        SEQUENCE NUMBER        |          MACHINE ID           |
+-------------------------------+-------------------------------+ 0020
|                      MACHINE ID (CONT.)                       |
+-------------------------------+---------------+---------------+ 0024
|      MACHINE ID (CONT.)       | MARKER=99(EDP)| TYPE=08 (ESRP)|
+-------------------------------+---------------+---------------+ 0028
|         LENGTH = 001C         |0=IP 1=IPX 2=L2|   GROUP = 0   |
+-------------------------------+-------------------------------+ 002C
|           PRIORITY            |  STATE: 0=?? 1=MSTR 2=SLAVE   |
+-------------------------------+-------------------------------+ 0030
|    NUMBER OF ACTIVE PORTS     |      VIRTUAL IP ADDRESS       |
+-------------------------------+-------------------------------+ 0034
|  VIRTUAL IP ADDRESS (CONT)    |     SYSTEM MAC ADDRESS        |
+-------------------------------+-------------------------------+ 0038
|                   SYSTEM MAC ADDRESS (CONT.)                  |
+-------------------------------+-------------------------------+ 003C
|         HELLO TIMER           |           RESERVED            |
+-------------------------------+-------------------------------+ 0040


******************************************************************************


EDP is a SNAP encapsulated frame.  The top level looks like this:
The top level format is like this:
[ SNAP header ] [ EDP header] [ TLV 0 ] [ TLV 1 ] ... [ TLV N ]

Header format:
1 octet: EDP version
1 octet: reserved
2 octets: length
2 octets: checksum
2 octets: sequence #
8 octets: device id (currently 2 0 octets followed by system mac address)

TLV stands for Type, Length, Value.
Format of a TLV entry:
marker ( 1 octet): Hex 99
type ( 1 octet):
        The following types are used:
              Null (used as an end signal): 0
              Display (Mib II display string): 1
              Info (Basic system information): 2
              Vlan Info                      : 5
              ESRP                           : 8
Length: Length of subsequent data(2 octets)
Value: Length octets of data.

Format for Info TLV:
two octets: originating slot #
two octets: originating port #
two octets: Virtual Chassis Id (If originating port is connected to a virtual chassis).
six octets: reserved
four octets: software version
16 octets: Virtual Chassis Id connections

Format for Vlan info:
octet 0: Flags (bit 8 = 1 means this vlan has an IP interface)
octets 1,2,3: reserved.
octets 4,5: vlan Id (0 if untagged)
octets 6,7: reserved.
octets 8 - 11: Vlan IP address.
Rest of value: VLAN name.

Display string is merely length octets of the MIBII display string.

These are the structures you will see most often in EDP frames.

================================ snap ================================

 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-llc.h"
#include "oui.h"

static int hf_llc_extreme_pid = -1;

static int proto_edp = -1;
/* EDP header */
static int hf_edp_version = -1;
static int hf_edp_reserved = -1;
static int hf_edp_length = -1;
static int hf_edp_chksum = -1;
static int hf_edp_seqno = -1;
static int hf_edp_midtype = -1;
static int hf_edp_midmac = -1;
/* TLV header */
static int hf_edp_tlv_marker = -1;
static int hf_edp_tlv_type = -1;
static int hf_edp_tlv_length = -1;
/* Display string */
static int hf_edp_display = -1;
/* Info element */
static int hf_edp_info_slot = -1;
static int hf_edp_info_port = -1;
static int hf_edp_info_vchassid = -1;
static int hf_edp_info_reserved = -1;
static int hf_edp_info_version = -1;
static int hf_edp_info_version_major1 = -1;
static int hf_edp_info_version_major2 = -1;
static int hf_edp_info_version_sustaining = -1;
static int hf_edp_info_version_internal = -1;
static int hf_edp_info_vchassconn = -1;
/* Vlan element */
static int hf_edp_vlan_flags = -1;
static int hf_edp_vlan_flags_ip = -1;
static int hf_edp_vlan_flags_reserved = -1;
static int hf_edp_vlan_flags_unknown = -1;
static int hf_edp_vlan_reserved1 = -1;
static int hf_edp_vlan_id = -1;
static int hf_edp_vlan_reserved2 = -1;
static int hf_edp_vlan_ip = -1;
static int hf_edp_vlan_name = -1;
/* ESRP element */
static int hf_edp_esrp_proto = -1;
static int hf_edp_esrp_group = -1;
static int hf_edp_esrp_prio = -1;
static int hf_edp_esrp_state = -1;
static int hf_edp_esrp_ports = -1;
static int hf_edp_esrp_virtip = -1;
static int hf_edp_esrp_sysmac = -1;
static int hf_edp_esrp_hello = -1;
static int hf_edp_esrp_reserved = -1;
/* EAPS element */
static int hf_edp_eaps_ver = -1;
static int hf_edp_eaps_type = -1;
static int hf_edp_eaps_ctrlvlanid = -1;
static int hf_edp_eaps_reserved0 = -1;
static int hf_edp_eaps_sysmac = -1;
static int hf_edp_eaps_hello = -1;
static int hf_edp_eaps_fail = -1;
static int hf_edp_eaps_state = -1;
static int hf_edp_eaps_reserved1 = -1;
static int hf_edp_eaps_helloseq = -1;
static int hf_edp_eaps_reserved2 = -1;

static gint ett_edp = -1;
static gint ett_edp_tlv_header = -1;
static gint ett_edp_display = -1;
static gint ett_edp_info = -1;
static gint ett_edp_info_version = -1;
static gint ett_edp_vlan = -1;
static gint ett_edp_vlan_flags = -1;
static gint ett_edp_esrp = -1;
static gint ett_edp_eaps = -1;
static gint ett_edp_unknown = -1;

#define PROTO_SHORT_NAME "EDP"
#define PROTO_LONG_NAME "Extreme Discovery Protocol"

static const value_string extreme_pid_vals[] = {
	{ 0x00bb,	"EDP" },

	{ 0,		NULL }
};

static const value_string esrp_proto_vals[] = {
	{ 0,	"IP" },
	{ 1,	"IPX" },
	{ 2,	"L2" },

	{ 0, NULL }
};

static const value_string esrp_state_vals[] = {
	{ 0,	"??" },
	{ 1,	"Master" },
	{ 2,	"Slave" },

	{ 0, NULL }
};

typedef enum {
	EDP_TYPE_NULL = 0,
	EDP_TYPE_DISPLAY,
	EDP_TYPE_INFO,
	EDP_TYPE_VLAN = 5,
	EDP_TYPE_ESRP = 8,
	EDP_TYPE_EAPS = 0xb
} edp_type_t;

static const value_string edp_type_vals[] = {
	{ EDP_TYPE_NULL,	"Null"},
	{ EDP_TYPE_DISPLAY,	"Display"},
	{ EDP_TYPE_INFO,	"System"},
	{ EDP_TYPE_VLAN,	"VL"},
	{ EDP_TYPE_ESRP,	"ESRP"},
	{ EDP_TYPE_EAPS,	"EAPS"},

	{ 0,	NULL }
};

static const value_string edp_midtype_vals[] = {
	{ 0,	"MAC" },

	{ 0,	NULL }
};

static const value_string eaps_type_vals[] = {
	{ 5,	"Health" },
	{ 6,	"Ring up flush fdb" },
	{ 7,	"Ring down flush fdb" },
	{ 8,	"Link down" },

	{ 0,	NULL }
};

static const value_string eaps_state_vals[] = {
	{ 0,	"Idle" },
	{ 1,	"Complete" },
	{ 2,	"Failed" },
	{ 3,	"Links up" },
	{ 4,	"Links down" },
	{ 5,	"Pre Forwarding" },

	{ 0,	NULL }
};

static void
dissect_tlv_header(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int length _U_, proto_tree *tree)
{
	proto_item	*tlv_item;
	proto_tree	*tlv_tree;
	guint8		tlv_marker;
	guint8		tlv_type;
	guint16		tlv_length;

	tlv_marker = tvb_get_guint8(tvb, offset),
	tlv_type = tvb_get_guint8(tvb, offset + 1);
	tlv_length = tvb_get_ntohs(tvb, offset + 2);

	tlv_item = proto_tree_add_text(tree, tvb, offset, 4,
		"L: %d M: 0x%02x T: %d = %s",
		tlv_length, tlv_marker, tlv_type,
		val_to_str(tlv_type, edp_type_vals, "Unknown (0x%02x)"));

	tlv_tree = proto_item_add_subtree(tlv_item, ett_edp_tlv_header);
	proto_tree_add_item(tlv_tree, hf_edp_tlv_marker, tvb, offset, 1,
		FALSE);
	offset += 1;

	proto_tree_add_uint(tlv_tree, hf_edp_tlv_type, tvb, offset, 1,
		tlv_type);
	offset += 1;

	proto_tree_add_uint(tlv_tree, hf_edp_tlv_length, tvb, offset, 2,
		tlv_length);
	offset += 2;
}

static void
dissect_display_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree)
{
	proto_item	*display_item;
	proto_tree	*display_tree;

	display_item = proto_tree_add_text(tree, tvb, offset, length,
		"Display: \"%s\"", tvb_get_ephemeral_string(tvb, offset + 0 + 4, length));

	display_tree = proto_item_add_subtree(display_item, ett_edp_display);

	dissect_tlv_header(tvb, pinfo, offset, 4, display_tree);
	offset += 4;
	proto_tree_add_item(display_tree, hf_edp_display, tvb, offset, length - 4,
		FALSE);
}

static void
dissect_null_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length _U_, proto_tree *tree)
{
	dissect_tlv_header(tvb, pinfo, offset, 4, tree);
	offset += 4;
}

static void
dissect_info_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree)
{
	proto_item *ver_item;
	proto_tree *ver_tree;
	guint8 major1, major2, sustaining, internal;
	guint16 port, slot;
	proto_item	*info_item;
	proto_tree	*info_tree;

	/* The slot and port numbers printed on the chassis are 1
	   bigger than the transmitted values indicate */
	slot = tvb_get_ntohs(tvb, offset + 0 + 4) + 1;
	port = tvb_get_ntohs(tvb, offset + 2 + 4) + 1;

	/* version */
	major1 = tvb_get_guint8(tvb, offset + 12 + 4);
	major2 = tvb_get_guint8(tvb, offset + 13 + 4);
	sustaining = tvb_get_guint8(tvb, offset + 14 + 4);
	internal = tvb_get_guint8(tvb, offset + 15 + 4);

	info_item = proto_tree_add_text(tree, tvb, offset, length,
		"Info: Slot/Port: %d/%d, Version: %d.%d.%d.%d",
		slot, port, major1, major2, sustaining, internal);

	info_tree = proto_item_add_subtree(info_item, ett_edp_info);

	dissect_tlv_header(tvb, pinfo, offset, 4, info_tree);
	offset += 4;

	proto_tree_add_uint(info_tree, hf_edp_info_slot, tvb, offset, 2,
		slot);
	offset += 2;

	proto_tree_add_uint(info_tree, hf_edp_info_port, tvb, offset, 2,
		port);
	offset += 2;

	proto_tree_add_item(info_tree, hf_edp_info_vchassid, tvb, offset, 2,
		FALSE);
	offset += 2;

	proto_tree_add_item(info_tree, hf_edp_info_reserved, tvb, offset, 6,
		FALSE);
	offset += 6;

	/* Begin version subtree */
	ver_item = proto_tree_add_text(info_tree, tvb, offset, 4,
		"Version: %u.%u.%u Internal: %u", major1, major2,
		sustaining, internal);

	ver_tree = proto_item_add_subtree(ver_item, ett_edp_info_version);

	proto_tree_add_item(ver_tree, hf_edp_info_version, tvb, offset, 4,
		FALSE);

	proto_tree_add_uint(ver_tree, hf_edp_info_version_major1, tvb, offset, 1,
		major1);
	offset += 1;

	proto_tree_add_uint(ver_tree, hf_edp_info_version_major2, tvb, offset, 1,
		major2);
	offset += 1;

	proto_tree_add_uint(ver_tree, hf_edp_info_version_sustaining, tvb, offset, 1,
		sustaining);
	offset += 1;

	proto_tree_add_uint(ver_tree, hf_edp_info_version_internal, tvb, offset, 1,
		internal);
	offset += 1;
	/* End of version subtree */

	proto_tree_add_item(info_tree, hf_edp_info_vchassconn, tvb, offset, 16,
		FALSE);
	offset += 16;
}

static void
dissect_vlan_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree)
{
	proto_item	*flags_item;
	proto_tree	*flags_tree;
	proto_item	*vlan_item;
	proto_tree	*vlan_tree;
	guint16		vlan_id;

	vlan_id = tvb_get_ntohs(tvb, offset + 2 + 4);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, "%d", vlan_id);

	vlan_item = proto_tree_add_text(tree, tvb, offset, length,
		"Vlan: ID: %d Name: %s", vlan_id,
		tvb_get_ephemeral_string(tvb, offset + 12 + 4, length - (12 + 4)));

	vlan_tree = proto_item_add_subtree(vlan_item, ett_edp_vlan);

	dissect_tlv_header(tvb, pinfo, offset, 4, vlan_tree);
	offset += 4;

	/* Begin flags subtree */
	flags_item = proto_tree_add_item(vlan_tree, hf_edp_vlan_flags, tvb, offset, 1,
		FALSE);

	flags_tree = proto_item_add_subtree(flags_item, ett_edp_vlan_flags);

	proto_tree_add_item(flags_tree, hf_edp_vlan_flags_ip, tvb, offset, 1,
		FALSE);
	proto_tree_add_item(flags_tree, hf_edp_vlan_flags_reserved, tvb, offset, 1,
		FALSE);
	proto_tree_add_item(flags_tree, hf_edp_vlan_flags_unknown, tvb, offset, 1,
		FALSE);
	offset += 1;
	/* End of flags subtree */

	proto_tree_add_item(vlan_tree, hf_edp_vlan_reserved1, tvb, offset, 1,
		FALSE);
	offset += 1;

	proto_tree_add_item(vlan_tree, hf_edp_vlan_id, tvb, offset, 2,
		FALSE);
	offset += 2;

	proto_tree_add_item(vlan_tree, hf_edp_vlan_reserved2, tvb, offset, 4,
		FALSE);
	offset += 4;

	proto_tree_add_item(vlan_tree, hf_edp_vlan_ip, tvb, offset, 4,
		FALSE);
	offset += 4;

	proto_tree_add_item(vlan_tree, hf_edp_vlan_name, tvb, offset, length - 12,
		FALSE);
	offset += (length - 12);
}

static void
dissect_esrp_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length, proto_tree *tree)
{
	proto_item	*esrp_item;
	proto_tree	*esrp_tree;
	guint16		group;

	group = tvb_get_guint8(tvb, offset + 1 + 4);
	esrp_item = proto_tree_add_text(tree, tvb, offset, length,
		"ESRP: G: %d", group);

	esrp_tree = proto_item_add_subtree(esrp_item, ett_edp_esrp);

	dissect_tlv_header(tvb, pinfo, offset, 4, esrp_tree);
	offset += 4;

	proto_tree_add_item(esrp_tree, hf_edp_esrp_proto, tvb, offset, 1,
		FALSE);
	offset += 1;

	proto_tree_add_item(esrp_tree, hf_edp_esrp_group, tvb, offset, 1,
		FALSE);
	offset += 1;

	proto_tree_add_item(esrp_tree, hf_edp_esrp_prio, tvb, offset, 2,
		FALSE);
	offset += 2;

	proto_tree_add_item(esrp_tree, hf_edp_esrp_state, tvb, offset, 2,
		FALSE);
	offset += 2;

	proto_tree_add_item(esrp_tree, hf_edp_esrp_ports, tvb, offset, 2,
		FALSE);
	offset += 2;

	proto_tree_add_item(esrp_tree, hf_edp_esrp_virtip, tvb, offset, 4,
		FALSE);
	offset += 4;

	proto_tree_add_item(esrp_tree, hf_edp_esrp_sysmac, tvb, offset, 6,
		FALSE);
	offset += 6;

	proto_tree_add_item(esrp_tree, hf_edp_esrp_hello, tvb, offset, 2,
		FALSE);
	offset += 2;

	proto_tree_add_item(esrp_tree, hf_edp_esrp_reserved, tvb, offset, 2,
		FALSE);
	offset += 2;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESRP");
}

static void
dissect_eaps_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length _U_, proto_tree *tree)
{
	proto_item	*eaps_item;
	proto_tree	*eaps_tree;
	guint16		ctrlvlanid;

	ctrlvlanid = tvb_get_ntohs(tvb, offset + 2 + 4);

	eaps_item = proto_tree_add_text(tree, tvb, offset, length,
		"EAPS: C: %d", ctrlvlanid);

	eaps_tree = proto_item_add_subtree(eaps_item, ett_edp_eaps);

	dissect_tlv_header(tvb, pinfo, offset, 4, eaps_tree);
	offset += 4;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_ver, tvb, offset, 1,
		FALSE);
	offset += 1;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_type, tvb, offset, 1,
		FALSE);
	offset += 1;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_ctrlvlanid, tvb, offset, 2,
		FALSE);
	offset += 2;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_reserved0, tvb, offset, 4,
		FALSE);
	offset += 4;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_sysmac, tvb, offset, 6,
		FALSE);
	offset += 6;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_hello, tvb, offset, 2,
		FALSE);
	offset += 2;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_fail, tvb, offset, 2,
		FALSE);
	offset += 2;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_state, tvb, offset, 1,
		FALSE);
	offset += 1;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_reserved1, tvb, offset, 1,
		FALSE);
	offset += 1;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_helloseq, tvb, offset, 2,
		FALSE);
	offset += 2;

	proto_tree_add_item(eaps_tree, hf_edp_eaps_reserved2, tvb, offset, 38,
		FALSE);
	offset += 38;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAPS");
}

static void
dissect_unknown_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length _U_, proto_tree *tree)
{
	proto_item	*unknown_item;
	proto_tree	*unknown_tree;
	guint8		tlv_type;

	tlv_type = tvb_get_guint8(tvb, offset + 1);

	unknown_item = proto_tree_add_text(tree, tvb, offset, length,
		"Unknown element [0x%02x]", tlv_type);

	unknown_tree = proto_item_add_subtree(unknown_item, ett_edp_unknown);

	dissect_tlv_header(tvb, pinfo, offset, 4, unknown_tree);
	offset += 4;

	proto_tree_add_text(unknown_tree, tvb, offset + 0, length -4,
		"Unknown data");
}

static void
dissect_edp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_item *tlvi;
	proto_tree *edp_tree = NULL;
	guint32 offset = 0;
	gboolean last = FALSE;
	guint8 tlv_type;
	guint16 tlv_length;
	guint16 data_length;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME ":");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_edp, tvb, offset, -1,
		    FALSE);
		edp_tree = proto_item_add_subtree(ti, ett_edp);

		proto_tree_add_item(edp_tree, hf_edp_version, tvb, offset, 1,
			FALSE);
		offset += 1;

		proto_tree_add_item(edp_tree, hf_edp_reserved, tvb, offset, 1,
			FALSE);
		offset += 1;

		data_length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(edp_tree, hf_edp_length, tvb, offset, 2,
			data_length);
		offset += 2;

		proto_tree_add_item(edp_tree, hf_edp_chksum, tvb, offset, 2,
			FALSE);
		offset += 2;

		proto_tree_add_item(edp_tree, hf_edp_seqno, tvb, offset, 2,
			FALSE);
		offset += 2;

		/* Machine ID is 8 bytes, if it starts with 0000, the remaining
		   6 bytes are a MAC */
		proto_tree_add_item(edp_tree, hf_edp_midtype, tvb, offset, 2,
			FALSE);
		offset += 2;

		proto_tree_add_item(edp_tree, hf_edp_midmac, tvb, offset, 6,
			FALSE);
		offset += 6;

		/* Decode the individual TLVs */
		while (offset < data_length && !last) {
			if (data_length - offset < 4) {
	                	tlvi = proto_tree_add_text(edp_tree, tvb, offset, 4,
                    			"Too few bytes left for TLV: %u (< 4)",
					data_length - offset);
				offset += 4;
				break;
			}
			tlv_type = tvb_get_guint8(tvb, offset + 1);
			tlv_length = tvb_get_ntohs(tvb, offset + 2);

			if ((tlv_length < 4) || (tlv_length > (data_length - offset))) {
	                	tlvi = proto_tree_add_text(edp_tree, tvb, offset, 0,
                    			"TLV with invalid length: %u", tlv_length);
				last = TRUE;
				break;
			}
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
					val_to_str(tlv_type, edp_type_vals, "[0x%02x]"));

			switch (tlv_type) {
			case EDP_TYPE_NULL: /* Last TLV */
				dissect_null_tlv(tvb, pinfo, offset, tlv_length, edp_tree);
				last = 1;
				break;
			case EDP_TYPE_DISPLAY: /* MIB II display string */
				dissect_display_tlv(tvb, pinfo, offset, tlv_length, edp_tree);
				break;
			case EDP_TYPE_INFO: /* Basic system information */
				dissect_info_tlv(tvb, pinfo, offset, tlv_length, edp_tree);
				break;
			case EDP_TYPE_VLAN: /* VLAN info */
				dissect_vlan_tlv(tvb, pinfo, offset, tlv_length, edp_tree);
				break;
			case EDP_TYPE_ESRP: /* Extreme Standby Router Protocol */
				dissect_esrp_tlv(tvb, pinfo, offset, tlv_length, edp_tree);
				break;
			case EDP_TYPE_EAPS: /* Ethernet Automatic Protection Swtiching */
				dissect_eaps_tlv(tvb, pinfo, offset, tlv_length, edp_tree);
				break;
			default:
				dissect_unknown_tlv(tvb, pinfo, offset, tlv_length, edp_tree);
				break;
			}
			offset += tlv_length;
		}

	}
}

void
proto_register_edp(void)
{
	static hf_register_info hf[] = {

	/* EDP header */
		{ &hf_edp_version,
		{ "Version",	"edp.version", FT_UINT8, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_reserved,
		{ "Reserved",	"edp.reserved", FT_UINT8, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_length,
		{ "Data length",	"edp.length", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_chksum,
		{ "Checksum",	"edp.checksum", FT_UINT16, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_seqno,
		{ "Sequence number",	"edp.seqno", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_midtype,
		{ "Machine ID type",	"edp.midtype", FT_UINT16, BASE_DEC, VALS(edp_midtype_vals),
			0x0, "", HFILL }},

		{ &hf_edp_midmac,
		{ "Machine MAC",	"edp.midmac", FT_ETHER, BASE_NONE, NULL,
			0x0, "", HFILL }},

	/* TLV header */
		{ &hf_edp_tlv_marker,
		{ "TLV Marker",	"edp.tlv.marker", FT_UINT8, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_tlv_type,
		{ "TLV type",	"edp.tlv.type", FT_UINT8, BASE_DEC, VALS(edp_type_vals),
			0x0, "", HFILL }},

		{ &hf_edp_tlv_length,
		{ "TLV length",	"edp.tlv.length", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

	/* Display string */
		{ &hf_edp_display,
		{ "Display",	"edp.display", FT_STRING, BASE_NONE, NULL,
			0x0, "MIB II display string", HFILL }},

	/* Info element */
		{ &hf_edp_info_slot,
		{ "Slot",	"edp.info.slot", FT_UINT16, BASE_DEC, NULL,
			0x0, "Originating slot #", HFILL }},

		{ &hf_edp_info_port,
		{ "Port",	"edp.info.port", FT_UINT16, BASE_DEC, NULL,
			0x0, "Originating port #", HFILL }},

		{ &hf_edp_info_vchassid,
		{ "Virt chassis",	"edp.info.vchassid", FT_UINT16, BASE_DEC, NULL,
			0x0, "Virtual chassis ID", HFILL }},

		{ &hf_edp_info_reserved,
		{ "Reserved",	"edp.info.reserved", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_info_version,
		{ "Version",	"edp.info.version", FT_UINT32, BASE_HEX, NULL,
			0x0, "Software version", HFILL }},

		{ &hf_edp_info_version_major1,
		{ "Version (major1)",	"edp.info.version.major1", FT_UINT8, BASE_DEC, NULL,
			0x0, "Software version (major1)", HFILL }},

		{ &hf_edp_info_version_major2,
		{ "Version (major2)",	"edp.info.version.major2", FT_UINT8, BASE_DEC, NULL,
			0x0, "Software version (major2)", HFILL }},

		{ &hf_edp_info_version_sustaining,
		{ "Version (sustaining)",	"edp.info.version.sustaining", FT_UINT8, BASE_DEC, NULL,
			0x0, "Software version (sustaining)", HFILL }},

		{ &hf_edp_info_version_internal,
		{ "Version (internal)",	"edp.info.version.internal", FT_UINT8, BASE_DEC, NULL,
			0x0, "Software version (internal)", HFILL }},

		{ &hf_edp_info_vchassconn,
		{ "Connections",	"edp.info.vchassconn", FT_BYTES, BASE_NONE, NULL,
			0x0, "Virtual chassis connections", HFILL }},

	/* VLAN element */
		{ &hf_edp_vlan_flags,
		{ "Flags",	"edp.vlan.flags", FT_UINT8, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_vlan_flags_ip,
		{ "Flags-IP",	"edp.vlan.flags.ip", FT_BOOLEAN, 8, TFS(&flags_set_truth),
			0x80, "Vlan has IP address configured", HFILL }},

		{ &hf_edp_vlan_flags_reserved,
		{ "Flags-reserved",	"edp.vlan.flags.reserved", FT_UINT8, BASE_HEX, NULL,
			0x7e, "", HFILL }},

		{ &hf_edp_vlan_flags_unknown,
		{ "Flags-Unknown",	"edp.vlan.flags.unknown", FT_BOOLEAN, 8, TFS(&flags_set_truth),
			0x01, "", HFILL }},

		{ &hf_edp_vlan_reserved1,
		{ "Reserved1",	"edp.vlan.reserved1", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_vlan_id,
		{ "Vlan ID",	"edp.vlan.id", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_vlan_reserved2,
		{ "Reserved2",	"edp.vlan.reserved2", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_vlan_ip,
		{ "IP addr",	"edp.vlan.ip", FT_IPv4, BASE_NONE, NULL,
			0x0, "VLAN IP address", HFILL }},

		{ &hf_edp_vlan_name,
		{ "Name",	"edp.vlan.name", FT_STRING, BASE_NONE, NULL,
			0x0, "VLAN name", HFILL }},

	/* ESRP element */
		{ &hf_edp_esrp_proto,
		{ "Protocol",	"edp.esrp.proto", FT_UINT8, BASE_DEC, VALS(esrp_proto_vals),
			0x0, "", HFILL }},

		{ &hf_edp_esrp_group,
		{ "Group",	"edp.esrp.group", FT_UINT8, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_esrp_prio,
		{ "Prio",	"edp.esrp.prio", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_esrp_state,
		{ "State",	"edp.esrp.state", FT_UINT16, BASE_DEC, VALS(esrp_state_vals),
			0x0, "", HFILL }},

		{ &hf_edp_esrp_ports,
		{ "Ports",	"edp.esrp.ports", FT_UINT16, BASE_DEC, NULL,
			0x0, "Number of active ports", HFILL }},

		{ &hf_edp_esrp_virtip,
		{ "VirtIP",	"edp.esrp.virtip", FT_IPv4, BASE_NONE, NULL,
			0x0, "Virtual IP address", HFILL }},

		{ &hf_edp_esrp_sysmac,
		{ "Sys MAC",	"edp.esrp.sysmac", FT_ETHER, BASE_NONE, NULL,
			0x0, "System MAC address", HFILL }},

		{ &hf_edp_esrp_hello,
		{ "Hello",	"edp.esrp.hello", FT_UINT16, BASE_DEC, NULL,
			0x0, "Hello timer", HFILL }},

		{ &hf_edp_esrp_reserved,
		{ "Reserved",	"edp.esrp.reserved", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

	/* EAPS element */
		{ &hf_edp_eaps_ver,
		{ "Version",	"edp.eaps.ver", FT_UINT8, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_eaps_type,
		{ "Type",	"edp.eaps.type", FT_UINT8, BASE_DEC, VALS(eaps_type_vals),
			0x0, "", HFILL }},

		{ &hf_edp_eaps_ctrlvlanid,
		{ "Vlan ID",	"edp.eaps.vlanid", FT_UINT16, BASE_DEC, NULL,
			0x0, "Control Vlan ID", HFILL }},

		{ &hf_edp_eaps_reserved0,
		{ "Reserved0",	"edp.eaps.reserved0", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_eaps_sysmac,
		{ "Sys MAC",	"edp.eaps.sysmac", FT_ETHER, BASE_NONE, NULL,
			0x0, "System MAC address", HFILL }},

		{ &hf_edp_eaps_hello,
		{ "Hello",	"edp.eaps.hello", FT_UINT16, BASE_DEC, NULL,
			0x0, "Hello timer", HFILL }},

		{ &hf_edp_eaps_fail,
		{ "Fail",	"edp.eaps.fail", FT_UINT16, BASE_DEC, NULL,
			0x0, "Fail timer", HFILL }},

		{ &hf_edp_eaps_state,
		{ "State",	"edp.eaps.state", FT_UINT8, BASE_DEC, VALS(eaps_state_vals),
			0x0, "", HFILL }},

		{ &hf_edp_eaps_reserved1,
		{ "Reserved1",	"edp.eaps.reserved1", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_eaps_helloseq,
		{ "Helloseq",	"edp.eaps.helloseq", FT_UINT16, BASE_DEC, NULL,
			0x0, "Hello sequence", HFILL }},

		{ &hf_edp_eaps_reserved2,
		{ "Reserved2",	"edp.eaps.reserved2", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

        };
	static gint *ett[] = {
		&ett_edp,
		&ett_edp_tlv_header,
		&ett_edp_vlan_flags,
		&ett_edp_display,
		&ett_edp_info,
		&ett_edp_info_version,
		&ett_edp_vlan,
		&ett_edp_esrp,
		&ett_edp_eaps,
		&ett_edp_unknown,
	};

        proto_edp = proto_register_protocol(PROTO_LONG_NAME,
	    PROTO_SHORT_NAME, "edp");
        proto_register_field_array(proto_edp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_edp(void)
{
	dissector_handle_t edp_handle;

	edp_handle = create_dissector_handle(dissect_edp, proto_edp);
	dissector_add("llc.extreme_pid", 0x00bb, edp_handle);
}

void
proto_register_extreme_oui(void)
{
	static hf_register_info hf = {
	    &hf_llc_extreme_pid,
		{ "PID",	"llc.extreme_pid",  FT_UINT16, BASE_HEX,
		  VALS(extreme_pid_vals), 0x0, "", HFILL },
	};

	llc_add_oui(OUI_EXTREME, "llc.extreme_pid", "Extreme OUI PID", &hf);
}
