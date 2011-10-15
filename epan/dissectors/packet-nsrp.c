/* packet-nsrp.c
 * Routines for the Juniper Netscreen Redundant Protocol (NSRP)
 *
 * Secfire <secfire@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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
 *
 * NSRP update information can be found at www.juniper.net
 *
 *
 *
 *    NSRP Packet Header is defined as follow:
 *
 *       1         2       3        4        5         6       7        8
 *   +--------+--------+--------+--------+--------+--------+--------+--------+
 *   |Version | Type   |Clust ID|MSG Flag|     Length      |HA Port |Not Used|
 *   +--------+--------+--------+--------+--------+--------+--------+--------+
 *   |          Destination Unit         |             Source Unit           |
 *   +--------+--------+--------+--------+--------+--------+--------+--------+
 *
 *
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/etypes.h>

#define NSRP_MIN_LEN    32

/* Initialize the protocol and registered fields */
static int proto_nsrp       = -1;

static int hf_nsrp_version       = -1;
static int hf_nsrp_msg_type      = -1;
static int hf_nsrp_clust_id      = -1;
static int hf_nsrp_msg_flag      = -1;
static int hf_nsrp_len           = -1;
static int hf_nsrp_ha_port       = -1;
static int hf_nsrp_not_used      = -1;
static int hf_nsrp_dst_unit      = -1;
static int hf_nsrp_src_unit      = -1;
static int hf_nsrp_msgtype       = -1;
static int hf_nsrp_wst_group     = -1;
static int hf_nsrp_hst_group     = -1;
static int hf_nsrp_msgflag     = -1;
static int hf_nsrp_authflag      = -1;
static int hf_nsrp_priority      = -1;
static int hf_nsrp_dummy         = -1;
static int hf_nsrp_authchecksum  = -1;
static int hf_nsrp_ifnum         = -1;


/* Dada defined for HA Message */
static int hf_nsrp_msglen      = -1;
static int hf_nsrp_encflag      = -1;
static int hf_nsrp_notused = -1;

static int hf_nsrp_total_size = -1;

static int hf_nsrp_ns = -1;
static int hf_nsrp_nr = -1;

static int hf_nsrp_no_used = -1;
static int hf_nsrp_checksum = -1;

static int hf_nsrp_data = -1;


static const value_string nsrp_msg_type_vals[] = {
	{ 0x01,	"HA MESSAGE" },
	{ 0x02,	"MNG MESSAGE" },
	{ 0x03,	"DADA MESSAGE" },
	{ 0,			NULL }
};

static const value_string nsrp_msgtype_vals[] = {
	{ 0x01,	"CREATE SESSION" },
	{ 0x02,	"CLOSE SESSION" },
	{ 0x03,	"CHANG SESSION" },
	{ 0x04,	"CREATE SP SESSION" },
	{ 0x05,	"SYS CONFIG" },
	{ 0x06,	"FILE SYS" },
	{ 0x07,	"CMD WEB" },
	{ 0x08,	"SAVE SLAVE" },
	{ 0x09,	"VPN SPI" },
	{ 0x0a,	"ARP" },
	{ 0x0b,	"HEALTH CHECK" },
	{ 0x0c,	"EMW DATA" },
	{ 0x0d,	"INVITE SYNC" },
	{ 0x0e,	"DOWNLOAD CONFIG" },
	{ 0x0f,	"L2TP TUNL CREATE" },
	{ 0x10,	"L2TP TUNL DELETE" },
	{ 0x11,	"L2TP CALL CREATE" },
	{ 0x12,	"L2TP CALL DELETE" },
	{ 0x13,	"PKI SYNC" },
	{ 0x14,	"VPN SEQ" },
	{ 0x15,	"MAX" },
	{ 0,			NULL }
};

static const value_string nsrp_flag_vals[] = {
	{ 0x80,	"ENCRPT MESSAGE" },
	{ 0x40,	"CLOSE SESSION" },
	{ 0x20,	"CHANG SESSION" },
	{ 0x10,	"CREATE SP SESSION" },
	{ 0x08,	"SYS CONFIG" },
	{ 0x04,	"FILE SYS" },
	{ 0x02,	"CMD WEB" },
	{ 0,			NULL }
};

static const value_string nsrp_encflag_vals[] = {
	{ 0xf0,	"ENCRYPT METHOD MASK" },
	{ 0x0f,	"ENCRYPT PAD BIT MASK" },
	{ 0,			NULL }
};


/* Initialize the subtree pointers */
static gint ett_nsrp = -1;

/* Code to actually dissect the packets */
static void
dissect_nsrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ti;
    proto_tree  *nsrp_tree = NULL;
    gint        offset = 0;
    guint8      msgtype = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NSRP");

    col_set_str(pinfo->cinfo, COL_INFO, "NSRP Protocol");

    if (tree) {
			ti = proto_tree_add_item(tree, proto_nsrp, tvb, 0, -1, FALSE);
			nsrp_tree = proto_item_add_subtree(ti, ett_nsrp);


			proto_tree_add_item(nsrp_tree, hf_nsrp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			msgtype = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(nsrp_tree, hf_nsrp_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_clust_id, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_msg_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_len, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(nsrp_tree, hf_nsrp_ha_port, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_not_used, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_dst_unit, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(nsrp_tree, hf_nsrp_src_unit, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
		}

/*
 *
 *
 *    NSRP HA Packet is defined as follow:
 *
 *       1         2       3        4        5         6       7        8
 *   +--------+--------+--------+--------+--------+--------+--------+--------+
 *   | Type   |WstGroup|HstGroup|MSG Flag|     Length      |Enc Flag|Not Used|
 *   +--------+--------+--------+--------+--------+--------+--------+--------+
 *   |            Total Size             |        NS       |        NR       |
 *   +--------+--------+--------+--------+--------+--------+--------+--------+
 *   |     No Used     |    Checksum     |              Data                 |
 *   +--------+--------+--------+--------+-----------------------------------+
 *
 *
 */

		if ( msgtype == 0x00 ) {

			proto_tree_add_item(nsrp_tree, hf_nsrp_msgtype, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_wst_group, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_hst_group, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_msgflag, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_msglen, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(nsrp_tree, hf_nsrp_encflag, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_not_used, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_total_size, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(nsrp_tree, hf_nsrp_ns, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(nsrp_tree, hf_nsrp_nr, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(nsrp_tree, hf_nsrp_no_used, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(nsrp_tree, hf_nsrp_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(nsrp_tree, hf_nsrp_data, tvb, offset, -1, ENC_ASCII|ENC_NA);

    }

/*
 *
 *    NSRP MNG Packet is defined as follow:
 *
 *       1         2       3        4        5         6       7        8
 *   +--------+--------+--------+--------+--------+--------+--------+--------+
 *   | Type   |WstGroup|HstGroup|MSG Flag|     Length      |AuthFlag|Not Used|
 *   +--------+--------+--------+--------+--------+--------+--------+--------+
 *   |Priority+ Dummy  +   Auth CheckSum +                Data               |
 *   +--------+--------+--------+--------+-----------------------------------+
 *
 *
 */

		if ( msgtype == 0x02 ) {

			proto_tree_add_item(nsrp_tree, hf_nsrp_msgtype, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_wst_group, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_hst_group, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_msgflag, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_msglen, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(nsrp_tree, hf_nsrp_authflag, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_not_used, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_dummy, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_authchecksum, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(nsrp_tree, hf_nsrp_data, tvb, offset, -1, ENC_ASCII|ENC_NA);

    }




/*
 *    NSRP DATA Packet is defined as follow:
 *
 *       1         2       3        4        5         6       7        8
 *   +--------+--------+--------+--------+--------+--------+--------+--------+
 *   | Type   |WstGroup|HstGroup|MSG Flag|     Length      | Ifnum  |Not Used|
 *   +--------+--------+--------+--------+--------+--------+--------+--------+
 *   |            Total Size             |                Data               |
 *   +--------+--------+--------+--------+-----------------------------------+
 *
 *
 */
   if ( msgtype == 0x03 ) {

			proto_tree_add_item(nsrp_tree, hf_nsrp_msgtype, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_wst_group, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_hst_group, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_msgflag, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_msglen, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;

			proto_tree_add_item(nsrp_tree, hf_nsrp_ifnum, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_not_used, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;

			proto_tree_add_item(nsrp_tree, hf_nsrp_total_size, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;

			proto_tree_add_item(nsrp_tree, hf_nsrp_data, tvb, offset, -1, ENC_ASCII|ENC_NA);

    }

}


void
proto_register_nsrp(void)
{

    static hf_register_info hf[] = {
	{ &hf_nsrp_version,
	  { "Version", "nsrp.version",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "NSRP Version", HFILL }
	},
		{ &hf_nsrp_msg_type,
	  { "Type", "nsrp.type",
	    FT_UINT8, BASE_DEC, nsrp_msg_type_vals, 0,
	    "NSRP Message Type", HFILL }
	},
		{ &hf_nsrp_clust_id,
	  { "Clust ID", "nsrp.clustid",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "NSRP CLUST ID", HFILL }
	},
		{ &hf_nsrp_msg_flag,
	  { "Flag", "nsrp.flag",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "NSRP FLAG", HFILL }
	},
	{ &hf_nsrp_len,
	  { "Length", "nsrp.length",
	    FT_UINT16, BASE_DEC, NULL, 0,
	    "NSRP Length", HFILL }
	},
		{ &hf_nsrp_ha_port,
	  { "Port", "nsrp.haport",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "NSRP HA Port", HFILL }
	},
		{ &hf_nsrp_not_used,
	  { "Not used", "nsrp.notused",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    NULL, HFILL }
	},
		{ &hf_nsrp_dst_unit,
	  { "Destination", "nsrp.dst",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "DESTINATION UNIT INFORMATION", HFILL }
	},
	{ &hf_nsrp_src_unit,
	  { "Source", "nsrp.src",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "SOURCE UNIT INFORMATION", HFILL }
	},
		{ &hf_nsrp_msgtype,
	  { "MsgType", "nsrp.msgtype",
	    FT_UINT8, BASE_DEC, VALS(nsrp_msgtype_vals), 0,
	    "Message Type", HFILL }
	},
		{ &hf_nsrp_wst_group,
	  { "Wst group", "nsrp.wst",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "NSRP WST GROUP", HFILL }
	},
		{ &hf_nsrp_hst_group,
	  { "Hst group", "nsrp.hst",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "NSRP HST GROUP", HFILL }
	},
	{ &hf_nsrp_msgflag,
	  { "Msgflag", "nsrp.msgflag",
	    FT_UINT8, BASE_DEC, VALS(nsrp_flag_vals), 0,
	    "NSRP MSG FLAG", HFILL }
	},
	{ &hf_nsrp_msglen,
	  { "Msg Length", "nsrp.msglen",
	    FT_UINT16, BASE_DEC, NULL, 0,
	    "NSRP MESSAGE LENGTH", HFILL }
	},

	{ &hf_nsrp_encflag,
	  { "Enc Flag", "nsrp.encflag",
	    FT_UINT8, BASE_DEC, VALS(nsrp_encflag_vals), 0,
	    "NSRP ENCRYPT FLAG", HFILL }
	},
		{ &hf_nsrp_notused,
	  { "Not Used", "nsrp.notused",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    NULL, HFILL }
	},
		{ &hf_nsrp_total_size,
	  { "Total Size", "nsrp.totalsize",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "NSRP MSG TOTAL MESSAGE", HFILL }
	},
		{ &hf_nsrp_ns,
	  { "Ns", "nsrp.ns",
	    FT_UINT16, BASE_DEC, NULL, 0,
	    NULL, HFILL }
	},
		{ &hf_nsrp_nr,
	  { "Nr", "nsrp.nr",
	    FT_UINT16, BASE_DEC, NULL, 0,
	    NULL, HFILL }
	},
		{ &hf_nsrp_no_used,
	  { "Reserved", "nsrp.reserved",
	    FT_UINT16, BASE_DEC, NULL, 0,
	    NULL, HFILL }
	},
		{ &hf_nsrp_checksum,
	  { "Checksum", "nsrp.checksum",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "NSRP PACKET CHECKSUM", HFILL }
	},
		{ &hf_nsrp_authflag,
	  { "AuthFlag", "nsrp.authflag",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "NSRP Auth Flag", HFILL }
	},
			{ &hf_nsrp_priority,
	  { "Priority", "nsrp.priority",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "NSRP Priority", HFILL }
	},
			{ &hf_nsrp_dummy,
	  { "Dummy", "nsrp.dummy",
	    FT_UINT8, BASE_HEX, NULL, 0,
	    "NSRP Dummy", HFILL }
	},
		{ &hf_nsrp_authchecksum,
	  { "Checksum", "nsrp.authchecksum",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "NSRP AUTH CHECKSUM", HFILL }
	},
		{ &hf_nsrp_ifnum,
	  { "Ifnum", "nsrp.ifnum",
	    FT_UINT16, BASE_HEX, NULL, 0,
	    "NSRP IfNum", HFILL }
	},
	{ &hf_nsrp_data,
	  { "Data", "nsrp.data",
	    FT_STRING, BASE_NONE, NULL, 0,
	    "PADDING", HFILL }
	}
    };

    static gint *ett[] = {
	&ett_nsrp
    };

    proto_nsrp = proto_register_protocol("Juniper Netscreen Redundant Protocol",
	"NSRP", "nsrp");
    proto_register_field_array(proto_nsrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_nsrp(void)
{
    dissector_handle_t nsrp_handle;

    nsrp_handle = create_dissector_handle(dissect_nsrp, proto_nsrp);
    dissector_add_uint("ethertype", ETHERTYPE_NSRP, nsrp_handle);
}
