/* packet-socketcan.c
 * Routines for disassembly of packets from SocketCAN
 * Felix Obenhuber <felix@obenhuber.de>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <prefs.h>
#include "packet-sll.h"

/* controller area network (CAN) kernel definitions
 * This maskare usualy defined within <linux/can.h> but not
 * available on non-Linux platforms - that the reason for the
 * redefinition right here
 *
 * special address description flags for the CAN_ID */
#define CAN_EFF_FLAG 0x80000000U /* EFF/SFF is set in the MSB */
#define CAN_RTR_FLAG 0x40000000U /* remote transmission request */
#define CAN_ERR_FLAG 0x20000000U /* error frame */
#define CAN_EFF_MASK 0x1FFFFFFFU /* extended frame format (EFF) */


static int hf_can_len = -1;
static int hf_can_ident = -1;
static int hf_can_extflag = -1;
static int hf_can_rtrflag = -1;
static int hf_can_errflag = -1;

static gint ett_can = -1;

static int proto_can = -1;

static dissector_handle_t data_handle;
static dissector_handle_t canopen_handle;

static module_t *can_module;

#define LINUX_CAN_STD 0
#define LINUX_CAN_EXT 1
#define LINUX_CAN_RTR 2
#define LINUX_CAN_ERR 3

#define CAN_LEN_OFFSET 4
#define CAN_DATA_OFFSET 8

typedef enum {
  DATA_DISSECTOR = 1,
  CANOPEN_DISSECTOR = 2
} Dissector_Option;

static enum_val_t can_high_level_protocol_dissector_options[] = {
  { "raw",	"Raw data (no further dissection)",	DATA_DISSECTOR },
  { "CANopen",	"CANopen protocol",	CANOPEN_DISSECTOR },
  { NULL,	NULL,				0 }
};

static guint can_high_level_protocol_dissector = DATA_DISSECTOR;

static const value_string frame_type_vals[] =
{
	{ LINUX_CAN_STD, "STD" },
	{ LINUX_CAN_EXT, "XTD" },
	{ LINUX_CAN_RTR, "RTR" },
	{ LINUX_CAN_ERR, "ERR" },
	{ 0, NULL }
};

static void
dissect_socketcan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 frame_type = LINUX_CAN_STD;
	tvbuff_t *next_tvb;
	guint8 frame_len = tvb_get_guint8( tvb, CAN_LEN_OFFSET );
	guint32 id = tvb_get_ntohl(tvb, 0);

	if( id & CAN_RTR_FLAG )
	{
		frame_type = LINUX_CAN_RTR;
	}
	else if ( id & CAN_ERR_FLAG )
	{
		frame_type = LINUX_CAN_ERR;
	}
	else if( id & CAN_EFF_FLAG )
	{
		frame_type = LINUX_CAN_EXT;
	}

	id &= CAN_EFF_MASK;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAN");
	col_clear(pinfo->cinfo,COL_INFO);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: 0x%08x", val_to_str(frame_type, frame_type_vals, "Unknown (0x%02x)"), id );
	col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(tvb, CAN_DATA_OFFSET, frame_len, ' '));

	if (tree)
	{
		proto_tree *can_tree = NULL;
		proto_item *ti = proto_tree_add_item(tree, proto_can, tvb, 0, 1 , ENC_NA );
		can_tree = proto_item_add_subtree(ti, ett_can);

		proto_tree_add_item(can_tree, hf_can_ident, tvb, 0, 4, ENC_BIG_ENDIAN );
		proto_tree_add_item(can_tree, hf_can_extflag, tvb, 0, 4, ENC_BIG_ENDIAN );
		proto_tree_add_item(can_tree, hf_can_rtrflag, tvb, 0, 4, ENC_BIG_ENDIAN );
		proto_tree_add_item(can_tree, hf_can_errflag, tvb, 0, 4, ENC_BIG_ENDIAN );
		proto_tree_add_item(can_tree, hf_can_len, tvb, CAN_LEN_OFFSET, 1, ENC_BIG_ENDIAN );

		switch (can_high_level_protocol_dissector)
		{
			case DATA_DISSECTOR:
				next_tvb =  tvb_new_subset(tvb, CAN_DATA_OFFSET, tvb_get_guint8(tvb, CAN_LEN_OFFSET), 8 );
				call_dissector(data_handle, next_tvb, pinfo, tree );
				break;
			case CANOPEN_DISSECTOR:
				call_dissector(canopen_handle, tvb, pinfo, tree );
				break;
		}
	}
}

void
proto_reg_handoff_socketcan(void)
{
	dissector_handle_t can_handle;

	data_handle = find_dissector("data");
	canopen_handle = find_dissector("canopen");

	can_handle = create_dissector_handle(dissect_socketcan, proto_can);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_SOCKETCAN, can_handle);
	dissector_add_uint("sll.ltype", LINUX_SLL_P_CAN, can_handle);
}

void
proto_register_socketcan(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_can_ident,
			{
				"Identifier", "can.id",
					FT_UINT32, BASE_HEX,
					NULL, CAN_EFF_MASK,
					NULL, HFILL
			}
		},
		{
			&hf_can_extflag,
			{
				"Extended Flag", "can.flags.xtd",
					FT_BOOLEAN, 32,
					NULL, CAN_EFF_FLAG,
					NULL, HFILL
			}
		},
		{
			&hf_can_rtrflag,
			{
				"Remote Transmission Request Flag", "can.flags.rtr",
					FT_BOOLEAN, 32,
					NULL, CAN_RTR_FLAG,
					NULL, HFILL
			}
		},
		{
			&hf_can_errflag,
			{
				"Error Flag", "can.flags.err",
					FT_BOOLEAN, 32,
					NULL, CAN_ERR_FLAG,
					NULL, HFILL
			}
		},
		{
			&hf_can_len,
			{
				"Frame-Length", "can.len",
					FT_UINT8, BASE_DEC,
					NULL, 0x0,
					NULL, HFILL
			}
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
	{
		&ett_can
	};

	proto_can = proto_register_protocol (
		"Controller Area Network",/* name       */
		"CAN",					 /* short name */
		"can"					 /* abbrev     */
		);

	proto_register_field_array(proto_can, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	can_module = prefs_register_protocol(proto_can, proto_reg_handoff_socketcan);

	prefs_register_enum_preference(can_module, "protocol",
					 "Next level protocol",
					 "Next level protocol like CANopen etc.",
					 (gint *)&can_high_level_protocol_dissector,
					 can_high_level_protocol_dissector_options, FALSE);
}

/* eof */
