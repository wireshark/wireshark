/* packet-socketcan.c
 * Routines for disassembly of packets from SocketCAN
 * Felix Obenhuber <felix@obenhuber.de>
 *
 * Added support for the DeviceNet Dissector
 * Hans-Joergen Gunnarsson <hag@hms.se>
 * Copyright 2013
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <prefs.h>
#include <wiretap/wtap.h>

#include "packet-sll.h"

/* controller area network (CAN) kernel definitions
 * These masks are usually defined within <linux/can.h> but are not
 * available on non-Linux platforms; that's the reason for the
 * redefinitions below
 *
 * special address description flags for the CAN_ID */
#define CAN_EFF_FLAG 0x80000000U /* EFF/SFF is set in the MSB */
#define CAN_RTR_FLAG 0x40000000U /* remote transmission request */
#define CAN_ERR_FLAG 0x20000000U /* error frame */
#define CAN_EFF_MASK 0x1FFFFFFFU /* extended frame format (EFF) */

void proto_register_socketcan(void);
void proto_reg_handoff_socketcan(void);

static int hf_can_len = -1;
static int hf_can_ident = -1;
static int hf_can_extflag = -1;
static int hf_can_rtrflag = -1;
static int hf_can_errflag = -1;

static gint ett_can = -1;

static int proto_can = -1;

static dissector_handle_t data_handle;
static dissector_handle_t canopen_handle;
static dissector_handle_t devicenet_handle;
static dissector_handle_t j1939_handle;

#define LINUX_CAN_STD   0
#define LINUX_CAN_EXT   1
#define LINUX_CAN_RTR   2
#define LINUX_CAN_ERR   3

#define CAN_LEN_OFFSET  4
#define CAN_DATA_OFFSET 8

typedef enum {
	CAN_DATA_DISSECTOR = 1,
	CAN_CANOPEN_DISSECTOR = 2,
	CAN_DEVICENET_DISSECTOR = 3,
	CAN_J1939_DISSECTOR = 4
} Dissector_Option;

/* Structure that gets passed between dissectors.  Since it's just a simple 32-bit
   value, no sense in creating a header file for it.  Just expect subdissectors
   to provide their own.
 */
struct can_identifier
{
	guint32 id;
};

static const enum_val_t can_high_level_protocol_dissector_options[] = {
	{ "raw",		"Raw data (no further dissection)",	CAN_DATA_DISSECTOR },
	{ "CANopen",	"CANopen protocol",			CAN_CANOPEN_DISSECTOR },
	{ "DeviceNet",	"DeviceNet protocol",			CAN_DEVICENET_DISSECTOR },
	{ "J1939",		"J1939 protocol",			CAN_J1939_DISSECTOR },
	{ NULL,	NULL, 0 }
};

static guint can_high_level_protocol_dissector = CAN_DATA_DISSECTOR;

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
	proto_tree *can_tree;
	proto_item *ti;
	guint8      frame_type;
	gint        frame_len;
	struct can_identifier can_id;
	tvbuff_t*   next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAN");
	col_clear(pinfo->cinfo,COL_INFO);

	frame_len  = tvb_get_guint8( tvb, CAN_LEN_OFFSET);
	can_id.id  = tvb_get_ntohl(tvb, 0);

	if (can_id.id & CAN_RTR_FLAG)
	{
		frame_type = LINUX_CAN_RTR;
	}
	else if (can_id.id & CAN_ERR_FLAG)
	{
		frame_type = LINUX_CAN_ERR;
	}
	else if (can_id.id & CAN_EFF_FLAG)
	{
		frame_type = LINUX_CAN_EXT;
	}
	else
	{
		frame_type = LINUX_CAN_STD;
	}

	can_id.id &= CAN_EFF_MASK;

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: 0x%08x",
		     val_to_str(frame_type, frame_type_vals, "Unknown (0x%02x)"), can_id.id);
	col_append_fstr(pinfo->cinfo, COL_INFO, "   %s",
			tvb_bytes_to_ep_str_punct(tvb, CAN_DATA_OFFSET, frame_len, ' '));

	ti       = proto_tree_add_item(tree, proto_can, tvb, 0, -1, ENC_NA);
	can_tree = proto_item_add_subtree(ti, ett_can);

	proto_tree_add_item(can_tree, hf_can_ident,   tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(can_tree, hf_can_extflag, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(can_tree, hf_can_rtrflag, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(can_tree, hf_can_errflag, tvb, 0, 4, ENC_BIG_ENDIAN);

	proto_tree_add_item(can_tree, hf_can_len,     tvb, CAN_LEN_OFFSET, 1, ENC_BIG_ENDIAN);

	next_tvb = tvb_new_subset_length(tvb, CAN_DATA_OFFSET, frame_len);

	switch (can_high_level_protocol_dissector)
	{
		case CAN_DATA_DISSECTOR:
			call_dissector(data_handle, next_tvb, pinfo, tree);
			break;
		case CAN_CANOPEN_DISSECTOR:
			call_dissector_with_data(canopen_handle, next_tvb, pinfo, tree, &can_id);
			break;
		case CAN_DEVICENET_DISSECTOR:
			/* XXX - Not sure this is correct.  But the capture provided in
             * bug 8564 provides CAN ID in little endian format, so this makes it work */
			can_id.id = GUINT32_SWAP_LE_BE(can_id.id);

			call_dissector_with_data(devicenet_handle, next_tvb, pinfo, tree, &can_id);
			break;
		case CAN_J1939_DISSECTOR:
			call_dissector_with_data(j1939_handle, next_tvb, pinfo, tree, &can_id);
			break;
	}
}

void
proto_register_socketcan(void)
{
	static hf_register_info hf[] = {
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
	module_t *can_module;

	proto_can = proto_register_protocol(
		"Controller Area Network",	/* name       */
		"CAN",				/* short name */
		"can"				/* abbrev     */
		);

	proto_register_field_array(proto_can, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	can_module = prefs_register_protocol(proto_can, NULL);

	prefs_register_enum_preference(
		can_module,
		"protocol",
		"Next level protocol",
		"Next level protocol like CANopen etc.",
		(gint *)&can_high_level_protocol_dissector,
		can_high_level_protocol_dissector_options,
		FALSE
		);
}

void
proto_reg_handoff_socketcan(void)
{
	dissector_handle_t can_handle;

	can_handle = create_dissector_handle(dissect_socketcan, proto_can);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_SOCKETCAN, can_handle);
	dissector_add_uint("sll.ltype", LINUX_SLL_P_CAN, can_handle);

	canopen_handle = find_dissector("canopen");
	devicenet_handle = find_dissector("devicenet");
	j1939_handle   = find_dissector("j1939");
	data_handle    = find_dissector("data");
}
