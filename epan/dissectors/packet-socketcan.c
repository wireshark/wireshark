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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>
#include <wiretap/wtap.h>

#include "packet-sll.h"
#include "packet-socketcan.h"

/* controller area network (CAN) kernel definitions
 * These masks are usually defined within <linux/can.h> but are not
 * available on non-Linux platforms; that's the reason for the
 * redefinitions below
 *
 * special address description flags for the CAN_ID */
#define CAN_EFF_FLAG 0x80000000 /* EFF/SFF is set in the MSB */
#define CAN_RTR_FLAG 0x40000000 /* remote transmission request */
#define CAN_ERR_FLAG 0x20000000 /* error frame */
#define CAN_EFF_MASK 0x1FFFFFFF /* extended frame format (EFF) */
#define CAN_SFF_MASK 0x000007FF /* standard frame format (SFF) */

void proto_register_socketcan(void);
void proto_reg_handoff_socketcan(void);

static int hf_can_len = -1;
static int hf_can_ident_ext = -1;
static int hf_can_ident_std = -1;
static int hf_can_extflag = -1;
static int hf_can_rtrflag = -1;
static int hf_can_errflag = -1;
static int hf_can_reserved = -1;
static int hf_can_padding = -1;

static int hf_canfd_brsflag = -1;
static int hf_canfd_esiflag = -1;

static gint ett_can = -1;
static gint ett_can_fd = -1;

static int proto_can = -1;
static int proto_canfd = -1;

static gboolean byte_swap = FALSE;

#define LINUX_CAN_STD   0
#define LINUX_CAN_EXT   1
#define LINUX_CAN_ERR   2

#define CAN_LEN_OFFSET     4
#define CAN_DATA_OFFSET    8

#define CANFD_FLAG_OFFSET  5

#define CANFD_BRS 0x01 /* bit rate switch (second bitrate for payload data) */
#define CANFD_ESI 0x02 /* error state indicator of the transmitting node */

static dissector_table_t subdissector_table;
static dissector_handle_t socketcan_bigendian_handle;
static dissector_handle_t socketcan_hostendian_handle;
static dissector_handle_t socketcan_fd_handle;

static const value_string frame_type_vals[] =
{
	{ LINUX_CAN_STD, "STD" },
	{ LINUX_CAN_EXT, "XTD" },
	{ LINUX_CAN_ERR, "ERR" },
	{ 0, NULL }
};

static void can_prompt(packet_info *pinfo _U_, gchar* result)
{
	g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Next level protocol as");
}

static gpointer can_value(packet_info *pinfo _U_)
{
	return 0;
}

static int
dissect_socketcan_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
						guint encoding)
{
	proto_tree *can_tree;
	proto_item *ti;
	guint8      frame_type;
	gint        frame_len;
	struct can_identifier can_id;
	guint32 raw_can_id;
	tvbuff_t*   next_tvb;
	int * can_flags[] = {
		&hf_can_ident_ext,
		&hf_can_extflag,
		&hf_can_rtrflag,
		&hf_can_errflag,
		NULL,
	};

	raw_can_id = tvb_get_guint32(tvb, 0, encoding);
	frame_len  = tvb_get_guint8( tvb, CAN_LEN_OFFSET);

	if (raw_can_id & CAN_EFF_FLAG)
	{
		frame_type = LINUX_CAN_EXT;
		can_id.id = raw_can_id & CAN_EFF_MASK;
	}
	else
	{
		frame_type = LINUX_CAN_STD;
		can_id.id = raw_can_id & CAN_SFF_MASK;
		can_flags[0] = &hf_can_ident_std;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAN");
	col_clear(pinfo->cinfo, COL_INFO);

	/* Error Message Frames are only encapsulated in Classic CAN frames */
	if (raw_can_id & CAN_ERR_FLAG)
	{
		frame_type = LINUX_CAN_ERR;
	}

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: 0x%08x   ",
		     val_to_str(frame_type, frame_type_vals, "Unknown (0x%02x)"), can_id.id);
	if (raw_can_id & CAN_RTR_FLAG)
	{
		col_append_str(pinfo->cinfo, COL_INFO, "(Remote Transmission Request)");
	}
	else
	{
		col_append_str(pinfo->cinfo, COL_INFO, tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, CAN_DATA_OFFSET, frame_len, ' '));
	}

	ti = proto_tree_add_item(tree, proto_can, tvb, 0, -1, ENC_NA);
	can_tree = proto_item_add_subtree(ti, ett_can);

	proto_tree_add_bitmask_list(can_tree, tvb, 0, 4, (const int**)can_flags, encoding);
	proto_tree_add_item(can_tree, hf_can_len, tvb, CAN_LEN_OFFSET, 1, ENC_NA);
	proto_tree_add_item(can_tree, hf_can_reserved, tvb, CAN_LEN_OFFSET+1, 3, ENC_NA);

	next_tvb = tvb_new_subset_length(tvb, CAN_DATA_OFFSET, frame_len);

	/* Functionality for choosing subdissector is controlled through Decode As as CAN doesn't
	   have a unique identifier to determine subdissector */
	if (!dissector_try_uint_new(subdissector_table, 0, next_tvb, pinfo, tree, TRUE, &can_id))
	{
		call_data_dissector(next_tvb, pinfo, tree);
	}

	if (tvb_captured_length_remaining(tvb, CAN_DATA_OFFSET+frame_len) > 0)
	{
		proto_tree_add_item(can_tree, hf_can_padding, tvb, CAN_DATA_OFFSET+frame_len, -1, ENC_NA);
	}

	return tvb_captured_length(tvb);
}

static int
dissect_socketcan_bigendian(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void* data _U_)
{
	return dissect_socketcan_common(tvb, pinfo, tree,
	    byte_swap ? ENC_LITTLE_ENDIAN : ENC_BIG_ENDIAN);
}

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
    #define ENC_ANTI_HOST_ENDIAN ENC_BIG_ENDIAN
#else
    #define ENC_ANTI_HOST_ENDIAN ENC_LITTLE_ENDIAN
#endif

static int
dissect_socketcan_hostendian(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void* data _U_)
{
	return dissect_socketcan_common(tvb, pinfo, tree,
	    byte_swap ? ENC_ANTI_HOST_ENDIAN : ENC_HOST_ENDIAN);
}

static int
dissect_socketcanfd_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
							guint encoding)
{
	proto_tree *can_tree;
	proto_item *ti;
	guint8      frame_type;
	gint        frame_len;
	struct can_identifier can_id;
	guint32 raw_can_id;
	tvbuff_t*   next_tvb;
	int * can_flags_fd[] = {
		&hf_can_ident_ext,
		&hf_can_extflag,
		NULL,
	};
	static const int * canfd_flag_fields[] = {
		&hf_canfd_brsflag,
		&hf_canfd_esiflag,
		NULL,
	};

	raw_can_id = tvb_get_guint32(tvb, 0, encoding);
	frame_len  = tvb_get_guint8( tvb, CAN_LEN_OFFSET);

	if (raw_can_id & CAN_EFF_FLAG)
	{
		frame_type = LINUX_CAN_EXT;
		can_id.id = raw_can_id & CAN_EFF_MASK;
	}
	else
	{
		frame_type = LINUX_CAN_STD;
		can_id.id = raw_can_id & CAN_SFF_MASK;
		can_flags_fd[0] = &hf_can_ident_std;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CANFD");
	col_clear(pinfo->cinfo, COL_INFO);

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: 0x%08x   %s",
		     val_to_str(frame_type, frame_type_vals, "Unknown (0x%02x)"), can_id.id,
		     tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, CAN_DATA_OFFSET, frame_len, ' '));

	ti = proto_tree_add_item(tree, proto_canfd, tvb, 0, -1, ENC_NA);
	can_tree = proto_item_add_subtree(ti, ett_can_fd);

	proto_tree_add_bitmask_list(can_tree, tvb, 0, 4, (const int**)can_flags_fd, encoding);

	proto_tree_add_item(can_tree, hf_can_len, tvb, CAN_LEN_OFFSET, 1, ENC_NA);
	proto_tree_add_bitmask_list(can_tree, tvb, CANFD_FLAG_OFFSET, 1, canfd_flag_fields, ENC_NA);
    proto_tree_add_item(can_tree, hf_can_reserved, tvb, CANFD_FLAG_OFFSET+1, 2, ENC_NA);

	next_tvb = tvb_new_subset_length(tvb, CAN_DATA_OFFSET, frame_len);

	/* Functionality for choosing subdissector is controlled through Decode As as CAN doesn't
	   have a unique identifier to determine subdissector */
	if (!dissector_try_uint_new(subdissector_table, 0, next_tvb, pinfo, tree, TRUE, &can_id))
	{
		call_data_dissector(next_tvb, pinfo, tree);
	}

    if (tvb_captured_length_remaining(tvb, CAN_DATA_OFFSET+frame_len) > 0)
    {
        proto_tree_add_item(can_tree, hf_can_padding, tvb, CAN_DATA_OFFSET+frame_len, -1, ENC_NA);
    }

	return tvb_captured_length(tvb);
}

static int
dissect_socketcan_fd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void* data _U_)
{
	return dissect_socketcanfd_common(tvb, pinfo, tree,
	    byte_swap ? ENC_ANTI_HOST_ENDIAN : ENC_HOST_ENDIAN);
}

void
proto_register_socketcan(void)
{
	static hf_register_info hf[] = {
		{
			&hf_can_ident_ext,
			{
				"Identifier", "can.id",
				FT_UINT32, BASE_HEX,
				NULL, CAN_EFF_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_can_ident_std,
			{
				"Identifier", "can.id",
				FT_UINT32, BASE_HEX,
				NULL, CAN_SFF_MASK,
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
				"Error Message Flag", "can.flags.err",
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
		},
		{
			&hf_can_reserved,
			{
				"Reserved", "can.reserved",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_can_padding,
			{
				"Padding", "can.padding",
				FT_BYTES, BASE_NONE,
				NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_canfd_brsflag,
			{
				"Bit Rate Setting", "canfd.flags.brs",
				FT_BOOLEAN, 8,
				NULL, CANFD_BRS,
				NULL, HFILL
			}
		},
		{
			&hf_canfd_esiflag,
			{
				"Error State Indicator", "canfd.flags.esi",
				FT_BOOLEAN, 8,
				NULL, CANFD_ESI,
				NULL, HFILL
			}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_can,
			&ett_can_fd
		};

	module_t *can_module;

	/* Decode As handling */
	static build_valid_func can_da_build_value[1] = {can_value};
	static decode_as_value_t can_da_values = {can_prompt, 1, can_da_build_value};
	static decode_as_t can_da = {"can", "Network", "can.subdissector", 1, 0, &can_da_values, NULL, NULL,
									decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

	proto_can = proto_register_protocol("Controller Area Network", "CAN", "can");
	socketcan_bigendian_handle = register_dissector("can-bigendian", dissect_socketcan_bigendian, proto_can);
	socketcan_hostendian_handle = register_dissector("can-hostendian", dissect_socketcan_hostendian, proto_can);

	proto_canfd = proto_register_protocol("Controller Area Network FD", "CANFD", "canfd");
	socketcan_fd_handle = register_dissector("canfd", dissect_socketcan_fd, proto_canfd);

	proto_register_field_array(proto_can, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	subdissector_table = register_dissector_table("can.subdissector",
		"CAN next level dissector", proto_can, FT_UINT32, BASE_HEX);

	can_module = prefs_register_protocol(proto_can, NULL);

	prefs_register_obsolete_preference(can_module, "protocol");
	prefs_register_bool_preference(can_module, "byte_swap",
	    "Byte-swap the CAN ID/flags field",
	    "Whether the CAN ID/flags field should be byte-swapped",
	    &byte_swap);

	register_decode_as(&can_da);
}

void
proto_reg_handoff_socketcan(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_SOCKETCAN, socketcan_bigendian_handle);
	dissector_add_uint("sll.ltype", LINUX_SLL_P_CAN, socketcan_hostendian_handle);
	dissector_add_uint("sll.ltype", LINUX_SLL_P_CANFD, socketcan_fd_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
