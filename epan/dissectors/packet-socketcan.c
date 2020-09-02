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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/decode_as.h>
#include <wiretap/wtap.h>

#include "packet-sll.h"
#include "packet-socketcan.h"

void proto_register_socketcan(void);
void proto_reg_handoff_socketcan(void);

static int hf_can_len = -1;
static int hf_can_infoent_ext = -1;
static int hf_can_infoent_std = -1;
static int hf_can_extflag = -1;
static int hf_can_rtrflag = -1;
static int hf_can_errflag = -1;
static int hf_can_reserved = -1;
static int hf_can_padding = -1;

static int hf_can_err_tx_timeout = -1;
static int hf_can_err_lostarb = -1;
static int hf_can_err_ctrl = -1;
static int hf_can_err_prot = -1;
static int hf_can_err_trx = -1;
static int hf_can_err_ack = -1;
static int hf_can_err_busoff = -1;
static int hf_can_err_buserror = -1;
static int hf_can_err_restarted = -1;
static int hf_can_err_reserved = -1;

static int hf_can_err_lostarb_bit_number = -1;

static int hf_can_err_ctrl_rx_overflow = -1;
static int hf_can_err_ctrl_tx_overflow = -1;
static int hf_can_err_ctrl_rx_warning = -1;
static int hf_can_err_ctrl_tx_warning = -1;
static int hf_can_err_ctrl_rx_passive = -1;
static int hf_can_err_ctrl_tx_passive = -1;
static int hf_can_err_ctrl_active = -1;

static int hf_can_err_prot_error_type_bit = -1;
static int hf_can_err_prot_error_type_form = -1;
static int hf_can_err_prot_error_type_stuff = -1;
static int hf_can_err_prot_error_type_bit0 = -1;
static int hf_can_err_prot_error_type_bit1 = -1;
static int hf_can_err_prot_error_type_overload = -1;
static int hf_can_err_prot_error_type_active = -1;
static int hf_can_err_prot_error_type_tx = -1;

static int hf_can_err_prot_error_location = -1;

static int hf_can_err_trx_canh = -1;
static int hf_can_err_trx_canl = -1;

static int hf_can_err_ctrl_specific = -1;

static expert_field ei_can_err_dlc_mismatch = EI_INIT;

static int hf_canfd_brsflag = -1;
static int hf_canfd_esiflag = -1;

static gint ett_can = -1;
static gint ett_can_fd = -1;

static int proto_can = -1;
static int proto_canfd = -1;

static gboolean byte_swap = FALSE;
static gboolean heuristic_first = FALSE;

static heur_dissector_list_t heur_subdissector_list;
static heur_dtbl_entry_t *heur_dtbl_entry;

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

static const value_string can_err_prot_error_location_vals[] =
{
	{ 0x00, "unspecified" },
	{ 0x02, "ID bits 28 - 21 (SFF: 10 - 3)" },
	{ 0x03, "start of frame" },
	{ 0x04, "substitute RTR (SFF: RTR)" },
	{ 0x05, "identifier extension" },
	{ 0x06, "ID bits 20 - 18 (SFF: 2 - 0)" },
	{ 0x07, "ID bits 17-13" },
	{ 0x08, "CRC sequence" },
	{ 0x09, "reserved bit 0" },
	{ 0x0A, "data section" },
	{ 0x0B, "data length code" },
	{ 0x0C, "RTR" },
	{ 0x0D, "reserved bit 1" },
	{ 0x0E, "ID bits 4-0" },
	{ 0x0F, "ID bits 12-5" },
	{ 0x12, "intermission" },
	{ 0x18, "CRC delimiter" },
	{ 0x19, "ACK slot" },
	{ 0x1A, "end of frame" },
	{ 0x1B, "ACK delimiter" },
	{ 0, NULL }
};

static const value_string can_err_trx_canh_vals[] =
{
	{ 0x00, "unspecified" },
	{ 0x04, "no wire" },
	{ 0x05, "short to BAT" },
	{ 0x06, "short to VCC" },
	{ 0x07, "short to GND" },
	{ 0, NULL }
};

static const value_string can_err_trx_canl_vals[] =
{
	{ 0x00, "unspecified" },
	{ 0x04, "no wire" },
	{ 0x05, "short to BAT" },
	{ 0x06, "short to VCC" },
	{ 0x07, "short to GND" },
	{ 0x08, "short to CANH" },
	{ 0, NULL }
};

static int
dissect_socketcan_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
						guint encoding)
{
	proto_tree *can_tree;
	proto_item *ti;
	guint8      frame_type;
	struct can_info can_info;
	int        * const *can_flags;

	static int * const can_std_flags[] = {
		&hf_can_infoent_std,
		&hf_can_extflag,
		&hf_can_rtrflag,
		&hf_can_errflag,
		NULL,
	};
	static int * const can_ext_flags[] = {
		&hf_can_infoent_ext,
		&hf_can_extflag,
		&hf_can_rtrflag,
		&hf_can_errflag,
		NULL,
	};
	static int * const can_err_flags[] = {
		&hf_can_errflag,
		&hf_can_err_tx_timeout,
		&hf_can_err_lostarb,
		&hf_can_err_ctrl,
		&hf_can_err_prot,
		&hf_can_err_trx,
		&hf_can_err_ack,
		&hf_can_err_busoff,
		&hf_can_err_buserror,
		&hf_can_err_restarted,
		&hf_can_err_reserved,
		NULL,
	};

	can_info.id = tvb_get_guint32(tvb, 0, encoding);
	can_info.len = tvb_get_guint8(tvb, CAN_LEN_OFFSET);
	can_info.fd = FALSE;

	/* Error Message Frames are only encapsulated in Classic CAN frames */
	if (can_info.id & CAN_ERR_FLAG)
	{
		frame_type = LINUX_CAN_ERR;
		can_flags  = can_err_flags;
	}
	else if (can_info.id & CAN_EFF_FLAG)
	{
		frame_type = LINUX_CAN_EXT;
		can_info.id &= (CAN_EFF_MASK | CAN_FLAG_MASK);
		can_flags  = can_ext_flags;
	}
	else
	{
		frame_type = LINUX_CAN_STD;
		can_info.id &= (CAN_SFF_MASK | CAN_FLAG_MASK);
		can_flags  = can_std_flags;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CAN");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_can, tvb, 0, -1, ENC_NA);
	can_tree = proto_item_add_subtree(ti, ett_can);

	proto_tree_add_bitmask_list(can_tree, tvb, 0, 4, can_flags, encoding);
	proto_tree_add_item(can_tree, hf_can_len, tvb, CAN_LEN_OFFSET, 1, ENC_NA);
	if (frame_type == LINUX_CAN_ERR && can_info.len != CAN_ERR_DLC)
	{
		proto_tree_add_expert(tree, pinfo, &ei_can_err_dlc_mismatch, tvb, CAN_LEN_OFFSET, 1);
	}
	proto_tree_add_item(can_tree, hf_can_reserved, tvb, CAN_LEN_OFFSET+1, 3, ENC_NA);

	if (frame_type == LINUX_CAN_ERR)
	{
		int * const *flag;
		const char *sepa = ": ";

		col_set_str(pinfo->cinfo, COL_INFO, "ERR");

		for (flag = can_err_flags; *flag; flag++)
		{
			header_field_info *hfi;

			hfi = proto_registrar_get_nth(**flag);
			if (!hfi)
				continue;

			if ((can_info.id & hfi->bitmask & ~CAN_FLAG_MASK) == 0)
				continue;

			col_append_sep_str(pinfo->cinfo, COL_INFO, sepa, hfi->name);
			sepa = ", ";
		}

		if (can_info.id & CAN_ERR_LOSTARB)
			proto_tree_add_item(can_tree, hf_can_err_lostarb_bit_number, tvb, CAN_DATA_OFFSET+0, 1, ENC_NA);
		if (can_info.id & CAN_ERR_CTRL)
		{
			static int * const can_err_ctrl_flags[] = {
				&hf_can_err_ctrl_rx_overflow,
				&hf_can_err_ctrl_tx_overflow,
				&hf_can_err_ctrl_rx_warning,
				&hf_can_err_ctrl_tx_warning,
				&hf_can_err_ctrl_rx_passive,
				&hf_can_err_ctrl_tx_passive,
				&hf_can_err_ctrl_active,
				NULL,
			};

			proto_tree_add_bitmask_list(can_tree, tvb, CAN_DATA_OFFSET+1, 1, can_err_ctrl_flags, ENC_NA);
		}
		if (can_info.id & CAN_ERR_PROT)
		{
			static int * const can_err_prot_error_type_flags[] = {
				&hf_can_err_prot_error_type_bit,
				&hf_can_err_prot_error_type_form,
				&hf_can_err_prot_error_type_stuff,
				&hf_can_err_prot_error_type_bit0,
				&hf_can_err_prot_error_type_bit1,
				&hf_can_err_prot_error_type_overload,
				&hf_can_err_prot_error_type_active,
				&hf_can_err_prot_error_type_tx,
				NULL
			};
			proto_tree_add_bitmask_list(can_tree, tvb, CAN_DATA_OFFSET+2, 1, can_err_prot_error_type_flags, ENC_NA);
			proto_tree_add_item(can_tree, hf_can_err_prot_error_location, tvb, CAN_DATA_OFFSET+3, 1, ENC_NA);
		}
		if (can_info.id & CAN_ERR_TRX)
		{
			proto_tree_add_item(can_tree, hf_can_err_trx_canh, tvb, CAN_DATA_OFFSET+4, 1, ENC_NA);
			proto_tree_add_item(can_tree, hf_can_err_trx_canl, tvb, CAN_DATA_OFFSET+4, 1, ENC_NA);
		}
		proto_tree_add_item(can_tree, hf_can_err_ctrl_specific, tvb, CAN_DATA_OFFSET+5, 3, ENC_NA);
	}
	else
	{
		tvbuff_t   *next_tvb;

		col_add_fstr(pinfo->cinfo, COL_INFO, "%s: 0x%08x   ",
			     val_to_str(frame_type, frame_type_vals, "Unknown (0x%02x)"), (can_info.id & ~CAN_FLAG_MASK));

		if (can_info.id & CAN_RTR_FLAG)
		{
			col_append_str(pinfo->cinfo, COL_INFO, "(Remote Transmission Request)");
		}
		else
		{
			col_append_str(pinfo->cinfo, COL_INFO, tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, CAN_DATA_OFFSET, can_info.len, ' '));
		}

		next_tvb = tvb_new_subset_length(tvb, CAN_DATA_OFFSET, can_info.len);
		if (!dissector_try_payload_new(subdissector_table, next_tvb, pinfo, tree, TRUE, &can_info))
		{
			call_data_dissector(next_tvb, pinfo, tree);
		}
	}

	if (tvb_captured_length_remaining(tvb, CAN_DATA_OFFSET+can_info.len) > 0)
	{
		proto_tree_add_item(can_tree, hf_can_padding, tvb, CAN_DATA_OFFSET+can_info.len, -1, ENC_NA);
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
	struct can_info can_info;
	tvbuff_t*   next_tvb;
	int * can_flags_fd[] = {
		&hf_can_infoent_ext,
		&hf_can_extflag,
		NULL,
	};
	static int * const canfd_flag_fields[] = {
		&hf_canfd_brsflag,
		&hf_canfd_esiflag,
		NULL,
	};

	can_info.id = tvb_get_guint32(tvb, 0, encoding);
	can_info.len = tvb_get_guint8(tvb, CAN_LEN_OFFSET);
	can_info.fd = TRUE;

	if (can_info.id & CAN_EFF_FLAG)
	{
		frame_type = LINUX_CAN_EXT;
		can_info.id &= (CAN_EFF_MASK | CAN_FLAG_MASK);
	}
	else
	{
		frame_type = LINUX_CAN_STD;
		can_info.id &= (CAN_SFF_MASK | CAN_FLAG_MASK);
		can_flags_fd[0] = &hf_can_infoent_std;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CANFD");
	col_clear(pinfo->cinfo, COL_INFO);

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: 0x%08x   %s",
		     val_to_str(frame_type, frame_type_vals, "Unknown (0x%02x)"), (can_info.id & ~CAN_FLAG_MASK),
		     tvb_bytes_to_str_punct(wmem_packet_scope(), tvb, CAN_DATA_OFFSET, can_info.len, ' '));

	ti = proto_tree_add_item(tree, proto_canfd, tvb, 0, -1, ENC_NA);
	can_tree = proto_item_add_subtree(ti, ett_can_fd);

	proto_tree_add_bitmask_list(can_tree, tvb, 0, 4, can_flags_fd, encoding);

	proto_tree_add_item(can_tree, hf_can_len, tvb, CAN_LEN_OFFSET, 1, ENC_NA);
	proto_tree_add_bitmask_list(can_tree, tvb, CANFD_FLAG_OFFSET, 1, canfd_flag_fields, ENC_NA);
	proto_tree_add_item(can_tree, hf_can_reserved, tvb, CANFD_FLAG_OFFSET+1, 2, ENC_NA);

	next_tvb = tvb_new_subset_length(tvb, CAN_DATA_OFFSET, can_info.len);

	if(!heuristic_first)
	{
		if (!dissector_try_payload_new(subdissector_table, next_tvb, pinfo, tree, TRUE, &can_info))
		{
			if(!dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &heur_dtbl_entry, &can_info))
			{
				call_data_dissector(next_tvb, pinfo, tree);
			}
		}
	}
	else
	{
		if (!dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &heur_dtbl_entry, &can_info))
		{
			if(!dissector_try_payload_new(subdissector_table, next_tvb, pinfo, tree, FALSE, &can_info))
			{
				call_data_dissector(next_tvb, pinfo, tree);
			}
		}
	}

	if (tvb_captured_length_remaining(tvb, CAN_DATA_OFFSET+can_info.len) > 0)
	{
		proto_tree_add_item(can_tree, hf_can_padding, tvb, CAN_DATA_OFFSET+can_info.len, -1, ENC_NA);
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
			&hf_can_infoent_ext,
			{
				"Identifier", "can.id",
				FT_UINT32, BASE_HEX,
				NULL, CAN_EFF_MASK,
				NULL, HFILL
			}
		},
		{
			&hf_can_infoent_std,
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
		{
			&hf_can_err_tx_timeout,
			{
				"Transmit timeout", "can.err.tx_timeout",
				FT_BOOLEAN, 32,
				NULL, CAN_ERR_TX_TIMEOUT,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_lostarb,
			{
				"Lost arbitration", "can.err.lostarb",
				FT_BOOLEAN, 32,
				NULL, CAN_ERR_LOSTARB,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_ctrl,
			{
				"Controller problems", "can.err.ctrl",
				FT_BOOLEAN, 32,
				NULL, CAN_ERR_CTRL,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_prot,
			{
				"Protocol violation", "can.err.prot",
				FT_BOOLEAN, 32,
				NULL, CAN_ERR_PROT,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_trx,
			{
				"Transceiver status", "can.err.trx",
				FT_BOOLEAN, 32,
				NULL, CAN_ERR_TRX,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_ack,
			{
				"No acknowledgement", "can.err.ack",
				FT_BOOLEAN, 32,
				NULL, CAN_ERR_ACK,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_busoff,
			{
				"Bus off", "can.err.busoff",
				FT_BOOLEAN, 32,
				NULL, CAN_ERR_BUSOFF,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_buserror,
			{
				"Bus error", "can.err.buserror",
				FT_BOOLEAN, 32,
				NULL, CAN_ERR_BUSERROR,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_restarted,
			{
				"Controller restarted", "can.err.restarted",
				FT_BOOLEAN, 32,
				NULL, CAN_ERR_RESTARTED,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_reserved,
			{
				"Reserved", "can.err.reserved",
				FT_UINT32, BASE_HEX,
				NULL, CAN_ERR_RESERVED,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_lostarb_bit_number,
			{
				"Lost arbitration in bit number", "can.err.lostarb.bitnum",
				FT_UINT8, BASE_DEC,
				NULL, 0,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_ctrl_rx_overflow,
			{
				"RX buffer overflow", "can.err.ctrl.rx_overflow",
				FT_BOOLEAN, 8,
				NULL, 0x01,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_ctrl_tx_overflow,
			{
				"TX buffer overflow", "can.err.ctrl.tx_overflow",
				FT_BOOLEAN, 8,
				NULL, 0x02,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_ctrl_rx_warning,
			{
				"Reached warning level for RX errors", "can.err.ctrl.rx_warning",
				FT_BOOLEAN, 8,
				NULL, 0x04,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_ctrl_tx_warning,
			{
				"Reached warning level for TX errors", "can.err.ctrl.tx_warning",
				FT_BOOLEAN, 8,
				NULL, 0x08,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_ctrl_rx_passive,
			{
				"Reached error passive status RX", "can.err.ctrl.rx_passive",
				FT_BOOLEAN, 8,
				NULL, 0x10,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_ctrl_tx_passive,
			{
				"Reached error passive status TX", "can.err.ctrl.tx_passive",
				FT_BOOLEAN, 8,
				NULL, 0x20,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_ctrl_active,
			{
				"Recovered to error active state", "can.err.ctrl.active",
				FT_BOOLEAN, 8,
				NULL, 0x40,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_prot_error_type_bit,
			{
				"Single bit error", "can.err.prot.type.bit",
				FT_BOOLEAN, 8,
				NULL, 0x01,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_prot_error_type_form,
			{
				"Frame format error", "can.err.prot.type.form",
				FT_BOOLEAN, 8,
				NULL, 0x02,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_prot_error_type_stuff,
			{
				"Bit stuffing error", "can.err.prot.type.stuff",
				FT_BOOLEAN, 8,
				NULL, 0x04,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_prot_error_type_bit0,
			{
				"Unable to send dominant bit", "can.err.prot.type.bit0",
				FT_BOOLEAN, 8,
				NULL, 0x08,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_prot_error_type_bit1,
			{
				"Unable to send recessive bit", "can.err.prot.type.bit1",
				FT_BOOLEAN, 8,
				NULL, 0x10,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_prot_error_type_overload,
			{
				"Bus overload", "can.err.prot.type.overload",
				FT_BOOLEAN, 8,
				NULL, 0x20,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_prot_error_type_active,
			{
				"Active error announcement", "can.err.prot.type.active",
				FT_BOOLEAN, 8,
				NULL, 0x40,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_prot_error_type_tx,
			{
				"Error occurred on transmission", "can.err.prot.type.tx",
				FT_BOOLEAN, 8,
				NULL, 0x80,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_prot_error_location,
			{
				"Protocol error location", "can.err.prot.location",
				FT_UINT8, BASE_DEC,
				VALS(can_err_prot_error_location_vals), 0,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_trx_canh,
			{
				"Transceiver CANH status", "can.err.trx.canh",
				FT_UINT8, BASE_DEC,
				VALS(can_err_trx_canh_vals), 0x0F,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_trx_canl,
			{
				"Transceiver CANL status", "can.err.trx.canl",
				FT_UINT8, BASE_DEC,
				VALS(can_err_trx_canl_vals), 0xF0,
				NULL, HFILL
			}
		},
		{
			&hf_can_err_ctrl_specific,
			{
				"Controller specific data", "can.err.ctrl_specific",
				FT_BYTES, SEP_SPACE,
				NULL, 0,
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

	static ei_register_info ei[] = {
		{
			&ei_can_err_dlc_mismatch,
			{
				"can.err.dlc_mismatch", PI_MALFORMED, PI_ERROR,
				"ERROR: DLC mismatch", EXPFILL
			}
		}
	};

	module_t *can_module;

	proto_can = proto_register_protocol("Controller Area Network", "CAN", "can");
	socketcan_bigendian_handle = register_dissector("can-bigendian", dissect_socketcan_bigendian, proto_can);
	socketcan_hostendian_handle = register_dissector("can-hostendian", dissect_socketcan_hostendian, proto_can);

	proto_canfd = proto_register_protocol("Controller Area Network FD", "CANFD", "canfd");
	socketcan_fd_handle = register_dissector("canfd", dissect_socketcan_fd, proto_canfd);

	proto_register_field_array(proto_can, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_register_field_array(expert_register_protocol(proto_can), ei, array_length(ei));

	can_module = prefs_register_protocol(proto_can, NULL);

	prefs_register_obsolete_preference(can_module, "protocol");
	prefs_register_bool_preference(can_module, "byte_swap",
	    "Byte-swap the CAN ID/flags field",
	    "Whether the CAN ID/flags field should be byte-swapped",
	    &byte_swap);

	prefs_register_bool_preference(can_module, "try_heuristic_first",
		"Try heuristic sub-dissectors first",
		"Try to decode a packet using an heuristic sub-dissector"
		" before using a sub-dissector registered to \"decode as\"",
		&heuristic_first);

	subdissector_table = register_decode_as_next_proto(proto_can, "can.subdissector", "CAN next level dissector", NULL);

	heur_subdissector_list = register_heur_dissector_list("can", proto_can);
}

void
proto_reg_handoff_socketcan(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_SOCKETCAN, socketcan_bigendian_handle);
	dissector_add_uint("sll.ltype", LINUX_SLL_P_CAN, socketcan_hostendian_handle);
	dissector_add_uint("sll.ltype", LINUX_SLL_P_CANFD, socketcan_fd_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
