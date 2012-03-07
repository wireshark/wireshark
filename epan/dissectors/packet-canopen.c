/* packet-canopen.c
 * Routines for CANopen dissection
 * Copyright 2011, Yegor Yefremov <yegorslists@googlemail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

/* Initialize the protocol and registered fields */
static int proto_canopen = -1;
static int hf_canopen_cob_id = -1;
static int hf_canopen_type = -1;
static int hf_canopen_function_code = -1;
static int hf_canopen_node_id = -1;
static int hf_canopen_pdo_data = -1;
static int hf_canopen_pdo_data_string = -1;
static int hf_canopen_sdo_cmd = -1;
static int hf_canopen_sdo_main_idx = -1;
static int hf_canopen_sdo_sub_idx = -1;
static int hf_canopen_sdo_data = -1;
static int hf_canopen_em_err_code = -1;
static int hf_canopen_em_err_reg = -1;
static int hf_canopen_em_err_field = -1;
static int hf_canopen_nmt_ctrl_cs = -1;
static int hf_canopen_nmt_ctrl_node_id = -1;
static int hf_canopen_nmt_guard_state = -1;
static int hf_canopen_time_stamp = -1;
static int hf_canopen_time_stamp_ms = -1;
static int hf_canopen_time_stamp_days = -1;

/* Initialize the subtree pointers */
static gint ett_canopen = -1;

/* broadcast messages */
#define FC_NMT			0x0
#define FC_SYNC			0x1
#define FC_TIME_STAMP		0x2

/* point-to-point messages */
#define FC_EMERGENCY		0x1
#define FC_PDO1_TX		0x3
#define FC_PDO1_RX		0x4
#define FC_PDO2_TX		0x5
#define FC_PDO2_RX		0x6
#define FC_PDO3_TX		0x7
#define FC_PDO3_RX		0x8
#define FC_PDO4_TX		0x9
#define FC_PDO4_RX		0xA
#define FC_DEFAULT_SDO_TX	0xB
#define FC_DEFAULT_SDO_RX	0xC
#define FC_NMT_ERR_CONTROL	0xE

static const value_string CAN_open_bcast_msg_type_vals[] = {
	{ FC_NMT,              "EMERGENCY"},
	{ FC_SYNC,             "Sync"},
	{ FC_TIME_STAMP,       "TIME STAMP"},
	{ 0, NULL}
};

static const value_string CAN_open_p2p_msg_type_vals[] = {
	{ FC_EMERGENCY,        "EMERGENCY"},
	{ FC_PDO1_TX,          "PDO1 (tx)"},
	{ FC_PDO1_RX,          "PDO1 (rx)"},
	{ FC_PDO2_TX,          "PDO2 (tx)"},
	{ FC_PDO2_RX,          "PDO2 (rx)"},
	{ FC_PDO3_TX,          "PDO3 (tx)"},
	{ FC_PDO3_RX,          "PDO3 (rx)"},
	{ FC_PDO4_TX,          "PDO4 (tx)"},
	{ FC_PDO4_RX,          "PDO4 (rx)"},
	{ FC_DEFAULT_SDO_TX,   "Default-SDO (tx)"},
	{ FC_DEFAULT_SDO_RX,   "Default-SDO (rx)"},
	{ FC_NMT_ERR_CONTROL,  "NMT Error Control"},
	{ 0, NULL}
};

/* message types */
#define MT_UNKNOWN			0
#define MT_NMT_CTRL			1
#define MT_SYNC				2
#define MT_TIME_STAMP		3
#define MT_EMERGENCY		4
#define MT_PDO				5
#define MT_SDO				6
#define MT_NMT_GUARD			7

/* PDO offsets */
#define CO_PDO_DATA_OFFSET		8

/* SDO offsets */
#define CO_SDO_CMD_OFFSET			8
#define CO_SDO_MAIN_IDX_OFFSET		9
#define CO_SDO_MAIN_SUB_OFFSET		11
#define CO_SDO_DATA_OFFSET			12

/* EMERGENCY offsets */
#define CO_EM_ERR_CODE_OFFSET		8
#define CO_EM_ERR_REG_OFFSET		10
#define CO_EM_ERR_FIELD_OFFSET		11

/* NMT offsets */
#define CO_NMT_CTRL_CS_OFFSET		8
#define CO_NMT_CTRL_NODE_ID_OFFSET	9
#define CO_NMT_GUARD_STATE_OFFSET	8

/* TIME STAMP offsets */
#define CO_TIME_STAMP_MS_OFFSET		8
#define CO_TIME_STAMP_DAYS_OFFSET	12

/* TIME STAMP conversion defines */
#define TS_DAYS_BETWEEN_1970_AND_1984	5113
#define TS_SECONDS_IN_PER_DAY		86400
#define TS_NANOSEC_PER_MSEC		1000000

/* NMT command specifiers */
static const value_string nmt_ctrl_cs[] = {
	{ 0x1, "Start remote node"},
	{ 0x2, "Stop remote node"},
	{ 0x80, "Enter pre-operational state"},
	{ 0x81, "Reset node"},
	{ 0x82, "Reset communication"},
	{ 0, NULL}
};

/* NMT states */
static const value_string nmt_guard_state[] = {
	{ 0x0, "Initialising"},
	{ 0x1, "Disconnected"},
	{ 0x2, "Connecting"},
	{ 0x3, "Preparing"},
	{ 0x4, "Stopped"},
	{ 0x5, "Operational"},
	{ 0x7F, "Pre-operational"},
	{ 0, NULL}
};

static void
canopen_detect_msg_type(guint function_code, guint node_id,guint *msg_type_id)
{
	switch(function_code)
	{
		case FC_NMT:
			*msg_type_id = MT_NMT_CTRL;
			break;
		case FC_SYNC:
			if (!node_id)
			{
				*msg_type_id = MT_SYNC;
			}
			else
			{
				*msg_type_id = MT_EMERGENCY;
			}
			break;
		case FC_TIME_STAMP:
			*msg_type_id = MT_TIME_STAMP;
			break;
		case FC_PDO1_TX:
			*msg_type_id = MT_PDO;
			break;
		case FC_PDO1_RX:
			*msg_type_id = MT_PDO;
			break;
		case FC_PDO2_TX:
			*msg_type_id = MT_PDO;
			break;
		case FC_PDO2_RX:
			*msg_type_id = MT_PDO;
			break;
		case FC_PDO3_TX:
			*msg_type_id = MT_PDO;
			break;
		case FC_PDO3_RX:
			*msg_type_id = MT_PDO;
			break;
		case FC_PDO4_TX:
			*msg_type_id = MT_PDO;
			break;
		case FC_PDO4_RX:
			*msg_type_id = MT_PDO;
			break;
		case FC_DEFAULT_SDO_TX:
			*msg_type_id = MT_SDO;
			break;
		case FC_DEFAULT_SDO_RX:
			*msg_type_id = MT_SDO;
			break;
		case FC_NMT_ERR_CONTROL:
			*msg_type_id = MT_NMT_GUARD;
			break;
		default:
			*msg_type_id = MT_UNKNOWN;
			break;
	}
}

/* Code to actually dissect the packets */
static void
dissect_canopen(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti, *cob_ti, *type_ti;
    proto_tree *canopen_tree = NULL;
    proto_tree *canopen_cob_tree = NULL;
    proto_tree *canopen_type_tree = NULL;
    guint function_code = -1;
    guint node_id = -1;
    guint32 id = -1;
    guint32 time_stamp_msec = -1;
    guint32 time_stamp_days = -1;
    guint msg_type_id = -1;
    nstime_t time_stamp;
    guint8 can_data_len;

    can_data_len = tvb_get_guint8(tvb, 4);
    id = tvb_get_ntohl(tvb, 0);

    node_id = (guint)(id & 0x7F);
    function_code = (guint)((id >> 7) & 0xF);

    if (tvb_length(tvb) < 1)
        return;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CANopen");
    col_clear(pinfo->cinfo, COL_INFO);
    canopen_detect_msg_type(function_code, node_id, &msg_type_id);
	if(node_id == 0 ){
		/* brodcast */
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(function_code, CAN_open_bcast_msg_type_vals, "Unknown (%u)"));
	}else{
		/*pet-to-per */
		col_add_fstr(pinfo->cinfo, COL_INFO, "p2p %s", val_to_str(function_code, CAN_open_p2p_msg_type_vals, "Unknown (%u)"));
	}
    col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(tvb, CO_PDO_DATA_OFFSET, can_data_len, ' '));

    if (tree) {

        ti = proto_tree_add_item(tree, proto_canopen, tvb, 0, 1, ENC_NA);

        canopen_tree = proto_item_add_subtree(ti, ett_canopen);

        /* add COB-ID with function code and node id */
        cob_ti = proto_tree_add_item(canopen_tree, hf_canopen_cob_id, tvb, 0, 4, ENC_BIG_ENDIAN);
        canopen_cob_tree = proto_item_add_subtree(cob_ti, ett_canopen);

        /* add function code */
        proto_tree_add_item(canopen_cob_tree, hf_canopen_function_code, tvb, 0, 4, ENC_BIG_ENDIAN);

        /* add node id */
        proto_tree_add_item(canopen_cob_tree, hf_canopen_node_id, tvb, 0, 4, ENC_BIG_ENDIAN);

        /* add CANopen frame type */
		if(node_id == 0 ){
			/* brodcast */
			type_ti = proto_tree_add_string(canopen_tree, hf_canopen_type, tvb, 0, 4, val_to_str(function_code, CAN_open_bcast_msg_type_vals, "Unknown (%u)"));
		}else{
			/*pet-to-per */
			type_ti = proto_tree_add_string(canopen_tree, hf_canopen_type, tvb, 0, 4, val_to_str(function_code, CAN_open_p2p_msg_type_vals, "Unknown (%u)"));
		}
        canopen_type_tree = proto_item_add_subtree(type_ti, ett_canopen);

        switch(msg_type_id)
        {
        case MT_NMT_CTRL:
            proto_tree_add_item(canopen_type_tree,
                hf_canopen_nmt_ctrl_cs, tvb, CO_NMT_CTRL_CS_OFFSET, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(canopen_type_tree,
                hf_canopen_nmt_ctrl_node_id, tvb, CO_NMT_CTRL_NODE_ID_OFFSET, 1, ENC_BIG_ENDIAN);
            break;
        case MT_NMT_GUARD:
            proto_tree_add_item(canopen_type_tree,
                hf_canopen_nmt_guard_state, tvb, CO_NMT_GUARD_STATE_OFFSET, 1, ENC_BIG_ENDIAN);
            break;
        case MT_SYNC:
            break;
        case MT_TIME_STAMP:
            /* calculate the real time stamp */
            time_stamp_msec = tvb_get_letohl(tvb, CO_PDO_DATA_OFFSET);
            time_stamp_days = tvb_get_ntohs(tvb, CO_PDO_DATA_OFFSET + 4);
            time_stamp.secs = (time_stamp_days + TS_DAYS_BETWEEN_1970_AND_1984)
                * TS_SECONDS_IN_PER_DAY + (time_stamp_msec / 1000);
            time_stamp.nsecs = (time_stamp_msec % 1000) * TS_NANOSEC_PER_MSEC;

            proto_tree_add_time(canopen_type_tree,
                hf_canopen_time_stamp, tvb, CO_TIME_STAMP_MS_OFFSET, 6, &time_stamp);

            proto_tree_add_uint(canopen_type_tree,
                hf_canopen_time_stamp_ms, tvb, CO_TIME_STAMP_MS_OFFSET, 4, time_stamp_msec);

            proto_tree_add_uint(canopen_type_tree,
                hf_canopen_time_stamp_days, tvb, CO_TIME_STAMP_DAYS_OFFSET, 2, time_stamp_days);

            break;
        case MT_EMERGENCY:
            proto_tree_add_item(canopen_type_tree,
                hf_canopen_em_err_code, tvb, CO_EM_ERR_CODE_OFFSET, 2, ENC_BIG_ENDIAN);

            proto_tree_add_item(canopen_type_tree,
                hf_canopen_em_err_reg, tvb, CO_EM_ERR_REG_OFFSET, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(canopen_type_tree,
                hf_canopen_em_err_field, tvb, CO_EM_ERR_FIELD_OFFSET, 4, ENC_NA);
            break;
        case MT_PDO:
            if(can_data_len)
            {
                proto_tree_add_item(canopen_type_tree,
                    hf_canopen_pdo_data, tvb, CO_PDO_DATA_OFFSET, can_data_len, ENC_NA);
            }
            else
            {
                proto_tree_add_string(canopen_type_tree, hf_canopen_pdo_data_string, tvb, CO_PDO_DATA_OFFSET, 0, "empty");
            }
            break;
        case MT_SDO:
            proto_tree_add_item(canopen_type_tree,
                hf_canopen_sdo_cmd, tvb, CO_SDO_CMD_OFFSET, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(canopen_type_tree,
                hf_canopen_sdo_main_idx, tvb, CO_SDO_MAIN_IDX_OFFSET, 2, ENC_BIG_ENDIAN);

            proto_tree_add_item(canopen_type_tree,
                hf_canopen_sdo_sub_idx, tvb, CO_SDO_MAIN_SUB_OFFSET, 1, ENC_BIG_ENDIAN);

            proto_tree_add_item(canopen_type_tree,
                hf_canopen_sdo_data, tvb, CO_SDO_DATA_OFFSET, 4, ENC_NA);
            break;
        }

    }
}


/* Register the protocol with Wireshark */
void
proto_register_canopen(void)
{
        static hf_register_info hf[] = {
                { &hf_canopen_cob_id,
                        { "COB-ID",           "canopen.cob_id",
                        FT_UINT32, BASE_HEX, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_type,
                        { "Type",           "canopen.type",
                        FT_STRINGZ, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_function_code,
                        { "Function code", "canopen.function_code",
                        FT_UINT32, BASE_HEX, NULL, 0x780,
                        NULL, HFILL }
                },
                { &hf_canopen_node_id,
                        { "Node-ID", "canopen.node_id",
                        FT_UINT32, BASE_HEX, NULL, 0x7F,
                        NULL, HFILL }
                },
                { &hf_canopen_pdo_data,
                        { "Data", "canopen.pdo.data",
                        FT_BYTES, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_pdo_data_string,
                        { "Data", "canopen.pdo.data",
                        FT_STRINGZ, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_sdo_cmd,
                        { "SDO command byte", "canopen.sdo.cmd",
                        FT_UINT8, BASE_HEX, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_sdo_main_idx,
                        { "OD main-index", "canopen.sdo.main_idx",
                        FT_UINT16, BASE_HEX, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_sdo_sub_idx,
                        { "OD sub-index", "canopen.sdo.sub_idx",
                        FT_UINT8, BASE_HEX, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_sdo_data,
                        { "Data", "canopen.sdo.data",
                        FT_BYTES, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_em_err_code,
                        { "Error code", "canopen.em.err_code",
                        FT_UINT16, BASE_HEX, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_em_err_reg,
                        { "Error register", "canopen.em.err_reg",
                        FT_UINT8, BASE_HEX, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_em_err_field,
                        { "Manufacture specific error field", "canopen.em.err_field",
                        FT_BYTES, BASE_NONE, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_nmt_ctrl_cs,
                        { "Command specifier", "canopen.nmt_ctrl.cd",
                        FT_UINT8, BASE_HEX, nmt_ctrl_cs, 0xFF,
                        NULL, HFILL }
                },
                { &hf_canopen_nmt_ctrl_node_id,
                        { "Node-ID", "canopen.nmt_ctrl.node_id",
                        FT_UINT8, BASE_HEX, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_nmt_guard_state,
                        { "Node-ID", "canopen.nmt_guard.state",
                        FT_UINT8, BASE_HEX, nmt_guard_state, 0x7F,
                        NULL, HFILL }
                },
                { &hf_canopen_time_stamp,
                        { "Time stamp",           "canopen.time_stamp",
                        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_time_stamp_ms,
                        { "Time, after Midnight in Milliseconds", "canopen.time_stamp_ms",
                        FT_UINT32, BASE_DEC, NULL, 0x0,
                        NULL, HFILL }
                },
                { &hf_canopen_time_stamp_days,
                        { "Current day since 1 Jan 1984", "canopen.time_stamp_days",
                        FT_UINT16, BASE_DEC, NULL, 0x0,
                        NULL, HFILL }
                },
        };

        static gint *ett[] = {
                &ett_canopen
        };

	/* Register the protocol name and description */
        proto_canopen = proto_register_protocol("CANopen",
						"CANOPEN",
						"canopen");

	register_dissector("canopen", dissect_canopen, proto_canopen);

	/* Required function calls to register the header fields and subtrees used */
        proto_register_field_array(proto_canopen, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_canopen(void){}

