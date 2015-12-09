/* packet-epl_v1.c
 * Routines for "ETHERNET Powerlink 1.0" dissection
 * (ETHERNET Powerlink Powerlink WhitePaper V0006-B)
 *
 * Copyright (c) 2006: Zurich University of Applied Sciences Winterthur (ZHW)
 *                     Institute of Embedded Systems (InES)
 *                     http://ines.zhwin.ch
 *
 *                     - Dominic Bechaz <bdo@zhwin.ch>
 *                     - David Buechi <bhd@zhwin.ch>
 *
 *
 * A dissector for:
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
#include <epan/etypes.h>
void proto_register_epl_v1(void);
void proto_reg_handoff_epl_v1(void);

/* Offsets of fields within an EPL_V1 packet. */
#define EPL_V1_SERVICE_OFFSET                     0   /* same offset for all message types*/
#define EPL_V1_DEST_OFFSET                        1   /* same offset for all message types*/
#define EPL_V1_SRC_OFFSET                         2   /* same offset for all message types*/

#define EPL_V1_SOC_C2_OFFSET                      3
#define EPL_V1_SOC_PF_OFFSET                      3
#define EPL_V1_SOC_NET_COMMAND_OFFSET             4
#define EPL_V1_SOC_NET_TIME_OFFSET                6
#define EPL_V1_SOC_POWERLINK_CYCLE_TIME_OFFSET   10
#define EPL_V1_SOC_NET_COMMAND_PARAMETER_OFFSET  14

#define EPL_V1_PREQ_C2_OFFSET                     3
/* "Powerlink Multimanager Konzept V1.1" protocol extension*/
#define PMM_KONZEPT_V1_1_PREQ_YA                  3
#define PMM_KONZEPT_V1_1_PREQ_SC                  3
/* end "Powerlink Multimanager Konzept V1.1" protocol extension*/
#define EPL_V1_PREQ_RD_OFFSET                     3
#define EPL_V1_PREQ_RD_OFFSET                     3
#define EPL_V1_PREQ_POLL_SIZE_OUT_OFFSET          4
#define EPL_V1_PREQ_OUT_DATA_OFFSET              10

#define EPL_V1_PRES_C2_OFFSET                     3
#define EPL_V1_PRES_EX_OFFSET                     3
#define EPL_V1_PRES_RS_OFFSET                     3
#define EPL_V1_PRES_WA_OFFSET                     3
#define EPL_V1_PRES_ER_OFFSET                     3
#define EPL_V1_PRES_RD_OFFSET                     3
#define EPL_V1_PRES_POLL_SIZE_IN_OFFSET           4
#define EPL_V1_PRES_IN_DATA_OFFSET               10

#define EPL_V1_EOC_NET_COMMAND_OFFSET             4
#define EPL_V1_EOC_NET_COMMAND_PARAMETER_OFFSET  14

#define EPL_V1_AINV_CHANNEL_OFFSET                3

#define EPL_V1_ASND_CHANNEL_OFFSET                3
#define EPL_V1_ASND_SIZE_OFFSET                   4
#define EPL_V1_ASND_DATA_OFFSET                   6
#define EPL_V1_ASND_NODE_ID_OFFSET                6
#define EPL_V1_ASND_HARDWARE_REVISION_OFFSET     10
#define EPL_V1_ASND_FIRMWARE_VERSION_OFFSET      14
#define EPL_V1_ASND_DEVICE_VARIANT_OFFSET        18
#define EPL_V1_ASND_POLL_IN_SIZE_OFFSET          22
#define EPL_V1_ASND_POLL_OUT_SIZE_OFFSET         26

/* EPL_V1 message types */
#define EPL_V1_SOC    0x01
#define EPL_V1_EOC    0x02
#define EPL_V1_PREQ   0x03
#define EPL_V1_PRES   0x04
#define EPL_V1_AINV   0x05
#define EPL_V1_ASND   0x06

static const value_string service_vals[] = {
	{EPL_V1_SOC,  "Start of Cyclic (SoC)"   },
	{EPL_V1_EOC,  "End of Cyclic (EoC)"     },
	{EPL_V1_PREQ, "Poll Request (PReq)"     },
	{EPL_V1_PRES, "Poll Response (PRes)"    },
	{EPL_V1_AINV, "Acyclic Invite (AInv)"   },
	{EPL_V1_ASND, "Acyclic Send (ASnd)"     },
	{0,NULL}
};

/* Channel values for EPL_V1 message type "AInv" */
#define EPL_V1_AINV_IDENT         1
#define EPL_V1_AINV_GENERIC     255

static const value_string ainv_channel_number_vals[] = {
	{EPL_V1_AINV_IDENT,     "Ident"             },
	{EPL_V1_AINV_GENERIC,   "Generic Channel"   },
	{0,NULL}
};

/* Channel values for EPL_V1 message type "ASnd" */
#define EPL_V1_ASND_IDENT         1
#define EPL_V1_ASND_GENERIC     255

static const value_string asnd_channel_number_vals[] = {
	{EPL_V1_ASND_IDENT,     "Ident"             },
	{EPL_V1_ASND_GENERIC,   "Generic Channel"   },
	{0,NULL}
};

/* Net Command values for EPL_V1 message type "SoC" */
#define EPL_V1_SOC_NET_COMMAND_IDLE   0
#define EPL_V1_SOC_NET_COMMAND_ACTIVE 1

static const value_string soc_net_command_vals[] = {
	{EPL_V1_SOC_NET_COMMAND_IDLE,   "Net Command Idle"  },
	{EPL_V1_SOC_NET_COMMAND_ACTIVE, "Net Command Active"},
	{0,NULL}
};

/* Net Command values for EPL_V1 message type "EoC" */
#define EPL_V1_EOC_NET_COMMAND_IDLE   0
#define EPL_V1_EOC_NET_COMMAND_ACTIVE 1

static const value_string eoc_net_command_vals[] = {
	{EPL_V1_EOC_NET_COMMAND_IDLE,   "Net Command Idle"  },
	{EPL_V1_EOC_NET_COMMAND_ACTIVE, "Net Command Active"},
	{0,NULL}
};


/* Initialize the protocol and registered fields */
static int proto_epl_v1                           = -1;
static int hf_epl_v1_service                      = -1;
static int hf_epl_v1_dest                         = -1;
static int hf_epl_v1_src                          = -1;

static int hf_epl_v1_soc_ms                       = -1;
static int hf_epl_v1_soc_ps                       = -1;
static int hf_epl_v1_soc_net_command              = -1;
static int hf_epl_v1_soc_net_time                 = -1;
static int hf_epl_v1_soc_powerlink_cycle_time     = -1;
static int hf_epl_v1_soc_net_command_parameter    = -1;

static int hf_epl_v1_preq_ms                      = -1;
static int hf_epl_v1_preq_rd                      = -1;
static int hf_epl_v1_preq_poll_size_out           = -1;
static int hf_epl_v1_preq_out_data                = -1;

static int hf_epl_v1_pres_ms                      = -1;
static int hf_epl_v1_pres_ex                      = -1;
static int hf_epl_v1_pres_rs                      = -1;
static int hf_epl_v1_pres_wa                      = -1;
static int hf_epl_v1_pres_er                      = -1;
static int hf_epl_v1_pres_rd                      = -1;
static int hf_epl_v1_pres_poll_size_in            = -1;
static int hf_epl_v1_pres_in_data                 = -1;

static int hf_epl_v1_eoc_net_command              = -1;
static int hf_epl_v1_eoc_net_command_parameter    = -1;

static int hf_epl_v1_ainv_channel                 = -1;

static int hf_epl_v1_asnd_channel                 = -1;
static int hf_epl_v1_asnd_size                    = -1;
static int hf_epl_v1_asnd_data                    = -1;
static int hf_epl_v1_asnd_node_id                 = -1;
static int hf_epl_v1_asnd_hardware_revision       = -1;
static int hf_epl_v1_asnd_firmware_version        = -1;
static int hf_epl_v1_asnd_device_variant          = -1;
static int hf_epl_v1_asnd_poll_in_size            = -1;
static int hf_epl_v1_asnd_poll_out_size           = -1;

static gint ett_epl_v1 = -1;


static gint
dissect_epl_v1_soc(proto_tree *epl_v1_tree, tvbuff_t *tvb, gint offset)
{
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_soc_ms, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_soc_ps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(epl_v1_tree, hf_epl_v1_soc_net_command, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(epl_v1_tree, hf_epl_v1_soc_net_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(epl_v1_tree, hf_epl_v1_soc_powerlink_cycle_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(epl_v1_tree, hf_epl_v1_soc_net_command_parameter, tvb, offset, 32, ENC_NA);
	offset += 32;

	return offset;
}


static gint
dissect_epl_v1_eoc(proto_tree *epl_v1_tree, tvbuff_t *tvb, gint offset)
{
	offset += 1;

	proto_tree_add_item(epl_v1_tree, hf_epl_v1_eoc_net_command, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 8;

	proto_tree_add_item(epl_v1_tree, hf_epl_v1_eoc_net_command_parameter, tvb, offset, 32, ENC_NA);
	offset += 32;

	return offset;
}


static gint
dissect_epl_v1_preq(proto_tree *epl_v1_tree, tvbuff_t *tvb, gint offset)
{
	guint16 len;

	proto_tree_add_item(epl_v1_tree, hf_epl_v1_preq_ms, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_preq_rd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* get length of data */
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_preq_poll_size_out, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	len = tvb_get_letohs(tvb, offset);
	offset += 6;

	if(len>0){
		proto_tree_add_item(epl_v1_tree, hf_epl_v1_preq_out_data, tvb, offset, len, ENC_NA);
		offset += len;
	}

	return offset;
}



static gint
dissect_epl_v1_pres(proto_tree *epl_v1_tree, tvbuff_t *tvb, gint offset)
{
	guint16 len;

	proto_tree_add_item(epl_v1_tree, hf_epl_v1_pres_ms, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_pres_ex, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_pres_rs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_pres_wa, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_pres_er, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_pres_rd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* get length of data */
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_pres_poll_size_in, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	len = tvb_get_letohs(tvb, offset);
	offset += 6;

	if(len>0){
		proto_tree_add_item(epl_v1_tree, hf_epl_v1_pres_in_data, tvb, offset, len, ENC_NA);
		offset += len;
	}

	return offset;
}



static gint
dissect_epl_v1_ainv(proto_tree *epl_v1_tree, tvbuff_t *tvb, gint offset)
{
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_ainv_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	return offset;
}



static gint
dissect_epl_v1_asnd(proto_tree *epl_v1_tree, tvbuff_t *tvb, gint offset)
{
	guint8  epl_v1_asnd_channel;
	guint16 len;

	/* get ASnd channel */
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_asnd_channel, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	epl_v1_asnd_channel = tvb_get_guint8(tvb, offset);
	offset += 1;

	/* get length of data */
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_asnd_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	len = tvb_get_letohs(tvb, offset);
	offset += 2;

	/* "Ident" or "Generic" channel? */
	if(epl_v1_asnd_channel == EPL_V1_AINV_IDENT){   /* Ident channel*/
		proto_tree_add_item(epl_v1_tree, hf_epl_v1_asnd_node_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(epl_v1_tree, hf_epl_v1_asnd_hardware_revision, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(epl_v1_tree, hf_epl_v1_asnd_firmware_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(epl_v1_tree, hf_epl_v1_asnd_device_variant, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(epl_v1_tree, hf_epl_v1_asnd_poll_in_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(epl_v1_tree, hf_epl_v1_asnd_poll_out_size, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
	} else {   /* "Generic" and all other channels */
		proto_tree_add_item(epl_v1_tree, hf_epl_v1_asnd_data, tvb, offset, len, ENC_NA);
		offset += len;
	}

	return offset;
}



/* Code to actually dissect the packets */
static int
dissect_epl_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint8  epl_v1_service, epl_v1_dest, epl_v1_src, epl_v1_ainv_ch, epl_v1_asnd_ch;
	gint    offset;
	proto_item *ti=NULL;
	proto_tree *epl_v1_tree=NULL;


	if(tvb_captured_length(tvb) < 3){
		/* Not enough data for an EPL_V1 header; don't try to interpret it */
		return FALSE;
	}

	offset = 0;

	/* make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "EPL_V1");
	col_clear(pinfo->cinfo, COL_INFO);

	/* get service type */
	epl_v1_service = tvb_get_guint8(tvb, EPL_V1_SERVICE_OFFSET) & 0x7F;

	/* get destination */
	epl_v1_dest = tvb_get_guint8(tvb, EPL_V1_DEST_OFFSET);

	/* get source */
	epl_v1_src = tvb_get_guint8(tvb, EPL_V1_SRC_OFFSET);

	/* choose the right string for "Info" column */
	switch(epl_v1_service){
	case EPL_V1_SOC:
		col_add_fstr(pinfo->cinfo, COL_INFO, "SoC    dest = %3d   src = %3d   ", epl_v1_dest, epl_v1_src);
		break;

	case EPL_V1_EOC:
		col_add_fstr(pinfo->cinfo, COL_INFO, "EoC    dest = %3d   src = %3d   ", epl_v1_dest, epl_v1_src);
		break;

	case EPL_V1_PREQ:
		col_add_fstr(pinfo->cinfo, COL_INFO, "PReq   dest = %3d   src = %3d   ", epl_v1_dest, epl_v1_src);
		break;

	case EPL_V1_PRES:
		col_add_fstr(pinfo->cinfo, COL_INFO, "PRes   dest = %3d   src = %3d   ", epl_v1_dest, epl_v1_src);
		break;

	case EPL_V1_AINV:
		/* get AInv channel */
		epl_v1_ainv_ch = tvb_get_guint8(tvb, EPL_V1_AINV_CHANNEL_OFFSET);
		col_add_fstr(pinfo->cinfo, COL_INFO, "AInv   dest = %3d   src = %3d   channel = %s   ",
			epl_v1_dest, epl_v1_src, val_to_str(epl_v1_ainv_ch, ainv_channel_number_vals, "unknown Channel (%d)"));
		break;

	case EPL_V1_ASND:
		/* get ASnd channel */
		epl_v1_asnd_ch = tvb_get_guint8(tvb, EPL_V1_ASND_CHANNEL_OFFSET);
		col_add_fstr(pinfo->cinfo, COL_INFO, "ASnd   dest = %3d   src = %3d   channel = %s   ",
			epl_v1_dest, epl_v1_src, val_to_str(epl_v1_asnd_ch, asnd_channel_number_vals, "unknown Channel (%d)"));
		break;

	default:     /* no valid EPL packet */
		return FALSE;
	}

	if(tree){
		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_epl_v1, tvb, 0, -1, ENC_NA);

		epl_v1_tree = proto_item_add_subtree(ti, ett_epl_v1);
	}
	proto_tree_add_item(epl_v1_tree, hf_epl_v1_service, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(epl_v1_tree, hf_epl_v1_dest, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(epl_v1_tree, hf_epl_v1_src, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* The rest of the epl_v1 dissector depends on the message type  */
	switch(epl_v1_service){
	case EPL_V1_SOC:
		offset = dissect_epl_v1_soc(epl_v1_tree, tvb, offset);
		break;

	case EPL_V1_EOC:
		offset = dissect_epl_v1_eoc(epl_v1_tree, tvb, offset);
		break;

	case EPL_V1_PREQ:
		offset = dissect_epl_v1_preq(epl_v1_tree, tvb, offset);
		break;

	case EPL_V1_PRES:
		offset = dissect_epl_v1_pres(epl_v1_tree, tvb,  offset);
		break;

	case EPL_V1_AINV:
		offset = dissect_epl_v1_ainv(epl_v1_tree, tvb,  offset);
		break;

	case EPL_V1_ASND:
		offset = dissect_epl_v1_asnd(epl_v1_tree, tvb,  offset);
		break;

	default: /* not a valid MessageType - can't dissect any further. */
		return FALSE;
	}
	return offset;
}



void
proto_register_epl_v1(void)
{
	static hf_register_info hf[] = {
		/* Common data fields (same for all message types) */
		{ &hf_epl_v1_service,
		  { "Service", "epl_v1.service",
		    FT_UINT8, BASE_DEC, VALS(service_vals), 0x7F,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_dest,
		  { "Destination", "epl_v1.dest",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_src,
		  { "Source", "epl_v1.src",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		/* SoC data fields*/
		{ &hf_epl_v1_soc_ms,
		  { "MS (Multiplexed Slot)", "epl_v1.soc.ms",
		    FT_UINT8, BASE_DEC, NULL, 0x80,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_soc_ps,
		  { "PS (Prescaled Slot)", "epl_v1.soc.ps",
		    FT_UINT8, BASE_DEC, NULL, 0x40,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_soc_net_command,
		  { "Net Command", "epl_v1.soc.netcommand",
		    FT_UINT16, BASE_DEC, VALS(soc_net_command_vals), 0x0,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_soc_net_time,
		  { "Net Time", "epl_v1.soc.nettime",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_soc_powerlink_cycle_time,
		  { "Cycle Time", "epl_v1.soc.cycletime",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_soc_net_command_parameter,
		  { "Net Command Parameter", "epl_v1.soc.netcommand.parameter",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }
		},
		/* PReq data fields*/
		{ &hf_epl_v1_preq_ms,
		  { "MS (Multiplexed Slot)", "epl_v1.preq.ms",
		    FT_UINT8, BASE_DEC, NULL, 0x20,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_preq_rd,
		  { "RD (Ready)", "epl_v1.preq.rd",
		    FT_UINT8, BASE_DEC, NULL, 0x01,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_preq_poll_size_out,
		  { "Poll Size OUT", "epl_v1.preq.pollsize",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_preq_out_data,
		  { "OUT Data", "epl_v1.preq.data",
		    FT_BYTES, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		/* PRes data fields*/
		{ &hf_epl_v1_pres_ms,
		  { "MS (Multiplexed)", "epl_v1.pres.ms",
		    FT_UINT8, BASE_DEC, NULL, 0x20,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_pres_ex,
		  { "EX (Exception)", "epl_v1.pres.ex",
		    FT_UINT8, BASE_DEC, NULL, 0x10,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_pres_rs,
		  { "RS (Request to Send)", "epl_v1.pres.rs",
		    FT_UINT8, BASE_DEC, NULL, 0x08,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_pres_wa,
		  { "WA (Warning)", "epl_v1.pres.wa",
		    FT_UINT8, BASE_DEC, NULL, 0x04,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_pres_er,
		  { "ER (Error)", "epl_v1.pres.er",
		    FT_UINT8, BASE_DEC, NULL, 0x02,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_pres_rd,
		  { "RD (Ready)", "epl_v1.pres.rd",
		    FT_UINT8, BASE_DEC, NULL, 0x01,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_pres_poll_size_in,
		  { "Poll Size IN", "epl_v1.pres.pollsize",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_pres_in_data,
		  { "IN Data", "epl_v1.pres.data",
		    FT_BYTES, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		/* EoC data fields*/
		{ &hf_epl_v1_eoc_net_command,
		  { "Net Command", "epl_v1.eoc.netcommand",
		    FT_UINT16, BASE_DEC, VALS(eoc_net_command_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_eoc_net_command_parameter,
		  { "Net Command Parameter", "epl_v1.soa.netcommand.parameter",
		    FT_BYTES, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},
		/* AInv data fields*/
		{ &hf_epl_v1_ainv_channel,
		  { "Channel", "epl_v1.ainv.channel",
		    FT_UINT8, BASE_DEC, VALS(ainv_channel_number_vals), 0x00,
		    NULL, HFILL }
		},
		/* ASnd data fields*/
		{ &hf_epl_v1_asnd_channel,
		  { "Channel", "epl_v1.asnd.channel",
		    FT_UINT8, BASE_DEC, VALS(asnd_channel_number_vals), 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_asnd_size,
		  { "Size", "epl_v1.asnd.size",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_asnd_data,
		  { "Data", "epl_v1.asnd.data",
		    FT_BYTES, BASE_NONE, NULL, 0x00,
		    NULL, HFILL }
		},

		{ &hf_epl_v1_asnd_node_id,
		  { "NodeID", "epl_v1.asnd.node_id",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_asnd_hardware_revision,
		  { "Hardware Revision", "epl_v1.asnd.hardware.revision",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_asnd_firmware_version,
		  { "Firmware Version", "epl_v1.asnd.firmware.version",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_asnd_device_variant,
		  { "Device Variant", "epl_v1.asnd.device.variant",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_asnd_poll_in_size,
		  { "Poll IN Size", "epl_v1.asnd.poll.in.size",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
		{ &hf_epl_v1_asnd_poll_out_size,
		  { "Poll OUT Size", "epl_v1.asnd.poll.out.size",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_epl_v1,
	};

	/* Register the protocol name and description */
	proto_epl_v1 = proto_register_protocol("ETHERNET Powerlink V1.0", "EPL_V1", "epl_v1");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_epl_v1, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}



void
proto_reg_handoff_epl_v1(void)
{
	dissector_handle_t epl_v1_handle;

	epl_v1_handle = create_dissector_handle(dissect_epl_v1, proto_epl_v1);
	dissector_add_uint("ethertype", ETHERTYPE_EPL_V1, epl_v1_handle);
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
