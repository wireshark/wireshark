/* packet-rfid-pn532.c
 * Dissector for the NXP PN532 Protocol
 *
 * References:
 * http://www.nxp.com/documents/user_manual/141520.pdf
 *
 * Copyright 2012, Tyson Key <tyson.key@gmail.com>
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
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

static int proto_pn532 = -1;

/* Device-specific HFs */
static int hf_pn532_command = -1;
static int hf_pn532_direction = -1;
static int hf_pn532_MaxTg = -1;
static int hf_pn532_NbTg = -1;
static int hf_pn532_BrTy = -1;
static int hf_pn532_payload_length = -1;
static int hf_pn532_ic_version = -1;
static int hf_pn532_fw_version = -1;
static int hf_pn532_fw_revision = -1;
static int hf_pn532_fw_support = -1;

/* Card type-specific HFs */
static int hf_pn532_14443a_sak = -1;
static int hf_pn532_14443a_atqa = -1;
static int hf_pn532_14443a_uid = -1;
static int hf_pn532_14443a_ats = -1;
static int hf_pn532_14443b_pupi = -1;
static int hf_pn532_14443b_app_data = -1;
static int hf_pn532_14443b_proto_info = -1;

/* - Command Set (Misc) - */
#define DIAGNOSE  		0x00

/* Get Firmware Version */
#define GET_FIRMWARE_VERSION_REQ    0x02
#define GET_FIRMWARE_VERSION_RSP    0x03

#define GET_GENERAL_STATUS	0x04
#define READ_REGISTER		0x06
#define WRITE_REGISTER		0x08
#define READ_GPIO		0x0C
#define WRITE_GPIO		0x0E
#define SET_SERIAL_BAUD_RATE	0x10
#define SET_PARAMETERS		0x12
#define SAM_CONFIGURATION	0x14
#define POWER_DOWN   		0x16

/* RF Communication Commands */
#define RF_CONFIGURATION  	0x32
#define RF_REGULATION_TEST  	0x58

/* - Initiator Commands - */
#define IN_JUMP_FOR_DEP  	0x56
#define IN_JUMP_FOR_PSL  	0x46

/* List targets (tags) in the field */
#define IN_LIST_PASSIVE_TARGET_REQ 0x4A
#define IN_LIST_PASSIVE_TARGET_RSP 0x4B

#define IN_ATR 			0x50
#define IN_PSL 			0x4E
#define IN_DATA_EXCHANGE	0x40

/* Communicate through */
#define IN_COMMUNICATE_THRU_REQ	0x42
#define IN_COMMUNICATE_THRU_RSP	0x43

#define IN_DESELECT		0x44
#define IN_RELEASE		0x52
#define IN_SELECT	  	0x54

/* Auto/long-time polling*/
#define IN_AUTO_POLL_REQ	0x60
#define IN_AUTO_POLL_RES	0x61

/* Target Commands */
#define TG_INIT_AS_TARGET	0x8C
#define TG_SET_GENERAL_BYTES	0x92
#define TG_GET_DATA		0x86
#define TG_SET_DATA		0x8E
#define TG_SET_METADATA		0x94
#define TG_GET_INITIATOR_CMD	0x88
#define TG_RESP_TO_INITIATOR	0x90
#define TG_GET_TARGET_STATUS	0x8A

/* TFI (Frame Identifier) Directions */
#define HOST_TO_PN532 		0xD4
#define PN532_TO_HOST		0xD5

/* Baud rate and modulation types */
#define ISO_IEC_14443A_106	0x00
#define FELICA_212		0x01
#define FELICA_424		0x02
#define ISO_IEC_14443B_106	0x03
#define JEWEL_14443A_106	0x04

static const value_string pn532_commands[] = {
    {DIAGNOSE, "Diagnose"},

    /* Discover the device's firmware version */
    {GET_FIRMWARE_VERSION_REQ, "GetFirmwareVersion"},
    {GET_FIRMWARE_VERSION_RSP, "GetFirmwareVersion (Response)"},

    {GET_GENERAL_STATUS, "GetGeneralStatus"},
    {READ_REGISTER, "ReadRegister"},
    {WRITE_REGISTER, "WriteRegister"},
    {READ_GPIO, "ReadGPIO"},
    {WRITE_GPIO, "WriteGPIO"},
    {SET_SERIAL_BAUD_RATE, "SetSerialBaudRate"},
    {SET_PARAMETERS, "SetParameters"},
    {SAM_CONFIGURATION, "SAMConfiguration"},
    {POWER_DOWN, "PowerDown"},
    {RF_CONFIGURATION, "RFConfiguration"},
    {RF_REGULATION_TEST, "RFRegulationTest"},
    {IN_JUMP_FOR_DEP, "InJumpForDEP"},
    {IN_JUMP_FOR_PSL, "InJumpForPSL"},

    /* List tags in the proximity of the reader's field */
    {IN_LIST_PASSIVE_TARGET_REQ, "InListPassiveTarget"},
    {IN_LIST_PASSIVE_TARGET_RSP, "InListPassiveTarget (Response)"},

    {IN_ATR, "InATR"},
    {IN_PSL, "InPSL"},
    {IN_DATA_EXCHANGE, "InDataExchange"},
    
    /* Communicate through */
    {IN_COMMUNICATE_THRU_REQ, "InCommunicateThru"},
    {IN_COMMUNICATE_THRU_RSP, "InCommunicateThru (Response)"},
    
    {IN_DESELECT, "InDeselect"},
    {IN_RELEASE, "InRelease"},
    {IN_SELECT, "InSelect"},

    /* Automatic/long-time polling */
    {IN_AUTO_POLL_REQ, "InAutoPoll"},
    {IN_AUTO_POLL_RES, "InAutoPoll (Response)"},

    {TG_INIT_AS_TARGET, "TgInitAsTarget"},
    {TG_SET_GENERAL_BYTES, "TgSetGeneralBytes"},
    {TG_GET_DATA, "TgGetData"},
    {TG_SET_DATA, "TgSetData"},
    {TG_SET_METADATA, "TgSetMetaData"},
    {TG_GET_INITIATOR_CMD, "TgGetInitiatorCommand"},
    {TG_RESP_TO_INITIATOR, "TgResponseToInitiator"},
    {TG_GET_TARGET_STATUS, "TgGetTargetStatus"},

    /* End of commands */
    {0x00, NULL}
};

/* TFI - 1 byte frame identifier; specifying direction of communication */
static const value_string pn532_directions[] = {
    {HOST_TO_PN532, "Host to PN532"},
    {PN532_TO_HOST, "PN532 to Host"},

    /* End of directions */
    {0x00, NULL}
};

/* Baud rates and modulation types */
static const value_string pn532_brtypes[] = {
    {ISO_IEC_14443A_106, "ISO/IEC 14443-A at 106 kbps"},
    {FELICA_212, "FeliCa at 212 kbps"},
    {FELICA_424, "FeliCa at 424 kbps"},
    {ISO_IEC_14443B_106, "ISO/IEC 14443-B at 106 kbps"},
    {JEWEL_14443A_106, "InnoVision Jewel/Topaz at 106 kbps"},

    /* End of directions */
    {0x00, NULL}
};

static dissector_handle_t data_handle;
static dissector_handle_t felica_handle;

static dissector_table_t pn532_dissector_table;

/* Subtree handles: set by register_subtree_array */
static gint ett_pn532 = -1;

static void dissect_pn532(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    proto_item *item;
    proto_tree *pn532_tree;
    guint8 cmd;
    tvbuff_t *next_tvb = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PN532");
    col_set_str(pinfo->cinfo, COL_INFO, "PN532 Packet");

    if (tree) {
	/* Start with a top-level item to add everything else to */

	item = proto_tree_add_item(tree, proto_pn532, tvb, 0, -1, ENC_NA);
	pn532_tree = proto_item_add_subtree(item, ett_pn532);

	proto_tree_add_item(pn532_tree, hf_pn532_direction, tvb, 0, 1, ENC_NA);
	proto_tree_add_item(pn532_tree, hf_pn532_command, tvb, 1, 1, ENC_NA);

	/* Direction byte */
	cmd = tvb_get_guint8(tvb, 1);
	
	col_set_str(pinfo->cinfo, COL_INFO, val_to_str(cmd, pn532_commands, "Unknown"));

	switch (cmd) {

	case DIAGNOSE:
	    break;

	    /* Device Firmware Version */
	case GET_FIRMWARE_VERSION_REQ:
	    break;

	case GET_FIRMWARE_VERSION_RSP:
	    proto_tree_add_item(pn532_tree, hf_pn532_ic_version, tvb, 2, 1, ENC_NA);
	    proto_tree_add_item(pn532_tree, hf_pn532_fw_version, tvb, 3, 1, ENC_NA);
	    proto_tree_add_item(pn532_tree, hf_pn532_fw_revision, tvb, 4, 1, ENC_NA);
	    proto_tree_add_item(pn532_tree, hf_pn532_fw_support, tvb, 5, 1, ENC_NA);
	    break;

	case GET_GENERAL_STATUS:
	    break;

	case READ_REGISTER:
	    break;

	case WRITE_REGISTER:
	    break;

	case READ_GPIO:
	    break;

	case WRITE_GPIO:
	    break;

	case SET_SERIAL_BAUD_RATE:
	    break;

	case SET_PARAMETERS:
	    break;

	case SAM_CONFIGURATION:
	    break;

	case POWER_DOWN:
	    break;

	case RF_CONFIGURATION:
	    break;

	case RF_REGULATION_TEST:
	    break;

	case IN_JUMP_FOR_DEP:
	    break;

	case IN_JUMP_FOR_PSL:
	    break;

	    /* List targets (tags) in the field */
	case IN_LIST_PASSIVE_TARGET_REQ:

	    /* Maximum number of supported tags */
	    proto_tree_add_item(pn532_tree, hf_pn532_MaxTg, tvb, 2, 1, ENC_BIG_ENDIAN);

	    /* Modulation and Baud Rate Type */
	    proto_tree_add_item(pn532_tree, hf_pn532_BrTy, tvb, 3, 1, ENC_BIG_ENDIAN);

	    /* Attempt to dissect FeliCa payloads */
	    if (tvb_get_guint8(tvb, 3) == FELICA_212 || tvb_get_guint8(tvb, 3) == FELICA_424) {

		next_tvb = tvb_new_subset_remaining(tvb, 4);
		call_dissector(felica_handle, next_tvb, pinfo, tree);

	    }

	    break;

	case IN_LIST_PASSIVE_TARGET_RSP:
	    proto_tree_add_item(pn532_tree, hf_pn532_NbTg, tvb, 2, 1, ENC_BIG_ENDIAN);

	    /* Probably an ISO/IEC 14443-B tag */
	    if (tvb_reported_length(tvb) == 20) {

		/* Add the PUPI */
		proto_tree_add_item(pn532_tree, hf_pn532_14443b_pupi, tvb, 5, 4, ENC_BIG_ENDIAN);

		/* Add the Application Data */
		proto_tree_add_item(pn532_tree, hf_pn532_14443b_app_data, tvb, 9, 4, ENC_BIG_ENDIAN);

		/* Add the Protocol Info */
		proto_tree_add_item(pn532_tree, hf_pn532_14443b_proto_info, tvb, 13, 3, ENC_BIG_ENDIAN);
	    }

	    /* Probably one of:
	     * a MiFare DESFire card (23 bytes), 
	     * an MF UltraLight tag (17 bytes) 
	     * an MF Classic card with a 4 byte UID (14 bytes) */

	    if (tvb_reported_length(tvb) == 23 || (tvb_reported_length(tvb) == 17) || (tvb_reported_length(tvb) == 14)) {

		/* Add the ATQA/SENS_RES */
		proto_tree_add_item(pn532_tree, hf_pn532_14443a_atqa, tvb, 4, 2, ENC_BIG_ENDIAN);

		/* Add the SAK/SEL_RES value */
		proto_tree_add_item(pn532_tree, hf_pn532_14443a_sak, tvb, 6, 1, ENC_BIG_ENDIAN);

		/* Add the UID */
		if (tvb_reported_length(tvb) != 14) {
		    proto_tree_add_item(pn532_tree, hf_pn532_14443a_uid, tvb, 8, 7, ENC_BIG_ENDIAN);

		    /* Probably MiFare DESFire, or some other 14443-A card with an ATS value/7 byte UID */
		    if (tvb_reported_length(tvb) == 23) {

			/* Add the ATS value */
			proto_tree_add_item(pn532_tree, hf_pn532_14443a_ats, tvb, 16, 5, ENC_BIG_ENDIAN);
		    }
		}
		/* Probably MiFare Classic with a 4 byte UID */
		else {
		    proto_tree_add_item(pn532_tree, hf_pn532_14443a_uid, tvb, 7, 4, ENC_BIG_ENDIAN);
		}

	    }

	    /* See if we've got a FeliCa payload with a System Code */
	    if (tvb_reported_length(tvb) == 26) {

		/* For FeliCa, this is at position 4. This doesn't exist for other payload types. */
		proto_tree_add_item(pn532_tree, hf_pn532_payload_length, tvb, 4, 1, ENC_BIG_ENDIAN);

		/* Use the length value (20?) at position 5, and skip the Status Word (9000) at the end */
		next_tvb = tvb_new_subset(tvb, 5, tvb_get_guint8(tvb, 4) - 1, 19);
		call_dissector(felica_handle, next_tvb, pinfo, tree);
	    }

	    break;

	case IN_ATR:
	    break;

	case IN_PSL:
	    break;

	case IN_DATA_EXCHANGE:
	    break;

	case IN_COMMUNICATE_THRU_REQ:
	    break;

	case IN_DESELECT:
	    break;

	case IN_RELEASE:
	    break;

	case IN_SELECT:
	    break;

	case IN_AUTO_POLL_REQ:
	    break;

	case IN_AUTO_POLL_RES:
	    break;

	case TG_INIT_AS_TARGET:
	    break;

	case TG_SET_GENERAL_BYTES:
	    break;

	case TG_GET_DATA:
	    break;

	case TG_SET_DATA:
	    break;

	case TG_SET_METADATA:
	    break;

	case TG_GET_INITIATOR_CMD:
	    break;

	case TG_RESP_TO_INITIATOR:
	    break;

	case TG_GET_TARGET_STATUS:
	    break;

	default:
	    break;
	}
	
    }
}

void proto_register_pn532(void)
{
    static hf_register_info hf[] = {

	{&hf_pn532_command,
	 {"Command", "pn532.cmd", FT_UINT8, BASE_HEX,
	  VALS(pn532_commands), 0x0, NULL, HFILL}},
	{&hf_pn532_direction,
	 {"Direction", "pn532.tfi", FT_UINT8, BASE_HEX,
	  VALS(pn532_directions), 0x0, NULL, HFILL}},
	{&hf_pn532_BrTy,
	 {"Baud Rate and Modulation", "pn532.BrTy", FT_UINT8, BASE_HEX,
	  VALS(pn532_brtypes), 0x0, NULL, HFILL}},
	{&hf_pn532_MaxTg,
	 {"Maximum Number of Targets", "pn532.MaxTg", FT_INT8, BASE_DEC,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_NbTg,
	 {"Number of Targets", "pn532.NbTg", FT_INT8, BASE_DEC,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_payload_length,
	 {"Payload Length", "pn532.payload.length", FT_INT8, BASE_DEC,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_ic_version,
	 {"Integrated Circuit Version", "pn532.ic.version", FT_INT8, BASE_DEC,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_fw_version,
	 {"Firmware Version", "pn532.fw.version", FT_INT8, BASE_DEC,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_fw_revision,
	 {"Firmware Revision", "pn532.fw.revision", FT_INT8, BASE_DEC,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_fw_support,
	 {"Firmware Support", "pn532.fw.support", FT_INT8, BASE_DEC,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_14443a_sak,
	 {"ISO/IEC 14443-A SAK", "pn532.iso.14443a.sak", FT_UINT8, BASE_HEX,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_14443a_atqa,
	 {"ISO/IEC 14443-A ATQA", "pn532.iso.14443a.atqa", FT_UINT16, BASE_HEX,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_14443a_uid,
	 {"ISO/IEC 14443-A UID", "pn532.iso.14443a.uid", FT_UINT64, BASE_HEX,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_14443a_ats,
	 {"ISO/IEC 14443-A ATS", "pn532.iso.14443a.ats", FT_UINT64, BASE_HEX,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_14443b_pupi,
	 {"ISO/IEC 14443-B PUPI", "pn532.iso.14443b.pupi", FT_UINT64, BASE_HEX,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_14443b_app_data,
	 {"ISO/IEC 14443-B Application Data", "pn532.iso.14443b.app.data", FT_UINT64, BASE_HEX,
	  NULL, 0x0, NULL, HFILL}},
	{&hf_pn532_14443b_proto_info,
	 {"ISO/IEC 14443-B Protocol Info", "pn532.iso.14443b.protocol.info", FT_UINT64, BASE_HEX,
	  NULL, 0x0, NULL, HFILL}},
    };

    static gint *ett[] = {
	&ett_pn532
    };

    proto_pn532 = proto_register_protocol("NXP PN532", "PN532", "pn532");
    proto_register_field_array(proto_pn532, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pn532_dissector_table = register_dissector_table("pn532.payload", "PN532 Payload", FT_UINT8, BASE_DEC);

    register_dissector("pn532", dissect_pn532, proto_pn532);
}

/* Handler registration */
void proto_reg_handoff_pn532(void)
{
    data_handle = find_dissector("data");
    felica_handle = find_dissector("felica");
}

/*
 * Editor modelines - http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
