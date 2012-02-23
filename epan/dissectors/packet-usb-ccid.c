/* packet-usb-ccid.c
 * Dissector for the Integrated Circuit Card Interface Device Class
 *
 * References:
 * http://www.usb.org/developers/devclass_docs/DWG_Smart-Card_CCID_Rev110.pdf
 *
 * Copyright 2011, Tyson Key <tyson.key@gmail.com>
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
#include <epan/dissectors/packet-usb.h>
#include <epan/prefs.h>

static int proto_ccid = -1;

static int hf_ccid_bMessageType = -1;
static int hf_ccid_dwLength = -1;
static int hf_ccid_bSlot = -1;
static int hf_ccid_bSeq = -1;
static int hf_ccid_bStatus = -1;
static int hf_ccid_bError = -1;
static int hf_ccid_bChainParameter = -1;
static int hf_ccid_bPowerSelect = -1;
static int hf_ccid_bClockStatus = -1;
static int hf_ccid_bProtocolNum = -1;
static int hf_ccid_bBWI = -1;
static int hf_ccid_wLevelParameter = -1;

/* Standardised Bulk Out message types */
#define PC_RDR_SET_PARAMS      0x61
#define PC_RDR_ICC_ON          0x62
#define PC_RDR_ICC_OFF         0x63
#define PC_RDR_GET_SLOT_STATUS 0x65
#define PC_RDR_SECURE          0x69
#define PC_RDR_T0APDU          0x6A
#define PC_RDR_ESCAPE          0x6B
#define PC_RDR_GET_PARAMS      0x6C
#define PC_RDR_RESET_PARAMS    0x6D
#define PC_RDR_ICC_CLOCK       0x6E
#define PC_RDR_XFR_BLOCK       0x6F
#define PC_RDR_MECH            0x71
#define PC_RDR_ABORT           0x72
#define PC_RDR_DATA_CLOCK      0x73

/* Standardised Bulk In message types */
#define RDR_PC_DATA_BLOCK      0x80
#define RDR_PC_SLOT_STATUS     0x81
#define RDR_PC_PARAMS          0x82
#define RDR_PC_ESCAPE          0x83
#define RDR_PC_DATA_CLOCK      0x84

static const value_string ccid_messagetypes_vals[] = {
    /* Standardised Bulk Out message types */
    {PC_RDR_SET_PARAMS      , "PC_to_RDR_SetParameters"},
    {PC_RDR_ICC_ON          , "PC_to_RDR_IccPowerOn"},
    {PC_RDR_ICC_OFF         , "PC_to_RDR_IccPowerOff"},
    {PC_RDR_GET_SLOT_STATUS , "PC_to_RDR_GetSlotStatus"},
    {PC_RDR_SECURE          , "PC_to_RDR_Secure"},
    {PC_RDR_T0APDU          , "PC_to_RDR_T0APDU"},
    {PC_RDR_ESCAPE          , "PC_to_RDR_Escape"},
    {PC_RDR_GET_PARAMS      , "PC_to_RDR_GetParameters"},
    {PC_RDR_RESET_PARAMS    , "PC_to_RDR_ResetParameters"},
    {PC_RDR_ICC_CLOCK       , "PC_to_RDR_IccClock"},
    {PC_RDR_XFR_BLOCK       , "PC_to_RDR_XfrBlock"},
    {PC_RDR_MECH            , "PC_to_RDR_Mechanical"},
    {PC_RDR_ABORT           , "PC_to_RDR_Abort"},
    {PC_RDR_DATA_CLOCK      , "PC_to_RDR_SetDataRateAndClockFrequency"},

    /* Standardised Bulk In message types */
    {RDR_PC_DATA_BLOCK      , "RDR_to_PC_DataBlock"},
    {RDR_PC_SLOT_STATUS     , "RDR_to_PC_SlotStatus"},
    {RDR_PC_PARAMS          , "RDR_to_PC_Parameters"},
    {RDR_PC_ESCAPE          , "RDR_to_PC_Escape"},
    {RDR_PC_DATA_CLOCK      , "RDR_to_PC_DataRateAndClockFrequency"},

    /* End of message types */
    {0x00, NULL}
};

static const value_string ccid_voltage_levels_vals[] = {
    /* Standardised voltage levels */
    {0x00, "Automatic Voltage Selection"},
    {0x01, "5.0 volts"},
    {0x02, "3.0 volts"},
    {0x03, "1.8 volts"},

    /* End of voltage levels */
    {0x00, NULL}
};

static const value_string ccid_clock_states_vals[] = {
    /* Standardised clock states */
    {0x00, "Clock running"},
    {0x01, "Clock stopped in state L"},
    {0x02, "Clock stopped in state H"},
    {0x03, "Clock stopped in an unknown state"},

    /* End of clock states */
    {0x00, NULL}
};

static const value_string ccid_proto_structs_vals[] = {
    /* Standardised clock states */
    {0x00, "Structure for protocol T=0"},
    {0x01, "Structure for protocol T=1"},

    /* Marked as RFU, but added for completeness: */
    {0x80, "Structure for 2-wire protocol"},
    {0x81, "Structure for 3-wire protocol"},
    {0x82, "Structure for I2C protocol"},

    /* End of protocol structures */
    {0x00, NULL}
};

static dissector_handle_t data_handle;
static dissector_table_t  ccid_dissector_table;

/* Subtree handles: set by register_subtree_array */
static gint ett_ccid = -1;

/* Table of payload types - adapted from the I2C dissector*/
enum {
    SUB_DATA = 0,
    SUB_GSM_SIM,

    SUB_MAX
};

typedef gboolean (*sub_checkfunc_t)(packet_info *);

static dissector_handle_t sub_handles[SUB_MAX];
static gint sub_selected = SUB_DATA;

static void
dissect_ccid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item;
    proto_tree *ccid_tree;
    guint8      cmd;
    tvbuff_t   *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBCCID");
    col_set_str(pinfo->cinfo, COL_INFO,     "CCID Packet");

    if (tree) {
        /* Start with a top-level item to add everything else to */

        item = proto_tree_add_item(tree, proto_ccid, tvb, 0, -1, ENC_NA);
        ccid_tree = proto_item_add_subtree(item, ett_ccid);

        proto_tree_add_item(ccid_tree, hf_ccid_bMessageType, tvb, 0, 1, ENC_NA);
        cmd = tvb_get_guint8(tvb, 0);

        switch (cmd) {

        case PC_RDR_SET_PARAMS:
            proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bProtocolNum, tvb, 7, 1, ENC_LITTLE_ENDIAN);

            /* Placeholder for abRFU */
            proto_tree_add_text(ccid_tree, tvb, 8, 2, "Reserved for Future Use");

            next_tvb = tvb_new_subset_remaining(tvb, 10);

            call_dissector(data_handle, next_tvb, pinfo, ccid_tree);

            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: Set Parameters");
            break;

        case PC_RDR_ICC_ON:
            proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bPowerSelect, tvb, 7, 1, ENC_LITTLE_ENDIAN);

            /* Placeholder for abRFU */
            proto_tree_add_text(ccid_tree, tvb, 8, 2, "Reserved for Future Use");

            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: ICC Power On");
            break;

        case PC_RDR_ICC_OFF:
            proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

            /* Placeholder for abRFU */
            proto_tree_add_text(ccid_tree, tvb, 7, 3, "Reserved for Future Use");

            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: ICC Power Off");
            break;

        case PC_RDR_GET_SLOT_STATUS:
            proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

            /* Placeholder for abRFU */
            proto_tree_add_text(ccid_tree, tvb, 7, 3, "Reserved for Future Use");

            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: Get Slot Status");
            break;

        case PC_RDR_SECURE:
            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: Secure");
            break;

        case PC_RDR_T0APDU:
            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: T=0 APDU");
            break;

        case PC_RDR_ESCAPE:
            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: Escape");
            break;

        case PC_RDR_GET_PARAMS:
            proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

            /* Placeholder for abRFU */
            proto_tree_add_text(ccid_tree, tvb, 7, 3, "Reserved for Future Use");

            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: Get Parameters");
            break;

        case PC_RDR_RESET_PARAMS:
            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: Reset Parameters");
            break;

        case PC_RDR_ICC_CLOCK:
            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: ICC Clock");
            break;

        case PC_RDR_XFR_BLOCK:
            proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bBWI, tvb, 7, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_wLevelParameter, tvb, 8, 2, ENC_LITTLE_ENDIAN);

            next_tvb = tvb_new_subset_remaining(tvb, 10);

        if (sub_selected != SUB_DATA) {
            call_dissector(sub_handles[sub_selected], next_tvb, pinfo, tree);
		} else {
		  call_dissector(sub_handles[SUB_DATA], next_tvb, pinfo, tree);
		}

            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: Transfer Block");
            break;

        case PC_RDR_MECH:
            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: Mechanical");
            break;

        case PC_RDR_ABORT:
            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: Abort");
            break;

        case PC_RDR_DATA_CLOCK:
            col_set_str(pinfo->cinfo, COL_INFO, "PC to Reader: Set Data Rate and Clock Frequency");
            break;

        case RDR_PC_DATA_BLOCK:
            col_set_str(pinfo->cinfo, COL_INFO, "Reader to PC: Data Block");
            proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bStatus, tvb, 7, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bError, tvb, 8, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bChainParameter, tvb, 9, 1, ENC_LITTLE_ENDIAN);

            next_tvb = tvb_new_subset_remaining(tvb, 10);
            call_dissector(data_handle, next_tvb, pinfo, ccid_tree);
            break;

        case RDR_PC_SLOT_STATUS:
            proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bStatus, tvb, 7, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bError, tvb, 8, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_bClockStatus, tvb, 9, 1, ENC_LITTLE_ENDIAN);

            col_set_str(pinfo->cinfo, COL_INFO, "Reader to PC: Slot Status");
            break;

        case RDR_PC_PARAMS:
            col_set_str(pinfo->cinfo, COL_INFO, "Reader to PC: Parameters");
            break;

        case RDR_PC_ESCAPE:
            col_set_str(pinfo->cinfo, COL_INFO, "Reader to PC: Escape");
            break;

        case RDR_PC_DATA_CLOCK:
            col_set_str(pinfo->cinfo, COL_INFO, "Reader to PC: Data Rate and Clock Frequency");
            break;

        default:
            col_set_str(pinfo->cinfo, COL_INFO, "Unknown type");
            break;
        }
    }
}

void
proto_register_ccid(void)
{
    static hf_register_info hf[] = {

        {&hf_ccid_bMessageType,
         { "Message Type", "usbccid.bMessageType", FT_UINT8, BASE_HEX,
           VALS(ccid_messagetypes_vals), 0x0, NULL, HFILL }},
        {&hf_ccid_dwLength,
         { "Packet Length", "usbccid.dwLength", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bSlot,
         { "Slot", "usbccid.bSlot", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bSeq,
         { "Sequence", "usbccid.bSeq", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bStatus,
         { "Status", "usbccid.bStatus", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bError,
         { "Error", "usbccid.bError", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bChainParameter,
         { "Chain Parameter", "usbccid.bChainParameter", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bPowerSelect,
         { "Voltage Level", "usbccid.bPowerSelect", FT_UINT8, BASE_HEX,
           VALS(ccid_voltage_levels_vals), 0x0, NULL, HFILL }},
        {&hf_ccid_bClockStatus,
         { "Clock Status", "usbccid.bClockStatus", FT_UINT8, BASE_HEX,
           VALS(ccid_clock_states_vals), 0x0, NULL, HFILL }},
        {&hf_ccid_bProtocolNum,
         { "Data Structure Type", "usbccid.bProtocolNum", FT_UINT8, BASE_HEX,
           VALS(ccid_proto_structs_vals), 0x0, NULL, HFILL }},
        {&hf_ccid_bBWI,
         { "Block Wait Time Integer", "usbccid.bBWI", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_wLevelParameter,
         { "Level Parameter", "usbccid.wLevelParameter", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }}

    };

    static gint *ett[] = {
        &ett_ccid
    };

    static const enum_val_t sub_enum_vals[] = {
        { "data", "Data", SUB_DATA },
        { "gsm_sim", "GSM SIM", SUB_GSM_SIM },
        { NULL, NULL, 0 }
    };
    
    module_t *pref_mod;
    
    proto_ccid = proto_register_protocol("USB CCID", "USBCCID", "usbccid");
    proto_register_field_array(proto_ccid, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    
    pref_mod = prefs_register_protocol(proto_ccid, NULL);
    prefs_register_enum_preference(pref_mod, "prtype", "PC -> Reader Payload Type", "How commands from the PC to the reader are interpreted",
        &sub_selected, sub_enum_vals, FALSE);

    ccid_dissector_table = register_dissector_table("usbccid.payload",
                                                    "CCID Payload", FT_UINT8, BASE_DEC);

    register_dissector("usbccid", dissect_ccid, proto_ccid);
}

/* Handler registration */
void
proto_reg_handoff_ccid(void)
{
    dissector_handle_t usb_ccid_bulk_handle;

    usb_ccid_bulk_handle = find_dissector("usbccid");
    dissector_add_uint("usb.bulk", IF_CLASS_SMART_CARD, usb_ccid_bulk_handle);
    
    sub_handles[SUB_DATA] = find_dissector("data");

    data_handle = sub_handles[SUB_DATA];
    sub_handles[SUB_GSM_SIM] = find_dissector("gsm_sim");
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
