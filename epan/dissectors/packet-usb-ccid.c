/* packet-usb-ccid.c
 * Dissector for the Integrated Circuit Card Interface Device Class
 *
 * References:
 * http://www.usb.org/developers/devclass_docs/DWG_Smart-Card_CCID_Rev110.pdf
 *
 * Copyright 2011, Tyson Key <tyson.key@gmail.com>
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
 *
 */
#include "config.h"

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
static int hf_ccid_bRFU = -1;
static int hf_ccid_abRFU = -1;
static int hf_ccid_bChainParameter = -1;
static int hf_ccid_bPowerSelect = -1;
static int hf_ccid_bClockStatus = -1;
static int hf_ccid_bProtocolNum = -1;
static int hf_ccid_bBWI = -1;
static int hf_ccid_wLevelParameter = -1;
static int hf_ccid_bcdCCID = -1;
static int hf_ccid_bMaxSlotIndex = -1;
static int hf_ccid_bVoltageSupport = -1;
static int hf_ccid_bVoltageSupport50 = -1;
static int hf_ccid_bVoltageSupport30 = -1;
static int hf_ccid_bVoltageSupport18 = -1;
static int hf_ccid_dwProtocols = -1;
static int hf_ccid_dwDefaultClock = -1;
static int hf_ccid_dwMaximumClock = -1;
static int hf_ccid_bNumClockSupported = -1;
static int hf_ccid_dwDataRate = -1;
static int hf_ccid_dwMaxDataRate = -1;
static int hf_ccid_bNumDataRatesSupported = -1;
static int hf_ccid_dwSynchProtocols = -1;
static int hf_ccid_dwMechanical = -1;
static int hf_ccid_dwFeatures = -1;
static int hf_ccid_dwMaxCCIDMessageLength = -1;
static int hf_ccid_bClassGetResponse = -1;
static int hf_ccid_bClassEnvelope = -1;
static int hf_ccid_wLcdLayout = -1;
static int hf_ccid_bPINSupport = -1;
static int hf_ccid_bMaxCCIDBusySlots = -1;

static dissector_handle_t usb_ccid_handle;

static const int *bVoltageLevel_fields[] = {
    &hf_ccid_bVoltageSupport50,
    &hf_ccid_bVoltageSupport30,
    &hf_ccid_bVoltageSupport18,
    NULL
};


/* smart card descriptor, as defined in section 5.1
   of the USB CCID specification */
#define USB_DESC_TYPE_SMARTCARD 0x21

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

void proto_register_ccid(void);
void proto_reg_handoff_ccid(void);

static const value_string ccid_descriptor_type_vals[] = {
        {USB_DESC_TYPE_SMARTCARD, "smart card"},
        {0,NULL}
};
static value_string_ext ccid_descriptor_type_vals_ext =
    VALUE_STRING_EXT_INIT(ccid_descriptor_type_vals);

static const value_string ccid_opcode_vals[] = {
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

static const value_string ccid_messagetypes_vals[] = {
    /* Standardised Bulk Out message types */
    {PC_RDR_SET_PARAMS      , "PC to Reader: Set Parameters"},
    {PC_RDR_ICC_ON          , "PC to Reader: ICC Power On"},
    {PC_RDR_ICC_OFF         , "PC to Reader: ICC Power Off"},
    {PC_RDR_GET_SLOT_STATUS , "PC to Reader: Get Slot Status"},
    {PC_RDR_SECURE          , "PC to Reader: Secure"},
    {PC_RDR_T0APDU          , "PC to Reader: T=0 APDU"},
    {PC_RDR_ESCAPE          , "PC to Reader: Escape"},
    {PC_RDR_GET_PARAMS      , "PC to Reader: Get Parameters"},
    {PC_RDR_RESET_PARAMS    , "PC to Reader: Reset Parameters"},
    {PC_RDR_ICC_CLOCK       , "PC to Reader: ICC Clock"},
    {PC_RDR_XFR_BLOCK       , "PC to Reader: Transfer Block"},
    {PC_RDR_MECH            , "PC to Reader: Mechanical"},
    {PC_RDR_ABORT           , "PC to Reader: Abort"},
    {PC_RDR_DATA_CLOCK      , "PC to Reader: Set Data Rate and Clock Frequency"},

    /* Standardised Bulk In message types */
    {RDR_PC_DATA_BLOCK      , "Reader to PC: Data Block"},
    {RDR_PC_SLOT_STATUS     , "Reader to PC: Slot Status"},
    {RDR_PC_PARAMS          , "Reader to PC: Parameters"},
    {RDR_PC_ESCAPE          , "Reader to PC: Escape"},
    {RDR_PC_DATA_CLOCK      , "Reader to PC: Data Rate and Clock Frequency"},

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

/* Subtree handles: set by register_subtree_array */
static gint ett_ccid      = -1;
static gint ett_ccid_desc = -1;
static gint ett_ccid_voltage_level = -1;

/* Table of payload types - adapted from the I2C dissector */
enum {
    SUB_DATA = 0,
    SUB_ISO7816,
    SUB_GSM_SIM_CMD,
    SUB_PN532,
    SUB_ACR122_PN532,
    SUB_GSM_SIM_RSP,

    SUB_MAX
};

typedef gboolean (*sub_checkfunc_t)(packet_info *);

static dissector_handle_t sub_handles[SUB_MAX];
static gint sub_selected = SUB_DATA;


static gint
dissect_usb_ccid_descriptor(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, void *data _U_)
{
    gint        offset = 0;
    guint8      descriptor_type;
    guint8      descriptor_len;
    proto_item *item, *freq_item;
    proto_tree *desc_tree;
    guint8      num_clock_supp;

    descriptor_len  = tvb_get_guint8(tvb, offset);
    descriptor_type = tvb_get_guint8(tvb, offset+1);
    if (descriptor_type!=USB_DESC_TYPE_SMARTCARD)
        return 0;

    item = proto_tree_add_text(tree, tvb, offset, descriptor_len,
                "SMART CARD DEVICE CLASS DESCRIPTOR");
    desc_tree = proto_item_add_subtree(item, ett_ccid_desc);

    dissect_usb_descriptor_header(desc_tree, tvb, offset,
            &ccid_descriptor_type_vals_ext);
    offset += 2;

    proto_tree_add_item(desc_tree, hf_ccid_bcdCCID, tvb,
            offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(desc_tree, hf_ccid_bMaxSlotIndex, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_bitmask(desc_tree, tvb, offset,
            hf_ccid_bVoltageSupport, ett_ccid_voltage_level, bVoltageLevel_fields,
            ENC_LITTLE_ENDIAN);
    offset++;

    /* XXX - convert into a bitmask */
    proto_tree_add_item(desc_tree, hf_ccid_dwProtocols, tvb,
            offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    freq_item = proto_tree_add_item(desc_tree, hf_ccid_dwDefaultClock, tvb,
            offset, 4, ENC_LITTLE_ENDIAN);
    proto_item_append_text(freq_item, " kHz");
    offset += 4;
    freq_item = proto_tree_add_item(desc_tree, hf_ccid_dwMaximumClock, tvb,
            offset, 4, ENC_LITTLE_ENDIAN);
    proto_item_append_text(freq_item, " kHz");
    offset += 4;
    num_clock_supp = tvb_get_guint8(tvb, offset);
    freq_item = proto_tree_add_item(desc_tree, hf_ccid_bNumClockSupported, tvb,
            offset, 1, ENC_LITTLE_ENDIAN);
    if (num_clock_supp==0)
        proto_item_append_text(freq_item, " (only default and maximum)");
    offset++;

    proto_tree_add_item(desc_tree, hf_ccid_dwDataRate,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(desc_tree, hf_ccid_dwMaxDataRate,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(desc_tree, hf_ccid_bNumDataRatesSupported,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    /* skip dwMaxIFSD */
    offset += 4;

    proto_tree_add_item(desc_tree, hf_ccid_dwSynchProtocols,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(desc_tree, hf_ccid_dwMechanical,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(desc_tree, hf_ccid_dwFeatures,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(desc_tree, hf_ccid_dwMaxCCIDMessageLength,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(desc_tree, hf_ccid_bClassGetResponse,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;
    proto_tree_add_item(desc_tree, hf_ccid_bClassEnvelope,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(desc_tree, hf_ccid_wLcdLayout,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(desc_tree, hf_ccid_bPINSupport,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(desc_tree, hf_ccid_bMaxCCIDBusySlots,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset;
}


static gint
dissect_ccid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *item;
    proto_tree *ccid_tree;
    guint8      cmd;
    tvbuff_t   *next_tvb;
    usb_conv_info_t  *usb_conv_info;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    usb_conv_info = (usb_conv_info_t *)data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBCCID");
    col_set_str(pinfo->cinfo, COL_INFO,     "CCID Packet");

    /* Start with a top-level item to add everything else to */
    item = proto_tree_add_item(tree, proto_ccid, tvb, 0, 10, ENC_NA);
    ccid_tree = proto_item_add_subtree(item, ett_ccid);

    proto_tree_add_item(ccid_tree, hf_ccid_bMessageType, tvb, 0, 1, ENC_NA);
    cmd = tvb_get_guint8(tvb, 0);

    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_const(cmd, ccid_messagetypes_vals, "Unknown"));

    switch (cmd) {

    case PC_RDR_SET_PARAMS:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bProtocolNum, tvb, 7, 1, ENC_LITTLE_ENDIAN);

        /* Placeholder for abRFU */
        proto_tree_add_text(ccid_tree, tvb, 8, 2, "Reserved for Future Use");
        if (tvb_get_letohl(tvb, 1) != 0)
        {
            next_tvb = tvb_new_subset_remaining(tvb, 10);
            call_dissector(sub_handles[SUB_DATA], next_tvb, pinfo, tree);
        }
        break;

    case PC_RDR_ICC_ON:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bPowerSelect, tvb, 7, 1, ENC_LITTLE_ENDIAN);

        /* Placeholder for abRFU */
        proto_tree_add_text(ccid_tree, tvb, 8, 2, "Reserved for Future Use");
        break;

    case PC_RDR_ICC_OFF:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

        /* Placeholder for abRFU */
        proto_tree_add_text(ccid_tree, tvb, 7, 3, "Reserved for Future Use");
        break;

    case PC_RDR_GET_SLOT_STATUS:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

        /* Placeholder for abRFU */
        proto_tree_add_text(ccid_tree, tvb, 7, 3, "Reserved for Future Use");
        break;

    case PC_RDR_GET_PARAMS:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

        /* Placeholder for abRFU */
        proto_tree_add_text(ccid_tree, tvb, 7, 3, "Reserved for Future Use");
        break;

    case PC_RDR_XFR_BLOCK:
    case PC_RDR_ESCAPE:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

        if (cmd == PC_RDR_ESCAPE) {
            proto_tree_add_item(ccid_tree, hf_ccid_abRFU, tvb, 7, 3, ENC_NA);
        } else {
            proto_tree_add_item(ccid_tree, hf_ccid_bBWI, tvb, 7, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_wLevelParameter, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        }

        if (tvb_get_letohl(tvb, 1) != 0)
        {
            next_tvb = tvb_new_subset_remaining(tvb, 10);

            /* See if the dissector isn't Data */
            if (sub_selected != SUB_DATA) {

                if (sub_selected == SUB_PN532) {
                    call_dissector_with_data(sub_handles[sub_selected], tvb_new_subset_remaining(tvb, 10), pinfo, tree, usb_conv_info);
                } else if (sub_selected == SUB_ACR122_PN532) {
                    pinfo->p2p_dir = P2P_DIR_SENT;
                    call_dissector_with_data(sub_handles[sub_selected], tvb_new_subset_remaining(tvb, 10), pinfo, tree, usb_conv_info);
                } else if (sub_selected == SUB_ISO7816) {
                    /* sent/received is from the perspective of the card reader */
                    pinfo->p2p_dir = P2P_DIR_SENT;
                    call_dissector(sub_handles[SUB_ISO7816], next_tvb, pinfo, tree);
                } else { /* The user probably wanted GSM SIM, or something else */
                    call_dissector(sub_handles[sub_selected], next_tvb, pinfo, tree);
                }

            } else if (usb_conv_info->deviceVendor == 0x072F && usb_conv_info->deviceProduct == 0x2200) {
                    pinfo->p2p_dir = P2P_DIR_SENT;
                    call_dissector_with_data(sub_handles[SUB_ACR122_PN532], tvb_new_subset_remaining(tvb, 10), pinfo, tree, usb_conv_info);
            } else { /* The user only wants plain data */
                call_dissector(sub_handles[SUB_DATA], next_tvb, pinfo, tree);
            }
        }
        break;

    case RDR_PC_DATA_BLOCK:
    case RDR_PC_ESCAPE:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bStatus, tvb, 7, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bError, tvb, 8, 1, ENC_LITTLE_ENDIAN);
        if (cmd == RDR_PC_ESCAPE)
            proto_tree_add_item(ccid_tree, hf_ccid_bRFU, tvb, 9, 1, ENC_LITTLE_ENDIAN);
        else
            proto_tree_add_item(ccid_tree, hf_ccid_bChainParameter, tvb, 9, 1, ENC_LITTLE_ENDIAN);

        if (tvb_get_letohl(tvb, 1) != 0)
        {
            next_tvb = tvb_new_subset_remaining(tvb, 10);

            if (sub_selected == SUB_PN532) {
                next_tvb= tvb_new_subset_length(tvb, 10, tvb_get_guint8(tvb, 1));
                call_dissector_with_data(sub_handles[SUB_PN532], next_tvb, pinfo, tree, usb_conv_info);
            } else if (sub_selected == SUB_ACR122_PN532) {
                pinfo->p2p_dir = P2P_DIR_RECV;
                call_dissector_with_data(sub_handles[SUB_ACR122_PN532], tvb_new_subset_remaining(tvb, 10), pinfo, tree, usb_conv_info);
            } else if (sub_selected == SUB_GSM_SIM_CMD) {  /* Try to dissect responses to GSM SIM packets */
                call_dissector(sub_handles[SUB_GSM_SIM_RSP], next_tvb, pinfo, tree);
            } else if (sub_selected == SUB_ISO7816) {
                pinfo->p2p_dir = P2P_DIR_RECV;
                call_dissector(sub_handles[SUB_ISO7816], next_tvb, pinfo, tree);
            } else if (usb_conv_info->deviceVendor == 0x072F && usb_conv_info->deviceProduct == 0x2200) {
                pinfo->p2p_dir = P2P_DIR_RECV;
                call_dissector_with_data(sub_handles[SUB_ACR122_PN532], tvb_new_subset_remaining(tvb, 10), pinfo, tree, usb_conv_info);
            } else {
                call_dissector(sub_handles[SUB_DATA], next_tvb, pinfo, tree);
            }
        }
        break;

    case RDR_PC_SLOT_STATUS:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bStatus, tvb, 7, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bError, tvb, 8, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bClockStatus, tvb, 9, 1, ENC_LITTLE_ENDIAN);
        break;
    }

    /* TODO: Try use "offset" instead of hardcoded constants */
    return tvb_length(tvb);
}

void
proto_register_ccid(void)
{
    static hf_register_info hf[] = {

        {&hf_ccid_bMessageType,
         { "Message Type", "usbccid.bMessageType", FT_UINT8, BASE_HEX,
           VALS(ccid_opcode_vals), 0x0, NULL, HFILL }},
        {&hf_ccid_dwLength,
         { "Packet Length", "usbccid.dwLength", FT_UINT32, BASE_DEC,
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
        {&hf_ccid_bRFU,
         { "RFU", "usbccid.bRFU", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_abRFU,
         { "RFU", "usbccid.abRFU", FT_BYTES, BASE_NONE,
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
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bcdCCID,
         { "bcdCCID", "usbccid.bcdCCID", FT_UINT16, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bMaxSlotIndex,
         { "max slot index", "usbccid.bMaxSlotIndex", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bVoltageSupport,
         { "voltage support", "usbccid.bVoltageSupport", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bVoltageSupport50,
         { "supports 5.0V", "usbccid.bVoltageSupport.50", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x01, NULL, HFILL }},
        {&hf_ccid_bVoltageSupport30,
         { "supports 3.0V", "usbccid.bVoltageSupport.30", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x02, NULL, HFILL }},
        {&hf_ccid_bVoltageSupport18,
         { "supports 1.8V", "usbccid.bVoltageSupport.18", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), 0x04, NULL, HFILL }},
        {&hf_ccid_dwProtocols,
         { "dwProtocols", "usbccid.dwProtocols", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwDefaultClock,
         { "default clock frequency", "usbccid.dwDefaultClock",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwMaximumClock,
         { "maximum clock frequency", "usbccid.dwMaximumClock",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bNumClockSupported,
         { "number of supported clock frequencies", "usbccid.bNumClockSupported",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwDataRate,
         { "default ICC I/O data rate in bps", "usbccid.dwDataRate",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwMaxDataRate,
         { "maximum ICC I/O data rate in bps", "usbccid.dwMaxDataRate",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bNumDataRatesSupported,
         { "number of supported data rates", "usbccid.bNumDataRatesSupported",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwSynchProtocols,
         { "supported protocol types", "usbccid.dwSynchProtocols",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwMechanical,
         { "mechanical characteristics", "usbccid.dwMechanical",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwFeatures,
         { "intelligent features", "usbccid.dwFeatures",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwMaxCCIDMessageLength,
         { "maximum CCID message length", "usbccid.dwMaxCCIDMessageLength",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bClassGetResponse,
         { "default class for Get Response", "usbccid.hf_ccid_bClassGetResponse",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bClassEnvelope,
         { "default class for Envelope", "usbccid.hf_ccid_bClassEnvelope",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_wLcdLayout,
         { "LCD layout", "usbccid.hf_ccid_wLcdLayout",
             FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bPINSupport,
         { "PIN support", "usbccid.hf_ccid_bPINSupport",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bMaxCCIDBusySlots,
         { "maximum number of busy slots", "usbccid.hf_ccid_bMaxCCIDBusySlots",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_ccid,
        &ett_ccid_desc,
        &ett_ccid_voltage_level
    };

    static const enum_val_t sub_enum_vals[] = {
        { "data", "Data", SUB_DATA },
        { "iso7816", "Generic ISO 7816", SUB_ISO7816 },
        { "gsm_sim", "GSM SIM", SUB_GSM_SIM_CMD },
        { "pn532", "NXP PN532", SUB_PN532},
        { "acr122", "ACR122 PN532", SUB_ACR122_PN532},
        { NULL, NULL, 0 }
    };

    module_t *pref_mod;

    proto_ccid = proto_register_protocol("USB CCID", "USBCCID", "usbccid");
    proto_register_field_array(proto_ccid, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pref_mod = prefs_register_protocol(proto_ccid, NULL);
    prefs_register_enum_preference(pref_mod, "prtype", "PC -> Reader Payload Type", "How commands from the PC to the reader are interpreted",
        &sub_selected, sub_enum_vals, FALSE);

    usb_ccid_handle = new_register_dissector("usbccid", dissect_ccid, proto_ccid);
}

/* Handler registration */
void
proto_reg_handoff_ccid(void)
{
    dissector_handle_t usb_ccid_descr_handle;

    usb_ccid_descr_handle = new_create_dissector_handle(
            dissect_usb_ccid_descriptor, proto_ccid);
    dissector_add_uint("usb.descriptor", IF_CLASS_SMART_CARD, usb_ccid_descr_handle);

    dissector_add_uint("usb.bulk", IF_CLASS_SMART_CARD, usb_ccid_handle);

    dissector_add_for_decode_as("usb.device", usb_ccid_handle);
    dissector_add_for_decode_as("usb.product", usb_ccid_handle);
    dissector_add_for_decode_as("usb.protocol", usb_ccid_handle);

    sub_handles[SUB_DATA] = find_dissector("data");
    sub_handles[SUB_ISO7816] = find_dissector("iso7816");
    sub_handles[SUB_GSM_SIM_CMD] = find_dissector("gsm_sim.command");
    sub_handles[SUB_PN532] = find_dissector("pn532");
    sub_handles[SUB_ACR122_PN532] = find_dissector("acr122");
    sub_handles[SUB_GSM_SIM_RSP] = find_dissector("gsm_sim.response");
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
