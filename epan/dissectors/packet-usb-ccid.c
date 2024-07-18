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
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */
#include "config.h"

#include <epan/decode_as.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-usb.h"

static int proto_ccid;

static dissector_table_t subdissector_table;

static int hf_ccid_bMessageType;
static int hf_ccid_dwLength;
static int hf_ccid_bSlot;
static int hf_ccid_bSeq;
static int hf_ccid_bStatus;
static int hf_ccid_bStatus_bmIccStatus;
static int hf_ccid_bStatus_bmCommandStatus;
static int hf_ccid_bError;
static int hf_ccid_bRFU;
static int hf_ccid_abRFU;
static int hf_ccid_bChainParameter;
static int hf_ccid_bPowerSelect;
static int hf_ccid_bClockStatus;
static int hf_ccid_bProtocolNum;
static int hf_ccid_bBWI;
static int hf_ccid_wLevelParameter;
static int hf_ccid_bcdCCID;
static int hf_ccid_bMaxSlotIndex;
static int hf_ccid_bVoltageSupport;
static int hf_ccid_bVoltageSupport18;
static int hf_ccid_bVoltageSupport30;
static int hf_ccid_bVoltageSupport50;
static int hf_ccid_dwProtocols;
static int hf_ccid_dwProtocols_t0;
static int hf_ccid_dwProtocols_t1;
static int hf_ccid_dwDefaultClock;
static int hf_ccid_dwMaximumClock;
static int hf_ccid_bNumClockSupported;
static int hf_ccid_dwDataRate;
static int hf_ccid_dwMaxDataRate;
static int hf_ccid_bNumDataRatesSupported;
static int hf_ccid_dwMaxIFSD;
static int hf_ccid_dwSynchProtocols;
static int hf_ccid_dwMechanical;
static int hf_ccid_dwFeatures;
static int hf_ccid_dwFeatures_autoParam;
static int hf_ccid_dwFeatures_autoIccActivation;
static int hf_ccid_dwFeatures_autoIccVoltSelect;
static int hf_ccid_dwFeatures_autoIccClk;
static int hf_ccid_dwFeatures_autoBaudRate;
static int hf_ccid_dwFeatures_autoParamNegotiation;
static int hf_ccid_dwFeatures_autoPPS;
static int hf_ccid_dwFeatures_stopIccClk;
static int hf_ccid_dwFeatures_nadValNot0accept;
static int hf_ccid_dwFeatures_autoIfsd;
static int hf_ccid_dwFeatures_levelExchangeTDPU;
static int hf_ccid_dwFeatures_levelExchangeShortAPDU;
static int hf_ccid_dwFeatures_levelExchangeShortExtendedAPDU;
static int hf_ccid_dwFeatures_UsbWakeUp;
static int hf_ccid_dwMaxCCIDMessageLength;
static int hf_ccid_bClassGetResponse;
static int hf_ccid_bClassEnvelope;
static int hf_ccid_wLcdLayout;
static int hf_ccid_wLcdLayout_lines;
static int hf_ccid_wLcdLayout_chars;
static int hf_ccid_bPINSupport;
static int hf_ccid_bPINSupport_modify;
static int hf_ccid_bPINSupport_vrfy;
static int hf_ccid_bMaxCCIDBusySlots;
static int hf_ccid_Reserved;
static int hf_ccid_bmSlotICCState;
static int hf_ccid_bmSlotICCState_slot0Current;
static int hf_ccid_bmSlotICCState_slot0Changed;
static int hf_ccid_bmSlotICCState_slot1Current;
static int hf_ccid_bmSlotICCState_slot1Changed;
static int hf_ccid_bmSlotICCState_slot2Current;
static int hf_ccid_bmSlotICCState_slot2Changed;
static int hf_ccid_bmSlotICCState_slot3Current;
static int hf_ccid_bmSlotICCState_slot3Changed;
static int hf_ccid_bmSlotICCState_slot4Current;
static int hf_ccid_bmSlotICCState_slot4Changed;
static int hf_ccid_bmSlotICCState_slot5Current;
static int hf_ccid_bmSlotICCState_slot5Changed;
static int hf_ccid_bmSlotICCState_slot6Current;
static int hf_ccid_bmSlotICCState_slot6Changed;
static int hf_ccid_bmSlotICCState_slot7Current;
static int hf_ccid_bmSlotICCState_slot7Changed;
static int hf_ccid_bHardwareErrorCode;
static int hf_ccid_bmFindexDindex;
static int hf_ccid_bmTCCKST0;
static int hf_ccid_bmTCCKST1;
static int hf_ccid_bGuardTimeT0;
static int hf_ccid_bGuardTimeT1;
static int hf_ccid_bWaitingIntegerT0;
static int hf_ccid_bmWaitingIntegersT1;
static int hf_ccid_bClockStop;
static int hf_ccid_bIFSC;
static int hf_ccid_bNadValue;

static dissector_handle_t usb_ccid_handle;
static dissector_handle_t usb_ccid_descr_handle;


static int * const bVoltageLevel_fields[] = {
    &hf_ccid_bVoltageSupport18,
    &hf_ccid_bVoltageSupport30,
    &hf_ccid_bVoltageSupport50,
    NULL
};

static int * const dwProtocols_fields[] = {
    &hf_ccid_dwProtocols_t0,
    &hf_ccid_dwProtocols_t1,
    NULL
};

static int * const bFeatures_fields[] = {
    /* XXX - add the missing components */
    &hf_ccid_dwFeatures_autoParam,
    &hf_ccid_dwFeatures_autoIccActivation,
    &hf_ccid_dwFeatures_autoIccVoltSelect,
    &hf_ccid_dwFeatures_autoIccClk,
    &hf_ccid_dwFeatures_autoBaudRate,
    &hf_ccid_dwFeatures_autoParamNegotiation,
    &hf_ccid_dwFeatures_autoPPS,
    &hf_ccid_dwFeatures_stopIccClk,
    &hf_ccid_dwFeatures_nadValNot0accept,
    &hf_ccid_dwFeatures_autoIfsd,
    &hf_ccid_dwFeatures_levelExchangeTDPU,
    &hf_ccid_dwFeatures_levelExchangeShortAPDU,
    &hf_ccid_dwFeatures_levelExchangeShortExtendedAPDU,
    &hf_ccid_dwFeatures_UsbWakeUp,
    NULL
};

static int * const bPINSupport_fields[] = {
    &hf_ccid_bPINSupport_modify,
    &hf_ccid_bPINSupport_vrfy,
    NULL
};

static int * const bmSlotICCStateb0_fields[] = {
    &hf_ccid_bmSlotICCState_slot0Current,
    &hf_ccid_bmSlotICCState_slot0Changed,
    &hf_ccid_bmSlotICCState_slot1Current,
    &hf_ccid_bmSlotICCState_slot1Changed,
    &hf_ccid_bmSlotICCState_slot2Current,
    &hf_ccid_bmSlotICCState_slot2Changed,
    &hf_ccid_bmSlotICCState_slot3Current,
    &hf_ccid_bmSlotICCState_slot3Changed,
    NULL
};

static int * const bmSlotICCStateb1_fields[] = {
    &hf_ccid_bmSlotICCState_slot4Current,
    &hf_ccid_bmSlotICCState_slot4Changed,
    &hf_ccid_bmSlotICCState_slot5Current,
    &hf_ccid_bmSlotICCState_slot5Changed,
    &hf_ccid_bmSlotICCState_slot6Current,
    &hf_ccid_bmSlotICCState_slot6Changed,
    &hf_ccid_bmSlotICCState_slot7Current,
    &hf_ccid_bmSlotICCState_slot7Changed,
    NULL
};

static int * const bStatus_fields[] = {
    &hf_ccid_bStatus_bmIccStatus,
    &hf_ccid_bStatus_bmCommandStatus,
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

/* Standardised Interrupt IN message types */
#define RDR_PC_NOTIF_SLOT_CHNG 0x50
#define RDR_PC_HWERROR         0x51

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

    /* Standardised Interrupt IN message types */
    {RDR_PC_NOTIF_SLOT_CHNG , "RDR_to_PC_NotifySlotChange"},
    {RDR_PC_HWERROR         , "RDR_to_PC_HardwareError"},

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

    /* Standardised Interrupt IN message types */
    {RDR_PC_NOTIF_SLOT_CHNG , "Reader to PC: Notify Slot Change"},
    {RDR_PC_HWERROR         , "Reader to PC: Hardware Error"},

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

static const value_string ccid_status_icc_status_vals[] = {
    /* Standardised icc status */
    { 0x00, "An ICC is present and active" },
    { 0x01, "An ICC is present and inactive" },
    { 0x02, "No ICC is present" },
    { 0x03, "RFU" },

    /* End of icc status */
    { 0x00, NULL }
};

static const value_string ccid_status_cmd_status_vals[] = {
    /* Standardised status values */
    { 0x00, "Processed without error " },
    { 0x01, "Failed" },
    { 0x02, "Time Extension is requested " },
    { 0x03, "RFU" },

    /* End of status values */
    { 0x00, NULL }
};

/* Subtree handles: set by register_subtree_array */
static int ett_ccid;
static int ett_ccid_desc;
static int ett_ccid_protocol_data_structure;
static int ett_ccid_voltage_level;
static int ett_ccid_protocols;
static int ett_ccid_features;
static int ett_ccid_lcd_layout;
static int ett_ccid_pin_support;
static int ett_ccid_slot_change;
static int ett_ccid_status;

static int
dissect_usb_ccid_descriptor(tvbuff_t *tvb, packet_info *pinfo _U_,
        proto_tree *tree, void *data _U_)
{
    int         offset = 0;
    uint8_t     descriptor_type;
    uint8_t     descriptor_len;
    proto_item *freq_item;
    proto_tree *desc_tree;
    uint8_t     num_clock_supp;
    proto_item *lcd_layout_item;
    proto_tree *lcd_layout_tree;

    descriptor_len  = tvb_get_uint8(tvb, offset);
    descriptor_type = tvb_get_uint8(tvb, offset+1);
    if (descriptor_type!=USB_DESC_TYPE_SMARTCARD)
        return 0;

    desc_tree = proto_tree_add_subtree(tree, tvb, offset, descriptor_len,
                ett_ccid_desc, NULL, "SMART CARD DEVICE CLASS DESCRIPTOR");

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

    proto_tree_add_bitmask(desc_tree, tvb, offset,
            hf_ccid_dwProtocols, ett_ccid_protocols, dwProtocols_fields,
            ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(desc_tree, hf_ccid_dwDefaultClock, tvb,
            offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    proto_tree_add_item(desc_tree, hf_ccid_dwMaximumClock, tvb,
            offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    num_clock_supp = tvb_get_uint8(tvb, offset);
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

    proto_tree_add_item(desc_tree, hf_ccid_dwMaxIFSD,
        tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(desc_tree, hf_ccid_dwSynchProtocols,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(desc_tree, hf_ccid_dwMechanical,
            tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_bitmask(desc_tree, tvb, offset,
            hf_ccid_dwFeatures, ett_ccid_features, bFeatures_fields,
            ENC_LITTLE_ENDIAN);
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

    lcd_layout_item = proto_tree_add_item(desc_tree, hf_ccid_wLcdLayout,
            tvb, offset, 2, ENC_LITTLE_ENDIAN);
    lcd_layout_tree = proto_item_add_subtree(
            lcd_layout_item, ett_ccid_lcd_layout);
    proto_tree_add_item(lcd_layout_tree, hf_ccid_wLcdLayout_lines,
            tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(lcd_layout_tree, hf_ccid_wLcdLayout_chars,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(desc_tree, tvb, offset,
            hf_ccid_bPINSupport, ett_ccid_pin_support, bPINSupport_fields,
            ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(desc_tree, hf_ccid_bMaxCCIDBusySlots,
            tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    return offset;
}


static int
dissect_ccid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *item;
    proto_tree *ccid_tree;
    uint8_t     cmd;
    uint32_t    payload_len;
    tvbuff_t   *next_tvb;
    usb_conv_info_t  *usb_conv_info;
    int len_remaining;
    uint8_t bProtocolNum;
    proto_tree *protocol_tree;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    usb_conv_info = (usb_conv_info_t *)data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "USBCCID");
    col_set_str(pinfo->cinfo, COL_INFO,     "CCID Packet");

    /* Start with a top-level item to add everything else to */
    item = proto_tree_add_item(tree, proto_ccid, tvb, 0, 10, ENC_NA);
    ccid_tree = proto_item_add_subtree(item, ett_ccid);

    proto_tree_add_item(ccid_tree, hf_ccid_bMessageType, tvb, 0, 1, ENC_LITTLE_ENDIAN);
    cmd = tvb_get_uint8(tvb, 0);

    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_const(cmd, ccid_messagetypes_vals, "Unknown"));

    switch (cmd) {

    case PC_RDR_SET_PARAMS:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bProtocolNum, tvb, 7, 1, ENC_LITTLE_ENDIAN);

        /* Placeholder for abRFU */
        proto_tree_add_item(ccid_tree, hf_ccid_Reserved, tvb, 8, 2, ENC_LITTLE_ENDIAN);

        payload_len = tvb_get_letohl(tvb, 1);

        /* abProtocolDataStructure */
        bProtocolNum = tvb_get_uint8(tvb, 7);
        switch (bProtocolNum)
        {
            case 0: /* T=0 */
                protocol_tree = proto_tree_add_subtree(tree, tvb, 10, payload_len, ett_ccid_protocol_data_structure, NULL, "Protocol Data Structure for Protocol T=0");
                proto_tree_add_item(protocol_tree, hf_ccid_bmFindexDindex, tvb, 10, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bmTCCKST0, tvb, 11, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bGuardTimeT0, tvb, 12, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bWaitingIntegerT0, tvb, 13, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bClockStop, tvb, 14, 1, ENC_LITTLE_ENDIAN);
                break;

            case 1: /* T=1 */
                protocol_tree = proto_tree_add_subtree(tree, tvb, 10, payload_len, ett_ccid_protocol_data_structure, NULL, "Protocol Data Structure for Protocol T=1");
                proto_tree_add_item(protocol_tree, hf_ccid_bmFindexDindex, tvb, 10, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bmTCCKST1, tvb, 11, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bGuardTimeT1, tvb, 12, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bmWaitingIntegersT1, tvb, 13, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bClockStop, tvb, 14, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bIFSC, tvb, 15, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bNadValue, tvb, 16, 1, ENC_LITTLE_ENDIAN);
                break;

            default:
                next_tvb = tvb_new_subset_remaining(tvb, 10);
                call_data_dissector(next_tvb, pinfo, tree);
        }
        break;

    case PC_RDR_ICC_ON:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bPowerSelect, tvb, 7, 1, ENC_LITTLE_ENDIAN);

        /* Placeholder for abRFU */
        proto_tree_add_item(ccid_tree, hf_ccid_Reserved, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        break;

    case PC_RDR_ICC_OFF:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

        /* Placeholder for abRFU */
        proto_tree_add_item(ccid_tree, hf_ccid_Reserved, tvb, 7, 3, ENC_LITTLE_ENDIAN);
        break;

    case PC_RDR_GET_SLOT_STATUS:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

        /* Placeholder for abRFU */
        proto_tree_add_item(ccid_tree, hf_ccid_Reserved, tvb, 7, 3, ENC_LITTLE_ENDIAN);
        break;

    case PC_RDR_GET_PARAMS:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

        /* Placeholder for abRFU */
        proto_tree_add_item(ccid_tree, hf_ccid_Reserved, tvb, 7, 3, ENC_LITTLE_ENDIAN);
        break;

    case PC_RDR_XFR_BLOCK:
    case PC_RDR_ESCAPE:
        proto_tree_add_item_ret_uint(ccid_tree, hf_ccid_dwLength,
                tvb, 1, 4, ENC_LITTLE_ENDIAN, &payload_len);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);

        if (cmd == PC_RDR_ESCAPE) {
            proto_tree_add_item(ccid_tree, hf_ccid_abRFU, tvb, 7, 3, ENC_NA);
        } else {
            proto_tree_add_item(ccid_tree, hf_ccid_bBWI, tvb, 7, 1, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ccid_tree, hf_ccid_wLevelParameter, tvb, 8, 2, ENC_LITTLE_ENDIAN);
        }

        if (payload_len == 0)
            break;

        next_tvb = tvb_new_subset_length(tvb, 10, payload_len);
        /* sent/received is from the perspective of the card reader */
        pinfo->p2p_dir = P2P_DIR_SENT;

        if (!dissector_try_payload_new(subdissector_table, next_tvb, pinfo, tree, true, usb_conv_info)) {
            call_data_dissector(next_tvb, pinfo, tree);
        }
        break;

    case RDR_PC_DATA_BLOCK:
    case RDR_PC_ESCAPE:
        proto_tree_add_item_ret_uint(ccid_tree, hf_ccid_dwLength,
                tvb, 1, 4, ENC_LITTLE_ENDIAN, &payload_len);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask(ccid_tree, tvb, 7, hf_ccid_bStatus, ett_ccid_status, bStatus_fields, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bError, tvb, 8, 1, ENC_LITTLE_ENDIAN);
        if (cmd == RDR_PC_ESCAPE)
            proto_tree_add_item(ccid_tree, hf_ccid_bRFU, tvb, 9, 1, ENC_LITTLE_ENDIAN);
        else
            proto_tree_add_item(ccid_tree, hf_ccid_bChainParameter, tvb, 9, 1, ENC_LITTLE_ENDIAN);

        if (payload_len == 0)
            break;

        next_tvb = tvb_new_subset_length(tvb, 10, payload_len);
        pinfo->p2p_dir = P2P_DIR_RECV;

        if (!dissector_try_payload_new(subdissector_table, next_tvb, pinfo, tree, true, usb_conv_info)) {
            call_data_dissector(next_tvb, pinfo, tree);
        }
        break;

    case RDR_PC_SLOT_STATUS:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask(ccid_tree, tvb, 7, hf_ccid_bStatus, ett_ccid_status, bStatus_fields, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bError, tvb, 8, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bClockStatus, tvb, 9, 1, ENC_LITTLE_ENDIAN);
        break;

    case RDR_PC_PARAMS:
        proto_tree_add_item(ccid_tree, hf_ccid_dwLength, tvb, 1, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 5, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 6, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_bitmask(ccid_tree, tvb, 7, hf_ccid_bStatus, ett_ccid_status, bStatus_fields, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bError, tvb, 8, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bProtocolNum, tvb, 9, 1, ENC_LITTLE_ENDIAN);

        payload_len = tvb_get_letohl(tvb, 1);

        /* abProtocolDataStructure */
        bProtocolNum = tvb_get_uint8(tvb, 9);
        switch (bProtocolNum)
        {
            case 0: /* T=0 */
                protocol_tree = proto_tree_add_subtree(tree, tvb, 10, payload_len, ett_ccid_protocol_data_structure, NULL, "Protocol Data Structure for Protocol T=0");
                proto_tree_add_item(protocol_tree, hf_ccid_bmFindexDindex, tvb, 10, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bmTCCKST0, tvb, 11, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bGuardTimeT0, tvb, 12, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bWaitingIntegerT0, tvb, 13, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bClockStop, tvb, 14, 1, ENC_LITTLE_ENDIAN);
                break;

            case 1: /* T=1 */
                protocol_tree = proto_tree_add_subtree(tree, tvb, 10, payload_len, ett_ccid_protocol_data_structure, NULL, "Protocol Data Structure for Protocol T=1");
                proto_tree_add_item(protocol_tree, hf_ccid_bmFindexDindex, tvb, 10, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bmTCCKST1, tvb, 11, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bGuardTimeT1, tvb, 12, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bmWaitingIntegersT1, tvb, 13, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bClockStop, tvb, 14, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bIFSC, tvb, 15, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(protocol_tree, hf_ccid_bNadValue, tvb, 16, 1, ENC_LITTLE_ENDIAN);
                break;

            default:
                next_tvb = tvb_new_subset_remaining(tvb, 10);
                call_data_dissector(next_tvb, pinfo, tree);
        }
        break;

    /*Interrupt IN*/
    case RDR_PC_NOTIF_SLOT_CHNG:
        proto_tree_add_bitmask(ccid_tree, tvb, 1,
            hf_ccid_bmSlotICCState, ett_ccid_slot_change, bmSlotICCStateb0_fields,
            ENC_LITTLE_ENDIAN);
        len_remaining = tvb_reported_length_remaining (tvb, 2);
        if (len_remaining <= 0)
            break;
        proto_tree_add_bitmask(ccid_tree, tvb, 2,
            hf_ccid_bmSlotICCState, ett_ccid_slot_change, bmSlotICCStateb1_fields,
            ENC_LITTLE_ENDIAN);
        break;

    case RDR_PC_HWERROR:
        proto_tree_add_item(ccid_tree, hf_ccid_bSlot, tvb, 1, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bSeq, tvb, 2, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ccid_tree, hf_ccid_bHardwareErrorCode, tvb, 3, 1, ENC_LITTLE_ENDIAN);
        break;



    }

    /* TODO: Try use "offset" instead of hardcoded constants */
    return tvb_captured_length(tvb);
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
        {&hf_ccid_bStatus_bmIccStatus,
         { "Status", "usbccid.bStatus.bmIccStatus", FT_UINT8, BASE_DEC,
           VALS(ccid_status_icc_status_vals), 0x03, NULL, HFILL }},
        {&hf_ccid_bStatus_bmCommandStatus,
         { "Status", "usbccid.bStatus.bmCommandStatus", FT_UINT8, BASE_DEC,
           VALS(ccid_status_cmd_status_vals), 0xC0, NULL, HFILL }},
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
         { "Level Parameter", "usbccid.wLevelParameter", FT_UINT16, BASE_HEX,
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
        {&hf_ccid_bVoltageSupport18,
         { "1.8V", "usbccid.bVoltageSupport.18", FT_BOOLEAN, 8,
            TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL }},
        {&hf_ccid_bVoltageSupport30,
         { "3.0V", "usbccid.bVoltageSupport.30", FT_BOOLEAN, 8,
            TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }},
        {&hf_ccid_bVoltageSupport50,
         { "5.0V", "usbccid.bVoltageSupport.50", FT_BOOLEAN, 8,
            TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }},
        {&hf_ccid_dwProtocols,
         { "dwProtocols", "usbccid.dwProtocols", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwProtocols_t0,
         { "T=0", "usbccid.dwProtocols.t0", FT_BOOLEAN, 32,
            TFS(&tfs_supported_not_supported), 0x00000001, NULL, HFILL }},
        {&hf_ccid_dwProtocols_t1,
         { "T=1", "usbccid.dwProtocols.t1", FT_BOOLEAN, 32,
            TFS(&tfs_supported_not_supported), 0x00000002, NULL, HFILL }},
        {&hf_ccid_dwDefaultClock,
         { "default clock frequency", "usbccid.dwDefaultClock",
             FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_khz, 0x0, NULL, HFILL }},
        {&hf_ccid_dwMaximumClock,
         { "maximum clock frequency", "usbccid.dwMaximumClock",
             FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_khz, 0x0, NULL, HFILL }},
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
        { &hf_ccid_dwMaxIFSD,
         { "maximum IFSD supported", "usbccid.dwMaxIFSD",
             FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwSynchProtocols,
         { "supported protocol types", "usbccid.dwSynchProtocols",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwMechanical,
         { "mechanical characteristics", "usbccid.dwMechanical",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwFeatures,
         { "intelligent features", "usbccid.dwFeatures",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_dwFeatures_autoIccActivation,
         { "Automatic activation of ICC on inserting",
             "usbccid.dwFeatures.autoIccActivation", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00000004, NULL, HFILL }},
        {&hf_ccid_dwFeatures_autoIccVoltSelect,
         { "Automatic ICC voltage selection",
             "usbccid.dwFeatures.autoIccVoltSelect", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00000008, NULL, HFILL }},
        {&hf_ccid_dwFeatures_autoParam,
         { "Automatic parameter configuration based on ATR",
             "usbccid.dwFeatures.autoParam", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00000002, NULL, HFILL }},
        {&hf_ccid_dwFeatures_autoIccClk,
         { "Automatic ICC clock frequency change",
             "usbccid.dwFeatures.autoIccClk", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00000010, NULL, HFILL }},
        {&hf_ccid_dwFeatures_autoBaudRate,
         { "Automatic baud rate change",
             "usbccid.dwFeatures.autoBaudRate", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00000020, NULL, HFILL }},
        {&hf_ccid_dwFeatures_autoParamNegotiation,
         { "Automatic parameters negotiation",
             "usbccid.dwFeatures.autoParamNegotiation", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00000040, NULL, HFILL }},
        {&hf_ccid_dwFeatures_autoPPS,
         { "Automatic PPS",
             "usbccid.dwFeatures.autoPPS", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00000080, NULL, HFILL }},
        {&hf_ccid_dwFeatures_stopIccClk,
         { "CCID can set ICC in clock stop mode",
             "usbccid.dwFeatures.stopIccClk", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00000100, NULL, HFILL }},
        {&hf_ccid_dwFeatures_nadValNot0accept,
         { "NAD value other than 00 accepted",
             "usbccid.dwFeatures.nadValNot0accept", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00000200, NULL, HFILL }},
        {&hf_ccid_dwFeatures_autoIfsd,
         { "Automatic IFSD exchange as first exchange",
             "usbccid.dwFeatures.autoIfsd", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00000400, NULL, HFILL }},
        {&hf_ccid_dwFeatures_levelExchangeTDPU,
         { "TPDU level exchanges",
             "usbccid.dwFeatures.levelExchangeTDPU", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00010000, NULL, HFILL }},
        {&hf_ccid_dwFeatures_levelExchangeShortAPDU,
         { "Short APDU level exchange",
             "usbccid.dwFeatures.levelExchangeShortAPDU", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00020000, NULL, HFILL }},
        {&hf_ccid_dwFeatures_levelExchangeShortExtendedAPDU,
         { "Short and Extended APDU level exchange",
             "usbccid.dwFeatures.levelExchangeShortExtendedAPDU", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00040000, NULL, HFILL }},
        {&hf_ccid_dwFeatures_UsbWakeUp,
         { "USB Wake up signaling supported on card insertion and removal",
             "usbccid.dwFeatures.UsbWakeUp", FT_BOOLEAN, 32,
             TFS(&tfs_supported_not_supported), 0x00100000, NULL, HFILL }},
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
        {&hf_ccid_wLcdLayout_lines,
         { "Lines", "usbccid.hf_ccid_wLcdLayout.lines",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_wLcdLayout_chars,
         { "Characters per line", "usbccid.hf_ccid_wLcdLayout.chars",
             FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bPINSupport,
         { "PIN support", "usbccid.hf_ccid_bPINSupport",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bPINSupport_modify,
         { "PIN modification", "usbccid.hf_ccid_bPINSupport.modify",
             FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }},
        {&hf_ccid_bPINSupport_vrfy,
         { "PIN verification", "usbccid.hf_ccid_bPINSupport.verify",
             FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }},
        {&hf_ccid_bMaxCCIDBusySlots,
         { "maximum number of busy slots", "usbccid.hf_ccid_bMaxCCIDBusySlots",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_Reserved,
         { "Reserved for Future Use", "usbccid.hf_ccid_Reserved",
             FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_ccid_bmSlotICCState,
         { "Slot ICC State", "usbccid.hf_ccid_bmSlotICCState",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot0Current,
         { "Slot 0 Current Status", "usbccid.hf_ccid_bmSlotICCState.slot0Current",
             FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot0Changed,
         { "Slot 0 Status changed", "usbccid.hf_ccid_bmSlotICCState.slot0Changed",
             FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot1Current,
         { "Slot 1 Current Status", "usbccid.hf_ccid_bmSlotICCState.slot1Current",
             FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot1Changed,
         { "Slot 1 Status changed", "usbccid.hf_ccid_bmSlotICCState.slot1Changed",
             FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot2Current,
         { "Slot 2 Current Status", "usbccid.hf_ccid_bmSlotICCState.slot2Current",
             FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x10, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot2Changed,
         { "Slot 2 Status changed", "usbccid.hf_ccid_bmSlotICCState.slot2Changed",
             FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot3Current,
         { "Slot 3 Current Status", "usbccid.hf_ccid_bmSlotICCState.slot3Current",
             FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x40, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot3Changed,
         { "Slot 3 Status changed", "usbccid.hf_ccid_bmSlotICCState.slot3Changed",
             FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot4Current,
         { "Slot 4 Current Status", "usbccid.hf_ccid_bmSlotICCState.slot4Current",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot4Changed,
         { "Slot 4 Status changed", "usbccid.hf_ccid_bmSlotICCState.slot4Changed",
          FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot5Current,
         { "Slot 5 Current Status", "usbccid.hf_ccid_bmSlotICCState.slot5Current",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x04, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot5Changed,
         { "Slot 5 Status changed", "usbccid.hf_ccid_bmSlotICCState.slot5Changed",
          FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot6Current,
         { "Slot 6 Current Status", "usbccid.hf_ccid_bmSlotICCState.slot6Current",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x10, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot6Changed,
         { "Slot 6 Status changed", "usbccid.hf_ccid_bmSlotICCState.slot6Changed",
          FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot7Current,
         { "Slot 7 Current Status", "usbccid.hf_ccid_bmSlotICCState.slot7Current",
          FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x40, NULL, HFILL } },
        { &hf_ccid_bmSlotICCState_slot7Changed,
         { "Slot 7 Status changed", "usbccid.hf_ccid_bmSlotICCState.slot7Changed",
          FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80, NULL, HFILL } },
        { &hf_ccid_bHardwareErrorCode,
         { "Hardware Error Code", "usbccid.hf_ccid_bHardwareErrorCode",
             FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        {&hf_ccid_bmFindexDindex,
         { "Fi/Di selecting clock rate", "usbccid.bmFindexDindex", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bmTCCKST0,
         { "Convention used", "usbccid.bmTCCKST0", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bmTCCKST1,
         { "Checksum type - Convention used", "usbccid.bmTCCKST1", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bGuardTimeT0,
         { "Extra Guardtime between two characters", "usbccid.bGuardTimeT0", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bGuardTimeT1,
         { "Extra Guardtime", "usbccid.bGuardTimeT1", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bmWaitingIntegersT1,
         { "BWI - CWI", "usbccid.bmWaitingIntegersT1", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bClockStop,
         { "ICC Clock Stop Support", "usbccid.bClockStop", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bIFSC,
         { "Size of negotiated IFSC", "usbccid.bIFSC", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bNadValue,
         { "NAD", "usbccid.bNadValue", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
        {&hf_ccid_bWaitingIntegerT0,
         { "WI for T= 0 used to define WWT", "usbccid.bWaitingIntegerT0", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_ccid,
        &ett_ccid_desc,
        &ett_ccid_protocol_data_structure,
        &ett_ccid_voltage_level,
        &ett_ccid_protocols,
        &ett_ccid_features,
        &ett_ccid_lcd_layout,
        &ett_ccid_pin_support,
        &ett_ccid_slot_change,
        &ett_ccid_status
    };

    module_t *pref_mod;

    proto_ccid = proto_register_protocol("USB CCID", "USBCCID", "usbccid");
    proto_register_field_array(proto_ccid, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pref_mod = prefs_register_protocol_obsolete(proto_ccid);
    prefs_register_obsolete_preference(pref_mod, "prtype");

    usb_ccid_handle = register_dissector("usbccid", dissect_ccid, proto_ccid);
    usb_ccid_descr_handle = register_dissector("usbccid.descriptor", dissect_usb_ccid_descriptor, proto_ccid);

    subdissector_table = register_decode_as_next_proto(proto_ccid, "usbccid.subdissector", "USB CCID payload", NULL);
}

/* Handler registration */
void
proto_reg_handoff_ccid(void)
{
    dissector_add_uint("usb.descriptor", IF_CLASS_SMART_CARD, usb_ccid_descr_handle);

    dissector_add_uint("usb.bulk", IF_CLASS_SMART_CARD, usb_ccid_handle);

    dissector_add_for_decode_as("usb.device", usb_ccid_handle);
    dissector_add_for_decode_as("usb.product", usb_ccid_handle);
    dissector_add_for_decode_as("usb.protocol", usb_ccid_handle);
}

/*
* Editor modelines - https://www.wireshark.org/tools/modelines.html
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
