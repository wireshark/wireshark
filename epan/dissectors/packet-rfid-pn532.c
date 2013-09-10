/* packet-rfid-pn532.c
 * Dissector for the NXP PN532 Protocol
 *
 * References:
 * http://www.nxp.com/documents/user_manual/141520.pdf
 *
 * Copyright 2012, Tyson Key <tyson.key@gmail.com>
 * Copyright 2013, Michal Labedzki for Tieto Corporation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>

static int proto_pn532 = -1;

/* Device-specific HFs */
static int hf_pn532_command = -1;
static int hf_pn532_direction = -1;
static int hf_pn532_MaxTg = -1;
static int hf_pn532_Tg = -1;
static int hf_pn532_NbTg = -1;
static int hf_pn532_BrTy = -1;
static int hf_pn532_status_nad_present = -1;
static int hf_pn532_status_mi = -1;
static int hf_pn532_status_error_code = -1;
static int hf_pn532_payload_length = -1;
static int hf_pn532_ic_version = -1;
static int hf_pn532_fw_version = -1;
static int hf_pn532_fw_revision = -1;
static int hf_pn532_fw_support = -1;
static int hf_pn532_fw_support_rfu = -1;
static int hf_pn532_fw_support_iso_018092 = -1;
static int hf_pn532_fw_support_iso_iec_14443_type_b = -1;
static int hf_pn532_fw_support_iso_iec_14443_type_a = -1;

/* Card type-specific HFs */
static int hf_pn532_14443a_sak = -1;
static int hf_pn532_14443a_atqa = -1;
static int hf_pn532_14443a_uid = -1;
static int hf_pn532_14443a_ats_length = -1;
static int hf_pn532_14443a_uid_length = -1;
static int hf_pn532_14443a_ats = -1;
static int hf_pn532_14443b_pupi = -1;
static int hf_pn532_14443b_app_data = -1;
static int hf_pn532_14443b_proto_info = -1;
static int hf_pn532_sam_mode = -1;
static int hf_pn532_config = -1;
static int hf_pn532_config_not_used = -1;
static int hf_pn532_config_auto_rfca = -1;
static int hf_pn532_config_rf = -1;
static int hf_pn532_config_rfu = -1;
static int hf_pn532_config_atr_res_timeout = -1;
static int hf_pn532_config_timeout_non_dep = -1;
static int hf_pn532_config_max_rty_com = -1;
static int hf_pn532_config_max_rty_atr = -1;
static int hf_pn532_config_max_rty_psl = -1;
static int hf_pn532_config_max_rty_passive_activation = -1;
static int hf_pn532_afi = -1;
static int hf_pn532_polling_method = -1;
static int hf_pn532_config_ciu_rf_cfg = -1;
static int hf_pn532_config_ciu_cw_gs_p = -1;
static int hf_pn532_config_ciu_mod_gs_p = -1;
static int hf_pn532_config_ciu_rx_threshold = -1;
static int hf_pn532_config_ciu_demon_rf_on = -1;
static int hf_pn532_config_ciu_demon_rf_off = -1;
static int hf_pn532_config_ciu_gs_n_on = -1;
static int hf_pn532_config_ciu_gs_n_off = -1;
static int hf_pn532_config_ciu_mod_width = -1;
static int hf_pn532_config_ciu_mif_nfc = -1;
static int hf_pn532_config_ciu_tx_bit_phase = -1;
static int hf_pn532_config_212_kbps = -1;
static int hf_pn532_config_424_kbps = -1;
static int hf_pn532_config_848_kbps = -1;
static int hf_pn532_state = -1;
static int hf_pn532_brit_nu_7 = -1;
static int hf_pn532_brit_speed_target = -1;
static int hf_pn532_brit_nu_3 = -1;
static int hf_pn532_brit_speed_initiator = -1;
static int hf_pn532_tg_response = -1;
static int hf_pn532_initiator_command = -1;
static int hf_pn532_data_in = -1;
static int hf_pn532_data_out = -1;
static int hf_pn532_gt = -1;
static int hf_pn532_mode_nu_7 = -1;
static int hf_pn532_mode_nu_3_7 = -1;
static int hf_pn532_mode_picc_only = -1;
static int hf_pn532_mode_dep_only = -1;
static int hf_pn532_mode_passive_only = -1;
static int hf_pn532_mode_mifare_parameters = -1;
static int hf_pn532_mode_mifare_parameters_sens_res = -1;
static int hf_pn532_mode_mifare_parameters_nfc_id_1t = -1;
static int hf_pn532_mode_mifare_parameters_sel_res = -1;
static int hf_pn532_mode_felica_parameters = -1;
static int hf_pn532_mode_felica_parameters_nfc_id_2t = -1;
static int hf_pn532_mode_felica_parameters_pad = -1;
static int hf_pn532_mode_felica_parameters_system_code = -1;
static int hf_pn532_mode_nfc_id_3t = -1;
static int hf_pn532_mode_gt_length = -1;
static int hf_pn532_mode_gt = -1;
static int hf_pn532_mode_tk_length = -1;
static int hf_pn532_mode_tk = -1;
static int hf_pn532_mode_baudrate = -1;
static int hf_pn532_mode_iso_iec_14443_4_picc = -1;
static int hf_pn532_mode_dep = -1;
static int hf_pn532_mode_framing_type = -1;
static int hf_pn532_brit = -1;
static int hf_pn532_brti = -1;
static int hf_pn532_txmode_nu_7 = -1;
static int hf_pn532_txmode_tx_speed = -1;
static int hf_pn532_txmode_nu_2_3 = -1;
static int hf_pn532_txmode_tx_framing = -1;

static expert_field ei_unknown_data = EI_INIT;
static expert_field ei_unexpected_data = EI_INIT;

void proto_register_pn532(void);
void proto_reg_handoff_pn532(void);

#define DIAGNOSE_REQ               0x00
#define DIAGNOSE_RSP               0x01
#define GET_FIRMWARE_VERSION_REQ   0x02
#define GET_FIRMWARE_VERSION_RSP   0x03
#define GET_GENERAL_STATUS_REQ     0x04
#define GET_GENERAL_STATUS_RSP     0x05
#define READ_REGISTER_REQ          0x06
#define READ_REGISTER_RSP          0x07
#define WRITE_REGISTER_REQ         0x08
#define WRITE_REGISTER_RSP         0x09
#define READ_GPIO_REQ              0x0C
#define READ_GPIO_RSP              0x0D
#define WRITE_GPIO_REQ             0x0E
#define WRITE_GPIO_RSP             0x0F
#define SET_SERIAL_BAUD_RATE_REQ   0x10
#define SET_SERIAL_BAUD_RATE_RSP   0x11
#define SET_PARAMETERS_REQ         0x12
#define SET_PARAMETERS_RSP         0x13
#define SAM_CONFIGURATION_REQ      0x14
#define SAM_CONFIGURATION_RSP      0x15
#define POWER_DOWN_REQ             0x16
#define POWER_DOWN_RSP             0x17
#define RF_CONFIGURATION_REQ       0x32
#define RF_CONFIGURATION_RSP       0x33
#define IN_DATA_EXCHANGE_REQ       0x40
#define IN_DATA_EXCHANGE_RSP       0x41
#define IN_COMMUNICATE_THRU_REQ    0x42
#define IN_COMMUNICATE_THRU_RSP    0x43
#define IN_DESELECT_REQ            0x44
#define IN_DESELECT_RSP            0x45
#define IN_JUMP_FOR_PSL_REQ        0x46
#define IN_JUMP_FOR_PSL_RSP        0x47
#define IN_LIST_PASSIVE_TARGET_REQ 0x4A
#define IN_LIST_PASSIVE_TARGET_RSP 0x4B
#define IN_PSL_REQ                 0x4E
#define IN_PSL_RSP                 0x4F
#define IN_ATR_REQ                 0x50
#define IN_ATR_RSP                 0x51
#define IN_RELEASE_REQ             0x52
#define IN_RELEASE_RSP             0x53
#define IN_SELECT_REQ              0x54
#define IN_SELECT_RSP              0x55
#define IN_JUMP_FOR_DEP_REQ        0x56
#define IN_JUMP_FOR_DEP_RSP        0x57
#define RF_REGULATION_TEST_REQ     0x58
#define RF_REGULATION_TEST_RSP     0x59
#define IN_AUTO_POLL_REQ           0x60
#define IN_AUTO_POLL_RSP           0x61
#define TG_GET_DATA_REQ            0x86
#define TG_GET_DATA_RSP            0x87
#define TG_GET_INITIATOR_CMD_REQ   0x88
#define TG_GET_INITIATOR_CMD_RSP   0x89
#define TG_GET_TARGET_STATUS_REQ   0x8A
#define TG_GET_TARGET_STATUS_RSP   0x8B
#define TG_INIT_AS_TARGET_REQ      0x8C
#define TG_INIT_AS_TARGET_RSP      0x8D
#define TG_SET_DATA_REQ            0x8E
#define TG_SET_DATA_RSP            0x8F
#define TG_RESP_TO_INITIATOR_REQ   0x90
#define TG_RESP_TO_INITIATOR_RSP   0x91
#define TG_SET_GENERAL_BYTES_REQ   0x92
#define TG_SET_GENERAL_BYTES_RSP   0x93
#define TG_SET_METADATA_REQ        0x94
#define TG_SET_METADATA_RSP        0x95

/* Baud rate and modulation types */
#define ISO_IEC_14443A_106         0x00
#define FELICA_212                 0x01
#define FELICA_424                 0x02
#define ISO_IEC_14443B_106         0x03
#define JEWEL_14443A_106           0x04


/* Table of payload types - adapted from the I2C dissector */
enum {
    SUB_DATA = 0,
    SUB_FELICA,
    SUB_MIFARE,
    SUB_ISO7816,
    SUB_MAX
};

static dissector_handle_t sub_handles[SUB_MAX];
static gint sub_selected = SUB_DATA;

static dissector_table_t pn532_dissector_table;

/* Subtree handles: set by register_subtree_array */
static gint ett_pn532 = -1;
static gint ett_pn532_fw_support = -1;
static gint ett_pn532_config_212_kbps = -1;
static gint ett_pn532_config_424_kbps = -1;
static gint ett_pn532_config_848_kbps = -1;
static gint ett_pn532_mifare_parameters = -1;
static gint ett_pn532_felica_parameters = -1;

/* Re-arranged from defs above to be in ascending order by value */
static const value_string pn532_commands[] = {
    {DIAGNOSE_REQ,               "Diagnose"},
    {DIAGNOSE_RSP,               "Diagnose (Response)"},
    {GET_FIRMWARE_VERSION_REQ,   "GetFirmwareVersion"},
    {GET_FIRMWARE_VERSION_RSP,   "GetFirmwareVersion (Response)"},
    {GET_GENERAL_STATUS_REQ,     "GetGeneralStatus"},
    {GET_GENERAL_STATUS_RSP,     "GetGeneralStatus (Response)"},
    {READ_REGISTER_REQ,          "ReadRegister"},
    {READ_REGISTER_RSP,          "ReadRegister (Response)"},
    {WRITE_REGISTER_REQ,         "WriteRegister"},
    {WRITE_REGISTER_RSP,         "WriteRegister (Response)"},
    {READ_GPIO_REQ,              "ReadGPIO"},
    {READ_GPIO_RSP,              "ReadGPIO (Response)"},
    {WRITE_GPIO_REQ,             "WriteGPIO"},
    {WRITE_GPIO_RSP,             "WriteGPIO (Response)"},
    {SET_SERIAL_BAUD_RATE_REQ,   "SetSerialBaudRate"},
    {SET_SERIAL_BAUD_RATE_RSP,   "SetSerialBaudRate (Response)"},
    {SET_PARAMETERS_REQ,         "SetParameters"},
    {SET_PARAMETERS_RSP,         "SetParameters (Response)"},
    {SAM_CONFIGURATION_REQ,      "SAMConfiguration"},
    {SAM_CONFIGURATION_RSP,      "SAMConfiguration (Response)"},
    {POWER_DOWN_REQ,             "PowerDown"},
    {POWER_DOWN_RSP,             "PowerDown (Response)"},
    {RF_CONFIGURATION_REQ,       "RFConfiguration"},
    {RF_CONFIGURATION_RSP,       "RFConfiguration (Response)"},
    {IN_DATA_EXCHANGE_REQ,       "InDataExchange"},
    {IN_DATA_EXCHANGE_RSP,       "InDataExchange (Response)"},
    {IN_COMMUNICATE_THRU_REQ,    "InCommunicateThru"},
    {IN_COMMUNICATE_THRU_RSP,    "InCommunicateThru (Response)"},
    {IN_DESELECT_REQ,            "InDeselect"},
    {IN_DESELECT_RSP,            "InDeselect (Response)"},
    {IN_JUMP_FOR_PSL_REQ,        "InJumpForPSL"},
    {IN_JUMP_FOR_PSL_RSP,        "InJumpForPSL (Response)"},
    {IN_LIST_PASSIVE_TARGET_REQ, "InListPassiveTarget"},
    {IN_LIST_PASSIVE_TARGET_RSP, "InListPassiveTarget (Response)"},
    {IN_PSL_REQ,                 "InPSL"},
    {IN_PSL_RSP,                 "InPSL (Response)"},
    {IN_ATR_REQ,                 "InATR"},
    {IN_ATR_RSP,                 "InATR (Response)"},
    {IN_RELEASE_REQ,             "InRelease"},
    {IN_RELEASE_RSP,             "InRelease (Response)"},
    {IN_SELECT_REQ,              "InSelect"},
    {IN_SELECT_RSP,              "InSelect (Response)"},
    {IN_JUMP_FOR_DEP_REQ,        "InJumpForDEP"},
    {IN_JUMP_FOR_DEP_RSP,        "InJumpForDEP (Response)"},
    {RF_REGULATION_TEST_REQ,     "RFRegulationTest"},
    {RF_REGULATION_TEST_RSP,     "RFRegulationTest (Response)"},
    {IN_AUTO_POLL_REQ,           "InAutoPoll"},
    {IN_AUTO_POLL_RSP,           "InAutoPoll (Response)"},
    {TG_GET_DATA_REQ,            "TgGetData"},
    {TG_GET_DATA_RSP,            "TgGetData (Response)"},
    {TG_GET_INITIATOR_CMD_REQ,   "TgGetInitiatorCommand"},
    {TG_GET_INITIATOR_CMD_RSP,   "TgGetInitiatorCommand (Response)"},
    {TG_GET_TARGET_STATUS_REQ,   "TgGetTargetStatus"},
    {TG_GET_TARGET_STATUS_RSP,   "TgGetTargetStatus (Response)"},
    {TG_INIT_AS_TARGET_REQ,      "TgInitAsTarget"},
    {TG_INIT_AS_TARGET_RSP,      "TgInitAsTarget (Response)"},
    {TG_SET_DATA_REQ,            "TgSetData"},
    {TG_SET_DATA_RSP,            "TgSetData (Response)"},
    {TG_RESP_TO_INITIATOR_REQ,   "TgResponseToInitiator"},
    {TG_RESP_TO_INITIATOR_RSP,   "TgResponseToInitiator (Response)"},
    {TG_SET_GENERAL_BYTES_REQ,   "TgSetGeneralBytes"},
    {TG_SET_GENERAL_BYTES_RSP,   "TgSetGeneralBytes (Response)"},
    {TG_SET_METADATA_REQ,        "TgSetMetaData"},
    {TG_SET_METADATA_RSP,        "TgSetMetaData (Response)"},
    {0x00, NULL}
};
static value_string_ext pn532_commands_ext = VALUE_STRING_EXT_INIT(pn532_commands);

/* TFI - 1 byte frame identifier; specifying direction of communication */
static const value_string pn532_directions[] = {
    {0xD4,  "Host to PN532"},
    {0xD5,  "PN532 to Host"},
    {0x00, NULL}
};

static const value_string pn532_errors[] = {
    {0x00,  "No Error"},
    {0x01,  "Time Out"},
    {0x02,  "CRC Error detected by the CIU"},
    {0x03,  "Parity Error detected by the CIU"},
    {0x04,  "Erroneous Bit Count has been detected"},
    {0x05,  "Framing error during Mifare operation"},
    {0x06,  "Abnormal Bit-Collision"},
    {0x07,  "Communication Buffer Size Insufficient"},
    {0x09,  "RF Buffer overflow has been detected by the CIU"},
    {0x0A,  "In active communication mode, the RF field has not been switched on in time by the counterpart"},
    {0x0B,  "RF Protocol Error"},
    {0x0D,  "Temperature Error"},
    {0x0E,  "Internal Buffer Overflow"},
    {0x10,  "Invalid Parameter"},
    {0x12,  "The PN532 configured in target mode does not support the command received from the initiator"},
    {0x13,  "Invalid Data Format"},
    {0x14,  "Authentication Error"},
    {0x23,  "UID Check Byte is Wrong"},
    {0x25,  "Invalid Device State"},
    {0x26,  "Operation not allowed in this configuration"},
    {0x27,  "Unacceptable Command"},
    {0x29,  "The PN532 configured as target has been released by its initiator"},
    {0x2A,  "ID of the card does not match"},
    {0x2B,  "Card previously activated has disappeared"},
    {0x2C,  "Mismatch between the NFCID3 initiator and the NFCID3 target in DEP 212/424 kbps passive"},
    {0x2D,  "Over-current event has been detected"},
    {0x2E,  "NAD missing in DEP frame"},
    {0x00, NULL}
};

static const value_string pn532_config_vals[] = {
    {0x01,  "RF Field"},
    {0x02,  "Various Timings"},
    {0x04,  "Max Rty COM"},
    {0x05,  "Max Retries"},
    {0x0A,  "Analog settings for the baudrate 106 kbps type A"},
    {0x0B,  "Analog settings for the baudrate 212/424 kbps"},
    {0x0C,  "Analog settings for the type B"},
    {0x0D,  "Analog settings for baudrates 212/424 and 848 kbps with ISO/IEC14443-4 protocol"},
    {0x00, NULL}
};

static const value_string pn532_config_timeout_vals[] = {
    {0x00,  "No Timeout"},
    {0x01,  "100 us"},
    {0x02,  "200 us"},
    {0x03,  "400 us"},
    {0x04,  "800 us"},
    {0x05,  "1.6 ms"},
    {0x06,  "3.2 ms"},
    {0x07,  "6.4 ms"},
    {0x08,  "12.8 ms"},
    {0x09,  "25.6 ms"},
    {0x0A,  "51.2 ms"},
    {0x0B,  "102.4 ms"},
    {0x0C,  "204.8 ms"},
    {0x0D,  "409.6 ms"},
    {0x0E,  "819.2 ms"},
    {0x0F,  "1.64 sec"},
    {0x10,  "3.28 sec"},
    {0x00, NULL}
};

static const value_string pn532_polling_method_vals[] = {
    {0x00,  "Timeslot Approach"},
    {0x01,  "Probabilistic Approach"},
    {0x00, NULL}
};

/* Baud rates and modulation types */
static const value_string pn532_brtypes[] = {
    {ISO_IEC_14443A_106,        "ISO/IEC 14443-A at 106 kbps"},
    {FELICA_212,                "FeliCa at 212 kbps"},
    {FELICA_424,                "FeliCa at 424 kbps"},
    {ISO_IEC_14443B_106,        "ISO/IEC 14443-B at 106 kbps"},
    {JEWEL_14443A_106,          "InnoVision Jewel/Topaz at 106 kbps"},
    {0x00, NULL}
};

/* SAM Modes */
static const value_string pn532_sam_modes[] = {
    {0x01,  "Normal Mode"},
    {0x02,  "Virtual Card Mode"},
    {0x03,  "Wired Card Mode"},
    {0x03,  "Dual Card Mode"},
    {0x00, NULL}
};

static const value_string pn532_state_vals[] = {
    {0x00,  "TG Idle / TG Released"},
    {0x01,  "TG Activated"},
    {0x02,  "TG Deselected"},
    {0x80,  "PICC Released"},
    {0x81,  "PICC Activated"},
    {0x82,  "PICC Deselected"},
    {0x00, NULL}
};

static const value_string pn532_speed_vals[] = {
    {0x00,  "106 kbps"},
    {0x01,  "212 kbps"},
    {0x02,  "424 kbps"},
    {0x00, NULL}
};

static const value_string pn532_framing_type_vals[] = {
    {0x00,  "Mifare"},
    {0x01,  "Active Mode"},
    {0x02,  "FeliCa"},
    {0x00, NULL}
};

static const value_string pn532_txspeed_vals[] = {
    {0x00,  "106 kbps"},
    {0x01,  "212 kbps"},
    {0x02,  "424 kbps"},
    {0x03,  "848 kbps"},
    {0x00, NULL}
};

static const value_string pn532_txframing_vals[] = {
    {0x00,  "Mifare"},
    {0x02,  "FeliCa"},
    {0x00, NULL}
};

static gint
dissect_status(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    proto_tree_add_item(tree, hf_pn532_status_nad_present, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pn532_status_mi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_pn532_status_error_code, tvb, offset, 1, ENC_BIG_ENDIAN);

    return offset + 1;
}

static void
dissect_pn532(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item;
    proto_tree *pn532_tree;
    proto_item *sub_item;
    proto_tree *sub_tree;
    guint8      cmd;
    guint8      config;
    guint8      baudrate;
    guint8      length;
    tvbuff_t   *next_tvb;
    gint        offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PN532");

    item = proto_tree_add_item(tree, proto_pn532, tvb, 0, -1, ENC_NA);
    pn532_tree = proto_item_add_subtree(item, ett_pn532);

    proto_tree_add_item(pn532_tree, hf_pn532_direction, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item(pn532_tree, hf_pn532_command, tvb, offset, 1, ENC_NA);
    cmd = tvb_get_guint8(tvb, offset);
    offset += 1;

    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(cmd, &pn532_commands_ext, "Unknown command"));

    switch (cmd) {

    case DIAGNOSE_REQ:
/* TODO */
        break;

    case DIAGNOSE_RSP:
/* TODO */
        break;

    case GET_FIRMWARE_VERSION_REQ:
        /* No parameters */
        break;

    case GET_FIRMWARE_VERSION_RSP:
        proto_tree_add_item(pn532_tree, hf_pn532_ic_version,  tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(pn532_tree, hf_pn532_fw_version,  tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(pn532_tree, hf_pn532_fw_revision, tvb, offset, 1, ENC_NA);
        offset += 1;

        sub_item = proto_tree_add_item(pn532_tree, hf_pn532_fw_support,  tvb, offset, 1, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn532_fw_support);
        proto_tree_add_item(sub_tree, hf_pn532_fw_support_rfu, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sub_tree, hf_pn532_fw_support_iso_018092, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sub_tree, hf_pn532_fw_support_iso_iec_14443_type_b, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(sub_tree, hf_pn532_fw_support_iso_iec_14443_type_a, tvb, offset, 1, ENC_NA);
        offset += 1;
        break;

    case GET_GENERAL_STATUS_REQ:
        /* No parameters */
        break;

    case GET_GENERAL_STATUS_RSP:
/* TODO */
        break;

    case READ_REGISTER_REQ:
/* TODO */
        break;

    case READ_REGISTER_RSP:
/* TODO */
        break;

    case WRITE_REGISTER_REQ:
        /* No parameters */
        break;

    case WRITE_REGISTER_RSP:
/* TODO */
        break;

    case READ_GPIO_REQ:
        /* No parameters */
        break;

    case READ_GPIO_RSP:
/* TODO */
        break;

    case WRITE_GPIO_REQ:
/* TODO */
        break;

    case WRITE_GPIO_RSP:
        /* No parameters */
        break;

    case SET_SERIAL_BAUD_RATE_REQ:
/* TODO */
        break;

    case SET_SERIAL_BAUD_RATE_RSP:
        /* No parameters */
        break;

    case SET_PARAMETERS_REQ:
/* TODO */
        break;

    case SET_PARAMETERS_RSP:
        /* No parameters */
        break;

    case SAM_CONFIGURATION_REQ: /* Secure Application/Security Access Module Configuration Request */
        proto_tree_add_item(pn532_tree, hf_pn532_sam_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

/* TODO Timeout */
/* TODO IRQ */
        break;

    case SAM_CONFIGURATION_RSP:
        /* No parameters */
        break;

    case POWER_DOWN_REQ:
/* TODO */
        break;

    case POWER_DOWN_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);
        break;

    case RF_CONFIGURATION_REQ:
        proto_tree_add_item(pn532_tree, hf_pn532_config, tvb, offset, 1, ENC_BIG_ENDIAN);
        config = tvb_get_guint8(tvb, offset);
        offset += 1;

        switch(config) {
        case 0x01:
            proto_tree_add_item(pn532_tree, hf_pn532_config_not_used, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pn532_tree, hf_pn532_config_auto_rfca, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pn532_tree, hf_pn532_config_rf, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case 0x02:
            proto_tree_add_item(pn532_tree, hf_pn532_config_rfu, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_atr_res_timeout, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_timeout_non_dep, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case 0x04:
            proto_tree_add_item(pn532_tree, hf_pn532_config_max_rty_com, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case 0x05:
            proto_tree_add_item(pn532_tree, hf_pn532_config_max_rty_atr, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_max_rty_psl, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_max_rty_passive_activation, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case 0x0A:
        case 0x0B:
            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_rf_cfg, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_gs_n_on, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_cw_gs_p, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_mod_gs_p, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_demon_rf_on, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_rx_threshold, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_demon_rf_off, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_gs_n_off, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            if (config == 0x0A) {
                proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_mod_width, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_mif_nfc, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;

                proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_tx_bit_phase, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
        case 0x0C:
            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_gs_n_on, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_mod_gs_p, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(pn532_tree, hf_pn532_config_ciu_rx_threshold, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case 0x0D:
            sub_item = proto_tree_add_item(pn532_tree, hf_pn532_config_212_kbps,  tvb, offset, 3, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_pn532_config_212_kbps);

            proto_tree_add_item(sub_tree, hf_pn532_config_ciu_rx_threshold, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_pn532_config_ciu_mod_width, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_pn532_config_ciu_mif_nfc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            sub_item = proto_tree_add_item(pn532_tree, hf_pn532_config_424_kbps,  tvb, offset, 3, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_pn532_config_424_kbps);

            proto_tree_add_item(sub_tree, hf_pn532_config_ciu_rx_threshold, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_pn532_config_ciu_mod_width, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_pn532_config_ciu_mif_nfc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            sub_item = proto_tree_add_item(pn532_tree, hf_pn532_config_848_kbps,  tvb, offset, 3, ENC_NA);
            sub_tree = proto_item_add_subtree(sub_item, ett_pn532_config_848_kbps);

            proto_tree_add_item(sub_tree, hf_pn532_config_ciu_rx_threshold, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_pn532_config_ciu_mod_width, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            proto_tree_add_item(sub_tree, hf_pn532_config_ciu_mif_nfc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        default:
            proto_tree_add_expert(pn532_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_length_remaining(tvb, offset));
            offset += tvb_length_remaining(tvb, offset);
        }
        break;

    case RF_CONFIGURATION_RSP:
        /* No parameters */
        break;

    case RF_REGULATION_TEST_REQ:
        proto_tree_add_item(pn532_tree, hf_pn532_txmode_nu_7, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_txmode_tx_speed, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_txmode_nu_2_3, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_txmode_tx_framing, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    case RF_REGULATION_TEST_RSP:
        /* This should never happend */
        break;

    case IN_JUMP_FOR_DEP_REQ:
/* TODO */
        break;

    case IN_JUMP_FOR_DEP_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);

/* TODO */
        break;

    case IN_JUMP_FOR_PSL_REQ:
/* TODO */
        break;

    case IN_JUMP_FOR_PSL_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);

/* TODO */
        break;

    case IN_LIST_PASSIVE_TARGET_REQ:

        proto_tree_add_item(pn532_tree, hf_pn532_MaxTg, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(pn532_tree, hf_pn532_BrTy, tvb, offset, 1, ENC_BIG_ENDIAN);
        baudrate = tvb_get_guint8(tvb, offset);
        offset += 1;

        switch(baudrate) {
        case ISO_IEC_14443A_106:
            while (tvb_length_remaining(tvb, offset) >= 4) {
                proto_tree_add_item(pn532_tree, hf_pn532_14443a_uid, tvb, 6, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
            break;
        case FELICA_212:
        case FELICA_424:
            next_tvb = tvb_new_subset(tvb, offset, 5, 5);
            call_dissector(sub_handles[SUB_FELICA], next_tvb, pinfo, tree);
            offset += 5;
            break;

        case ISO_IEC_14443B_106:
            proto_tree_add_item(pn532_tree, hf_pn532_afi, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;

            if (tvb_length_remaining(tvb, offset) >= 1) {
                proto_tree_add_item(pn532_tree, hf_pn532_polling_method, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
        case JEWEL_14443A_106:
            /* No parameter */
            break;
        }
        break;

    case IN_LIST_PASSIVE_TARGET_RSP:
        proto_tree_add_item(pn532_tree, hf_pn532_NbTg, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

/* TODO for + storing infos in tree */

        /* Probably an ISO/IEC 14443-B tag */
        if (tvb_reported_length(tvb) == 18) {

            /* Add the PUPI */
            proto_tree_add_item(pn532_tree, hf_pn532_14443b_pupi, tvb, 5, 4, ENC_BIG_ENDIAN);

            /* Add the Application Data */
            proto_tree_add_item(pn532_tree, hf_pn532_14443b_app_data, tvb, 9, 4, ENC_BIG_ENDIAN);

            /* Add the Protocol Info */
            proto_tree_add_item(pn532_tree, hf_pn532_14443b_proto_info, tvb, 13, 3, ENC_BIG_ENDIAN);
        }

        /* InnoVision Jewel/Topaz (ISO 14443-A/proprietary) */
        if (tvb_reported_length(tvb) == 10) {

            /* Add the ATQA/SENS_RES (0x0C00)*/
            proto_tree_add_item(pn532_tree, hf_pn532_14443a_atqa, tvb, 4, 2, ENC_BIG_ENDIAN);

            /* Add the UID (4 bytes) */
            proto_tree_add_item(pn532_tree, hf_pn532_14443a_uid, tvb, 6, 4, ENC_BIG_ENDIAN);
        }

        /* Probably one of:
         * a MiFare DESFire card (21 bytes),
         * an MF UltraLight tag (15 bytes)
         * an MF Classic card with a 4 byte UID (12 bytes) */

        if ((tvb_reported_length(tvb) == 21) || (tvb_reported_length(tvb) == 15) || (tvb_reported_length(tvb) == 12)) {

            /* Add the ATQA/SENS_RES */
            proto_tree_add_item(pn532_tree, hf_pn532_14443a_atqa, tvb, 4, 2, ENC_BIG_ENDIAN);

            /* Add the SAK/SEL_RES value */
            proto_tree_add_item(pn532_tree, hf_pn532_14443a_sak, tvb, 6, 1, ENC_BIG_ENDIAN);

            /* Add the UID length */
            proto_tree_add_item(pn532_tree, hf_pn532_14443a_uid_length, tvb, 7, 1, ENC_BIG_ENDIAN);

            /* Add the UID */
            if (tvb_reported_length(tvb) != 12) {
                proto_tree_add_item(pn532_tree, hf_pn532_14443a_uid, tvb, 8, 7, ENC_BIG_ENDIAN);

                /* Probably MiFare DESFire, or some other 14443-A card with an ATS value/7 byte UID */
                if (tvb_reported_length(tvb) == 21) {

                    /* Add the ATS value */
                    proto_tree_add_item(pn532_tree, hf_pn532_14443a_ats, tvb, 16, 5, ENC_BIG_ENDIAN);
                }
            }
            /* Probably MiFare Classic with a 4 byte UID */
            else {
                proto_tree_add_item(pn532_tree, hf_pn532_14443a_uid, tvb, 8, 4, ENC_BIG_ENDIAN);
            }

        }

        /* Probably an EMV/ISO 14443-A (VISA - 28 bytes payload/MC - 31 bytes payload)
                 card with a 4 byte UID

           MTCOS-based contactless passports also have a 4 byte (randomised) UID (26 bytes payload)
        */

        if (tvb_reported_length(tvb) == 26 || tvb_reported_length(tvb) == 28 || tvb_reported_length(tvb) == 31) {

        /* Check to see if there's a plausible ATQA value (0x0004 for my MC/VISA cards, and 0x0008 for MTCOS) */

            if (tvb_get_ntohs(tvb, 4) == 0x0004 || tvb_get_ntohs(tvb, 4) == 0x08) {

                /* Add the ATQA/SENS_RES */
                proto_tree_add_item(pn532_tree, hf_pn532_14443a_atqa, tvb, 4, 2, ENC_BIG_ENDIAN);

                /* Add the SAK/SEL_RES value */
                proto_tree_add_item(pn532_tree, hf_pn532_14443a_sak, tvb, 6, 1, ENC_BIG_ENDIAN);

                /* Add the UID length */
                proto_tree_add_item(pn532_tree, hf_pn532_14443a_uid_length, tvb, 7, 1, ENC_BIG_ENDIAN);

                /* Add the UID */
                proto_tree_add_item(pn532_tree, hf_pn532_14443a_uid, tvb, 8, 4, ENC_BIG_ENDIAN);

                /* Dissect the ATS length for certainty... */
                proto_tree_add_item(pn532_tree, hf_pn532_14443a_ats_length, tvb, 12, 1, ENC_BIG_ENDIAN);

                /* Pass the ATS value to the Data dissector, since it's too long to handle normally
                    Don't care about the "status word" at the end, right now */
                next_tvb = tvb_new_subset_remaining(tvb, 13);
                call_dissector(sub_handles[SUB_DATA], next_tvb, pinfo, tree);
            }
        }

        /* See if we've got a FeliCa payload with a System Code */
        if (tvb_reported_length(tvb) == 24) {

            /* For FeliCa, this is at position 4. This doesn't exist for other payload types. */
            proto_tree_add_item(pn532_tree, hf_pn532_payload_length, tvb, 4, 1, ENC_BIG_ENDIAN);

            /* Use the length value (20?) at position 4, and skip the Status Word (9000) at the end */
            next_tvb = tvb_new_subset(tvb, 5, tvb_get_guint8(tvb, 4) - 1, 19);
            call_dissector(sub_handles[SUB_FELICA], next_tvb, pinfo, tree);
        }

        break;

    case IN_ATR_REQ:
        proto_tree_add_item(pn532_tree, hf_pn532_Tg, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

/* TODO */
        break;

    case IN_ATR_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);

/* TODO */
        break;

    case IN_PSL_REQ:
        proto_tree_add_item(pn532_tree, hf_pn532_Tg, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(pn532_tree, hf_pn532_brit, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(pn532_tree, hf_pn532_brti, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    case IN_PSL_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);
        break;

    case IN_DATA_EXCHANGE_REQ:
        proto_tree_add_item(pn532_tree, hf_pn532_Tg, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (sub_selected == SUB_MIFARE) {
            /* Seems to work for payloads from LibNFC's "nfc-mfultralight" command */
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(sub_handles[SUB_MIFARE], next_tvb, pinfo, tree);
            offset += tvb_length_remaining(tvb, offset);
        } else if (sub_selected == SUB_ISO7816) {
            /* Seems to work for EMV payloads sent using TAMA shell scripts */
            next_tvb = tvb_new_subset_remaining(tvb, offset);

            /* Need to do this, for the ISO7816 dissector to work, it seems */
            pinfo->p2p_dir = P2P_DIR_SENT;
            call_dissector(sub_handles[SUB_ISO7816], next_tvb, pinfo, tree);
            offset += tvb_length_remaining(tvb, offset);
        } else {
            proto_tree_add_item(pn532_tree, hf_pn532_data_out, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
            offset += tvb_length_remaining(tvb, offset);
        }

        break;

    case IN_DATA_EXCHANGE_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);

        if (sub_selected == SUB_ISO7816) {

            /* Seems to work for identifying responses to Select File requests...
               Might need to investigate "Status Words", later */

            next_tvb = tvb_new_subset_remaining(tvb, offset);

            /* Need to do this, for the ISO7816 dissector to work, it seems */
            pinfo->p2p_dir = P2P_DIR_RECV;
            call_dissector(sub_handles[SUB_ISO7816], next_tvb, pinfo, tree);
            offset += tvb_length_remaining(tvb, offset);
        } else {
            proto_tree_add_item(pn532_tree, hf_pn532_data_in, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
            offset += tvb_length_remaining(tvb, offset);
        }

        break;

    case IN_COMMUNICATE_THRU_REQ:
        if (sub_selected == SUB_FELICA) {

            /* Alleged payload length for FeliCa */
            proto_tree_add_item(pn532_tree, hf_pn532_payload_length, tvb, 2, 1, ENC_BIG_ENDIAN);

            /* Attempt to dissect FeliCa payloads */
            next_tvb = tvb_new_subset_remaining(tvb, 3);
            call_dissector(sub_handles[SUB_FELICA], next_tvb, pinfo, tree);
        } else {
            /* NOTE: MiFare transmissions may identify as spurious FeliCa packets, in some cases */

            proto_tree_add_item(pn532_tree, hf_pn532_data_out, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
            offset += tvb_length_remaining(tvb, offset);
        }
        break;

    case IN_COMMUNICATE_THRU_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);

        if (sub_selected == SUB_FELICA) {

            /* Alleged payload length for FeliCa */
            proto_tree_add_item(pn532_tree, hf_pn532_payload_length, tvb, 3, 1, ENC_BIG_ENDIAN);

            /* Attempt to dissect FeliCa payloads */
            next_tvb = tvb_new_subset_remaining(tvb, 4);
            call_dissector(sub_handles[SUB_FELICA], next_tvb, pinfo, tree);
        } else {
            /* NOTE: MiFare transmissions may identify as spurious FeliCa packets, in some cases */

            proto_tree_add_item(pn532_tree, hf_pn532_data_in, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
            offset += tvb_length_remaining(tvb, offset);
        }
        break;

    case IN_DESELECT_REQ:
    case IN_RELEASE_REQ:
    case IN_SELECT_REQ:
        proto_tree_add_item(pn532_tree, hf_pn532_Tg, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    case IN_DESELECT_RSP:
    case IN_RELEASE_RSP:
    case IN_SELECT_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);
        break;

    case IN_AUTO_POLL_REQ:
/* TODO */
        break;

    case IN_AUTO_POLL_RSP:
/* TODO */
        break;

    case TG_INIT_AS_TARGET_REQ:
        proto_tree_add_item(pn532_tree, hf_pn532_mode_nu_3_7, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_mode_picc_only, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_mode_dep_only, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_mode_passive_only, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        sub_item = proto_tree_add_item(pn532_tree, hf_pn532_mode_mifare_parameters, tvb, offset, 6, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn532_mifare_parameters);

        proto_tree_add_item(sub_tree, hf_pn532_mode_mifare_parameters_sens_res, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(sub_tree, hf_pn532_mode_mifare_parameters_nfc_id_1t, tvb, offset, 3, ENC_NA);
        offset += 3;

        proto_tree_add_item(sub_tree, hf_pn532_mode_mifare_parameters_sel_res, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        sub_item = proto_tree_add_item(pn532_tree, hf_pn532_mode_felica_parameters, tvb, offset, 18, ENC_NA);
        sub_tree = proto_item_add_subtree(sub_item, ett_pn532_felica_parameters);

        proto_tree_add_item(sub_tree, hf_pn532_mode_felica_parameters_nfc_id_2t, tvb, offset, 8, ENC_NA);
        offset += 8;

        proto_tree_add_item(sub_tree, hf_pn532_mode_felica_parameters_pad, tvb, offset, 8, ENC_NA);
        offset += 8;

        proto_tree_add_item(sub_tree, hf_pn532_mode_felica_parameters_system_code, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(pn532_tree, hf_pn532_mode_nfc_id_3t, tvb, offset, 10, ENC_NA);
        offset += 10;

        proto_tree_add_item(pn532_tree, hf_pn532_mode_gt_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        length = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (length > 0) {
            proto_tree_add_item(pn532_tree, hf_pn532_mode_gt, tvb, offset, length, ENC_NA);
            offset += length;
        }

        proto_tree_add_item(pn532_tree, hf_pn532_mode_tk_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        length = tvb_get_guint8(tvb, offset);
        offset += 1;

        if (length > 0) {
            proto_tree_add_item(pn532_tree, hf_pn532_mode_tk, tvb, offset, length, ENC_NA);
            offset += length;
        }
        break;

    case TG_INIT_AS_TARGET_RSP:
        proto_tree_add_item(pn532_tree, hf_pn532_mode_nu_7, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_mode_baudrate, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_mode_iso_iec_14443_4_picc, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_mode_dep, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_mode_framing_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(pn532_tree, hf_pn532_initiator_command, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_length_remaining(tvb, offset);
        break;

    case TG_SET_GENERAL_BYTES_REQ:
        proto_tree_add_item(pn532_tree, hf_pn532_gt, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_length_remaining(tvb, offset);
        break;

    case TG_SET_GENERAL_BYTES_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);
        break;

    case TG_GET_DATA_REQ:
        /* No parameters */
        break;

    case TG_GET_DATA_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);

        proto_tree_add_item(pn532_tree, hf_pn532_data_in, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_length_remaining(tvb, offset);
        break;

    case TG_SET_DATA_REQ:
    case TG_SET_METADATA_REQ:
        proto_tree_add_item(pn532_tree, hf_pn532_data_out, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_length_remaining(tvb, offset);
        break;

    case TG_SET_DATA_RSP:
    case TG_SET_METADATA_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);
        break;

    case TG_GET_INITIATOR_CMD_REQ:
        /* No parameters */
        break;

    case TG_GET_INITIATOR_CMD_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);

        proto_tree_add_item(pn532_tree, hf_pn532_initiator_command, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_length_remaining(tvb, offset);
        break;

    case TG_RESP_TO_INITIATOR_REQ:
        proto_tree_add_item(pn532_tree, hf_pn532_tg_response, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
        offset += tvb_length_remaining(tvb, offset);
        break;

    case TG_RESP_TO_INITIATOR_RSP:
        offset = dissect_status(pn532_tree, tvb, offset);
        break;

    case TG_GET_TARGET_STATUS_REQ:
        /* No parameters */
        break;

    case TG_GET_TARGET_STATUS_RSP:
        proto_tree_add_item(pn532_tree, hf_pn532_state, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(pn532_tree, hf_pn532_brit_nu_7, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_brit_speed_initiator, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_brit_nu_3, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pn532_tree, hf_pn532_brit_speed_target, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        break;

    default:
        proto_tree_add_expert(pn532_tree, pinfo, &ei_unknown_data, tvb, offset, tvb_length_remaining(tvb, offset));
        offset += tvb_length_remaining(tvb, offset);
        break;
    }

    if (tvb_length_remaining(tvb, offset) > 0) {
        proto_tree_add_expert(pn532_tree, pinfo, &ei_unexpected_data, tvb, offset, tvb_length_remaining(tvb, offset));
    }
}

void proto_register_pn532(void)
{
    module_t *pref_mod;
    expert_module_t *expert_pn532;

    static hf_register_info hf[] = {

        {&hf_pn532_command,
         {"Command", "pn532.cmd", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
          &pn532_commands_ext, 0x0, NULL, HFILL}},
        {&hf_pn532_direction,
         {"Direction", "pn532.tfi", FT_UINT8, BASE_HEX,
          VALS(pn532_directions), 0x0, NULL, HFILL}},
        {&hf_pn532_status_nad_present,
         {"NAD Present", "pn532.status.nad_present", FT_UINT8, BASE_HEX,
          NULL, 0x80, NULL, HFILL}},
        {&hf_pn532_status_mi,
         {"MI", "pn532.status.mi", FT_UINT8, BASE_HEX,
          NULL, 0x40, NULL, HFILL}},
        {&hf_pn532_status_error_code,
         {"Error Code", "pn532.status.error_code", FT_UINT8, BASE_HEX,
          VALS(pn532_errors), 0x3F, NULL, HFILL}},
        {&hf_pn532_BrTy,
         {"Baud Rate and Modulation", "pn532.BrTy", FT_UINT8, BASE_HEX,
          VALS(pn532_brtypes), 0x0, NULL, HFILL}},
        {&hf_pn532_MaxTg,
         {"Maximum Number of Targets", "pn532.MaxTg", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_Tg,
         {"Logical Target Number", "pn532.Tg", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_NbTg,
         {"Number of Targets", "pn532.NbTg", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_payload_length,
         {"Payload Length", "pn532.payload.length", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_ic_version,
         {"Integrated Circuit Version", "pn532.ic.version", FT_UINT8, BASE_HEX,
          NULL, 0x0, "Version of the IC. For PN532, the contain of this byte is 0x32", HFILL}},
        {&hf_pn532_fw_version,
         {"Firmware Version", "pn532.fw.version", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_fw_revision,
         {"Firmware Revision", "pn532.fw.revision", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_fw_support,
         {"Firmware Support", "pn532.fw.support", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_fw_support_rfu,
         {"RFU", "pn532.fw.support.rfu", FT_UINT8, BASE_HEX,
          NULL, 0xF8, NULL, HFILL}},
        {&hf_pn532_fw_support_iso_018092,
         {"ISO 018092", "pn532.fw.support.iso_018092", FT_BOOLEAN, 8,
          NULL, 0x04, NULL, HFILL}},
        {&hf_pn532_fw_support_iso_iec_14443_type_b,
         {"ISO/IEC 14443 Type B", "pn532.fw.support.iso_iec_14443_type_b", FT_BOOLEAN, 8,
          NULL, 0x02, NULL, HFILL}},
        {&hf_pn532_fw_support_iso_iec_14443_type_a,
         {"ISO/IEC 14443 Type A", "pn532.fw.support.iso_iec_14443_type_a", FT_BOOLEAN, 8,
          NULL, 0x01, NULL, HFILL}},
        {&hf_pn532_14443a_sak,
         {"ISO/IEC 14443-A SAK", "pn532.iso.14443a.sak", FT_UINT8, BASE_HEX,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_14443a_atqa,
         {"ISO/IEC 14443-A ATQA", "pn532.iso.14443a.atqa", FT_UINT16, BASE_HEX,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_14443a_uid,
         {"ISO/IEC 14443-A UID", "pn532.iso.14443a.uid", FT_UINT64, BASE_HEX,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_14443a_uid_length,
         {"ISO/IEC 14443-A UID Length", "pn532.iso.14443a.uid.length", FT_INT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_pn532_14443a_ats_length,
         {"ISO/IEC 14443-A ATS Length", "pn532.iso.14443a.ats.length", FT_INT8, BASE_DEC,
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
        {&hf_pn532_sam_mode,
         {"SAM Mode", "pn532.sam.mode", FT_UINT8, BASE_HEX,
          VALS(pn532_sam_modes), 0x0, NULL, HFILL}},
        {&hf_pn532_config,
         {"Config Item", "pn532.config", FT_UINT8, BASE_HEX,
          VALS(pn532_config_vals), 0x0, NULL, HFILL}},
        {&hf_pn532_config_not_used,
         {"Not used", "pn532.config.not_used", FT_UINT8, BASE_HEX,
          NULL, 0xFC, NULL, HFILL}},
        {&hf_pn532_config_auto_rfca,
         {"Auto RFCA", "pn532.config.auto_rfca", FT_BOOLEAN, 8,
          NULL, 0x02, NULL, HFILL}},
        {&hf_pn532_config_rf,
         {"RF", "pn532.config.rf", FT_BOOLEAN, 8,
          NULL, 0x01, NULL, HFILL}},
        {&hf_pn532_config_rfu,
         {"RFU", "pn532.config.rfu", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_atr_res_timeout,
         {"ATR Res Timeout", "pn532.config.atr_res_timeout", FT_UINT8, BASE_HEX,
          VALS(pn532_config_timeout_vals), 0x00, NULL, HFILL}},
        {&hf_pn532_config_timeout_non_dep,
         {"TimeOut during non-DEP communications", "pn532.config.timeout_non_dep", FT_UINT8, BASE_HEX,
          VALS(pn532_config_timeout_vals), 0x00, NULL, HFILL}},
        {&hf_pn532_config_max_rty_com,
         {"Max Retry COM", "pn532.config.max_rty_com", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_max_rty_atr,
         {"Max Retry ATR", "pn532.config.max_rty_atr", FT_UINT8, BASE_DEC,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_max_rty_psl,
         {"Max Retry PSL", "pn532.config.max_rty_psl", FT_UINT8, BASE_DEC,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_max_rty_passive_activation,
         {"Max Retry Passive Activation", "pn532.config.max_rty_passive_activation", FT_UINT8, BASE_DEC,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_afi,
         {"AFI", "pn532.afi", FT_UINT8, BASE_DEC,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_polling_method,
         {"Polling Method", "pn532.polling_method", FT_UINT8, BASE_DEC,
          VALS(pn532_polling_method_vals), 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_rf_cfg,
         {"CIU RF Cfg", "pn532.ciu_rf_cfg", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_gs_n_on,
         {"CIU GsN On", "pn532.ciu_gs_n_on", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_gs_n_off,
         {"CIU GsN Off", "pn532.ciu_gs_n_off", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_cw_gs_p,
         {"CIU CW GsP", "pn532.ciu_cw_gs_p", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_demon_rf_on,
         {"CIU Demon when RF is On", "pn532.ciu_demon_rf_on", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_demon_rf_off,
         {"CIU Demon when RF is Off", "pn532.ciu_demon_rf_off", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_rx_threshold,
         {"CIU RX Threshold", "pn532.ciu_rx_threshold", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_mod_width,
         {"CIU Mod Width", "pn532.ciu_mod_width", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_mod_gs_p,
         {"CIU Mod GsP", "pn532.ciu_mod_gs_p", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_mif_nfc,
         {"CIU Mif NFC", "pn532.ciu_mif_nfc", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_ciu_tx_bit_phase,
         {"CIU TX Bit Phase", "pn532.ciu_tx_bit_phase", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_212_kbps,
         {"212 kbps settings", "pn532.212_kbps", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_424_kbps,
         {"424 kbps settings", "pn532.424_kbps", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_config_848_kbps,
         {"848 kbps settings", "pn532.848_kbps", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_state,
         {"State", "pn532.state", FT_UINT8, BASE_HEX,
          VALS(pn532_state_vals), 0x00, NULL, HFILL}},
        {&hf_pn532_brit_nu_7,
         {"Not Used", "pn532.brit.not_used.7", FT_UINT8, BASE_HEX,
          NULL, 0x80, NULL, HFILL}},
        {&hf_pn532_brit_speed_initiator,
         {"Speed Initiator", "pn532.brit.speed_initiator", FT_UINT8, BASE_HEX,
          VALS(pn532_speed_vals), 0x70, NULL, HFILL}},
        {&hf_pn532_brit_nu_3,
         {"Not Used", "pn532.brit.not_used.3", FT_UINT8, BASE_HEX,
          NULL, 0x08, NULL, HFILL}},
        {&hf_pn532_brit_speed_target,
         {"Speed Target", "pn532.brit.speed_target", FT_UINT8, BASE_HEX,
          VALS(pn532_speed_vals), 0x07, NULL, HFILL}},
        {&hf_pn532_tg_response,
         {"TG Response", "pn532.tg_response", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_initiator_command,
         {"Initiator Command", "pn532.initiator_command", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_data_out,
         {"Data Out", "pn532.data_out", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_data_in,
         {"Data In", "pn532.data_in", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_gt,
         {"Gt", "pn532.gt", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_nu_3_7,
         {"Not Used", "pn532.mode.not_used.3_7", FT_UINT8, BASE_HEX,
          NULL, 0xF8, NULL, HFILL}},
        {&hf_pn532_mode_picc_only,
         {"PICC Only", "pn532.mode.picc_only", FT_BOOLEAN, 8,
          NULL, 0x04, NULL, HFILL}},
        {&hf_pn532_mode_dep_only,
         {"DEP Only", "pn532.mode.dep_only", FT_BOOLEAN, 8,
          NULL, 0x02, NULL, HFILL}},
        {&hf_pn532_mode_passive_only,
         {"Passive Only", "pn532.mode.passive_only", FT_BOOLEAN, 8,
          NULL, 0x01, NULL, HFILL}},
        {&hf_pn532_mode_mifare_parameters,
         {"Mifare Parameters", "pn532.mode.mifare_parameters", FT_NONE, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_mifare_parameters_sens_res,
         {"SENS RES", "pn532.mode.mifare_parameters.sens_res", FT_UINT16, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_mifare_parameters_nfc_id_1t,
         {"NFC ID 1t", "pn532.mode.mifare_parameters.nfc_id_1t", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_mifare_parameters_sel_res,
         {"SEL RES", "pn532.mode.mifare_parameters.sel_res", FT_UINT8, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_felica_parameters,
         {"FeliCA Parameters", "pn532.mode.felica_parameters", FT_NONE, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_felica_parameters_nfc_id_2t,
         {"NFC ID 2t", "pn532.mode.felica_parameters.nfc_id_2t", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_felica_parameters_pad,
         {"Pad", "pn532.mode.felica_parameters.pad", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_felica_parameters_system_code,
         {"System Code", "pn532.mode.felica_parameters.system_code", FT_UINT16, BASE_HEX,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_nfc_id_3t,
         {"NFC ID 3t", "pn532.mode.nfc_id_3t", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_gt,
         {"Gt", "pn532.mode.gt", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_gt_length,
         {"Gt Length", "pn532.mode.gt.length", FT_UINT8, BASE_DEC,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_tk,
         {"Tk", "pn532.mode.tk", FT_BYTES, BASE_NONE,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_tk_length,
         {"Tk Length", "pn532.mode.tk.length", FT_UINT8, BASE_DEC,
          NULL, 0x00, NULL, HFILL}},
        {&hf_pn532_mode_nu_7,
         {"Not Used", "pn532.mode.not_used.7", FT_BOOLEAN, 8,
          NULL, 0x80, NULL, HFILL}},
        {&hf_pn532_mode_baudrate,
         {"Baudrate", "pn532.mode.baudrate", FT_UINT8, BASE_HEX,
          VALS(pn532_speed_vals), 0x70, NULL, HFILL}},
        {&hf_pn532_mode_iso_iec_14443_4_picc,
         {"ISO/IEC 14443-4 PICC", "pn532.mode.iso_iec_14443_4_picc", FT_BOOLEAN, 8,
          NULL, 0x08, NULL, HFILL}},
        {&hf_pn532_mode_dep,
         {"DEP", "pn532.mode.dep", FT_BOOLEAN, 8,
          NULL, 0x04, NULL, HFILL}},
        {&hf_pn532_mode_framing_type,
         {"Framing Type", "pn532.mode.framing_type", FT_UINT8, BASE_HEX,
          VALS(pn532_framing_type_vals), 0x03, NULL, HFILL}},
        {&hf_pn532_brit,
         {"BRit", "pn532.brit", FT_UINT8, BASE_HEX,
          VALS(pn532_speed_vals), 0x00, NULL, HFILL}},
        {&hf_pn532_brti,
         {"BRti", "pn532.brti", FT_UINT8, BASE_HEX,
          VALS(pn532_speed_vals), 0x00, NULL, HFILL}},
        {&hf_pn532_txmode_nu_7,
         {"Not Used", "pn532.txmode.not_used.7", FT_BOOLEAN, 8,
          NULL, 0x80, NULL, HFILL}},
        {&hf_pn532_txmode_tx_speed,
         {"Not Used", "pn532.txmode.txspeed", FT_UINT8, BASE_HEX,
          VALS(pn532_txspeed_vals), 0x70, NULL, HFILL}},
        {&hf_pn532_txmode_nu_2_3,
         {"Not Used", "pn532.txmode.not_used.2_3", FT_BOOLEAN, 8,
          NULL, 0xC0, NULL, HFILL}},
        {&hf_pn532_txmode_tx_framing,
         {"Not Used", "pn532.txmode.not_used.2_3", FT_BOOLEAN, 8,
          VALS(pn532_txframing_vals), 0x03, NULL, HFILL}},
    };

    static ei_register_info ei[] = {
        { &ei_unknown_data,    { "pn532.expert.unknown_data",    PI_PROTOCOL, PI_NOTE, "Unknown data", EXPFILL }},
        { &ei_unexpected_data, { "pn532.expert.unexpected_data", PI_PROTOCOL, PI_WARN, "Unexpected data", EXPFILL }},
    };

    static gint *ett[] = {
        &ett_pn532,
        &ett_pn532_fw_support,
        &ett_pn532_config_212_kbps,
        &ett_pn532_config_424_kbps,
        &ett_pn532_config_848_kbps,
        &ett_pn532_mifare_parameters,
        &ett_pn532_felica_parameters
    };

    static const enum_val_t sub_enum_vals[] = {
        { "data", "Data", SUB_DATA },
        { "felica", "Sony FeliCa", SUB_FELICA },
        { "mifare", "NXP MiFare", SUB_MIFARE },
        { "iso7816", "ISO 7816", SUB_ISO7816 },
        { NULL, NULL, 0 }
    };

    proto_pn532 = proto_register_protocol("NXP PN532", "PN532", "pn532");
    proto_register_field_array(proto_pn532, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_pn532 = expert_register_protocol(proto_pn532);
    expert_register_field_array(expert_pn532, ei, array_length(ei));

    pref_mod = prefs_register_protocol(proto_pn532, NULL);
    prefs_register_enum_preference(pref_mod, "prtype532", "Payload Type", "Protocol payload type",
        &sub_selected, sub_enum_vals, FALSE);

    pn532_dissector_table = register_dissector_table("pn532.payload", "PN532 Payload", FT_UINT8, BASE_DEC);

    register_dissector("pn532", dissect_pn532, proto_pn532);
}

/* Handler registration */
void proto_reg_handoff_pn532(void)
{
    sub_handles[SUB_DATA] = find_dissector("data");
    sub_handles[SUB_FELICA] = find_dissector("felica");
    sub_handles[SUB_MIFARE] = find_dissector("mifare");
    sub_handles[SUB_ISO7816] = find_dissector("iso7816");
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
