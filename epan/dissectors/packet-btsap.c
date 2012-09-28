/* packet-btsap.c
 * Routines for Bluetooth SAP dissection
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
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
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/expert.h>

#include "packet-btl2cap.h"
#include "packet-btsdp.h"

enum {
    TOP_DISSECT_OFF       = 0,
    TOP_DISSECT_INTERNAL  = 1,
    TOP_DISSECT_TOP       = 2,
};

enum {
    PARAMETER_MAX_MSG_SIZE                 = 0x00,
    PARAMETER_CONNECTION_STATUS            = 0x01,
    PARAMETER_RESULT_CODE                  = 0x02,
    PARAMETER_DISCONNECTION_TYPE           = 0x03,
    PARAMETER_COMMAND_APDU                 = 0x04,
    PARAMETER_RESPONSE_APDU                = 0x05,
    PARAMETER_ATR                          = 0x06,
    PARAMETER_CARD_READER_STATUS           = 0x07,
    PARAMETER_STATUS_CHANGE                = 0x08,
    PARAMETER_TRANSPORT_PROTOCOL           = 0x09,
    PARAMETER_COMMAND_APDU_7816            = 0x10
};

/* Initialize the protocol and registered fields */
static int proto_btsap                                                     = -1;
static int hf_btsap_header_msg_id                                          = -1;
static int hf_btsap_header_number_of_parameters                            = -1;
static int hf_btsap_header_reserved                                        = -1;
static int hf_btsap_parameter_id                                           = -1;
static int hf_btsap_parameter_reserved                                     = -1;
static int hf_btsap_parameter_length                                       = -1;
static int hf_btsap_parameter_padding                                      = -1;
static int hf_btsap_parameter_max_msg_size                                 = -1;
static int hf_btsap_parameter_connection_status                            = -1;
static int hf_btsap_parameter_result_code                                  = -1;
static int hf_btsap_parameter_disconnection_type                           = -1;
static int hf_btsap_parameter_status_change                                = -1;
static int hf_btsap_parameter_transport_protocol                           = -1;
static int hf_btsap_parameter_card_reader_status_card_reader_identity      = -1;
static int hf_btsap_parameter_card_reader_status_card_reader_removable     = -1;
static int hf_btsap_parameter_card_reader_status_card_reader_present       = -1;
static int hf_btsap_parameter_card_reader_status_card_reader_present_lower = -1;
static int hf_btsap_parameter_card_reader_status_card_present              = -1;
static int hf_btsap_parameter_card_reader_status_card_powered              = -1;

static int hf_btsap_data                                                   = -1;

static int top_dissect                                                     = TOP_DISSECT_INTERNAL;

static gint ett_btsap                                                      = -1;
static gint ett_btsap_parameter                                            = -1;

static dissector_handle_t gsm_sim_handle;
static dissector_handle_t iso7816_atr_handle;

static const value_string msg_id_vals[] = {
    { 0x00,   "CONNECT_REQ" },
    { 0x01,   "CONNECT_RESP" },
    { 0x02,   "DISCONNECT_REQ" },
    { 0x03,   "DISCONNECT_RESP" },
    { 0x04,   "DISCONNECT_IND" },
    { 0x05,   "TRANSFER_APDU_REQ" },
    { 0x06,   "TRANSFER_APDU_RESP" },
    { 0x07,   "TRANSFER_ATR_REQ" },
    { 0x08,   "TRANSFER_ATR_RESP" },
    { 0x09,   "POWER_SIM_OFF_REQ" },
    { 0x0A,   "POWER_SIM_OFF_RESP" },
    { 0x0B,   "POWER_SIM_ON_REQ" },
    { 0x0C,   "POWER_SIM_ON_RESP" },
    { 0x0D,   "RESET_SIM_REQ" },
    { 0x0E,   "RESET_SIM_RESP" },
    { 0x0F,   "TRANSFER_CARD_READER_STATUS_REQ" },
    { 0x10,   "TRANSFER_CARD_READER_STATUS_RESP" },
    { 0x11,   "STATUS_IND" },
    { 0x12,   "ERROR_RESP" },
    { 0x13,   "SET_TRANSPORT_PROTOCOL_REQ" },
    { 0x14,   "SET_TRANSPORT_PROTOCOL_RESP" },
    { 0, NULL }
};

static const value_string parameter_id_vals[] = {
    { 0x00,   "MaxMsgSize" },
    { 0x01,   "ConnectionStatus" },
    { 0x02,   "ResultCode" },
    { 0x03,   "DisconnectionType" },
    { 0x04,   "CommandAPDU" },
    { 0x05,   "ResponseAPDU" },
    { 0x06,   "ATR" },
    { 0x07,   "CardReaderStatus" },
    { 0x08,   "StatusChange" },
    { 0x09,   "TransportProtocol" },
    { 0x10,   "CommandAPDU7816" },
    { 0, NULL }
};

static const value_string connection_status_vals[] = {
    { 0x00,   "OK, Server can fulfill requirements" },
    { 0x01,   "Error, Server unable to establish connection" },
    { 0x02,   "Error, Server does not support maximum message size" },
    { 0x03,   "Error, maximum message size by Client is too small" },
    { 0x04,   "OK, ongoing call" },
    { 0, NULL }
};

static const value_string result_code_vals[] = {
    { 0x00,   "OK, request processed correctly" },
    { 0x01,   "Error, no reason defined" },
    { 0x02,   "Error, card not accessible" },
    { 0x03,   "Error, card (already) powered off" },
    { 0x04,   "Error, card removed" },
    { 0x05,   "Error, card already powered on" },
    { 0x06,   "Error, data no available" },
    { 0x07,   "Error, not supported" },
    { 0, NULL }
};

static const value_string disconnection_type_vals[] = {
    { 0x00,   "Graceful" },
    { 0x01,   "Immediate" },
    { 0, NULL }
};

static const value_string status_change_vals[] = {
    { 0x00,   "Unknown Error" },
    { 0x01,   "Card Reset" },
    { 0x02,   "Card Not Accessible" },
    { 0x03,   "Card Removed" },
    { 0x04,   "Card Inserted" },
    { 0x05,   "Card Recovered" },
    { 0, NULL }
};

static enum_val_t pref_top_dissect[] = {
    { "off",      "off",                                  TOP_DISSECT_OFF },
    { "internal", "Put higher dissectors under this one", TOP_DISSECT_INTERNAL },
    { "top",      "On top",                               TOP_DISSECT_TOP },
    { NULL, NULL, 0 }
};

static unsigned int
dissect_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *top_tree, proto_tree *tree, unsigned int offset, guint8 *parameter, unsigned int *parameter_offset)
{
    unsigned int parameter_id;
    unsigned int parameter_length;
    unsigned int parameter_padding_length;
    unsigned int padding_length;
    unsigned int length;
    guint16      max_msg_size;
    guint8       connection_status;
    guint8       result_code;
    guint8       disconnection_type;
    guint8       status_change;
    guint8       transport_protocol;
    proto_item   *parameter_item = NULL;
    proto_item   *pitem = NULL;
    proto_tree   *ptree = NULL;
    tvbuff_t     *next_tvb;

    parameter_id = tvb_get_guint8(tvb, offset);
    parameter_length = tvb_get_ntohs(tvb, offset + 2);
    parameter_padding_length = parameter_length % 4;
    if (parameter_padding_length > 0)
        parameter_padding_length = 4 - parameter_padding_length;

    parameter_item = proto_tree_add_text(tree, tvb, offset, 2 + 2 + parameter_length + parameter_padding_length, "Parameter: %s: ",  val_to_str_const(parameter_id, parameter_id_vals, "Unknown ParameterID"));
    ptree = proto_item_add_subtree(parameter_item, ett_btsap_parameter);

    proto_tree_add_item(ptree, hf_btsap_parameter_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str_const(parameter_id, parameter_id_vals, "Unknown ParameterID"));
    offset += 1;

    proto_tree_add_item(ptree, hf_btsap_parameter_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    pitem = proto_tree_add_item(ptree, hf_btsap_parameter_length, tvb, offset, 2, ENC_BIG_ENDIAN);

    proto_item_append_text(pitem, " (in 4 bytes sections, padding length: %u)", parameter_padding_length);
    offset += 2;

    switch(parameter_id) {
        case 0x00: /* MaxMsgSize */
            proto_tree_add_item(ptree, hf_btsap_parameter_max_msg_size, tvb, offset, 2, ENC_BIG_ENDIAN);
            max_msg_size = tvb_get_ntohs(tvb, offset);
            proto_item_append_text(parameter_item, "%u", max_msg_size);
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %u", max_msg_size);
            length = 2;
            padding_length = 2;
            break;
        case 0x01: /* ConnectionStatus */
            proto_tree_add_item(ptree, hf_btsap_parameter_connection_status, tvb, offset, 1, ENC_BIG_ENDIAN);
            connection_status = tvb_get_guint8(tvb, offset);
            proto_item_append_text(parameter_item, "%s", val_to_str_const(connection_status, connection_status_vals, "Unknown"));
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(connection_status, connection_status_vals, "Unknown"));
            length = 1;
            padding_length = 3;
            break;
        case 0x02: /* ResultCode */
            proto_tree_add_item(ptree, hf_btsap_parameter_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            result_code = tvb_get_guint8(tvb, offset);
            proto_item_append_text(parameter_item, "%s", val_to_str_const(result_code, result_code_vals, "Unknown"));
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(result_code, result_code_vals, "Unknown"));
            length = 1;
            padding_length = 3;
            break;
        case 0x03: /* DisconnectionType */
            proto_tree_add_item(ptree, hf_btsap_parameter_disconnection_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            disconnection_type = tvb_get_guint8(tvb, offset);
            proto_item_append_text(parameter_item, "%s", val_to_str_const(disconnection_type, disconnection_type_vals, "Unknown"));
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(disconnection_type, disconnection_type_vals, "Unknown"));
            length = 1;
            padding_length = 3;
            break;
        case 0x04: /* CommandAPDU */
            /* GSM 11.11 */
            if (gsm_sim_handle && top_dissect != TOP_DISSECT_OFF) {
                next_tvb = tvb_new_subset(tvb, offset, parameter_length, parameter_length);
                col_append_str(pinfo->cinfo, COL_INFO, ": ");

                if (top_dissect == TOP_DISSECT_INTERNAL) {
                    call_dissector(gsm_sim_handle, next_tvb, pinfo, ptree);
                } else {
                    col_clear(pinfo->cinfo, COL_INFO);
                    call_dissector(gsm_sim_handle, next_tvb, pinfo, top_tree);
                }
            } else {
                proto_tree_add_item(ptree, hf_btsap_data, tvb, offset, parameter_length, ENC_NA);
            }

            length = parameter_length;
            padding_length = parameter_padding_length;
            break;
        case 0x05: /* ResponseAPDU */
            /* GSM 11.11 or ISO/IEC 7816-4; depend of TRANSFER_APDU_REQ */
            if (gsm_sim_handle && top_dissect != TOP_DISSECT_OFF) {
                next_tvb = tvb_new_subset(tvb, offset, parameter_length, parameter_length);
                col_append_str(pinfo->cinfo, COL_INFO, ": ");

                if (top_dissect == TOP_DISSECT_INTERNAL) {
                    call_dissector(gsm_sim_handle, next_tvb, pinfo, ptree);
                } else {
                    col_clear(pinfo->cinfo, COL_INFO);
                    call_dissector(gsm_sim_handle, next_tvb, pinfo, top_tree);
                }
            } else {
                proto_tree_add_item(ptree, hf_btsap_data, tvb, offset, parameter_length, ENC_NA);
            }

            length = parameter_length;
            padding_length = parameter_padding_length;
            break;
        case 0x06: /* ATR */
            /* ISO/IEC 7816-3 */
            if (iso7816_atr_handle && top_dissect != TOP_DISSECT_OFF) {
                next_tvb = tvb_new_subset(tvb, offset, parameter_length, parameter_length);
                col_append_str(pinfo->cinfo, COL_INFO, ": ");

                if (top_dissect == TOP_DISSECT_INTERNAL) {
                    call_dissector(iso7816_atr_handle, next_tvb, pinfo, ptree);
                } else {
                    col_clear(pinfo->cinfo, COL_INFO);
                    call_dissector(iso7816_atr_handle, next_tvb, pinfo, top_tree);
                }
            } else {
                proto_tree_add_item(ptree, hf_btsap_data, tvb, offset, parameter_length, ENC_NA);
            }

            length = parameter_length;
            padding_length = parameter_padding_length;
            break;
        case 0x07: /* CardReaderStatus */
            /* 3GPP TS 11.14 */
            proto_tree_add_item(ptree, hf_btsap_parameter_card_reader_status_card_powered, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ptree, hf_btsap_parameter_card_reader_status_card_present, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ptree, hf_btsap_parameter_card_reader_status_card_reader_present_lower, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ptree, hf_btsap_parameter_card_reader_status_card_reader_present, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ptree, hf_btsap_parameter_card_reader_status_card_reader_removable, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ptree, hf_btsap_parameter_card_reader_status_card_reader_identity, tvb, offset, 1, ENC_BIG_ENDIAN);
            length = 1;
            padding_length = 3;
            break;
        case 0x08: /* StatusChange */
            proto_tree_add_item(ptree, hf_btsap_parameter_status_change, tvb, offset, 1, ENC_BIG_ENDIAN);
            status_change = tvb_get_guint8(tvb, offset);
            proto_item_append_text(parameter_item, "%s", val_to_str_const(status_change, status_change_vals, "Unknown"));
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(status_change, status_change_vals, "Unknown"));
            length = 1;
            padding_length = 3;
            break;
        case 0x09: /* TransportProtocol */
            proto_tree_add_item(ptree, hf_btsap_parameter_transport_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
            transport_protocol = tvb_get_guint8(tvb, offset);
            proto_item_append_text(parameter_item, "%u", transport_protocol);
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %u", transport_protocol);
            length = 1;
            padding_length = 3;
            break;
        case 0x10: /* CommandAPDU7816 */
            /* ISO/IEC 7816-4 */
            if (gsm_sim_handle && top_dissect != TOP_DISSECT_OFF) {
                next_tvb = tvb_new_subset(tvb, offset, parameter_length, parameter_length);
                col_append_str(pinfo->cinfo, COL_INFO, ": ");

                if (top_dissect == TOP_DISSECT_INTERNAL) {
                    call_dissector(gsm_sim_handle, next_tvb, pinfo, ptree);
                } else {
                    col_clear(pinfo->cinfo, COL_INFO);
                    call_dissector(gsm_sim_handle, next_tvb, pinfo, top_tree);
                }
            } else {
                proto_tree_add_item(ptree, hf_btsap_data, tvb, offset, parameter_length, ENC_NA);
            }

            length = parameter_length;
            padding_length = parameter_padding_length;
            break;
        default:
            proto_tree_add_item(ptree, hf_btsap_data, tvb, offset, parameter_length, ENC_NA);
            length = parameter_length;
            padding_length = parameter_padding_length;
    }

    *parameter = parameter_id;
    *parameter_offset = offset;

    if (length != parameter_length || padding_length != parameter_padding_length) {
        /* Malformed frame */
        expert_add_info_format(pinfo, pitem, PI_PROTOCOL, PI_WARN,
            "Parameter Length does not meet content length");
    }

    offset += parameter_length;

    if (parameter_padding_length > 0) {
        pitem = proto_tree_add_item(ptree, hf_btsap_parameter_padding, tvb, offset, parameter_padding_length, ENC_BIG_ENDIAN);
        proto_item_append_text(pitem, " (length %d)", parameter_padding_length);
        offset += parameter_padding_length;
    }

    return offset;
}

/* Code to actually dissect the packets */
static void
dissect_btsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item   *ti;
    proto_tree   *btsap_tree;
    unsigned int offset = 0;
    unsigned int msg_id;
    unsigned int number_of_parameters;
    unsigned int i_parameter;
    guint8       *parameters;
    unsigned int *parameter_offsets;
    unsigned int parameters_check = 0;
    unsigned int required_parameters = 0;
    unsigned int i_next_parameter;
    proto_item   *pitem;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SAP");
    col_clear(pinfo->cinfo, COL_INFO);

    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_add_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_add_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
            pinfo->p2p_dir);
        break;
    }

    ti = proto_tree_add_item(tree, proto_btsap, tvb, offset, -1, FALSE);
    btsap_tree = proto_item_add_subtree(ti, ett_btsap);

    proto_tree_add_item(btsap_tree, hf_btsap_header_msg_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    msg_id = tvb_get_guint8(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const(msg_id, msg_id_vals, "Unknown MsgID"));
    offset += 1;

    proto_tree_add_item(btsap_tree, hf_btsap_header_number_of_parameters, tvb, offset, 1, ENC_BIG_ENDIAN);
    number_of_parameters = tvb_get_guint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(btsap_tree, hf_btsap_header_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    parameters = ep_alloc(number_of_parameters * sizeof(guint8));
    parameter_offsets = ep_alloc(number_of_parameters * sizeof(unsigned int));

    for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
        offset = dissect_parameter(tvb, pinfo, tree, btsap_tree, offset, &parameters[i_parameter], &parameter_offsets[i_parameter]);
    }

    /* detect invalid data  */
    switch(msg_id) {
        case 0x02: /* DISCONNECT_REQ */
        case 0x03: /* DISCONNECT_RESP */
        case 0x07: /* TRANSFER_ATR_REQ */
        case 0x09: /* POWER_SIM_OFF_REQ */
        case 0x0B: /* POWER_SIM_ON_REQ */
        case 0x0D: /* RESET_SIM_REQ */
        case 0x0F: /* TRANSFER_CARD_READER_STATUS_REQ */
        case 0x12: /* ERROR_RESP */
            required_parameters = 0;
            break;
        case 0x0A: /* POWER_SIM_OFF_RESP */
        case 0x0C: /* POWER_SIM_ON_RESP */
        case 0x0E: /* RESET_SIM_RESP */
        case 0x14: /* SET_TRANSPORT_PROTOCOL_RESP */
            /* Parameters: 1 - ResultCode */
            required_parameters = 1;
            for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
                if (parameters[i_parameter] == PARAMETER_RESULT_CODE) ++parameters_check;
            }
            break;
        case 0x00: /* CONNECT_REQ */
            /* 1 - MaxMsgSize */
            required_parameters = 1;
            for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
                if (parameters[i_parameter] == PARAMETER_MAX_MSG_SIZE) ++parameters_check;
            }
            break;
        case 0x01: /* CONNECT_RESP */
            /* Parameters: 1..2 - ConnectionStatus, MaxMsgSize (if error cannot fulfill) */
            required_parameters = 1;
            for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
                if (parameters[i_parameter] == PARAMETER_CONNECTION_STATUS) {
                    if (tvb_get_guint8(tvb, parameter_offsets[i_parameter]) != 0x00) {
                        for (i_next_parameter = 0; i_next_parameter < number_of_parameters; ++i_next_parameter) {
                            if (parameters[i_next_parameter] == PARAMETER_MAX_MSG_SIZE) {
                                ++parameters_check;
                                required_parameters = 2;
                            }
                        }
                    }
                    ++parameters_check;
                }
            }
            break;
        case 0x04: /* DISCONNECT_IND */
            /* Parameters: 1 - DisconnectionType */
            required_parameters = 1;
            for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
                if (parameters[i_parameter] == PARAMETER_DISCONNECTION_TYPE) ++parameters_check;
            }
            break;
        case 0x05: /* TRANSFER_APDU_REQ */
            /* Parameters: 1 - CommandAPU or CommandAPU7816 */
            required_parameters = 1;
            for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
                if (parameters[i_parameter] == PARAMETER_COMMAND_APDU ||
                        parameters[i_parameter] == PARAMETER_COMMAND_APDU_7816)
                    ++parameters_check;
            }
            break;
        case 0x06: /* TRANSFER_APDU_RESP */
            /* Parameters: 1..2 - ResultCode, ResponseAPDU (if status ok) */
            required_parameters = 1;
            for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
                if (parameters[i_parameter] == PARAMETER_RESULT_CODE) {
                    if (tvb_get_guint8(tvb, parameter_offsets[i_parameter]) == 0x00) {
                        for (i_next_parameter = 0; i_next_parameter < number_of_parameters; ++i_next_parameter) {
                            if (parameters[i_next_parameter] == PARAMETER_RESPONSE_APDU) {
                                ++parameters_check;
                                required_parameters = 2;
                            }
                        }
                    }
                    ++parameters_check;
                }
            }
            break;
        case 0x08: /* TRANSFER_ATR_RESP */
            /* Parameters: 1..2 - ResultCode, ATR (if status ok) */
            required_parameters = 1;
            for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
                if (parameters[i_parameter] == PARAMETER_RESULT_CODE) {
                    if (tvb_get_guint8(tvb, parameter_offsets[i_parameter]) == 0x00) {
                        for (i_next_parameter = 0; i_next_parameter < number_of_parameters; ++i_next_parameter) {
                            if (parameters[i_next_parameter] == PARAMETER_ATR) {
                                ++parameters_check;
                                required_parameters = 2;
                            }
                        }
                    }
                    ++parameters_check;
                }
            }
            break;
        case 0x10: /* TRANSFER_CARD_READER_STATUS_RESP */
            /* Parameters: 1..2 - ResultCode, CardReaderStatus (if status ok)  */
            required_parameters = 1;
            for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
                if (parameters[i_parameter] == PARAMETER_RESULT_CODE) {
                    if (tvb_get_guint8(tvb, parameter_offsets[i_parameter]) == 0x00) {
                        for (i_next_parameter = 0; i_next_parameter < number_of_parameters; ++i_next_parameter) {
                            if (parameters[i_next_parameter] == PARAMETER_CARD_READER_STATUS) {
                                ++parameters_check;
                                required_parameters = 2;
                            }
                        }
                    }
                    ++parameters_check;
                }
            }
            break;
        case 0x11: /* STATUS_IND */
            /* Parameters: 1 - StatusChange */
            required_parameters = 1;
            for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
                if (parameters[i_parameter] == PARAMETER_STATUS_CHANGE) ++parameters_check;
            }
            break;
        case 0x13: /* SET_TRANSPORT_PROTOCOL_REQ */
            /* Parameters: 1 - TransportProtocol */
            required_parameters = 1;
            for (i_parameter = 0; i_parameter < number_of_parameters; ++i_parameter) {
                if (parameters[i_parameter] == PARAMETER_TRANSPORT_PROTOCOL) ++parameters_check;
            }
            break;
    }

    if (parameters_check < required_parameters) {
        gchar *error_message = "There is no required parameters";
        pitem = proto_tree_add_text(tree, tvb, offset, 0, error_message, NULL);
        PROTO_ITEM_SET_GENERATED(pitem);
        expert_add_info_format(pinfo, pitem, PI_PROTOCOL, PI_WARN, error_message, NULL);
    } else if (parameters_check > required_parameters) {
        gchar *error_message = "Invalid parameters";
        pitem = proto_tree_add_text(tree, tvb, offset, 0, error_message, NULL);
        PROTO_ITEM_SET_GENERATED(pitem);
        expert_add_info_format(pinfo, pitem, PI_PROTOCOL, PI_WARN, error_message, NULL);
    }
    if (number_of_parameters < required_parameters) {
        gchar *error_message = "Too few parameters";
        pitem = proto_tree_add_text(tree, tvb, offset, 0, error_message, NULL);
        PROTO_ITEM_SET_GENERATED(pitem);
        expert_add_info_format(pinfo, pitem, PI_PROTOCOL, PI_WARN, error_message, NULL);
    } else if (number_of_parameters > required_parameters) {
        gchar *error_message = "Too many parameters";
        pitem = proto_tree_add_text(tree, tvb, offset, 0, error_message, NULL);
        PROTO_ITEM_SET_GENERATED(pitem);
        expert_add_info_format(pinfo, pitem, PI_PROTOCOL, PI_WARN, error_message, NULL);
    }

    if (tvb_length(tvb) > offset) {
        proto_tree_add_item(btsap_tree, hf_btsap_data, tvb, offset, -1, ENC_NA);
    }
}


void
proto_register_btsap(void)
{
    module_t *module;

    static hf_register_info hf[] = {
        { &hf_btsap_header_msg_id,
            { "MsgID",                           "btsap.msg_id",
            FT_UINT8, BASE_HEX, VALS(msg_id_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_header_number_of_parameters,
            { "Number of Parameters",            "btsap.number_of_parameters",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_header_reserved,
            { "reserved",                        "btsap.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_id,
            { "Parameter ID",                    "btsap.parameter_id",
            FT_UINT8, BASE_HEX, VALS(parameter_id_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_reserved,
            { "reserved",                        "btsap.parameter.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_length,
            { "Parameter Length",                "btsap.parameter.length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_padding,
            { "Parameter Padding",               "btsap.parameter.padding",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_max_msg_size,
            { "Max Msg Size",                    "btsap.parameter.max_msg_size",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_connection_status,
            { "Connection Status",               "btsap.parameter.connection_status",
            FT_UINT8, BASE_HEX, VALS(connection_status_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_result_code,
            { "Result Code",                     "btsap.parameter.result_code",
            FT_UINT8, BASE_HEX, VALS(result_code_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_disconnection_type,
            { "Disconnection Type",              "btsap.parameter.disconnection_type",
            FT_UINT8, BASE_HEX, VALS(disconnection_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_card_reader_status_card_reader_identity,
            { "Identify of Card Reader",         "btsap.parameter.card_reader_status.card_reader_identity",
            FT_UINT8, BASE_HEX, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_card_reader_status_card_reader_removable,
            { "Card Reader is Removable",        "btsap.parameter.card_reader_status.card_reader_removable",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_card_reader_status_card_reader_present,
            { "Card Reader is Present",          "btsap.parameter.card_reader_status.card_reader_present",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_card_reader_status_card_reader_present_lower,
            { "Card Reader Present is ID-1 Size","btsap.parameter.card_reader_status.card_reader_present_lower",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_card_reader_status_card_present,
            { "Card is Present in Reader",       "btsap.parameter.card_reader_status.card_present",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_card_reader_status_card_powered,
            { "Card in Reader is Powered",       "btsap.parameter.card_reader_status.card_powered",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_status_change,
            { "Status Change",                   "btsap.parameter.status_change",
            FT_UINT8, BASE_HEX, VALS(status_change_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_btsap_parameter_transport_protocol,
            { "Transport Protocol",              "btsap.parameter.transport_protocol",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },

        { &hf_btsap_data,
            { "Data",                            "btsap.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

    };

    static gint *ett[] = {
        &ett_btsap,
        &ett_btsap_parameter
    };

    proto_btsap = proto_register_protocol("Bluetooth SAP Profile", "BT SAP", "btsap");
    register_dissector("btsap", dissect_btsap, proto_btsap);

    proto_register_field_array(proto_btsap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    module = prefs_register_protocol(proto_btsap, NULL);
    prefs_register_static_text_preference(module, "sap.version",
            "Bluetooth Profile SAP version: 1.1",
            "Version of protocol supported by this dissector.");

    prefs_register_enum_preference(module, "sap.top_dissect",
            "Dissecting the top protocols", "Dissecting the top protocols",
            &top_dissect, pref_top_dissect, FALSE);
}


void
proto_reg_handoff_btsap(void)
{
    dissector_handle_t btsap_handle;

    btsap_handle = find_dissector("btsap");
    gsm_sim_handle = find_dissector("gsm_sim");
    iso7816_atr_handle = find_dissector("iso7816.atr");

    dissector_add_uint("btrfcomm.service", BTSDP_SAP_SERVICE_UUID, btsap_handle);

    dissector_add_handle("btrfcomm.channel", btsap_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
