/* packet-bthcrp.c
 * Routines for Bluetooth HCRP dissection
 *
 * Copyright 2013, Michal Labedzki for Tieto Corporation
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
#include <epan/expert.h>

#include "packet-btl2cap.h"
#include "packet-btsdp.h"

enum {
    FORCE_CLIENT_DEFAULT  = 0,
    FORCE_CLIENT_YES      = 1,
    FORCE_CLIENT_NO       = 2
};

static int proto_bthcrp = -1;

static int hf_bthcrp_notification_pdu_id                                   = -1;
static int hf_bthcrp_control_pdu_id                                        = -1;
static int hf_bthcrp_control_transaction_id                                = -1;
static int hf_bthcrp_control_parameter_length                              = -1;
static int hf_bthcrp_control_status                                        = -1;
static int hf_bthcrp_callback_context_id                                   = -1;
static int hf_bthcrp_control_callback_timeout                              = -1;
static int hf_bthcrp_control_timeout                                       = -1;
static int hf_bthcrp_control_1284_id                                       = -1;
static int hf_bthcrp_control_register                                      = -1;
static int hf_bthcrp_control_start_byte                                    = -1;
static int hf_bthcrp_control_number_of_bytes                               = -1;
static int hf_bthcrp_control_client_credit_granted                         = -1;
static int hf_bthcrp_control_server_credit_granted                         = -1;
static int hf_bthcrp_control_client_credit_return                          = -1;
static int hf_bthcrp_control_server_credit_return                          = -1;
static int hf_bthcrp_control_client_credit_query                           = -1;
static int hf_bthcrp_control_server_credit_query                           = -1;
static int hf_bthcrp_control_status_reserved_76                            = -1;
static int hf_bthcrp_control_status_paper_empty                            = -1;
static int hf_bthcrp_control_status_select                                 = -1;
static int hf_bthcrp_control_status_not_error                              = -1;
static int hf_bthcrp_control_status_reserved_20                            = -1;
static int hf_bthcrp_data                                                  = -1;

static gint ett_bthcrp                                                     = -1;

static expert_field ei_bthcrp_control_parameter_length = EI_INIT;
static expert_field ei_bthcrp_unexpected_data = EI_INIT;

static dissector_handle_t bthcrp_handle;

static gint     force_client     = FORCE_CLIENT_DEFAULT;
static gint     psm_control      = 0;
static gint     psm_data_stream  = 0;
static gint     psm_notification = 0;

static const value_string control_pdu_id_vals[] = {
    { 0x0001,   "CR_DataChannelCreditGrant" },
    { 0x0002,   "CR_DataChannelCreditRequest" },
    { 0x0003,   "CR_DataChannelCreditReturn" },
    { 0x0004,   "CR_DataChannelCreditQuery" },
    { 0x0005,   "CR_GetLPTStatus" },
    { 0x0006,   "CR_Get1284ID" },
    { 0x0007,   "CR_SoftReset" },
    { 0x0008,   "CR_HardReset" },
    { 0x0009,   "CR_RegisterNotification" },
    { 0x000A,   "CR_NotificationConnectionAlive" },
    { 0, NULL }
};

static const value_string status_vals[] = {
    { 0x0000,   "Feature Unsupported" },
    { 0x0001,   "Success" },
    { 0x0002,   "Credit Synchronization Error" },
    { 0xFFFF,   "Generic Failure" },
    { 0, NULL }
};

static const value_string notification_pdu_id_vals[] = {
    { 0x0001,   "N_Notification" },
    { 0, NULL }
};

static const value_string register_vals[] = {
    { 0x00,   "Remove Client From Receiver Notification" },
    { 0x01,   "Add Client To Receiver Notification" },
    { 0, NULL }
};

static const enum_val_t force_client_enum[] = {
    { "default",  "Default",  FORCE_CLIENT_DEFAULT },
    { "yes",      "Yes",      FORCE_CLIENT_YES },
    { "no",       "No",       FORCE_CLIENT_NO },
    { NULL, NULL, 0 }
};

void proto_register_bthcrp(void);
void proto_reg_handoff_bthcrp(void);


static gint
dissect_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset,  gboolean is_client_message)
{
    /* flow: reqests: only client -> server; responses: only server ->  */
    proto_item   *pitem;
    guint16       control_pdu_id;
    guint         credits;
    guint         timeout;
    guint         context_id;
    guint         notification_register;
    guint         number;
    gint          parameter_length;

    pitem = proto_tree_add_item(tree, hf_bthcrp_control_pdu_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    control_pdu_id = tvb_get_ntohs(tvb, offset);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, "Control: %s %s",
            ((is_client_message) ? "Request" : "Response"),
            val_to_str(control_pdu_id, control_pdu_id_vals,  "Unknown PDU ID"));

    if (control_pdu_id >= 0x8000) {
        proto_item_append_text(pitem, " (Vendor Specific)");
        col_append_str(pinfo->cinfo, COL_INFO, " (Vendor Specific)");
    } else if (control_pdu_id == 0x0000 || control_pdu_id >= 0x000B ) {
        proto_item_append_text(pitem, " (Reserved)");
        col_append_str(pinfo->cinfo, COL_INFO, " (Reserved)");
    }

    proto_tree_add_item(tree, hf_bthcrp_control_transaction_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    pitem = proto_tree_add_item(tree, hf_bthcrp_control_parameter_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    parameter_length = tvb_get_ntohs(tvb, offset);
    offset += 2;

    if (!is_client_message && parameter_length < 2) {
        expert_add_info_format(pinfo, pitem, &ei_bthcrp_control_parameter_length,
                "Parameter length is shorter than 2 in response");
    }

    if (parameter_length < tvb_reported_length_remaining(tvb, offset)) {
        expert_add_info_format(pinfo, pitem, &ei_bthcrp_control_parameter_length,
                "Parameter length is shorter than payload length");
    } else if (parameter_length > tvb_reported_length_remaining(tvb, offset)) {
        expert_add_info_format(pinfo, pitem, &ei_bthcrp_control_parameter_length,
                "Parameter length is larger than payload length");
    }

    if (!is_client_message) {
        proto_tree_add_item(tree, hf_bthcrp_control_status, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    if (control_pdu_id >= 0x8000) {
        if (tvb_reported_length_remaining(tvb, offset)) {
            proto_tree_add_item(tree, hf_bthcrp_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
            offset += tvb_reported_length_remaining(tvb, offset);
        }
    } else switch(control_pdu_id) {
        case 0x0001: /* CR_DataChannelCreditGrant */
            if (is_client_message) {
                proto_tree_add_item(tree, hf_bthcrp_control_client_credit_granted, tvb, offset, 4, ENC_BIG_ENDIAN);
                credits = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - CreditGranted: %u", credits);
                offset += 4;
            }
            break;
        case 0x0002: /* CR_DataChannelCreditRequest */
            if (!is_client_message) {
                proto_tree_add_item(tree, hf_bthcrp_control_server_credit_granted, tvb, offset, 4, ENC_BIG_ENDIAN);
                credits = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - CreditGranted: %u", credits);
                offset += 4;
            }
            break;
        case 0x0003: /* CR_DataChannelCreditReturn */
            if (is_client_message) {
                proto_tree_add_item(tree, hf_bthcrp_control_client_credit_return, tvb, offset, 4, ENC_BIG_ENDIAN);
                credits = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - Client Credit Return: %u", credits);
                offset += 4;
            } else {
                proto_tree_add_item(tree, hf_bthcrp_control_server_credit_return, tvb, offset, 4, ENC_BIG_ENDIAN);
                credits = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - Server Credit Return: %u", credits);
                offset += 4;
            }
            break;
        case 0x0004: /* CR_DataChannelCreditQuery */
            if (is_client_message) {
                proto_tree_add_item(tree, hf_bthcrp_control_client_credit_query, tvb, offset, 4, ENC_BIG_ENDIAN);
                credits = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - Client Credit: %u", credits);
                offset += 4;
            } else {
                proto_tree_add_item(tree, hf_bthcrp_control_server_credit_query, tvb, offset, 4, ENC_BIG_ENDIAN);
                credits = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - Server Credit: %u", credits);
                offset += 4;
            }
            break;
        case 0x0005: /* CR_GetLPTStatus */
            if (!is_client_message) {
                proto_tree_add_item(tree, hf_bthcrp_control_status_reserved_76, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_bthcrp_control_status_paper_empty, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_bthcrp_control_status_select, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_bthcrp_control_status_not_error, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_bthcrp_control_status_reserved_20, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
        case 0x0006: /* CR_Get1284ID */
            if (is_client_message) {
                proto_tree_add_item(tree, hf_bthcrp_control_start_byte, tvb, offset, 2, ENC_BIG_ENDIAN);
                number = tvb_get_ntohs(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - Start Byte: %u", number);
                offset += 2;

                proto_tree_add_item(tree, hf_bthcrp_control_number_of_bytes, tvb, offset, 2, ENC_BIG_ENDIAN);
                number = tvb_get_ntohs(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Number Of Bytes: %u", number);
                offset += 2;
            } else {
                const guint8 *id;

                proto_tree_add_item_ret_string(tree, hf_bthcrp_control_1284_id, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_ASCII | ENC_NA, wmem_packet_scope(), &id);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - 1284 ID: %s", id);
                offset += tvb_reported_length_remaining(tvb, offset);
            }
            break;
        case 0x0007: /* CR_SoftReset */
        case 0x0008: /* CR_HardReset */
            break;
        case 0x0009: /* CR_RegisterNotification */
            if (is_client_message) {
                proto_tree_add_item(tree, hf_bthcrp_control_register, tvb, offset, 1, ENC_BIG_ENDIAN);
                notification_register = tvb_get_guint8(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " -  Register: %s", val_to_str(notification_register, register_vals, "unknown register"));
                offset += 1;

                proto_tree_add_item(tree, hf_bthcrp_callback_context_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                context_id = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Callback ContextID: %u", context_id);
                offset += 4;

                proto_tree_add_item(tree, hf_bthcrp_control_callback_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
                timeout = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Callback Timeout: %u", timeout);
                offset += 4;
            } else {
                proto_tree_add_item(tree, hf_bthcrp_control_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
                timeout = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - Timeout: %u", timeout);
                offset += 4;

                proto_tree_add_item(tree, hf_bthcrp_control_callback_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
                timeout = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Callback Timeout: %u", timeout);
                offset += 4;
            }
            break;
        case 0x000A: /* CR_NotificationConnectionAlive */
            if (!is_client_message) {
                proto_tree_add_item(tree, hf_bthcrp_control_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);
                timeout = tvb_get_ntohl(tvb, offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, " - Timeout: %u", timeout);
                offset += 4;
            }
            break;
    }

    return offset;
}


static gint
dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint offset)
{
    /* flow: server <-> client */
    tvbuff_t *next_tvb;

    col_append_str(pinfo->cinfo, COL_INFO, "HCRP data stream");

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, tree);

    offset += tvb_reported_length_remaining(tvb, offset);

    return offset;
}


static gint
dissect_notification(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        gint offset, gboolean is_client_message)
{
    /* flow: only server -> client */
    guint16       notification_pdu_id;
    proto_item   *pitem;

    if (is_client_message) {
        col_append_str(pinfo->cinfo, COL_INFO, "Notification: unexpected notification stream");
        return offset;
    }

    pitem = proto_tree_add_item(tree, hf_bthcrp_notification_pdu_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    notification_pdu_id = tvb_get_ntohs(tvb, offset);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, "Notification: %s", val_to_str(notification_pdu_id, notification_pdu_id_vals,  "Unknown PDU ID"));

    if (notification_pdu_id >= 0x8000) {
        proto_item_append_text(pitem, " (Vendor Specific)");
        col_append_str(pinfo->cinfo, COL_INFO, " (Vendor Specific)");
        if (tvb_reported_length_remaining(tvb, offset)) {
            proto_tree_add_item(tree, hf_bthcrp_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
            offset += tvb_reported_length_remaining(tvb, offset);
        }
    } else if (notification_pdu_id != 0x001) {
        proto_item_append_text(pitem, " (Reserved)");
        col_append_str(pinfo->cinfo, COL_INFO, " (Reserved)");
    }

    switch(notification_pdu_id) {
        case 0x01: /* N_NOTIFICATION */
            proto_tree_add_item(tree, hf_bthcrp_callback_context_id, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
    }

    return offset;
}

static gint
dissect_bthcrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item      *main_item;
    proto_tree      *main_tree;
    gint             offset = 0;
    gint             protocol = -1;
    gboolean         is_client_message = FALSE;
    gint             previous_proto;

    previous_proto = (GPOINTER_TO_INT(wmem_list_frame_data(wmem_list_frame_prev(wmem_list_tail(pinfo->layers)))));
    if (previous_proto == proto_btl2cap) {
        btl2cap_data_t  *l2cap_data;
        wmem_tree_key_t  key[10];
        guint32          interface_id;
        guint32          adapter_id;
        guint32          sdp_psm = SDP_PSM_DEFAULT;
        guint32          direction;
        guint32          bd_addr_oui;
        guint32          bd_addr_id;
        guint32          service_type;
        guint32          service_channel;
        guint32          frame_number;
        service_info_t  *service_info;

        l2cap_data = (btl2cap_data_t *) data;

        interface_id       = l2cap_data->interface_id;
        adapter_id         = l2cap_data->adapter_id;

        direction       = (l2cap_data->is_local_psm) ? P2P_DIR_SENT : P2P_DIR_RECV;
        if (direction == P2P_DIR_RECV) {
            bd_addr_oui = l2cap_data->remote_bd_addr_oui;
            bd_addr_id  = l2cap_data->remote_bd_addr_id;
        } else {
            bd_addr_oui = 0;
            bd_addr_id  = 0;
        }

        service_type    = BTSDP_L2CAP_PROTOCOL_UUID;
        service_channel = l2cap_data->psm;
        frame_number    = pinfo->num;

        key[0].length = 1;
        key[0].key = &interface_id;
        key[1].length = 1;
        key[1].key = &adapter_id;
        key[2].length = 1;
        key[2].key = &sdp_psm;
        key[3].length = 1;
        key[3].key = &direction;
        key[4].length = 1;
        key[4].key = &bd_addr_oui;
        key[5].length = 1;
        key[5].key = &bd_addr_id;
        key[6].length = 1;
        key[6].key = &service_type;
        key[7].length = 1;
        key[7].key = &service_channel;
        key[8].length = 1;
        key[8].key = &frame_number;
        key[9].length = 0;
        key[9].key = NULL;

        service_info = btsdp_get_service_info(key);
        if (service_info && service_info->interface_id == interface_id &&
                service_info->adapter_id == adapter_id &&
                service_info->sdp_psm == SDP_PSM_DEFAULT &&
                ((service_info->direction == P2P_DIR_RECV &&
                service_info->bd_addr_oui == bd_addr_oui &&
                service_info->bd_addr_id == bd_addr_id) ||
                (service_info->direction != P2P_DIR_RECV &&
                service_info->bd_addr_oui == 0 &&
                service_info->bd_addr_id == 0)) &&
                service_info->type == BTSDP_L2CAP_PROTOCOL_UUID &&
                service_info->channel == l2cap_data->psm) {

            if ((service_info->protocol == BTSDP_HARDCOPY_CONTROL_CHANNEL_PROTOCOL_UUID ||
                    service_info->protocol == BTSDP_HARDCOPY_DATA_CHANNEL_PROTOCOL_UUID) &&
                    ((!l2cap_data->is_local_psm && pinfo->p2p_dir == P2P_DIR_SENT) ||
                    (l2cap_data->is_local_psm && pinfo->p2p_dir == P2P_DIR_RECV))) {
                is_client_message = TRUE;
            } else if (service_info->protocol == BTSDP_HARDCOPY_NOTIFICATION_PROTOCOL_UUID &&
                    ((l2cap_data->is_local_psm && pinfo->p2p_dir == P2P_DIR_SENT) ||
                    (!l2cap_data->is_local_psm && pinfo->p2p_dir == P2P_DIR_RECV))) {
                is_client_message = TRUE;
            }

            protocol = service_info->protocol;
        }

        if (psm_control != 0 && l2cap_data->psm == psm_control) {
            protocol = BTSDP_HARDCOPY_CONTROL_CHANNEL_PROTOCOL_UUID;
        } else if (psm_data_stream != 0 && l2cap_data->psm == psm_data_stream) {
            protocol = BTSDP_HARDCOPY_DATA_CHANNEL_PROTOCOL_UUID;
        } else if (psm_notification != 0 && l2cap_data->psm == psm_notification) {
            protocol = BTSDP_HARDCOPY_NOTIFICATION_PROTOCOL_UUID;
        }

    }

    main_item = proto_tree_add_item(tree, proto_bthcrp, tvb, offset, -1, ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_bthcrp);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCRP");

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    if (force_client != FORCE_CLIENT_DEFAULT) {
        is_client_message = (force_client == FORCE_CLIENT_YES && pinfo->p2p_dir == P2P_DIR_SENT) ||
                (force_client != FORCE_CLIENT_YES && pinfo->p2p_dir == P2P_DIR_RECV);
    }

    if (protocol == BTSDP_HARDCOPY_CONTROL_CHANNEL_PROTOCOL_UUID) {
        offset = dissect_control(tvb, pinfo, main_tree, offset, is_client_message);
    } else if (protocol == BTSDP_HARDCOPY_DATA_CHANNEL_PROTOCOL_UUID) {
        offset = dissect_data(tvb, pinfo, main_tree, offset);
    } else if (protocol == BTSDP_HARDCOPY_NOTIFICATION_PROTOCOL_UUID) {
        offset = dissect_notification(tvb, pinfo, main_tree, offset, is_client_message);
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, "HCRP stream");
    }

    if (tvb_reported_length_remaining(tvb, offset)) {
        proto_item *pitem;

        pitem = proto_tree_add_item(main_tree, hf_bthcrp_data, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
        expert_add_info(pinfo, pitem, &ei_bthcrp_unexpected_data);
    }

    return offset;
}


void
proto_register_bthcrp(void)
{
    module_t *module;
    expert_module_t* expert_bthcrp;

    static hf_register_info hf[] = {
        { &hf_bthcrp_control_pdu_id,
            { "Control PDU ID",                  "bthcrp.control.pdu_id",
            FT_UINT16, BASE_HEX, VALS(control_pdu_id_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_transaction_id,
            { "Transaction ID",                  "bthcrp.control.transaction_id",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_parameter_length,
            { "Parameter Length",                "bthcrp.control.parameter_length",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_status,
            { "Status",                          "bthcrp.control.status",
            FT_UINT16, BASE_HEX, VALS(status_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_notification_pdu_id,
            { "Notification PDU ID",             "bthcrp.notification.pdu_id",
            FT_UINT16, BASE_HEX, VALS(notification_pdu_id_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_callback_context_id,
            { "Callback Context ID",             "bthcrp.callback.context_id",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_callback_timeout,
            { "Callback Timeout",                "bthcrp.callback.timeout",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_timeout,
            { "Timeout",                         "bthcrp.timeout",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_register,
            { "Register",                        "bthcrp.register",
            FT_UINT8, BASE_HEX, VALS(register_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_1284_id,
            { "1284 ID",                         "bthcrp.1284_id",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_start_byte,
            { "Start Byte",                      "bthcrp.start_byte",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_number_of_bytes,
            { "Number Of Bytes",                 "bthcrp.number_of_bytes",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_client_credit_granted,
            { "Client Credit Granted",           "bthcrp.client_credit_granted",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_server_credit_granted,
            { "Server Credit Granted",           "bthcrp.server_credit_granted",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_client_credit_return,
            { "Client Credit Return",            "bthcrp.client_credit_return",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_server_credit_return,
            { "Server Credit Return",            "bthcrp.server_credit_return",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_client_credit_query,
            { "Client Credit Query",             "bthcrp.client_credit_query",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_server_credit_query,
            { "Server Credit Query",             "bthcrp.server_credit_query",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_status_reserved_76,
            { "Reserved",                        "bthcrp.status.reserved76",
            FT_UINT8, BASE_DEC, NULL, 0xC0,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_status_paper_empty,
            { "Paper Empty",                     "bthcrp.status.paper_empty",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_status_select,
            { "Select",                          "bthcrp.status.select",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_status_not_error,
            { "Not Error",                       "bthcrp.status.not_error",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_bthcrp_control_status_reserved_20,
            { "Reserved",                        "bthcrp.status.reserved210",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_bthcrp_data,
            { "Data",                            "bthcrp.data",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        }
    };

    static gint *ett[] = {
        &ett_bthcrp
    };

    static ei_register_info ei[] = {
        { &ei_bthcrp_control_parameter_length, { "bthcrp.control_parameter_length.bad", PI_PROTOCOL, PI_WARN, "Length bad", EXPFILL }},
        { &ei_bthcrp_unexpected_data, { "bthcrp.unexpected_data", PI_PROTOCOL, PI_WARN, "Unexpected data", EXPFILL }},
    };

    proto_bthcrp = proto_register_protocol("Bluetooth HCRP Profile", "BT HCRP", "bthcrp");
    bthcrp_handle = register_dissector("bthcrp", dissect_bthcrp, proto_bthcrp);

    proto_register_field_array(proto_bthcrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_bthcrp = expert_register_protocol(proto_bthcrp);
    expert_register_field_array(expert_bthcrp, ei, array_length(ei));

    module = prefs_register_protocol(proto_bthcrp, NULL);
    prefs_register_static_text_preference(module, "hcrp.version",
            "Bluetooth Profile HCRP version: 1.2",
            "Version of profile supported by this dissector.");

    prefs_register_obsolete_preference(module, "hcrp.is_client");

    prefs_register_enum_preference(module, "hcrp.force_client", "Force Client",
         "If \"yes\" localhost will be treat as Client, \"no\" as Server",
         &force_client, force_client_enum, FALSE);

    prefs_register_uint_preference(module, "hcrp.control.psm", "L2CAP PSM for Control",
         "L2CAP PSM for Control",
         10, &psm_control);
    prefs_register_uint_preference(module, "hcrp.data.psm", "L2CAP PSM for Data",
         "L2CAP PSM for Data",
         10, &psm_data_stream);
    prefs_register_uint_preference(module, "hcrp.notification.psm", "L2CAP PSM for Notification",
         "L2CAP PSM for Notification",
         10, &psm_notification);
}

void
proto_reg_handoff_bthcrp(void)
{
    dissector_add_string("bluetooth.uuid", "12", bthcrp_handle);
    dissector_add_string("bluetooth.uuid", "14", bthcrp_handle);
    dissector_add_string("bluetooth.uuid", "16", bthcrp_handle);
    dissector_add_string("bluetooth.uuid", "1125", bthcrp_handle);
    dissector_add_string("bluetooth.uuid", "1126", bthcrp_handle);
    dissector_add_string("bluetooth.uuid", "1127", bthcrp_handle);

    dissector_add_for_decode_as("btl2cap.psm", bthcrp_handle);
    dissector_add_for_decode_as("btl2cap.cid", bthcrp_handle);
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
