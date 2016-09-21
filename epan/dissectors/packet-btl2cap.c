/* packet-btl2cap.c
 * Routines for the Bluetooth L2CAP dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *  From: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>

#include <wiretap/wtap.h>

#include "packet-bluetooth.h"
#include "packet-bthci_acl.h"
#include "packet-btsdp.h"
#include "packet-btl2cap.h"

/* Initialize the protocol and registered fields */
int proto_btl2cap = -1;

static int hf_btl2cap_length = -1;
static int hf_btl2cap_cid = -1;
static int hf_btl2cap_payload = -1;
static int hf_btl2cap_command = -1;
static int hf_btl2cap_cmd_code = -1;
static int hf_btl2cap_cmd_ident = -1;
static int hf_btl2cap_cmd_length = -1;
static int hf_btl2cap_cmd_data = -1;
static int hf_btl2cap_psm = -1;
static int hf_btl2cap_psm_dynamic = -1;
static int hf_btl2cap_scid = -1;
static int hf_btl2cap_dcid = -1;
static int hf_btl2cap_icid = -1;
static int hf_btl2cap_controller = -1;
static int hf_btl2cap_dcontroller = -1;
static int hf_btl2cap_result = -1;
static int hf_btl2cap_move_result = -1;
static int hf_btl2cap_move_confirmation_result = -1;
static int hf_btl2cap_status = -1;
static int hf_btl2cap_rej_reason = -1;
static int hf_btl2cap_sig_mtu = -1;
static int hf_btl2cap_info_mtu = -1;
static int hf_btl2cap_info_flowcontrol = -1;
static int hf_btl2cap_info_retransmission = -1;
static int hf_btl2cap_info_bidirqos = -1;
static int hf_btl2cap_info_enh_retransmission = -1;
static int hf_btl2cap_info_streaming = -1;
static int hf_btl2cap_info_fcs = -1;
static int hf_btl2cap_info_flow_spec = -1;
static int hf_btl2cap_info_fixedchan = -1;
static int hf_btl2cap_info_fixedchans = -1;
static int hf_btl2cap_info_fixedchans_null = -1;
static int hf_btl2cap_info_fixedchans_signal = -1;
static int hf_btl2cap_info_fixedchans_connless = -1;
static int hf_btl2cap_info_fixedchans_amp_man = -1;
static int hf_btl2cap_info_fixedchans_amp_test = -1;
static int hf_btl2cap_info_window = -1;
static int hf_btl2cap_info_unicast = -1;
static int hf_btl2cap_info_type = -1;
static int hf_btl2cap_info_result = -1;
static int hf_btl2cap_configuration_result = -1;
static int hf_btl2cap_info_extfeatures = -1;
static int hf_btl2cap_option = -1;
static int hf_btl2cap_option_type = -1;
static int hf_btl2cap_option_length = -1;
static int hf_btl2cap_option_mtu = -1;
static int hf_btl2cap_option_flushTO = -1;
static int hf_btl2cap_option_flush_to_us = -1;
static int hf_btl2cap_option_flags = -1;
static int hf_btl2cap_option_service_type = -1;
static int hf_btl2cap_option_tokenrate = -1;
static int hf_btl2cap_option_tokenbucketsize = -1;
static int hf_btl2cap_option_peakbandwidth = -1;
static int hf_btl2cap_option_latency = -1;
static int hf_btl2cap_option_delayvariation = -1;
static int hf_btl2cap_option_retransmissionmode = -1;
static int hf_btl2cap_option_txwindow = -1;
static int hf_btl2cap_option_maxtransmit = -1;
static int hf_btl2cap_option_retransmittimeout = -1;
static int hf_btl2cap_option_monitortimeout = -1;
static int hf_btl2cap_option_mps = -1;
static int hf_btl2cap_option_fcs = -1;
static int hf_btl2cap_option_window = -1;
static int hf_btl2cap_option_identifier = -1;
static int hf_btl2cap_option_sdu_size = -1;
static int hf_btl2cap_option_sdu_arrival_time = -1;
static int hf_btl2cap_option_access_latency = -1;
static int hf_btl2cap_control = -1;
static int hf_btl2cap_control_sar = -1;
static int hf_btl2cap_control_reqseq = -1;
static int hf_btl2cap_control_txseq = -1;
static int hf_btl2cap_control_retransmissiondisable = -1;
static int hf_btl2cap_control_supervisory = -1;
static int hf_btl2cap_control_type = -1;
static int hf_btl2cap_fcs = -1;
static int hf_btl2cap_sdulength = -1;
static int hf_btl2cap_continuation_to = -1;
static int hf_btl2cap_reassembled_in = -1;
static int hf_btl2cap_min_interval = -1;
static int hf_btl2cap_max_interval = -1;
static int hf_btl2cap_slave_latency = -1;
static int hf_btl2cap_timeout_multiplier = -1;
static int hf_btl2cap_conn_param_result = -1;
static int hf_btl2cap_credits = -1;
static int hf_btl2cap_initial_credits = -1;
static int hf_btl2cap_le_result = -1;
static int hf_btl2cap_le_psm = -1;
static int hf_btl2cap_flags_reserved = -1;
static int hf_btl2cap_flags_continuation = -1;
static int hf_btl2cap_data = -1;
static int hf_btl2cap_service = -1;
static int hf_btl2cap_connect_in_frame = -1;
static int hf_btl2cap_disconnect_in_frame = -1;

/* Initialize the subtree pointers */
static gint ett_btl2cap = -1;
static gint ett_btl2cap_cmd = -1;
static gint ett_btl2cap_option = -1;
static gint ett_btl2cap_extfeatures = -1;
static gint ett_btl2cap_fixedchans = -1;
static gint ett_btl2cap_control = -1;

static expert_field ei_btl2cap_parameter_mismatch = EI_INIT;
static expert_field ei_btl2cap_sdulength_bad = EI_INIT;
static expert_field ei_btl2cap_length_bad = EI_INIT;
static expert_field ei_btl2cap_unknown_command_code = EI_INIT;

/* Initialize dissector table */
static dissector_table_t l2cap_psm_dissector_table;
static dissector_table_t l2cap_cid_dissector_table;

/* This table maps cid values to psm values.
 * The same table is used both for SCID and DCID.
 * For Remote CIDs (Receive Request SCID or Sent Response DCID)
 * we 'or' the CID with 0x80000000 in this table
 */
static wmem_tree_t *cid_to_psm_table  = NULL;

typedef struct _config_data_t {
    guint8      mode;
    guint8      txwindow;
    wmem_tree_t *start_fragments;  /* indexed by pinfo->num */
} config_data_t;

typedef struct _sdu_reassembly_t
{
    guint8  *reassembled;
    guint8   seq;
    guint32  first_frame;
    guint32  last_frame;
    guint16  tot_len;
    int      cur_off;           /* counter used by reassembly */
} sdu_reassembly_t;

typedef struct _psm_data_t {
    guint32       interface_id;
    guint32       adapter_id;
    guint32       chandle;
    guint32       local_cid;
    guint32       remote_cid;
    guint16       psm;
    gboolean      local_service;
    guint32       connect_in_frame;
    guint32       disconnect_in_frame;
    config_data_t in;
    config_data_t out;
} psm_data_t;

static const value_string command_code_vals[] = {
    { 0x01,   "Command Reject" },
    { 0x02,   "Connection Request" },
    { 0x03,   "Connection Response" },
    { 0x04,   "Configure Request" },
    { 0x05,   "Configure Response" },
    { 0x06,   "Disconnection Request" },
    { 0x07,   "Disconnection Response" },
    { 0x08,   "Echo Request" },
    { 0x09,   "Echo Response" },
    { 0x0A,   "Information Request" },
    { 0x0B,   "Information Response" },
    { 0x0C,   "Create Channel Request" },
    { 0x0D,   "Create Channel Response" },
    { 0x0E,   "Move Channel Request" },
    { 0x0F,   "Move Channel Response" },
    { 0x10,   "Move Channel Confirmation" },
    { 0x11,   "Move Channel Confirmation Response" },
    { 0x12,   "Connection Parameter Update Request" },
    { 0x13,   "Connection Parameter Update Response" },
    { 0x14,   "LE Credit Based Connection Request" },
    { 0x15,   "LE Credit Based Connection Response" },
    { 0x16,   "LE Flow Control Credit" },
    { 0, NULL }
};


static const value_string psm_vals[] = {
    { 0x0001, "SDP" },
    { 0x0003, "RFCOMM" },
    { 0x0005, "TCS-BIN" },
    { 0x0007, "TCS-BIN-CORDLESS" },
    { 0x000F, "BNEP" },
    { 0x0011, "HID-Control" },
    { 0x0013, "HID-Interrupt" },
    { 0x0015, "UPnP" },
    { 0x0017, "AVCTP-Control" },
    { 0x0019, "AVDTP" },
    { 0x001B, "AVCTP-Browsing" },
    { 0x001D, "UDI_C-Plane" },
    { 0x001F, "ATT" },
    { 0x0021, "3DSP" },
    { 0x0023, "IPSP" },
    { 0x0025, "OTS" },
    { 0, NULL }
};
value_string_ext ext_psm_vals = VALUE_STRING_EXT_INIT(psm_vals);

static const value_string result_vals[] = {
    { 0x0000, "Successful" },
    { 0x0001, "Pending" },
    { 0x0002, "Refused - PSM not supported" },
    { 0x0003, "Refused - security block" },
    { 0x0004, "Refused - no resources available" },
    { 0x0005, "Refused - Controller ID not supported" },
    { 0, NULL }
};

static const value_string le_result_vals[] = {
    { 0x0000, "Connection Successful" },
    { 0x0002, "Connection Refused - LE_PSM Not Supported" },
    { 0x0004, "Connection Refused - No Resources Available" },
    { 0x0005, "Connection Refused - Insufficient Authentication" },
    { 0x0006, "Connection Refused - Insufficient Authorization" },
    { 0x0007, "Connection Refused - Insufficient Encryption Key Size" },
    { 0x0008, "Connection Refused - Insufficient Encryption" },
    { 0, NULL }
};

static const value_string move_result_vals[] = {
    { 0x0000, "Success" },
    { 0x0001, "Pending" },
    { 0x0002, "Refused - Controller ID not supported" },
    { 0x0003, "Refused - New Controller ID is same as old" },
    { 0x0004, "Refused - Configuration not supported" },
    { 0x0005, "Refused - Move Channel collision" },
    { 0x0006, "Refused - Channel not allowed to be moved" },
    { 0, NULL }
};

static const value_string move_result_confirmation_vals[] = {
    { 0x0000,   "Success - both sides succeed" },
    { 0x0001,   "Failure - one or both sides refuse" },
    { 0, NULL }
};

static const value_string configuration_result_vals[] = {
    { 0x0000, "Success"},
    { 0x0001, "Failure - unacceptable parameters" },
    { 0x0002, "Failure - reject (no reason provided)" },
    { 0x0003, "Failure - unknown options" },
    { 0x0004, "Pending" },
    { 0x0005, "Failure - flow spec rejected" },
    { 0, NULL }
};

static const value_string conn_param_result_vals[] = {
    { 0x0000,   "Accepted" },
    { 0x0001,   "Rejected" },
    { 0, NULL }
};

static const value_string status_vals[] = {
    { 0x0000, "No further information available" },
    { 0x0001, "Authentication pending" },
    { 0x0002, "Authorization pending" },
    { 0, NULL }
};

static const value_string reason_vals[] = {
    { 0x0000, "Command not understood" },
    { 0x0001, "Signaling MTU exceeded" },
    { 0x0002, "Invalid CID in request" },
    { 0, NULL }
};

static const value_string info_type_vals[] = {
    { 0x0001, "Connectionless MTU" },
    { 0x0002, "Extended Features Mask" },
    { 0x0003, "Fixed Channels Supported" },
    { 0, NULL }
};

static const value_string info_result_vals[] = {
    { 0x0000, "Success" },
    { 0x0001, "Not Supported" },
    { 0, NULL }
};

static const value_string option_servicetype_vals[] = {
    { 0x00,   "No traffic" },
    { 0x01,   "Best effort (Default)" },
    { 0x02,   "Guaranteed" },
    { 0, NULL }
};

static const value_string option_type_vals[] = {
    { 0x01,   "Maximum Transmission Unit" },
    { 0x02,   "Flush Timeout" },
    { 0x03,   "Quality of Service" },
    { 0x04,   "Retransmission and Flow Control" },
    { 0x05,   "FCS" },
    { 0x06,   "Extended Flow Specification" },
    { 0x07,   "Extended Window Size" },
    { 0, NULL }
};

static const value_string option_retransmissionmode_vals[] = {
    { 0x00,   "Basic Mode" },
    { 0x01,   "Retransmission Mode" },
    { 0x02,   "Flow Control Mode" },
    { 0x03,   "Enhanced Retransmission Mode" },
    { 0x04,   "Streaming Mode" },
    { 0, NULL }
};

static const value_string control_sar_vals[] = {
    { 0x00,   "Unsegmented" },
    { 0x01,   "Start" },
    { 0x02,   "End" },
    { 0x03,   "Continuation" },
    { 0, NULL }
};

static const value_string control_supervisory_vals[] = {
    { 0x00,   "RR" },
    { 0x01,   "REJ" },
    { 0x02,   "RNR" },
    { 0x03,   "SREJ" },
    { 0, NULL }
};

static const value_string control_type_vals[] = {
    { 0x00,   "I-Frame" },
    { 0x01,   "S-Frame" },
    { 0, NULL }
};

static const value_string option_fcs_vals[] = {
    { 0x00,   "No FCS" },
    { 0x01,   "16-bit FCS" },
    { 0, NULL }
};

static const value_string ctrl_id_code_vals[] = {
    { 0x00,   "Bluetooth BR/EDR" },
    { 0x01,   "Wifi 802.11" },
    { 0, NULL }
};

static const range_string cid_rvals[] = {
    { 0x0000, 0x0000,  "Null identifier" },
    { 0x0001, 0x0001,  "L2CAP Signaling Channel" },
    { 0x0002, 0x0002,  "Connectionless Channel" },
    { 0x0003, 0x0003,  "AMP Manager Protocol" },
    { 0x0004, 0x0004,  "Attribute Protocol" },
    { 0x0005, 0x0005,  "Low Energy L2CAP Signaling Channel" },
    { 0x0006, 0x0006,  "Security Manager Protocol" },
    { 0x0007, 0x003E,  "Reserved" },
    { 0x003F, 0x003F,  "AMP Test Manager" },
    { 0x0040, 0xFFFF,  "Dynamically Allocated Channel" },
    { 0, 0, NULL }
};

static const range_string le_psm_rvals[] = {
    { 0x0001, 0x007F,  "Fixed, SIG Assigned" },
    { 0x0080, 0x00FF,  "Dynamically Allocated" },
    { 0x0100, 0xFFFF,  "Reserved" },
    { 0, 0, NULL }
};

#define PROTO_DATA_BTL2CAP_CID        0
#define PROTO_DATA_BTL2CAP_PSM        1

void proto_register_btl2cap(void);
void proto_reg_handoff_btl2cap(void);

static void btl2cap_cid_prompt(packet_info *pinfo, gchar* result)
{
    guint16 *value_data;

    value_data = (guint16 *) p_get_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_CID);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "L2CAP CID 0x%04x as", (guint) *value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown L2CAP CID");
}

static gpointer btl2cap_cid_value(packet_info *pinfo)
{
    guint16 *value_data;

    value_data = (guint16 *) p_get_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_CID);

    if (value_data)
        return GUINT_TO_POINTER((gulong)*value_data);

    return NULL;
}

static void btl2cap_psm_prompt(packet_info *pinfo, gchar* result)
{
    guint16 *value_data;

    value_data = (guint16 *) p_get_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_PSM);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "L2CAP PSM 0x%04x as", (guint) *value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown L2CAP PSM");
}

static gpointer btl2cap_psm_value(packet_info *pinfo)
{
    guint16 *value_data;

    value_data = (guint16 *) p_get_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_PSM);

    if (value_data)
        return GUINT_TO_POINTER((gulong)*value_data);

    return NULL;
}

static guint16
get_service_uuid(packet_info *pinfo, btl2cap_data_t *l2cap_data, guint16 psm, gboolean is_local_psm)
{
    wmem_tree_key_t    key[10];
    guint32            k_interface_id;
    guint32            k_adapter_id;
    guint32            k_sdp_psm;
    guint32            k_direction;
    guint32            k_bd_addr_oui;
    guint32            k_bd_addr_id;
    guint32            k_service_type;
    guint32            k_service_channel;
    guint32            k_frame_number;
    guint32            interface_id;
    guint32            adapter_id;
    guint32            remote_bd_addr_oui;
    guint32            remote_bd_addr_id;
    service_info_t    *service_info;

    interface_id       = l2cap_data->interface_id;
    adapter_id         = l2cap_data->adapter_id;

    k_interface_id    = interface_id;
    k_adapter_id      = adapter_id;
    k_sdp_psm         = SDP_PSM_DEFAULT;
    k_direction       = (is_local_psm) ? P2P_DIR_SENT : P2P_DIR_RECV;
    if (k_direction == P2P_DIR_RECV) {
        k_bd_addr_oui = l2cap_data->remote_bd_addr_oui;
        k_bd_addr_id  = l2cap_data->remote_bd_addr_id;
    } else {
        k_bd_addr_oui = 0;
        k_bd_addr_id  = 0;
    }

    remote_bd_addr_oui = k_bd_addr_oui;
    remote_bd_addr_id  = k_bd_addr_id;

    k_service_type    = BTSDP_L2CAP_PROTOCOL_UUID;
    k_service_channel = psm;
    k_frame_number    = pinfo->num;

    key[0].length = 1;
    key[0].key = &k_interface_id;
    key[1].length = 1;
    key[1].key = &k_adapter_id;
    key[2].length = 1;
    key[2].key = &k_sdp_psm;
    key[3].length = 1;
    key[3].key = &k_direction;
    key[4].length = 1;
    key[4].key = &k_bd_addr_oui;
    key[5].length = 1;
    key[5].key = &k_bd_addr_id;
    key[6].length = 1;
    key[6].key = &k_service_type;
    key[7].length = 1;
    key[7].key = &k_service_channel;
    key[8].length = 1;
    key[8].key = &k_frame_number;
    key[9].length = 0;
    key[9].key = NULL;

    service_info = btsdp_get_service_info(key);

    if (service_info && service_info->interface_id == interface_id &&
            service_info->adapter_id == adapter_id &&
            service_info->sdp_psm == SDP_PSM_DEFAULT &&
            ((service_info->direction == P2P_DIR_RECV &&
            service_info->bd_addr_oui == remote_bd_addr_oui &&
            service_info->bd_addr_id == remote_bd_addr_id) ||
            (service_info->direction != P2P_DIR_RECV &&
            service_info->bd_addr_oui == 0 &&
            service_info->bd_addr_id == 0)) &&
            service_info->type == BTSDP_L2CAP_PROTOCOL_UUID &&
            service_info->channel == psm) {
        return service_info->uuid.bt_uuid;
    }

    return 0;
}

static int
dissect_comrej(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint16 reason;

    reason  = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_rej_reason, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    switch (reason) {
    case 0x0000: /* Command not understood */
        break;

    case 0x0001: /* Signaling MTU exceeded */
        proto_tree_add_item(tree, hf_btl2cap_sig_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        break;

    case 0x0002: /* Invalid CID in requets */
        proto_tree_add_item(tree, hf_btl2cap_scid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_btl2cap_dcid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        break;

    default:
        break;
    }

    return offset;
}

static int
dissect_connrequest(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, proto_tree *command_tree, gboolean is_ch_request,
        bthci_acl_data_t *acl_data, btl2cap_data_t *l2cap_data)
{
    guint16            scid;
    guint16            psm;
    const gchar       *psm_str = "<NONE>";

    psm = tvb_get_letohs(tvb, offset);

    if (p_get_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_PSM ) == NULL) {
        guint16 *value_data;

        value_data = wmem_new(wmem_file_scope(), guint16);
        *value_data = psm;

        p_add_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_PSM, value_data);
    }

    if (psm < BTL2CAP_DYNAMIC_PSM_START) {
        proto_tree_add_item(command_tree, hf_btl2cap_psm, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        psm_str = val_to_str_const(psm, psm_vals, "Unknown PSM");
    } else {
        proto_item  *item;
        guint16      uuid;

        item = proto_tree_add_item(command_tree, hf_btl2cap_psm_dynamic, tvb, offset, 2, ENC_LITTLE_ENDIAN);

        uuid = get_service_uuid(pinfo, l2cap_data, psm, (pinfo->p2p_dir == P2P_DIR_RECV) ? TRUE : FALSE);
        if (uuid) {
            psm_str = val_to_str_ext_const(uuid, &bluetooth_uuid_vals_ext, "Unknown PSM");
            proto_item_append_text(item, " (%s)", psm_str);
        }
    }
    offset += 2;

    scid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(command_tree, hf_btl2cap_scid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s, SCID: 0x%04x)", psm_str, scid);

    if (is_ch_request) {
        proto_tree_add_item(command_tree, hf_btl2cap_controller, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset += 1;
    }

    if (!pinfo->fd->flags.visited) {
        wmem_tree_key_t    key[6];
        guint32            k_interface_id;
        guint32            k_adapter_id;
        guint32            k_chandle;
        guint32            k_cid;
        guint32            k_frame_number;
        guint32            interface_id;
        guint32            adapter_id;
        guint32            chandle;
        psm_data_t        *psm_data;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->phdr->interface_id;
        else
            interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = (acl_data) ? acl_data->adapter_id : HCI_ADAPTER_DEFAULT;
        chandle      = (acl_data) ? acl_data->chandle : 0;

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = scid | ((pinfo->p2p_dir == P2P_DIR_RECV) ? 0x80000000 : 0x00000000);
        k_frame_number = pinfo->num;

        psm_data = wmem_new(wmem_file_scope(), psm_data_t);
        if (pinfo->p2p_dir == P2P_DIR_RECV) {
            psm_data->local_cid = BTL2CAP_UNKNOWN_CID;
            psm_data->remote_cid = scid |  0x80000000;
        } else {
            psm_data->local_cid = scid;
            psm_data->remote_cid = BTL2CAP_UNKNOWN_CID;
        }
        psm_data->psm  = psm;
        psm_data->local_service = (pinfo->p2p_dir == P2P_DIR_RECV) ? TRUE : FALSE;
        psm_data->in.mode      = 0;
        psm_data->in.txwindow  = 0;
        psm_data->in.start_fragments = wmem_tree_new(wmem_file_scope());
        psm_data->out.mode     = 0;
        psm_data->out.txwindow = 0;
        psm_data->out.start_fragments = wmem_tree_new(wmem_file_scope());
        psm_data->interface_id = k_interface_id;
        psm_data->adapter_id   = k_adapter_id;
        psm_data->chandle      = k_chandle;
        psm_data->connect_in_frame = pinfo->num;
        psm_data->disconnect_in_frame = max_disconnect_in_frame;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        wmem_tree_insert32_array(cid_to_psm_table, key, psm_data);
    }

    if (l2cap_data) {
        proto_item        *sub_item;
        guint32            bt_uuid = 0;
        guint32            disconnect_in_frame = 0;
        psm_data_t        *psm_data;
        wmem_tree_key_t    key[6];
        guint32            k_interface_id;
        guint32            k_adapter_id;
        guint32            k_chandle;
        guint32            k_cid;
        guint32            k_frame_number;
        guint32            interface_id;
        guint32            adapter_id;
        guint32            chandle;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->phdr->interface_id;
        else
            interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = (acl_data) ? acl_data->adapter_id : HCI_ADAPTER_DEFAULT;
        chandle      = (acl_data) ? acl_data->chandle : 0;

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = scid | ((pinfo->p2p_dir == P2P_DIR_RECV) ? 0x80000000 : 0x00000000);
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                psm_data->local_cid == k_cid) {
            bt_uuid = get_service_uuid(pinfo, l2cap_data, psm_data->psm, psm_data->local_service);
            disconnect_in_frame = psm_data->disconnect_in_frame;
        }

        if (bt_uuid) {
            sub_item = proto_tree_add_uint(tree, hf_btl2cap_service, tvb, 0, 0, bt_uuid);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        if (disconnect_in_frame < max_disconnect_in_frame) {
            sub_item = proto_tree_add_uint(tree, hf_btl2cap_disconnect_in_frame, tvb, 0, 0, disconnect_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    }

    return offset;
}

static int
dissect_movechanrequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint16 icid;
    guint8  ctrl_id;

    icid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_icid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    ctrl_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_dcontroller, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (ICID: 0x%04x, move to %s)", icid,
                    val_to_str_const(ctrl_id, ctrl_id_code_vals, "Unknown controller"));

    return offset;
}

static int
dissect_options(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int length, config_data_t *config_data)
{
    proto_item *ti_option;
    proto_tree *ti_option_subtree;
    guint8      option_type, option_length;

    if (config_data) {
        config_data->mode     = 0;
        config_data->txwindow = 0;
    }

    while (length > 0) {
        option_type   = tvb_get_guint8(tvb, offset);
        option_length = tvb_get_guint8(tvb, offset + 1);

        ti_option = proto_tree_add_none_format(tree,
                hf_btl2cap_option, tvb,
                offset, option_length + 2,
                "Option: ");
        ti_option_subtree = proto_item_add_subtree(ti_option, ett_btl2cap_option);
        proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_length, tvb, offset + 1, 1, ENC_LITTLE_ENDIAN);
        offset += 2;

        if (option_length != 0) {
            switch (option_type) {
            case 0x01: /* MTU */
                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_item_append_text(ti_option, "MTU");
                break;

            case 0x02: /* Flush timeout */
                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_flushTO, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_item_append_text(ti_option, "Flush Timeout");
                break;

            case 0x03: /* QOS */
                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_service_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_tokenrate, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_tokenbucketsize, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_peakbandwidth, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_latency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_delayvariation, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_item_append_text(ti_option, "QOS");
                break;

            case 0x04: /* Retransmission and Flow Control*/
                if (config_data)
                {
                    config_data->mode     = tvb_get_guint8(tvb, offset);
                    config_data->txwindow = tvb_get_guint8(tvb, offset + 1);
                }
                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_retransmissionmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_txwindow, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_maxtransmit, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_retransmittimeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_monitortimeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_mps, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_item_append_text(ti_option, "Retransmission and Flow Control");
                break;

            case 0x05: /* FCS */
                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_fcs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_item_append_text(ti_option, "FCS");
                break;

            case 0x06: /* Extended Flow Specification */
                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_identifier, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_service_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
                offset += 1;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_sdu_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_sdu_arrival_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_access_latency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_flush_to_us, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;

                proto_item_append_text(ti_option, "Extended Flow Specification");
                break;

            case 0x07: /* Extended Window Size */
                proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_window, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_item_append_text(ti_option, "Extended Window Size");
                break;

            default:
                proto_item_append_text(ti_option, "unknown");
                offset += option_length;
                break;
            }
        }
        length -= (option_length + 2);
    }
    return offset;
}



static int
dissect_configrequest(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, guint16 length, bthci_acl_data_t *acl_data)
{
    guint16  dcid;

    dcid = tvb_get_letohs(tvb, offset);

    proto_tree_add_item(tree, hf_btl2cap_dcid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (DCID: 0x%04x)", dcid);

    proto_tree_add_item(tree, hf_btl2cap_flags_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_btl2cap_flags_continuation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        psm_data_t        *psm_data;
        config_data_t     *config_data;
        wmem_tree_key_t    key[6];
        guint32            k_interface_id;
        guint32            k_adapter_id;
        guint32            k_chandle;
        guint32            k_cid;
        guint32            k_frame_number;
        guint32            interface_id;
        guint32            adapter_id;
        guint32            chandle;
        guint32            cid;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->phdr->interface_id;
        else
            interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = (acl_data) ? acl_data->adapter_id : HCI_ADAPTER_DEFAULT;
        chandle      = (acl_data) ? acl_data->chandle : 0;
        cid          = dcid | ((pinfo->p2p_dir == P2P_DIR_RECV) ? 0x00000000 : 0x80000000);

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = cid;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                ((pinfo->p2p_dir == P2P_DIR_SENT && psm_data->remote_cid == cid) ||
                (pinfo->p2p_dir == P2P_DIR_RECV && psm_data->local_cid == cid)) &&
                psm_data->disconnect_in_frame > pinfo->num) {
            if (pinfo->p2p_dir == P2P_DIR_RECV)
                config_data = &(psm_data->out);
            else
                config_data = &(psm_data->in);
        } else {
            config_data = NULL;
        }
        offset = dissect_options(tvb, offset, pinfo, tree, length - 4, config_data);
    }

    return offset;
}


static int
dissect_inforequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint16 info_type;

    info_type = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_info_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset   += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str_const(info_type, info_type_vals, "Unknown type"));
    return offset;
}

static int
dissect_inforesponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint16     info_type, result;

    info_type = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_info_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset   += 2;

    result    = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_info_result, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset   += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s, %s)",
                        val_to_str_const(info_type, info_type_vals, "Unknown type"),
                        val_to_str_const(result, info_result_vals, "Unknown result"));

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_item *ti_features;
        proto_tree *ti_features_subtree;
        guint32     features;

        switch (info_type) {
        case 0x0001: /* Connectionless MTU */
            proto_tree_add_item(tree, hf_btl2cap_info_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;

            break;
        case 0x0002: /* Extended Features */
            ti_features = proto_tree_add_none_format(tree,
                    hf_btl2cap_info_extfeatures, tvb,
                    offset, 4,
                    "Features: ");
            ti_features_subtree = proto_item_add_subtree(ti_features, ett_btl2cap_extfeatures);
            features = tvb_get_letohl(tvb, offset);
            if (features & 0x1)
                proto_item_append_text(ti_features, "FlowControl ");
            if (features & 0x2)
                proto_item_append_text(ti_features, "Retransmission ");
            if (features & 0x4)
                proto_item_append_text(ti_features, "BiDirQOS ");
            if (features & 0x8)
                proto_item_append_text(ti_features, "EnhRetransmission ");
            if (features & 0x10)
                proto_item_append_text(ti_features, "Streaming ");
            if (features & 0x20)
                proto_item_append_text(ti_features, "FCS ");
            if (features & 0x40)
                proto_item_append_text(ti_features, "FlowSpec ");
            if (features & 0x80)
                proto_item_append_text(ti_features, "FixedChan ");
            if (features & 0x100)
                proto_item_append_text(ti_features, "WindowSize ");
            if (features & 0x200)
                proto_item_append_text(ti_features, "Unicast ");
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_flowcontrol,         tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_retransmission,      tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_bidirqos,            tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_enh_retransmission,  tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_streaming,           tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_fcs,                 tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_flow_spec,           tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_fixedchan,           tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_window,              tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_unicast,             tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;

        case 0x0003: /* Fixed Channels Supported */
            ti_features = proto_tree_add_none_format(tree,
                    hf_btl2cap_info_fixedchans, tvb,
                    offset, 8,
                    "Fixed Channels Supported:");
            ti_features_subtree = proto_item_add_subtree(ti_features, ett_btl2cap_fixedchans);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_fixedchans_null,     tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_fixedchans_signal,   tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_fixedchans_connless, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_fixedchans_amp_man,  tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(ti_features_subtree, hf_btl2cap_info_fixedchans_amp_test, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            break;

        default:
            proto_tree_add_item(tree, hf_btl2cap_cmd_data, tvb, offset, -1, ENC_NA);
            offset += tvb_reported_length_remaining(tvb, offset);

            break;
        }
    }

    return offset;
}

static int
dissect_configresponse(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, guint16 length, bthci_acl_data_t *acl_data)
{
    guint16            scid;
    guint16            result;


    scid = tvb_get_letohs(tvb, offset);

    proto_tree_add_item(tree, hf_btl2cap_scid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_btl2cap_flags_reserved, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(tree, hf_btl2cap_flags_continuation, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    result = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_configuration_result, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s (SCID: 0x%04x)",
                    val_to_str_const(result, configuration_result_vals, "Unknown"), scid);

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        psm_data_t        *psm_data;
        config_data_t     *config_data;
        wmem_tree_key_t    key[6];
        guint32            k_interface_id;
        guint32            k_adapter_id;
        guint32            k_chandle;
        guint32            k_cid;
        guint32            k_frame_number;
        guint32            interface_id;
        guint32            adapter_id;
        guint32            chandle;
        guint32            cid;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->phdr->interface_id;
        else
            interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = (acl_data) ? acl_data->adapter_id : HCI_ADAPTER_DEFAULT;
        chandle      = (acl_data) ? acl_data->chandle : 0;
        cid          = scid | ((pinfo->p2p_dir == P2P_DIR_RECV) ? 0x00000000 : 0x80000000);

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = cid;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                ((pinfo->p2p_dir == P2P_DIR_SENT && psm_data->local_cid == cid) ||
                (pinfo->p2p_dir == P2P_DIR_RECV && psm_data->remote_cid == cid)) &&
                psm_data->disconnect_in_frame > pinfo->num) {
            if (pinfo->p2p_dir == P2P_DIR_RECV)
                config_data = &(psm_data->out);
            else
                config_data = &(psm_data->in);
        } else {
            config_data = NULL;
        }
        offset = dissect_options(tvb, offset, pinfo, tree, length - 6, config_data);
    }

    return offset;
}

static int
dissect_connresponse(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, bthci_acl_data_t *acl_data)
{
    guint16            scid, dcid, result;

    dcid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_dcid,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    scid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_scid,   tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    result = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_result, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_btl2cap_status, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (result == 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " - Success (SCID: 0x%04x, DCID: 0x%04x)", scid, dcid);
    }
    else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " - %s (SCID: 0x%04x)",
                        val_to_str_const(result, result_vals, "Unknown"), scid);
    }

    if (pinfo->fd->flags.visited == 0) {
        psm_data_t        *psm_data;
        wmem_tree_key_t    key[6];
        guint32            k_interface_id;
        guint32            k_adapter_id;
        guint32            k_chandle;
        guint32            k_cid;
        guint32            k_frame_number;
        guint32            interface_id;
        guint32            adapter_id;
        guint32            chandle;
        guint32            cid;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->phdr->interface_id;
        else
            interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = (acl_data) ? acl_data->adapter_id : HCI_ADAPTER_DEFAULT;
        chandle      = (acl_data) ? acl_data->chandle : 0;
        cid          = scid | ((pinfo->p2p_dir == P2P_DIR_RECV) ? 0x00000000 : 0x80000000);

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = cid;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                ((pinfo->p2p_dir == P2P_DIR_SENT && psm_data->remote_cid == cid) ||
                (pinfo->p2p_dir == P2P_DIR_RECV && psm_data->local_cid == cid)) &&
                psm_data->disconnect_in_frame > pinfo->num) {
            cid = dcid | ((pinfo->p2p_dir == P2P_DIR_RECV) ? 0x80000000 : 0x00000000);

            k_interface_id = interface_id;
            k_adapter_id   = adapter_id;
            k_chandle      = chandle;
            k_cid          = cid;
            k_frame_number = pinfo->num;

            key[0].length = 1;
            key[0].key    = &k_interface_id;
            key[1].length = 1;
            key[1].key    = &k_adapter_id;
            key[2].length = 1;
            key[2].key    = &k_chandle;
            key[3].length = 1;
            key[3].key    = &k_cid;
            key[4].length = 1;
            key[4].key    = &k_frame_number;
            key[5].length = 0;
            key[5].key    = NULL;

            if (pinfo->p2p_dir == P2P_DIR_RECV)
                psm_data->remote_cid = cid;
            else
                psm_data->local_cid = cid;

            wmem_tree_insert32_array(cid_to_psm_table, key, psm_data);
        }
    }

    return offset;
}

static int
dissect_chanresponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, bthci_acl_data_t *acl_data)
{
    return dissect_connresponse(tvb, offset, pinfo, tree, acl_data);
}

static int
dissect_movechanresponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint16 icid, result;

    icid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_icid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    result = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_move_result, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (ICID: 0x%04x, %s)", icid,
                    val_to_str_const(result, move_result_vals, "Unknown result"));

    return offset;
}

static int
dissect_movechanconfirmation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint16 icid, result;

    icid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_icid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    result = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_move_confirmation_result, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (ICID: 0x%04x, %s)", icid,
                    val_to_str_const(result, move_result_confirmation_vals, "Unknown result"));

    return offset;
}

static int
dissect_movechanconfirmationresponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint16 icid;

    icid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_icid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (ICID: 0x%04x)", icid);
    return offset;
}

static int
dissect_connparamrequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item;
    guint16 max_interval, slave_latency;

    item = proto_tree_add_item(tree, hf_btl2cap_min_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset) * 1.25);
    offset += 2;
    item = proto_tree_add_item(tree, hf_btl2cap_max_interval, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_item_append_text(item, " (%g msec)",  tvb_get_letohs(tvb, offset) * 1.25);
    max_interval = tvb_get_letohs(tvb, offset);
    offset += 2;
    item = proto_tree_add_item(tree, hf_btl2cap_slave_latency, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_item_append_text(item, " LL Connection Events");
    slave_latency = tvb_get_letohs(tvb, offset);

    if(slave_latency >= 500 || slave_latency > 10.0 * tvb_get_letohs(tvb, offset + 2) / (max_interval *1.25))
        expert_add_info(pinfo, item, &ei_btl2cap_parameter_mismatch);

    offset += 2;
    item = proto_tree_add_item(tree, hf_btl2cap_timeout_multiplier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_item_append_text(item, " (%g sec)",  tvb_get_letohs(tvb, offset) * 0.01);
    offset += 2;

    return offset;
}

static int
dissect_connparamresponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint16 result;

    result = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btl2cap_conn_param_result, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
                    val_to_str_const(result, conn_param_result_vals, "Unknown result"));

    return offset;
}

static int
dissect_disconnrequestresponse(tvbuff_t *tvb, int offset, packet_info *pinfo,
        proto_tree *tree, proto_tree *command_tree, bthci_acl_data_t *acl_data, btl2cap_data_t *l2cap_data,
        gboolean is_request)
{
    guint16       scid;
    guint16       dcid;
    guint         psm = 0;
    const gchar  *service_name = "Unknown";

    dcid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(command_tree, hf_btl2cap_dcid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    scid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(command_tree, hf_btl2cap_scid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (!pinfo->fd->flags.visited) {
        psm_data_t        *psm_data;
        wmem_tree_key_t    key[6];
        guint32            k_interface_id;
        guint32            k_adapter_id;
        guint32            k_chandle;
        guint32            k_cid;
        guint32            k_frame_number;
        guint32            interface_id;
        guint32            adapter_id;
        guint32            chandle;
        guint32            key_scid;
        guint32            key_dcid;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->phdr->interface_id;
        else
            interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = (acl_data) ? acl_data->adapter_id : HCI_ADAPTER_DEFAULT;
        chandle      = (acl_data) ? acl_data->chandle : 0;
        if ((is_request && pinfo->p2p_dir == P2P_DIR_SENT) ||
                (!is_request && pinfo->p2p_dir == P2P_DIR_RECV)) {
            key_dcid     = dcid | 0x80000000;
            key_scid     = scid;
        } else {
            key_dcid     = scid | 0x80000000;
            key_scid     = dcid;
        }

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = key_dcid;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                psm_data->remote_cid == key_dcid &&
                psm_data->disconnect_in_frame == max_disconnect_in_frame) {
            psm_data->disconnect_in_frame = pinfo->num;
        }

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = key_scid;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                psm_data->local_cid == key_scid &&
                psm_data->disconnect_in_frame == max_disconnect_in_frame) {
            psm_data->disconnect_in_frame = pinfo->num;
        }
    }

    if (l2cap_data) {
        proto_item        *sub_item;
        guint32            bt_uuid = 0;
        guint32            connect_in_frame = 0;
        psm_data_t        *psm_data;
        wmem_tree_key_t    key[6];
        guint32            k_interface_id;
        guint32            k_adapter_id;
        guint32            k_chandle;
        guint32            k_cid;
        guint32            k_frame_number;
        guint32            interface_id;
        guint32            adapter_id;
        guint32            chandle;
        guint32            key_dcid;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->phdr->interface_id;
        else
            interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = (acl_data) ? acl_data->adapter_id : HCI_ADAPTER_DEFAULT;
        chandle      = (acl_data) ? acl_data->chandle : 0;
        if ((is_request && pinfo->p2p_dir == P2P_DIR_SENT) ||
                (!is_request && pinfo->p2p_dir == P2P_DIR_RECV)) {
            key_dcid     = dcid | 0x80000000;
        } else {
            key_dcid     = scid | 0x80000000;
        }

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = key_dcid;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                psm_data->remote_cid == key_dcid) {
            psm = psm_data->psm;
            bt_uuid = get_service_uuid(pinfo, l2cap_data, psm_data->psm, psm_data->local_service);
            connect_in_frame = psm_data->connect_in_frame;
        }

        if (bt_uuid) {
            bluetooth_uuid_t   uuid;

            uuid.size = 2;
            uuid.bt_uuid = bt_uuid;
            uuid.data[0] = bt_uuid >> 8;
            uuid.data[1] = bt_uuid & 0xFF;

            service_name = val_to_str_ext_const(uuid.bt_uuid, &bluetooth_uuid_vals_ext, "Unknown");
        }

        if (strcmp(service_name, "Unknown") == 0) {
            service_name = val_to_str_const(psm, psm_vals, "Unknown");
        }

        if (psm > 0) {
            sub_item = proto_tree_add_uint(tree, hf_btl2cap_psm, tvb, offset, 0, psm);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        if (bt_uuid) {
            sub_item = proto_tree_add_uint(tree, hf_btl2cap_service, tvb, 0, 0, bt_uuid);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }

        if (connect_in_frame > 0) {
            sub_item = proto_tree_add_uint(tree, hf_btl2cap_connect_in_frame, tvb, 0, 0, connect_in_frame);
            PROTO_ITEM_SET_GENERATED(sub_item);
        }
    }

    if (psm > 0)
        col_append_fstr(pinfo->cinfo, COL_INFO, " (SCID: 0x%04x, DCID: 0x%04x, PSM: 0x%04x, Service: %s)", scid, dcid, psm, service_name);
    else
        col_append_fstr(pinfo->cinfo, COL_INFO, " (SCID: 0x%04x, DCID: 0x%04x, PSM: Unknown, Service: %s)", scid, dcid, service_name);


    return offset;
}

static int
dissect_b_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        proto_tree *btl2cap_tree, guint16 cid, guint16 psm,
        gboolean is_local_psm, guint16 length, int offset, btl2cap_data_t *l2cap_data)
{
    tvbuff_t *next_tvb;

    next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb, offset), length);

    col_append_str(pinfo->cinfo, COL_INFO, "Connection oriented channel");

    if (psm) {
        proto_item        *psm_item;
        guint16            bt_uuid;
        bluetooth_uuid_t   uuid;

        if (p_get_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_PSM ) == NULL) {
            guint16 *value_data;

            value_data = wmem_new(wmem_file_scope(), guint16);
            *value_data = psm;

            p_add_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_PSM, value_data);
        }

        bt_uuid = get_service_uuid(pinfo, l2cap_data, psm, is_local_psm);

        uuid.size = 2;
        uuid.bt_uuid = bt_uuid;
        uuid.data[0] = bt_uuid >> 8;
        uuid.data[1] = bt_uuid & 0xFF;

        if (bt_uuid && p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID) == NULL) {
            guint8 *value_data;

            value_data = wmem_strdup(wmem_file_scope(), print_numeric_uuid(&uuid));

            p_add_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID, value_data);
        }

        if (psm < BTL2CAP_DYNAMIC_PSM_START) {
            psm_item = proto_tree_add_uint(btl2cap_tree, hf_btl2cap_psm, tvb, offset, 0, psm);
        }
        else {
            psm_item = proto_tree_add_uint(btl2cap_tree, hf_btl2cap_psm_dynamic, tvb, offset, 0, psm);
            if (uuid.bt_uuid)
                proto_item_append_text(psm_item, ": %s",
                                       val_to_str_ext_const(uuid.bt_uuid, &bluetooth_uuid_vals_ext, "Unknown service"));
        }
        PROTO_ITEM_SET_GENERATED(psm_item);

        /* call next dissector */
        if (!dissector_try_uint_new(l2cap_cid_dissector_table, (guint32) cid, next_tvb, pinfo, tree, TRUE, l2cap_data)) {
            if (!dissector_try_uint_new(l2cap_psm_dissector_table, (guint32) psm, next_tvb, pinfo, tree, TRUE, l2cap_data)) {
                /* not a known fixed PSM, try to find a registered service to a dynamic PSM */
                if (!dissector_try_string(bluetooth_uuid_table, print_numeric_uuid(&uuid), next_tvb, pinfo, tree, l2cap_data)) {
                    /* unknown protocol. declare as data */
                    proto_tree_add_item(btl2cap_tree, hf_btl2cap_payload, tvb, offset, length, ENC_NA);
                }
            }
        }
        offset = tvb_captured_length(tvb);
    } else {
        if (!dissector_try_uint_new(l2cap_cid_dissector_table, (guint32) cid, next_tvb, pinfo, tree, TRUE, l2cap_data))
            proto_tree_add_item(btl2cap_tree, hf_btl2cap_payload, tvb, offset, length, ENC_NA);
        offset = tvb_captured_length(tvb);
    }
    return offset;
}

static int
dissect_i_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        proto_tree *btl2cap_tree, psm_data_t *psm_data, guint16 length,
        gint offset, config_data_t *config_data, btl2cap_data_t *l2cap_data)
{
    tvbuff_t         *next_tvb = NULL;
    guint16           control, segment;
    guint16           sdulen;
    proto_item*       ti_control;
    proto_tree*       ti_control_subtree;
    sdu_reassembly_t *mfp      = NULL;
    guint16           psm      = (psm_data ? psm_data->psm : 0);

    control = tvb_get_letohs(tvb, offset);
    segment = (control & 0xC000) >> 14;
    switch (segment) {
    case 0:
        col_append_str(pinfo->cinfo, COL_INFO, "[I] Unsegmented SDU");
        break;
    case 1:
        col_append_str(pinfo->cinfo, COL_INFO, "[I] Start SDU");
        break;
    case 2:
        col_append_str(pinfo->cinfo, COL_INFO, "[I] End SDU");
        break;
    case 3:
        col_append_str(pinfo->cinfo, COL_INFO, "[I] Continuation SDU");
        break;
    }
    ti_control = proto_tree_add_none_format(btl2cap_tree, hf_btl2cap_control, tvb,
                                            offset, 2, "Control: %s reqseq:%d r:%d txseq:%d",
                                            val_to_str_const((control & 0xC000) >> 14, control_sar_vals, "unknown"),
                                            (control & 0x3F00) >> 8,
                                            (control & 0x0080) >> 7,
                                            (control & 0x007E) >> 1);
    ti_control_subtree = proto_item_add_subtree(ti_control, ett_btl2cap_control);
    proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_sar, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_reqseq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_retransmissiondisable, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_txseq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset  +=  2;

    /*Segmented frames with SAR = start have an extra SDU length header field*/
    if (segment == 0x01) {
        proto_item *pi;

        sdulen = tvb_get_letohs(tvb, offset);
        pi = proto_tree_add_item(btl2cap_tree, hf_btl2cap_sdulength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;


        /* Detect malformed data */

        if (length <= 6) {
            expert_add_info_format(pinfo, pi, &ei_btl2cap_sdulength_bad,
                    "SDU length too short: %u", length);
            THROW(ReportedBoundsError);
        }

        length -= 6; /*Control, SDUlength, FCS*/

        if (sdulen < length) {
            sdulen = length;
            expert_add_info_format(pinfo, pi, &ei_btl2cap_sdulength_bad,
                    "SDU length less than length of first packet (%u < %u)", sdulen, length);
        }

        if (!pinfo->fd->flags.visited) {
            mfp              = wmem_new(wmem_file_scope(), sdu_reassembly_t);
            mfp->first_frame = pinfo->num;
            mfp->last_frame  = 0;
            mfp->tot_len     = sdulen;
            mfp->reassembled = (guint8 *) wmem_alloc(wmem_file_scope(), sdulen);
            tvb_memcpy(tvb, mfp->reassembled, offset, sdulen);
            mfp->cur_off     = sdulen;
            wmem_tree_insert32(config_data->start_fragments, pinfo->num, mfp);
        } else {
            mfp              = (sdu_reassembly_t *)wmem_tree_lookup32(config_data->start_fragments, pinfo->num);
        }
        if (mfp != NULL && mfp->last_frame) {
            proto_item *item;
            item = proto_tree_add_uint(btl2cap_tree, hf_btl2cap_reassembled_in, tvb, 0, 0, mfp->last_frame);
            PROTO_ITEM_SET_GENERATED(item);
            col_append_fstr(pinfo->cinfo, COL_INFO, "[Reassembled in #%u] ", mfp->last_frame);
        }
    } else {
        if (length <= 4) {
            expert_add_info_format(pinfo, btl2cap_tree, &ei_btl2cap_length_bad,
                    "Control / FCS length too short: %u", length);
            THROW(ReportedBoundsError);
        }
        length -= 4; /*Control, FCS*/
    }
    if (segment == 0x02 || segment == 0x03) {
        mfp = (sdu_reassembly_t *)wmem_tree_lookup32_le(config_data->start_fragments, pinfo->num);
        if (!pinfo->fd->flags.visited) {
            if (mfp != NULL && !mfp->last_frame && (mfp->tot_len>=mfp->cur_off + length)) {
                tvb_memcpy(tvb, mfp->reassembled + mfp->cur_off, offset, length);
                mfp->cur_off += length;
                if (segment == 0x02) {
                    mfp->last_frame = pinfo->num;
                }
            }
        }
        if (mfp) {
            proto_item *item;
            item = proto_tree_add_uint(btl2cap_tree, hf_btl2cap_continuation_to, tvb, 0, 0, mfp->first_frame);
            PROTO_ITEM_SET_GENERATED(item);
            col_append_fstr(pinfo->cinfo, COL_INFO, "[Continuation to #%u] ", mfp->first_frame);
        }
    }
    if (segment == 0x02 && mfp != NULL && mfp->last_frame == pinfo->num) {
        next_tvb = tvb_new_child_real_data(tvb, (guint8 *)mfp->reassembled, mfp->tot_len, mfp->tot_len);
        add_new_data_source(pinfo, next_tvb, "Reassembled L2CAP");
    }
    /*pass up to higher layer if we have a complete packet*/
    if (segment == 0x00) {
        next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb, offset) - 2, length);
    }
    if (next_tvb) {
        if (psm) {
            proto_item        *psm_item;
            guint16            bt_uuid;
             bluetooth_uuid_t  uuid;

            if (p_get_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_PSM ) == NULL) {
                guint16 *value_data;

                value_data = wmem_new(wmem_file_scope(), guint16);
                *value_data = psm;

                p_add_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_PSM, value_data);
            }

            bt_uuid = get_service_uuid(pinfo, l2cap_data, psm, psm_data->local_service);

            uuid.size = 2;
            uuid.bt_uuid = bt_uuid;
            uuid.data[0] = bt_uuid >> 8;
            uuid.data[1] = bt_uuid & 0xFF;

            if (bt_uuid && p_get_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BLUETOOTH_SERVICE_UUID) == NULL) {
                guint8 *value_data;

                value_data = wmem_strdup(wmem_file_scope(), print_numeric_uuid(&uuid));

                p_add_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BLUETOOTH_SERVICE_UUID, value_data);
            }

            if (psm < BTL2CAP_DYNAMIC_PSM_START) {
                psm_item = proto_tree_add_uint(btl2cap_tree, hf_btl2cap_psm, tvb, offset, 0, psm);
            } else {
                psm_item = proto_tree_add_uint(btl2cap_tree, hf_btl2cap_psm_dynamic, tvb, offset, 0, psm);
                if (uuid.bt_uuid)
                    proto_item_append_text(psm_item, " (%s)",
                                           val_to_str_ext_const(uuid.bt_uuid, &bluetooth_uuid_vals_ext, "Unknown service"));
            }
            PROTO_ITEM_SET_GENERATED(psm_item);

            /* call next dissector */
            if (!dissector_try_uint_new(l2cap_psm_dissector_table, (guint32) psm, next_tvb, pinfo, tree, TRUE, l2cap_data)) {
                /* not a known fixed PSM, try to find a registered service to a dynamic PSM */
                if (!dissector_try_string(bluetooth_uuid_table, print_numeric_uuid(&uuid), next_tvb, pinfo, tree, l2cap_data)) {
                    /* unknown protocol. declare as data */
                    proto_tree_add_item(btl2cap_tree, hf_btl2cap_payload, next_tvb, 0, tvb_reported_length(next_tvb), ENC_NA);
                }
            }
        }
        else {
            proto_tree_add_item(btl2cap_tree, hf_btl2cap_payload, next_tvb, 0, tvb_reported_length(next_tvb), ENC_NA);
        }
    }
    offset += tvb_reported_length_remaining(tvb, offset) - 2;
    proto_tree_add_item(btl2cap_tree, hf_btl2cap_fcs, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset +=  2;
    return offset;
}

static int
dissect_s_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, proto_tree *btl2cap_tree,
                guint16 psm _U_, guint16 length _U_, int offset, config_data_t *config_data _U_)
{
    proto_item *ti_control;
    proto_tree *ti_control_subtree;
    guint16     control;

    control = tvb_get_letohs(tvb, offset);

    switch ((control & 0x000C) >> 2) {
    case 0:
        col_append_str(pinfo->cinfo, COL_INFO, "[S] Receiver Ready");
        break;
    case 1:
        col_append_str(pinfo->cinfo, COL_INFO, "[S] Reject");
        break;
    default:
        col_append_str(pinfo->cinfo, COL_INFO, "[S] Unknown supervisory frame");
        break;
    }

    ti_control = proto_tree_add_none_format(btl2cap_tree, hf_btl2cap_control, tvb,
        offset, 2, "Control: %s reqseq:%d r:%d",
        val_to_str_const((control & 0x000C) >> 2, control_supervisory_vals, "unknown"),
        (control & 0x3F00) >> 8,
        (control & 0x0080) >> 7);
    ti_control_subtree = proto_item_add_subtree(ti_control, ett_btl2cap_control);

    proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_reqseq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_retransmissiondisable, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_supervisory, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(btl2cap_tree, hf_btl2cap_fcs, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static gint
dissect_btl2cap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    gint              offset       = 0;
    proto_item       *ti;
    proto_tree       *btl2cap_tree;
    proto_item       *length_item;
    guint16           length;
    guint16           cid;
    guint16           psm;
    guint16           control;
    tvbuff_t         *next_tvb     = NULL;
    psm_data_t       *psm_data;
    bthci_acl_data_t *acl_data;
    btl2cap_data_t   *l2cap_data;

    acl_data = (bthci_acl_data_t *) data;

    ti = proto_tree_add_item(tree, proto_btl2cap, tvb, offset, -1, ENC_NA);
    btl2cap_tree = proto_item_add_subtree(ti, ett_btl2cap);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "L2CAP");

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

    length  = tvb_get_letohs(tvb, offset);
    length_item = proto_tree_add_item(btl2cap_tree, hf_btl2cap_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    if (tvb_captured_length_remaining(tvb, offset) < length) {
        expert_add_info(pinfo, length_item, &ei_btl2cap_length_bad);
        /* Try to dissect as more as possible */
        length = tvb_captured_length_remaining(tvb, offset) - 4;
    }

    offset += 2;

    cid = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(btl2cap_tree, hf_btl2cap_cid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    if (p_get_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_CID ) == NULL) {
        guint16 *value_data;

        value_data = wmem_new(wmem_file_scope(), guint16);
        *value_data = cid;

        p_add_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_CID, value_data);
    }
    offset += 2;

    l2cap_data = wmem_new(wmem_packet_scope(), btl2cap_data_t);

    if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
        l2cap_data->interface_id = pinfo->phdr->interface_id;
    else
        l2cap_data->interface_id = HCI_INTERFACE_DEFAULT;
    if (acl_data) {
        l2cap_data->adapter_id                  = acl_data->adapter_id;
        l2cap_data->adapter_disconnect_in_frame = acl_data->adapter_disconnect_in_frame;
        l2cap_data->chandle                     = acl_data->chandle;
        l2cap_data->hci_disconnect_in_frame     = acl_data->disconnect_in_frame;
        l2cap_data->remote_bd_addr_oui          = acl_data->remote_bd_addr_oui;
        l2cap_data->remote_bd_addr_id           = acl_data->remote_bd_addr_id;
    } else {
        l2cap_data->adapter_id                  = HCI_ADAPTER_DEFAULT;
        l2cap_data->adapter_disconnect_in_frame = &max_disconnect_in_frame;
        l2cap_data->chandle                     = 0;
        l2cap_data->hci_disconnect_in_frame     = &max_disconnect_in_frame;
        l2cap_data->remote_bd_addr_oui          = 0;
        l2cap_data->remote_bd_addr_id           = 0;
    }

    l2cap_data->disconnect_in_frame         = &max_disconnect_in_frame;

    l2cap_data->cid              = cid;
    l2cap_data->local_cid        = BTL2CAP_UNKNOWN_CID;
    l2cap_data->remote_cid       = BTL2CAP_UNKNOWN_CID;
    l2cap_data->is_local_psm     = FALSE;
    l2cap_data->psm              = 0;

    if (cid == BTL2CAP_FIXED_CID_SIGNAL || cid == BTL2CAP_FIXED_CID_LE_SIGNAL) {
        /* This is a command packet*/
        while (offset < length + 4) {

            proto_item  *ti_command;
            proto_tree  *btl2cap_cmd_tree;
            guint8       cmd_code;
            guint16      cmd_length;
            const gchar *cmd_str;

            ti_command = proto_tree_add_none_format(btl2cap_tree,
                    hf_btl2cap_command, tvb,
                    offset, length,
                    "Command: ");
            btl2cap_cmd_tree = proto_item_add_subtree(ti_command, ett_btl2cap_cmd);

            cmd_code = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_cmd_code,   tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_cmd_ident,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;

            cmd_length = tvb_get_letohs(tvb, offset);
            proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_cmd_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            proto_item_set_len(ti_command, cmd_length + 4);
            offset += 2;

            cmd_str = val_to_str_const(cmd_code, command_code_vals, "Unknown command");
            proto_item_append_text(ti_command, "%s", cmd_str);
            col_append_str(pinfo->cinfo, COL_INFO, cmd_str);

            switch (cmd_code) {
            case 0x01: /* Command Reject */
                offset  = dissect_comrej(tvb, offset, pinfo, btl2cap_cmd_tree);
                break;

            case 0x02: /* Connection Request */
                offset  = dissect_connrequest(tvb, offset, pinfo, btl2cap_tree, btl2cap_cmd_tree, FALSE, acl_data, l2cap_data);
                break;

            case 0x03: /* Connection Response */
                offset  = dissect_connresponse(tvb, offset, pinfo, btl2cap_cmd_tree, acl_data);
                break;

            case 0x04: /* Configure Request */
                offset  = dissect_configrequest(tvb, offset, pinfo, btl2cap_cmd_tree, cmd_length, acl_data);
                break;

            case 0x05: /* Configure Response */
                offset  = dissect_configresponse(tvb, offset, pinfo, btl2cap_cmd_tree, cmd_length, acl_data);
                break;

            case 0x06: /* Disconnect Request */
                offset  = dissect_disconnrequestresponse(tvb, offset, pinfo, btl2cap_tree, btl2cap_cmd_tree, acl_data, l2cap_data, TRUE);
                break;

            case 0x07: /* Disconnect Response */
                offset  = dissect_disconnrequestresponse(tvb, offset, pinfo, btl2cap_tree, btl2cap_cmd_tree, acl_data, l2cap_data, FALSE);
                break;

            case 0x08: /* Echo Request */
                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_data, tvb, offset, -1, ENC_NA);
                offset = tvb_reported_length(tvb);
                break;

            case 0x09: /* Echo Response */
                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_data, tvb, offset, -1, ENC_NA);
                offset = tvb_reported_length(tvb);
                break;

            case 0x0a: /* Information Request */
                offset  = dissect_inforequest(tvb, offset, pinfo, btl2cap_cmd_tree);
                break;

            case 0x0b: /* Information Response */
                offset  = dissect_inforesponse(tvb, offset, pinfo, btl2cap_cmd_tree);
                break;

            case 0x0c: /* Create Channel Request */
                offset  = dissect_connrequest(tvb, offset, pinfo, btl2cap_tree, btl2cap_cmd_tree, TRUE, acl_data, l2cap_data);
                break;

            case 0x0d: /* Create Channel Response */
                offset  = dissect_chanresponse(tvb, offset, pinfo, btl2cap_cmd_tree, acl_data);
                break;

            case 0x0e: /* Move Channel Request */
                offset  = dissect_movechanrequest(tvb, offset, pinfo, btl2cap_cmd_tree);
                break;

            case 0x0f: /* Move Channel Response */
                offset  = dissect_movechanresponse(tvb, offset, pinfo, btl2cap_cmd_tree);
                break;

            case 0x10: /* Move Channel Confirmation */
                offset  = dissect_movechanconfirmation(tvb, offset, pinfo, btl2cap_cmd_tree);
                break;

            case 0x11: /* Move Channel Confirmation Response */
                offset  = dissect_movechanconfirmationresponse(tvb, offset, pinfo, btl2cap_cmd_tree);
                break;

            case 0x12: /* Connection Parameter Request */
                offset  = dissect_connparamrequest(tvb, offset, pinfo, btl2cap_cmd_tree);
                break;

            case 0x13: /* Connection Parameter Response */
                offset  = dissect_connparamresponse(tvb, offset, pinfo, btl2cap_cmd_tree);
                break;

            case 0x14: /* LE Credit Based Connection Request */
                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_le_psm, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_scid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_option_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_option_mps, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_initial_credits, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                break;

            case 0x15: /* LE Credit Based Connection Response */
                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_dcid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_option_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_option_mps, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_initial_credits, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_le_result, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                break;

            case 0x16: /* LE Flow Control Credit */
                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_cid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_credits, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                col_append_fstr(pinfo->cinfo, COL_INFO, " (CID: %04x, Credits: %u)",
                        tvb_get_letohs(tvb, offset - 4), tvb_get_letohs(tvb, offset - 2));
                break;

            default:
                proto_tree_add_expert(btl2cap_cmd_tree, pinfo, &ei_btl2cap_unknown_command_code, tvb, offset, -1);
                offset += tvb_reported_length_remaining(tvb, offset);
                break;
            }
        }
    }
    else if (cid == BTL2CAP_FIXED_CID_CONNLESS) { /* Connectionless reception channel */
        col_append_str(pinfo->cinfo, COL_INFO, "Connectionless reception channel");

        psm = tvb_get_letohs(tvb, offset);
        if (pinfo->p2p_dir == P2P_DIR_RECV) {
            l2cap_data->local_cid = cid;
            l2cap_data->remote_cid = BTL2CAP_UNKNOWN_CID;
        } else {
            l2cap_data->local_cid = BTL2CAP_UNKNOWN_CID;
            l2cap_data->remote_cid = cid;
        }
        l2cap_data->psm = psm;
        l2cap_data->disconnect_in_frame = &max_disconnect_in_frame;

        if (p_get_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_PSM ) == NULL) {
            guint16 *value_data;

            value_data = wmem_new(wmem_file_scope(), guint16);
            *value_data = psm;

            p_add_proto_data(pinfo->pool, pinfo, proto_btl2cap, PROTO_DATA_BTL2CAP_PSM, value_data);
        }

        proto_tree_add_item(btl2cap_tree, hf_btl2cap_psm, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;

        next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb, offset), length);

        /* call next dissector */
        if (!dissector_try_uint_new(l2cap_psm_dissector_table, (guint32) psm, next_tvb, pinfo, tree, TRUE, l2cap_data)) {
            /* not a known fixed PSM, try to find a registered service to a dynamic PSM */
            guint16  bt_uuid;
            bluetooth_uuid_t  uuid;

            bt_uuid = get_service_uuid(pinfo, l2cap_data, psm, (pinfo->p2p_dir == P2P_DIR_RECV) ? TRUE : FALSE );

            uuid.size = 2;
            uuid.bt_uuid = bt_uuid;
            uuid.data[0] = bt_uuid >> 8;
            uuid.data[1] = bt_uuid & 0xFF;

            if (bt_uuid && p_get_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID ) == NULL) {
                guint8 *value_data;

                value_data = wmem_strdup(wmem_file_scope(), print_numeric_uuid(&uuid));

                p_add_proto_data(pinfo->pool, pinfo, proto_bluetooth, PROTO_DATA_BLUETOOTH_SERVICE_UUID, value_data);
            }

            if (!dissector_try_string(bluetooth_uuid_table, print_numeric_uuid(&uuid), next_tvb, pinfo, tree, l2cap_data)) {
                /* unknown protocol. declare as data */
                proto_tree_add_item(btl2cap_tree, hf_btl2cap_payload, tvb, offset, length, ENC_NA);
            }
            offset = tvb_captured_length(tvb);
        }
    }
    else if (cid <= BTL2CAP_FIXED_CID_LAST) {
        if (cid == BTL2CAP_FIXED_CID_AMP_MAN) {
            control = tvb_get_letohs(tvb, offset);
            if (control & 0x1) {
                offset = dissect_s_frame(tvb, pinfo, tree, btl2cap_tree, 0 /* unused */, length, offset, NULL /* unused */);
            } else {
                proto_item* ti_control;
                proto_tree* ti_control_subtree;

                ti_control = proto_tree_add_none_format(btl2cap_tree, hf_btl2cap_control, tvb,
                    offset, 2, "Control: %s reqseq:%d r:%d txseq:%d",
                    val_to_str_const((control & 0xC000) >> 14, control_sar_vals, "unknown"),
                    (control & 0x3F00) >> 8,
                    (control & 0x0080) >> 7,
                    (control & 0x007E) >> 1);
                ti_control_subtree = proto_item_add_subtree(ti_control, ett_btl2cap_control);
                proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_sar, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_reqseq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_retransmissiondisable, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_txseq, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                proto_tree_add_item(ti_control_subtree, hf_btl2cap_control_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(btl2cap_tree, hf_btl2cap_fcs, tvb, tvb_reported_length(tvb) - 2, 2, ENC_LITTLE_ENDIAN);

                next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb, offset)-2, length);
            }
        }
        else {
            next_tvb = tvb_new_subset(tvb, offset, tvb_captured_length_remaining(tvb, offset), length);
        }
        /* call next dissector */
        if (next_tvb && !dissector_try_uint_new(l2cap_cid_dissector_table, (guint32) cid,
                    next_tvb, pinfo, tree, TRUE, l2cap_data)) {
            /* unknown protocol. declare as data */
            proto_tree_add_item(btl2cap_tree, hf_btl2cap_payload, tvb, offset, length, ENC_NA);
        }
        offset = tvb_captured_length(tvb);
    }
    else /* if (cid > BTL2CAP_FIXED_CID_LAST) */ { /* Connection oriented channel */
        wmem_tree_key_t    key[6];
        guint32            k_interface_id;
        guint32            k_adapter_id;
        guint32            k_chandle;
        guint32            k_cid;
        guint32            k_frame_number;
        guint32            interface_id;
        guint32            adapter_id;
        guint32            chandle;
        guint32            key_cid;

        if (pinfo->phdr->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->phdr->interface_id;
        else
            interface_id = HCI_INTERFACE_DEFAULT;
        adapter_id   = (acl_data) ? acl_data->adapter_id : HCI_ADAPTER_DEFAULT;
        chandle      = (acl_data) ? acl_data->chandle : 0;
        key_cid      = cid | ((pinfo->p2p_dir == P2P_DIR_RECV) ? 0x00000000 : 0x80000000);

        k_interface_id = interface_id;
        k_adapter_id   = adapter_id;
        k_chandle      = chandle;
        k_cid          = key_cid;
        k_frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key    = &k_interface_id;
        key[1].length = 1;
        key[1].key    = &k_adapter_id;
        key[2].length = 1;
        key[2].key    = &k_chandle;
        key[3].length = 1;
        key[3].key    = &k_cid;
        key[4].length = 1;
        key[4].key    = &k_frame_number;
        key[5].length = 0;
        key[5].key    = NULL;

        psm_data = (psm_data_t *)wmem_tree_lookup32_array_le(cid_to_psm_table, key);
        if (psm_data && psm_data->interface_id == interface_id &&
                psm_data->adapter_id == adapter_id &&
                psm_data->chandle == chandle &&
                (psm_data->local_cid == key_cid ||
                psm_data->remote_cid == key_cid) &&
                psm_data->disconnect_in_frame > pinfo->num) {
            config_data_t  *config_data;
            proto_item     *sub_item;
            guint32         bt_uuid;

            psm = psm_data->psm;
            l2cap_data->local_cid = psm_data->local_cid;
            l2cap_data->remote_cid = psm_data->remote_cid;
            l2cap_data->psm = psm;
            l2cap_data->is_local_psm = psm_data->local_service;
            l2cap_data->disconnect_in_frame = &psm_data->disconnect_in_frame;

            if (pinfo->p2p_dir == P2P_DIR_RECV)
                config_data = &(psm_data->in);
            else
                config_data = &(psm_data->out);

            if (psm_data->connect_in_frame > 0 && psm_data->connect_in_frame < G_MAXUINT32) {
                sub_item = proto_tree_add_uint(btl2cap_tree, hf_btl2cap_connect_in_frame, tvb, 0, 0, psm_data->connect_in_frame);
                PROTO_ITEM_SET_GENERATED(sub_item);
            }

            if (psm_data->disconnect_in_frame > 0 && psm_data->disconnect_in_frame < G_MAXUINT32) {
                sub_item = proto_tree_add_uint(btl2cap_tree, hf_btl2cap_disconnect_in_frame, tvb, 0, 0, psm_data->disconnect_in_frame);
                PROTO_ITEM_SET_GENERATED(sub_item);
            }

            bt_uuid = get_service_uuid(pinfo, l2cap_data, psm_data->psm, psm_data->local_service);
            if (bt_uuid) {
                sub_item = proto_tree_add_uint(btl2cap_tree, hf_btl2cap_service, tvb, 0, 0, bt_uuid);
                PROTO_ITEM_SET_GENERATED(sub_item);
            }

            if (config_data->mode == 0) {
                offset = dissect_b_frame(tvb, pinfo, tree, btl2cap_tree, cid, psm, psm_data->local_service, length, offset, l2cap_data);
            } else {
                control = tvb_get_letohs(tvb, offset);
                if (control & 0x1) {
                    offset = dissect_s_frame(tvb, pinfo, tree, btl2cap_tree, psm, length, offset, config_data);
                } else {
                    offset = dissect_i_frame(tvb, pinfo, tree, btl2cap_tree, psm_data, length, offset, config_data, l2cap_data);
                }
            }
        } else {
            psm = 0;
            offset = dissect_b_frame(tvb, pinfo, tree, btl2cap_tree, cid, psm, FALSE, length, offset, l2cap_data);
        }
    }

    return offset;
}


/* Register the protocol with Wireshark */
void
proto_register_btl2cap(void)
{
    expert_module_t *expert_btl2cap;
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_btl2cap_length,
          { "Length",           "btl2cap.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "L2CAP Payload Length", HFILL }
        },
        { &hf_btl2cap_cid,
          { "CID",           "btl2cap.cid",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(cid_rvals), 0x0,
            "L2CAP Channel Identifier", HFILL }
        },
        { &hf_btl2cap_payload,
          { "Payload",           "btl2cap.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "L2CAP Payload", HFILL }
        },
        { &hf_btl2cap_command,
          { "Command",           "btl2cap.command",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "L2CAP Command", HFILL }
        },
        { &hf_btl2cap_cmd_code,
          { "Command Code",           "btl2cap.cmd_code",
            FT_UINT8, BASE_HEX, VALS(command_code_vals), 0x0,
            "L2CAP Command Code", HFILL }
        },
        { &hf_btl2cap_cmd_ident,
          { "Command Identifier",           "btl2cap.cmd_ident",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "L2CAP Command Identifier", HFILL }
        },
        { &hf_btl2cap_cmd_length,
          { "Command Length",           "btl2cap.cmd_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "L2CAP Command Length", HFILL }
        },
        { &hf_btl2cap_cmd_data,
          { "Command Data",           "btl2cap.cmd_data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "L2CAP Command Data", HFILL }
        },
        { &hf_btl2cap_psm,
          { "PSM",           "btl2cap.psm",
            FT_UINT16, BASE_HEX, VALS(psm_vals), 0x0,
            "Protocol/Service Multiplexer", HFILL }
        },
        { &hf_btl2cap_psm_dynamic,
          { "Dynamic PSM",           "btl2cap.psm",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Dynamic Protocol/Service Multiplexer", HFILL }
        },
        { &hf_btl2cap_scid,
          { "Source CID",           "btl2cap.scid",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(cid_rvals), 0x0,
            "Source Channel Identifier", HFILL }
        },
        { &hf_btl2cap_dcid,
          { "Destination CID",           "btl2cap.dcid",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(cid_rvals), 0x0,
            "Destination Channel Identifier", HFILL }
        },
        { &hf_btl2cap_icid,
          { "Initiator CID",           "btl2cap.icid",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(cid_rvals), 0x0,
            "Initiator Channel Identifier", HFILL }
        },
        { &hf_btl2cap_controller,
          { "Controller ID",           "btl2cap.ctrl_id",
            FT_UINT8, BASE_DEC, VALS(ctrl_id_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_dcontroller,
          { "Controller ID",           "btl2cap.dctrl_id",
            FT_UINT8, BASE_DEC, VALS(ctrl_id_code_vals), 0x0,
            "Destination Controller ID", HFILL }
        },
        { &hf_btl2cap_result,
          { "Result",           "btl2cap.result",
            FT_UINT16, BASE_HEX, VALS(result_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_move_result,
          { "Move Result",           "btl2cap.move_result",
            FT_UINT16, BASE_HEX, VALS(move_result_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_move_confirmation_result,
          { "Move Result",           "btl2cap.move_result",
            FT_UINT16, BASE_HEX, VALS(move_result_confirmation_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_status,
          { "Status",           "btl2cap.status",
            FT_UINT16, BASE_HEX, VALS(status_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_rej_reason,
          { "Reason",           "btl2cap.rej_reason",
            FT_UINT16, BASE_HEX, VALS(reason_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_sig_mtu,
          { "Maximum Signalling MTU",           "btl2cap.sig_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_info_mtu,
          { "Remote Entity MTU",           "btl2cap.info_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Remote entity acceptable connectionless MTU", HFILL }
        },
        { &hf_btl2cap_info_flowcontrol,
          { "Flow Control Mode",           "btl2cap.info_flowcontrol",
            FT_UINT32, BASE_DEC, NULL, 0x01,
            "Flow Control mode support", HFILL }
        },
        { &hf_btl2cap_info_retransmission,
          { "Retransmission Mode",         "btl2cap.info_retransmission",
            FT_UINT32, BASE_DEC, NULL, 0x02,
            "Retransmission mode support", HFILL }
        },
        { &hf_btl2cap_info_bidirqos,
          { "Bi-Directional QOS",          "btl2cap.info_bidirqos",
            FT_UINT32, BASE_DEC, NULL, 0x04,
            "Bi-Directional QOS support", HFILL }
        },
        { &hf_btl2cap_info_enh_retransmission,
          { "Enhanced Retransmission Mode", "btl2cap.info_enh_retransmission",
            FT_UINT32, BASE_DEC, NULL, 0x08,
            "Enhanced Retransmission mode support", HFILL }
        },
        { &hf_btl2cap_info_streaming,
          { "Streaming Mode", "btl2cap.info_streaming",
            FT_UINT32, BASE_DEC, NULL, 0x10,
            "Streaming mode support", HFILL }
        },
        { &hf_btl2cap_info_fcs,
          { "FCS", "btl2cap.info_fcs",
            FT_UINT32, BASE_DEC, NULL, 0x20,
            "FCS support", HFILL }
        },
        { &hf_btl2cap_info_flow_spec,
          { "Extended Flow Specification for BR/EDR", "btl2cap.info_flow_spec",
            FT_UINT32, BASE_DEC, NULL, 0x40,
            "Extended Flow Specification for BR/EDR support", HFILL }
        },
        { &hf_btl2cap_info_fixedchan,
          { "Fixed Channels", "btl2cap.info_fixedchan",
            FT_UINT32, BASE_DEC, NULL, 0x80,
            "Fixed Channels support", HFILL }
        },
        { &hf_btl2cap_info_window,
          { "Extended Window Size", "btl2cap.info_window",
            FT_UINT32, BASE_DEC, NULL, 0x0100,
            "Extended Window Size support", HFILL }
        },
        { &hf_btl2cap_info_unicast,
          { "Unicast Connectionless Data Reception", "btl2cap.info_unicast",
            FT_UINT32, BASE_DEC, NULL, 0x0200,
            "Unicast Connectionless Data Reception support", HFILL }
        },
        { &hf_btl2cap_info_fixedchans,
          { "Fixed Channels", "btl2cap.info_fixedchans",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_info_fixedchans_null,
          { "Null identifier", "btl2cap.info_fixedchans_null",
            FT_UINT32, BASE_DEC, NULL, 0x1,
            NULL, HFILL }
        },
        { &hf_btl2cap_info_fixedchans_signal,
          { "L2CAP signaling channel", "btl2cap.info_fixedchans_signal",
            FT_UINT32, BASE_DEC, NULL, 0x2,
            NULL, HFILL }
        },
        { &hf_btl2cap_info_fixedchans_connless,
          { "Connectionless reception", "btl2cap.info_fixedchans_connless",
            FT_UINT32, BASE_DEC, NULL, 0x4,
            NULL, HFILL }
        },
        { &hf_btl2cap_info_fixedchans_amp_man,
          { "AMP Manager protocol", "btl2cap.info_fixedchans_amp_man",
            FT_UINT32, BASE_DEC, NULL, 0x8,
            NULL, HFILL }
        },
        { &hf_btl2cap_info_fixedchans_amp_test,
          { "AMP Test Manager", "btl2cap.info_fixedchans_amp_test",
            FT_UINT32, BASE_DEC, NULL, 0x80000000,
            NULL, HFILL }
        },
        { &hf_btl2cap_info_type,
          { "Information Type",           "btl2cap.info_type",
            FT_UINT16, BASE_HEX, VALS(info_type_vals), 0x0,
            "Type of implementation-specific information", HFILL }
        },
        { &hf_btl2cap_info_result,
          { "Result",           "btl2cap.info_result",
            FT_UINT16, BASE_HEX, VALS(info_result_vals), 0x0,
            "Information about the success of the request", HFILL }
        },
        { &hf_btl2cap_info_extfeatures,
          { "Extended Features",           "btl2cap.info_extfeatures",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Extended Features Mask", HFILL }
        },
        { &hf_btl2cap_flags_reserved,
          { "Reserved",           "btl2cap.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, 0xFFFE,
            NULL, HFILL }
        },
        { &hf_btl2cap_flags_continuation,
          { "Continuation Flag",           "btl2cap.flags.continuation",
            FT_BOOLEAN, 16, NULL, 0x0001,
            NULL, HFILL }
        },
        { &hf_btl2cap_configuration_result,
          { "Result",           "btl2cap.conf_result",
            FT_UINT16, BASE_HEX, VALS(configuration_result_vals), 0x0,
            "Configuration Result", HFILL }
        },
        { &hf_btl2cap_option_type,
          { "Type",           "btl2cap.option_type",
            FT_UINT8, BASE_HEX, VALS(option_type_vals), 0x0,
            "Type of option", HFILL }
        },
        { &hf_btl2cap_option_length,
          { "Length",           "btl2cap.option_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Number of octets in option payload", HFILL }
        },
        { &hf_btl2cap_option_mtu,
          { "MTU",           "btl2cap.option_mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Maximum Transmission Unit", HFILL }
        },
        { &hf_btl2cap_option_flushTO,
          { "Flush Timeout (ms)",           "btl2cap.option_flushto",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Flush Timeout in milliseconds", HFILL }
        },
        { &hf_btl2cap_option_flush_to_us,
          { "Flush Timeout (us)",           "btl2cap.option_flushto",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Flush Timeout (microseconds)", HFILL }
        },
        { &hf_btl2cap_option_sdu_size,
          { "Maximum SDU Size",           "btl2cap.option_sdu_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_option_sdu_arrival_time,
          { "SDU Inter-arrival Time (us)",           "btl2cap.option_sdu_arrival_time",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "SDU Inter-arrival Time (microseconds)", HFILL }
        },
        { &hf_btl2cap_option_identifier,
          { "Identifier",           "btl2cap.option_ident",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Flow Specification Identifier", HFILL }
        },
        { &hf_btl2cap_option_access_latency,
          { "Access Latency (us)",           "btl2cap.option_access_latency",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Access Latency (microseconds)", HFILL }
        },
        { &hf_btl2cap_option_flags,
          { "Flags",           "btl2cap.option_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Flags - must be set to 0 (Reserved for future use)", HFILL }
        },
        { &hf_btl2cap_option_service_type,
          { "Service Type",           "btl2cap.option_servicetype",
            FT_UINT8, BASE_HEX, VALS(option_servicetype_vals), 0x0,
            "Level of service required", HFILL }
        },
        { &hf_btl2cap_option_tokenrate,
          { "Token Rate (bytes/s)",           "btl2cap.option_tokenrate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Rate at which traffic credits are granted (bytes/s)", HFILL }
        },
        { &hf_btl2cap_option_tokenbucketsize,
          { "Token Bucket Size (bytes)",           "btl2cap.option_tokenbsize",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Size of the token bucket (bytes)", HFILL }
        },
        { &hf_btl2cap_option_peakbandwidth,
          { "Peak Bandwidth (bytes/s)",           "btl2cap.option_peakbandwidth",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Limit how fast packets may be sent (bytes/s)", HFILL }
        },
        { &hf_btl2cap_option_latency,
          { "Latency (microseconds)",           "btl2cap.option_latency",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Maximal acceptable delay (microseconds)", HFILL }
        },
        { &hf_btl2cap_option_delayvariation,
          { "Delay Variation (microseconds)",           "btl2cap.option_delayvar",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Difference between maximum and minimum delay (microseconds)", HFILL }
        },
        { &hf_btl2cap_option_retransmissionmode,
          { "Mode",                               "btl2cap.retransmissionmode",
            FT_UINT8, BASE_HEX, VALS(option_retransmissionmode_vals), 0x0,
            "Retransmission/Flow Control mode", HFILL }
        },
        { &hf_btl2cap_option_txwindow,
          { "TxWindow",                           "btl2cap.txwindow",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Retransmission window size", HFILL }
        },
        { &hf_btl2cap_option_maxtransmit,
          { "MaxTransmit",                        "btl2cap.maxtransmit",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Maximum I-frame retransmissions", HFILL }
        },
        { &hf_btl2cap_option_retransmittimeout,
          { "Retransmit timeout (ms)",            "btl2cap.retransmittimeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Retransmission timeout (milliseconds)", HFILL }
        },
        { &hf_btl2cap_option_monitortimeout,
          { "Monitor Timeout (ms)",               "btl2cap.monitortimeout",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "S-frame transmission interval (milliseconds)", HFILL }
        },
        { &hf_btl2cap_option_mps,
          { "MPS",                                "btl2cap.mps",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Maximum PDU Payload Size", HFILL }
        },
        { &hf_btl2cap_option_fcs,
          { "FCS",           "btl2cap.option_fcs",
            FT_UINT16, BASE_HEX, VALS(option_fcs_vals), 0x0,
            "Frame Check Sequence", HFILL }
        },
        { &hf_btl2cap_option_window,
          { "Extended Window Size",           "btl2cap.option_window",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_option,
          { "Configuration Parameter Option",           "btl2cap.conf_param_option",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_control_sar,
          { "Segmentation and reassembly",           "btl2cap.control_sar",
            FT_UINT16, BASE_HEX, VALS(control_sar_vals), 0xC000,
            NULL, HFILL }
        },
        { &hf_btl2cap_control_reqseq,
          { "ReqSeq",           "btl2cap.control_reqseq",
            FT_UINT16, BASE_DEC, NULL, 0x3F00,
            "Request Sequence Number", HFILL }
        },
        { &hf_btl2cap_control_txseq,
          { "TxSeq",           "btl2cap.control_txseq",
            FT_UINT16, BASE_DEC, NULL, 0x007E,
            "Transmitted Sequence Number", HFILL }
        },
        { &hf_btl2cap_control_retransmissiondisable,
          { "R",           "btl2cap.control_retransmissiondisable",
            FT_UINT16, BASE_HEX, NULL, 0x0080,
            "Retransmission Disable", HFILL }
        },
        { &hf_btl2cap_control_supervisory,
          { "S",           "btl2cap.control_supervisory",
            FT_UINT16, BASE_HEX, VALS(control_supervisory_vals), 0x000C,
            "Supervisory Function", HFILL }
        },
        { &hf_btl2cap_control_type,
          { "Frame Type",           "btl2cap.control_type",
            FT_UINT16, BASE_HEX, VALS(control_type_vals), 0x0001,
            NULL, HFILL }
        },
        { &hf_btl2cap_control,
          { "Control field",           "btl2cap.control",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_fcs,
          { "FCS",           "btl2cap.fcs",
            FT_UINT16, BASE_HEX, NULL, 0,
            "Frame Check Sequence", HFILL }
        },
        { &hf_btl2cap_sdulength,
          { "SDU Length",           "btl2cap.sdulength",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_btl2cap_reassembled_in,
          { "This SDU is reassembled in frame",           "btl2cap.reassembled_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "This SDU is reassembled in frame #", HFILL }
        },
        { &hf_btl2cap_continuation_to,
          { "This is a continuation to the SDU in frame",           "btl2cap.continuation_to",
            FT_FRAMENUM, BASE_NONE, NULL, 0,
            "This is a continuation to the SDU in frame #", HFILL }
        },
        { &hf_btl2cap_min_interval,
          { "Min. Interval",           "btl2cap.min_interval",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_btl2cap_max_interval,
          { "Max. Interval",           "btl2cap.max_interval",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_btl2cap_slave_latency,
          { "Slave Latency",           "btl2cap.slave_latency",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_btl2cap_timeout_multiplier,
          { "Timeout Multiplier",           "btl2cap.timeout_multiplier",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_btl2cap_conn_param_result,
          { "Move Result",           "btl2cap.move_result",
            FT_UINT16, BASE_HEX, VALS(conn_param_result_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_le_result,
          { "LE Result",           "btl2cap.le_result",
            FT_UINT16, BASE_HEX, VALS(le_result_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_credits,
          { "Credits",               "btl2cap.credits",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "L2CAP Channel Identifier", HFILL }
        },
        { &hf_btl2cap_initial_credits,
          { "Initial Credits",       "btl2cap.initial_credits",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "L2CAP Channel Identifier", HFILL }
        },
        { &hf_btl2cap_le_psm,
          { "LE PSM",           "btl2cap.le_psm",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(le_psm_rvals), 0x0,
            "Protocol/Service Multiplexer", HFILL }
        },
        { &hf_btl2cap_data,
          { "Data",           "btl2cap.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_service,
          { "Service",           "btl2cap.service",
            FT_UINT16, BASE_HEX, VALS(bluetooth_uuid_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_connect_in_frame,
            { "Connect in frame",                            "btl2cap.connect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btl2cap_disconnect_in_frame,
            { "Disconnect in frame",                         "btl2cap.disconnect_in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_btl2cap,
        &ett_btl2cap_cmd,
        &ett_btl2cap_option,
        &ett_btl2cap_extfeatures,
        &ett_btl2cap_fixedchans,
        &ett_btl2cap_control
    };

    static ei_register_info ei[] = {
        { &ei_btl2cap_parameter_mismatch, { "btl2cap.parameter_mismatch", PI_PROTOCOL, PI_WARN, "Unexpected frame", EXPFILL }},
        { &ei_btl2cap_sdulength_bad, { "btl2cap.sdulength.bad", PI_MALFORMED, PI_WARN, "SDU length bad", EXPFILL }},
        { &ei_btl2cap_length_bad, { "btl2cap.length.bad", PI_MALFORMED, PI_WARN, "Length too short", EXPFILL }},
        { &ei_btl2cap_unknown_command_code, { "btl2cap.unknown_command_code", PI_PROTOCOL, PI_WARN, "Unknown Command Code", EXPFILL }},
    };

    /* Decode As handling */
    static build_valid_func btl2cap_cid_da_build_value[1] = {btl2cap_cid_value};
    static decode_as_value_t btl2cap_cid_da_values = {btl2cap_cid_prompt, 1, btl2cap_cid_da_build_value};
    static decode_as_t btl2cap_cid_da = {"btl2cap", "L2CAP CID", "btl2cap.cid", 1, 0, &btl2cap_cid_da_values, NULL, NULL,
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static build_valid_func btl2cap_psm_da_build_value[1] = {btl2cap_psm_value};
    static decode_as_value_t btl2cap_psm_da_values = {btl2cap_psm_prompt, 1, btl2cap_psm_da_build_value};
    static decode_as_t btl2cap_psm_da = {"btl2cap", "L2CAP PSM", "btl2cap.psm", 1, 0, &btl2cap_psm_da_values, NULL, NULL,
                                 decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    /* Register the protocol name and description */
    proto_btl2cap = proto_register_protocol("Bluetooth L2CAP Protocol", "BT L2CAP", "btl2cap");

    register_dissector("btl2cap", dissect_btl2cap, proto_btl2cap);

    /* subdissector code */
    l2cap_psm_dissector_table = register_dissector_table("btl2cap.psm", "BT L2CAP PSM", proto_btl2cap, FT_UINT16, BASE_HEX);
    l2cap_cid_dissector_table = register_dissector_table("btl2cap.cid", "BT L2CAP CID", proto_btl2cap, FT_UINT16, BASE_HEX);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btl2cap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_btl2cap = expert_register_protocol(proto_btl2cap);
    expert_register_field_array(expert_btl2cap, ei, array_length(ei));

    cid_to_psm_table     = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    register_decode_as(&btl2cap_cid_da);
    register_decode_as(&btl2cap_psm_da);
}


void
proto_reg_handoff_btl2cap(void)
{
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
