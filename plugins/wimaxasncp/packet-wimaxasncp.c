/* packet-wimaxasncp.c
 *
 * Routines for WiMAX ASN Control Plane packet dissection dissection
 *
 * Copyright 2007, Mobile Metrics - http://mobilemetrics.net/
 *
 * Author: Stephen Croll <croll@mobilemetrics.net>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/expert.h>

/* IF PROTO exposes code to other dissectors, then it must be exported
   in a header file. If not, a header file is not needed at all. */
#include "packet-wimaxasncp.h"

/* Forward declaration we need below */
void proto_reg_handoff_wimaxasncp(void);

/* Initialize the protocol and registered fields */
static int proto_wimaxasncp                     = -1;
static int hf_wimaxasncp_version                = -1;
static int hf_wimaxasncp_flags                  = -1;
static int hf_wimaxasncp_function_type          = -1;
static int hf_wimaxasncp_op_id                  = -1;
static int hf_wimaxasncp_message_type           = -1;
static int hf_wimaxasncp_qos_msg                = -1;
static int hf_wimaxasncp_ho_control_msg         = -1;
static int hf_wimaxasncp_data_path_control_msg  = -1;
static int hf_wimaxasncp_context_delivery_msg   = -1;
static int hf_wimaxasncp_r3_mobility_msg        = -1;
static int hf_wimaxasncp_paging_msg             = -1;
static int hf_wimaxasncp_rrm_msg                = -1;
static int hf_wimaxasncp_authentication_msg     = -1;
static int hf_wimaxasncp_ms_state_msg           = -1;
static int hf_wimaxasncp_reauthentication_msg   = -1;
static int hf_wimaxasncp_session_msg            = -1;
static int hf_wimaxasncp_length                 = -1;
static int hf_wimaxasncp_msid                   = -1;
static int hf_wimaxasncp_reserved1              = -1;
static int hf_wimaxasncp_transaction_id         = -1;
static int hf_wimaxasncp_reserved2              = -1;
static int hf_wimaxasncp_tlv                    = -1;
static int hf_wimaxasncp_tlv_type               = -1;
static int hf_wimaxasncp_tlv_length             = -1;
static int hf_wimaxasncp_tlv_value_bytes        = -1;
static int hf_wimaxasncp_tlv_value_enum8        = -1;
static int hf_wimaxasncp_tlv_value_enum16       = -1;
static int hf_wimaxasncp_tlv_value_enum32       = -1;
static int hf_wimaxasncp_tlv_value_ether        = -1;
static int hf_wimaxasncp_tlv_value_string       = -1;
static int hf_wimaxasncp_tlv_value_bitflags16   = -1;
static int hf_wimaxasncp_tlv_value_bitflags32   = -1;
static int hf_wimaxasncp_tlv_value_ipv4         = -1;
static int hf_wimaxasncp_tlv_value_ipv4_address = -1;
static int hf_wimaxasncp_tlv_value_ipv4_mask    = -1;
static int hf_wimaxasncp_tlv_value_ipv6         = -1;
static int hf_wimaxasncp_tlv_value_ipv6_address = -1;
static int hf_wimaxasncp_tlv_value_ipv6_mask    = -1;
static int hf_wimaxasncp_tlv_value_hex8         = -1;
static int hf_wimaxasncp_tlv_value_hex16        = -1;
static int hf_wimaxasncp_tlv_value_hex32        = -1;
static int hf_wimaxasncp_tlv_value_dec8         = -1;
static int hf_wimaxasncp_tlv_value_dec16        = -1;
static int hf_wimaxasncp_tlv_value_dec32        = -1;
static int hf_wimaxasncp_tlv_value_protocol     = -1;
static int hf_wimaxasncp_tlv_value_vendor_id    = -1;

/* preferences */
static gboolean show_transaction_id_d_bit      = FALSE;
static gboolean debug_enabled                  = FALSE;

/* Initialize the subtree pointers */
static gint ett_wimaxasncp                                       = -1;
static gint ett_wimaxasncp_flags                                 = -1;
static gint ett_wimaxasncp_tlv                                   = -1;
static gint ett_wimaxasncp_tlv_value_bitflags16                  = -1;
static gint ett_wimaxasncp_tlv_value_bitflags32                  = -1;
static gint ett_wimaxasncp_tlv_protocol_list                     = -1;
static gint ett_wimaxasncp_tlv_port_range_list                   = -1;
static gint ett_wimaxasncp_tlv_ip_address_mask_list              = -1;
static gint ett_wimaxasncp_tlv_ip_address_mask                   = -1;
static gint ett_wimaxasncp_tlv_vendor_specific_information_field = -1;

/* Header size, up to, but not including, the TLV fields. */
#define WIMAXASNCP_HEADER_SIZE       20

/* Offset to end of the length field in the headder. */
#define WIMAXASNCP_HEADER_LENGTH_END 6

#define WIMAXASNCP_BIT32(n) (1 << (31 - (n)))
#define WIMAXASNCP_BIT16(n) (1 << (15 - (n)))
#define WIMAXASNCP_BIT8(n)  (1 << ( 7 - (n)))

#define WIMAXASNCP_FLAGS_T  WIMAXASNCP_BIT8(6)
#define WIMAXASNCP_FLAGS_R  WIMAXASNCP_BIT8(7)

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x) (x) = (x)
#endif

/* ------------------------------------------------------------------------- */
/* generic
 */

static const value_string wimaxasncp_tlv_success_failure_vals[] =
{
    { 0, "Success"},
    { 1, "Failure"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_flag_vals[] =
{
    { WIMAXASNCP_BIT8(0), "Reserved" },
    { WIMAXASNCP_BIT8(1), "Reserved" },
    { WIMAXASNCP_BIT8(2), "Reserved" },
    { WIMAXASNCP_BIT8(3), "Reserved" },
    { WIMAXASNCP_BIT8(4), "Reserved" },
    { WIMAXASNCP_BIT8(5), "Reserved" },
    { WIMAXASNCP_FLAGS_T, "T - Source and Destination Identifier TLVs"},
    { WIMAXASNCP_FLAGS_R, "R - Reset Next Expected Transaction ID"},
    { 0,                  NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_op_id_vals[] =
{
    { 0,   "Invalid"},
    { 1,   "Request/Initiation"},
    { 2,   "Response"},
    { 3,   "Ack"},
    { 4,   "Indication"},
    { 5,   "Reserved"},
    { 6,   "Reserved"},
    { 7,   "Reserved"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

#define WIMAXASNCP_FT_QOS                 1
#define WIMAXASNCP_FT_HO_CONTROL          2
#define WIMAXASNCP_FT_DATA_PATH_CONTROL   3
#define WIMAXASNCP_FT_CONTEXT_DELIVERY    4
#define WIMAXASNCP_FT_R3_MOBILITY         5
#define WIMAXASNCP_FT_PAGING              6
#define WIMAXASNCP_FT_RRM                 7
#define WIMAXASNCP_FT_AUTHENTICATION      8
#define WIMAXASNCP_FT_MS_STATE            9
#define WIMAXASNCP_FT_REAUTHENTICATION    10
#define WIMAXASNCP_FT_SESSION             11    /* Nokia recommended value */

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_function_type_vals[] =
{
    { WIMAXASNCP_FT_QOS,               "QoS"},
    { WIMAXASNCP_FT_HO_CONTROL,        "HO Control"},
    { WIMAXASNCP_FT_DATA_PATH_CONTROL, "Data Path Control"},
    { WIMAXASNCP_FT_CONTEXT_DELIVERY,  "Context Delivery"},
    { WIMAXASNCP_FT_R3_MOBILITY,       "R3 Mobility"},
    { WIMAXASNCP_FT_PAGING,            "Paging"},
    { WIMAXASNCP_FT_RRM,               "RRM"},
    { WIMAXASNCP_FT_AUTHENTICATION,    "Authentication"},
    { WIMAXASNCP_FT_MS_STATE,          "MS State"},
    { WIMAXASNCP_FT_REAUTHENTICATION,  "Re-Authentication"},
    { WIMAXASNCP_FT_SESSION,           "Session"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_qos_msg_vals[] =
{
    { 1,  "RR_Ack"},
    { 2,  "RR_Req"},
    { 3,  "RR_Rsp"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_ho_control_msg_vals[] =
{
    { 1,  "HO_Ack"},
    { 2,  "HO_Complete"},
    { 3,  "HO_Cnf"},
    { 4,  "HO_Req"},
    { 5,  "HO_Rsp"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_data_path_control_msg_vals[] =
{
    { 1,   "Path_Dereg_Ack"},
    { 2,   "Path_Dereg_Req"},
    { 3,   "Path_Dereg_Rsp"},
    { 4,   "Path_Modification_Ack"},
    { 5,   "Path_Modification_Req"},
    { 6,   "Path_Modification_Rsp"},
    { 7,   "Path_Prereg_Ack"},
    { 8,   "Path_Prereg_Req"},
    { 9,   "Path_Prereg_Rsp"},
    { 10,  "Path_Reg_Ack"},
    { 11,  "Path_Reg_Req"},
    { 12,  "Path_Reg_Rsp"},

    /* see also wimaxasncp_ms_state_msg_vals[] */
    { 13,  "MS_Attachment_Req (DPC)"},
    { 14,  "MS_Attachment_Rsp (DPC)"},
    { 15,  "MS_Attachment_Ack (DPC)"},

    { 16,  "Key_Change_Directive"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_context_delivery_msg_vals[] =
{
    { 1,  "Context_Rpt"},
    { 2,  "Context_Req"},
    { 3,  "Context_Ack"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_r3_mobility_msg_vals[] =
{
    { 1,  "Anchor_DPF_HO_Req"},
    { 2,  "Anchor_DPF_HO_Trigger"},
    { 3,  "Anchor_DPF_HO_Rsp"},
    { 4,  "Anchor_DPF_Relocate_Req"},
    { 5,  "FA_Register_Req"},
    { 6,  "FA_Register_Rsp"},
    { 7,  "Anchor_DPF_Relocate_Rsp"},
    { 8,  "FA_Revoke_Req"},
    { 9,  "FA_Revoke_Rsp"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_paging_msg_vals[] =
{
    { 1,  "Initiate_Paging_Req"},
    { 2,  "Initiate_Paging_Rsp"},
    { 3,  "LU_Cnf"},
    { 4,  "LU_Req"},
    { 5,  "LU_Rsp"},
    { 6,  "Paging_Announce"},
    { 7,  "CMAC_Key_Count_Req"},
    { 8,  "CMAC_Key_Count_Rsp"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_rrm_msg_vals[] =
{
    { 1,  "R6 PHY_Parameters_Req"},
    { 2,  "R6 PHY_Parameters_Rpt"},
    { 3,  "R4/R6 Spare_Capacity_Req"},
    { 4,  "R4/R6 Spare_Capacity_Rpt"},
    { 5,  "R6 Neighbor_BS_Resource_Status_Update"},
    { 6,  "R4/R6 Radio_Config_Update_Req"},
    { 7,  "R4/R6 Radio_Config_Update_Rpt"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_authentication_msg_vals[] =
{
    { 1,  "AR_Authenticated_EAP_Start"},
    { 2,  "AR_Authenticated_EAP_Transfer"},
    { 3,  "AR_EAP_Start"},
    { 4,  "AR_EAP_Transfer"},
    { 5,  "AR_EAP_Complete"},
    { 6,  "CMAC_Key_Count_Update"},       /* Nokia recommended value */
    { 7,  "CMAC_Key_Count_Update_Ack"},   /* Nokia recommended value */
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_ms_state_msg_vals[] =
{
    { 1,  "IM_Entry_State_Change_Req"},
    { 2,  "IM_Entry_State_Change_Rsp"},
    { 3,  "IM_Exit_State_Change_Req"},
    { 4,  "IM_Exit_State_Change_Rsp"},
    { 5,  "NW_ReEntry_State_Change_Directive"},
    { 6,  "MS_PreAttachment_Req"},
    { 7,  "MS_PreAttachment_Rsp"},
    { 8,  "MS_PreAttachment_Ack"},
    { 9,  "MS_Attachment_Req"},
    { 10, "MS_Attachment_Rsp"},
    { 11, "MS_Attachment_Ack"},
    { 12, "IM_Entry_State_Change_Ack"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_reauthentication_msg_vals[] =
{
    { 1,  "AR_EAP_Start"},
    { 2,  "Key_Change_Directive"},
    { 3,  "Key_Change_Cnf"},
    { 4,  "Relocation_Cnf"},
    { 5,  "Relocation_Confirm_Ack"},
    { 6,  "Relocation_Notify"},
    { 7,  "Relocation_Notify_Ack"},
    { 8,  "Relocation_Req"},
    { 9,  "Relocation_Rsp"},
    { 10, "Key_Change_Ack"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_session_msg_vals[] =
{
    { 1,  "Session_Release_Req"},  /* Nokia recommended value */
    { 2,  "Session_Release_Rsp"},  /* Nokia recommended value */
    { 3,  "Session_Release_Ack"},  /* Nokia recommended value */
    { 4,  "Session_Failure_Rpt"},  /* Nokia recommended value */
    { 5,  "Session_Failure_Rsp"},  /* Nokia recommended value */
    { 0,   NULL}
};

/* ========================================================================= */

typedef struct {
    guint8 function_type;
    const value_string *vals;
} wimaxasncp_func_msg_t;

/* ------------------------------------------------------------------------ */

static const wimaxasncp_func_msg_t wimaxasncp_func_to_msg_vals_map[] =
{
    { WIMAXASNCP_FT_QOS,               wimaxasncp_qos_msg_vals },
    { WIMAXASNCP_FT_HO_CONTROL,        wimaxasncp_ho_control_msg_vals },
    { WIMAXASNCP_FT_DATA_PATH_CONTROL, wimaxasncp_data_path_control_msg_vals },
    { WIMAXASNCP_FT_CONTEXT_DELIVERY,  wimaxasncp_context_delivery_msg_vals },
    { WIMAXASNCP_FT_R3_MOBILITY,       wimaxasncp_r3_mobility_msg_vals },
    { WIMAXASNCP_FT_PAGING,            wimaxasncp_paging_msg_vals },
    { WIMAXASNCP_FT_RRM,               wimaxasncp_rrm_msg_vals },
    { WIMAXASNCP_FT_AUTHENTICATION,    wimaxasncp_authentication_msg_vals },
    { WIMAXASNCP_FT_MS_STATE,          wimaxasncp_ms_state_msg_vals },
    { WIMAXASNCP_FT_REAUTHENTICATION,  wimaxasncp_reauthentication_msg_vals },
    { WIMAXASNCP_FT_SESSION,           wimaxasncp_session_msg_vals }
};

/* =========================================================================
 * TLV related structures.
 * Note: The value_string structures and TLV types are kept in the same
 * order as found in the spec.
 * ========================================================================= */

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_accept_reject_indicator_vals[]=
{
    { 0x00, "accept"},
    { 0x01, "reject"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_action_code_vals[] =
{
    { 0x0000, "Deregister MS"},
    { 0x0001, "Suspend all MS traffic"},
    { 0x0002, "Suspend user traffic"},
    { 0x0003, "Resume traffic"},
    { 0x0004, "MS terminate current normal operations with BS"},
    { 0,      NULL}
};

/* ------------------------------------------------------------------------- */

static const
value_string wimaxasncp_tlv_anchor_pc_relocation_request_response_vals[] =
{
    { 0xff,  "accept"},
    { 0x00,  "refuse"},
    { 0,     NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_auth_ind_vals[]=
{
    { 0, "Initial authentication"},
    { 1, "Re-authentication"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_authorization_policy_vals[] =
{
    { WIMAXASNCP_BIT16(0),  "RSA authorization"},
    { WIMAXASNCP_BIT16(1),  "EAP authorization"},
    { WIMAXASNCP_BIT16(2),  "Authenticated-EAP authorization"},
    { WIMAXASNCP_BIT16(3),  "HMAC supported"},
    { WIMAXASNCP_BIT16(4),  "CMAC supported"},
    { WIMAXASNCP_BIT16(5),  "64-bit Short-HMAC"},
    { WIMAXASNCP_BIT16(6),  "80-bit Short-HMAC"},
    { WIMAXASNCP_BIT16(7),  "96-bit Short-HMAC"},
    { WIMAXASNCP_BIT16(8),  "Reauthentication Policy (TBD)"},
    { WIMAXASNCP_BIT16(9),  "Reauthentication Policy (TBD)"},
    { WIMAXASNCP_BIT16(10), "Reauthentication Policy (TBD)"},
    { WIMAXASNCP_BIT16(11), "Reauthentication Policy (TBD)"},
    { WIMAXASNCP_BIT16(12), "Reauthentication Policy (TBD)"},
    { WIMAXASNCP_BIT16(13), "Reauthentication Policy (TBD)"},
    { WIMAXASNCP_BIT16(14), "Reauthentication Policy (TBD)"},
    { WIMAXASNCP_BIT16(15), "Reauthentication Policy (TBD)"},
    { 0,                    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_classifier_action_vals[] =
{
    { 0, "Add Classifier"},
    { 1, "Replace Classifier"},
    { 2, "Delete Classifier"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_classifier_type_vals[] =
{
    { 1,  "IP TOS/DSCP Range and Mask"},
    { 2,  "Protocol"},
    { 3,  "IP Source Address and Mask"},
    { 4,  "IP Destination Address and Mask"},
    { 5,  "Protocol Source Port Range"},
    { 6,  "Protocol Destination Port Range"},
    { 7,  "IEEE 802.3/Ethernet Destination MAC address"},
    { 8,  "IEEE 802.3/Ethernet Source MAC address"},
    { 9,  "Ethertype/IEEE 802.2 SAP"},
    { 10, "IEEE 802.1D User_Priority"},
    { 11, "IEEE 802.1Q VLAN_ID"},
    { 0,  NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_combined_resources_required_vals[] =
{
    { 0x0000, "Not combined"},
    { 0x0001, "Combined"},
    { 0,      NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_context_purpose_indicator_vals[] =
{
    { WIMAXASNCP_BIT32(0), "MS AK Context"},
    { WIMAXASNCP_BIT32(1), "MS Network Context"},
    { WIMAXASNCP_BIT32(2), "MS MAC Context"},
    { WIMAXASNCP_BIT32(3), "Service Authorization Context"},
    { WIMAXASNCP_BIT32(4), "FA Context"},
    { 0,                   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_cryptographic_suite_vals[] =
{
    { 0x000000, "No data encryption, no data authentication & 3-DES, 128"},
    { 0x010001, "CBC-Mode 56-bit DES, no data authentication & 3-DES, 128"},
    { 0x000002, "No data encryption, no data authentication & RSA, 1024"},
    { 0x010002, "CBC-Mode 56-bit DES, no data authentication & RSA, 1024"},
    { 0x020103, "CCM-Mode 128-bit AES, CCM-Mode, 128-bit, ECB mode AES"
                " with 128-bit key"},
    { 0x020104, "CCM-Mode 128bits AES, CCM-Mode, AES Key Wrap with 128-bit"
                " key"},
    { 0x030003, "CBC-Mode 128-bit AES, no data authentication, ECB mode AES"
                " with 128-bit key"},
    { 0x800003, "MBS CTR Mode 128 bits AES, no data authentication, AES ECB"
                " mode with 128-bit key"},
    { 0x800004, "MBS CTR mode 128 bits AES, no data authentication, AES Key"
                " Wrap with 128-bit key"},
    { 0,        NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_cs_type_vals[]=
{
    { 1, "Packet, IPv4"},
    { 2, "Packet, IPv6"},
    { 3, "Packet, 802.3"},
    { 4, "Packet, 802.1Q"},
    { 5, "Packet, IPv4over802.3"},
    { 6, "Packet, IPv6over802.3"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_data_integrity_vals[] =
{
    { 0x0, "No recommendation"},
    { 0x1, "Data integrity requested"},
    { 0x2, "Data delay jitter sensitive"},
    { 0,   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_data_path_encapsulation_type_vals[] =
{
    { 1, "GRE"},
    { 2, "IP-in-IP"},
    { 3, "VLAN"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxasncp_tlv_data_path_establishment_option_vals[] =
{
    { 0, "Do not (Pre-) Establish DP"},
    { 1, "(Pre-) Establish DP"},
    { 0, NULL }
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_data_path_integrity_mechanism_vals[]=
{
    /* No values defined yet. */
    { 0,     NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_data_path_type_vals[]=
{
    { 0, "Type1"},
    { 1, "Type2"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxasncp_tlv_device_authentication_indicator_vals[]=
{
    { 0, "Reserved"},
    { 1, "Certificate-based device authentication has been successfully"
         " performed"},
    { 2, "Device authentication has been successfully performed."},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_direction_vals[] =
{
    { 0x001, "For Uplink"},
    { 0x002, "For Downlink"},
    { 0,     NULL}
};

/* ------------------------------------------------------------------------- */

static
const value_string wimaxasncp_tlv_exit_idle_mode_operation_indication_vals[]=
{
    { 0, "No"},
    { 1, "Yes"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_failure_indication_vals[]=
{
    { 0,  "Unspecified Error"},
    { 1,  "Incompatible Version Number"},
    { 2,  "Invalid Function Type"},
    { 3,  "Invalid Message Type"},
    { 4,  "Unknown MSID"},
    { 5,  "Transaction Failure"},
    { 6,  "Unknown Source Identifier"},
    { 7,  "Unknown Destination Identifier"},
    { 8,  "Invalid Message Header"},
    { 16, "Invalid message format"},
    { 17, "Mandatory TLV missing"},
    { 18, "TLV Value Invalid"},
    { 19, "Unsupported Options"},
    { 32, "Timer expired without response"},
    { 48, "Requested Context Unavailable"},
    { 49, "Authorization Failure"},
    { 50, "Registration Failure"},
    { 51, "No Resources"},
    { 0,  NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_ho_confirm_type_vals[] =
{
    { 0, "Confirm"},
    { 1, "Unconfirm"},
    { 2, "Cancel"},
    { 3, "Reject"},
    { 0,  NULL}
};

static const value_string wimaxasncp_tlv_ho_type_vals[] =
{
    { 0, "HHO"},
    { 0, NULL }
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_location_update_status_vals[]=
{
    { 0, "Refuse"},
    { 1, "Accept"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const
value_string wimaxasncp_tlv_location_update_success_failure_indication_vals[]=
{
    { 0, "Success"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_ms_mobility_mode_vals[]=
{
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_network_exit_indicator_vals[]=
{
    { 0x00, "MS Power Down indication"},
    { 0x01, "Radio link with MS is lost"},
    { 0,    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_paging_cause_vals[]=
{
    { 1, "LCS"},
    { 2, "Incoming Data for Idle MS"},
    { 3, "Acknowledge Exiting Idle Mode"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_phs_rule_action_vals[]=
{
    { 0, "Add PHS Rule"},
    { 1, "Replace PHS Rule"},
    { 2, "Delete PHS Rule"},
    { 3, "Delete All PHS Rules"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_phsv_vals[]=
{
    { 0, "Verify"},
    { 1, "Don't verify"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_pkm_context_vals[]=
{
    { 0, "PKM Capabilities defined in the MTG Profile."},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_pkm2_vals[]=
{
    { 18, "EAP Transfer"},
    { 19, "Authenticated EAP Transfer"},
    { 29, "EAP Complete"},
    { 0,  NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_reg_context_vals[] =
{
    { 0, "REG handshake related capabilities defined in the MTG Profile"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_registration_type_vals[] =
{
    { 0, "Initial Network Entry"},
    { 1, "HO"},
    { 2, "In-Service Data Path Establishment"},
    { 3, "MS Network Exit"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_reservation_action_vals[] =
{
    { WIMAXASNCP_BIT16(15), "Create service flow"},
    { WIMAXASNCP_BIT16(14), "Admit service flow"},
    { WIMAXASNCP_BIT16(13), "Activate service flow"},
    { WIMAXASNCP_BIT16(12), "Modify service flow"},
    { WIMAXASNCP_BIT16(11), "Delete service flow"},
    { 0,                     NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_reservation_result_vals[] =
{
    { 0x0000, "Successfully Created"},
    { 0x0001, "Request Denied - No resources"},
    { 0x0002, "Request Denied due to Policy"},
    { 0x0003, "Request Denied due to Requests for Other Flows Failed"},
    { 0x0004, "Request Failed (Unspecified reason)"},
    { 0x0005, "Request Denied due to MS reason"},
    { 0,      NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_request_transmission_policy_vals[]=
{
    { WIMAXASNCP_BIT32(0), "Service flow SHALL not use broadcast bandwidth"
                           " request opportunities"},
    { WIMAXASNCP_BIT32(1), "Reserved"},
    { WIMAXASNCP_BIT32(2), "Service flow SHALL not piggyback requests"
                           " with data"},
    { WIMAXASNCP_BIT32(3), "Service flow SHALL not fragment data"},
    { WIMAXASNCP_BIT32(4), "Service flow SHALL not suppress payload headers"},
    { WIMAXASNCP_BIT32(5), "Service flow SHALL not pack multiple SDUs"
                           " (or fragments) into single MAC PDUs"},
    { WIMAXASNCP_BIT32(6), "Service flow SHALL not include CRC in the"
                           " MAC PDU"},
    {0,                    NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_response_code_vals[]=
{
    { 1, "not allowed - Paging Reference is zero"},
    { 2, "not allowed - no such SF"},
    { 0,  NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_rrm_reporting_characteristics_vals[]=
{
    { WIMAXASNCP_BIT32(0), "periodically as defined by reporting period P"},
    { WIMAXASNCP_BIT32(1), "regularly whenever resources have changed as"
                           " defined by RT since the last measurement"
                           " period"},
    { WIMAXASNCP_BIT32(2), "regularly whenever resources cross predefined"
                           " total threshold(s) defined by reporting"
                           " absolute threshold values J"},
    { WIMAXASNCP_BIT32(3), "DCD/UCD Configuration Change Count modification"},
    { 0,                   NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_rrm_spare_capacity_report_type_vals[]=
{
    { 0, "Type 1: Available radio resource indicator"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_r3_operation_status_vals[]=
{
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_r3_release_reason_vals[]=
{
    { 0, "MS power down"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_sa_service_type_vals[]=
{
    { 0, "Unicast Service"},
    { 1, "Group Multicast Service"},
    { 2, "MBS Service"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_sa_type_vals[]=
{
    { 0, "Primary"},
    { 1, "Static"},
    { 2, "Dynamic"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_serving_target_indicator_vals[] =
{
    { 0, "Serving"},
    { 1, "Target"},
    { 0, NULL}
};

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_tlv_sf_classification_vals[]=
{
    { 0, "SF classification not supported"},
    { 1, "SF classification supported"},
    { 0, NULL}
};

/* -------------------------------------------------------------------------
 * decode types
 * ------------------------------------------------------------------------- */

enum
{
    WIMAXASNCP_TLV_TBD,
    WIMAXASNCP_TLV_COMPOUND,
    WIMAXASNCP_TLV_BYTES,
    WIMAXASNCP_TLV_ENUM8,
    WIMAXASNCP_TLV_ENUM16,
    WIMAXASNCP_TLV_ENUM32,
    WIMAXASNCP_TLV_ETHER,
    WIMAXASNCP_TLV_ASCII_STRING,
    WIMAXASNCP_TLV_FLAG0,
    WIMAXASNCP_TLV_BITFLAGS16,
    WIMAXASNCP_TLV_BITFLAGS32,
    WIMAXASNCP_TLV_ID,
    WIMAXASNCP_TLV_HEX8,
    WIMAXASNCP_TLV_HEX16,
    WIMAXASNCP_TLV_HEX32,
    WIMAXASNCP_TLV_DEC8,
    WIMAXASNCP_TLV_DEC16,
    WIMAXASNCP_TLV_DEC32,
    WIMAXASNCP_TLV_IP_ADDRESS,   /* Note: IPv4 or IPv6, determined by length */
    WIMAXASNCP_TLV_IPV4_ADDRESS,
    WIMAXASNCP_TLV_PROTOCOL_LIST,
    WIMAXASNCP_TLV_PORT_RANGE_LIST,
    WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST,
    WIMAXASNCP_TLV_VENDOR_SPECIFIC
};

/* -------------------------------------------------------------------------
 * TLV database
 * ------------------------------------------------------------------------- */

typedef struct {
    guint16 type;
    const gchar *name;
    gint decode_type;
    const value_string *vals;
} wimaxasncp_tlv_info_t;

/* ------------------------------------------------------------------------- */

static const wimaxasncp_tlv_info_t wimaxasncp_tlv_db[] =
{
    {
        1,     "Accept/Reject Indicator",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_accept_reject_indicator_vals
    },
    {
        2,     "Accounting Extension",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        3,     "Action Code",
        WIMAXASNCP_TLV_ENUM16,
        wimaxasncp_tlv_action_code_vals
    },
    {
        4,     "Action Time",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        5,     "AK",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        6,     "AK Context",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        7,     "AK ID",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        8,     "AK Lifetime",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        9,     "AK SN",
        WIMAXASNCP_TLV_HEX8,
        NULL
    },
    {
        10,    "Anchor ASN GW ID / Anchor DPF Identifier",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        11,    "Anchor MM Context",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        12,    "Anchor PCID - Anchor Paging Controller ID",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        13,    "Anchor PC Relocation Destination",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        14,    "Anchor PC Relocation Request Response",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_anchor_pc_relocation_request_response_vals
    },
    {
        15,    "Associated PHSI",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        16,    "Anchor Authenticator ID",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        17,    "Authentication Complete",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        18,    "Authentication Result",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_success_failure_vals
    },
    {
        19,    "Authenticator Identifier",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        20,    "Auth-IND",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_auth_ind_vals
    },
    {
        21,    "Authorization Policy",
        WIMAXASNCP_TLV_BITFLAGS16,
        wimaxasncp_tlv_authorization_policy_vals
    },
    {
        22,    "Available Radio Resource DL",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        23,    "Available Radio Resource UL",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        24,    "BE Data Delivery Service",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        25,    "BS ID",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        26,    "BS Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        27,    "BS-originated EAP-Start Flag",
        WIMAXASNCP_TLV_FLAG0,
        NULL
    },
    {
        28,    "Care-Of Address (CoA)",
        WIMAXASNCP_TLV_IPV4_ADDRESS,
        NULL
    },
    {
        29,    "CID",
        WIMAXASNCP_TLV_HEX16,
        NULL
    },
    {
        30,    "Classifier",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        31,    "Classifier Action",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_classifier_action_vals
    },
    {
        32,    "Classifier Rule Priority",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        33,    "Classifier Type",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_classifier_type_vals
    },
    {
        34,    "CMAC_KEY_COUNT",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        35,    "Combined Resources Required",
        WIMAXASNCP_TLV_ENUM16,
        wimaxasncp_tlv_combined_resources_required_vals
    },
    {
        36,    "Context Purpose Indicator",
        WIMAXASNCP_TLV_ENUM32,
        wimaxasncp_tlv_context_purpose_indicator_vals
    },
    {
        37,    "Correlation ID",
        WIMAXASNCP_TLV_HEX32,
        NULL
    },
    {
        38,    "Cryptographic Suite",
        WIMAXASNCP_TLV_ENUM32,
        wimaxasncp_tlv_cryptographic_suite_vals
    },
    {
        39,    "CS Type",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_cs_type_vals
    },
    {
        40,    "Data Integrity",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_data_integrity_vals
    },
    {
        41,    "Data Integrity Info",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        42,    "Data Path Encapsulation Type",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_data_path_encapsulation_type_vals
    },
    {
        43,    "Data Path Establishment Option",
        WIMAXASNCP_TLV_HEX8,
        wimaxasncp_tlv_data_path_establishment_option_vals
    },
    {
        44,    "Data Path ID",
        WIMAXASNCP_TLV_HEX32,
        NULL
    },
    {
        45,    "Data Path Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        46,    "Data Path Integrity Mechanism",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_data_path_integrity_mechanism_vals
    },
    {
        47,    "Data Path Type",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_data_path_type_vals
    },
    {
        48,    "DCD/UCD Configuration Change Count",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        49,    "DCD Setting",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        50,    "Device Authentication Indicator",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_device_authentication_indicator_vals
    },
    {
        51,    "DHCP Key",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        52,    "DHCP Key ID",
        WIMAXASNCP_TLV_HEX32,
        NULL
    },
    {
        53,    "DHCP Key Lifetime",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        54,    "DHCP Proxy Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        55,    "DHCP Relay Address",
        WIMAXASNCP_TLV_IPV4_ADDRESS,
        NULL
    },
    {
        56,    "DHCP Relay Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        57,    "DHCP Server Address",
        WIMAXASNCP_TLV_IPV4_ADDRESS,
        NULL
    },
    {
        58,    "DHCP Server List",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        59,    "Direction",
        WIMAXASNCP_TLV_ENUM16,
        wimaxasncp_tlv_direction_vals
    },
    {
        60,    "DL PHY Quality Info",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        61,    "DL PHY Service Level",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        62,    "EAP Payload",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        63,    "EIK",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        64,    "ERT-VR Data Delivery Service",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        65,    "Exit IDLE Mode Operation Indication",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_exit_idle_mode_operation_indication_vals
    },
    {
        66,    "FA-HA Key",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        67,    "FA-HA Key Lifetime",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        68,    "FA-HA Key SPI",
        WIMAXASNCP_TLV_HEX32,
        NULL
    },
    {
        69,    "Failure Indication",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_failure_indication_vals
    },
    {
        70,    "FA IP Address",
        WIMAXASNCP_TLV_IPV4_ADDRESS,
        NULL
    },
    {
        71,    "FA Relocation Indication",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_success_failure_vals
    },
    {
        72,    "Full DCD Setting",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        73,    "Full UCD Setting",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        74,    "Global Service Class Change",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        75,    "HA IP Address",
        WIMAXASNCP_TLV_IP_ADDRESS,
        NULL
    },
    {
        76,    "HO Confirm Type",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_ho_confirm_type_vals
    },
    {
        77,    "Home Address (HoA)",
        WIMAXASNCP_TLV_IPV4_ADDRESS,
        NULL
    },
    {
        78,    "HO Process Optimization",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        79,    "HO Type",
        WIMAXASNCP_TLV_ENUM32,
        wimaxasncp_tlv_ho_type_vals
    },
    {
        80,    "IDLE Mode Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        81,    "IDLE Mode Retain Info",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        82,    "IP Destination Address and Mask",
        WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST,
        NULL
    },
    {
        83,    "IP Remained Time",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        84,    "IP Source Address and Mask",
        WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST,
        NULL
    },
    {
        85,    "IP TOS/DSCP Range and Mask",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        86,    "Key Change Indicator",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_success_failure_vals
    },
    {
        87,    "L-BSID",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        88,    "Location Update Status",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_location_update_status_vals
    },
    {
        89,    "Location Update Success/Failure Indication",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_location_update_success_failure_indication_vals
    },
    {
        90,    "LU Result Indicator",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_success_failure_vals
    },
    {
        91,    "Maximum Latency",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        92,    "Maximum Sustained Traffic Rate",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        93,    "Maximum Traffic Burst",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        94,    "Media Flow Type",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        95,    "Minimum Reserved Traffic Rate",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        96,    "MIP4 Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        97,    "MIP4 Security Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        98,    "MN-FA Key",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        99,    "MN-FA SPI",
        WIMAXASNCP_TLV_HEX32,
        NULL
    },
    {
        100,   "MS Authorization Context",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        101,   "MS FA Context",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        102,   "MS ID",
        WIMAXASNCP_TLV_ETHER,
        NULL
    },
    {
        103,   "MS Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        104,   "MS Mobility Mode",
        WIMAXASNCP_TLV_TBD,
        wimaxasncp_tlv_ms_mobility_mode_vals
    },
    {
        105,   "MS NAI",
        WIMAXASNCP_TLV_ASCII_STRING,
        NULL
    },
    {
        106,   "MS Networking Context",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        107,   "MS Security Context",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        108,   "MS Security History",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        109,   "Network Exit Indicator",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_network_exit_indicator_vals
    },
    {
        110,   "Newer TEK Parameters",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        111,   "NRT-VR Data Delivery Service",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        112,   "Older TEK Parameters",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        113,   "Old Anchor PCID",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        114,   "Packet Classification Rule / Media Flow Description",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        115,   "Paging Announce Timer",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        116,   "Paging Cause",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_paging_cause_vals
    },
    {
        117,   "Paging Controller Identifier",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        118,   "Paging Cycle",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        119,   "Paging Information",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        120,   "Paging Offset",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        121,   "Paging Start/Stop",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        122,   "PC Relocation Indication",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        123,   "PGID - Paging Group ID",
        WIMAXASNCP_TLV_HEX16,
        NULL
    },
    {
        124,   "PHSF",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        125,   "PHSI",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        126,   "PHSM",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        127,   "PHS Rule",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        128,   "PHS Rule Action",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_phs_rule_action_vals
    },
    {
        129,   "PHSS",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        130,   "PHSV",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_phsv_vals
    },
    {
        131,   "PKM Context",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_pkm_context_vals
    },
    {
        132,   "PMIP4 Client Location",
        WIMAXASNCP_TLV_IPV4_ADDRESS,
        NULL
    },
    {
        133,   "PMK SN",
        WIMAXASNCP_TLV_HEX8,
        NULL
    },
    {
        134,   "PKM2",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_pkm2_vals
    },
    {
        135,   "PMK2 SN",
        WIMAXASNCP_TLV_HEX8,
        NULL
    },
    {
        136,   "PN Counter",
        WIMAXASNCP_TLV_HEX32,
        NULL
    },
    {
        137,   "Preamble Index/Sub-channel Index",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        138,   "Protocol",
        WIMAXASNCP_TLV_PROTOCOL_LIST,
        NULL
    },
    {
        139,   "Protocol Destination Port Range",
        WIMAXASNCP_TLV_PORT_RANGE_LIST,
        NULL
    },
    {
        140,   "Protocol Source Port Range",
        WIMAXASNCP_TLV_PORT_RANGE_LIST,
        NULL
    },
    {
        141,   "QoS Parameters",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        142,   "Radio Resource Fluctuation",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        143,   "Reduced Resources Code",
        WIMAXASNCP_TLV_FLAG0,
        NULL
    },
    {
        144,   "REG Context",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_reg_context_vals
    },
    {
        145,   "Registration Type",
        WIMAXASNCP_TLV_ENUM32,
        wimaxasncp_tlv_registration_type_vals
    },
    {
        146,   "Relative Delay",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        147,   "Relocation Destination ID",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        148,   "Relocation Response",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        149,   "Relocation Success Indication",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        150,   "Request/Transmission Policy",
        WIMAXASNCP_TLV_BITFLAGS32,
        wimaxasncp_tlv_request_transmission_policy_vals
    },
    {
        151,   "Reservation Action",
        WIMAXASNCP_TLV_BITFLAGS16,
        wimaxasncp_tlv_reservation_action_vals
    },
    {
        152,   "Reservation Result",
        WIMAXASNCP_TLV_ENUM16,
        wimaxasncp_tlv_reservation_result_vals
    },
    {
        153,   "Response Code",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_response_code_vals
    },
    {
        154,   "Result Code",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_success_failure_vals
    },
    {
        155,   "ROHC/ECRTP Context ID",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        156,   "Round Trip Delay",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        157,   "RRM Absolute Threshold Value J",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        158,   "RRM Averaging Time T",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        159,   "RRM BS Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        160,   "RRM BS-MS PHY Quality Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        161,   "RRM Relative Threshold RT",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        162,   "RRM Reporting Characteristics",
        WIMAXASNCP_TLV_BITFLAGS32,
        wimaxasncp_tlv_rrm_reporting_characteristics_vals
    },
    {
        163,   "RRM Reporting Period P",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        164,   "RRM Spare Capacity Report Type",
        WIMAXASNCP_TLV_HEX8,
        wimaxasncp_tlv_rrm_spare_capacity_report_type_vals
    },
    {
        165,   "RT-VR Data Delivery Service",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        166,   "RxPN Counter",
        WIMAXASNCP_TLV_HEX32,
        NULL
    },
    {
        167,   "R3 Operation Status",
        WIMAXASNCP_TLV_TBD,
        wimaxasncp_tlv_r3_operation_status_vals
    },
    {
        168,   "R3 Release Reason",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_r3_release_reason_vals
    },
    {
        169,   "SAID",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        170,   "SA Descriptor",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        171,   "SA Index",
        WIMAXASNCP_TLV_HEX32,
        NULL
    },
    {
        172,   "SA Service Type",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_sa_service_type_vals
    },
    {
        173,   "SA Type",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_sa_type_vals
    },
    {
        174,   "SBC Context",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        175,   "SDU BSN Map",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        176,   "SDU Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        177,   "SDU Size",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        178,   "SDU SN",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        179,   "Service Class Name",
        WIMAXASNCP_TLV_ASCII_STRING,
        NULL
    },
    {
        180,   "Service Level Prediction",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        181,   "Service Authorization Code",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        182,   "Serving/Target Indicator",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_serving_target_indicator_vals
    },
    {
        183,   "SF Classification",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_sf_classification_vals
    },
    {
        184,   "SFID",
        WIMAXASNCP_TLV_HEX32,
        NULL
    },
    {
        185,   "SF Info",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        186,   "Spare Capacity Indicator",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        187,   "TEK",
        WIMAXASNCP_TLV_BYTES,
        NULL
    },
    {
        188,   "TEK Lifetime",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        189,   "TEK SN",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        190,   "Tolerated Jitter",
        WIMAXASNCP_TLV_DEC32,
        NULL
    },
    {
        191,   "Total Slots DL",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        192,   "Total Slots UL",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        193,   "Traffic Priority/QoS Priority",
        WIMAXASNCP_TLV_DEC8,
        NULL
    },
    {
        194,   "Tunnel Endpoint",
        WIMAXASNCP_TLV_IP_ADDRESS,
        NULL
    },
    {
        195,   "UCD Setting",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        196,   "UGS Data Delivery Service",
        WIMAXASNCP_TLV_COMPOUND,
        NULL
    },
    {
        197,   "UL PHY Quality Info",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        198,   "UL PHY Service Level",
        WIMAXASNCP_TLV_TBD,
        NULL
    },
    {
        199,   "Unsolicited Grant Interval",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        200,   "Unsolicited Polling Interval",
        WIMAXASNCP_TLV_DEC16,
        NULL
    },
    {
        201,   "VAAA IP Address",
        WIMAXASNCP_TLV_IP_ADDRESS,
        NULL
    },
    {
        202,   "VAAA Realm",
        WIMAXASNCP_TLV_ASCII_STRING,
        NULL
    },
    {
        1136,  "Control Plane Indicator",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_success_failure_vals
    },
    {
        1228,  "IM Auth Indication",
        WIMAXASNCP_TLV_ENUM8,
        wimaxasncp_tlv_success_failure_vals
    },
    {
        0xff01, "Source Identifier",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        0xff02, "Destination Identifier",
        WIMAXASNCP_TLV_ID,
        NULL
    },
    {
        0xffff, "Vendor Specific",
        WIMAXASNCP_TLV_VENDOR_SPECIFIC,
        NULL
    }
};

/* ========================================================================= */

static const wimaxasncp_tlv_info_t *wimaxasncp_get_tlv_info(
    guint16 type)
{
    static wimaxasncp_tlv_info_t not_found =
    {
        0,     "Unknown",
        WIMAXASNCP_TLV_BYTES,
        NULL
    };

    gsize i;
    for (i = 0; i < array_length(wimaxasncp_tlv_db); ++i)
    {
        if (wimaxasncp_tlv_db[i].type == type)
        {
            return &wimaxasncp_tlv_db[i];
        }
    }

    if (debug_enabled)
    {
        g_print("fix-me: unknown TLV type: %u\n", type);
    }

    return &not_found;
}

/* ========================================================================= */

static const gchar *wimaxasncp_get_enum_name(
    const wimaxasncp_tlv_info_t *tlv_info,
    guint32 value)
{

    if (tlv_info->vals != NULL)
    {
        const gchar *name = match_strval(value, tlv_info->vals);
        if (name != NULL)
        {
            return name;
        }
    }

    return "Unknown";
}

/* ========================================================================= */

static void wimaxasncp_proto_treee_add_tlv_ipv4_value(
    tvbuff_t *tvb,
    proto_tree *tree,
    proto_item *tlv_item,
    guint offset)
{
    guint32 ip;
    ip = tvb_get_ipv4(tvb, offset);

    proto_tree_add_item(
        tree, hf_wimaxasncp_tlv_value_ipv4,
        tvb, offset, 4, FALSE);

    proto_item_append_text(
        tlv_item, " - %s (%s)",
        get_hostname(ip), ip_to_str((guint8 *)&ip));
}


/* ========================================================================= */

static void wimaxasncp_proto_treee_add_tlv_ipv6_value(
    tvbuff_t *tvb,
    proto_tree *tree,
    proto_item *tlv_item,
    guint offset)
{
    struct e_in6_addr ip;
    tvb_get_ipv6(tvb, offset, &ip);

    proto_tree_add_item(
        tree, hf_wimaxasncp_tlv_value_ipv6,
        tvb, offset, 16, FALSE);

    proto_item_append_text(
        tlv_item, " - %s (%s)",
        get_hostname6(&ip), ip6_to_str(&ip));
}

/* ========================================================================= */

static void wimaxasncp_dissect_tlv_value(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    proto_item *tlv_item,
    const wimaxasncp_tlv_info_t *tlv_info)
{
    guint offset = 0;
    guint length;
    const gchar *s;

    UNREFERENCED_PARAMETER(pinfo);

    length = tvb_reported_length(tvb);

    switch(tlv_info->decode_type)
    {
    case WIMAXASNCP_TLV_ENUM8:
    {
        if (length != 1)
        {
            /* encoding error */
            break;
        }

        if (tlv_info->vals == NULL)
        {
            if (debug_enabled)
            {
                g_print("fix-me: enum values missing for TLV %s (%u)\n",
                        tlv_info->name, tlv_info->type);
            }
        }

        if (tree)
        {
            guint8 value;

            value = tvb_get_guint8(tvb, offset);

            s = wimaxasncp_get_enum_name(tlv_info, value);

            proto_tree_add_uint_format(
                tree, hf_wimaxasncp_tlv_value_enum8,
                tvb, offset, length, value,
                "Value: %s (%u)", s, value);

            proto_item_append_text(tlv_item, " - %s", s);
        }

        return;
    }
    case WIMAXASNCP_TLV_ENUM16:
    {
        if (length != 2)
        {
            /* encoding error */
            break;
        }

        if (tlv_info->vals == NULL)
        {
            if (debug_enabled)
            {
                g_print("fix-me: enum values missing for TLV %s (%d)\n",
                        tlv_info->name, tlv_info->type);
            }
        }

        if (tree)
        {
            guint16 value;

            value = tvb_get_ntohs(tvb, offset);

            s = wimaxasncp_get_enum_name(tlv_info, value);

            proto_tree_add_uint_format(
                tree, hf_wimaxasncp_tlv_value_enum16,
                tvb, offset, length, value,
                "Value: %s (%u)", s, value);

            proto_item_append_text(tlv_item, " - %s", s);
        }

        return;
    }
    case WIMAXASNCP_TLV_ENUM32:
    {
        if (length != 4)
        {
            /* encoding error */
            break;
        }

        if (tlv_info->vals == NULL)
        {
            if (debug_enabled)
            {
                g_print("fix-me: enum values missing for TLV %s (%d)\n",
                        tlv_info->name, tlv_info->type);
            }
        }

        if (tree)
        {
            guint32 value;

            value = tvb_get_ntohl(tvb, offset);

            s = wimaxasncp_get_enum_name(tlv_info, value);

            proto_tree_add_uint_format(
                tree, hf_wimaxasncp_tlv_value_enum32,
                tvb, offset, length, value,
                "Value: %s (%u)", s, value);

            proto_item_append_text(tlv_item, " - %s", s);
        }

        return;
    }
    case WIMAXASNCP_TLV_ETHER:
    {
        if (length != 6)
        {
            /* encoding error */
            break;
        }

        if (tree)
        {
            const guint8 *p;

            p = tvb_get_ptr(tvb, offset, length);

            proto_tree_add_ether(
                tree, hf_wimaxasncp_tlv_value_ether,
                tvb, offset, length, p);

            proto_item_append_text(
                tlv_item, " - %s (%s)",
                get_ether_name(p), ether_to_str(p));
        }

        return;
    }
    case WIMAXASNCP_TLV_ASCII_STRING:
    {
        if (tree)
        {
            const guint8 *p;

            p = tvb_get_ptr(tvb, offset, length);

            proto_tree_add_string(
                tree, hf_wimaxasncp_tlv_value_string,
                tvb, offset, length, p);

            proto_item_append_text(
                tlv_item, " - %s", tvb_get_string(tvb, offset, length));
        }

        return;
    }
    case WIMAXASNCP_TLV_FLAG0:
    {
        if (length != 0)
        {
            /* encoding error */
            break;
        }

        return;
    }
    case WIMAXASNCP_TLV_BITFLAGS16:
    {
        if (length != 2)
        {
            /* encoding error */
            break;
        }

        if (tlv_info->vals == NULL)
        {
            /* enum values missing */
        }

        if (tree)
        {
            proto_tree *flags_tree;
            proto_item *item;
            guint16 value;
            guint i;

            value = tvb_get_ntohs(tvb, offset);

            item = proto_tree_add_uint_format(
                tree, hf_wimaxasncp_tlv_value_bitflags16,
                tvb, offset, length, value,
                "Value: %s",
                decode_numeric_bitfield(value, 0xffff, 16, "0x%04x"));

            proto_item_append_text(tlv_item, " - 0x%04x", value);

            if (value != 0)
            {
                flags_tree = proto_item_add_subtree(
                    item, ett_wimaxasncp_tlv_value_bitflags16);

                for (i = 0; i < 16; ++i)
                {
                    guint16 mask;
                    mask = 1 << (15 - i);

                    if (value & mask)
                    {
                        s = wimaxasncp_get_enum_name(tlv_info, value & mask);

                        proto_tree_add_uint_format(
                            flags_tree, hf_wimaxasncp_tlv_value_bitflags16,
                            tvb, offset, length, value,
                            "Bit #%u is set: %s", i, s);
                    }
                }
            }
        }

        return;
    }
    case WIMAXASNCP_TLV_BITFLAGS32:
    {
        if (length != 4)
        {
            /* encoding error */
            break;
        }

        if (tlv_info->vals == NULL)
        {
            /* enum values missing */
        }

        if (tree)
        {
            proto_tree *flags_tree;
            proto_item *item;
            guint32 value;
            guint i;

            value = tvb_get_ntohl(tvb, offset);

            item = proto_tree_add_uint_format(
                tree, hf_wimaxasncp_tlv_value_bitflags32,
                tvb, offset, length, value,
                "Value: %s",
                decode_numeric_bitfield(value, 0xffffffff, 32, "0x%08x"));

            proto_item_append_text(tlv_item, " - 0x%08x", value);

            if (value != 0)
            {
                flags_tree = proto_item_add_subtree(
                    item, ett_wimaxasncp_tlv_value_bitflags32);

                for (i = 0; i < 32; ++i)
                {
                    guint32 mask;
                    mask = 1 << (31 - i);

                    if (value & mask)
                    {
                        s = wimaxasncp_get_enum_name(tlv_info, value & mask);

                        proto_tree_add_uint_format(
                            flags_tree, hf_wimaxasncp_tlv_value_bitflags32,
                            tvb, offset, length, value,
                            "Bit #%u is set: %s", i, s);
                    }
                }
            }
        }

        return;
    }
    case WIMAXASNCP_TLV_ID:
    {
        if (length == 4)
        {
            if (tree)
            {
                wimaxasncp_proto_treee_add_tlv_ipv4_value(
                    tvb, tree, tlv_item, offset);
            }

            return;
        }
        else if (length == 6)
        {
            if (tree)
            {
                const guint8 *p;

                p = tvb_get_ptr(tvb, offset, length);

                proto_tree_add_ether(
                    tree, hf_wimaxasncp_tlv_value_ether,
                    tvb, offset, length, p);

                proto_item_append_text(
                    tlv_item, " - %s (%s)",
                    get_ether_name(p), ether_to_str(p));
            }

            return;
        }
        else if (length == 16)
        {
            if (tree)
            {
                wimaxasncp_proto_treee_add_tlv_ipv6_value(
                    tvb, tree, tlv_item, offset);
            }

            return;
        }
        else
        {
            /* encoding error */
            break;
        }
    }
    case WIMAXASNCP_TLV_BYTES:
    {
        if (tree)
        {
            proto_tree_add_item(
                tree, hf_wimaxasncp_tlv_value_bytes,
                tvb, offset, length, FALSE);

            if (length <= 48) /* arbitrary */
            {
                proto_item_append_text(
                    tlv_item, " - %s",
                    bytestring_to_str(
                        tvb_get_ptr(tvb, offset, length), length, 0));
            }
            else
            {
                proto_item_append_text(
                    tlv_item, " - %s...",
                    bytestring_to_str(
                        tvb_get_ptr(tvb, offset, length), length, 0));
            }
        }

        return;
    }
    case WIMAXASNCP_TLV_HEX8:
    {
        if (length != 1)
        {
            /* encoding error */
            break;
        }

        if (tree)
        {
            guint8 value;

            value = tvb_get_guint8(tvb, offset);

            proto_tree_add_uint(
                tree, hf_wimaxasncp_tlv_value_hex8,
                tvb, offset, length, value);

            proto_item_append_text(tlv_item, " - 0x%02x", value);
        }

        return;
    }
    case WIMAXASNCP_TLV_HEX16:
    {
        if (length != 2)
        {
            /* encoding error */
            break;
        }

        if (tree)
        {
            guint16 value;

            value = tvb_get_ntohs(tvb, offset);

            proto_tree_add_uint(
                tree, hf_wimaxasncp_tlv_value_hex16,
                tvb, offset, length, value);

            proto_item_append_text(tlv_item, " - 0x%04x", value);
        }

        return;
    }
    case WIMAXASNCP_TLV_HEX32:
    {
        if (length != 4)
        {
            /* encoding error */
            break;
        }

        if (tree)
        {
            guint32 value;

            value = tvb_get_ntohl(tvb, offset);

            proto_tree_add_uint(
                tree, hf_wimaxasncp_tlv_value_hex32,
                tvb, offset, length, value);

            proto_item_append_text(tlv_item, " - 0x%08x", value);
        }

        return;
    }
    case WIMAXASNCP_TLV_DEC8:
    {
        if (length != 1)
        {
            /* encoding error */
            break;
        }

        if (tree)
        {
            guint8 value;

            value = tvb_get_guint8(tvb, offset);

            proto_tree_add_uint(
                tree, hf_wimaxasncp_tlv_value_dec8,
                tvb, offset, length, value);

            proto_item_append_text(tlv_item, " - %u", value);
        }

        return;
    }
    case WIMAXASNCP_TLV_DEC16:
    {
        if (length != 2)
        {
            /* encoding error */
            break;
        }

        if (tree)
        {
            guint16 value;

            value = tvb_get_ntohs(tvb, offset);

            proto_tree_add_uint(
                tree, hf_wimaxasncp_tlv_value_dec16,
                tvb, offset, length, value);

            proto_item_append_text(tlv_item, " - %u", value);
        }

        return;
    }
    case WIMAXASNCP_TLV_DEC32:
    {
        if (length != 4)
        {
            /* encoding error */
            break;
        }

        if (tree)
        {
            guint32 value;

            value = tvb_get_ntohl(tvb, offset);

            proto_tree_add_uint(
                tree, hf_wimaxasncp_tlv_value_dec32,
                tvb, offset, length, value);

            proto_item_append_text(tlv_item, " - %u", value);
        }

        return;
    }
    case WIMAXASNCP_TLV_TBD:
    {
        if (debug_enabled)
        {
            g_print(
                "fix-me: TBD: TLV %s (%d)\n", tlv_info->name, tlv_info->type);
        }

        if (tree)
        {
            proto_item_append_text(tlv_item, " - TBD");
        }

        break;
    }
    case WIMAXASNCP_TLV_IP_ADDRESS:
    {
        if (length == 4)
        {
            if (tree)
            {
                wimaxasncp_proto_treee_add_tlv_ipv4_value(
                    tvb, tree, tlv_item, offset);
            }

            return;
        }
        else if (length == 16)
        {
            if (tree)
            {
                wimaxasncp_proto_treee_add_tlv_ipv6_value(
                    tvb, tree, tlv_item, offset);
            }

            return;
        }
        else
        {
            /* encoding error */
            break;
        }
    }
    case WIMAXASNCP_TLV_IPV4_ADDRESS:
    {
        if (length != 4)
        {
            /* encoding error */
            break;
        }

        if (tree)
        {
            wimaxasncp_proto_treee_add_tlv_ipv4_value(
                tvb, tree, tlv_item, offset);
        }

        return;
    }
    case WIMAXASNCP_TLV_PROTOCOL_LIST:
    {
        if (length % 2 != 0)
        {
            /* encoding error */
            break;
        }

        if (tree && length > 0)
        {
            proto_tree *protocol_list_tree;
            proto_item *item;
            const guint max_protocols_in_tlv_item = 8; /* arbitrary */

            item = proto_tree_add_text(
                tree, tvb, offset, length,
                "Value");

            protocol_list_tree = proto_item_add_subtree(
                item, ett_wimaxasncp_tlv_protocol_list);

            while (offset < tvb_length(tvb))
            {
                guint16 protocol;
                const gchar *protocol_name;

                protocol = tvb_get_ntohs(tvb, offset);
                protocol_name = ipprotostr(protocol);

                proto_tree_add_uint_format(
                    protocol_list_tree, hf_wimaxasncp_tlv_value_protocol,
                    tvb, offset, 2, protocol,
                    "Protocol: %s (%u)", protocol_name, protocol);

                if (offset == 0)
                {
                    proto_item_append_text(tlv_item, " - %s", protocol_name);
                }
                else if (offset < 2 * max_protocols_in_tlv_item)
                {
                    proto_item_append_text(tlv_item, ", %s", protocol_name);
                }
                else if (offset == 2 * max_protocols_in_tlv_item)
                {
                    proto_item_append_text(tlv_item, ", ...");
                }

                offset += 2;
            }
        }

        return;
    }
    case WIMAXASNCP_TLV_PORT_RANGE_LIST:
    {
        if (length % 4 != 0)
        {
            /* encoding error */
            break;
        }

        if (tree && length > 0)
        {
            proto_tree *port_range_list_tree;
            proto_item *item;
            const guint max_port_ranges_in_tlv_item = 3; /* arbitrary */

            item = proto_tree_add_text(
                tree, tvb, offset, length,
                "Value");

            port_range_list_tree = proto_item_add_subtree(
                item, ett_wimaxasncp_tlv_port_range_list);

            while (offset < tvb_length(tvb))
            {
                guint16 portLow;
                guint16 portHigh;

                portLow = tvb_get_ntohs(tvb, offset);
                portHigh = tvb_get_ntohs(tvb, offset + 2);

                proto_tree_add_text(
                    port_range_list_tree, tvb, offset, 4,
                    "Port Range: %d-%d", portLow, portHigh);

                if (offset == 0)
                {
                    proto_item_append_text(
                        tlv_item, " - %d-%d", portLow, portHigh);
                }
                else if (offset < 4 * max_port_ranges_in_tlv_item)
                {
                    proto_item_append_text(
                        tlv_item, ", %d-%d", portLow, portHigh);
                }
                else if (offset == 4 * max_port_ranges_in_tlv_item)
                {
                    proto_item_append_text(tlv_item, ", ...");
                }

                offset += 4;
            }
        }

        return;
    }
    case WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST:
    {
        /* --------------------------------------------------------------------
         * The definion of these TLVs are ambiguous. The length in octets is
         * described as Nx8 (IPv4) or Nx32 (IPv6), but this function cannot
         * always differentiate between IPv4 and IPv6. For example, if length
         * = 32, then is it IPv4 where N=4 (4x8) or IPv6 where N=1 (1x32)?
         *
         * For now, we presume lengths that *can* indicate an IPv6 address and
         * mask list *do* denote an IPv6 address and mask list.
         * --------------------------------------------------------------------
         */

        if (length % 8 != 0)
        {
            /* encoding error */
            break;
        }

        if (tree && length > 0)
        {
            proto_tree *ip_address_mask_list_tree;
            proto_item *item;

            item = proto_tree_add_text(
                tree, tvb, offset, length,
                "Value");

            ip_address_mask_list_tree = proto_item_add_subtree(
                item, ett_wimaxasncp_tlv_ip_address_mask_list);

            if (length % 32 == 0)
            {
                /* ------------------------------------------------------------
                 * presume IPv6
                 * ------------------------------------------------------------
                 */

                while (offset < tvb_length(tvb))
                {
                    proto_tree *ip_address_mask_tree;
                    struct e_in6_addr ip;
                    const gchar *s;

                    item = proto_tree_add_text(
                        ip_address_mask_list_tree, tvb, offset, 32,
                        "IPv6 Address and Mask");

                    ip_address_mask_tree = proto_item_add_subtree(
                        item, ett_wimaxasncp_tlv_ip_address_mask);

                    /* --------------------------------------------------------
                     * address
                     * --------------------------------------------------------
                     */

                    tvb_get_ipv6(tvb, offset, &ip);

                    proto_tree_add_item(
                        ip_address_mask_tree,
                        hf_wimaxasncp_tlv_value_ipv6_address,
                        tvb, offset, 16, FALSE);

                    /* too long to display ?
                    proto_item_append_text(
                        item, " - %s (%s)",
                        get_hostname6(&ip), ip6_to_str(&ip));
                    */

                    offset += 16;

                    /* --------------------------------------------------------
                     * mask
                     * --------------------------------------------------------
                     */

                    tvb_get_ipv6(tvb, offset, &ip);

                    s = ip6_to_str(&ip);

                    proto_tree_add_ipv6_format_value(
                        ip_address_mask_tree,
                        hf_wimaxasncp_tlv_value_ipv6_mask,
                        tvb, offset, 16, (const guint8*)&ip,
                        "%s", s);

                    /* too long to display ?
                    proto_item_append_text(
                        item, " / %s", s);
                    */

                    offset += 16;
                }
            }
            else
            {
                /* ------------------------------------------------------------
                 * IPv4
                 * ------------------------------------------------------------
                 */

                while (offset < tvb_length(tvb))
                {
                    proto_tree *ip_address_mask_tree;
                    guint32 ip;
                    const gchar *s;

                    item = proto_tree_add_text(
                        ip_address_mask_list_tree, tvb, offset, 8,
                        "IPv4 Address and Mask");

                    ip_address_mask_tree = proto_item_add_subtree(
                        item, ett_wimaxasncp_tlv_ip_address_mask);

                    /* --------------------------------------------------------
                     * address
                     * --------------------------------------------------------
                     */

                    ip = tvb_get_ipv4(tvb, offset);

                    proto_tree_add_item(
                        ip_address_mask_tree,
                        hf_wimaxasncp_tlv_value_ipv4_address,
                        tvb, offset, 4, FALSE);

                    proto_item_append_text(
                        item, " - %s (%s)",
                        get_hostname(ip), ip_to_str((guint8 *)&ip));

                    offset += 4;

                    /* --------------------------------------------------------
                     * mask
                     * --------------------------------------------------------
                     */

                    ip = tvb_get_ipv4(tvb, offset);

                    s = ip_to_str((guint8 *)&ip);

                    proto_tree_add_ipv4_format_value(
                        ip_address_mask_tree,
                        hf_wimaxasncp_tlv_value_ipv4_mask,
                        tvb, offset, 4, ip,
                        "%s", s);

                    proto_item_append_text(
                        item, " / %s", s);

                    offset += 4;
                }
            }
        }

        return;
    }
    case WIMAXASNCP_TLV_VENDOR_SPECIFIC:
    {
        /* --------------------------------------------------------------------
         *  The format of the vendor specific information field (VSIF) is not
         *  clearly defined.  It appears to be compound as the spec states
         *  that the vendor ID field shall be the first TLV embedded inside
         *  the VSIF.  However, the vendor ID is shown as a 24-bit value. Does
         *  this mean the field is 24-bits?  If so, how is alignment/padding
         *  handled?
         *
         * For now, we decode the vendor ID as a non-padded 24-bit value and
         * dump the rest as hex.
         * --------------------------------------------------------------------
         */

        if (length < 3)
        {
            /* encoding error */
            break;
        }

        if (tree)
        {
            proto_tree *vsif_tree;
            proto_item *item;
            guint32 vendorId;

            item = proto_tree_add_text(
                tree, tvb, offset, length,
                "Value");

            vsif_tree = proto_item_add_subtree(
                item, ett_wimaxasncp_tlv_vendor_specific_information_field);

            /* ----------------------------------------------------------------
             * vendor ID (24-bit)
             * ----------------------------------------------------------------
             */

            vendorId = tvb_get_ntoh24(tvb, offset);

            proto_tree_add_uint(
                vsif_tree, hf_wimaxasncp_tlv_value_vendor_id,
                tvb, offset, 3, vendorId);

            proto_item_append_text(
                tlv_item,
                " - %s",
                val_to_str(vendorId, sminmpec_values, "Unknown"));

            offset += 3;

            /* ----------------------------------------------------------------
             * hex dump the rest
             * ----------------------------------------------------------------
             */

            if (offset < tvb_length(tvb))
            {
                proto_tree_add_item(
                    vsif_tree, hf_wimaxasncp_tlv_value_bytes,
                    tvb, offset, length - offset, FALSE);
            }
        }

        return;
    }
    default:
        if (debug_enabled)
        {
            g_print(
                "fix-me: unknown decode_type: %d\n", tlv_info->decode_type);
        }
        break;
    }

    /* default is hex dump*/

    if (tree)
    {
        proto_tree_add_item(
            tree, hf_wimaxasncp_tlv_value_bytes,
            tvb, offset, length, FALSE);
    }
}

/* ========================================================================= */

static guint dissect_wimaxasncp_tlvs(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree)
{
    guint offset;

    offset = 0;
    while (offset < tvb_reported_length(tvb))
    {
        proto_tree *tlv_tree = NULL;
        proto_item *tlv_item = NULL;
        const wimaxasncp_tlv_info_t *tlv_info;

        guint16 type;
        guint16 length;
        guint pad;

        /* --------------------------------------------------------------------
         * type and length
         * --------------------------------------------------------------------
         */

        type = tvb_get_ntohs(tvb, offset);
        tlv_info = wimaxasncp_get_tlv_info(type);

        length = tvb_get_ntohs(tvb, offset + 2);
        pad = 4 - (length % 4);
        if (pad == 4)
        {
            pad = 0;
        }

        if (tree)
        {
            gint tree_length = MIN(
                (gint)(4 + length + pad), tvb_length_remaining(tvb, offset));

            if (tlv_info->decode_type == WIMAXASNCP_TLV_COMPOUND)
            {
                tlv_item = proto_tree_add_uint_format(
                    tree, hf_wimaxasncp_tlv_type,
                    tvb, offset, tree_length, type,
                    "TLV: %s [compound]", tlv_info->name);
            }
            else
            {
                tlv_item = proto_tree_add_uint_format(
                    tree, hf_wimaxasncp_tlv_type,
                    tvb, offset, tree_length, type,
                    "TLV: %s", tlv_info->name);
            }

            tlv_tree = proto_item_add_subtree(
                tlv_item, ett_wimaxasncp_tlv);

            proto_tree_add_uint_format(
                tlv_tree, hf_wimaxasncp_tlv_type,
                tvb, offset, 2, type,
                "Type: %s (%u)", tlv_info->name, type);

            proto_tree_add_uint(
                tlv_tree, hf_wimaxasncp_tlv_length,
                tvb, offset + 2, 2, length);

        }

        offset += 4;

        /* --------------------------------------------------------------------
         * value
         * --------------------------------------------------------------------
         */

        if (tlv_info->decode_type == WIMAXASNCP_TLV_COMPOUND)
        {
            if (length == 0)
            {
                /* error? compound, but no TLVs inside */
            }
            else if (tvb_length_remaining(tvb, offset) > 0)
            {
                tvbuff_t *tlv_tvb;

                tlv_tvb = tvb_new_subset(
                    tvb, offset,
                    MIN(length, tvb_length_remaining(tvb, offset)),
                    length);

                dissect_wimaxasncp_tlvs(tlv_tvb, pinfo, tlv_tree);
            }
            else
            {
                /* this should throw */
                tvb_ensure_bytes_exist(tvb, offset, length + pad);
            }
        }
        else
        {
            tvbuff_t *tlv_tvb;

            tvb_ensure_bytes_exist(tvb, offset, length + pad);

            tlv_tvb = tvb_new_subset(
                tvb, offset,
                MIN(length, tvb_length_remaining(tvb, offset)),
                length);

            wimaxasncp_dissect_tlv_value(
                tlv_tvb, pinfo, tlv_tree, tlv_item, tlv_info);
        }

        offset += length + pad;
    }

    return offset;
}

/* ========================================================================= */

static guint dissect_wimaxasncp_backend(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree)
{
    guint offset = 0;
    guint16 ui16;
    guint32 ui32;
    const guint8 *p;

    /* ------------------------------------------------------------------------
     * MSID
     * ------------------------------------------------------------------------
     */

    p = tvb_get_ptr(tvb, offset, 6);

    if (tree)
    {
        proto_tree_add_ether(
            tree, hf_wimaxasncp_msid,
            tvb, offset, 6, p);

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_append_fstr(
                pinfo->cinfo, COL_INFO, " - MSID:%s", ether_to_str(p));
        }
    }

    offset += 6;

    /* ------------------------------------------------------------------------
     * reserved
     * ------------------------------------------------------------------------
     */

    ui32 = tvb_get_ntohl(tvb, offset);

    if (tree)
    {
        proto_tree_add_uint(
            tree, hf_wimaxasncp_reserved1,
            tvb, offset, 4, ui32);
    }

    offset += 4;

    /* ------------------------------------------------------------------------
     * transaction ID
     * ------------------------------------------------------------------------
     */

    ui16 = tvb_get_ntohs(tvb, offset);

    if (tree)
    {
        if (show_transaction_id_d_bit)
        {
            const guint16 mask = 0x7fff;

            if (ui16 & 0x8000)
            {
                proto_tree_add_uint_format(
                    tree, hf_wimaxasncp_transaction_id,
                    tvb, offset, 2, ui16,
                    "Transaction ID: D + 0x%04x (0x%04x)", mask & ui16, ui16);

                if (check_col(pinfo->cinfo, COL_INFO))
                {
                    col_append_fstr(
                        pinfo->cinfo, COL_INFO, ", TID:D+0x%04x", mask & ui16);
                }
            }
            else
            {
                proto_tree_add_uint_format(
                    tree, hf_wimaxasncp_transaction_id,
                    tvb, offset, 2, ui16,
                    "Transaction ID: 0x%04x", ui16);

                if (check_col(pinfo->cinfo, COL_INFO))
                {
                    col_append_fstr(
                        pinfo->cinfo, COL_INFO, ", TID:0x%04x", ui16);
                }
            }
        }
        else
        {
            proto_tree_add_uint(
                tree, hf_wimaxasncp_transaction_id,
                tvb, offset, 2, ui16);

            if (check_col(pinfo->cinfo, COL_INFO))
            {
                col_append_fstr(
                    pinfo->cinfo, COL_INFO, ", TID:0x%04x", ui16);
            }
        }
    }

    offset += 2;

    /* ------------------------------------------------------------------------
     * reserved
     * ------------------------------------------------------------------------
     */

    ui16 = tvb_get_ntohs(tvb, offset);

    if (tree)
    {
        proto_tree_add_uint(
            tree, hf_wimaxasncp_reserved2,
            tvb, offset, 2, ui16);
    }

    offset += 2;

    /* ------------------------------------------------------------------------
     * TLVs
     * ------------------------------------------------------------------------
     */

    if (offset < tvb_length(tvb))
    {
        tvbuff_t *tlv_tvb;

        tlv_tvb = tvb_new_subset(
            tvb, offset,
            tvb_length(tvb) - offset,
            tvb_length(tvb) - offset);

        offset += dissect_wimaxasncp_tlvs(tlv_tvb, pinfo, tree);
    }

    return offset;
}

/* ========================================================================= */

static int
dissect_wimaxasncp(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *packet_item = NULL;
    proto_item *item = NULL;
    proto_tree *wimaxasncp_tree = NULL;
    tvbuff_t *subtree;

    guint offset;
    guint8 ui8;

    guint8 function_type;
    guint16 length;

    /* ------------------------------------------------------------------------
     * First, we do some heuristics to check if the packet cannot be our
     * protocol.
     * ------------------------------------------------------------------------
     */

    /* Should we check a minimum size?  If so, uncomment out the following
     * code. */
    /*
    if (tvb_length(tvb) < WIMAXASNCP_HEADER_SIZE)
    {
        return 0;
    }
    */

    /* We currently only support version 1. */
    if (tvb_bytes_exist(tvb, 0, 1) && tvb_get_guint8(tvb, 0) != 1)
    {
        return 0;
    }

    /* ------------------------------------------------------------------------
     * Initialize the protocol and info column.
     * ------------------------------------------------------------------------
     */

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "WiMAX");
    }

    /* We'll fill in the "Info" column after fetch data, so we clear the
       column first in case calls to fetch data from the packet throw an
       exception. */
    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    /* ========================================================================
     * Disesction starts here
     * ========================================================================
     */

    /* ------------------------------------------------------------------------
     * total packet, we'll adjust after we read the length field
     * ------------------------------------------------------------------------
     */

    offset = 0;

    if (tree)
    {
        packet_item = proto_tree_add_item(
            tree, proto_wimaxasncp,
            tvb, 0, MIN(WIMAXASNCP_HEADER_LENGTH_END, tvb_length(tvb)), FALSE);

        wimaxasncp_tree = proto_item_add_subtree(
            packet_item, ett_wimaxasncp);
    }

    /* ------------------------------------------------------------------------
     * version
     * ------------------------------------------------------------------------
     */

    ui8 = tvb_get_guint8(tvb, offset);

    if (tree)
    {
        proto_tree_add_uint(
            wimaxasncp_tree, hf_wimaxasncp_version,
            tvb, offset, 1, ui8);
    }

    offset += 1;

    /* ------------------------------------------------------------------------
     * flags
     * ------------------------------------------------------------------------
     */

    ui8 = tvb_get_guint8(tvb, offset);

    if (tree)
    {
        proto_tree *flags_tree;
        guint i;

        if (ui8 == 0)
        {
            item = proto_tree_add_uint_format(
                wimaxasncp_tree, hf_wimaxasncp_flags,
                tvb, offset, 1, ui8,
                "Flags: 0x%02x", ui8);
        }
        else
        {
            item = proto_tree_add_uint_format(
                wimaxasncp_tree, hf_wimaxasncp_flags,
                tvb, offset, 1, ui8,
                "Flags: ");

            if (ui8 & (WIMAXASNCP_FLAGS_T | WIMAXASNCP_FLAGS_R))
            {
                if (ui8 & WIMAXASNCP_FLAGS_T)
                {
                    proto_item_append_text(item, "T");
                }

                if (ui8 & WIMAXASNCP_FLAGS_R)
                {
                    proto_item_append_text(item, "R");
                }

                proto_item_append_text(item, " - ");
            }

            proto_item_append_text(
                item, "%s", decode_numeric_bitfield(ui8, 0xff, 8, "0x%02x"));

            flags_tree = proto_item_add_subtree(
                item, ett_wimaxasncp_flags);

            for (i = 0; i < 8; ++i)
            {
                guint8 mask;
                mask = 1 << (7 - i);

                if (ui8 & mask)
                {
                    proto_tree_add_uint_format(
                        flags_tree, hf_wimaxasncp_flags,
                        tvb, offset, 1, ui8,
                        "Bit #%u is set: %s",
                        i,
                        val_to_str(
                            ui8 & mask, wimaxasncp_flag_vals, "Unknown"));
                }
            }
        }
    }

    offset += 1;

    /* ------------------------------------------------------------------------
     * function type
     * ------------------------------------------------------------------------
     */

    function_type = tvb_get_guint8(tvb, offset);

    if (tree)
    {
        proto_tree_add_uint(
            wimaxasncp_tree, hf_wimaxasncp_function_type,
            tvb, offset, 1, function_type);
    }

    offset += 1;

    /* ------------------------------------------------------------------------
     * OP ID and message type
     * ------------------------------------------------------------------------
     */

    ui8 = tvb_get_guint8(tvb, offset);

    if (tree)
    {
        const gchar *unknown = "Unknown";
        const gchar *message_name;
        const wimaxasncp_func_msg_t *p = NULL;
        gsize i;

        /* --------------------------------------------------------------------
         * OP ID
         * --------------------------------------------------------------------
         */

        item = proto_tree_add_uint_format(
            wimaxasncp_tree, hf_wimaxasncp_op_id,
             tvb, offset, 1, ui8,
            "OP ID: %s", val_to_str(ui8 >> 5, wimaxasncp_op_id_vals, unknown));

        proto_item_append_text(
            item, " (%s)", decode_numeric_bitfield(ui8, 0xe0, 8, "%u"));


        /* use the function type to find the message vals */
        for (i = 0; i < array_length(wimaxasncp_func_to_msg_vals_map); ++i)
        {
            p = &wimaxasncp_func_to_msg_vals_map[i];

            if (function_type == p->function_type)
            {
                break;
            }
        }

        /* --------------------------------------------------------------------
         * message type
         * --------------------------------------------------------------------
         */

        message_name = p ? val_to_str(0x1f & ui8, p->vals, unknown) : unknown;

        item = proto_tree_add_uint_format(
            wimaxasncp_tree, hf_wimaxasncp_op_id,
            tvb, offset, 1, ui8,
            "Message Type: %s", message_name);

        proto_item_append_text(
            item, " (%s)", decode_numeric_bitfield(ui8, 0x1f, 8, "%u"));

        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_add_str(pinfo->cinfo, COL_INFO, message_name);
        }
    }

    offset += 1;

    /* ------------------------------------------------------------------------
     * length
     * ------------------------------------------------------------------------
     */

    length = tvb_get_ntohs(tvb, offset);

    if (tree)
    {
        proto_item_set_len(
            packet_item, MAX(WIMAXASNCP_HEADER_LENGTH_END, length));

        item = proto_tree_add_uint(
            item = wimaxasncp_tree, hf_wimaxasncp_length,
            tvb, offset, 2, length);
    }

    offset += 2;

    if (length < WIMAXASNCP_HEADER_SIZE)
    {
        expert_add_info_format(
            pinfo, item, PI_MALFORMED, PI_ERROR, "Bad length");

        if (tree)
        {
            proto_item_append_text(
                item, " [error: specified length less than header size (20)]");
        }

        if (length <= WIMAXASNCP_HEADER_LENGTH_END)
        {
            return offset;
        }
    }

    /* ------------------------------------------------------------------------
     * remaining header fields and TLVs
     * ------------------------------------------------------------------------
     */

    subtree = tvb_new_subset(
        tvb, offset,
        MIN(length, tvb_length(tvb) - offset),
        length - WIMAXASNCP_HEADER_LENGTH_END);

    offset += dissect_wimaxasncp_backend(
        subtree, pinfo, wimaxasncp_tree);

    /* ------------------------------------------------------------------------
     * done, return the amount of data this dissector was able to dissect
     * ------------------------------------------------------------------------
     */

    return offset;
}

/* ========================================================================= */
/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_wimaxasncp(void)
{
	module_t *wimaxasncp_module;

        /* --------------------------------------------------------------------
         * List of header fields
         * --------------------------------------------------------------------
         */
	static hf_register_info hf[] = {
            {
                &hf_wimaxasncp_version,      /* ID */
                {
                    "Version",               /* FIELDNAME */
                    "wimaxasncp.version",    /* PROTOABBREV.FIELDABBRE */
                    FT_UINT8,                /* FIELDTYPE */
                    BASE_DEC,                /* FIELDBASE */
                    NULL,                    /* FIELDCONVERT */
                    0x0,                     /* BITMASK */
                    "",                      /* FIELDDESCR */
                    HFILL                    /* HFILL */
                }
            },
            {
                &hf_wimaxasncp_flags,
                {
                    "Flags",
                    "wimaxasncp.flags",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0xff,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_function_type,
                {
                    "Function Type",
                    "wimaxasncp.function_type",
                    FT_UINT8,
                    BASE_DEC,
                    VALS(wimaxasncp_function_type_vals),
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_op_id,
                {
                    "OP ID",
                    "wimaxasncp.opid",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_op_id_vals),
                    0xE0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_message_type,
                {
                    "Message Type",
                    "wimaxasncp.message_type",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_qos_msg,
                {
                    "Message Type",
                    "wimaxasncp.qos_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_qos_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_ho_control_msg,
                {
                    "Message Type",
                    "wimaxasncp.ho_control_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_ho_control_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_data_path_control_msg,
                {
                    "Message Type",
                    "wimaxasncp.data_path_control_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_data_path_control_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_context_delivery_msg,
                {
                    "Message Type",
                    "wimaxasncp.context_delivery_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_context_delivery_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_r3_mobility_msg,
                {
                    "Message Type",
                    "wimaxasncp.r3_mobility_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_r3_mobility_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_paging_msg,
                {
                    "Message Type",
                    "wimaxasncp.paging_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_paging_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_rrm_msg,
                {
                    "Message Type",
                    "wimaxasncp.rrm_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_rrm_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_authentication_msg,
                {
                    "Message Type",
                    "wimaxasncp.authentication_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_authentication_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_ms_state_msg,
                {
                    "Message Type",
                    "wimaxasncp.ms_state_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_ms_state_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_reauthentication_msg,
                {
                    "Message Type",
                    "wimaxasncp.reauthentication_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_reauthentication_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_session_msg,
                {
                    "Message Type",
                    "wimaxasncp.session_msg",
                    FT_UINT8,
                    BASE_HEX,
                    VALS(wimaxasncp_session_msg_vals),
                    0x1F,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_length,
                {
                    "Length",
                    "wimaxasncp.length",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_msid,
                {
                    "MSID",
                    "wimaxasncp.msid",
                    FT_ETHER,
                    BASE_NONE,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_reserved1,
                {
                    "Reserved",
                    "wimaxasncp.reserved1",
                    FT_UINT32,
                    BASE_HEX,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_transaction_id,
                {
                    "Transaction ID",
                    "wimaxasncp.transaction_id",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_reserved2,
                {
                    "Reserved",
                    "wimaxasncp.reserved2",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv,
                {
                    "TLV",
                    "wimaxasncp.tlv",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_type,
                {
                    "Type",
                    "wimaxasncp.tlv_type",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_length,
                {
                    "Length",
                    "wimaxasncp.tlv_length",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_bytes,
                {
                    "Value",
                    "wimaxasncp.tlv_value_bytes",
                    FT_BYTES,
                    BASE_HEX,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_enum8,
                {
                    "Value",
                    "wimaxasncp.tlv_value_enum8",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_enum16,
                {
                    "Value",
                    "wimaxasncp.tlv_value_enum16",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_enum32,
                {
                    "Value",
                    "wimaxasncp.tlv_value_enum32",
                    FT_UINT32,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_ether,
                {
                    "Value",
                    "wimaxasncp.tlv_value_ether",
                    FT_ETHER,
                    BASE_NONE,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_string,
                {
                    "Value",
                    "wimaxasncp.tlv_value_string",
                    FT_STRING,
                    BASE_NONE,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_bitflags16,
                {
                    "Value",
                    "wimaxasncp.tlv_value_bitflags16",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0xffff,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_bitflags32,
                {
                    "Value",
                    "wimaxasncp.tlv_value_bitflags32",
                    FT_UINT32,
                    BASE_HEX,
                    NULL,
                    0xffffffff,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_ipv4,
                {
                    "Value",
                    "wimaxasncp.tlv_value_ipv4",
                    FT_IPv4,
                    BASE_NONE,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_ipv4_address,
                {
                    "IPv4 Address",
                    "wimaxasncp.tlv_value_ipv4_address",
                    FT_IPv4,
                    BASE_NONE,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_ipv4_mask,
                {
                    "IPv4 Mask",
                    "wimaxasncp.tlv_value_ipv4_mask",
                    FT_IPv4,
                    BASE_NONE,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_ipv6,
                {
                    "Value",
                    "wimaxasncp.tlv_value_ipv6",
                    FT_IPv6,
                    BASE_NONE,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_ipv6_address,
                {
                    "IPv6 Address",
                    "wimaxasncp.tlv_value_ipv6_address",
                    FT_IPv6,
                    BASE_NONE,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_ipv6_mask,
                {
                    "IPv6 Mask",
                    "wimaxasncp.tlv_value_ipv6_mask",
                    FT_IPv6,
                    BASE_NONE,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_hex8,
                {
                    "Value",
                    "wimaxasncp.tlv_value_hex8",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_hex16,
                {
                    "Value",
                    "wimaxasncp.tlv_value_hex16",
                    FT_UINT16,
                    BASE_HEX,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_hex32,
                {
                    "Value",
                    "wimaxasncp.tlv_value_hex32",
                    FT_UINT32,
                    BASE_HEX,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_dec8,
                {
                    "Value",
                    "wimaxasncp.tlv_value_dec8",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_dec16,
                {
                    "Value",
                    "wimaxasncp.tlv_value_dec16",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_dec32,
                {
                    "Value",
                    "wimaxasncp.tlv_value_dec32",
                    FT_UINT32,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_protocol,
                {
                    "Value",
                    "wimaxasncp.tlv_value_protocol",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_vendor_id,
                {
                    "Vendor ID",
                    "wimaxasncp.tlv_value_vendor_id",
                    FT_UINT24,
                    BASE_DEC,
                    NULL,
                    0x0,
                    "",
                    HFILL
                }
            }
        };

        /* Protocol subtree array */
	static gint *ett[] = {
            &ett_wimaxasncp,
            &ett_wimaxasncp_flags,
            &ett_wimaxasncp_tlv,
            &ett_wimaxasncp_tlv_value_bitflags16,
            &ett_wimaxasncp_tlv_value_bitflags32,
            &ett_wimaxasncp_tlv_protocol_list,
            &ett_wimaxasncp_tlv_port_range_list,
            &ett_wimaxasncp_tlv_ip_address_mask_list,
            &ett_wimaxasncp_tlv_ip_address_mask,
            &ett_wimaxasncp_tlv_vendor_specific_information_field
	};

        /* Register the protocol name and description */
	proto_wimaxasncp = proto_register_protocol(
            "WiMAX ASN Control Plane Protocol",
	    "WiMAX ASN CP",
            "wimaxasncp");

        /* Required function calls to register the header fields and subtrees
         * used */
	proto_register_field_array(proto_wimaxasncp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	    /* Register this dissector by name */
	new_register_dissector("wimaxasncp", dissect_wimaxasncp, proto_wimaxasncp);
    
        /* Register preferences module (See Section 2.6 for more on
         * preferences) */
	wimaxasncp_module = prefs_register_protocol(
            proto_wimaxasncp,
	    proto_reg_handoff_wimaxasncp);

        /* Register preferences */
	prefs_register_bool_preference(
            wimaxasncp_module,
            "show_transaction_id_d_bit",
            "Show transaction ID direction bit",
            "Show transaction ID direction bit separately from the rest of "
            "the transaction ID field.",
            &show_transaction_id_d_bit);

	prefs_register_bool_preference(
            wimaxasncp_module,
            "debug_enabled",
            "Enable debug output",
            "Print debug output to the console.",
            &debug_enabled);
}

/* ========================================================================= */
/* If this dissector uses sub-dissector registration add a registration
   routine.  This exact format is required because a script is used to find
   these routines and create the code that calls these routines.

   This function is also called by preferences whenever "Apply" is pressed
   (see prefs_register_protocol above) so it should accommodate being called
   more than once.
*/
void
proto_reg_handoff_wimaxasncp(void)
{
	static gboolean inited = FALSE;

	if ( ! inited)
        {
	    dissector_handle_t wimaxasncp_handle;

        /*  Use new_create_dissector_handle() to indicate that
         *  dissect_wimaxasncp() returns the number of bytes it dissected (or
         *  0 if it * thinks the packet does not belong to WiMAX ASN Control
         *  Plane).
         */
	    wimaxasncp_handle = new_create_dissector_handle(
                dissect_wimaxasncp,
	        proto_wimaxasncp);

	    dissector_add("udp.port", 2231, wimaxasncp_handle);

	    inited = TRUE;
	}

        /*
          If you perform registration functions which are dependant upon
          prefs the you should de-register everything which was associated
          with the previous settings and re-register using the new prefs
	  settings here. In general this means you need to keep track of what
	  value the preference had at the time you registered using a local
	  static in this function. ie.

          static int currentPort = -1;

          if (currentPort != -1) {
              dissector_delete("tcp.port", currentPort, wimaxasncp_handle);
          }

          currentPort = gPortPref;

          dissector_add("tcp.port", currentPort, wimaxasncp_handle);

        */
}
