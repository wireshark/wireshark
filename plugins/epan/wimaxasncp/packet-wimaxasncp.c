/* packet-wimaxasncp.c
 *
 * Routines for WiMAX ASN Control Plane packet dissection dissection
 *
 * Copyright 2007, Mobile Metrics - http://www.mobilemetrics.net
 *
 * Author: Stephen Croll <croll@mobilemetrics.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/expert.h>
#include <epan/eap.h>
#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>
#include <epan/ws_printf.h>

#include "wimaxasncp_dict.h"

/* Forward declarations we need below */
void proto_register_wimaxasncp(void);
void proto_reg_handoff_wimaxasncp(void);

/* Initialize the protocol and registered fields */
static int proto_wimaxasncp;
static int hf_wimaxasncp_version;
static int hf_wimaxasncp_flags;
static int hf_wimaxasncp_function_type;
static int hf_wimaxasncp_op_id;
static int hf_wimaxasncp_message_type;
/* static int hf_wimaxasncp_qos_msg; */
/* static int hf_wimaxasncp_ho_control_msg; */
/* static int hf_wimaxasncp_data_path_control_msg; */
/* static int hf_wimaxasncp_context_delivery_msg; */
/* static int hf_wimaxasncp_r3_mobility_msg; */
/* static int hf_wimaxasncp_paging_msg; */
/* static int hf_wimaxasncp_rrm_msg; */
/* static int hf_wimaxasncp_authentication_msg; */
/* static int hf_wimaxasncp_ms_state_msg; */
/* static int hf_wimaxasncp_reauthentication_msg; */
/* static int hf_wimaxasncp_session_msg; */
static int hf_wimaxasncp_length;
static int hf_wimaxasncp_msid;
static int hf_wimaxasncp_reserved1;
static int hf_wimaxasncp_transaction_id;
static int hf_wimaxasncp_reserved2;
/* static int hf_wimaxasncp_tlv; */
static int hf_wimaxasncp_tlv_type;
static int hf_wimaxasncp_tlv_length;
static int hf_wimaxasncp_tlv_value_bytes;
static int hf_wimaxasncp_tlv_value_bitflags8;
static int hf_wimaxasncp_tlv_value_bitflags16;
static int hf_wimaxasncp_tlv_value_bitflags32;
/* static int hf_wimaxasncp_tlv_value_protocol; */
/* static int hf_wimaxasncp_tlv_value_vendor_id; */

/* Preferences */
static bool show_transaction_id_d_bit;
static bool debug_enabled;

/* Default WiMAX ASN control protocol port */
#define WIMAXASNCP_DEF_UDP_PORT     2231


/* Initialize the subtree pointers */
static int ett_wimaxasncp;
static int ett_wimaxasncp_flags;
static int ett_wimaxasncp_tlv;
static int ett_wimaxasncp_tlv_value_bitflags8;
static int ett_wimaxasncp_tlv_value_bitflags16;
static int ett_wimaxasncp_tlv_value_bitflags32;
static int ett_wimaxasncp_tlv_protocol_list;
static int ett_wimaxasncp_tlv_port_range_list;
static int ett_wimaxasncp_tlv_ip_address_mask_list;
static int ett_wimaxasncp_tlv_ip_address_mask;
static int ett_wimaxasncp_tlv_eap;
static int ett_wimaxasncp_tlv_vendor_specific_information_field;
static int ett_wimaxasncp_port_range;

static expert_field ei_wimaxasncp_tlv_type;
static expert_field ei_wimaxasncp_function_type;
static expert_field ei_wimaxasncp_op_id;
static expert_field ei_wimaxasncp_message_type;
static expert_field ei_wimaxasncp_length_bad;

/* Header size, up to, but not including, the TLV fields. */
#define WIMAXASNCP_HEADER_SIZE       20

/* Offset to end of the length field in the header. */
#define WIMAXASNCP_HEADER_LENGTH_END 6

#define WIMAXASNCP_BIT32(n) (1U << (31 - (n)))
#define WIMAXASNCP_BIT16(n) (1U << (15 - (n)))
#define WIMAXASNCP_BIT8(n)  (1U << ( 7 - (n)))

#define WIMAXASNCP_FLAGS_T  WIMAXASNCP_BIT8(6)
#define WIMAXASNCP_FLAGS_R  WIMAXASNCP_BIT8(7)

typedef struct {
    wmem_array_t* hf;
    wmem_array_t* ett;
} wimaxasncp_build_dict_t;

static wimaxasncp_dict_t *wimaxasncp_dict;

wimaxasncp_build_dict_t wimaxasncp_build_dict;

static wimaxasncp_dict_tlv_t wimaxasncp_tlv_not_found =
{
    0, "Unknown", NULL, WIMAXASNCP_TLV_UNKNOWN, 0,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    NULL, NULL, NULL
};

static dissector_handle_t wimaxasncp_handle;
static dissector_handle_t eap_handle;

/* ------------------------------------------------------------------------- */

static const value_string wimaxasncp_flag_vals[] =
{
    { WIMAXASNCP_BIT8(0), "Reserved" },
    { WIMAXASNCP_BIT8(1), "Reserved" },
    { WIMAXASNCP_BIT8(2), "Reserved" },
    { WIMAXASNCP_BIT8(3), "Reserved" },
    { WIMAXASNCP_BIT8(4), "Reserved" },
    { WIMAXASNCP_BIT8(5), "Reserved" },
    { WIMAXASNCP_FLAGS_T, "T - Source and Destination Identifier TLVs"},
    { WIMAXASNCP_FLAGS_R, "R - Reset Next Expected Transaction ID"},
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
#define WIMAXASNCP_FT_CONTEXT_TRANSFER    4
#define WIMAXASNCP_FT_R3_MOBILITY         5
#define WIMAXASNCP_FT_PAGING              6
#define WIMAXASNCP_FT_RRM                 7
#define WIMAXASNCP_FT_AUTHENTICATION      8
#define WIMAXASNCP_FT_MS_STATE            9
#define WIMAXASNCP_FT_REAUTHENTICATION    10
/* since NWG R1 V1.2.0 */
#define WIMAXASNCP_FT_IM_OPERATIONS       10
/* since NWG R1 V1.2.1 */
#define WIMAXASNCP_FT_ACCOUNTING          11

/* ------------------------------------------------------------------------- */

/* struct to hold a value_string tuple, per version */
typedef struct _ver_value_string
{
    uint32_t since;
    value_string vs;
} ver_value_string;

static const ver_value_string wimaxasncp_function_type_vals[] =
{
    {0,                          { WIMAXASNCP_FT_QOS,                   "QoS"}},
    {0,                          { WIMAXASNCP_FT_HO_CONTROL,            "HO Control"}},
    {0,                          { WIMAXASNCP_FT_DATA_PATH_CONTROL,     "Data Path Control"}},
    {0,                          { WIMAXASNCP_FT_CONTEXT_TRANSFER,      "Context Transfer"}},
    {0,                          { WIMAXASNCP_FT_R3_MOBILITY,           "R3 Mobility"}},
    {0,                          { WIMAXASNCP_FT_PAGING,                "Paging"}},
    {0,                          { WIMAXASNCP_FT_RRM,                   "RRM"}},
    {0,                          { WIMAXASNCP_FT_AUTHENTICATION,        "Authentication Relay"}},
    {0,                          { WIMAXASNCP_FT_MS_STATE,              "MS State"}},
    {0,                          { WIMAXASNCP_FT_REAUTHENTICATION,      "Re-Authentication"}},
    {WIMAXASNCP_NWGVER_R10_V120, {WIMAXASNCP_FT_IM_OPERATIONS,          "IM Operations"}},
    {WIMAXASNCP_NWGVER_R10_V121, { WIMAXASNCP_FT_ACCOUNTING,            "Accounting"}},
    {0, { 0, NULL}}
};

/* ------------------------------------------------------------------------- */

static const ver_value_string wimaxasncp_qos_msg_vals[] =
{
    {0,{ 1,  "RR_Req"}},
    {0,{ 2,  "RR_Rsp"}},
    {0,{ 3,  "RR_Ack"}},
    {0,{ 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

static const ver_value_string wimaxasncp_ho_control_msg_vals[] =
{
    {0,                          { 1,  "HO_Ack"}},
    {0,                          { 2,  "HO_Complete"}},
    {0,                          { 3,  "HO_Cnf"}},
    {0,                          { 4,  "HO_Req"}},
    {0,                          { 5,  "HO_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 1,  "HO_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 2,  "HO_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 3,  "HO_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 4,  "HO_Cnf"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 5,  "HO_Complete"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 6,  "HO_Directive"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 7,  "HO_Directive_Rsp"}},
    {0, { 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

static const ver_value_string wimaxasncp_data_path_control_msg_vals[] =
{
    {0, { 1,   "Path_Dereg_Ack"}},
    {0, { 2,   "Path_Dereg_Req"}},
    {0, { 3,   "Path_Dereg_Rsp"}},
    {0, { 4,   "Path_Modification_Ack"}},
    {0, { 5,   "Path_Modification_Req"}},
    {0, { 6,   "Path_Modification_Rsp"}},
    {0, { 7,   "Path_Prereg_Ack"}},
    {0, { 8,   "Path_Prereg_Req"}},
    {0, { 9,   "Path_Prereg_Rsp"}},
    {0, { 10,  "Path_Reg_Ack"}},
    {0, { 11,  "Path_Reg_Req"}},
    {0, { 12,  "Path_Reg_Rsp"}},
    {0, { 13,  "MS_Attachment_Req"}},
    {0, { 14,  "MS_Attachment_Rsp"}},
    {0, { 15,  "MS_Attachment_Ack"}},
    {0, { 16,  "Key_Change_Directive"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 1,   "Path_Dereg_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 2,   "Path_Dereg_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 3,   "Path_Dereg_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 4,   "Path_Modification_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 5,   "Path_Modification_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 6,   "Path_Modification_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 7,   "Path_Prereg_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 8,   "Path_Prereg_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 9,   "Path_Prereg_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 10,  "Path_Reg_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 11,  "Path_Reg_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 12,  "Path_Reg_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 13,  "Obsolete"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 14,  "Obsolete"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 15,  "Obsolete"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 16,  "Obsolete"}},
    {0, { 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

static const ver_value_string wimaxasncp_context_transfer_msg_vals[] =
{
    {0,                          { 1,  "Context_Rpt"}},
    {0,                          { 2,  "Context_Req"}},
    {0,                          { 3,  "Context_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 1,  "Context_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 2,  "Context_Rpt"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 4,  "CMAC_Key_Count_Update"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 5,  "CMAC_Key_Count_Update_ACK"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 6,  "CMAC_Key_Count_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 7,  "CMAC_Key_Count_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 8,  "Prepaid Request"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 9,  "Prepaid Notify"}},
    {WIMAXASNCP_NWGVER_R10_V121, { 6,  "VOID"}},
    {WIMAXASNCP_NWGVER_R10_V121, { 7,  "VOID"}},
    {WIMAXASNCP_NWGVER_R10_V121, { 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

static const ver_value_string wimaxasncp_r3_mobility_msg_vals[] =
{
    {0,                          { 1,  "Anchor_DPF_HO_Req"}},
    {0,                          { 2,  "Anchor_DPF_HO_Trigger"}},
    {0,                          { 3,  "Anchor_DPF_HO_Rsp"}},
    {0,                          { 4,  "Anchor_DPF_Relocate_Req"}},
    {0,                          { 5,  "FA_Register_Req"}},
    {0,                          { 6,  "FA_Register_Rsp"}},
    {0,                          { 7,  "Anchor_DPF_Relocate_Rsp"}},
    {0,                          { 8,  "FA_Revoke_Req"}},
    {0,                          { 9,  "FA_Revoke_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 5,  "Anchor_DPF_Relocate_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 6,  "FA_Register_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 7,  "FA_Register_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 10, "Anchor_DPF_Release_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 11, "Relocation_Ready_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 12, "Relocation_Ready_Rsp"}},
    {0, { 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

static const ver_value_string wimaxasncp_paging_msg_vals[] =
{
    {0,                          { 1,  "Initiate_Paging_Req"}},
    {0,                          { 2,  "Initiate_Paging_Rsp"}},
    {0,                          { 3,  "LU_Cnf"}},
    {0,                          { 4,  "LU_Req"}},
    {0,                          { 5,  "LU_Rsp"}},
    {0,                          { 6,  "Paging_Announce"}},
    {0,                          { 7,  "CMAC_Key_Count_Req"}},
    {0,                          { 8,  "CMAC_Key_Count_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 1,  "Paging_Announce"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 2,  "Delete_MS_Entry_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 3,  "PC_Relocation_Ind"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 4,  "PC_Relocation_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 5,  "Obsolete"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 6,  "Obsolete"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 7,  "Obsolete"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 8,  "Obsolete"}},
    {0, { 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

static const ver_value_string wimaxasncp_rrm_msg_vals[] =
{
    {0,                          { 1,  "R6 PHY_Parameters_Req"}},
    {0,                          { 2,  "R6 PHY_Parameters_Rpt"}},
    {0,                          { 3,  "R4/R6 Spare_Capacity_Req"}},
    {0,                          { 4,  "R4/R6 Spare_Capacity_Rpt"}},
    {0,                          { 5,  "R6 Neighbor_BS_Resource_Status_Update"}},
    {0,                          { 6,  "R4/R6 Radio_Config_Update_Req"}},
    {0,                          { 7,  "R4/R6 Radio_Config_Update_Rpt"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 8,  "R4/R6 Radio_Config_Update_Ack"}},
    {0, { 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

static const ver_value_string wimaxasncp_authentication_msg_vals[] =
{
    {0,                          { 1,  "AR_Authenticated_Eap_Start"}},
    {0,                          { 2,  "AR_Authenticated_EAP_Transfer"}},
    {0,                          { 3,  "AR_Eap_Start"}},
    {0,                          { 4,  "AR_EAP_Transfer"}},
    {0,                          { 5,  "AR_EAP_Complete"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 1,  "AR_EAP_Start"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 2,  "AR_EAP_Transfer"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 3,  "Bulk_Interim_Update"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 4,  "Bulk_Interim_Update_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 5,  "Obsolete"}},
    {0, { 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

static const ver_value_string wimaxasncp_ms_state_msg_vals[] =
{
    {0,                          { 1,  "IM_Entry_State_Change_Req"}},
    {0,                          { 2,  "IM_Entry_State_Change_Rsp"}},
    {0,                          { 3,  "IM_Exit_State_Change_Req"}},
    {0,                          { 4,  "IM_Exit_State_Change_Rsp"}},
    {0,                          { 5,  "NW_ReEntry_State_Change_Directive"}},
    {0,                          { 6,  "MS_PreAttachment_Req"}},
    {0,                          { 7,  "MS_PreAttachment_Rsp"}},
    {0,                          { 8,  "MS_PreAttachment_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 1,  "MS_PreAttachment_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 2,  "MS_PreAttachment_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 3,  "MS_PreAttachment_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 4,  "MS_Attachment_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 5,  "MS_Attachment_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 6,  "MS_Attachment_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 7,  "Key_Change_Directive"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 8,  "Key_Change_Cnf"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 9,  "Key_Change_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 10, "Relocation_Complete_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 11, "Relocation_Complete_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 12, "Relocation_Complete_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 13, "Relocation_Notify"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 14, "Relocation_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 15, "Relocation_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 16, "NetExit_MS_State_Change_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 17, "NetExit_MS_State_Change_Rsp"}},
    {0, { 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

/* note - function type 10-im_operation, was once used for re-authentication */
static const ver_value_string wimaxasncp_im_operations_msg_vals[] =
{
    {0,                          { 1,  "AR_EAP_Start"}},
    {0,                          { 2,  "Key_Change_Directive"}},
    {0,                          { 3,  "Key_Change_Cnf"}},
    {0,                          { 4,  "Relocation_Cnf"}},
    {0,                          { 5,  "Relocation_Confirm_Ack"}},
    {0,                          { 6,  "Relocation_Notify"}},
    {0,                          { 7,  "Relocation_Notify_Ack"}},
    {0,                          { 8,  "Relocation_Req"}},
    {0,                          { 9,  "Relocation_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 1,  "IM_Entry_State_Change_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 2,  "IM_Entry_State_Change_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 3,  "IM_Entry_State_Change_Ack"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 4,  "IM_Exit_State_Change_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 5,  "IM_Exit_State_Change_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 6,  "Initiate_Paging_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 7,  "Initiate_Paging_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 8,  "LU_Req"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 9,  "LU_Rsp"}},
    {WIMAXASNCP_NWGVER_R10_V120, { 10, "LU_Cnf"}},
    {0, { 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

static const ver_value_string wimaxasncp_accounting_msg_vals_r1v121[] =
{
    {WIMAXASNCP_NWGVER_R10_V121, { 1,  "Hot_lining_Req"}},
    {WIMAXASNCP_NWGVER_R10_V121, { 2,  "Hot_lining_Rsp"}},
    {0, { 0,   NULL}}
};

/* ------------------------------------------------------------------------- */

/* supported NWG versions */
static const enum_val_t wimaxasncp_nwg_versions[] = {
    { "Release 1.0, Version 1.0.0" , "R1.0 v1.0.0" , WIMAXASNCP_NWGVER_R10_V100  },
    { "Release 1.0, Version 1.2.0" , "R1.0 v1.2.0" , WIMAXASNCP_NWGVER_R10_V120  },
    { "Release 1.0, Version 1.2.1" , "R1.0 v1.2.1" , WIMAXASNCP_NWGVER_R10_V121  },
    { NULL, NULL, 0 }
};

/* ------------------------------------------------------------------------- */

/* NWG version */
#define WIMAXASNCP_DEF_NWGVER       WIMAXASNCP_NWGVER_R10_V121
static unsigned global_wimaxasncp_nwg_ver = WIMAXASNCP_DEF_NWGVER;

/* ========================================================================= */

typedef struct {
    uint8_t function_type;
    const ver_value_string *vals;
} wimaxasncp_func_msg_t;

/* ------------------------------------------------------------------------ */

static const wimaxasncp_func_msg_t wimaxasncp_func_to_msg_vals_map[] =
{
    { WIMAXASNCP_FT_QOS,               wimaxasncp_qos_msg_vals },
    { WIMAXASNCP_FT_HO_CONTROL,        wimaxasncp_ho_control_msg_vals },
    { WIMAXASNCP_FT_DATA_PATH_CONTROL, wimaxasncp_data_path_control_msg_vals },
    { WIMAXASNCP_FT_CONTEXT_TRANSFER,  wimaxasncp_context_transfer_msg_vals },
    { WIMAXASNCP_FT_R3_MOBILITY,       wimaxasncp_r3_mobility_msg_vals },
    { WIMAXASNCP_FT_PAGING,            wimaxasncp_paging_msg_vals },
    { WIMAXASNCP_FT_RRM,               wimaxasncp_rrm_msg_vals },
    { WIMAXASNCP_FT_AUTHENTICATION,    wimaxasncp_authentication_msg_vals },
    { WIMAXASNCP_FT_MS_STATE,          wimaxasncp_ms_state_msg_vals },
    { WIMAXASNCP_FT_IM_OPERATIONS,     wimaxasncp_im_operations_msg_vals },
    { WIMAXASNCP_FT_ACCOUNTING,        wimaxasncp_accounting_msg_vals_r1v121 }
};

/* ========================================================================= */

static const wimaxasncp_dict_tlv_t *wimaxasncp_get_tlv_info(
    uint16_t type)
{
    wimaxasncp_dict_tlv_t *res = NULL;

    if (wimaxasncp_dict)
    {
        wimaxasncp_dict_tlv_t *tlv;

        for (tlv = wimaxasncp_dict->tlvs; tlv; tlv = tlv->next)
        {
            if (tlv->type == type)
            {
                /* if the TLV is defined for current NWG version */
                if (tlv->since<= global_wimaxasncp_nwg_ver)
                {
                    /* if the current TLV is newer then last found TLV, save it */
                    if (!res || (tlv->since > res->since))
                    {
                        res = tlv;
                    }
                }
            }
        }
    }

    if (debug_enabled && !res)
    {
        g_print("fix-me: unknown TLV type: %u\n", type);
    }

    return res? res:&wimaxasncp_tlv_not_found;
}

/* ========================================================================= */

static const char *wimaxasncp_get_enum_name(
    const wimaxasncp_dict_tlv_t *tlv_info,
    uint32_t code)
{
    if (tlv_info->enum_vs)
    {
        return val_to_str_const(code, tlv_info->enum_vs, "Unknown");
    }
    else
    {
        return "Unknown";
    }
}

/* ========================================================================= */

static const value_string wimaxasncp_decode_type_vals[] =
{
    { WIMAXASNCP_TLV_UNKNOWN,              "WIMAXASNCP_TLV_UNKNOWN"},
    { WIMAXASNCP_TLV_TBD,                  "WIMAXASNCP_TLV_TBD"},
    { WIMAXASNCP_TLV_COMPOUND,             "WIMAXASNCP_TLV_COMPOUND"},
    { WIMAXASNCP_TLV_BYTES,                "WIMAXASNCP_TLV_BYTES"},
    { WIMAXASNCP_TLV_ENUM8,                "WIMAXASNCP_TLV_ENUM8"},
    { WIMAXASNCP_TLV_ENUM16,               "WIMAXASNCP_TLV_ENUM16"},
    { WIMAXASNCP_TLV_ENUM32,               "WIMAXASNCP_TLV_ENUM32"},
    { WIMAXASNCP_TLV_ETHER,                "WIMAXASNCP_TLV_ETHER"},
    { WIMAXASNCP_TLV_ASCII_STRING,         "WIMAXASNCP_TLV_ASCII_STRING"},
    { WIMAXASNCP_TLV_FLAG0,                "WIMAXASNCP_TLV_FLAG0"},
    { WIMAXASNCP_TLV_BITFLAGS8,            "WIMAXASNCP_TLV_BITFLAGS8"},
    { WIMAXASNCP_TLV_BITFLAGS16,           "WIMAXASNCP_TLV_BITFLAGS16"},
    { WIMAXASNCP_TLV_BITFLAGS32,           "WIMAXASNCP_TLV_BITFLAGS32"},
    { WIMAXASNCP_TLV_ID,                   "WIMAXASNCP_TLV_ID"},
    { WIMAXASNCP_TLV_HEX8,                 "WIMAXASNCP_TLV_HEX8"},
    { WIMAXASNCP_TLV_HEX16,                "WIMAXASNCP_TLV_HEX16"},
    { WIMAXASNCP_TLV_HEX32,                "WIMAXASNCP_TLV_HEX32"},
    { WIMAXASNCP_TLV_DEC8,                 "WIMAXASNCP_TLV_DEC8"},
    { WIMAXASNCP_TLV_DEC16,                "WIMAXASNCP_TLV_DEC16"},
    { WIMAXASNCP_TLV_DEC32,                "WIMAXASNCP_TLV_DEC32"},
    { WIMAXASNCP_TLV_IP_ADDRESS,           "WIMAXASNCP_TLV_IP_ADDRESS"},
    { WIMAXASNCP_TLV_IPV4_ADDRESS,         "WIMAXASNCP_TLV_IPV4_ADDRESS"},
    { WIMAXASNCP_TLV_PROTOCOL_LIST,        "WIMAXASNCP_TLV_PROTOCOL_LIST"},
    { WIMAXASNCP_TLV_PORT_RANGE_LIST,      "WIMAXASNCP_TLV_PORT_RANGE_LIST"},
    { WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST, "WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST"},
    { WIMAXASNCP_TLV_VENDOR_SPECIFIC,      "WIMAXASNCP_TLV_VENDOR_SPECIFIC"},
    { 0, NULL}
};

/* ========================================================================= */

static void wimaxasncp_proto_tree_add_tlv_ipv4_value(
    packet_info *pinfo,
    tvbuff_t   *tvb,
    proto_tree *tree,
    proto_item *tlv_item,
    unsigned    offset,
    const wimaxasncp_dict_tlv_t *tlv_info)
{
    int          hf_value;
    uint32_t     ip;
    const char *addr_res;

    if (tlv_info->hf_ipv4 > 0)
    {
        hf_value = tlv_info->hf_ipv4;
    }
    else
    {
        hf_value = tlv_info->hf_value;
    }

    ip = tvb_get_ipv4(tvb, offset);
    addr_res = tvb_address_with_resolution_to_str(pinfo->pool, tvb, AT_IPv4, offset);

    proto_tree_add_ipv4_format(
        tree, hf_value,
        tvb, offset, 4, ip,
        "Value: %s", addr_res);

    proto_item_append_text(
        tlv_item, " - %s", addr_res);
}

/* ========================================================================= */

static void wimaxasncp_proto_tree_add_tlv_ipv6_value(
    packet_info *pinfo,
    tvbuff_t   *tvb,
    proto_tree *tree,
    proto_item *tlv_item,
    unsigned    offset,
    const wimaxasncp_dict_tlv_t *tlv_info)
{
    int                hf_value;
    ws_in6_addr  ip;
    const char *addr_res;

    if (tlv_info->hf_ipv4 > 0)
    {
        hf_value = tlv_info->hf_ipv6;
    }
    else
    {
        hf_value = tlv_info->hf_value;
    }

    tvb_get_ipv6(tvb, offset, &ip);
    addr_res = tvb_address_with_resolution_to_str(pinfo->pool, tvb, AT_IPv6, offset);

    proto_tree_add_ipv6_format(
        tree, hf_value,
        tvb, offset, 16, &ip,
        "Value: %s", addr_res);

    proto_item_append_text(
        tlv_item, " - %s", addr_res);
}

/* ========================================================================= */

static void wimaxasncp_proto_tree_add_ether_value(
    packet_info *pinfo,
    tvbuff_t   *tvb,
    proto_tree *tree,
    proto_item *tlv_item,
    unsigned    offset,
    unsigned    length,
    const wimaxasncp_dict_tlv_t *tlv_info)
{
    int           hf_value;
    const uint8_t *p;
    const char   *ether_name;

    if (tlv_info->hf_bsid > 0)
    {
        hf_value = tlv_info->hf_bsid;
    }
    else
    {
        hf_value = tlv_info->hf_value;
    }

    p = tvb_get_ptr(tvb, offset, length);
    ether_name = tvb_address_with_resolution_to_str(pinfo->pool, tvb, AT_ETHER, offset);

    proto_tree_add_ether_format(
        tree, hf_value,
        tvb, offset, length, p,
        "Value: %s",
        ether_name);

    proto_item_append_text(
        tlv_item, " - %s",
        ether_name);
}

/* ========================================================================= */

static void wimaxasncp_dissect_tlv_value(
    tvbuff_t           *tvb,
    packet_info        *pinfo,
    proto_tree         *tree,
    proto_item         *tlv_item,
    const wimaxasncp_dict_tlv_t *tlv_info)
{
    unsigned     offset          = 0;
    unsigned     length;
    const unsigned  max_show_bytes  = 24; /* arbitrary */
    static const char *hex_note = "[hex]";

    length = tvb_reported_length(tvb);

    switch (tlv_info->decoder)
    {
    case WIMAXASNCP_TLV_ENUM8:
    {
        if (length != 1)
        {
            /* encoding error */
            break;
        }

        if (tlv_info->enums == NULL)
        {
            if (debug_enabled)
            {
                g_print("fix-me: enum values missing for TLV %s (%u)\n",
                        tlv_info->name, tlv_info->type);
            }
        }

        if (tree)
        {
            uint8_t      value;
            const char *s;

            value = tvb_get_uint8(tvb, offset);

            s = wimaxasncp_get_enum_name(tlv_info, value);

            proto_tree_add_uint_format(
                tree, tlv_info->hf_value,
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

        if (tlv_info->enums == NULL)
        {
            if (debug_enabled)
            {
                g_print("fix-me: enum values missing for TLV %s (%u)\n",
                        tlv_info->name, tlv_info->type);
            }
        }

        if (tree)
        {
            uint16_t     value;
            const char *s;

            value = tvb_get_ntohs(tvb, offset);

            s = wimaxasncp_get_enum_name(tlv_info, value);

            proto_tree_add_uint_format(
                tree, tlv_info->hf_value,
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

        if (tlv_info->enums == NULL)
        {
            if (debug_enabled)
            {
                g_print("fix-me: enum values missing for TLV %s (%u)\n",
                        tlv_info->name, tlv_info->type);
            }
        }

        if (tree)
        {
            uint32_t     value;
            const char *s;

            value = tvb_get_ntohl(tvb, offset);

            s = wimaxasncp_get_enum_name(tlv_info, value);

            proto_tree_add_uint_format(
                tree, tlv_info->hf_value,
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
            wimaxasncp_proto_tree_add_ether_value(
                pinfo, tvb, tree, tlv_item, offset, length, tlv_info);
        }

        return;
    }
    case WIMAXASNCP_TLV_ASCII_STRING:
    {
        if (tree)
        {
            const char   *s = tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_ASCII);

            proto_tree_add_string_format(
                tree, tlv_info->hf_value,
                tvb, offset, length, s,
                "Value: %s", s);

            proto_item_append_text(
                tlv_item, " - %s", s);
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
    case WIMAXASNCP_TLV_BITFLAGS8:
    {
        if (length != 1)
        {
            /* encoding error */
            break;
        }

        if (tlv_info->enums == NULL)
        {
            /* enum values missing */
        }

        if (tree)
        {
            proto_tree *flags_tree;
            proto_item *item;
            uint8_t     value;
            unsigned    i;

            value = tvb_get_uint8(tvb, offset);

            item = proto_tree_add_item(
                tree, tlv_info->hf_value,
                tvb, offset, 1, ENC_NA);

            proto_item_append_text(tlv_item, " - 0x%02x", value);

            if (value != 0)
            {
                flags_tree = proto_item_add_subtree(
                    item, ett_wimaxasncp_tlv_value_bitflags8);

                for (i = 0; i < 8; ++i)
                {
                    uint8_t mask;
                    mask = 1U << (7 - i);

                    if (value & mask)
                    {
                        const char *s;

                        s = wimaxasncp_get_enum_name(tlv_info, value & mask);

                        proto_tree_add_uint_format(
                            flags_tree, hf_wimaxasncp_tlv_value_bitflags8,
                            tvb, offset, length, value,
                            "Bit #%u is set: %s", i, s);
                    }
                }
            }
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

        if (tlv_info->enums == NULL)
        {
            /* enum values missing */
        }

        if (tree)
        {
            proto_tree *flags_tree;
            proto_item *item;
            uint16_t    value;
            unsigned    i;

            value = tvb_get_ntohs(tvb, offset);

            item = proto_tree_add_item(
                tree, tlv_info->hf_value,
                tvb, offset, 2, ENC_BIG_ENDIAN);

            proto_item_append_text(tlv_item, " - 0x%04x", value);

            if (value != 0)
            {
                flags_tree = proto_item_add_subtree(
                    item, ett_wimaxasncp_tlv_value_bitflags16);

                for (i = 0; i < 16; ++i)
                {
                    uint16_t mask;
                    mask = 1U << (15 - i);

                    if (value & mask)
                    {
                        const char *s;

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

        if (tlv_info->enums == NULL)
        {
            /* enum values missing */
        }

        if (tree)
        {
            proto_tree *flags_tree;
            proto_item *item;
            uint32_t    value;
            unsigned    i;

            value = tvb_get_ntohl(tvb, offset);

            item = proto_tree_add_item(
                tree, tlv_info->hf_value,
                tvb, offset, 4, ENC_BIG_ENDIAN);

            proto_item_append_text(tlv_item, " - 0x%08x", value);

            if (value != 0)
            {
                flags_tree = proto_item_add_subtree(
                    item, ett_wimaxasncp_tlv_value_bitflags32);

                for (i = 0; i < 32; ++i)
                {
                    uint32_t mask;
                    mask = 1U << (31 - i);

                    if (value & mask)
                    {
                        const char *s;
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
                wimaxasncp_proto_tree_add_tlv_ipv4_value(
                    pinfo, tvb, tree, tlv_item, offset, tlv_info);
            }

            return;
        }
        else if (length == 6)
        {
            if (tree)
            {
                wimaxasncp_proto_tree_add_ether_value(
                    pinfo, tvb, tree, tlv_item, offset, length, tlv_info);
            }

            return;
        }
        else if (length == 16)
        {
            if (tree)
            {
                wimaxasncp_proto_tree_add_tlv_ipv6_value(
                    pinfo, tvb, tree, tlv_item, offset, tlv_info);
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
                tree, tlv_info->hf_value,
                tvb, offset, length, ENC_NA);

            if (length) {
                const char* format;
                if (length <= max_show_bytes)
                {
                    format = " - %s";
                }
                else
                {
                    format = " - %s...";
                }
                const char* s = tvb_bytes_to_str_punct(
                    pinfo->pool, tvb, offset, MIN(length, max_show_bytes), 0);

                proto_item_append_text(
                    tlv_item, format, s);
            } else {
                proto_item_append_text(tlv_item, " - <MISSING>");
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
            uint8_t value;

            value = tvb_get_uint8(tvb, offset);

            proto_tree_add_uint_format(
                tree, tlv_info->hf_value,
                tvb, offset, length, value,
                "Value: 0x%02x", value);

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
            uint16_t value;

            value = tvb_get_ntohs(tvb, offset);

            proto_tree_add_uint_format(
                tree, tlv_info->hf_value,
                tvb, offset, length, value,
                "Value: 0x%04x", value);

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
            uint32_t value;

            value = tvb_get_ntohl(tvb, offset);

            proto_tree_add_uint_format(
                tree, tlv_info->hf_value,
                tvb, offset, length, value,
                "Value: 0x%08x", value);

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
            uint8_t value;

            value = tvb_get_uint8(tvb, offset);

            proto_tree_add_uint_format(
                tree, tlv_info->hf_value,
                tvb, offset, length, value,
                "Value: %u", value);

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
            uint16_t value;

            value = tvb_get_ntohs(tvb, offset);

            proto_tree_add_uint_format(
                tree, tlv_info->hf_value,
                tvb, offset, length, value,
                "Value: %u", value);

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
            uint32_t value;

            value = tvb_get_ntohl(tvb, offset);

            proto_tree_add_uint_format(
                tree, tlv_info->hf_value,
                tvb, offset, length, value,
                "Value: %u", value);

            proto_item_append_text(tlv_item, " - %u", value);
        }

        return;
    }
    case WIMAXASNCP_TLV_TBD:
    {
        if (debug_enabled)
        {
            g_print(
                "fix-me: TBD: TLV %s (%u)\n", tlv_info->name, tlv_info->type);
        }

        if (tree)
        {
            if (length) {
                const char *format;
                const char *s = tvb_bytes_to_str_punct(
                    pinfo->pool, tvb, offset, length, 0);

                if (length <= max_show_bytes) {
                    format = "%s %s";
                } else {
                    format = "%s %s...";
                }

                proto_tree_add_bytes_format_value(
                    tree, tlv_info->hf_value,
                    tvb, offset, length, NULL, format, hex_note, s);

            } else {
                proto_tree_add_bytes_format_value(
                    tree, tlv_info->hf_value,
                    tvb, offset, length, NULL, "%s", "<MISSING>");
            }

            proto_item_append_text(tlv_item, " - TBD");
        }

        return;
    }
    case WIMAXASNCP_TLV_IP_ADDRESS:
    {
        if (length == 4)
        {
            if (tree)
            {
                wimaxasncp_proto_tree_add_tlv_ipv4_value(
                    pinfo, tvb, tree, tlv_item, offset, tlv_info);
            }

            return;
        }
        else if (length == 16)
        {
            if (tree)
            {
                wimaxasncp_proto_tree_add_tlv_ipv6_value(
                    pinfo, tvb, tree, tlv_item, offset, tlv_info);
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
            wimaxasncp_proto_tree_add_tlv_ipv4_value(
                pinfo, tvb, tree, tlv_item, offset, tlv_info);
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
            proto_tree  *protocol_list_tree;
            proto_item  *item;
            const unsigned  max_protocols_in_tlv_item = 8; /* arbitrary */

            protocol_list_tree = proto_tree_add_subtree(
                tree, tvb, offset, length,
                ett_wimaxasncp_tlv_protocol_list, NULL, "Value");

            /* hidden item for filtering */
            item = proto_tree_add_item(
                protocol_list_tree, tlv_info->hf_value,
                tvb, offset, length, ENC_NA);

            proto_item_set_hidden(item);

            while (offset < tvb_reported_length(tvb))
            {
                uint16_t     protocol;
                const char *protocol_name;

                protocol = tvb_get_ntohs(tvb, offset);
                protocol_name = ipprotostr(protocol);

                proto_tree_add_uint_format(
                    protocol_list_tree, tlv_info->hf_protocol,
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
            proto_tree  *port_range_list_tree;
            proto_item  *item;
            const unsigned  max_port_ranges_in_tlv_item = 3; /* arbitrary */

            port_range_list_tree = proto_tree_add_subtree(
                tree, tvb, offset, length,
                ett_wimaxasncp_tlv_port_range_list, NULL, "Value");

            /* hidden item for filtering */
            item = proto_tree_add_item(
                port_range_list_tree, tlv_info->hf_value,
                tvb, offset, length, ENC_NA);

            proto_item_set_hidden(item);

            while (offset < tvb_reported_length(tvb))
            {
                uint16_t portLow;
                uint16_t portHigh;
                proto_tree* range_tree;

                portLow  = tvb_get_ntohs(tvb, offset);
                portHigh = tvb_get_ntohs(tvb, offset + 2);

                range_tree = proto_tree_add_subtree_format(
                    port_range_list_tree, tvb, offset, 4,
                    ett_wimaxasncp_port_range, NULL, "Port Range: %u-%u", portLow, portHigh);

                /* hidden items are for filtering */

                item = proto_tree_add_item(
                    range_tree, tlv_info->hf_port_low,
                    tvb, offset, 2, ENC_BIG_ENDIAN);

                proto_item_set_hidden(item);

                item = proto_tree_add_item(
                    range_tree, tlv_info->hf_port_high,
                    tvb, offset + 2, 2, ENC_BIG_ENDIAN);

                proto_item_set_hidden(item);

                if (offset == 0)
                {
                    proto_item_append_text(
                        tlv_item, " - %u-%u", portLow, portHigh);
                }
                else if (offset < 4 * max_port_ranges_in_tlv_item)
                {
                    proto_item_append_text(
                        tlv_item, ", %u-%u", portLow, portHigh);
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

            ip_address_mask_list_tree = proto_tree_add_subtree(
                tree, tvb, offset, length,
                ett_wimaxasncp_tlv_ip_address_mask_list, NULL, "Value");

            /* hidden item for filtering */
            item = proto_tree_add_item(
                ip_address_mask_list_tree, tlv_info->hf_value,
                tvb, offset, length, ENC_NA);

            proto_item_set_hidden(item);

            if (length % 32 == 0)
            {
                /* ------------------------------------------------------------
                 * presume IPv6
                 * ------------------------------------------------------------
                 */

                while (offset < tvb_reported_length(tvb))
                {
                    proto_tree        *ip_address_mask_tree;

                    ip_address_mask_tree = proto_tree_add_subtree(
                        ip_address_mask_list_tree, tvb, offset, 32,
                        ett_wimaxasncp_tlv_ip_address_mask, NULL, "IPv6 Address and Mask");

                    /* --------------------------------------------------------
                     * address
                     * --------------------------------------------------------
                     */

                    proto_tree_add_item(
                        ip_address_mask_tree,
                        tlv_info->hf_ipv6,
                        tvb, offset, 16, ENC_NA);

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
                    proto_tree_add_item(
                        ip_address_mask_tree,
                        tlv_info->hf_ipv6_mask,
                        tvb, offset, 16, ENC_NA);

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

                while (offset < tvb_reported_length(tvb))
                {
                    proto_tree  *ip_address_mask_tree;
                    uint32_t     ip;
                    const char *s;

                    ip_address_mask_tree = proto_tree_add_subtree(
                        ip_address_mask_list_tree, tvb, offset, 8,
                        ett_wimaxasncp_tlv_ip_address_mask, NULL, "IPv4 Address and Mask");

                    /* --------------------------------------------------------
                     * address
                     * --------------------------------------------------------
                     */

                    ip = tvb_get_ipv4(tvb, offset);

                    proto_tree_add_item(
                        ip_address_mask_tree,
                        tlv_info->hf_ipv4,
                        tvb, offset, 4, ENC_BIG_ENDIAN);

                    proto_item_append_text(
                        item, " - %s (%s)",
                        get_hostname(ip), tvb_ip_to_str(pinfo->pool, tvb, offset));

                    offset += 4;

                    /* --------------------------------------------------------
                     * mask
                     * --------------------------------------------------------
                     */

                    s = tvb_ip_to_str(pinfo->pool, tvb, offset);

                    proto_tree_add_item(
                        ip_address_mask_tree,
                        tlv_info->hf_ipv4_mask,
                        tvb, offset, 4, ENC_BIG_ENDIAN);

                    proto_item_append_text(
                        item, " / %s", s);

                    offset += 4;
                }
            }
        }

        return;
    }
    case WIMAXASNCP_TLV_EAP:
    {
        /*
         *   EAP payload, call eap dissector to dissect eap payload
         */
        uint8_t eap_code;
        uint8_t eap_type = 0;

        /* Get code */
        eap_code = tvb_get_uint8(tvb, offset);
        if (eap_code == EAP_REQUEST || eap_code == EAP_RESPONSE)
        {
            /* Get type */
            eap_type = tvb_get_uint8(tvb, offset + 4);
        }

        /* Add code and type to info column */
        col_append_str(pinfo->cinfo, COL_INFO, " [");
        col_append_str(pinfo->cinfo, COL_INFO,
                        val_to_str(eap_code, eap_code_vals, "Unknown code (0x%02X)"));

        if (eap_code == EAP_REQUEST || eap_code == EAP_RESPONSE)
        {
            col_append_str(pinfo->cinfo, COL_INFO, ", ");
            col_append_str(pinfo->cinfo, COL_INFO,
                            val_to_str_ext(eap_type, &eap_type_vals_ext, "Unknown type (0x%02X)"));
        }

        col_append_str(pinfo->cinfo, COL_INFO, "]");


        {
            proto_tree *eap_tree;
            proto_item *item;
            bool save_writable;
            tvbuff_t *eap_tvb;

            /* Create EAP subtree */
            item = proto_tree_add_item(tree, tlv_info->hf_value, tvb,
                                       offset, length, ENC_NA);
            proto_item_set_text(item, "Value");
            eap_tree = proto_item_add_subtree(item, ett_wimaxasncp_tlv_eap);

            /* Also show high-level details in this root item */
            proto_item_append_text(item, " (%s",
                                   val_to_str(eap_code, eap_code_vals,
                                              "Unknown code (0x%02X)"));
            if (eap_code == EAP_REQUEST || eap_code == EAP_RESPONSE)
            {
                proto_item_append_text(item, ", %s",
                                       val_to_str_ext(eap_type, &eap_type_vals_ext,
                                       "Unknown type (0x%02X)"));
            }
            proto_item_append_text(item, ")");


            /* Extract remaining bytes into new tvb */
            eap_tvb = tvb_new_subset_remaining(tvb, offset);

            /* Disable writing to info column while calling eap dissector */
            save_writable = col_get_writable(pinfo->cinfo, -1);
            col_set_writable(pinfo->cinfo, -1, false);

            /* Call the EAP dissector. */
            call_dissector(eap_handle, eap_tvb, pinfo, eap_tree);

            /* Restore previous writable state of info column */
            col_set_writable(pinfo->cinfo, -1, save_writable);
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
            uint32_t vendorId;
            const char *vendorName;

            vsif_tree = proto_tree_add_subtree(
                tree, tvb, offset, length,
                ett_wimaxasncp_tlv_vendor_specific_information_field, NULL, "Value");

            /* hidden item for filtering */
            item = proto_tree_add_item(
                vsif_tree, tlv_info->hf_value,
                tvb, offset, length, ENC_NA);

            proto_item_set_hidden(item);

            /* ----------------------------------------------------------------
             * vendor ID (24-bit)
             * ----------------------------------------------------------------
             */

            vendorId = tvb_get_ntoh24(tvb, offset);

            vendorName = enterprises_lookup(vendorId, "Unknown");
            proto_tree_add_uint_format(
                vsif_tree, tlv_info->hf_vendor_id,
                tvb, offset, 3, vendorId,
                "Vendor ID: %s (%u)", vendorName, vendorId);

            proto_item_append_text(tlv_item, " - %s", vendorName);

            offset += 3;

            /* ----------------------------------------------------------------
             * hex dump the rest
             * ----------------------------------------------------------------
             */

            if (offset < tvb_reported_length(tvb))
            {
                proto_tree_add_item(
                    vsif_tree, tlv_info->hf_vendor_rest_of_info,
                    tvb, offset, length - offset, ENC_NA);
            }
        }

        return;
    }
    case WIMAXASNCP_TLV_UNKNOWN:
    {
        if (tree)
        {
            const char* s;
            if (length) {
                const char* format1;
                const char* format2;
                if (length <= max_show_bytes)
                {
                    format1 = "%s %s";
                    format2 = " - %s %s";
                }
                else
                {
                    format1 = "%s %s...";
                    format2 = " - %s %s...";
                }
                s = tvb_bytes_to_str_punct(
                    pinfo->pool, tvb, offset, MIN(length, max_show_bytes), 0);

                proto_tree_add_bytes_format_value(
                    tree, tlv_info->hf_value,
                    tvb, offset, length, NULL, format1, hex_note, s);

                proto_item_append_text(
                    tlv_item, format2, hex_note, s);
            }
            else {
                proto_tree_add_bytes_format_value(
                    tree, tlv_info->hf_value,
                    tvb, offset, length, NULL, "%s", "<MISSING>");

                proto_item_append_text(tlv_item, " - <MISSING>");
            }

        }

        return;
    }
    default:
        if (debug_enabled)
        {
            g_print(
                "fix-me: unknown decoder: %d\n", tlv_info->decoder);
        }
        break;
    }

    /* default is hex dump */

    if (tree)
    {
        if (length) {
            const char* format;
            const char *s = tvb_bytes_to_str_punct(
                pinfo->pool, tvb, offset, MIN(length, max_show_bytes), 0);

            if (length <= max_show_bytes) {
                format = "%s %s";
            } else {
                format = "%s %s...";
            }

            proto_tree_add_bytes_format_value(
                tree, hf_wimaxasncp_tlv_value_bytes,
                tvb, offset, length, NULL,
                format, hex_note, s);
        } else {
            proto_tree_add_bytes_format_value(
                tree, hf_wimaxasncp_tlv_value_bytes,
                tvb, offset, length, NULL,
                "%s", "<MISSING>");
        }
    }
}

/* ========================================================================= */

// NOLINTNEXTLINE(misc-no-recursion)
static unsigned dissect_wimaxasncp_tlvs(
    tvbuff_t    *tvb,
    packet_info *pinfo,
    proto_tree  *tree)
{
    unsigned offset;

    offset = 0;
    while (offset < tvb_reported_length(tvb))
    {
        const wimaxasncp_dict_tlv_t *tlv_info;

        proto_tree *tlv_tree;
        proto_item *tlv_item;
        uint16_t    type;
        uint16_t    length;
        unsigned    pad;

        /* --------------------------------------------------------------------
         * type and length
         * --------------------------------------------------------------------
         */

        type = tvb_get_ntohs(tvb, offset);
        tlv_info = wimaxasncp_get_tlv_info(type);

        length = tvb_get_ntohs(tvb, offset + 2);
#if 0   /* Commented out padding; As there is no mention of padding in
           the Latest specification */
        pad = 4 - (length % 4);
        if (pad == 4)
        {
            pad = 0;
        }
#endif
        pad = 0;
        {
            proto_item *type_item;

            int tree_length = MIN(
                (int)(4 + length + pad), tvb_captured_length_remaining(tvb, offset));

            tlv_item = proto_tree_add_item(
                tree, tlv_info->hf_root,
                tvb, offset, tree_length, ENC_NA);

            /* Set label for tlv item */
            proto_item_set_text(tlv_item, "TLV: %s", tlv_info->name);

            /* Show code number if unknown */
            if (tlv_info->decoder == WIMAXASNCP_TLV_UNKNOWN)
            {
                proto_item_append_text(tlv_item, " (%u)", type);
            }

            /* Indicate if a compound tlv */
            if (tlv_info->decoder == WIMAXASNCP_TLV_COMPOUND)
            {
                proto_item_append_text(tlv_item, " [Compound]");
            }

            /* Create TLV subtree */
            tlv_tree = proto_item_add_subtree(
                tlv_item, ett_wimaxasncp_tlv);

            /* Type (expert item if unknown) */
            type_item = proto_tree_add_uint_format(
                tlv_tree, hf_wimaxasncp_tlv_type,
                tvb, offset, 2, type,
                "Type: %s (%u)", tlv_info->name, type);

            if (tlv_info->decoder == WIMAXASNCP_TLV_UNKNOWN)
            {
                expert_add_info_format(pinfo, type_item, &ei_wimaxasncp_tlv_type,
                                       "Unknown TLV type (%u)",
                                       type);
            }

            /* Length */
            proto_tree_add_uint(
                tlv_tree, hf_wimaxasncp_tlv_length,
                tvb, offset + 2, 2, length);

        }

        offset += 4;

        /* --------------------------------------------------------------------
         * value
         * --------------------------------------------------------------------
         */

        if (tlv_info->decoder == WIMAXASNCP_TLV_COMPOUND)
        {
            if (length == 0)
            {
                /* error? compound, but no TLVs inside */
            }
            else if (tvb_reported_length_remaining(tvb, offset) > 0)
            {
                tvbuff_t *tlv_tvb;

                /* N.B.  Not padding out tvb length */
                tlv_tvb = tvb_new_subset_length_caplen(
                    tvb, offset,
                    MIN(length, tvb_captured_length_remaining(tvb, offset)),
                    length);

                increment_dissection_depth(pinfo);
                dissect_wimaxasncp_tlvs(tlv_tvb, pinfo, tlv_tree);
                decrement_dissection_depth(pinfo);
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

            tlv_tvb = tvb_new_subset_length_caplen(
                tvb, offset,
                MIN(length, tvb_captured_length_remaining(tvb, offset)),
                length);

            wimaxasncp_dissect_tlv_value(
                tlv_tvb, pinfo, tlv_tree, tlv_item, tlv_info);
        }

        offset += length + pad;
    }

    return offset;
}

/* ========================================================================= */

static unsigned dissect_wimaxasncp_backend(
    tvbuff_t    *tvb,
    packet_info *pinfo,
    proto_tree  *tree)
{
    unsigned  offset = 0;
    uint16_t  ui16;
    uint32_t  ui32;
    const uint8_t *pmsid;
    uint16_t  tid    = 0;
    bool      dbit_show;


    /* ------------------------------------------------------------------------
     * MSID
     * ------------------------------------------------------------------------
     */

    if (tree)
    {
        proto_tree_add_item(
            tree, hf_wimaxasncp_msid,
            tvb, offset, 6, ENC_NA);
    }
    pmsid = tvb_ether_to_str(pinfo->pool, tvb, offset);

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

    dbit_show = false;
    ui16 = tvb_get_ntohs(tvb, offset);

    if (show_transaction_id_d_bit)
    {
        const uint16_t mask = 0x7fff;

        if (ui16 & 0x8000)
        {
            proto_tree_add_uint_format(
                tree, hf_wimaxasncp_transaction_id,
                tvb, offset, 2, ui16,
                "Transaction ID: D + 0x%04x (0x%04x)", mask & ui16, ui16);

            tid = ui16 & mask;
            dbit_show = true;
        }
        else
        {
            proto_tree_add_uint_format(
                tree, hf_wimaxasncp_transaction_id,
                tvb, offset, 2, ui16,
                "Transaction ID: 0x%04x", ui16);

            tid = ui16;
        }
    }
    else
    {
        proto_tree_add_uint(
            tree, hf_wimaxasncp_transaction_id,
            tvb, offset, 2, ui16);

        tid = ui16;
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

    if (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        tvbuff_t *tlv_tvb;

        tlv_tvb = tvb_new_subset_remaining(tvb, offset);

        offset += dissect_wimaxasncp_tlvs(tlv_tvb, pinfo, tree);
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " - MSID:%s", pmsid);
    if (dbit_show)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", TID:D+0x%04x", tid);
    }
    else
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", TID:0x%04x", tid);
    }

    return offset;
}

/* ========================================================================= */


static const char*
match_ver_value_string(
    const uint32_t val,
    const ver_value_string* const strings,
    const uint32_t max_ver)
{
    const ver_value_string* vvs;
    const ver_value_string* res = NULL;

    /* loop on the levels, from max to 0 */
    for(vvs=strings; vvs->vs.strptr; vvs++)
    {
        if ((vvs->vs.value == val) && (vvs->since <= max_ver))
        {
            if (!res || (vvs->since > res->since))
            {
                res = vvs;
            }
        }
    }

    return res? res->vs.strptr : NULL;
}

static int
dissect_wimaxasncp(
    tvbuff_t    *tvb,
    packet_info *pinfo,
    proto_tree  *tree,
    void *data   _U_)
{
    static const char unknown[] = "Unknown";

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *packet_item     = NULL;
    proto_item *item            = NULL;
    proto_tree *wimaxasncp_tree = NULL;
    tvbuff_t   *subtree;

    unsigned  offset;
    uint8_t ui8;

    uint8_t      function_type;
    const char *function_type_name;
    proto_item  *function_type_item;
    uint16_t     length;

    const wimaxasncp_func_msg_t *p = NULL;
    const char *message_name;
    size_t       i;

    /* ------------------------------------------------------------------------
     * First, we do some heuristics to check if the packet cannot be our
     * protocol.
     * ------------------------------------------------------------------------
     */

    /* Should we check a minimum size?  If so, uncomment out the following
     * code. */
#if 0
    if (tvb_reported_length(tvb) < WIMAXASNCP_HEADER_SIZE)
    {
        return 0;
    }
#endif

    /* We currently only support version 1. */
    if (tvb_bytes_exist(tvb, 0, 1) && tvb_get_uint8(tvb, 0) != 1)
    {
        return 0;
    }

    /* ------------------------------------------------------------------------
     * Initialize the protocol and info column.
     * ------------------------------------------------------------------------
     */

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WiMAX");

    /* We'll fill in the "Info" column after fetch data, so we clear the
       column first in case calls to fetch data from the packet throw an
       exception. */
    col_clear(pinfo->cinfo, COL_INFO);

    /* ========================================================================
     * Disesction starts here
     * ========================================================================
     */

    /* ------------------------------------------------------------------------
     * total packet, we'll adjust after we read the length field
     * ------------------------------------------------------------------------
     */

    offset = 0;

    /* Register protocol fields, etc if haven't done yet. */
    if (hf_wimaxasncp_version <= 0)
    {
        proto_registrar_get_byname("wimaxasncp.version");
    }

    if (tree)
    {
        packet_item = proto_tree_add_item(
            tree, proto_wimaxasncp,
            tvb, 0, MIN(WIMAXASNCP_HEADER_LENGTH_END, tvb_captured_length(tvb)), ENC_NA);

        wimaxasncp_tree = proto_item_add_subtree(
            packet_item, ett_wimaxasncp);
    }

    /* ------------------------------------------------------------------------
     * version
     * ------------------------------------------------------------------------
     */

    if (tree)
    {
        proto_tree_add_item(
            wimaxasncp_tree, hf_wimaxasncp_version,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    }

    offset += 1;

    /* ------------------------------------------------------------------------
     * flags
     * ------------------------------------------------------------------------
     */

    ui8 = tvb_get_uint8(tvb, offset);

    if (tree)
    {
        proto_tree *flags_tree;

        if (ui8 == 0)
        {
            proto_tree_add_uint_format(
                wimaxasncp_tree, hf_wimaxasncp_flags,
                tvb, offset, 1, ui8,
                "Flags: 0x%02x", ui8);
        }
        else
        {
            unsigned j;
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

            proto_item_append_text(item, "0x%02x", ui8);

            flags_tree = proto_item_add_subtree(
                item, ett_wimaxasncp_flags);

            for (j = 0; j < 8; ++j)
            {
                uint8_t mask;
                mask = 1U << (7 - j);

                /* Only add flags that are set */
                if (ui8 & mask)
                {
                    proto_tree_add_uint_format(
                        flags_tree, hf_wimaxasncp_flags,
                        tvb, offset, 1, ui8,
                        "Bit #%u is set: %s",
                        j,
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

    function_type = tvb_get_uint8(tvb, offset);

    function_type_name = match_ver_value_string(function_type,
        wimaxasncp_function_type_vals,
        global_wimaxasncp_nwg_ver);

    if (function_type_name)
    {
        /* add the item to the tree */
        proto_tree_add_uint_format(
            wimaxasncp_tree, hf_wimaxasncp_function_type,
            tvb, offset, 1, function_type,
            "%s (%u)", function_type_name, function_type);
    }
    else
    {
        /* if not matched, add the item and append expert item  */
        function_type_item = proto_tree_add_uint_format(
            wimaxasncp_tree, hf_wimaxasncp_function_type,
            tvb, offset, 1, function_type,
            "Unknown (%u)", function_type);

        expert_add_info_format(pinfo, function_type_item,
                               &ei_wimaxasncp_function_type,
                               "Unknown function type (%u)",
                               function_type);
    }

    offset += 1;

    /* ------------------------------------------------------------------------
     * OP ID and message type
     * ------------------------------------------------------------------------
     */

    ui8 = tvb_get_uint8(tvb, offset);


    /* --------------------------------------------------------------------
     * OP ID
     * --------------------------------------------------------------------
     */

    item = proto_tree_add_uint_format(
        wimaxasncp_tree, hf_wimaxasncp_op_id,
         tvb, offset, 1, ui8,
        "OP ID: %s", val_to_str(ui8 >> 5, wimaxasncp_op_id_vals, unknown));

    proto_item_append_text(item, " (%u)", ((ui8 >> 5) & 7));


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

    message_name = p ? match_ver_value_string(0x1f & ui8, p->vals, global_wimaxasncp_nwg_ver) : unknown;
    if (message_name == NULL)
    {
        message_name = unknown;
    }

    item = proto_tree_add_uint_format(
        wimaxasncp_tree, hf_wimaxasncp_message_type,
        tvb, offset, 1, ui8,
        "Message Type: %s", message_name);

    proto_item_append_text(item, " (%u)", ui8 & 0x1F);

    /* Add expert item if not matched */
    if (strcmp(message_name, unknown) == 0)
    {
        expert_add_info_format(pinfo, item, &ei_wimaxasncp_message_type,
                               "Unknown message type (%u)",
                               0x1f & ui8);
    }

    col_add_str(pinfo->cinfo, COL_INFO, message_name);

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
            wimaxasncp_tree, hf_wimaxasncp_length,
            tvb, offset, 2, length);
    }

    offset += 2;

    if (length < WIMAXASNCP_HEADER_SIZE)
    {
        expert_add_info(pinfo, item, &ei_wimaxasncp_length_bad);

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

    subtree = tvb_new_subset_length_caplen(
        tvb, offset,
        MIN(length, tvb_captured_length_remaining(tvb, offset)),
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
/* Modify the given string to make a suitable display filter                 */
static char *alnumerize(
    char *name)
{
    char *r = name;  /* read pointer */
    char *w = name;  /* write pointer */
    char  c;

    for ( ; (c = *r); ++r)
    {
        if (g_ascii_isalnum(c) || c == '_' || c == '.')
        {
            /* These characters are fine - copy them */
            *(w++) = c;
        }
        else if (c == ' ' || c == '-' || c == '/')
        {
            /* Skip these others if haven't written any characters out yet */
            if (w == name)
            {
                continue;
            }

            /* Skip if we would produce multiple adjacent '_'s */
            if (*(w - 1) == '_')
            {
                continue;
            }

            /* OK, replace with underscore */
            *(w++) = '_';
        }

        /* Other undesirable characters are just skipped */
    }

    /* Terminate and return modified string */
    *w = '\0';
    return name;
}

/* ========================================================================= */

static void add_reg_info(
    int         *hf_ptr,
    const char  *name,
    const char  *abbrev,
    enum ftenum  type,
    int          display,
    const char  *blurb)
{
    hf_register_info hf = {
        hf_ptr, { name, abbrev, type, display, NULL, 0x0, blurb, HFILL } };

    wmem_array_append_one(wimaxasncp_build_dict.hf, hf);
}

/* ========================================================================= */

static void add_tlv_reg_info(
    wimaxasncp_dict_tlv_t *tlv)
{
    char *name;
    char *abbrev;
    const char *root_blurb;
    char *blurb;

    /* ------------------------------------------------------------------------
     * add root reg info
     * ------------------------------------------------------------------------
     */

    name = wmem_strdup(wmem_epan_scope(), tlv->name);
    abbrev = alnumerize(wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s", tlv->name));

    switch (tlv->decoder)
    {
    case WIMAXASNCP_TLV_UNKNOWN:
        root_blurb = "type=Unknown";
        break;
    case WIMAXASNCP_TLV_TBD:
        root_blurb = wmem_strdup_printf(wmem_epan_scope(), "type=%u, TBD", tlv->type);
        break;
    case WIMAXASNCP_TLV_COMPOUND:
        root_blurb = wmem_strdup_printf(wmem_epan_scope(), "type=%u, Compound", tlv->type);
        break;
    case WIMAXASNCP_TLV_FLAG0:
        root_blurb = wmem_strdup_printf(wmem_epan_scope(), "type=%u, Value = Null", tlv->type);
        break;
    default:
        root_blurb = wmem_strdup_printf(wmem_epan_scope(), "type=%u", tlv->type);
        break;
    }

    add_reg_info(
        &tlv->hf_root, name, abbrev, FT_BYTES, BASE_NONE, root_blurb);

    /* ------------------------------------------------------------------------
     * add value(s) reg info
     * ------------------------------------------------------------------------
     */

    name = wmem_strdup(wmem_epan_scope(), "Value");
    abbrev = alnumerize(wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.value", tlv->name));
    blurb = wmem_strdup_printf(wmem_epan_scope(), "value for type=%u", tlv->type);

    switch (tlv->decoder)
    {
    case WIMAXASNCP_TLV_UNKNOWN:
        wmem_free(wmem_epan_scope(), blurb);

        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_BYTES, BASE_NONE,
            "value for unknown type");
        break;

    case WIMAXASNCP_TLV_TBD:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_BYTES, BASE_NONE, blurb);
        break;

    case WIMAXASNCP_TLV_COMPOUND:
    case WIMAXASNCP_TLV_FLAG0:
        wmem_free(wmem_epan_scope(), name);
        wmem_free(wmem_epan_scope(), abbrev);
        wmem_free(wmem_epan_scope(), blurb);
        break;

    case WIMAXASNCP_TLV_BYTES:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_BYTES, BASE_NONE, blurb);
        break;

    case WIMAXASNCP_TLV_ENUM8:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT8, BASE_DEC, blurb);
        break;

    case WIMAXASNCP_TLV_ENUM16:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT16, BASE_DEC, blurb);
        break;

    case WIMAXASNCP_TLV_ENUM32:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT32, BASE_DEC, blurb);
        break;

    case WIMAXASNCP_TLV_ETHER:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_ETHER, BASE_NONE, blurb);
        break;

    case WIMAXASNCP_TLV_ASCII_STRING:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_STRING, BASE_NONE, blurb);
        break;

    case WIMAXASNCP_TLV_BITFLAGS8:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT8, BASE_HEX, blurb);
        break;

    case WIMAXASNCP_TLV_BITFLAGS16:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT16, BASE_HEX, blurb);
        break;

    case WIMAXASNCP_TLV_BITFLAGS32:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT32, BASE_HEX, blurb);
        break;

    case WIMAXASNCP_TLV_ID:
        wmem_free(wmem_epan_scope(), abbrev);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.ipv4_value", tlv->name));

        add_reg_info(
            &tlv->hf_ipv4, "IPv4 Address", abbrev, FT_IPv4, BASE_NONE, blurb);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.ipv6_value", tlv->name));

        add_reg_info(
            &tlv->hf_ipv6, "IPv6 Address", abbrev, FT_IPv6, BASE_NONE, blurb);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.bsid_value", tlv->name));

        add_reg_info(
            &tlv->hf_bsid, "BS ID", abbrev, FT_ETHER, BASE_NONE, blurb);

        break;

    case WIMAXASNCP_TLV_HEX8:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT8, BASE_HEX, blurb);
        break;

    case WIMAXASNCP_TLV_HEX16:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT16, BASE_HEX, blurb);
        break;

    case WIMAXASNCP_TLV_HEX32:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT32, BASE_HEX, blurb);
        break;

    case WIMAXASNCP_TLV_DEC8:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT8, BASE_DEC, blurb);
        break;

    case WIMAXASNCP_TLV_DEC16:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT16, BASE_DEC, blurb);
        break;

    case WIMAXASNCP_TLV_DEC32:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_UINT32, BASE_DEC, blurb);
        break;

    case WIMAXASNCP_TLV_IP_ADDRESS:
        wmem_free(wmem_epan_scope(), abbrev);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.ipv4_value", tlv->name));

        add_reg_info(
            &tlv->hf_ipv4, "IPv4 Address", abbrev, FT_IPv4, BASE_NONE, blurb);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.ipv6_value", tlv->name));

        add_reg_info(
            &tlv->hf_ipv6, "IPv6 Address", abbrev, FT_IPv6, BASE_NONE, blurb);

        break;

    case WIMAXASNCP_TLV_IPV4_ADDRESS:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_IPv4, BASE_NONE, blurb);
        break;

    case WIMAXASNCP_TLV_PROTOCOL_LIST:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_BYTES, BASE_NONE, blurb);

        blurb = wmem_strdup_printf(wmem_epan_scope(), "value component for type=%u", tlv->type);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.value.protocol", tlv->name));

        add_reg_info(
            &tlv->hf_protocol, "Protocol", abbrev, FT_UINT16, BASE_DEC, blurb);

        break;

    case WIMAXASNCP_TLV_PORT_RANGE_LIST:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_BYTES, BASE_NONE, blurb);

        blurb = wmem_strdup_printf(wmem_epan_scope(), "value component for type=%u", tlv->type);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.value.port_low", tlv->name));

        add_reg_info(
            &tlv->hf_port_low, "Port Low", abbrev, FT_UINT16, BASE_DEC, blurb);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.value.port_high", tlv->name));

        add_reg_info(
            &tlv->hf_port_high, "Port High", abbrev, FT_UINT16, BASE_DEC, blurb);

        break;

    case WIMAXASNCP_TLV_IP_ADDRESS_MASK_LIST:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_BYTES, BASE_NONE, blurb);

        blurb = wmem_strdup_printf(wmem_epan_scope(), "value component for type=%u", tlv->type);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.value.ipv4", tlv->name));

        add_reg_info(
            &tlv->hf_ipv4, "IPv4 Address", abbrev, FT_IPv4, BASE_NONE, blurb);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.value.ipv4_mask", tlv->name));

        add_reg_info(
            &tlv->hf_ipv4_mask, "IPv4 Mask", abbrev, FT_IPv4, BASE_NONE, blurb);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.value.ipv6", tlv->name));

        add_reg_info(
            &tlv->hf_ipv6, "IPv6 Address", abbrev, FT_IPv6, BASE_NONE, blurb);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.value.ipv6_mask", tlv->name));

        add_reg_info(
            &tlv->hf_ipv6_mask, "IPv6 Mask", abbrev, FT_IPv6, BASE_NONE, blurb);

        break;

    case WIMAXASNCP_TLV_VENDOR_SPECIFIC:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_BYTES, BASE_NONE, blurb);

        blurb = wmem_strdup_printf(wmem_epan_scope(), "value component for type=%u", tlv->type);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(), "wimaxasncp.tlv.%s.value.vendor_id", tlv->name));

        add_reg_info(
            &tlv->hf_vendor_id, "Vendor ID", abbrev, FT_UINT24, BASE_DEC, blurb);

        abbrev = alnumerize(
            wmem_strdup_printf(wmem_epan_scope(),
                "wimaxasncp.tlv.%s.value.vendor_rest_of_info", tlv->name));

        add_reg_info(
            &tlv->hf_vendor_rest_of_info, "Rest of Info", abbrev, FT_BYTES, BASE_NONE,
            blurb);

        break;

    case WIMAXASNCP_TLV_EAP:
        blurb = wmem_strdup_printf(wmem_epan_scope(), "EAP payload embedded in %s", name);

        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_BYTES, BASE_NONE, blurb);
        break;


    default:
        add_reg_info(
            &tlv->hf_value, name, abbrev, FT_BYTES, BASE_NONE, blurb);

        if (debug_enabled)
        {
            g_print(
                "fix-me: unknown decoder: %d\n", tlv->decoder);
        }

        break;
    }
}

/* ========================================================================= */
/* Register the protocol fields and subtrees with Wireshark */
static void
register_wimaxasncp_fields(const char* unused _U_)
{
    bool      debug_parser;
    bool      dump_dict;
    char     *dir;
    char*    dict_error;

    /* ------------------------------------------------------------------------
     * List of header fields
     * ------------------------------------------------------------------------
     */

    static hf_register_info hf_base[] = {
            {
                &hf_wimaxasncp_version,
                {
                    "Version",
                    "wimaxasncp.version",
                    FT_UINT8,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
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
                    NULL,
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
                    NULL,
                    0x0,
                    NULL,
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
                    NULL,
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
                    NULL,
                    HFILL
                }
            },
#if 0
            {
                &hf_wimaxasncp_qos_msg,
                {
                    "Message Type",
                    "wimaxasncp.qos_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_ho_control_msg,
                {
                    "Message Type",
                    "wimaxasncp.ho_control_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_data_path_control_msg,
                {
                    "Message Type",
                    "wimaxasncp.data_path_control_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_context_delivery_msg,
                {
                    "Message Type",
                    "wimaxasncp.context_delivery_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_r3_mobility_msg,
                {
                    "Message Type",
                    "wimaxasncp.r3_mobility_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_paging_msg,
                {
                    "Message Type",
                    "wimaxasncp.paging_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_rrm_msg,
                {
                    "Message Type",
                    "wimaxasncp.rrm_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_authentication_msg,
                {
                    "Message Type",
                    "wimaxasncp.authentication_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_ms_state_msg,
                {
                    "Message Type",
                    "wimaxasncp.ms_state_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_reauthentication_msg,
                {
                    "Message Type",
                    "wimaxasncp.reauthentication_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_session_msg,
                {
                    "Message Type",
                    "wimaxasncp.session_msg",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0x1F,
                    NULL,
                    HFILL
                }
            },
#endif
            {
                &hf_wimaxasncp_length,
                {
                    "Length",
                    "wimaxasncp.length",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
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
                    NULL,
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
                    NULL,
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
                    NULL,
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
                    NULL,
                    HFILL
                }
            },
#if 0
            {
                &hf_wimaxasncp_tlv,
                {
                    "TLV",
                    "wimaxasncp.tlv",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
#endif
            {
                &hf_wimaxasncp_tlv_type,
                {
                    "Type",
                    "wimaxasncp.tlv.type",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_length,
                {
                    "Length",
                    "wimaxasncp.tlv.length",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_bytes,
                {
                    "Value",
                    "wimaxasncp.tlv_value_bytes",
                    FT_BYTES,
                    BASE_NONE,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
            {
                &hf_wimaxasncp_tlv_value_bitflags8,
                {
                    "Value",
                    "wimaxasncp.tlv_value_bitflags8",
                    FT_UINT8,
                    BASE_HEX,
                    NULL,
                    0xff,
                    NULL,
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
                    NULL,
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
                    NULL,
                    HFILL
                }
            },
#if 0
            {
                &hf_wimaxasncp_tlv_value_protocol,
                {
                    "Value",
                    "wimaxasncp.tlv_value_protocol",
                    FT_UINT16,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            },
#endif
#if 0
            {
                &hf_wimaxasncp_tlv_value_vendor_id,
                {
                    "Vendor ID",
                    "wimaxasncp.tlv_value_vendor_id",
                    FT_UINT24,
                    BASE_DEC,
                    NULL,
                    0x0,
                    NULL,
                    HFILL
                }
            }
#endif
        };

    /* ------------------------------------------------------------------------
     * Protocol subtree array
     * ------------------------------------------------------------------------
     */

    static int *ett_base[] = {
            &ett_wimaxasncp,
            &ett_wimaxasncp_flags,
            &ett_wimaxasncp_tlv,
            &ett_wimaxasncp_tlv_value_bitflags8,
            &ett_wimaxasncp_tlv_value_bitflags16,
            &ett_wimaxasncp_tlv_value_bitflags32,
            &ett_wimaxasncp_tlv_protocol_list,
            &ett_wimaxasncp_tlv_port_range_list,
            &ett_wimaxasncp_tlv_ip_address_mask_list,
            &ett_wimaxasncp_tlv_ip_address_mask,
            &ett_wimaxasncp_tlv_eap,
            &ett_wimaxasncp_tlv_vendor_specific_information_field,
            &ett_wimaxasncp_port_range
    };

    static ei_register_info ei[] = {
        { &ei_wimaxasncp_tlv_type, { "wimaxasncp.tlv.type.unknown", PI_UNDECODED, PI_WARN, "Unknown tlv", EXPFILL }},
        { &ei_wimaxasncp_function_type, { "wimaxasncp.function_type.unknown", PI_UNDECODED, PI_WARN, "Unknown function type", EXPFILL }},
        { &ei_wimaxasncp_op_id, { "wimaxasncp.opid.unknown", PI_UNDECODED, PI_WARN, "Unknown message op", EXPFILL }},
        { &ei_wimaxasncp_message_type, { "wimaxasncp.message_type.unknown", PI_UNDECODED, PI_WARN, "Unknown message type", EXPFILL }},
        { &ei_wimaxasncp_length_bad, { "wimaxasncp.length.bad", PI_MALFORMED, PI_ERROR, "Bad length", EXPFILL }},
    };

    expert_module_t* expert_wimaxasncp;

    /* ------------------------------------------------------------------------
     * load the XML dictionary
     * ------------------------------------------------------------------------
     */

    debug_parser = getenv("WIRESHARK_DEBUG_WIMAXASNCP_DICT_PARSER") != NULL;
    dump_dict    = getenv("WIRESHARK_DUMP_WIMAXASNCP_DICT") != NULL;

    dir = ws_strdup_printf(
        "%s" G_DIR_SEPARATOR_S "wimaxasncp",
        get_datafile_dir());

    wimaxasncp_dict =
        wimaxasncp_dict_scan(dir, "dictionary.xml", debug_parser, &dict_error);

    g_free(dir);

    if (dict_error)
    {
        report_failure("wimaxasncp - %s", dict_error);
        g_free(dict_error);
    }

    if (wimaxasncp_dict && dump_dict)
    {
        wimaxasncp_dict_print(stdout, wimaxasncp_dict);
    }

    /* ------------------------------------------------------------------------
     * build the hf and ett dictionary entries
     * ------------------------------------------------------------------------
     */

    wimaxasncp_build_dict.hf =
        wmem_array_new(wmem_epan_scope(), sizeof(hf_register_info));

    wmem_array_append(
        wimaxasncp_build_dict.hf, hf_base, array_length(hf_base));

    wimaxasncp_build_dict.ett =
        wmem_array_new(wmem_epan_scope(), sizeof(int*));

    wmem_array_append(
        wimaxasncp_build_dict.ett, ett_base, array_length(ett_base));

    if (wimaxasncp_dict)
    {
        wimaxasncp_dict_tlv_t *tlv;

        /* For each TLV found in XML file */
        for (tlv = wimaxasncp_dict->tlvs; tlv; tlv = tlv->next)
        {
            if (tlv->enums)
            {
                /* Create array for enums */
                wimaxasncp_dict_enum_t *e;
                wmem_array_t* array = wmem_array_new(wmem_epan_scope(), sizeof(value_string));

                /* Copy each entry into value_string array */
                for (e = tlv->enums; e; e = e->next)
                {
                    value_string item = { e->code, e->name };
                    wmem_array_append_one(array, item);
                }

                /* Set enums to use with this TLV */
                wmem_array_set_null_terminator(array);
                tlv->enum_vs = (value_string*)wmem_array_get_raw(array);
            }

            add_tlv_reg_info(tlv);
        }
    }

    /* add an entry for unknown TLVs */
    add_tlv_reg_info(&wimaxasncp_tlv_not_found);

    /* The following debug will only be printed if the debug_enabled variable
     * is set programmatically.  Setting the value via preferences will not
     * work as it will be set too late to affect this code path.
     */
    if (debug_enabled)
    {
        if (wimaxasncp_dict)
        {
            wimaxasncp_dict_tlv_t *tlv;

            for (tlv = wimaxasncp_dict->tlvs; tlv; tlv = tlv->next)
            {
                ws_debug_printf(
                    "%s\n"
                    "  type                   = %u\n"
                    "  description            = %s\n"
                    "  decoder                = %s\n"
                    "  hf_root                = %d\n"
                    "  hf_value               = %d\n"
                    "  hf_ipv4                = %d\n"
                    "  hf_ipv6                = %d\n"
                    "  hf_bsid                = %d\n"
                    "  hf_protocol            = %d\n"
                    "  hf_port_low            = %d\n"
                    "  hf_port_high           = %d\n"
                    "  hf_ipv4_mask           = %d\n"
                    "  hf_ipv6_mask           = %d\n"
                    "  hf_vendor_id           = %d\n"
                    "  hf_vendor_rest_of_info = %d\n",
                    tlv->name,
                    tlv->type,
                    tlv->description,
                    val_to_str(
                        tlv->decoder, wimaxasncp_decode_type_vals, "Unknown"),
                    tlv->hf_root,
                    tlv->hf_value,
                    tlv->hf_ipv4,
                    tlv->hf_ipv6,
                    tlv->hf_bsid,
                    tlv->hf_protocol,
                    tlv->hf_port_low,
                    tlv->hf_port_high,
                    tlv->hf_ipv4_mask,
                    tlv->hf_ipv6_mask,
                    tlv->hf_vendor_id,
                    tlv->hf_vendor_rest_of_info);
            }
        }
    }

        /* Required function calls to register the header fields and subtrees
         * used */
    proto_register_field_array(
        proto_wimaxasncp,
        (hf_register_info*)wmem_array_get_raw(wimaxasncp_build_dict.hf),
        wmem_array_get_count(wimaxasncp_build_dict.hf));

    proto_register_subtree_array(
        (int**)wmem_array_get_raw(wimaxasncp_build_dict.ett),
        wmem_array_get_count(wimaxasncp_build_dict.ett));

    expert_wimaxasncp = expert_register_protocol(proto_wimaxasncp);
    expert_register_field_array(expert_wimaxasncp, ei, array_length(ei));

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

    /* ------------------------------------------------------------------------
     * complete registration
     * ------------------------------------------------------------------------
     */

        /* Register the protocol name and description */
    proto_wimaxasncp = proto_register_protocol("WiMAX ASN Control Plane Protocol", "WiMAX ASN CP", "wimaxasncp");

        /* Register this dissector by name */
    wimaxasncp_handle = register_dissector("wimaxasncp", dissect_wimaxasncp, proto_wimaxasncp);

    wimaxasncp_module = prefs_register_protocol(proto_wimaxasncp, NULL);

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

    prefs_register_enum_preference(
        wimaxasncp_module,
        "nwg_version",
        "NWG Version",
        "Version of the NWG that the R6 protocol complies with",
        &global_wimaxasncp_nwg_ver,
        wimaxasncp_nwg_versions,
        false);

    proto_register_prefix("wimaxasncp", register_wimaxasncp_fields);
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
    /* Find the EAP dissector */
    eap_handle = find_dissector_add_dependency("eap", proto_wimaxasncp);

    dissector_add_uint_with_preference("udp.port", WIMAXASNCP_DEF_UDP_PORT, wimaxasncp_handle);
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
