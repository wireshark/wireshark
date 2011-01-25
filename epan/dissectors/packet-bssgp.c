/* packet-bssgp.c
 * Routines for Base Station Subsystem GPRS Protocol dissection
 * Copyright 2000, Susanne Edlund <susanne.edlund@ericsson.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/* 3GPP TS 48.018 V 6.5.0 (2004-07) Release 6 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <math.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>
#include <prefs.h>
#include <epan/asn1.h>

#include "packet-bssgp.h"
#include "packet-e212.h"
#include "packet-gsm_a_common.h"
#include "packet-rrc.h"
#include "packet-lte-rrc.h"
#include "packet-s1ap.h"

/* #define BSSGP_DEBUG */
/*
 * TS 48.018 V6.6.0 (2004-11) says, of information elements:
 *
 *    Refer to General Structure Of The Information Elements/3GPP TS 48.016.
 *
 * TS 48.016 V9.0.0 (2010-02), in that section, says, of information elements:
 *
 *    When a field extends over more than one octet, the order of bit
 *    values progressively decreases as the octet number increases.
 *    The least significant bit of the field is represented by the
 *    lowest numbered bit of the highest numbered octet of the field.
 *
 * which sure sounds little-endian.
 *
 * However, for some not-entirely-obvious reason, BSSGP_LITTLE_ENDIAN, which
 * was passed to proto_tree_add_item() as the byte-order argument, was
 * defined as FALSE - which meant big-endian.
 *
 * For now, we'll use ENC_BIG_ENDIAN, now that we have ENC_BIG_ENDIAN and
 * REP_LITTLE_ENDIAN definitions.
 */
#define BSSGP_TRANSLATION_MAX_LEN 50
#define BSSGP_MASK_LEFT_OCTET_HALF 0xf0
#define BSSGP_MASK_RIGHT_OCTET_HALF 0x0f
#define BSSGP_MOBILE_IDENTITY_TYPE_IMSI 1
#define BSSGP_MOBILE_IDENTITY_TYPE_IMEI 2
#define BSSGP_MOBILE_IDENTITY_TYPE_IMEISV 3
#define BSSGP_MOBILE_IDENTITY_TYPE_TMSI_PTMSI 4
#define BSSGP_MOBILE_IDENTITY_TYPE_NO_IDENTITY 0
#define BSSGP_SEP ", "
#define BSSGP_NOT_DECODED "< Not decoded yet >"
#define BSSGP_UNKNOWN (-1)
static int bssgp_decode_nri = 0;
static guint bssgp_nri_length = 4;

static packet_info *gpinfo;
static proto_tree *parent_tree;
static dissector_handle_t llc_handle;
static dissector_handle_t rrlp_handle;
static dissector_handle_t data_handle;

static module_t *bssgp_module;

/* Initialize the protocol and registered fields */
static int hf_bssgp_iei_nacc_cause = -1;
static int proto_bssgp = -1;
static int hf_bssgp_msg_type = -1;
int hf_bssgp_elem_id = -1;
static int hf_bssgp_ie_type = -1;
static int hf_bssgp_mcc = -1;
static int hf_bssgp_mnc = -1;
static int hf_bssgp_lac = -1;
static int hf_bssgp_rac = -1;
static int hf_bssgp_ci = -1;
static int hf_bssgp_flush_action = -1;
static int hf_bssgp_llc_frames_disc = -1;
static int hf_bssgp_ra_discriminator = -1;
static int hf_bssgp_appid = -1;
static int hf_bssgp_rcid = -1;
static int hf_bssgp_rrc_si_msg_type = -1;
static int hf_ran_inf_req_pdu_type_ext = -1;
static int hf_ran_inf_pdu_type_ext = -1;
static int hf_bssgp_nri = -1;
static int hf_bssgp_imsi = -1;
static int hf_bssgp_imei = -1;
static int hf_bssgp_imeisv = -1;
static int hf_bssgp_tmsi_ptmsi = -1;
static int hf_bssgp_bss_area_ind = -1;
static int hf_bssgp_bvci = -1;
static int hf_bssgp_bmax = -1;
static int hf_bssgp_r = -1;
static int hf_bssgp_bucket_size = -1;
static int hf_bssgp_omc_id = -1;
static int hf_bssgp_nsei = -1;
static int hf_bssgp_tlli = -1;

static int hf_bssgp_delay_val = -1;
static int hf_bssgp_cause = -1;
static int hf_bssgp_peak_rate_gran = -1;
static int hf_bssgp_cr_bit = -1;
static int hf_bssgp_t_bit = -1;
static int hf_bssgp_a_bit = -1;
static int hf_bssgp_ra_cause = -1;
static int hf_bssgp_ra_cap_upd_cause = -1;
static int hf_bssgp_r_default_ms = -1;
static int hf_bssgp_suspend_ref_no = -1;
static int hf_bssgp_tag = -1;
static int hf_bssgp_trace_ref = -1;
static int hf_bssgp_trigger_id = -1;
static int hf_bssgp_transaction_id = -1;
static int hf_bssgp_no_of_oct = -1;
static int hf_bssgp_unit_val = -1;
static int hf_bssgp_gprs_timer = -1;
static int hf_bssgp_mbms = -1;
static int hf_bssgp_EnhancedRadioStatus = -1;
static int hf_bssgp_pfcfc = -1;
static int hf_bssgp_rim = -1;
static int hf_bssgp_lcs = -1;
static int hf_bssgp_inr = -1;
static int hf_bssgp_cbl = -1;
static int hf_bssgp_pfc = -1;
static int hf_bssgp_bucket_full_ratio = -1;

static int hf_bssgp_precedence = -1;
static int hf_bssgp_serv_utran_cco = -1;
static int hf_bssgp_mbs_session_id = -1;
static int hf_bssgp_gb_if = -1;
static int hf_bssgp_ps_ho = -1;
static int hf_bssgp_src_to_trg_transp_cont = -1;
static int hf_bssgp_trg_to_src_transp_cont = -1;
static int hf_bssgp_rnc_id = -1;
static int hf_bssgp_page_mode = -1;
static int hf_bssgp_container_id = -1;
static int hf_bssgp_global_tfi = -1;
static int hf_bssgp_ul_tfi = -1;
static int hf_bssgp_dl_tfi = -1;
static int hf_bssgp_ps_ho_cmd = -1;
static int hf_bssgp_sipsi = -1;
static int hf_bssgp_type = -1;
static int hf_bssgp_cs_indication = -1;
static int hf_bssgp_flow_control_gran = -1;
static int hf_bssgp_serv_eutran_cco = -1;
static int hf_bssgp_sub_prof_id_f_rat_freq_prio = -1;
static int hf_bssgp_rel_int_rat_ho_inf_ind = -1;
static int hf_bssgp_csg_id = -1;
static int hf_bssgp_cell_acc_mode = -1;

/* Initialize the subtree pointers */
static gint ett_bssgp = -1;
static gint ett_bssgp_new = -1;
static gint ett_bssgp_qos_profile = -1;
static gint ett_bssgp_gprs_timer = -1;
static gint ett_bssgp_cell_identifier = -1;
static gint ett_bssgp_channel_needed = -1;
static gint ett_bssgp_drx_parameters = -1;
static gint ett_bssgp_mobile_identity = -1;
static gint ett_bssgp_priority = -1;
static gint ett_bssgp_lsa_identifier_list = -1;
static gint ett_bssgp_lsa_information = -1;
static gint ett_bssgp_lsa_information_lsa_identification_and_attributes = -1;
static gint ett_bssgp_abqp = -1;
static gint ett_bssgp_lcs_qos = -1;
static gint ett_bssgp_lcs_client_type = -1;
static gint ett_bssgp_requested_gps_assistance_data = -1;
static gint ett_bssgp_requested_gps_assistance_data_satellite = -1;
static gint ett_bssgp_location_type = -1;
static gint ett_bssgp_positioning_data_positioning_method = -1;
static gint ett_bssgp_deciphering_keys = -1;
static gint ett_bssgp_lcs_cause = -1;
static gint ett_bssgp_lcs_capability = -1;
static gint ett_bssgp_rrlp_flags = -1;
static gint ett_bssgp_rim_pdu_indications = -1;
static gint ett_bssgp_mcc = -1;
static gint ett_bssgp_mnc = -1;
static gint ett_bssgp_routing_area = -1;
static gint ett_bssgp_location_area = -1;
static gint ett_bssgp_rai_ci = -1;
static gint ett_bssgp_rim_routing_information =-1;
static gint ett_bssgp_ran_information_request_application_container = -1;
static gint ett_bssgp_ran_information_request_container_unit = -1;
static gint ett_bssgp_ran_information_container_unit = -1;
static gint ett_bssgp_pfc_flow_control_parameters = -1;
static gint ett_bssgp_pfc_flow_control_parameters_pfc = -1;
static gint ett_bssgp_global_cn_id = -1;
static gint ett_bssgp_ms_radio_access_capability = -1;
static gint ett_bssgp_msrac_value_part = -1;
static gint ett_bssgp_msrac_additional_access_technologies = -1;
static gint ett_bssgp_msrac_access_capabilities = -1;
static gint ett_bssgp_msrac_a5_bits = -1;
static gint ett_bssgp_msrac_multislot_capability = -1;
static gint ett_bssgp_feature_bitmap = -1;
static gint ett_bssgp_positioning_data = -1;
static gint ett_bssgp_tlli = -1;
static gint ett_bssgp_tmsi_ptmsi = -1;

/* PDU type coding, v6.5.0, table 11.3.26, p 80 */
#define BSSGP_PDU_DL_UNITDATA                  0x00
#define BSSGP_PDU_UL_UNITDATA                  0x01
#define BSSGP_PDU_RA_CAPABILITY                0x02
#define BSSGP_PDU_PTM_UNITDATA                 0x03
#define BSSGP_PDU_DL_MBMS_UNITDATA             0x04
#define BSSGP_PDU_UL_MBMS_UNITDATA             0x05
#define BSSGP_PDU_PAGING_PS                    0x06
#define BSSGP_PDU_PAGING_CS                    0x07
#define BSSGP_PDU_RA_CAPABILITY_UPDATE         0x08
#define BSSGP_PDU_RA_CAPABILITY_UPDATE_ACK     0x09
#define BSSGP_PDU_RADIO_STATUS                 0x0a
#define BSSGP_PDU_SUSPEND                      0x0b
#define BSSGP_PDU_SUSPEND_ACK                  0x0c
#define BSSGP_PDU_SUSPEND_NACK                 0x0d
#define BSSGP_PDU_RESUME                       0x0e
#define BSSGP_PDU_RESUME_ACK                   0x0f
#define BSSGP_PDU_RESUME_NACK                  0x10

#define BSSGP_PDU_RESERVED_0X11                0x11
#define BSSGP_PDU_RESERVED_0X12                0x12
#define BSSGP_PDU_RESERVED_0X13                0x13
#define BSSGP_PDU_RESERVED_0X14                0x14
#define BSSGP_PDU_RESERVED_0X15                0x15
#define BSSGP_PDU_RESERVED_0X16                0x16
#define BSSGP_PDU_RESERVED_0X17                0x17
#define BSSGP_PDU_RESERVED_0X18                0x18
#define BSSGP_PDU_RESERVED_0X19                0x19
#define BSSGP_PDU_RESERVED_0X1A                0x1a
#define BSSGP_PDU_RESERVED_0X1B                0x1b
#define BSSGP_PDU_RESERVED_0X1C                0x1c
#define BSSGP_PDU_RESERVED_0X1D                0x1d
#define BSSGP_PDU_RESERVED_0X1E                0x1e
#define BSSGP_PDU_RESERVED_0X1F                0x1f

#define BSSGP_PDU_BVC_BLOCK                    0x20
#define BSSGP_PDU_BVC_BLOCK_ACK                0x21
#define BSSGP_PDU_BVC_RESET                    0x22
#define BSSGP_PDU_BVC_RESET_ACK                0x23
#define BSSGP_PDU_BVC_UNBLOCK                  0x24
#define BSSGP_PDU_BVC_UNBLOCK_ACK              0x25
#define BSSGP_PDU_FLOW_CONTROL_BVC             0x26
#define BSSGP_PDU_FLOW_CONTROL_BVC_ACK         0x27
#define BSSGP_PDU_FLOW_CONTROL_MS              0x28
#define BSSGP_PDU_FLOW_CONTROL_MS_ACK          0x29
#define BSSGP_PDU_FLUSH_LL                     0x2a
#define BSSGP_PDU_FLUSH_LL_ACK                 0x2b
#define BSSGP_PDU_LLC_DISCARDED                0x2c
#define BSSGP_PDU_FLOW_CONTROL_PFC             0x2d
#define BSSGP_PDU_FLOW_CONTROL_PFC_ACK         0x2e

#define BSSGP_PDU_RESERVED_0X2F                0x2f
#define BSSGP_PDU_RESERVED_0X30                0x30
#define BSSGP_PDU_RESERVED_0X31                0x31
#define BSSGP_PDU_RESERVED_0X32                0x32
#define BSSGP_PDU_RESERVED_0X33                0x33
#define BSSGP_PDU_RESERVED_0X34                0x34
#define BSSGP_PDU_RESERVED_0X35                0x35
#define BSSGP_PDU_RESERVED_0X36                0x36
#define BSSGP_PDU_RESERVED_0X37                0x37
#define BSSGP_PDU_RESERVED_0X38                0x38
#define BSSGP_PDU_RESERVED_0X39                0x39
#define BSSGP_PDU_RESERVED_0X3A                0x3a
#define BSSGP_PDU_RESERVED_0X3B                0x3b
#define BSSGP_PDU_RESERVED_0X3C                0x3c
#define BSSGP_PDU_RESERVED_0X3D                0x3d
#define BSSGP_PDU_RESERVED_0X3E                0x3e
#define BSSGP_PDU_RESERVED_0X3F                0x3f

#define BSSGP_PDU_SGSN_INVOKE_TRACE            0x40
#define BSSGP_PDU_STATUS                       0x41

#define BSSGP_PDU_RESERVED_0X42                0x42
#define BSSGP_PDU_RESERVED_0X43                0x43
#define BSSGP_PDU_RESERVED_0X44                0x44
#define BSSGP_PDU_RESERVED_0X45                0x45
#define BSSGP_PDU_RESERVED_0X46                0x46
#define BSSGP_PDU_RESERVED_0X47                0x47
#define BSSGP_PDU_RESERVED_0X48                0x48
#define BSSGP_PDU_RESERVED_0X49                0x49
#define BSSGP_PDU_RESERVED_0X4A                0x4a
#define BSSGP_PDU_RESERVED_0X4B                0x4b
#define BSSGP_PDU_RESERVED_0X4C                0x4c
#define BSSGP_PDU_RESERVED_0X4D                0x4d
#define BSSGP_PDU_RESERVED_0X4E                0x4e
#define BSSGP_PDU_RESERVED_0X4F                0x4f

#define BSSGP_PDU_DOWNLOAD_BSS_PFC             0x50
#define BSSGP_PDU_CREATE_BSS_PFC               0x51
#define BSSGP_PDU_CREATE_BSS_PFC_ACK           0x52
#define BSSGP_PDU_CREATE_BSS_PFC_NACK          0x53
#define BSSGP_PDU_MODIFY_BSS_PFC               0x54
#define BSSGP_PDU_MODIFY_BSS_PFC_ACK           0x55
#define BSSGP_PDU_DELETE_BSS_PFC               0x56
#define BSSGP_PDU_DELETE_BSS_PFC_ACK           0x57
#define BSSGP_PDU_DELETE_BSS_PFC_REQ           0x58
#define BSSGP_PDU_PS_HANDOVER_REQUIRED         0x59
#define BSSGP_PDU_PS_HANDOVER_REQUIRED_ACK     0x5a
#define BSSGP_PDU_PS_HANDOVER_REQUIRED_NACK    0x5b
#define BSSGP_PDU_PS_HANDOVER_REQUEST          0x5c
#define BSSGP_PDU_PS_HANDOVER_REQUEST_ACK      0x5d
#define BSSGP_PDU_PS_HANDOVER_REQUEST_NACK     0x5e

#define BSSGP_PDU_PERFORM_LOCATION_REQUEST     0x60
#define BSSGP_PDU_PERFORM_LOCATION_RESPONSE    0x61
#define BSSGP_PDU_PERFORM_LOCATION_ABORT       0x62
#define BSSGP_PDU_POSITION_COMMAND             0x63
#define BSSGP_PDU_POSITION_RESPONSE            0x64

#define BSSGP_PDU_RAN_INFORMATION              0x70
#define BSSGP_PDU_RAN_INFORMATION_REQUEST      0x71
#define BSSGP_PDU_RAN_INFORMATION_ACK          0x72
#define BSSGP_PDU_RAN_INFORMATION_ERROR        0x73
#define BSSGP_PDU_RAN_APPLICATION_ERROR        0x74

/*
0x80 MBMS-SESSION-START-REQUEST
0x81 MBMS-SESSION-START-RESPONSE
0x82 MBMS-SESSION-STOP-REQUEST
0x83 MBMS-SESSION-STOP-RESPONSE
0x84 MBMS-SESSION-UPDATE-REQUEST
0x85 MBMS-SESSION-UPDATE-RESPONSE
*/
/*
0x91 PS-HANDOVER-COMPLETE
0x92 PS-HANDOVER-CANCEL
0x93 PS-HANDOVER-COMPLETE-ACK
*/
static const value_string tab_bssgp_pdu_types[] = {
/* 0x00 */  { BSSGP_PDU_DL_UNITDATA,                  "DL-UNITDATA" },
/* 0x01 */  { BSSGP_PDU_UL_UNITDATA,                  "UL-UNITDATA" },
/* 0x02 */  { BSSGP_PDU_RA_CAPABILITY,                "RA-CAPABILITY" },
/* 0x03 */  { BSSGP_PDU_PTM_UNITDATA,                 "PTM-UNITDATA" },
/* 0x04 */  { BSSGP_PDU_DL_MBMS_UNITDATA,             "DL-MBMS-UNITDATA" },
/* 0x05 */  { BSSGP_PDU_UL_MBMS_UNITDATA,             "UL-MBMS-UNITDATA" },
/* 0x06 */  { BSSGP_PDU_PAGING_PS,                    "PAGING-PS" },
/* 0x07 */  { BSSGP_PDU_PAGING_CS,                    "PAGING-CS" },
/* 0x08 */  { BSSGP_PDU_RA_CAPABILITY_UPDATE,         "RA-CAPABILITY-UPDATE" },
/* 0x09 */  { BSSGP_PDU_RA_CAPABILITY_UPDATE_ACK,     "RA-CAPABILITY-UPDATE-ACK" },
/* 0x0a */  { BSSGP_PDU_RADIO_STATUS,                 "RADIO-STATUS" },
/* 0x0b */  { BSSGP_PDU_SUSPEND,                      "SUSPEND" },
/* 0x0c */  { BSSGP_PDU_SUSPEND_ACK,                  "SUSPEND-ACK" },
/* 0x0d */  { BSSGP_PDU_SUSPEND_NACK,                 "SUSPEND-NACK" },
/* 0x0e */  { BSSGP_PDU_RESUME,                       "RESUME" },
/* 0x0f */  { BSSGP_PDU_RESUME_ACK,                   "RESUME-ACK" },
/* 0x10 */  { BSSGP_PDU_RESUME_NACK,                  "RESUME-NACK" },
  /* 0x11 to 0x1f Reserved */
/* 0x20 */  { BSSGP_PDU_BVC_BLOCK,                    "BVC-BLOCK" },
/* 0x21 */  { BSSGP_PDU_BVC_BLOCK_ACK,                "BVC-BLOCK-ACK" },
/* 0x22 */  { BSSGP_PDU_BVC_RESET,                    "BVC-RESET" },
/* 0x23 */  { BSSGP_PDU_BVC_RESET_ACK,                "BVC-RESET-ACK" },
/* 0x24 */  { BSSGP_PDU_BVC_UNBLOCK,                  "UNBLOCK" },
/* 0x25 */  { BSSGP_PDU_BVC_UNBLOCK_ACK,              "UNBLOCK-ACK" },
/* 0x26 */  { BSSGP_PDU_FLOW_CONTROL_BVC,             "FLOW-CONTROL-BVC" },
/* 0x27 */  { BSSGP_PDU_FLOW_CONTROL_BVC_ACK,         "FLOW-CONTROL-BVC-ACK" },
/* 0x28 */  { BSSGP_PDU_FLOW_CONTROL_MS,              "FLOW-CONTROL-MS" },
/* 0x29 */  { BSSGP_PDU_FLOW_CONTROL_MS_ACK,          "FLOW-CONTROL-MS-ACK" },
/* 0x2a */  { BSSGP_PDU_FLUSH_LL,                     "FLUSH-LL" },
/* 0x2b */  { BSSGP_PDU_FLUSH_LL_ACK,                 "FLUSH_LL_ACK" },
/* 0x2c */  { BSSGP_PDU_LLC_DISCARDED,                "LLC-DISCARDED" },
/* 0x2d */  { BSSGP_PDU_FLOW_CONTROL_PFC,             "FLOW-CONTROL-PFC" },
/* 0x2e */  { BSSGP_PDU_FLOW_CONTROL_PFC_ACK,         "FLOW-CONTROL-PFC-ACK" },
  /* 0x2f to 0x3f Reserved */

/* 0x40 */  { BSSGP_PDU_SGSN_INVOKE_TRACE,            "SGSN-INVOKE-TRACE" },
/* 0x41 */  { BSSGP_PDU_STATUS,                       "STATUS" },
  /* 0x42 to 0x4f Reserved */
/* 0x50 */  { BSSGP_PDU_DOWNLOAD_BSS_PFC,             "DOWNLOAD-BSS-PFC" },
/* 0x51 */  { BSSGP_PDU_CREATE_BSS_PFC,               "CREATE-BSS-PFC" },
/* 0x52 */  { BSSGP_PDU_CREATE_BSS_PFC_ACK,           "CREATE-BSS-PFC-ACK" },
/* 0x53 */  { BSSGP_PDU_CREATE_BSS_PFC_NACK,          "CREATE-BSS-PFC-NACK" },
/* 0x54 */  { BSSGP_PDU_MODIFY_BSS_PFC,               "MODIFY-BSS-PFC" },
/* 0x55 */  { BSSGP_PDU_MODIFY_BSS_PFC_ACK,           "MODIFY-BSS-PFC-ACK" },
/* 0x56 */  { BSSGP_PDU_DELETE_BSS_PFC,               "DELETE-BSS-PFC" },
/* 0x57 */  { BSSGP_PDU_DELETE_BSS_PFC_ACK,           "DELETE-BSS-PFC-ACK" },
/* 0x58 */  { BSSGP_PDU_DELETE_BSS_PFC_REQ,           "DELETE-BSS-PFC-REQ" }, 
/* 0x59 */  { BSSGP_PDU_PS_HANDOVER_REQUIRED,          "PS-HANDOVER-REQUIRED" },
/* 0x5a */  { BSSGP_PDU_PS_HANDOVER_REQUIRED_ACK,      "PS-HANDOVER-REQUIRED-ACK" },
/* 0x5b */  { BSSGP_PDU_PS_HANDOVER_REQUIRED_NACK,     "PS-HANDOVER-REQUIRED-NACK" },
/* 0x5c */  { BSSGP_PDU_PS_HANDOVER_REQUEST,           "PS-HANDOVER-REQUEST" },
/* 0x5d */  { BSSGP_PDU_PS_HANDOVER_REQUEST_ACK,       "PS-HANDOVER-REQUEST-ACK" },
/* 0x5e */  { BSSGP_PDU_PS_HANDOVER_REQUEST_NACK,      "PS-HANDOVER-REQUEST-NACK" },

/* 0x60 */  { BSSGP_PDU_PERFORM_LOCATION_REQUEST,     "PERFORM-LOCATION-REQUEST" },
/* 0x61 */  { BSSGP_PDU_PERFORM_LOCATION_RESPONSE,    "PERFORM-LOCATION-RESPONSE" },
/* 0x62 */  { BSSGP_PDU_PERFORM_LOCATION_ABORT,       "PERFORM-LOCATION-ABORT" },
/* 0x63 */  { BSSGP_PDU_POSITION_COMMAND,             "POSITION-COMMAND" },
/* 0x64 */  { BSSGP_PDU_POSITION_RESPONSE,            "POSITION-RESPONSE" },

/* 0x70 */  { BSSGP_PDU_RAN_INFORMATION,              "RAN-INFORMATION" },
/* 0x71 */  { BSSGP_PDU_RAN_INFORMATION_REQUEST,      "RAN-INFORMATION-REQUEST" },
/* 0x72 */  { BSSGP_PDU_RAN_INFORMATION_ACK,          "RAN-INFORMATION-ACK" },
/* 0x73 */  { BSSGP_PDU_RAN_INFORMATION_ERROR,        "RAN-INFORMATION-ERROR" },
/* 0x74 */  { 0x74,                                   "RAN-INFORMATION-APPLICATION-ERROR" },

/* 0x80 */  {0x80,                                   "MBMS-SESSION-START-REQUEST" },
/* 0x81 */  {0x81,                                   "MBMS-SESSION-START-RESPONSE" },
/* 0x82 */  {0x82,                                   "MBMS-SESSION-STOP-REQUEST" },
/* 0x83 */  {0x83,                                   "MBMS-SESSION-STOP-RESPONSE" },
/* 0x84 */  {0x84,                                   "MBMS-SESSION-UPDATE-REQUEST" },
/* 0x85 */  {0x85,                                   "MBMS-SESSION-UPDATE-RESPONSE" },

/* 0x91 */  {0x91,                                   "PS-HANDOVER-COMPLETE" },
/* 0x92 */  {0x92,                                   "PS-HANDOVER-CANCEL" },
/* 0x93 */  {0x93,                                   "PS-HANDOVER-COMPLETE-ACK" },
  { 0,                                NULL },
};

/* Information element coding, v 6.5.0, table 11.3, p 72 */
#define BSSGP_IEI_ALIGNMENT_OCTETS                         0x00
#define BSSGP_IEI_BMAX_DEFAULT_MS                          0x01
#define BSSGP_IEI_BSS_AREA_INDICATION                      0x02
#define BSSGP_IEI_BUCKET_LEAK_RATE                         0x03
#define BSSGP_IEI_BVCI                                     0x04
#define BSSGP_IEI_BVC_BUCKET_SIZE                          0x05
#define BSSGP_IEI_BVC_MEASUREMENT                          0x06
#define BSSGP_IEI_CAUSE                                    0x07
#define BSSGP_IEI_CELL_IDENTIFIER                          0x08
#define BSSGP_IEI_CHANNEL_NEEDED                           0x09
#define BSSGP_IEI_DRX_PARAMETERS                           0x0a
#define BSSGP_IEI_EMLPP_PRIORITY                           0x0b
#define BSSGP_IEI_FLUSH_ACTION                             0x0c
#define BSSGP_IEI_IMSI                                     0x0d
#define BSSGP_IEI_LLC_PDU                                  0x0e
#define BSSGP_IEI_LLC_FRAMES_DISCARDED                     0x0f
#define BSSGP_IEI_LOCATION_AREA                            0x10
#define BSSGP_IEI_MOBILE_ID                                0x11
#define BSSGP_IEI_MS_BUCKET_SIZE                           0x12
#define BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY               0x13
#define BSSGP_IEI_OMC_ID                                   0x14
#define BSSGP_IEI_PDU_IN_ERROR                             0x15
#define BSSGP_IEI_PDU_LIFETIME                             0x16
#define BSSGP_IEI_PRIORITY                                 0x17
#define BSSGP_IEI_QOS_PROFILE                              0x18
#define BSSGP_IEI_RADIO_CAUSE                              0x19
#define BSSGP_IEI_RA_CAP_UPD_CAUSE                         0x1a
#define BSSGP_IEI_ROUTING_AREA                             0x1b
#define BSSGP_IEI_R_DEFAULT_MS                             0x1c
#define BSSGP_IEI_SUSPEND_REFERENCE_NUMBER                 0x1d
#define BSSGP_IEI_TAG                                      0x1e
#define BSSGP_IEI_TLLI                                     0x1f
#define BSSGP_IEI_TMSI                                     0x20
#define BSSGP_IEI_TRACE_REFERENCE                          0x21
#define BSSGP_IEI_TRACE_TYPE                               0x22
#define BSSGP_IEI_TRANSACTION_ID                           0x23
#define BSSGP_IEI_TRIGGER_ID                               0x24
#define BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED                0x25
#define BSSGP_IEI_LSA_IDENTIFIER_LIST                      0x26
#define BSSGP_IEI_LSA_INFORMATION                          0x27
#define BSSGP_IEI_PFI                                      0x28
#define BSSGP_IEI_GPRS_TIMER                               0x29
#define BSSGP_IEI_ABQP                                     0x3a
#define BSSGP_IEI_FEATURE_BITMAP                           0x3b
#define BSSGP_IEI_BUCKET_FULL_RATIO                        0x3c
#define BSSGP_IEI_SERVICE_UTRAN_CCO                        0x3d
#define BSSGP_IEI_NSEI                                     0x3e
#define BSSGP_IEI_RRLP_APDU                                0x3f
#define BSSGP_IEI_LCS_QOS                                  0x40
#define BSSGP_IEI_LCS_CLIENT_TYPE                          0x41
#define BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA            0x42
#define BSSGP_IEI_LOCATION_TYPE                            0x43
#define BSSGP_IEI_LOCATION_ESTIMATE                        0x44
#define BSSGP_IEI_POSITIONING_DATA                         0x45
#define BSSGP_IEI_DECIPHERING_KEYS                         0x46
#define BSSGP_IEI_LCS_PRIORITY                             0x47
#define BSSGP_IEI_LCS_CAUSE                                0x48
#define BSSGP_IEI_LCS_CAPABILITY                           0x49
#define BSSGP_IEI_RRLP_FLAGS                               0x4a
#define BSSGP_IEI_RIM_APPLICATION_IDENTITY                 0x4b
#define BSSGP_IEI_RIM_SEQUENCE_NUMBER                      0x4c
#define BSSGP_IEI_RAN_INFORMATION_REQUEST_APPLICATION_CONTAINER        0x4d
#define BSSGP_IEI_RAN_INFORMATION_APPLICATION_CONTAINER                0x4e
#define BSSGP_IEI_RIM_PDU_INDICATIONS					   0x4f
#define BSSGP_IEI_NUMBER_OF_CONTAINER_UNITS                0x50
#define BSSGP_IEI_PFC_FLOW_CONTROL_PARAMETERS              0x52
#define BSSGP_IEI_GLOBAL_CN_ID                             0x53
#define BSSGP_IEI_RIM_ROUTING_INFORMATION				   0x54
#define BSSGP_IEI_RIM_PROTOCOL_VERSION					   0x55
#define BSSGP_IEI_APPLICATION_ERROR_CONTAINER			   0x56

#define BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT   0x57
#define BSSGP_IEI_RAN_INFORMATION_CONTAINER_UNIT           0x58

#define BSSGP_IEI_RAN_INFORMATION_APPLICATION_ERROR_CONTAINER_UNIT            0x59
#define BSSGP_IEI_RAN_INFORMATION_ACK_RIM_CONTAINER        0x5a
#define BSSGP_IEI_RAN_INFORMATION_ERROR_RIM_CONTAINER      0x5b
/*
ETSI
3GPP TS 48.018 version 6.16.0 Release 6 108 ETSI TS 148 018 V6.16.0 (2006-12)
IEI coding
(hexadecimal)
IEI Types

x5c TMGI
x5d MBMS Session Identity
x5e MBMS Session Duration
x5f MBMS Service Area Identity List
x60 MBMS Response
x61 MBMS Routing Area List
x62 MBMS Session Information
x63 MBMS Stop Cause
x64 Source BSS to Target BSS Transparent Container
x65 Target BSS to Source BSS Transparent Container
x66 NAS container for PS Handover
x67 PFCs to be set-up list
x68 List of set-up PFCs
x69 Extended Feature Bitmap
x6a Source RNC to Target RNC Transparent Container
x6b Target RNC to Source RNC Transparent Container
x6c RNC Identifier
x6d Page Mode
x6e Container ID
x6f Global TFI
x70 IMEI
x71 Time to MBMS Data Transfer
x72 MBMS Session Repetition Number
x73 Inter RAT Handover Info
x74 PS Handover Command
x75 PS Handover Indications
x76 SI/PSI Container
x77 Active PFCs List
x78 Velocity Data
x79 DTM Handover Command
x7a CS Indication
x7b Requested GANSS Assistance Data
x7c GANSS Location Type
x7d GANSS Positioning Data
x7e Flow Control Granularity
x7f eNB Identifier
x80 E-UTRAN Inter RAT Handover Info
x81 Subscriber Profile ID for RAT/Frequency priority
x82 Request for Inter RAT Handover Info
x83 Reliable Inter RAT Handover Info
x84 SON Transfer Application Identity
x85 CSG Identifier
x86 TAC
*/

/* Forward declarations */
static guint16 de_bssgp_source_BSS_to_target_BSS_transp_cont(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_);
static guint16 de_bssgp_target_BSS_to_source_BSS_transp_cont(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_);


static const value_string tab_nacc_cause[]={
  { 0x00,			"Other unspecified error" },
  { 0x01,			"Syntax error in the Application Container" },
  { 0x02,			"Reporting Cell Identifier does not match with the Destination Cell Identifier or with the Source Cell Identifier" },
  { 0x03,			"SI/PSI type error" },
  { 0x04,			"Inconsistent length of a SI/PSI message" },
  { 0x05,			"Inconsistent set of messages" },
  { 0,				NULL },

};
static const value_string tab_bssgp_ie_types[] = {
  { BSSGP_IEI_ALIGNMENT_OCTETS,            "Alignment Octets" },
  { BSSGP_IEI_BMAX_DEFAULT_MS,             "Bmax Default MS" },
  { BSSGP_IEI_BSS_AREA_INDICATION,         "BSS Area Indication" },
  { BSSGP_IEI_BUCKET_LEAK_RATE,            "Bucket Leak Rate" },
  { BSSGP_IEI_BVCI,                        "BVCI" },
  { BSSGP_IEI_BVC_BUCKET_SIZE,             "BVC Bucket Size" },
  { BSSGP_IEI_BVC_MEASUREMENT,             "BVC Measurement" },
  { BSSGP_IEI_CAUSE,                       "Cause" },
  { BSSGP_IEI_CELL_IDENTIFIER,             "Cell Identifier" },
  { BSSGP_IEI_CHANNEL_NEEDED,              "Channel Needed" },
  { BSSGP_IEI_DRX_PARAMETERS,              "DRX Parameters" },
  { BSSGP_IEI_EMLPP_PRIORITY,              "eMLPP Priority" },
  { BSSGP_IEI_FLUSH_ACTION,                "Flush Action" },
  { BSSGP_IEI_IMSI,                        "IMSI" },
  { BSSGP_IEI_LLC_PDU,                     "LLC PDU" },
  { BSSGP_IEI_LLC_FRAMES_DISCARDED,        "LLC Frames Discarded" },
  { BSSGP_IEI_LOCATION_AREA,               "Location Area" },
  { BSSGP_IEI_MOBILE_ID,                   "Mobile Id" },
  { BSSGP_IEI_MS_BUCKET_SIZE,              "MS Bucket Size" },
  { BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY,  "MS Radio Access Capability" },
  { BSSGP_IEI_OMC_ID,                      "OMC Id" },
  { BSSGP_IEI_PDU_IN_ERROR,                "PDU In Error" },
  { BSSGP_IEI_PDU_LIFETIME,                "PDU Lifetime" },
  { BSSGP_IEI_PRIORITY,                    "Priority" },
  { BSSGP_IEI_QOS_PROFILE,                 "QoS Profile" },
  { BSSGP_IEI_RADIO_CAUSE,                 "Radio Cause" },
  { BSSGP_IEI_RA_CAP_UPD_CAUSE,            "RA-Cap-UPD-Cause" },
  { BSSGP_IEI_ROUTING_AREA,                "Routing Area" },
  { BSSGP_IEI_R_DEFAULT_MS,                "R_default_MS" },
  { BSSGP_IEI_SUSPEND_REFERENCE_NUMBER,    "Suspend Reference Number" },
  { BSSGP_IEI_TAG,                         "Tag" },
  { BSSGP_IEI_TLLI,                        "TLLI" },
  { BSSGP_IEI_TMSI,                        "TMSI" },
  { BSSGP_IEI_TRACE_REFERENCE,             "Trace Reference" },
  { BSSGP_IEI_TRACE_TYPE,                  "Trace Type" },
  { BSSGP_IEI_TRANSACTION_ID,              "Transaction Id" },
  { BSSGP_IEI_TRIGGER_ID,                  "Trigger Id" },
  { BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED,   "Number of Octets Affected" },
  { BSSGP_IEI_LSA_IDENTIFIER_LIST,         "LSA Identifier List" },
  { BSSGP_IEI_LSA_INFORMATION,             "LSA Information" },
  { BSSGP_IEI_PFI,                         "Packet Flow Identifier: " },
  { BSSGP_IEI_GPRS_TIMER,                  "GPRS Timer" },
  { BSSGP_IEI_ABQP,                        "ABQP" },
  { BSSGP_IEI_FEATURE_BITMAP,              "Feature Bitmap" },
  { BSSGP_IEI_BUCKET_FULL_RATIO,           "Bucket Full Ratio" },
  { BSSGP_IEI_SERVICE_UTRAN_CCO,           "Service UTRAN CCO" },
  { BSSGP_IEI_NSEI,                        "NSEI" },
  { BSSGP_IEI_RRLP_APDU,                   "RRLP APDU" },
  { BSSGP_IEI_LCS_QOS,                     "LCS QoS" },
  { BSSGP_IEI_LCS_CLIENT_TYPE,             "LCS Client Type" },
  { BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA, "Requested GPS Assistance Data" },
  { BSSGP_IEI_LOCATION_TYPE,               "Location Type" },
  { BSSGP_IEI_LOCATION_ESTIMATE,           "Location Estimate" },
  { BSSGP_IEI_POSITIONING_DATA,            "Positioning Data" },
  { BSSGP_IEI_DECIPHERING_KEYS,            "Deciphering Keys" },
  { BSSGP_IEI_LCS_PRIORITY,                "LCS Priority" },
  { BSSGP_IEI_LCS_CAUSE,                   "LCS Cause" },
  { BSSGP_IEI_LCS_CAPABILITY,              "LCS Capability" },
  { BSSGP_IEI_RRLP_FLAGS,								"RRLP Flags" },
  { BSSGP_IEI_RIM_APPLICATION_IDENTITY,					"RIM Application Identity" },
  { BSSGP_IEI_RAN_INFORMATION_APPLICATION_CONTAINER,	"RAN INFORMATION Application Container" },
  { BSSGP_IEI_RIM_SEQUENCE_NUMBER,						"RIM Sequence Number" },
  { BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT,	"RAN INFORMATION REQUEST RIM Container" },
  { BSSGP_IEI_RAN_INFORMATION_CONTAINER_UNIT,			"RAN INFORMATION RIM Container" },
  { BSSGP_IEI_RIM_PDU_INDICATIONS,						"RIM PDU Indications" },
  { BSSGP_IEI_RIM_PROTOCOL_VERSION,						"RIM Protocol Version Number" },
  { BSSGP_IEI_NUMBER_OF_CONTAINER_UNITS,				"Number of Container Units" },
  { BSSGP_IEI_PFC_FLOW_CONTROL_PARAMETERS,				"PFC Flow Control Parameters" },
  { BSSGP_IEI_GLOBAL_CN_ID,								"Global CN Id" },
  { 0,                                NULL },
};

/* Presence requirements of Information Elements
   48.016 v 5.3.0, chapter 8.1.1, p. 35 */
#define BSSGP_IE_PRESENCE_M 1   /* Mandatory */
#define BSSGP_IE_PRESENCE_C 2   /* Conditional */
#define BSSGP_IE_PRESENCE_O 3   /* Optional */

/* Format options */
#define BSSGP_IE_FORMAT_V 1
#define BSSGP_IE_FORMAT_TV 2
#define BSSGP_IE_FORMAT_TLV 3


static guint8
get_masked_guint8(guint8 value, guint8 mask) {
  const guint8 MASK_BIT_1 = 0x01;
  guint8 i = 0;

  while (!((mask >> i) & MASK_BIT_1)) {
    i++;
    if (i > 7) return 0;
  }
  return (value & mask) >> i;
}

#if 0
static guint16
get_masked_guint16(guint16 value, guint16 mask) {
  const guint16 MASK_BIT_1 = 0x01;
  guint8 i = 0;

  while (!((mask >> i) & MASK_BIT_1)) {
    i++;
    if (i > 15) return 0;
  }
  return (value & mask) >> i;
}
#endif

static gint32
make_mask32(guint8 num_bits, guint8 shift_value) {
  const guint32 LEFT_MOST_1 = 0x80000000;
  int i;
  guint32 mask = LEFT_MOST_1;

  for (i = 0; i < (num_bits - 1); i++) {
    mask = (mask >> 1) | LEFT_MOST_1;
  }
  return mask >> shift_value;
}

static guint32
get_masked_guint32(guint32 value, guint32 mask) {
  const guint16 MASK_BIT_1 = 0x01;
  guint8 i = 0;

  while (!((mask >> i) & MASK_BIT_1)) {
    i++;
    if (i > 31) return 0;
  }
  return (value & mask) >> i;
}

static guint8
tvb_get_masked_guint8(tvbuff_t *tvb, int offset, guint8 mask) {
  guint8 value = tvb_get_guint8(tvb, offset);
  return get_masked_guint8(value, mask);
}

static char*
get_bit_field_label(guint16 value, guint16 value_mask, guint16 num_bits) {
#define MAX_NUM_BITS 16
  guint16 i, bit_mask;
  static char label[MAX_NUM_BITS + 1];

  DISSECTOR_ASSERT(num_bits <= MAX_NUM_BITS);
  for (i = 0; i < num_bits; i++) {
    bit_mask = 1 << i;
    if (value_mask & bit_mask) {
      label[num_bits - 1 - i] = (value & bit_mask) ? '1' : '0';
    }
    else {
      label[num_bits - 1 - i] = '.';
    }
  }
#undef MAX_NUM_BITS
  return label;
}

static char*
get_bit_field_label8(guint8 value, guint8 value_mask) {
  char *bits;
  static char formatted_label[10];
  bits = get_bit_field_label(value, value_mask, 8);
  g_snprintf(formatted_label, 10, "%c%c%c%c %c%c%c%c",
	     bits[0], bits[1], bits[2], bits[3],
	     bits[4], bits[5], bits[6], bits[7]);
  return formatted_label;
}

static char*
get_bit_field_label16(guint16 value, guint16 value_mask) {
  char *bits;
  static char formatted_label[18];
  bits = get_bit_field_label(value, value_mask, 16);
  g_snprintf(formatted_label, 18, "%c%c%c%c%c%c%c%c %c%c%c%c%c%c%c%c",
	     bits[0], bits[1], bits[2], bits[3],
	     bits[4], bits[5], bits[6], bits[7],
	     bits[8], bits[9], bits[10], bits[11],
	     bits[12], bits[13], bits[14], bits[15]);
  return formatted_label;
}

static proto_item *
proto_tree_add_bitfield8(proto_tree *tree, tvbuff_t *tvb, int offset, guint8 mask) {
  /* XXX: Use varargs */
  guint8 value = tvb_get_guint8(tvb, offset);
  char *label = get_bit_field_label8(value, mask);
  proto_item *pi = proto_tree_add_text(tree, tvb, offset, 1, "%s = ",
				       label);
  return pi;
}

#if 0
static proto_item *
proto_tree_add_bitfield16(proto_tree *tree, tvbuff_t *tvb, int offset, guint16 mask) {
  /* XXX: Use varargs */
  guint16 value = tvb_get_ntohs(tvb, offset);
  char *label = get_bit_field_label16(value, mask);
  proto_item *pi = proto_tree_add_text(tree, tvb, offset, 2, "%s = ",
				       label);
  return pi;
}
#endif

static guint8
get_byte_offset(guint32 bo) {
  return (guint8) bo % 8;
}

static guint32
get_end_octet(guint32 bo, guint32 bl)
{
  return (guint32) ceil((bo + bl) / 8.0);
}

static guint32
get_num_octets_spanned(guint32 bo, guint32 bl)
{
  return get_end_octet(bo, bl) - (bo >> 3);
}

static gint16
make_mask(guint8 num_bits, guint8 shift_value) {
  guint16 mask;

  switch (num_bits) {
  case 0: mask = 0x0000; break;
  case 1: mask = 0x8000; break;
  case 2: mask = 0xc000; break;
  case 3: mask = 0xe000; break;
  case 4: mask = 0xf000; break;
  case 5: mask = 0xf800; break;
  case 6: mask = 0xfc00; break;
  case 7: mask = 0xfe00; break;
  case 8: mask = 0xff00; break;
  default: DISSECTOR_ASSERT_NOT_REACHED(); mask = 0; break;
  }
  return mask >> shift_value;
}

static proto_item *
bit_proto_tree_add_text(proto_tree *tree, tvbuff_t *tvb,
			guint32 bo, guint8 bl, const char *value) {
  /* XXX: Use varargs */
  return proto_tree_add_text(tree, tvb, bo >> 3,
			     get_num_octets_spanned(bo, bl), "%s", value);
}

static proto_item *
bit_proto_tree_add_bit_field8(proto_tree *tree, tvbuff_t *tvb,
			      guint32 bo, guint8 bl) {
  /* XXX: Use varargs */
  guint16 mask = make_mask(bl, get_byte_offset(bo));
  guint16 value;
  guint8 end_i;
  int i;
  proto_item *pi;
  char *label;
  if (( mask & 0xff ) == 0 ) value = tvb_get_guint8 ( tvb , bo >> 3) << 8;
  else value = tvb_get_ntohs(tvb, bo >> 3);
  label = get_bit_field_label16(value, mask);

  DISSECTOR_ASSERT(bl < 9);

  if (get_num_octets_spanned(bo, bl) == 1) {
    end_i = 7;
  }
  else {
    end_i = 16;
  }
  pi = bit_proto_tree_add_text(tree, tvb, bo, bl, "");

  for (i = 0; i <=end_i; i++) {
    proto_item_append_text(pi, "%c", label[i]);
  }
  proto_item_append_text(pi, " = ");
  return pi;
}

static const char*
translate_abqp_reliability_class(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed reliability class";
    }
    else {
      return "Reserved";
    }
  case 1:
    return "Unused (Unacknowledged GTP; Acknowledged LLc and RLC, Protected data)";
  case 2:
    return "Unacknowledged GTP; Acknowledged LLc and RLC, Protected data";
  case 3:
    return "Unacknowledged GTP and LLC; Acknowledged RLC, Protected data";
  case 4:
    return "Unacknowledged GTP, LLC, and RLC, Protected data";
  case 5:
    return "Unacknowledged GTP, LLC, and RLC, Unprotedcted data";
  case 7:
    return "Reserved";
  default:
    return "Unacknowledged GTP and LLC; Acknowledged RLC, Protected data";
  }
}
static const char*
translate_abqp_delay_class(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed delay class";
    }
    else {
      return "Reserved";
    }
  case 1: return "Delay class 1";
  case 2: return "Delay class 2";
  case 3: return "Delay class 3";
  case 4: return "Delay class 4 (best effort)";
  case 7: return "Reserved";
  default:
    return "Delay class 4 (best effort)";
  }
}
static const char*
translate_abqp_peak_throughput(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed peak throughput";
    }
    else {
      return "Reserved";
    }
  case 1: return "Up to 1 000 octets/s";
  case 2: return "Up to 2 000 octets/s";
  case 3: return "Up to 4 000 octets/s";
  case 4: return "Up to 8 000 octets/s";
  case 5: return "Up to 16 000 octets/s";
  case 6: return "Up to 32 000 octets/s";
  case 7: return "Up to 64 000 octets/s";
  case 8: return "Up to 128 000 octets/s";
  case 9: return "Up to 256 000 octets/s";
  case 15: return "Reserved";
  default:
    return "Up to 1 000 octets/s";
  }
}
static const char*
translate_abqp_precedence_class(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed precedence";
    }
    else {
      return "Reserved";
    }
  case 1: return "High priority";
  case 2: return "Normal priority";
  case 3: return "Low priority";
  case 7: return "Reserved";
  default:
    return "Normal priority";
  }
}
static const char*
translate_abqp_mean_throughput(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed mean throughput";
    }
    else {
      return "Reserved";
    }
  case 1: return "100 octets/h";
  case 2: return "200 octets/h";
  case 3: return "500 octets/h";
  case 4: return "1 000 octets/h";
  case 5: return "2 000 octets/h";
  case 6: return "5 000 octets/h";
  case 7: return "10 000 octets/h";
  case 8: return "20 000 octets/h";
  case 9: return "50 000 octets/h";
  case 0x0a: return "100 000 octets/h";
  case 0x0b: return "200 000 octets/h";
  case 0x0c: return "500 000 octets/h";
  case 0x0d: return "1 000 000 octets/h";
  case 0x0e: return "2 000 000 octets/h";
  case 0x0f: return "5 000 000 octets/h";
  case 0x10: return "10 000 000 octets/h";
  case 0x11: return "20 000 000 octets/h";
  case 0x12: return "50 000 000 octets/h";
  case 0x1e: return "Reserved";
  case 0x1f: return "Best effort";
  default:
    return "Best effort";
  }
}
static const char*
translate_abqp_traffic_class(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed traffic class";
    }
    else {
      return "Reserved";
    }
  case 1: return "Conversational class";
  case 2: return "Streaming class";
  case 3: return "Interactive class";
  case 4: return "Background class";
  case 7: return "Reserved";
  default:
    if (bi->ul_data) {
      /* The MS shall consider all other values as reserved */
      return "Reserved";
    }
    else {
      /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
      return "Error";
    }
  }
}
static const char*
translate_abqp_delivery_order(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed delivery order";
    }
    else {
      return "Reserved";
    }
  case 1: return "With delivery order ('yes')";
  case 2: return "Without delivery order ('no')";
  case 3: return "Reserved";
  default:
    return "Error in BSSGP dissector";
  }
}
static const char*
translate_abqp_delivery_of_erroneous_sdu(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed delivery of erroneous SDUs";
    }
    else {
      return "Reserved";
    }
  case 1: return "No detect ('-')";
  case 2: return "Erroneous SDUs are delivered ('yes')";
  case 3: return "Erroneous SDUs are not delivered ('no')";
  case 7: return "Reserved";
  default:
    if (bi->ul_data) {
      /* The MS shall consider all other values as reserved */
      return "Reserved";
    }
    else {
      /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
      return "Error";
    }
  }
}
static const char*
translate_abqp_max_sdu_size(guint8 value, build_info_t *bi) {
  static char result[BSSGP_TRANSLATION_MAX_LEN];

  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed maximum SDU size";
    }
    else {
      return "Reserved";
    }
  case 0xff:
    if (bi->ul_data) {
      return "Reserved";
    }
    else {
      return "Reserved";
    }
  case 0x97: return "1502 octets";
  case 0x98: return "1510 octets";
  case 0x99: return "1520 octets";
  }
  if ((value >= 1) && (value <= 0x96)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u octets", value * 10);
    return result;
  }
  if (bi->ul_data) {
    /* The MS shall consider all other values as reserved */
    return "Reserved";
  }
  else {
    /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
    return "Error";
  }
}

static const char*
translate_abqp_max_bit_rate_for_ul(guint8 value, build_info_t *bi) {
  static char result[BSSGP_TRANSLATION_MAX_LEN];

  if (value == 0) {
    if (bi->ul_data) {
      return "Subscribed maximum bit rate for uplink";
    }
    else {
      return "Reserved";
    }
  }
  if ((value >= 1) && (value <= 0x3f)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u kbps", value);
    return result;
  }
  if ((value >= 0x40) && (value <= 0x7f)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u kbps", 64 + (value - 0x40) * 8);
    return result;
  }
  if ((value >= 0x80) && (value <= 0xfe)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u kbps", 576 + (value - 0x80) * 64);
    return result;
  }
  return "0 kbps";
}

static const char*
translate_abqp_max_bit_rate_for_dl(guint8 value, build_info_t *bi) {
  return translate_abqp_max_bit_rate_for_ul(value, bi);
}

static const char*
translate_abqp_residual_ber(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed residual BER";
    }
    else {
      return "Reserved";
    }
  case 1: return "5*10^-2";
  case 2: return "1*10^-2";
  case 3: return "5*10^-3";
  case 4: return "4*10^-3";
  case 5: return "1*10^-3";
  case 6: return "1*10^-4";
  case 7: return "1*10^-5";
  case 8: return "1*10^-6";
  case 9: return "6*10^-8";
  case 15: return "Reserved";
  }
  if (bi->ul_data) {
    /* The MS shall consider all other values as reserved */
    return "Reserved";
  }
  else {
    /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
    return "Error";
  }
}

static const char*
translate_abqp_sdu_error_ratio(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed SDU error ratio";
    }
    else {
      return "Reserved";
    }
  case 1: return "1*10^-2";
  case 2: return "7*10^-3";
  case 3: return "1*10^-3";
  case 4: return "1*10^-4";
  case 5: return "1*10^-5";
  case 6: return "1*10^-6";
  case 7: return "1*10^-1";
  case 15: return "Reserved";
  }
  if (bi->ul_data) {
    /* The MS shall consider all other values as reserved */
    return "Reserved";
  }
  else {
    /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
    return "";
  }
}

static const char*
translate_abqp_transfer_delay(guint8 value, build_info_t *bi) {
  static char result[BSSGP_TRANSLATION_MAX_LEN];

  if (value == 0) {
    if (bi->ul_data) {
      return "Subscribed transfer delay";
    }
    else {
      return "Reserved";
    }
  }
  if ((value >= 1) && (value <= 0x0f)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u ms", value * 10);
    return result;
  }
  if ((value >= 0x10) && (value <= 0x1f)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u ms", 200 + (value - 0x10) * 50);
    return result;
  }
  if ((value >= 0x20) && (value <= 0x3e)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u ms", 1000 + (value - 0x20) * 100);
    return result;
  }
  return "Reserved";
}

static const char*
translate_abqp_traffic_handling_priority(guint8 value, build_info_t *bi) {
  switch (value) {
  case 0:
    if (bi->ul_data) {
      return "Subscribed traffic handling_priority";
    }
    else {
      return "Reserved";
    }
  case 1: return "Priority level 1";
  case 2: return "Priority level 2";
  case 3: return "Priority level 3";
  default: return "";
  }
}

static const char*
translate_abqp_guaranteed_bit_rate_for_ul(guint8 value, build_info_t *bi) {
  return translate_abqp_max_bit_rate_for_ul(value, bi);
}
static const char*
translate_abqp_guaranteed_bit_rate_for_dl(guint8 value, build_info_t *bi) {
  return translate_abqp_max_bit_rate_for_ul(value, bi);
}

static const char*
translate_abqp_source_statistics_descriptor(guint8 value, build_info_t *bi) {
  if (bi->ul_data) {
    switch (value) {
    case 0: return "Unknown";
    case 1: return "Speech";
    default: return "Unknown";
    }
  }
  else {
    return "Spare";
  }
}

static const char*
translate_abqp_max_bit_rate_for_dl_extended(guint8 value, build_info_t *bi _U_) {
  static char result[BSSGP_TRANSLATION_MAX_LEN];

  if (value == 0) {
    return "Use the value indicated by the Maximum bit rate for downlink";
  }
  if ((value >= 1) && (value <= 0x4a)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u kbps", 8600 + value * 100);
    return result;
  }
  /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
  return "";
}

static const char*
translate_abqp_guaranteed_bit_rate_for_dl_extended(guint8 value, build_info_t *bi _U_) {
  static char result[BSSGP_TRANSLATION_MAX_LEN];

  if (value == 0) {
    return "Use the value indicated by the Guaranteed bit rate for downlink";
  }
  if ((value >= 1) && (value <= 0x4a)) {
    g_snprintf(result, BSSGP_TRANSLATION_MAX_LEN, "%u kbps", 8600 + value * 100);
    return result;
  }
  /* The network shall map all other values not explicitly defined onto one of the values defined in this version of the protocol. The network shall return a negotiated value which is explicitly defined in this version of the protocol */
  return "";
}

static const char*
translate_msrac_access_technology_type(guint8 value) {
  static const value_string tab_values[] = {
    { 0, "GSM P" },
    { 1, "GSM E" },
    { 2, "GSM R" },
    { 3, "GSM 1800" },
    { 4, "GSM 1900" },
    { 5, "GSM 450" },
    { 6, "GSM 480" },
    { 7, "GSM 850" },
    { 8, "GSM 700" },
    { 9, "GSM T 380" },
    { 10, "GSM T 410" },
    { 11, "GSM T 900" },
    { 15, "List of Additional Access Technologies present" },
    { 0, NULL },
    /* Otherwise "Unknown" */
  };
  return val_to_str(value, tab_values, "Unknown");
}

static const char*
translate_msrac_dtm_gprs_multislot_class(guint8 value) {
  static const value_string tab_values[] = {
    { 0, "Unused, interpreted as \"Multislot class 5 supported\"" },
    { 1, "Multislot class 5 supported" },
    { 2, "Multislot class 9 supported" },
    { 3, "Multislot class 11 supported" },
    { 0, NULL },
    /* No other combinations*/
  };
  return val_to_str(value, tab_values, "");
}

static const char*
translate_msrac_extended_dtm_gprs_multislot_class(guint8 value, guint8 dgmsc) {
  switch (dgmsc) {
  case 0: return "Unused, interpreted as Multislot class 5 supported";
  case 1:
    switch (value) {
    case 0: return "Multislot class 5 supported";
    case 1: return "Multislot class 6 supported";
    case 2:
    case 3:
      return "Unused, interpreted as Multislot class 5 supported";
    }
  case 2:
    switch (value) {
    case 0: return "Multislot class 9 supported";
    case 1: return "Multislot class 10 supported";
    case 2:
    case 3:
      return "Unused, interpreted as Multislot class 5 supported";
    }
  case 3:
    switch (value) {
    case 0: return "Multislot class 11 supported";
    case 1:
    case 2:
    case 3:
      return "Unused, interpreted as Multislot class 5 supported";
    }
  }
  DISSECTOR_ASSERT_NOT_REACHED();
  return "Error"; /* Dummy */
}

#if 0
static guint8
translate_msrac_high_multislot_capability(guint8 capability, guint8 class) {
  switch (capability) {
  case 0:
    switch (class) {
    case 8:
      return 30;
    case 10:
    case 23:
    case 28:
    case 29:
      return 39;
    case 11:
    case 20:
    case 25:
      return 32;
    case 12:
    case 21:
    case 22:
    case 26:
    case 27:
      return 33;
    default:
      return class;
    }
  case 1:
    switch (class) {
    case 8:
      return 35;
    case 10:
    case 19:
    case 24:
      return 36;
    case 11:
    case 23:
    case 28:
    case 29:
      return 45;
    case 12:
    case 21:
    case 22:
    case 26:
    case 27:
      return 38;
    default:
      return class;
    }
  case 2:
    switch (class) {
    case 8:
      return 40;
    case 10:
    case 19:
    case 24:
      return 41;
    case 11:
    case 20:
    case 25:
      return 42;
    case 12:
    case 23:
    case 28:
    case 29:
      return 44;
    default:
      return class;
    }
  case 3:
    switch (class) {
    case 12:
    case 21:
    case 22:
    case 26:
    case 27:
      return 43;
    case 11:
    case 20:
    case 25:
      return 37;
    case 10:
    case 19:
    case 24:
      return 31;
    case 9:
    case 23:
    case 28:
    case 29:
      return 34;
    default:
      return class;
    }
  }
  DISSECTOR_ASSERT_NOT_REACHED();
  return 0;
}
#endif

static const char*
translate_channel_needed(guint8 value) {
  switch (value) {
  case 0: return "Any channel";
  case 1: return "SDCCH";
  case 2: return "TCH/F (Full rate)";
  case 3: return "TCH/H or TCH/F (Dual rate)";
  }
  DISSECTOR_ASSERT_NOT_REACHED();
  return NULL;
}

static proto_item*
bssgp_proto_tree_add_ie(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const char *iename;

  iename = ie->name;
  if (iename == NULL)
    iename = val_to_str(ie->iei, tab_bssgp_ie_types, "Unknown");
  return proto_tree_add_uint_format(bi->bssgp_tree, hf_bssgp_ie_type,
				  bi->tvb, ie_start_offset, 1,
				  ie->iei, "%s", iename);
}

static void
bssgp_proto_handoff(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset, dissector_handle_t handle) {
  tvbuff_t *next_tvb=NULL;

  if(ie->value_length > 0)
    next_tvb = tvb_new_subset_remaining(bi->tvb, bi->offset);

  if (bi->bssgp_tree) {
    bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  }
  if(next_tvb){
    if (handle) {
      call_dissector(handle, next_tvb, bi->pinfo, bi->parent_tree);
    }
    else if (data_handle) {
      call_dissector(data_handle, next_tvb, bi->pinfo, bi->parent_tree);
    }
  }
}

static void
decode_nri(proto_tree *tf, build_info_t *bi, guint32 tmsi_tlli) {
  proto_item *hidden_item;
  const guint32 LOCAL_TLLI_MASK = 0xc0000000;
  const guint32 FOREIGN_TLLI_MASK = 0x80000000;
  guint16 nri;

  if (bssgp_decode_nri && (bssgp_nri_length != 0) &&
      (((tmsi_tlli & LOCAL_TLLI_MASK) == LOCAL_TLLI_MASK) ||
       ((tmsi_tlli & FOREIGN_TLLI_MASK) == FOREIGN_TLLI_MASK))) {
    nri = get_masked_guint32(tmsi_tlli, make_mask32( (guint8) bssgp_nri_length, 8));
    if (tf) {
      hidden_item = proto_tree_add_uint(tf, hf_bssgp_nri, bi->tvb, bi->offset, 4, nri);
      PROTO_ITEM_SET_HIDDEN(hidden_item);
    }
    col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP, "NRI %u", nri);
  }
}

static void
decode_mobile_identity(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
#define MAX_NUM_IMSI_DIGITS 15
  const guint8 MASK_ODD_EVEN_INDICATION = 0x08;
  const guint8 MASK_TYPE_OF_IDENTITY = 0x07;
  const guint8 ODD = 1;
  proto_item *ti = NULL, *pi;
  proto_tree *tf = NULL;
  guint8 data, odd_even, type, num_digits, i;
  int hf_id;
  guint32 tmsi;
  guint8 digits[MAX_NUM_IMSI_DIGITS];
  char digits_str[MAX_NUM_IMSI_DIGITS + 1];

  static const value_string tab_type_of_identity[] = {
    { BSSGP_MOBILE_IDENTITY_TYPE_IMSI, "IMSI" },
    { BSSGP_MOBILE_IDENTITY_TYPE_IMEI, "IMEI" },
    { BSSGP_MOBILE_IDENTITY_TYPE_IMEISV, "IMEISV" },
    { BSSGP_MOBILE_IDENTITY_TYPE_TMSI_PTMSI, "TMSI//P-TMSI" },
    { BSSGP_MOBILE_IDENTITY_TYPE_NO_IDENTITY, "No identity" },
    { 0, NULL },
    /* Otherwise "Reserved" */
  };

  digits_str[0] = '\0'; /* conceivably num_digits below could be zero */

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    tf = proto_item_add_subtree(ti, ett_bssgp_mobile_identity);
  }
  data = tvb_get_guint8(bi->tvb, bi->offset);
  odd_even = get_masked_guint8(data, MASK_ODD_EVEN_INDICATION);

  if (bi->bssgp_tree) {
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				  MASK_ODD_EVEN_INDICATION);
    proto_item_append_text(pi, "Odd/Even Indication: %s number of identity digits%s",
			odd_even == ODD ? "Odd" : "Even",
			odd_even == ODD ? "" : " and also when the TMSI/P_TMSI is used");
  }
  type = get_masked_guint8(data, MASK_TYPE_OF_IDENTITY);

  if (bi->bssgp_tree) {
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				  MASK_TYPE_OF_IDENTITY);
    proto_item_append_text(pi, "Type of Identity: %s",
			   val_to_str(type, tab_type_of_identity,
				      "Reserved"));
  }
  bi->offset++;
  switch (type) {
  case BSSGP_MOBILE_IDENTITY_TYPE_IMSI:
  case BSSGP_MOBILE_IDENTITY_TYPE_IMEI:
  case BSSGP_MOBILE_IDENTITY_TYPE_IMEISV:
    num_digits = 1 + (ie->value_length - 1) * 2;
    if (odd_even != ODD ) num_digits--;
    if (num_digits > MAX_NUM_IMSI_DIGITS) THROW(ReportedBoundsError);

    i = 0;
    digits[i] = get_masked_guint8(data, BSSGP_MASK_LEFT_OCTET_HALF);

    i++;
    while (TRUE) {
      data = tvb_get_guint8(bi->tvb, bi->offset);

      digits[i] = get_masked_guint8(data, BSSGP_MASK_RIGHT_OCTET_HALF);
      i++;
      if (i >= num_digits) break;

      digits[i] = get_masked_guint8(data, BSSGP_MASK_LEFT_OCTET_HALF);
      i++;
      if (i >= num_digits) break;
      bi->offset++;
    }
    bi->offset++;

    if (bi->bssgp_tree) {
      proto_item_append_text(ti, ": ");
      for (i = 0; i < num_digits; i++) {
	proto_item_append_text(ti, "%u", digits[i]);
	g_snprintf(&digits_str[i], 2, "%u", digits[i]);
      }
      switch (type) {
      case BSSGP_MOBILE_IDENTITY_TYPE_IMSI:
        hf_id = hf_bssgp_imsi;
        break;
      case BSSGP_MOBILE_IDENTITY_TYPE_IMEI:
        hf_id = hf_bssgp_imei;
        break;
      case BSSGP_MOBILE_IDENTITY_TYPE_IMEISV:
        hf_id = hf_bssgp_imeisv;
        break;
      default:
        DISSECTOR_ASSERT_NOT_REACHED();
        hf_id = -1;
        break;
      }
      if (tf)
        proto_tree_add_string(tf, hf_id, bi->tvb, ie_start_offset + 2, ((num_digits/2)+1), digits_str);

    }
    col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP, "%s %s",
			  val_to_str(type, tab_type_of_identity,
				     "Mobile identity unknown"),
			  digits_str);
    break;
  case BSSGP_MOBILE_IDENTITY_TYPE_TMSI_PTMSI:
    tmsi = tvb_get_ntohl(bi->tvb, bi->offset);
    col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP,
			  "TMSI/P-TMSI %0x04x", tmsi);
    if (bi->bssgp_tree) {
      proto_tree_add_item(tf, hf_bssgp_tmsi_ptmsi, bi->tvb, bi->offset, 4,
			  ENC_BIG_ENDIAN);
      proto_item_append_text(ti, ": %#04x", tmsi);
    }
    decode_nri(tf, bi, tmsi);
    bi->offset += 4;
    break;
  default:
    ;
  }
#undef MAX_NUM_IMSI_DIGITS
}

static char*
decode_mcc_mnc(build_info_t *bi, proto_tree *parent_tree) {
#define RES_LEN 15
  const guint8 UNUSED_MNC3 = 0x0f;
  guint8 mcc1, mcc2, mcc3, mnc1, mnc2, mnc3, data;
  guint16 start_offset, mcc, mnc;
  static char mcc_mnc[RES_LEN];

  start_offset = bi->offset;


  data = tvb_get_guint8(bi->tvb, bi->offset);
  mcc2 = get_masked_guint8(data, BSSGP_MASK_LEFT_OCTET_HALF);
  mcc1 = get_masked_guint8(data, BSSGP_MASK_RIGHT_OCTET_HALF);
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  mnc3 = get_masked_guint8(data, BSSGP_MASK_LEFT_OCTET_HALF);
  mcc3 = get_masked_guint8(data, BSSGP_MASK_RIGHT_OCTET_HALF);
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  mnc2 = get_masked_guint8(data, BSSGP_MASK_LEFT_OCTET_HALF);
  mnc1 = get_masked_guint8(data, BSSGP_MASK_RIGHT_OCTET_HALF);
  bi->offset++;

  /* XXX: If mxci out of range the ms should transmit the values using full hexademical encoding? */

  /* XXX: Interpretation of mcci? */
  mcc = 100 * mcc1 + 10 * mcc2 + mcc3;

  /* XXX: Interpretation of mnci? */
  mnc = 10 * mnc1 + mnc2;

  if (mnc3 != UNUSED_MNC3) {
    mnc += 10 * mnc + mnc3;
  }

  proto_tree_add_uint(parent_tree, hf_bssgp_mcc,
			     bi->tvb, start_offset, 3, mcc);
  proto_tree_add_uint(parent_tree, hf_bssgp_mnc,
			     bi->tvb, start_offset, 3, mnc);

  if (mnc3 != UNUSED_MNC3) {
    /* Three digits mnc */
    g_snprintf(mcc_mnc, RES_LEN, "%u-%03u", mcc, mnc);
  }
  else {
    /* Two digits mnc */
    g_snprintf(mcc_mnc, RES_LEN, "%u-%02u", mcc, mnc);
  }
#undef RES_LEN
  return mcc_mnc;
}

static char*
decode_lai(build_info_t *bi, proto_tree *parent_tree) {
#define RES_LEN 15
  guint16 lac;
  char *mcc_mnc;
  static char lai[RES_LEN];

  mcc_mnc = decode_mcc_mnc(bi, parent_tree);

  lac = tvb_get_ntohs(bi->tvb, bi->offset);
  proto_tree_add_item(parent_tree, hf_bssgp_lac,
		      bi->tvb, bi->offset, 2, ENC_BIG_ENDIAN);
  bi->offset += 2;

  g_snprintf(lai, RES_LEN, "%s-%u", mcc_mnc, lac);
#undef RES_LEN
  return lai;
}

static char*
decode_rai(build_info_t *bi, proto_tree *parent_tree) {
#define RES_LEN 20
  guint8 rac;
  static char rai[RES_LEN];
  char *lai = decode_lai(bi, parent_tree);

  rac = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_item(parent_tree, hf_bssgp_rac, bi->tvb, bi->offset, 1, ENC_BIG_ENDIAN);
  bi->offset++;

  g_snprintf(rai, RES_LEN, "%s-%u", lai, rac);
#undef RES_LEN
  return rai;
}

static char*
decode_rai_ci(build_info_t *bi, proto_tree *parent_tree) {
#define RES_LEN 30
  char *rai;
  static char rai_ci[RES_LEN];
  guint16 ci;

  rai = decode_rai(bi, parent_tree);

  ci = tvb_get_ntohs(bi->tvb, bi->offset);
  proto_tree_add_item(parent_tree, hf_bssgp_ci,
		      bi->tvb, bi->offset, 2, ENC_BIG_ENDIAN);
  bi->offset += 2;
  g_snprintf(rai_ci, RES_LEN, "RAI %s, CI %u", rai, ci);
#undef RES_LEN
  return rai_ci;
}

static void
bssgp_pi_append_queuing_delay(proto_item *pi, tvbuff_t *tvb, int offset) {
  const guint16 INFINITE_DELAY = 0xffff;
  guint16 value = tvb_get_ntohs(tvb, offset);
  if (value == INFINITE_DELAY) {
    proto_item_append_text(pi, ": Infinite delay (%#4x)", value);
  }
  else {
    proto_item_append_text(pi, ": %u centi-seconds delay", value);
  }
}

static void
bssgp_pi_append_bucket_leak_rate(proto_item *pi, tvbuff_t *tvb, int offset) {
  guint16 value = tvb_get_ntohs(tvb, offset);
  proto_item_append_text(pi, ": %u bits", value * 100);
}

static void
bssgp_pi_append_bucket_size(proto_item *pi, tvbuff_t *tvb, int offset) {
  guint16 value = tvb_get_ntohs(tvb, offset);
  proto_item_append_text(pi, ": %u bytes", value * 100);
}

static void
bssgp_pi_append_bucket_full_ratio(proto_item *pi, tvbuff_t *tvb, int offset) {
  guint8 value = tvb_get_guint8(tvb, offset);
  proto_item_append_text(pi, ": %.2f * Bmax ", value / 100.0);
}

static void
bssgp_pi_append_pfi(proto_item *pi, tvbuff_t *tvb, int offset) {
  const guint8 MASK_PFI = 0x7f;
  guint8 value;

  static const value_string tab_pfi[] = {
    { 0, "Best effort" },
    { 1, "Signaling" },
    { 2, "SMS" },
    { 3, "TOMB" },
    { 4, "Reserved" },
    { 5, "Reserved" },
    { 6, "Reserved" },
    { 7, "Reserved" },
    { 0, NULL },
    /* Otherwise "Dynamically assigned (PFI: <value>)" */
  };
  value = tvb_get_masked_guint8(tvb, offset, MASK_PFI);
  proto_item_append_text(pi,
		  "%s", val_to_str(value, tab_pfi, "Dynamically assigned (PFI: %d)"));
}

static void
decode_pfi(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    bssgp_pi_append_pfi(ti, bi->tvb, bi->offset);
  }
  bi->offset += ie->value_length;
}

static void
decode_queuing_delay(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    bssgp_pi_append_queuing_delay(ti, bi->tvb, bi->offset);
  }
  bi->offset += ie->value_length;
}

static void
decode_bucket_size(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    bssgp_pi_append_bucket_size(ti, bi->tvb, bi->offset);
  }
  bi->offset += ie->value_length;
}

static void
decode_bucket_leak_rate(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    bssgp_pi_append_bucket_leak_rate(ti, bi->tvb, bi->offset);
  }
  bi->offset += ie->value_length;
}

static void
get_value_length(bssgp_ie_t *ie, build_info_t *bi) {
  /* length indicator in bit 8, 0 => two bytes, 1 => one byte */
  const guint8 MASK_LENGTH_INDICATOR = 0x80;
  const guint8 MASK_ONE_BYTE_LENGTH = 0x7f;
  guint8 length_len;
  guint16 length;

  length = tvb_get_guint8(bi->tvb, bi->offset);
  length_len = 1;

  if (length & MASK_LENGTH_INDICATOR) {
    length &= MASK_ONE_BYTE_LENGTH;
  }
  else {
    length_len++;
    length <<= 8;
    length |= tvb_get_guint8(bi->tvb, bi->offset+1);
  }
  ie->value_length = length;
  ie->total_length += length_len + length;
  bi->offset += length_len;
}

static void
decode_simple_ie(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset,
		 const char *pre_str, const char *post_str,
		 gboolean show_as_dec) {
  /* XXX: Allow mask? */
  proto_item *ti;
  guint32 value;

  switch (ie->value_length) {
  case 1: value = tvb_get_guint8(bi->tvb, bi->offset); break;
  case 2: value = tvb_get_ntohs(bi->tvb, bi->offset); break;
  case 3: value = tvb_get_ntoh24(bi->tvb, bi->offset); break;
  case 4: value = tvb_get_ntohl(bi->tvb, bi->offset); break;
  default: value = 0; break;
  }

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);

    proto_item_append_text(ti, ": ");

    if (pre_str) {
      proto_item_append_text(ti, "%s ", pre_str);
    }
    if (show_as_dec) {
      proto_item_append_text(ti, "%u", value);
    }
    else {
      switch (ie->value_length) {
      case 1: proto_item_append_text(ti, "%#1x", value); break;
      case 2: proto_item_append_text(ti, "%#2x", value); break;
      case 3: proto_item_append_text(ti, "%#3x", value); break;
      case 4: proto_item_append_text(ti, "%#4x", value); break;
      default: ;
      }
    }
    proto_item_append_text(ti, " %s", post_str);
  }
  bi->offset += ie->value_length;
}

static int
check_correct_iei(bssgp_ie_t *ie, build_info_t *bi) {
  guint8 fetched_iei = tvb_get_guint8(bi->tvb, bi->offset);

#ifdef BSSGP_DEBUG
  if (fetched_iei != ie->iei) {
    proto_tree_add_text(bi->bssgp_tree, bi->tvb, bi->offset, 1,
			"Tried IEI %s (%#02x), found IEI %s (%#02x)",
			val_to_str(ie->iei, tab_bssgp_ie_types, "Unknown"),
			ie->iei,
			val_to_str(fetched_iei, tab_bssgp_ie_types, "Unknown"),
			fetched_iei);
  }
#endif
  return (fetched_iei == ie->iei);
}

static void
decode_iei_alignment_octets(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, " (%u bytes)", ie->value_length);
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_bvci(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti, *hidden_item;
  guint16 bvci;

  bvci = tvb_get_ntohs(bi->tvb, bi->offset);

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %u", bvci);
    hidden_item = proto_tree_add_item(bi->bssgp_tree, hf_bssgp_bvci,
			       bi->tvb, bi->offset, 2,
			       ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
  }
  bi->offset += ie->value_length;

  col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP,
			"BVCI %u", bvci);
}

const value_string tab_cause[] = {
  { 0x00, "Processor overload" },
  { 0x01, "Equipment failure" },
  { 0x02, "Transit network service failure" },
  { 0x03, "Network service transmission capacity modified from zero kbps to greater than zero kbps" },
  { 0x04, "Unknown MS" },
  { 0x05, "BVCI unknown" },
  { 0x06, "Cell traffic congestion" },
  { 0x07, "SGSN congestion" },
  { 0x08, "O&M intervention" },
  { 0x09, "BVCI blocked" },
  { 0x0a, "PFC create failure" },
  { 0x0b, "PFC preempted" },
  { 0x0c, "ABQP no more supported" },
  { 0x20, "Semantically incorrect PDU" },
  { 0x21, "Invalid mandatory information" },
  { 0x22, "Missing mandatory IE" },
  { 0x23, "Missing conditional IE" },
  { 0x24, "Unexpected conditional IE" },
  { 0x25, "Conditional IE error" },
  { 0x26, "PDU not compatible with the protocol state" },
  { 0x27, "Protocol error - unspecified" },
  { 0x28, "PDU not compatible with the feature set" },
  { 0x29, "Requested information not available" },
  { 0x2a, "Unknown destination address" },
  { 0x2b, "Unknown RIM application identity" },
  { 0x2c, "Invalid container unit information" },
  { 0x2d, "PFC queuing" },
  { 0x2e, "PFC created successfully" },
  { 0x2f, "T12 expiry" },
  { 0x30, "MS under PS Handover treatment" },
  { 0x31, "Uplink quality" },
  { 0x32, "Uplink strength" },
  { 0x33, "Downlink quality" },
  { 0x34, "Downlink strength" },
  { 0x35, "Distance" },
  { 0x36, "Better cell" },
  { 0x37, "Traffic" },
  { 0x38, "Radio contact lost with MS" },
  { 0x39, "MS back on old channel" },
  { 0x3a, "T13 expiry" },
  { 0x3b, "T14 expiry" },
  { 0x3c, "Not all requested PFCs created" },
  { 0x3d, "CS cause" },
  { 0x3e, "Requested ciphering and/or integrity protection algorithms not supported" },
  { 0x3f, "Relocation failure in target system" },
  { 0x40, "Directed Retry" },
  { 0x41, "Time critical relocation" },
  { 0x42, "PS Handover Target not allowed" },
  { 0x43, "PS Handover not Supported in Target BSS or Target System" },
  { 0x44, "Incoming relocation not supported due to PUESBINE feature" },
  { 0,    NULL },
};
/*
 * 11.3.8 Cause
 */
static void
decode_iei_cause(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;


  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_item_append_text(ti, ": %s (%#02x)",
			   val_to_str(value, tab_cause,
				      "Protocol error - unspecified"),
			   value);
  }
  bi->offset += ie->value_length;
}

/*
 * 11.3.9 Cell Identifier 3GPP TS 48.018 version 6.7.0 Release 6
 */
static void
decode_iei_cell_identifier(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  char *rai_ci;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    tf = proto_item_add_subtree(ti, ett_bssgp_cell_identifier);

    rai_ci = decode_rai_ci(bi, tf);
    proto_item_append_text(ti, ": %s", rai_ci);

  } else {
    bi->offset += ie->value_length;
  }

}

/*
 * 11.3.10 Channel needed
 */
static void
decode_iei_channel_needed(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /* XXX: 'If this IE is used for only one MS, the the first CHANNEL field
     is used and the second CHANNEL field is spare.' How know? */
  const guint8 MASK_CH1 = 0x03;
  const guint8 MASK_CH2 = 0x0c;
  proto_item *ti;
  guint8 data, ch1, ch2;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    data = tvb_get_guint8(bi->tvb, bi->offset);
    ch1 = get_masked_guint8(data, MASK_CH1);
    ch2 = get_masked_guint8(data, MASK_CH2);
    proto_item_append_text(ti, ": Ch1: %s (%u), Ch2: %s (%u)",
			   translate_channel_needed(ch1),
			   ch1,
			   translate_channel_needed(ch2),
			   ch2);
  }
  bi->offset += ie->value_length;
}
/*
 * 11.3.11 DRX Parameters
 */
static void
decode_iei_drx_parameters(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_CYCLE_LENGTH_COEFFICIENT = 0xf0;
  const guint8 MASK_SPLIT_ON_CCCH = 0x08;
  const guint8 MASK_NON_DRX_TIMER = 0x07;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;
  guint16 cycle_value;

  static const value_string tab_non_drx_timer[] = {
    { 0, "No non-DRX mode after transfer state" },
    { 1, "Max. 1 sec non-DRX mode after transfer state" },
    { 2, "Max. 2 sec non-DRX mode after transfer state" },
    { 3, "Max. 4 sec non-DRX mode after transfer state" },
    { 4, "Max. 8 sec non-DRX mode after transfer state" },
    { 5, "Max. 16 sec non-DRX mode after transfer state" },
    { 6, "Max. 32 sec non-DRX mode after transfer state" },
    { 7, "Max. 64 sec non-DRX mode after transfer state" },
    { 0, NULL},
    /* Otherwise "" */
  };

  static const value_string tab_cycle_length_coefficient[] = {
    { 0, "CN Specific DRX cycle length coefficient not specified by the MS, ie. the system information value 'CN domain specific DRX cycle length' is used" },
    { 6, "CN Specific DRX cycle length coefficient 6" },
    { 7, "CN Specific DRX cycle length coefficient 7" },
    { 8, "CN Specific DRX cycle length coefficient 8" },
    { 9, "CN Specific DRX cycle length coefficient 9" },
    { 0, NULL },
    /* Otherwise "CN Specific DRX cycle length coefficient not specified by the MS" */
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_drx_parameters);

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "SPLIT PG CYCLE: code %u", value);
  if ((value >= 1) && (value <= 64)) {
    cycle_value = value;
  }
  else {
    switch (value) {
    case 0: cycle_value = 704; break;
    case 65: cycle_value = 71; break;
    case 66: cycle_value = 72; break;
    case 67: cycle_value = 74; break;
    case 68: cycle_value = 75; break;
    case 69: cycle_value = 77; break;
    case 70: cycle_value = 79; break;
    case 71: cycle_value = 80; break;
    case 72: cycle_value = 83; break;
    case 73: cycle_value = 86; break;
    case 74: cycle_value = 88; break;
    case 75: cycle_value = 90; break;
    case 76: cycle_value = 92; break;
    case 77: cycle_value = 96; break;
    case 78: cycle_value = 101; break;
    case 79: cycle_value = 103; break;
    case 80: cycle_value = 107; break;
    case 81: cycle_value = 112; break;
    case 82: cycle_value = 116; break;
    case 83: cycle_value = 118; break;
    case 84: cycle_value = 128; break;
    case 85: cycle_value = 141; break;
    case 86: cycle_value = 144; break;
    case 87: cycle_value = 150; break;
    case 88: cycle_value = 160; break;
    case 89: cycle_value = 171; break;
    case 90: cycle_value = 176; break;
    case 91: cycle_value = 192; break;
    case 92: cycle_value = 214; break;
    case 93: cycle_value = 224; break;
    case 94: cycle_value = 235; break;
    case 95: cycle_value = 256; break;
    case 96: cycle_value = 288; break;
    case 97: cycle_value = 320; break;
    case 98: cycle_value = 352; break;
    default:
      cycle_value = 1;
    }
    proto_item_append_text(ti, " => value %u", cycle_value);
    if (cycle_value == 704) {
      proto_item_append_text(ti, " (equivalent to no DRX)");
    }
  }
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_CYCLE_LENGTH_COEFFICIENT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_CYCLE_LENGTH_COEFFICIENT);
  proto_item_append_text(pi, "CN specific DRX cycle length coefficient: %s (%#02x)",
			 val_to_str(value, tab_cycle_length_coefficient,
				    "Not specified by the MS"),
			 value);

  value = get_masked_guint8(data, MASK_SPLIT_ON_CCCH);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_SPLIT_ON_CCCH);
  proto_item_append_text(pi, "SPLIT on CCCH: Split pg cycle on CCCH is%s supported by the mobile station",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_NON_DRX_TIMER);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_NON_DRX_TIMER);
  proto_item_append_text(pi, "Non-DRX Timer: %s (%#x)",
			 val_to_str(value, tab_non_drx_timer, ""), value);
  bi->offset++;
}

/*
 * 11.3.12 eMLPP-Priority
 */

static void
decode_iei_emlpp_priority(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_CALL_PRIORITY = 0x07;
  proto_item *ti;
  guint8 data, value;

  static const value_string tab_call_priority[] = {
    { 0, "No priority applied" },
    { 1, "Call priority level 4" },
    { 2, "Call priority level 3" },
    { 3, "Call priority level 2" },
    { 4, "Call priority level 1" },
    { 5, "Call priority level 0" },
    { 6, "Call priority level B" },
    { 7, "Call priority level A" },
    { 0, NULL },
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    data = tvb_get_guint8(bi->tvb, bi->offset);
    value = get_masked_guint8(data, MASK_CALL_PRIORITY);
    proto_item_append_text(ti, ": %s",
			   val_to_str(value, tab_call_priority, ""));
  }
  bi->offset += ie->value_length;
}
/*
 * 11.3.13 Flush Action
 */

static void
decode_iei_flush_action(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;

  static const value_string tab_action_value[] = {
    { 0x00, "LLC-PDU(s) deleted" },
    { 0x01, "LLC-PDU(s) transferred" },
    { 0,    NULL },
    /* Otherwise "Reserved" */
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_item_append_text(ti, ": %s (%u)",
			   val_to_str(value, tab_action_value, "Reserved"),
			   value);

  }
  bi->offset += ie->value_length;
}
/*
 * 11.3.16 LLC Frames Discarded
 */

static void
decode_iei_llc_frames_discarded(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  decode_simple_ie(ie, bi, ie_start_offset, "", " frames discarded", TRUE);
}
/*
 * 11.3.17 Location Area
 */
static void
decode_iei_location_area(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  char *lai;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_location_area);

  lai = decode_rai(bi, tf);
  proto_item_append_text(ti, ": LAI %s", lai);
}

static void
decode_msrac_additional_access_technologies(proto_tree *tree, tvbuff_t *tvb,
					    guint32 bo, guint32 length _U_) {
  proto_item *pi;
  guint8 value;
  guint8 bl; /* Bit length */

  bl = 4;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Access Technology Type: %s (%#01x)",
			 translate_msrac_access_technology_type(value),
			 value);

  bl = 3;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "GMSK Power Class: Power class %u", value);

  bl = 2;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "8PSK Power Class");
  if (value == 0) {
    proto_item_append_text(pi, ": 8PSK modulation not supported for uplink");
  }
  else{
    proto_item_append_text(pi, ": Power Class E%u", value);
  }
}

static gboolean
struct_bits_exist(guint32 start_bo, guint32 struct_length,
		  guint32 bo, guint32 num_bits) {
  return (bo + num_bits) <= (start_bo + struct_length);

}

static void
decode_msrac_access_capabilities(proto_tree *tree, tvbuff_t *tvb,
				 guint32 bo, guint32 struct_length) {
  /* Error handling:
     - Struct too short: assume features do not exist
     - Struct too long: ignore data and jump to next Access Technology */
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 value, i;
  guint8 dgmsc = 0, demsc = 0; /* DTM GPRS/EGPRS Multi Slot Class */
  guint8 bl; /* Bit length */
  guint32 start_bo = bo;

  /* RF Power Capability */
  bl = 3;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "RF Power Capability");
  if (value == 0) {
    proto_item_append_text(pi, ": The MS does not support any GSM access technology type");
  }
  else {
    proto_item_append_text(pi, ": GMSK Power Class %u", value);
  }

  /* A5 bits */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  if (value == 1) {
    bo += bl;
    bl = 7;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    ti = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    proto_item_append_text(ti, "A5 Bits: %#02x", value);
    tf = proto_item_add_subtree(ti, ett_bssgp_msrac_a5_bits);
    for (i = 0; i < bl; i++) {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo + i, 1);
      proto_item_append_text(pi, "Encryption algorithm A5/%u%s available",
			     i + 1,
			     value & (0x40 >> i) ? "" : " not");
    }
    bo += bl;
  }
  else {
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "A5 bits: Same as in the immediately preceding Access capabilities field within this IE");
  }

  /* ES IND */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "ESD IND: Controlled Early Classmark Sending"" option is%s implemented",
			 value == 0 ? " not" : "");

  /* PS */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "PS: PS capability%s present",
			 value == 0 ? " not" : "");

  /* VGCS */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "VBCS:%s VGCS capability %s notifications wanted",
			 value == 0 ? " No" : "",
			 value == 0 ? "or no" : "and");

  /* VBS */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "VBS:%s VBS capability %s notifications wanted",
			 value == 0 ? " No" : "",
			 value == 0 ? "or no" : "and");

  /* Multislot capability */
  /* XXX: 'Error: struct too short, assume features do not exist'
     No length is given! */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  if (value == 1) {
    bo += bl;
    ti = bit_proto_tree_add_text(tree, tvb, bo, bl, "Multislot capability");
    tf = proto_item_add_subtree(ti, ett_bssgp_msrac_multislot_capability);

    /* HSCSD Multislot Class */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 5;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "HSCSD Multislot Class");
      if ((value > 0 ) && (value < 19)) {
	proto_item_append_text(pi, ": Multislot Class %u", value);
      }
      else {
	proto_item_append_text(pi, ": Reserved");
      }
    }
    else
    {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo-1, bl);
      proto_item_append_text(pi, "HSCSD Multislot Class - Bits are not available" );
    }

    /* GPRS Multislot Class, GPRS Extended Dynamic Allocation Capability */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 5;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "GPRS Multislot Class: Multislot Class %u",
			     value);

      bl = 1;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "GPRS Extended Dynamic Allocation Capability: Extended Dynamic Allocation for GPRS is%s implemented",
			     value == 0 ? " not" : "");
    }
    else
    {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo-1, bl);
      proto_item_append_text(pi, "GPRS Multislot Class: Multislot Class - Bits are not available" );
    }

    /* SMS Value, SM Value */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 4;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi,
			     "SMS_VALUE: %u/4 timeslot (~%u microseconds)",
			     value + 1, (value + 1) * 144);

      bl = 4;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi,
			     "SM_VALUE: %u/4 timeslot (~%u microseconds)",
			     value + 1, (value + 1) * 144);
    }
    else
    {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo-1, bl);
      proto_item_append_text(pi, "SMS Value, SM Value - Bits are not available" );
    }

    /* Additions in release 99 */

    /* ECSD Multislot Class */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 5;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "ECSD Multislot Class");
      if ((value > 0 ) && (value < 19)) {
	proto_item_append_text(pi, ": Multislot Class %u", value);
      }
      else {
	proto_item_append_text(pi, ": Reserved");
      }
    }
    else
    {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo-1, bl);
      proto_item_append_text(pi, "ECSD Multislot Class - Bits are not available" );
    }

    /* EGPRS Multislot Class, EGPRS Extended Dynamic Allocation Capability */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 5;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "EGPRS Multislot Class: Multislot Class %u",
			     value);

      bl = 1;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "EGPRS Extended Dynamic Allocation Capability: Extended Dynamic Allocation for EGPRS is%s implemented",
			     value == 0 ? " not" : "");
    }
    else
    {
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo-1, bl);
      proto_item_append_text(pi, "EGPRS Multislot Class: Multislot Class - Bits are not available");
    }

    /* DTM GPRS Multislot Class */
    bl = 1;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    bo += bl;
    if (value == 1) {
      bl = 2;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      dgmsc = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi, "DTM GPRS Multislot Class: %s",
			     translate_msrac_dtm_gprs_multislot_class(dgmsc));

      /* Single slot DTM */
      bl = 1;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
      bo += bl;
      proto_item_append_text(pi,
			     "Single Slot DTM: Single slot DTM%s supported",
			     value == 0 ? " not" : "");

      /* DTM EGPRS Multislot Class */
      bl = 1;
      if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
      value = tvb_get_bits8(tvb, bo, bl);
      bo += bl;
      if (value == 1) {
	bl = 2;
	if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
	demsc = tvb_get_bits8(tvb, bo, bl);
	pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
	bo += bl;
	proto_item_append_text(pi, "DTM EGPRS Multislot Class: %s",
			       translate_msrac_dtm_gprs_multislot_class(demsc));
      }
    }
    proto_item_set_len(ti, get_num_octets_spanned(start_bo,
						  (guint32) (bo - start_bo)));
  }
  else {
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "Multislot capability: Same as in the immediately preceding Access capabilities field within this IE");
  }

  /* Additions in release 99 */

  /* 8PSK Power Capability */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  bo += bl;
  if (value == 1) {
    bl = 2;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "8PSK Power Capability");

    if (value == 0) {
      proto_item_append_text(pi, ": Reserved");
    }
    else{
      proto_item_append_text(pi, ": Power Class E%u", value);
    }
    proto_item_append_text(pi, ", 8PSK modulation capability in uplink");
  }

  /* COMPACT Interference Measurement Capability */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi,
			 "COMPACT Interference Measurement Capability: %s",
			 value == 0 ? "Not implemented" : "Implemented");

  /* Revision level indicator */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Revision Level Indicator: The ME is Release '%u %s",
			 value == 0 ? 98 : 99,
			 value == 0 ? "or older" : "onwards");


  /* 3G RAT */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "UMTS FDD Radio Access Technology Capability: UMTS FDD%s supported",
			 value == 0 ? " not" : "");

  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "UMTS 3.84 Mcps TDD Radio Access Technology Capability: UMTS 3.84 Mcps TDD%s supported",
			 value == 0 ? " not" : "");

  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "CDMA 2000 Radio Access Technology Capability: CDMA 2000%s supported",
			 value == 0 ? " not" : "");


  /* Additions in release 4*/
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "UMTS 1.28 Mcps TDD Radio Access Technology Capability: UMTS 1.28 Mcps TDD%s supported",
			 value == 0 ? " not" : "");


  /* GERAN Feature Package 1 */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "GERAN Feature Package 1: GERAN Feature Package 1%s supported",
			 value == 0 ? " not" : "");


  /* Extended DTM xGPRS Multislot Class */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  bo += bl;
  if (value == 1) {
    bl = 2;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "Extended DTM GPRS Multi Slot Class: %s",
			   translate_msrac_extended_dtm_gprs_multislot_class(value, dgmsc));

    /* XXX: 'This field shall be included only if the MS supports EGPRS DTM'.
       How know? */
    bl = 2;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "Extended DTM EGPRS Multi Slot Class: %s",
			   translate_msrac_extended_dtm_gprs_multislot_class(value, demsc));
  }

  /* Modulation based multislot class support */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Modulation based multislot class support: %s supported",
			 value == 0 ? "Not" : "");

  /* Additions in release 5 */

  /* High multislot capability */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  bo += bl;
  if (value == 1) {
    bl = 2;
    if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
    value = tvb_get_bits8(tvb, bo, bl);
    pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
    bo += bl;
    proto_item_append_text(pi, "High Multislot Capability: %u", value);
    /* XXX: Translate? In that case, which values to compare with?
       What if Multislot capability struct was not included? */
  }

  /* GERAN Iu Mode Capabilities */
  /* XXX: Interpretation? Length? */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "GERAN Iu Mode Capabilities: %s",
			 value == 0 ? "Not supported" : "Supported");

  /* GMSK Multislot Power Profile */
  bl = 2;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "GMSK Multislot Power Profile: GMSK_MULTI_SLOT_POWER_PROFILE %u",
			 value);

  /* 8PSK Multislot Power Profile */
  /* XXX: 'If the MS does not support 8PSK in the uplink, then it shall
     set this field to 00' */
  bl = 2;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "8PSK Multislot Power Profile: 8PSK_MULTI_SLOT_POWER_PROFILE %u",
			 value);

  /* Additions in release 6 */

  /* Multiple TBF Capability */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Multiple TBF Capability: Multiple TBF procedures in A/Gb mode%s supported",
			 value == 0 ? " not" : "");

  /* Downlink Advanced Receiver Performance */
  bl = 2;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Downlink Advanced Receiver Performance: Downlink Advanced Receiver Performance %s supported",
			 value == 0 ? "not" : "- phase 1");


  /* Extended RLC_MAC Control Message Segmentation Capability */
  bl = 1;
  if (!struct_bits_exist(start_bo, struct_length, bo, bl)) return;
  value = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tree, tvb, bo, bl);
  bo += bl;
  proto_item_append_text(pi, "Extended RLC/MAC Control Message Segmentation Capability: Extended RLC/MAC Control Message Segmentation%s supported",
			 value == 0 ? " not" : "");
}

static void
decode_msrac_value_part(proto_tree *tree, tvbuff_t *tvb, guint32 bo) {
  /* No need to check bi->bssgp_tree here */
  const guint8 ADD_ACC_TECHN = 0x0f;
  guint8 att, length, bit, bl;
  proto_item *ti, *ti2, *pi;
  proto_tree *tf, *tf2;
  const char *att_name;
  guint32 start_bo;

  start_bo = bo;
  ti = bit_proto_tree_add_text(tree, tvb, bo, 8,
			       "MS RA capability value part");
  /* Temporary length of item */
  tf = proto_item_add_subtree(ti, ett_bssgp_msrac_value_part);

  bl = 4;
  att = tvb_get_bits8(tvb, bo, bl);
  att_name = translate_msrac_access_technology_type(att);
  pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
  proto_item_append_text(pi, "Access Technology Type: %s (%#01x)", att_name, att);
  proto_item_append_text(ti, ": Technology Type %s", att_name);
  bo += bl;

  bl = 7;
  length = tvb_get_bits8(tvb, bo, bl);
  pi = bit_proto_tree_add_bit_field8(tf, tvb, bo, bl);
  proto_item_append_text(pi, "Length: %u bits", length);
  bo += bl;

  if (att == ADD_ACC_TECHN) {
    bo++; /* Always '1' */
    ti2 = bit_proto_tree_add_text(tf, tvb, bo, length,
				  "Additional Access Technologies");
    tf2 = proto_item_add_subtree(ti2, ett_bssgp_msrac_additional_access_technologies);
    proto_item_set_len(ti, get_num_octets_spanned(start_bo, 4 + 7 + length + 1 + 1));
    decode_msrac_additional_access_technologies(tf2, tvb, bo, length);
  }
  else if (att <= 0x0b) {
    ti2 = bit_proto_tree_add_text(tf, tvb, bo, length, "Access Capabilities");
    tf2 = proto_item_add_subtree(ti2, ett_bssgp_msrac_access_capabilities);
    proto_item_set_len(ti, get_num_octets_spanned(start_bo, 4 + 7 + length + 1));
    decode_msrac_access_capabilities(tf2, tvb, bo, length);
  }
  /* else unknown Access Technology Type */

  bo += length;
  bit = tvb_get_bits8(tvb, bo, 1);
  bo++;
  if (bit == 1) {
    decode_msrac_value_part(tree, tvb, bo);
  }
}
/*
 * 11.3.22 MS Radio Access Capability
 */
static void
decode_iei_ms_radio_access_capability(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_ms_radio_access_capability);
  /* Rest of element coded as the value part defined in
   * 3GPP TS 24.008, not including 3GPP TS 24.008 IEI and
   * 3GPP TS 24.008 octet length indicator.
   * 10.5.5.12a MS Radio Access capability
   */
  decode_msrac_value_part(tf, bi->tvb, bi->offset * 8);
  bi->offset += ie->value_length;
}
/*
 * 11.3.23 OMC Id
 */
static void
decode_iei_omc_id(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /* XXX: Translation: where in 3GPP TS 12.20? */
  proto_item *ti;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %s", BSSGP_NOT_DECODED);
  }
  bi->offset += ie->value_length;
}
/*
 * 11.3.24 PDU In Error
 */
static void
decode_iei_pdu_in_error(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": Erroneous BSSGP PDU (%u bytes)",
			   ie->value_length);
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_priority(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_PCI = 0x40;
  const guint8 MASK_PRIORITY_LEVEL = 0x3c;
  const guint8 MASK_QA = 0x02;
  const guint8 MASK_PVI = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;

  static const value_string tab_priority_level[] = {
    { 0, "Spare" },
    { 1, "Priority Level 1 = highest priority" },
    { 2, "Priority Level 2 = 2nd highest priority" },
    { 3, "Priority Level 3 = 3rd highest priority" },
    { 4, "Priority Level 4 = 4th highest priority" },
    { 5, "Priority Level 5 = 5th highest priority" },
    { 6, "Priority Level 6 = 6th highest priority" },
    { 7, "Priority Level 7 = 7th highest priority" },
    { 8, "Priority Level 8 = 8th highest priority" },
    { 9, "Priority Level 9 = 9th highest priority" },
    { 10, "Priority Level 10 = 10th highest priority" },
    { 11, "Priority Level 11 = 11th highest priority" },
    { 12, "Priority Level 12 = 12th highest priority" },
    { 13, "Priority Level 13 = 13th highest priority" },
    { 14, "Priority Level 14 = lowest priority" },
    { 15, "Priority not used" },
    { 0, NULL },
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_priority);

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_PCI);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_PCI);
  proto_item_append_text(pi, "PCI: This allocation request %s preempt an existing connection",
			 value == 0 ? "shall not" : "may");

  value = get_masked_guint8(data, MASK_PRIORITY_LEVEL);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PRIORITY_LEVEL);
  proto_item_append_text(pi, "Priority Level: %s",
			 val_to_str(value, tab_priority_level, ""));

  value = get_masked_guint8(data, MASK_QA);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_QA);
  proto_item_append_text(pi, "QA: Queuing%s allowed",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_PVI);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PVI);
  proto_item_append_text(pi, "PVI: This connection %s be preempted by another allocation request",
                         value == 0 ? "shall not" : "might");

  bi->offset += ie->value_length;
}
/*
 * 11.3.28 QoS Profile
 */
static void
decode_iei_qos_profile(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_CR_BIT = 0x20;
  const guint8 MASK_T_BIT = 0x10;
  const guint8 MASK_A_BIT = 0x08;
  const guint8 MASK_PRECEDENCE = 0x07;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;
  guint16 peak_bit_rate;

  static const value_string tab_precedence_ul[] = {
    { 0,   "High priority" },
    { 1,   "Normal priority" },
    { 2,   "Low priority" },
    { 0,   NULL },
  };

  static const value_string tab_precedence_dl[] = {
    { 0,   "Radio priority 1" },
    { 1,   "Radio priority 2" },
    { 2,   "Radio priority 3" },
    { 3,   "Radio priority 4" },
    { 4,   "Radio priority unknown" },
    { 0,   NULL },
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_qos_profile);

  peak_bit_rate = tvb_get_ntohs(bi->tvb, bi->offset);
  pi = proto_tree_add_text(tf, bi->tvb, bi->offset, 1, "Peak bit rate: ");
  if (peak_bit_rate == 0) {
    proto_item_append_text(pi, "Best effort");
  }
  else {
    proto_item_append_text(pi, "%u bits/s", peak_bit_rate * 100);
  }
  bi->offset += 2;

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_CR_BIT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_CR_BIT);
  proto_item_append_text(pi, "C/R: The SDU %s command/response frame type",
			 value == 0 ? "contains" : "does not contain");

  value = get_masked_guint8(data, MASK_T_BIT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_T_BIT);
  proto_item_append_text(pi, "T: The SDU contains %s",
			 value == 0 ? "signalling (e.g. related to GMM)" : "data");

  value = get_masked_guint8(data, MASK_A_BIT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_A_BIT);
  proto_item_append_text(pi, "A: Radio interface uses RLC/MAC %s functionality",
			 value == 0 ? "ARQ " : "UNITDATA ");

  value = get_masked_guint8(data, MASK_PRECEDENCE);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PRECEDENCE);
  proto_item_append_text(pi, "Precedence: ");

  if (bi->ul_data) {
    proto_item_append_text(pi, "%s", val_to_str(value, tab_precedence_ul,
					  "Reserved (Low priority)"));
  }
  else {
    proto_item_append_text(pi, "%s", val_to_str(value, tab_precedence_dl,
					  "Reserved (Radio priority 3)"));
  }
  proto_item_append_text(pi, " (%#x)", value);
  bi->offset++;
}
/*
 * 11.3.29 Radio Cause
 */
static void
decode_iei_radio_cause(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;

  static const value_string tab_radio_cause[] = {
    { 0x00, "Radio contact lost with the MS" },
    { 0x01, "Radio link quality insufficient to continue communication" },
    { 0x02, "Cell reselection ordered" },
    { 0x03, "Cell reselection prepare" },
    { 0x04, "Cell reselection failure" },
    { 0,    NULL },
    /* Otherwise "Reserved (Radio contact lost with the MS)" */
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_item_append_text(ti, ": %s (%#02x)",
			   val_to_str(value, tab_radio_cause, "Reserved (Radio contact lost with the MS)"),
			   value);
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_ra_cap_upd_cause(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;

  static const value_string tab_cause_value[] = {
    { 0x00, "OK, RA capability IE present" },
    { 0x01, "TLLI unknown in SGSN" },
    { 0x02, "No RA capabilities or IMSI available for this MS" },
    { 0,    NULL },
    /* Otherwise "Reserved (TLLI unknown in SGSN)" */
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_item_append_text(ti, ": %s (%#2x)",
			   val_to_str(value, tab_cause_value, "Reserved (TLLI unknown in SGSN)"),
			   value);
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_routing_area(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  char *rai;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_routing_area);

  rai = decode_rai(bi, tf);
  proto_item_append_text(ti, ": RAI %s", rai);
}

static void
decode_iei_tlli(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;

  guint32 tlli;
  tlli = tvb_get_ntohl(bi->tvb, bi->offset);

	ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
	proto_item_append_text(ti, ": %#04x", tlli);
	/* By Stefan Boman LN/Ericsson 2006-07-14 --
	 * Commented the following four lines. Preventing redundant data
	 */
	/*
	ti = bssgp_proto_tree_add_ie(ie, bi, bi->offset);
	*/
	/* If we want to keep the posibillity to filter on ie:s without a Tag and the ie "content"
	 * this is how it has to be done.
	 */
	tf = proto_item_add_subtree(ti, ett_bssgp_tlli);

	proto_tree_add_item(tf, hf_bssgp_tlli,
				   bi->tvb, bi->offset, 4, ENC_BIG_ENDIAN);

  bi->offset += 4;

 col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP,
			"TLLI %#4x", tlli);

  decode_nri(bi->bssgp_tree, bi, tlli);
}

static void
decode_iei_tmsi(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  guint32 tmsi;

  tmsi = tvb_get_ntohl(bi->tvb, bi->offset);

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %#04x", tmsi);

    ti = bssgp_proto_tree_add_ie(ie, bi, bi->offset);
    tf = proto_item_add_subtree(ti, ett_bssgp_tmsi_ptmsi);

    proto_tree_add_item(tf, hf_bssgp_tmsi_ptmsi,
			       bi->tvb, bi->offset, 4, ENC_BIG_ENDIAN);
  }
  bi->offset += 4;

  col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP,
			"(P)TMSI %#4x", tmsi);

  decode_nri(bi->bssgp_tree, bi, tmsi);
}

static void
decode_iei_trigger_id(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /* XXX: value is 20 octets long! How add/show? */
  proto_item *ti;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  }
  bi->offset += ie->value_length;
}

static void
proto_tree_add_lsa_id(build_info_t *bi, proto_tree *tree) {
  guint32 data, lsa_id;
  proto_item *pi;

  data = tvb_get_ntoh24(bi->tvb, bi->offset);
  lsa_id = data >> 1;

  pi = proto_tree_add_text(tree, bi->tvb, bi->offset, 3,
			   "LSA ID: %#03x (%s)", lsa_id,
			   data & 1 ?
			   "Universal LSA" : "PLMN significant number");
  bi->offset += 3;
}

static void
decode_iei_lsa_identifier_list(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_EP = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  int num_lsa_ids, i;
  guint32 value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_lsa_identifier_list);

  value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_EP);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_EP);
  proto_item_append_text(pi, "EP: The escape PLMN is%s broadcast",
			 value == 0 ? " not" : "");
  bi->offset++;

  num_lsa_ids = (ie->value_length - 1) / 3;

  for (i = 0; i < num_lsa_ids; i++) {
    proto_tree_add_lsa_id(bi, tf);
  }
}

static void
decode_iei_lsa_information(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_LSA_ONLY = 0x01;
  const guint8 MASK_ACT = 0x20;
  const guint8 MASK_PREF = 0x10;
  const guint8 MASK_PRIORITY = 0x0f;
  proto_item *ti, *ti2, *pi;
  proto_tree *tf, *tf2;
  int num_lsa_infos, i;
  guint8 data, value;

  static const value_string tab_priority[] = {
    { 0, "Priority 1 = lowest priority" },
    { 1, "Priority 2 = 2nd lowest priority" },
    { 2, "Priority 3 = 3rd lowest priority" },
    { 3, "Priority 4 = 4th lowest priority" },
    { 4, "Priority 5 = 5th lowest priority" },
    { 5, "Priority 6 = 6th lowest priority" },
    { 6, "Priority 7 = 7th lowest priority" },
    { 7, "Priority 8 = 8th lowest priority" },
    { 8, "Priority 9 = 9th lowest priority" },
    { 9, "Priority 10 = 10th lowest priority" },
    { 10, "Priority 11 = 11th lowest priority" },
    { 11, "Priority 12 = 12th lowest priority" },
    { 12, "Priority 13 = 13th lowest priority" },
    { 13, "Priority 14 = 14th lowest priority" },
    { 14, "Priority 15 = 15th lowest priority" },
    { 15, "Priority 16 = highest priority" },
    { 0, NULL },
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_lsa_information);

  value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_LSA_ONLY);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_LSA_ONLY);
  proto_item_append_text(pi, "LSA Only: %s",
			 value == 0 ?
			 "The subscriber has only access to the LSAs that are defined by the LSA information element" :
			 "Allow an emergency call");
  bi->offset++;

  num_lsa_infos = (ie->value_length - 1) / 4;

  for (i = 0; i < num_lsa_infos; i++) {
    ti2 = proto_tree_add_text(tf, bi->tvb, bi->offset, 4,
			      "LSA Identification and attributes %u", i + 1);
    tf2 = proto_item_add_subtree(ti2, ett_bssgp_lsa_information_lsa_identification_and_attributes);

    data = tvb_get_guint8(bi->tvb, bi->offset);

    value = get_masked_guint8(data, MASK_ACT);
    pi = proto_tree_add_bitfield8(tf2, bi->tvb, bi->offset, MASK_ACT);
    proto_item_append_text(pi, "Act: The subscriber %s active mode support in the LSA",
			   value == 0 ? "does not have" : "has");

    value = get_masked_guint8(data, MASK_PREF);
    pi = proto_tree_add_bitfield8(tf2, bi->tvb, bi->offset, MASK_PREF);
    proto_item_append_text(pi, "Pref: The subscriber %s preferential access in the LSA",
			   value == 0 ? "does not have" : "has");

    value = get_masked_guint8(data, MASK_PRIORITY);
    pi = proto_tree_add_bitfield8(tf2, bi->tvb, bi->offset, MASK_PRIORITY);
    proto_item_append_text(pi, "Priority: %s",
			   val_to_str(value, tab_priority, ""));
    bi->offset++;

    proto_tree_add_lsa_id(bi, tf2);
  }
}

static void
decode_iei_gprs_timer(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_UNIT_VALUE = 0xe0;
  const guint8 MASK_TIMER_VALUE = 0x1f;
  proto_item *ti;
  guint8 data, value;

  static const value_string tab_unit_value[] = {
    { 0, "incremented in multiples of 2 s" },
    { 1, "incremented in multiples of 1 minute" },
    { 2, "incremented in multiples of decihours" },
    { 3, "incremented in multiples of 500 msec" },
    { 7, "the timer does not expire" },
    { 0, NULL},
    /* Otherwise "incremented in multiples of 1 minute" */
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    data = tvb_get_guint8(bi->tvb, bi->offset);
    value = get_masked_guint8(data, MASK_TIMER_VALUE);
    proto_item_append_text(ti, ": %u", value);

    value = get_masked_guint8(data, MASK_UNIT_VALUE);
    proto_item_append_text(ti, ", %s",
			   val_to_str(value, tab_unit_value,
				      "incremented in multiples of 1 minute"));
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_abqp(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_DELAY_CLASS = 0x38;
  const guint8 MASK_RELIABILITY_CLASS = 0x07;
  const guint8 MASK_PEAK_THROUGHPUT = 0xf0;
  const guint8 MASK_PRECEDENCE_CLASS = 0x07;
  const guint8 MASK_MEAN_THROUGHPUT = 0x1f;
  const guint8 MASK_TRAFFIC_CLASS = 0xe0;
  const guint8 MASK_DELIVERY_ORDER = 0x18;
  const guint8 MASK_DELIVERY_OF_ERRONEOUS_SDU = 0x07;
  const guint8 MASK_RESIDUAL_BER = 0xf0;
  const guint8 MASK_SDU_ERROR_RATIO = 0x0f;
  const guint8 MASK_TRANSFER_DELAY = 0xfc;
  const guint8 MASK_TRAFFIC_HANDLING_PRIORITY = 0x03;
  const guint8 MASK_SIGNALLING_INDICATION = 0x10;
  const guint8 MASK_SOURCE_STATISTICS_DESCRIPTOR = 0x0f;
  const guint8 TRAFFIC_CLASS_CONVERSATIONAL = 1;
  const guint8 TRAFFIC_CLASS_STREAMING = 2;
  const guint8 TRAFFIC_CLASS_INTERACTIVE = 3;
  const guint8 TRAFFIC_CLASS_BACKGROUND = 4;
  guint8 data, value, traffic_class;
  proto_item *ti, *pi;
  proto_tree *tf;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_abqp);

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_DELAY_CLASS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_DELAY_CLASS);
  proto_item_append_text(pi, "Delay Class: %s (%#x)",
			 translate_abqp_delay_class(value, bi), value);

  value = get_masked_guint8(data, MASK_RELIABILITY_CLASS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_RELIABILITY_CLASS);
  proto_item_append_text(pi, "Reliability Class: %s (%#x)",
			 translate_abqp_reliability_class(value, bi), value);
  bi->offset++;
  /* Octet 4 */
  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_PEAK_THROUGHPUT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_PEAK_THROUGHPUT);
  proto_item_append_text(pi, "Peak Throughput: %s (%#x)",
			 translate_abqp_peak_throughput(value, bi), value);

  value = get_masked_guint8(data, MASK_PRECEDENCE_CLASS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_PRECEDENCE_CLASS);
  proto_item_append_text(pi, "Precedence Class: %s (%#x)",
			 translate_abqp_precedence_class(value, bi), value);
  bi->offset++;
  /* Octet 5 */
  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_MEAN_THROUGHPUT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_MEAN_THROUGHPUT);
  proto_item_append_text(pi, "Mean Throughput: %s (%#02x)",
			 translate_abqp_mean_throughput(value, bi), value);
  /*
   * A QoS IE received without octets 6-16, without octets 14-16, or without octets 15-16 shall be accepted by the
   * receiving entity.
   */
  bi->offset++;
  if (ie->value_length == 3)
    return;
  /* Octet 6 */
  data = tvb_get_guint8(bi->tvb, bi->offset);

  traffic_class = get_masked_guint8(data, MASK_TRAFFIC_CLASS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_TRAFFIC_CLASS);
  proto_item_append_text(pi, "Traffic Class: %s (%#x)",
			 translate_abqp_traffic_class(traffic_class, bi),
			 value);
  if ((traffic_class == TRAFFIC_CLASS_INTERACTIVE) ||
      (traffic_class == TRAFFIC_CLASS_BACKGROUND)) {
    proto_item_append_text(pi, " (ignored)");
  }

  value = get_masked_guint8(data, MASK_DELIVERY_ORDER);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_DELIVERY_ORDER);
  proto_item_append_text(pi, "Delivery Order: %s (%#x)",
			 translate_abqp_delivery_order(value, bi), value);

  value = get_masked_guint8(data, MASK_DELIVERY_OF_ERRONEOUS_SDU);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_DELIVERY_OF_ERRONEOUS_SDU);
  proto_item_append_text(pi, "Delivery of Erroneous SDU: %s (%#x)",
			 translate_abqp_delivery_of_erroneous_sdu(value, bi),
			 value);
  bi->offset++;
  /* Octet 7 */

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "Maximum SDU Size: %s",
		      translate_abqp_max_sdu_size(value, bi));
  /* Octet 8 */
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "Maximum bit rate for uplink: %s",
		      translate_abqp_max_bit_rate_for_ul(value, bi));
  /* Octet 9 */
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "Maximum bit rate for downlink: %s",
		      translate_abqp_max_bit_rate_for_dl(value, bi));
  /* Octet 10 */
  bi->offset++;
  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_RESIDUAL_BER);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_RESIDUAL_BER);
  proto_item_append_text(pi, "Residual BER: %s (%#x)",
			 translate_abqp_residual_ber(value, bi), value);

  value = get_masked_guint8(data, MASK_SDU_ERROR_RATIO);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_SDU_ERROR_RATIO);
  proto_item_append_text(pi, "SDU Error Ratio: %s (%#x)",
			 translate_abqp_sdu_error_ratio(value, bi), value);
  /* Octet 11 */
  bi->offset++;
  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_TRANSFER_DELAY);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_TRANSFER_DELAY);
  proto_item_append_text(pi, "Transfer Delay: %s (%#02x)",
			 translate_abqp_transfer_delay(value, bi), value);

  value = get_masked_guint8(data, MASK_TRAFFIC_HANDLING_PRIORITY);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_TRAFFIC_HANDLING_PRIORITY);
  proto_item_append_text(pi, "Traffic Handling Priority: %s (%#x)",
			 translate_abqp_traffic_handling_priority(value, bi),
			 value);
  if ((traffic_class == TRAFFIC_CLASS_CONVERSATIONAL) ||
      (traffic_class == TRAFFIC_CLASS_STREAMING) ||
      (traffic_class == TRAFFIC_CLASS_BACKGROUND)) {
    proto_item_append_text(pi, " (ignored)");
  }
  /* Octet 12 */
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "Guaranteed bit rate for uplink: %s",
		      translate_abqp_guaranteed_bit_rate_for_ul(value, bi));
  /* Octet 13 */
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "Guaranteed bit rate for downlink: %s",
		      translate_abqp_guaranteed_bit_rate_for_dl(value, bi));
  /*
   * A QoS IE received without octets 6-16, without octets 14-16, or without octets 15-16 shall be accepted by the
   * receiving entity.
   */
  /* Octet 14 */
  bi->offset++;
  if (ie->value_length == 11)
    return;

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_SIGNALLING_INDICATION);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_SIGNALLING_INDICATION);
  proto_item_append_text(pi, "Signalling Indication: %s for signalling traffic",
			 value == 0 ? "Not optimized" : "Optimized");
  if ((traffic_class == TRAFFIC_CLASS_CONVERSATIONAL) ||
      (traffic_class == TRAFFIC_CLASS_STREAMING) ||
      (traffic_class == TRAFFIC_CLASS_BACKGROUND)) {
    proto_item_append_text(pi, " (ignored)");
  }

  value = get_masked_guint8(data, MASK_SOURCE_STATISTICS_DESCRIPTOR);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_SOURCE_STATISTICS_DESCRIPTOR);
  proto_item_append_text(pi, "Source Statistics Descriptor: %s (%#x)",
			 translate_abqp_source_statistics_descriptor(value, bi),
			 value);
  if ((traffic_class == TRAFFIC_CLASS_INTERACTIVE) ||
      (traffic_class == TRAFFIC_CLASS_BACKGROUND)) {
    proto_item_append_text(pi, " (ignored)");
  }
  /*
   * A QoS IE received without octets 6-16, without octets 14-16, or without octets 15-16 shall be accepted by the
   * receiving entity.
   */
  /* Octet 15 */
  bi->offset++;
  if (ie->value_length == 12)
    return;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "Maximum bit rate for downlink (extended): %s",
		      translate_abqp_max_bit_rate_for_dl_extended(value, bi));
  /* Octet 16 */
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "Guaranteed bit rate for downlink (extended): %s",
		      translate_abqp_guaranteed_bit_rate_for_dl_extended(value, bi));
  bi->offset++;
}

static void
decode_iei_feature_bitmap(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_ENHANCED_RADIO_STATUS = 0x40;
  const guint8 MASK_PFC_FC = 0x20;
  const guint8 MASK_RIM = 0x10;
  const guint8 MASK_LCS = 0x08;
  const guint8 MASK_INR = 0x04;
  const guint8 MASK_CBL = 0x02;
  const guint8 MASK_PFC = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_feature_bitmap);

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_ENHANCED_RADIO_STATUS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_ENHANCED_RADIO_STATUS);
  proto_item_append_text(pi, "Enhanced Radio Status: Enhanced Radio Status Procedures%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_PFC_FC);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PFC_FC);
  proto_item_append_text(pi, "PFC_FC: PFC Flow Control Procedures%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_RIM);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_RIM);
  proto_item_append_text(pi, "RIM: RAN Information Management (RIM) Procedures%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_LCS);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_LCS);
  proto_item_append_text(pi, "LCS: LCS Procedures%s supported",
                         value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_INR);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_INR);
  proto_item_append_text(pi, "INR: Inter-NSE re-routing%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_CBL);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_CBL);
  proto_item_append_text(pi, "CBL: Current Bucket Level Procedures%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_PFC);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PFC);
  proto_item_append_text(pi, "PFC: Packet Flow Context Procedures%s supported",
			 value == 0 ? " not" : "");

  bi->offset += ie->value_length;
}

static void
decode_iei_bucket_full_ratio(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    bssgp_pi_append_bucket_full_ratio(ti, bi->tvb, bi->offset);
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_service_utran_cco(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_SERVICE_UTRAN_CCO = 0x07;
  proto_item *ti;
  guint8 data, value;

  static const value_string tab_service_utran_cco[] = {
    { 0, "Network initiated cell change order procedure to UTRAN should be performed" },
    { 1, "Network initiated cell change order procedure to UTRAN should not be performed" },
    { 2, "Network initiated cell change order procedure to UTRAN shall not be performed" },
	{ 3, " If received, shall be interpreted as no information available (bits 4-5 valid)" },
	{ 0,    NULL },
    /* Otherwise "No information available" */
  };

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    data = tvb_get_guint8(bi->tvb, bi->offset);
    value = get_masked_guint8(data, MASK_SERVICE_UTRAN_CCO);
    proto_item_append_text(ti, ": %s (%#02x)",
			   val_to_str(value, tab_service_utran_cco,
				      "No information available"),
			   value);
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_nsei(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti, *hidden_item;
  guint16 nsei;

  nsei = tvb_get_ntohs(bi->tvb, bi->offset);

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %u", nsei);
    hidden_item = proto_tree_add_item(bi->bssgp_tree, hf_bssgp_nsei,
                                      bi->tvb, bi->offset, 2, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
  }
  bi->offset += ie->value_length;

  col_append_sep_fstr(bi->pinfo->cinfo, COL_INFO, BSSGP_SEP,
			"NSEI %u", nsei);
}

static void
decode_iei_lcs_qos(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_VERT = 0x01;
  const guint8 MASK_XA = 0x80;
  const guint8 MASK_ACCURACY = 0x7f;
  const guint8 MASK_RT = 0xc0;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value, vert;

  static const value_string tab_rt[] = {
    { 0, "Response time is not specified" },
    { 1, "Low delay" },
    { 2, "Delay tolerant" },
    { 3, "Reserved" },
    { 0, NULL },
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_lcs_qos);

  data = tvb_get_guint8(bi->tvb, bi->offset);
  vert = get_masked_guint8(data, MASK_VERT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_VERT);
  proto_item_append_text(pi, "VERT: Vertical coordinate is%s requested",
			 vert == 0 ? " not" : "");
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_XA);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_XA);
  proto_item_append_text(pi, "HA: Horizontal Accuracy is%s specified",
			 value == 0 ? " not" : "");

  if (value == 1) {
    value = get_masked_guint8(data, MASK_ACCURACY);
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_ACCURACY);
    proto_item_append_text(pi, "Horizontal Accuracy: %.1f m",
			   10 * (pow(1.1, (double)value) - 1));
  }
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);

  if (vert == 1) {
    value = get_masked_guint8(data, MASK_XA);
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_XA);
    proto_item_append_text(pi, "VA: Vertical Accuracy is%s specified",
			   value == 0 ? " not" : "");

    value = get_masked_guint8(data, MASK_ACCURACY);
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_ACCURACY);
    proto_item_append_text(pi, "Vertical Accuracy: %.1f m",
			   45 * (pow(1.025, (double)value) - 1));
  }
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  value = get_masked_guint8(data, MASK_RT);

  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_RT);
  proto_item_append_text(pi, "RT: %s",
			 val_to_str(value, tab_rt, ""));
  bi->offset++;
}

static void
decode_iei_lcs_client_type(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_CATEGORY = 0xf0;
  const guint8 MASK_SUBTYPE = 0x0f;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, category, subtype;

  static const value_string tab_category[] = {
    { 0, "Value Added Client" },
    /* { 1, ??? XXX }, */
    { 2, "PLMN Operator" },
    { 3, "Emergency Services" },
    { 4, "Lawful Intercept Services" },
    { 0, NULL },
    /* Otherwise "Reserved" */
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_lcs_client_type);

  data = tvb_get_guint8(bi->tvb, bi->offset);

  category = get_masked_guint8(data, MASK_CATEGORY);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_CATEGORY);
  proto_item_append_text(pi, "Category: %s (%#x)",
			 val_to_str(category, tab_category, "Reserved"),
			 category);

  subtype = get_masked_guint8(data, MASK_SUBTYPE);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_SUBTYPE);
  proto_item_append_text(pi, "Subtype: ");

  switch (category) {
  case 0:
    if (subtype == 0) {
      proto_item_append_text(pi, "Unspecified"); break;
    }
    else {
      proto_item_append_text(pi, "Reserved"); break;
    }
    /* case 1: ??? XXX*/
  case 2:
    switch (subtype) {
    case 0: proto_item_append_text(pi, "Unspecified"); break;
    case 1: proto_item_append_text(pi, "Broadcast service"); break;
    case 2: proto_item_append_text(pi, "O&M"); break;
    case 3: proto_item_append_text(pi, "Anonymous statistics"); break;
    case 4: proto_item_append_text(pi, "Target MS service support node"); break;
    default: proto_item_append_text(pi, "Reserved"); break;
    }
    break;
  case 3:
  case 4:
    if (subtype == 0) {
      proto_item_append_text(pi, "Unspecified"); break;
    }
    else {
      proto_item_append_text(pi, "Reserved"); break;
    }
  default: /* Not category == 1! */
    proto_item_append_text(pi, "Reserved"); break;
  }

  bi->offset++;
}

static void
decode_iei_requested_gps_assistance_data(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_A = 0x01;
  const guint8 MASK_B = 0x02;
  const guint8 MASK_C = 0x04;
  const guint8 MASK_D = 0x08;
  const guint8 MASK_E = 0x10;
  const guint8 MASK_F = 0x20;
  const guint8 MASK_G = 0x40;
  const guint8 MASK_H = 0x80;
  const guint8 MASK_I = 0x01;
  const guint8 MASK_NSAT = 0xf0;
  const guint8 MASK_T_TOE_LIMIT = 0x0f;
  const guint8 MASK_SAT_ID =0x3f;
  proto_tree *tf, *tf2;
  proto_item *ti, *ti2, *pi;
  guint8 data, value, d, nsat;
  guint16 gps_week;
  int i;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_requested_gps_assistance_data);

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_A);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_A);
  proto_item_append_text(pi, "A: Almanac is%s srequested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_B);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_B);
  proto_item_append_text(pi, "B: UTC Model is%s requested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_C);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_C);
  proto_item_append_text(pi, "C: Ionospheric Model is%s requested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_D);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_D);
  proto_item_append_text(pi, "D: Navigation Model is%s requested",
			 value == 0 ? " not" : "");
  d = value;

  value = get_masked_guint8(data, MASK_E);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_E);
  proto_item_append_text(pi, "E: DGPS Corrections are%s requested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_F);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_F);
  proto_item_append_text(pi, "F: Reference Location is%s requested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_G);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_G);
  proto_item_append_text(pi, "G: Reference Time is%s requested",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_H);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_H);
  proto_item_append_text(pi, "H: Acquisition Assistance is%s requested",
			 value == 0 ? " not" : "");

  bi->offset++;

  value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_I);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_I);
  proto_item_append_text(pi, "I: Real-Time Integrity is%s requested",
			 value == 0 ? " not" : "");
  if (d == 0) return;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  gps_week = (data & 0xc0) << 2;
  data = tvb_get_guint8(bi->tvb, bi->offset + 1);
  gps_week += data;
  proto_tree_add_text(tf, bi->tvb, bi->offset, 2,
		      "GPS Week: %u", gps_week);
  bi->offset += 2;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "GPS Toe: %u", value);
  bi->offset++;

  data = tvb_get_guint8(bi->tvb, bi->offset);
  nsat = get_masked_guint8(data, MASK_NSAT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_NSAT);
  proto_item_append_text(pi, "NSAT: %u", value);

  value = get_masked_guint8(data, MASK_T_TOE_LIMIT);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_T_TOE_LIMIT);
  proto_item_append_text(pi, "T-Toe Limit: %u", value);
  bi->offset++;

  for (i = 0; i < nsat; i++) {
    ti2 = proto_tree_add_text(tf, bi->tvb, bi->offset, 2, "Satellite %u", i);
    tf2 = proto_item_add_subtree(ti2, ett_bssgp_requested_gps_assistance_data_satellite);

    value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_SAT_ID);
    pi = proto_tree_add_bitfield8(tf2, bi->tvb, bi->offset, MASK_SAT_ID);
    proto_item_append_text(pi, "SatId: %u", value);
    proto_item_append_text(ti2, ": Id %u", value);
    bi->offset++;

    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_tree_add_text(tf2, bi->tvb, bi->offset, 1,
			"IODE: %u", value);
    proto_item_append_text(ti2, ", IODE %u", value);
    bi->offset++;
  }
}

static void
decode_iei_location_type(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 LOCATION_ASSISTANCE = 1;
  const guint8 DECIPHERING_KEYS = 2;
  proto_item *ti;
  proto_tree *tf;
  guint8 value;

  static const value_string tab_location_information[] = {
    { 0, "Current geographic location" },
    { 1, "Location assistance information for the target MS" },
    { 2, "Deciphering keys for broadcast assistance data for the target MS" },
    { 0, NULL },
    /* Otherwise "Reserved" */
  };

  static const value_string tab_positioning_method[] = {
    { 0, "Reserved" },
    { 1, "Mobile Assisted E-OTD" },
    { 2, "Mobile Based E-OTD" },
    { 3, "Assisted GPS" },
    { 0, NULL },
    /* Otherwise "Reserved" */
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_location_type);

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, "Location Information: %s",
		      val_to_str(value, tab_location_information,
				 "Reserved"));
  bi->offset++;

  if ((value == LOCATION_ASSISTANCE) || (value == DECIPHERING_KEYS)) {
    value = tvb_get_guint8(bi->tvb, bi->offset);
    proto_tree_add_text(tf, bi->tvb, bi->offset, 1, "Positioning Method: %s",
			val_to_str(value, tab_positioning_method,
				   "Reserved"));
    bi->offset++;
  }
}

static void
decode_iei_location_estimate(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /* XXX: Which paragraph in 3GPP TS 23.032?*/
  proto_item *ti;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %s", BSSGP_NOT_DECODED);
  }
  if (ie->value_length != BSSGP_UNKNOWN) {
    bi->offset += ie->value_length;
  }
}

static void
decode_iei_positioning_data(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_PDD = 0x0f;
  const guint8 MASK_METHOD = 0xf8;
  const guint8 MASK_USAGE = 0x07;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value, i, num_methods;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_positioning_data);

  value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_PDD);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_PDD);
  proto_item_append_text(pi, "Positioning Data Discriminator: %s",
                         value == 0 ?
                         "Indicate usage of each positioning method that was attempted either successfully or unsuccessfully" :
                         "Reserved");
  bi->offset++;

  num_methods = ie->value_length - 1;
  for (i = 0; i < num_methods; i++) {
    data = tvb_get_guint8(bi->tvb, bi->offset);

    value = get_masked_guint8(data, MASK_METHOD);
    pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_METHOD);
    proto_item_append_text(pi, "Method: ");

    switch (value) {
    case 0: proto_item_set_text(pi, "Timing Advance"); break;
    case 1: proto_item_set_text(pi, "Reserved"); break;
    case 2: proto_item_set_text(pi, "Reserved"); break;
    case 3: proto_item_set_text(pi, "Mobile Assisted E-OTD"); break;
    case 4: proto_item_set_text(pi, "Mobile Based E-OTD"); break;
    case 5: proto_item_set_text(pi, "Mobile Assisted GPS"); break;
    case 6: proto_item_set_text(pi, "Mobile Based GPS"); break;
    case 7: proto_item_set_text(pi, "Conventional GPS"); break;
    case 8: proto_item_set_text(pi, "U-TDOA"); break;
    default:
      if ((value >= 9) && (value <= 0x0f)) {
	proto_item_set_text(pi, "Reserved for GSM");
      }
      else {
	proto_item_set_text(pi, "Reserved for network specific positioning methods");
      }
    }
    proto_item_append_text(pi, " (%#02x)", value); /* Method */

    value = get_masked_guint8(data, MASK_USAGE);

    switch (value) {
    case 0: proto_item_append_text(pi, " attempted unsuccessfully due to failure or interruption "); break;
    case 1: proto_item_append_text(pi, " attempted successfully: results not used to generate location"); break;
    case 2: proto_item_append_text(pi, " attempted successfully: results used to verify but not generate location"); break;
    case 3: proto_item_append_text(pi, " attempted successfully: results used to generate location"); break;
    case 4: proto_item_append_text(pi, " attempted successfully: case where MS supports multiple mobile based"
                                       " positioning methods and the actual method or methods used by the MS cannot be determined"); break;
    default: ; /* ??? */
    }
    proto_item_append_text(pi, " (%#x)", value); /* Usage */
    bi->offset++;
  }
}

static void
decode_iei_deciphering_keys(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_KEY_FLAG = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }

  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_deciphering_keys);

  data = tvb_get_guint8(bi->tvb, bi->offset);
  value = get_masked_guint8(data, MASK_KEY_FLAG);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_KEY_FLAG);
  proto_item_append_text(pi, "Ciphering Key Flag: %u", value);
  bi->offset++;

  proto_tree_add_text(tf, bi->tvb, bi->offset, 7,
		      "Current Deciphering Key Value");
  bi->offset += 7;

  proto_tree_add_text(tf, bi->tvb, bi->offset, 7,
		      "Next Deciphering Key Value");
  bi->offset += 7;
}

static void
decode_iei_lcs_priority(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /* XXX: coding (3GPP TS 29.002 7.6.11.7)? */
  proto_item *ti;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    proto_item_append_text(ti, ": %s", BSSGP_NOT_DECODED);
  }
  bi->offset += ie->value_length;
}

static void
decode_iei_lcs_cause(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  guint8 value;

  static const value_string tab_cause_value[] = {
    { 0, "Unspecified" },
    { 1, "System failure" },
    { 2, "Protocol error" },
    { 3, "Data missing in position request" },
    { 4, "Unexpected value in position request" },
    { 5, "Position method failure" },
    { 6, "Target MS unreachable" },
    { 7, "Location request aborted" },
    { 8, "Facility not supported" },
    { 9, "Inter-BSC handover ongoing" },
    { 10, "Intra-BSC handover ongoing" },
    { 11, "Congestion" },
    { 12, "Inter NSE cell change" },
    { 13, "Routing area update" },
    { 14, "PTMSI reallocation" },
    { 15, "Suspension of GPRS services" },
    { 0, NULL },
    /* Otherwise "Unspecified" */
  };

  static const value_string tab_diagnostic_value[] = {
    { 0, "Congestion" },
    { 1, "Insufficient resources" },
    { 2, "Insufficient measurement data" },
    { 3, "Inconsistent measurement data" },
    { 4, "Location procedure not completed" },
    { 5, "Location procedure not supported by target MS" },
    { 6, "QoS not attainable" },
    { 7, "Position method not available in network" },
    { 8, "Position method not available in location area" },
    { 0, NULL },
    /* Otherwise "Unrecognized => ignored" */
  };

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  value = tvb_get_guint8(bi->tvb, bi->offset);

  if (ie->value_length == 1) {
    /* Diagnostic value not included */
    proto_item_append_text(ti, ": %s (%#02x)",
                           val_to_str(value, tab_cause_value, "Unspecified"),
                           value);
    bi->offset++;
    return;
  }

  tf = proto_item_add_subtree(ti, ett_bssgp_lcs_cause);

  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, ": %s (%#02x)",
                      val_to_str(value, tab_cause_value, "Unspecified"),
                      value);
  bi->offset++;

  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1, ": %s (%#02x)",
                      val_to_str(value, tab_diagnostic_value,
                                 "Unrecognized => ignored"),
		      value);
  bi->offset++;
}

static void
decode_iei_lcs_capability(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_OTD_A = 0x10;
  const guint8 MASK_OTD_B = 0x08;
  const guint8 MASK_GPS_A = 0x04;
  const guint8 MASK_GPS_B = 0x02;
  const guint8 MASK_GPS_C = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_lcs_capability);

  data = tvb_get_guint8(bi->tvb, bi->offset);

  value = get_masked_guint8(data, MASK_OTD_A);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_OTD_A);
  proto_item_append_text(pi, "OTD-A: MS Assisted E-OTD%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_OTD_B);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_OTD_B);
  proto_item_append_text(pi, "OTD-B: MS Based E-OTD%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_GPS_A);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_GPS_A);
  proto_item_append_text(pi, "GPS-A: MS Assisted GPS%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_GPS_B);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_GPS_B);
  proto_item_append_text(pi, "GPS-B: MS Based GPS%s supported",
			 value == 0 ? " not" : "");

  value = get_masked_guint8(data, MASK_GPS_C);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_GPS_C);
  proto_item_append_text(pi, "GPS-C: Conventional GPS%s supported",
			 value == 0 ? " not" : "");

  bi->offset++;
}

static void
decode_iei_rrlp_flags(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_FLAG1 = 0x01;
  proto_item *ti;
  guint8 value;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    value = tvb_get_masked_guint8(bi->tvb, bi->offset, MASK_FLAG1);
    proto_item_append_text(ti, ": Flag1:%s Position Command (BSS to SGSN) or final response (SGSN to BSS) (%u)",
			   value == 0 ? " Not a" : "", value);
  }
  bi->offset++;
}

static void /* [7] 11.3.61 RIM Application Identity */
decode_iei_rim_application_identity(bssgp_ie_t *ie _U_, build_info_t *bi, int ie_start_offset _U_) {
  proto_item *ti;
  guint8 appid;

  if (!bi->bssgp_tree) {
    bi->offset += 8;
    return;
  }

  ti = proto_tree_add_item(bi->bssgp_tree, hf_bssgp_appid,
                           bi->tvb, bi->offset, 1, ENC_BIG_ENDIAN);

  appid = tvb_get_guint8(bi->tvb, bi->offset);
  switch (appid) {
  case 0: proto_item_append_text(ti, " - Reserved"); break;
  case 1: proto_item_append_text(ti, " - Network Assisted Cell Change (NACC)"); break;
  case 0x10: proto_item_append_text(ti, " - System Information 3 (SI3)"); break;
  case 0x11: proto_item_append_text(ti, " - MBMS data channel"); break;
  default: proto_item_append_text(ti, " - Reserved");
  }
  bi->offset++;

}

#if 0
static void
decode_ran_information_common(build_info_t *bi, proto_tree *parent_tree) {
  proto_tree *tf;
  proto_item *ti;
  char *rai_ci;
  guint8 num_rai_cis, i;

  ti = proto_tree_add_text(parent_tree, bi->tvb, bi->offset, 8,
			   "RAI + CI for Source Cell");
  tf = proto_item_add_subtree(ti, ett_bssgp_rai_ci);

  rai_ci = decode_rai_ci(bi, tf);
  proto_item_append_text(ti, ": %s", rai_ci);

  num_rai_cis = tvb_get_guint8(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 1,
		      "%u ""RAI+CI for Destination Cell"" follow%s",
		      num_rai_cis, (num_rai_cis == 0) ? "" : "s");
  bi->offset++;

  for (i = 0; i < num_rai_cis; i++) {
    ti = proto_tree_add_text(parent_tree, bi->tvb, bi->offset, 8,
			     """RAI + CI for Destination Cell"" (%u)", i + 1);
    tf = proto_item_add_subtree(ti, ett_bssgp_rai_ci);
    rai_ci = decode_rai_ci(bi, tf);
    proto_item_append_text(ti, ": %s", rai_ci);
  }
}
#endif

/*
 * 11.3.77 RIM Routing Information
 */
static const value_string ra_discriminator_vals[] = {
  { 0, "A Cell Identifier is used to identify a GERAN cell" },
  { 1, "A Global RNC-ID is used to identify a UTRAN RNC" },
  { 0, NULL },
};

static void
decode_iei_rim_routing_information(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  guint8 data;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    tf = proto_item_add_subtree(ti, ett_bssgp_rim_routing_information);

    proto_tree_add_item(tf, hf_bssgp_ra_discriminator,
                        bi->tvb, bi->offset, 1, ENC_BIG_ENDIAN);

    data = tvb_get_guint8(bi->tvb, bi->offset);

    bi->offset += 1;

    decode_rai(bi, tf);

    proto_tree_add_item(tf, hf_bssgp_ci,
		      bi->tvb, bi->offset, 2, ENC_BIG_ENDIAN);
    bi->offset += 2;

  } else {
    bi->offset += ie->value_length;
  }

}

static void  /* [7] 11.62a.1 */
decode_iei_ran_container_unit(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;

  if (!bi->bssgp_tree) {
    bi->offset += 8;
    return;
  }

  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_ran_information_request_container_unit);
}

static void
decode_iei_application_error(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    tf = proto_item_add_subtree(ti, ett_bssgp_ran_information_container_unit);

    proto_tree_add_item(tf, hf_bssgp_iei_nacc_cause, bi->tvb, bi->offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_text(tf, bi->tvb, bi->offset, tvb_length(bi->tvb) - bi->offset , "Erroneous Application Container including IEI and LI");

  } else {
    bi->offset += ie->value_length;
  }
}

/*
 * 11.3.63.1.1 RAN-INFORMATION-REQUEST Application Container for the NACC Application
 */
static void
decode_iei_ran_information_request_application_container(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  proto_tree *tf;
  char *rai_ci;

  if (bi->bssgp_tree) {
    ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
    tf = proto_item_add_subtree(ti, ett_bssgp_ran_information_container_unit);

    /*
     * Octet 3-10 Reporting Cell Identifier:
     * This field is encoded as the Cell Identifier defined in sub-clause 11.3.9
     */
    rai_ci = decode_rai_ci(bi, tf);
    proto_item_append_text(ti, ": %s", rai_ci);

  } else {
    bi->offset += ie->value_length;
  }
}
static void
decode_iei_ran_information_application_container(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  const guint8 MASK_NUMBER_OF_SI_PSI = 0xfe;
  const guint8 MASK_UNIT_TYPE = 0x01;
  const guint8 TYPE_SI = 0;
  const guint8 TYPE_PSI = 1;
  const guint8 LEN_SI = 21;
  const guint8 LEN_PSI = 22;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 num_si_psi, type_si_psi, data, i;

  if (! bi->bssgp_tree) {
    bi->offset += 8;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_ran_information_container_unit);

  /* don't work, ran_information_common read number of rai's but it is only one.
     decode_ran_information_common(bi, tf); */
  decode_rai_ci(bi,tf);

  data = tvb_get_guint8(bi->tvb, bi->offset);
  num_si_psi = get_masked_guint8(data, MASK_NUMBER_OF_SI_PSI);
  type_si_psi = get_masked_guint8(data, MASK_UNIT_TYPE);

  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset,
				MASK_NUMBER_OF_SI_PSI);
  proto_item_append_text(pi, "Number of SI/PSI: %u ""SI/PSI"" follow%s",
                         num_si_psi,
                         num_si_psi < 2 ? "s" : "");

  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_UNIT_TYPE);
  proto_item_append_text(pi, "Type: %s messages as specified for %s follow",
                         type_si_psi == TYPE_SI ? "SI" : "PSI",
                         type_si_psi == TYPE_SI ? "BCCH" : "PBCCH");

  bi->offset++;

  for (i = 0; i < num_si_psi; i++) {
    if (type_si_psi == TYPE_SI) {
      proto_tree_add_text(tf, bi->tvb, bi->offset, LEN_SI,
			  " SI (%u), %u octets", i + 1, LEN_SI);
      /* XXX: Not decoded yet; which section in 3GPP TS 44.018? */
      proto_tree_add_item(tf, hf_bssgp_rrc_si_msg_type, bi->tvb, bi->offset, 1, ENC_BIG_ENDIAN);
      /* TODO:
       * Add decoding in packet-gsm_a.c ? Needs a new exported function "gsm_a_decode_rr_message?)
       *
       */
      bi->offset += LEN_SI;
    }
    else if (type_si_psi == TYPE_PSI) {
      proto_tree_add_text(tf, bi->tvb, bi->offset, LEN_PSI,
			  " PSI (%u), %u octets", i + 1, LEN_PSI);
      /* XXX: Not decoded yet; which section in 3GPP TS 44.060?

	  System information messages: Reference
          Packet System Information Type 1 11.2.18
          Packet System Information Type 2 11.2.19
          Packet System Information Type 3 11.2.20
          Packet System Information Type 3 bis 11.2.21
          Packet System Information Type 3 ter 11.2.21a
          Packet System Information Type 3 quater 11.2.21b
          Packet System Information Type 5 11.2.23
          Packet System Information Type 6 11.2.23a
          Packet System Information Type 7 11.2.23b
          Packet System Information Type 8 11.2.24
          Packet System Information Type 13 11.2.25
          Packet System Information Type 14 11.2.25a
          Packet System Information Type 15 11.2.25b
          Packet System Information Type 16 11.2.25c
      */
      bi->offset += LEN_PSI;
    }
  }
}
static const value_string ran_inf_req_pdu_type_ext_vals[] = {
  { 0,"RAN-INFORMATION-REQUEST/Stop PDU" },
  { 1,"RAN-INFORMATION-REQUEST/Single Report PDU" },
  { 2,"RAN-INFORMATION-REQUEST/Multiple Report PDU" },
  { 3,"Reserved" },
  { 4,"Reserved" },
  { 5,"Reserved" },
  { 6,"Reserved" },
  { 7,"Reserved" },
  { 0, NULL },
};

static const value_string ran_inf_pdu_type_ext_vals[] = {
  { 0,"RAN-INFORMATION/Stop PDU" },
  { 1,"RAN-INFORMATION/Single Report PDU" },
  { 2,"RAN-INFORMATION/Initial Multiple Report PDU" },
  { 3,"RAN-INFORMATION/Multiple Report PDU" },
  { 4,"RAN-INFORMATION/End PDU" },
  { 5,"Reserved" },
  { 6,"Reserved" },
  { 7,"Reserved" },
  { 0, NULL },
};
/* 11.3.65 RIM PDU Indications 3GPP TS 48.018 version 6.7.0 Release 6 */
static void
decode_iei_rim_pdu_indications(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  /**  const guint8 MASK_EXT = 0x0E; **/
  const guint8 MASK_ACK = 0x01;
  proto_item *ti, *pi;
  proto_tree *tf;
  guint8 data, value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_rim_pdu_indications);

  data = tvb_get_guint8(bi->tvb, bi->offset);

  if (bi->pdutype == BSSGP_IEI_RAN_INFORMATION_CONTAINER_UNIT) {
    proto_tree_add_item(tf, hf_ran_inf_pdu_type_ext, bi->tvb, bi->offset, 1, ENC_BIG_ENDIAN);
  }else{
    proto_tree_add_item(tf, hf_ran_inf_req_pdu_type_ext, bi->tvb, bi->offset, 1, ENC_BIG_ENDIAN);
  }

  value = get_masked_guint8(data, MASK_ACK);
  pi = proto_tree_add_bitfield8(tf, bi->tvb, bi->offset, MASK_ACK);
  proto_item_append_text(pi, "ACK: %sACK requested",
			 value == 0 ? "No " : "");
  bi->offset++;
}

static void
decode_iei_number_of_container_units(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_item *ti;
  guint8 value;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  value = tvb_get_guint8(bi->tvb, bi->offset);
  proto_item_append_text(ti, ": %u Container Unit%s follow%s",
			 value + 1,
			 value == 0 ? "" : "s",
			 value > 0 ? "s" : "");
  bi->offset++;
}

static void
decode_iei_pfc_flow_control_parameters(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_tree *tf, *tf2;
  proto_item *ti, *ti2, *pi;
  guint8 num_pfc, i, pfc_len;
  gboolean b_pfc_included;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_pfc_flow_control_parameters);

  num_pfc = tvb_get_guint8(bi->tvb, bi->offset);
  pi = proto_tree_add_text(bi->bssgp_tree, bi->tvb, bi->offset, 1,
			   "Number of PFCs: ");

  if (num_pfc < 12) {
    proto_item_append_text(pi, "%u", num_pfc);
  }
  else {
    proto_item_append_text(pi, "Reserved");
    return;
  }
  bi->offset++;
  if (num_pfc == 0) return;

  pfc_len = (ie->value_length - 1) / num_pfc;
  b_pfc_included = (pfc_len == 6);

  for (i = 0; i < num_pfc; i++) {
    ti2 = proto_tree_add_text(tf, bi->tvb, bi->offset, pfc_len,
			      "PFC (%u)", i + 1);
    tf2 = proto_item_add_subtree(ti2, ett_bssgp_pfc_flow_control_parameters_pfc);

    pi = proto_tree_add_text(tf2, bi->tvb, bi->offset, 1, "PFI");
    bssgp_pi_append_pfi(pi, bi->tvb, bi->offset);
    bi->offset++;

    pi = proto_tree_add_text(tf2, bi->tvb, bi->offset, 2, "BMax_PFC");
    bssgp_pi_append_bucket_size(pi, bi->tvb, bi->offset);
    bi->offset += 2;

    pi = proto_tree_add_text(tf2, bi->tvb, bi->offset, 2, "R_PFC");
    bssgp_pi_append_bucket_leak_rate(pi, bi->tvb, bi->offset);
    bi->offset += 2;

    if (b_pfc_included) {
      pi = proto_tree_add_text(tf2, bi->tvb, bi->offset, 1, "B_PFC");
      bssgp_pi_append_bucket_full_ratio(pi, bi->tvb, bi->offset);
      bi->offset++;
    }
  }
}

static void
decode_iei_global_cn_id(bssgp_ie_t *ie, build_info_t *bi, int ie_start_offset) {
  proto_tree *ti;
  proto_tree *tf;
  guint16 value;
  char *mcc_mnc;

  if (!bi->bssgp_tree) {
    bi->offset += ie->value_length;
    return;
  }
  ti = bssgp_proto_tree_add_ie(ie, bi, ie_start_offset);
  tf = proto_item_add_subtree(ti, ett_bssgp_global_cn_id);

  mcc_mnc = decode_mcc_mnc(bi, tf);
  proto_item_append_text(ti, ": PLMN-Id %s", mcc_mnc);

  value = tvb_get_ntohs(bi->tvb, bi->offset);
  proto_tree_add_text(tf, bi->tvb, bi->offset, 2,
		      "CN-ID: %u", value);
  proto_item_append_text(ti, ", CN-Id %u", value);
  bi->offset += 2;
}

static void
decode_ie(bssgp_ie_t *ie, build_info_t *bi) {
  int org_offset = bi->offset;

  if (tvb_length_remaining(bi->tvb, bi->offset) < 1) {
    /* TODO This code does not work well with omitted Optional elements
       proto_tree_add_none_format(bi->bssgp_tree, NULL, bi->tvb, 0, -1, "[tvb_length_remaining] length remaining: %d", tvb_length_remaining(bi->tvb, bi->offset));
    */
    return;
  }
  switch (ie->format) {
  case BSSGP_IE_FORMAT_TLV:
    if (!check_correct_iei(ie, bi)) {
#ifdef BSSGP_DEBUG
      /* TODO This code does not work well with omitted Optional elements */
      proto_tree_add_none_format(bi->bssgp_tree, NULL, bi->tvb, 0, -1, "[BSSGP_IE_FORMAT_TLV] format: %d", ie->format);
#endif
      return;
    }
    bi->offset++; /* Account for type */
    ie->total_length = 1;
    get_value_length(ie, bi);
    break;
  case BSSGP_IE_FORMAT_TV:
    if (!check_correct_iei(ie, bi)) {
#ifdef BSSGP_DEBUG
      /* TODO This code does not work well with omitted Optional elements */
      proto_tree_add_none_format(bi->bssgp_tree, NULL, bi->tvb, 0, -1, "[BSSGP_IE_FORMAT_TV] format: %d", ie->format);
#endif
      return;
    }
    bi->offset++; /* Account for type */
    ie->value_length = ie->total_length - 1;
    break;
  case BSSGP_IE_FORMAT_V:
    ie->value_length = ie->total_length;
    break;
  default:
    ;
  }

  switch (ie->iei) {
  case BSSGP_IEI_ALIGNMENT_OCTETS:
    decode_iei_alignment_octets(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BMAX_DEFAULT_MS:
    decode_bucket_size(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BSS_AREA_INDICATION:
    /* XXX: 'The recipient shall ignore the value of this octet'??? */
    decode_simple_ie(ie, bi, org_offset, "BSS Indicator", "", TRUE);
    break;
  case BSSGP_IEI_BUCKET_LEAK_RATE:
    decode_bucket_leak_rate(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BVCI:
    decode_iei_bvci(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BVC_BUCKET_SIZE:
    decode_bucket_size(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BVC_MEASUREMENT:
    decode_queuing_delay(ie, bi, org_offset);
    break;
  case BSSGP_IEI_CAUSE:
    decode_iei_cause(ie, bi, org_offset);
    break;
  case BSSGP_IEI_CELL_IDENTIFIER:
    decode_iei_cell_identifier(ie, bi, org_offset);
    break;
  case BSSGP_IEI_CHANNEL_NEEDED:
    decode_iei_channel_needed(ie, bi, org_offset);
    break;
  case BSSGP_IEI_DRX_PARAMETERS:
    decode_iei_drx_parameters(ie, bi, org_offset);
    break;
  case BSSGP_IEI_EMLPP_PRIORITY:
    decode_iei_emlpp_priority(ie, bi, org_offset);
    break;
  case BSSGP_IEI_FLUSH_ACTION:
    decode_iei_flush_action(ie, bi, org_offset);
    break;
  case BSSGP_IEI_IMSI:
    decode_mobile_identity(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LLC_PDU:
    bssgp_proto_handoff(ie, bi, org_offset, llc_handle);
    break;
  case BSSGP_IEI_LLC_FRAMES_DISCARDED:
    decode_iei_llc_frames_discarded(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LOCATION_AREA:
    decode_iei_location_area(ie, bi, org_offset);
    break;
  case BSSGP_IEI_MOBILE_ID:
    decode_mobile_identity(ie, bi, org_offset);
    break;
  case BSSGP_IEI_MS_BUCKET_SIZE:
    decode_bucket_size(ie, bi, org_offset);
    break;
  case BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY:
    decode_iei_ms_radio_access_capability(ie, bi, org_offset);
    break;
  case BSSGP_IEI_OMC_ID:
    decode_iei_omc_id(ie, bi, org_offset);
    break;
  case BSSGP_IEI_PDU_IN_ERROR:
    decode_iei_pdu_in_error(ie, bi, org_offset);
    break;
  case BSSGP_IEI_PDU_LIFETIME:
    decode_queuing_delay(ie, bi, org_offset);
    break;
  case BSSGP_IEI_PRIORITY:
    decode_iei_priority(ie, bi, org_offset);
    break;
  case BSSGP_IEI_QOS_PROFILE:
    decode_iei_qos_profile(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RADIO_CAUSE:
    decode_iei_radio_cause(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RA_CAP_UPD_CAUSE:
    decode_iei_ra_cap_upd_cause(ie, bi, org_offset);
    break;
  case BSSGP_IEI_ROUTING_AREA:
    decode_iei_routing_area(ie, bi, org_offset);
    break;
  case BSSGP_IEI_R_DEFAULT_MS:
    decode_bucket_leak_rate(ie, bi, org_offset);
    break;
  case BSSGP_IEI_SUSPEND_REFERENCE_NUMBER:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_TAG:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_TLLI:
    decode_iei_tlli(ie, bi, org_offset);
    break;
  case BSSGP_IEI_TMSI:
    decode_iei_tmsi(ie, bi, org_offset);
    break;
  case BSSGP_IEI_TRACE_REFERENCE:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_TRACE_TYPE:
    /* XXX: Coding unknown (Specification withdrawn) 3GPP TS 32.008 */
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_TRANSACTION_ID:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_TRIGGER_ID:
    decode_iei_trigger_id(ie, bi, org_offset);
    break;
  case BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_LSA_IDENTIFIER_LIST:
    decode_iei_lsa_identifier_list(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LSA_INFORMATION:
    decode_iei_lsa_information(ie, bi, org_offset);
    break;
  case BSSGP_IEI_PFI:
    decode_pfi(ie, bi, org_offset);
    break;
  case BSSGP_IEI_GPRS_TIMER:
    decode_iei_gprs_timer(ie, bi, org_offset);
    break;
  case BSSGP_IEI_ABQP:
    decode_iei_abqp(ie, bi, org_offset);
    break;
  case BSSGP_IEI_FEATURE_BITMAP:
    decode_iei_feature_bitmap(ie, bi, org_offset);
    break;
  case BSSGP_IEI_BUCKET_FULL_RATIO:
    decode_iei_bucket_full_ratio(ie, bi, org_offset);
    break;
  case BSSGP_IEI_SERVICE_UTRAN_CCO:
    decode_iei_service_utran_cco(ie, bi, org_offset);
    break;
  case BSSGP_IEI_NSEI:
    decode_iei_nsei(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RRLP_APDU:
    bssgp_proto_handoff(ie, bi, org_offset, rrlp_handle);
    break;
  case BSSGP_IEI_LCS_QOS:
    decode_iei_lcs_qos(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LCS_CLIENT_TYPE:
    decode_iei_lcs_client_type(ie, bi, org_offset);
    break;
  case BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA:
    decode_iei_requested_gps_assistance_data(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LOCATION_TYPE:
    decode_iei_location_type(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LOCATION_ESTIMATE:
    decode_iei_location_estimate(ie, bi, org_offset);
    break;
  case BSSGP_IEI_POSITIONING_DATA:
    decode_iei_positioning_data(ie, bi, org_offset);
    break;
  case BSSGP_IEI_DECIPHERING_KEYS:
    decode_iei_deciphering_keys(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LCS_PRIORITY:
    decode_iei_lcs_priority(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LCS_CAUSE:
    decode_iei_lcs_cause(ie, bi, org_offset);
    break;
  case BSSGP_IEI_LCS_CAPABILITY:
    decode_iei_lcs_capability(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RRLP_FLAGS:
    decode_iei_rrlp_flags(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RIM_ROUTING_INFORMATION:
    decode_iei_rim_routing_information(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RIM_APPLICATION_IDENTITY:
    decode_iei_rim_application_identity(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RIM_SEQUENCE_NUMBER:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;
  case BSSGP_IEI_RIM_PROTOCOL_VERSION:
    decode_simple_ie(ie, bi, org_offset, "", "", TRUE);
    break;

  case BSSGP_IEI_RAN_INFORMATION_REQUEST_APPLICATION_CONTAINER:
    decode_iei_ran_information_request_application_container(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RAN_INFORMATION_APPLICATION_CONTAINER:
    decode_iei_ran_information_application_container(ie, bi, org_offset);
    break;

  case BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT:
    decode_iei_ran_container_unit(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RAN_INFORMATION_CONTAINER_UNIT:
    decode_iei_ran_container_unit(ie, bi, org_offset);
    break;
  case  BSSGP_IEI_RAN_INFORMATION_APPLICATION_ERROR_CONTAINER_UNIT:
    decode_iei_ran_container_unit(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RAN_INFORMATION_ACK_RIM_CONTAINER:
    decode_iei_ran_container_unit(ie, bi, org_offset);
    break;
  case BSSGP_IEI_RAN_INFORMATION_ERROR_RIM_CONTAINER:
    decode_iei_ran_container_unit(ie, bi, org_offset);
    break;

  case BSSGP_IEI_APPLICATION_ERROR_CONTAINER:
    decode_iei_application_error(ie, bi, org_offset);
    break;


  case BSSGP_IEI_RIM_PDU_INDICATIONS:
    decode_iei_rim_pdu_indications(ie, bi, org_offset);
    break;
  case BSSGP_IEI_NUMBER_OF_CONTAINER_UNITS:
    decode_iei_number_of_container_units(ie, bi, org_offset);
    break;
  case BSSGP_IEI_PFC_FLOW_CONTROL_PARAMETERS:
    decode_iei_pfc_flow_control_parameters(ie, bi, org_offset);
    break;
  case BSSGP_IEI_GLOBAL_CN_ID:
    decode_iei_global_cn_id(ie, bi, org_offset);
    break;
  default:
    ;
  }
}

static void
decode_pdu_general(bssgp_ie_t *ies, int num_ies, build_info_t *bi) {
  int i;
  for (i = 0; i < num_ies; i++) {
    decode_ie(&ies[i], bi);
  }
}

static void
decode_pdu_dl_unitdata(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, "TLLI (current)",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_V, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_QOS_PROFILE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_V, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_PDU_LIFETIME, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4},

    { BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},

    { BSSGP_IEI_PRIORITY, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3},

    { BSSGP_IEI_DRX_PARAMETERS, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4},

    { BSSGP_IEI_IMSI, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},

    { BSSGP_IEI_TLLI, "TLLI (old)",
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6},

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3},

    { BSSGP_IEI_LSA_INFORMATION, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},

    { BSSGP_IEI_SERVICE_UTRAN_CCO, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3},

    { BSSGP_IEI_ALIGNMENT_OCTETS, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},

    { BSSGP_IEI_LLC_PDU, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 13, bi);
}

static void
decode_pdu_ul_unitdata(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_V, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_QOS_PROFILE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_V, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CELL_IDENTIFIER, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_LSA_IDENTIFIER_LIST, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_ALIGNMENT_OCTETS, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LLC_PDU, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 7, bi);
}

static void
decode_pdu_ra_capability(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu_ptm_unitdata(build_info_t *bi) {
  proto_tree_add_text(bi->bssgp_tree, bi->tvb, bi->offset, -1,
		      "This shall be developed in GPRS phase 2");
}

static void
decode_pdu_paging_ps(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_IMSI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_DRX_PARAMETERS, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BVCI, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_LOCATION_AREA, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 7 },

    { BSSGP_IEI_ROUTING_AREA, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_BSS_AREA_INDICATION, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_ABQP, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_QOS_PROFILE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 5 },

    { BSSGP_IEI_TMSI, "P-TMSI",
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 10, bi);
}

static void
decode_pdu_paging_cs(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_IMSI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_DRX_PARAMETERS, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BVCI, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_LOCATION_AREA, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 7 },

    { BSSGP_IEI_ROUTING_AREA, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_BSS_AREA_INDICATION, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_CHANNEL_NEEDED, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_EMLPP_PRIORITY, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_TMSI, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_GLOBAL_CN_ID, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 7 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 11, bi);
}

static void
decode_pdu_ra_capability_update(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu_ra_capability_update_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_IMSI, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_RA_CAP_UPD_CAUSE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN},
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 5, bi);
}

static void
decode_pdu_radio_status(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TMSI, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_IMSI, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_RADIO_CAUSE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 4, bi);
}

static void
decode_pdu_suspend(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTING_AREA, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 2, bi);
}

void
decode_pdu_suspend_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTING_AREA, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_SUSPEND_REFERENCE_NUMBER, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_suspend_nack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTING_AREA, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_CAUSE, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_resume(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTING_AREA, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_SUSPEND_REFERENCE_NUMBER, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_resume_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTING_AREA, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu_resume_nack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_ROUTING_AREA, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 8 },

    { BSSGP_IEI_CAUSE, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_bvc_block(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_CAUSE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu_bvc_block_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4},
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 1, bi);
}

static void
decode_pdu_bvc_reset(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_CAUSE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CELL_IDENTIFIER, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_FEATURE_BITMAP, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 4, bi);
}

static void
decode_pdu_bvc_reset_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_CELL_IDENTIFIER, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_FEATURE_BITMAP, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_bvc_unblock(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 1, bi);
}

static void
decode_pdu_bvc_unblock_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_BVCI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 1, bi);
}

static void
decode_pdu_flow_control_bvc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TAG, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_BVC_BUCKET_SIZE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_LEAK_RATE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BMAX_DEFAULT_MS, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_R_DEFAULT_MS, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_FULL_RATIO, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_BVC_MEASUREMENT, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 7, bi);
}

static void
decode_pdu_flow_control_bvc_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TAG, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 1, bi);
}

static void
decode_pdu_flow_control_ms(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_MS_BUCKET_SIZE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_LEAK_RATE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_FULL_RATIO, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 5, bi);
}

static void
decode_pdu_flow_control_ms_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu_flush_ll(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_BVCI, "BVCI (old)",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BVCI, "BVCI (new)",
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_NSEI, "NSEI (new)",
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 4, bi);
}

static void
decode_pdu_flush_ll_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_FLUSH_ACTION, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_BVCI, "BVCI (new)",
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 5 },

    { BSSGP_IEI_NSEI, "NSEI (new)",
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 5, bi);
}

static void
decode_pdu_llc_discarded(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_LLC_FRAMES_DISCARDED, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_BVCI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED, "Number of octets deleted",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 5 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 5, bi);
}

static void
decode_pdu_flow_control_pfc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_MS_BUCKET_SIZE, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_LEAK_RATE, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BUCKET_FULL_RATIO, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_PFC_FLOW_CONTROL_PARAMETERS, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 6, bi);
}

static void
decode_pdu_flow_control_pfc_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_TAG, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu_sgsn_invoke_trace(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TRACE_TYPE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_TRACE_REFERENCE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_TRIGGER_ID, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_MOBILE_ID, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_OMC_ID, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_TRANSACTION_ID, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 6, bi);
}

static void
decode_pdu_status(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_CAUSE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_BVCI, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_PDU_IN_ERROR, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_download_bss_pfc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 2, bi);
}

/* 10.4.17 CREATE-BSS-PFC */
static void
decode_pdu_create_bss_pfc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_IMSI, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_GPRS_TIMER, "PFT",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_ABQP, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_SERVICE_UTRAN_CCO, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_PRIORITY, "Allocation/Retention Priority",
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_GPRS_TIMER, "T10",
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
    /* Inter RAT Handover Info 11.3.94 3GPP TS 48.018 version 6.11.0 Release 6 */
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 9, bi);
}

static void
decode_pdu_create_bss_pfc_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_ABQP, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_CAUSE, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 4, bi);
}

static void
decode_pdu_create_bss_pfc_nack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CAUSE, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_modify_bss_pfc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_ABQP, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_modify_bss_pfc_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_GPRS_TIMER, "PFT",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_ABQP, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 4, bi);
}

static void
decode_pdu_delete_bss_pfc(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 2, bi);
}

static void
decode_pdu_delete_bss_pfc_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 2, bi);
}
/*
 * 10.4.26 DELETE-BSS-PFC-REQ
 */
static void
decode_pdu_delete_bss_pfc_req(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_PFI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CAUSE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_perform_location_request(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_IMSI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_DRX_PARAMETERS, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_BVCI, "BVCI (PCU-PTP)",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_NSEI, "NSEI (PCU-PTP)",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LOCATION_TYPE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_CELL_IDENTIFIER, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_LCS_CAPABILITY, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LCS_PRIORITY, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LCS_QOS, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LCS_CLIENT_TYPE, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_REQUESTED_GPS_ASSISTANCE_DATA, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 12, bi);
}

static void
decode_pdu_perform_location_response(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_BVCI, "BVCI (PCU-PTP)",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_LOCATION_ESTIMATE, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_POSITIONING_DATA, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_DECIPHERING_KEYS, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LCS_CAUSE, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 6, bi);
}

static void
decode_pdu_perform_location_abort(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_BVCI, "BVCI (PCU-PTP)",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_LCS_CAUSE, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 3, bi);
}

static void
decode_pdu_position_command(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_BVCI, "BVCI (PCU-PTP)",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_RRLP_FLAGS, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RRLP_APDU, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = FALSE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 4, bi);
}

static void
decode_pdu_position_response(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_TLLI, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_BVCI, "BVCI (PCU-PTP)",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

    { BSSGP_IEI_RRLP_FLAGS, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RRLP_APDU, NULL,
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

    { BSSGP_IEI_LCS_CAUSE, NULL,
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = FALSE;

  decode_pdu_general(ies, 5, bi);
}


static void
decode_pdu_ran_information(build_info_t *bi) {
  bssgp_ie_t ies[] = {

    { BSSGP_IEI_RIM_ROUTING_INFORMATION, "Destination Cell Identifier",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RIM_ROUTING_INFORMATION, "Source Cell Identifier",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RAN_INFORMATION_CONTAINER_UNIT, "RAN-INFORMATION RIM Container",
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 2 },

    { BSSGP_IEI_RIM_APPLICATION_IDENTITY, "Application Identity",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RIM_SEQUENCE_NUMBER, "Sequence Number",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_RIM_PDU_INDICATIONS, "PDU Indications",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RIM_PROTOCOL_VERSION, "Protocol Version",
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RAN_INFORMATION_APPLICATION_CONTAINER, "RAN-INFORMATION RIM Container",
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

  };

  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 8, bi);
}

static void
decode_pdu_ran_information_request(build_info_t *bi) {

  bssgp_ie_t ies[] = {

    { BSSGP_IEI_RIM_ROUTING_INFORMATION, "Destination Cell Identifier",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RIM_ROUTING_INFORMATION, "Source Cell Identifier",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT, "RAN-INFORMATION-REQUEST RIM Container",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 2 },

    { BSSGP_IEI_RIM_APPLICATION_IDENTITY, "Application Identity",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RIM_SEQUENCE_NUMBER, "Sequence Number",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_RIM_PDU_INDICATIONS, "PDU Indications",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RIM_PROTOCOL_VERSION, "Protocol Version",
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RAN_INFORMATION_REQUEST_APPLICATION_CONTAINER, "RAN-INFORMATION-REQUEST Application Container",
      BSSGP_IE_PRESENCE_O, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

  };

  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 8, bi);

}

static void
decode_pdu_ran_information_ack(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_RIM_ROUTING_INFORMATION, "Destination Cell Identifier",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RIM_ROUTING_INFORMATION, "Source Cell Identifier",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT, "RAN-INFORMATION-ACK RIM Container",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 2 },

    { BSSGP_IEI_RIM_APPLICATION_IDENTITY, "Application Identity",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RIM_SEQUENCE_NUMBER, "Sequence Number",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_RIM_PROTOCOL_VERSION, "Protocol Version",
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 4 },

  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 6, bi);
}

static void
decode_pdu_ran_information_error(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_RIM_ROUTING_INFORMATION, "Destination Cell Identifier",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RIM_ROUTING_INFORMATION, "Source Cell Identifier",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT, "RAN-INFORMATION-ERROR RIM Container",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 2 },

    { BSSGP_IEI_RIM_APPLICATION_IDENTITY, "Application Identity",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_CAUSE, "RIM Cause",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RIM_PROTOCOL_VERSION, "Protocol Version",
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_PDU_IN_ERROR, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },
  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 7, bi);
}

static void
decode_pdu_ran_information_application_error(build_info_t *bi) {
  bssgp_ie_t ies[] = {
    { BSSGP_IEI_RIM_ROUTING_INFORMATION, "Destination Cell Identifier",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RIM_ROUTING_INFORMATION, "Source Cell Identifier",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 10 },

    { BSSGP_IEI_RAN_INFORMATION_REQUEST_CONTAINER_UNIT, "RAN-INFORMATION-APPLICATION RIM Container",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 2 },

    { BSSGP_IEI_RIM_APPLICATION_IDENTITY, "Application Identity",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    /* pdu indication, I hope RIM_PDU_INDICATIONS decode it right, it use the same IEI so it should... */
    { BSSGP_IEI_RIM_PDU_INDICATIONS, "PDU Indications",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_RIM_SEQUENCE_NUMBER, "Sequence Number",
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 6 },

    { BSSGP_IEI_RIM_PROTOCOL_VERSION, "Protocol Version",
      BSSGP_IE_PRESENCE_C, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, 3 },

    { BSSGP_IEI_APPLICATION_ERROR_CONTAINER, NULL,
      BSSGP_IE_PRESENCE_M, BSSGP_IE_FORMAT_TLV, BSSGP_UNKNOWN, BSSGP_UNKNOWN },

  };
  bi->dl_data = TRUE;
  bi->ul_data = TRUE;

  decode_pdu_general(ies, 8, bi);
}


static void
decode_pdu(build_info_t *bi) {

  switch (bi->pdutype) {
  case BSSGP_PDU_DL_UNITDATA:
    decode_pdu_dl_unitdata(bi);
    break;
  case BSSGP_PDU_UL_UNITDATA:
    decode_pdu_ul_unitdata(bi);
    break;
  case BSSGP_PDU_RA_CAPABILITY:
    decode_pdu_ra_capability(bi);
    break;
  case BSSGP_PDU_PTM_UNITDATA:
    decode_pdu_ptm_unitdata(bi);
    break;
  case BSSGP_PDU_PAGING_PS:
    decode_pdu_paging_ps(bi);
    break;
  case BSSGP_PDU_PAGING_CS:
    decode_pdu_paging_cs(bi);
    break;
  case BSSGP_PDU_RA_CAPABILITY_UPDATE:
    decode_pdu_ra_capability_update(bi);
    break;
  case BSSGP_PDU_RA_CAPABILITY_UPDATE_ACK:
    decode_pdu_ra_capability_update_ack(bi);
    break;
  case BSSGP_PDU_RADIO_STATUS:
    decode_pdu_radio_status(bi);
    break;
  case BSSGP_PDU_SUSPEND:
    decode_pdu_suspend(bi);
    break;
  case BSSGP_PDU_SUSPEND_ACK:
    decode_pdu_suspend_ack(bi);
    break;
  case BSSGP_PDU_SUSPEND_NACK:
    decode_pdu_suspend_nack(bi);
    break;
  case BSSGP_PDU_RESUME:
    decode_pdu_resume(bi);
    break;
  case BSSGP_PDU_RESUME_ACK:
    decode_pdu_resume_ack(bi);
    break;
  case BSSGP_PDU_RESUME_NACK:
    decode_pdu_resume_nack(bi);
    break;
  case BSSGP_PDU_BVC_BLOCK:
    decode_pdu_bvc_block(bi);
    break;
  case BSSGP_PDU_BVC_BLOCK_ACK:
    decode_pdu_bvc_block_ack(bi);
    break;
  case BSSGP_PDU_BVC_RESET:
    decode_pdu_bvc_reset(bi);
    break;
  case BSSGP_PDU_BVC_RESET_ACK:
    decode_pdu_bvc_reset_ack(bi);
    break;
  case BSSGP_PDU_BVC_UNBLOCK:
    decode_pdu_bvc_unblock(bi);
    break;
  case BSSGP_PDU_BVC_UNBLOCK_ACK:
    decode_pdu_bvc_unblock_ack(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_BVC:
    decode_pdu_flow_control_bvc(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_BVC_ACK:
    decode_pdu_flow_control_bvc_ack(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_MS:
    decode_pdu_flow_control_ms(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_MS_ACK:
    decode_pdu_flow_control_ms_ack(bi);
    break;
  case BSSGP_PDU_FLUSH_LL:
    decode_pdu_flush_ll(bi);
    break;
  case BSSGP_PDU_FLUSH_LL_ACK:
    decode_pdu_flush_ll_ack(bi);
    break;
  case BSSGP_PDU_LLC_DISCARDED:
    decode_pdu_llc_discarded(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_PFC:
    decode_pdu_flow_control_pfc(bi);
    break;
  case BSSGP_PDU_FLOW_CONTROL_PFC_ACK:
    decode_pdu_flow_control_pfc_ack(bi);
    break;
  case BSSGP_PDU_SGSN_INVOKE_TRACE:
    decode_pdu_sgsn_invoke_trace(bi);
    break;
  case BSSGP_PDU_STATUS:
    decode_pdu_status(bi);
    break;
  case BSSGP_PDU_DOWNLOAD_BSS_PFC:
    decode_pdu_download_bss_pfc(bi);
    break;
  case BSSGP_PDU_CREATE_BSS_PFC:
    decode_pdu_create_bss_pfc(bi);
    break;
  case BSSGP_PDU_CREATE_BSS_PFC_ACK:
    decode_pdu_create_bss_pfc_ack(bi);
    break;
  case BSSGP_PDU_CREATE_BSS_PFC_NACK:
    decode_pdu_create_bss_pfc_nack(bi);
    break;
  case BSSGP_PDU_MODIFY_BSS_PFC:
    decode_pdu_modify_bss_pfc(bi);
    break;
  case BSSGP_PDU_MODIFY_BSS_PFC_ACK:
    decode_pdu_modify_bss_pfc_ack(bi);
    break;
  case BSSGP_PDU_DELETE_BSS_PFC:
    decode_pdu_delete_bss_pfc(bi);
    break;
  case BSSGP_PDU_DELETE_BSS_PFC_ACK:
    decode_pdu_delete_bss_pfc_ack(bi);
    break;
  case BSSGP_PDU_DELETE_BSS_PFC_REQ:
    decode_pdu_delete_bss_pfc_req(bi);
    break;
#if 0
  case BSSGP_PDU_PS_HANDOVER_REQUIRED:
	decode_pdu_ps_handover_required(bi);
	break;
  case BSSGP_PDU_PS_HANDOVER_REQUIRED_ACK:
  case BSSGP_PDU_PS_HANDOVER_REQUIRED_NACK:
  case BSSGP_PDU_PS_HANDOVER_REQUEST:
  case BSSGP_PDU_PS_HANDOVER_REQUEST_ACK:
  case BSSGP_PDU_PS_HANDOVER_REQUEST_NACK:
	break;
#endif
  case BSSGP_PDU_PERFORM_LOCATION_REQUEST:
    decode_pdu_perform_location_request(bi);
    break;
  case BSSGP_PDU_PERFORM_LOCATION_RESPONSE:
    decode_pdu_perform_location_response(bi);
    break;
  case BSSGP_PDU_PERFORM_LOCATION_ABORT:
    decode_pdu_perform_location_abort(bi);
    break;
  case BSSGP_PDU_POSITION_COMMAND:
    decode_pdu_position_command(bi);
    break;
  case BSSGP_PDU_POSITION_RESPONSE:
    decode_pdu_position_response(bi);
    break;
  case BSSGP_PDU_RAN_INFORMATION:
    decode_pdu_ran_information(bi);
    break;
  case BSSGP_PDU_RAN_INFORMATION_REQUEST:
    decode_pdu_ran_information_request(bi);
    break;
  case BSSGP_PDU_RAN_INFORMATION_ACK:
    decode_pdu_ran_information_ack(bi);
    break;
  case BSSGP_PDU_RAN_APPLICATION_ERROR:
    decode_pdu_ran_information_application_error(bi);
    break;
  case BSSGP_PDU_RAN_INFORMATION_ERROR:
    decode_pdu_ran_information_error(bi);
    break;
  default:
    ;
  }
}
/*
 * 11.3	Information Element Identifier (IEI)
 */

/*
 * 11.3.1	Alignment octets
 */
static guint16
de_bssgp_aligment_octets(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree, tvb, curr_offset, len, "%u Spare octet(s)",len);
	
	return(len);
}

/*
 * 11.3.2	Bmax default MS
 */
static guint16
de_bssgp_bmax_default_ms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_bmax, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;
	
	return(curr_offset-offset);
}
/*
 * 11.3.3	BSS Area Indication
 */
static guint16
de_bssgp_bss_area_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_bss_area_ind, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset++;
	
	return(curr_offset-offset);
}
/*
 * 11.3.4	Bucket Leak Rate (R)
 */
static guint16
de_bssgp_bucket_leak_rate(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_r, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;
	
	return(curr_offset-offset);
}
/*
 * 11.3.5	BVC Bucket Size
 */
static guint16
de_bssgp_bvc_bucket_size(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_bucket_size, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;
	
	return(curr_offset-offset);
}
/*
 * 11.3.6	BVCI (BSSGP Virtual Connection Identifier)
 */
static guint16
de_bssgp_bvci(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* octet 3-4 Unstructured value */
	proto_tree_add_item(tree, hf_bssgp_bvci, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}
/*
 * 11.3.7	BVC Measurement
 */
static guint16
de_bssgp_bvc_meas(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* 	The Delay Value field is coded as a 16-bit integer value in units of centi-seconds (one hundredth of a second). This
	 * coding provides a range of over 10 minutes in increments of 10 ms. As a special case, the hexadecimal value 0xFFFF
	 *(decimal 65 535) shall be interpreted as "infinite delay".
	 */
	proto_tree_add_item(tree, hf_bssgp_delay_val, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}
/*
 * 11.3.8	Cause
 */
static const value_string bssgp_cause_vals[] = {
  { 0x00, "Processor overload" },
  { 0x01, "Equipment failure" },
  { 0x02, "Transit network service failure" },
  { 0x03, "Network service transmission capacity modified from zero kbps to greater than zero kbps" },
  { 0x04, "Unknown MS" },
  { 0x05, "BVCI unknown" },
  { 0x06, "Cell traffic congestion" },
  { 0x07, "SGSN congestion" },
  { 0x08, "O&M intervention" },
  { 0x09, "BVCI blocked" },
  { 0x0a, "PFC create failure" },
  { 0x0b, "PFC preempted" },
  { 0x0c, "ABQP no more supported" },
	
  { 0x0d, "Undefined - protocol error - unspecified" },
  { 0x0e, "Undefined - protocol error - unspecified" },
  { 0x0f, "Undefined - protocol error - unspecified" },
  { 0x10, "Undefined - protocol error - unspecified" },
  { 0x11, "Undefined - protocol error - unspecified" },
  { 0x12, "Undefined - protocol error - unspecified" },
  { 0x13, "Undefined - protocol error - unspecified" },
  { 0x14, "Undefined - protocol error - unspecified" },
  { 0x15, "Undefined - protocol error - unspecified" },
  { 0x16, "Undefined - protocol error - unspecified" },
  { 0x17, "Undefined - protocol error - unspecified" },
  { 0x18, "Undefined - protocol error - unspecified" },
  { 0x19, "Undefined - protocol error - unspecified" },
  { 0x1a, "Undefined - protocol error - unspecified" },
  { 0x1b, "Undefined - protocol error - unspecified" },
  { 0x1c, "Undefined - protocol error - unspecified" },
  { 0x1d, "Undefined - protocol error - unspecified" },
  { 0x1e, "Undefined - protocol error - unspecified" },
  { 0x1f, "Undefined - protocol error - unspecified" },

  { 0x20, "Semantically incorrect PDU" },
  { 0x21, "Invalid mandatory information" },
  { 0x22, "Missing mandatory IE" },
  { 0x23, "Missing conditional IE" },
  { 0x24, "Unexpected conditional IE" },
  { 0x25, "Conditional IE error" },
  { 0x26, "PDU not compatible with the protocol state" },
  { 0x27, "Protocol error - unspecified" },
  { 0x28, "PDU not compatible with the feature set" },
  { 0x29, "Requested information not available" },
  { 0x2a, "Unknown destination address" },
  { 0x2b, "Unknown RIM application identity" },
  { 0x2c, "Invalid container unit information" },
  { 0x2d, "PFC queuing" },
  { 0x2e, "PFC created successfully" },
  { 0x2f, "T12 expiry" },
  { 0x30, "MS under PS Handover treatment" },
  { 0x31, "Uplink quality" },
  { 0x32, "Uplink strength" },
  { 0x33, "Downlink quality" },
  { 0x34, "Downlink strength" },
  { 0x35, "Distance" },
  { 0x36, "Better cell" },
  { 0x37, "Traffic" },
  { 0x38, "Radio contact lost with MS" },
  { 0x39, "MS back on old channel" },
  { 0x3a, "T13 expiry" },
  { 0x3b, "T14 expiry" },
  { 0x3c, "Not all requested PFCs created" },
  { 0x3d, "CS cause" },
  { 0x3e, "Requested ciphering and/or integrity protection algorithms not supported" },
  { 0x3f, "Relocation failure in target system" },
  { 0x40, "Directed Retry" },
  { 0x41, "Time critical relocation" },
  { 0x42, "PS Handover Target not allowed" },
  { 0x43, "PS Handover not Supported in Target BSS or Target System" },
  { 0x44, "Incoming relocation not supported due to PUESBINE feature" },
  { 0x45, "DTM Handover - No CS resource" },
  { 0x46, "DTM Handover - PS Allocation failure" },
  { 0x47, "DTM Handover - T24 expiry" },
  { 0x48, "DTM Handover - Invalid CS Indication IE" },
  { 0x49, "DTM Handover - T23 expiry" },
  { 0x4a, "DTM Handover - MSC Error" },
  { 0x4b, "Invalid CSG cell" },
  { 0,    NULL },
};
static value_string_ext bssgp_cause_vals_ext = VALUE_STRING_EXT_INIT(bssgp_cause_vals);

static guint16
de_bssgp_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* 	The Delay Value field is coded as a 16-bit integer value in units of centi-seconds (one hundredth of a second). This
	 * coding provides a range of over 10 minutes in increments of 10 ms. As a special case, the hexadecimal value 0xFFFF
	 *(decimal 65 535) shall be interpreted as "infinite delay".
	 */
	proto_tree_add_item(tree, hf_bssgp_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+=1;

	return(curr_offset-offset);
}
/*
 * 11.3.9	Cell Identifier
 */
/*
 * octets 3-8 Octets 3 to 8 contain the value part (starting with octet 2) of the
 * Routing Area Identification IE defined in 3GPP TS 24.008, not
 * including 3GPP TS 24.008 IEI
 * Octets 9 and 10 contain the value part (starting with octet 2) of the
 * Cell Identity IE defined in 3GPP TS 24.008, not including
 * 3GPP TS 24.008 IEI (10.5.1.1)
 */

static guint16
de_bssgp_cell_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
	guint32	curr_offset;
	guint16 ci;

	curr_offset = offset;

	curr_offset = curr_offset + de_gmm_rai(tvb, tree, curr_offset , 6, add_string, string_len);
	/*Why doesn't this work? ( add_string will not contain RAI + CI ) 
	 * curr_offset = curr_offset + de_cell_id(tvb, tree, curr_offset , 2, add_string, string_len);
	 */
	ci = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_bssgp_ci, tvb, offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;
	if (add_string)
		g_snprintf(add_string, string_len, " %s, CI %u", add_string, ci);


	return(curr_offset-offset);
}
/*
 * 11.3.10	Channel needed
 */
/* Rest of element coded as the value part of the Channel Needed
 * PDU defined in 3GPP TS 29.018, not including 3GPP TS 29.018
 * IEI and 3GPP TS 29.018 length indicator
 * TS 29.018
 * The rest of the information element is coded as the IEI part and the
 * value part of the Channel Needed IE defined in 3GPP TS 44.018.
 */
static guint16
de_bssgp_chnl_needed(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string, int string_len)
{
	guint32	curr_offset;

	curr_offset = offset;

	curr_offset = de_rr_chnl_needed(tvb, tree, curr_offset, len , NULL, 0);

	return(curr_offset-offset);
}

/*
 * 11.3.11	DRX Parameters
 */
/*
 * Rest of element coded as the value part defined in
 * 3GPP TS 24.008, not including 3GPP TS 24.008 IEI and
 * 3GPP TS 24.008 octet length indicator
 */
/*
 * 11.3.12	eMLPP-Priority
 */
/*
 * Rest of element coded as the value part of the eMLPP-Priority IE
 * defined in 3GPP TS 48.008, not including 3GPP TS 48.008 IEI and
 * 3GPP TS 48.008 length indicator
 */
/*
 * 11.3.13	Flush Action
 */
static const value_string bssgp_flush_action_vals[] = {
    { 0x00, "LLC-PDU(s) deleted" },
    { 0x01, "LLC-PDU(s) transferred" },
    { 0,    NULL },
    /* Otherwise "Reserved" */
  };

static guint16
de_bssgp_flush_action(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Action value */
	proto_tree_add_item(tree, hf_bssgp_flush_action, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}
/*
 * 11.3.14	IMSI
 */
/* Octets 3-n contain an IMSI coded as the value part of the Mobile
 * Identity IE defined in 3GPP TS 24.008
 * (NOTE 1)
 * NOTE 1: The Type of identity field in the Mobile Identity IE shall be ignored by
 * the receiver.
 */
/*
 * 11.3.15	LLC-PDU
 */

static guint16
de_bssgp_llc_pdu(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t *next_tvb=NULL;
	guint32	curr_offset;

	curr_offset = offset;



	if(len > 0){
		next_tvb = tvb_new_subset_remaining(tvb, curr_offset);
		proto_tree_add_text(tree, tvb, curr_offset, len, "LLC Data");
	}

  if(next_tvb){
    if (llc_handle) {
      call_dissector(llc_handle, next_tvb, gpinfo, parent_tree);
    }
    else if (data_handle) {
      call_dissector(data_handle, next_tvb, gpinfo, parent_tree);
    }
  }

	return(len);
}
/*
 * 11.3.16	LLC Frames Discarded
 */
static guint16
de_bssgp_llc_frames_disc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Action value */
	proto_tree_add_item(tree, hf_bssgp_llc_frames_disc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset+=1;

	return(curr_offset-offset);
}
/*
 * 11.3.17	Location Area
 */
/* Octets 3 to 7 contain the value part (starting with octet 2) of the
 * Location Area Identification IE defined in 3GPP TS 24.008, not
 * including 3GPP TS 24.008 IEI
 */

/*
 * 11.3.18	LSA Identifier List
 */
/* Rest of element coded as in 3GPP TS 48.008, not including
 * 3GPP TS 48.008 IEI and 3GPP TS 48.008 length indicator
 */
/*
 * 11.3.19	LSA Information
 */
/* Rest of element coded as in 3GPP TS 48.008, not including
 * 3GPP TS 48.008 IEI and 3GPP TS 48.008 length indicator
 */
/*
 * 11.3.20	Mobile Id
 */
/* Octets 3-n contain either the IMSI, IMEISV or IMEI coded as the
 * value part (starting with octet 3) of the Mobile Identity IE defined in
 * 3GPP TS 24.008, not including 3GPP TS 24.008 IEI and
 * 3GPP TS 24.008 length indcator
 */
/*
 * 11.3.21	MS Bucket Size
 */

static guint16
de_bssgp_ms_bucket_size(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* The Bmax field is coded as Bmax of BVC Bucket Size, see sub-clause 11.3.5. */
	proto_tree_add_item(tree, hf_bssgp_bucket_size, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}
/*
 * 11.3.22	MS Radio Access Capability
 */
/* Rest of element coded as the value part defined in
 * 3GPP TS 24.008, not including 3GPP TS 24.008 IEI and
 * 3GPP TS 24.008 octet length indicator.
 */
/*
 * 11.3.23	OMC Id
 */
static guint16
de_bssgp_omc_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* octet 3-22 For the OMC identity, see 3GPP TS 12.20 */
	proto_tree_add_item(tree, hf_bssgp_omc_id, tvb, curr_offset, len, ENC_BIG_ENDIAN);

	return len;
}
/*
 * 11.3.24	PDU In Error
 */
static guint16
de_bssgp_pdu_in_error(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* octet 3-? Erroneous BSSGP PDU */
	 proto_tree_add_item(tree, hf_bssgp_msg_type, tvb, 0, 1, ENC_BIG_ENDIAN);
	 curr_offset++;

	 proto_tree_add_text(tree, tvb, curr_offset, len-1, "PDU Data");

	return len;
}
/*
 * 11.3.25 PDU Lifetime
 */
static guint16
de_bssgp_pdu_lifetime(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_delay_val, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	return(curr_offset-offset);
}

/*
The Delay Value field is coded as a 16-bit integer value in units of centi-seconds (one hundredth of a second). This
coding provides a range of over 10 minutes in increments of 10 ms. As a special case, the hexadecimal value 0xFFFF
(decimal 65 535) shall be interpreted as "infinite delay".
*/
/*
 * 11.3.26	PDU Type
 */
/*
 * 11.3.27	Priority
 */
/* Rest of element coded as the value part of the Priority IE defined in
 * 3GPP TS 48.008, not including 3GPP TS 48.008 IEI and
 * 3GPP TS 48.008 length indicator
 */
/*
 * 11.3.28	QoS Profile
 */
static const true_false_string  bssgp_a_bit_vals = {
    "Radio interface uses RLC/MAC-UNITDATA functionality",
    "Radio interface uses RLC/MAC ARQ functionality"
};

static const true_false_string  bssgp_t_bit_vals = {
    "The SDU contains data",
    "The SDU contains signalling"
};

static const true_false_string  bssgp_cr_bit_vals = {
    "The SDU does not contain a LLC ACK or SACK command/response frame type",
    "The SDU contains a LLC ACK or SACK command/response frame type"
};

const value_string bssgp_peak_rate_gran_vals[] = {
	{ 0x0, "100 bits/s increments" },
    { 0x1, "1000 bits/s increments" },
    { 0x2, "10000 bits/s increments" },
    { 0x3, "100000 bits/s increments" },
  { 0, NULL }
};
  static const value_string bssgp_precedence_ul[] = {
    { 0,   "High priority" },
    { 1,   "Normal priority" },
    { 2,   "Low priority" },
    { 0,   NULL },
  };

  static const value_string bssgp_precedence_dl[] = {
    { 0,   "Radio priority 1" },
    { 1,   "Radio priority 2" },
    { 2,   "Radio priority 3" },
    { 3,   "Radio priority 4" },
    { 4,   "Radio priority unknown" },
    { 0,   NULL },
  };

static guint16
de_bssgp_qos_profile(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_item *pi, *pre_item;
	guint32	curr_offset;
	guint16 peak_bit_rate;
	guint8  rate_gran, precedence;
	int     link_dir;

	curr_offset = offset;

	/* octet 3-4 Peak bit rate provided by the network (note)
	 * NOTE: The bit rate 0 (zero) shall mean "best effort" in this IE.
	 */
	link_dir = gpinfo->link_dir;

	peak_bit_rate = tvb_get_ntohs(tvb, curr_offset);
	pi = proto_tree_add_text(tree, tvb, curr_offset, 1, "Peak bit rate: ");
	if (peak_bit_rate == 0) {
		proto_item_append_text(pi, "Best effort");
	}else{
		rate_gran = tvb_get_guint8(tvb, curr_offset+2)&0xc0;
		switch(rate_gran){
			case 0:
				/* 100 bits/s increments */
				proto_item_append_text(pi, "%u bits/s", peak_bit_rate * 100);
				break;
			case 1:
				/* 1000 bits/s increments */
				proto_item_append_text(pi, "%u kbits/s", peak_bit_rate);
				break;
			case 2:
				/* 10000 bits/s increments */
				proto_item_append_text(pi, "%u kbits/s", peak_bit_rate * 10);
				break;
			case 3:
				/* 100000 bits/s increments */
				proto_item_append_text(pi, "%u kbits/s", peak_bit_rate * 100);
				break;
			default:
				break;
		}
	}
	curr_offset+=2;

	/* octet 5 Peak Bit Rate Granularity C/R T A Precedence */
	/* If the Gigabit Interface feature has not been negotiated, the "Peak bit rate" 
	 * field is the binary encoding of the peak bit rate information expressed in 100 bits/s
	 * increments, starting from 0 x 100 bits/s until 65 535 x 100 bits/s (6 Mbps).
	 *
	 * If the Gigabit Interface feature has been negotiated, the "Peak bit rate" field is the 
	 * binary encoding of the peak bit rate information expressed in increments as defined by 
	 * the Peak Bit Rate Granularity field.
	 */
	proto_tree_add_item(tree, hf_bssgp_peak_rate_gran, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_bssgp_cr_bit, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_bssgp_t_bit, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_bssgp_a_bit, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	precedence = tvb_get_guint8(tvb, curr_offset) & 0x7;
	pre_item = proto_tree_add_item(tree, hf_bssgp_precedence, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	if(link_dir == P2P_DIR_DL){
		proto_item_append_text(pre_item, " %s", val_to_str_const((guint32)precedence, bssgp_precedence_dl, "Radio Priority Unknown(Radio priority 3)"));
	}else{
		proto_item_append_text(pre_item, " %s", val_to_str_const((guint32)precedence, bssgp_precedence_ul, "Priority Unknown(Low priority)"));
	}
	
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.29	Radio Cause
 */
  static const value_string bssgp_radio_cause_vals[] = {
    { 0x00, "Radio contact lost with the MS" },
    { 0x01, "Radio link quality insufficient to continue communication" },
    { 0x02, "Cell reselection ordered" },
    { 0x03, "Cell reselection prepare" },
    { 0x04, "Cell reselection failure" },
    { 0,    NULL },
    /* Otherwise "Reserved (Radio contact lost with the MS)" */
  };

static guint16
de_bssgp_ra_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_ra_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.30	RA-Cap-UPD-Cause
 */
  static const value_string bssgp_ra_cap_upd_cause_vals[] = {
    { 0x00, "OK, RA capability IE present" },
    { 0x01, "TLLI unknown in SGSN" },
    { 0x02, "No RA capabilities or IMSI available for this MS" },
    { 0,    NULL },
    /* Otherwise "Reserved (TLLI unknown in SGSN)" */
  };

static guint16
de_bssgp_ra_cap_upd_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_ra_cap_upd_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.31	Routeing Area
 */
/* Octets 3 to 8 contain the value part (starting with octet 2) of the
 * Routing Area Identification IE defined in 3GPP TS 24.008, not
 * including 3GPP TS 24.008 IEI
 */
/*
 * 11.3.32	R_default_MS
 */
static guint16
de_bssgp_r_default_ms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_r_default_ms, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;
	
	return(curr_offset-offset);
}

/*
 * 11.3.33	Suspend Reference Number
 */
static guint16
de_bssgp_suspend_ref_no(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Unstructured value */
	proto_tree_add_item(tree, hf_bssgp_suspend_ref_no, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.34	Tag
 */

static guint16
de_bssgp_tag(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Unstructured value */
	proto_tree_add_item(tree, hf_bssgp_tag, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.35	Temporary logical link Identity (TLLI)
 * Rest of element coded as the value part of the TLLI information
 * element in 3GPP TS 44.018, not including 3GPP TS 44.018 IEI.
 */
/*
 * 11.3.36	Temporary Mobile Subscriber Identity (TMSI)
 */
/* Rest of element coded as the value part of the TMSI/P-TMSI
 * information element in 3GPP TS 24.008, not including
 * 3GPP TS 24.008 IEI.
 */
/*
 * 11.3.37	Trace Reference
 */
static guint16
de_bssgp_trace_ref(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* octet 3-4 Trace Reference */
	proto_tree_add_item(tree, hf_bssgp_trace_ref, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

	curr_offset+=2;

	return(curr_offset-offset);
}

/*
 * 11.3.38	Trace Type
 */
/* This is coded as specified in Technical Specification
 * 3GPP TS 32.008
 * XXX: Coding unknown (Specification withdrawn) 3GPP TS 32.008
 */
static guint16
de_bssgp_trace_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_text(tree, tvb, curr_offset, len, "Trace Type data ( Coding unknown (Specification withdrawn) 3GPP TS 32.008)");

	return(len);
}
/*
 * 11.3.39	Transaction Id
 */
static guint16
de_bssgp_transaction_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_transaction_id, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

	return(curr_offset-offset);
}
/*
 * 11.3.40	Trigger Id
 */
static guint16
de_bssgp_trigger_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_trigger_id, tvb, curr_offset, len, ENC_BIG_ENDIAN);

	return(len);
}
/*
 * 11.3.41	Number of octets affected
 */
static guint16
de_bssgp_no_of_oct_affected(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* octet 3-5 number of octets transferred or deleted */
	proto_tree_add_item(tree, hf_bssgp_no_of_oct, tvb, curr_offset, 3, ENC_BIG_ENDIAN);

	curr_offset+=3;

	return(curr_offset-offset);
}
/*
 * 11.3.42	Packet Flow Identifier (PFI)
 */
/* Rest of element coded as the value part of the Packet Flow
 * Identifier information element in 3GPP TS 24.008, not including
 * 3GPP TS 24.008 IEI
 */
/*
 * 11.3.42a	(void)
 */
/*
 * 11.3.43	Aggregate BSS QoS Profile
 */
/* Rest of element coded as the value part of the QoS information
 * element in 3GPP TS 24.008, not including 3GPP TS 24.008 IEI and
 * length indicator. The shorter 3-byte form of QoS information is not
 * allowed in BSSGP PDUs.
 * 10.5.6.5
 */
/*
 * 11.3.44	GPRS Timer
 */
static const value_string bssgp_unit_vals[] = {
    { 0, "incremented in multiples of 2 s" },
    { 1, "incremented in multiples of 1 minute" },
    { 2, "incremented in multiples of decihours" },
    { 3, "incremented in multiples of 500 msec" },
    { 4, "incremented in multiples of 1 minute(Undefined)" },
	{ 5, "incremented in multiples of 1 minute(Undefined)" },
    { 6, "incremented in multiples of 1 minute(Undefined)" },
    { 7, "the timer does not expire" },
    { 0, NULL},
    /* Otherwise "incremented in multiples of 1 minute" */
  };

static guint16
de_bssgp_gprs_timer(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/*octet 3 Unit Value Timer value */
	proto_tree_add_item(tree, hf_bssgp_unit_val, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_bssgp_gprs_timer, tvb, curr_offset, 3, ENC_BIG_ENDIAN);

	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.45	Feature Bitmap
 */
static guint16
de_bssgp_feature_bitmap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	/* MBMS */
	proto_tree_add_item(tree, hf_bssgp_mbms, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* EnhancedRadioStatus */
	proto_tree_add_item(tree, hf_bssgp_EnhancedRadioStatus, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* PFCFC */
	proto_tree_add_item(tree, hf_bssgp_pfcfc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* RIM */
	proto_tree_add_item(tree, hf_bssgp_rim, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* LCS */ 
	proto_tree_add_item(tree, hf_bssgp_lcs, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* INR */
	proto_tree_add_item(tree, hf_bssgp_inr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* CBL */
	proto_tree_add_item(tree, hf_bssgp_cbl, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* PFC */
	proto_tree_add_item(tree, hf_bssgp_pfc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.46	Bucket Full Ratio
 */
static guint16
de_bssgp_bucket_full_ratio(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Ratio of the bucket that is filled up with data */
	proto_tree_add_item(tree, hf_bssgp_bucket_full_ratio, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.47	Service UTRAN CCO
 */
static const value_string bssgp_service_utran_cco_vals[] = {
    { 0, "Network initiated cell change order procedure to UTRAN should be performed" },
    { 1, "Network initiated cell change order procedure to UTRAN should not be performed" },
    { 2, "Network initiated cell change order procedure to UTRAN shall not be performed" },
	{ 3, "If received, shall be interpreted as no information available (bits 4-5 valid)" },
	{ 0,    NULL },
    /* Otherwise "No information available" */
  };

static const value_string bssgp_service_eutran_cco_vals[] = {
    { 0, "If received, shall be interpreted as no information available" },
    { 1, "Network initiated cell change order to E-UTRAN or PS handover to E-UTRAN procedure should be performed" },
    { 2, "Network initiated cell change order to E-UTRAN or PS handover to E-UTRAN procedure should not be performed" },
	{ 3, "Network initiated cell change order to E-UTRAN or PS handover to E-UTRAN procedure shall not be performed" },
	{ 0,    NULL },
    /* Otherwise "No information available" */
  };

static guint16
de_bssgp_serv_utran_cco(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Service EUTRAN CCO Value part */
	proto_tree_add_item(tree, hf_bssgp_serv_eutran_cco, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* Service UTRAN CCO Value part */
	proto_tree_add_item(tree, hf_bssgp_serv_utran_cco, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.48	NSEI (Network Service Entity Identifier)
 */
static guint16
de_bssgp_nsei(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint16 nsei;

	curr_offset = offset;

	nsei = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_bssgp_nsei, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;
	
	col_append_sep_fstr(gpinfo->cinfo, COL_INFO, BSSGP_SEP, "NSEI %u", nsei);


	return(curr_offset-offset);
}
/*
 * 11.3.49	RRLP APDU
 */
/*
 * 11.3.50	LCS QoS
 * 11.3.51	LCS Client Type
 * 11.3.52	Requested GPS Assistance Data
 * 11.3.53	Location Type
 * 11.3.54	Location Estimate
 * 11.3.55	Positioning Data
 * 11.3.56	Deciphering Keys
 * 11.3.57	LCS Priority
 * 11.3.58	LCS Cause
 * 11.3.59	LCS Capability
 * 11.3.60	RRLP Flags
 * 11.3.61	RIM Application Identity
 * 11.3.62	RIM Sequence Number
 * 11.3.62a	RIM Container
 * 11.3.62a.0	General
 * 11.3.62a.1	RAN-INFORMATION-REQUEST RIM Container
 * 11.3.62a.2	RAN-INFORMATION RIM Container
 * 11.3.62a.3	RAN-INFORMATION-ACK RIM Container
 * 11.3.62a.4	RAN-INFORMATION-ERROR RIM Container
 * 11.3.62a.5	RAN-INFORMATION-APPLICATION-ERROR RIM Container
 * 11.3.63	Application Container
 * 11.3.63.1	RAN-INFORMATION-REQUEST Application Container
 * 11.3.63.1.0	General
 * 11.3.63.1.1	RAN-INFORMATION-REQUEST Application Container for the NACC Application
 * 11.3.63.1.2	RAN-INFORMATION-REQUEST Application Container for the SI3 Application
 * 11.3.63.1.3	RAN-INFORMATION-REQUEST Application Container for the MBMS data channel Application
 * 11.3.63.1.4	RAN-INFORMATION-REQUEST Application Container for the SON Transfer Application
 * 11.3.63.2	RAN-INFORMATION Application Container Unit
 * 11.3.63.2.0	General
 * 11.3.63.2.1	RAN-INFORMATION Application Container for the NACC Application
 * 11.3.63.2.2	RAN-INFORMATION Application Container for the SI3 Application
 * 11.3.63.2.3	RAN-INFORMATION Application Container for the MBMS data channel Application
 * 11.3.63.2.4	RAN-INFORMATION Application Container for the SON Transfer Application
 * 11.3.64	Application Error Container
 * 11.3.64.1	Application Error Container layout for the NACC application
 * 11.3.64.2	Application Error Container for the SI3 application
 * 11.3.64.3	Application Error Container for the MBMS data channel application
 * 11.3.64.4	Application Error Container for the SON Transfer Application
 * 11.3.65	RIM PDU Indications	
 * 11.3.65.0	General
 * 11.3.65.1	RAN-INFORMATION-REQUEST RIM PDU Indications
 * 11.3.65.2	RAN-INFORMATION RIM PDU Indications
 * 11.3.65.3	RAN-INFORMATION-APPLICATION-ERROR RIM PDU Indications
 * 11.3.66	(void)
 * 11.3.67	RIM Protocol Version Number
 */
/*
 * 11.3.68	PFC Flow Control parameters
 */
 
static guint16
de_bssgp_pfc_flow_ctrl(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree *pfc_tree;
	proto_item *pi, *ti2;

	guint32	curr_offset;
	guint8 num_pfc, i, pfc_len;
	gboolean b_pfc_included;

	curr_offset = offset;

	num_pfc = tvb_get_guint8(tvb, curr_offset);
	pi = proto_tree_add_text(tree, tvb, curr_offset, 1,
			   "Number of PFCs: ");

	if (num_pfc < 12) {
		proto_item_append_text(pi, "%u", num_pfc);
	}else {
		proto_item_append_text(pi, "Reserved");
		return (curr_offset-offset);
	}
	curr_offset++;
	if (num_pfc == 0) 
		return (curr_offset-offset);

	pfc_len = (len - 1) / num_pfc;
	b_pfc_included = (pfc_len == 6);

	for (i = 0; i < num_pfc; i++) {
		ti2 = proto_tree_add_text(tree, tvb, curr_offset, pfc_len,
					  "PFC (%u)", i + 1);
		pfc_tree = proto_item_add_subtree(ti2, ett_bssgp_pfc_flow_control_parameters_pfc);

		pi = proto_tree_add_text(pfc_tree, tvb, curr_offset, 1, "PFI");
		bssgp_pi_append_pfi(pi, tvb, curr_offset);
		curr_offset++;

		pi = proto_tree_add_text(pfc_tree, tvb, curr_offset, 2, "BMax_PFC");
		bssgp_pi_append_bucket_size(pi, tvb, curr_offset);
		curr_offset += 2;

		pi = proto_tree_add_text(pfc_tree, tvb, curr_offset, 2, "R_PFC");
		bssgp_pi_append_bucket_leak_rate(pi, tvb, curr_offset);
		curr_offset += 2;

		if (b_pfc_included) {
			pi = proto_tree_add_text(pfc_tree, tvb, curr_offset, 1, "B_PFC");
			bssgp_pi_append_bucket_full_ratio(pi, tvb, curr_offset);
			curr_offset++;
		}
	}
	return(curr_offset-offset);
}
/*
 * 11.3.69	Global CN-Id
 */
/* Coded as octets 3 to 7 of the Global CN-Id IE, defined in
 * 3GPP TS 29.018
 */
/*
 * 11.3.70	RIM Routing Information
 */
/*
 * 11.3.71	MBMS Session Identity
 */
/* MBMS-Session-Identity AVP encoded as in 3GPP TS 29.061 [31],
 * excluding AVP Header fields as defined in IETF RFC 3588 [33].
 * TS 29.061
 * 17.7.11 MBMS-Session-Identity AVP
 * The MBMS-Session-Identity AVP (AVP code 908) is of type OctetString. Its length is one octet. It is allocated by the
 * BM-SC. Together with TMGI it identifies a transmission of a specific MBMS session. The initial transmission and
 * subsequent retransmissions of the MBMS session will use the same values of these parameters. This AVP is optional
 * within the Gmb interface.
 */
static guint16
de_bssgp_mbms_session_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* MBMS Session Identity */
	proto_tree_add_item(tree, hf_bssgp_mbs_session_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.72	MBMS Session Duration
 * 11.3.73	MBMS Service Area Identity List
 * 11.3.74	MBMS Response
 * 11.3.75	MBMS Routing Area List
 * 11.3.76	MBMS Session Information
 */
/*
 * 11.3.77	TMGI (Temporary Mobile Group Identity)
 */
/*
/* Rest of element coded as in 3GPP TS 24.008, not including 3GPP
 * TS 24.008 IEI and 3GPP TS 24.008 length indicator.
 */
/*
 * 11.3.78	MBMS Stop Cause
 */
/*
 * 11.3.79	Source BSS to Target BSS Transparent Container
 */
/* Defined localy here without the check of curr_len wrapping, that will be taken care of when this IEI dissecton finishes */
#define ELEM_IN_ELM_OPT_TELV(EOT_iei, EOT_pdu_type, EOT_elem_idx, EOT_elem_name_addition) \
{\
	if ((consumed = elem_telv(tvb, tree, (guint8) EOT_iei, EOT_pdu_type, EOT_elem_idx, curr_offset, curr_len, EOT_elem_name_addition)) > 0) \
	{ \
		curr_offset += consumed; \
		curr_len -= consumed; \
	} \
}
/* The actual function moved to after defining the enums */

/*
 * 11.3.80	Target BSS to Source BSS Transparent Container
 */
/*
 * 11.3.81	NAS container for PS Handover
 */
/*
 * 11.3.82	PFCs to be set-up list
 */
/*
 * 11.3.83	List of set-up PFCs
 */
static guint16
de_bssgp_list_of_setup_pfcs(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree *pfc_tree;
	proto_item *pi, *ti2;

	guint32	curr_offset;
	guint8 num_pfc, i;

	curr_offset = offset;

	num_pfc = tvb_get_guint8(tvb, curr_offset);
	pi = proto_tree_add_text(tree, tvb, curr_offset, 1,
			   "Number of PFCs: ");

	if (num_pfc < 12) {
		proto_item_append_text(pi, "%u", num_pfc);
	}else {
		proto_item_append_text(pi, "Reserved");
		return (curr_offset-offset);
	}
	curr_offset++;
	if (num_pfc == 0) 
		return (curr_offset-offset);

	for (i = 0; i < num_pfc; i++) {
		ti2 = proto_tree_add_text(tree, tvb, curr_offset, 1,
					  "PFC (%u)", i + 1);
		pfc_tree = proto_item_add_subtree(ti2, ett_bssgp_pfc_flow_control_parameters_pfc);

		pi = proto_tree_add_text(pfc_tree, tvb, curr_offset, 1, "PFI");
		bssgp_pi_append_pfi(pi, tvb, curr_offset);
		curr_offset++;

	}

	return(curr_offset-offset);
}
/*
 * 11.3.84	Extended Feature Bitmap
 */
static guint16
de_bssgp_ext_feature_bitmap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Gigabit Interface */
	proto_tree_add_item(tree, hf_bssgp_gb_if, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* PS Handover */
	proto_tree_add_item(tree, hf_bssgp_ps_ho, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.85	Source to Target Transparent Container
 */
static guint16
de_bssgp_src_to_trg_transp_cont(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Octets 3-? Source to Target Transparent Container content coded as
	 * specified in 3GPP TS 25.413 or 3GPP TS 36.413.
	 * In inter-RAT handovers ... RANAP specification 3GPP TS 25.413, excluding RANAP tag.
	 * In inter-RAT handover to E-UTRAN ... encoding is defined in 3GPP TS 36.413
	 */
	proto_tree_add_item(tree, hf_bssgp_src_to_trg_transp_cont, tvb, curr_offset, len, ENC_BIG_ENDIAN);

	return(len);
}

/*
 * 11.3.86	Target to Source Transparent Container
 */
static guint16
de_bssgp_trg_to_src_transp_cont(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Rest of element coded as either a complete Handover to UTRAN
	 * Command radio interface message (as defined in 3GPP TS
	 * 25.331) or a complete Radio Bearer Reconfiguration radio
	 * interface message (as defined in 3GPP TS 44.118) or a complete
	 * DL-DCCH-Message including a complete
	 * RRCConnectionReconfiguration radio interface message (as
	 * defined in 3GPP TS 36.331)
	 */
	proto_tree_add_item(tree, hf_bssgp_trg_to_src_transp_cont, tvb, curr_offset, len, ENC_BIG_ENDIAN);

	return(len);
}

/*
 * 11.3.87	RNC Identifier
 */
static guint16
de_bssgp_rnc_identifier(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint16 rnc_id;

	curr_offset = offset;
	/* Octets 3-8 Octets 3 to 8 contain the value part (starting with octet 2) of the
	 * Routing Area Identification IE defined in 3GPP TS 24.008, not including 3GPP TS 24.008 IEI
	 */
	curr_offset = curr_offset + de_gmm_rai(tvb, tree, curr_offset , 6, add_string, string_len);
	/* Octet 9 - 10 RNC ID (or Extended RNC-ID or Corresponding RNC-ID) */
	rnc_id = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_bssgp_rnc_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	curr_offset+=2;

	if (add_string)
		g_snprintf(add_string, string_len, " %s, RNC-ID %u", add_string, rnc_id);
 
	return(curr_offset-offset);

}
/*
 * 11.3.88	Page Mode
 */
/* PAGE_MODE (2 bit field) */

static const value_string bssgp_page_mode_vals[] = {
    { 0, "Normal Paging" },
    { 1, "Extended Paging" },
    { 2, "Paging Reorganization" },
	{ 3, "Same as before" },
	{ 0,    NULL },
  };
static guint16
de_bssgp_page_mode(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_page_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.89	Container ID
 */
static guint16
de_bssgp_container_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_bssgp_container_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.90	Global TFI
 */
static const value_string bssgp_global_tfi_vals[] = {
    { 0, "UPLINK_TFI" },
    { 1, "DOWNLINK_TFI" },
	{ 0,    NULL },
  };

static guint16
de_bssgp_global_tfi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32 bit_offset;
	guint8  gtfi;

	curr_offset = offset;

	/* Bits 6 - 1 Global TFI coded as specified in 3GPP TS 44.060 */
	bit_offset = (curr_offset << 3) +3;
	gtfi = tvb_get_bits8(tvb,bit_offset,1);
	proto_tree_add_bits_item(tree, hf_bssgp_global_tfi, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	/* < Global TFI IE > ::=
	 *    { 0 < UPLINK_TFI : bit (5) >
	 *    | 1 < DOWNLINK_TFI : bit (5) > } ;
	 */
	if(gtfi == 0){
		/* UPLINK_TFI (5 bit field)
		 * This field identifies an uplink TBF. This field is coded the same as the 
		 * TFI field defined in sub-clause 12.15.
		 * This field is encoded as a binary number. Range 0 to 31
		 */
		proto_tree_add_bits_item(tree, hf_bssgp_ul_tfi, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	}else{
		/* DOWNLINK_TFI (5 bit field)
		 * This field identifies an uplink TBF. This field is coded the same as the 
		 * TFI field defined in sub-clause 12.15.
		 * This field is encoded as a binary number. Range 0 to 31
		 */
		proto_tree_add_bits_item(tree, hf_bssgp_dl_tfi, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	}
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.91	IMEI
 * 11.3.92	Time to MBMS Data Transfer
 * 11.3.93	MBMS Session Repetition Number
 */
/*
 * 11.3.94	Inter RAT Handover Info
 */
static guint16
de_bssgp_inter_rat_ho_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t	*new_tvb;
	guint32	curr_offset;

	curr_offset = offset;

	new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
	/*
	 * Inter RAT Handover Information coded as specified in 3GPP
	 * Technical Specification 25.331
	 */
	dissect_rrc_InterRATHandoverInfo_PDU(new_tvb, gpinfo, tree);

	return(len);
}
/*
 * 11.3.95	PS Handover Command
 */
static guint16
de_bssgp_ps_ho_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Octet 3-? Rest of element coded as a complete PS Handover Command
	* radio interface message as defined in 3GPP TS 44.060 (carrying
	* the PS Handover to A/Gb Mode Payload)
	*/
	proto_tree_add_item(tree, hf_bssgp_ps_ho_cmd, tvb, curr_offset, len, ENC_BIG_ENDIAN);


	return(len);
}

/*
 * 11.3.95a	PS Handover Indications
 */
static guint16
de_bssgp_ps_ho_indications(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* SI/PSI */
	proto_tree_add_item(tree, hf_bssgp_sipsi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}

/*
 * 11.3.95b	SI/PSI Container
 */

 static const value_string type_vals[] = {
    { 0, "SI messages as specified for BCCH (3GPP TS 44.018) follow" },
    { 1, "PSI messages as specified for PBCCH (3GPP TS 44.060) follow" },
	{ 0,    NULL },
  };
static guint16
de_bssgp_sipsi_container(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 oct,num, type, i;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	num = oct >>1;
	type = oct & 1;
	proto_tree_add_text(tree, tvb, curr_offset, 1,
			   "Number of SI/PSI: %u",num);

	/* Type */
	proto_tree_add_item(tree, hf_bssgp_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;
	if (type==0){
		/* BCCH (3GPP TS 44.018) */
		for (i = 0; i < num; i++) {
			proto_tree_add_text(tree, tvb, curr_offset, 21, "SI (%u)", i + 1);
			curr_offset+=21;
		}
	}else{
		/* PBCCH (3GPP TS 44.060) */
		for (i = 0; i < num; i++) {
			proto_tree_add_text(tree, tvb, curr_offset, 22, "PSI (%u)", i + 1);
			curr_offset+=22;
		}
	}

	return(curr_offset-offset);
}
/*
 * 11.3.95c	Active PFCs List
 */
static guint16
de_bssgp_active_pfcs_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree *pfc_tree;
	proto_item *pi, *ti2;

	guint32	curr_offset;
	guint8 num_pfc, i;

	curr_offset = offset;

	num_pfc = tvb_get_guint8(tvb, curr_offset);
	pi = proto_tree_add_text(tree, tvb, curr_offset, 1,
			   "Number of PFCs: ");

	if (num_pfc < 12) {
		proto_item_append_text(pi, "%u", num_pfc);
	}else {
		proto_item_append_text(pi, "Reserved");
		return (curr_offset-offset);
	}
	curr_offset++;
	if (num_pfc == 0) 
		return (curr_offset-offset);

	for (i = 0; i < num_pfc; i++) {
		ti2 = proto_tree_add_text(tree, tvb, curr_offset, 1, "PFC (%u)", i + 1);
		pfc_tree = proto_item_add_subtree(ti2, ett_bssgp_pfc_flow_control_parameters_pfc);

		pi = proto_tree_add_text(pfc_tree, tvb, curr_offset, 1, "PFI");
		bssgp_pi_append_pfi(pi, tvb, curr_offset);
		curr_offset++;

	}

	return(curr_offset-offset);
}
/*
 * 11.3.96	Velocity Data
 */
/*
 * 11.3.97	DTM Handover Command
 */
static guint16
de_bssgp_dtm_ho_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Rest of element coded as a complete DTM Handover Command
	 * radio interface message as defined in 3GPP TS 44.060 (carrying
	 * the DTM Handover to A/Gb Mode Payload)
	 */
	proto_tree_add_text(tree, tvb, curr_offset, len, "DTM Handover Command data");

	return(len);
}
/*
 * 11.3.98	CS Indication
 */
static guint16
de_bssgp_cs_indication(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* CS Indication Contents 
	 * CS Indication Contents: This identifies a particular handover attempt for this MS. This shall be identical to the PS
	 * Indication Contents value in the corresponding PS Indication IE included in the Old BSS to New BSS Information IE
	 * (see 3GPP TS 48.008). The choice of the value of this field is implementation specific, with the requirement that
	 * consecutive handover attempts for the same mobile station shall not have the same CS Indication Contents value.
	 */
	proto_tree_add_item(tree, hf_bssgp_cs_indication, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.99	Requested GANSS Assistance Data
 * 11.3.100 	GANSS Location Type
 * 11.3.101 	GANSS Positioning Data
 */
/*
 * 11.3.102 	Flow Control Granularity
 */
static const value_string bssgp_flow_control_gran_vals[] = {
    { 0, "100 octets or bits/s increments" },
    { 1, "1000 octets or bits/s increments" },
    { 2, "10000 octets or bits/s increments" },
	{ 3, "100000 octets or bits/s increments" },
	{ 0,    NULL },
  };


static guint16
de_bssgp_flow_control_gran(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Granularity */
	proto_tree_add_item(tree, hf_bssgp_flow_control_gran, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.103 	eNB Identifier
 */
static guint16
de_bssgp_enb_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t	*new_tvb;
	guint32	curr_offset;

	curr_offset = offset;

	/* Octets 3 to 7 contain the value part (starting with octet 2) of the
	 * Tracking Area Identity IE defined in 3GPP TS 24.301 [37], not
	 * including 3GPP TS 24.301 IEI [37]
	*/
	curr_offset = curr_offset+ de_emm_trac_area_id(tvb, tree, curr_offset, 5, add_string, string_len);

	/* Octets 8-n contain the Global eNB ID (see 3GPP TS 36.413) of the eNodeB. */
	new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
	dissect_s1ap_Global_ENB_ID_PDU(new_tvb, gpinfo, tree);

	return(len);
}
/*
 * 11.3.104 	E-UTRAN Inter RAT Handover Info
 */
static guint16
de_bssgp_e_utran_inter_rat_ho_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t	*new_tvb;
	guint32	curr_offset;

	curr_offset = offset;

	new_tvb = tvb_new_subset_remaining(tvb, curr_offset);
	/*
	 * Formatted and coded according to the UE-EUTRA-Capability IE
	 * defined in 3GPP Technical Specification 36.331. The most
	 * significant bit of the first octet of the octet string contains bit 8 of
	 * the first octet of the IE.
	 */
	dissect_lte_rrc_UE_EUTRA_Capability_PDU(new_tvb, gpinfo, tree);

	return(len);
}
/*
 * 11.3.105 	Subscriber Profile ID for RAT/Frequency priority
 */

static guint16
de_bssgp_sub_prof_id_f_rat_freq_prio(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 value;

	curr_offset = offset;

	/* Octet 3 contains a number in binary representation ranging from 0 to 255. 
	 * The Subscriber Profile ID for RAT/Frequency priority is given by 
	 * the indicated value +1.
	 */
	value = tvb_get_guint8(tvb,curr_offset) + 1;
	proto_tree_add_uint(tree, hf_bssgp_sub_prof_id_f_rat_freq_prio, tvb, curr_offset, 1, value);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.106 	Request for Inter-RAT Handover Info
 */
/*
 * 11.3.107 	Reliable Inter-RAT Handover Info
 */
static guint16
de_bssgp_reliable_inter_rat_ho_inf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Reliable Inter RAT Handover Info Indicator */
	proto_tree_add_item(tree, hf_bssgp_rel_int_rat_ho_inf_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.108 	SON Transfer Application Identity
 */
/*
 * 11.3.109 	CSG Identifier
 */

/* Cell Access Mode (bit 1 of octet 7) */
static const value_string bssgp_cell_access_mode_vals[] = {
    { 0, "CSG cell" },
    { 1, "Hybrid cell" },
	{ 0,    NULL },
};

static guint16
de_bssgp_csg_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* Octets 3 to 6 contain the CSG Identity (CSG-ID) of the cell (defined in
	 * 3GPP TS 23.003) as reported by the mobile station (see 3GPP TS
	 * 44.060). Bits 4 to 8 of octet 6 are spare and set to zero.
	 */
	proto_tree_add_item(tree, hf_bssgp_csg_id, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
	curr_offset+=4;
	/* Cell Access Mode */
	proto_tree_add_item(tree, hf_bssgp_cell_acc_mode, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 11.3.110 	Tracking Area Code
 */
/*
 * Octets 3 to 5 contain the value part (starting with octet 2) of the TAC
 * IE defined in 3GPP TS 24.301.
 */
/*
 * 11.3.111 	Redirect Attempt Flag
 * 11.3.112 	Redirection Indication
 * 11.3.113 	Redirection Completed
*/


const value_string bssgp_elem_strings[] = {
    { 0x00, "Alignment Octets" },									/* 11.3.1	Alignment octets */
	{ 0x01, "Bmax default MS" },									/* 11.3.2	Bmax default MS  */
	{ 0x02, "BSS Area Indication" },								/* 11.3.3	BSS Area Indication	 */
	{ 0x03, "Bucket Leak Rate (R)" },								/* 11.3.4	Bucket Leak Rate (R) */
	{ 0x04, "BVCI (BSSGP Virtual Connection Identifier)" },			/* 11.3.6	BVCI (BSSGP Virtual Connection Identifier)  */
	{ 0x05,	"BVC Bucket size" },									/* 11.3.5	BVC Bucket Size */
	{ 0x06, "BVC Measurement" },									/* 11.3.7	BVC Measurement */
	{ 0x07, "Cause" },												/* 11.3.8	Cause */
	{ 0x08, "Cell Identifier" },									/* 11.3.9	Cell Identifier */
	{ 0x09, "Channel needed" },										/* 11.3.10	Channel needed */
	{ 0x0a, "DRX Parameters" },										/* 11.3.11	DRX Parameters */
	{ 0x0b, "eMLPP-Priority" },										/* 11.3.12	eMLPP-Priority */
	{ 0x0c, "Flush Action" },										/* 11.3.13	Flush Action */
	{ 0x0d, "IMSI" },												/* 11.3.14	IMSI */
	{ 0x0e, "LLC-PDU" },											/* 11.3.15	LLC-PDU */
 	{ 0x0f, "LLC Frames Discarded" },								/* 11.3.16	LLC Frames Discarded  */
	{ 0x10, "Location Area" },										/* 11.3.17	Location Area  */
	{ 0x11, "Mobile Id" },											/* 11.3.20	Mobile Id */
	{ 0x12, "MS Bucket Size" },										/* 11.3.21	MS Bucket Size */
 	{ 0x13, "MS Radio Access Capability" },						    /* 11.3.22	MS Radio Access Capability GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP */
	{ 0x14, "OMC Id" },												/* 11.3.23	OMC Id */
	{ 0x15, "PDU In Error" },										/* 11.3.24	PDU In Error */
	{ 0x16, "PDU Lifetime" },										/* 11.3.25	PDU Lifetime */
	{ 0x17, "Priority" },											/* 11.3.27	Priority */
    { 0x18, "QoS Profile" },										/* 11.3.28	QoS Profile */
    { 0x19, "Radio Cause" },										/* 11.3.29	Radio Cause */
	{ 0x1a, "RA-Cap-UPD-Cause" },									/* 11.3.30	RA-Cap-UPD-Cause */
	{ 0x1b, "Routeing Area" },										/* 11.3.31	Routeing Area */
 	{ 0x1c, "R_default_MS" },										/* 11.3.32	R_default_MS */
	{ 0x1d, "Suspend Reference Number" },							/* 11.3.33	Suspend Reference Number */ 
    { 0x1e, "Tag" },												/* 11.3.34	Tag */
 	{ 0x1f, "Temporary logical link Identity (TLLI)" },				/* 11.3.35	Temporary logical link Identity (TLLI) GSM_A_PDU_TYPE_RR, DE_RR_TLLI*/
	{ 0x20, "Temporary Mobile Subscriber Identity (TMSI)" },		/* 11.3.36	Temporary Mobile Subscriber Identity (TMSI)GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI */
    { 0x21, "Trace Reference" },									/* 11.3.37	Trace Reference */
    { 0x22, "Trace Type" },											/* 11.3.38	Trace Type */
    { 0x23, "Transaction Id" },										/* 11.3.39	Transaction Id */
    { 0x24, "Trigger Id" },											/* 11.3.40	Trigger Id */
    { 0x25, "Number of octets affected" },							/* 11.3.41	Number of octets affected */
	{ 0x26, "LSA Identifier List" },								/* 11.3.18	LSA Identifier List */
	{ 0x27, "LSA Information" },									/* 11.3.19	LSA Information */
	{ 0x28, "Packet Flow Identifier (PFI)" },						/* 11.3.42	Packet Flow Identifier (PFI) GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID*/
																	/* 11.3.42a	(void) */ 
	{ 0x29, "GPRS Timer" },											/* 11.3.44	GPRS Timer */
	{ 0x3a, "Aggregate BSS QoS Profile" },							/* 11.3.43	Aggregate BSS QoS Profile GSM_A_PDU_TYPE_GM, DE_QOS*/
	{ 0x3b, "Feature Bitmap" },										/* 11.3.45	Feature Bitmap */
	{ 0x3c, "Bucket Full Ratio" },									/* 11.3.46	Bucket Full Ratio */
	{ 0x3d, "Service UTRAN CCO" },									/* 11.3.47	Service UTRAN CCO */
	{ 0x3e, "NSEI (Network Service Entity Identifier)" },			/* 11.3.48	NSEI (Network Service Entity Identifier) */

 /* 11.3.50	LCS QoS */
 /* 11.3.51	LCS Client Type */
 /* 11.3.52	Requested GPS Assistance Data */
 /* 11.3.53	Location Type */
 /* 11.3.54	Location Estimate */
 /* 11.3.55	Positioning Data */
 /* 11.3.56	Deciphering Keys */
 /* 11.3.57	LCS Priority */
 /* 11.3.58	LCS Cause */
 /* 11.3.59	LCS Capability */
 /* 11.3.60	RRLP Flags */
 /* 11.3.61	RIM Application Identity */
 /* 11.3.62	RIM Sequence Number */
 /* 11.3.62a	RIM Container */
 /* 11.3.62a.0	General */
 /* 11.3.62a.1	RAN-INFORMATION-REQUEST RIM Container */
 /* 11.3.62a.2	RAN-INFORMATION RIM Container */
 /* 11.3.62a.3	RAN-INFORMATION-ACK RIM Container */
 /* 11.3.62a.4	RAN-INFORMATION-ERROR RIM Container */
 /* 11.3.62a.5	RAN-INFORMATION-APPLICATION-ERROR RIM Container */
 /* 11.3.63	Application Container */
 /* 11.3.63.1	RAN-INFORMATION-REQUEST Application Container */
 /* 11.3.63.1.0	General */
 /* 11.3.63.1.1	RAN-INFORMATION-REQUEST Application Container for the NACC Application */
 /* 11.3.63.1.2	RAN-INFORMATION-REQUEST Application Container for the SI3 Application */
 /* 11.3.63.1.3	RAN-INFORMATION-REQUEST Application Container for the MBMS data channel Application */
 /* 11.3.63.1.4	RAN-INFORMATION-REQUEST Application Container for the SON Transfer Application */
 /* 11.3.63.2	RAN-INFORMATION Application Container Unit */
 /* 11.3.63.2.0	General */
 /* 11.3.63.2.1	RAN-INFORMATION Application Container for the NACC Application */
 /* 11.3.63.2.2	RAN-INFORMATION Application Container for the SI3 Application */
 /* 11.3.63.2.3	RAN-INFORMATION Application Container for the MBMS data channel Application */
 /* 11.3.63.2.4	RAN-INFORMATION Application Container for the SON Transfer Application */
 /* 11.3.64	Application Error Container */
 /* 11.3.64.1	Application Error Container layout for the NACC application */
 /* 11.3.64.2	Application Error Container for the SI3 application */
 /* 11.3.64.3	Application Error Container for the MBMS data channel application */
 /* 11.3.64.4	Application Error Container for the SON Transfer Application */
 /* 11.3.65	RIM PDU Indications */	
 /* 11.3.65.0	General */
 /* 11.3.65.1	RAN-INFORMATION-REQUEST RIM PDU Indications */
 /* 11.3.65.2	RAN-INFORMATION RIM PDU Indications */
 /* 11.3.65.3	RAN-INFORMATION-APPLICATION-ERROR RIM PDU Indications */
 /* 11.3.66	(void) */
 /* 11.3.67	RIM Protocol Version Number */
	{ 0x00, "PFC Flow Control parameters" },						/* 11.3.68	PFC Flow Control parameters */
 /* 0x53, SGSAP_PDU_TYPE, DE_SGSAP_GLOBAL_CN_ID */					/* 11.3.69	Global CN-Id */
 /* 11.3.70	RIM Routing Information */
	{ 0x00, "MBMS Session Identity" },								/* 11.3.71 MBMS Session Identity */
 /* 11.3.72	MBMS Session Duration */
 /* 11.3.73	MBMS Service Area Identity List */
 /* 11.3.74	MBMS Response */
 /* 11.3.75	MBMS Routing Area List */
 /* 11.3.76	MBMS Session Information */
 /* ELEM_MAND_TELV(GSM_A_PDU_TYPE_GM, DE_TMGI,  */					/* 11.3.77	TMGI (Temporary Mobile Group Identity) */
 /* 11.3.78	MBMS Stop Cause */
	{ 0x00, "Source BSS to Target BSS Transparent Container" },		/* 11.3.79	Source BSS to Target BSS Transparent Container */
	{ 0x00, "Target BSS to Source BSS Transparent Container" },		/* 11.3.80	Target BSS to Source BSS Transparent Container */
 /* 11.3.81	NAS container for PS Handover */
 /* 11.3.82	PFCs to be set-up list */
	{ 0x00, "List of set-up PFCs" },								/* 11.3.83	List of set-up PFCs */
	{ 0x00, "Extended Feature Bitmap" },							/* 11.3.84	Extended Feature Bitmap */
	{ 0x00, "Source to Target Transparent Container" },				/* 11.3.85	Source to Target Transparent Container */
	{ 0x00, "Target to Source Transparent Container" },				/* 11.3.86	Target to Source Transparent Container */
	{ 0x00, "RNC Identifier" },										/* 11.3.87	RNC Identifier */
	{ 0x00, "Page Mode" },											/* 11.3.88	Page Mode */
 	{ 0x00, "Container ID" },										/* 11.3.89	Container ID */
 	{ 0x00, "Global TFI" },											/* 11.3.90	Global TFI */
 /* 11.3.91	IMEI */
 /* 11.3.92	Time to MBMS Data Transfer */
 /* 11.3.93	MBMS Session Repetition Number */
	{ 0x00, "Inter RAT Handover Info" },							/* 11.3.94	Inter RAT Handover Info */
	{ 0x00, "PS Handover Command" },								/* 11.3.95	PS Handover Command */
 	{ 0x00, "PS Handover Indications" },							/* 11.3.95a	PS Handover Indications */
 	{ 0x00, "SI/PSI Container" },									/* 11.3.95b	SI/PSI Container */
 	{ 0x00, "Active PFCs List" },									/* 11.3.95c	Active PFCs List */
 /* 11.3.96	Velocity Data */
 	{ 0x00, "DTM Handover Command" },								/* 11.3.97	DTM Handover Command */
	{ 0x00, "PS Handover Indications" },							/* 11.3.98	CS Indication */
 /* 11.3.99	Requested GANSS Assistance Data */
 /* 11.3.100 	GANSS Location Type */
 /* 11.3.101 	GANSS Positioning Data */
	{ 0x00, "Flow Control Granularity" },							/* 11.3.102 	Flow Control Granularity */
	{ 0x00, "eNB Identifier" },										/* 11.3.103 	eNB Identifier */
 	{ 0x00, "E-UTRAN Inter RAT Handover Info" },					/* 11.3.104 	E-UTRAN Inter RAT Handover Info */
	{ 0x00, "Subscriber Profile ID for RAT/Frequency priority" },	/* 11.3.105 Subscriber Profile ID for RAT/Frequency priority */
/* 11.3.106 Request for Inter-RAT Handover Info */
	{ 0x00, "Reliable Inter-RAT Handover Info" },					/* 11.3.107 Reliable Inter-RAT Handover Info */ 
/* 11.3.108 SON Transfer Application Identity */
	{ 0x00, "CSG Identifier" },										/* 11.3.109 CSG Identifier */
/* 11.3.110 Tracking Area Code */	
	
	{ 0, NULL }
};

#define	NUM_BSSGP_ELEM (sizeof(bssgp_elem_strings)/sizeof(value_string))
gint ett_bssgp_elem[NUM_BSSGP_ELEM];


typedef enum
{
	DE_BSSGP_ALIGNMENT_OCTETS,									/* 11.3.1	0x00 Alignment octets */
	DE_BSSGP_BMAX_DEFAULT_MS,									/* 11.3.2	0x01 Bmax default MS  */
	DE_BSSGP_BSS_AREA_IND,										/* 11.3.3	0x02 BSS Area Indication */
	DE_BSSGP_BUCKET_LEAK_RATE,									/* 11.3.4	0x03 Bucket Leak Rate (R) */
	DE_BSSGP_BVCI,												/* 11.3.6	0x04 BVCI (BSSGP Virtual Connection Identifier)  */
	DE_BSSGP_BVC_BUCKET_SIZE,									/* 11.3.5	0x05 BVC Bucket Size */
	DE_BSSGP_BVC_MEAS,											/* 11.3.7	0x06 BVC Measurement */
	DE_BSSGP_CAUSE,												/* 11.3.8	0x07 Cause */
	DE_BSSGP_CELL_ID,											/* 11.3.9	0x08 Cell Identifier */
	DE_BSSGP_CHLN_NEEDED,										/* 11.3.10	0x09 Channel needed */
	DE_BBSGP_DRX_PARAM,											/* 11.3.11	0x0a DRX Parameters GSM_A_PDU_TYPE_GM, DE_DRX_PARAM */
	DE_BBSGP_EMLPP_PRIO,										/* 11.3.12	0x0b eMLPP-Priority BSSAP_PDU_TYPE_BSSMAP, BE_EMLPP_PRIO*/
	DE_BSSGP_FLUSH_ACTION,										/* 11.3.13	0x0c Flush Action */
	DE_BSSGP_IMSI,												/* 11.3.14	0x0d IMSI */
	DE_BSSGP_LLC_PDU,											/* 11.3.15	0x0e LLC-PDU */
 	DE_BSSGP_LLC_FRAMES_DISC,									/* 11.3.16	0x0f LLC Frames Discarded  */
	DE_BSSGP_LAI	,											/* 11.3.17	0x10 Location Area  GSM_A_PDU_TYPE_COMMON, DE_LAI*/
	DE_BSSGP_MID,												/* 11.3.20	0x11 Mobile Id GSM_A_PDU_TYPE_COMMON, DE_MID*/
	DE_BSSGP_MS_BUCKET_SIZE,									/* 11.3.21	0x12 MS Bucket Size */
	DE_BSSGP_MS_RAD_ACC_CAP,									/* 11.3.22	0x13 MS Radio Access Capability GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP*/
	DE_BSSGP_OMC_ID,											/* 11.3.23	0x14 OMC Id */
	DE_BSSGP_PDU_IN_ERROR,										/* 11.3.24	0x15 PDU In Error */
	DE_BSSGP_PDU_LIFETIME,										/* 11.3.25	0x16 PDU Lifetime */
	DE_BSSP_PRIORITY,											/* 11.3.27  0x17	Priority */
	DE_BSSGP_QOS_PROFILE,										/* 11.3.28	0x18 QoS Profile */
	DE_BSSGP_RA_CAUSE,											/* 11.3.29	0x19 Radio Cause */
	DE_BSSGP_RA_CAP_UPD_CAUSE,									/* 11.3.30	0x1a RA-Cap-UPD-Cause */
	DE_BSSGP_RAI,												/* 11.3.31	0x1b Routeing Area GSM_A_PDU_TYPE_GM, DE_RAI*/
	DE_BSSGP_R_DEFAULT_MS,										/* 11.3.32	0x1c R_default_MS */
	DE_BBSGP_SUSPEND_REF_NO,									/* 11.3.33	0x1d Suspend Reference Number */ 
	DE_BSSGP_TAG,												/* 11.3.34	0x1e Tag */
	DE_BSSGP_TLLI,												/* 11.3.35	0x1f Temporary logical link Identity (TLLI) GSM_A_PDU_TYPE_RR, DE_RR_TLLI*/
	DE_BSSGP_TMSI_PTMSI,										/* 11.3.36	0x20 Temporary Mobile Subscriber Identity (TMSI) GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI*/
	DE_BSSGP_TRACE_REF,											/* 11.3.37	0x21 Trace Reference */
	DE_BSSGP_TRACE_TYPE,										/* 11.3.38	0x22 Trace Type */
	DE_BSSGP_TRANSACTION_ID,									/* 11.3.39	0x23 Transaction Id */
	DE_BSSGP_TRIGGER_ID,										/* 11.3.40	0x24 Trigger Id */
	DE_BSSGP_NO_OF_OCT_AFFECTED,								/* 11.3.41	0x25 Number of octets affected */
	DE_BSSGP_LSA_ID_LIST,										/* 11.3.18	0x26 LSA Identifier List GSM_A_PDU_TYPE_BSSMAP, BE_LSA_ID_LIST*/
	DE_BSSGP_LSA_INFO,											/* 11.3.19	0x27 LSA Information GSM_A_PDU_TYPE_BSSMAP, BE_LSA_INFO */
	DE_BSSGP_ACKET_FLOW_ID,										/* 11.3.42	0x28 Packet Flow Identifier (PFI)  GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID*/
	DE_BSSGP_GPRS_TIMER,										/* 11.3.44	0x29 GPRS Timer */
	DE_BSSGP_QOS,												/* 11.3.43	0x3a Aggregate BSS QoS Profile GSM_A_PDU_TYPE_GM, DE_QOS*/
	DE_BSSGP_FEATURE_BITMAP,									/* 11.3.45	0x3b Feature Bitmap */
	DE_BSSGP_BUCKET_FULL_RATIO,									/* 11.3.46	0x3c Bucket Full Ratio */
	DE_BSSGP_SERV_UTRAN_CCO,									/* 11.3.47	0x3d Service UTRAN CCO */
	DE_BSSGP_NSEI,												/* 11.3.48	0x3e NSEI (Network Service Entity Identifier) */

	DE_BSSGP_PFC_FLOW_CTRL,										/* 11.3.68	PFC Flow Control parameters */
	DE_BSSGP_GLOBAL_CN_ID,										/* 11.3.69	Global CN-Id SGSAP_PDU_TYPE, DE_SGSAP_GLOBAL_CN_ID*/
	DE_BSSGP_MBMS_SESSION_ID,									/* 11.3.71	MBMS Session Identity */
	DE_BSSGP_TMGI,												/* 11.3.77	TMGI (Temporary Mobile Group Identity) GSM_A_PDU_TYPE_GM, DE_TMGI*/
	DE_BSSGP_SOURCE_BSS_TO_TARGET_BSS_TRANSP_CONT,				/* 11.3.79	Source BSS to Target BSS Transparent Container */
	DE_BSSGP_TARGET_BSS_TO_SOURCE_BSS_TRANSP_CONT,				/* 11.3.80	Target BSS to Source BSS Transparent Container */

	DE_BSSGP_LIST_OF_SETUP_PFCS,								/* 11.3.83	List of set-up PFCs */
	DE_BSSGP_EXT_FEATURE_BITMAP,								/* 11.3.84	Extended Feature Bitmap */
	DE_BSSGP_SRC_TO_TRG_TRANSP_CONT,							/* 11.3.85	Source to Target Transparent Container */
	DE_BSSGP_TRG_TO_SRC_TRANSP_CONT,							/* 11.3.86	Target to Source Transparent Container */
	BE_BSSGP_RNC_ID,											/* 11.3.87	RNC Identifier */
	DE_BSSGP_PAGE_MODE,											/* 11.3.88	Page Mode */
 	DE_BSSGP_CONTAINER_ID,										/* 11.3.89	Container ID */
	DE_BSSGP_GLOBAL_TFI,										/* 11.3.90	Global TFI */

	DE_BSSGP_INTER_RAT_HO_INFO,									/* 11.3.94	Inter RAT Handover Info */
	DE_BSSGP_PS_HO_CMD,											/* 11.3.95	PS Handover Command */
 	DE_BSSGP_PS_HO_INDICATIONS,									/* 11.3.95a	PS Handover Indications */
 	DE_BSSGP_SIPSI_CONTAINER,									/* 11.3.95b	SI/PSI Container */
 	DE_BSSGP_ACTIVE_PFCS_LIST,									/* 11.3.95c	Active PFCs List */
 	DE_BBSGP_DTM_HO_CMD,										/* 11.3.97	DTM Handover Command */
	DE_BSSGP_CS_INDICATION,										/* 11.3.98	CS Indication */
	DE_BSSGP_FLOW_CONTROL_GRAN,									/* 11.3.102	Flow Control Granularity */
	DE_BSSGP_ENB_ID,											/* 11.3.103 	eNB Identifier */
	DE_BSSGP_E_UTRAN_INTER_RAT_HO_INFO,							/* 11.3.104	E-UTRAN Inter RAT Handover Info */
 	DE_BSSGP_SUB_PROF_ID_F_RAT_FRQ_PRIO,						/* 11.3.105 Subscriber Profile ID for RAT/Frequency priority */
	DE_BSSGP_RELIABLE_INTER_RAT_HO_INF,							/* 11.3.107 Reliable Inter-RAT Handover Info */ 
	DE_BSSGP_CSG_ID,											/* 11.3.109 CSG Identifier */
	DE_BSSGP_NONE												/* NONE */
}
bssgp_elem_idx_t;

guint16 (*bssgp_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
	de_bssgp_aligment_octets,									/* 11.3.1	0x00 Alignment octets */
	de_bssgp_bmax_default_ms,									/* 11.3.2	0x01 Bmax default MS  */
	de_bssgp_bss_area_ind,										/* 11.3.3	0x02 BSS Area Indication */
	de_bssgp_bucket_leak_rate,									/* 11.3.4	0x03 Bucket Leak Rate (R) */
	de_bssgp_bvci,												/* 11.3.6	0x04 BVCI (BSSGP Virtual Connection Identifier)  */
	de_bssgp_bvc_bucket_size,									/* 11.3.5	0x05 BVC Bucket Size */
	de_bssgp_bvc_meas,											/* 11.3.7	0x06 BVC Measurement */
	de_bssgp_cause,												/* 11.3.8	0x07 Cause */
 	de_bssgp_cell_id,											/* 11.3.9	0x08 Cell Identifier */
	de_bssgp_chnl_needed,										/* 11.3.10	0x09 Channel needed */
	NULL,														/* 11.3.11	0x0a DRX Parameters */
	NULL,														/* 11.3.12	0x0b eMLPP-Priority */
	de_bssgp_flush_action,										/* 11.3.13	0x0c Flush Action */
	de_mid,														/* 11.3.14	0x0d IMSI */
	de_bssgp_llc_pdu,											/* 11.3.15	0x0e LLC-PDU */
 	de_bssgp_llc_frames_disc,									/* 11.3.16	0x0f LLC Frames Discarded  */
	NULL,														/* 11.3.17	0x10 Location Area  */
	NULL,														/* 11.3.20	0x11 Mobile Id */
	de_bssgp_ms_bucket_size,									/* 11.3.21	0x12 MS Bucket Size */
	NULL,														/* 11.3.22	0x13 MS Radio Access Capability */
	de_bssgp_omc_id,											/* 11.3.23	0x14 OMC Id */
	de_bssgp_pdu_in_error,										/* 11.3.24	0x15 PDU In Error */
	de_bssgp_pdu_lifetime,										/* 11.3.25	0x16 PDU Lifetime */
	NULL,														/* 11.3.27  0x17	Priority */
	de_bssgp_qos_profile,										/* 11.3.28	0x18 QoS Profile */
	de_bssgp_ra_cause,											/* 11.3.29	0x19 Radio Cause */
	de_bssgp_ra_cap_upd_cause,									/* 11.3.30	0x1a RA-Cap-UPD-Cause */
	NULL,														/* 11.3.31	0x1b Routeing Area */
	de_bssgp_r_default_ms,										/* 11.3.32	0x1c R_default_MS */
	de_bssgp_suspend_ref_no,									/* 11.3.33	0x1d Suspend Reference Number */ 
	de_bssgp_tag,												/* 11.3.34	0x1e Tag */
	NULL,														/* 11.3.35	0x1f Temporary logical link Identity (TLLI) */
	NULL,														/* 11.3.36	0x20 Temporary Mobile Subscriber Identity (TMSI) */
 	de_bssgp_trace_ref,											/* 11.3.37	0x21 Trace Reference */
 	de_bssgp_trace_type,										/* 11.3.38	0x22 Trace Type */
	de_bssgp_transaction_id,									/* 11.3.39	0x23 Transaction Id */
	de_bssgp_trigger_id,										/* 11.3.40	0x24 Trigger Id */
	de_bssgp_no_of_oct_affected,								/* 11.3.41	0x25 Number of octets affected */
	NULL,														/* 11.3.18	0x26 LSA Identifier List GSM_A_PDU_TYPE_BSSMAP, BE_LSA_ID_LIST*/
	NULL,														/* 11.3.19	0x27 LSA Information */
	NULL,														/* 11.3.42	0x28 Packet Flow Identifier (PFI) */
	de_bssgp_gprs_timer,										/* 11.3.44	0x29 GPRS Timer */
	NULL,														/* 11.3.43	0x3a Aggregate BSS QoS Profile */
	de_bssgp_feature_bitmap,									/* 11.3.45	0x3b Feature Bitmap */
	de_bssgp_bucket_full_ratio,									/* 11.3.46	0x3c Bucket Full Ratio */
	de_bssgp_serv_utran_cco,									/* 11.3.47	0x3d Service UTRAN CCO */
	de_bssgp_nsei,												/* 11.3.48	0x3e NSEI (Network Service Entity Identifier) */
	NULL,														/* 11.3.69	0x53 Global CN-Id */
	de_bssgp_mbms_session_id,									/* 11.3.71	MBMS Session Identity */
	NULL,														/* 11.3.77	TMGI (Temporary Mobile Group Identity) */
	de_bssgp_source_BSS_to_target_BSS_transp_cont,				/* 11.3.79	Source BSS to Target BSS Transparent Container */
	de_bssgp_target_BSS_to_source_BSS_transp_cont,				/* 11.3.80	Target BSS to Source BSS Transparent Container */
	de_bssgp_list_of_setup_pfcs,								/* 11.3.83	List of set-up PFCs */
	de_bssgp_ext_feature_bitmap,								/* 11.3.84	Extended Feature Bitmap */
	de_bssgp_src_to_trg_transp_cont,							/* 11.3.85	Source to Target Transparent Container */
	de_bssgp_trg_to_src_transp_cont,							/* 11.3.86	Target to Source Transparent Container */
	de_bssgp_rnc_identifier,									/* 11.3.87	RNC Identifier */
	de_bssgp_page_mode,											/* 11.3.88	Page Mode */
	de_bssgp_container_id,										/* 11.3.89	Container ID */
	de_bssgp_global_tfi,										/* 11.3.90	Global TFI */
	de_bssgp_inter_rat_ho_info,									/* 11.3.94	Inter RAT Handover Info */
	de_bssgp_ps_ho_cmd,											/* 11.3.95	PS Handover Command */
 	de_bssgp_ps_ho_indications,									/* 11.3.95a	PS Handover Indications */
 	de_bssgp_sipsi_container,									/* 11.3.95b	SI/PSI Container */
	de_bssgp_active_pfcs_list,									/* 11.3.95c	Active PFCs List */
 	de_bssgp_dtm_ho_cmd,										/* 11.3.97	DTM Handover Command */
	de_bssgp_cs_indication,										/* 11.3.98	CS Indication */
	de_bssgp_flow_control_gran,									/* 11.3.102	Flow Control Granularity */
	de_bssgp_enb_id,											/* 11.3.103 	eNB Identifier */
	de_bssgp_e_utran_inter_rat_ho_info,							/* 11.3.104	E-UTRAN Inter RAT Handover Info */
	de_bssgp_sub_prof_id_f_rat_freq_prio,						/* 11.3.105	Subscriber Profile ID for RAT/Frequency priority */
	de_bssgp_reliable_inter_rat_ho_inf,							/* 11.3.107 Reliable Inter-RAT Handover Info */ 
	de_bssgp_csg_id,											/* 11.3.109 CSG Identifier */

	NULL,	/* NONE */
};


/* 11.3.79	Source BSS to Target BSS Transparent Container */
static guint16
de_bssgp_source_BSS_to_target_BSS_transp_cont(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;


	/* Octet 3-? Source BSS to Target BSS Transparent Container Contents coded
	 * as defined in table 11.3.79.b
	 */
	/* MS Radio Access Capability MS Radio Access Capability/11.3.22 M TLV 7-? */
	ELEM_IN_ELM_OPT_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);
	/* Inter RAT Handover Info Inter RAT Handover Info/11.3.94 O (note 1) TLV 3-? */
	ELEM_IN_ELM_OPT_TELV(0x73, BSSGP_PDU_TYPE, DE_BSSGP_INTER_RAT_HO_INFO, NULL);
	/* Page Mode Page Mode/11.3.88 O (note 2, note 3) TLV 3 */
	ELEM_IN_ELM_OPT_TELV(0x6d, BSSGP_PDU_TYPE, DE_BSSGP_PAGE_MODE, NULL);
	/* Container ID Container ID/11.3.89 O (note 2) TLV 3 */
	ELEM_IN_ELM_OPT_TELV(0x6e, BSSGP_PDU_TYPE, DE_BSSGP_CONTAINER_ID, NULL);
	/* Global TFI Global TFI/11.3.90 O (note 2, note 3) TLV 3 */
	ELEM_IN_ELM_OPT_TELV(0x6f, BSSGP_PDU_TYPE, DE_BSSGP_GLOBAL_TFI, NULL);
	/* PS Handover Indications PS Handover Indications/11.3.95a O TLV 3 */
	ELEM_IN_ELM_OPT_TELV(0x75, BSSGP_PDU_TYPE, DE_BSSGP_PS_HO_INDICATIONS, NULL);
	/* CS Indication CS Indication/11.3.98 O (note 3) TLV 3 */
	ELEM_IN_ELM_OPT_TELV(0x7a, BSSGP_PDU_TYPE, DE_BSSGP_CS_INDICATION, NULL);
	/* E-UTRAN Inter RAT Handover Info E-UTRAN Inter RAT HandoverInfo/11.3.104 O (note 1) TLV 3-? */
	ELEM_IN_ELM_OPT_TELV(0x80, BSSGP_PDU_TYPE, DE_BSSGP_E_UTRAN_INTER_RAT_HO_INFO, NULL);

	return(curr_offset-offset);
}

/*
 * 11.3.80 Target BSS to Source BSS Transparent Container
 */
static guint16
de_bssgp_target_BSS_to_source_BSS_transp_cont(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;


	/* Octet 3-? Target BSS to Source BSS Transparent Container Contents coded
	 * as defined in table 11.3.80.b
	 */

	/* PS Handover Command PS Handover Command/11.3.95 O (Note 2) TLV 4-? */
	ELEM_IN_ELM_OPT_TELV(0x74, BSSGP_PDU_TYPE, DE_BSSGP_PS_HO_CMD, NULL);
	/* SI/PSI Container SI/PSI Container/11.3.95b O (Note 1) TLV 3-? */
	ELEM_IN_ELM_OPT_TELV(0x76, BSSGP_PDU_TYPE, DE_BSSGP_SIPSI_CONTAINER, NULL);
	/* DTM Handover Command DTM Handover Command/11.3.97 O (Note 2) TLV 22-? */
	ELEM_IN_ELM_OPT_TELV(0x79, BSSGP_PDU_TYPE, DE_BBSGP_DTM_HO_CMD, NULL);

	return(curr_offset-offset);
}

/* MESSAGE FUNCTIONS */

/* 
 * 10.2	PDU functional definitions and contents at RL and BSSGP SAPs
 * 10.2.1 DL-UNITDATA
 */
static void
bssgp_dl_unitdata(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU is sent to the BSS to transfer an LLC-PDU across the radio interface to an MS. */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI (current) TLLI/11.3.35 M V 4 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TLLI);
	/* QoS Profile (note 1) QoS Profile/11.3.28 M V 3 */
	ELEM_MAND_V(BSSGP_PDU_TYPE, DE_BSSGP_QOS_PROFILE);

	/* PDU Lifetime PDU Lifetime/11.3.25 M TLV 4 */
	ELEM_MAND_TELV(0x16, BSSGP_PDU_TYPE, DE_BSSGP_PDU_LIFETIME, NULL);
	/* MS Radio Access Capability (note 2) MS Radio Access Capability/11.3.22 O TLV 7-? */
	ELEM_OPT_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);
	/* Priority (note 3) Priority/11.3.27 O TLV 3 */
	ELEM_OPT_TELV(0x0b, GSM_A_PDU_TYPE_BSSMAP, BE_PRIO, NULL);
	/* DRX Parameters DRX Parameters/11.3.11 O TLV 4 */
	ELEM_OPT_TELV(0x0a , GSM_A_PDU_TYPE_GM, DE_DRX_PARAM , NULL);
	/* IMSI IMSI/11.3.14 O TLV 5-10 */
	ELEM_OPT_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* TLLI (old) TLLI/11.3.35 O TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , " - old");
	/* PFI PFI/11.3.42 O TLV 3 */
	ELEM_OPT_TELV( BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* LSA Information LSA Information/11.3.19 O TLV 7-? */
	ELEM_OPT_TELV(0x27, GSM_A_PDU_TYPE_BSSMAP, BE_LSA_INFO, NULL);
	/* Service UTRAN CCO Service UTRAN CCO/11.3.47 O TLV 3 */
	ELEM_OPT_TELV(0x3d, BSSGP_PDU_TYPE, DE_BSSGP_SERV_UTRAN_CCO, NULL);
	
	/* Subscriber Profile ID for RAT/Frequency priority (note 5)
	 * Subscriber Profile ID for RAT/Frequency priority/11.3.105 O TLV 3
	 */
	ELEM_OPT_TELV(0x81, BSSGP_PDU_TYPE, DE_BSSGP_SUB_PROF_ID_F_RAT_FRQ_PRIO, NULL);
	/* Alignment octets Alignment octets/11.3.1 O TLV 2-5 */
	ELEM_OPT_TELV(0x00, BSSGP_PDU_TYPE, DE_BSSGP_ALIGNMENT_OCTETS, NULL);
	/* LLC-PDU (note 4) LLC-PDU/11.3.15 M TLV 2-? */
	ELEM_MAND_TELV(0x0e, BSSGP_PDU_TYPE, DE_BSSGP_LLC_PDU, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.2.2	UL-UNITDATA	
 */
static void
bssgp_ul_unitdata(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU transfers an MS's LLC-PDU and its associated radio interface information across the Gb-interface.
	 * Direction: BSS to SGSN
	 */
	gpinfo->link_dir = P2P_DIR_UL;
	/* TLLI TLLI/11.3.35 M V 4 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TLLI);
	/* QoS Profile QoS Profile/11.3.28 M V 3 */
	ELEM_MAND_V(BSSGP_PDU_TYPE, DE_BSSGP_QOS_PROFILE);
	/* Cell Identifier Cell Identifier/11.3.9 M TLV 10 */
	ELEM_OPT_TELV(0x08, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , NULL);
	/* PFI PFI/11.3.42 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* LSA Identifier List LSA Identifier List/11.3.18 O TLV 3-?  */
	ELEM_OPT_TLV(0x26, GSM_A_PDU_TYPE_BSSMAP, BE_LSA_ID_LIST, NULL);
	/* Alignment octets Alignment octets/11.3.1 O TLV 2-5  */
	ELEM_OPT_TELV(0x00, BSSGP_PDU_TYPE, DE_BSSGP_ALIGNMENT_OCTETS, NULL);
	/* LLC-PDU (note) LLC-PDU/11.3.15 M TLV 2-?  */
	ELEM_MAND_TELV(0x0e, BSSGP_PDU_TYPE, DE_BSSGP_LLC_PDU, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.2.3	RA-CAPABILITY
 */
static void
bssgp_ra_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the BSS of the new Radio Access Capability of an MS. */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* MS Radio Access Capability MS Radio Access Capability/11.3.22 M TLV 7-? */
	ELEM_MAND_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.2.4	(void)
 */
/*
 * 10.2.5	DL-MBMS-UNITDATA
 */
static void
bssgp_dl_mbms_unitdata(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU is sent to the BSS to transfer an LLC-PDU across the radio interface.
	 * Direction: SGSN to BSS 
	 */
	gpinfo->link_dir = P2P_DIR_DL;

	/* PDU Lifetime PDU Lifetime/11.3.25 M TLV 4  */
	ELEM_MAND_TELV(0x16, BSSGP_PDU_TYPE, DE_BSSGP_PDU_LIFETIME, NULL);
	/* TMGI TMGI/ 11.3.77 M TLV 3-8 */
	ELEM_MAND_TELV(0x5c, GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);
	/* MBMS Session Identity MBMS Session Identity/ 11.3.71 O TLV 3 */
	ELEM_OPT_TELV(0x5d, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_ID, NULL);
	/* Alignment octets Alignment octets/11.3.1 O TLV 2-5 */
	ELEM_OPT_TELV(0x00, BSSGP_PDU_TYPE, DE_BSSGP_ALIGNMENT_OCTETS, NULL);
	/* LLC-PDU LLC-PDU/11.3.15 M TLV 3-? */
	ELEM_MAND_TELV(0x0e, BSSGP_PDU_TYPE, DE_BSSGP_LLC_PDU, NULL);


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.2.6	UL-MBMS-UNITDATA
 */
static void
bssgp_ul_mbms_unitdata(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU transfers an LLC-PDU for an MBMS session across the Gb-interface.
	 * Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TMGI TMGI/ 11.3.77 M TLV 3-8 */
	ELEM_MAND_TELV(0x5c, GSM_A_PDU_TYPE_GM, DE_TMGI, NULL);
	/* MBMS Session Identity MBMS Session Identity/ 11.3.71 O TLV 3 */
	ELEM_OPT_TELV(0x5d, BSSGP_PDU_TYPE, DE_BSSGP_MBMS_SESSION_ID, NULL);
	/* Alignment octets Alignment octets/11.3.1 O TLV 2-5 */
	ELEM_OPT_TELV(0x00, BSSGP_PDU_TYPE, DE_BSSGP_ALIGNMENT_OCTETS, NULL);
	/* LLC-PDU (note 1) LLC-PDU/11.3.15 M TLV 2-? */
	ELEM_MAND_TELV(0x0e, BSSGP_PDU_TYPE, DE_BSSGP_LLC_PDU, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.3	PDU functional definitions and contents at GMM SAP
 * 10.3.1	PAGING PS
 */

static void
bssgp_paging_ps(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	/* This PDU indicates that a BSS shall initiate the packet paging procedure for an MS within a group of cells.
	 * Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* IMSI IMSI/11.3.14 M TLV 5 -10 */
	ELEM_MAND_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* DRX Parameters DRX Parameters/11.3.11 O TLV 4 */
	ELEM_OPT_TELV(0x0a , GSM_A_PDU_TYPE_GM, DE_DRX_PARAM , NULL);
	/* BVCI a) BVCI/11.3.6 C TLV 4 */
	ELEM_OPT_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Location Area (note) Location Area/11.3.17 C TLV 7 */
	ELEM_OPT_TELV(0x10,GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);
	/* Routeing Area (note) Routeing Area/11.3.31 C TLV 8 */
	ELEM_OPT_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* BSS Area Indication (note) BSS Area Indication/11.3.3 C TLV 3 */ 
	ELEM_OPT_TELV(0x02,BSSGP_PDU_TYPE, DE_BSSGP_BSS_AREA_IND, NULL);
	/* PFI PFI/11.3.42 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* ABQP ABQP/11.3.43 O TLV 13-? */
	ELEM_OPT_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);
	/* QoS Profile QoS Profile/11.3.28 M TLV 5 */
	ELEM_MAND_TELV(0x18,BSSGP_PDU_TYPE, DE_BSSGP_QOS_PROFILE, NULL);
	/* P-TMSI TMSI/11.3.36 O TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TMSI,GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.3.2	PAGING CS
 */
static void
bssgp_paging_cs(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	/* This PDU indicates that a BSS shall initiate a circuit-switched paging procedure for an MS within a group of cells.
	 * Direction: SGSN to BSS
	 */
	gpinfo->link_dir = P2P_DIR_DL;
	/* IMSI IMSI/11.3.14 M TLV 5 -10 */
	ELEM_MAND_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* DRX Parameters DRX Parameters/11.3.11 M TLV 4 */
	ELEM_MAND_TELV(0x0a , GSM_A_PDU_TYPE_GM, DE_DRX_PARAM , NULL);
	/* BVCI a) BVCI/11.3.6 C TLV 4 */
	ELEM_OPT_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Location Area (note 1) Location Area/11.3.17 C TLV 7 */
	ELEM_OPT_TELV(0x10,GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);
	/* Routeing Area (note 1) Routeing Area/11.3.31 C TLV 8 */
	ELEM_OPT_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* BSS Area Indication (note 1) BSS Area Indication/11.3.3 C TLV 3 */
	ELEM_OPT_TELV(0x02,BSSGP_PDU_TYPE, DE_BSSGP_BSS_AREA_IND, NULL);
	/* TLLI TLLI/11.3.35 O TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Channel needed (note 2) Channel needed/11.3.10 O TLV 3 */
	ELEM_OPT_TELV(0x09, BSSGP_PDU_TYPE, DE_BSSGP_CHLN_NEEDED , NULL);
	/* eMLPP-Priority (note 2) eMLPP-Priority/11.3.12 O TLV 3 */
	ELEM_OPT_TELV(0x0b, GSM_A_PDU_TYPE_BSSMAP, BE_EMLPP_PRIO, NULL);
	/* TMSI (note 2) TMSI/11.3.36 O TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TMSI,GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, NULL);
	/* Global CN-Id (note 2) Global CN-Id/11.3.69 O TLV 7 */
	ELEM_OPT_TELV(0x53, SGSAP_PDU_TYPE, DE_SGSAP_GLOBAL_CN_ID, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.3.3	RA-CAPABILITY-UPDATE
 */
static void
bssgp_ra_cap_upd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	/* This PDU requests that the SGSN send an MS's current Radio Access capability or IMSI to the BSS. */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);
	/* IMSI (note) IMSI/11.3.14 C TLV 5 -10 */
	ELEM_OPT_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* RA-Cap-UPD-CAUSE RA-Cap-UPDCAUSE/11.3.30 M TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_RA_CAP_UPD_CAUSE, BSSGP_PDU_TYPE, DE_BSSGP_RA_CAP_UPD_CAUSE , NULL);
	/* MS Radio Access Capability MS Radio Access Capability/11.3.22 C TLV 7-? */
	ELEM_OPT_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.3.4	RA-CAPABILITY-UPDATE-ACK
 */

static void
bssgp_ra_cap_upd_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	/* This PDU provides the BSS with an MS's current Radio Access capability and IMSI */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);
	/* IMSI (note) IMSI/11.3.14 C TLV 5 -10 */
	ELEM_OPT_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* RA-Cap-UPD-CAUSE RA-Cap-UPDCAUSE/11.3.30 M TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_RA_CAP_UPD_CAUSE, BSSGP_PDU_TYPE, DE_BSSGP_RA_CAP_UPD_CAUSE , NULL);
	/* MS Radio Access Capability MS Radio Access Capability/11.3.22 C TLV 7-? */
	ELEM_OPT_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.3.5	RADIO-STATUS
 */
static void
bssgp_ra_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that an exception condition related to the radio interface has occurred. */
	/* BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI (note) TLLI/11.3.35 C TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* TMSI (note) TMSI/11.3.36 C TLV 6 */
	ELEM_OPT_TELV(BSSGP_IEI_TMSI,GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, NULL);
	/* IMSI (note) IMSI/11.3.14 C TLV 5-10 */
	ELEM_OPT_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* Radio Cause Radio Cause/11.3.29 M TLV 3 */ 
	ELEM_MAND_TELV(BSSGP_IEI_RADIO_CAUSE, BSSGP_PDU_TYPE, DE_BSSGP_RA_CAUSE , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.3.6	SUSPEND
 */
static void
bssgp_suspend(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that an MS wishes to suspend its GPRS service. */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.3.7	SUSPEND-ACK
 */
static void
bssgp_suspend_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU positively acknowledges the reception of a SUSPEND PDU for an MS. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* Suspend Reference Number Suspend Reference Number/11.3.33 M TLV 3 */
	ELEM_MAND_TELV(0x1d,BSSGP_PDU_TYPE, DE_BBSGP_SUSPEND_REF_NO, NULL);


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.3.8	SUSPEND-NACK
 */
static void
bssgp_suspend_nack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;


	/* This PDU negatively acknowledges the reception of a SUSPEND PDU for an MS. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* Cause Cause/11.3.8 O TLV 3 */ 
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.3.9	RESUME
 */
static void
bssgp_resume(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that an MS wishes to RESUME its GPRS service. */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* Suspend Reference Number Suspend Reference Number/11.3.33 M TLV 3 */
	ELEM_MAND_TELV(0x1d,BSSGP_PDU_TYPE, DE_BBSGP_SUSPEND_REF_NO, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.3.10	RESUME-ACK
 */

static void
bssgp_resume_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU positively acknowledges the reception of a RESUME PDU for an MS. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.3.11	RESUME-NACK
 */

static void
bssgp_resume_nack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU negatively acknowledges the reception of a RESUME PDU for an MS. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Routeing Area Routeing Area/11.3.31 M TLV 8 */
	ELEM_MAND_TELV(0x1b,GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
	/* Cause Cause/11.3.8 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4	PDU functional definitions and contents at NM SAP
 * 10.4.1	FLUSH-LL
 */
static void
bssgp_flush_ll(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs a BSS that an MS has moved from one cell to another. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* BVCI (old) BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - Old");
	/* BVCI (new) BVCI/11.3.6 O TLV 4 */
	ELEM_OPT_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - New");
	/* NSEI (new) NSEI/11.3.48 O (note) TLV 4 */
	ELEM_OPT_TELV(0x3e, GSM_A_PDU_TYPE_RR, DE_BSSGP_NSEI , " - New");

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.2	FLUSH-LL-ACK
 */
static void
bssgp_flush_ll_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that LLC-PDU(s) buffered for an MS in the old cell
	 * have been either deleted or transferred to the new cell within the routing area. */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Flush Action Flush Action/11.3.13 M TLV 3 */
	ELEM_MAND_TELV(0x0c, BSSGP_PDU_TYPE, DE_BSSGP_FLUSH_ACTION , NULL);
	/* BVCI (new) BVCI/11.3.13 C (note 1) TLV 4 */
	ELEM_OPT_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , " - New");
	/* Number of octets affected Number of octets affected/11.3.41 M TLV 5 */
	ELEM_MAND_TELV(BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED, BSSGP_PDU_TYPE, DE_BSSGP_NO_OF_OCT_AFFECTED , NULL);
	/* NSEI (new) NSEI/11.3.48 C (note 2) TLV 4 */
	ELEM_OPT_TELV(0x3e, GSM_A_PDU_TYPE_RR, DE_BSSGP_NSEI , " - New");


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.3	LLC-DISCARDED
 */
static void
bssgp_llc_discarded(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* LLC Frames Discarded LLC Frames Discarded/11.3.16 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_LLC_FRAMES_DISCARDED, BSSGP_PDU_TYPE, DE_BSSGP_LLC_FRAMES_DISC , NULL);
	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Number of octets deleted Number of octets affected/11.3.41 M TLV 5 */
	ELEM_MAND_TELV(BSSGP_IEI_NUMBER_OF_OCTETS_AFFECTED, BSSGP_PDU_TYPE, DE_BSSGP_NO_OF_OCT_AFFECTED , NULL);
	/* PFI (note) PFI/11.3.42 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.4	FLOW-CONTROL-BVC
 */
static void
bssgp_flow_control_bvc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the flow control mechanism at an SGSN of the status of a 
	 * BVC's maximum acceptable SGSN to BSS throughput on the Gb interface.
	 */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);
	/* BVC Bucket Size BVC Bucket Size/11.3.5 M TLV 4 */ 
	ELEM_MAND_TELV(0x05, BSSGP_PDU_TYPE, DE_BSSGP_BVC_BUCKET_SIZE , NULL);
	/* Bucket Leak Rate Bucket Leak Rate/11.3.4 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BUCKET_LEAK_RATE, BSSGP_PDU_TYPE, DE_BSSGP_BUCKET_LEAK_RATE , NULL);
	/* Bmax default MS Bmax default MS/11.3.2 M TLV 4 */
	ELEM_MAND_TELV(0x01, BSSGP_PDU_TYPE, DE_BSSGP_BMAX_DEFAULT_MS , NULL);
	/* R_default_MS R_default_MS/11.3.32 M TLV 4 */
	ELEM_MAND_TELV(0x1c, BSSGP_PDU_TYPE, DE_BSSGP_R_DEFAULT_MS , NULL);
	/* Bucket_Full Ratio Bucket_Full Ratio/11.3.46 C TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_BUCKET_FULL_RATIO, BSSGP_PDU_TYPE, DE_BSSGP_BUCKET_FULL_RATIO , NULL);
	/* BVC Measurement BVC Measurement/11.3.7 O TLV 4  */
	ELEM_OPT_TELV(0x06, BSSGP_PDU_TYPE, DE_BSSGP_BVC_MEAS , NULL);
	/* Flow Control Granularity (note) Flow Control Granularity/11.3.102 O TLV 3 */ 
	ELEM_OPT_TELV(0x7e, BSSGP_PDU_TYPE, DE_BSSGP_FLOW_CONTROL_GRAN , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.5	FLOW-CONTROL-BVC-ACK
 */
static void
bssgp_flow_control_bvc_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the flow control mechanism at the BSS that the SGSN has received 
	 * the FLOW-CONTROL-BVC PDU indicated by the Tag. 
	 */

	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.6	FLOW-CONTROL-MS
 */
static void
bssgp_flow_control_ms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the flow control mechanism at an SGSN of the status of an MS's  
	 * maximum acceptable SGSN to BSS throughput on the Gb interface.
	 */

	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);
	/* MS Bucket Size MS Bucket Size/11.3.21 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_MS_BUCKET_SIZE, BSSGP_PDU_TYPE, DE_BSSGP_MS_BUCKET_SIZE , NULL);
	/* Bucket Leak rate Bucket Leak rate/11.3.4 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BUCKET_LEAK_RATE, BSSGP_PDU_TYPE, DE_BSSGP_BUCKET_LEAK_RATE , NULL);
	/* Bucket_Full Ratio Bucket_Full Ratio/11.3.46 C TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_BUCKET_FULL_RATIO, BSSGP_PDU_TYPE, DE_BSSGP_BUCKET_FULL_RATIO , NULL);
	/* Flow Control Granularity (note) Flow Control Granularity/11.3.102 O TLV 3 */
	ELEM_OPT_TELV(0x7e, BSSGP_PDU_TYPE, DE_BSSGP_FLOW_CONTROL_GRAN , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.7	FLOW-CONTROL-MS-ACK
 */
static void
bssgp_flow_control_ms_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the flow control mechanism at the BSS that the SGSN has received 
	 * the FLOW-CONTROL-MS PDU indicated by the TLLI and the Tag. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6  */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.8	BVC-BLOCK
 */

static void
bssgp_bvc_block(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that the contained BVC shall be blocked at the recipient entity. */
	/* BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.9	BVC-BLOCK-ACK
 */
static void
bssgp_bvc_block_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU acknowledges that a BVC has been blocked. */
	/* SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.10	BVC-UNBLOCK
 */
static void
bssgp_bvc_un_block(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that the identified BVC shall be unblocked at the recipient entity. */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.11	BVC-UNBLOCK-ACK
 */
 
static void
bssgp_bvc_un_block_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU acknowledges that a BVC has been unblocked. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.12	BVC-RESET
 */
 
static void
bssgp_bvc_reset(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that BVC initialisation is required, e.g. because of a BVC failure. */
	/* Direction: SGSN to BSS, BSS to SGSN */

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);
	/* Cell Identifier (note 1) C TLV 10 */
	ELEM_OPT_TELV(0x08, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , NULL);
	/* Feature bitmap (note 2) Feature bitmap/11.3.45 O TLV 3 */
	ELEM_OPT_TELV(0x3b, BSSGP_PDU_TYPE, DE_BSSGP_FEATURE_BITMAP , NULL);
	/* Extended Feature Bitmap (note 3) Extended Feature Bitmap/11.3.84 O TLV 3 */
	ELEM_OPT_TELV(0x69, BSSGP_PDU_TYPE, DE_BSSGP_EXT_FEATURE_BITMAP , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.13	BVC-RESET-ACK
 */
 
static void
bssgp_bvc_reset_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that BVC initialisation has been executed */
	/* BSS to SGSN, SGSN to BSS */

	/* BVCI BVCI/11.3.6 M TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Cell Identifier (note 1) C TLV 10 */
	ELEM_OPT_TELV(0x08, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , NULL);
	/* Feature bitmap (note 2) Feature bitmap/11.3.45 O TLV 3 */
	ELEM_OPT_TELV(0x3b, BSSGP_PDU_TYPE, DE_BSSGP_FEATURE_BITMAP , NULL);
	/* Extended Feature Bitmap (note 3) Extended Feature Bitmap/11.3.84 O TLV 3 */
	ELEM_OPT_TELV(0x69, BSSGP_PDU_TYPE, DE_BSSGP_EXT_FEATURE_BITMAP , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.14	STATUS
 */
static void
bssgp_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that an exception condition occurred. */
	/* Direction: SGSN to BSS, BSS to SGSN */

	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);
	/* BVCI BVCI/11.3.6 C TLV 4 */
	ELEM_MAND_TELV(BSSGP_IEI_BVCI, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* PDU In Error (note) PDU In Error/11.3.24 O TLV 3-? */
	ELEM_MAND_TELV(0x15, BSSGP_PDU_TYPE, DE_BSSGP_PDU_IN_ERROR , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.15	SGSN-INVOKE-TRACE
 */
static void
bssgp_sgsn_invoke_trace(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that the BSS shall begin the production of a trace record for an MS. */
	/* Direction: SGSN to BSS */

	gpinfo->link_dir = P2P_DIR_UL;

	/* Trace Type Trace Type/11.3.38 M TLV 3 */
	ELEM_MAND_TELV(0x22, BSSGP_PDU_TYPE, DE_BSSGP_BVCI , NULL);
	/* Trace Reference Trace Reference/11.3.37 M TLV 4 */
	ELEM_MAND_TELV(0x21, BSSGP_PDU_TYPE, DE_BSSGP_TRACE_REF , NULL);
	/* Trigger Id Trigger Id/11.3.40 O TLV 4-24 */
	ELEM_OPT_TELV(0x24, BSSGP_PDU_TYPE, DE_BSSGP_TRIGGER_ID , NULL);
	/* Mobile Id Mobile Id/11.3.20 O TLV 3-10 */
	ELEM_OPT_TELV(0x11,GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);
	/* OMC Id OMC Id/11.3.23 O TLV 4-24 */
	ELEM_OPT_TELV(0x14,GSM_A_PDU_TYPE_COMMON, DE_BSSGP_OMC_ID, NULL);
	/* TransactionId TransactionId/11.3.39 O TLV 4 */
	ELEM_OPT_TELV(0x23, BSSGP_PDU_TYPE, DE_BSSGP_TRANSACTION_ID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.16	DOWNLOAD-BSS-PFC
 */
static void
bssgp_download_bss_pfc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU requests a SGSN to initiate a CREATE-BSS-PFC procedure. */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.17	CREATE-BSS-PFC
 */
static void
bssgp_create_bss_pfc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the SGSN to request that a BSS create or modify a BSS Packet Flow Context. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* IMSI IMSI/11.3.14 O (note 4) TLV 5 -10 */
	ELEM_OPT_TELV(BSSGP_IEI_IMSI, BSSGP_PDU_TYPE, DE_BSSGP_IMSI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* PFT GPRS Timer/11.3.44 M TLV 3 */
	ELEM_MAND_TELV(0x29, BSSGP_PDU_TYPE, DE_BSSGP_GPRS_TIMER , " - PFT");
	/* ABQP ABQP/11.3.43 M TLV 13-? */
	ELEM_MAND_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);
	/* Service UTRAN CCO Service UTRAN CCO/11.3.47 O TLV 3 */
	ELEM_OPT_TELV(0x3d, BSSGP_PDU_TYPE, DE_BSSGP_SERV_UTRAN_CCO, NULL);
	/* MS Radio Access Capability MS Radio Access Capability/11.3.22 O (note 1) TLV 7-? */
	ELEM_OPT_TELV(BSSGP_IEI_MS_RADIO_ACCESS_CAPABILITY, GSM_A_PDU_TYPE_GM, DE_MS_RAD_ACC_CAP , NULL);
	/* Allocation/Retention Priority Priority/11.3.27 O TLV 3 */
	ELEM_OPT_TELV(0x0b, GSM_A_PDU_TYPE_BSSMAP, BE_PRIO, NULL);
	/* T10 GPRS Timer/11.3.44 C (note 2) TLV 3 */
	ELEM_MAND_TELV(0x29, BSSGP_PDU_TYPE, DE_BSSGP_GPRS_TIMER , " - T10");
	/* Inter RAT Handover Info Inter RAT Handover Info/11.3.94 O (note 3) TLV 3-? */
	ELEM_OPT_TELV(0x73, BSSGP_PDU_TYPE, DE_BSSGP_INTER_RAT_HO_INFO, NULL);
	/* E-UTRAN Inter RAT Handover Info E-UTRAN Inter RAT Handover Info/11.3.104 O (note 3) TLV 3-? */
	ELEM_OPT_TELV(0x80, BSSGP_PDU_TYPE, DE_BSSGP_E_UTRAN_INTER_RAT_HO_INFO, NULL);
	/* Subscriber Profile ID for RAT/Frequency priority (note 5) 
	 * Subscriber Profile ID for RAT/Frequency priority/11.3.105 O TLV 3
	 */
	ELEM_OPT_TELV(0x81, BSSGP_PDU_TYPE, DE_BSSGP_SUB_PROF_ID_F_RAT_FRQ_PRIO, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.18	CREATE-BSS-PFC-ACK
 */
static void
bssgp_create_bss_pfc_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to acknowledge a request from the SGSN for the creation
	 * or modification of a BSS Packet Flow Context.
	 */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* ABQP ABQP/11.3.43 M TLV 13-? */
	ELEM_MAND_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);
	/* Cause Cause/11.3.8 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.19	CREATE-BSS-PFC-NACK
 */
static void
bssgp_create_bss_pfc_nack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to Nack a request from the SGSN for the 
	 * creation of a BSS Packet Flow Context
	 */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.20	MODIFY-BSS-PFC
 */
static void
bssgp_modify_bss_pfc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to request a modification of a BSS Packet Flow Context. */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* ABQP ABQP/11.3.43 M TLV 13-? */
	ELEM_MAND_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.21	MODIFY-BSS-PFC-ACK
 */
static void
bssgp_modify_bss_pfc_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the SGSN to acknowledge a modification to a BSS Packet Flow Context. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* PFT GPRS Timer/11.3.44 M TLV 3 */
	ELEM_MAND_TELV(0x29, BSSGP_PDU_TYPE, DE_BSSGP_GPRS_TIMER , " - PFT");
	/* ABQP ABQP/11.3.43 M TLV 13-? */
	ELEM_MAND_TELV(0x3a , GSM_A_PDU_TYPE_GM, DE_QOS , NULL);


	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.22	DELETE-BSS-PFC
 */
static void
bssgp_delete_bss_pfc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the SGSN to request that a BSS delete a BSS Packet Flow Context. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.23	DELETE-BSS-PFC-ACK
 */
static void
bssgp_delete_bss_pfc_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to acknowledge a request for the deletion of a BSS Packet Flow Context. */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.24	FLOW-CONTROL-PFC
 */
static void
bssgp_flow_cntrl_pfc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU provides the SGSN with flow control information regarding one or more PFC(s) of a given Mobile Station. */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);
	/* MS Bucket Size MS Bucket Size/11.3.21 O TLV 4 */
	ELEM_OPT_TELV(BSSGP_IEI_MS_BUCKET_SIZE, BSSGP_PDU_TYPE, DE_BSSGP_MS_BUCKET_SIZE , NULL);
	/* Bucket Leak rate Bucket Leak rate/11.3.4 O TLV 4 */
	ELEM_OPT_TELV(0x3b, BSSGP_PDU_TYPE, DE_BSSGP_FEATURE_BITMAP , NULL);
	/* Bucket_Full Ratio Bucket_Full Ratio/11.3.46 O TLV 3 */
	ELEM_OPT_TELV(BSSGP_IEI_BUCKET_FULL_RATIO, BSSGP_PDU_TYPE, DE_BSSGP_BUCKET_FULL_RATIO , NULL);
	/* PFC flow control parameters PFC flow control parameters/11.3.68 M TLV */ 
	ELEM_MAND_TELV(0x52, BSSGP_PDU_TYPE, DE_BSSGP_PFC_FLOW_CTRL , NULL);
	/* Flow Control Granularity (note) Flow Control Granularity/11.3.102 O TLV 3 */
	ELEM_OPT_TELV(0x7e, BSSGP_PDU_TYPE, DE_BSSGP_FLOW_CONTROL_GRAN , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.25	FLOW-CONTROL-PFC-ACK
 */
static void
bssgp_flow_cntrl_pfc_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the flow control mechanism at the BSS that the SGSN has received the FLOW-CONTROL-PFC
	 * PDU indicated by the TLLI and the Tag.
	 */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Tag Tag/11.3.34 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_TAG, BSSGP_PDU_TYPE, DE_BSSGP_TAG , NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.26	DELETE-BSS-PFC-REQ
 */
static void
bssgp_delete_bss_pfc_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU allows the BSS to inform the SGSN that the BSS Packet Flow Context cannot be supported anymore */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* PFI PFI/11.3.42 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_PFI , GSM_A_PDU_TYPE_GM, DE_PACKET_FLOW_ID , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.27	PS-HANDOVER-REQUIRED
 */
static void
bssgp_ps_ho_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU initiates the allocation of resources in the target system for an MS. */
	/* Direction: BSS to SGSN */
	gpinfo->link_dir = P2P_DIR_UL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);
	/* Source Cell Identifier Cell Identifier/11.3.9 M TLV 10 */
	ELEM_MAND_TELV(0x08, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , " - Source");
	/* Target Cell Identifier (note 2) Cell Identifier/11.3.9 C TLV 10 */
	ELEM_OPT_TELV(0x08, BSSGP_PDU_TYPE, DE_BSSGP_CELL_ID , " - Target");
	/* Source BSS to Target BSS Transparent Container (note 1) 
	 * Source BSS to Target BSS Transparent Container/11.3.79 C TLV 10-? 
	 */
	ELEM_OPT_TELV(0x64,BSSGP_PDU_TYPE, DE_BSSGP_SOURCE_BSS_TO_TARGET_BSS_TRANSP_CONT, NULL);
	/* Target RNC Identifier (note 2) (note 3) RNC Identifier/11.3.87 C TLV 10 */
	ELEM_OPT_TELV(0x6c,BSSGP_PDU_TYPE, BE_BSSGP_RNC_ID, NULL);
	/* Source to Target Transparent Container (note 1)
	 * Source to Target Transparent Container/11.3.85 C TLV 3-? 
	 */
	ELEM_OPT_TELV(0x6a,BSSGP_PDU_TYPE, DE_BSSGP_SRC_TO_TRG_TRANSP_CONT, NULL);
	/* Active PFCs List Active PFCs List/11.3.95c M TLV 3-? */
	ELEM_OPT_TELV(0x77,BSSGP_PDU_TYPE, DE_BSSGP_ACTIVE_PFCS_LIST, NULL);
	/* Target eNB identifier (note 2) (note 3) eNB Identifier/11.3.103 C TLV 3-n */
	ELEM_OPT_TELV(0x7f,BSSGP_PDU_TYPE, DE_BSSGP_ENB_ID, NULL);
	/* Reliable Inter RAT Handover Info (note 4) 
	 * Reliable Inter RAT Handover Info/11.3.107 C TLV 3
	 */
	ELEM_OPT_TELV(0x83,BSSGP_PDU_TYPE, DE_BSSGP_RELIABLE_INTER_RAT_HO_INF, NULL);
	/* CSG Identifier (note 5) CSG Identifier/11.3.109 C TLV 7 */
	ELEM_OPT_TELV(0x85,BSSGP_PDU_TYPE, DE_BSSGP_CSG_ID, NULL);
	/* TAC (note 6) Tracking Area Code/11.3.110 C TLV 5 */
	ELEM_OPT_TELV(0x86, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.28	PS-HANDOVER-REQUIRED-ACK
 */
static void
bssgp_ps_ho_req_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU indicates that resources have been allocated in the target system and
	 * that the BSS may initiate the channel change attempt for the corresponding MS.
	 */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* List of set-up PFCs List of set-up PFCs/11.3.83 M TLV 3-?S */
	ELEM_MAND_TELV(0x68,BSSGP_PDU_TYPE, DE_BSSGP_LIST_OF_SETUP_PFCS, NULL);
	/* Target BSS to Source BSS Transparent Container (note)
	 * Target BSS to Source BSS Transparent Container/11.3.80 C TLV 3-?
	 */
	ELEM_MAND_TELV(0x65,BSSGP_PDU_TYPE, DE_BSSGP_TARGET_BSS_TO_SOURCE_BSS_TRANSP_CONT, NULL);
	/* Target to Source Transparent Container (note)
	 * Target to Source Transparent Container/11.3.86 C TLV 3-?
	 */
	ELEM_MAND_TELV(0x6b,BSSGP_PDU_TYPE, DE_BSSGP_TRG_TO_SRC_TRANSP_CONT, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}

/*
 * 10.4.29	PS-HANDOVER-REQUIRED-NACK
 */
static void
bssgp_ps_ho_req_nack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* This PDU informs the source BSS about failed resource allocation in the target system. */
	/* Direction: SGSN to BSS */
	gpinfo->link_dir = P2P_DIR_DL;

	/* TLLI TLLI/11.3.35 M TLV 6 */
	ELEM_MAND_TELV(BSSGP_IEI_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI , NULL);
	/* Cause Cause/11.3.8 M TLV 3 */
	ELEM_MAND_TELV(BSSGP_IEI_CAUSE,BSSGP_PDU_TYPE, DE_BSSGP_CAUSE, NULL);

	EXTRANEOUS_DATA_CHECK_EXPERT(curr_len, 0, gpinfo);
}
/*
 * 10.4.30	PS-HANDOVER-REQUEST
 * 10.4.31	PS-HANDOVER-REQUEST-ACK
 * 10.4.32	PS-HANDOVER-REQUEST-NACK
 * 10.4.33	PS-HANDOVER-COMPLETE
 * 10.4.34	PS-HANDOVER-CANCEL
 * 10.4.35	PS-HANDOVER-COMPLETE-ACK
 * 10.5	PDU functional definitions and contents at LCS SAP	114
 * 10.5.1	PERFORM-LOCATION-REQUEST	114
 * 10.5.2	PERFORM-LOCATION-RESPONSE	115
 * 10.5.3	PERFORM-LOCATION-ABORT	115
 * 10.5.4	POSITION-COMMAND	115
 * 10.5.5	POSITION-RESPONSE
 * 10.6	PDU functional definitions and contents at RIM SAP
 * 10.6.1	RAN-INFORMATION-REQUEST
 * 10.6.2	RAN-INFORMATION
 * 10.6.3	RAN-INFORMATION-ACK
 * 10.6.4	RAN-INFORMATION-ERROR
 * 10.6.5	RAN-INFORMATION-APPLICATION-ERROR
 * 10.7	PDU functional definitions and contents at MBMS SAP
 * 10.7.1	MBMS-SESSION-START-REQUEST
 * 10.7.2	MBMS-SESSION-START-RESPONSE
 * 10.7.3	MBMS-SESSION-STOP-REQUEST
 * 10.7.4	MBMS-SESSION-STOP-RESPONSE
 * 10.7.5	MBMS-SESSION-UPDATE-REQUEST
 * 10.7.6	MBMS-SESSION-UPDATE-RESPONSE
*/

static const value_string bssgp_msg_strings[] = {
/* 0x00 */  { BSSGP_PDU_DL_UNITDATA,                  "DL-UNITDATA" },					/* 10.2.1 DL-UNITDATA */
/* 0x01 */  { BSSGP_PDU_UL_UNITDATA,                  "UL-UNITDATA" },					/* 10.2.2 UL-UNITDATA */
/* 0x02 */  { BSSGP_PDU_RA_CAPABILITY,                "RA-CAPABILITY" },				/* 10.2.3 RA-CAPABILITY */
/* NOTE 1: This value was allocated in an earlier version of the protocol and shall	not be used */
/* 0x03 */  { BSSGP_PDU_PTM_UNITDATA,                 "Reserved" },						/* 10.2.4 (void) */
/* 0x04 */  { BSSGP_PDU_DL_MBMS_UNITDATA,             "DL-MBMS-UNITDATA" },				/* 10.2.5 DL-MBMS-UNITDATA */
/* 0x05 */  { BSSGP_PDU_UL_MBMS_UNITDATA,             "UL-MBMS-UNITDATA" },				/* 10.2.6 UL-MBMS-UNITDATA */
/* 0x06 */  { BSSGP_PDU_PAGING_PS,                    "PAGING-PS" },					/* 10.3.1 PAGING PS */
/* 0x07 */  { BSSGP_PDU_PAGING_CS,                    "PAGING-CS" },					/* 10.3.2 PAGING CS */
/* 0x08 */  { BSSGP_PDU_RA_CAPABILITY_UPDATE,         "RA-CAPABILITY-UPDATE" },			/* 10.3.3 RA-CAPABILITY-UPDATE */
/* 0x09 */  { BSSGP_PDU_RA_CAPABILITY_UPDATE_ACK,     "RA-CAPABILITY-UPDATE-ACK" },		/* 10.3.4 RA-CAPABILITY-UPDATE-ACK */
/* 0x0a */  { BSSGP_PDU_RADIO_STATUS,                 "RADIO-STATUS" },					/* 10.3.5 RADIO-STATUS */
/* 0x0b */  { BSSGP_PDU_SUSPEND,                      "SUSPEND" },						/* 10.3.6 SUSPEND */
/* 0x0c */  { BSSGP_PDU_SUSPEND_ACK,                  "SUSPEND-ACK" },					/* 10.3.7 SUSPEND-ACK */
/* 0x0d */  { BSSGP_PDU_SUSPEND_NACK,                 "SUSPEND-NACK" },					/* 10.3.8 SUSPEND-NACK */
/* 0x0e */  { BSSGP_PDU_RESUME,                       "RESUME" },						/* 10.3.9 RESUME */
/* 0x0f */  { BSSGP_PDU_RESUME_ACK,                   "RESUME-ACK" },					/* 10.3.10 RESUME-ACK */
/* 0x10 */  { BSSGP_PDU_RESUME_NACK,                  "RESUME-NACK" },					/* 10.3.11 RESUME-NACK */
  /* 0x11 to 0x1f Reserved */	
/* 0x11 */  { BSSGP_PDU_RESERVED_0X11,                 "Reserved" },					/*  */
/* 0x12 */  { BSSGP_PDU_RESERVED_0X12,                 "Reserved" },					/*  */
/* 0x13 */  { BSSGP_PDU_RESERVED_0X13,                 "Reserved" },					/*  */
/* 0x14 */  { BSSGP_PDU_RESERVED_0X14,                 "Reserved" },					/*  */
/* 0x15 */  { BSSGP_PDU_RESERVED_0X15,                 "Reserved" },					/*  */
/* 0x16 */  { BSSGP_PDU_RESERVED_0X16,                 "Reserved" },					/*  */
/* 0x17 */  { BSSGP_PDU_RESERVED_0X17,                 "Reserved" },					/*  */
/* 0x18 */  { BSSGP_PDU_RESERVED_0X18,                 "Reserved" },					/*  */
/* 0x19 */  { BSSGP_PDU_RESERVED_0X19,                 "Reserved" },					/*  */
/* 0x1a */  { BSSGP_PDU_RESERVED_0X1A,                 "Reserved" },					/*  */
/* 0x1b */  { BSSGP_PDU_RESERVED_0X1B,                 "Reserved" },					/*  */
/* 0x1c */  { BSSGP_PDU_RESERVED_0X1C,                 "Reserved" },					/*  */
/* 0x1d */  { BSSGP_PDU_RESERVED_0X1D,                 "Reserved" },					/*  */
/* 0x1e */  { BSSGP_PDU_RESERVED_0X1E,                 "Reserved" },					/*  */
/* 0x1f */  { BSSGP_PDU_RESERVED_0X1F,                 "Reserved" },					/*  */
	
/* 0x20 */  { BSSGP_PDU_BVC_BLOCK,                    "BVC-BLOCK" },					/* 10.4.8 BVC-BLOCK */
/* 0x21 */  { BSSGP_PDU_BVC_BLOCK_ACK,                "BVC-BLOCK-ACK" },				/* 10.4.9 BVC-BLOCK-ACK */
/* 0x22 */  { BSSGP_PDU_BVC_RESET,                    "BVC-RESET" },					/* 10.4.12 BVC-RESET */
/* 0x23 */  { BSSGP_PDU_BVC_RESET_ACK,                "BVC-RESET-ACK" },				/* 10.4.13 BVC-RESET-ACK */
/* 0x24 */  { BSSGP_PDU_BVC_UNBLOCK,                  "UNBLOCK" },						/* 10.4.10 BVC-UNBLOCK */
/* 0x25 */  { BSSGP_PDU_BVC_UNBLOCK_ACK,              "UNBLOCK-ACK" },					/* 10.4.11 BVC-UNBLOCK-ACK */
/* 0x26 */  { BSSGP_PDU_FLOW_CONTROL_BVC,             "FLOW-CONTROL-BVC" },				/* 10.4.4 FLOW-CONTROL-BVC */
/* 0x27 */  { BSSGP_PDU_FLOW_CONTROL_BVC_ACK,         "FLOW-CONTROL-BVC-ACK" },			/* 10.4.5 FLOW-CONTROL-BVC-ACK */
/* 0x28 */  { BSSGP_PDU_FLOW_CONTROL_MS,              "FLOW-CONTROL-MS" },				/* 10.4.6 FLOW-CONTROL-MS */
/* 0x29 */  { BSSGP_PDU_FLOW_CONTROL_MS_ACK,          "FLOW-CONTROL-MS-ACK" },			/* 10.4.7 FLOW-CONTROL-MS-ACK */
/* 0x2a */  { BSSGP_PDU_FLUSH_LL,                     "FLUSH-LL" },						/* 10.4.1 FLUSH-LL */
/* 0x2b */  { BSSGP_PDU_FLUSH_LL_ACK,                 "FLUSH_LL_ACK" },					/* 10.4.2 FLUSH-LL-ACK */
/* 0x2c */  { BSSGP_PDU_LLC_DISCARDED,                "LLC-DISCARDED" },				/* 10.4.3 LLC-DISCARDED */
/* 0x2d */  { BSSGP_PDU_FLOW_CONTROL_PFC,             "FLOW-CONTROL-PFC" },				/* 10.4.24 FLOW-CONTROL-PFC */
/* 0x2e */  { BSSGP_PDU_FLOW_CONTROL_PFC_ACK,         "FLOW-CONTROL-PFC-ACK" },			/* 10.4.25 FLOW-CONTROL-PFC-ACK */
  /* 0x2f to 0x3f Reserved */	
/* 0x2f */  { BSSGP_PDU_RESERVED_0X2F,                 "Reserved" },					/*  */
/* 0x30 */  { BSSGP_PDU_RESERVED_0X30,                 "Reserved" },					/*  */
/* 0x31 */  { BSSGP_PDU_RESERVED_0X31,                 "Reserved" },					/*  */
/* 0x32 */  { BSSGP_PDU_RESERVED_0X32,                 "Reserved" },					/*  */
/* 0x33 */  { BSSGP_PDU_RESERVED_0X33,                 "Reserved" },					/*  */
/* 0x34 */  { BSSGP_PDU_RESERVED_0X34,                 "Reserved" },					/*  */
/* 0x35 */  { BSSGP_PDU_RESERVED_0X35,                 "Reserved" },					/*  */
/* 0x36 */  { BSSGP_PDU_RESERVED_0X36,                 "Reserved" },					/*  */
/* 0x37 */  { BSSGP_PDU_RESERVED_0X37,                 "Reserved" },					/*  */
/* 0x38 */  { BSSGP_PDU_RESERVED_0X38,                 "Reserved" },					/*  */
/* 0x39 */  { BSSGP_PDU_RESERVED_0X39,                 "Reserved" },					/*  */
/* 0x3a */  { BSSGP_PDU_RESERVED_0X3A,                 "Reserved" },					/*  */
/* 0x3b */  { BSSGP_PDU_RESERVED_0X3B,                 "Reserved" },					/*  */
/* 0x3c */  { BSSGP_PDU_RESERVED_0X3C,                 "Reserved" },					/*  */
/* 0x3d */  { BSSGP_PDU_RESERVED_0X3D,                 "Reserved" },					/*  */
/* 0x3e */  { BSSGP_PDU_RESERVED_0X3E,                 "Reserved" },					/*  */
/* 0x3f */  { BSSGP_PDU_RESERVED_0X3F,                 "Reserved" },					/*  */

/* 0x40 */  { BSSGP_PDU_SGSN_INVOKE_TRACE,            "SGSN-INVOKE-TRACE" },			/* 10.4.15 SGSN-INVOKE-TRACE */
/* 0x41 */  { BSSGP_PDU_STATUS,                       "STATUS" },						/* 10.4.14 STATUS */
  /* 0x42 to 0x4f Reserved */
/* 0x42 */  { BSSGP_PDU_RESERVED_0X42,                 "Reserved" },					/*  */
/* 0x43 */  { BSSGP_PDU_RESERVED_0X43,                 "Reserved" },					/*  */
/* 0x44 */  { BSSGP_PDU_RESERVED_0X44,                 "Reserved" },					/*  */
/* 0x45 */  { BSSGP_PDU_RESERVED_0X45,                 "Reserved" },					/*  */
/* 0x46 */  { BSSGP_PDU_RESERVED_0X46,                 "Reserved" },					/*  */
/* 0x47 */  { BSSGP_PDU_RESERVED_0X47,                 "Reserved" },					/*  */
/* 0x48 */  { BSSGP_PDU_RESERVED_0X48,                 "Reserved" },					/*  */
/* 0x49 */  { BSSGP_PDU_RESERVED_0X49,                 "Reserved" },					/*  */
/* 0x4a */  { BSSGP_PDU_RESERVED_0X4A,                 "Reserved" },					/*  */
/* 0x4b */  { BSSGP_PDU_RESERVED_0X4B,                 "Reserved" },					/*  */
/* 0x4c */  { BSSGP_PDU_RESERVED_0X4C,                 "Reserved" },					/*  */
/* 0x4d */  { BSSGP_PDU_RESERVED_0X4D,                 "Reserved" },					/*  */
/* 0x4e */  { BSSGP_PDU_RESERVED_0X4E,                 "Reserved" },					/*  */
/* 0x4f */  { BSSGP_PDU_RESERVED_0X4F,                 "Reserved" },					/*  */
/* 0x50 */  { BSSGP_PDU_DOWNLOAD_BSS_PFC,              "DOWNLOAD-BSS-PFC" },			/* 10.4.16	DOWNLOAD-BSS-PFC */
/* 0x51 */  { BSSGP_PDU_CREATE_BSS_PFC,                "CREATE-BSS-PFC" },				/* 10.4.17 CREATE-BSS-PFC */
/* 0x52 */  { BSSGP_PDU_CREATE_BSS_PFC_ACK,            "CREATE-BSS-PFC-ACK" },			/* 10.4.18 CREATE-BSS-PFC-ACK */
/* 0x53 */  { BSSGP_PDU_CREATE_BSS_PFC_NACK,           "CREATE-BSS-PFC-NACK" },			/* 10.4.19 CREATE-BSS-PFC-NACK */
/* 0x54 */  { BSSGP_PDU_MODIFY_BSS_PFC,                "MODIFY-BSS-PFC" },				/* 10.4.20 MODIFY-BSS-PFC */
/* 0x55 */  { BSSGP_PDU_MODIFY_BSS_PFC_ACK,            "MODIFY-BSS-PFC-ACK" },			/* 10.4.21 MODIFY-BSS-PFC-ACK */
/* 0x56 */  { BSSGP_PDU_DELETE_BSS_PFC,                "DELETE-BSS-PFC" },				/* 10.4.22 DELETE-BSS-PFC */
/* 0x57 */  { BSSGP_PDU_DELETE_BSS_PFC_ACK,            "DELETE-BSS-PFC-ACK" },			/* 10.4.23 DELETE-BSS-PFC-ACK */
/* 0x58 */  { BSSGP_PDU_DELETE_BSS_PFC_REQ,            "DELETE-BSS-PFC-REQ" },			/* 10.4.26 DELETE-BSS-PFC-REQ */
/* 0x59 */  { BSSGP_PDU_PS_HANDOVER_REQUIRED,          "PS-HANDOVER-REQUIRED" },		/* 10.4.27 PS-HANDOVER-REQUIRED */
/* 0x5a */  { BSSGP_PDU_PS_HANDOVER_REQUIRED_ACK,      "PS-HANDOVER-REQUIRED-ACK" },	/* 10.4.28 PS-HANDOVER-REQUIRED-ACK */
/* 0x5b */  { BSSGP_PDU_PS_HANDOVER_REQUIRED_NACK,     "PS-HANDOVER-REQUIRED-NACK" },	/* 10.4.29 PS-HANDOVER-REQUIRED-NACK */
/* 0x5c */  { BSSGP_PDU_PS_HANDOVER_REQUEST,           "PS-HANDOVER-REQUEST" },			
/* 0x5d */  { BSSGP_PDU_PS_HANDOVER_REQUEST_ACK,       "PS-HANDOVER-REQUEST-ACK" },		
/* 0x5e */  { BSSGP_PDU_PS_HANDOVER_REQUEST_NACK,      "PS-HANDOVER-REQUEST-NACK" },

	{ 0,	NULL }
};
static value_string_ext bssgp_msg_strings_ext = VALUE_STRING_EXT_INIT(bssgp_msg_strings);

#define	NUM_BSSGP_MSG (sizeof(bssgp_msg_strings)/sizeof(value_string))
static gint ett_bssgp_msg[NUM_BSSGP_MSG];
static void (*bssgp_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
/* 0x00 */	bssgp_dl_unitdata,				/* 10.2.1 DL-UNITDATA */
	bssgp_ul_unitdata,				/* 10.2.2 UL-UNITDATA */
	bssgp_ra_cap,					/* 10.2.3 RA-CAPABILITY */
	NULL,							/* 10.2.4 (void) */
	bssgp_dl_mbms_unitdata,			/* 10.2.5 DL-MBMS-UNITDATA */
	bssgp_ul_mbms_unitdata,			/* 10.2.6 UL-MBMS-UNITDATA */
	bssgp_paging_ps,				/* 10.3.1 PAGING PS */
	bssgp_paging_cs,				/* 10.3.2 PAGING CS */
	bssgp_ra_cap_upd,				/* 10.3.3 RA-CAPABILITY-UPDATE */
	bssgp_ra_cap_upd_ack,			/* 10.3.3 RA-CAPABILITY-UPDATE */
	bssgp_ra_status,				/* 10.3.5 RADIO-STATUS */
	bssgp_suspend,					/* 10.3.6 SUSPEND */
	bssgp_suspend_ack,				/* 10.3.7 SUSPEND-ACK */
	bssgp_suspend_nack,				/* 10.3.8 SUSPEND-NACK */
	bssgp_resume,					/* 10.3.9 RESUME */
	bssgp_resume_ack,				/* 10.3.10 RESUME-ACK */
	bssgp_resume_nack,				/* 10.3.11 RESUME-NACK */
  /* 0x11 to 0x1f Reserved */
	NULL,							/* 0x11 */  
	NULL,							/* 0x12 */  
	NULL,							/* 0x13 */  
	NULL,							/* 0x14 */  
	NULL,							/* 0x15 */  
	NULL,							/* 0x16 */  
	NULL,							/* 0x17 */  
	NULL,							/* 0x18 */  
	NULL,							/* 0x19 */  
	NULL,							/* 0x1A */  
	NULL,							/* 0x1B */  
	NULL,							/* 0x1C */  
	NULL,							/* 0x1D */  
	NULL,							/* 0x1E */  
	NULL,							/* 0x1F */  

	bssgp_bvc_block,				/* 10.4.8 BVC-BLOCK */
	bssgp_bvc_block_ack,			/* 10.4.9 BVC-BLOCK-ACK */
	bssgp_bvc_reset,	            /* 10.4.12 BVC-RESET */
	bssgp_bvc_reset_ack,            /* 10.4.13 BVC-RESET-ACK */
	bssgp_bvc_un_block,             /* 10.4.10 BVC-UNBLOCK */
    bssgp_bvc_un_block_ack,         /* 10.4.11 BVC-UNBLOCK-ACK */
    bssgp_flow_control_bvc,         /* 10.4.4 FLOW-CONTROL-BVC */
	bssgp_flow_control_bvc_ack,		/* 10.4.5 FLOW-CONTROL-BVC-ACK */
	bssgp_flow_control_ms,			/* 10.4.6 FLOW-CONTROL-MS */
	bssgp_flow_control_ms_ack,		/* 10.4.7 FLOW-CONTROL-MS-ACK */
	bssgp_flush_ll,					/* 10.4.1 FLUSH-LL */
	bssgp_flush_ll_ack,				/* 10.4.2 FLUSH-LL-ACK */
	bssgp_llc_discarded,			/* 10.4.3 LLC-DISCARDED */
	bssgp_flow_cntrl_pfc,			/* 10.4.24 FLOW-CONTROL-PFC */
	bssgp_flow_cntrl_pfc_ack,		/* 10.4.25 FLOW-CONTROL-PFC-ACK */

	/* 0x2f to 0x3f Reserved */
  	NULL,							/* 0x2f */  
  	NULL,							/* 0x30 */  
  	NULL,							/* 0x31 */  
	NULL,							/* 0x32 */  
	NULL,							/* 0x33 */  
	NULL,							/* 0x34 */  
	NULL,							/* 0x35 */  
	NULL,							/* 0x36 */  
	NULL,							/* 0x37 */  
	NULL,							/* 0x38 */  
	NULL,							/* 0x39 */  
	NULL,							/* 0x3A */  
	NULL,							/* 0x3B */  
	NULL,							/* 0x3C */  
	NULL,							/* 0x3D */  
	NULL,							/* 0x3E */  
	NULL,							/* 0x3F */  

	bssgp_sgsn_invoke_trace,		/* 10.4.15 SGSN-INVOKE-TRACE */
	bssgp_status,					/* 10.4.14 STATUS */
  /* 0x42 to 0x4f Reserved */
	NULL,							/* 0x42 */  
	NULL,							/* 0x43 */  
	NULL,							/* 0x44 */  
	NULL,							/* 0x45 */  
	NULL,							/* 0x46 */  
	NULL,							/* 0x47 */  
	NULL,							/* 0x48 */  
	NULL,							/* 0x49 */  
	NULL,							/* 0x4A */  
	NULL,							/* 0x4B */  
	NULL,							/* 0x4C */  
	NULL,							/* 0x4D */  
	NULL,							/* 0x4E */  
	NULL,							/* 0x4F */

	bssgp_download_bss_pfc,			/* 10.4.16	DOWNLOAD-BSS-PFC */
	bssgp_create_bss_pfc,			/* 10.4.17 CREATE-BSS-PFC */
	bssgp_create_bss_pfc_ack,		/* 10.4.18 CREATE-BSS-PFC-ACK */
	bssgp_create_bss_pfc_nack,		/* 10.4.19 CREATE-BSS-PFC-NACK */
	bssgp_modify_bss_pfc,			/* 10.4.20 MODIFY-BSS-PFC */
	bssgp_modify_bss_pfc_ack,		/* 10.4.21 MODIFY-BSS-PFC-ACK */
	bssgp_delete_bss_pfc,			/* 10.4.22 DELETE-BSS-PFC */
	bssgp_delete_bss_pfc_ack,		/* 10.4.23 DELETE-BSS-PFC-ACK */
	bssgp_delete_bss_pfc_req,		/* 10.4.26 DELETE-BSS-PFC-REQ */
	bssgp_ps_ho_req,				/* 10.4.27 PS-HANDOVER-REQUIRED */
	bssgp_ps_ho_req_ack,			/* 10.4.28 PS-HANDOVER-REQUIRED-ACK */
	bssgp_ps_ho_req_nack,			/* 10.4.29 PS-HANDOVER-REQUIRED-NACK */
	NULL,	/* NONE */
};

void get_bssgp_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn)
{
	gint			idx;

	*msg_str = match_strval_idx_ext((guint32) (oct & 0xff), &bssgp_msg_strings_ext, &idx);
	*ett_tree = ett_bssgp_msg[idx];
	*hf_idx = hf_bssgp_msg_type;
	*msg_fcn = bssgp_msg_fcn[idx];

	return;
}

static void
dissect_bssgp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  build_info_t bi = { NULL, 0, NULL, NULL, NULL, FALSE, FALSE, 0 };

  proto_item *ti;
  proto_tree *bssgp_tree = NULL;
	int				offset = 0;
	guint32			len;
	const gchar		*msg_str = NULL;
	gint			ett_tree;
	int				hf_idx;
	void			(*msg_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);
	guint8			oct;

	/* Save pinfo */
	gpinfo = pinfo;
	parent_tree = tree;
	len = tvb_length(tvb);


  bi.tvb = tvb;
  bi.pinfo = pinfo;
  bi.parent_tree = tree;

  pinfo->current_proto = "BSSGP";

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BSSGP");

  col_clear(pinfo->cinfo, COL_INFO);

  bi.pdutype = tvb_get_guint8(tvb, 0);
  bi.offset++;

  oct = tvb_get_guint8(tvb,offset);
  if (tree) {
    ti = proto_tree_add_item(tree, proto_bssgp, tvb, 0, -1, ENC_NA);
    bssgp_tree = proto_item_add_subtree(ti, ett_bssgp);
    bi.bssgp_tree = bssgp_tree;
  }

  /* Messge type IE*/
  msg_fcn = NULL;
  ett_tree = -1;
  hf_idx = -1;
  msg_str = NULL;

  get_bssgp_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn);

  col_add_str(pinfo->cinfo, COL_INFO, val_to_str(bi.pdutype,
						   tab_bssgp_pdu_types,
						   "Unknown PDU type"));

  /* PDU's with msg no lover than this value are converted to common dissection style */
  if(oct>0x5b){
	  proto_tree_add_item(bssgp_tree, hf_bssgp_msg_type, tvb, 0, 1, ENC_BIG_ENDIAN);
	  decode_pdu(&bi);
  }else{
	/* New dissection code, aligning the dissector with the other GSM/UMTS/LTE dissectors
	* to make it possible to share IE dissection as IE's are shared between specs.
	* old code is keept untill transition is complete.
	*/

	  if(msg_str){
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s", msg_str);
		}else{
			proto_tree_add_text(bssgp_tree, tvb, offset, 1,"Unknown message 0x%x",oct);
			return;
		}

		/*
		 * Add BSSGP message name
		 */
		proto_tree_add_item(bssgp_tree, hf_idx, tvb, offset, 1, FALSE);
		offset++;


		/*
		 * decode elements
		 */
		if (msg_fcn == NULL)
		{
			proto_tree_add_text(bssgp_tree, tvb, offset, len - offset, "Message Elements");
		}
		else
		{
			/* If calling any "gsm" ie dissectors needing pinfo */
			gsm_a_dtap_pinfo = pinfo;
			(*msg_fcn)(tvb, bssgp_tree, offset, len - offset);
		}
  }/*End new dissection */

}

void
proto_register_bssgp(void)
{
	guint		i;
	guint		last_offset;

  static hf_register_info hf[] = {
    { &hf_bssgp_msg_type,
      { "PDU Type", "bssgp.pdu_type",
	FT_UINT8, BASE_HEX, VALS(tab_bssgp_pdu_types), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_elem_id,
		{ "Element ID",	"bssgp.elem_id",
		FT_UINT8, BASE_DEC, NULL, 0,
		NULL, HFILL }
	},
    { &hf_bssgp_iei_nacc_cause,
      { "NACC Cause", "bssgp.iei.nacc_cause",
	FT_UINT8, BASE_HEX, VALS(tab_nacc_cause), 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_ie_type,
      { "IE Type", "bssgp.ie_type",
	FT_UINT8, BASE_HEX, VALS(tab_bssgp_ie_types), 0x0,
	"Information element type", HFILL }
    },
	{ &hf_bssgp_bss_area_ind,
      { "BSS indicator", "bssgp.bss_ind",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_bvci,
      { "BVCI", "bssgp.bvci",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_bmax,
      { "Bmax(x 100 or in increments as defined by the Flow Control Granularity IE)", "bssgp.bmax",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_r,
      { "R(x 100 or in increments as defined by the Flow Control Granularity IE)", "bssgp.r",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_bucket_size,
      { "Bmax(x 100 or in increments as defined by the Flow Control Granularity IE)", "bssgp.bucket_size",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_omc_id,
      { "OMC identity", "bssgp.omc_id",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_tlli,
      { "TLLI", "bssgp.tlli",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_nsei,
      { "NSEI", "bssgp.nsei",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_mcc,
      { "MCC", "bssgp.mcc",
	FT_UINT8, BASE_DEC|BASE_EXT_STRING, &E212_codes_ext, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_mnc,
      { "MNC", "bssgp.mnc",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_lac,
      { "LAC", "bssgp.lac",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_rac,
      { "RAC", "bssgp.rac",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_ci,
      { "CI", "bssgp.ci",
	FT_UINT16, BASE_HEX, NULL, 0x0,
	"Cell Identity", HFILL }
    },
	{ &hf_bssgp_flush_action,
      { "Action", "bssgp.ci",
	FT_UINT8, BASE_DEC, VALS(bssgp_flush_action_vals), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_llc_frames_disc,
      { "Number of frames discarded", "bssgp.llc_frames_disc",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_ra_discriminator,
      { "Routing Address Discriminator", "bssgp.rad",
	FT_UINT8, BASE_DEC, VALS(ra_discriminator_vals), 0x0f,
	NULL, HFILL }
    },
    { &hf_bssgp_appid,
      { "Application ID", "bssgp.appid",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_rcid,
      { "Reporting Cell Identity", "bssgp.rcid",
	FT_UINT64, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_rrc_si_msg_type,
      { "RRC SI type", "bssgp.rrc_si_type",
	FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_rr_strings), 0x0,
	NULL, HFILL }
    },
    { &hf_ran_inf_req_pdu_type_ext,
      { "PDU Type Extension", "bssgp.ran_inf_req_pdu_type_ext",
	FT_UINT8, BASE_DEC, VALS(ran_inf_req_pdu_type_ext_vals), 0x0e,
	NULL, HFILL }
    },
    { &hf_ran_inf_pdu_type_ext,
      { "PDU Type Extension", "bssgp.ran_req_pdu_type_ext",
	FT_UINT8, BASE_DEC, VALS(ran_inf_pdu_type_ext_vals), 0x0e,
	NULL, HFILL }
    },
    { &hf_bssgp_tmsi_ptmsi,
      { "TMSI/PTMSI", "bssgp.tmsi_ptmsi",
	FT_UINT32, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_imsi,
      { "IMSI", "bssgp.imsi",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_imei,
      { "IMEI", "bssgp.imei",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_imeisv,
      { "IMEISV", "bssgp.imeisv",
	FT_STRING, BASE_NONE, NULL, 0x0,
	NULL, HFILL }
    },
    { &hf_bssgp_nri,
      { "NRI", "bssgp.nri",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_delay_val,
      { "Delay Value (in centi-seconds)", "bssgp.delay_val",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_cause,
      { "Cause", "bssgp.cause",
	FT_UINT8, BASE_DEC|BASE_EXT_STRING, &bssgp_cause_vals_ext, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_peak_rate_gran,
      { "Peak Bit Rate Granularity", "bssgp.peak_rate_gran",
	FT_UINT8, BASE_DEC, NULL, 0xc0,
	NULL, HFILL }
    },
	{ &hf_bssgp_cr_bit,
      { "C/R", "bssgp.cr_bit",
	FT_BOOLEAN, 8, TFS(&bssgp_cr_bit_vals), 0x20,
	NULL, HFILL }
    },
	{ &hf_bssgp_t_bit,
      { "T", "bssgp.t_bit",
	FT_BOOLEAN, 8, TFS(&bssgp_t_bit_vals), 0x10,
	NULL, HFILL }
    },
	{ &hf_bssgp_a_bit,
      { "A", "bssgp.a_bit",
	FT_BOOLEAN, 8, TFS(&bssgp_a_bit_vals), 0x08,
	NULL, HFILL }
    },
	{ &hf_bssgp_ra_cause,
      { "Radio Cause", "bssgp.ra_cause",
	FT_UINT8, BASE_DEC, VALS(bssgp_radio_cause_vals), 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_ra_cap_upd_cause,
      { "RA-Cap-UPD Cause", "bssgp.ra_cap_upd_cause",
	FT_UINT8, BASE_DEC, VALS(bssgp_ra_cap_upd_cause_vals), 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_r_default_ms,
      { "R_default_MS(x 100 or in increments as defined by the Flow Control Granularity IE)", "bssgp.r",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },

	{ &hf_bssgp_suspend_ref_no,
      { "Suspend Reference Number", "bssgp.r_default_ms",
	FT_UINT8, BASE_DEC, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_tag,
      { "Tag", "bssgp.tag",
	FT_UINT8, BASE_DEC, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_trace_ref,
      { "Trace Reference", "bssgp.trace_ref",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_trigger_id,
      { "Entity Identity", "bssgp.entity_id",
	FT_BYTES, BASE_NONE, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_transaction_id,
      { "Transaction Id", "bssgp.transaction_id",
	FT_UINT16, BASE_DEC, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_no_of_oct,
      { "Number of octets transferred or deleted", "bssgp.no_of_oct",
	FT_UINT24, BASE_DEC, NULL, 0x00,
	NULL, HFILL }
    },
	{ &hf_bssgp_unit_val,
      { "Unit Value", "bssgp.unit_val",
	FT_UINT8, BASE_DEC, VALS(bssgp_unit_vals), 0xe0,
	NULL, HFILL }
    },
	{ &hf_bssgp_gprs_timer,
      { "Unit Value", "bssgp.gprs_timer",
	FT_UINT8, BASE_DEC, NULL, 0x1f,
	NULL, HFILL }
    },

	{ &hf_bssgp_mbms,
      { "MBMS Procedures", "bssgp.mbms",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x80,
	NULL, HFILL }
    },
	{ &hf_bssgp_EnhancedRadioStatus,
      { "Enhanced Radio Status Procedures", "bssgp.enhancedradiostatus",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x40,
	NULL, HFILL }
    },
	{ &hf_bssgp_pfcfc,
      { "PFC Flow Control Procedures", "bssgp.pfcfc",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x20,
	NULL, HFILL }
    },
	{ &hf_bssgp_rim,
      { "RAN Information Management (RIM) procedures", "bssgp.rim",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x10,
	NULL, HFILL }
    },
	{ &hf_bssgp_lcs,
      { "LCS Procedures", "bssgp.lcs",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x08,
	NULL, HFILL }
    },
	{ &hf_bssgp_inr,
      { "Inter-NSE re-routing(INR)", "bssgp.inr",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
	NULL, HFILL }
    },
	{ &hf_bssgp_cbl,
      { "Current Bucket Level(CBL) Procedures", "bssgp.cbl",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
	NULL, HFILL }
    },
	{ &hf_bssgp_pfc,
      { "Packet Flow Context(PFC) Procedures", "bssgp.pfc",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_bucket_full_ratio,
     { "Ratio of the bucket that is filled up with data", "bssgp.bucket_full_ratio",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	"Bcurrent x (100 / Bmax)", HFILL }
    },

	{ &hf_bssgp_precedence,
      { "Precedence", "bssgp.a_bit",
	FT_UINT8, BASE_DEC, NULL, 0x07,
	NULL, HFILL }
    },
	{ &hf_bssgp_serv_utran_cco,
      { "Service UTRAN CCO", "bssgp.serv_utran_cco",
	FT_UINT8, BASE_DEC, VALS(bssgp_service_utran_cco_vals), 0x07,
	NULL, HFILL }
    },
	{ &hf_bssgp_mbs_session_id,
		{ "MBMS Session ID", "bssgp.mbs_session_id",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		NULL, HFILL }
	},
	{ &hf_bssgp_gb_if,
      { "Gigabit Interface", "bssgp.gb_if",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
	NULL, HFILL }
    },
	{ &hf_bssgp_ps_ho,
      { "PS Handover", "bssgp.ps_ho",
	FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_src_to_trg_transp_cont,
      { "Source to Target Transparent Container", "bssgp.src_to_trg_transp_cont",
	FT_BYTES, FT_NONE, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_trg_to_src_transp_cont,
      { "Target to Source Transparent Container", "bssgp.trg_to_src_transp_cont",
	FT_BYTES, FT_NONE, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_rnc_id,
      { "RNC ID", "bssgp.rnc_id",
	FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_page_mode,
      { "PAGE_MODE", "bssgp.page_mode",
	FT_UINT8, BASE_DEC, VALS(bssgp_page_mode_vals), 0x03,
	NULL, HFILL }
    },
	{ &hf_bssgp_container_id,
      { "Container ID", "bssgp.container_id",
	FT_UINT8, BASE_DEC, NULL, 0x03,
	NULL, HFILL }
    },
	{ &hf_bssgp_global_tfi,
      { "Global TFI", "bssgp.global_tfi",
	FT_UINT8, BASE_DEC, VALS(bssgp_global_tfi_vals), 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_ul_tfi,
      { "UPLINK_TFI", "bssgp.global_tfi",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_dl_tfi,
      { "DOWNLINK_TFI", "bssgp.global_tfi",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_ps_ho_cmd,
      { "PS Handover Command", "bssgp.ps_ho_cmd",
	FT_BYTES, BASE_NONE, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_sipsi,
      { "SI/PSI", "bssgp.sipsi",
	FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_type,
      { "Type", "bssgp.type",
	FT_UINT8, BASE_DEC, VALS(type_vals), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_cs_indication,
      { "CS Indication Contents", "bssgp.cs_indication",
	FT_UINT8, BASE_HEX, NULL, 0x0,
	NULL, HFILL }
    },

	{ &hf_bssgp_flow_control_gran,
      { "Granularity", "bssgp.flow_control_gran",
	FT_UINT8, BASE_DEC, VALS(bssgp_flow_control_gran_vals), 0x03,
	NULL, HFILL }
    },
	{ &hf_bssgp_serv_eutran_cco,
      { "Service EUTRAN CCO", "bssgp.serv_eutran_cco",
	FT_UINT8, BASE_DEC, VALS(bssgp_service_eutran_cco_vals), 0x18,
	NULL, HFILL }
    },
	{ &hf_bssgp_sub_prof_id_f_rat_freq_prio,
      { "Subscriber Profile ID for RAT/Frequency priority", "bssgp.sub_prof_id_f_rat_freq_prio",
	FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL }
    },
	{ &hf_bssgp_rel_int_rat_ho_inf_ind,
      { "Inter RAT Handover Info", "bssgp.rel_int_rat_ho_inf_ind",
	FT_BOOLEAN, 8, TFS(&tfs_reliable_not_reliable), 0x01,
	NULL, HFILL }
    },
	{ &hf_bssgp_csg_id,
      { "CSG Identity (CSG-ID)", "bssgp.csg_id",
	FT_UINT32, BASE_HEX, NULL, 0xffffff0f,
	NULL, HFILL }
    },
	{ &hf_bssgp_cell_acc_mode,
      { "Cell Access Mode", "bssgp.cell_acc_mode",
	FT_UINT8, BASE_DEC, VALS(bssgp_cell_access_mode_vals), 0x01,
	NULL, HFILL }
    },

  };

  /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	45
	gint *ett[NUM_INDIVIDUAL_ELEMS +
		  NUM_BSSGP_ELEM +
		  NUM_BSSGP_MSG];
	ett[0] = &ett_bssgp;
    ett[1] = &ett_bssgp_qos_profile;
    ett[2] = &ett_bssgp_gprs_timer;
    ett[3] = &ett_bssgp_cell_identifier;
    ett[4] = &ett_bssgp_channel_needed;
    ett[5] = &ett_bssgp_drx_parameters;
    ett[6] = &ett_bssgp_mobile_identity;
    ett[7] = &ett_bssgp_priority;
    ett[8] = &ett_bssgp_lsa_identifier_list;
    ett[9] = &ett_bssgp_lsa_information;
    ett[10] = &ett_bssgp_lsa_information_lsa_identification_and_attributes;
    ett[11] = &ett_bssgp_abqp;
    ett[12] = &ett_bssgp_lcs_qos;
    ett[13] = &ett_bssgp_lcs_client_type;
    ett[14] = &ett_bssgp_requested_gps_assistance_data;
    ett[15] = &ett_bssgp_requested_gps_assistance_data_satellite;
    ett[16] = &ett_bssgp_location_type;
    ett[17] = &ett_bssgp_positioning_data_positioning_method;
    ett[18] = &ett_bssgp_lcs_cause;
    ett[19] = &ett_bssgp_lcs_capability;
    ett[20] = &ett_bssgp_rrlp_flags;
    ett[21] = &ett_bssgp_rim_pdu_indications;
    ett[22] = &ett_bssgp_mcc;
    ett[23] = &ett_bssgp_mnc;
    ett[24] = &ett_bssgp_routing_area;
    ett[25] = &ett_bssgp_location_area;
    ett[26] = &ett_bssgp_rai_ci;
    ett[27] = &ett_bssgp_ran_information_request_application_container;
    ett[28] = &ett_bssgp_rim_routing_information;
    ett[29] = &ett_bssgp_ran_information_request_container_unit;
    ett[30] = &ett_bssgp_ran_information_container_unit;
    ett[31] = &ett_bssgp_pfc_flow_control_parameters;
    ett[32] = &ett_bssgp_pfc_flow_control_parameters_pfc;
    ett[33] = &ett_bssgp_global_cn_id;
    ett[34] = &ett_bssgp_ms_radio_access_capability;
    ett[35] = &ett_bssgp_feature_bitmap;
    ett[36] = &ett_bssgp_positioning_data;
    ett[37] = &ett_bssgp_msrac_value_part;
    ett[38] = &ett_bssgp_msrac_additional_access_technologies;
    ett[39] = &ett_bssgp_msrac_access_capabilities;
    ett[40] = &ett_bssgp_msrac_a5_bits;
    ett[41] = &ett_bssgp_msrac_multislot_capability;
    ett[42] = &ett_bssgp_tlli;
    ett[43] = &ett_bssgp_tmsi_ptmsi;
	ett[44] = &ett_bssgp_new;
  
	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_BSSGP_ELEM; i++, last_offset++)
	{
		ett_bssgp_elem[i] = -1;
		ett[last_offset] = &ett_bssgp_elem[i];
	}

	for (i=0; i < NUM_BSSGP_MSG; i++, last_offset++)
	{
		ett_bssgp_msg[i] = -1;
		ett[last_offset] = &ett_bssgp_msg[i];
	}

  /* Register the protocol name and description */
  proto_bssgp = proto_register_protocol("Base Station Subsystem GPRS Protocol", "BSSGP", "bssgp");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_bssgp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("bssgp", dissect_bssgp, proto_bssgp);

  /* Register configuration options */
  bssgp_module = prefs_register_protocol(proto_bssgp, NULL);
  prefs_register_bool_preference(bssgp_module, "decode_nri",
				 "Decode NRI",
				 "Decode NRI (for use with SGSN in Pool)",
				 &bssgp_decode_nri);
  prefs_register_uint_preference(bssgp_module, "nri_length", "NRI length",
				 "NRI length, in bits",
				 10, &bssgp_nri_length);
}

/* If this dissector uses sub-dissector registration add a registration routine.
 */
void
proto_reg_handoff_bssgp(void)
{
  llc_handle = find_dissector("llcgprs");
  rrlp_handle = find_dissector("rrlp");
  data_handle = find_dissector("data");
}
