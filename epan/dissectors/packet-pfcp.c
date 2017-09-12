/* packet-pfcp.c
*
* Routines for Packet Forwarding Control Protocol (PFCP) dissection
*
* Copyright 2017, Anders Broman <anders.broman@ericsson.com>
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
* Ref 3GPP TS 29.244 V14.0.0 (2017-06)
*/
#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/sminmpec.h>
#include <epan/addr_resolv.h> /* Needed for BASE_ENTERPRISES */

#include "packet-ntp.h"

void proto_register_pfcp(void);
void proto_reg_handoff_pfcp(void);

static dissector_handle_t pfcp_handle;
static dissector_handle_t pfcp_3gpp_ies_handle;

static int proto_pfcp = -1;

static int hf_pfcp_msg_type = -1;
static int hf_pfcp_msg_length = -1;
static int hf_pfcp_hdr_flags = -1;
static int hf_pfcp_version = -1;
static int hf_pfcp_mp_flag = -1;
static int hf_pfcp_s_flag = -1;
static int hf_pfcp_seid = -1;
static int hf_pfcp_seqno = -1;
static int hf_pfcp_mp = -1;

static int hf_pfcp2_ie = -1;
static int hf_pfcp2_ie_len = -1;
static int hf_pfcp2_enterprise_ie = -1;
static int hf_pfcp_enterprice_id = -1;

static int hf_pfcp_spare_b2 = -1;
static int hf_pfcp_spare_b3 = -1;
static int hf_pfcp_spare_b4 = -1;
static int hf_pfcp_spare_b5 = -1;
static int hf_pfcp_spare_b6 = -1;
static int hf_pfcp_spare_b7 = -1;
static int hf_pfcp_spare_b7_b5 = -1;
static int hf_pfcp_spare_h0 = -1;
static int hf_pfcp_spare_h1 = -1;
static int hf_pfcp_spare_oct = -1;
static int hf_pfcp_spare = -1;

static int hf_pfcp2_cause = -1;
static int hf_pfcp_node_id_type = -1;
static int hf_pfcp_node_id_ipv4 = -1;
static int hf_pfcp_node_id_ipv6 = -1;
static int hf_pfcp_node_id_fqdn = -1;
static int hf_pfcp_recovery_time_stamp = -1;
static int hf_pfcp_f_seid_flags = -1;
static int hf_pfcp_b0_v6 = -1;
static int hf_pfcp_b1_v4 = -1;
static int hf_pfcp_f_seid_ipv4 = -1;
static int hf_pfcp_f_seid_ipv6 = -1;
static int hf_pfcp_pdr_id = -1;
static int hf_pfcp_precedence = -1;
static int hf_pfcp_source_interface = -1;
static int hf_pfcp_f_teid_flags = -1;
static int hf_pfcp_fteid_flg_spare = -1;
static int hf_pfcp_fteid_flg_b2_ch = -1;
static int hf_pfcp_fteid_flg_b1_v6 = -1;
static int hf_pfcp_fteid_flg_b0_v4 = -1;
static int hf_pfcp_f_teid_ipv4 = -1;
static int hf_pfcp_f_teid_ipv6 = -1;
static int hf_pfcp_pdn_instance = -1;
static int hf_pfcp_ue_ip_address_flags = -1;
static int hf_pfcp_ue_ip_address_flag_b0 = -1;
static int hf_pfcp_ue_ip_address_flag_b1 = -1;
static int hf_pfcp_ue_ip_address_flag_b2 = -1;
static int hf_pfcp_ue_ip_addr_ipv4 = -1;
static int hf_pfcp_ue_ip_add_ipv6 = -1;
static int hf_pfcp_application_id = -1;
static int hf_pfcp_sdf_filter_flags = -1;
static int hf_pfcp_sdf_filter_b0_fd = -1;
static int hf_pfcp_sdf_filter_b1_ttc = -1;
static int hf_pfcp_sdf_filter_b2_spi = -1;
static int hf_pfcp_sdf_filter_b3_fl = -1;
static int hf_pfcp_flow_desc_len = -1;
static int hf_pfcp_fd = -1;
static int hf_pfcp_ttc = -1;
static int hf_pfcp_spi = -1;
static int hf_pfcp_fl = -1;
static int hf_pfcp_out_hdr_desc = -1;
static int hf_pfcp_far_id_flg = -1;
static int hf_pfcp_far_id = -1;
static int hf_pfcp_urr_id_flg = -1;
static int hf_pfcp_urr_id = -1;
static int hf_pfcp_qer_id_flg = -1;
static int hf_pfcp_qer_id = -1;
static int hf_pfcp_predef_rules_name = -1;
static int hf_pfcp_apply_action_flags = -1;
static int hf_pfcp_apply_action_b4_dupl = -1;
static int hf_pfcp_apply_action_b3_nocp = -1;
static int hf_pfcp_apply_action_b2_buff = -1;
static int hf_pfcp_apply_action_b1_forw = -1;
static int hf_pfcp_apply_action_b0_drop = -1;
static int hf_pfcp_bar_id = -1;
static int hf_pfcp_fq_csid_node_id_type = -1;
static int hf_pfcp_num_csid = -1;
static int hf_pfcp_fq_csid_node_id_ipv4 = -1;
static int hf_pfcp_fq_csid_node_id_ipv6 = -1;
static int hf_pfcp_fq_csid_node_id_mcc_mnc = -1;
static int hf_pfcp_fq_csid_node_id_int = -1;
static int hf_pfcp_fq_csid = -1;
static int hf_pfcp_measurement_period = -1;
static int hf_pfcp_duration_measurement = -1;
static int hf_pfcp_time_of_first_packet = -1;
static int hf_pfcp_time_of_last_packet = -1;

static int ett_pfcp = -1;
static int ett_pfcp_flags = -1;
static int ett_pfcp_ie = -1;
static int ett_pfcp_grouped_ie = -1;
static int ett_pfcp_f_seid_flags = -1;
static int ett_f_teid_flags = -1;
static int ett_pfcp_ue_ip_address_flags = -1;
static int ett_pfcp_sdf_filter_flags = -1;
static int ett_pfcp_apply_action_flags = -1;

static expert_field ei_pfcp_ie_reserved = EI_INIT;
static expert_field ei_pfcp_ie_data_not_decoded = EI_INIT;
static expert_field ei_pfcp_ie_not_decoded_null = EI_INIT;
static expert_field ei_pfcp_ie_not_decoded_to_large = EI_INIT;
static expert_field ei_pfcp_enterprise_ie_3gpp = EI_INIT;
static expert_field ei_pfcp_ie_encoding_error = EI_INIT;



static dissector_table_t pfcp_enterprise_ies_dissector_table;

static void dissect_pfcp_ies_common(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint offset, guint8 message_type);
static void dissect_pfcp_create_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_pdi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_create_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_forwarding_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_duplicating_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_create_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_create_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_created_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_update_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_update_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_upd_forwarding_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_update_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_update_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_update_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_remove_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_remove_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_remove_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_remove_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_load_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_overload_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_application_ids_pfds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_application_detection_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_pfcp_query_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_usage_report_smr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_usage_report_sdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_usage_report_srr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_downlink_data_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_create_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_update_bar_smr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_remove_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_error_indication_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_user_plane_path_failure_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);
static void dissect_pfcp_update_duplicating_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type);

static const true_false_string pfcp_id_predef_dynamic_tfs = {
    "Predefined by UP",
    "Dynamic by CP",
};

#define PFCP_MSG_RESERVED_0    0

static const value_string pfcp_message_type[] = {
    {PFCP_MSG_RESERVED_0,             "Reserved"},
    /* Sx Node related messages */

    { 1, "Sx Heartbeat Request"},
    { 2, "Sx Heartbeat Response"},
    { 3, "Sx PFD Management Request"},
    { 4, "Sx PFD Management Response"},
    { 5, "Sx Association Setup Request"},
    { 6, "Sx Association Setup Response"},
    { 7, "Sx Association Update Request"},
    { 8, "Sx Association Update Response"},
    { 9, "Sx Association Release Request"},
    { 10, "Sx Association Release Response"},
    { 11, "Sx Version Not Supported Response"},
    { 12, "Sx Node Report Request"},
    { 13, "Sx Node Report Response"},
    { 14, "Sx Session Set Deletion Request"},
    { 15, "Sx Session Set Deletion Response"},
    //16 to 49	For future use
    //Sx Session related messages
    { 50, "Sx Session Establishment Request"},
    { 51, "Sx Session Establishment Response"},
    { 52, "Sx Session Modification Request"},
    { 53, "Sx Session Modification Response"},
    { 54, "Sx Session Deletion Request"},
    { 55, "Sx Session Deletion Response"},
    { 56, "Sx Session Report Request"},
    { 57, "Sx Session Report Response"},
    //58 to 99	For future use
    //Other messages
    //100 to 255 	For future use
    {0, NULL}
};
static value_string_ext pfcp_message_type_ext = VALUE_STRING_EXT_INIT(pfcp_message_type);

/* 8.1.2    Information Element Types */
#define PFCP_IE_ID_CREATE_PDR                   1
#define PFCP_IE_ID_PDI                          2
#define PFCP_IE_CREATE_FAR                      3
#define PFCP_IE_FORWARDING_PARAMETERS           4
#define PFCP_IE_DUPLICATING_PARAMETERS          5
#define PFCP_IE_CREATE_URR                      6
#define PFCP_IE_CREATE_QER                      7
#define PFCP_IE_CREATED_PDR                     8
#define PFCP_IE_UPDATE_PDR                      9
#define PFCP_IE_UPDATE_FAR                     10
#define PFCP_IE_UPD_FORWARDING_PARAM   11
#define PFCP_IE_UPDATE_BAR                     12
#define PFCP_IE_UPDATE_URR                     13
#define PFCP_IE_UPDATE_QER                     14
#define PFCP_IE_REMOVE_PDR                     15
#define PFCP_IE_REMOVE_FAR                     16
#define PFCP_IE_REMOVE_URR                     17
#define PFCP_IE_REMOVE_QER                     18

#define PFCP_LOAD_CONTROL_INFORMATION          51
#define PFCP_OVERLOAD_CONTROL_INFORMATION      54
#define PFCP_APPLICATION_IDS_PFDS              58
#define PFCP_APPLICATION_DETECTION_INF         68
#define PFCP_QUERY_URR                         77
#define PFCP_USAGE_REPORT_SMR                  78
#define PFCP_USAGE_REPORT_SDR                  79
#define PFCP_USAGE_REPORT_SRR                  80
#define PFCP_DOWNLINK_DATA_REPORT              83
#define PFCP_CREATE_BAR                        85
#define PFCP_UPDATE_BAR_SMR                    86
#define PFCP_REMOVE_BAR                        87
#define PFCP_ERROR_INDICATION_REPORT           99
#define PFCP_USER_PLANE_PATH_FAILURE_REPORT   102
#define PFCP_UPDATE_DUPLICATING_PARAMETERS    105

static const value_string pfcp_ie_type[] = {

    { 0, "Reserved"},
    { 1, "Create PDR"},                                             /* Extendable / Table 7.5.2.2-1 */
    { 2, "PDI"},                                                    /* Extendable / Table 7.5.2.2-2 */
    { 3, "Create FAR"},                                             /* Extendable / Table 7.5.2.3-1 */
    { 4, "Forwarding Parameters"},                                  /* Extendable / Table 7.5.2.3-2 */
    { 5, "Duplicating Parameters"},                                 /* Extendable / Table 7.5.2.3-3 */
    { 6, "Create URR"},                                             /* Extendable / Table 7.5.2.4-1 */
    { 7, "Create QER"},                                             /* Extendable / Table 7.5.2.5-1 */
    { 8, "Created PDR"},                                            /* Extendable / Table 7.5.3.2-1 */
    { 9, "Update PDR" },                                            /* Extendable / Table 7.5.4.2-1 */
    { 10, "Update FAR" },                                           /* Extendable / Table 7.5.4.3-1 */
    { 11, "Update Forwarding Parameters" },                         /* Extendable / Table 7.5.4.3-2 */
    { 12, "Update BAR (Sx Session Report Response)" },              /* Extendable / Table 7.5.9.2-1 */
    { 13, "Update URR" },                                           /* Extendable / Table 7.5.4.4 */
    { 14, "Update QER" },                                           /* Extendable / Table 7.5.4.5 */
    { 15, "Remove PDR" },                                           /* Extendable / Table 7.5.4.6 */
    { 16, "Remove FAR" },                                           /* Extendable / Table 7.5.4.7 */
    { 17, "Remove URR" },                                           /* Extendable / Table 7.5.4.8 */
    { 18, "Remove QER" },                                           /* Extendable / Table 7.5.4.9 */
    { 19, "Cause" },                                                /* Fixed / Subclause 8.2.1 */
    { 20, "Source Interface" },                                     /* Extendable / Subclause 8.2.2 */
    { 21, "F-TEID" },                                               /* Extendable / Subclause 8.2.3 */
    { 22, "PDN Instance" },                                         /* Variable Length / Subclause 8.2.4 */
    { 23, "SDF Filter" },                                           /* Extendable / Subclause 8.2.5 */
    { 24, "Application ID" },                                       /* Variable Length / Subclause 8.2.6 */
    { 25, "Gate Status" },                                          /* Extendable / Subclause 8.2.7 */
    { 26, "MBR" },                                                  /* Extendable / Subclause 8.2.8 */
    { 27, "GBR" },                                                  /* Extendable / Subclause 8.2.9 */
    { 28, "QER Correlation ID" },                                   /* Extendable / Subclause 8.2.10 */
    { 29, "Precedence" },                                           /* Extendable / Subclause 8.2.11 */
    { 30, "DL Transport Level Marking" },                           /* Extendable / Subclause 8.2.12 */
    { 31, "Volume Threshold" },                                     /* Extendable /Subclause 8.2.13 */
    { 32, "Time Threshold" },                                       /* Extendable /Subclause 8.2.14 */
    { 33, "Monitoring Time" },                                      /* Extendable /Subclause 8.2.15 */
    { 34, "Subsequent Volume Threshold" },                          /* Extendable /Subclause 8.2.16 */
    { 35, "Subsequent Time Threshold" },                            /* Extendable /Subclause 8.2.17 */
    { 36, "Inactivity Detection Time" },                            /* Extendable /Subclause 8.2.18 */
    { 37, "Reporting Triggers" },                                   /* Extendable /Subclause 8.2.19 */
    { 38, "Redirect Information" },                                 /* Extendable /Subclause 8.2.20 */
    { 39, "Report Type" },                                          /* Extendable / Subclause 8.2.21 */
    { 40, "Offending IE" },                                         /* Fixed / Subclause 8.2.22 */
    { 41, "Forwarding Policy" },                                    /* Extendable / Subclause 8.2.23 */
    { 42, "Destination Interface" },                                /* Extendable / Subclause 8.2.24 */
    { 43, "UP Function Features" },                                 /* Extendable / Subclause 8.2.25 */
    { 44, "Apply Action" },                                         /* Extendable / Subclause 8.2.26 */
    { 45, "Downlink Data Service Information" },                    /* Extendable / Subclause 8.2.27 */
    { 46, "Downlink Data Notification Delay" },                     /* Extendable / Subclause 8.2.28 */
    { 47, "DL Buffering Duration" },                                /* Extendable / Subclause 8.2.29 */
    { 48, "DL Buffering Suggested Packet Count" },                  /* Variable / Subclause 8.2.30 */
    { 49, "SxSMReq-Flags" },                                        /* Extendable / Subclause 8.2.31 */
    { 50, "SxSRRsp-Flags" },                                        /* Extendable / Subclause 8.2.32 */
    { 51, "Load Control Information" },                             /* Extendable / Table 7.5.3.3-1 */
    { 52, "Sequence Number" },                                      /* Fixed Length / Subclause 8.2.33 */
    { 53, "Metric" },                                               /* Fixed Length / Subclause 8.2.34 */
    { 54, "Overload Control Information" },                         /* Extendable / Table 7.5.3.4-1 */
    { 55, "Timer" },                                                /* Extendable / Subclause 8.2 35 */
    { 56, "Packet Detection Rule ID" },                             /* Extendable / Subclause 8.2 36 */
    { 57, "F-SEID" },                                               /* Extendable / Subclause 8.2 37 */
    { 58, "Application ID's PFDs" },                                /* Extendable / Table 7.4.3.1-2 */
    { 59, "PFD context" },                                          /* Extendable / Table 7.4.3.1-3 */
    { 60, "Node ID" },                                              /* Extendable / Subclause 8.2.38 */
    { 61, "PFD contents" },                                         /* Extendable / Subclause 8.2.39 */
    { 62, "Measurement Method" },                                   /* Extendable / Subclause 8.2.40 */
    { 63, "Usage Report Trigger" },                                 /* Extendable / Subclause 8.2.41 */
    { 64, "Measurement Period" },                                   /* Extendable / Subclause 8.2.42 */
    { 65, "FQ-CSID" },                                              /* Extendable / Subclause 8.2.43 */
    { 66, "Volume Measurement" },                                   /* Extendable / Subclause 8.2.44 */
    { 67, "Duration Measurement" },                                 /* Extendable / Subclause 8.2.45 */
    { 68, "Application Detection Information" },                    /* Extendable / Table 7.5.8.3-2 */
    { 69, "Time of First Packet" },                                 /* Extendable / Subclause 8.2.46 */
    { 70, "Time of Last Packet" },                                  /* Extendable / Subclause 8.2.47 */
    { 71, "Quota Holding Time" },                                   /* Extendable / Subclause 8.2.48 */
    { 72, "Dropped DL Traffic Threshold" },                         /* Extendable / Subclause 8.2.49 */
    { 73, "Volume Quota" },                                         /* Extendable / Subclause 8.2.50 */
    { 74, "Time Quota" },                                           /* Extendable / Subclause 8.2.51 */
    { 75, "Start Time" },                                           /* Extendable / Subclause 8.2.52 */
    { 76, "End Time" },                                             /* Extendable / Subclause 8.2.53 */
    { 77, "Query URR" },                                            /* Extendable / Table 7.5.4.10-1 */
    { 78, "Usage Report (in Session Modification Response)" },      /* Extendable / Table 7.5.5.2-1 */
    { 79, "Usage Report (Session Deletion Response)" },             /* Extendable / Table 7.5.7.2-1 */
    { 80, "Usage Report (Session Report Request)" },                /* Extendable / Table 7.5.8.3-1 */
    { 81, "URR ID" },                                               /* Extendable / Subclause 8.2.54 */
    { 82, "Linked URR ID" },                                        /* Extendable / Subclause 8.2.55 */
    { 83, "Downlink Data Report" },                                 /* Extendable / Table 7.5.8.2-1 */
    { 84, "Outer Header Creation" },                                /* Extendable / Subclause 8.2.56 */
    { 85, "Create BAR" },                                           /* Extendable / Table 7.5.2.6-1 */
    { 86, "Update BAR (Session Modification Request)" },            /* Extendable / Table 7.5.4.11-1 */
    { 87, "Remove BAR" },                                           /* Extendable / Table 7.5.4.12-1 */
    { 88, "BAR ID" },                                               /* Extendable / Subclause 8.2.57 */
    { 89, "CP Function Features" },                                 /* Extendable / Subclause 8.2.58 */
    { 90, "Usage Information" },                                    /* Extendable / Subclause 8.2.59 */
    { 91, "Application Instance ID" },                              /* Variable Length / Subclause 8.2.60 */
    { 92, "Flow Information" },                                     /* Extendable / Subclause 8.2.61 */
    { 93, "UE IP Address" },                                        /* Extendable / Subclause 8.2.62 */
    { 94, "Packet Rate" },                                          /* Extendable / Subclause 8.2.63 */
    { 95, "Outer Header Removal" },                                 /* Extendable / Subclause 8.2.64 */
    { 96, "Recovery Time Stamp" },                                  /* Extendable / Subclause 8.2.65 */
    { 97, "DL Flow Level Marking" },                                /* Extendable / Subclause 8.2.66 */
    { 98, "Header Enrichment" },                                    /* Extendable / Subclause 8.2.67 */
    { 99, "Error Indication Report" },                              /* Extendable / Table 7.5.8.4-1 */
    { 100, "Measurement Information" },                             /* Extendable / Subclause 8.2.68 */
    { 101, "Node Report Type" },                                    /* Extendable / Subclause 8.2.69 */
    { 102, "User Plane Path Failure Report" },                      /* Extendable / Table 7.4.5.1.2-1 */
    { 103, "Remote GTP-U Peer" },                                   /* Extendable / Subclause 8.2.70 */
    { 104, "UR-SEQN" },                                             /* Fixed Length / Subclause 8.2.71 */
    { 105, "Update Duplicating Parameters" },                       /* Extendable / Table 7.5.4.3-3 */
    { 106, "Activate Predefined Rules" },                           /* Variable Length / Subclause 8.2.72 */
    { 107, "Deactivate Predefined Rules" },                         /* Variable Length / Subclause 8.2.73 */
    { 108, "FAR ID" },                                              /* Extendable / Subclause 8.2.74 */
    { 109, "QER ID" },                                              /* Extendable / Subclause 8.2.75 */
    { 110, "OCI Flags" },                                           /* Extendable / Subclause 8.2.76 */
    { 111, "Sx Association Release Request" },                      /* Extendable / Subclause 8.2.77 */
    { 112, "Graceful Release Period" },                             /* Extendable / Subclause 8.2.78 */
    //113 to 65535	Spare. For future use.
    {0, NULL}
};

static value_string_ext pfcp_ie_type_ext = VALUE_STRING_EXT_INIT(pfcp_ie_type);

static void
dissect_pfcp_reserved(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_reserved, tvb, 0, length);
}

/*
 * 8.2.1    Cause
 */
static const value_string pfcp_cause_vals[] = {

    {  0, "Reserved" },
    {  1, "Request accepted(success)" },
/* 2 - 63	Spare. */
    { 64, "Request rejected(reason not specified)" },
    { 65, "Session context not found" },
    { 66, "Mandatory IE missing" },
    { 67, "Conditional IE missing" },
    { 68, "Invalid length" },
    { 69, "Mandatory IE incorrect" },
    { 70, "Invalid Forwarding Policy" },
    { 71, "Invalid F - TEID allocation option" },
    { 72, "No established Sx Association" },
    { 73, "Rule creation / modification Failure" },
    { 74, "PFCP entity in congestion" },
    { 75, "No resources available" },
    { 76, "Service not supported" },
    { 77, "System failure" },
    /* 78 to 255	Spare for future use in a response message.See NOTE 2. */
    {0, NULL}
};

static void
dissect_pfcp_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_)
{
    /* Octet 5 Cause value */
    proto_tree_add_item(tree, hf_pfcp2_cause, tvb, 0, 1, ENC_BIG_ENDIAN);
}
/*
 * 8.2.2    Source Interface
 */
static const value_string pfcp_source_interface_vals[] = {

    { 0, "Access" },
    { 1, "Core" },
    { 2, "SGi-LAN" },
    { 3, "CP-function" },
    { 0, NULL }
};
static void
dissect_pfcp_source_interface(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5 Spare    Interface value */
    proto_tree_add_item(tree, hf_pfcp_spare_h1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_source_interface, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset += 1;

    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_source_interface_vals, "Unknown"));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
 /*
 * 8.2.3    F-TEID
 */
static void
dissect_pfcp_f_teid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint64 fteid_flags_val;

    static const int * pfcp_fteid_flags[] = {
        &hf_pfcp_fteid_flg_spare,
        &hf_pfcp_fteid_flg_b2_ch,
        &hf_pfcp_fteid_flg_b1_v6,
        &hf_pfcp_fteid_flg_b0_v4,
        NULL
    };
    /* Octet 5  Spare   CH  V6  V4*/
    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_pfcp_f_teid_flags,
        ett_f_teid_flags, pfcp_fteid_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT | BMT_NO_TFS, &fteid_flags_val);
    offset += 1;
    /* The following flags are coded within Octet 5:
     * Bit 1 - V4: If this bit is set to "1" and the CH bit is not set, then the IPv4 address field shall be present,
     *         otherwise the IPv4 address field shall not be present.
     * Bit 2 - V6: If this bit is set to "1" and the CH bit is not set, then the IPv6 address field shall be present,
     *         otherwise the IPv6 address field shall not be present.
     * Bit 3 - CH (CHOOSE): If this bit is set to "1", then the TEID, IPv4 address and IPv6 address fields shall not be
     *         present and the UP function shall assign an F-TEID with an IP4 or an IPv6 address if the V4 or V6 bit is set respectively.
               This bit shall only be set by the CP function.
     */
    if ((fteid_flags_val & 0x4) == 0) {
        return;
    }
    if ((fteid_flags_val & 0x1) == 1) {
        /* m to (m+3)    IPv4 address */
        proto_tree_add_item(tree, hf_pfcp_f_teid_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    if ((fteid_flags_val & 0x2) == 2) {
        /* p to (p+15)   IPv6 address */
        proto_tree_add_item(tree, hf_pfcp_f_teid_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }
    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.4    PDN Instance
 */
static void
dissect_pfcp_pdn_instance(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    /* Octet 5 5 to (n+4)   PDN Instance
     * The PDN instance field shall be encoded as an OctetString
     */
    proto_tree_add_item(tree, hf_pfcp_pdn_instance, tvb, offset, length, ENC_NA);
}
/*
 * 8.2.5    SDF Filter
 */
static void
dissect_pfcp_sdf_filter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length _U_, guint8 message_type _U_)
{
    int offset = 0;
    guint64 flags_val;
    guint32 fd_length;

    static const int * pfcp_sdf_filter_flags[] = {
        &hf_pfcp_spare_h1,
        &hf_pfcp_sdf_filter_b3_fl,
        &hf_pfcp_sdf_filter_b2_spi,
        &hf_pfcp_sdf_filter_b1_ttc,
        &hf_pfcp_sdf_filter_b0_fd,
        NULL
    };
    /* Octet 5  Spare   FL  SPI TTC FD*/
    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_pfcp_sdf_filter_flags,
        ett_pfcp_sdf_filter_flags, pfcp_sdf_filter_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT | BMT_NO_TFS, &flags_val);
    offset += 1;
    /* Octet 6 Spare*/
    proto_tree_add_item(tree, hf_pfcp_spare, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if ((flags_val & 0x1) == 1) {
        /* FD (Flow Description): If this bit is set to "1",
         * then the Length of Flow Description and the Flow Description fields shall be present
         */
        /* m to (m+1)	Length of Flow Description */
        proto_tree_add_item_ret_uint(tree, hf_pfcp_flow_desc_len, tvb, offset, 1, ENC_BIG_ENDIAN, &fd_length);
        offset += 1;
        /* Flow Description
         * The Flow Description field, when present, shall be encoded as an OctetString
         * as specified in subclause 5.4.2 of 3GPP TS 29.212
         */
        proto_tree_add_item(tree, hf_pfcp_fd, tvb, offset, fd_length, ENC_NA);
        offset += fd_length;
    }
    if ((flags_val & 0x2) == 2) {
        /* TTC (ToS Traffic Class): If this bit is set to "1", then the ToS Traffic Class field shall be present */
        /* ToS Traffic Class field, when present, shall be encoded as an OctetString on two octets
         * as specified in subclause 5.3.15 of 3GPP TS 29.212
         */
        proto_tree_add_item(tree, hf_pfcp_ttc, tvb, offset, 2, ENC_NA);
        offset += 2;
    }

    if ((flags_val & 0x4) == 4) {
        /* SPI (The Security Parameter Index) field, when present, shall be encoded as an OctetString on four octets and shall
         * contain the IPsec security parameter index (which is a 32-bit field),
         * as specified in subclause 5.3.51 of 3GPP TS 29.212
         */
        proto_tree_add_item(tree, hf_pfcp_spi, tvb, offset, 4, ENC_NA);
        offset += 4;
    }
    if ((flags_val & 0x8) == 8) {
        /* FL (Flow Label), when present, shall be encoded as an OctetString on 3 octets as specified in
         * subclause 5.3.52 of 3GPP TS 29.212 and shall contain an IPv6 flow label (which is a 20-bit field).
         * The bits 8 to 5 of the octet "v" shall be spare and set to zero, and the remaining 20 bits shall
         * contain the IPv6 flow label.*/
        proto_tree_add_item(tree, hf_pfcp_fl, tvb, offset, 3, ENC_NA);
        /*offset += 3;*/
    }

}
/*
 * 8.2.6    Application ID
 */
static void
dissect_pfcp_application_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    /* Octet 5 to (n+4) Application Identifier
    * The Application Identifier shall be encoded as an OctetString (see 3GPP TS 29.212)
    */
    proto_tree_add_item(tree, hf_pfcp_application_id, tvb, offset, length, ENC_NA);
}
/*
 * 8.2.7    Gate Status
 */
/*
 * 8.2.8    MBR
 */
/*
 * 8.2.9    GBR
 */
/*
 * 8.2.10   QER Correlation ID
 */
/*
 * 8.2.11   Precedence
 */
static void
dissect_pfcp_precedence(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5 5 to 8   Precedence value */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_precedence, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.12   DL Transport Level Marking
 * 8.2.13   Volume Threshold
 * 8.2.14   Time Threshold
 * 8.2.15   Monitoring Time
 * 8.2.16   Subsequent Volume Threshold
 * 8.2.17   Subsequent Time Threshold
 * 8.2.18   Inactivity Detection Time
 * 8.2.19   Reporting Triggers
 * 8.2.20   Redirect Information
 * 8.2.21   Report Type
 * 8.2.22   Offending IE
 * 8.2.23   Forwarding Policy
 * 8.2.24   Destination Interface
 * 8.2.25   UP Function Features
 */
/*
 * 8.2.26   Apply Action
 */
static void
dissect_pfcp_apply_action(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint64 flags_val;

    static const int * pfcp_apply_action_flags[] = {
        &hf_pfcp_spare_b7_b5,
        &hf_pfcp_apply_action_b4_dupl,
        &hf_pfcp_apply_action_b3_nocp,
        &hf_pfcp_apply_action_b2_buff,
        &hf_pfcp_apply_action_b1_forw,
        &hf_pfcp_apply_action_b0_drop,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   DUPL    NOCP    BUFF    FORW    DROP */
    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_pfcp_apply_action_flags,
        ett_pfcp_apply_action_flags, pfcp_apply_action_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT | BMT_NO_TFS, &flags_val);
    offset += 1;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.27   Downlink Data Service Information
 * 8.2.28   Downlink Data Notification Delay
 * 8.2.29   DL Buffering Duration
 * 8.2.30   DL Buffering Suggested Packet Count
 * 8.2.31   SxSMReq-Flags
 * 8.2.32   SxSRRsp-Flags
 * 8.2.33   Sequence Number
 * 8.2.34   Metric
 * 8.2.35   Timer
 * 8.2.36   Packet Detection Rule ID (PDR ID)
 */
static void
dissect_pfcp_pdr_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint32 rule_id;
    /* Octet 5 to 6 Rule ID*/
    proto_tree_add_item_ret_uint(tree, hf_pfcp_pdr_id, tvb, offset, 2, ENC_BIG_ENDIAN, &rule_id);
    offset += 2;

    proto_item_append_text(item, "%u", rule_id);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.37   F-SEID
 */
static void
dissect_pfcp_f_seid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint64 f_seid_flags;

    static const int * pfcp_f_seid_flags[] = {
        &hf_pfcp_spare_b7,
        &hf_pfcp_spare_b6,
        &hf_pfcp_spare_b5,
        &hf_pfcp_spare_b4,
        &hf_pfcp_spare_b3,
        &hf_pfcp_spare_b2,
        &hf_pfcp_b1_v4,
        &hf_pfcp_b0_v6,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   Spare   Spare   Spare   V4  V6*/
    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_pfcp_f_seid_flags,
        ett_pfcp_f_seid_flags, pfcp_f_seid_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT, &f_seid_flags);
    offset += 1;

    if ((f_seid_flags & 0x3) == 0) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_encoding_error, tvb, 0, 1);
        return;
    }
    /* Octet 6 to 13    SEID  */
    proto_tree_add_item(tree, hf_pfcp_seid, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    /* IPv4 address (if present)*/
    if ((f_seid_flags & 0x2) == 2) {
        proto_tree_add_item(tree, hf_pfcp_f_seid_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    /* IPv6 address (if present)*/
    if ((f_seid_flags & 0x1) == 1) {
        proto_tree_add_item(tree, hf_pfcp_f_seid_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }
    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

 /*
 * 8.2.38   Node ID
 */

static const value_string pfcp_node_id_type_vals[] = {

    { 0, "IPv4 address" },
    { 1, "IPv6 address" },
    { 2, "FQDN" },
    { 0, NULL }
};

static void
dissect_pfcp_node_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_)
{
    int offset = 0, name_len, tmp;
    guint32 node_id_type;
    guint8 *fqdn = NULL;

    /* Octet 5    Spare Node ID Type*/
    proto_tree_add_item(tree, hf_pfcp_spare_h1, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_node_id_type, tvb, offset, 1, ENC_BIG_ENDIAN, &node_id_type);
    offset++;

    switch (node_id_type) {
    case 0:
        /* IPv4 address */
        proto_tree_add_item(tree, hf_pfcp_node_id_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, "IPv4 %s", tvb_ip_to_str(tvb, offset));
        offset += 4;
        break;
    case 1:
        /* IPv4 address */
        proto_tree_add_item(tree, hf_pfcp_node_id_ipv6, tvb, offset, 16, ENC_NA);
        proto_item_append_text(item, "IPv6 %s", tvb_ip6_to_str(tvb, offset));
        offset += 16;
        break;
    case 2:
        /* FQDN, the Node ID value encoding shall be identical to the encoding of a FQDN
         * within a DNS message of section 3.1 of IETF RFC 1035 [27] but excluding the trailing zero byte.
         */
        if (length > 0) {
            name_len = tvb_get_guint8(tvb, offset);

            if (name_len < 0x20) {
                fqdn = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, length - 1, ENC_ASCII);
                for (;;) {
                    if (name_len >= length - 1)
                        break;
                    tmp = name_len;
                    name_len = name_len + fqdn[tmp] + 1;
                    fqdn[tmp] = '.';
                }
            }
            else {
                fqdn = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII);
            }
            proto_tree_add_string(tree, hf_pfcp_node_id_fqdn, tvb, offset, length, fqdn);
            proto_item_append_text(item, "%s", fqdn);
            offset += length;
        }
        break;
    default:
        break;
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.39   PFD Contents
 * 8.2.40   Measurement Method
 * 8.2.41   Usage Report Trigger
 */
/*
 * 8.2.42   Measurement Period
 */
static void
dissect_pfcp_measurement_period(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint32 value;
    /* 5 to 8   Measurement Period*/
    proto_tree_add_item_ret_uint(tree, hf_pfcp_measurement_period, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
 * 8.2.43   Fully qualified PDN Connection Set Identifier (FQ-CSID)
 */
static const value_string pfcp_fq_csid_node_id_type_vals[] = {

    { 0, "Node-Address is a global unicast IPv4 address" },
    { 1, "Node-Address is a global unicast IPv6 address" },
    { 2, "Node-Address is a 4 octets long field" },
    { 0, NULL }
};

static void
dissect_pfcp_fq_csid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint32 node_id_type, num_csid;

    /* Octet 5  FQ-CSID Node-ID Type	Number of CSIDs= m*/
    proto_tree_add_item_ret_uint(tree, hf_pfcp_fq_csid_node_id_type, tvb, offset, 1, ENC_BIG_ENDIAN, &node_id_type);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_num_csid, tvb, offset, 1, ENC_BIG_ENDIAN, &num_csid);
    offset++;

    /* 6 to p   Node-Address  */
    switch (node_id_type) {
    case 0:
        /* 0    indicates that Node-Address is a global unicast IPv4 address and p = 9 */
        proto_tree_add_item(tree, hf_pfcp_fq_csid_node_id_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 1:
        /* 1    indicates that Node-Address is a global unicast IPv6 address and p = 21 */
        proto_tree_add_item(tree, hf_pfcp_fq_csid_node_id_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;
    case 2:
        /* 2    indicates that Node-Address is a 4 octets long field with a 32 bit value stored in network order, and p= 9
         *      Most significant 20 bits are the binary encoded value of (MCC * 1000 + MNC).
         *      Least significant 12 bits is a 12 bit integer assigned by an operator to an MME, SGW-C, SGW-U, PGW-C or PGW-U
         */
        proto_tree_add_item(tree, hf_pfcp_fq_csid_node_id_mcc_mnc, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_pfcp_fq_csid_node_id_int, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    default:
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
        break;
    }

    while (num_csid > 0) {
        proto_tree_add_item(tree, hf_pfcp_fq_csid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 2;
        num_csid--;
    }
    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.44   Volume Measurement
 */
/*
 * 8.2.45   Duration Measurement
 */
static void
dissect_pfcp_duration_measurement(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint32 value;
    /* 5 to 8   Measurement Period*/
    proto_tree_add_item_ret_uint(tree, hf_pfcp_duration_measurement, tvb, offset, 4, ENC_BIG_ENDIAN, &value);
    offset += 4;

    proto_item_append_text(item, "%u s", value);

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.46   Time of First Packet
 */
static void
dissect_pfcp_time_of_first_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    const gchar *time_str;

    /* Octets 5 to 8 shall be encoded in the same format as the first four octets of the 64-bit timestamp
     * format as defined in section 6 of IETF RFC 5905
     */

    time_str = tvb_ntp_fmt_ts_sec(tvb, 0);
    proto_tree_add_string(tree, hf_pfcp_time_of_first_packet, tvb, offset, 4, time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.47   Time of Last Packet
 */
static void
dissect_pfcp_time_of_last_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    const gchar *time_str;

    /* Octets 5 to 8 shall be encoded in the same format as the first four octets of the 64-bit timestamp
    * format as defined in section 6 of IETF RFC 5905
    */

    time_str = tvb_ntp_fmt_ts_sec(tvb, 0);
    proto_tree_add_string(tree, hf_pfcp_time_of_last_packet, tvb, offset, 4, time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
/*
 * 8.2.48   Quota Holding Time
 */
/*
 * 8.2.49   Dropped DL Traffic Threshold
 */
/*
 * 8.2.50   Volume Quota
 */
/*
 * 8.2.51   Time Quota
 */
/*
 * 8.2.52   Start Time
 */
/*
 * 8.2.53   End Time
 */
/*
 * 8.2.54   URR ID
 */
static void
dissect_pfcp_urr_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint32 urr_id;
    /* Octet 5 to 8 URR ID value
    * The bit 8 of octet 5 is used to indicate if the Rule ID is dynamically allocated by the CP function
    * or predefined in the UP function. If set to 0, it indicates that the Rule is dynamically provisioned
    * by the CP Function. If set to 1, it indicates that the Rule is predefined in the UP Function
    */
    proto_tree_add_item(tree, hf_pfcp_urr_id_flg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_urr_id, tvb, offset, 4, ENC_BIG_ENDIAN, &urr_id);
    offset += 4;

    proto_item_append_text(item, "%s %u",
        ((urr_id & 80000000) ? pfcp_id_predef_dynamic_tfs.true_string : pfcp_id_predef_dynamic_tfs.false_string),
        (urr_id & 0x7fffffff));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.55   Linked URR ID IE
 * 8.2.56   Outer Header Creation
 */
/*
 * 8.2.57   BAR ID
 */
static void
dissect_pfcp_bar_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    /* Octet 5 BAR ID value
    * The BAR ID value shall be encoded as a binary integer value
    */
    proto_tree_add_item(tree, hf_pfcp_bar_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}

/*
 * 8.2.58   CP Function Features
 */
/*
 * 8.2.59   Usage Information
 */
/*
 * 8.2.60   Application Instance ID
 */
/*
 * 8.2.61   Flow Information
 */
/*
 * 8.2.62   UE IP Address
 */
static const true_false_string pfcp_ue_ip_add_sd_flag_vals = {
    "Destination IP address",
    "Source IP address",
};

static void
dissect_pfcp_ue_ip_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint64 ue_ip_address_flags;

    static const int * pfcp_ue_ip_address_flags[] = {
        &hf_pfcp_ue_ip_address_flag_b2,
        &hf_pfcp_ue_ip_address_flag_b1,
        &hf_pfcp_ue_ip_address_flag_b0,
        NULL
    };
    /* Octet 5  Spare   Spare   Spare   Spare   Spare   Spare   V4  V6*/
    proto_tree_add_bitmask_with_flags_ret_uint64(tree, tvb, offset, hf_pfcp_ue_ip_address_flags,
        ett_pfcp_ue_ip_address_flags, pfcp_ue_ip_address_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT, &ue_ip_address_flags);
    offset += 1;

    /* IPv4 address (if present)*/
    if ((ue_ip_address_flags & 0x1) == 1) {
        proto_tree_add_item(tree, hf_pfcp_ue_ip_addr_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }
    /* IPv6 address (if present)*/
    if ((ue_ip_address_flags & 0x2) == 2) {
        proto_tree_add_item(tree, hf_pfcp_ue_ip_add_ipv6, tvb, offset, 16, ENC_NA);
        offset += 16;
    }
    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.63   Packet Rate
 */
/*
 * 8.2.64   Outer Header Removal
 */
static const value_string pfcp_out_hdr_desc_vals[] = {
    { 0, "GTP-U/UDP/IPv4" },
    { 1, "GTP-U/UDP/IPv6" },
    { 2, "UDP/IPv4" },
    { 3, "UDP/IPv6 " },
    { 0, NULL }
};

static void
dissect_pfcp_outer_hdr_rem(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint32 value;
    /* Octet 5 to (n+4) Application Identifier
    * The Application Identifier shall be encoded as an OctetString (see 3GPP TS 29.212)
    */
    proto_tree_add_item_ret_uint(tree, hf_pfcp_out_hdr_desc, tvb, offset, 1, ENC_BIG_ENDIAN, &value);
    offset++;

    proto_item_append_text(item, "%s", val_to_str_const(value, pfcp_out_hdr_desc_vals, "Unknown"));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}
 /*
 * 8.2.65   Recovery Time Stamp
 */

static void
dissect_pfcp_recovery_time_stamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type _U_)
{
    const gchar *time_str;
    int offset = 0;

    /* indicates the UTC time when the node started. Octets 5 to 8 are encoded in the same format as
    * the first four octets of the 64-bit timestamp format as defined in section 6 of IETF RFC 5905 [26].
    */
    time_str = tvb_ntp_fmt_ts_sec(tvb, 0);
    proto_tree_add_string(tree, hf_pfcp_recovery_time_stamp, tvb, offset, 4, time_str);
    proto_item_append_text(item, "%s", time_str);
    offset += 4;

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.66   DL Flow Level Marking
 */
/*
 * 8.2.67   Header Enrichment
 */
/*
 * 8.2.68   Measurement Information
 */
/*
 * 8.2.69   Node Report Type
 */
/*
 * 8.2.70   Remote GTP-U Peer
 */
/*
 * 8.2.71   UR-SEQN
 */
/*
 * 8.2.72   Activate Predefined Rules
 */
static void
dissect_pfcp_act_predef_rules(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    /* Octet 5 to (n+4) Predefined Rules Name
    * The Predefined Rules Name field shall be encoded as an OctetString
    */
    proto_tree_add_item(tree, hf_pfcp_predef_rules_name, tvb, offset, length, ENC_NA);
}
/*
 * 8.2.73   Deactivate Predefined Rules
 */
static void
dissect_pfcp_deact_predef_rules(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    /* Octet 5 to (n+4) Predefined Rules Name
    * The Predefined Rules Name field shall be encoded as an OctetString
    */
    proto_tree_add_item(tree, hf_pfcp_predef_rules_name, tvb, offset, length, ENC_NA);
}
/*
 * 8.2.74   FAR ID
 */
static void
dissect_pfcp_far_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint32 far_id;
    /* Octet 5 to 8 FAR ID value
     * The bit 8 of octet 5 is used to indicate if the Rule ID is dynamically allocated
     * by the CP function or predefined in the UP function. If set to 0, it indicates that
     * the Rule is dynamically provisioned by the CP Function. If set to 1, it indicates that
     * the Rule is predefined in the UP Function.
     */
    proto_tree_add_item(tree, hf_pfcp_far_id_flg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_far_id, tvb, offset, 4, ENC_BIG_ENDIAN, &far_id);
    offset += 4;

    proto_item_append_text(item, "%s %u",
        ((far_id&80000000)? pfcp_id_predef_dynamic_tfs.true_string : pfcp_id_predef_dynamic_tfs.false_string),
        (far_id & 0x7fffffff));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.75   QER ID
 */
static void
dissect_pfcp_qer_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_)
{
    int offset = 0;
    guint32 qer_id;
    /* Octet 5 to 8 URR ID value
    * The bit 8 of octet 5 is used to indicate if the Rule ID is dynamically allocated by the CP function
    * or predefined in the UP function. If set to 0, it indicates that the Rule is dynamically provisioned
    * by the CP Function. If set to 1, it indicates that the Rule is predefined in the UP Function
    */
    proto_tree_add_item(tree, hf_pfcp_qer_id_flg, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item_ret_uint(tree, hf_pfcp_qer_id, tvb, offset, 4, ENC_BIG_ENDIAN, &qer_id);
    offset += 4;

    proto_item_append_text(item, "%s %u",
        ((qer_id & 80000000) ? pfcp_id_predef_dynamic_tfs.true_string : pfcp_id_predef_dynamic_tfs.false_string),
        (qer_id & 0x7fffffff));

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }

}
/*
 * 8.2.76   OCI Flag
 */
/*
 * 8.2.77   Sx Association Release Request
 */
/*
 * 8.2.78   Graceful Release Period
 */



/* Array of functions to dissect IEs
* (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
*/
typedef struct _pfcp_ie {
    void(*decode) (tvbuff_t *, packet_info *, proto_tree *, proto_item *, guint16, guint8);
} pfcp_ie_t;

static const pfcp_ie_t pfcp_ies[] = {
/*      0 */    { dissect_pfcp_reserved },
/*      1 */    { dissect_pfcp_create_pdr },                                    /* Create PDR                                       Extendable / Table 7.5.2.2-1 */
/*      2 */    { dissect_pfcp_pdi },                                           /* PDI                                              Extendable / Table 7.5.2.2-2 */
/*      3 */    { dissect_pfcp_create_far },                                    /* Create FAR                                       Extendable / Table 7.5.2.3-1 */
/*      4 */    { dissect_pfcp_forwarding_parameters },                         /* Forwarding Parameters                            Extendable / Table 7.5.2.3-2 */
/*      5 */    { dissect_pfcp_duplicating_parameters },                        /* Duplicating Parameters                           Extendable / Table 7.5.2.3-3 */
/*      6 */    { dissect_pfcp_create_urr },                                    /* Create URR                                       Extendable / Table 7.5.2.4-1 */
/*      7 */    { dissect_pfcp_create_qer },                                    /* Create QER                                       Extendable / Table 7.5.2.5-1 */
/*      8 */    { dissect_pfcp_created_pdr },                                   /* Created PDR                                      Extendable / Table 7.5.3.2-1 */
/*      9 */    { dissect_pfcp_update_pdr },                                    /* Update PDR                                       Extendable / Table 7.5.4.2-1 */
/*     10 */    { dissect_pfcp_update_far },                                    /* Update FAR                                       Extendable / Table 7.5.4.3-1 */
/*     11 */    { dissect_pfcp_upd_forwarding_param },                          /* Update Forwarding Parameters                     Extendable / Table 7.5.4.3-2 */
/*     12 */    { dissect_pfcp_update_bar },                                    /* Update BAR (Sx Session Report Response)          Extendable / Table 7.5.9.2-1 */
/*     13 */    { dissect_pfcp_update_urr },                                    /* Update URR                                       Extendable / Table 7.5.4.4 */
/*     14 */    { dissect_pfcp_update_qer },                                    /* Update QER                                       Extendable / Table 7.5.4.5 */
/*     15 */    { dissect_pfcp_remove_pdr },                                    /* Remove PDR                                       Extendable / Table 7.5.4.6 */
/*     16 */    { dissect_pfcp_remove_far },                                    /* Remove FAR                                       Extendable / Table 7.5.4.7 */
/*     17 */    { dissect_pfcp_remove_urr },                                    /* Remove URR                                       Extendable / Table 7.5.4.8 */
/*     18 */    { dissect_pfcp_remove_qer },                                    /* Remove QER                                       Extendable / Table 7.5.4.9 */
/*     19 */    { dissect_pfcp_cause },                                         /* Cause                                            Fixed / Subclause 8.2.1 */
/*     20 */    { dissect_pfcp_source_interface },                              /* Source Interface                                 Extendable / Subclause 8.2.2 */
/*     21 */    { dissect_pfcp_f_teid },                                        /* F-TEID                                           Extendable / Subclause 8.2.3 */
/*     22 */    { dissect_pfcp_pdn_instance },                                  /* PDN Instance                                     Variable Length / Subclause 8.2.4 */
/*     23 */    { dissect_pfcp_sdf_filter },                                    /* SDF Filter                                       Extendable / Subclause 8.2.5 */
/*     24 */    { dissect_pfcp_application_id },                                /* Application ID                                   Variable Length / Subclause 8.2.6 */
/*     25 */    { NULL },    /* Gate Status                                     Extendable / Subclause 8.2.7 */
/*     26 */    { NULL },    /* MBR                                             Extendable / Subclause 8.2.8 */
/*     27 */    { NULL },    /* GBR                                             Extendable / Subclause 8.2.9 */
/*     28 */    { NULL },    /* QER Correlation ID                              Extendable / Subclause 8.2.10 */
/*     29 */    { dissect_pfcp_precedence },                                    /* Precedence                                      Extendable / Subclause 8.2.11 */
/*     30 */    { NULL },    /* DL Transport Level Marking                      Extendable / Subclause 8.2.12 */
/*     31 */    { NULL },    /* Volume Threshold                                Extendable /Subclause 8.2.13 */
/*     32 */    { NULL },    /* Time Threshold                                  Extendable /Subclause 8.2.14 */
/*     33 */    { NULL },    /* Monitoring Time                                 Extendable /Subclause 8.2.15 */
/*     34 */    { NULL },    /* Subsequent Volume Threshold                     Extendable /Subclause 8.2.16 */
/*     35 */    { NULL },    /* Subsequent Time Threshold                       Extendable /Subclause 8.2.17 */
/*     36 */    { NULL },    /* Inactivity Detection Time                       Extendable /Subclause 8.2.18 */
/*     37 */    { NULL },    /* Reporting Triggers                              Extendable /Subclause 8.2.19 */
/*     38 */    { NULL },    /* Redirect Information                            Extendable /Subclause 8.2.20 */
/*     39 */    { NULL },    /* Report Type                                     Extendable / Subclause 8.2.21 */
/*     40 */    { NULL },    /* Offending IE                                    Fixed / Subclause 8.2.22 */
/*     41 */    { NULL },    /* Forwarding Policy                               Extendable / Subclause 8.2.23 */
/*     42 */    { NULL },    /* Destination Interface                           Extendable / Subclause 8.2.24 */
/*     43 */    { NULL },    /* UP Function Features                            Extendable / Subclause 8.2.25 */
/*     44 */    { dissect_pfcp_apply_action },                                  /* Apply Action                                    Extendable / Subclause 8.2.26 */
/*     45 */    { NULL },    /* Downlink Data Service Information               Extendable / Subclause 8.2.27 */
/*     46 */    { NULL },    /* Downlink Data Notification Delay                Extendable / Subclause 8.2.28 */
/*     47 */    { NULL },    /* DL Buffering Duration                           Extendable / Subclause 8.2.29 */
/*     48 */    { NULL },    /* DL Buffering Suggested Packet Count             Variable / Subclause 8.2.30 */
/*     49 */    { NULL },    /* SxSMReq-Flags                                   Extendable / Subclause 8.2.31 */
/*     50 */    { NULL },    /* SxSRRsp-Flags                                   Extendable / Subclause 8.2.32 */
/*     51 */    { dissect_pfcp_load_control_information },                      /* Load Control Information                        Extendable / Table 7.5.3.3-1 */
/*     52 */    { NULL },    /* Sequence Number                                 Fixed Length / Subclause 8.2.33 */
/*     53 */    { NULL },    /* Metric                                          Fixed Length / Subclause 8.2.34 */
/*     54 */    { dissect_pfcp_overload_control_information },                  /* Overload Control Information                    Extendable / Table 7.5.3.4-1 */
/*     55 */    { NULL },    /* Timer                                           Extendable / Subclause 8.2 35 */
/*     56 */    { dissect_pfcp_pdr_id },                                        /* Packet Detection Rule ID                        Extendable / Subclause 8.2 36 */
/*     57 */    { dissect_pfcp_f_seid },                                        /* F-SEID                                          Extendable / Subclause 8.2 37 */
/*     58 */    { dissect_pfcp_application_ids_pfds },                          /* Application ID's PFDs                           Extendable / Table 7.4.3.1-2 */
/*     59 */    { NULL },    /* PFD context                                     Extendable / Table 7.4.3.1-3 */
/*     60 */    { dissect_pfcp_node_id },                                       /* Node ID                                         Extendable / Subclause 8.2.38 */
/*     61 */    { NULL },    /* PFD contents                                    Extendable / Subclause 8.2.39 */
/*     62 */    { NULL },    /* Measurement Method                              Extendable / Subclause 8.2.40 */
/*     63 */    { NULL },    /* Usage Report Trigger                            Extendable / Subclause 8.2.41 */
/*     64 */    { dissect_pfcp_measurement_period },                            /* Measurement Period                              Extendable / Subclause 8.2.42 */
/*     65 */    { dissect_pfcp_fq_csid },                                       /* FQ-CSID                                         Extendable / Subclause 8.2.43 */
/*     66 */    { NULL },    /* Volume Measurement                              Extendable / Subclause 8.2.44 */
/*     67 */    { dissect_pfcp_duration_measurement },                          /* Duration Measurement                            Extendable / Subclause 8.2.45 */
/*     68 */    { dissect_pfcp_application_detection_inf },                     /* Application Detection Information               Extendable / Table 7.5.8.3-2 */
/*     69 */    { dissect_pfcp_time_of_first_packet },                          /* Time of First Packet                            Extendable / Subclause 8.2.46 */
/*     70 */    { dissect_pfcp_time_of_last_packet },                           /* Time of Last Packet                             Extendable / Subclause 8.2.47 */
/*     71 */    { NULL },    /* Quota Holding Time                              Extendable / Subclause 8.2.48 */
/*     72 */    { NULL },    /* Dropped DL Traffic Threshold                    Extendable / Subclause 8.2.49 */
/*     73 */    { NULL },    /* Volume Quota                                    Extendable / Subclause 8.2.50 */
/*     74 */    { NULL },    /* Time Quota                                      Extendable / Subclause 8.2.51 */
/*     75 */    { NULL },    /* Start Time                                      Extendable / Subclause 8.2.52 */
/*     76 */    { NULL },    /* End Time                                        Extendable / Subclause 8.2.53 */
/*     77 */    { dissect_pfcp_pfcp_query_urr },                                /* Query URR                                       Extendable / Table 7.5.4.10-1 */
/*     78 */    { dissect_pfcp_usage_report_smr },                              /* Usage Report (in Session Modification Response) Extendable / Table 7.5.5.2-1 */
/*     79 */    { dissect_pfcp_usage_report_sdr },                              /* Usage Report (Session Deletion Response)        Extendable / Table 7.5.7.2-1 */
/*     80 */    { dissect_pfcp_usage_report_srr },                              /* Usage Report (Session Report Request)           Extendable / Table 7.5.8.3-1 */
/*     81 */    { dissect_pfcp_urr_id },                                        /* URR ID                                          Extendable / Subclause 8.2.54 */
/*     82 */    { NULL },    /* Linked URR ID                                   Extendable / Subclause 8.2.55 */
/*     83 */    { dissect_pfcp_downlink_data_report },                          /* Downlink Data Report                            Extendable / Table 7.5.8.2-1 */
/*     84 */    { NULL },    /* Outer Header Creation                           Extendable / Subclause 8.2.56 */
/*     85 */    { dissect_pfcp_create_bar },                                    /* Create BAR                                      Extendable / Table 7.5.2.6-1 */
/*     86 */    { dissect_pfcp_update_bar_smr },                                /* Update BAR (Session Modification Request)       Extendable / Table 7.5.4.11-1 */
/*     87 */    { dissect_pfcp_remove_bar },                                    /* Remove BAR                                      Extendable / Table 7.5.4.12-1 */
/*     88 */    { dissect_pfcp_bar_id },                                        /* BAR ID                                          Extendable / Subclause 8.2.57 */
/*     89 */    { NULL },    /* CP Function Features                            Extendable / Subclause 8.2.58 */
/*     90 */    { NULL },    /* Usage Information                               Extendable / Subclause 8.2.59 */
/*     91 */    { NULL },    /* Application Instance ID                         Variable Length / Subclause 8.2.60 */
/*     92 */    { NULL },    /* Flow Information                                Extendable / Subclause 8.2.61 */
/*     93 */    { dissect_pfcp_ue_ip_address },                                 /* UE IP Address                                   Extendable / Subclause 8.2.62 */
/*     94 */    { NULL },    /* Packet Rate                                     Extendable / Subclause 8.2.63 */
/*     95 */    { dissect_pfcp_outer_hdr_rem },                                 /* Outer Header Removal                            Extendable / Subclause 8.2.64 */
/*     96 */    { dissect_pfcp_recovery_time_stamp },                           /* Recovery Time Stamp              Extendable / Subclause 8.2.65 */
/*     97 */    { NULL },    /* DL Flow Level Marking                           Extendable / Subclause 8.2.66 */
/*     98 */    { NULL },    /* Header Enrichment                               Extendable / Subclause 8.2.67 */
/*     99 */    { dissect_pfcp_error_indication_report },                       /* Error Indication Report                         Extendable / Table 7.5.8.4-1 */
/*    100 */    { NULL },                /* Measurement Information                        Extendable / Subclause 8.2.68 */
/*    101 */    { NULL },    /* Node Report Type                               Extendable / Subclause 8.2.69 */
/*    102 */    { dissect_pfcp_user_plane_path_failure_report },                /* User Plane Path Failure Report                 Extendable / Table 7.4.5.1.2-1 */
/*    103 */    { NULL },    /* Remote GTP-U Peer                              Extendable / Subclause 8.2.70 */
/*    104 */    { NULL },    /* UR-SEQN                                        Fixed Length / Subclause 8.2.71 */
/*    105 */    { dissect_pfcp_update_duplicating_parameters },                 /* Update Duplicating Parameters                  Extendable / Table 7.5.4.3-3 */
/*    106 */    { dissect_pfcp_act_predef_rules },                              /* Activate Predefined Rules                      Variable Length / Subclause 8.2.72 */
/*    107 */    { dissect_pfcp_deact_predef_rules },                            /* Deactivate Predefined Rules                    Variable Length / Subclause 8.2.73 */
/*    108 */    { dissect_pfcp_far_id },                                        /* FAR ID                                         Extendable / Subclause 8.2.74 */
/*    109 */    { dissect_pfcp_qer_id },                                        /* QER ID                                         Extendable / Subclause 8.2.75 */
/*    110 */    { NULL },    /* OCI Flags                                      Extendable / Subclause 8.2.76 */
/*    111 */    { NULL },    /* Sx Association Release Request                 Extendable / Subclause 8.2.77 */
/*    112 */    { NULL },    /* Graceful Release Period                        Extendable / Subclause 8.2.78 */
    { NULL },                                                        /* End of List */
};

#define NUM_PFCP_IES (sizeof(pfcp_ies)/sizeof(pfcp_ie_t))
/* Set up the array to hold "etts" for each IE*/
gint ett_pfcp_elem[NUM_PFCP_IES-1];

/* 7.2.3.3  Grouped Information Elements */

static void
dissect_pfcp_grouped_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type, int ett_index)
{
    int         offset = 0;
    tvbuff_t   *new_tvb;
    proto_tree *grouped_tree;

    proto_item_append_text(item, "[Grouped IE]");
    grouped_tree = proto_item_add_subtree(tree, ett_index);

    new_tvb = tvb_new_subset_length(tvb, offset, length);
    dissect_pfcp_ies_common(new_tvb, pinfo, grouped_tree, 0, message_type);

}

static void
dissect_pfcp_pdi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ID_PDI]);
}

static void
dissect_pfcp_create_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_ID_CREATE_PDR]);
}

static void
dissect_pfcp_create_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATE_FAR]);
}

static void
dissect_pfcp_forwarding_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_FORWARDING_PARAMETERS]);
}

static void
dissect_pfcp_duplicating_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_DUPLICATING_PARAMETERS]);
}

static void
dissect_pfcp_create_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATE_URR]);
}

static void
dissect_pfcp_create_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATE_QER]);
}

static void
dissect_pfcp_created_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_CREATED_PDR]);
}

static void
dissect_pfcp_update_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_PDR]);
}

static void
dissect_pfcp_update_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_FAR]);
}

static void
dissect_pfcp_upd_forwarding_param(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPD_FORWARDING_PARAM]);
}

static void
dissect_pfcp_update_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_BAR]);
}

static void
dissect_pfcp_update_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_URR]);
}

static void
dissect_pfcp_update_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_UPDATE_QER]);
}

static void
dissect_pfcp_remove_pdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_PDR]);
}

static void
dissect_pfcp_remove_far(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_FAR]);
}

static void
dissect_pfcp_remove_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_URR]);
}

static void
dissect_pfcp_remove_qer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_IE_REMOVE_QER]);
}

static void
dissect_pfcp_load_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_LOAD_CONTROL_INFORMATION]);
}

static void
dissect_pfcp_overload_control_information(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_OVERLOAD_CONTROL_INFORMATION]);
}

static void
dissect_pfcp_application_ids_pfds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_APPLICATION_IDS_PFDS]);
}


static void
dissect_pfcp_application_detection_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_APPLICATION_DETECTION_INF]);
}

static void
dissect_pfcp_pfcp_query_urr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_QUERY_URR]);
}

static void
dissect_pfcp_usage_report_smr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_USAGE_REPORT_SMR]);
}

static void
dissect_pfcp_usage_report_sdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_USAGE_REPORT_SDR]);
}

static void
dissect_pfcp_usage_report_srr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_USAGE_REPORT_SRR]);
}

static void
dissect_pfcp_downlink_data_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_DOWNLINK_DATA_REPORT]);
}

static void
dissect_pfcp_create_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_CREATE_BAR]);
}

static void
dissect_pfcp_update_bar_smr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_UPDATE_BAR_SMR]);
}

static void
dissect_pfcp_remove_bar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_REMOVE_BAR]);
}

static void
dissect_pfcp_error_indication_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_ERROR_INDICATION_REPORT]);
}

static void
dissect_pfcp_user_plane_path_failure_report(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_USER_PLANE_PATH_FAILURE_REPORT]);
}

static void
dissect_pfcp_update_duplicating_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_item *item, guint16 length, guint8 message_type)
{
    dissect_pfcp_grouped_ie(tvb, pinfo, tree, item, length, message_type, ett_pfcp_elem[PFCP_UPDATE_DUPLICATING_PARAMETERS]);
}


static void
dissect_pfcp_ies_common(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, gint offset, guint8 message_type)
{
    proto_tree *ie_tree;
    proto_item *ti;
    tvbuff_t   *ie_tvb;
    guint16 type, length, enterprise_type;
    guint16 enterprise_id;

    /* 8.1.1    Information Element Format */
    /*
    Octets      8   7   6   5   4   3   2   1
    1 to 2      Type = xxx (decimal)
    3 to 4      Length = n
    p to (p+1)  Enterprise ID
    k to (n+4)  IE specific data or content of a grouped IE

    If the Bit 8 of Octet 1 is not set, this indicates that the IE is defined by 3GPP and the Enterprise ID is absent.
    If Bit 8 of Octet 1 is set, this indicates that the IE is defined by a vendor and the Enterprise ID is present
    identified by the Enterprise ID
    */

    /*Enterprise ID : if the IE type value is within the range of 32768 to 65535,
     * this field shall contain the IANA - assigned "SMI Network Management Private Enterprise Codes"
     * value of the vendor defining the IE.
     */
    /* Length: this field contains the length of the IE excluding the first four octets, which are common for all IEs */

    /* Process the IEs*/
    while (offset < (gint)tvb_reported_length(tvb)) {
        /* Octet 1 -2 */
        type = tvb_get_ntohs(tvb, offset);
        length = tvb_get_ntohs(tvb, offset + 2);

        if ((type & 0x8000) == 0x8000 ) {
            enterprise_id = tvb_get_ntohs(tvb, offset + 4);
            enterprise_type = (type & 0x8000);
            ie_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 + length, ett_pfcp_ie, &ti, "Enterprise %s specific IE: %u",
                try_enterprises_lookup(enterprise_id),
                enterprise_type);

            proto_tree_add_item(ie_tree, hf_pfcp2_enterprise_ie, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(ie_tree, hf_pfcp2_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            /* Bit 8 of Octet 1 is set, this indicates that the IE is defined by a vendor and the Enterprise ID is present */
            proto_tree_add_item(ie_tree, hf_pfcp_enterprice_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* give the whole IE to the subdissector */
            ie_tvb = tvb_new_subset_length(tvb, offset-6, length);
            dissector_try_uint_new(pfcp_enterprise_ies_dissector_table, enterprise_id, ie_tvb, pinfo, ie_tree, FALSE, ti);
            offset += length;
        } else {
            int tmp_ett;
            if (type < (NUM_PFCP_IES - 1)) {
                tmp_ett = ett_pfcp_elem[type];
            } else {
                tmp_ett = ett_pfcp_ie;
            }
            ie_tree = proto_tree_add_subtree_format(tree, tvb, offset, 4 + length, tmp_ett, &ti, "%s : ",
                val_to_str_ext_const(type, &pfcp_ie_type_ext, "Unknown"));

            proto_tree_add_item(ie_tree, hf_pfcp2_ie, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(ie_tree, hf_pfcp2_ie_len, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            if (type < (NUM_PFCP_IES -1)) {
                ie_tvb = tvb_new_subset_length(tvb, offset, length);
                if(pfcp_ies[type].decode){
                    (*pfcp_ies[type].decode) (ie_tvb, pinfo, ie_tree, ti, length, message_type);
                } else {
                    /* NULL function pointer, we have no decoding function*/
                    proto_tree_add_expert(ie_tree, pinfo, &ei_pfcp_ie_not_decoded_null, tvb, offset, length);
                }
            } else {
                /* IE id outside of array, We have no decoding function for it */
                proto_tree_add_expert(ie_tree, pinfo, &ei_pfcp_ie_not_decoded_to_large, tvb, offset, length);
            }

            offset += length;
        }
    }
}

static int
dissect_pfcp(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void *data _U_)
{
    proto_item          *item;
    proto_tree          *sub_tree;
    int                  offset = 0;
    guint64              pfcp_flags;
    guint8               message_type;
    guint32              length;

    static const int * pfcp_hdr_flags[] = {
        &hf_pfcp_version,
        &hf_pfcp_spare_b4,
        &hf_pfcp_spare_b3,
        &hf_pfcp_spare_b2,
        &hf_pfcp_mp_flag,
        &hf_pfcp_s_flag,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PFCP");
    col_clear(pinfo->cinfo, COL_INFO);

    message_type = tvb_get_guint8(tvb, 1);
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_ext_const(message_type, &pfcp_message_type_ext, "Unknown"));

    item = proto_tree_add_item(tree, proto_pfcp, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_pfcp);

    /* 7.2.2    Message Header */
    /*
        Octet     8     7     6     5     4     3     2     1
          1    | Version         |Spare|Spare|Spare|  MP  |  S  |
          2    |        Message Type                            |
          3    |        Message Length (1st Octet)              |
          4    |        Message Length (2nd Octet)              |
        m to   | If S flag is set to 1, then SEID shall be      |
        k(m+7) | placed into octets 5-12. Otherwise, SEID field |
               | is not present at all.                         |
        n to   | Sequence Number                                |
        (n+2)  |                                                |
        (n+3)  |         Spare                                  |

    */
    /* Octet 1 */
    proto_tree_add_bitmask_with_flags_ret_uint64(sub_tree, tvb, offset, hf_pfcp_hdr_flags,
        ett_pfcp_flags, pfcp_hdr_flags, ENC_BIG_ENDIAN, BMT_NO_FALSE | BMT_NO_INT, &pfcp_flags);
    offset += 1;

    /* Octet 2 Message Type */
    proto_tree_add_item(sub_tree, hf_pfcp_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* Octet 3 - 4 Message Length */
    proto_tree_add_item_ret_uint(sub_tree, hf_pfcp_msg_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);

    if ((pfcp_flags & 0x1) == 1) {
        /* If S flag is set to 1, then SEID shall be placed into octets 5-12*/
        /* Session Endpoint Identifier 8 Octets */
        proto_tree_add_item(sub_tree, hf_pfcp_seid, tvb, offset, 8, ENC_BIG_ENDIAN);
        offset += 8;
    }
    /* 7.2.2.2	PFCP Header for Node Related Messages */
    /*
        Octet     8     7     6     5     4     3     2     1
          1    | Version         |Spare|Spare|Spare| MP=0 | S=0 |
          2    |        Message Type                            |
          3    |        Message Length (1st Octet)              |
          4    |        Message Length (2nd Octet)              |
          5    |        Sequence Number (1st Octet)             |
          6    |        Sequence Number (2st Octet)             |
          7    |        Sequence Number (3st Octet)             |
          8    |             Spare                              |
          */
    proto_tree_add_item(sub_tree, hf_pfcp_seqno, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    if ((pfcp_flags & 0x2) == 0x2) {
        /* If the "MP" flag is set to "1", then bits 8 to 5 of octet 16 shall indicate the message priority.*/
        proto_tree_add_item(sub_tree, hf_pfcp_mp, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_pfcp_spare_h0, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(sub_tree, hf_pfcp_spare_oct, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    offset++;

    /* Dissect the IEs in the message */
    dissect_pfcp_ies_common(tvb, pinfo, sub_tree, offset, message_type);

    return tvb_reported_length(tvb);
}

/* Enterprise IE decoding 3GPP */
static int
dissect_pfcp_3gpp_enterprise_ies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item *top_item = (proto_item *)data;
    /* We are give the complete ie, but the first 6 octets are dissected in the pfcp dissector*/
    proto_item_append_text(top_item, " Enterprise ID set to '10415' shall not be used for the vendor specific IEs.");
    proto_tree_add_expert(tree, pinfo, &ei_pfcp_enterprise_ie_3gpp, tvb, 0, -1);

    return tvb_reported_length(tvb);
}

void
proto_register_pfcp(void)
{

    static hf_register_info hf_pfcp[] = {

        { &hf_pfcp_msg_type,
        { "Message Type", "pfcp.msg_type",
        FT_UINT8, BASE_DEC | BASE_EXT_STRING, &pfcp_message_type_ext, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_msg_length,
        { "Length", "pfcp.length",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_hdr_flags,
        { "Flags", "pfcp.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_version,
        { "Version", "pfcp.version",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL }
        },
        { &hf_pfcp_mp_flag,
        { "MP", "pfcp.mp",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }
        },
        { &hf_pfcp_s_flag,
        { "S", "pfcp.s",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b2,
        { "Spare", "pfcp.spare_b2",
        FT_UINT8, BASE_DEC, NULL, 0x04,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b3,
        { "Spare", "pfcp.spare_b3",
        FT_UINT8, BASE_DEC, NULL, 0x08,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b4,
        { "Spare", "pfcp.spare_b4",
        FT_UINT8, BASE_DEC, NULL, 0x10,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b5,
        { "Spare", "pfcp.spare_b5",
        FT_UINT8, BASE_DEC, NULL, 0x20,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b6,
        { "Spare", "pfcp.spare_b6",
        FT_UINT8, BASE_DEC, NULL, 0x40,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b7,
        { "Spare", "pfcp.spare_b7",
        FT_UINT8, BASE_DEC, NULL, 0x80,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_b7_b5,
        { "Spare", "pfcp.spare_b7_b5",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_oct,
        { "Spare", "pfcp.spare_oct",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_h0,
        { "Spare", "pfcp.spare_h0",
        FT_UINT8, BASE_DEC, NULL, 0x0f,
        NULL, HFILL }
        },
        { &hf_pfcp_spare_h1,
        { "Spare", "pfcp.spare_h1",
        FT_UINT8, BASE_DEC, NULL, 0xf0,
        NULL, HFILL }
        },
        { &hf_pfcp_spare,
        { "Spare", "pfcp.spare",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_seid,
        { "SEID", "pfcp.seid",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_seqno,
        { "Sequence Number", "pfcp.seqno",
        FT_UINT24, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_mp,
        { "Message Priority", "pfcp.mp",
        FT_UINT24, BASE_DEC, NULL, 0xf0,
        NULL, HFILL }
        },
        { &hf_pfcp_enterprice_id,
        { "Enterprise ID",	"pfcp.enterprice_id",
        FT_UINT16, BASE_ENTERPRISES, STRINGS_ENTERPRISES,
        0x0, NULL, HFILL } },
        { &hf_pfcp2_ie,
        { "IE Type", "pfcp.ie_type",
        FT_UINT16, BASE_DEC | BASE_EXT_STRING, &pfcp_ie_type_ext, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp2_enterprise_ie,
        { "Enterprise specific IE Type", "pfcp.enterprise_ie",
        FT_UINT16, BASE_DEC, NULL, 0x7fff,
        NULL, HFILL }
        },
        { &hf_pfcp2_ie_len,
        { "Length", "pfcp.ie_len",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_recovery_time_stamp,
        { "Recovery Time Stamp", "pfcp.recovery_time_stamp",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }
        },
        { &hf_pfcp2_cause,
        { "Cause", "pfcp.cause",
        FT_UINT8, BASE_DEC, VALS(pfcp_cause_vals), 0x0,
        NULL, HFILL }
        },
        { &hf_pfcp_node_id_type,
        { "Node ID Type", "pfcp.node_id_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_node_id_type_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_pfcp_node_id_ipv4,
        { "Node ID IPv4", "pfcp.node_id_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_node_id_ipv6,
        { "Node ID IPv6", "pfcp.node_id_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_node_id_fqdn,
        { "Node ID FQDN", "pfcp.node_id_fqdn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_f_seid_flags,
        { "Flags", "pfcp.f_seid_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_b0_v6,
        { "V6", "pfcp.f_seid_flags.v6",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_b1_v4,
        { "V4", "pfcp.f_seid_flags.v4",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_f_seid_ipv4,
        { "IPv4 address", "pfcp.f_seid.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_f_seid_ipv6,
        { "IPv6 address", "pfcp.f_seid.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_pdr_id,
        { "Rule ID", "pfcp.pdr_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_precedence,
        { "Precedence", "pfcp.precedence",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_source_interface,
        { "Source Interface", "pfcp.source_interface",
            FT_UINT8, BASE_DEC, VALS(pfcp_source_interface_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_pfcp_f_teid_flags,
        { "Flags", "pfcp.f_teid_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_fteid_flg_spare,
        { "Spare", "pfcp.fteid_flg.spare",
            FT_UINT8, BASE_DEC, NULL, 0xf8,
            NULL, HFILL }
        },
        { &hf_pfcp_fteid_flg_b2_ch,
        { "CH (CHOOSE)", "pfcp.f_teid_flags.ch",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_fteid_flg_b1_v6,
        { "V6", "pfcp.f_teid_flags.v6",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_fteid_flg_b0_v4,
        { "V4", "pfcp.f_teid_flags.v4",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_f_teid_ipv4,
        { "IPv4 address", "pfcp.f_teid.ipv4_addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_f_teid_ipv6,
        { "IPv6 address", "pfcp.f_teid.ipv6_addr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_pdn_instance,
        { "PDN Instance", "pfcp.pdn_instance",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flags,
        { "Flags", "pfcp.ue_ip_address_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flag_b0,
        { "V6", "pfcp.ue_ip_address_flag.v6",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flag_b1,
        { "V4", "pfcp.ue_ip_address_flag.v4",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_address_flag_b2,
        { "S/D", "pfcp.ue_ip_address_flag.sd",
            FT_BOOLEAN, 8, TFS(&pfcp_ue_ip_add_sd_flag_vals), 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_addr_ipv4,
        { "IPv4 address", "pfcp.ue_ip_addr_ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ue_ip_add_ipv6,
        { "IPv6 address", "pfcp.ue_ip_addr_ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_application_id,
        { "Application Identifier", "pfcp.application_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_flags,
        { "Flags", "pfcp.sdf_filter_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_b0_fd,
        { "FD (Flow Description)", "pfcp.sdf_filter.fd",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_b1_ttc,
        { "TTC (ToS Traffic Class)", "pfcp.sdf_filter.ttc",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_b2_spi,
        { "SPI (Security Parameter Index)", "pfcp.sdf_filter.spi",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_sdf_filter_b3_fl,
        { "FL (Flow Label)", "pfcp.sdf_filter.fl",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_pfcp_flow_desc_len,
        { "Length of Flow Description", "pfcp.flow_desc_len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_fd,
        { "Flow Description field", "pfcp.fd",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_ttc,
        { "ToS Traffic Class field", "pfcp.ttc",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_spi,
        { "Security Parameter Index field", "pfcp.spi",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_fl,
        { "Flow Label field", "pfcp.fl",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_out_hdr_desc,
        { "Outer Header Removal Description", "pfcp.out_hdr_desc",
            FT_UINT8, BASE_DEC, VALS(pfcp_out_hdr_desc_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_far_id_flg,
        { "Allocation type", "pfcp.far_id_flg",
            FT_BOOLEAN, 32, TFS(&pfcp_id_predef_dynamic_tfs), 0x80000000,
            NULL, HFILL }
        },
        { &hf_pfcp_far_id,
        { "FAR ID", "pfcp.far_id",
            FT_UINT32, BASE_DEC, NULL, 0x7fffffff,
            NULL, HFILL }
        },
        { &hf_pfcp_urr_id_flg,
        { "Allocation type", "pfcp.urr_id_flg",
            FT_BOOLEAN, 32, TFS(&pfcp_id_predef_dynamic_tfs), 0x80000000,
            NULL, HFILL }
        },
        { &hf_pfcp_urr_id,
        { "URR ID", "pfcp.urr_id",
            FT_UINT32, BASE_DEC, NULL, 0x7fffffff,
            NULL, HFILL }
        },
        { &hf_pfcp_qer_id_flg,
        { "Allocation type", "pfcp.qer_id_flg",
            FT_BOOLEAN, 32, TFS(&pfcp_id_predef_dynamic_tfs), 0x80000000,
            NULL, HFILL }
        },
        { &hf_pfcp_qer_id,
        { "QER ID", "pfcp.qer_id",
            FT_UINT32, BASE_DEC, NULL, 0x7fffffff,
            NULL, HFILL }
        },
        { &hf_pfcp_predef_rules_name,
        { "Predefined Rules Name", "pfcp.predef_rules_name",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_flags,
        { "Flags", "pfcp.apply_action_flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_b0_drop,
        { "DROP (Drop)", "pfcp.apply_action.drop",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_b1_forw,
        { "FORW (Forward)", "pfcp.apply_action.forw",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_b2_buff,
        { "BUFF (Buffer)", "pfcp.apply_action.buff",
            FT_BOOLEAN, 8, NULL, 0x03,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_b3_nocp,
        { "NOCP (Notify the CP function)", "pfcp.apply_action.nocp",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_pfcp_apply_action_b4_dupl,
        { "DUPL (Duplicate)", "pfcp.apply_action.dupl",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }
        },
        { &hf_pfcp_bar_id,
        { "BAR ID", "pfcp.bar_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_id_type,
        { "FQ-CSID Node-ID Type", "pfcp.fq_csid_node_id_type",
            FT_UINT8, BASE_DEC, VALS(pfcp_fq_csid_node_id_type_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_pfcp_num_csid,
        { "Number of CSID", "pfcp.num_csid",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_id_ipv4,
        { "Node-Address", "pfcp.q_csid_node_id.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_id_ipv6,
        { "Node-Address", "pfcp.q_csid_node_id.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_id_mcc_mnc,
        { "Node-Address MCC MNC", "pfcp.q_csid_node_id.mcc_mnc",
            FT_UINT32, BASE_DEC, NULL, 0xfffff000,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid_node_id_int,
        { "Node-Address Number", "pfcp.q_csid_node_id.int",
            FT_UINT32, BASE_DEC, NULL, 0x00000fff,
            NULL, HFILL }
        },
        { &hf_pfcp_fq_csid,
        { "PDN Connection Set Identifier (CSID)", "pfcp.csid",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_measurement_period,
        { "Measurement Period", "pfcp.measurement_period",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_duration_measurement,
        { "Duration", "pfcp.duration_measurement",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pfcp_time_of_first_packet,
        { "Time of First Packet", "pfcp.time_of_first_packet",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_pfcp_time_of_last_packet,
        { "Time of Last Packet", "pfcp.time_of_last_packet",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_ELEMS_PFCP    9
    gint *ett[NUM_INDIVIDUAL_ELEMS_PFCP +
        (NUM_PFCP_IES - 1)];

    ett[0] = &ett_pfcp;
    ett[1] = &ett_pfcp_flags;
    ett[2] = &ett_pfcp_ie;
    ett[3] = &ett_pfcp_grouped_ie;
    ett[4] = &ett_pfcp_f_seid_flags;
    ett[5] = &ett_f_teid_flags;
    ett[6] = &ett_pfcp_ue_ip_address_flags;
    ett[7] = &ett_pfcp_sdf_filter_flags;
    ett[8] = &ett_pfcp_apply_action_flags;

    static ei_register_info ei[] = {
        { &ei_pfcp_ie_reserved,{ "pfcp.ie_id_reserved", PI_PROTOCOL, PI_ERROR, "Reserved IE value used", EXPFILL } },
        { &ei_pfcp_ie_data_not_decoded,{ "pfcp.ie_data_not_decoded", PI_UNDECODED, PI_NOTE, "IE data not decoded by WS yet", EXPFILL } },
        { &ei_pfcp_ie_not_decoded_null,{ "pfcp.ie_not_decoded_null", PI_UNDECODED, PI_NOTE, "IE not decoded yet(WS:no decoding function(NULL))", EXPFILL } },
        { &ei_pfcp_ie_not_decoded_to_large,{ "pfcp.ie_not_decoded", PI_UNDECODED, PI_NOTE, "IE not decoded yet(WS:IE id to large)", EXPFILL } },
        { &ei_pfcp_enterprise_ie_3gpp,{ "pfcp.ie_enterprise_3gpp", PI_PROTOCOL, PI_ERROR, "IE not decoded yet(WS:No vendor dissector)", EXPFILL } },
        { &ei_pfcp_ie_encoding_error,{ "pfcp.ie_encoding_error", PI_PROTOCOL, PI_ERROR, "IE wrongly encoded)", EXPFILL } },
    };

    expert_module_t* expert_pfcp;

    guint last_index = NUM_INDIVIDUAL_ELEMS_PFCP, i;

    for (i = 0; i < (NUM_PFCP_IES-1); i++, last_index++)
    {
        ett_pfcp_elem[i] = -1;
        ett[last_index] = &ett_pfcp_elem[i];
    }
    proto_pfcp = proto_register_protocol("Packet Forwarding Control Protocol", "PFCP", "pfcp");
    pfcp_handle = register_dissector("pfcp", dissect_pfcp, proto_pfcp);

    proto_register_field_array(proto_pfcp, hf_pfcp, array_length(hf_pfcp));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pfcp = expert_register_protocol(proto_pfcp);
    expert_register_field_array(expert_pfcp, ei, array_length(ei));

    /* Register dissector table for enterprise IE dissectors */
    pfcp_enterprise_ies_dissector_table = register_dissector_table("pfcp.enterprise_ies", "PFCP Enterprice IEs",
        proto_pfcp, FT_UINT32, BASE_DEC);

    pfcp_3gpp_ies_handle = register_dissector("pfcp_3gpp_ies", dissect_pfcp_3gpp_enterprise_ies, proto_pfcp);


}

void
proto_reg_handoff_pfcp(void)
{

    dissector_add_for_decode_as_with_preference("udp.port", pfcp_handle);
    /* Register 3GPP in the table to give expert info and serve as an example how to add decoding of enterprise IEs*/
    dissector_add_uint("pfcp.enterprise_ies", VENDOR_THE3GPP, pfcp_3gpp_ies_handle);


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
