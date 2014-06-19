/* packet-pcep.c
 * Routines for PCEP packet disassembly
 * draft-ietf-pce-pcep-09
 * draft-ietf-pce-pcep-xro-02
 * See also RFC 4655, RFC 4657, RFC 5520, RFC 5521, RFC 5440 and RFC 5541
 *
 * (c) Copyright 2007 Silvia Cristina Tejedor <silviacristina.tejedor@gmail.com>
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
 * Added support of "A Set of Monitoring Tools for Path Computation Element
 * (PCE)-Based Architecture" (RFC 5886)
 * (c) Copyright 2012 Svetoslav Duhovnikov <duhovnikov[AT]gmail.com>
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/expert.h>
#include "packet-tcp.h"

void proto_register_pcep(void);
void proto_reg_handoff_pcep(void);

/*differents types of objects*/
#define PCEP_OPEN_OBJ                    1
#define PCEP_RP_OBJ                      2
#define PCEP_NO_PATH_OBJ                 3
#define PCEP_END_POINT_OBJ               4
#define PCEP_BANDWIDTH_OBJ               5
#define PCEP_METRIC_OBJ                  6
#define PCEP_EXPLICIT_ROUTE_OBJ          7
#define PCEP_RECORD_ROUTE_OBJ            8
#define PCEP_LSPA_OBJ                    9
#define PCEP_IRO_OBJ                    10
#define PCEP_SVEC_OBJ                   11
#define PCEP_NOTIFICATION_OBJ           12
#define PCEP_PCEP_ERROR_OBJ             13
#define PCEP_LOAD_BALANCING_OBJ         14
#define PCEP_CLOSE_OBJ                  15
#define PCEP_PATH_KEY_OBJ               16
#define PCEP_XRO_OBJ                    17
#define PCEP_OBJ_MONITORING             19
#define PCEP_OBJ_PCC_ID_REQ             20
#define PCEP_OF_OBJ                     21
#define PCEP_OBJ_PCE_ID                 25
#define PCEP_OBJ_PROC_TIME              26
#define PCEP_OBJ_OVERLOAD               27

/*Subobjects of EXPLICIT ROUTE Object*/
#define PCEP_SUB_IPv4                    1
#define PCEP_SUB_IPv6                    2
#define PCEP_SUB_LABEL_CONTROL           3
#define PCEP_SUB_UNNUMB_INTERFACE_ID     4
#define PCEP_SUB_AUTONOMOUS_SYS_NUM     32
#define PCEP_SUB_EXRS                   33
#define PCEP_SUB_SRLG                   34
#define PCEP_SUB_PKSv4                  64
#define PCEP_SUB_PKSv6                  65

/*Possible values of the NI in the NO-PATH object*/
#define NO_SATISFYING                    0
#define CHAIN_BROKEN                     1

/*Possible values of L in the ERO and IRO objects */
#define STRICT_HOP                       0
#define LOOSE_HOP                        1

/*Possible values of U in the ERO and RRO objects */
#define DOWNSTREAM_LABEL                 0
#define UPSTREAM_LABEL                   1

/*Possible values of Notification Type */
#define NOT_REQ_CANCEL                   1
#define PCEP_CONGESTION                  2

/*Possible values of Notification Value for NT=1*/
#define NOTI_PCC_CANCEL_REQ              1
#define NOTI_PCE_CANCEL_REQ              2

/*Possible values of Notification Value for NT=2*/
#define NOTI_PCE_CONGEST                 1
#define NOTI_PCE_NO_CONGEST              2

/*Possible types of errors */
#define ESTABLISH_FAILURE                1
#define CAP_NOT_SUPPORTED                2
#define UNKNOWN_OBJ                      3
#define NOT_SUPP_OBJ                     4
#define POLICY_VIOLATION                 5
#define MANDATORY_OBJ_MIS                6
#define SYNCH_PCREQ_MIS                  7
#define UNKNOWN_REQ_REF                  8
#define ATTEMPT_2_SESSION                9
#define INVALID_OBJ                     10
#define UNRECO_EXRS_SUBOBJ              11
#define DIFFSERV_TE_ERROR               12
#define BRPC_FAILURE                    13
#define GCO_ERROR                       15
#define P2MP_CAPABILITY_ERROR           16
#define P2MP_END_POINTS_ERROR           17
#define P2MP_FRAGMENT_ERROR             18

/*Different values of Reason in the CLOSE object */
#define NO_EXP_PROV                      1
#define DEADTIME_PROV                    2
#define RECEP_MALFORM_MSG                3

/*Different values of Attribute in the XRO object */
#define ATTR_INTERFACE                   0
#define ATTR_NODE                        1
#define ATTR_SRLG                        2

/*Mask for the flags of HEADER of Messages*/
#define  PCEP_HDR_MSG_RESERVED          0x1f

/*Mask for the type of HEADER of Objects*/
#define  MASK_OBJ_TYPE                  0xF0

/*Mask for the flags of HEADER of Objects*/
#define  PCEP_HDR_OBJ_RESERVED          0x0C
#define  PCEP_HDR_OBJ_P                 0x02
#define  PCEP_HDR_OBJ_I                 0x01

/*Mask for the flags of OPEN Object*/
#define  PCEP_OPEN_RES                  0x1F

/*Mask for the flags of RP Object*/
#define  PCEP_RP_PRI                    0x000007
#define  PCEP_RP_R                      0x000008
#define  PCEP_RP_B                      0x000010
#define  PCEP_RP_O                      0x000020
#define  PCEP_RP_V                      0x000040
#define  PCEP_RP_S                      0x000080
#define  PCEP_RP_P                      0x000100
#define  PCEP_RP_D                      0x000200
#define  PCEP_RP_M                      0x000400
#define  PCEP_RP_E                      0x000800
#define  PCEP_RP_N                      0x001000
#define  PCEP_RP_F                      0x002000
#define  PCEP_RP_RESERVED               0xFFC000

/*Mask for the flags of NO PATH Object*/
#define  PCEP_NO_PATH_C                 0x8000

/*Mask for the flags of METRIC Object*/
#define  PCEP_METRIC_B                  0x01
#define  PCEP_METRIC_C                  0x02

/*Mask for the flags of LSPA Object*/
#define  PCEP_LSPA_L                    0x01

/* Mask to differentiate the value of L and Type (Explicit Object)*/
#define Mask_L                          0x80
#define Mask_Type                       0x7f

/* RFC 5440 */
#define TCP_PORT_PCEP                   4189

#define IPv4                            1
#define IPv6                            2

/*Mask for the flags os SVEC Object*/
#define  PCEP_SVEC_L                    0x000001
#define  PCEP_SVEC_N                    0x000002
#define  PCEP_SVEC_S                    0x000004

/*Mask for the flags of XRO Object*/
#define  PCEP_XRO_F                     0x0001

/*Mask for the flags of MONITORING Object*/
#define  PCEP_OBJ_MONITORING_FLAGS_L            0x000001
#define  PCEP_OBJ_MONITORING_FLAGS_G            0x000002
#define  PCEP_OBJ_MONITORING_FLAGS_P            0x000004
#define  PCEP_OBJ_MONITORING_FLAGS_C            0x000008
#define  PCEP_OBJ_MONITORING_FLAGS_I            0x000010
#define  PCEP_OBJ_MONITORING_FLAGS_RESERVED     0xFFFFE0

/*Define types for PCC-ID-REQ Object*/
#define  PCEP_OBJ_PCC_ID_REQ_IPv4               1
#define  PCEP_OBJ_PCC_ID_REQ_IPv6               2

/*Define types for PCE-ID Object*/
#define  PCEP_OBJ_PCE_ID_IPv4                   1
#define  PCEP_OBJ_PCE_ID_IPv6                   2

/*Mask for the flags of PROC-TIME Object*/
#define  PCEP_OBJ_PROC_TIME_FLAGS_E             0x0001
#define  PCEP_OBJ_PROC_TIME_FLAGS_RESERVED      0xFFFE

/*Mask for the flags of IPv4, IPv6 and UNnumbered InterfaceID Subobjects of RRO Object*/
#define PCEP_SUB_LPA                    0x01
#define PCEP_SUB_LPU                    0x02

/*Mask for the flags of Label SubObject*/
#define PCEP_SUB_LABEL_GL               0x01


static int proto_pcep = -1;

static gint hf_pcep_hdr_msg_flags_reserved= -1;
static gint hf_pcep_hdr_obj_flags_reserved= -1;
static gint hf_pcep_hdr_obj_flags_p= -1;
static gint hf_pcep_hdr_obj_flags_i= -1;
static gint hf_pcep_open_flags_res = -1;
static gint hf_pcep_rp_flags_pri = -1;
static gint hf_pcep_rp_flags_r = -1;
static gint hf_pcep_rp_flags_b = -1;
static gint hf_pcep_rp_flags_o = -1;
static gint hf_pcep_rp_flags_v = -1;
static gint hf_pcep_rp_flags_s = -1;
static gint hf_pcep_rp_flags_p = -1;
static gint hf_pcep_rp_flags_d = -1;
static gint hf_pcep_rp_flags_m = -1;
static gint hf_pcep_rp_flags_e = -1;
static gint hf_pcep_rp_flags_n = -1;
static gint hf_pcep_rp_flags_f = -1;
static gint hf_pcep_rp_flags_reserved = -1;
static gint hf_pcep_no_path_flags_c = -1;
static gint hf_pcep_metric_flags_c = -1;
static gint hf_pcep_metric_flags_b = -1;
static gint hf_pcep_lspa_flags_l = -1;
static gint hf_pcep_svec_flags_l = -1;
static gint hf_pcep_svec_flags_n = -1;
static gint hf_pcep_svec_flags_s = -1;
static gint hf_pcep_xro_flags_f = -1;
static gint hf_pcep_obj_monitoring_flags_reserved = -1;
static gint hf_pcep_obj_monitoring_flags_l= -1;
static gint hf_pcep_obj_monitoring_flags_g= -1;
static gint hf_pcep_obj_monitoring_flags_p= -1;
static gint hf_pcep_obj_monitoring_flags_c= -1;
static gint hf_pcep_obj_monitoring_flags_i= -1;
static gint hf_pcep_obj_monitoring_monitoring_id_number = -1;
static gint hf_pcep_obj_pcc_id_req_ipv4 = -1;
static gint hf_pcep_obj_pcc_id_req_ipv6 = -1;
static gint hf_pcep_obj_pce_id_ipv4 = -1;
static gint hf_pcep_obj_pce_id_ipv6 = -1;
static gint hf_pcep_obj_proc_time_flags_reserved = -1;
static gint hf_pcep_obj_proc_time_flags_e = -1;
static gint hf_pcep_obj_proc_time_cur_proc_time = -1;
static gint hf_pcep_obj_proc_time_min_proc_time = -1;
static gint hf_pcep_obj_proc_time_max_proc_time = -1;
static gint hf_pcep_obj_proc_time_ave_proc_time = -1;
static gint hf_pcep_obj_proc_time_var_proc_time = -1;
static gint hf_pcep_obj_overload_duration = -1;
static gint pcep_subobj_flags_lpa= -1;
static gint pcep_subobj_flags_lpu= -1;
static gint pcep_subobj_label_flags_gl= -1;
static gint hf_pcep_no_path_tlvs_pce = -1;
static gint hf_pcep_no_path_tlvs_unk_dest = -1;
static gint hf_pcep_no_path_tlvs_unk_src = -1;
static gint hf_PCEPF_MSG = -1;
static gint hf_PCEPF_OBJECT_CLASS = -1;
static gint hf_PCEPF_OBJ_OPEN = -1;
static gint hf_PCEPF_OBJ_RP = -1;
static gint hf_PCEPF_OBJ_NO_PATH = -1;
static gint hf_PCEPF_OBJ_END_POINT = -1;
static gint hf_PCEPF_OBJ_BANDWIDTH = -1;
static gint hf_PCEPF_OBJ_METRIC = -1;
static gint hf_PCEPF_OBJ_EXPLICIT_ROUTE = -1;
static gint hf_PCEPF_OBJ_RECORD_ROUTE = -1;
static gint hf_PCEPF_OBJ_LSPA = -1;
static gint hf_PCEPF_OBJ_IRO = -1;
static gint hf_PCEPF_OBJ_SVEC = -1;
static gint hf_PCEPF_OBJ_NOTIFICATION = -1;
static gint hf_PCEPF_OBJ_UNKNOWN_TYPE = -1;
static gint hf_PCEPF_NOTI_TYPE = -1;
static gint hf_PCEPF_NOTI_VAL1 = -1;
static gint hf_PCEPF_NOTI_VAL2 = -1;
static gint hf_PCEPF_OBJ_PCEP_ERROR = -1;
static gint hf_PCEPF_ERROR_TYPE = -1;
static gint hf_PCEPF_OBJ_LOAD_BALANCING = -1;
static gint hf_PCEPF_OBJ_CLOSE = -1;
static gint hf_PCEPF_OBJ_PATH_KEY = -1;
static gint hf_PCEPF_OBJ_XRO = -1;
static gint hf_PCEPF_OBJ_MONITORING = -1;
static gint hf_PCEPF_OBJ_PCC_ID_REQ = -1;
static gint hf_PCEPF_OBJ_OF = -1;
static gint hf_PCEPF_OBJ_PCE_ID = -1;
static gint hf_PCEPF_OBJ_PROC_TIME = -1;
static gint hf_PCEPF_OBJ_OVERLOAD = -1;
static gint hf_PCEPF_SUBOBJ = -1;
static gint hf_PCEPF_SUBOBJ_7F = -1;
static gint hf_PCEPF_SUBOBJ_IPv4 = -1;
static gint hf_PCEPF_SUBOBJ_IPv6 = -1;
static gint hf_PCEPF_SUBOBJ_LABEL_CONTROL = -1;
static gint hf_PCEPF_SUBOBJ_UNNUM_INTERFACEID = -1;
static gint hf_PCEPF_SUBOBJ_AUTONOMOUS_SYS_NUM = -1;
static gint hf_PCEPF_SUBOBJ_SRLG = -1;
static gint hf_PCEPF_SUBOBJ_EXRS = -1;
static gint hf_PCEPF_SUBOBJ_PKSv4 = -1;
static gint hf_PCEPF_SUBOBJ_PKSv6 = -1;
static gint hf_PCEPF_SUBOBJ_XRO = -1;
#if 0
static gint hf_PCEPF_SUB_XRO_ATTRIB = -1;
#endif

/* Generated from convert_proto_tree_add_text.pl */
static int hf_pcep_xro_obj_flags = -1;
static int hf_pcep_open_obj_keepalive = -1;
static int hf_pcep_request_id = -1;
static int hf_pcep_lspa_obj_reserved = -1;
static int hf_pcep_rp_obj_reserved = -1;
static int hf_pcep_svec_obj_reserved = -1;
static int hf_pcep_rp_obj_flags = -1;
static int hf_pcep_lspa_obj_exclude_any = -1;
static int hf_pcep_subobj_srlg_attribute = -1;
static int hf_pcep_end_point_obj_destination_ipv4_address = -1;
static int hf_pcep_subobj_unnumb_interfaceID_reserved_xroobj = -1;
static int hf_pcep_balancing_obj_flags = -1;
static int hf_pcep_subobj_unnumb_interfaceID_reserved = -1;
static int hf_pcep_lspa_obj_setup_priority = -1;
static int hf_pcep_svec_obj_request_id_number = -1;
static int hf_pcep_end_point_obj_source_ipv4_address = -1;
static int hf_pcep_open_obj_sid = -1;
static int hf_pcep_subobj_ipv6_padding = -1;
static int hf_pcep_notification_obj_reserved = -1;
static int hf_pcep_close_obj_reason = -1;
static int hf_pcep_subobj_ipv4_attribute = -1;
static int hf_pcep_obj_overload_flags = -1;
static int hf_pcep_balancing_obj_maximum_number_of_te_lsps = -1;
static int hf_pcep_subobj_exrs_reserved = -1;
static int hf_pcep_subobj_label_control_length = -1;
static int hf_pcep_subobj_ipv4_length = -1;
static int hf_pcep_subobj_ipv6_ipv6 = -1;
static int hf_pcep_lspa_obj_holding_priority = -1;
static int hf_pcep_rp_obj_requested_id_number = -1;
static int hf_pcep_subobj_pksv6_path_key = -1;
static int hf_pcep_subobj_unnumb_interfaceID_router_id = -1;
static int hf_pcep_subobj_pksv6_pce_id = -1;
static int hf_pcep_tlv_padding = -1;
static int hf_pcep_subobj_unnumb_interfaceID_flags = -1;
static int hf_pcep_subobj_unnumb_interfaceID_length = -1;
static int hf_pcep_obj_proc_time_reserved = -1;
static int hf_pcep_object_type = -1;
static int hf_pcep_subobj_pksv4_length = -1;
static int hf_pcep_subobj_ipv6_prefix_length = -1;
static int hf_pcep_subobj_ipv6_length = -1;
static int hf_pcep_flags = -1;
static int hf_pcep_no_path_obj_reserved = -1;
static int hf_pcep_subobj_unnumb_interfaceID_interface_id = -1;
static int hf_pcep_close_obj_flags = -1;
static int hf_pcep_error_obj_flags = -1;
static int hf_pcep_metric_obj_flags = -1;
static int hf_pcep_subobj_autonomous_sys_num_reserved = -1;
static int hf_pcep_subobj_pksv4_path_key = -1;
static int hf_pcep_subobj_label_control_flags = -1;
static int hf_pcep_notification_obj_value = -1;
static int hf_pcep_subobj_label_control_label = -1;
static int hf_pcep_metric_obj_metric_value = -1;
static int hf_pcep_no_path_obj_flags = -1;
static int hf_pcep_obj_monitoring_reserved = -1;
static int hf_pcep_obj_of_code = -1;
static int hf_pcep_subobj_label_control_u = -1;
static int hf_pcep_subobj_autonomous_sys_num_length = -1;
static int hf_pcep_message_length = -1;
static int hf_pcep_subobj_ipv4_prefix_length = -1;
static int hf_pcep_xro_obj_reserved = -1;
static int hf_pcep_subobj_pksv4_pce_id = -1;
static int hf_pcep_subobj_pksv6_length = -1;
static int hf_pcep_end_point_obj_destination_ipv6_address = -1;
static int hf_pcep_subobj_autonomous_sys_num_as_number = -1;
static int hf_pcep_notification_obj_flags = -1;
static int hf_pcep_subobj_unnumb_interfaceID_attribute = -1;
static int hf_pcep_object_length = -1;
static int hf_pcep_tlv_data = -1;
static int hf_pcep_balancing_obj_reserved = -1;
static int hf_pcep_subobj_ipv4_flags = -1;
static int hf_pcep_subobj_ipv6_attribute = -1;
static int hf_pcep_subobj_srlg_id = -1;
static int hf_pcep_balancing_obj_minimum_bandwidth = -1;
static int hf_pcep_subobj_unnumb_interfaceID_reserved_rrobj = -1;
static int hf_pcep_error_obj_reserved = -1;
static int hf_pcep_obj_overload_reserved = -1;
static int hf_pcep_notification_obj_type = -1;
static int hf_pcep_subobj_ipv6_flags = -1;
static int hf_pcep_obj_monitoring_flags = -1;
static int hf_pcep_subobj_exrs_length = -1;
static int hf_pcep_obj_proc_time_flags = -1;
static int hf_pcep_subobj_label_control_reserved = -1;
static int hf_pcep_version = -1;
static int hf_pcep_lspa_obj_flags = -1;
static int hf_pcep_subobj_ipv4_ipv4 = -1;
static int hf_pcep_tlv_type = -1;
static int hf_pcep_subobj_autonomous_sys_num_optional_as_number_high_octets = -1;
static int hf_pcep_open_obj_deadtime = -1;
static int hf_pcep_bandwidth = -1;
static int hf_pcep_tlv_length = -1;
static int hf_pcep_subobj_srlg_reserved = -1;
static int hf_pcep_metric_obj_type = -1;
static int hf_pcep_metric_obj_reserved = -1;
static int hf_pcep_svec_obj_flags = -1;
static int hf_pcep_open_obj_pcep_version = -1;
static int hf_pcep_open_obj_flags = -1;
static int hf_pcep_end_point_obj_source_ipv6_address = -1;
static int hf_pcep_lspa_obj_include_any = -1;
static int hf_pcep_lspa_obj_include_all = -1;
static int hf_pcep_subobj_ipv4_padding = -1;
static int hf_pcep_subobj_srlg_length = -1;
static int hf_pcep_subobj_autonomous_sys_num_attribute = -1;
static int hf_pcep_close_obj_reserved = -1;
static int hf_pcep_subobj_label_control_c_type = -1;
static int hf_pcep_subobj_iro_autonomous_sys_num_l = -1;
static int hf_pcep_subobj_autonomous_sys_num_x = -1;
static int hf_pcep_subobj_label_control_l = -1;
static int hf_pcep_subobj_exrs_l = -1;
static int hf_pcep_subobj_unnumb_interfaceID_x = -1;
static int hf_pcep_subobj_autonomous_sys_num_l = -1;
static int hf_pcep_subobj_pksv6_l = -1;
static int hf_pcep_subobj_srlg_x = -1;
static int hf_pcep_subobj_ipv4_x = -1;
static int hf_pcep_subobj_iro_unnumb_interfaceID_l = -1;
static int hf_pcep_subobj_exrs_type = -1;
static int hf_pcep_subobj_ipv4_l = -1;
static int hf_pcep_of_code = -1;
static int hf_pcep_subobj_ipv6_x = -1;
static int hf_pcep_no_path_obj_nature_of_issue = -1;
static int hf_pcep_subobj_ipv6_l = -1;
static int hf_pcep_subobj_pksv4_l = -1;
static int hf_pcep_subobj_iro_ipv6_l = -1;
static int hf_pcep_subobj_unnumb_interfaceID_l = -1;
static int hf_pcep_subobj_iro_ipv4_l = -1;

static gint ett_pcep = -1;
static gint ett_pcep_hdr = -1;
static gint ett_pcep_obj_open = -1;
static gint ett_pcep_obj_request_parameters = -1;
static gint ett_pcep_obj_no_path = -1;
static gint ett_pcep_obj_end_point = -1;
static gint ett_pcep_obj_bandwidth = -1;
static gint ett_pcep_obj_metric = -1;
static gint ett_pcep_obj_explicit_route = -1;
static gint ett_pcep_obj_record_route = -1;
static gint ett_pcep_obj_lspa = -1;
static gint ett_pcep_obj_iro = -1;
static gint ett_pcep_obj_svec = -1;
static gint ett_pcep_obj_notification = -1;
static gint ett_pcep_obj_error = -1;
static gint ett_pcep_obj_load_balancing = -1;
static gint ett_pcep_obj_close = -1;
static gint ett_pcep_obj_path_key = -1;
static gint ett_pcep_obj_xro = -1;
static gint ett_pcep_obj_monitoring = -1;
static gint ett_pcep_obj_pcc_id_req = -1;
static gint ett_pcep_obj_of = -1;
static gint ett_pcep_obj_pce_id = -1;
static gint ett_pcep_obj_proc_time = -1;
static gint ett_pcep_obj_overload = -1;
static gint ett_pcep_obj_unknown = -1;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_pcep_pcep_object_body_non_defined = EI_INIT;
static expert_field ei_pcep_non_defined_object = EI_INIT;
static expert_field ei_pcep_object_length = EI_INIT;
static expert_field ei_pcep_subobject_bad_length = EI_INIT;
static expert_field ei_pcep_non_defined_subobject = EI_INIT;
static expert_field ei_pcep_unknown_type_object = EI_INIT;

/* PCEP message types.*/
typedef enum {
    PCEP_MSG_NO_VALID,
    PCEP_MSG_OPEN,
    PCEP_MSG_KEEPALIVE,
    PCEP_MSG_PATH_COMPUTATION_REQUEST,
    PCEP_MSG_PATH_COMPUTATION_REPLY,
    PCEP_MSG_NOTIFICATION,
    PCEP_MSG_ERROR,
    PCEP_MSG_CLOSE,
    PCEP_MSG_PATH_COMPUTATION_MONITORING_REQUEST,
    PCEP_MSG_PATH_COMPUTATION_MONITORING_REPLY
} pcep_message_types;

static const value_string message_type_vals[] = {
    {PCEP_MSG_OPEN,                                "OPEN MESSAGE"                                },
    {PCEP_MSG_KEEPALIVE,                           "KEEPALIVE MESSAGE"                           },
    {PCEP_MSG_PATH_COMPUTATION_REQUEST,            "PATH COMPUTATION REQUEST MESSAGE"            },
    {PCEP_MSG_PATH_COMPUTATION_REPLY,              "PATH COMPUTATION REPLY MESSAGE"              },
    {PCEP_MSG_NOTIFICATION,                        "NOTIFICATION MESSAGE"                        },
    {PCEP_MSG_ERROR,                               "ERROR MESSAGE"                               },
    {PCEP_MSG_CLOSE,                               "CLOSE MESSAGE"                               },
    {PCEP_MSG_PATH_COMPUTATION_MONITORING_REQUEST, "PATH COMPUTATION MONITORING REQUEST MESSAGE" },
    {PCEP_MSG_PATH_COMPUTATION_MONITORING_REPLY,   "PATH COMPUTATION MONITORING REPLY MESSAGE"   },
    {0, NULL }
};

static const value_string pcep_class_vals[] = {
    {PCEP_OPEN_OBJ,                "OPEN OBJECT"                        },
    {PCEP_RP_OBJ,                  "RP OBJECT"                          },
    {PCEP_NO_PATH_OBJ,             "NO-PATH OBJECT"                     },
    {PCEP_END_POINT_OBJ,           "END-POINT OBJECT"                   },
    {PCEP_BANDWIDTH_OBJ,           "BANDWIDTH OBJECT"                   },
    {PCEP_METRIC_OBJ,              "METRIC OBJECT"                      },
    {PCEP_EXPLICIT_ROUTE_OBJ,      "EXPLICIT ROUTE OBJECT (ERO)"        },
    {PCEP_RECORD_ROUTE_OBJ,        "RECORD ROUTE OBJECT (RRO)"          },
    {PCEP_LSPA_OBJ,                "LSPA OBJECT"                        },
    {PCEP_IRO_OBJ,                 "IRO OBJECT"                         },
    {PCEP_SVEC_OBJ,                "SVEC OBJECT"                        },
    {PCEP_NOTIFICATION_OBJ,        "NOTIFICATION OBJECT"                },
    {PCEP_PCEP_ERROR_OBJ,          "PCEP ERROR OBJECT"                  },
    {PCEP_LOAD_BALANCING_OBJ,      "LOAD BALANCING OBJECT"              },
    {PCEP_CLOSE_OBJ,               "CLOSE OBJECT"                       },
    {PCEP_PATH_KEY_OBJ,            "PATH-KEY OBJECT"                    },
    {PCEP_XRO_OBJ,                 "EXCLUDE ROUTE OBJECT (XRO)"         },
    {PCEP_OBJ_MONITORING,          "MONITORING OBJECT"                  },
    {PCEP_OBJ_PCC_ID_REQ,          "PCC-ID-REQ OBJECT"                  },
    {PCEP_OF_OBJ,                  "OBJECTIVE FUNCTION OBJECT (OF)"     },
    {PCEP_OBJ_PCE_ID,              "PCE-ID OBJECT"                      },
    {PCEP_OBJ_PROC_TIME,           "PROC-TIME OBJECT"                   },
    {PCEP_OBJ_OVERLOAD,            "OVERLOAD OBJECT"                    },
    {0, NULL }
};
static value_string_ext pcep_class_vals_ext = VALUE_STRING_EXT_INIT(pcep_class_vals);

static const value_string pcep_subobj_vals[] = {
    {PCEP_SUB_IPv4,                "SUBOBJECT IPv4"                     },
    {PCEP_SUB_IPv6,                "SUBOBJECT IPv6"                     },
    {PCEP_SUB_LABEL_CONTROL,       "SUBOBJECT LABEL"                    },
    {PCEP_SUB_UNNUMB_INTERFACE_ID, "SUBOBJECT UNNUMBERED INTERFACE-ID"  },
    {PCEP_SUB_AUTONOMOUS_SYS_NUM,  "SUBOBJECT AUTONOMOUS SYSTEM NUMBER" },
    {PCEP_SUB_SRLG,                "SUBOBJECT SRLG"                     },
    {PCEP_SUB_PKSv4,               "SUBOBJECT PATH KEY (IPv4)"          },
    {PCEP_SUB_PKSv6,               "SUBOBJECT PATH KEY (IPv6)"          },
    {0, NULL }
};


static const value_string pcep_subobj_xro_vals[] = {
    {PCEP_SUB_IPv4,                "SUBOBJECT IPv4"                     },
    {PCEP_SUB_IPv6,                "SUBOBJECT IPv6"                     },
    {PCEP_SUB_UNNUMB_INTERFACE_ID, "SUBOBJECT UNNUMBERED INTERFACE-ID"  },
    {PCEP_SUB_AUTONOMOUS_SYS_NUM,  "SUBOBJECT AUTONOMOUS SYSTEM NUMBER" },
    {PCEP_SUB_SRLG,                "SUBOBJECT SRLG"                     },
    {0, NULL }
};

/*In the NO-PATH Object the two different possibilities that NI can have*/
static const value_string pcep_no_path_obj_vals[] = {
    {NO_SATISFYING,                "No path satisfying the set of constraints could be found" },
    {CHAIN_BROKEN,                 "PCEP Chain Broken"                                        },
    {0, NULL }
};

/*Different values of "Type (T)" in the METRIC Obj */
static const value_string pcep_metric_obj_vals[] = {
    { 0, "not defined"                     },
    { 1, "IGP Metric"                      },
    { 2, "TE Metric"                       },
    { 3, "Hop Counts"                      },
    { 4, "Aggregate bandwidth consumption" },
    { 5, "Load of the most loaded link"    },
    { 6, "Cumulative IGP cost"             },
    { 7, "Cumulative TE cost"              },
    { 8, "P2MP IGM metric"                 },
    { 9, "P2MP TE metric"                  },
    {10, "P2MP hop count metric"           },
    {0, NULL }
};

/*Different values for (L) in the ERO and IRO Objs */
static const value_string pcep_route_l_obj_vals[] = {
    {STRICT_HOP,          "Strict Hop"  },
    {LOOSE_HOP,           "Loose Hop"   },
    {0, NULL }
};

/*Different values of the direction of the label (U) in the ERO and RRO Objs */
static const value_string pcep_route_u_obj_vals[] = {
    {DOWNSTREAM_LABEL,    "Downstream Label" },
    {UPSTREAM_LABEL,      "Upstream Label"   },
    {0, NULL }
};

/*Values of Notification type*/
static const value_string pcep_notification_types_vals[] = {
    {NOT_REQ_CANCEL,      "Pending Request Cancelled" },
    {PCEP_CONGESTION,     "PCE Congestion"            },
    {0, NULL }
};

/*Values of Notification value for Notification Type=1*/
static const value_string pcep_notification_values1_vals[] = {
    {NOTI_PCC_CANCEL_REQ, "PCC Cancels a set of Pending Request (s)" },
    {NOTI_PCE_CANCEL_REQ, "PCE Cancels a set of Pending Request (s)" },
    {0, NULL }
};

/*Values of Notification value for Notification Type=2*/
static const value_string pcep_notification_values2_vals[] = {
    {NOTI_PCE_CONGEST,    "PCE in Congested State"           },
    {NOTI_PCE_NO_CONGEST, "PCE no Longer in Congested state" },
    {0, NULL }
};


/* PCEP TLVs */
static const value_string pcep_tlvs_vals[] = {
    {1,         "NO-PATH-VECTOR TLV"    },
    {2,         "OVERLOAD-DURATION TLV" },
    {3,         "REQ-MISSING TLV"       },
    {4,         "OF-list TLV"           },
    {5,         "Order TLV"             },
    {6,         "P2MP Capable"          },
    {0, NULL }
};


/*Values of Objective Functions*/
static const value_string pcep_of_vals[] = {
    {1,         "Minimum Cost Path"                             },
    {2,         "Minimum Load Path"                             },
    {3,         "Maximum residual Bandwidth Path"               },
    {4,         "Minimize aggregate Bandwidth Consumption"      },
    {5,         "Minimize the Load of the most loaded Link"     },
    {6,         "Minimize the Cumulative Cost of a set of paths"},
    {0,         NULL                                            }
};


/*Values of different types of errors*/
static const value_string pcep_error_types_obj_vals[] = {
    {ESTABLISH_FAILURE,     "PCEP Session Establishment Failure"            },
    {CAP_NOT_SUPPORTED,     "Capability non supported"                      },
    {UNKNOWN_OBJ,           "Unknown Object"                                },
    {NOT_SUPP_OBJ,          "Not Supported Object"                          },
    {POLICY_VIOLATION,      "Policy Violation"                              },
    {MANDATORY_OBJ_MIS,     "Mandatory Object Missing"                      },
    {SYNCH_PCREQ_MIS,       "Synchronized Path Computation Request Missing" },
    {UNKNOWN_REQ_REF,       "Unknown Request Reference"                     },
    {ATTEMPT_2_SESSION,     "Attempt to Establish a Second PCEP Session"    },
    {INVALID_OBJ,           "Reception of an invalid object"                },
    {UNRECO_EXRS_SUBOBJ,    "Unrecognized EXRS Subobject"                   },
    {DIFFSERV_TE_ERROR,     "Differsv-aware TE error"                       },
    {BRPC_FAILURE,          "BRPC procedure completion failure"             },
    {GCO_ERROR,             "Global Concurrent Optimization error"          },
    {P2MP_CAPABILITY_ERROR, "P2PM capability error"                         },
    {P2MP_END_POINTS_ERROR, "P2PM END-POINTS error"                         },
    {P2MP_FRAGMENT_ERROR,   "P2PM Fragmentation error"                      },
    {0, NULL }
};
static value_string_ext pcep_error_types_obj_vals_ext = VALUE_STRING_EXT_INIT(pcep_error_types_obj_vals);

/*Error values for error type 1*/
static const value_string pcep_error_value_1_vals[] = {
    {1, "Reception of an invalid Open msg or a non Open msg"},
    {2, "No Open Message received before the expiration of the OpenWait Timer "},
    {3, "Unacceptable and non Negotiable session characteristics"},
    {4, "Unacceptable but Negotiable session characteristics"},
    {5, "Reception of a second Open Message with still Unacceptable Session characteristics"},
    {6, "Reception of a PCEPrr message proposing unacceptable session characteristics"},
    {7, "NO Keepalive or PCEPrr message received before the expiration of the Keepwait timer supported"},
    {8, "PCEP version not supported"},
    {0, NULL}
};

/*Error values for error type 3*/
static const value_string pcep_error_value_3_vals[] = {
    {1, "Unrecognized object class"},
    {2, "Unrecognized object type"},
    {0, NULL}
};

/*Error values for error type 4*/
static const value_string pcep_error_value_4_vals[] = {
    {1, "Not supported object class"},
    {2, "Not supported object type"},
    {4, "Not supported parameter"},
    {0, NULL}
};

/*Error values for error type 5*/
static const value_string pcep_error_value_5_vals[] = {
    {1, "C bit of the METRIC object set (Request Rejected)"},
    {2, "O bit of the RP object set (Request Rejected)"},
    {3, "Objective Function not allowed (Request Rejected)"},
    {4, "OF bit of the RP object set (Request Rejected)"},
    {5, "Global concurrent optimization not allowed"},
    {6, "Monitoring message supported but rejected due to policy violation"},
    {7, "P2MP path computation is not allowed"},
    {0, NULL}
};


/*Error values for error type 6*/
static const value_string pcep_error_value_6_vals[] = {
    {1, "RP object missing"},
    {2, "RRO object missing for a reoptimization request (R bit of the RP Object set)"},
    {3, "END-POINTS object missing"},
    {4, "MONITORINS object missing"},
    {0, NULL}
};

/*Error values for error type 10*/
static const value_string pcep_error_value_10_vals[] = {
    {1, "Reception of an object with P flag not set although the P-flag must be set"},
    {0, NULL}
};

/*Error values for error type 12*/
static const value_string pcep_error_value_12_vals[] = {
    {1, "Unsupported class-type"},
    {2, "Invalid class-type"},
    {3, "Class-type ans setup priority do not form a configured TE-class"},
    {0, NULL}
};

/*Error values for error type 13*/
static const value_string pcep_error_value_13_vals[] = {
    {1, "BRPC procedure not supported by one or more PCEs along the domain path"},
    {0, NULL}
};

/*Error values for error type 15*/
static const value_string pcep_error_value_15_vals[] = {
    {1, "Insufficient memory"},
    {2, "Global concurrent optimization not supported"},
    {0, NULL}
};

/*Error values for error type 16*/
static const value_string pcep_error_value_16_vals[] = {
    {1, "The PCE cannot satisfy the request due to insufficient memory"},
    {2, "The PCE is not capable of P2MP computation"},
    {0, NULL}
};

/*Error values for error type 17*/
static const value_string pcep_error_value_17_vals[] = {
    {1, "The PCE cannot satisfy the request due to no END-POINTS with leaf type 2"},
    {2, "The PCE cannot satisfy the request due to no END-POINTS with leaf type 3"},
    {3, "The PCE cannot satisfy the request due to no END-POINTS with leaf type 4"},
    {4, "The PCE cannot satisfy the request due to inconsistent END-POINTS"},
    {0, NULL}
};

/*Error values for error type 18*/
static const value_string pcep_error_value_18_vals[] = {
    {1, "Fragmented request failure"},
    {0, NULL}
};

static const value_string pcep_close_reason_obj_vals[] = {
    {0,                         "Not defined"                           },
    {NO_EXP_PROV,               "No Explanation Provided"               },
    {DEADTIME_PROV,             "Deadtime Expired"                      },
    {RECEP_MALFORM_MSG,         "Reception of a Malformed PCEP Message" },
    {0, NULL }
};

static const value_string pcep_xro_attribute_obj_vals[] = {
    {ATTR_INTERFACE,            "Interface"     },
    {ATTR_NODE,                 "Node"          },
    {ATTR_SRLG,                 "SRLG"          },
    {0, NULL }
};


#define OBJ_HDR_LEN  4       /* length of object header */

static void
dissect_pcep_tlvs(proto_tree *pcep_obj, tvbuff_t *tvb, int offset, gint length, gint ett_pcep_obj)
{
    proto_tree *tlv;
    proto_item *ti;
    guint16     tlv_length, tlv_type, of_code;
    int         i, j;
    int         padding = 0;

    for (j = 0; j < length; j += 4 + tlv_length + padding) {
        tlv_type = tvb_get_ntohs(tvb, offset+j);
        tlv_length = tvb_get_ntohs(tvb, offset + j + 2);
        ti = proto_tree_add_text(pcep_obj, tvb, offset + j, tlv_length+4, "%s", val_to_str(tlv_type, pcep_tlvs_vals, "Unknown TLV (%u). "));
        tlv = proto_item_add_subtree(ti, ett_pcep_obj);
        proto_tree_add_item(tlv, hf_pcep_tlv_type, tvb, offset + j, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tlv, hf_pcep_tlv_length, tvb, offset + 2 + j, 2, ENC_BIG_ENDIAN);
        switch (tlv_type)
        {
            case 1:    /* NO-PATH TLV */
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_pce,      tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_unk_dest, tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_unk_src,  tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);
                break;

            case 3:   /* REQ-MISSING TLV */
                proto_tree_add_item(tlv, hf_pcep_request_id,            tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);
                break;

            case 4:   /* OF TLV */
                for (i=0; i<tlv_length/2; i++) {
                    of_code = tvb_get_ntohs(tvb, offset+4+j+i*2);
                    proto_tree_add_uint_format(tlv, hf_pcep_of_code, tvb, offset+4+j+i*2, 2, of_code, "OF-Code #%d: %s (%u)",
                                               i+1, val_to_str_const(of_code, pcep_of_vals, "Unknown"), of_code);
                }
                break;

            default:
                proto_tree_add_item(tlv, hf_pcep_tlv_data, tvb, offset+4+j, tlv_length, ENC_NA);
        }

        padding = (4 - (tlv_length % 4)) % 4;
        if (padding != 0) {
            proto_tree_add_item(tlv, hf_pcep_tlv_padding, tvb, offset+4+j+tlv_length, padding, ENC_NA);
        }
    }
}

/*------------------------------------------------------------------------------
 *SUBOBJECTS
 *------------------------------------------------------------------------------*/
static void
dissect_subobj_ipv4(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, gint ett_pcep_obj, guint length)
{
    proto_tree *pcep_subobj_ipv4;
    proto_tree *pcep_subobj_ipv4_flags;
    proto_item *ti;
    guint8      prefix_length;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_IPv4, tvb, offset, length, ENC_NA);
    pcep_subobj_ipv4 = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 8) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad IPv4 subobject: length %u != 8", length);
        return;
    }

    prefix_length = tvb_get_guint8(tvb, offset+6);
    proto_item_append_text(ti, ": %s/%u", tvb_ip_to_str(tvb, offset+2),
                           prefix_length);

    switch (obj_class) {

        case PCEP_EXPLICIT_ROUTE_OBJ:
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_l,             tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_PCEPF_SUBOBJ_7F,                tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_length,        tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_ipv4,          tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_prefix_length, tvb, offset+6, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_padding,       tvb, offset+7, 1, ENC_NA);
            break;

        case PCEP_RECORD_ROUTE_OBJ:
            proto_tree_add_item(pcep_subobj_ipv4, hf_PCEPF_SUBOBJ,                   tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_length,        tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_ipv4,          tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_prefix_length, tvb, offset+6, 1, ENC_NA);
            ti = proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_flags,    tvb, offset+7, 1, ENC_NA);
            pcep_subobj_ipv4_flags = proto_item_add_subtree(ti, ett_pcep_obj);
            proto_tree_add_item(pcep_subobj_ipv4_flags, pcep_subobj_flags_lpa,       tvb, offset+7, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4_flags, pcep_subobj_flags_lpu,       tvb, offset+7, 1, ENC_NA);
            break;

        case PCEP_IRO_OBJ:
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_iro_ipv4_l,         tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_PCEPF_SUBOBJ_7F,                tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_length,        tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_ipv4,          tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_prefix_length, tvb, offset+6, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_padding,       tvb, offset+7, 1, ENC_NA);
            break;

        case PCEP_XRO_OBJ:
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_x,             tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_PCEPF_SUBOBJ_XRO,               tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_length,        tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_ipv4,          tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_prefix_length, tvb, offset+6, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_attribute,     tvb, offset+7, 1, ENC_NA);
            break;

        default:
            expert_add_info_format(pinfo, ti, &ei_pcep_non_defined_subobject,
                                   "Non defined subobject for this object");
            break;
    }
}

static void
dissect_subobj_ipv6(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, gint ett_pcep_obj, guint length)
{
    proto_tree *pcep_subobj_ipv6;
    proto_tree *pcep_subobj_ipv6_flags;
    proto_item *ti;
    guint8      prefix_length;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_IPv6, tvb, offset, length, ENC_NA);
    pcep_subobj_ipv6 = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 20) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad IPv6 subobject: length %u != 20", length);
        return;
    }

    prefix_length = tvb_get_guint8(tvb, offset+18);
    proto_item_append_text(ti, ": %s/%u", tvb_ip6_to_str(tvb, offset+2),
                           prefix_length);

    switch (obj_class) {
        case PCEP_EXPLICIT_ROUTE_OBJ:
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_l,             tvb, offset,    1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_PCEPF_SUBOBJ_7F,                tvb, offset,    1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_length,        tvb, offset+1,  1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_ipv6,          tvb, offset+2, 16, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_prefix_length, tvb, offset+18, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_padding,       tvb, offset+19, 1, ENC_NA);
            break;

        case PCEP_RECORD_ROUTE_OBJ:
            proto_tree_add_item(pcep_subobj_ipv6, hf_PCEPF_SUBOBJ,                   tvb, offset,    1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_length,        tvb, offset+1,  1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_ipv6,          tvb, offset+2, 16, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_prefix_length, tvb, offset+18, 1, ENC_NA);
            ti = proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_flags,    tvb, offset+19, 1, ENC_NA);
            pcep_subobj_ipv6_flags = proto_item_add_subtree(ti, ett_pcep_obj);
            proto_tree_add_item(pcep_subobj_ipv6_flags, pcep_subobj_flags_lpa,       tvb, offset+19, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6_flags, pcep_subobj_flags_lpu,       tvb, offset+19, 1, ENC_NA);
            break;

        case PCEP_IRO_OBJ:
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_iro_ipv6_l,         tvb, offset,    1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_PCEPF_SUBOBJ_7F,                tvb, offset,    1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_length,        tvb, offset+1,  1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_ipv6,          tvb, offset+2, 16, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_prefix_length, tvb, offset+18, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_padding,       tvb, offset+19, 1, ENC_NA);
            break;

        case PCEP_XRO_OBJ:
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_x,             tvb, offset,    1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_PCEPF_SUBOBJ_XRO,               tvb, offset,    1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_length,        tvb, offset+1,  1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_ipv6,          tvb, offset+2, 16, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_prefix_length, tvb, offset+18, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_attribute,     tvb, offset+19, 1, ENC_NA);
            break;

        default:
            expert_add_info_format(pinfo, ti, &ei_pcep_non_defined_subobject,
                                   "Non defined subobject for this object");
            break;
    }
}


static void
dissect_subobj_label_control(proto_tree *pcep_subobj_tree,  packet_info *pinfo, tvbuff_t *tvb,  int offset, int obj_class, gint ett_pcep_obj, guint length)
{
    proto_tree *pcep_subobj_label_control;
    proto_tree *pcep_subobj_label_flags;
    proto_item *ti;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_LABEL_CONTROL, tvb, offset, length, ENC_NA);
    pcep_subobj_label_control = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length < 5) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad label control subobject: length %u < 5", length);
        return;
    }

    switch (obj_class) {

        case PCEP_EXPLICIT_ROUTE_OBJ:
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_l,          tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_PCEPF_SUBOBJ_7F,                      tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_length,     tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_u,          tvb, offset+2, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_reserved,   tvb, offset+2, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_c_type,     tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_label,      tvb, offset+4, length-4, ENC_NA);
            break;

        case PCEP_RECORD_ROUTE_OBJ:
            proto_tree_add_item(pcep_subobj_label_control, hf_PCEPF_SUBOBJ,                         tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_length,     tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_u,          tvb, offset+2, 1, ENC_NA);

            ti = proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_flags, tvb, offset+2, 1, ENC_NA);
            pcep_subobj_label_flags = proto_item_add_subtree(ti, ett_pcep_obj);
            proto_tree_add_item(pcep_subobj_label_flags, pcep_subobj_label_flags_gl,                tvb, offset+2, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_c_type,     tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_label,      tvb, offset+4, length-4, ENC_NA);
            break;

        default:
            expert_add_info_format(pinfo, ti, &ei_pcep_non_defined_subobject,
                                   "Non defined subobject for this object");
            break;
    }
}

static void
dissect_subobj_unnumb_interfaceID(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, gint ett_pcep_obj, guint length)
{
    proto_tree *pcep_subobj_unnumb_interfaceID;
    proto_tree *pcep_subobj_unnumb_interfaceID_flags;
    proto_item *ti;
    guint32     router_ID;
    guint32     interface_ID;
    guint16     reserved_flags;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_UNNUM_INTERFACEID, tvb, offset, length, ENC_NA);
    pcep_subobj_unnumb_interfaceID = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 12) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad unnumbered interface ID subobject: length %u != 12", length);
        return;
    }

    reserved_flags = tvb_get_ntohs(tvb, offset+2);
    router_ID = tvb_get_ipv4(tvb, offset+4);
    interface_ID = tvb_get_ntohl(tvb, offset+8);
    proto_item_append_text(ti, ": %s:%u", ip_to_str ((guint8 *) &router_ID),
                           interface_ID);

    switch (obj_class) {

        case PCEP_EXPLICIT_ROUTE_OBJ:
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_l, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_PCEPF_SUBOBJ_7F, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_length, tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_reserved, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            break;

        case PCEP_RECORD_ROUTE_OBJ:
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_PCEPF_SUBOBJ, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_length, tvb, offset+1, 1, ENC_NA);

            ti = proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_flags, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            pcep_subobj_unnumb_interfaceID_flags = proto_item_add_subtree(ti, ett_pcep_obj);
            proto_tree_add_boolean(pcep_subobj_unnumb_interfaceID_flags, pcep_subobj_flags_lpa, tvb, offset+2, 1, (reserved_flags & 0xff00)>>8);
            proto_tree_add_boolean(pcep_subobj_unnumb_interfaceID_flags, pcep_subobj_flags_lpu, tvb, offset+2, 1, (reserved_flags & 0xff00)>>8);

            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_reserved_rrobj, tvb, offset+3, 1, ENC_NA);
            break;

        case PCEP_IRO_OBJ:
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_iro_unnumb_interfaceID_l, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_PCEPF_SUBOBJ_7F, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_length, tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_reserved, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            break;

        case PCEP_XRO_OBJ:
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_x, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_PCEPF_SUBOBJ_XRO, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_reserved_xroobj, tvb, offset+2, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_attribute, tvb, offset+3, 1, ENC_NA);
            break;

        default:
            expert_add_info_format(pinfo, ti, &ei_pcep_non_defined_subobject,
                                   "Non defined subobject for this object");
            break;
    }

    proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_router_id, tvb, offset+4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_interface_id, tvb, offset+8, 4, ENC_BIG_ENDIAN);
}

static void
dissect_subobj_autonomous_sys_num(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, guint ett_pcep_obj, guint length)
{
    proto_tree *pcep_subobj_autonomous_sys_num;
    proto_item *ti;

    if (obj_class == PCEP_XRO_OBJ) {
        ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_AUTONOMOUS_SYS_NUM, tvb, offset, length, ENC_NA);
        pcep_subobj_autonomous_sys_num = proto_item_add_subtree(ti, ett_pcep_obj);
        if (length != 8) {
            expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                                   "Bad autonomous system number subobject: length %u != 8", length);
            return;
        }

        proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_pcep_subobj_autonomous_sys_num_x,         tvb, offset,   1, ENC_NA);
        proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_PCEPF_SUBOBJ_XRO,                         tvb, offset,   1, ENC_NA);
        proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_pcep_subobj_autonomous_sys_num_length,    tvb, offset+1, 1, ENC_NA);

        proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_pcep_subobj_autonomous_sys_num_reserved,  tvb, offset+2, 1, ENC_NA);
        proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_pcep_subobj_autonomous_sys_num_attribute, tvb, offset+3, 1, ENC_NA);
        proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_pcep_subobj_autonomous_sys_num_optional_as_number_high_octets, tvb, offset+4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_pcep_subobj_autonomous_sys_num_as_number, tvb, offset+6, 2, ENC_BIG_ENDIAN);
    } else {
        ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_AUTONOMOUS_SYS_NUM,                   tvb, offset, length, ENC_NA);
        pcep_subobj_autonomous_sys_num = proto_item_add_subtree(ti, ett_pcep_obj);

        if (length != 4) {
            expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                                   "Bad autonomous system number subobject: length %u != 4", length);
            return;
        }

        if (obj_class == PCEP_IRO_OBJ)
            proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_pcep_subobj_iro_autonomous_sys_num_l, tvb, offset, 1, ENC_NA);
        else
            proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_pcep_subobj_autonomous_sys_num_l,     tvb, offset, 1, ENC_NA);
        proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_PCEPF_SUBOBJ_7F,                          tvb, offset,   1, ENC_NA);
        proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_pcep_subobj_autonomous_sys_num_length,    tvb, offset+1, 1, ENC_NA);
        proto_tree_add_item(pcep_subobj_autonomous_sys_num, hf_pcep_subobj_autonomous_sys_num_as_number, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    }
}

static void
dissect_subobj_srlg(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, guint ett_pcep_obj, guint length)
{
    proto_tree *pcep_subobj_srlg;
    proto_item *ti;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_SRLG, tvb, offset, length, ENC_NA);
    pcep_subobj_srlg = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 8) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad SRLG subobject: length %u != 8", length);
        return;
    }

    proto_tree_add_item(pcep_subobj_srlg, hf_pcep_subobj_srlg_x,         tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_srlg, hf_PCEPF_SUBOBJ_XRO,           tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_srlg, hf_pcep_subobj_srlg_length,    tvb, offset+1, 1, ENC_NA);

    proto_tree_add_item(pcep_subobj_srlg, hf_pcep_subobj_srlg_id,        tvb, offset+2, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_subobj_srlg, hf_pcep_subobj_srlg_reserved,  tvb, offset+6, 1, ENC_NA);
    proto_tree_add_item(pcep_subobj_srlg, hf_pcep_subobj_srlg_attribute, tvb, offset+7, 1, ENC_NA);
}

static void
dissect_subobj_exrs(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, guint ett_pcep_obj, guint type_iro, guint length)
{
    proto_tree *pcep_subobj_exrs;
    proto_item *ti;
    guint8      l_type;
    guint8      length2;
    guint       type_exrs;
    guint       offset_exrs = 0;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_EXRS, tvb, offset, length, ENC_NA);
    pcep_subobj_exrs = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length < 4) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad EXRS subobject: length %u < 4", length);
        return;
    }

    proto_tree_add_item(pcep_subobj_exrs, hf_pcep_subobj_exrs_l,        tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_exrs, hf_pcep_subobj_exrs_type,     tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_exrs, hf_pcep_subobj_exrs_length,   tvb, offset+1, 1, ENC_NA);

    proto_tree_add_item(pcep_subobj_exrs, hf_pcep_subobj_exrs_reserved, tvb, offset+2, 2, ENC_BIG_ENDIAN);

    offset += 4;

    while (offset_exrs<length-4) {

        l_type  = tvb_get_guint8(tvb, offset);
        length2 = tvb_get_guint8(tvb, offset+1);

        if (length2 < 2) {
            expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                                   "Bad packet: subobject length %u < 2", length2);
            break;
        }

        type_exrs = (l_type & Mask_Type);

        if (type_iro == PCEP_SUB_EXRS)
            obj_class = PCEP_XRO_OBJ;

        switch (type_exrs) {

            case PCEP_SUB_IPv4:
                dissect_subobj_ipv4(pcep_subobj_exrs, pinfo, tvb, offset,  obj_class, ett_pcep_obj, length2);
                break;
            case PCEP_SUB_IPv6:
                dissect_subobj_ipv6(pcep_subobj_exrs, pinfo, tvb, offset, obj_class, ett_pcep_obj, length2);
                break;
            case PCEP_SUB_UNNUMB_INTERFACE_ID:
                dissect_subobj_unnumb_interfaceID(pcep_subobj_exrs, pinfo, tvb, offset, obj_class, ett_pcep_obj, length2);
                break;
            case PCEP_SUB_AUTONOMOUS_SYS_NUM:
                dissect_subobj_autonomous_sys_num(pcep_subobj_exrs, pinfo, tvb, offset, obj_class, ett_pcep_obj, length2);
                break;
            case PCEP_SUB_SRLG:
                dissect_subobj_srlg(pcep_subobj_exrs, pinfo, tvb, offset, ett_pcep_obj, length2);
                break;
            default:
                proto_tree_add_expert_format(pcep_subobj_exrs, pinfo, &ei_pcep_non_defined_subobject,
                                             tvb, offset+2, length-2,
                                             "Non defined subobject (%d)", type_exrs);
                break;
        }
        offset_exrs += length2;
        offset += length2;
    }
}

static void
dissect_subobj_pksv4(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, gint ett_pcep_obj, guint length)
{
    proto_tree *pcep_subobj_pksv4;
    proto_item *ti;
    guint16     path_key;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_PKSv4, tvb, offset, length, ENC_NA);
    pcep_subobj_pksv4 = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 8) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad path key subobject: length %u != 8", length);
        return;
    }

    path_key = tvb_get_ntohs(tvb, offset+2);
    proto_item_append_text(ti, ": %s, Path Key %u", tvb_ip_to_str(tvb, offset+4), path_key);
    proto_tree_add_item(pcep_subobj_pksv4, hf_pcep_subobj_pksv4_l,        tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv4, hf_PCEPF_SUBOBJ_7F,            tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv4, hf_pcep_subobj_pksv4_length,   tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv4, hf_pcep_subobj_pksv4_path_key, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_subobj_pksv4, hf_pcep_subobj_pksv4_pce_id,   tvb, offset+4, 4, ENC_BIG_ENDIAN);
}

static void
dissect_subobj_pksv6(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, gint ett_pcep_obj, guint length)
{
    proto_tree *pcep_subobj_pksv6;
    proto_item *ti;
    guint16     path_key;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_PKSv6, tvb, offset, length, ENC_NA);
    pcep_subobj_pksv6 = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 20) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad path key subobject: length %u != 20", length);
        return;
    }

    path_key = tvb_get_ntohs(tvb, offset+2);
    proto_item_append_text(ti, ": %s, Path Key %u", tvb_ip6_to_str(tvb, offset+4), path_key);

    proto_tree_add_item(pcep_subobj_pksv6, hf_pcep_subobj_pksv6_l,        tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv6, hf_PCEPF_SUBOBJ_7F,            tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv6, hf_pcep_subobj_pksv6_length,   tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv6, hf_pcep_subobj_pksv6_path_key, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_subobj_pksv6, hf_pcep_subobj_pksv6_pce_id,   tvb, offset+4, 4, ENC_NA);
}

/*------------------------------------------------------------------------------
 * OPEN OBJECT
 *------------------------------------------------------------------------------*/
#define OPEN_OBJ_MIN_LEN    4

static void
dissect_pcep_open_obj (proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    proto_tree *pcep_open_obj_flags;
    proto_item *ti;

    if (obj_length < OBJ_HDR_LEN+OPEN_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad OPEN object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+OPEN_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_open_obj_pcep_version, tvb, offset2, 1, ENC_NA);

    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_open_obj_flags, tvb, offset2, 1, ENC_NA);
    pcep_open_obj_flags = proto_item_add_subtree(ti, ett_pcep_obj_open);
    proto_tree_add_item(pcep_open_obj_flags, hf_pcep_open_flags_res,  tvb, offset2,   1, ENC_NA);

    proto_tree_add_item(pcep_object_tree, hf_pcep_open_obj_keepalive, tvb, offset2+1, 1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_open_obj_deadtime,  tvb, offset2+2, 1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_open_obj_sid,       tvb, offset2+3, 1, ENC_NA);

    /*it's suppose that obj_length is a valid date. The object can have optional TLV(s)*/
    offset2 += OPEN_OBJ_MIN_LEN;
    obj_length -= OBJ_HDR_LEN+OPEN_OBJ_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_open);
}

/*------------------------------------------------------------------------------
 * RP OBJECT
 *------------------------------------------------------------------------------*/
#define RP_OBJ_MIN_LEN  8

static void
dissect_pcep_rp_obj(proto_tree *pcep_object_tree, packet_info *pinfo,
                    tvbuff_t *tvb, int offset2, int obj_length)
{
    proto_tree *pcep_rp_obj_flags;
    proto_item *ti;

    if (obj_length < OBJ_HDR_LEN+RP_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad RP object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+RP_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_rp_obj_reserved, tvb, offset2, 1, ENC_NA);

    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_rp_obj_flags, tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    pcep_rp_obj_flags = proto_item_add_subtree(ti, ett_pcep_obj_request_parameters);

    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_reserved, tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_f,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_n,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_e,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_m,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_d,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_p,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_s,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_v,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_o,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_b,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_r,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_pri,      tvb, offset2+1, 3, ENC_BIG_ENDIAN);

    proto_tree_add_item(pcep_object_tree, hf_pcep_rp_obj_requested_id_number, tvb, offset2+4, 4, ENC_BIG_ENDIAN);

    /*it's suppose that obj_length is a valid date. The object can have optional TLV(s)*/
    offset2 += RP_OBJ_MIN_LEN;
    obj_length -= OBJ_HDR_LEN+RP_OBJ_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_request_parameters);
}

/*------------------------------------------------------------------------------
 * NO PATH OBJECT
 *------------------------------------------------------------------------------*/
#define NO_PATH_OBJ_MIN_LEN  4

static void
dissect_pcep_no_path_obj(proto_tree *pcep_object_tree, packet_info *pinfo,
                         tvbuff_t *tvb, int offset2, int obj_length)
{
    proto_tree *pcep_no_path_obj_flags;
    proto_item *ti;

    if (obj_length < OBJ_HDR_LEN+NO_PATH_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad NO-PATH object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+NO_PATH_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_no_path_obj_nature_of_issue, tvb, offset2, 1, ENC_NA);

    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_no_path_obj_flags, tvb, offset2+1, 2, ENC_BIG_ENDIAN);
    pcep_no_path_obj_flags = proto_item_add_subtree(ti, ett_pcep_obj_no_path);
    proto_tree_add_item(pcep_no_path_obj_flags, hf_pcep_no_path_flags_c, tvb, offset2+1, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(pcep_object_tree, hf_pcep_no_path_obj_reserved, tvb, offset2+3, 1, ENC_NA);

    /*it's suppose that obj_length is a valid date. The object can have optional TLV(s)*/
    offset2 += NO_PATH_OBJ_MIN_LEN;
    obj_length -= OBJ_HDR_LEN+NO_PATH_OBJ_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_no_path);
}

/*------------------------------------------------------------------------------
 * END POINT OBJECT
 *------------------------------------------------------------------------------*/
#define END_POINT_IPV4_OBJ_LEN   8
#define END_POINT_IPV6_OBJ_LEN  32

static void
dissect_pcep_end_point_obj(proto_tree *pcep_object_tree, packet_info *pinfo,
                           tvbuff_t *tvb, int offset2, int obj_length, int type)
{
    switch (type)
    {
        case IPv4:
            if (obj_length != OBJ_HDR_LEN+END_POINT_IPV4_OBJ_LEN) {
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                             tvb, offset2, obj_length,
                                             "Bad IPv4 END-POINTS object length %u, should be %u",
                                             obj_length, OBJ_HDR_LEN+END_POINT_IPV4_OBJ_LEN);
                return;
            }

            proto_tree_add_item(pcep_object_tree, hf_pcep_end_point_obj_source_ipv4_address,      tvb, offset2,   4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcep_object_tree, hf_pcep_end_point_obj_destination_ipv4_address, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
            break;

        case IPv6:
            if (obj_length != OBJ_HDR_LEN+END_POINT_IPV6_OBJ_LEN) {
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                             tvb, offset2, obj_length,
                                             "Bad IPv6 END-POINTS object length %u, should be %u",
                                             obj_length, OBJ_HDR_LEN+END_POINT_IPV6_OBJ_LEN);
                return;
            }

            proto_tree_add_item(pcep_object_tree, hf_pcep_end_point_obj_source_ipv6_address,      tvb, offset2,    16, ENC_NA);
            proto_tree_add_item(pcep_object_tree, hf_pcep_end_point_obj_destination_ipv6_address, tvb, offset2+16, 16, ENC_NA);
            break;

        default:
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_unknown_type_object,
                                         tvb, offset2, obj_length-OBJ_HDR_LEN,
                                         "UNKNOWN Type Object (%u)", type);
            break;
    }
}



/*------------------------------------------------------------------------------
 * BANDWIDTH OBJECT
 *------------------------------------------------------------------------------*/
#define BANDWIDTH_OBJ_LEN  4

static void
dissect_pcep_bandwidth_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    if (obj_length != OBJ_HDR_LEN+BANDWIDTH_OBJ_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad BANDWIDTH object length %u, should be %u",
                                     obj_length, OBJ_HDR_LEN+BANDWIDTH_OBJ_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_bandwidth, tvb, offset2, 4, ENC_BIG_ENDIAN);
}

/*------------------------------------------------------------------------------
 * METRIC OBJECT
 *------------------------------------------------------------------------------*/
#define METRIC_OBJ_LEN  8

static void
dissect_pcep_metric_obj(proto_tree *pcep_object_tree, packet_info *pinfo,
                        tvbuff_t *tvb, int offset2, int obj_length)
{
    proto_tree *pcep_metric_obj_flags;
    proto_item *ti;

    if (obj_length != OBJ_HDR_LEN+METRIC_OBJ_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad METRIC object length %u, should be %u",
                                     obj_length, OBJ_HDR_LEN+METRIC_OBJ_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_metric_obj_reserved, tvb, offset2, 2, ENC_BIG_ENDIAN);

    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_metric_obj_flags, tvb, offset2+2, 1, ENC_NA);
    pcep_metric_obj_flags = proto_item_add_subtree(ti, ett_pcep_obj_metric);
    proto_tree_add_item(pcep_metric_obj_flags, hf_pcep_metric_flags_c, tvb, offset2+2, 1, ENC_NA);
    proto_tree_add_item(pcep_metric_obj_flags, hf_pcep_metric_flags_b, tvb, offset2+2, 1, ENC_NA);

    proto_tree_add_item(pcep_object_tree, hf_pcep_metric_obj_type,         tvb, offset2+3, 1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_metric_obj_metric_value, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
}

/*------------------------------------------------------------------------------
 * EXPLICIT ROUTE OBJECT (ERO)
 *------------------------------------------------------------------------------*/
static void
dissect_pcep_explicit_route_obj(proto_tree *pcep_object_tree, packet_info *pinfo,
                                tvbuff_t *tvb, int offset2, int obj_length, int obj_class)
{
    guint8 l_type;
    guint8 length;
    guint  type_exp_route;
    guint  body_obj_len;

    body_obj_len = obj_length - OBJ_HDR_LEN;

    while (body_obj_len) {
        if (body_obj_len < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad ERO object: subobject goes past end of object");
            break;
        }

        l_type = tvb_get_guint8(tvb, offset2);
        length = tvb_get_guint8(tvb, offset2+1);

        if (length < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad ERO object: subobject length %u < 2", length);
            break;
        }

        type_exp_route = (l_type & Mask_Type);
        if (body_obj_len <length) {
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                         tvb, offset2, length,
                                         "Bad ERO object: subobject length %u > remaining length %u",
                                         length, body_obj_len);
            break;
        }

        switch (type_exp_route) {

            case PCEP_SUB_IPv4:
                dissect_subobj_ipv4(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, length);
                break;
            case PCEP_SUB_IPv6:
                dissect_subobj_ipv6(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, length);
                break;
            case PCEP_SUB_LABEL_CONTROL:
                dissect_subobj_label_control(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, length);
                break;
            case PCEP_SUB_UNNUMB_INTERFACE_ID:
                dissect_subobj_unnumb_interfaceID(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, length);
                break;
            case PCEP_SUB_AUTONOMOUS_SYS_NUM:
                dissect_subobj_autonomous_sys_num(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, length);
                break;
            case PCEP_SUB_PKSv4:
                dissect_subobj_pksv4(pcep_object_tree, pinfo, tvb, offset2, ett_pcep_obj_explicit_route, length);
                break;
            default:
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_subobject,
                                             tvb, offset2, length,
                                             "Non defined subobject (%d)", type_exp_route);
                break;
        }
        offset2 += length;
        body_obj_len -= length;
    }
}

/*------------------------------------------------------------------------------
 * RECORD ROUTE OBJECT (RRO)
 *------------------------------------------------------------------------------*/
static void
dissect_pcep_record_route_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class)
{
    guint8 type;
    guint8 length;
    guint  body_obj_len;

    body_obj_len = obj_length - OBJ_HDR_LEN;

    while (body_obj_len) {
        if (body_obj_len < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad RRO object: subobject goes past end of object");
            break;
        }

        type = tvb_get_guint8(tvb, offset2);
        length = tvb_get_guint8(tvb, offset2+1);

        if (length < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad RRO object: subobject length %u < 2", length);
            break;
        }

        if (body_obj_len <length) {
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                         tvb, offset2, length,
                                         "Bad RRO subobject: subobject length %u > remaining length %u",
                                         length, body_obj_len);
            break;
        }

        switch (type) {

            case PCEP_SUB_IPv4:
                dissect_subobj_ipv4(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_record_route, length);
                break;
            case PCEP_SUB_IPv6:
                dissect_subobj_ipv6(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_record_route, length);
                break;
            case PCEP_SUB_LABEL_CONTROL:
                dissect_subobj_label_control(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_record_route, length);
                break;
            case PCEP_SUB_UNNUMB_INTERFACE_ID:
                dissect_subobj_unnumb_interfaceID(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_record_route, length);
                break;
            default:
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_subobject,
                                             tvb, offset2, length,
                                             "Non defined subobject (%d)", type);
                break;
        }
        offset2 += length;
        body_obj_len -= length;
    }
}

/*------------------------------------------------------------------------------
 * LSPA OBJECT
 *------------------------------------------------------------------------------*/
#define LSPA_OBJ_MIN_LEN  16

static void
dissect_pcep_lspa_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    proto_tree *pcep_lspa_obj_flags;
    proto_item *ti;

    if (obj_length < OBJ_HDR_LEN+LSPA_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad LSPA object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+LSPA_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_lspa_obj_exclude_any,      tvb, offset2,    4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_lspa_obj_include_any,      tvb, offset2+4,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_lspa_obj_include_all,      tvb, offset2+8,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_lspa_obj_setup_priority,   tvb, offset2+12, 1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_lspa_obj_holding_priority, tvb, offset2+13, 1, ENC_NA);

    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_lspa_obj_flags, tvb, offset2+14, 1, ENC_NA);
    pcep_lspa_obj_flags = proto_item_add_subtree(ti, ett_pcep_obj_metric);
    proto_tree_add_item(pcep_lspa_obj_flags, hf_pcep_lspa_flags_l, tvb, offset2+14, 1, ENC_NA);

    proto_tree_add_item(pcep_object_tree, hf_pcep_lspa_obj_reserved, tvb, offset2+15, 1, ENC_NA);

    /*it's suppose that obj_length is a valid date. The object can have optional TLV(s)*/
    offset2 += LSPA_OBJ_MIN_LEN;
    obj_length -= OBJ_HDR_LEN+LSPA_OBJ_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_lspa);
}

/*------------------------------------------------------------------------------
 * INCLUDE ROUTE OBJECT (IRO)
 *------------------------------------------------------------------------------*/
static void
dissect_pcep_iro_obj(proto_tree *pcep_object_tree, packet_info *pinfo,
                     tvbuff_t *tvb, int offset2, int obj_length, int obj_class)
{
    guint8 l_type;
    guint8 length;
    int    type_iro;
    guint  body_obj_len;

    body_obj_len = obj_length - OBJ_HDR_LEN;

    while (body_obj_len) {
        if (body_obj_len < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad IRO object: subobject goes past end of object");
            break;
        }

        l_type = tvb_get_guint8(tvb, offset2);
        length = tvb_get_guint8(tvb, offset2+1);

        if (length < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad IRO object: subobject length %u < 2", length);
            break;
        }

        type_iro = (l_type & Mask_Type);

        if (body_obj_len <length) {
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                         tvb, offset2, length,
                                         "Bad IRO object: subobject length %u > remaining length %u",
                                         length, body_obj_len);
            break;
        }

        switch (type_iro) {

            case PCEP_SUB_IPv4:
                dissect_subobj_ipv4(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_iro, length);
                break;
            case PCEP_SUB_IPv6:
                dissect_subobj_ipv6(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_iro, length);
                break;
            case PCEP_SUB_UNNUMB_INTERFACE_ID:
                dissect_subobj_unnumb_interfaceID(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_iro, length);
                break;
            case PCEP_SUB_AUTONOMOUS_SYS_NUM:
                dissect_subobj_autonomous_sys_num(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_iro, length);
                break;
            case PCEP_SUB_EXRS:
                dissect_subobj_exrs(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_iro, type_iro, length);
                break;
            default:
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_subobject,
                                             tvb, offset2, length,
                                             "Non defined subobject (%d)", type_iro);
                break;
        }
        offset2 += length;
        body_obj_len -= length;
    }
}

/*------------------------------------------------------------------------------
 * SVEC OBJECT
 *------------------------------------------------------------------------------*/
#define SVEC_OBJ_MIN_LEN  4

static void
dissect_pcep_svec_obj(proto_tree *pcep_object_tree, packet_info *pinfo,
                      tvbuff_t *tvb, int offset2, int obj_length)
{
    proto_item *ti;
    proto_tree *pcep_svec_flags_obj;
    int         m;
    int         i;
    guint32     requestID;

    if (obj_length < OBJ_HDR_LEN+SVEC_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad SVEC object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+SVEC_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_svec_obj_reserved, tvb, offset2, 1, ENC_NA);

    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_svec_obj_flags, tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    pcep_svec_flags_obj = proto_item_add_subtree(ti, ett_pcep_obj_svec);
    proto_tree_add_item(pcep_svec_flags_obj, hf_pcep_svec_flags_l, tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_svec_flags_obj, hf_pcep_svec_flags_n, tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_svec_flags_obj, hf_pcep_svec_flags_s, tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);

    m = 1;
    for ( i=4 ; i<(obj_length-OBJ_HDR_LEN) ; ) {
        requestID = tvb_get_ntohl(tvb, offset2+i);
        proto_tree_add_uint_format(pcep_object_tree, hf_pcep_svec_obj_request_id_number, tvb, offset2+i, 4, requestID,
                                   "Request-ID-Number %u: 0x%x", m++, requestID);
        i += 4;
    }
}

/*------------------------------------------------------------------------------
 * NOTIFICATION OBJECT
 *------------------------------------------------------------------------------*/
#define NOTIFICATION_OBJ_MIN_LEN  4

static void
dissect_pcep_notification_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    guint8 nt;

    if (obj_length < OBJ_HDR_LEN+NOTIFICATION_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad NOTIFICATION object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+NOTIFICATION_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_notification_obj_reserved, tvb, offset2,   1, ENC_NA);

    proto_tree_add_item(pcep_object_tree, hf_pcep_notification_obj_flags,    tvb, offset2+1, 1, ENC_NA);

    nt = tvb_get_guint8(tvb, offset2+2);
    proto_tree_add_item(pcep_object_tree, hf_PCEPF_NOTI_TYPE, tvb, offset2+2, 1, ENC_NA);

    switch (nt) {

        case 1:
            proto_tree_add_item(pcep_object_tree, hf_PCEPF_NOTI_VAL1, tvb, offset2+2, 1, ENC_NA);
            break;

        case 2:
            proto_tree_add_item(pcep_object_tree, hf_PCEPF_NOTI_VAL2, tvb, offset2+2, 1, ENC_NA);
            break;

        default:
            proto_tree_add_item(pcep_object_tree, hf_pcep_notification_obj_type, tvb, offset2+2, 1, ENC_NA);
            break;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_notification_obj_value, tvb, offset2+3, 1, ENC_NA);

    /*it's suppose that obj_length is a valid date. The object can have optional TLV(s)*/
    offset2 += NOTIFICATION_OBJ_MIN_LEN;
    obj_length -= OBJ_HDR_LEN+NOTIFICATION_OBJ_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_notification);
}

/*------------------------------------------------------------------------------
 * ERROR OBJECT
 *------------------------------------------------------------------------------*/
#define ERROR_OBJ_MIN_LEN  4

static void
dissect_pcep_error_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    guint8       error_type;
    guint8       error_value;
    const gchar *err_str = "Unassigned";

    if (obj_length < OBJ_HDR_LEN+ERROR_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad ERROR object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+ERROR_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_error_obj_reserved, tvb, offset2,   1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_error_obj_flags,    tvb, offset2+1, 1, ENC_NA);

    error_type  = tvb_get_guint8(tvb, offset2+2);
    error_value = tvb_get_guint8(tvb, offset2+3);
    proto_tree_add_item(pcep_object_tree, hf_PCEPF_ERROR_TYPE, tvb, offset2+2, 1, ENC_NA);

    switch (error_type) {
        case ESTABLISH_FAILURE:
            err_str = val_to_str_const(error_value, pcep_error_value_1_vals, "Unknown");
            break;
        case CAP_NOT_SUPPORTED:
            break;
        case UNKNOWN_OBJ:
            err_str = val_to_str_const(error_value, pcep_error_value_3_vals, "Unknown");
            break;
        case NOT_SUPP_OBJ:
            err_str = val_to_str_const(error_value, pcep_error_value_4_vals, "Unknown");
            break;
        case POLICY_VIOLATION:
            err_str = val_to_str_const(error_value, pcep_error_value_5_vals, "Unknown");
            break;
        case MANDATORY_OBJ_MIS:
            err_str = val_to_str_const(error_value, pcep_error_value_6_vals, "Unknown");
            break;
        case SYNCH_PCREQ_MIS:
            break;
        case UNKNOWN_REQ_REF:
            break;
        case ATTEMPT_2_SESSION:
            break;
        case INVALID_OBJ:
            err_str = val_to_str_const(error_value, pcep_error_value_10_vals, "Unknown");
            break;
        case UNRECO_EXRS_SUBOBJ:
            break;
        case DIFFSERV_TE_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_12_vals, "Unknown");
            break;
        case BRPC_FAILURE:
            err_str = val_to_str_const(error_value, pcep_error_value_13_vals, "Unknown");
            break;
        case GCO_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_15_vals, "Unknown");
            break;
        case P2MP_CAPABILITY_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_16_vals, "Unknown");
            break;
        case P2MP_END_POINTS_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_17_vals, "Unknown");
            break;
        case P2MP_FRAGMENT_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_18_vals, "Unknown");
            break;
        default:
            proto_tree_add_text(pcep_object_tree, tvb, offset2+2, 1, "Error-Type: %u Non defined Error-Value", error_type);
    }
    proto_tree_add_text(pcep_object_tree, tvb, offset2+3, 1, "Error-Value: %s (%u)", err_str, error_value);

    /*it's suppose that obj_length is a valid date. The object can have optional TLV(s)*/
    offset2 += ERROR_OBJ_MIN_LEN;
    obj_length -= OBJ_HDR_LEN+ERROR_OBJ_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_error);
}


/*------------------------------------------------------------------------------
 * LOAD-BALANCING OBJECT
 *------------------------------------------------------------------------------*/
#define LOAD_BALANCING_OBJ_LEN  8

static void
dissect_pcep_balancing_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    if (obj_length != OBJ_HDR_LEN+LOAD_BALANCING_OBJ_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad LOAD-BALANCING object length %u, should be %u",
                                     obj_length, OBJ_HDR_LEN+LOAD_BALANCING_OBJ_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_balancing_obj_reserved,                  tvb, offset2,   2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_balancing_obj_flags,                     tvb, offset2+2, 1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_balancing_obj_maximum_number_of_te_lsps, tvb, offset2+3, 1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_balancing_obj_minimum_bandwidth,         tvb, offset2+4, 4, ENC_BIG_ENDIAN);
}

/*------------------------------------------------------------------------------
 * CLOSE OBJECT
 *------------------------------------------------------------------------------*/
#define CLOSE_OBJ_MIN_LEN  4

static void
dissect_pcep_close_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    if (obj_length < OBJ_HDR_LEN+CLOSE_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad CLOSE object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+CLOSE_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_close_obj_reserved, tvb, offset2,   2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_close_obj_flags,    tvb, offset2+2, 1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_close_obj_reason,   tvb, offset2+3, 1, ENC_NA);

    /*it's suppose that obj_length is a valid date. The object can have optional TLV(s)*/
    offset2 += CLOSE_OBJ_MIN_LEN;
    obj_length -= OBJ_HDR_LEN+CLOSE_OBJ_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_load_balancing);
}

/*------------------------------------------------------------------------------
 * PATH-KEY OBJECT
 *------------------------------------------------------------------------------*/
static void
dissect_pcep_path_key_obj(proto_tree *pcep_object_tree, packet_info *pinfo,
                          tvbuff_t *tvb, int offset2, int obj_length)
{
    guint8 l_type;
    guint8 length;
    guint  type_exp_route;
    guint  body_obj_len;

    body_obj_len = obj_length - OBJ_HDR_LEN;

    while (body_obj_len) {
        if (body_obj_len < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad PATH-KEY object: subobject goes past end of object");
            break;
        }

        l_type = tvb_get_guint8(tvb, offset2);
        length = tvb_get_guint8(tvb, offset2+1);

        if (length < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad PATH-KEY object: subobject length %u < 2", length);
            break;
        }

        type_exp_route = (l_type & Mask_Type);
        if (body_obj_len <length) {
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                         tvb, offset2, length,
                                         "Bad PATH-KEY object: subobject length %u > remaining length %u",
                                         length, body_obj_len);
            break;
        }

        switch (type_exp_route) {
            case PCEP_SUB_PKSv4:
                dissect_subobj_pksv4(pcep_object_tree, pinfo, tvb, offset2, ett_pcep_obj_explicit_route, length);
                break;
            default:
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_subobject,
                                             tvb, offset2, length,
                                             "Non defined subobject (%d)", type_exp_route);
                break;
        }
        offset2 += length;
        body_obj_len -= length;
    }
}

/*------------------------------------------------------------------------------
 * XRO OBJECT
 *------------------------------------------------------------------------------*/
#define XRO_OBJ_MIN_LEN  4

static void
dissect_pcep_xro_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class)
{
    proto_tree *pcep_xro_flags_obj;
    proto_item *ti;
    guint8      x_type;
    guint8      length;
    guint       type_xro;
    guint       body_obj_len;

    body_obj_len = obj_length - OBJ_HDR_LEN;

    if (obj_length < OBJ_HDR_LEN+XRO_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad XRO object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+XRO_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_xro_obj_reserved, tvb, offset2, 2, ENC_BIG_ENDIAN);

    ti =  proto_tree_add_item(pcep_object_tree, hf_pcep_xro_obj_flags, tvb, offset2+2, 2, ENC_BIG_ENDIAN);
    pcep_xro_flags_obj = proto_item_add_subtree(ti, ett_pcep_obj_xro);
    proto_tree_add_item(pcep_xro_flags_obj, hf_pcep_xro_flags_f, tvb, offset2 + 2, 2, ENC_BIG_ENDIAN);

    offset2 += XRO_OBJ_MIN_LEN;
    body_obj_len -= XRO_OBJ_MIN_LEN;

    while (body_obj_len >= 2) {
        if (body_obj_len < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad XRO object: subobject goes past end of object");
            break;
        }

        x_type = tvb_get_guint8(tvb, offset2);
        length = tvb_get_guint8(tvb, offset2+1);

        if (length < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad XRO object: object length %u < 2", length);
            break;
        }

        type_xro = (x_type & Mask_Type);

        if (body_obj_len <length) {
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                         tvb, offset2, length,
                                         "Bad XRO object: object length %u > remaining length %u",
                                         length, body_obj_len);
            break;
        }

        switch (type_xro) {

            case PCEP_SUB_IPv4:
                dissect_subobj_ipv4(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_xro, length);
                break;
            case PCEP_SUB_IPv6:
                dissect_subobj_ipv6(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_xro, length);
                break;
            case PCEP_SUB_UNNUMB_INTERFACE_ID:
                dissect_subobj_unnumb_interfaceID(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_xro, length);
                break;
            case PCEP_SUB_AUTONOMOUS_SYS_NUM:
                dissect_subobj_autonomous_sys_num(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_xro, length);
                break;
            case PCEP_SUB_SRLG:
                dissect_subobj_srlg(pcep_object_tree, pinfo, tvb, offset2, ett_pcep_obj_xro, length);
                break;
            case PCEP_SUB_PKSv4:
                dissect_subobj_pksv4(pcep_object_tree, pinfo, tvb, offset2, ett_pcep_obj_xro, length);
                break;
            case PCEP_SUB_PKSv6:
                dissect_subobj_pksv6(pcep_object_tree, pinfo, tvb, offset2, ett_pcep_obj_xro, length);
                break;
            default:
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_subobject,
                                             tvb, offset2-4, length,
                                             "Non defined subobject (%d)", type_xro);
                break;
        }
        offset2 += length;
        body_obj_len -= length;
    }
}

/*------------------------------------------------------------------------------
 * MONITORING OBJECT
 *------------------------------------------------------------------------------*/
#define OBJ_MONITORING_MIN_LEN 8

static void
dissect_pcep_obj_monitoring(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    proto_item *ti;
    proto_tree *monitoring_flags;

    if (obj_length < OBJ_HDR_LEN + OBJ_MONITORING_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad MONITORING object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN + OBJ_MONITORING_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_monitoring_reserved, tvb, offset2, 1, ENC_NA);
    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_obj_monitoring_flags, tvb, offset2+1, 3, ENC_BIG_ENDIAN);
    monitoring_flags = proto_item_add_subtree(ti, ett_pcep_obj_monitoring);
    proto_tree_add_item(monitoring_flags, hf_pcep_obj_monitoring_flags_reserved,       tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(monitoring_flags, hf_pcep_obj_monitoring_flags_i,              tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(monitoring_flags, hf_pcep_obj_monitoring_flags_c,              tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(monitoring_flags, hf_pcep_obj_monitoring_flags_p,              tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(monitoring_flags, hf_pcep_obj_monitoring_flags_g,              tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(monitoring_flags, hf_pcep_obj_monitoring_flags_l,              tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_monitoring_monitoring_id_number, tvb, offset2 + 4, 4, ENC_BIG_ENDIAN);

    /* The object can have optional TLV(s)*/
    offset2 += OBJ_MONITORING_MIN_LEN;
    obj_length -= OBJ_HDR_LEN + OBJ_MONITORING_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_monitoring);
}

/*------------------------------------------------------------------------------
 * PCC-ID-REQ OBJECT
 *------------------------------------------------------------------------------*/
#define OBJ_PCC_ID_REQ_IPV4_LEN   4
#define OBJ_PCC_ID_REQ_IPV6_LEN  16

static void
dissect_pcep_obj_pcc_id_req(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int type)
{
    switch (type)
    {
        case PCEP_OBJ_PCC_ID_REQ_IPv4:
            if (obj_length != OBJ_HDR_LEN + OBJ_PCC_ID_REQ_IPV4_LEN) {
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                             tvb, offset2, obj_length,
                                             "Bad IPv4 PCC-ID-REQ object length %u, should be %u",
                                             obj_length, OBJ_HDR_LEN + OBJ_PCC_ID_REQ_IPV4_LEN);
                return;
            }
            proto_tree_add_item(pcep_object_tree, hf_pcep_obj_pcc_id_req_ipv4, tvb, offset2, 4, ENC_BIG_ENDIAN);
            break;

        case PCEP_OBJ_PCC_ID_REQ_IPv6:
            if (obj_length != OBJ_HDR_LEN + OBJ_PCC_ID_REQ_IPV6_LEN) {
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                             tvb, offset2, obj_length,
                                             "Bad IPv6 PCC-ID-REQ object length %u, should be %u",
                                             obj_length, OBJ_HDR_LEN + OBJ_PCC_ID_REQ_IPV6_LEN);
                return;
            }
            proto_tree_add_item(pcep_object_tree, hf_pcep_obj_pcc_id_req_ipv6, tvb, offset2, 16, ENC_NA);
            break;

        default:
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_subobject,
                                         tvb, offset2, obj_length - OBJ_HDR_LEN,
                                         "UNKNOWN Type Object (%u)", type);
            break;
    }
}

/*------------------------------------------------------------------------------
 * OF OBJECT
 *------------------------------------------------------------------------------*/
#define OF_OBJ_MIN_LEN 4

static void
dissect_pcep_of_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    if (obj_length < OBJ_HDR_LEN+OF_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad OF object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+OF_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_of_code, tvb, offset2, 2, ENC_BIG_ENDIAN);

    /*The object can have optional TLV(s)*/
    offset2 += OPEN_OBJ_MIN_LEN;
    obj_length -= OBJ_HDR_LEN+OF_OBJ_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_open);
}

/*------------------------------------------------------------------------------
 * PCE-ID OBJECT
 *------------------------------------------------------------------------------*/
#define OBJ_PCE_ID_IPV4_LEN   4
#define OBJ_PCE_ID_IPV6_LEN  16

static void
dissect_pcep_obj_pce_id(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int type)
{
    switch (type)
    {
        case PCEP_OBJ_PCE_ID_IPv4:
            if (obj_length != OBJ_HDR_LEN + OBJ_PCE_ID_IPV4_LEN) {
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                             tvb, offset2, obj_length,
                                             "Bad IPv4 PCE-ID object length %u, should be %u",
                                             obj_length, OBJ_HDR_LEN + OBJ_PCE_ID_IPV4_LEN);
                return;
            }
            proto_tree_add_item(pcep_object_tree, hf_pcep_obj_pce_id_ipv4, tvb, offset2, 4, ENC_BIG_ENDIAN);
            break;

        case PCEP_OBJ_PCE_ID_IPv6:
            if (obj_length != OBJ_HDR_LEN + OBJ_PCE_ID_IPV6_LEN) {
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                             tvb, offset2, obj_length,
                                             "Bad IPv6 PCE-ID object length %u, should be %u",
                                             obj_length, OBJ_HDR_LEN + OBJ_PCE_ID_IPV6_LEN);
                return;
            }
            proto_tree_add_item(pcep_object_tree, hf_pcep_obj_pce_id_ipv6, tvb, offset2, 16, ENC_NA);
            break;

        default:
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_subobject,
                                         tvb, offset2, obj_length - OBJ_HDR_LEN,
                                         "UNKNOWN Type Object (%u)", type);
            break;
    }
}

/*------------------------------------------------------------------------------
 * PROC-TIME OBJECT
 *------------------------------------------------------------------------------*/
#define OBJ_PROC_TIME_LEN 24

static void
dissect_pcep_obj_proc_time(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    proto_item *ti;
    proto_tree *proc_time_flags;

    if (obj_length != OBJ_HDR_LEN + OBJ_PROC_TIME_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad PROC-TIME object length %u, should be %u",
                                     obj_length, OBJ_HDR_LEN + OBJ_PROC_TIME_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_proc_time_reserved, tvb, offset2, 2, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_obj_proc_time_flags, tvb, offset2 + 2, 2, ENC_BIG_ENDIAN);
    proc_time_flags = proto_item_add_subtree(ti, ett_pcep_obj_proc_time);
    proto_tree_add_item(proc_time_flags,  hf_pcep_obj_proc_time_flags_reserved, tvb, offset2 +  2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(proc_time_flags,  hf_pcep_obj_proc_time_flags_e,        tvb, offset2 +  2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_proc_time_cur_proc_time,  tvb, offset2 +  4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_proc_time_min_proc_time,  tvb, offset2 +  8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_proc_time_max_proc_time,  tvb, offset2 + 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_proc_time_ave_proc_time,  tvb, offset2 + 16, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_proc_time_var_proc_time,  tvb, offset2 + 20, 4, ENC_BIG_ENDIAN);
}

/*------------------------------------------------------------------------------
 * OVERLOAD OBJECT
 *------------------------------------------------------------------------------*/
#define OBJ_OVERLOAD_LEN 4

static void
dissect_pcep_obj_overload(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length)
{
    if (obj_length != OBJ_HDR_LEN + OBJ_OVERLOAD_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad OVERLOAD object length %u, should be %u",
                                     obj_length, OBJ_HDR_LEN + OBJ_OVERLOAD_LEN);
        return;
    }
    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_overload_flags,    tvb, offset2,     1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_overload_reserved, tvb, offset2 + 1, 1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_overload_duration, tvb, offset2 + 2, 2, ENC_BIG_ENDIAN);
}


/*------------------------------------------------------------------------------*/
/* Dissect in Objects */
/*------------------------------------------------------------------------------*/
static void
dissect_pcep_obj_tree(proto_tree *pcep_tree, packet_info *pinfo, tvbuff_t *tvb, int len, int offset, int msg_length)
{
    guint8      obj_class;
    guint8      ot_res_p_i;
    guint16     obj_length;
    int         type;
    proto_tree *pcep_object_tree;
    proto_item *pcep_object_item;
    proto_tree *pcep_header_obj_flags;
    proto_item *ti;

    while (len < msg_length) {
        obj_class = tvb_get_guint8(tvb, offset);
        switch (obj_class) {

            case PCEP_OPEN_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_OPEN, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_open);
                break;

            case PCEP_RP_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_RP, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_request_parameters);
                break;

            case PCEP_NO_PATH_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_NO_PATH, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_no_path);
                break;

            case PCEP_END_POINT_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_END_POINT, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_end_point);
                break;

            case PCEP_BANDWIDTH_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_BANDWIDTH, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_bandwidth);
                break;

            case PCEP_METRIC_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_METRIC, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_metric);
                break;

            case PCEP_EXPLICIT_ROUTE_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_EXPLICIT_ROUTE, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_explicit_route);
                break;

            case PCEP_RECORD_ROUTE_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_RECORD_ROUTE, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_record_route);
                break;

            case PCEP_LSPA_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_LSPA, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_lspa);
                break;

            case PCEP_IRO_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_IRO, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_iro);
                break;

            case PCEP_SVEC_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_SVEC, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_svec);
                break;

            case PCEP_NOTIFICATION_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_NOTIFICATION, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_notification);
                break;

            case PCEP_PCEP_ERROR_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_PCEP_ERROR, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_error);
                break;

            case PCEP_LOAD_BALANCING_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_LOAD_BALANCING, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_load_balancing);
                break;

            case PCEP_CLOSE_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_CLOSE, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_close);
                break;

            case PCEP_PATH_KEY_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_PATH_KEY, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_path_key);
                break;

            case PCEP_XRO_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_XRO, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_xro);
                break;

            case PCEP_OBJ_MONITORING:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_MONITORING, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_monitoring);
                break;

            case PCEP_OBJ_PCC_ID_REQ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_PCC_ID_REQ, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_pcc_id_req);
                break;

            case PCEP_OF_OBJ:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_OF, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_of);
                break;

            case PCEP_OBJ_PCE_ID:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_PCE_ID, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_pce_id);
                break;

            case PCEP_OBJ_PROC_TIME:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_PROC_TIME, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_proc_time);
                break;

            case PCEP_OBJ_OVERLOAD:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_OVERLOAD, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_overload);
                break;

            default:
                pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_UNKNOWN_TYPE, tvb, offset, -1, ENC_NA);
                pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_unknown);
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_object,
                                             tvb, offset, -1,
                                             "Unknown object (%u)", obj_class);
                break;
        }

        proto_tree_add_uint(pcep_object_tree, hf_PCEPF_OBJECT_CLASS, tvb, offset, 1, obj_class);
        proto_tree_add_item(pcep_object_tree, hf_pcep_object_type, tvb, offset+1, 1, ENC_NA);

        ot_res_p_i = tvb_get_guint8(tvb, offset+1);
        type = (ot_res_p_i & MASK_OBJ_TYPE)>>4;
        ti = proto_tree_add_text(pcep_object_tree, tvb, offset+1, 1, "Flags");
        pcep_header_obj_flags = proto_item_add_subtree(ti, ett_pcep_hdr);
        proto_tree_add_item(pcep_header_obj_flags, hf_pcep_hdr_obj_flags_reserved, tvb, offset+1, 1, ENC_NA);
        proto_tree_add_item(pcep_header_obj_flags, hf_pcep_hdr_obj_flags_p,        tvb, offset+1, 1, ENC_NA);
        proto_tree_add_item(pcep_header_obj_flags, hf_pcep_hdr_obj_flags_i,        tvb, offset+1, 1, ENC_NA);

        proto_tree_add_item(pcep_object_tree, hf_pcep_object_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);

        obj_length = tvb_get_ntohs(tvb, offset+2);
        proto_item_set_len(pcep_object_item, obj_length);
        if (obj_length < 4) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_object_length,
                                   "Object Length: %u (bogus, must be >= 4)", obj_length);
            break;
        }

        switch (obj_class) {

            case PCEP_OPEN_OBJ:
                dissect_pcep_open_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_RP_OBJ:
                dissect_pcep_rp_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_NO_PATH_OBJ:
                dissect_pcep_no_path_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_END_POINT_OBJ:
                dissect_pcep_end_point_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length, type);
                break;

            case PCEP_BANDWIDTH_OBJ:
                dissect_pcep_bandwidth_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_METRIC_OBJ:
                dissect_pcep_metric_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_EXPLICIT_ROUTE_OBJ:
                dissect_pcep_explicit_route_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length, obj_class);
                break;

            case PCEP_RECORD_ROUTE_OBJ:
                dissect_pcep_record_route_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length, obj_class);
                break;

            case PCEP_LSPA_OBJ:
                dissect_pcep_lspa_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_IRO_OBJ:
                dissect_pcep_iro_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length, obj_class);
                break;

            case PCEP_SVEC_OBJ:
                dissect_pcep_svec_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_NOTIFICATION_OBJ:
                dissect_pcep_notification_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_PCEP_ERROR_OBJ:
                dissect_pcep_error_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_LOAD_BALANCING_OBJ:
                dissect_pcep_balancing_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_CLOSE_OBJ:
                dissect_pcep_close_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_PATH_KEY_OBJ:
                dissect_pcep_path_key_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_XRO_OBJ:
                dissect_pcep_xro_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length, obj_class);
                break;

            case PCEP_OBJ_MONITORING:
                dissect_pcep_obj_monitoring(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_OBJ_PCC_ID_REQ:
                dissect_pcep_obj_pcc_id_req(pcep_object_tree, pinfo, tvb, offset+4, obj_length, type);
                break;

            case PCEP_OF_OBJ:
                dissect_pcep_of_obj(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_OBJ_PCE_ID:
                dissect_pcep_obj_pce_id(pcep_object_tree, pinfo, tvb, offset+4, obj_length, type);
                break;

            case PCEP_OBJ_PROC_TIME:
                dissect_pcep_obj_proc_time(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            case PCEP_OBJ_OVERLOAD:
                dissect_pcep_obj_overload(pcep_object_tree, pinfo, tvb, offset+4, obj_length);
                break;

            default:
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_pcep_object_body_non_defined,
                                             tvb, offset+4, obj_length-OBJ_HDR_LEN,
                                             "PCEP Object BODY non defined (%u)", type);
                break;
        }

        offset += obj_length;
        len    += obj_length;
    }
}


/*------------------------------------------------------------------------------
 * Dissect a single PCEP message in a tree
 *------------------------------------------------------------------------------*/
static void
dissect_pcep_msg_tree(tvbuff_t *tvb, proto_tree *tree, guint tree_mode, packet_info *pinfo)
{
    proto_tree *pcep_tree, *pcep_header_tree, *pcep_header_msg_flags;
    proto_item *ti;

    int         offset = 0;
    int         len    = 0;
    guint8      message_type;
    guint16     msg_length;

    message_type = tvb_get_guint8(tvb, 1);
    msg_length = tvb_get_ntohs(tvb, 2);

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(message_type, message_type_vals, "Unknown Message (%u). "));

    ti = proto_tree_add_item(tree, proto_pcep, tvb, offset, msg_length, ENC_NA);
    pcep_tree = proto_item_add_subtree(ti, tree_mode);

    ti = proto_tree_add_text(pcep_tree, tvb, offset, 4, "%s Header", val_to_str(message_type, message_type_vals, "Unknown Message (%u). "));
    pcep_header_tree = proto_item_add_subtree(ti, ett_pcep_hdr);

    proto_tree_add_item(pcep_header_tree, hf_pcep_version, tvb, offset, 1, ENC_NA);

    ti = proto_tree_add_item(pcep_header_tree, hf_pcep_flags, tvb, offset, 1, ENC_NA);
    pcep_header_msg_flags = proto_item_add_subtree(ti, ett_pcep_hdr);
    proto_tree_add_item(pcep_header_msg_flags, hf_pcep_hdr_msg_flags_reserved, tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_header_tree,      hf_PCEPF_MSG,                   tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(pcep_header_tree,      hf_pcep_message_length,         tvb, offset+2, 2, ENC_BIG_ENDIAN);

    offset = 4;
    len = 4;

    dissect_pcep_obj_tree(pcep_tree, pinfo, tvb, len, offset, msg_length);
}


static guint
get_pcep_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    guint16 plen;

    /* Get the length of the PCEP packet.*/
    plen = tvb_get_ntohs(tvb, offset+2);

    return plen;
}

static int
dissect_pcep_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

/* Set up structures needed to add the protocol subtree and manage it */

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCEP");

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    dissect_pcep_msg_tree(tvb, tree, ett_pcep, pinfo);
    return tvb_length(tvb);
}

static int
dissect_pcep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 4, get_pcep_message_len,
                     dissect_pcep_pdu, data);
    return tvb_length(tvb);
}

/*Register the protocol with wireshark*/
void
proto_register_pcep(void)
{
    static hf_register_info pcepf_info[] = {

        /* Message type number */
        { &hf_PCEPF_MSG,
          { "Message Type", "pcep.msg",
            FT_UINT8, BASE_DEC, VALS(message_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_hdr_msg_flags_reserved,
          { "Reserved Flags", "pcep.hdr.msg.flags.reserved",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_HDR_MSG_RESERVED,
            NULL, HFILL }
        },

        /*Object header*/
        { &hf_pcep_hdr_obj_flags_reserved,
          { "Reserved Flags", "pcep.hdr.obj.flags.reserved",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCEP_HDR_OBJ_RESERVED,
            NULL, HFILL }
        },
        { &hf_pcep_hdr_obj_flags_p,
          { "Processing-Rule (P)", "pcep.hdr.obj.flags.p",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCEP_HDR_OBJ_P,
            NULL, HFILL }
        },
        { &hf_pcep_hdr_obj_flags_i,
          { "Ignore (I)", "pcep.hdr.obj.flags.i",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCEP_HDR_OBJ_I,
            NULL, HFILL }
        },
        /* Object class */
        { &hf_PCEPF_OBJECT_CLASS,
          { "Object Class", "pcep.object",
            FT_UINT32, BASE_DEC | BASE_EXT_STRING, &pcep_class_vals_ext, 0x0,
            NULL, HFILL }
        },

        /* Object types */
        { &hf_PCEPF_OBJ_OPEN,
          { "OPEN object", "pcep.obj.open",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_open_flags_res,
          { "Reserved Flags", "pcep.open.flags.res",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_OPEN_RES,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_RP,
          { "RP object", "pcep.obj.rp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_reserved,
          { "Reserved Flags", "pcep.rp.flags.reserved",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_RESERVED,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_pri,
          { "(PRI) Priority", "pcep.rp.flags.pri",
            FT_BOOLEAN, 24, TFS(&tfs_on_off), PCEP_RP_PRI,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_r,
          { "(R) Reoptimization", "pcep.rp.flags.r",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_R,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_b,
          { "(B) Bi-directional", "pcep.rp.flags.b",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_B,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_o,
          { "(L) Strict/Loose", "pcep.rp.flags.o",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_O,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_v,
          { "(V) VSPT", "pcep.rp.flags.v",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_V,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_s,
          { "(S) Supply OF on response", "pcep.rp.flags.s",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_S,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_p,
          { "(P) Path Key", "pcep.rp.flags.p",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_P,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_d,
          { "(D) Report the request order", "pcep.rp.flags.d",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_D,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_m,
          { "(M) Make-before-break", "pcep.rp.flags.m",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_M,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_e,
          { "(E) ERO-compression", "pcep.rp.flags.e",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_E,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_n,
          { "(N) P2MP", "pcep.rp.flags.n",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_N,
            NULL, HFILL }
        },
        { &hf_pcep_rp_flags_f,
          { "(F) Fragmentation", "pcep.rp.flags.f",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_F,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_NO_PATH,
          { "NO-PATH object", "pcep.obj.nopath",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_flags_c,
          { "C", "pcep.no.path.flags.c",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_NO_PATH_C,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_END_POINT,
          { "END-POINT object", "pcep.obj.endpoint",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_BANDWIDTH,
          { "BANDWIDTH object", "pcep.obj.bandwidth",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_METRIC,
          { "METRIC object", "pcep.obj.metric",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_metric_flags_c,
          { "(C) Cost", "pcep.metric.flags.c",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_METRIC_C,
            NULL, HFILL }
        },
        { &hf_pcep_metric_flags_b,
          { "(B) Bound", "pcep.metric.flags.b",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_METRIC_B,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_EXPLICIT_ROUTE,
          { "EXPLICIT ROUTE object (ERO)", "pcep.obj.ero",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_RECORD_ROUTE,
          { "RECORD ROUTE object (RRO)", "pcep.obj.rro",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_LSPA,
          { "LSPA object", "pcep.obj.lspa",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_lspa_flags_l,
          { "Local Protection Desired (L)", "pcep.lspa.flags.l",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_LSPA_L,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_IRO,
          { "IRO object", "pcep.obj.iro",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_SVEC,
          { "SVEC object", "pcep.obj.svec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pcep_svec_flags_l,
          { "Link diverse (L)", "pcep.svec.flags.l",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_SVEC_L,
            NULL, HFILL }
        },

        { &hf_pcep_svec_flags_n,
          { "Node diverse (N)", "pcep.svec.flags.n",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_SVEC_N,
            NULL, HFILL }
        },

        { &hf_pcep_svec_flags_s,
          { "SRLG diverse (S)", "pcep.svec.flags.s",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_SVEC_S,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_NOTIFICATION,
          { "NOTIFICATION object", "pcep.obj.notification",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_NOTI_TYPE,
          { "Notification Value", "pcep.notification.value1",
            FT_UINT32, BASE_DEC, VALS(pcep_notification_types_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_NOTI_VAL1,
          { "Notification Type", "pcep.notification.type2",
            FT_UINT32, BASE_DEC, VALS(pcep_notification_values1_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_NOTI_VAL2,
          { "Notification Type", "pcep.notification.type",
            FT_UINT32, BASE_DEC, VALS(pcep_notification_values2_vals), 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_PCEP_ERROR,
          { "ERROR object", "pcep.obj.error",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_ERROR_TYPE,
          { "Error-Type", "pcep.error.type",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &pcep_error_types_obj_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_LOAD_BALANCING,
          { "LOAD BALANCING object", "pcep.obj.loadbalancing",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_CLOSE,
          { "CLOSE object", "pcep.obj.close",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_PATH_KEY,
          { "PATH-KEY object", "pcep.obj.path_key",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_XRO,
          { "EXCLUDE ROUTE object (XRO)", "pcep.obj.xro",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_MONITORING,
          { "MONITORING object", "pcep.obj.monitoring",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_monitoring_flags_reserved,
          { "Reserved Flags", "pcep.obj.monitoring.flags.reserved",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_OBJ_MONITORING_FLAGS_RESERVED,
            NULL, HFILL }
        },
        { &hf_pcep_obj_monitoring_flags_l,
          { "Liveness (L)", "pcep.obj.monitoring.flags.l",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_OBJ_MONITORING_FLAGS_L,
            NULL, HFILL }
        },
        { &hf_pcep_obj_monitoring_flags_g,
          { "General (G)", "pcep.obj.monitoring.flags.g",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_OBJ_MONITORING_FLAGS_G,
            NULL, HFILL }
        },
        { &hf_pcep_obj_monitoring_flags_p,
          { "Processing Time (P)", "pcep.obj.monitoring.flags.p",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_OBJ_MONITORING_FLAGS_P,
            NULL, HFILL }
        },
        { &hf_pcep_obj_monitoring_flags_c,
          { "Overload (C)", "pcep.obj.monitoring.flags.c",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_OBJ_MONITORING_FLAGS_C,
            NULL, HFILL }
        },
        { &hf_pcep_obj_monitoring_flags_i,
          { "Incomplete (I)", "pcep.obj.monitoring.flags.i",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_OBJ_MONITORING_FLAGS_I,
            NULL, HFILL }
        },
        { &hf_pcep_obj_monitoring_monitoring_id_number,
          { "Monitoring ID Number", "pcep.obj.monitoring.monidnumber",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_PCC_ID_REQ,
          { "PCC-ID-REQ object", "pcep.obj.pccidreq",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_pcc_id_req_ipv4,
          { "IPv4 address", "pcep.obj.pccidreq.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_pcc_id_req_ipv6,
          { "IPv6 address", "pcep.obj.pccidreq.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_OF,
          { "OBJECTIVE FUNCTION object (OF)", "pcep.obj.of",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_PCE_ID,
          { "PCE-ID object", "pcep.obj.pceid",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_pce_id_ipv4,
          { "IPv4 address", "pcep.obj.pceid.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_pce_id_ipv6,
          { "IPv6 address", "pcep.obj.pceid.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_PROC_TIME,
          { "PROC-TIME object", "pcep.obj.proctime",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_proc_time_flags_reserved,
          { "Reserved Flags", "pcep.obj.proctime.flags.reserved",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_OBJ_PROC_TIME_FLAGS_RESERVED,
            NULL, HFILL }
        },
        { &hf_pcep_obj_proc_time_flags_e,
          { "Estimated (E)", "pcep.obj.proctime.flags.e",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_OBJ_PROC_TIME_FLAGS_E,
            NULL, HFILL }
        },
        { &hf_pcep_obj_proc_time_cur_proc_time,
          { "Current processing time", "pcep.obj.proctime.curproctime",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_proc_time_min_proc_time,
          { "Minimum processing time", "pcep.obj.proctime.minproctime",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_proc_time_max_proc_time,
          { "Maximum processing time", "pcep.obj.proctime.maxproctime",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_proc_time_ave_proc_time,
          { "Average processing time", "pcep.obj.proctime.aveproctime",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_proc_time_var_proc_time,
          { "Variance processing time", "pcep.obj.proctime.varproctime",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_OVERLOAD,
          { "OVERLOAD object", "pcep.obj.overload",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_overload_duration,
          { "Overload Duration", "pcep.obj.overload.duration",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_UNKNOWN_TYPE,
          { "Unknown object", "pcep.obj.unknown",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /*Subobjects*/
        { &hf_PCEPF_SUBOBJ,
          { "Type", "pcep.subobj",
            FT_UINT8, BASE_DEC, VALS(pcep_subobj_vals), 0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_7F,
          { "Type", "pcep.subobj",
            FT_UINT8, BASE_DEC, VALS(pcep_subobj_vals), 0x7F,
            NULL, HFILL }
        },

        { &hf_PCEPF_SUBOBJ_IPv4,
          { "SUBOBJECT: IPv4 Prefix", "pcep.subobj.ipv4",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_IPv6,
          { "SUBOBJECT: IPv6 Prefix", "pcep.subobj.ipv6",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_LABEL_CONTROL,
          { "SUBOBJECT: Label Control", "pcep.subobj.label.control",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_UNNUM_INTERFACEID,
          { "SUBOBJECT: Unnumbered Interface ID", "pcep.subobj.unnum.interfaceid",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_AUTONOMOUS_SYS_NUM,
          { "SUBOBJECT: Autonomous System Number", "pcep.subobj.autonomous.sys.num",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_SRLG,
          { "SUBOBJECT: SRLG", "pcep.subobj.srlg",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_EXRS,
          { "SUBOBJECT: EXRS", "pcep.subobj.exrs",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_PKSv4,
          { "SUBOBJECT: Path Key (IPv4)", "pcep.subobj.path_key.ipv4",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_PKSv6,
          { "SUBOBJECT: Path Key (IPv6)", "pcep.subobj.path_key.ipv6",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_XRO,
          { "Type", "pcep.subobj.label",
            FT_UINT32, BASE_DEC, VALS(pcep_subobj_xro_vals), 0x7F,
            NULL, HFILL }
        },
        { &hf_pcep_xro_flags_f,
          { "Fail (F)", "pcep.xro.flags.f",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_XRO_F,
            NULL, HFILL }
        },
#if 0
        { &hf_PCEPF_SUB_XRO_ATTRIB,
          { "Attribute", "pcep.xro.sub.attribute",
            FT_UINT32, BASE_DEC, VALS(pcep_xro_attribute_obj_vals), 0x0,
            NULL, HFILL }
        },
#endif
        { &pcep_subobj_flags_lpa,
          { "Local Protection Available", "pcep.subobj.flags.lpa",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_SUB_LPA,
            NULL, HFILL }
        },
        { &pcep_subobj_flags_lpu,
          { "Local protection in Use", "pcep.subobj.flags.lpu",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_SUB_LPU,
            NULL, HFILL }
        },

        { &pcep_subobj_label_flags_gl,
          { "Global Label", "pcep.subobj.label.flags.gl",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_SUB_LABEL_GL,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_pce,
          { "PCE currently unavailable", "pcep.no_path_tlvs.pce",
            FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0001,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_unk_dest,
          { "Unknown destination", "pcep.no_path_tlvs.unk_dest",
            FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0002,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_unk_src,
          { "Unknown source", "pcep.no_path_tlvs.unk_src",
            FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x0004,
            NULL, HFILL }
        },

        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_pcep_tlv_type,
          { "Type", "pcep.tlv.type",
            FT_UINT16, BASE_DEC, VALS(pcep_tlvs_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_tlv_length,
          { "Length", "pcep.tlv.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_request_id,
          { "Request-ID", "pcep.request_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_tlv_data,
          { "Data", "pcep.tlv.data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_tlv_padding,
          { "Padding", "pcep.tlv.padding",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv4_length,
          { "Length", "pcep.subobj.ipv4.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv4_ipv4,
          { "IPv4 Address", "pcep.subobj.ipv4.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv4_prefix_length,
          { "Prefix Length", "pcep.subobj.ipv4.prefix_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv4_padding,
          { "Padding", "pcep.subobj.ipv4.padding",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv4_flags,
          { "Flags", "pcep.subobj.ipv4.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv4_attribute,
          { "Attribute", "pcep.subobj.ipv4.attribute",
            FT_UINT8, BASE_DEC, VALS(pcep_xro_attribute_obj_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv6_length,
          { "Length", "pcep.subobj.ipv6.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv6_ipv6,
          { "IPv6 Address", "pcep.subobj.ipv6.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv6_prefix_length,
          { "Prefix Length", "pcep.subobj.ipv6.prefix_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv6_padding,
          { "Padding", "pcep.subobj.ipv6.padding",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv6_flags,
          { "Flags", "pcep.subobj.ipv6.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv6_attribute,
          { "Attribute", "pcep.attribute",
            FT_UINT8, BASE_DEC, VALS(pcep_xro_attribute_obj_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_label_control_length,
          { "Length", "pcep.subobj.label_control.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_label_control_u,
          { "U", "pcep.subobj.label_control.u",
            FT_UINT8, BASE_DEC, VALS(pcep_route_u_obj_vals), 0x80,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_label_control_reserved,
          { "Reserved", "pcep.subobj.label_control.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_label_control_c_type,
          { "C-Type", "pcep.subobj.label_control.c_type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_label_control_label,
          { "Label", "pcep.subobj.label_control.label",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_label_control_flags,
          { "Flags", "pcep.subobj.label_control.flags",
            FT_UINT8, BASE_HEX, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_unnumb_interfaceID_length,
          { "Length", "pcep.subobj.unnumb_interfaceID.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_unnumb_interfaceID_reserved,
          { "Reserved", "pcep.subobj.unnumb_interfaceID.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_unnumb_interfaceID_flags,
          { "Flags", "pcep.subobj.unnumb_interfaceID.flags",
            FT_UINT16, BASE_HEX, NULL, 0xFF00,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_unnumb_interfaceID_reserved_rrobj,
          { "Reserved", "pcep.subobj.unnumb_interfaceID.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x00FF,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_unnumb_interfaceID_reserved_xroobj,
          { "Reserved", "pcep.subobj.unnumb_interfaceID.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_unnumb_interfaceID_attribute,
          { "Attribute", "pcep.subobj.unnumb_interfaceID.attribute",
            FT_UINT8, BASE_DEC, VALS(pcep_xro_attribute_obj_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_unnumb_interfaceID_router_id,
          { "Router ID", "pcep.subobj.unnumb_interfaceID.router_id",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_unnumb_interfaceID_interface_id,
          { "Interface ID", "pcep.subobj.unnumb_interfaceID.interface_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_autonomous_sys_num_length,
          { "Length", "pcep.subobj.autonomous_sys_num.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_autonomous_sys_num_reserved,
          { "Reserved", "pcep.subobj.autonomous_sys_num.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_autonomous_sys_num_attribute,
          { "Attribute", "pcep.subobj.autonomous_sys_num.attribute",
            FT_UINT8, BASE_DEC, VALS(pcep_xro_attribute_obj_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_autonomous_sys_num_optional_as_number_high_octets,
          { "Optional AS Number High Octets", "pcep.subobj.autonomous_sys_num.optional_as_number_high_octets",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_autonomous_sys_num_as_number,
          { "AS Number", "pcep.subobj.autonomous_sys_num.as_number",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srlg_length,
          { "Length", "pcep.subobj.srlg.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srlg_id,
          { "SRLG ID", "pcep.subobj.srlg.id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srlg_reserved,
          { "Reserved", "pcep.subobj.srlg.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srlg_attribute,
          { "Attribute", "pcep.subobj.srlg.attribute",
            FT_UINT8, BASE_DEC, VALS(pcep_xro_attribute_obj_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_exrs_length,
          { "Length", "pcep.subobj.exrs.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_exrs_reserved,
          { "Reserved", "pcep.subobj.exrs.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_pksv4_length,
          { "Length", "pcep.subobj.pksv4.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_pksv4_path_key,
          { "Path Key", "pcep.subobj.pksv4.path_key",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_pksv4_pce_id,
          { "PCE ID", "pcep.subobj.pksv4.pce_id",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_pksv6_length,
          { "Length", "pcep.subobj.pksv6.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_pksv6_path_key,
          { "Path Key", "pcep.subobj.pksv6.path_key",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_pksv6_pce_id,
          { "PCE ID", "pcep.subobj.pksv6.pce_id",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_open_obj_pcep_version,
          { "PCEP Version", "pcep.obj.open.pcep_version",
            FT_UINT8, BASE_DEC, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_pcep_open_obj_flags,
          { "Flags", "pcep.obj.open.flags",
            FT_UINT8, BASE_HEX, NULL, 0x1F,
            NULL, HFILL }
        },
        { &hf_pcep_open_obj_keepalive,
          { "Keepalive", "pcep.obj.open.keepalive",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_open_obj_deadtime,
          { "Deadtime", "pcep.obj.open.deadtime",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_open_obj_sid,
          { "SID", "pcep.obj.open.sid",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_rp_obj_reserved,
          { "Reserved", "pcep.obj.rp.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_rp_obj_flags,
          { "Flags", "pcep.obj.rp.flags",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_rp_obj_requested_id_number,
          { "Requested ID Number", "pcep.obj.rp.requested_id_number",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_obj_flags,
          { "Flags", "pcep.obj.no_path.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_obj_reserved,
          { "Reserved", "pcep.obj.no_path.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_end_point_obj_source_ipv4_address,
          { "Source IPv4 Address", "pcep.obj.end_point.source_ipv4_address",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_end_point_obj_destination_ipv4_address,
          { "Destination IPv4 Address", "pcep.obj.end_point.destination_ipv4_address",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_end_point_obj_source_ipv6_address,
          { "Source IPv6 Address", "pcep.obj.end_point.source_ipv6_address",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_end_point_obj_destination_ipv6_address,
          { "Destination IPv6 Address", "pcep.obj.end_point.destination_ipv6_address",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_bandwidth,
          { "Bandwidth", "pcep.bandwidth",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_metric_obj_reserved,
          { "Reserved", "pcep.obj.metric.reserved",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_metric_obj_flags,
          { "Flags", "pcep.obj.metric.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_metric_obj_type,
          { "Type", "pcep.obj.metric.type",
            FT_UINT8, BASE_DEC, VALS(pcep_metric_obj_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_metric_obj_metric_value,
          { "Metric Value", "pcep.obj.metric.metric_value",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_lspa_obj_exclude_any,
          { "Exclude-Any", "pcep.obj.lspa.exclude_any",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_lspa_obj_include_any,
          { "Include-Any", "pcep.obj.lspa.include_any",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_lspa_obj_include_all,
          { "Include-All", "pcep.obj.lspa.include_all",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_lspa_obj_setup_priority,
          { "Setup Priority", "pcep.obj.lspa.setup_priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_lspa_obj_holding_priority,
          { "Holding Priority", "pcep.obj.lspa.holding_priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_lspa_obj_flags,
          { "Flags", "pcep.obj.lspa.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_lspa_obj_reserved,
          { "Reserved", "pcep.obj.lspa.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_svec_obj_reserved,
          { "Reserved", "pcep.obj.svec.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_svec_obj_flags,
          { "Flags", "pcep.obj.svec.flags",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_svec_obj_request_id_number,
          { "Request-ID-Number", "pcep.obj.svec.request_id_number",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_notification_obj_reserved,
          { "Reserved", "pcep.obj.notification.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_notification_obj_flags,
          { "Flags", "pcep.obj.notification.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_notification_obj_type,
          { "Notification Type", "pcep.obj.notification.type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_notification_obj_value,
          { "Notification Value", "pcep.obj.notification.value",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_error_obj_reserved,
          { "Reserved", "pcep.obj.error.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_error_obj_flags,
          { "Flags", "pcep.obj.error.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_balancing_obj_reserved,
          { "Reserved", "pcep.obj.balancing.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_balancing_obj_flags,
          { "Flags", "pcep.obj.balancing.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_balancing_obj_maximum_number_of_te_lsps,
          { "Maximum Number of TE LSPs", "pcep.obj.balancing.maximum_number_of_te_lsps",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_balancing_obj_minimum_bandwidth,
          { "Minimum Bandwidth", "pcep.obj.balancing.minimum_bandwidth",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_close_obj_reserved,
          { "Reserved", "pcep.obj.close.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_close_obj_flags,
          { "Flags", "pcep.obj.close.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_close_obj_reason,
          { "Reason", "pcep.obj.close.reason",
            FT_UINT8, BASE_DEC, VALS(pcep_close_reason_obj_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_xro_obj_reserved,
          { "Reserved", "pcep.obj.xro.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_xro_obj_flags,
          { "Flags", "pcep.obj.xro.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_monitoring_reserved,
          { "Reserved", "pcep.obj.monitoring.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_monitoring_flags,
          { "Flags", "pcep.obj.monitoring.flags",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_of_code,
          { "OF-Code", "pcep.obj.of.code",
            FT_UINT16, BASE_DEC, VALS(pcep_of_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_proc_time_reserved,
          { "Reserved", "pcep.obj.proc_time.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_proc_time_flags,
          { "Flags", "pcep.obj.proc_time.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_overload_flags,
          { "Flags", "pcep.obj.overload.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_overload_reserved,
          { "Reserved", "pcep.obj.overload.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_object_type,
          { "Object Type", "pcep.object_type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },
        { &hf_pcep_object_length,
          { "Object Length", "pcep.object_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_version,
          { "PCEP Version", "pcep.version",
            FT_UINT8, BASE_HEX, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_pcep_flags,
          { "Flags", "pcep.flags",
            FT_UINT8, BASE_HEX, NULL, 0x1F,
            NULL, HFILL }
        },
        { &hf_pcep_message_length,
          { "Message length", "pcep.msg_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_of_code,
          { "OF-Code", "pcep.of_code",
            FT_UINT16, BASE_DEC, VALS(pcep_of_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv4_l,
          { "L", "pcep.subobj.ipv4.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_iro_ipv4_l,
          { "L", "pcep.iro.subobj.ipv4.l",
            FT_UINT8, BASE_HEX, NULL, Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv4_x,
          { "X", "pcep.subobj.ipv4.x",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv6_l,
          { "L", "pcep.subobj.ipv6.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_iro_ipv6_l,
          { "L", "pcep.iro.subobj.ipv6.l",
            FT_UINT8, BASE_HEX, NULL, Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_ipv6_x,
          { "X", "pcep.subobj.ipv6.x",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_label_control_l,
          { "L", "pcep.subobj.label_control.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_unnumb_interfaceID_l,
          { "L", "pcep.subobj.unnumb_interfaceID.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_iro_unnumb_interfaceID_l,
          { "L", "pcep.iro.subobj.unnumb_interfaceID.l",
            FT_UINT8, BASE_HEX, NULL, Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_unnumb_interfaceID_x,
          { "X", "pcep.subobj.unnumb_interfaceID.x",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_autonomous_sys_num_x,
          { "X", "pcep.subobj.autonomous_sys_num.x",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_iro_autonomous_sys_num_l,
          { "L", "pcep.iro.subobj.autonomous_sys_num.l",
            FT_UINT8, BASE_HEX, NULL, Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_autonomous_sys_num_l,
          { "L", "pcep.subobj.autonomous_sys_num.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srlg_x,
          { "X", "pcep.subobj.srlg.x",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_exrs_l,
          { "L", "pcep.subobj.exrs.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_exrs_type,
          { "Type", "pcep.subobj.exrs.type",
            FT_UINT8, BASE_DEC, NULL, 0x7F,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_pksv4_l,
          { "L", "pcep.subobj.pksv4.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_pksv6_l,
          { "L", "pcep.subobj.pksv6.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_obj_nature_of_issue,
          { "Nature of Issue", "pcep.obj.no_path.nature_of_issue",
            FT_UINT8, BASE_DEC, VALS(pcep_no_path_obj_vals), 0x0,
            NULL, HFILL }
        },

    };

    static gint *ett[] = {
        &ett_pcep,
        &ett_pcep_hdr,
        &ett_pcep_obj_open,
        &ett_pcep_obj_request_parameters,
        &ett_pcep_obj_no_path,
        &ett_pcep_obj_end_point,
        &ett_pcep_obj_bandwidth,
        &ett_pcep_obj_metric,
        &ett_pcep_obj_explicit_route,
        &ett_pcep_obj_record_route,
        &ett_pcep_obj_lspa,
        &ett_pcep_obj_iro,
        &ett_pcep_obj_svec,
        &ett_pcep_obj_notification,
        &ett_pcep_obj_error,
        &ett_pcep_obj_load_balancing,
        &ett_pcep_obj_close,
        &ett_pcep_obj_path_key,
        &ett_pcep_obj_xro,
        &ett_pcep_obj_monitoring,
        &ett_pcep_obj_pcc_id_req,
        &ett_pcep_obj_of,
        &ett_pcep_obj_pce_id,
        &ett_pcep_obj_proc_time,
        &ett_pcep_obj_overload,
        &ett_pcep_obj_unknown
    };

    static ei_register_info ei[] = {
        /* Generated from convert_proto_tree_add_text.pl */
        { &ei_pcep_subobject_bad_length, { "pcep.subobject_bad_length", PI_MALFORMED, PI_WARN, "Bad subobject length", EXPFILL }},
        { &ei_pcep_non_defined_subobject, { "pcep.non_defined_subobject", PI_PROTOCOL, PI_WARN, "Non defined subobject for this object", EXPFILL }},
        { &ei_pcep_non_defined_object, { "pcep.unknown_object", PI_PROTOCOL, PI_WARN, "Unknown object", EXPFILL }},
        { &ei_pcep_object_length, { "pcep.object_length.bad", PI_MALFORMED, PI_WARN, "Object Length bogus", EXPFILL }},
        { &ei_pcep_pcep_object_body_non_defined, { "pcep.object_body_non_defined", PI_PROTOCOL, PI_WARN, "PCEP Object BODY non defined", EXPFILL }},
        { &ei_pcep_unknown_type_object, { "pcep.unknown_type_object", PI_PROTOCOL, PI_WARN, "UNKNOWN Type Object", EXPFILL }},
    };

    expert_module_t* expert_pcep;

    /*Register the protocol name and description*/
    proto_pcep = proto_register_protocol (
        "Path Computation Element communication Protocol", "PCEP", "pcep");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_pcep, pcepf_info, array_length(pcepf_info));
    proto_register_subtree_array(ett, array_length(ett));
    expert_pcep = expert_register_protocol(proto_pcep);
    expert_register_field_array(expert_pcep, ei, array_length(ei));
}

/*Dissector Handoff*/
void
proto_reg_handoff_pcep(void)
{
    dissector_handle_t pcep_handle;

    pcep_handle = new_create_dissector_handle(dissect_pcep, proto_pcep);
    dissector_add_uint("tcp.port", TCP_PORT_PCEP, pcep_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
