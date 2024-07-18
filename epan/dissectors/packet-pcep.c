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
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Added support of "A Set of Monitoring Tools for Path Computation Element
 * (PCE)-Based Architecture" (RFC 5886)
 * (c) Copyright 2012 Svetoslav Duhovnikov <duhovnikov[AT]gmail.com>
 *
 * Added support of "PCEP Extensions for Stateful PCE"
 *  (draft-ietf-pce-stateful-pce-09) and
 * "PCEP Extensions for PCE-initiated LSP Setup in a Stateful PCE Model"
 *  (draft-ietf-pce-pce-initiated-lsp-01) and
 * "Optimizations of Label Switched Path State Synchronization Procedures for a Stateful PCE"
 *  (draft-ietf-pce-stateful-sync-optimizations-01)
 * (c) Copyright 2014 Simon Zhong <szhong[AT]juniper.net>
 *
 * Added support of "PCEP Extensions for Segment Routing"
 *  (draft-ietf-pce-segment-routing-03) and
 * "Conveying path setup type in PCEP messages"
 *  (draft-ietf-pce-lsp-setup-type-02)
 * (c) Copyright 2015 Francesco Fondelli <francesco.fondelli[AT]gmail.com>
 *
 * Added support of "Extensions to the Path Computation Element Communication Protocol (PCEP)
 * for Point-to-Multipoint Traffic Engineering Label Switched Paths" (RFC 6006)
 * (c) Copyright 2015 Francesco Paolucci <fr.paolucci[AT].sssup.it>,
 * Oscar Gonzalez de Dios <oscar.gonzalezdedios@telefonica.com>,
 * ICT EU PACE Project, www.ict-pace.net
 *
 * Added support of "PCEP Extensions for Establishing Relationships
 * Between Sets of LSPs" (draft-ietf-pce-association-group-00)
 * (c) Copyright 2015 Francesco Fondelli <francesco.fondelli[AT]gmail.com>
 *
 * Added support of "Conveying Vendor-Specific Constraints in the
 *  Path Computation Element Communication Protocol" (RFC 7470)
 * Completed support of RFC 6006
 * Added support of "PCE-Based Computation Procedure to Compute Shortest
    Constrained Point-to-Multipoint (P2MP) Inter-Domain Traffic Engineering
    Label Switched Paths" (RFC 7334)
 * (c) Copyright 2016 Simon Zhong <szhong[AT]juniper.net>
 *
 * Added support of "Extensions to the Path Computation Element Communication Protocol (PCEP)
 *  to compute service aware Label Switched Path (LSP)." (draft-ietf-pce-pcep-service-aware-13)
 * Updated support of "PCEP Extensions for Segment Routing" (draft-ietf-pce-segment-routing-08)
 * (c) Copyright 2017 Simon Zhong <szhong[AT]juniper.net>
 * Updated support from draft-ietf-pce-segment-routing-08 to RFC 8664  "PCEP Extensions for Segment Routing"
 * Added support of draft-ietf-pce-segment-routing-policy-cp-05 "PCEP extension to support Segment Routing Policy Candidate Paths"
 * (c) Copyright 2021 Oscar Gonzalez de Dios <oscar.gonzalezdedios[AT]telefonica.com>
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/addr_resolv.h>
#include "packet-tcp.h"

void proto_register_pcep(void);
void proto_reg_handoff_pcep(void);

static dissector_handle_t pcep_handle;

/* Object-Class */
#define PCEP_OPEN_OBJ                    1 /* RFC 5440 */
#define PCEP_RP_OBJ                      2 /* RFC 5440 */
#define PCEP_NO_PATH_OBJ                 3 /* RFC 5440 */
#define PCEP_END_POINT_OBJ               4 /* RFC 5440, XXX extended by RFC 8306 */
#define PCEP_BANDWIDTH_OBJ               5 /* RFC 5440 */
#define PCEP_METRIC_OBJ                  6 /* RFC 5440 */
#define PCEP_EXPLICIT_ROUTE_OBJ          7 /* RFC 5440 */
#define PCEP_RECORD_ROUTE_OBJ            8 /* RFC 5440 */
#define PCEP_LSPA_OBJ                    9 /* RFC 5440 */
#define PCEP_IRO_OBJ                    10 /* RFC 5440 */
#define PCEP_SVEC_OBJ                   11 /* RFC 5440 */
#define PCEP_NOTIFICATION_OBJ           12 /* RFC 5440 */
#define PCEP_PCEP_ERROR_OBJ             13 /* RFC 5440 */
#define PCEP_LOAD_BALANCING_OBJ         14 /* RFC 5440 */
#define PCEP_CLOSE_OBJ                  15 /* RFC 5440 */
#define PCEP_PATH_KEY_OBJ               16 /* RFC 5520 */
#define PCEP_XRO_OBJ                    17 /* RFC 5521 */
/* 18 is unassigned */
#define PCEP_OBJ_MONITORING             19 /* RFC 5886 */
#define PCEP_OBJ_PCC_ID_REQ             20 /* RFC 5886 */
#define PCEP_OF_OBJ                     21 /* RFC 5541 */
#define PCEP_CLASSTYPE_OBJ              22 /* RFC 5455 */
/* 23 is unassigned */
#define PCEP_GLOBAL_CONSTRAINTS_OBJ     24 /* RFC 5557 */
#define PCEP_OBJ_PCE_ID                 25 /* RFC 5886 */
#define PCEP_OBJ_PROC_TIME              26 /* RFC 5886 */
#define PCEP_OBJ_OVERLOAD               27 /* RFC 5886 */
#define PCEP_OBJ_UNREACH_DESTINATION    28 /* RFC 6006 */
#define PCEP_SERO_OBJ                   29 /* RFC 8306 */
#define PCEP_SRRO_OBJ                   30 /* RFC 8306 */
#define PCEP_OBJ_BRANCH_NODE_CAPABILITY 31 /* RFC 6006 XXX RFC 8306 */
#define PCEP_OBJ_LSP                    32 /* RFC 8231 */
#define PCEP_OBJ_SRP                    33 /* RFC 8231 */
#define PCEP_OBJ_VENDOR_INFORMATION     34 /* RFC 7470 */
#define PCEP_OBJ_BU                     35 /* draft-ietf-pce-pcep-service-aware XXX RFC 8233 */
#define PCEP_INTER_LAYER_OBJ            36 /* RFC 8282 */
#define PCEP_SWITCH_LAYER_OBJ           37 /* RFC 8282 */
#define PCEP_REQ_ADAP_CAP_OBJ           38 /* RFC 8282 */
#define PCEP_SERVER_IND_OBJ             39 /* RFC 8282 */
#define PCEP_ASSOCIATION_OBJ            40 /* RFC 8697 */
#define PCEP_S2LS_OBJ                   41 /* RFC 8623 */
#define PCEP_WA_OBJ                     42 /* RFC 8780 */
#define PCEP_FLOWSPEC_OBJ               43 /* RFC 9168 */
#define PCEP_CCI_TYPE_OBJ               44 /* RFC 9050 */
#define PCEP_PATH_ATTRIB_OBJ            45 /* draft-ietf-pce-multipath-05 */

/*Subobjects of EXPLICIT ROUTE Object*/
#define PCEP_SUB_IPv4                    1
#define PCEP_SUB_IPv6                    2
#define PCEP_SUB_LABEL_CONTROL           3
#define PCEP_SUB_UNNUMB_INTERFACE_ID     4
#define PCEP_SUB_SR_PRE_IANA             5 /* squatted, pre IANA assignment */
#define PCEP_SUB_AUTONOMOUS_SYS_NUM     32
#define PCEP_SUB_EXRS                   33
#define PCEP_SUB_SRLG                   34
#define PCEP_SUB_SR                     36 /* IANA assigned code point */
#define PCEP_SUB_SRv6                   40
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
#define INVALID_OPERATION               19
#define LSP_STATE_SYNCHRONIZATION_ERROR 20
#define INVALID_PATH_SETUP_TYPE         21
#define BAD_PARAMETER_VALUE             23
#define LSP_INSTANTIATION_ERROR         24
#define PCEP_STARTTLS_ERROR             25
#define ASSOCIATION_ERROR               26
#define WSON_RWA_ERROR                  27
#define H_PCE_ERROR                     28
#define PATH_COMPUTATION_FAILURE        29
#define FLOWSPEC_ERROR                  30
#define PCECC_FAILURE                   31

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
#define  PCEP_HDR_OBJ_RESERVED          0xC
#define  PCEP_HDR_OBJ_P                 0x2
#define  PCEP_HDR_OBJ_I                 0x1

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
#define  PCEP_RP_C                      0x004000    /* RFC 7334 */
#define  PCEP_RP_RESERVED               0xFF8000

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

/*RFC 6006*/
#define IPv4_P2MP                       3
#define IPv6_P2MP                       4
/*RFC 6006 - End Points Leaf Types */
#define EP_P2MP_NEW_LEAF_TYPE           1
#define EP_P2MP_OLD_REMOVE_LEAF_TYPE    2
#define EP_P2MP_OLD_MODIFY_LEAF_TYPE    3
#define EP_P2MP_OLD_UNCHANGED_LEAF_TYPE 4

/*Mask for the flags os SVEC Object*/
#define  PCEP_SVEC_L                    0x000001
#define  PCEP_SVEC_N                    0x000002
#define  PCEP_SVEC_S                    0x000004
#define  PCEP_SVEC_D                    0x000008
#define  PCEP_SVEC_P                    0x000010

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

/* Mask for the flags of LSP Object */
#define PCEP_OBJ_LSP_PLSP_ID            0xFFFFF0
#define PCEP_OBJ_LSP_FLAGS_D            0x0001
#define PCEP_OBJ_LSP_FLAGS_S            0x0002
#define PCEP_OBJ_LSP_FLAGS_R            0x0004
#define PCEP_OBJ_LSP_FLAGS_A            0x0008
#define PCEP_OBJ_LSP_FLAGS_O            0x0070
#define PCEP_OBJ_LSP_FLAGS_C            0x0080
#define PCEP_OBJ_LSP_FLAGS_RESERVED     0x0F00

/* Mask for the flags of SRP Object */
#define PCEP_OBJ_SRP_FLAGS_R            0x00000001

/* Mask for the flags of Stateful PCE Capability TLV */
#define PCEP_TLV_STATEFUL_PCE_CAPABILITY_U  0x00000001
#define PCEP_TLV_STATEFUL_PCE_CAPABILITY_S  0x00000002
#define PCEP_TLV_STATEFUL_PCE_CAPABILITY_I  0x00000004
#define PCEP_TLV_STATEFUL_PCE_CAPABILITY_T  0x00000008
#define PCEP_TLV_STATEFUL_PCE_CAPABILITY_D  0x00000010
#define PCEP_TLV_STATEFUL_PCE_CAPABILITY_F  0x00000020

/* Mask for the flags of ASSOCIATION Object */
#define PCEP_OBJ_ASSOCIATION_FLAGS_R 0x0001

/* Mask for the flags of SR PCE Capability TLV */
#define PCEP_TLV_SR_PCE_CAPABILITY_L    0x01

/* Mask for the flags of Subobjevct SR*/
#define PCEP_SUBOBJ_SR_FLAGS_M  0x001
#define PCEP_SUBOBJ_SR_FLAGS_C  0x002
#define PCEP_SUBOBJ_SR_FLAGS_S  0x004
#define PCEP_SUBOBJ_SR_FLAGS_F  0x008

/* Mask for the flags of Subobject SRv6 */
#define PCEP_SUBOBJ_SRV6_FLAGS_S    0x001
#define PCEP_SUBOBJ_SRV6_FLAGS_F    0x002
#define PCEP_SUBOBJ_SRV6_FLAGS_T    0x004
#define PCEP_SUBOBJ_SRV6_FLAGS_V    0x008

static int proto_pcep;

static int hf_pcep_endpoint_p2mp_leaf;
static int hf_pcep_hdr_msg_flags_reserved;
static int hf_pcep_hdr_obj_flags;
static int hf_pcep_hdr_obj_flags_reserved;
static int hf_pcep_hdr_obj_flags_p;
static int hf_pcep_hdr_obj_flags_i;
static int hf_pcep_open_flags_res;
static int hf_pcep_rp_flags_pri;
static int hf_pcep_rp_flags_r;
static int hf_pcep_rp_flags_b;
static int hf_pcep_rp_flags_o;
static int hf_pcep_rp_flags_v;
static int hf_pcep_rp_flags_s;
static int hf_pcep_rp_flags_p;
static int hf_pcep_rp_flags_d;
static int hf_pcep_rp_flags_m;
static int hf_pcep_rp_flags_e;
static int hf_pcep_rp_flags_n;
static int hf_pcep_rp_flags_f;
static int hf_pcep_rp_flags_c;
static int hf_pcep_rp_flags_reserved;
static int hf_pcep_no_path_flags_c;
static int hf_pcep_metric_flags_c;
static int hf_pcep_metric_flags_b;
static int hf_pcep_lspa_flags_l;
static int hf_pcep_svec_flags_l;
static int hf_pcep_svec_flags_n;
static int hf_pcep_svec_flags_s;
static int hf_pcep_svec_flags_d;
static int hf_pcep_svec_flags_p;
static int hf_pcep_xro_flags_f;
static int hf_pcep_obj_monitoring_flags_reserved;
static int hf_pcep_obj_monitoring_flags_l;
static int hf_pcep_obj_monitoring_flags_g;
static int hf_pcep_obj_monitoring_flags_p;
static int hf_pcep_obj_monitoring_flags_c;
static int hf_pcep_obj_monitoring_flags_i;
static int hf_pcep_obj_monitoring_monitoring_id_number;
static int hf_pcep_obj_pcc_id_req_ipv4;
static int hf_pcep_obj_pcc_id_req_ipv6;
static int hf_pcep_obj_pce_id_ipv4;
static int hf_pcep_obj_pce_id_ipv6;
static int hf_pcep_obj_proc_time_flags_reserved;
static int hf_pcep_obj_proc_time_flags_e;
static int hf_pcep_obj_proc_time_cur_proc_time;
static int hf_pcep_obj_proc_time_min_proc_time;
static int hf_pcep_obj_proc_time_max_proc_time;
static int hf_pcep_obj_proc_time_ave_proc_time;
static int hf_pcep_obj_proc_time_var_proc_time;
static int hf_pcep_obj_overload_duration;
static int hf_pcep_subobj_flags_lpa;
static int hf_pcep_subobj_flags_lpu;
static int hf_pcep_subobj_label_flags_gl;
static int hf_pcep_no_path_tlvs_pce;
static int hf_pcep_no_path_tlvs_unk_dest;
static int hf_pcep_no_path_tlvs_unk_src;
static int hf_pcep_no_path_tlvs_brpc;
static int hf_pcep_no_path_tlvs_pks;
static int hf_pcep_no_path_tlvs_no_gco_migr;
static int hf_pcep_no_path_tlvs_no_gco_soln;
static int hf_pcep_no_path_tlvs_p2mp;
static int hf_PCEPF_MSG;
static int hf_PCEPF_OBJECT_CLASS;
static int hf_PCEPF_OBJ_OPEN;
static int hf_PCEPF_OBJ_RP;
static int hf_PCEPF_OBJ_NO_PATH;
static int hf_PCEPF_OBJ_END_POINT;
static int hf_PCEPF_OBJ_BANDWIDTH;
static int hf_PCEPF_OBJ_METRIC;
static int hf_PCEPF_OBJ_EXPLICIT_ROUTE;
static int hf_PCEPF_OBJ_RECORD_ROUTE;
static int hf_PCEPF_OBJ_LSPA;
static int hf_PCEPF_OBJ_IRO;
static int hf_PCEPF_OBJ_SVEC;
static int hf_PCEPF_OBJ_NOTIFICATION;
static int hf_PCEPF_OBJ_PCEP_ERROR;
static int hf_PCEPF_OBJ_LOAD_BALANCING;
static int hf_PCEPF_OBJ_CLOSE;
static int hf_PCEPF_OBJ_PATH_KEY;
static int hf_PCEPF_OBJ_XRO;
static int hf_PCEPF_OBJ_MONITORING;
static int hf_PCEPF_OBJ_PCC_ID_REQ;
static int hf_PCEPF_OBJ_OF;
static int hf_PCEPF_OBJ_CLASSTYPE;
static int hf_PCEPF_OBJ_GLOBAL_CONSTRAINTS;
static int hf_PCEPF_OBJ_PCE_ID;
static int hf_PCEPF_OBJ_PROC_TIME;
static int hf_PCEPF_OBJ_OVERLOAD;
static int hf_PCEPF_OBJ_UNREACH_DESTINATION;
static int hf_PCEPF_OBJ_SERO;
static int hf_PCEPF_OBJ_SRRO;
static int hf_PCEPF_OBJ_BRANCH_NODE_CAPABILITY;
static int hf_PCEPF_OBJ_LSP;
static int hf_PCEPF_OBJ_SRP;
static int hf_PCEPF_OBJ_VENDOR_INFORMATION;
static int hf_PCEPF_OBJ_BU;
static int hf_PCEPF_OBJ_INTER_LAYER;
static int hf_PCEPF_OBJ_SWITCH_LAYER;
static int hf_PCEPF_OBJ_REQ_ADAP_CAP;
static int hf_PCEPF_OBJ_SERVER_IND;
static int hf_PCEPF_OBJ_ASSOCIATION;
static int hf_PCEPF_OBJ_S2LS;
static int hf_PCEPF_OBJ_WA;
static int hf_PCEPF_OBJ_FLOWSPEC;
static int hf_PCEPF_OBJ_CCI_TYPE;
static int hf_PCEPF_OBJ_PATH_ATTRIB;
static int hf_PCEPF_OBJ_UNKNOWN_TYPE;
static int hf_PCEPF_NOTI_TYPE;
static int hf_PCEPF_NOTI_VAL1;
static int hf_PCEPF_NOTI_VAL2;
static int hf_PCEPF_ERROR_TYPE;
static int hf_PCEPF_ERROR_VALUE;
static int hf_PCEPF_SUBOBJ;
static int hf_PCEPF_SUBOBJ_7F;
static int hf_PCEPF_SUBOBJ_IPv4;
static int hf_PCEPF_SUBOBJ_IPv6;
static int hf_PCEPF_SUBOBJ_LABEL_CONTROL;
static int hf_PCEPF_SUBOBJ_UNNUM_INTERFACEID;
static int hf_PCEPF_SUBOBJ_AUTONOMOUS_SYS_NUM;
static int hf_PCEPF_SUBOBJ_SRLG;
static int hf_PCEPF_SUBOBJ_EXRS;
static int hf_PCEPF_SUBOBJ_PKSv4;
static int hf_PCEPF_SUBOBJ_PKSv6;
static int hf_PCEPF_SUBOBJ_XRO;
static int hf_PCEPF_SUBOBJ_SR;
static int hf_PCEPF_SUBOBJ_SRv6;
#if 0
static int hf_PCEPF_SUB_XRO_ATTRIB;
#endif

static int hf_pcep_obj_open_type;
static int hf_pcep_obj_rp_type;
static int hf_pcep_obj_no_path_type;
static int hf_pcep_obj_end_point_type;
static int hf_pcep_obj_bandwidth_type;
static int hf_pcep_obj_metric_type;
static int hf_pcep_obj_explicit_route_type;
static int hf_pcep_obj_record_route_type;
static int hf_pcep_obj_lspa_type;
static int hf_pcep_obj_iro_type;
static int hf_pcep_obj_svec_type;
static int hf_pcep_obj_notification_type;
static int hf_pcep_obj_pcep_error_type;
static int hf_pcep_obj_load_balancing_type;
static int hf_pcep_obj_close_type;
static int hf_pcep_obj_path_key_type;
static int hf_pcep_obj_xro_type;
static int hf_pcep_obj_monitoring_type;
static int hf_pcep_obj_pcc_id_req_type;
static int hf_pcep_obj_of_type;
static int hf_pcep_obj_classtype;
static int hf_pcep_obj_global_constraints;
static int hf_pcep_obj_pce_id_type;
static int hf_pcep_obj_proc_time_type;
static int hf_pcep_obj_overload_type;
static int hf_pcep_obj_unreach_destination_type;
static int hf_pcep_obj_sero_type;
static int hf_pcep_obj_srro_type;
static int hf_pcep_obj_branch_node_capability_type;
static int hf_pcep_obj_lsp_type;
static int hf_pcep_obj_srp_type;
static int hf_pcep_obj_vendor_information_type;
static int hf_pcep_obj_bu_type;
static int hf_pcep_obj_inter_layer_type;
static int hf_pcep_obj_switch_layer_type;
static int hf_pcep_obj_req_adap_cap_type;
static int hf_pcep_obj_server_ind_type;
static int hf_pcep_obj_association_type;
static int hf_pcep_obj_s2ls_type;
static int hf_pcep_obj_wa_type;
static int hf_pcep_obj_flowspec_type;
static int hf_pcep_obj_cci_type;
static int hf_pcep_obj_path_attrib_type;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_pcep_xro_obj_flags;
static int hf_pcep_open_obj_keepalive;
static int hf_pcep_request_id;
static int hf_pcep_lspa_obj_reserved;
static int hf_pcep_rp_obj_reserved;
static int hf_pcep_svec_obj_reserved;
static int hf_pcep_rp_obj_flags;
static int hf_pcep_lspa_obj_exclude_any;
static int hf_pcep_subobj_srlg_attribute;
static int hf_pcep_end_point_obj_destination_ipv4_address;
static int hf_pcep_subobj_unnumb_interfaceID_reserved_xroobj;
static int hf_pcep_balancing_obj_flags;
static int hf_pcep_subobj_unnumb_interfaceID_reserved;
static int hf_pcep_lspa_obj_setup_priority;
static int hf_pcep_svec_obj_request_id_number;
static int hf_pcep_end_point_obj_source_ipv4_address;
static int hf_pcep_open_obj_sid;
static int hf_pcep_subobj_ipv6_padding;
static int hf_pcep_notification_obj_reserved;
static int hf_pcep_close_obj_reason;
static int hf_pcep_subobj_ipv4_attribute;
static int hf_pcep_obj_overload_flags;
static int hf_pcep_balancing_obj_maximum_number_of_te_lsps;
static int hf_pcep_subobj_exrs_reserved;
static int hf_pcep_subobj_label_control_length;
static int hf_pcep_subobj_ipv4_length;
static int hf_pcep_subobj_ipv6_ipv6;
static int hf_pcep_lspa_obj_holding_priority;
static int hf_pcep_rp_obj_requested_id_number;
static int hf_pcep_subobj_pksv6_path_key;
static int hf_pcep_subobj_unnumb_interfaceID_router_id;
static int hf_pcep_subobj_pksv6_pce_id;
static int hf_pcep_tlv_padding;
static int hf_pcep_subobj_unnumb_interfaceID_flags;
static int hf_pcep_subobj_unnumb_interfaceID_length;
static int hf_pcep_obj_proc_time_reserved;
static int hf_pcep_object_type;
static int hf_pcep_subobj_pksv4_length;
static int hf_pcep_subobj_ipv6_prefix_length;
static int hf_pcep_subobj_ipv6_length;
static int hf_pcep_flags;
static int hf_pcep_no_path_obj_reserved;
static int hf_pcep_subobj_unnumb_interfaceID_interface_id;
static int hf_pcep_close_obj_flags;
static int hf_pcep_error_obj_flags;
static int hf_pcep_metric_obj_flags;
static int hf_pcep_subobj_autonomous_sys_num_reserved;
static int hf_pcep_subobj_pksv4_path_key;
static int hf_pcep_subobj_label_control_flags;
static int hf_pcep_notification_obj_value;
static int hf_pcep_subobj_label_control_label;
static int hf_pcep_metric_obj_metric_value;
static int hf_pcep_no_path_obj_flags;
static int hf_pcep_obj_monitoring_reserved;
static int hf_pcep_obj_of_code;
static int hf_pcep_subobj_label_control_u;
static int hf_pcep_subobj_autonomous_sys_num_length;
static int hf_pcep_message_length;
static int hf_pcep_subobj_ipv4_prefix_length;
static int hf_pcep_xro_obj_reserved;
static int hf_pcep_subobj_pksv4_pce_id;
static int hf_pcep_subobj_pksv6_length;
static int hf_pcep_end_point_obj_destination_ipv6_address;
static int hf_pcep_subobj_autonomous_sys_num_as_number;
static int hf_pcep_notification_obj_flags;
static int hf_pcep_subobj_unnumb_interfaceID_attribute;
static int hf_pcep_object_length;
static int hf_pcep_tlv_data;
static int hf_pcep_balancing_obj_reserved;
static int hf_pcep_subobj_ipv4_flags;
static int hf_pcep_subobj_ipv6_attribute;
static int hf_pcep_subobj_srlg_id;
static int hf_pcep_balancing_obj_minimum_bandwidth;
static int hf_pcep_subobj_unnumb_interfaceID_reserved_rrobj;
static int hf_pcep_error_obj_reserved;
static int hf_pcep_obj_overload_reserved;
static int hf_pcep_notification_obj_type;
static int hf_pcep_subobj_ipv6_flags;
static int hf_pcep_obj_monitoring_flags;
static int hf_pcep_subobj_exrs_length;
static int hf_pcep_obj_proc_time_flags;
static int hf_pcep_subobj_label_control_reserved;
static int hf_pcep_version;
static int hf_pcep_lspa_obj_flags;
static int hf_pcep_subobj_ipv4_ipv4;
static int hf_pcep_tlv_type;
static int hf_pcep_subobj_autonomous_sys_num_optional_as_number_high_octets;
static int hf_pcep_open_obj_deadtime;
static int hf_pcep_bandwidth;
static int hf_pcep_tlv_length;
static int hf_pcep_subobj_srlg_reserved;
static int hf_pcep_metric_obj_type;
static int hf_pcep_metric_obj_reserved;
static int hf_pcep_svec_obj_flags;
static int hf_pcep_open_obj_pcep_version;
static int hf_pcep_open_obj_flags;
static int hf_pcep_end_point_obj_source_ipv6_address;
static int hf_pcep_lspa_obj_include_any;
static int hf_pcep_lspa_obj_include_all;
static int hf_pcep_subobj_ipv4_padding;
static int hf_pcep_subobj_srlg_length;
static int hf_pcep_subobj_autonomous_sys_num_attribute;
static int hf_pcep_close_obj_reserved;
static int hf_pcep_subobj_label_control_c_type;
static int hf_pcep_subobj_iro_autonomous_sys_num_l;
static int hf_pcep_subobj_autonomous_sys_num_x;
static int hf_pcep_subobj_label_control_l;
static int hf_pcep_subobj_exrs_l;
static int hf_pcep_subobj_unnumb_interfaceID_x;
static int hf_pcep_subobj_autonomous_sys_num_l;
static int hf_pcep_subobj_pksv6_l;
static int hf_pcep_subobj_srlg_x;
static int hf_pcep_subobj_ipv4_x;
static int hf_pcep_subobj_iro_unnumb_interfaceID_l;
static int hf_pcep_subobj_exrs_type;
static int hf_pcep_subobj_ipv4_l;
static int hf_pcep_of_code;
static int hf_pcep_subobj_ipv6_x;
static int hf_pcep_no_path_obj_nature_of_issue;
static int hf_pcep_subobj_ipv6_l;
static int hf_pcep_subobj_pksv4_l;
static int hf_pcep_subobj_iro_ipv6_l;
static int hf_pcep_subobj_unnumb_interfaceID_l;
static int hf_pcep_subobj_iro_ipv4_l;
static int hf_pcep_subobj_sr_l;
static int hf_pcep_subobj_sr_length;
static int hf_pcep_subobj_sr_nt;
static int hf_pcep_subobj_sr_flags;
static int hf_pcep_subobj_sr_flags_m;
static int hf_pcep_subobj_sr_flags_c;
static int hf_pcep_subobj_sr_flags_s;
static int hf_pcep_subobj_sr_flags_f;
static int hf_pcep_subobj_sr_sid;
static int hf_pcep_subobj_sr_sid_label;
static int hf_pcep_subobj_sr_sid_tc;
static int hf_pcep_subobj_sr_sid_s;
static int hf_pcep_subobj_sr_sid_ttl;
static int hf_pcep_subobj_sr_nai_ipv4_node;
static int hf_pcep_subobj_sr_nai_ipv6_node;
static int hf_pcep_subobj_sr_nai_local_ipv4_addr;
static int hf_pcep_subobj_sr_nai_remote_ipv4_addr;
static int hf_pcep_subobj_sr_nai_local_ipv6_addr;
static int hf_pcep_subobj_sr_nai_remote_ipv6_addr;
static int hf_pcep_subobj_sr_nai_local_node_id;
static int hf_pcep_subobj_sr_nai_local_interface_id;
static int hf_pcep_subobj_sr_nai_remote_node_id;
static int hf_pcep_subobj_sr_nai_remote_interface_id;
static int hf_pcep_subobj_srv6_l;
static int hf_pcep_subobj_srv6_length;
static int hf_pcep_subobj_srv6_nt;
static int hf_pcep_subobj_srv6_flags;
static int hf_pcep_subobj_srv6_flags_s;
static int hf_pcep_subobj_srv6_flags_f;
static int hf_pcep_subobj_srv6_flags_t;
static int hf_pcep_subobj_srv6_flags_v;
static int hf_pcep_subobj_srv6_reserved;
static int hf_pcep_subobj_srv6_endpoint_behavior;
static int hf_pcep_subobj_srv6_sid;
static int hf_pcep_subobj_srv6_nai;
static int hf_pcep_subobj_srv6_nai_ipv6_node;
static int hf_pcep_subobj_srv6_nai_local_ipv6_addr;
static int hf_pcep_subobj_srv6_nai_remote_ipv6_addr;
static int hf_pcep_subobj_srv6_nai_local_interface_id;
static int hf_pcep_subobj_srv6_nai_remote_interface_id;
static int hf_pcep_subobj_srv6_sid_struct;
static int hf_pcep_subobj_srv6_sid_struct_lb_len;
static int hf_pcep_subobj_srv6_sid_struct_ln_len;
static int hf_pcep_subobj_srv6_sid_struct_fun_len;
static int hf_pcep_subobj_srv6_sid_struct_arg_len;
static int hf_pcep_subobj_srv6_sid_struct_reserved;
static int hf_pcep_subobj_srv6_sid_struct_flags;

static int hf_pcep_stateful_pce_capability_flags;
static int hf_pcep_lsp_update_capability;
static int hf_pcep_include_db_version;
static int hf_pcep_lsp_instantiation_capability;
static int hf_pcep_triggered_resync;
static int hf_pcep_delta_lsp_sync_capability;
static int hf_pcep_triggered_initial_sync;
static int hf_pcep_obj_lsp_flags;
static int hf_pcep_obj_lsp_plsp_id;
static int hf_pcep_obj_lsp_flags_d;
static int hf_pcep_obj_lsp_flags_s;
static int hf_pcep_obj_lsp_flags_r;
static int hf_pcep_obj_lsp_flags_a;
static int hf_pcep_obj_lsp_flags_o;
static int hf_pcep_obj_lsp_flags_c;
static int hf_pcep_obj_lsp_flags_reserved;
static int hf_pcep_obj_srp_flags;
static int hf_pcep_obj_srp_flags_r;
static int hf_pcep_obj_srp_id_number;
static int hf_pcep_symbolic_path_name;
static int hf_pcep_ipv4_lsp_id_tunnel_sender_address;
static int hf_pcep_ipv4_lsp_id_lsp_id;
static int hf_pcep_ipv4_lsp_id_tunnel_id;
static int hf_pcep_ipv4_lsp_id_extended_tunnel_id;
static int hf_pcep_ipv4_lsp_id_tunnel_endpoint_address;
static int hf_pcep_ipv6_lsp_id_tunnel_sender_address;
static int hf_pcep_ipv6_lsp_id_lsp_id;
static int hf_pcep_ipv6_lsp_id_tunnel_id;
static int hf_pcep_ipv6_lsp_id_extended_tunnel_id;
static int hf_pcep_ipv6_lsp_id_tunnel_endpoint_address;
static int hf_pcep_lsp_error_code;
static int hf_pcep_rsvp_user_error_spec;
static int hf_pcep_lsp_state_db_version_number;
static int hf_pcep_speaker_entity_id;
static int hf_pcep_path_setup_type_reserved24;
static int hf_pcep_path_setup_type;
static int hf_pcep_path_setup_type_capability_reserved24;
static int hf_pcep_path_setup_type_capability_psts;
static int hf_pcep_path_setup_type_capability_pst;
static int hf_pcep_sr_pce_capability_reserved; //deprecated
static int hf_pcep_sr_pce_capability_sub_tlv_reserved;
static int hf_pcep_sr_pce_capability_flags; //deprecated
static int hf_pcep_sr_pce_capability_sub_tlv_flags;
static int hf_pcep_sr_pce_capability_flags_l; //deprecated
static int hf_pcep_sr_pce_capability_sub_tlv_flags_x;
static int hf_pcep_sr_pce_capability_sub_tlv_flags_n;
static int hf_pcep_sr_pce_capability_msd; //deprecated
static int hf_pcep_sr_pce_capability_sub_tlv_msd;
static int hf_pcep_association_reserved;
static int hf_pcep_association_flags;
static int hf_pcep_association_flags_r;
static int hf_pcep_association_type;
static int hf_pcep_association_id;
static int hf_pcep_association_source_ipv4;
static int hf_pcep_association_source_ipv6;
static int hf_pcep_association_source_global;
static int hf_pcep_association_id_extended;

static int hf_pcep_association_id_extended_color;
static int hf_pcep_association_id_extended_ipv4_endpoint;
static int hf_pcep_association_id_extended_ipv6_endpoint;
static int hf_pcep_unreach_destination_obj_ipv4_address;
static int hf_pcep_unreach_destination_obj_ipv6_address;

static int hf_pcep_op_conf_assoc_range_reserved;
static int hf_pcep_op_conf_assoc_range_assoc_type;
static int hf_pcep_op_conf_assoc_range_start_assoc;
static int hf_pcep_op_conf_assoc_range_range;

static int hf_pcep_srcpag_info_color;
static int hf_pcep_srcpag_info_destination_endpoint;
static int hf_pcep_srcpag_info_preference;


static int hf_pcep_sr_policy_name;
static int hf_pcep_sr_policy_cpath_id_proto_origin;
static int hf_pcep_sr_policy_cpath_id_originator_asn;
static int hf_pcep_sr_policy_cpath_id_originator_address;
static int hf_pcep_sr_policy_cpath_id_discriminator;
static int hf_pcep_sr_policy_cpath_name;
static int hf_pcep_sr_policy_cpath_preference;

static int hf_pcep_enterprise_number;
static int hf_pcep_enterprise_specific_info;
static int hf_pcep_tlv_enterprise_number;
static int hf_pcep_tlv_enterprise_specific_info;

static int hf_pcep_bu_reserved;
static int hf_pcep_bu_butype;
static int hf_pcep_bu_utilization;

static int hf_pcep_path_setup_type_capability_sub_tlv_type;
static int hf_pcep_path_setup_type_capability_sub_tlv_length;

static int ett_pcep;
static int ett_pcep_hdr;
static int ett_pcep_obj_open;
static int ett_pcep_obj_request_parameters;
static int ett_pcep_obj_no_path;
static int ett_pcep_obj_end_point;
static int ett_pcep_obj_bandwidth;
static int ett_pcep_obj_metric;
static int ett_pcep_obj_explicit_route;
static int ett_pcep_obj_record_route;
static int ett_pcep_obj_lspa;
static int ett_pcep_obj_iro;
static int ett_pcep_obj_svec;
static int ett_pcep_obj_notification;
static int ett_pcep_obj_error;
static int ett_pcep_obj_load_balancing;
static int ett_pcep_obj_close;
static int ett_pcep_obj_path_key;
static int ett_pcep_obj_xro;
static int ett_pcep_obj_monitoring;
static int ett_pcep_obj_pcc_id_req;
static int ett_pcep_obj_of;
static int ett_pcep_obj_classtype;
static int ett_pcep_obj_global_constraints;
static int ett_pcep_obj_pce_id;
static int ett_pcep_obj_proc_time;
static int ett_pcep_obj_overload;
static int ett_pcep_obj_unreach_destination;
static int ett_pcep_obj_sero;
static int ett_pcep_obj_srro;
static int ett_pcep_obj_branch_node_capability;
static int ett_pcep_obj_lsp;
static int ett_pcep_obj_srp;
static int ett_pcep_obj_vendor_information;
static int ett_pcep_obj_bu;
static int ett_pcep_obj_inter_layer;
static int ett_pcep_obj_switch_layer;
static int ett_pcep_obj_req_adap_cap;
static int ett_pcep_obj_server_ind;
static int ett_pcep_obj_association;
static int ett_pcep_obj_s2ls;
static int ett_pcep_obj_wa;
static int ett_pcep_obj_flowspec;
static int ett_pcep_obj_cci_type;
static int ett_pcep_obj_path_attrib;
static int ett_pcep_obj_unknown;

/* Generated from convert_proto_tree_add_text.pl */
static expert_field ei_pcep_pcep_object_body_non_defined;
static expert_field ei_pcep_non_defined_object;
static expert_field ei_pcep_object_length;
static expert_field ei_pcep_subobject_bad_length;
static expert_field ei_pcep_non_defined_subobject;
static expert_field ei_pcep_unknown_type_object;

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
    PCEP_MSG_PATH_COMPUTATION_MONITORING_REPLY,
    PCEP_MSG_PATH_COMPUTATION_LSP_STATE_REPORT,
    PCEP_MSG_PATH_COMPUTATION_LSP_UPDATE_REQUEST,
    PCEP_MSG_INITIATE,
    PCEP_MSG_STARTTLS
} pcep_message_types;

static const value_string message_type_vals[] = {
    {PCEP_MSG_OPEN,                                "Open"                                           },
    {PCEP_MSG_KEEPALIVE,                           "Keepalive"                                      },
    {PCEP_MSG_PATH_COMPUTATION_REQUEST,            "Path Computation Request (PCReq)"               },
    {PCEP_MSG_PATH_COMPUTATION_REPLY,              "Path Computation Reply (PCRep)"                 },
    {PCEP_MSG_NOTIFICATION,                        "Notification (PCNtf)"                           },
    {PCEP_MSG_ERROR,                               "Error (PCErr)"                                  },
    {PCEP_MSG_CLOSE,                               "Close"                                          },
    {PCEP_MSG_PATH_COMPUTATION_MONITORING_REQUEST, "Path Computation Monitoring Request (PCMonReq)" },
    {PCEP_MSG_PATH_COMPUTATION_MONITORING_REPLY,   "Path Computation Monitoring Reply (PCMonRep)"   },
    {PCEP_MSG_PATH_COMPUTATION_LSP_STATE_REPORT,   "Path Computation LSP State Report (PCRpt)"      },
    {PCEP_MSG_PATH_COMPUTATION_LSP_UPDATE_REQUEST, "Path Computation LSP Update Request (PCUpd)"    },
    {PCEP_MSG_INITIATE,                            "Path Computation LSP Initiate (PCInitiate)"     },
    {PCEP_MSG_STARTTLS,                            "StartTLS"                                       },
    {0, NULL }
};

static const value_string pcep_class_vals[] = {
    {PCEP_OPEN_OBJ,                   "OPEN OBJECT"                            },
    {PCEP_RP_OBJ,                     "RP OBJECT"                              },
    {PCEP_NO_PATH_OBJ,                "NO-PATH OBJECT"                         },
    {PCEP_END_POINT_OBJ,              "END-POINT OBJECT"                       },
    {PCEP_BANDWIDTH_OBJ,              "BANDWIDTH OBJECT"                       },
    {PCEP_METRIC_OBJ,                 "METRIC OBJECT"                          },
    {PCEP_EXPLICIT_ROUTE_OBJ,         "EXPLICIT ROUTE OBJECT (ERO)"            },
    {PCEP_RECORD_ROUTE_OBJ,           "RECORD ROUTE OBJECT (RRO)"              },
    {PCEP_LSPA_OBJ,                   "LSPA OBJECT"                            },
    {PCEP_IRO_OBJ,                    "IRO OBJECT"                             },
    {PCEP_SVEC_OBJ,                   "SVEC OBJECT"                            },
    {PCEP_NOTIFICATION_OBJ,           "NOTIFICATION OBJECT"                    },
    {PCEP_PCEP_ERROR_OBJ,             "PCEP ERROR OBJECT"                      },
    {PCEP_LOAD_BALANCING_OBJ,         "LOAD BALANCING OBJECT"                  },
    {PCEP_CLOSE_OBJ,                  "CLOSE OBJECT"                           },
    {PCEP_PATH_KEY_OBJ,               "PATH-KEY OBJECT"                        },
    {PCEP_XRO_OBJ,                    "EXCLUDE ROUTE OBJECT (XRO)"             },
    {PCEP_OBJ_MONITORING,             "MONITORING OBJECT"                      },
    {PCEP_OBJ_PCC_ID_REQ,             "PCC-ID-REQ OBJECT"                      },
    {PCEP_OF_OBJ,                     "OBJECTIVE FUNCTION OBJECT (OF)"         },
    {PCEP_CLASSTYPE_OBJ,              "CLASSTYPE OBJECT"                       },
    {PCEP_GLOBAL_CONSTRAINTS_OBJ,     "GLOBAL-CONSTRAINTS OBJECT"              },
    {PCEP_OBJ_PCE_ID,                 "PCE-ID OBJECT"                          },
    {PCEP_OBJ_PROC_TIME,              "PROC-TIME OBJECT"                       },
    {PCEP_OBJ_OVERLOAD,               "OVERLOAD OBJECT"                        },
    {PCEP_OBJ_UNREACH_DESTINATION,    "UNREACH-DESTINATION OBJECT"             },
    {PCEP_SERO_OBJ,                   "SECONDARY EXPLICIT ROUTE OBJECT (SERO)" },
    {PCEP_SRRO_OBJ,                   "SECONDARY RECORD ROUTE OBJECT (SRRO)"   },
    {PCEP_OBJ_BRANCH_NODE_CAPABILITY, "BRANCH NODE CAPABILITY OBJECT (BNC)"    },
    {PCEP_OBJ_LSP,                    "LSP OBJECT"                             },
    {PCEP_OBJ_SRP,                    "SRP OBJECT"                             },
    {PCEP_OBJ_VENDOR_INFORMATION,     "VENDOR-INFORMATION OBJECT"              },
    {PCEP_OBJ_BU,                     "BU OBJECT"                              },
    {PCEP_INTER_LAYER_OBJ,            "INTER-LAYER OBJECT"                     },
    {PCEP_SWITCH_LAYER_OBJ,           "SWITCH-LAYER OBJECT"                    },
    {PCEP_REQ_ADAP_CAP_OBJ,           "REQ-ADAP-CAP OBJECT"                    },
    {PCEP_SERVER_IND_OBJ,             "SERVER-INDICATION OBJECT"               },
    {PCEP_ASSOCIATION_OBJ,            "ASSOCIATION OBJECT"                     },
    {PCEP_S2LS_OBJ,                   "S2LS OBJECT"                            },
    {PCEP_WA_OBJ,                     "WA OBJECT"                              },
    {PCEP_FLOWSPEC_OBJ,               "FLOWSPEC OBJECT"                        },
    {PCEP_CCI_TYPE_OBJ,               "CCI OBJECT-TYPE"                        },
    {PCEP_PATH_ATTRIB_OBJ,            "PATH-ATTRIB OBJECT"                     },
    {0, NULL }
};
static value_string_ext pcep_class_vals_ext = VALUE_STRING_EXT_INIT(pcep_class_vals);

static const value_string pcep_obj_open_type_vals[] = {
    {1, "Open"},
    {0, NULL }
};

static const value_string pcep_obj_rp_type_vals[] = {
    {1, "Request Parameters"},
    {0, NULL }
};

static const value_string pcep_obj_no_path_type_vals[] = {
    {1, "No Path"},
    {0, NULL }
};

static const value_string pcep_obj_end_point_type_vals[] = {
    {1, "IPv4 addresses"},
    {2, "IPv6 addresses"},
    {3, "IPv4"          },
    {4, "IPv6"          },
    {0, NULL }
};

static const value_string pcep_obj_bandwidth_type_vals[] = {
    {1, "Requested bandwidth"                                                       },
    {2, "Bandwidth of an existing TE LSP for which a reoptimization is requested"   },
    {0, NULL }
};

static const value_string pcep_obj_metric_type_vals[] = {
    {1, "Metric"},
    {0, NULL }
};

static const value_string pcep_obj_explicit_route_type_vals[] = {
    {1, "Explicit Route"},
    {0, NULL }
};

static const value_string pcep_obj_record_route_type_vals[] = {
    {1, "Recorded Route"},
    {0, NULL }
};

static const value_string pcep_obj_lspa_type_vals[] = {
    {1, "LSP Attributes"},
    {0, NULL }
};

static const value_string pcep_obj_iro_type_vals[] = {
    {1, "Include Route"},
    {0, NULL }
};

static const value_string pcep_obj_svec_type_vals[] = {
    {1, "Synchronization Vector"},
    {0, NULL }
};

static const value_string pcep_obj_notification_type_vals[] = {
    {1, "Notification"},
    {0, NULL }
};

static const value_string pcep_obj_pcep_error_type_vals[] = {
    {1, "PCEP Error"},
    {0, NULL }
};

static const value_string pcep_obj_load_balancing_type_vals[] = {
    {1, "Load Balancing"},
    {0, NULL }
};

static const value_string pcep_obj_close_type_vals[] = {
    {1, "Close"},
    {0, NULL }
};

static const value_string pcep_obj_path_key_type_vals[] = {
    {1, "Path Key"},
    {0, NULL }
};

static const value_string pcep_obj_xro_type_vals[] = {
    {1, "Route exclusion"},
    {0, NULL }
};

static const value_string pcep_obj_monitoring_type_vals[] = {
    {1, "Monitoring"},
    {0, NULL }
};

static const value_string pcep_obj_pcc_id_req_type_vals[] = {
    {1, "IPv4 addresses"},
    {2, "IPv6 addresses"},
    {0, NULL }
};

static const value_string pcep_obj_of_type_vals[] = {
    {1, "Objective Function"},
    {0, NULL }
};

static const value_string pcep_obj_pce_id_type_vals[] = {
    {1, "IPv4 addresses"},
    {2, "IPv6 addresses"},
    {0, NULL }
};

static const value_string pcep_obj_proc_time_type_vals[] = {
    {1, "PROC-TIME"},
    {0, NULL }
};

static const value_string pcep_obj_overload_type_vals[] = {
    {1, "overload"},
    {0, NULL }
};

static const value_string pcep_obj_unreach_destination_type_vals[] = {
    {1, "IPv4"},
    {2, "IPv6"},
    {0, NULL }
};

static const value_string pcep_obj_sero_type_vals[] = {
    {1, "SERO"},
    {0, NULL }
};

static const value_string pcep_obj_srro_type_vals[] = {
    {1, "SRRO"},
    {0, NULL }
};

static const value_string pcep_obj_branch_node_capability_type_vals[] = {
    {1, "Branch node list"},
    {2, "Non-branch node list"},
    {0, NULL }
};

static const value_string pcep_obj_lsp_type_vals[] = {
    {1, "LSP"},
    {0, NULL }
};

static const value_string pcep_obj_srp_type_vals[] = {
    {1, "SRP"},
    {0, NULL }
};

static const value_string pcep_obj_vendor_information_type_vals[] = {
    {1, "Vendor-Specific Constraints"},
    {0, NULL }
};

static const value_string pcep_obj_bu_type_vals[] = {
    {1, "BU"},
    {0, NULL }
};

static const value_string pcep_obj_association_type_vals[] = {
    {1, "IPv4"},
    {2, "IPv6"},
    {0, NULL }
};

static const value_string pcep_subobj_vals[] = {
    {PCEP_SUB_IPv4,                "SUBOBJECT IPv4"                     },
    {PCEP_SUB_IPv6,                "SUBOBJECT IPv6"                     },
    {PCEP_SUB_LABEL_CONTROL,       "SUBOBJECT LABEL"                    },
    {PCEP_SUB_UNNUMB_INTERFACE_ID, "SUBOBJECT UNNUMBERED INTERFACE-ID"  },
    {PCEP_SUB_AUTONOMOUS_SYS_NUM,  "SUBOBJECT AUTONOMOUS SYSTEM NUMBER" },
    {PCEP_SUB_SRLG,                "SUBOBJECT SRLG"                     },
    {PCEP_SUB_SR_PRE_IANA,         "SUBOBJECT SR"                       },
    {PCEP_SUB_PKSv4,               "SUBOBJECT PATH KEY (IPv4)"          },
    {PCEP_SUB_PKSv6,               "SUBOBJECT PATH KEY (IPv6)"          },
    {PCEP_SUB_SR,                  "SUBOBJECT SR"                       },
    {PCEP_SUB_SRv6,                "SUBOBJECT SRv6"                     },
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
    { 0, "Reserved"                        },
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
    {11, "Segment-ID (SID) Depth"          },   /* RFC 8664 */
    {12, "Path Delay metric"               },   /* draft-ietf-pce-pcep-service-aware */
    {13, "Path Delay Variation metric"     },   /* draft-ietf-pce-pcep-service-aware */
    {14, "Path Loss metric"                },   /* draft-ietf-pce-pcep-service-aware */
    {15, "P2MP Path Delay metric"          },   /* draft-ietf-pce-pcep-service-aware */
    {16, "P2MP Path Delay variation metric"},   /* draft-ietf-pce-pcep-service-aware */
    {17, "P2MP Path Loss metric"           },   /* draft-ietf-pce-pcep-service-aware */
    {18, "Number of adaptations on a path" },   /* RFC8282 */
    {19, "Number of layers on a path"      },   /* RFC8282 */
    {20, "Domain Count metric"             },   /* RFC8685 */
    {21, "Border Node Count metric"        },   /* RFC8685 */
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
    {1,  "NO-PATH-VECTOR TLV"                      },
    {2,  "OVERLOAD-DURATION TLV"                   },
    {3,  "REQ-MISSING TLV"                         },
    {4,  "OF-list TLV"                             },
    {5,  "Order TLV"                               },
    {6,  "P2MP Capable"                            },
    {7,  "VENDOR-INFORMATION-TLV"                  },
    {8,  "Wavelength Selection"                    },
    {9,  "Wavelength Restriction"                  },
    {10, "Wavelength Allocation"                   },
    {11, "Optical Interface Class List"            },
    {12, "Client Signal Information"               },
    {13, "H-PCE-CAPABILITY"                        },
    {14, "Domain-ID"                               },
    {15, "H-PCE-FLAG"                              },
    {16, "STATEFUL-PCE-CAPABILITY"                 },
    {17, "SYMBOLIC-PATH-NAME"                      },
    {18, "IPV4-LSP-IDENTIFIERS"                    },
    {19, "IPV6-LSP-IDENTIFIERS"                    },
    {20, "LSP-ERROR-CODE"                          },
    {21, "RSVP-ERROR-SPEC"                         },
    {23, "LSP-DB-VERSION"                          },
    {24, "SPEAKER-ENTITY-ID"                       },
    {26, "SR-PCE-CAPABILITY (deprecated)"          },
    {27, "PATH-SETUP-TYPE (PRE-IANA)"              },
    {28, "PATH-SETUP-TYPE"                         },
    {29, "OP-CONF-ASSOC-RANGE"                     },
    {30, "GLOBAL-ASSOCIATION-SOURCE"               },
    {31, "EXTENDED-ASSOCIATION-ID"                 },
    {32, "P2MP-IPV4-LSP-IDENTIFIERS"               },
    {33, "P2MP-IPV6-LSP-IDENTIFIERS"               },
    {34, "PATH-SETUP-TYPE-CAPABILITY"              },
    {35, "ASSOC-Type-List"                         },
    {36, "AUTO-BANDWIDTH-CAPABILITY"               },
    {37, "AUTO-BANDWIDTH-ATTRIBUTES"               },
    {38, "Path Protection Association Group TLV"   },
    {39, "IPV4-ADDRESS"                            },
    {40, "IPV6-ADDRESS"                            },
    {41, "UNNUMBERED-ENDPOINT"                     },
    {42, "LABEL-REQUEST"                           },
    {43, "LABEL-SET"                               },
    {44, "PROTECTION-ATTRIBUTE"                    },
    {45, "GMPLS-CAPABILITY"                        },
    {46, "DISJOINTNESS-CONFIGURATION"              },
    {47, "DISJOINTNESS-STATUS"                     },
    {48, "POLICY-PARAMETERS-TLV"                   },
    {49, "SCHED-LSP-ATTRIBUTE"                     },
    {50, "SCHED-PD-LSP-ATTRIBUTE"                  },
    {51, "PCE-FLOWSPEC-CAPABILITY TLV"             },
    {52, "FLOW FILTER TLV"                         },
    {53, "L2 FLOW FILTER TLV"                      },
    {54, "Bidirectional LSP Association Group TLV" },
    {55, "TE-PATH-BINDING"                         }, /* TEMPORARY - registered 2021-03-29, expires 2022-03-29 draft-ietf-pce-binding-label-sid-07 */
    {56, "SRPOLICY-POL-NAME"                       }, /* TEMPORARY - registered 2021-03-30, expires 2022-03-30 draft-ietf-pce-segment-routing-policy-cp-04 */
    {57, "SRPOLICY-CPATH-ID"                       }, /* TEMPORARY - registered 2021-03-30, expires 2022-03-30 draft-ietf-pce-segment-routing-policy-cp-04 */
    {58, "SRPOLICY-CPATH-NAME"                     }, /* TEMPORARY - registered 2021-03-30, expires 2022-03-30 draft-ietf-pce-segment-routing-policy-cp-04 */
    {59, "SRPOLICY-CPATH-PREFERENCE"               }, /* TEMPORARY - registered 2021-03-30, expires 2022-03-30 draft-ietf-pce-segment-routing-policy-cp-04 */
    {64, "LSP-EXTENDED-FLAG"                       },
    {65, "VIRTUAL-NETWORK-TLV"                     },
    {0, NULL                                       }
};


/*Values of Objective Functions*/
static const value_string pcep_of_vals[] = {
    { 1, "Minimum Cost Path (MCP)"                              },
    { 2, "Minimum Load Path (MLP)"                              },
    { 3, "Maximum residual Bandwidth Path (MBP)"                },
    { 4, "Minimize aggregate Bandwidth Consumption (MBC)"       },
    { 5, "Minimize the Load of the most loaded Link (MLL)"      },
    { 6, "Minimize the Cumulative Cost of a set of paths (MCC)" },
    { 7, "Shortest Path Tree (SPT)"                             }, /* RFC 6006 */
    { 8, "Minimum Cost Tree (MCT)"                              }, /* RFC 6006 */
    { 9, "Minimum Packet Loss Path (MPLP)"                      }, /* draft-ietf-pce-pcep-service-aware */
    {10, "Maximum Under-Utilized Path (MUP)"                    }, /* draft-ietf-pce-pcep-service-aware */
    {11, "Maximum Reserved Under-Utilized Path (MRUP)"          }, /* draft-ietf-pce-pcep-service-aware */
    {0, NULL }
};


/*Values of Bandwidth Utilization (BU) Object bandwidth utilization Type */
static const value_string pcep_bu_butype_vals[] = {
    {0, "Reserved"                                   }, /* draft-ietf-pce-pcep-service-aware */
    {1, "LBU (Link Bandwidth Utilization)"           }, /* draft-ietf-pce-pcep-service-aware */
    {2, "LRBU (Link Residual Bandwidth Utilization)" }, /* draft-ietf-pce-pcep-service-aware */
    {0, NULL }
};


/*Values of different types of errors*/
static const value_string pcep_error_types_obj_vals[] = {
    {ESTABLISH_FAILURE,                 "PCEP Session Establishment Failure"            },
    {CAP_NOT_SUPPORTED,                 "Capability non supported"                      },
    {UNKNOWN_OBJ,                       "Unknown Object"                                },
    {NOT_SUPP_OBJ,                      "Not Supported Object"                          },
    {POLICY_VIOLATION,                  "Policy Violation"                              },
    {MANDATORY_OBJ_MIS,                 "Mandatory Object Missing"                      },
    {SYNCH_PCREQ_MIS,                   "Synchronized Path Computation Request Missing" },
    {UNKNOWN_REQ_REF,                   "Unknown Request Reference"                     },
    {ATTEMPT_2_SESSION,                 "Attempt to Establish a Second PCEP Session"    },
    {INVALID_OBJ,                       "Reception of an invalid object"                },
    {UNRECO_EXRS_SUBOBJ,                "Unrecognized EXRS Subobject"                   },
    {DIFFSERV_TE_ERROR,                 "Diffserv-aware TE error"                       },
    {BRPC_FAILURE,                      "BRPC procedure completion failure"             },
    {GCO_ERROR,                         "Global Concurrent Optimization error"          },
    {P2MP_CAPABILITY_ERROR,             "P2PM capability error"                         },
    {P2MP_END_POINTS_ERROR,             "P2PM END-POINTS error"                         },
    {P2MP_FRAGMENT_ERROR,               "P2PM Fragmentation error"                      },
    {INVALID_OPERATION,                 "Invalid Operation"                             },
    {LSP_STATE_SYNCHRONIZATION_ERROR,   "LSP State synchronization error"               },
    {BAD_PARAMETER_VALUE,               "Bad parameter value"                           },
    {LSP_INSTANTIATION_ERROR,           "LSP instantiation error"                       },
    {ASSOCIATION_ERROR,                 "Association instantiation error"               },
    {WSON_RWA_ERROR,                    "WSON RWA error"                                },
    {H_PCE_ERROR,                       "H-PCE error"                                   },
    {PATH_COMPUTATION_FAILURE,          "Path computation failure"                      },
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
    {5, "Unsupported network performance constraint"},
    {6, "BANDWIDTH object type 3 or 4 not supported"},
    {7, "Unsupported endpoint type in END-POINTS Generalized Endpoint object type"},
    {8, "Unsupported TLV present in END-POINTS Generalized Endpoint object type"},
    {9, "Unsupported granularity in the RP object flags"},
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
    {8, "Not allowed network performance constraint"},  /* draft-ietf-pce-pcep-service-aware*/
    {0, NULL}
};


/*Error values for error type 6*/
static const value_string pcep_error_value_6_vals[] = {
    {1,  "RP object missing"},
    {2,  "RRO object missing for a reoptimization request (R bit of the RP Object set)"},
    {3,  "END-POINTS object missing"},
    {4,  "MONITORINS object missing"},
    {8,  "LSP Object missing"},
    {9,  "ERO Object missing"},
    {10, "SRP Object missing"},
    {11, "LSP-IDENTIFIERS TLV missing"},
    {12, "LSP-DB-VERSION TLV missing"},
    {13, "LSP cleanup TLV missing"},
    {14, "SYMBOLIC-PATH-NAME TLV missing"},
    {15, "DISJOINTNESS-CONFIGURATION TLV missing"},
    {16, "Scheduled TLV missing"},
    {17, "CCI object missing"},
    {18, "VIRTUAL-NETWORK-TLV missing"},
    {0, NULL}
};

/*Error values for error type 10*/
static const value_string pcep_error_value_10_vals[] = {
    {1,  "Reception of an object with P flag not set although the P-flag must be set"}, /*RFC 5440*/
    {2,  "Bad label value"},                                                            /* RFC 8664 */
    {3,  "Unsupported number of SR-ERO subobjects"},                                    /* RFC 8664 */
    {4,  "Bad label format"},                                                           /* RFC 8664 */
    {5,  "ERO mixes SR-ERO subobjects with other subobject types"},                     /* RFC 8664 */
    {6,  "Both SID and NAI are absent in ERO subobject"},                               /* RFC 8664 */
    {7,  "Both SID and NAI are absent in RRO subobject"},                               /* RFC 8664 */
    {8,  "SYMBOLIC-PATH-NAME TLV missing"},                                             /* RFC 8281 */
    {9,  "MSD exceeds the default for the PCEP session"},                               /* RFC 8664 */
    {10, "RRO mixes SR-RRO subobjects with other object types"},                        /* RFC 8664 */
    {11, "Malformed object"},                                                           /* RFC 8408 */
    {12, "Missing PCE-SR-CAPABILITY sub-TLV"},                                          /* RFC 8664 */
    {13, "Unsupported NAI Type in the SR-ERO/SR-RRO subobject"},                        /* RFC 8664 */
    {14, "Unknown SID"},                                                                /* RFC 8664 */
    {15, "NAI cannot be resolved to a SID"},                                            /* RFC 8664 */
    {16, "Could not find SRGB"},                                                        /* RFC 8664 */
    {17, "SID index exceeds SRGB size"},                                                /* RFC 8664 */
    {18, "Could not find SRLB"},                                                        /* RFC 8664 */
    {19, "SID index exceeds SRLB size"},                                                /* RFC 8664 */
    {20, "Inconsistent SIDs in SR-ERO/SR-RRO subobjects"},                              /* RFC 8664 */
    {21, "MSD must be nonzero"},                                                        /* RFC 8664 */
    {22, "Mismatch of O field in S2LS and LSP object"},                                 /* RFC 8623 */
    {23, "Incompatible OF codes in H-PCE"},                                             /* RFC 8685 */
    {24, "Bad BANDWIDTH object type 3 or 4"},                                           /* RFC 8779 */
    {25, "Unsupported LSP Protection Flags in PROTECTION-ATTRIBUTE TLV"},               /* RFC 8779 */
    {26, "Unsupported Secondary LSP Protection Flags in PROTECTION-ATTRIBUTE TLV"},     /* RFC 8779 */
    {27, "Unsupported Link Protection Type in PROTECTION-ATTRIBUTE TLV"},               /* RFC 8779 */
    {28, "LABEL-SET TLV present with O bit set but without R bit set in RP"},           /* RFC 8779 */
    {29, "Wrong LABEL-SET TLV present with O and L bits set"},                          /* RFC 8779 */
    {30, "Wrong LABEL-SET TLV present with O bit set and wrong format"},                /* RFC 8779 */
    {31, "Missing GMPLS-CAPABILITY TLV"},                                               /* RFC 8779 */
    {32, "Incompatible OF code"},                                                       /* RFC 8800 */
    {33, "Missing PCECC Capability sub-TLV"},                                           /* RFC 9050 */
    {34, "Missing PCE-SRv6-CAPABILITY sub-TLV"},                                        /* draft-ietf-pce-segment-routing-ipv6-13 */
    {35, "Both SID and NAI are absent in SRv6-RRO subobject "},                         /* draft-ietf-pce-segment-routing-ipv6-13 */
    {36, "RRO mixes SRv6-RRO subobjects with other subobject types"},                   /* draft-ietf-pce-segment-routing-ipv6-13 */
    {37, "Invalid SRv6 SID Structure "},                                                /* draft-ietf-pce-segment-routing-ipv6-13 */
    {38, "Conflicting Path ID"},                                                        /* draft-ietf-pce-multipath-07 */
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
    {2, "Fragmented Report failure"},
    {3, "Fragmented Update failure"},
    {4, "Fragmented Instantiation failure"},
    {0, NULL}
};

/*Error values for error type 19*/
static const value_string pcep_error_value_19_vals[] = {
    {1,  "Attempted LSP Update Request for a non-delegated LSP. The PCEP-ERROR Object is followed by the LSP Object that identifies the LSP"},
    {2,  "Attempted LSP Update Request if active stateful PCE capability was not advertised"},
    {3,  "Attempted LSP Update Request for an LSP identified by an unknown PLSP-ID"},
    {4,  "Unassigned"},
    {5,  "Attempted LSP State Report if active stateful PCE capability was not advertised"},
    {6,  "PCE-initiated LSP limit reached"},                    /* draft-ietf-pce-pce-initiated-lsp */
    {7,  "Delegation for PCE-initiated LSP cannot be revoked"}, /* draft-ietf-pce-pce-initiated-lsp */
    {8,  "Non-zero PLSP-ID in LSP initiation request"},         /* draft-ietf-pce-pce-initiated-lsp */
    {9,  "LSP is not PCE-initiated"},                           /* draft-ietf-pce-pce-initiated-lsp */
    {10, "PCE-initiated operation-frequency limit reached"},    /* draft-ietf-pce-pce-initiated-lsp */
    {11, "Attempted LSP State Report for P2MP if stateful PCE capability for P2MP was not advertised"},
    {12, "Attempted LSP Update Request for P2MP if active stateful PCE capability for P2MP was not advertised"},
    {13, "Attempted LSP Instantiation Request for P2MP if stateful PCE instantiation capability for P2MP was not advertised"},
    {14, "Auto-Bandwidth capability was not advertised"},
    {15, "Attempted LSP scheduling while the scheduling capability was not advertised"},
    {16, "Attempted PCECC operations when PCECC capability was not advertised"},
    {17, "Stateful PCE capability was not advertised"},
    {18, "Unknown Label"},
    {19, "Attempted SRv6 when the capability was not advertised"},
    {20, "Not supported path backup"},
    {21, "Non-empty path"},
    {0, NULL}
};

/*Error values for error type 20*/
static const value_string pcep_error_value_20_vals[] = {
    {1, "A PCE indicates to a PCC that it cannot process (an otherwise valid) LSP State Report. The PCEP-ERROR Object is followed by the LSP Object that identifies the LSP"},
    {2, "LSP Database version mismatch."},
    {3, "The LSP-DB-VERSION TLV Missing when state synchronization avoidance is enabled."},
    {4, "Attempt to trigger a synchronization when the TRIGGERED-SYNC capability has not been advertised."},
    {5, "A PCC indicates to a PCE that it cannot complete the state synchronization"},
    {6, "No sufficient LSP change information for incremental LSP state synchronization."},
    {7, "Received an invalid LSP DB Version Number"},
    {0, NULL}
};

/* Error values for error type 21 */
static const value_string pcep_error_value_21_vals[] = {
    {1, "Unsupported path setup type"},
    {2, "Mismatched path setup type"},
    {0, NULL}
};

/*Error values for error type 23*/
static const value_string pcep_error_value_23_vals[] = {
    {1, "SYMBOLIC-PATH-NAME in use"},                                       /* draft-ietf-pce-pce-initiated-lsp */
    {2, "Speaker identity included for an LSP that is not PCE-initiated"},  /* draft-ietf-pce-pce-initiated-lsp */
    {0, NULL}
};

/*Error values for error type 24*/
static const value_string pcep_error_value_24_vals[] = {
    {1, "Unacceptable instantiation parameters"},   /* draft-ietf-pce-pce-initiated-lsp */
    {2, "Internal error"},                          /* draft-ietf-pce-pce-initiated-lsp */
    {3, "Signaling error"},                         /* draft-ietf-pce-pce-initiated-lsp */
    {0, NULL}
};

/*Error values for error type 25*/
static const value_string pcep_error_value_25_vals[] = {
    {1, "Reception of StartTLS after any PCEP exchange"},
    {2, "Reception of any other message apart from StartTLS, Open, or PCErr"},
    {3, "Failure, connection without TLS is not possible"},
    {4, "Failure, connection without TLS is possible"},
    {5, "No StartTLS message (nor PCErr/Open) before StartTLSWait timer expiry"},
    {0, NULL}
};

/*Error values for error type 26*/
static const value_string pcep_error_value_26_vals[] = {
    {1, "Association-type is not supported"},                                              /* [RFC8697] */
    {2, "Too many LSPs in the association group"},                                         /* [RFC8697] */
    {3, "Too many association groups"},                                                    /* [RFC8697] */
    {4, "Association unknown"},                                                            /* [RFC8697] */
    {5, "Operator-configured association information mismatch "},                          /* [RFC8697] */
    {6, "Association information mismatch"},                                               /* [RFC8697] */
    {7, "Cannot join the association group"},                                              /* [RFC8697] */
    {8, "Association ID not in range"},                                                    /* [RFC8697] */
    {9, "Tunnel ID or End points mismatch for Path Protection Association"},               /* [RFC8745] */
    {10, "Attempt to add another working/protection LSP for Path Protection Association"}, /* [RFC8745] */
    {11, "Protection type is not supported"},                                              /* [RFC8745] */
    {12, "Not expecting policy parameters"},                                               /* [RFC9005] */
    {13, "Unacceptable policy parameters"},                                                /* [RFC9005] */
    {14, "Association group mismatch"},                                                    /* [RFC9059] */
    {15, "Tunnel mismatch in the association group"},                                      /* [RFC9059] */
    {16, "Path Setup Type not supported"},                                                 /* [RFC9059] */
    {17, "Bidirectional LSP direction mismatch"},                                          /* [RFC9059] */
    {18, "Bidirectional LSP co-routed mismatch"},                                          /* [RFC9059] */
    {19, "Endpoint mismatch in the association group"},                                    /* [RFC9059] */
    {0, NULL}
};

/*Error values for error type 27*/
static const value_string pcep_error_value_27_vals[] = {
    {1, "Insufficient memory"},           /* [RFC8780] */
    {2, "RWA computation not supported"}, /* [RFC8780] */
    {3, "Syntactical encoding error"},    /* [RFC8780] */
    {0, NULL}
};

/*Error values for error type 28*/
static const value_string pcep_error_value_28_vals[] = {
    {1, "H-PCE Capability not advertised"},          /* [RFC8685] */
    {2, "Parent PCE Capability cannot be provided"}, /* [RFC8685] */
    {0, NULL}
};

/*Error values for error type 29*/
static const value_string pcep_error_value_29_vals[] = {
    {1, "Unacceptable request message"},                    /* [RFC8779] */
    {2, "Generalized bandwidth value not supported"},       /* [RFC8779] */
    {3, "Label set constraint could not be met"},           /* [RFC8779] */
    {4, "Label constraint could not be met"},               /* [RFC8779] */
    {5, "Constraints could not be met for some intervals"}, /* [RFC8934] */
    {0, NULL}
};

/*Error values for error type 30*/
static const value_string pcep_error_value_30_vals[] = {
    {1, "Unsupported FlowSpec"},  /* [RFC9168] */
    {2, "Malformed FlowSpec"},    /* [RFC9168] */
    {3, "Unresolvable Conflict"}, /* [RFC9168] */
    {4, "Unknown FlowSpec"},      /* [RFC9168] */
    {5, "Unsupported LPM Route"}, /* [RFC9168] */
    {0, NULL}
};

/*Error values for error type 31*/
static const value_string pcep_error_value_31_vals[] = {
    {1, "Label out of range"},                   /* [RFC9050] */
    {2, "Instruction failed"},                   /* [RFC9050] */
    {3, "Invalid CCI"},                          /* [RFC9050] */
    {4, "Unable to allocate the specified CCI"}, /* [RFC9050] */
    {5, "Invalid next-hop information"},         /* [RFC9050] */
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

static const value_string pcep_object_lsp_flags_operational_vals[] = {
    {0, "DOWN"          },
    {1, "UP"            },
    {2, "ACTIVE"        },
    {3, "GOING-DOWN"    },
    {4, "GOING-UP"      },
    {5, "Reserved"      },
    {6, "Reserved"      },
    {7, "Reserved"      },
    {0, NULL }
};

static const value_string pcep_tlv_lsp_error_code_vals[] = {
    {1, "Unknown reason"                        },
    {2, "Limit reached for PCE-controlled LSPs" },
    {3, "Too many pending LSP update requests"  },
    {4, "Unacceptable parameters"               },
    {5, "Internal error"                        },
    {6, "LSP administratively brought down"     },
    {7, "LSP preempted"                         },
    {8, "RSVP signaling error"                  },
    {0, NULL }
};

static const value_string pcep_pst_vals[] = {
    {0, "Path is setup via RSVP-TE signaling (default)" },
    {1, "Path is setup using Segment Routing" },
    {3, "Path is setup using SRv6" },
    {0, NULL }
};

static const value_string pcep_sr_nt_vals[] = {
    {0, "NAI is absent" },
    {1, "IPv4 Node ID" },
    {2, "IPv6 Node ID" },
    {3, "IPv4 Adjacency" },
    {4, "IPv6 Adjacency with global IPv6 addresses" },
    {5, "Unnumbered Adjacency with IPv4 NodeIDs" },
    {6, "IPv6 Adjacency with link-local IPv6 addresses" },
    {0, NULL }
};

/* types of leaves in a P2MP request */
static const value_string pcep_p2mp_leaf_type_vals[] = {
    {EP_P2MP_NEW_LEAF_TYPE, "New leaves to add"                                        },
    {EP_P2MP_OLD_REMOVE_LEAF_TYPE , "Old leaves to remove"                             },
    {EP_P2MP_OLD_MODIFY_LEAF_TYPE, "Old leaves whose path can be modified/reoptimized" },
    {EP_P2MP_OLD_UNCHANGED_LEAF_TYPE, "Old leaves whose path must be left unchanged"   },
    {0, NULL }
};

/* Association Type Fields.  */
/* https://www.iana.org/assignments/pcep/pcep.xhtml#association-type-field */
static const value_string pcep_association_type_field_vals[] = {
    {0, "Reserved"}, /* RFC 8697*/
    {1, "Path Protection Association"}, /* RFC 8745 */
    {2, "Disjoint Association"}, /* RFC 8800 */
    {3, "Policy Association"}, /* RFC 9005 */
    {4, "Single-Sided Bidirectional LSP Association"}, /* RFC 9059 */
    {5, "Double-Sided Bidirectional LSP Association"}, /* RFC 9059 */
    {6, "SR Policy Association"}, /* TEMPORARY registered 2021-03-30 expires 2022-03-30 draft-ietf-pce-segment-routing-policy-cp-04 */
    {7, "VN Association"}, /* RFC 9358 */
    {0, NULL }
};

/* Path Setup Type Capability Sub TLV Type Indicators */
static const value_string pcep_path_setup_type_capability_sub_tlv_vals[] = {
    {0,  "Reserved"                                 }, /* RFC 8664*/
    {1,  "PCECC-CAPABILITY"                        }, /* RFC 9050*/
    {26, "SR-PCE-CAPABILITY"                       }, /* RFC 8664*/
    {0,  NULL }
};


/* Protocol Origin values in SR Policy Candidate Path Identifiers TLV*/
static const value_string pcep_sr_policy_id_proto_origin_vals[] = {
    {10, "PCEP"                        }, /*  draft-ietf-spring-segment-routing-policy section 2.3 */
    {20, "BGP SR Policy"               }, /*  draft-ietf-spring-segment-routing-policy section 2.3 */
    {30, "Via Configuration"           }, /*  draft-ietf-spring-segment-routing-policy section 2.3 */
    {0,  NULL }
};

/* SRv6 Endpoint behavior */
/* https://www.iana.org/assignments/segment-routing/segment-routing.xhtml */
static const value_string srv6_endpoint_behavior_vals[] = {
    {1,     "End" },
    {2,     "End with PSP" },
    {3,     "End with USP" },
    {4,     "End with PSP & USP" },
    {5,     "End.X" },
    {6,     "End.X with PSP" },
    {7,     "End.X with USP" },
    {8,     "End.X with PSP & USP" },
    {9,     "End.T" },
    {10,    "End.T with PSP" },
    {11,    "End.T with USP" },
    {12,    "End.T with PSP & USP" },
    {13,    "Unassigned" },
    {14,    "End.B6.Encaps" },
    {15,    "End.BM" },
    {16,    "End.DX6" },
    {17,    "End.DX4" },
    {18,    "End.DT6" },
    {19,    "End.DT4" },
    {20,    "End.DT46" },
    {21,    "End.DX2" },
    {22,    "End.DX2V" },
    {23,    "End.DT2U" },
    {24,    "End.DT2M" },
    {25,    "Reserved" },
    {26,    "Unassigned" },
    {27,    "End.B6.Encaps.Red" },
    {28,    "End with USD" },
    {29,    "End with PSP & USD" },
    {30,    "End with USP & USD" },
    {31,    "End with PSP, USP & USD" },
    {32,    "End.X with USD" },
    {33,    "End.X with PSP & USD" },
    {34,    "End.X with USP & USD" },
    {35,    "End.X with PSP, USP & USD" },
    {36,    "End.T with USD" },
    {37,    "End.T with PSP & USD" },
    {38,    "End.T with USP & USD" },
    {39,    "End.T with PSP, USP & USD" },
    {40,    "End.MAP" },
    {41,    "End.Limit" },
    {42,    "End with NEXT-ONLY-CSID" },
    {43,    "End with NEXT-CSID" },
    {44,    "End with NEXT-CSID & PSP" },
    {45,    "End with NEXT-CSID & USP" },
    {46,    "End with NEXT-CSID, PSP & USP" },
    {47,    "End with NEXT-CSID & USD" },
    {48,    "End with NEXT-CSID, PSP & USD" },
    {49,    "End with NEXT-CSID, USP & USD" },
    {50,    "End with NEXT-CSID, PSP, USP & USD" },
    {51,    "End.X with NEXT-ONLY-CSID" },
    {52,    "End.X with NEXT-CSID" },
    {53,    "End.X with NEXT-CSID & PSP" },
    {54,    "End.X with NEXT-CSID & USP" },
    {55,    "End.X with NEXT-CSID, PSP & USP" },
    {56,    "End.X with NEXT-CSID & USD" },
    {57,    "End.X with NEXT-CSID, PSP & USD" },
    {58,    "End.X with NEXT-CSID, USP & USD" },
    {59,    "End.X with NEXT-CSID, PSP, USP & USD" },
    {60,    "End.DX6 with NEXT-CSID" },
    {61,    "End.DX4 with NEXT-CSID" },
    {62,    "End.DT6 with NEXT-CSID" },
    {63,    "End.DT4 with NEXT-CSID" },
    {64,    "End.DT46 with NEXT-CSID" },
    {65,    "End.DX2 with NEXT-CSID" },
    {66,    "End.DX2V with NEXT-CSID" },
    {67,    "End.DT2U with NEXT-CSID" },
    {68,    "End.DT2M with NEXT-CSID" },
    {69,    "End.M.GTP6.D" },
    {70,    "End.M.GTP6.Di" },
    {71,    "End.M.GTP6.E" },
    {72,    "End.M.GTP4.E" },
    { 0,  NULL }
};

#define OBJ_HDR_LEN  4       /* length of object header */

/*------------------------------------------------------------
 * SUB-TLVS
 * ----------------------------------------------------------------*/
static void
dissect_pcep_path_setup_capabilities_sub_tlvs(proto_tree *pcep_tlv, tvbuff_t *tvb, int offset, int length, int ett_pcep_obj)
{
    proto_tree *sub_tlv;
    uint16_t    sub_tlv_length, sub_tlv_type;
    int         j;
    int         padding = 0;

    static int * const sr_pce_capability_sub_tlv_flags[] = {
        &hf_pcep_sr_pce_capability_sub_tlv_flags_n,
        &hf_pcep_sr_pce_capability_sub_tlv_flags_x,
        NULL
    };

    for (j = 0; j < length; j += 4 + sub_tlv_length + padding) {
        sub_tlv_type = tvb_get_ntohs(tvb, offset+j);
        sub_tlv_length = tvb_get_ntohs(tvb, offset + j + 2);
        sub_tlv = proto_tree_add_subtree(pcep_tlv, tvb, offset + j, sub_tlv_length+4,
                    ett_pcep_obj, NULL, val_to_str(sub_tlv_type, pcep_path_setup_type_capability_sub_tlv_vals, "Unknown SubTLV (%u). "));
        proto_tree_add_item(sub_tlv, hf_pcep_path_setup_type_capability_sub_tlv_type, tvb, offset + j, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tlv, hf_pcep_path_setup_type_capability_sub_tlv_length, tvb, offset + 2 + j, 2, ENC_BIG_ENDIAN);
        switch (sub_tlv_type)
        {
            case 1:    /* PCECC-CAPABILITY */
               //TODO
               break;

            case 26:  /* SR PCE CAPABILITY */
               proto_tree_add_item(sub_tlv, hf_pcep_sr_pce_capability_sub_tlv_reserved, tvb, offset + 4 + j, 2, ENC_NA);
               proto_tree_add_bitmask(sub_tlv, tvb, offset+4+j+2, hf_pcep_sr_pce_capability_sub_tlv_flags, ett_pcep_obj, sr_pce_capability_sub_tlv_flags, ENC_NA);
               proto_tree_add_item(sub_tlv, hf_pcep_sr_pce_capability_sub_tlv_msd, tvb, offset + 4 + j + 3, 1, ENC_NA);
               break;
        }
    }

}

/*------------------------------------------------------------
 * PCEP TLVS
 *----------------------------------------------------------------*/

/* The content of Extended Association ID TLV, type = 31 is scoped
 *  on the association type. The TLV dissection receives such
 *  information to be able to decode properly the TLV
 *  All the other TLVs do not need scope at the moment.
*/
static void
dissect_pcep_tlvs_with_scope(proto_tree *pcep_obj, tvbuff_t *tvb, int offset, int length, int ett_pcep_obj, uint16_t association_type)
{
    proto_tree *tlv;
    uint16_t    tlv_length, tlv_type, of_code, assoc_type;
    uint32_t psts;
    int         i, j;
    int         padding = 0;

    static int * const tlv_stateful_pce_capability_flags[] = {
        &hf_pcep_lsp_update_capability,
        &hf_pcep_include_db_version,
        &hf_pcep_lsp_instantiation_capability,
        &hf_pcep_triggered_resync,
        &hf_pcep_delta_lsp_sync_capability,
        &hf_pcep_triggered_initial_sync,
        NULL
    };

    static int * const tlv_sr_pce_capability_flags[] = {
        &hf_pcep_sr_pce_capability_flags_l,
        NULL
    };

    for (j = 0; j < length; j += 4 + tlv_length + padding) {
        tlv_type = tvb_get_ntohs(tvb, offset+j);
        tlv_length = tvb_get_ntohs(tvb, offset + j + 2);
        tlv = proto_tree_add_subtree(pcep_obj, tvb, offset + j, tlv_length+4,
                    ett_pcep_obj, NULL, val_to_str(tlv_type, pcep_tlvs_vals, "Unknown TLV (%u). "));
        proto_tree_add_item(tlv, hf_pcep_tlv_type, tvb, offset + j, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tlv, hf_pcep_tlv_length, tvb, offset + 2 + j, 2, ENC_BIG_ENDIAN);
        switch (tlv_type)
        {
            case 1:    /* NO-PATH TLV */
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_pce,          tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);   /* RFC 5440 */
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_unk_dest,     tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);   /* RFC 5440 */
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_unk_src,      tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);   /* RFC 5440 */
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_brpc,         tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);   /* RFC 5441 */
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_pks,          tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);   /* RFC 5520 */
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_no_gco_migr,  tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);   /* RFC 5557 */
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_no_gco_soln,  tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);   /* RFC 5557 */
                proto_tree_add_item(tlv, hf_pcep_no_path_tlvs_p2mp,         tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);   /* RFC 6006 */
                break;

            case 3:   /* REQ-MISSING TLV */
                proto_tree_add_item(tlv, hf_pcep_request_id, tvb, offset+4+j, tlv_length, ENC_BIG_ENDIAN);
                break;

            case 4:   /* OF TLV */
                for (i=0; i<tlv_length/2; i++) {
                    of_code = tvb_get_ntohs(tvb, offset+4+j+i*2);
                    proto_tree_add_uint_format(tlv, hf_pcep_of_code, tvb, offset+4+j+i*2, 2, of_code, "OF-Code #%d: %s (%u)",
                                               i+1, val_to_str_const(of_code, pcep_of_vals, "Unknown"), of_code);
                }
                break;

            case 7:   /* VENDOR-INFORMATION-TLV (RFC7470)*/
                proto_tree_add_item(tlv, hf_pcep_tlv_enterprise_number, tvb, offset+4+j, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_tlv_enterprise_specific_info, tvb, offset+4+j + 4, tlv_length - 4, ENC_STR_HEX);
                break;

            case 16:    /* STATEFUL-PCE-CAPABILITY TLV */
                proto_tree_add_bitmask(tlv, tvb, offset+4+j, hf_pcep_stateful_pce_capability_flags, ett_pcep_obj, tlv_stateful_pce_capability_flags, ENC_NA);
                break;

            case 17:    /* SYMBOLIC-PATH-NAME TLV */
                proto_tree_add_item(tlv, hf_pcep_symbolic_path_name, tvb, offset+4+j, tlv_length, ENC_ASCII);
                break;

            case 18:    /* IPV4-LSP-IDENTIFIERS TLV */
                proto_tree_add_item(tlv, hf_pcep_ipv4_lsp_id_tunnel_sender_address, tvb, offset+4+j, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_ipv4_lsp_id_lsp_id, tvb, offset+4+j + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_ipv4_lsp_id_tunnel_id, tvb, offset+4+j + 6, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_ipv4_lsp_id_extended_tunnel_id, tvb, offset+4+j + 8, 4, ENC_NA);
                proto_tree_add_item(tlv, hf_pcep_ipv4_lsp_id_tunnel_endpoint_address, tvb, offset+4+j + 12, 4, ENC_BIG_ENDIAN);
                break;

            case 19:    /* IPV6-LSP-IDENTIFIERS TLV */
                proto_tree_add_item(tlv, hf_pcep_ipv6_lsp_id_tunnel_sender_address, tvb, offset+4+j, 16, ENC_NA);
                proto_tree_add_item(tlv, hf_pcep_ipv6_lsp_id_lsp_id, tvb, offset+4+j + 16, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_ipv6_lsp_id_tunnel_id, tvb, offset+4+j + 18, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_ipv6_lsp_id_extended_tunnel_id, tvb, offset+4+j + 20, 16, ENC_NA);
                proto_tree_add_item(tlv, hf_pcep_ipv6_lsp_id_tunnel_endpoint_address, tvb, offset+4+j + 36, 16, ENC_NA);
                break;

            case 20:    /* LSP-ERROR-CODE TLV */
                proto_tree_add_item(tlv, hf_pcep_lsp_error_code, tvb, offset+4+j, 4, ENC_BIG_ENDIAN);
                break;

            case 21:    /* RSVP-ERROR-SPEC TLV */
                proto_tree_add_item(tlv, hf_pcep_rsvp_user_error_spec, tvb, offset+4+j, tlv_length, ENC_ASCII);
                break;

            case 23:    /* LSP-DB-VERSION TLV */
                proto_tree_add_item(tlv, hf_pcep_lsp_state_db_version_number, tvb, offset+4+j, 8, ENC_BIG_ENDIAN);
                break;

            case 24:    /* SPEAKER-ENTITY-ID TLV */
                proto_tree_add_item(tlv, hf_pcep_speaker_entity_id, tvb, offset+4+j, tlv_length, ENC_ASCII);
                break;

            case 26:    /* SR-PCE-CAPABILITY TLV Deprecated */
                proto_tree_add_item(tlv, hf_pcep_sr_pce_capability_reserved, tvb, offset + 4 + j, 2, ENC_NA);
                proto_tree_add_bitmask(tlv, tvb, offset+4+j+2, hf_pcep_sr_pce_capability_flags, ett_pcep_obj, tlv_sr_pce_capability_flags, ENC_NA);
                proto_tree_add_item(tlv, hf_pcep_sr_pce_capability_msd, tvb, offset + 4 + j + 3, 1, ENC_NA);
                break;

            case 27:    /* PATH-SETUP-TYPE TLV (FF: squatted pre IANA assignment) */
            case 28:    /* PATH-SETUP-TYPE TLV (FF: IANA code point) */
                proto_tree_add_item(tlv, hf_pcep_path_setup_type_reserved24, tvb, offset + 4 + j, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_path_setup_type, tvb, offset + 4 + j + 3, 1, ENC_NA);
                break;

            case 29:    /* OP-CONF-ASSOC-RANGE */
                offset += 4 + j;
                while(tlv_length > 0) {
                    proto_tree_add_item(tlv, hf_pcep_op_conf_assoc_range_reserved, tvb, offset, 2, ENC_NA);
                    offset += 2;
                    tlv_length -= 2;
                    proto_tree_add_item(tlv, hf_pcep_op_conf_assoc_range_assoc_type, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    tlv_length -= 2;
                    proto_tree_add_item(tlv, hf_pcep_op_conf_assoc_range_start_assoc, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    tlv_length -= 2;
                    proto_tree_add_item(tlv, hf_pcep_op_conf_assoc_range_range, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;
                    tlv_length -= 2;
                }
                break;

            case 30:    /* GLOBAL-ASSOCIATION-SOURCE */
                proto_tree_add_item(tlv, hf_pcep_association_source_global, tvb, offset + 4 + j, 4, ENC_BIG_ENDIAN);
                break;

            case 31:    /* EXTENDED-ASSOCIATION-ID TLV */
                /* The extend association ID is scoped depending on the association type of the object
                in which the TLV is present */
                if (association_type==6) {
                  if (tlv_length==8) {
                    proto_tree_add_item(tlv, hf_pcep_association_id_extended_color, tvb, offset + 4 + j, 4, ENC_NA);
                    proto_tree_add_item(tlv, hf_pcep_association_id_extended_ipv4_endpoint, tvb, offset + 8 + j, 4, ENC_NA);
                  } else if (tlv_length==20) {
                     proto_tree_add_item(tlv, hf_pcep_association_id_extended_color, tvb, offset + 4 + j, 4, ENC_NA);
                     proto_tree_add_item(tlv, hf_pcep_association_id_extended_ipv6_endpoint, tvb, offset + 8 + j, 16, ENC_NA);
                  } else {
                    proto_tree_add_item(tlv, hf_pcep_association_id_extended, tvb, offset + 4 + j, tlv_length, ENC_NA);
                  }
                } else {
                  proto_tree_add_item(tlv, hf_pcep_association_id_extended, tvb, offset + 4 + j, tlv_length, ENC_NA);
                }
                break;

            case 34:    /* PATH-SETUP-TYPE-CAPABILITY TLV */
                proto_tree_add_item(tlv, hf_pcep_path_setup_type_capability_reserved24, tvb, offset + 4 + j, 3, ENC_BIG_ENDIAN);
                proto_tree_add_item_ret_uint(tlv, hf_pcep_path_setup_type_capability_psts, tvb, offset + 4 + j + 3, 1, ENC_NA, &psts);
                for (i = 0; i < (int)psts; i++) {
                    proto_tree_add_item(tlv, hf_pcep_path_setup_type_capability_pst, tvb, offset + 4 + j + 4 + i, 1, ENC_NA);
                }

                padding = (4 - (psts % 4)) % 4;
                if (padding != 0) {
                    proto_tree_add_item(tlv, hf_pcep_tlv_padding, tvb, offset + 4 + j + 4 + psts, padding, ENC_NA);
                }
                if (tlv_length>8+psts+padding) {
                    //There are sub-TLVs to decode
                    dissect_pcep_path_setup_capabilities_sub_tlvs(tlv, tvb, offset+j+8+psts+padding, tlv_length -psts- padding-4, ett_pcep_obj);
                }
                break;

            case 35:    /* ASSOC-Type-List TLV */
                for (i=0; i<tlv_length/2; i++) {
                    assoc_type = tvb_get_ntohs(tvb, offset+4+j+i*2);
                    proto_tree_add_uint_format(tlv, hf_pcep_association_type, tvb, offset+4+j+i*2, 2, assoc_type, "Assoc-Type #%d: %s (%u)",
                                               i+1, val_to_str_const(assoc_type, pcep_association_type_field_vals, "Unknown"), assoc_type);
                }
                break;

            case 40:    /* SRCPAG-INFO TLV */
                proto_tree_add_item(tlv, hf_pcep_srcpag_info_color, tvb, offset + 4 + j, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_srcpag_info_destination_endpoint, tvb, offset + 4 + j + 4, 4, ENC_NA);
                proto_tree_add_item(tlv, hf_pcep_srcpag_info_preference, tvb, offset + 4 + j + 8, 4, ENC_NA);
                break;

            case 56:   /* SRPOLICY-POL-NAME */
                proto_tree_add_item(tlv, hf_pcep_sr_policy_name, tvb, offset+4+j, tlv_length, ENC_ASCII);
                break;

            case 57:   /* SRPOLICY-CPATH-ID */
                proto_tree_add_item(tlv, hf_pcep_sr_policy_cpath_id_proto_origin, tvb, offset + 4 + j, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_sr_policy_cpath_id_originator_asn, tvb, offset + 8 + j, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_sr_policy_cpath_id_originator_address, tvb, offset + 24+ j, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(tlv, hf_pcep_sr_policy_cpath_id_discriminator, tvb, offset + 28 + j, 4, ENC_BIG_ENDIAN);
                break;

            case 58:   /* SRPOLICY-CPATH-NAME */
                proto_tree_add_item(tlv, hf_pcep_sr_policy_cpath_name, tvb, offset+4+j, tlv_length, ENC_ASCII);
                break;

            case 59:   /* SRPOLICY-CPATH-PREFERENCE */
                proto_tree_add_item(tlv, hf_pcep_sr_policy_cpath_preference, tvb, offset + 4 + j, 4, ENC_BIG_ENDIAN);
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

static void
dissect_pcep_tlvs(proto_tree *pcep_obj, tvbuff_t *tvb, int offset, int length, int ett_pcep_obj)
{
  dissect_pcep_tlvs_with_scope(pcep_obj, tvb, offset, length, ett_pcep_obj,0);
}

/*------------------------------------------------------------------------------
 *SUBOBJECTS
 *------------------------------------------------------------------------------*/
static void
dissect_subobj_ipv4(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, int ett_pcep_obj, unsigned length)
{
    proto_tree *pcep_subobj_ipv4;
    proto_tree *pcep_subobj_ipv4_flags;
    proto_item *ti;
    uint8_t     prefix_length;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_IPv4, tvb, offset, length, ENC_NA);
    pcep_subobj_ipv4 = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 8) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad IPv4 subobject: length %u != 8", length);
        return;
    }

    prefix_length = tvb_get_uint8(tvb, offset+6);
    proto_item_append_text(ti, ": %s/%u", tvb_ip_to_str(pinfo->pool, tvb, offset+2),
                           prefix_length);

    switch (obj_class) {

        case PCEP_EXPLICIT_ROUTE_OBJ:
        case PCEP_SERO_OBJ:
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_l,             tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_PCEPF_SUBOBJ_7F,                tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_length,        tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_ipv4,          tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_prefix_length, tvb, offset+6, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_padding,       tvb, offset+7, 1, ENC_NA);
            break;

        case PCEP_RECORD_ROUTE_OBJ:
        case PCEP_SRRO_OBJ:
            proto_tree_add_item(pcep_subobj_ipv4, hf_PCEPF_SUBOBJ,                   tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_length,        tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_ipv4,          tvb, offset+2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_prefix_length, tvb, offset+6, 1, ENC_NA);
            ti = proto_tree_add_item(pcep_subobj_ipv4, hf_pcep_subobj_ipv4_flags,    tvb, offset+7, 1, ENC_NA);
            pcep_subobj_ipv4_flags = proto_item_add_subtree(ti, ett_pcep_obj);
            proto_tree_add_item(pcep_subobj_ipv4_flags, hf_pcep_subobj_flags_lpa,       tvb, offset+7, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv4_flags, hf_pcep_subobj_flags_lpu,       tvb, offset+7, 1, ENC_NA);
            break;

        case PCEP_IRO_OBJ:
        case PCEP_OBJ_BRANCH_NODE_CAPABILITY:
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
dissect_subobj_ipv6(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, int ett_pcep_obj, unsigned length)
{
    proto_tree *pcep_subobj_ipv6;
    proto_tree *pcep_subobj_ipv6_flags;
    proto_item *ti;
    uint8_t     prefix_length;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_IPv6, tvb, offset, length, ENC_NA);
    pcep_subobj_ipv6 = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 20) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad IPv6 subobject: length %u != 20", length);
        return;
    }

    prefix_length = tvb_get_uint8(tvb, offset+18);
    proto_item_append_text(ti, ": %s/%u", tvb_ip6_to_str(pinfo->pool, tvb, offset+2),
                           prefix_length);

    switch (obj_class) {
        case PCEP_EXPLICIT_ROUTE_OBJ:
        case PCEP_SERO_OBJ:
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_l,             tvb, offset,    1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_PCEPF_SUBOBJ_7F,                tvb, offset,    1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_length,        tvb, offset+1,  1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_ipv6,          tvb, offset+2, 16, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_prefix_length, tvb, offset+18, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_padding,       tvb, offset+19, 1, ENC_NA);
            break;

        case PCEP_RECORD_ROUTE_OBJ:
        case PCEP_SRRO_OBJ:
            proto_tree_add_item(pcep_subobj_ipv6, hf_PCEPF_SUBOBJ,                   tvb, offset,    1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_length,        tvb, offset+1,  1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_ipv6,          tvb, offset+2, 16, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_prefix_length, tvb, offset+18, 1, ENC_NA);
            ti = proto_tree_add_item(pcep_subobj_ipv6, hf_pcep_subobj_ipv6_flags,    tvb, offset+19, 1, ENC_NA);
            pcep_subobj_ipv6_flags = proto_item_add_subtree(ti, ett_pcep_obj);
            proto_tree_add_item(pcep_subobj_ipv6_flags, hf_pcep_subobj_flags_lpa,       tvb, offset+19, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_ipv6_flags, hf_pcep_subobj_flags_lpu,       tvb, offset+19, 1, ENC_NA);
            break;

        case PCEP_IRO_OBJ:
        case PCEP_OBJ_BRANCH_NODE_CAPABILITY:
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
dissect_subobj_label_control(proto_tree *pcep_subobj_tree,  packet_info *pinfo, tvbuff_t *tvb,  int offset, int obj_class, int ett_pcep_obj, unsigned length)
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
        case PCEP_SERO_OBJ:
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_l,          tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_PCEPF_SUBOBJ_7F,                      tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_length,     tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_u,          tvb, offset+2, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_reserved,   tvb, offset+2, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_c_type,     tvb, offset+3, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_label,      tvb, offset+4, length-4, ENC_NA);
            break;

        case PCEP_RECORD_ROUTE_OBJ:
        case PCEP_SRRO_OBJ:
            proto_tree_add_item(pcep_subobj_label_control, hf_PCEPF_SUBOBJ,                         tvb, offset,   1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_length,     tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_u,          tvb, offset+2, 1, ENC_NA);

            ti = proto_tree_add_item(pcep_subobj_label_control, hf_pcep_subobj_label_control_flags, tvb, offset+2, 1, ENC_NA);
            pcep_subobj_label_flags = proto_item_add_subtree(ti, ett_pcep_obj);
            proto_tree_add_item(pcep_subobj_label_flags, hf_pcep_subobj_label_flags_gl,                tvb, offset+2, 1, ENC_NA);
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
dissect_subobj_sr(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, int ett_pcep_obj, unsigned length)
{
    proto_tree *pcep_subobj_sr_tree = NULL;
    proto_item *ti = NULL;
    proto_tree *sid_tree = NULL;
    proto_item *sid_item = NULL;
    uint16_t flags;
    uint8_t j = 0, nt = 0;
    uint8_t octet0, octet1, octet2;
    uint32_t label;
    uint8_t tc, bos, ttl;

    static int * const subobj_sr_flags[] = {
        &hf_pcep_subobj_sr_flags_m,
        &hf_pcep_subobj_sr_flags_c,
        &hf_pcep_subobj_sr_flags_s,
        &hf_pcep_subobj_sr_flags_f,
        NULL
    };

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_SR, tvb, offset, length, ENC_NA);
    pcep_subobj_sr_tree = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length < 8) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad SR subobject: length %u < 8", length);
        return;
    }

    flags = tvb_get_uint16(tvb, offset+2, ENC_NA);
    nt = ((tvb_get_uint8(tvb, offset + 2)) >> 4);

    if (obj_class == PCEP_EXPLICIT_ROUTE_OBJ || obj_class == PCEP_RECORD_ROUTE_OBJ) {
        if (obj_class == PCEP_EXPLICIT_ROUTE_OBJ) {
            proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_l, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_sr_tree, hf_PCEPF_SUBOBJ_7F, tvb, offset, 1, ENC_NA);
        }
        else {
            proto_tree_add_item(pcep_subobj_sr_tree, hf_PCEPF_SUBOBJ, tvb, offset, 1, ENC_NA);
        }

        proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_length, tvb, offset + 1, 1, ENC_NA);
        proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nt, tvb, offset + 2, 1, ENC_NA);
        proto_tree_add_bitmask(pcep_subobj_sr_tree, tvb, offset + 2, hf_pcep_subobj_sr_flags, ett_pcep_obj, subobj_sr_flags, ENC_NA);

        if ( ! (flags & PCEP_SUBOBJ_SR_FLAGS_S) ) { /* S flag is not set, SID exists */
            j = 4;
            sid_item = proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_sid, tvb, offset + 4, 4, ENC_BIG_ENDIAN);

            if (flags & PCEP_SUBOBJ_SR_FLAGS_M) { /* M flag is set, SID represents MPLS label stack */
                sid_tree = proto_item_add_subtree(sid_item, ett_pcep_obj);
                proto_tree_add_item(sid_tree, hf_pcep_subobj_sr_sid_label, tvb, offset+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(sid_tree, hf_pcep_subobj_sr_sid_tc,    tvb, offset+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(sid_tree, hf_pcep_subobj_sr_sid_s ,    tvb, offset+4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(sid_tree, hf_pcep_subobj_sr_sid_ttl,   tvb, offset+4, 4, ENC_BIG_ENDIAN);

                octet0 = tvb_get_uint8(tvb, offset+4);
                octet1 = tvb_get_uint8(tvb, offset+5);
                octet2 = tvb_get_uint8(tvb, offset+6);
                label = (octet0 << 12) + (octet1 << 4) + ((octet2 >> 4) & 0xff);
                tc = (octet2 >> 1) & 0x7;
                bos = (octet2 & 0x1);
                ttl = tvb_get_uint8(tvb, offset+7);
                proto_item_append_text(sid_tree, " (Label: %u, TC: %u, S: %u, TTL: %u)", label, tc, bos, ttl);
            }
        }

        if ( ! (flags & PCEP_SUBOBJ_SR_FLAGS_F) ) { /* F flag is not set, NAI exists */
            switch (nt) {
                case 1: /* IPv4 Node ID */
                    proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_ipv4_node, tvb, offset+j+4, 4, ENC_BIG_ENDIAN);
                    break;

                case 2: /* IPv6 Node ID */
                    proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_ipv6_node, tvb, offset+j+4, 16, ENC_NA);
                    break;

                case 3: /* IPv4 Adjacency */
                    proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_local_ipv4_addr,  tvb, offset+j+4, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_remote_ipv4_addr, tvb, offset+j+8, 4, ENC_BIG_ENDIAN);
                    break;

                case 4: /* IPv6 Adjacency with global IPv6 addresses */
                    proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_local_ipv6_addr,  tvb, offset+j+4,  16, ENC_NA);
                    proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_remote_ipv6_addr, tvb, offset+j+20, 16, ENC_NA);
                    break;

                case 5: /* Unnumbered Adjacency with IPv4 Node IDs */
                    proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_local_node_id,       tvb, offset+j+4,  4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_local_interface_id,  tvb, offset+j+8,  4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_remote_node_id,      tvb, offset+j+12, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_remote_interface_id, tvb, offset+j+16, 4, ENC_BIG_ENDIAN);
                    break;

                case 6: /* IPv6 Adjacency with link-local IPv6 addresses */
                 proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_local_ipv6_addr,  tvb, offset+j+4,  16, ENC_NA);
                 proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_local_interface_id,  tvb, offset+j+20,  4, ENC_BIG_ENDIAN);
                 proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_remote_ipv6_addr, tvb, offset+j+24, 16, ENC_NA);
                 proto_tree_add_item(pcep_subobj_sr_tree, hf_pcep_subobj_sr_nai_remote_interface_id, tvb, offset+j+40, 4, ENC_BIG_ENDIAN);

                default:
                    break;
            }
        }
    }
    else {
        expert_add_info_format(pinfo, ti, &ei_pcep_non_defined_subobject, "Non defined subobject for this object");
    }
}

static void
dissect_subobj_srv6(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, int ett_pcep_obj, unsigned length)
{
    proto_tree *subtree = NULL;
    proto_tree *subsub_tree = NULL;
    proto_item *ti = NULL, *ti_nai = NULL;
    uint16_t flags;
    uint8_t j = 0, nt = 0;
    uint32_t lb_len = 0, ln_len = 0, fun_len = 0, arg_len = 0;

    static int * const subobj_srv6_flags[] = {
        &hf_pcep_subobj_srv6_flags_s,
        &hf_pcep_subobj_srv6_flags_f,
        &hf_pcep_subobj_srv6_flags_t,
        &hf_pcep_subobj_srv6_flags_v,
        NULL
    };

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_SRv6, tvb, offset, length, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length < 8) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad SRv6 subobject: length %u < 8", length);
        return;
    }

    flags = tvb_get_uint16(tvb, offset+2, ENC_NA);
    nt = ((tvb_get_uint8(tvb, offset + 2)) >> 4);

    if (obj_class != PCEP_EXPLICIT_ROUTE_OBJ && obj_class != PCEP_RECORD_ROUTE_OBJ) {
        expert_add_info_format(pinfo, ti, &ei_pcep_non_defined_subobject, "Non defined subobject for this object");
        return;
    }
    if (obj_class == PCEP_EXPLICIT_ROUTE_OBJ) {
        proto_tree_add_item(subtree, hf_pcep_subobj_srv6_l, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_PCEPF_SUBOBJ_7F, tvb, offset, 1, ENC_NA);
    }
    else {
        proto_tree_add_item(subtree, hf_PCEPF_SUBOBJ, tvb, offset, 1, ENC_NA);
    }

    proto_tree_add_item(subtree, hf_pcep_subobj_srv6_length, tvb, offset + 1, 1, ENC_NA);
    ti_nai = proto_tree_add_item(subtree, hf_pcep_subobj_srv6_nt, tvb, offset + 2, 1, ENC_NA);
    proto_tree_add_bitmask(subtree, tvb, offset + 2, hf_pcep_subobj_srv6_flags, ett_pcep_obj, subobj_srv6_flags, ENC_NA);
    proto_tree_add_item(subtree, hf_pcep_subobj_srv6_reserved, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_pcep_subobj_srv6_endpoint_behavior, tvb, offset + 6, 2, ENC_BIG_ENDIAN);

    if ( ! (flags & PCEP_SUBOBJ_SRV6_FLAGS_S) ) { /* S flag is not set, SID exists */
        proto_tree_add_item(subtree, hf_pcep_subobj_srv6_sid, tvb, offset + 8, 16, ENC_NA);
        j += 16;
    }

    if ( ! (flags & PCEP_SUBOBJ_SR_FLAGS_F) ) { /* F flag is not set, NAI exists */
        switch (nt) {
        case 2: /* IPv6 Node ID */
            ti = proto_tree_add_item(subtree, hf_pcep_subobj_srv6_nai, tvb, offset+j+8, 16, ENC_NA);
            subsub_tree = proto_item_add_subtree(ti, ett_pcep_obj);
            proto_tree_add_item(subsub_tree, hf_pcep_subobj_srv6_nai_ipv6_node, tvb, offset+j+8, 16, ENC_NA);
            j += 16;
            break;

        case 4: /* IPv6 Adjacency with global IPv6 addresses */
            ti = proto_tree_add_item(subtree, hf_pcep_subobj_srv6_nai, tvb, offset+j+8, 32, ENC_NA);
            subsub_tree = proto_item_add_subtree(ti, ett_pcep_obj);
            proto_tree_add_item(subsub_tree, hf_pcep_subobj_srv6_nai_local_ipv6_addr, tvb, offset+j+8, 16, ENC_NA);
            proto_tree_add_item(subsub_tree, hf_pcep_subobj_srv6_nai_remote_ipv6_addr, tvb, offset+j+24, 16, ENC_NA);
            j += 32;
            break;

        case 6: /* IPv6 Adjacency with link-local IPv6 addresses */
            ti = proto_tree_add_item(subtree, hf_pcep_subobj_srv6_nai, tvb, offset+j+8, 40, ENC_NA);
            subsub_tree = proto_item_add_subtree(ti, ett_pcep_obj);
            proto_tree_add_item(subsub_tree, hf_pcep_subobj_srv6_nai_local_ipv6_addr, tvb, offset+j+8, 16, ENC_NA);
            proto_tree_add_item(subsub_tree, hf_pcep_subobj_srv6_nai_local_interface_id, tvb, offset+j+24, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(subsub_tree, hf_pcep_subobj_srv6_nai_remote_ipv6_addr, tvb, offset+j+28, 16, ENC_NA);
            proto_tree_add_item(subsub_tree, hf_pcep_subobj_srv6_nai_remote_interface_id, tvb, offset+j+44, 4, ENC_BIG_ENDIAN);
            j += 40;
            break;

        default:
            expert_add_info_format(pinfo, ti_nai, &ei_pcep_non_defined_subobject,
                                   "Non defined NAI type (%u) for this subobject", nt);
            return;
        }
    }

    if (flags & PCEP_SUBOBJ_SRV6_FLAGS_T) { /* T flag is set, SID Structure exists */
        ti = proto_tree_add_item(subtree, hf_pcep_subobj_srv6_sid_struct, tvb, offset+j+8, 8, ENC_NA);
        subsub_tree = proto_item_add_subtree(ti, ett_pcep_obj);
        proto_tree_add_item_ret_uint(subsub_tree, hf_pcep_subobj_srv6_sid_struct_lb_len, tvb, offset+j+8, 1, ENC_NA, &lb_len);
        proto_tree_add_item_ret_uint(subsub_tree, hf_pcep_subobj_srv6_sid_struct_ln_len, tvb, offset+j+8+1, 1, ENC_NA, &ln_len);
        proto_tree_add_item_ret_uint(subsub_tree, hf_pcep_subobj_srv6_sid_struct_fun_len, tvb, offset+j+8+2, 1, ENC_NA, &fun_len);
        proto_tree_add_item_ret_uint(subsub_tree, hf_pcep_subobj_srv6_sid_struct_arg_len, tvb, offset+j+8+3, 1, ENC_NA, &arg_len);
        proto_tree_add_item(subsub_tree, hf_pcep_subobj_srv6_sid_struct_reserved, tvb, offset+j+8+4, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(subsub_tree, hf_pcep_subobj_srv6_sid_struct_flags, tvb, offset+j+8+7, 1, ENC_NA);
        proto_item_append_text(ti, " (LB: %u, LN: %u, Fun: %u, Arg: %u)", lb_len, ln_len, fun_len, arg_len);
    }
}

static void
dissect_subobj_unnumb_interfaceID(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, int ett_pcep_obj, unsigned length)
{
    proto_tree *pcep_subobj_unnumb_interfaceID;
    proto_item *ti;
    uint32_t    interface_ID;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_UNNUM_INTERFACEID, tvb, offset, length, ENC_NA);
    pcep_subobj_unnumb_interfaceID = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 12) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad unnumbered interface ID subobject: length %u != 12", length);
        return;
    }

    interface_ID = tvb_get_ntohl(tvb, offset+8);
    proto_item_append_text(ti, ": %s:%u", tvb_ip_to_str(pinfo->pool, tvb, offset+4),
                           interface_ID);

    switch (obj_class) {

        case PCEP_EXPLICIT_ROUTE_OBJ:
        case PCEP_SERO_OBJ:
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_l, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_PCEPF_SUBOBJ_7F, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_length, tvb, offset+1, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_reserved, tvb, offset+2, 2, ENC_BIG_ENDIAN);
            break;

        case PCEP_RECORD_ROUTE_OBJ:
        case PCEP_SRRO_OBJ:
            {
            static int * const flags[] = {
                &hf_pcep_subobj_flags_lpa,
                &hf_pcep_subobj_flags_lpu,
                NULL
            };

            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_PCEPF_SUBOBJ, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_length, tvb, offset+1, 1, ENC_NA);
            proto_tree_add_bitmask(pcep_subobj_unnumb_interfaceID, tvb, offset+2, hf_pcep_subobj_unnumb_interfaceID_flags, ett_pcep_obj, flags, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcep_subobj_unnumb_interfaceID, hf_pcep_subobj_unnumb_interfaceID_reserved_rrobj, tvb, offset+3, 1, ENC_NA);
            }
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
dissect_subobj_autonomous_sys_num(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, unsigned ett_pcep_obj, unsigned length)
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
dissect_subobj_srlg(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, unsigned ett_pcep_obj, unsigned length)
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
dissect_subobj_exrs(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int obj_class, unsigned ett_pcep_obj, unsigned type_iro, unsigned length)
{
    proto_tree *pcep_subobj_exrs;
    proto_item *ti;
    uint8_t     l_type;
    uint8_t     length2;
    unsigned    type_exrs;
    unsigned    offset_exrs = 0;

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

        l_type  = tvb_get_uint8(tvb, offset);
        length2 = tvb_get_uint8(tvb, offset+1);

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
dissect_subobj_pksv4(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int ett_pcep_obj, unsigned length)
{
    proto_tree *pcep_subobj_pksv4;
    proto_item *ti;
    uint16_t    path_key;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_PKSv4, tvb, offset, length, ENC_NA);
    pcep_subobj_pksv4 = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 8) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad path key subobject: length %u != 8", length);
        return;
    }

    path_key = tvb_get_ntohs(tvb, offset+2);
    proto_item_append_text(ti, ": %s, Path Key %u", tvb_ip_to_str(pinfo->pool, tvb, offset+4), path_key);
    proto_tree_add_item(pcep_subobj_pksv4, hf_pcep_subobj_pksv4_l,        tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv4, hf_PCEPF_SUBOBJ_7F,            tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv4, hf_pcep_subobj_pksv4_length,   tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv4, hf_pcep_subobj_pksv4_path_key, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_subobj_pksv4, hf_pcep_subobj_pksv4_pce_id,   tvb, offset+4, 4, ENC_BIG_ENDIAN);
}

static void
dissect_subobj_pksv6(proto_tree *pcep_subobj_tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int ett_pcep_obj, unsigned length)
{
    proto_tree *pcep_subobj_pksv6;
    proto_item *ti;
    uint16_t    path_key;

    ti = proto_tree_add_item(pcep_subobj_tree, hf_PCEPF_SUBOBJ_PKSv6, tvb, offset, length, ENC_NA);
    pcep_subobj_pksv6 = proto_item_add_subtree(ti, ett_pcep_obj);

    if (length != 20) {
        expert_add_info_format(pinfo, ti, &ei_pcep_subobject_bad_length,
                               "Bad path key subobject: length %u != 20", length);
        return;
    }

    path_key = tvb_get_ntohs(tvb, offset+2);
    proto_item_append_text(ti, ": %s, Path Key %u", tvb_ip6_to_str(pinfo->pool, tvb, offset+4), path_key);

    proto_tree_add_item(pcep_subobj_pksv6, hf_pcep_subobj_pksv6_l,        tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv6, hf_PCEPF_SUBOBJ_7F,            tvb, offset,   1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv6, hf_pcep_subobj_pksv6_length,   tvb, offset+1, 1, ENC_NA);
    proto_tree_add_item(pcep_subobj_pksv6, hf_pcep_subobj_pksv6_path_key, tvb, offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_subobj_pksv6, hf_pcep_subobj_pksv6_pce_id,   tvb, offset+4, 4, ENC_NA);
}

/*------------------------------------------------------------------------------
 * Pointer to an object dissector function.
 * All functions which dissect a single object type must match this signature.
 *------------------------------------------------------------------------------*/
typedef void (pcep_obj_dissector_t)(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class, int obj_type);

/*------------------------------------------------------------------------------
 * OPEN OBJECT
 *------------------------------------------------------------------------------*/
#define OPEN_OBJ_MIN_LEN    4

static void
dissect_pcep_open_obj (proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
                    tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
    proto_tree_add_item(pcep_rp_obj_flags, hf_pcep_rp_flags_c,        tvb, offset2+1, 3, ENC_BIG_ENDIAN);
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
    /* RFC 8408 allows PATH_SETUP_TYPE TLV in the RP object */
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_request_parameters);
}

/*------------------------------------------------------------------------------
 * NO PATH OBJECT
 *------------------------------------------------------------------------------*/
#define NO_PATH_OBJ_MIN_LEN  4

static void
dissect_pcep_no_path_obj(proto_tree *pcep_object_tree, packet_info *pinfo,
                         tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
                           tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type)
{
    int dest_leafs;
    int i=0;
    switch (obj_type)
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

        case IPv4_P2MP:
            proto_tree_add_item(pcep_object_tree, hf_pcep_endpoint_p2mp_leaf, tvb, offset2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcep_object_tree, hf_pcep_end_point_obj_source_ipv4_address, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
            dest_leafs = (obj_length - OBJ_HDR_LEN - 8)/4;
            for (i=0; i<dest_leafs; i++)
                proto_tree_add_item(pcep_object_tree, hf_pcep_end_point_obj_destination_ipv4_address, tvb, offset2+8+4*i, 4, ENC_BIG_ENDIAN);
            break;

       case IPv6_P2MP:
            proto_tree_add_item(pcep_object_tree, hf_pcep_endpoint_p2mp_leaf, tvb, offset2, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcep_object_tree, hf_pcep_end_point_obj_source_ipv6_address, tvb, offset2+4, 16, ENC_NA);
            dest_leafs = (obj_length - OBJ_HDR_LEN - 20)/16;
            for (i=0; i<dest_leafs; i++)
                proto_tree_add_item(pcep_object_tree, hf_pcep_end_point_obj_destination_ipv6_address, tvb, (offset2+20+i*16), 16, ENC_NA);
            break;

        default:
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_unknown_type_object,
                                         tvb, offset2, obj_length-OBJ_HDR_LEN,
                                         "UNKNOWN Type Object (%u)", obj_type);
            break;
    }
}



/*------------------------------------------------------------------------------
 * BANDWIDTH OBJECT
 *------------------------------------------------------------------------------*/
#define BANDWIDTH_OBJ_LEN  4

static void
dissect_pcep_bandwidth_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
                        tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
                                tvbuff_t *tvb, int offset2, int obj_length, int obj_class, int obj_type _U_)
{
    uint8_t l_type;
    uint8_t length;
    unsigned  type_exp_route;
    unsigned  body_obj_len;

    body_obj_len = obj_length - OBJ_HDR_LEN;

    while (body_obj_len) {
        if (body_obj_len < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad ERO object: subobject goes past end of object");
            break;
        }

        l_type = tvb_get_uint8(tvb, offset2);
        length = tvb_get_uint8(tvb, offset2+1);

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
            case PCEP_SUB_SR_PRE_IANA:
            case PCEP_SUB_SR:
                dissect_subobj_sr(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, length);
                break;
            case PCEP_SUB_SRv6:
                dissect_subobj_srv6(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_explicit_route, length);
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
dissect_pcep_record_route_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class, int obj_type _U_)
{
    uint8_t type_rro;
    uint8_t length;
    unsigned  body_obj_len;

    body_obj_len = obj_length - OBJ_HDR_LEN;

    while (body_obj_len) {
        if (body_obj_len < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad RRO object: subobject goes past end of object");
            break;
        }

        type_rro = tvb_get_uint8(tvb, offset2);
        length = tvb_get_uint8(tvb, offset2+1);

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

        switch (type_rro) {

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
            case PCEP_SUB_SR_PRE_IANA:
            case PCEP_SUB_SR:   /* draft-ietf-pce-segment-routing-08 section 5.4 */
                dissect_subobj_sr(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_record_route, length);
                break;
            case PCEP_SUB_SRv6:
                dissect_subobj_srv6(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_record_route, length);
                break;
            default:
                proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_subobject,
                                             tvb, offset2, length,
                                             "Non defined subobject (%d)", type_rro);
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
dissect_pcep_lspa_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
                     tvbuff_t *tvb, int offset2, int obj_length, int obj_class, int obj_type _U_)
{
    uint8_t l_type;
    uint8_t length;
    int    type_iro;
    unsigned  body_obj_len;

    body_obj_len = obj_length - OBJ_HDR_LEN;

    while (body_obj_len) {
        if (body_obj_len < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad IRO object: subobject goes past end of object");
            break;
        }

        l_type = tvb_get_uint8(tvb, offset2);
        length = tvb_get_uint8(tvb, offset2+1);

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
                      tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
{
    proto_item *ti;
    proto_tree *pcep_svec_flags_obj;
    int         m;
    int         i;
    uint32_t    requestID;

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
    proto_tree_add_item(pcep_svec_flags_obj, hf_pcep_svec_flags_d, tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);    /* RFC 6006 */
    proto_tree_add_item(pcep_svec_flags_obj, hf_pcep_svec_flags_p, tvb, offset2 + 1, 3, ENC_BIG_ENDIAN);    /* RFC 6006 */

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
dissect_pcep_notification_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
{
    uint8_t nt;

    if (obj_length < OBJ_HDR_LEN+NOTIFICATION_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad NOTIFICATION object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+NOTIFICATION_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_notification_obj_reserved, tvb, offset2,   1, ENC_NA);

    proto_tree_add_item(pcep_object_tree, hf_pcep_notification_obj_flags,    tvb, offset2+1, 1, ENC_NA);

    nt = tvb_get_uint8(tvb, offset2+2);
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
dissect_pcep_error_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
{
    uint8_t      error_type;
    uint8_t      error_value;
    proto_item*  type_item;
    const char *err_str = "Unassigned";

    if (obj_length < OBJ_HDR_LEN+ERROR_OBJ_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad ERROR object length %u, should be >= %u",
                                     obj_length, OBJ_HDR_LEN+ERROR_OBJ_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_error_obj_reserved, tvb, offset2,   1, ENC_NA);
    proto_tree_add_item(pcep_object_tree, hf_pcep_error_obj_flags,    tvb, offset2+1, 1, ENC_NA);

    error_type  = tvb_get_uint8(tvb, offset2+2);
    error_value = tvb_get_uint8(tvb, offset2+3);
    type_item = proto_tree_add_item(pcep_object_tree, hf_PCEPF_ERROR_TYPE, tvb, offset2+2, 1, ENC_NA);

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
        case INVALID_OPERATION:
            err_str = val_to_str_const(error_value, pcep_error_value_19_vals, "Unknown");
            break;
        case LSP_STATE_SYNCHRONIZATION_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_20_vals, "Unknown");
            break;
        case INVALID_PATH_SETUP_TYPE:
            err_str = val_to_str_const(error_value, pcep_error_value_21_vals, "Unknown");
            break;
        case BAD_PARAMETER_VALUE:
            err_str = val_to_str_const(error_value, pcep_error_value_23_vals, "Unknown");
            break;
        case LSP_INSTANTIATION_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_24_vals, "Unknown");
            break;
        case PCEP_STARTTLS_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_25_vals, "Unknown");
            break;
        case ASSOCIATION_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_26_vals, "Unknown");
            break;
        case WSON_RWA_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_27_vals, "Unknown");
            break;
        case H_PCE_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_28_vals, "Unknown");
            break;
        case PATH_COMPUTATION_FAILURE:
            err_str = val_to_str_const(error_value, pcep_error_value_29_vals, "Unknown");
            break;
        case FLOWSPEC_ERROR:
            err_str = val_to_str_const(error_value, pcep_error_value_30_vals, "Unknown");
            break;
        case PCECC_FAILURE:
            err_str = val_to_str_const(error_value, pcep_error_value_31_vals, "Unknown");
            break;
        default:
            proto_item_append_text(type_item, " (%u Non defined Error-Value)", error_type);
    }
    proto_tree_add_uint_format_value(pcep_object_tree, hf_PCEPF_ERROR_VALUE, tvb, offset2+3, 1, error_value, "%s (%u)", err_str, error_value);

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
dissect_pcep_balancing_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
dissect_pcep_close_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
                          tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
{
    uint8_t l_type;
    uint8_t length;
    unsigned  type_exp_route;
    unsigned  body_obj_len;

    body_obj_len = obj_length - OBJ_HDR_LEN;

    while (body_obj_len) {
        if (body_obj_len < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad PATH-KEY object: subobject goes past end of object");
            break;
        }

        l_type = tvb_get_uint8(tvb, offset2);
        length = tvb_get_uint8(tvb, offset2+1);

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
dissect_pcep_xro_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class, int obj_type _U_)
{
    proto_tree *pcep_xro_flags_obj;
    proto_item *ti;
    uint8_t     x_type;
    uint8_t     length;
    unsigned    type_xro;
    unsigned    body_obj_len;

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

    if (body_obj_len < 2) {
        expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                               "Bad XRO object: subobject goes past end of object");
        return;
    }

    while (body_obj_len >= 2) {

        x_type = tvb_get_uint8(tvb, offset2);
        length = tvb_get_uint8(tvb, offset2+1);

        if (length < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad XRO object: object length %u < 2", length);
            break;
        }

        type_xro = (x_type & Mask_Type);

        if (body_obj_len < length) {
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
dissect_pcep_obj_monitoring(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
dissect_pcep_obj_pcc_id_req(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type)
{
    switch (obj_type)
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
                                         "UNKNOWN Type Object (%u)", obj_type);
            break;
    }
}

/*------------------------------------------------------------------------------
 * OF OBJECT
 *------------------------------------------------------------------------------*/
#define OF_OBJ_MIN_LEN 4

static void
dissect_pcep_of_obj(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
dissect_pcep_obj_pce_id(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type)
{
    switch (obj_type)
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
                                         "UNKNOWN Type Object (%u)", obj_type);
            break;
    }
}

/*------------------------------------------------------------------------------
 * PROC-TIME OBJECT
 *------------------------------------------------------------------------------*/
#define OBJ_PROC_TIME_LEN 24

static void
dissect_pcep_obj_proc_time(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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
dissect_pcep_obj_overload(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
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

/*------------------------------------------------------------------------------
* UNREACH-DESTINATION OBJECT
*-----------------------------------------------------------------------------*/
static void
dissect_pcep_obj_unreach_destination(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type)
{
    int address_length = 4;

    int body_obj_len = obj_length-OBJ_HDR_LEN;

    switch (obj_type)
    {
        case IPv4:
            address_length = 4;
            break;
        case IPv6:
            address_length = 16;
            break;
    }

    while (body_obj_len > 0) {
        switch (obj_type) {
            case IPv4:
                if (body_obj_len < address_length) {
                    proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                                 tvb, offset2, body_obj_len,
                                                 "Bad UNREACH-DESTINATION object IPv4 address length %u, should be %u",
                                                 body_obj_len, address_length);
                    return;
                }
                proto_tree_add_item(pcep_object_tree, hf_pcep_unreach_destination_obj_ipv4_address,
                                    tvb, offset2, address_length, ENC_BIG_ENDIAN);
                break;
            case IPv6:
                if (body_obj_len < address_length) {
                    proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                                 tvb, offset2, body_obj_len,
                                                 "Bad UNREACH-DESTINATION object IPv6 address length %u, should be %u",
                                                 body_obj_len, address_length);
                    return;
                }
                proto_tree_add_item(pcep_object_tree, hf_pcep_unreach_destination_obj_ipv6_address,
                                    tvb, offset2, address_length, ENC_NA);
                break;
        }
        offset2 += address_length;
        body_obj_len -= address_length;
    }
}

/*------------------------------------------------------------------------------
 * Branch Node Capability OBJECT

   The BNC Object has the same format as the Include Route Object (IRO) defined
   in [RFC5440], except that it only supports IPv4 and IPv6 prefix sub-objects.
 *------------------------------------------------------------------------------*/
static void
dissect_pcep_obj_branch_node_capability(proto_tree *pcep_object_tree, packet_info *pinfo,
                                        tvbuff_t *tvb, int offset2, int obj_length, int obj_class, int obj_type _U_)
{
    uint8_t l_type;
    uint8_t length;
    int    type_bnco;
    unsigned  body_obj_len;

    body_obj_len = obj_length - OBJ_HDR_LEN;

    while (body_obj_len) {
        if (body_obj_len < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad Branch Node Capability Object: subobject goes past end of object");
            break;
        }

        l_type = tvb_get_uint8(tvb, offset2);
        length = tvb_get_uint8(tvb, offset2+1);

        if (length < 2) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_subobject_bad_length,
                                   "Bad Branch Node Capability Object: subobject length %u < 2", length);
            break;
        }

        type_bnco = (l_type & Mask_Type);

        if (body_obj_len <length) {
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                         tvb, offset2, length,
                                         "Bad Branch Node Capability Object: subobject length %u > remaining length %u",
                                         length, body_obj_len);
            break;
        }

        switch (type_bnco) {
        case PCEP_SUB_IPv4:
            dissect_subobj_ipv4(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_branch_node_capability, length);
            break;
        case PCEP_SUB_IPv6:
            dissect_subobj_ipv6(pcep_object_tree, pinfo, tvb, offset2, obj_class, ett_pcep_obj_branch_node_capability, length);
            break;
        default:
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_subobject,
                                         tvb, offset2, length,
                                         "Non defined subobject (%d)", type_bnco);
            break;
        }
        offset2 += length;
        body_obj_len -= length;
    }
}

/*------------------------------------------------------------------------------
 * LSP OBJECT
 *------------------------------------------------------------------------------*/
#define OBJ_LSP_MIN_LEN 4

static void
dissect_pcep_obj_lsp(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
{
    proto_item *ti;
    proto_tree *lsp_flags;

    if (obj_length < OBJ_HDR_LEN + OBJ_LSP_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad LSP object length %u, should >= %u",
                                     obj_length, OBJ_HDR_LEN + OBJ_LSP_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_lsp_plsp_id, tvb, offset2, 3, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_obj_lsp_flags, tvb, offset2+2, 2, ENC_BIG_ENDIAN);
    lsp_flags = proto_item_add_subtree(ti, ett_pcep_obj_lsp);
    proto_tree_add_item(lsp_flags, hf_pcep_obj_lsp_flags_d,         tvb, offset2+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsp_flags, hf_pcep_obj_lsp_flags_s,         tvb, offset2+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsp_flags, hf_pcep_obj_lsp_flags_r,         tvb, offset2+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsp_flags, hf_pcep_obj_lsp_flags_a,         tvb, offset2+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsp_flags, hf_pcep_obj_lsp_flags_o,         tvb, offset2+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsp_flags, hf_pcep_obj_lsp_flags_c,         tvb, offset2+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(lsp_flags, hf_pcep_obj_lsp_flags_reserved,  tvb, offset2+2, 2, ENC_BIG_ENDIAN);

    /* The object can have optional TLV(s)*/
    offset2 += OBJ_LSP_MIN_LEN;
    obj_length -= OBJ_HDR_LEN + OBJ_LSP_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_lsp);
}

/*------------------------------------------------------------------------------
 * SRP OBJECT
 *------------------------------------------------------------------------------*/
#define OBJ_SRP_MIN_LEN 8

static void
dissect_pcep_obj_srp(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type _U_)
{
    proto_item *ti;
    proto_tree *srp_flags;

    if (obj_length < OBJ_HDR_LEN + OBJ_SRP_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad SRP object length %u, should >= %u",
                                     obj_length, OBJ_HDR_LEN + OBJ_SRP_MIN_LEN);
        return;
    }
    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_obj_srp_flags, tvb, offset2, 4, ENC_BIG_ENDIAN);
    srp_flags = proto_item_add_subtree(ti, ett_pcep_obj_srp);
    proto_tree_add_item(srp_flags, hf_pcep_obj_srp_flags_r, tvb, offset2, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_obj_srp_id_number, tvb, offset2 + 4, 4, ENC_BIG_ENDIAN);

    /*The object can have optional TLV(s)*/
    offset2 += OBJ_SRP_MIN_LEN;
    obj_length -= OBJ_HDR_LEN + OBJ_SRP_MIN_LEN;
    dissect_pcep_tlvs(pcep_object_tree, tvb, offset2, obj_length, ett_pcep_obj_srp);
}

/*------------------------------------------------------------------------------
 * VENDOR-INFORMATION OBJECT
 *------------------------------------------------------------------------------*/
#define OBJ_VENDOR_INFORMATION_MIN_LEN 4

static void
dissect_pcep_obj_vendor_information(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2,
                                    int obj_length, int obj_class _U_, int obj_type _U_) {

    if (obj_length < OBJ_HDR_LEN + OBJ_VENDOR_INFORMATION_MIN_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad VENDOR-INFORMATION object length %u, should >= %u",
                                     obj_length, OBJ_HDR_LEN + OBJ_VENDOR_INFORMATION_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_enterprise_number, tvb, offset2, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_enterprise_specific_info, tvb, offset2 + 4,
                        obj_length - OBJ_HDR_LEN - 4, ENC_STR_HEX);
}

/*------------------------------------------------------------------------------
 * BU OBJECT
 *------------------------------------------------------------------------------*/
#define OBJ_BU_LEN 8 /* The BU object body has a fixed length of 8 bytes */

static void
dissect_pcep_obj_bu(proto_tree *pcep_object_tree, packet_info *pinfo, tvbuff_t *tvb, int offset2,
                                    int obj_length, int obj_class _U_, int obj_type _U_) {

    if (obj_length != OBJ_HDR_LEN + OBJ_BU_LEN) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad BU object length %u, should be %u",
                                     obj_length, OBJ_HDR_LEN + OBJ_BU_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_bu_reserved,    tvb, offset2,   3, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_bu_butype,      tvb, offset2+3, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(pcep_object_tree, hf_pcep_bu_utilization, tvb, offset2+4, 4, ENC_BIG_ENDIAN);
}

/*----------------------------------------------------------------------------
 * ASSOCIATION OBJECT
 *----------------------------------------------------------------------------*/
#define ASSOCIATION_OBJ_v4_MIN_LEN 12
#define ASSOCIATION_OBJ_v6_MIN_LEN 24
static void
dissect_pcep_association_obj(proto_tree *pcep_object_tree, packet_info *pinfo,
                             tvbuff_t *tvb, int offset2, int obj_length, int obj_class _U_, int obj_type)
{
    proto_tree *pcep_association_flags = NULL;
    proto_item *ti = NULL;
    uint16_t association_type;

    /* object length sanity checks */
    if ((obj_type == 1) &&
        (obj_length < OBJ_HDR_LEN + ASSOCIATION_OBJ_v4_MIN_LEN)) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo,
                                     &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad ASSOCIATION IPv4 object length %u"
                                     ", should be >= %u",
                                     obj_length,
                                     OBJ_HDR_LEN + ASSOCIATION_OBJ_v4_MIN_LEN);
        return;
    }
    if ((obj_type == 2) &&
        (obj_length < OBJ_HDR_LEN + ASSOCIATION_OBJ_v6_MIN_LEN)) {
        proto_tree_add_expert_format(pcep_object_tree, pinfo,
                                     &ei_pcep_subobject_bad_length,
                                     tvb, offset2, obj_length,
                                     "Bad ASSOCIATION IPv6 object length %u"
                                     ", should be >= %u",
                                     obj_length,
                                     OBJ_HDR_LEN + ASSOCIATION_OBJ_v4_MIN_LEN);
        return;
    }

    proto_tree_add_item(pcep_object_tree, hf_pcep_association_reserved,
                        tvb, offset2, 2, ENC_NA);
    offset2 += 2; /* consume reserved bytes */
    ti = proto_tree_add_item(pcep_object_tree, hf_pcep_association_flags,
                             tvb, offset2, 2, ENC_NA);
    pcep_association_flags =
        proto_item_add_subtree(ti, ett_pcep_obj_association);
    proto_tree_add_item(pcep_association_flags, hf_pcep_association_flags_r,
                        tvb, offset2, 2, ENC_NA);
    offset2 += 2; /* consume flags */
    proto_tree_add_item(pcep_object_tree, hf_pcep_association_type,
                        tvb, offset2, 2, ENC_BIG_ENDIAN);
    association_type = tvb_get_ntohs(tvb, offset2);
    offset2 += 2; /* consume association type */
    proto_tree_add_item(pcep_object_tree, hf_pcep_association_id,
                        tvb, offset2, 2, ENC_BIG_ENDIAN);
    offset2 += 2; /* consume association identifier */
    switch (obj_type) {
        case 1:
            proto_tree_add_item(pcep_object_tree,
                                hf_pcep_association_source_ipv4,
                                tvb, offset2, 4, ENC_BIG_ENDIAN);
            offset2 += 4; /* consume association source */
            obj_length -= OBJ_HDR_LEN + ASSOCIATION_OBJ_v4_MIN_LEN;
            break;
        case 2:
            proto_tree_add_item(pcep_object_tree,
                                hf_pcep_association_source_ipv6,
                                tvb, offset2, 16, ENC_NA);
            offset2 += 16; /* consume association source */
            obj_length -= OBJ_HDR_LEN + ASSOCIATION_OBJ_v6_MIN_LEN;
            break;
        default:
            proto_tree_add_expert_format(pcep_object_tree, pinfo,
                                         &ei_pcep_non_defined_subobject,
                                         tvb, offset2, obj_length - OBJ_HDR_LEN,
                                         "Unknown Association Type (%u)", obj_type);
            return;
    }

    /* The ASSOCIATION object can have optional TLV(s) */
    /* The EXTENDED_ASSOCIATION_ID TLV is scoped to the ASSOCIATION TYPE*/
    dissect_pcep_tlvs_with_scope(pcep_object_tree, tvb,
                      offset2, obj_length, ett_pcep_obj_association,association_type);
}

/*------------------------------------------------------------------------------*/
/* Dissect in Objects */
/*------------------------------------------------------------------------------*/
typedef struct {
    int *hf_outer;
    int *hf_inner;
    int *ett;
    pcep_obj_dissector_t *obj_func;
} pcep_lut_t;

static void
dissect_pcep_obj_tree(proto_tree *pcep_tree, packet_info *pinfo, tvbuff_t *tvb, int len, int offset, int msg_length)
{
    uint8_t     obj_class;
    uint8_t     ot_res_p_i;
    uint16_t    obj_length;
    int         type;
    proto_tree *pcep_object_tree;
    proto_item *pcep_object_item;

    static int * const pcep_hdr_obj_flags[] = {
        &hf_pcep_hdr_obj_flags_i,
        &hf_pcep_hdr_obj_flags_p,
        &hf_pcep_hdr_obj_flags_reserved,
        NULL
    };

    /* Lookup table for handling objects. Meant to reduce copy-pasting
     * and the likelihood of subtle errors happening for some objects and not
     * others caused by tpyos. Index number is Object-Class
     */
    static const pcep_lut_t obj_lut[] = {
        /*  0 is reserved */ { NULL, NULL, NULL, NULL },
        /*  1 */ { &hf_PCEPF_OBJ_OPEN,                   &hf_pcep_obj_open_type,                    &ett_pcep_obj_open,                 dissect_pcep_open_obj                       },
        /*  2 */ { &hf_PCEPF_OBJ_RP,                     &hf_pcep_obj_rp_type,                      &ett_pcep_obj_request_parameters,   dissect_pcep_rp_obj                         },
        /*  3 */ { &hf_PCEPF_OBJ_NO_PATH,                &hf_pcep_obj_no_path_type,                 &ett_pcep_obj_no_path,              dissect_pcep_no_path_obj                    },
        /*  4 */ { &hf_PCEPF_OBJ_END_POINT,              &hf_pcep_obj_end_point_type,               &ett_pcep_obj_end_point,            dissect_pcep_end_point_obj                  },
        /*  5 */ { &hf_PCEPF_OBJ_BANDWIDTH,              &hf_pcep_obj_bandwidth_type,               &ett_pcep_obj_bandwidth,            dissect_pcep_bandwidth_obj                  },
        /*  6 */ { &hf_PCEPF_OBJ_METRIC,                 &hf_pcep_obj_metric_type,                  &ett_pcep_obj_metric,               dissect_pcep_metric_obj                     },
        /*  7 */ { &hf_PCEPF_OBJ_EXPLICIT_ROUTE,         &hf_pcep_obj_explicit_route_type,          &ett_pcep_obj_explicit_route,       dissect_pcep_explicit_route_obj             },
        /*  8 */ { &hf_PCEPF_OBJ_RECORD_ROUTE,           &hf_pcep_obj_record_route_type,            &ett_pcep_obj_record_route,         dissect_pcep_record_route_obj               },
        /*  9 */ { &hf_PCEPF_OBJ_LSPA,                   &hf_pcep_obj_lspa_type,                    &ett_pcep_obj_lspa,                 dissect_pcep_lspa_obj                       },
        /* 10 */ { &hf_PCEPF_OBJ_IRO,                    &hf_pcep_obj_iro_type,                     &ett_pcep_obj_iro,                  dissect_pcep_iro_obj                        },
        /* 11 */ { &hf_PCEPF_OBJ_SVEC,                   &hf_pcep_obj_svec_type,                    &ett_pcep_obj_svec,                 dissect_pcep_svec_obj                       },
        /* 12 */ { &hf_PCEPF_OBJ_NOTIFICATION,           &hf_pcep_obj_notification_type,            &ett_pcep_obj_notification,         dissect_pcep_notification_obj               },
        /* 13 */ { &hf_PCEPF_OBJ_PCEP_ERROR,             &hf_pcep_obj_pcep_error_type,              &ett_pcep_obj_error,                dissect_pcep_error_obj                      },
        /* 14 */ { &hf_PCEPF_OBJ_LOAD_BALANCING,         &hf_pcep_obj_load_balancing_type,          &ett_pcep_obj_load_balancing,       dissect_pcep_balancing_obj                  },
        /* 15 */ { &hf_PCEPF_OBJ_CLOSE,                  &hf_pcep_obj_close_type,                   &ett_pcep_obj_close,                dissect_pcep_close_obj                      },
        /* 16 */ { &hf_PCEPF_OBJ_PATH_KEY,               &hf_pcep_obj_path_key_type,                &ett_pcep_obj_path_key,             dissect_pcep_path_key_obj                   },
        /* 17 */ { &hf_PCEPF_OBJ_XRO,                    &hf_pcep_obj_xro_type,                     &ett_pcep_obj_xro,                  dissect_pcep_xro_obj                        },
        /* 18 is unassigned */ { NULL, NULL, NULL, NULL },
        /* 19 */ { &hf_PCEPF_OBJ_MONITORING,             &hf_pcep_obj_monitoring_type,              &ett_pcep_obj_monitoring,           dissect_pcep_obj_monitoring                 },
        /* 20 */ { &hf_PCEPF_OBJ_PCC_ID_REQ,             &hf_pcep_obj_pcc_id_req_type,              &ett_pcep_obj_pcc_id_req,           dissect_pcep_obj_pcc_id_req                 },
        /* 21 */ { &hf_PCEPF_OBJ_OF,                     &hf_pcep_obj_of_type,                      &ett_pcep_obj_of,                   dissect_pcep_of_obj                         },
        /* 22 */ { &hf_PCEPF_OBJ_CLASSTYPE,              &hf_pcep_obj_classtype,                    &ett_pcep_obj_classtype,            NULL /* XXX */                              },
        /* 23 is unassigned */ { NULL, NULL, NULL, NULL },
        /* 24 */ { &hf_PCEPF_OBJ_GLOBAL_CONSTRAINTS,     &hf_pcep_obj_global_constraints,           &ett_pcep_obj_global_constraints,   NULL /* XXX */                              },
        /* 25 */ { &hf_PCEPF_OBJ_PCE_ID,                 &hf_pcep_obj_pce_id_type,                  &ett_pcep_obj_pce_id,               dissect_pcep_obj_pce_id                     },
        /* 26 */ { &hf_PCEPF_OBJ_PROC_TIME,              &hf_pcep_obj_proc_time_type,               &ett_pcep_obj_proc_time,            dissect_pcep_obj_proc_time                  },
        /* 27 */ { &hf_PCEPF_OBJ_OVERLOAD,               &hf_pcep_obj_overload_type,                &ett_pcep_obj_overload,             dissect_pcep_obj_overload                   },
        /* 28 */ { &hf_PCEPF_OBJ_UNREACH_DESTINATION,    &hf_pcep_obj_unreach_destination_type,     &ett_pcep_obj_unreach_destination,  dissect_pcep_obj_unreach_destination        },
        /* 29 */ { &hf_PCEPF_OBJ_SERO,                   &hf_pcep_obj_sero_type,                    &ett_pcep_obj_sero,                 dissect_pcep_explicit_route_obj             },
        /* 30 */ { &hf_PCEPF_OBJ_SRRO,                   &hf_pcep_obj_srro_type,                    &ett_pcep_obj_srro,                 dissect_pcep_record_route_obj               },
        /* 31 */ { &hf_PCEPF_OBJ_BRANCH_NODE_CAPABILITY, &hf_pcep_obj_branch_node_capability_type,  &ett_pcep_obj_branch_node_capability,  dissect_pcep_obj_branch_node_capability  },
        /* 32 */ { &hf_PCEPF_OBJ_LSP,                    &hf_pcep_obj_lsp_type,                     &ett_pcep_obj_lsp,                  dissect_pcep_obj_lsp                        },
        /* 33 */ { &hf_PCEPF_OBJ_SRP,                    &hf_pcep_obj_srp_type,                     &ett_pcep_obj_srp,                  dissect_pcep_obj_srp                        },
        /* 34 */ { &hf_PCEPF_OBJ_VENDOR_INFORMATION,     &hf_pcep_obj_vendor_information_type,      &ett_pcep_obj_vendor_information,   dissect_pcep_obj_vendor_information         },
        /* 35 */ { &hf_PCEPF_OBJ_BU,                     &hf_pcep_obj_bu_type,                      &ett_pcep_obj_bu,                   dissect_pcep_obj_bu                         },
        /* 36 */ { &hf_PCEPF_OBJ_INTER_LAYER,            &hf_pcep_obj_inter_layer_type,             &ett_pcep_obj_inter_layer,          NULL /* XXX */                              },
        /* 37 */ { &hf_PCEPF_OBJ_SWITCH_LAYER,           &hf_pcep_obj_switch_layer_type,            &ett_pcep_obj_switch_layer,         NULL /* XXX */                              },
        /* 38 */ { &hf_PCEPF_OBJ_REQ_ADAP_CAP,           &hf_pcep_obj_req_adap_cap_type,            &ett_pcep_obj_req_adap_cap,         NULL /* XXX */                              },
        /* 39 */ { &hf_PCEPF_OBJ_SERVER_IND,             &hf_pcep_obj_server_ind_type,              &ett_pcep_obj_server_ind,           NULL /* XXX */                              },
        /* 40 */ { &hf_PCEPF_OBJ_ASSOCIATION,            &hf_pcep_obj_association_type,             &ett_pcep_obj_association,          dissect_pcep_association_obj                },
        /* 41 */ { &hf_PCEPF_OBJ_S2LS,                   &hf_pcep_obj_s2ls_type,                    &ett_pcep_obj_s2ls,                 NULL /* XXX */                              },
        /* 42 */ { &hf_PCEPF_OBJ_WA,                     &hf_pcep_obj_wa_type,                      &ett_pcep_obj_wa,                   NULL /* XXX */                              },
        /* 43 */ { &hf_PCEPF_OBJ_FLOWSPEC,               &hf_pcep_obj_flowspec_type,                &ett_pcep_obj_flowspec,             NULL /* XXX */                              },
        /* 44 */ { &hf_PCEPF_OBJ_CCI_TYPE,               &hf_pcep_obj_cci_type,                     &ett_pcep_obj_cci_type,             NULL /* XXX */                              },
        /* 45 */ { &hf_PCEPF_OBJ_PATH_ATTRIB,            &hf_pcep_obj_path_attrib_type,             &ett_pcep_obj_path_attrib,          NULL /* XXX */                              },
    };
    pcep_lut_t lut_item;

    while (len < msg_length) {
        obj_class = tvb_get_uint8(tvb, offset);
        if (obj_class > 0 && obj_class < array_length(obj_lut)) {
            lut_item = obj_lut[obj_class];
        }
        else {
            lut_item = obj_lut[0];
        }
        if (lut_item.hf_outer != NULL) {
            pcep_object_item = proto_tree_add_item(pcep_tree, *lut_item.hf_outer, tvb, offset, -1, ENC_NA);
            pcep_object_tree = proto_item_add_subtree(pcep_object_item, *lut_item.ett);
            proto_tree_add_uint(pcep_object_tree, hf_PCEPF_OBJECT_CLASS, tvb, offset, 1, obj_class);
            proto_tree_add_item(pcep_object_tree, *lut_item.hf_inner, tvb, offset+1, 1, ENC_NA);
        }
        else {
            pcep_object_item = proto_tree_add_item(pcep_tree, hf_PCEPF_OBJ_UNKNOWN_TYPE, tvb, offset, -1, ENC_NA);
            pcep_object_tree = proto_item_add_subtree(pcep_object_item, ett_pcep_obj_unknown);
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_non_defined_object,
                                         tvb, offset, -1,
                                         "Unknown object (%u)", obj_class);
            proto_tree_add_uint(pcep_object_tree, hf_PCEPF_OBJECT_CLASS, tvb, offset, 1, obj_class);
            proto_tree_add_item(pcep_object_tree, hf_pcep_object_type, tvb, offset+1, 1, ENC_NA);
        }
        ot_res_p_i = tvb_get_uint8(tvb, offset+1);
        type = (ot_res_p_i & MASK_OBJ_TYPE)>>4;

        proto_tree_add_bitmask(pcep_object_tree, tvb, offset+1, hf_pcep_hdr_obj_flags, ett_pcep_hdr, pcep_hdr_obj_flags, ENC_NA);

        proto_tree_add_item(pcep_object_tree, hf_pcep_object_length, tvb, offset+2, 2, ENC_BIG_ENDIAN);

        obj_length = tvb_get_ntohs(tvb, offset+2);
        proto_item_set_len(pcep_object_item, obj_length);
        if (obj_length < 4) {
            expert_add_info_format(pinfo, pcep_object_tree, &ei_pcep_object_length,
                                   "Object Length: %u (bogus, must be >= 4)", obj_length);
            break;
        }

        if (lut_item.hf_outer != NULL && lut_item.obj_func != NULL) {
            lut_item.obj_func(pcep_object_tree, pinfo, tvb, offset+4, obj_length, obj_class, type);
        }
        else {
            proto_tree_add_expert_format(pcep_object_tree, pinfo, &ei_pcep_pcep_object_body_non_defined,
                                         tvb, offset+4, obj_length-OBJ_HDR_LEN,
                                         "PCEP Object BODY non defined (%u)", type);
        }

        offset += obj_length;
        len    += obj_length;
    }
}


/*------------------------------------------------------------------------------
 * Dissect a single PCEP message in a tree
 *------------------------------------------------------------------------------*/
static void
dissect_pcep_msg_tree(tvbuff_t *tvb, proto_tree *tree, unsigned tree_mode, packet_info *pinfo)
{
    proto_tree *pcep_tree, *pcep_header_tree, *pcep_header_msg_flags;
    proto_item *ti;

    int         offset = 0;
    int         len    = 0;
    uint8_t     message_type;
    uint16_t    msg_length;

    message_type = tvb_get_uint8(tvb, 1);
    msg_length = tvb_get_ntohs(tvb, 2);

    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, message_type_vals, "Unknown Message (%u). "));

    ti = proto_tree_add_item(tree, proto_pcep, tvb, offset, msg_length, ENC_NA);
    pcep_tree = proto_item_add_subtree(ti, tree_mode);

    pcep_header_tree = proto_tree_add_subtree_format(pcep_tree, tvb, offset, 4, ett_pcep_hdr, NULL,
                    "%s Header", val_to_str(message_type, message_type_vals, "Unknown Message (%u). "));

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


static unsigned
get_pcep_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    uint16_t plen;

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
    return tvb_captured_length(tvb);
}

static int
dissect_pcep(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, tree, true, 4, get_pcep_message_len,
                     dissect_pcep_pdu, data);
    return tvb_captured_length(tvb);
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
          { "Reserved Flags", "pcep.msg.hdr.flags.reserved",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_HDR_MSG_RESERVED,
            NULL, HFILL }
        },

        /*Object header*/
        { &hf_pcep_hdr_obj_flags,
          { "Object Header Flags", "pcep.obj.hdr.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_pcep_hdr_obj_flags_reserved,
          { "Reserved Flags", "pcep.obj.hdr.flags.reserved",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCEP_HDR_OBJ_RESERVED,
            NULL, HFILL }
        },
        { &hf_pcep_hdr_obj_flags_p,
          { "Processing-Rule (P)", "pcep.obj.hdr.flags.p",
            FT_BOOLEAN, 4, TFS(&tfs_set_notset), PCEP_HDR_OBJ_P,
            NULL, HFILL }
        },
        { &hf_pcep_hdr_obj_flags_i,
          { "Ignore (I)", "pcep.obj.hdr.flags.i",
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
        { &hf_pcep_endpoint_p2mp_leaf,
          { "P2MP Leaf type", "pcep.obj.endpoint.p2mp.leaf",
            FT_UINT32, BASE_DEC, VALS(pcep_p2mp_leaf_type_vals), 0x0,
            NULL, HFILL }
        },
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
        { &hf_pcep_rp_flags_c,
          { "(C) Core-tree computation", "pcep.rp.flags.c",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_RP_C,
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

        { &hf_pcep_svec_flags_d,
          { "Link Direction Diverse (D)", "pcep.svec.flags.d",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_SVEC_D,
            NULL, HFILL }
        },

        { &hf_pcep_svec_flags_p,
          { "Partial Path Diverse (P)", "pcep.svec.flags.p",
            FT_BOOLEAN, 24, TFS(&tfs_set_notset), PCEP_SVEC_P,
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
        { &hf_PCEPF_ERROR_VALUE,
          { "Error-Value", "pcep.error.value",
            FT_UINT8, BASE_DEC, NULL, 0x0,
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

        { &hf_PCEPF_OBJ_CLASSTYPE,
          { "CLASSTYPE object", "pcep.obj.classtype",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_GLOBAL_CONSTRAINTS,
          { "GLOBAL-CONSTRAINTS object", "pcep.obj.global_constraints",
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

        { &hf_PCEPF_OBJ_UNREACH_DESTINATION,
          { "UNREACH-DESTINATION object", "pcep.obj.unreach-destination",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pcep_unreach_destination_obj_ipv4_address,
          { "Destination IPv4 Address", "pcep.obj.unreach-destination.ipv4-addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pcep_unreach_destination_obj_ipv6_address,
          { "Destination IPv6 address", "pcep.obj.unreach-destination.ipv6-addr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_SERO,
          { "SECONDARY EXPLICIT ROUTE object (SERO)", "pcep.obj.sero",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_SRRO,
          { "SECONDARY RECORD ROUTE object (SRRO)", "pcep.obj.srro",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_BRANCH_NODE_CAPABILITY,
          { "Branch Node Capability object", "pcep.obj.branch-node-capability",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_LSP,
          { "LSP object", "pcep.obj.lsp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_SRP,
          { "SRP object", "pcep.obj.srp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_VENDOR_INFORMATION,
          { "VENDOR-INFORMATION object", "pcep.obj.vendor-information",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_BU,
          { "BU object", "pcep.obj.bu",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_PCEPF_OBJ_INTER_LAYER,
          { "INTER-LAYER object", "pcep.obj.inter_layer",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_SWITCH_LAYER,
          { "SWITCH-LAYER object", "pcep.obj.switch_layer",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_REQ_ADAP_CAP,
          { "REQ-ADAP-CAP object", "pcep.obj.req_adap_cap",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_SERVER_IND,
          { "SERVER-INDICATION object", "pcep.obj.server_ind",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_ASSOCIATION,
          { "ASSOCIATION object", "pcep.obj.association",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_S2LS,
          { "S2LS object", "pcep.obj.s2ls",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_WA,
          { "WAVELENGTH-ASSIGNMENT (WA) object", "pcep.obj.wa",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_FLOWSPEC,
          { "FLOWSPEC object", "pcep.obj.flowspec",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_CCI_TYPE,
          { "CCI Object-Type object", "pcep.obj.cci_type",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_OBJ_PATH_ATTRIB,
          { "PATH-ATTRIB object", "pcep.obj.path_attrib",
            FT_NONE, BASE_NONE, NULL, 0x0,
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
        { &hf_pcep_subobj_flags_lpa,
          { "Local Protection Available", "pcep.subobj.flags.lpa",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_SUB_LPA,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_flags_lpu,
          { "Local protection in Use", "pcep.subobj.flags.lpu",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_SUB_LPU,
            NULL, HFILL }
        },

        { &hf_pcep_subobj_label_flags_gl,
          { "Global Label", "pcep.subobj.label.flags.gl",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_SUB_LABEL_GL,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_pce,
          { "PCE currently unavailable", "pcep.no_path_tlvs.pce",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_unk_dest,
          { "Unknown destination", "pcep.no_path_tlvs.unk_dest",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_unk_src,
          { "Unknown source", "pcep.no_path_tlvs.unk_src",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_brpc,
          { "BRPC Path computation chain unavailable", "pcep.no_path_tlvs.brpc",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_pks,
          { "PKS expansion failure", "pcep.no_path_tlvs.pks",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_no_gco_migr,
          { "No GCO migration path found", "pcep.no_path_tlvs.no_gco_migr",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_no_gco_soln,
          { "No GCO solution found", "pcep.no_path_tlvs.no_gco_soln",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_tlvs_p2mp,
          { "P2MP Reachability Problem", "pcep.no_path_tlvs.p2mp",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL }
        },
        { &hf_pcep_stateful_pce_capability_flags,
          { "Flags", "pcep.stateful-pce-capability.flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_pcep_lsp_update_capability,
          { "LSP-UPDATE-CAPABILITY (U)", "pcep.stateful-pce-capability.lsp-update",
            FT_BOOLEAN, 32, NULL, PCEP_TLV_STATEFUL_PCE_CAPABILITY_U,
            NULL, HFILL }
        },
        { &hf_pcep_include_db_version,
          { "INCLUDE-DB-VERSION (S)", "pcep.sync-capability.include-db-version",
            FT_BOOLEAN, 32, NULL, PCEP_TLV_STATEFUL_PCE_CAPABILITY_S,
            NULL, HFILL }
        },
        { &hf_pcep_lsp_instantiation_capability,
          { "LSP-INSTANTIATION-CAPABILITY (I)", "pcep.stateful-pce-capability.lsp-instantiation",
            FT_BOOLEAN, 32, NULL, PCEP_TLV_STATEFUL_PCE_CAPABILITY_I,
            NULL, HFILL }
        },
        { &hf_pcep_triggered_resync,
          { "TRIGGERED-RESYNC (T)", "pcep.stateful-pce-capability.triggered-resync",
            FT_BOOLEAN, 32, NULL, PCEP_TLV_STATEFUL_PCE_CAPABILITY_T,
            NULL, HFILL }
        },
        { &hf_pcep_delta_lsp_sync_capability,
          { "DELTA-LSP-SYNC-CAPABILITY (D)", "pcep.stateful-pce-capability.delta-lsp-sync",
            FT_BOOLEAN, 32, NULL, PCEP_TLV_STATEFUL_PCE_CAPABILITY_D,
            NULL, HFILL }
        },
        { &hf_pcep_triggered_initial_sync,
          { "TRIGGERED-INITIAL-SYNC (F)", "pcep.stateful-pce-capability.triggered-initial-sync",
            FT_BOOLEAN, 32, NULL, PCEP_TLV_STATEFUL_PCE_CAPABILITY_F,
            NULL, HFILL }
        },
        { &hf_pcep_sr_pce_capability_reserved,
          { "Reserved", "pcep.tlv.sr-pce-capability.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_sr_pce_capability_sub_tlv_reserved,
           { "Reserved", "pcep.sub-tlv.sr-pce-capability.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        // DEPRECATED
        { &hf_pcep_sr_pce_capability_flags,
          { "Flags", "pcep.tlv.sr-pce-capability.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_sr_pce_capability_sub_tlv_flags,
          { "Flags", "pcep.sub-tlv.sr-pce-capability.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        // DEPRECATED
        // leave for backwards compatibility
        { &hf_pcep_sr_pce_capability_flags_l,
          { "L-flag", "pcep.tlv.sr-pce-capability.flags.l",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_TLV_SR_PCE_CAPABILITY_L,
            NULL, HFILL }
        },
        { &hf_pcep_sr_pce_capability_sub_tlv_flags_n,
          { "Node or Adjacency Identifier (NAI) is supported (N)", "pcep.sub-tlv.sr-pce-capability.flags.n",
            FT_BOOLEAN, 7, TFS(&tfs_set_notset), PCEP_TLV_SR_PCE_CAPABILITY_L,
            NULL, HFILL }
        },
        { &hf_pcep_sr_pce_capability_sub_tlv_flags_x,
          { "Unlimited Maximum SID Depth (X)", "pcep.sub-tlv.sr-pce-capability.flags.x",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), PCEP_TLV_SR_PCE_CAPABILITY_L,
            NULL, HFILL }
        },
        // SR-PCE CAPABILITY TLV is deprecated
        // leave for backwards compatibility
        { &hf_pcep_sr_pce_capability_msd,
          { "MSD", "pcep.tlv.sr-pce-capability.msd",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "MSD (Maximum SID Depth)", HFILL }
        },
        { &hf_pcep_sr_pce_capability_sub_tlv_msd,
          { "MSD", "pcep.sub-tlv.sr-pce-capability.msd",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "MSD (Maximum SID Depth)", HFILL }
        },
        { &hf_pcep_path_setup_type_reserved24,
          { "Reserved", "pcep.pst.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_path_setup_type,
          { "Path Setup Type", "pcep.pst",
            FT_UINT8, BASE_DEC, VALS(pcep_pst_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_path_setup_type_capability_reserved24,
          { "Reserved", "pcep.pst_capability.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_path_setup_type_capability_psts,
          { "Path Setup Types", "pcep.pst_capability.psts",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_path_setup_type_capability_pst,
          { "Path Setup Type", "pcep.pst_capability.pst",
            FT_UINT8, BASE_DEC, VALS(pcep_pst_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_SR,
          { "SR", "pcep.subobj.sr",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Segment Routing (SR)", HFILL }
        },
        { &hf_pcep_subobj_sr_l,
          { "L", "pcep.subobj.sr.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_length,
          { "Length", "pcep.subobj.sr.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_nt,
          { "NAI Type", "pcep.subobj.sr.nt",
            FT_UINT8, BASE_DEC, VALS(pcep_sr_nt_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_flags,
          { "Flags", "pcep.subobj.sr.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_flags_m,
          { "SID specifies an MPLS label (M)", "pcep.subobj.sr.flags.m",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), PCEP_SUBOBJ_SR_FLAGS_M,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_flags_c,
          { "SID specifies TC, S, and TTL in addition to an MPLS label (C)", "pcep.subobj.sr.flags.c",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), PCEP_SUBOBJ_SR_FLAGS_C,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_flags_s,
          { "SID is absent (S)", "pcep.subobj.sr.flags.s",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), PCEP_SUBOBJ_SR_FLAGS_S,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_flags_f,
          { "NAI is absent (F)", "pcep.subobj.sr.flags.f",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), PCEP_SUBOBJ_SR_FLAGS_F,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_sid,
          { "SID", "pcep.subobj.sr.sid",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_sid_label,
          { "SID/Label", "pcep.subobj.sr.sid.label",
            FT_UINT32, BASE_DEC, NULL, 0xfffff000,
            "SID represent MPLS Label stack: Label", HFILL }
        },
        { &hf_pcep_subobj_sr_sid_tc,
          {"SID/TC", "pcep.subobj.sr.sid.tc",
            FT_UINT32, BASE_DEC, NULL, 0x00000E00,
            "SID represent MPLS Label stack: Traffic Class field", HFILL }
        },
        { &hf_pcep_subobj_sr_sid_s,
          {"SID/S", "pcep.subobj.sr.sid.s",
            FT_UINT32, BASE_DEC, NULL, 0x00000100,
            "SID represent MPLS Label stack: Bottom of Stack", HFILL }
        },
        { &hf_pcep_subobj_sr_sid_ttl,
          {"SID/TTL", "pcep.subobj.sr.sid.ttl",
            FT_UINT32, BASE_DEC, NULL, 0x000000FF,
            "SID represent MPLS Label stack: Time to Live", HFILL }
        },
        { &hf_pcep_subobj_sr_nai_ipv4_node,
          { "NAI (IPv4 Node ID)", "pcep.subobj.sr.nai.ipv4node",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_nai_ipv6_node,
          { "NAI (IPv6 Node ID)", "pcep.subobj.sr.nai.ipv6node",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_nai_local_ipv4_addr,
          { "Local IPv4 address", "pcep.subobj.sr.nai.localipv4addr",
            FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_nai_remote_ipv4_addr,
          { "Remote IPv4 address", "pcep.subobj.sr.nai.remoteipv4addr",
            FT_IPv4, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_nai_local_ipv6_addr,
          { "Local IPv6 address", "pcep.subobj.sr.nai.localipv6addr",
            FT_IPv6, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_nai_remote_ipv6_addr,
          { "Remote IPv6 address", "pcep.subobj.sr.nai.remoteipv6addr",
            FT_IPv6, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_nai_local_node_id,
          { "Local Node-ID", "pcep.subobj.sr.nai.localnodeid",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_nai_local_interface_id,
          { "Local Interface ID", "pcep.subobj.sr.nai.localinterfaceid",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_nai_remote_node_id,
          { "Remote Node-ID", "pcep.subobj.sr.nai.remotenodeid",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_sr_nai_remote_interface_id,
          { "Remote Interface ID", "pcep.subobj.sr.nai.remoteinterfaceid",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_PCEPF_SUBOBJ_SRv6,
          { "SRv6", "pcep.subobj.srv6",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_l,
          { "L", "pcep.subobj.srv6.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_length,
          { "Length", "pcep.subobj.srv6.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_nt,
          { "NAI Type", "pcep.subobj.srv6.nt",
            FT_UINT8, BASE_DEC, VALS(pcep_sr_nt_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_flags,
          { "Flags", "pcep.subobj.srv6.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_flags_v,
          { "SID verification (V)", "pcep.subobj.srv6.flags.v",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), PCEP_SUBOBJ_SRV6_FLAGS_V,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_flags_t,
          { "SID structure is present (T)", "pcep.subobj.srv6.flags.t",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), PCEP_SUBOBJ_SRV6_FLAGS_T,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_flags_f,
          { "NAI is absent (F)", "pcep.subobj.srv6.flags.f",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), PCEP_SUBOBJ_SRV6_FLAGS_F,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_flags_s,
          { "SID is absent (S)", "pcep.subobj.srv6.flags.s",
            FT_BOOLEAN, 12, TFS(&tfs_set_notset), PCEP_SUBOBJ_SRV6_FLAGS_S,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_reserved,
          { "Reserved", "pcep.subobj.srv6.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_endpoint_behavior,
          { "Endpoint Behavior", "pcep.subobj.srv6.endpoint_behavior",
            FT_UINT16, BASE_DEC, VALS(srv6_endpoint_behavior_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_sid,
          { "SRv6 SID", "pcep.subobj.srv6.sid",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_nai,
          { "Node or Adjacency Identifier (NAI)", "pcep.subobj.srv6.nai",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_nai_ipv6_node,
          { "IPv6 Node ID", "pcep.subobj.srv6.nai.ipv6node",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_nai_local_ipv6_addr,
          { "Local IPv6 address", "pcep.subobj.srv6.nai.localipv6addr",
            FT_IPv6, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_nai_remote_ipv6_addr,
          { "Remote IPv6 address", "pcep.subobj.srv6.nai.remoteipv6addr",
            FT_IPv6, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_nai_local_interface_id,
          { "Local Interface ID", "pcep.subobj.srv6.nai.localinterfaceid",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_nai_remote_interface_id,
          { "Remote Interface ID", "pcep.subobj.srv6.nai.remoteinterfaceid",
            FT_UINT32, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_sid_struct,
          { "SID Structure", "pcep.subobj.srv6.sid_structure",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_sid_struct_lb_len,
          { "Locator Block Length", "pcep.subobj.srv6.sid_structure.locator_block_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_sid_struct_ln_len,
          { "Locator Node Length", "pcep.subobj.srv6.sid_structure.locator_node_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_sid_struct_fun_len,
          { "Function Length", "pcep.subobj.srv6.sid_structure.function_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_sid_struct_arg_len,
          { "Arguments Length", "pcep.subobj.srv6.sid_structure.arguments_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_sid_struct_reserved,
          { "Reserved", "pcep.subobj.srv6.sid_structure.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_srv6_sid_struct_flags,
          { "Flags", "pcep.subobj.srv6.sid_structure.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
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
            FT_UINT32, BASE_DEC, NULL, 0x0,
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
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_subobj_pksv6_l,
          { "L", "pcep.subobj.pksv6.l",
            FT_UINT8, BASE_DEC, VALS(pcep_route_l_obj_vals), Mask_L,
            NULL, HFILL }
        },
        { &hf_pcep_no_path_obj_nature_of_issue,
          { "Nature of Issue", "pcep.obj.no_path.nature_of_issue",
            FT_UINT8, BASE_DEC, VALS(pcep_no_path_obj_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_srp_id_number,
          { "SRP-ID-number", "pcep.obj.srp.id-number",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_lsp_plsp_id,
          { "PLSP-ID", "pcep.obj.lsp.plsp-id",
            FT_UINT32, BASE_DEC, NULL, PCEP_OBJ_LSP_PLSP_ID,
            NULL, HFILL }
        },
        { &hf_pcep_obj_lsp_flags,
          { "Flags", "pcep.obj.lsp.flags",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_lsp_flags_d,
          { "Delegate (D)", "pcep.obj.lsp.flags.delegate",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_OBJ_LSP_FLAGS_D,
            NULL, HFILL }
        },
        { &hf_pcep_obj_lsp_flags_s,
          { "SYNC (S)", "pcep.obj.lsp.flags.sync",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_OBJ_LSP_FLAGS_S,
            NULL, HFILL }
        },
        { &hf_pcep_obj_lsp_flags_r,
          { "Remove (R)", "pcep.obj.lsp.flags.remove",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_OBJ_LSP_FLAGS_R,
            NULL, HFILL }
        },
        { &hf_pcep_obj_lsp_flags_a,
          { "Administrative (A)", "pcep.obj.lsp.flags.administrative",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_OBJ_LSP_FLAGS_A,
            NULL, HFILL }
        },
        { &hf_pcep_obj_lsp_flags_o,
          { "Operational (O)", "pcep.obj.lsp.flags.operational",
            FT_UINT16, BASE_DEC, VALS(pcep_object_lsp_flags_operational_vals), PCEP_OBJ_LSP_FLAGS_O,
            NULL, HFILL }
        },
        { &hf_pcep_obj_lsp_flags_c,
          { "Create (C)", "pcep.obj.lsp.flags.create",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_OBJ_LSP_FLAGS_C,
            NULL, HFILL }
        },
        { &hf_pcep_obj_lsp_flags_reserved,
          { "Reserved", "pcep.obj.lsp.flags.reserved",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_OBJ_LSP_FLAGS_RESERVED,
            NULL, HFILL }
        },
        { &hf_pcep_obj_srp_flags,
          { "Flags", "pcep.obj.srp.flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_obj_srp_flags_r,
          { "Remove (R)", "pcep.obj.srp.flags.remove",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), PCEP_OBJ_SRP_FLAGS_R,
            NULL, HFILL }
        },
        { &hf_pcep_symbolic_path_name,
          { "SYMBOLIC-PATH-NAME", "pcep.tlv.symbolic-path-name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_ipv4_lsp_id_tunnel_sender_address,
          { "IPv4 Tunnel Sender Address", "pcep.tlv.ipv4-lsp-id.tunnel-sender-addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_ipv4_lsp_id_lsp_id,
          { "LSP ID", "pcep.tlv.ipv4-lsp-id.lsp-id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_ipv4_lsp_id_tunnel_id,
          { "Tunnel ID", "pcep.tlv.ipv4-lsp-id.tunnel-id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_ipv4_lsp_id_extended_tunnel_id,
          { "Extended Tunnel ID", "pcep.tlv.ipv4-lsp-id.extended-tunnel-id",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_ipv4_lsp_id_tunnel_endpoint_address,
          { "IPv4 Tunnel Endpoint Address", "pcep.tlv.ipv4-lsp-id.tunnel-endpoint-addr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_ipv6_lsp_id_tunnel_sender_address,
          { "IPv6 Tunnel Sender Address", "pcep.tlv.ipv6-lsp-id.tunnel-sender-addr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_ipv6_lsp_id_lsp_id,
          { "LSP ID", "pcep.tlv.ipv6-lsp-id.lsp-id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_ipv6_lsp_id_tunnel_id,
          { "Tunnel ID", "pcep.tlv.ipv6-lsp-id.tunnel-id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_ipv6_lsp_id_extended_tunnel_id,
          { "Extended Tunnel ID", "pcep.tlv.ipv6-lsp-id.extended-tunnel-id",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_ipv6_lsp_id_tunnel_endpoint_address,
          { "IPv6 Tunnel Endpoint Address", "pcep.tlv.ipv6-lsp-id.tunnel-endpoint-addr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_lsp_error_code,
          { "LSP Error Code", "pcep.tlv.lsp-error-code",
            FT_UINT32, BASE_DEC, VALS(pcep_tlv_lsp_error_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_rsvp_user_error_spec,
          { "RSVP/USER ERROR_SPEC", "pcep.tlv.rsvp-user-error-spec",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_lsp_state_db_version_number,
          { "LSP State DB Version Number", "pcep.tlv.lsp-state-db-version-number",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_speaker_entity_id,
          { "Speaker Entity Identifier", "pcep.tlv.speaker-entity-id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_reserved,
          { "Reserved", "pcep.association.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_flags,
          { "Flags", "pcep.association.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_flags_r,
          { "Remove (R)", "pcep.association.flags.r",
            FT_BOOLEAN, 16, TFS(&tfs_set_notset), PCEP_OBJ_ASSOCIATION_FLAGS_R,
            NULL, HFILL }
        },
        { &hf_pcep_association_type,
          { "Association Type", "pcep.association.type",
            FT_UINT16, BASE_DEC, VALS(pcep_association_type_field_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_id,
          { "Association ID", "pcep.association.id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_source_ipv4,
          { "IPv4 Association Source", "pcep.association.ipv4.source",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_source_ipv6,
          { "IPv6 Association Source", "pcep.association.ipv6.source",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_source_global,
          { "Global Association Source", "pcep.association.global.source",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_id_extended,
          { "Extended Association ID", "pcep.tlv.extended_association_id.id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_id_extended_color,
          { "Color", "pcep.tlv.extended_association_id.color",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_id_extended_ipv4_endpoint,
          { "IPv4 Endpoint", "pcep.tlv.extended_association_id.ipv4_endpoint",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_association_id_extended_ipv6_endpoint,
          { "IPv6 Endpoint", "pcep.tlv.extended_association_id.ipv6_endpoint",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_op_conf_assoc_range_reserved,
          { "Reserved", "pcep.op_conf_assoc_range.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_op_conf_assoc_range_assoc_type,
          { "Assoc-Type", "pcep.op_conf_assoc_range.assoc_type",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_op_conf_assoc_range_start_assoc,
          { "Start-Assoc", "pcep.op_conf_assoc_range.start_assoc",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_op_conf_assoc_range_range,
          { "Range", "pcep.op_conf_assoc_range.range",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_srcpag_info_color,
          { "Color", "pcep.srcpag_info.color",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_srcpag_info_destination_endpoint,
          { "Destination End-point", "pcep.srcpag_info.destination_endpoint",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_srcpag_info_preference,
          { "Preference", "pcep.srcpag_info.preference",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_sr_policy_name,
          { "SR Policy Name", "pcep.tlv.sr_policy_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_sr_policy_cpath_id_proto_origin,
          { "Proto origin", "pcep.tlv.sr_policy_cpath_id.proto_origin",
            FT_UINT8, BASE_DEC, VALS(pcep_sr_policy_id_proto_origin_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_sr_policy_cpath_id_originator_asn,
          { "Originator ASN", "pcep.tlv.sr_policy_cpath_id.originator_asn",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_sr_policy_cpath_id_originator_address,
          { "IPv4 Originator Address", "pcep.tlv.sr_policy_cpath_id.originator_ipv4_address",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_sr_policy_cpath_id_discriminator,
          { "Discriminator", "pcep.tlv.sr_policy_cpath_id.proto_discriminator",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_sr_policy_cpath_name,
          { "SR Policy Candidate Path Name", "pcep.tlv.sr_policy_cpath_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_sr_policy_cpath_preference,
          { "Preference", "pcep.tlv.sr_policy_cpath_preference",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_enterprise_number,
          { "Enterprise Number", "pcep.vendor-information.enterprise-number",
           FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
           "IANA Private Enterprise Number", HFILL }
        },
        { &hf_pcep_enterprise_specific_info,
          { "Enterprise-Specific Information", "pcep.vendor-information.enterprise-specific-info",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_tlv_enterprise_number,
          { "Enterprise Number", "pcep.tlv.enterprise-number",
           FT_UINT32, BASE_ENTERPRISES, STRINGS_ENTERPRISES, 0x0,
           "IANA Private Enterprise Number", HFILL }
        },
        { &hf_pcep_tlv_enterprise_specific_info,
          { "Enterprise-Specific Information", "pcep.tlv.enterprise-specific-info",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_bu_reserved,
          { "Reserved", "pcep.obj.bu.reserved",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_bu_butype,
          { "Type", "pcep.obj.bu.butype",
            FT_UINT8, BASE_DEC, VALS(pcep_bu_butype_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_pcep_bu_utilization,
          { "Bandwidth Utilization", "pcep.obj.bu.utilization",
            FT_FLOAT, BASE_NONE, NULL, 0x0,
            "The bandwidth utilization quantified as a percentage and encoded in IEEE floating point format", HFILL }
        },
        { &hf_pcep_obj_open_type,
          { "OPEN Object-Type", "pcep.obj.open.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_open_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_rp_type,
          { "RP Object-Type", "pcep.obj.rp.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_rp_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_no_path_type,
          { "NO-PATH Object-Type", "pcep.obj.nopath.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_no_path_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_end_point_type,
          { "END-POINT Object-Type", "pcep.obj.endpoint.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_end_point_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_bandwidth_type,
          { "BANDWIDTH Object-Type", "pcep.obj.bandwidth.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_bandwidth_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_metric_type,
          { "METRIC Object-Type", "pcep.obj.metric.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_metric_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_explicit_route_type,
          { "ERO Object-Type", "pcep.obj.ero.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_explicit_route_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_record_route_type,
          { "RRO Object-Type", "pcep.obj.rro.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_record_route_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_lspa_type,
          { "LSPA Object-Type", "pcep.obj.lspa.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_lspa_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_iro_type,
          { "IRO Object-Type", "pcep.obj.iro.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_iro_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_svec_type,
          { "SVEC Object-Type", "pcep.obj.svec.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_svec_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_notification_type,
          { "NOTIFICATION Object-Type", "pcep.obj.notification.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_notification_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_pcep_error_type,
          { "PCEP-ERROR Object-Type", "pcep.obj.error.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_pcep_error_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_load_balancing_type,
          { "LOAD-BALANCING Object-Type", "pcep.obj.loadbalancing.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_load_balancing_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_close_type,
          { "CLOSE Object-Type", "pcep.obj.close.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_close_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_path_key_type,
          { "PATH-KEY Object-Type", "pcep.obj.path_key.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_path_key_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_xro_type,
          { "XRO Object-Type", "pcep.obj.xro.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_xro_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_monitoring_type,
          { "MONITORING Object-Type", "pcep.obj.monitoring.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_monitoring_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_pcc_id_req_type,
          { "PCC-REQ-ID Object-Type", "pcep.obj.pccidreq.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_pcc_id_req_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_of_type,
          { "OF Object-Type", "pcep.obj.of.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_of_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_classtype,
          { "CLASSTYPE Type", "pcep.obj.classtype.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_global_constraints,
          { "Global-Constraints Type", "pcep.obj.global_constraints.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_pce_id_type,
          { "PCE-ID Object-Type", "pcep.obj.pceid.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_pce_id_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_proc_time_type,
          { "PROC-TIME Object-Type", "pcep.obj.proctime.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_proc_time_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_overload_type,
          { "OVERLOAD Object-Type", "pcep.obj.overload.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_overload_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_unreach_destination_type,
          { "UNREACH-DESTINATION Object-Type", "pcep.obj.unreach-destination.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_unreach_destination_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_sero_type,
          { "SERO Object-Type", "pcep.obj.sero.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_sero_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_srro_type,
          { "SRRO Object-Type", "pcep.obj.srro.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_srro_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_branch_node_capability_type,
          { "Branch Node Capability Object-Type", "pcep.obj.branch-node-capability.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_branch_node_capability_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_lsp_type,
          { "LSP Object-Type", "pcep.obj.lsp.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_lsp_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_srp_type,
          { "SRP Object-Type", "pcep.obj.srp.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_srp_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_vendor_information_type,
          { "VENDOR-INFORMATION Object-Type", "pcep.obj.vendor-information.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_vendor_information_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_bu_type,
          { "BU Object-Type", "pcep.obj.bu.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_bu_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_inter_layer_type,
          { "Inter-Layer Type", "pcep.obj.inter_layer.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_switch_layer_type,
          { "Switch-Layer Type", "pcep.obj.switch_layer.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_req_adap_cap_type,
          { "REQ_ADAP_CAP Type", "pcep.obj.req_adap_cap.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_server_ind_type,
          { "Server-Indication Type", "pcep.obj.server_indication.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_association_type,
          { "ASSOCIATION Object-Type", "pcep.obj.association.type",
            FT_UINT8, BASE_DEC, VALS(pcep_obj_association_type_vals), MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_s2ls_type,
          { "S2LS Type", "pcep.obj.s2ls.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_wa_type,
          { "Wavelength Assignment Type", "pcep.obj.wa.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_flowspec_type,
          { "Flow Specification Type", "pcep.obj.flowspec.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_cci_type,
          { "CCI Object-Type", "pcep.obj.cci_type.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_obj_path_attrib_type,
          { "Path-Attrib Type", "pcep.obj.path_attrib.type",
            FT_UINT8, BASE_DEC, NULL, MASK_OBJ_TYPE,
            NULL, HFILL }
        },

        { &hf_pcep_path_setup_type_capability_sub_tlv_type,
          { "Type", "pcep.path-setup-type-capability-sub-tlv.type",
            FT_UINT16, BASE_DEC, VALS(pcep_path_setup_type_capability_sub_tlv_vals), 0x0,
            NULL, HFILL }
        },

        { &hf_pcep_path_setup_type_capability_sub_tlv_length,
          { "Length", "pcep.path-setup-type-capability-sub-tlv.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
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
        &ett_pcep_obj_classtype,
        &ett_pcep_obj_global_constraints,
        &ett_pcep_obj_pce_id,
        &ett_pcep_obj_proc_time,
        &ett_pcep_obj_overload,
        &ett_pcep_obj_unreach_destination,
        &ett_pcep_obj_sero,
        &ett_pcep_obj_srro,
        &ett_pcep_obj_branch_node_capability,
        &ett_pcep_obj_lsp,
        &ett_pcep_obj_srp,
        &ett_pcep_obj_vendor_information,
        &ett_pcep_obj_bu,
        &ett_pcep_obj_inter_layer,
        &ett_pcep_obj_switch_layer,
        &ett_pcep_obj_req_adap_cap,
        &ett_pcep_obj_server_ind,
        &ett_pcep_obj_association,
        &ett_pcep_obj_s2ls,
        &ett_pcep_obj_wa,
        &ett_pcep_obj_flowspec,
        &ett_pcep_obj_cci_type,
        &ett_pcep_obj_path_attrib,
        &ett_pcep_obj_unknown,
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

    /* Register the dissector handle */
    pcep_handle = register_dissector("pcep", dissect_pcep, proto_pcep);
}

/*Dissector Handoff*/
void
proto_reg_handoff_pcep(void)
{
    dissector_add_uint_with_preference("tcp.port", TCP_PORT_PCEP, pcep_handle);
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
