/* packet-uet.c
 * Routines for Ultra Ethernet Transport dissection
 * Copyright Keysight Technologies 2024-2025
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Protocol specification:
 * https://ultraethernet.org/wp-content/uploads/sites/20/2025/10/UE-Specification-1.0.1.pdf
 */

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tfs.h>

static int proto_uet;

//UET TSS
static int hf_uet_tss_prlg;
static int hf_uet_tss_type;
static int hf_uet_tss_nh;
static int hf_uet_tss_ver;
static int hf_uet_tss_sp;
static int hf_uet_tss_reserved;
static int hf_uet_tss_an;
static int hf_uet_tss_sdi;
static int hf_uet_tss_ssi;
static int hf_uet_tss_tsc;

//PDS
static int hf_uet_pds_prlg;
static int hf_uet_pds_entropy;
static int hf_uet_pds_entropy_rsvd;
static int hf_uet_pds_type;
static int hf_uet_pds_nh;
static int hf_uet_pds_ctl_type;
static int hf_uet_pds_flags;
static int hf_uet_pds_flags_m;
static int hf_uet_pds_flags_retx;
static int hf_uet_pds_flags_ar;
static int hf_uet_pds_flags_p;
static int hf_uet_pds_flags_nt;
static int hf_uet_pds_flags_syn;
static int hf_uet_pds_flags_req;
static int hf_uet_pds_flags_rsvd_rud_rod;
static int hf_uet_pds_flags_rsvd_uud;
static int hf_uet_pds_flags_rsvd_ctl;
static int hf_uet_pds_flags_rsvd_ack;
static int hf_uet_pds_flags_rsvd_rudi;
static int hf_uet_pds_flags_rsvd_nack;
static int hf_uet_pds_clear_psn;
static int hf_uet_pds_psn;
static int hf_uet_pds_cack_psn;
static int hf_uet_pds_ack_psn;
static int hf_uet_pds_spdcid;
static int hf_uet_pds_dpdcid;
static int hf_uet_pds_nack_psn;
static int hf_uet_pds_nack_code;
static int hf_uet_pds_nack_vendor_code;
static int hf_uet_pds_nack_max_recv_psn;
static int hf_uet_pds_pdc_mode;
static int hf_uet_pds_pdc_mode_use_rsv;
static int hf_uet_pds_pdc_mode_rsv;
static int hf_uet_pds_psn_offset;
static int hf_uet_pds_start_psn;
static int hf_uet_pds_req_cc_state_ccc_id;
static int hf_uet_pds_req_cc_state_credit_target;
static int hf_uet_pds_ctl_probe_opaque;
static int hf_uet_pds_ctl_payload;
static int hf_uet_pds_ack_prlg;
static int hf_uet_pds_ack_cc_type;
static int hf_uet_pds_ack_mpr;
static int hf_uet_pds_ack_sack_offset;
static int hf_uet_pds_ack_cc_state;
static int hf_uet_pds_ack_cc_state_service_time;
static int hf_uet_pds_ack_cc_state_rc;
static int hf_uet_pds_ack_cc_state_rcv_cwnd_pend;
static int hf_uet_pds_ack_cc_state_rcvd_bytes;
static int hf_uet_pds_ack_cc_state_credit;
static int hf_uet_pds_ack_cc_state_reserved;
static int hf_uet_pds_ack_cc_state_ooo_count;
static int hf_uet_pds_ack_ccx_state;
static int hf_uet_pds_ack_sack_bitmap;
static int hf_uet_pds_rudi_pkt_id;

//SES
static int hf_uet_ses_prlg;
static int hf_uet_ses_std_eom;
static int hf_uet_ses_std_flags;
static int hf_uet_ses_std_rsv;
static int hf_uet_ses_std_opcode;
static int hf_uet_ses_std_ver;
static int hf_uet_ses_std_dc;
static int hf_uet_ses_std_ie;
static int hf_uet_ses_std_rel;
static int hf_uet_ses_std_hd;
static int hf_uet_ses_std_som;
static int hf_uet_ses_std_message_id;
static int hf_uet_ses_std_index_generation;
static int hf_uet_ses_std_job_id;
static int hf_uet_ses_std_reserved2;
static int hf_uet_ses_std_pidonfep;
static int hf_uet_ses_std_reserved3;
static int hf_uet_ses_std_resource_index;
static int hf_uet_ses_std_buffer_offset; //OR hf_uet_ses_std_restart_token
static int hf_uet_ses_std_restart_token;
static int hf_uet_ses_std_initiator;
static int hf_uet_ses_std_mem_key_match_bits;
static int hf_uet_ses_std_header_data; //OR hf_uet_ses_std_reserved4+hf_uet_ses_std_payload_length+hf_uet_ses_std_message_offset
static int hf_uet_ses_std_reserved4;
static int hf_uet_ses_std_payload_length;
static int hf_uet_ses_std_message_offset;
static int hf_uet_ses_std_request_length;
static int hf_uet_ses_atomic_op_ext_hdr;
static int hf_uet_ses_atomic_op_ext_hdr_atomic_opcode;
static int hf_uet_ses_atomic_op_ext_hdr_atomic_data_type;
static int hf_uet_ses_atomic_op_ext_hdr_sem_ctl;
static int hf_uet_ses_atomic_op_ext_hdr_rsvd;
static int hf_uet_ses_rendv_ext_hdr;
static int hf_uet_ses_rendv_ext_hdr_eager_length;
static int hf_uet_ses_rendv_ext_hdr_reserved;
static int hf_uet_ses_rendv_ext_hdr_read_pid_on_fep;
static int hf_uet_ses_rendv_ext_hdr_reserved2;
static int hf_uet_ses_rendv_ext_hdr_read_resource_index;
static int hf_uet_ses_rendv_ext_hdr_read_offset;
static int hf_uet_ses_rendv_ext_hdr_read_match_bits;
static int hf_uet_ses_comp_swap_ext_hdr;
static int hf_uet_ses_comp_swap_ext_hdr_atomic_opcode;
static int hf_uet_ses_comp_swap_ext_hdr_atomic_data_type;
static int hf_uet_ses_comp_swap_ext_hdr_sem_ctl;
static int hf_uet_ses_comp_swap_ext_hdr_rsvd;
static int hf_uet_ses_comp_swap_ext_hdr_comp_value;
static int hf_uet_ses_comp_swap_ext_hdr_swap_value;
static int hf_uet_ses_rsp_list;
static int hf_uet_ses_rsp_opcode;
static int hf_uet_ses_rsp_ver;
static int hf_uet_ses_rsp_return_code;
static int hf_uet_ses_rsp_message_id;
static int hf_uet_ses_rsp_resource_index_gen;
static int hf_uet_ses_rsp_job_id;
static int hf_uet_ses_rsp_mod_length;
static int hf_uet_ses_rsp_reserved;
static int hf_uet_ses_rsp_read_req_message_id;
static int hf_uet_ses_rsp_reserved2;
static int hf_uet_ses_rsp_payload_length;
static int hf_uet_ses_rsp_message_offset;
static int hf_uet_ses_rsp_reserved3;
static int hf_uet_ses_small_req_rsv;
static int hf_uet_ses_small_req_flags;
static int hf_uet_ses_small_req_flags_ver;
static int hf_uet_ses_small_req_flags_dc;
static int hf_uet_ses_small_req_flags_ie;
static int hf_uet_ses_small_req_flags_rel;
static int hf_uet_ses_small_req_flags_rsvd;
static int hf_uet_ses_small_req_flags_eom;
static int hf_uet_ses_small_req_flags_som;
static int hf_uet_ses_small_req_flags_rsv2;
static int hf_uet_ses_small_req_req_length;
static int hf_uet_ses_small_req_index_generation;
static int hf_uet_ses_small_req_job_id;
static int hf_uet_ses_small_req_rsv3;
static int hf_uet_ses_small_req_pidonfep;
static int hf_uet_ses_small_req_rsv4;
static int hf_uet_ses_small_req_resource_index;
static int hf_uet_ses_small_req_buffer_offset;
static int hf_uet_ses_med_req_rsv;
static int hf_uet_ses_med_req_flags;
static int hf_uet_ses_med_req_flags_ver;
static int hf_uet_ses_med_req_flags_dc;
static int hf_uet_ses_med_req_flags_ie;
static int hf_uet_ses_med_req_flags_rel;
static int hf_uet_ses_med_req_flags_hd;
static int hf_uet_ses_med_req_flags_eom;
static int hf_uet_ses_med_req_flags_som;
static int hf_uet_ses_med_req_flags_rsv2;
static int hf_uet_ses_med_req_req_length;
static int hf_uet_ses_med_req_resource_index_generation;
static int hf_uet_ses_med_req_job_id;
static int hf_uet_ses_med_req_rsv3;
static int hf_uet_ses_med_req_pidonfep;
static int hf_uet_ses_med_req_rsv4;
static int hf_uet_ses_med_req_resource_index;
static int hf_uet_ses_med_req_buffer_offset;
static int hf_uet_ses_med_req_header_data;
static int hf_uet_ses_med_req_initiator;
static int hf_uet_ses_med_req_mem_key_match_bits;

static int ett_all_layers;
static int ett_uet_tss_auth_proto;
static int ett_uet_pds_proto;
static int ett_uet_pds_flags;
static int ett_uet_pds_ack_cc_flags;
static int ett_uet_pds_ack_cc_state;
static int ett_uet_pds_pdc_mode;
static int ett_uet_ses_proto;
static int ett_uet_ses_std_flags;
static int ett_uet_ses_atomic_op_ext_hdr;
static int ett_uet_ses_rendv_ext_hdr;
static int ett_uet_ses_comp_swap_ext_hdr;
static int ett_uet_ses_small_req_flags;
static int ett_uet_ses_med_req_flags;

static expert_field ei_uet_pds_hdr_len_invalid;
static expert_field ei_uet_pds_rud_rod_hdr_len_invalid;
static expert_field ei_uet_pds_ack_ext_hdr_len_invalid;
static expert_field ei_uet_ses_rsp_opcode_invalid;
static expert_field ei_uet_ses_hdr_len_invalid;
static expert_field ei_uet_tss_hdr_len_invalid;

static dissector_handle_t uet_handle;
static dissector_handle_t uet_entropy_handle;

#define UDP_PORT_UET                4793

//UET Types
#define UET_PDS_TYPE_RESERVED   0
#define UET_TYPE_ENC            1
#define UET_PDS_TYPE_RUD_REQ    2
#define UET_PDS_TYPE_ROD_REQ    3
#define UET_PDS_TYPE_RUDI_REQ   4
#define UET_PDS_TYPE_RUDI_RESP  5
#define UET_PDS_TYPE_UUD_REQ    6
#define UET_PDS_TYPE_ACK        7
#define UET_PDS_TYPE_ACK_CC     8
#define UET_PDS_TYPE_ACK_CCX    9
#define UET_PDS_TYPE_NACK       10
#define UET_PDS_TYPE_CTRL       11
#define UET_PDS_TYPE_NACK_CCX   12
#define UET_PDS_TYPE_RUD_CC_REQ 13
#define UET_PDS_TYPE_ROD_CC_REQ 14

//TSS
static const value_string uet_tss_type_vals[] = {
    { UET_TYPE_ENC,      "UET_TSS"},
    { 0, NULL }
};

static value_string_ext uet_tss_type_vals_ext = VALUE_STRING_EXT_INIT(uet_tss_type_vals);


static const value_string uet_pds_opcode_type_vals[] = {
    { UET_PDS_TYPE_RESERVED,    "Reserved"},
    { UET_TYPE_ENC,             "Encryption Header"},
    { UET_PDS_TYPE_RUD_REQ,     "RUD Request"},
    { UET_PDS_TYPE_ROD_REQ,     "ROD Request"},
    { UET_PDS_TYPE_RUDI_REQ,    "RUDI Request"},
    { UET_PDS_TYPE_RUDI_RESP,   "RUDI Response"},
    { UET_PDS_TYPE_UUD_REQ,     "UUD Request"},
    { UET_PDS_TYPE_ACK,         "ACK"},
    { UET_PDS_TYPE_ACK_CC,      "ACK CC"},
    { UET_PDS_TYPE_ACK_CCX,     "ACK CCX"},
    { UET_PDS_TYPE_NACK,        "NACK"},
    { UET_PDS_TYPE_CTRL,        "Control"},
    { UET_PDS_TYPE_NACK_CCX,    "NACK CCX"},
    { UET_PDS_TYPE_RUD_CC_REQ,  "RUD CC Request"},
    { UET_PDS_TYPE_ROD_CC_REQ,  "ROD CC Request"},
    { 0, NULL }
};

static value_string_ext uet_pds_opcode_vals_ext = VALUE_STRING_EXT_INIT(uet_pds_opcode_type_vals);

static const value_string uet_pds_opcode_type_vals_for_info[] = {
    { UET_PDS_TYPE_RESERVED,    "Reserved"},
    { UET_TYPE_ENC,             "Encryption_Header"},
    { UET_PDS_TYPE_RUD_REQ,     "RUD_REQ"},
    { UET_PDS_TYPE_ROD_REQ,     "ROD_REQ"},
    { UET_PDS_TYPE_RUDI_REQ,    "RUDI_REQ"},
    { UET_PDS_TYPE_RUDI_RESP,   "RUDI_RESP"},
    { UET_PDS_TYPE_UUD_REQ,     "UUD_REQ"},
    { UET_PDS_TYPE_ACK,         "ACK"},
    { UET_PDS_TYPE_ACK_CC,      "ACK_CC"},
    { UET_PDS_TYPE_ACK_CCX,     "ACK_CCX"},
    { UET_PDS_TYPE_NACK,        "NACK"},
    { UET_PDS_TYPE_CTRL,        "Control"},
    { UET_PDS_TYPE_NACK_CCX,    "NACK_CCX"},
    { UET_PDS_TYPE_RUD_CC_REQ,  "RUD_CC_REQ"},
    { UET_PDS_TYPE_ROD_CC_REQ,  "ROD_CC_REQ"},
    { 0, NULL }
};

#define UET_PDS_NH_NONE               0 /* No next header */
#define UET_PDS_NH_REQ_SMALL          1 /* small SES request header */
#define UET_PDS_NH_REQ_MEDIUM         2 /* medium SES request header */
#define UET_PDS_NH_REQ_STD            3 /* standard SES request header */
#define UET_PDS_NH_RSP                4 /* SES response header */
#define UET_PDS_NH_RSP_DATA           5 /* SES response header with data */
#define UET_PDS_NH_RSP_DATA_SMALL     6 /* SES tiny response header with data */

static const value_string uet_pds_nh_type_vals[] = {
    { UET_PDS_NH_NONE,              "NO SES"},
    { UET_PDS_NH_REQ_SMALL,         "SES REQUEST SMALL"},
    { UET_PDS_NH_REQ_MEDIUM,        "SES REQUEST MEDIUM"},
    { UET_PDS_NH_REQ_STD,           "SES REQUEST STD"},
    { UET_PDS_NH_RSP,               "SES RESPONSE"},
    { UET_PDS_NH_RSP_DATA,          "SES RESPONSE DATA"},
    { UET_PDS_NH_RSP_DATA_SMALL,    "SES RESPONSE DATA_SMALL"},
    { 0, NULL }
};
static value_string_ext uet_pds_nh_vals_ext = VALUE_STRING_EXT_INIT(uet_pds_nh_type_vals);

static const value_string uet_pds_nh_type_vals_for_tree[] = {
    { UET_PDS_NH_NONE,              "NO SES"},
    { UET_PDS_NH_REQ_SMALL,         "REQUEST SMALL"},
    { UET_PDS_NH_REQ_MEDIUM,        "REQUEST MEDIUM"},
    { UET_PDS_NH_REQ_STD,           "REQUEST STD"},
    { UET_PDS_NH_RSP,               "RESPONSE"},
    { UET_PDS_NH_RSP_DATA,          "RESPONSE DATA"},
    { UET_PDS_NH_RSP_DATA_SMALL,    "RESPONSE DATA_SMALL"},
    { 0, NULL }
};

static const value_string uet_pds_nh_type_vals_for_info[] = {
    { UET_PDS_NH_NONE,              "NO_SES"},
    { UET_PDS_NH_REQ_SMALL,         "REQ_SMALL"},
    { UET_PDS_NH_REQ_MEDIUM,        "REQ_MEDIUM"},
    { UET_PDS_NH_REQ_STD,           "REQ_STD"},
    { UET_PDS_NH_RSP,               "RESP"},
    { UET_PDS_NH_RSP_DATA,          "RESP_DATA"},
    { UET_PDS_NH_RSP_DATA_SMALL,    "RESP_DATA_SMALL"},
    { 0, NULL }
};

#define PDS_CTL_TYPE_NO_OP          0
#define PDS_CTL_TYPE_REQ_FOR_ACK    1
#define PDS_CTL_TYPE_CLEAR          2
#define PDS_CTL_TYPE_REQ_FOR_CLEAR  3
#define PDS_CTL_TYPE_CLOSE          4
#define PDS_CTL_TYPE_REQ_FOR_CLOSE  5
#define PDS_CTL_TYPE_PROBE          6
#define PDS_CTL_TYPE_CREDIT         7
#define PDS_CTL_TYPE_CREDIT_REQ     8

static const value_string uet_pds_ctl_type_vals[] = {
    { PDS_CTL_TYPE_NO_OP,           "NO OP"},
    { PDS_CTL_TYPE_REQ_FOR_ACK,     "Request for ACK"},
    { PDS_CTL_TYPE_CLEAR,           "Clear"},
    { PDS_CTL_TYPE_REQ_FOR_CLEAR,   "Request for Clear"},
    { PDS_CTL_TYPE_CLOSE,           "Close"},
    { PDS_CTL_TYPE_REQ_FOR_CLOSE,   "Request for Close"},
    { PDS_CTL_TYPE_PROBE,           "Probe"},
    { PDS_CTL_TYPE_CREDIT,          "Credit"},
    { PDS_CTL_TYPE_CREDIT_REQ,      "Request for Credit"},
    { 0, NULL }
};
static value_string_ext uet_pds_ctl_type_vals_ext = VALUE_STRING_EXT_INIT(uet_pds_ctl_type_vals);

static const value_string pds_ctl_type_func_vals[] = {
  {PDS_CTL_TYPE_NO_OP,          "Null"},
  {PDS_CTL_TYPE_REQ_FOR_ACK,    "[0x0000, Message ID] or 0x0"},
  {PDS_CTL_TYPE_CLEAR,          "Clear Sequence Number"},
  {PDS_CTL_TYPE_REQ_FOR_CLEAR,  "Clear Sequence Number"},
  {PDS_CTL_TYPE_CLOSE,          "Null"},
  {PDS_CTL_TYPE_REQ_FOR_CLOSE,  "Null"},
  {PDS_CTL_TYPE_PROBE,          "SACK bitmap base PSN"},
  {PDS_CTL_TYPE_CREDIT,         "Credit allocation"},
  {PDS_CTL_TYPE_CREDIT_REQ,     "Credit Request"},
  {0, NULL}
};

//SES Opcodes
#define UET_SES_OPCODE_NO_OP                0x00
#define UET_SES_OPCODE_WRITE                0x01
#define UET_SES_OPCODE_READ                 0x02
#define UET_SES_OPCODE_ATOMIC               0x03
#define UET_SES_OPCODE_FETCHING_ATOMIC      0x04
#define UET_SES_OPCODE_SEND                 0x05
#define UET_SES_OPCODE_RENDEZVOUS_SEND      0x06
#define UET_SES_OPCODE_DATAGRAM_SEND        0x07
#define UET_SES_OPCODE_DEFERRABLE_SEND      0x08
#define UET_SES_OPCODE_TAGGED_SEND          0x09
#define UET_SES_OPCODE_RENDEZVOUS_TSEND     0x0A
#define UET_SES_OPCODE_DEFERRABLE_TSEND     0x0B
#define UET_SES_OPCODE_DEFERRABLE_RTR       0x0C
#define UET_SES_OPCODE_TSEND_ATOMIC         0x0D
#define UET_SES_OPCODE_TSEND_FETCH_ATOMIC   0x0E
#define UET_SES_OPCODE_MSG_ERROR            0x0F

static const value_string uet_ses_opcode_type_vals[] = {
    { UET_SES_OPCODE_NO_OP,                 "UET_NO_OP"},
    { UET_SES_OPCODE_WRITE,                 "UET_WRITE"},
    { UET_SES_OPCODE_READ,                  "UET_READ"},
    { UET_SES_OPCODE_ATOMIC,                "UET_ATOMIC"},
    { UET_SES_OPCODE_FETCHING_ATOMIC,       "UET_FETCHING_ATOMIC"},
    { UET_SES_OPCODE_SEND,                  "UET_SEND"},
    { UET_SES_OPCODE_RENDEZVOUS_SEND,       "UET_RENDEZVOUS_SEND"},
    { UET_SES_OPCODE_DATAGRAM_SEND,         "UET_DATAGRAM_SEND"},
    { UET_SES_OPCODE_DEFERRABLE_SEND,       "UET_DEFERRABLE_SEND"},
    { UET_SES_OPCODE_TAGGED_SEND,           "UET_TAGGED_SEND"},
    { UET_SES_OPCODE_RENDEZVOUS_TSEND,      "UET_RENDEZVOUS_TSEND"},
    { UET_SES_OPCODE_DEFERRABLE_TSEND,      "UET_DEFERRABLE_TSEND"},
    { UET_SES_OPCODE_DEFERRABLE_RTR,        "UET_DEFERRABLE_RTR"},
    { UET_SES_OPCODE_TSEND_ATOMIC,          "UET_TSEND_ATOMIC"},
    { UET_SES_OPCODE_TSEND_FETCH_ATOMIC,    "UET_TSEND_FETCH_ATOMIC"},
    { UET_SES_OPCODE_MSG_ERROR,             "UET_MSG_ERROR"},
    { 0, NULL }
};

static value_string_ext uet_ses_opcode_vals_ext = VALUE_STRING_EXT_INIT(uet_ses_opcode_type_vals);

//SES Flags
#define UET_SES_REQ_FLAGS_DC            0x20
#define UET_SES_REQ_FLAGS_IE            0x10
#define UET_SES_REQ_FLAGS_REL           0x08
#define UET_SES_REQ_FLAGS_HD            0x04
#define UET_SES_REQ_FLAGS_EOM           0x02
#define UET_SES_REQ_FLAGS_SOM           0x01

//PDS Flags
#define UET_PDS_RUD_ROD_FLAGS_RETX      0x10
#define UET_PDS_RUD_ROD_FLAGS_AR        0x08
#define UET_PDS_RUD_ROD_FLAGS_SYN       0x04

#define UET_PDS_ACK_FLAGS_M             0x20
#define UET_PDS_ACK_FLAGS_P             0x08
#define UET_PDS_ACK_FLAGS_REQ           0x06

//PDS cc_type
#define UET_PDS_CC_NSCC                 0
#define UET_PDS_CC_CREDIT               1

static const value_string uet_pds_flags_ack_req_vals[] = {
    { 0x0,        "No Request"},
    { 0x1,        "Clear PSN"},
    { 0x2,        "Close PDC"},
    { 0x3,        "Reserved"},
    { 0, NULL }
};
static value_string_ext uet_pds_flags_ack_req_vals_ext = VALUE_STRING_EXT_INIT(uet_pds_flags_ack_req_vals);

static const value_string uet_ses_atomic_op_ext_hdr_atomic_opcode_vals[] = {
    { 0x00,        "Minimum: Target = MIN(Target, Initiator)"},
    { 0x01,        "Maximum: Target = MAX(Target, Initiator)"},
    { 0x02,        "Sum : Target = Target + Initiator"},
    { 0x03,        "Diff : Target = Target – Initiator"},
    { 0x04,        "Product : Target = Target * Initiator"},
    { 0x05,        "Logical OR : Target = Target || Initiator"},
    { 0x06,        "Logical AND : Target = Target && Initiator"},
    { 0x07,        "Bitwise OR : Target = Target | Initiator"},
    { 0x08,        "Bitwise AND : Target = Target & Initiator"},
    { 0x09,        "Logical XOR :"},
    { 0x0A,        "Bitwise XOR : Target = Target ^ Initiator"},
    { 0x0B,        "Atomic Read : Initiator = Target"},
    { 0x0C,        "Atomic Write : Target = Initiator"},
    { 0x0D,        "Compare and swap if equal"},
    { 0x0E,        "Compare and swap if not equal"},
    { 0x0F,        "Compare and swap if less than or equal"},
    { 0x10,        "Compare and swap if less than"},
    { 0x11,        "Compare and swap if greater than or equal"},
    { 0x12,        "Compare and swap if greater than"},
    { 0x13,        "Swap masked bits : Target = (Target & Mask) ^ Initiator"},
    { 0, NULL }
};
static value_string_ext uet_ses_atomic_op_ext_hdr_atomic_opcode_vals_ext = VALUE_STRING_EXT_INIT(uet_ses_atomic_op_ext_hdr_atomic_opcode_vals);

static const value_string uet_ses_atomic_op_ext_hdr_atomic_data_type_vals[] = {
    { 0x00,        "8-bit signed integer"},
    { 0x01,        "8-bit unsigned integer"},
    { 0x02,        "16-bit signed integer"},
    { 0x03,        "16-bit unsigned integer"},
    { 0x04,        "32-bit signed integer"},
    { 0x05,        "32-bit unsigned integer"},
    { 0x06,        "64-bit signed integer"},
    { 0x07,        "64-bit unsigned integer"},
    { 0x08,        "128-bit signed integer"},
    { 0x09,        "128-bit unsigned integer"},
    { 0x0A,        "Single-precision floating point value"},
    { 0x0B,        "Double-precision floating point value"},
    { 0x0C,        "Pair of floats {real, imaginary)"},
    { 0x0D,        "Pair of doubles {real, imaginary)"},
    { 0x0E,        "Double-extended precision floating point"},
    { 0x0F,        "Pair of long doubles {real, imaginary)"},
    { 0x10,        "16-bit floating point (bfloat 16)"},
    { 0x11,        "16-bit floating point (FP16 format)"},
    { 0, NULL }
};
static value_string_ext uet_ses_atomic_op_ext_hdr_atomic_data_type_vals_ext = VALUE_STRING_EXT_INIT(uet_ses_atomic_op_ext_hdr_atomic_data_type_vals);
static value_string_ext uet_ses_comp_swap_ext_hdr_atomic_data_type_vals_ext = VALUE_STRING_EXT_INIT(uet_ses_atomic_op_ext_hdr_atomic_data_type_vals);

static const value_string uet_ses_atomic_op_ext_hdr_sem_ctl_vals[] = {
    { 0x00,        "None"},
    { 0x01,        "Cacheable"},
    { 0x02,        "CPU coherent"},
    { 0x03,        "Cacheable, CPU coherent"},
    { 0, NULL }
};
static value_string_ext uet_ses_atomic_op_ext_hdr_sem_ctl_vals_ext = VALUE_STRING_EXT_INIT(uet_ses_atomic_op_ext_hdr_sem_ctl_vals);
static value_string_ext uet_ses_comp_swap_ext_hdr_sem_ctl_vals_ext = VALUE_STRING_EXT_INIT(uet_ses_atomic_op_ext_hdr_sem_ctl_vals);

//SES RESP OPCODES
#define UET_SES_RSP_DEFAULT_RESPONSE    0x00
#define UET_SES_RSP_RESPONSE            0x01
#define UET_SES_RSP_RESPONSE_W_DATA     0x02
#define UET_SES_RSP_NO_RESPONSE         0x03

static const value_string uet_ses_rsp_opcode_vals[] = {
    { UET_SES_RSP_DEFAULT_RESPONSE,         "Default Response"},
    { UET_SES_RSP_RESPONSE,                 "Response"},
    { UET_SES_RSP_RESPONSE_W_DATA,          "Response With Data"},
    { UET_SES_RSP_NO_RESPONSE,              "No Response"},
    { 0, NULL }
};
static value_string_ext uet_ses_rsp_opcode_vals_ext = VALUE_STRING_EXT_INIT(uet_ses_rsp_opcode_vals);

#define UET_SES_RSP_RC_NULL                 0x00
#define UET_SES_RSP_RC_OK                   0x01
#define UET_SES_RSP_RC_BAD_GENERATION       0x02
#define UET_SES_RSP_RC_DISABLED             0x03
#define UET_SES_RSP_RC_DISABLED_GEN         0x04
#define UET_SES_RSP_RC_NO_MATCH             0x05
#define UET_SES_RSP_RC_UNSUPPORTED_OP       0x06
#define UET_SES_RSP_RC_UNSUPPORTED_SIZE     0x07
#define UET_SES_RSP_RC_AT_INVALID           0x08
#define UET_SES_RSP_RC_AT_PERM              0x09
#define UET_SES_RSP_RC_AT_ATS_ERROR         0x0A
#define UET_SES_RSP_RC_AT_NO_TRANS          0x0B
#define UET_SES_RSP_RC_AT_OUT_OF_RANGE      0x0C
#define UET_SES_RSP_RC_HOST_POISONED        0x0D
#define UET_SES_RSP_RC_HOST_UNSUCCESS_CMPL  0x0E
#define UET_SES_RSP_RC_AMO_UNSUPPORTED_OP   0x0F
#define UET_SES_RSP_RC_AMO_UNSUPPORTED_DT   0x10
#define UET_SES_RSP_RC_AMO_UNSUPPORTED_SIZE 0x11
#define UET_SES_RSP_RC_AMO_UNALIGNED        0x12
#define UET_SES_RSP_RC_AMO_FP_NAN           0x13
#define UET_SES_RSP_RC_AMO_FP_UNDERFLOW     0x14
#define UET_SES_RSP_RC_AMO_FP_OVERFLOW      0x15
#define UET_SES_RSP_RC_AMO_FP_INEXACT       0x16
#define UET_SES_RSP_RC_PERM_VIOLATION       0x17
#define UET_SES_RSP_RC_OP_VIOLATION         0x18
#define UET_SES_RSP_RC_BAD_INDEX            0x19
#define UET_SES_RSP_RC_BAD_PID              0x1A
#define UET_SES_RSP_RC_BAD_JOB_ID           0x1B
#define UET_SES_RSP_RC_BAD_MKEY             0x1C
#define UET_SES_RSP_RC_BAD_ADDR             0x1D
#define UET_SES_RSP_RC_CANCELLED            0x1E
#define UET_SES_RSP_RC_UNDELIVERABLE        0x1F
#define UET_SES_RSP_RC_UNCOR                0x20
#define UET_SES_RSP_RC_UNCOR_TRNSNT         0x21
#define UET_SES_RSP_RC_TOO_LONG             0x22
#define UET_SES_RSP_RC_INITIATOR_ERR        0x23
#define UET_SES_RSP_RC_DROPPED              0x24

static const value_string uet_ses_rsp_return_code_vals[] = {
    { UET_SES_RSP_RC_NULL,              "Null"},
    { UET_SES_RSP_RC_OK,                "Success"},
    { UET_SES_RSP_RC_BAD_GENERATION,    "The generation did not match the generation at the target index"},
    { UET_SES_RSP_RC_DISABLED,          "Targeted resource is disabled"},
    { UET_SES_RSP_RC_DISABLED_GEN,      "The targeted resource is disabled and supports the index generation"},
    { UET_SES_RSP_RC_NO_MATCH,          "The message could not be matched at the target and was dropped"},
    { UET_SES_RSP_RC_UNSUPPORTED_OP,    "Unsupported network operation type"},
    { UET_SES_RSP_RC_UNSUPPORTED_SIZE,  "The message was larger than the supported size"},
    { UET_SES_RSP_RC_AT_INVALID,        "Invalid address translation context"},
    { UET_SES_RSP_RC_AT_PERM,           "Address translation permission failure"},
    { UET_SES_RSP_RC_AT_ATS_ERROR,      "ATS translation request resulted in either Unsupported Request or Completer Abort"},
    { UET_SES_RSP_RC_AT_NO_TRANS,       "Unable to obtain a translation"},
    { UET_SES_RSP_RC_AT_OUT_OF_RANGE,   "Virtual address is out of range and unable to attempt translation"},
    { UET_SES_RSP_RC_HOST_POISONED,     "The host read (e.g. PCIe) indicated the access was poisoned"},
    { UET_SES_RSP_RC_HOST_UNSUCCESS_CMPL, "The host read (e.g. PCIe) indicated an unsuccessful completion"},
    { UET_SES_RSP_RC_AMO_UNSUPPORTED_OP, "Unsupported AMO message type"},
    { UET_SES_RSP_RC_AMO_UNSUPPORTED_DT, "Invalid datatype at the target"},
    { UET_SES_RSP_RC_AMO_UNSUPPORTED_SIZE, "The AMO operation was not an integral multiple of the datatype size"},
    { UET_SES_RSP_RC_AMO_UNALIGNED,     "The AMO operation address was not natively aligned to the datatype size"},
    { UET_SES_RSP_RC_AMO_FP_NAN,        "An AMO operation generated a NaN and signaling is enabled"},
    { UET_SES_RSP_RC_AMO_FP_UNDERFLOW,  "An AMO operation generated an underflow and signaling is enabled"},
    { UET_SES_RSP_RC_AMO_FP_OVERFLOW,   "An AMO operation generated an overflow and signaling is enabled"},
    { UET_SES_RSP_RC_AMO_FP_INEXACT,    "An AMO operation generated an inexact exception and signaling is enabled"},
    { UET_SES_RSP_RC_PERM_VIOLATION,    "Message processing encountered a permissions violation (e.g., a mismatch in the JobID)"},
    { UET_SES_RSP_RC_OP_VIOLATION,      "An operation violation occurred. This includes a read attempting to access a buffered configured as write only, a write attempting to access a buffered configured as read only, or an atomic attempting to access a buffer that does not have both read and write permissions"},
    { UET_SES_RSP_RC_BAD_INDEX,         "An unconfigured index was encountered"},
    { UET_SES_RSP_RC_BAD_PID,           "PID was not found at the target node (within the JobID for relative addressing, or at all for absolute addressing)"},
    { UET_SES_RSP_RC_BAD_JOB_ID,        "JobID was not found at the target node"},
    { UET_SES_RSP_RC_BAD_MKEY,          "The specified memory key does not map to a buffer"},
    { UET_SES_RSP_RC_BAD_ADDR,          "Invalid address (not covered elsewhere) (e.g., an offset that extends beyond the length of the configured memory region)"},
    { UET_SES_RSP_RC_CANCELLED,         "Response indicating the target cancelled an in-flight message"},
    { UET_SES_RSP_RC_UNDELIVERABLE,     "Message could not be delivered"},
    { UET_SES_RSP_RC_UNCOR,             "An uncorrectable error was detected. The error is not likely to be rectified without corrective action"},
    { UET_SES_RSP_RC_UNCOR_TRNSNT,      "An uncorrectable error was detected. The error is likely to be transient"},
    { UET_SES_RSP_RC_TOO_LONG,          "The message was longer than the buffer it addressed. The target was configured to reject a message that was too long rather than truncate it"},
    { UET_SES_RSP_RC_INITIATOR_ERR,     "This RC echoes back the initiator error field from the incoming packet"},
    { UET_SES_RSP_RC_DROPPED,           "Message dropped at the target for reasons other than those enumerated elsewhere"},
    { 0, NULL }
};
static value_string_ext uet_ses_rsp_return_code_vals_ext = VALUE_STRING_EXT_INIT(uet_ses_rsp_return_code_vals);

#define UET_PDS_NACK_CODE_TRIMMED               0x01
#define UET_PDS_NACK_CODE_TRIMMED_LASTHOP       0x02
#define UET_PDS_NACK_CODE_TRIMMED_ACK           0x03
#define UET_PDS_NACK_CODE_NO_PDC_AVAIL          0x04
#define UET_PDS_NACK_CODE_NO_CCC_AVAIL          0x05
#define UET_PDS_NACK_CODE_NO_BITMAP             0x06
#define UET_PDS_NACK_CODE_NO_PKT_BUFFER         0x07
#define UET_PDS_NACK_CODE_NO_GTD_DEL_AVAIL      0x08
#define UET_PDS_NACK_CODE_NO_SES_MSG_AVAIL      0x09
#define UET_PDS_NACK_CODE_NO_RESOURCE           0x0A
#define UET_PDS_NACK_CODE_PSN_OOR_WINDOW        0x0B
#define UET_PDS_NACK_CODE_ROD_OOO               0x0D
#define UET_PDS_NACK_CODE_INV_DPDCID            0x0E
#define UET_PDS_NACK_CODE_PDC_HDR_MISMATCH      0x0F
#define UET_PDS_NACK_CODE_CLOSING               0x10
#define UET_PDS_NACK_CODE_CLOSING_IN_ERR        0x11
#define UET_PDS_NACK_CODE_PKT_NOT_RCVD          0x12
#define UET_PDS_NACK_CODE_GTD_DEL_RESP_UNAVAIL  0x13
#define UET_PDS_NACK_CODE_ACK_WITH_DATA         0x14
#define UET_PDS_NACK_CODE_INVALID_SYN           0x15
#define UET_PDS_NACK_CODE_PDC_MODE_MISMATCH     0x16
#define UET_PDS_NACK_CODE_NEW_START_PSN         0x17
#define UET_PDS_NACK_CODE_RCVD_SES_PROCG        0x18
#define UET_PDS_NACK_CODE_UNEXP_EVENT           0x19
#define UET_PDS_NACK_CODE_RCVR_INFER_LOSS       0x1A
#define UET_PDS_NACK_CODE_EXP_NACK_NORMAL       0xFD
#define UET_PDS_NACK_CODE_EXP_NACK_ERR          0xFE
#define UET_PDS_NACK_CODE_EXP_NACK_FATAL        0xFF

static const value_string uet_pds_nack_code_vals[] = {
    { UET_PDS_NACK_CODE_TRIMMED, "Packet was trimmed"},
    { UET_PDS_NACK_CODE_TRIMMED_LASTHOP, "Packet was trimmed at the last hop switch"},
    { UET_PDS_NACK_CODE_TRIMMED_ACK, "An ACK carrying read response data was trimmed"},
    { UET_PDS_NACK_CODE_NO_PDC_AVAIL, "No PDC resource available"},
    { UET_PDS_NACK_CODE_NO_CCC_AVAIL, "No CCC resource available"},
    { UET_PDS_NACK_CODE_NO_BITMAP, "No bitmap or other PSN tracking resource available"},
    { UET_PDS_NACK_CODE_NO_PKT_BUFFER, "No packet buffer resource available"},
    { UET_PDS_NACK_CODE_NO_GTD_DEL_AVAIL, "No SES guaranteed delivery response resource available"},
    { UET_PDS_NACK_CODE_NO_SES_MSG_AVAIL, "No message tracking state available"},
    { UET_PDS_NACK_CODE_NO_RESOURCE, "General resource not available"},
    { UET_PDS_NACK_CODE_PSN_OOR_WINDOW, "PSN outside tracking window (e.g., beyond end of available bitmap)"},
    { UET_PDS_NACK_CODE_ROD_OOO, "A PSN arrived out of order on a ROD PDC"},
    { UET_PDS_NACK_CODE_INV_DPDCID, "DPDCID not recognized and SYN not set"},
    { UET_PDS_NACK_CODE_PDC_HDR_MISMATCH, "The packet does not have SYN set but did not match connection state (e.g., source IP address or other field doesn't match PDC state)"},
    { UET_PDS_NACK_CODE_CLOSING, "The target PDCID is in a closed state or is in the process of being closed and a new PDS Request is received which advances the PSN"},
    { UET_PDS_NACK_CODE_CLOSING_IN_ERR, "Timeout at target during close process - e.g. no response to close request"},
    { UET_PDS_NACK_CODE_PKT_NOT_RCVD, "Control Packet arrived with ACK Request but packet with requested PSN was not received"},
    { UET_PDS_NACK_CODE_GTD_DEL_RESP_UNAVAIL, "Duplicate PSN is received, state indicates there is a guaranteed delivery SES Response but that response cannot be found, and this PSN was not cleared"},
    { UET_PDS_NACK_CODE_ACK_WITH_DATA, "ACK request for PSN with associated read response data"},
    { UET_PDS_NACK_CODE_INVALID_SYN, "Packet is received with SYN set with PSN outside the expected range of PSNs with SYN"},
    { UET_PDS_NACK_CODE_PDC_MODE_MISMATCH, "Packet is received and delivery mode does not match (RUD/ROD)"},
    { UET_PDS_NACK_CODE_NEW_START_PSN, "Resend all packets with new starting PSN"},
    { UET_PDS_NACK_CODE_RCVD_SES_PROCG, "This is unexpected - retransmit times should be much higher than SES processing times, retry until fatal"},
    { UET_PDS_NACK_CODE_UNEXP_EVENT, "This is unexpected – processing requires an unsupported feature; use this if an event occurs that is unexpected - e.g., something indicating an implementation error"},
    { UET_PDS_NACK_CODE_RCVR_INFER_LOSS, "Destination infers a PSN was lost and effectively requests retransmission, application specific"},
    { UET_PDS_NACK_CODE_EXP_NACK_NORMAL, "Experimental normal code"},
    { UET_PDS_NACK_CODE_EXP_NACK_ERR, "Experimental error code"},
    { UET_PDS_NACK_CODE_EXP_NACK_FATAL, "Experimental fatal code"},
    { 0, NULL }
};
static value_string_ext uet_pds_nack_code_vals_ext = VALUE_STRING_EXT_INIT(uet_pds_nack_code_vals);

static const true_false_string uet_ses_std_rel_str = {
  "Relative Addressing",
  "Absolute Addressing"
};


// Atomic opcodes
#define UET_AMO_MIN 0
#define UET_AMO_MAX 1
#define UET_AMO_SUM 2
#define UET_AMO_DIFF 3
#define UET_AMO_PROD 4
#define UET_AMO_LOR 5
#define UET_AMO_LAND 6
#define UET_AMO_BOR 7
#define UET_AMO_BAND 8
#define UET_AMO_LXOR 9
#define UET_AMO_BXOR 0xA
#define UET_AMO_READ 0xB
#define UET_AMO_WRITE 0xC
#define UET_AMO_CSWAP 0xD
#define UET_AMO_CSWAP_NE 0xE
#define UET_AMO_CSWAP_LE 0xF
#define UET_AMO_CSWAP_LT 0x10
#define UET_AMO_CSWAP_GE 0x11
#define UET_AMO_CSWAP_GT 0x12
#define UET_AMO_MSWAP 0x13
#define UET_AMO_INVAL 0x14
#define UET_AMO_VENDOR0 0xE0
#define UET_AMO_RESERVED 0xFF

#define UET_COMMON_HDR_SIZE             4
#define UET_PDS_RUD_ROD_MIN_HDR_LEN     12
#define UET_PDS_RUD_ROD_CC_MIN_HDR_LEN  16
#define UET_PDS_ACK_EXT_HDR_SIZE        20
#define UET_SES_ATOMIC_OP_EXT_HDR_SIZE  4
#define UET_SES_RENDV_EXT_HDR_SIZE      24
#define UET_SES_COMP_SWAP_EXT_HDR_SIZE  36
#define UET_SES_SMALL_REQ_MIN_HDR_LEN   20
#define UET_SES_MEDIUM_REQ_MIN_HDR_LEN  32
#define UET_SES_RESP_HDR_LEN            12
#define UET_SES_STD_MIN_HDR_LEN         44
#define UET_TSS_HDR_LEN                 20

static int
dissect_ses_comp_swap_atomic_ext_hdr(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int offset)
{
    proto_tree* ext_tree = NULL;
    proto_item* ext_item = NULL;
    unsigned    orig_offset = offset;

    if (tvb_reported_length_remaining(tvb, offset) < UET_SES_COMP_SWAP_EXT_HDR_SIZE) {
        expert_add_info_format(pinfo, ext_item, &ei_uet_ses_hdr_len_invalid, "SES Compare and Swap Ext hdr len must be at least %d",
            UET_SES_COMP_SWAP_EXT_HDR_SIZE);

        return offset - orig_offset;
    }

    //Figure 14

    ext_item = proto_tree_add_item(tree, hf_uet_ses_comp_swap_ext_hdr, tvb, offset, UET_SES_COMP_SWAP_EXT_HDR_SIZE, ENC_NA);
    proto_item_set_text(ext_item, "%s", "Compare and Swap Operation Atomic Header");
    ext_tree = proto_item_add_subtree(ext_item, ett_uet_ses_comp_swap_ext_hdr);
    proto_tree_add_item(ext_tree, hf_uet_ses_comp_swap_ext_hdr_atomic_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ext_tree, hf_uet_ses_comp_swap_ext_hdr_atomic_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ext_tree, hf_uet_ses_comp_swap_ext_hdr_sem_ctl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ext_tree, hf_uet_ses_comp_swap_ext_hdr_rsvd, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(ext_tree, hf_uet_ses_comp_swap_ext_hdr_comp_value, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(ext_tree, hf_uet_ses_comp_swap_ext_hdr_swap_value, tvb, offset, 16, ENC_NA);
    offset += 16;

    return (offset - orig_offset);
}

static int
dissect_ses_atomic_op_ext_hdr(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, int offset)
{
    proto_tree *ext_tree = NULL;
    proto_item *ext_item = NULL;
    unsigned    orig_offset = offset;

    if (tvb_reported_length_remaining(tvb, offset) < UET_SES_ATOMIC_OP_EXT_HDR_SIZE) {
        expert_add_info_format(pinfo, ext_item, &ei_uet_ses_hdr_len_invalid, "SES Atomic Ext hdr len must be at least %d",
            UET_SES_ATOMIC_OP_EXT_HDR_SIZE);

        return offset - orig_offset;
    }

    ext_item = proto_tree_add_item(tree, hf_uet_ses_atomic_op_ext_hdr, tvb, offset, UET_SES_ATOMIC_OP_EXT_HDR_SIZE, ENC_NA);
    proto_item_set_text(ext_item, "%s", "Atomic Operation Extension Header");
    ext_tree = proto_item_add_subtree(ext_item, ett_uet_ses_atomic_op_ext_hdr);
    proto_tree_add_item(ext_tree, hf_uet_ses_atomic_op_ext_hdr_atomic_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ext_tree, hf_uet_ses_atomic_op_ext_hdr_atomic_data_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ext_tree, hf_uet_ses_atomic_op_ext_hdr_sem_ctl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ext_tree, hf_uet_ses_atomic_op_ext_hdr_rsvd, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return (offset - orig_offset);
}

/* Dissect an AMO header or a dual operand AMO header. */
static int dissect_ses_atomic_hdr(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, int offset)
{
    int rc;
    uint8_t op;

    op = tvb_get_bits8(tvb, offset * 8, 8);

    switch (op) {
    case UET_AMO_CSWAP:
    case UET_AMO_CSWAP_NE:
    case UET_AMO_CSWAP_LE:
    case UET_AMO_CSWAP_LT:
    case UET_AMO_CSWAP_GE:
    case UET_AMO_CSWAP_GT:
        rc = dissect_ses_comp_swap_atomic_ext_hdr(tree, tvb, pinfo, offset);
        break;

    default:
        rc = dissect_ses_atomic_op_ext_hdr(tree, tvb, pinfo, offset);
        break;
    }

    return rc;
}

static int
dissect_ses_rendv_ext_hdr(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, int offset)
{
    proto_tree* ext_tree = NULL;
    proto_item* ext_item = NULL;
    unsigned    orig_offset = offset;

    //Figure 12

    ext_item = proto_tree_add_item(tree, hf_uet_ses_rendv_ext_hdr, tvb, offset, UET_SES_RENDV_EXT_HDR_SIZE, ENC_NA);
    proto_item_set_text(ext_item, "%s", "Rendezvous Extension Header");
    ext_tree = proto_item_add_subtree(ext_item, ett_uet_ses_rendv_ext_hdr);

    if (tvb_reported_length_remaining(tvb, offset) < UET_SES_RENDV_EXT_HDR_SIZE) {
        expert_add_info_format(pinfo, ext_item, &ei_uet_ses_hdr_len_invalid, "SES Rendezvous Ext hdr len must be at least %d",
            UET_SES_RENDV_EXT_HDR_SIZE);
    }

    proto_tree_add_item(ext_tree, hf_uet_ses_rendv_ext_hdr_eager_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ext_tree, hf_uet_ses_rendv_ext_hdr_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_uet_ses_rendv_ext_hdr_read_pid_on_fep, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ext_tree, hf_uet_ses_rendv_ext_hdr_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ext_tree, hf_uet_ses_rendv_ext_hdr_read_resource_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ext_tree, hf_uet_ses_rendv_ext_hdr_read_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(ext_tree, hf_uet_ses_rendv_ext_hdr_read_match_bits, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return (offset - orig_offset);
}

static int
dissect_ses_std_req(proto_tree* ses_tree, proto_item* ses_item, tvbuff_t* tvb, packet_info* pinfo, unsigned offset)
{
    static int * const flag_fields[] = {
        &hf_uet_ses_std_ver,
        &hf_uet_ses_std_dc,
        &hf_uet_ses_std_ie,
        &hf_uet_ses_std_rel,
        &hf_uet_ses_std_hd,
        &hf_uet_ses_std_eom,
        &hf_uet_ses_std_som,
        NULL,
    };
    uint8_t     opcode = 0;
    unsigned    orig_offset = offset;
    uint64_t    flags = 0;

    /* 4.3.6 Header Parsing Guide */
    //    Non - Atomic Opcodes - Figure 6
    //    Atomic Opcodes - Figure 6 + Figure 13
    //    Two Op Atomics - Figure 6 + Figure 14
    //    Deferrable Send - Figure 8
    //    Ready to Restart - Figure 9
    //    Rendezvous Opcodes - Figure 6 + Figure 12
    //

    if (tvb_reported_length_remaining(tvb, offset) < UET_SES_STD_MIN_HDR_LEN) {
        expert_add_info_format(pinfo, ses_item, &ei_uet_ses_hdr_len_invalid, "SES STD header must be at least %d bytes",
            UET_SES_STD_MIN_HDR_LEN);
    }

    opcode = tvb_get_bits8(tvb, offset * 8 + 2, 6);
    proto_item_append_text(ses_item, ", Type: %s", val_to_str(pinfo->pool, opcode, uet_ses_opcode_type_vals, "Unknown (%u)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(pinfo->pool, opcode, uet_ses_opcode_type_vals, "Unknown (%u)"));

    proto_tree_add_item(ses_tree, hf_uet_ses_std_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_std_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_bitmask_ret_uint64(ses_tree, tvb, offset, hf_uet_ses_std_flags, ett_uet_ses_std_flags, flag_fields, ENC_BIG_ENDIAN, &flags);
    offset += 1;

    proto_tree_add_item(ses_tree, hf_uet_ses_std_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ses_tree, hf_uet_ses_std_index_generation, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ses_tree, hf_uet_ses_std_job_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(ses_tree, hf_uet_ses_std_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_std_pidonfep, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ses_tree, hf_uet_ses_std_reserved3, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_std_resource_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (opcode == UET_SES_OPCODE_DEFERRABLE_SEND || opcode == UET_SES_OPCODE_DEFERRABLE_TSEND) {
        proto_tree_add_item(ses_tree, hf_uet_ses_std_restart_token, tvb, offset, 8, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(ses_tree, hf_uet_ses_std_buffer_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    }
    offset += 8;
    proto_tree_add_item(ses_tree, hf_uet_ses_std_initiator, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if (opcode == UET_SES_OPCODE_DEFERRABLE_RTR) {
        proto_tree_add_item(ses_tree, hf_uet_ses_std_restart_token, tvb, offset, 8, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(ses_tree, hf_uet_ses_std_mem_key_match_bits, tvb, offset, 8, ENC_BIG_ENDIAN);
    }
    offset += 8;
    if (flags & UET_SES_REQ_FLAGS_SOM) {
        proto_tree_add_item(ses_tree, hf_uet_ses_std_header_data, tvb, offset, 8, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(ses_tree, hf_uet_ses_std_reserved4, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ses_tree, hf_uet_ses_std_payload_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ses_tree, hf_uet_ses_std_message_offset, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
    }
    offset += 8;
    proto_tree_add_item(ses_tree, hf_uet_ses_std_request_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    //TODO: decode crc header

    //decode ext header
    switch (opcode) {
    case UET_SES_OPCODE_ATOMIC:
    case UET_SES_OPCODE_FETCHING_ATOMIC:
    case UET_SES_OPCODE_TSEND_FETCH_ATOMIC:
        offset += dissect_ses_atomic_hdr(ses_tree, tvb, pinfo, offset);
        break;

    case UET_SES_OPCODE_RENDEZVOUS_SEND:
    case UET_SES_OPCODE_RENDEZVOUS_TSEND:
        //Figure 12
        offset += dissect_ses_rendv_ext_hdr(ses_tree, tvb, pinfo, offset);
        break;

    default:
        break;
    }

    return (offset - orig_offset);
}


static int
dissect_ses_small_req(proto_tree* ses_tree, proto_item* ses_item, tvbuff_t* tvb, packet_info* pinfo, unsigned offset)
{
    static int * const flag_fields[] = {
        &hf_uet_ses_small_req_flags_ver,
        &hf_uet_ses_small_req_flags_dc,
        &hf_uet_ses_small_req_flags_ie,
        &hf_uet_ses_small_req_flags_rel,
        &hf_uet_ses_small_req_flags_rsvd,
        &hf_uet_ses_small_req_flags_eom,
        &hf_uet_ses_small_req_flags_som,
        NULL,
    };
    uint8_t     opcode = 0;
    unsigned    orig_offset = offset;

    //Figure 10

    if (tvb_reported_length_remaining(tvb, offset) < UET_SES_SMALL_REQ_MIN_HDR_LEN) {
        expert_add_info_format(pinfo, ses_item, &ei_uet_ses_hdr_len_invalid, "SES SMALL Req header len must be at least %d", UET_SES_SMALL_REQ_MIN_HDR_LEN);
    }

    opcode = tvb_get_bits8(tvb, offset * 8 + 2, 6);
    proto_item_append_text(ses_item, ", Type: %s", val_to_str(pinfo->pool, opcode, uet_ses_opcode_type_vals, "Unknown (%u)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(pinfo->pool, opcode, uet_ses_opcode_type_vals, "Unknown (%u)"));

    proto_tree_add_item(ses_tree, hf_uet_ses_small_req_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_std_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_bitmask(ses_tree, tvb, offset, hf_uet_ses_small_req_flags, ett_uet_ses_small_req_flags, flag_fields, ENC_BIG_ENDIAN);
    /* XXX - ses.som and ses.eom must both be set (expert data?) */
    offset += 1;

    proto_tree_add_item(ses_tree, hf_uet_ses_small_req_flags_rsv2, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_small_req_req_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(ses_tree, hf_uet_ses_small_req_index_generation, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ses_tree, hf_uet_ses_small_req_job_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(ses_tree, hf_uet_ses_small_req_rsv3, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_small_req_pidonfep, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ses_tree, hf_uet_ses_small_req_rsv4, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_small_req_resource_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ses_tree, hf_uet_ses_small_req_buffer_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    //+++TODO: crc header

    //decode ext header
    switch (opcode) {
    case UET_SES_OPCODE_ATOMIC:
    case UET_SES_OPCODE_FETCHING_ATOMIC:
    case UET_SES_OPCODE_TSEND_FETCH_ATOMIC:
        offset += dissect_ses_atomic_hdr(ses_tree, tvb, pinfo, offset);
        break;

    default:
        break;
    }

    return (offset - orig_offset);
}

static int
dissect_ses_medium_req(proto_tree* ses_tree, proto_item* ses_item, tvbuff_t* tvb, packet_info* pinfo, unsigned offset)
{
    static int * const flag_fields[] = {
        &hf_uet_ses_med_req_flags_ver,
        &hf_uet_ses_med_req_flags_dc,
        &hf_uet_ses_med_req_flags_ie,
        &hf_uet_ses_med_req_flags_rel,
        &hf_uet_ses_med_req_flags_hd,
        &hf_uet_ses_med_req_flags_eom,
        &hf_uet_ses_med_req_flags_som,
        NULL,
    };
    uint8_t     opcode = 0;
    unsigned    orig_offset = offset;
    uint64_t    flags;

    //Figure 11

    if (tvb_reported_length_remaining(tvb, offset) < UET_SES_MEDIUM_REQ_MIN_HDR_LEN) {
        expert_add_info_format(pinfo, ses_item, &ei_uet_ses_hdr_len_invalid, "SES Medium Req header len must be at least %d",
            UET_SES_MEDIUM_REQ_MIN_HDR_LEN);
    }

    opcode = tvb_get_bits8(tvb, offset * 8 + 2, 6);
    proto_item_append_text(ses_item, ", Type: %s", val_to_str(pinfo->pool, opcode, uet_ses_opcode_type_vals, "Unknown (%u)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", val_to_str(pinfo->pool, opcode, uet_ses_opcode_type_vals, "Unknown (%u)"));

    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_std_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_bitmask_ret_uint64(ses_tree, tvb, offset, hf_uet_ses_med_req_flags, ett_uet_ses_med_req_flags, flag_fields, ENC_BIG_ENDIAN, &flags);
    /* XXX - ses.som and ses.eom must both be set (expert data?) */
    offset += 1;

    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_flags_rsv2, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_req_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_resource_index_generation, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_job_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_rsv3, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_pidonfep, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_rsv4, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_resource_index, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if (flags & UET_SES_REQ_FLAGS_HD) {
        proto_tree_add_item(ses_tree, hf_uet_ses_med_req_header_data, tvb, offset, 8, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(ses_tree, hf_uet_ses_med_req_buffer_offset, tvb, offset, 8, ENC_BIG_ENDIAN);
    }
    offset += 8;

    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_initiator, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ses_tree, hf_uet_ses_med_req_mem_key_match_bits, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    //TODO: decode crc header

    //decode ext header
    switch (opcode) {
    case UET_SES_OPCODE_ATOMIC:
    case UET_SES_OPCODE_FETCHING_ATOMIC:
    case UET_SES_OPCODE_TSEND_FETCH_ATOMIC:
        offset += dissect_ses_atomic_hdr(ses_tree, tvb, pinfo, offset);
        break;

    default:
        break;
    }

    return (offset - orig_offset);
}

static int
dissect_ses_resp(proto_tree* ses_tree, proto_item* ses_item, tvbuff_t* tvb, packet_info* pinfo, unsigned offset)
{
    proto_item* opcode_item = NULL;
    uint32_t    opcode = 0;
    unsigned    orig_offset = offset;

    //Figure 15

    if (tvb_reported_length_remaining(tvb, offset) < UET_SES_RESP_HDR_LEN) {
        expert_add_info_format(pinfo, ses_item, &ei_uet_ses_hdr_len_invalid, "SES Response header len must be %d",
            UET_SES_RESP_HDR_LEN);
        return (offset - orig_offset);
    }

    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_list, tvb, offset, 1, ENC_BIG_ENDIAN);
    opcode_item = proto_tree_add_item_ret_uint(ses_tree, hf_uet_ses_rsp_opcode, tvb, offset, 1, ENC_BIG_ENDIAN, &opcode);
    offset += 1;
    if ((opcode != UET_SES_RSP_DEFAULT_RESPONSE) && (opcode != UET_SES_RSP_RESPONSE) && (opcode != UET_SES_RSP_NO_RESPONSE)) {
        expert_add_info_format(pinfo, opcode_item, &ei_uet_ses_rsp_opcode_invalid,
            "Invalid opcode %d for ses resp, expected %d or %d or %d",
            (int)opcode, UET_SES_RSP_DEFAULT_RESPONSE, UET_SES_RSP_RESPONSE, UET_SES_RSP_NO_RESPONSE);
        return (offset - orig_offset);
    }
    proto_item_append_text(ses_item, ", Type: %s", val_to_str(pinfo->pool, (uint32_t) opcode, uet_ses_rsp_opcode_vals, "Unknown (%u)"));

    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_return_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_resource_index_gen, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_job_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_mod_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return (offset - orig_offset);
}

static int
dissect_ses_resp_data(proto_tree* ses_tree, proto_item* ses_item, tvbuff_t* tvb, packet_info* pinfo, unsigned offset)
{
    proto_item* opcode_item = NULL;
    uint32_t    opcode = 0;
    unsigned    orig_offset = offset;

    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_list, tvb, offset, 1, ENC_BIG_ENDIAN);
    opcode_item = proto_tree_add_item_ret_uint(ses_tree, hf_uet_ses_rsp_opcode, tvb, offset, 1, ENC_BIG_ENDIAN, &opcode);
    offset += 1;
    if (opcode != UET_SES_RSP_RESPONSE_W_DATA) {
        expert_add_info_format(pinfo, opcode_item, &ei_uet_ses_rsp_opcode_invalid,
            "Invalid opcode %d for ses resp data, expected %d", (int)opcode, UET_SES_RSP_RESPONSE_W_DATA);
        return (offset - orig_offset);
    }
    proto_item_append_text(ses_item, ", Type: %s", val_to_str(pinfo->pool, (uint32_t) opcode, uet_ses_rsp_opcode_vals, "Unknown (%u)"));

    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_return_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_job_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_read_req_message_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_reserved2, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_mod_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_message_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return (offset - orig_offset);
}


static int
dissect_ses_resp_data_small(proto_tree* ses_tree, proto_item* ses_item, tvbuff_t* tvb, packet_info* pinfo, unsigned offset)
{
    proto_item* opcode_item = NULL;
    uint32_t    opcode = 0;
    unsigned    orig_offset = offset;

    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_list, tvb, offset, 1, ENC_BIG_ENDIAN);
    opcode_item = proto_tree_add_item_ret_uint(ses_tree, hf_uet_ses_rsp_opcode, tvb, offset, 1, ENC_BIG_ENDIAN, &opcode);
    offset += 1;

    if (opcode != UET_SES_RSP_RESPONSE_W_DATA) {
        expert_add_info_format(pinfo, opcode_item, &ei_uet_ses_rsp_opcode_invalid,
            "Invalid opcode %d for ses resp data small, expected %d", (int)opcode, UET_SES_RSP_RESPONSE_W_DATA);
        return (offset - orig_offset);
    }
    proto_item_append_text(ses_item, ", Type: %s", val_to_str(pinfo->pool, (uint32_t) opcode, uet_ses_rsp_opcode_vals, "Unknown (%u)"));

    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_return_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_reserved3, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(ses_tree, hf_uet_ses_rsp_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return (offset - orig_offset);
}

static int
dissect_ses(tvbuff_t* tvb, packet_info* pinfo, proto_tree* uet_tree, proto_item* uet_item, int offset, uint8_t pds_next_hdr)
{
    proto_tree  *ses_tree = NULL;
    proto_item  *ses_item = NULL;
    int         orig_offset = offset;

    /* proto_tree_add_item() with length -1 will throw an exception if at the end of the buffer. */
    if (pds_next_hdr == UET_PDS_NH_NONE) {
        return offset - orig_offset;
    }

    proto_item_append_text(uet_item, ", SES: %s", val_to_str(pinfo->pool, pds_next_hdr, uet_pds_nh_type_vals_for_tree, "Unknown (%u)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, ", SES_%s", val_to_str(pinfo->pool, pds_next_hdr, uet_pds_nh_type_vals_for_info, "Unknown (%u)"));

    ses_item = proto_tree_add_item(uet_tree, hf_uet_ses_prlg, tvb, offset, -1, ENC_NA);
    proto_item_set_text(ses_item, "%s", "SES");
    ses_tree = proto_item_add_subtree(ses_item, ett_uet_ses_proto);

    proto_item_append_text(ses_item, ": %s", val_to_str(pinfo->pool, pds_next_hdr, uet_pds_nh_type_vals_for_tree, "Unknown (%u)"));

    /* 4.3.6 Header Parsing Guide */
    switch (pds_next_hdr) {
    case UET_PDS_NH_REQ_SMALL:
        //The semantic header following the PDS header
        //is the one illustrated in Figure 10.
        offset += dissect_ses_small_req(ses_tree, ses_item, tvb, pinfo, offset);
        break;
    case UET_PDS_NH_REQ_MEDIUM:
        //The semantic header following the PDS header
        //is the one illustrated in Figure 11.
        offset += dissect_ses_medium_req(ses_tree, ses_item, tvb, pinfo, offset);
        break;
    case UET_PDS_NH_REQ_STD:
        offset += dissect_ses_std_req(ses_tree, ses_item, tvb, pinfo, offset);
        break;
    case UET_PDS_NH_RSP:
        //The semantic header following the PDS header
        //is the one illustrated in Figure 15.
        //
        //UET_RESPONSE
        //UET_DEFAULT_RESPONSE
        //UET_NO_RESPONSE
        //Figure 15
        offset += dissect_ses_resp(ses_tree, ses_item, tvb, pinfo, offset);
        break;
    case UET_PDS_NH_RSP_DATA:
        //The semantic header following the PDS header
        //is the one illustrated in Figure 16.
        //UET_RESPONSE_W_DATA Figure 1 - 16
        offset += dissect_ses_resp_data(ses_tree, ses_item, tvb, pinfo, offset);
        break;
    case UET_PDS_NH_RSP_DATA_SMALL:
        //The semantic header following the PDS header
        //is the one illustrated in Figure 17..
        //UET_RESPONSE_W_DATA Figure 1-17
        offset += dissect_ses_resp_data_small(ses_tree, ses_item, tvb, pinfo, offset);
        break;
    default:
        break;
    }

    proto_item_set_len(ses_item, offset - orig_offset);
    return (offset - orig_offset);
}

static int
dissect_pds_rud_rod_req(tvbuff_t* tvb, packet_info* pinfo, proto_tree* pds_tree, proto_item* pds_item, int offset, uint8_t flags, uint8_t type)
{
    proto_tree* mode_tree = NULL;
    proto_item* mode_item = NULL;
    int         orig_offset = offset;
    int         len = tvb_reported_length_remaining(tvb, offset) + 2; // including prologue
    int32_t     clear_psn_offset;
    uint32_t    clear_psn;
    uint32_t    psn;

    if (len < UET_PDS_RUD_ROD_MIN_HDR_LEN) {
        expert_add_info_format(pinfo, pds_item, &ei_uet_pds_rud_rod_hdr_len_invalid, "PDS RUD/ROD header must be at least %d bytes",
            UET_PDS_RUD_ROD_MIN_HDR_LEN);
    }

    clear_psn_offset = tvb_get_ntohis(tvb, offset);
    psn = tvb_get_ntohl(tvb, offset + 2);
    clear_psn = psn + clear_psn_offset;
    proto_tree_add_uint_format_value(pds_tree, hf_uet_pds_clear_psn, tvb, offset, 2, clear_psn, "%u (%+d)", clear_psn, clear_psn_offset);
    offset += 2;
    proto_tree_add_item(pds_tree, hf_uet_pds_psn, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(pds_tree, hf_uet_pds_spdcid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (flags & UET_PDS_RUD_ROD_FLAGS_SYN) {
        uint32_t psn_offset;
        uint32_t start_psn;
        proto_item *item;

        mode_item = proto_tree_add_item(pds_tree, hf_uet_pds_pdc_mode, tvb, offset, 1, ENC_NA);
        proto_item_set_text(mode_item, "%s", "PDC Mode");
        mode_tree = proto_item_add_subtree(mode_item, ett_uet_pds_pdc_mode);
        proto_tree_add_item(mode_tree, hf_uet_pds_pdc_mode_use_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(mode_tree, hf_uet_pds_pdc_mode_rsv, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item_ret_uint(pds_tree, hf_uet_pds_psn_offset, tvb, offset, 2, ENC_BIG_ENDIAN, &psn_offset);
        start_psn = psn - psn_offset;
        item = proto_tree_add_uint(pds_tree, hf_uet_pds_start_psn, tvb, offset, 2, start_psn);
        proto_item_set_generated(item);
    } else {
        proto_tree_add_item(pds_tree, hf_uet_pds_dpdcid, tvb, offset, 2, ENC_BIG_ENDIAN);
    }
    offset += 2;

    if ((type == UET_PDS_TYPE_RUD_CC_REQ) || (type == UET_PDS_TYPE_ROD_CC_REQ)) {
        if (len < UET_PDS_RUD_ROD_CC_MIN_HDR_LEN) {
            expert_add_info_format(pinfo, pds_item, &ei_uet_pds_rud_rod_hdr_len_invalid, "PDS RUD/ROD CC header must be at least %d bytes",
                UET_PDS_RUD_ROD_CC_MIN_HDR_LEN);
        }

        proto_tree_add_item(pds_tree, hf_uet_pds_req_cc_state_ccc_id, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(pds_tree, hf_uet_pds_req_cc_state_credit_target, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
    }

    return (offset - orig_offset);
}

static int
dissect_pds_rudi_req_rsp(tvbuff_t* tvb, proto_tree* pds_tree, int offset)
{
    int         orig_offset = offset;

    proto_tree_add_item(pds_tree, hf_uet_pds_rudi_pkt_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return (offset - orig_offset);
}

static int
dissect_pds_ctl(tvbuff_t* tvb, packet_info *pinfo, proto_tree* pds_tree, int offset, uint8_t ctl_type)
{
    proto_item* ctl_pi = NULL;
    int         orig_offset = offset;

    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str(pinfo->pool, ctl_type, uet_pds_ctl_type_vals, "Unknown (%u)"));

    proto_tree_add_item(pds_tree, hf_uet_pds_ctl_probe_opaque, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(pds_tree, hf_uet_pds_psn, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(pds_tree, hf_uet_pds_spdcid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(pds_tree, hf_uet_pds_dpdcid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    ctl_pi = proto_tree_add_item(pds_tree, hf_uet_pds_ctl_payload, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_item_append_text(ctl_pi, " (%s)", val_to_str(pinfo->pool, ctl_type, pds_ctl_type_func_vals, "Unknown (%u)"));

    return (offset - orig_offset);
}

static int
dissect_pds_ack_ext_hdr(tvbuff_t* tvb, packet_info* pinfo, proto_tree* pds_tree, int offset, uint8_t type)
{
    proto_tree* ext_tree = NULL;
    proto_item* ext_item = NULL;
    proto_tree* cc_state_tree = NULL;
    proto_item* cc_state_item = NULL;
    int         orig_offset = offset;
    uint8_t     cc_type = 0;

    if (tvb_reported_length_remaining(tvb, offset) < UET_PDS_ACK_EXT_HDR_SIZE) {
        proto_tree_add_expert_format(pds_tree, pinfo, &ei_uet_pds_ack_ext_hdr_len_invalid, tvb, offset, 1,
            "Available length %d is less than PDS Ack Ext Hdr length (%d)",
            tvb_reported_length_remaining(tvb, offset), UET_PDS_ACK_EXT_HDR_SIZE);
        return (offset - orig_offset);
    }

    ext_item = proto_tree_add_item(pds_tree, hf_uet_pds_ack_prlg, tvb, offset, UET_PDS_ACK_EXT_HDR_SIZE, ENC_NA);
    proto_item_set_text(ext_item, "%s", "ROD/RUD ACK Extension Header");
    ext_tree = proto_item_add_subtree(ext_item, ett_uet_pds_ack_cc_flags);
    cc_type = tvb_get_bits8(tvb, offset * 8, 4);
    proto_tree_add_item(ext_tree, hf_uet_pds_ack_cc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ext_tree, hf_uet_pds_ack_mpr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(ext_tree, hf_uet_pds_ack_sack_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(ext_tree, hf_uet_pds_ack_sack_bitmap, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    if (type == UET_PDS_TYPE_ACK_CC) {
        cc_state_item = proto_tree_add_item(ext_tree, hf_uet_pds_ack_cc_state, tvb, offset, 8, ENC_NA);
        if (cc_type == UET_PDS_CC_NSCC) {
            proto_item_set_text(cc_state_item, "ACK CC State: %s", "NSCC");
            cc_state_tree = proto_item_add_subtree(cc_state_item, ett_uet_pds_ack_cc_state);
            proto_tree_add_item(cc_state_tree, hf_uet_pds_ack_cc_state_service_time, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(cc_state_tree, hf_uet_pds_ack_cc_state_rc, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(cc_state_tree, hf_uet_pds_ack_cc_state_rcv_cwnd_pend, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(cc_state_tree, hf_uet_pds_ack_cc_state_rcvd_bytes, tvb, offset + 3, 3, ENC_BIG_ENDIAN);
            proto_tree_add_item(cc_state_tree, hf_uet_pds_ack_cc_state_ooo_count, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
        } else if (cc_type == UET_PDS_CC_CREDIT) {
            proto_item_set_text(cc_state_item, "ACK CC State: %s", "Credit");
            cc_state_tree = proto_item_add_subtree(cc_state_item, ett_uet_pds_ack_cc_state);
            proto_tree_add_item(cc_state_tree, hf_uet_pds_ack_cc_state_credit, tvb, offset, 3, ENC_BIG_ENDIAN);
            proto_tree_add_item(cc_state_tree, hf_uet_pds_ack_cc_state_reserved, tvb, offset + 3, 3, ENC_NA);
            proto_tree_add_item(cc_state_tree, hf_uet_pds_ack_cc_state_ooo_count, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
        }
        offset += 8;
    } else {
        // type == UET_PDS_TYPE_ACK_CCX
        proto_tree_add_item(ext_tree, hf_uet_pds_ack_ccx_state, tvb, offset, 16, ENC_NA);
        offset += 16;
    }

    return (offset - orig_offset);
}

static int
dissect_pds_ack(tvbuff_t* tvb, packet_info* pinfo, proto_tree* pds_tree, int offset, uint8_t type)
{
    int         orig_offset = offset;
    int32_t     ack_psn_offset;
    uint32_t    ack_psn;
    uint32_t    cack_psn;

    ack_psn_offset = tvb_get_ntohis(tvb, offset);
    cack_psn = tvb_get_ntohl(tvb, offset + 2);
    ack_psn = cack_psn + ack_psn_offset;
    proto_tree_add_uint_format_value(pds_tree, hf_uet_pds_ack_psn, tvb, offset, 2, ack_psn, "%u (%+d)", ack_psn, ack_psn_offset);
    offset += 2;
    proto_tree_add_item(pds_tree, hf_uet_pds_cack_psn, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(pds_tree, hf_uet_pds_spdcid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(pds_tree, hf_uet_pds_dpdcid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if ((type == UET_PDS_TYPE_ACK_CC) || (type == UET_PDS_TYPE_ACK_CCX)) {
        //ext hdr
        offset += dissect_pds_ack_ext_hdr(tvb, pinfo, pds_tree, offset, type);
    }

    return (offset - orig_offset);
}

static int
dissect_pds_nack(tvbuff_t* tvb, packet_info* pinfo, proto_tree* pds_tree, int offset, uint8_t type)
{
    int         orig_offset = offset;
    uint8_t     nack_code;

    nack_code = tvb_get_uint8(tvb, offset);
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str(pinfo->pool, nack_code, uet_pds_nack_code_vals, "Unknown (%u)"));

    proto_tree_add_item(pds_tree, hf_uet_pds_nack_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(pds_tree, hf_uet_pds_nack_vendor_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(pds_tree, hf_uet_pds_nack_psn, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(pds_tree, hf_uet_pds_spdcid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(pds_tree, hf_uet_pds_dpdcid, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(pds_tree, hf_uet_pds_nack_max_recv_psn, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    if (type == UET_PDS_TYPE_NACK_CCX) {
        // TODO: Decode NACK CCX state.
        offset += 16;
    }

    return (offset - orig_offset);
}

static int
dissect_pds_flags(proto_tree* pds_tree, tvbuff_t* tvb, int offset, uint8_t type)
{
    switch (type) {
        case UET_PDS_TYPE_RESERVED:
            break;
        case UET_PDS_TYPE_RUD_REQ:
        case UET_PDS_TYPE_ROD_REQ:
        case UET_PDS_TYPE_RUD_CC_REQ:
        case UET_PDS_TYPE_ROD_CC_REQ:
        {
            static int * const fields[] = {
                &hf_uet_pds_flags_retx,
                &hf_uet_pds_flags_ar,
                &hf_uet_pds_flags_syn,
                &hf_uet_pds_flags_rsvd_rud_rod,
                NULL,
            };
            proto_tree_add_bitmask(pds_tree, tvb, offset, hf_uet_pds_flags, ett_uet_pds_flags, fields, ENC_BIG_ENDIAN);
            break;
        }
        case UET_PDS_TYPE_RUDI_REQ:
        case UET_PDS_TYPE_RUDI_RESP:
            proto_tree_add_item(pds_tree, hf_uet_pds_flags_rsvd_rudi, tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
        case UET_PDS_TYPE_UUD_REQ:
            proto_tree_add_item(pds_tree, hf_uet_pds_flags_rsvd_uud, tvb, offset, 2, ENC_BIG_ENDIAN);
            break;
        case UET_PDS_TYPE_ACK:
        case UET_PDS_TYPE_ACK_CC:
        case UET_PDS_TYPE_ACK_CCX:
        {
            static int * const fields[] = {
                &hf_uet_pds_flags_m,
                &hf_uet_pds_flags_retx,
                &hf_uet_pds_flags_p,
                &hf_uet_pds_flags_req,
                &hf_uet_pds_flags_rsvd_ack,
                NULL,
            };
            proto_tree_add_bitmask(pds_tree, tvb, offset, hf_uet_pds_flags, ett_uet_pds_flags, fields, ENC_BIG_ENDIAN);
            break;
        }
        case UET_PDS_TYPE_NACK:
        case UET_PDS_TYPE_NACK_CCX:
        {
            static int * const fields[] = {
                &hf_uet_pds_flags_m,
                &hf_uet_pds_flags_retx,
                &hf_uet_pds_flags_nt,
                &hf_uet_pds_flags_rsvd_nack,
                NULL,
            };
            proto_tree_add_bitmask(pds_tree, tvb, offset, hf_uet_pds_flags, ett_uet_pds_flags, fields, ENC_BIG_ENDIAN);
            break;
        }
        case UET_PDS_TYPE_CTRL:
        {
            static int * const fields[] = {
                &hf_uet_pds_flags_retx,
                &hf_uet_pds_flags_ar,
                &hf_uet_pds_flags_syn,
                &hf_uet_pds_flags_rsvd_ctl,
                NULL,
            };
            proto_tree_add_bitmask(pds_tree, tvb, offset, hf_uet_pds_flags, ett_uet_pds_flags, fields, ENC_BIG_ENDIAN);
            break;
        }
    };

    return 0;
}

static int
dissect_pds(tvbuff_t* tvb, packet_info* pinfo, proto_tree* uet_tree, proto_item* uet_item, int offset)
{
    proto_tree  *pds_tree = NULL;
    proto_item  *pds_item = NULL;
    uint16_t    type_nh_ctl_flags = 0;
    uint8_t     type = 0;
    uint8_t     flags = 0;
    uint8_t     nh_ctl_type = 0;
    int         orig_offset = offset, ses_len = 0;

    col_append_sep_str(pinfo->cinfo, COL_INFO, "", "PDS");

    pds_item = proto_tree_add_item(uet_tree, hf_uet_pds_prlg, tvb, offset, -1, ENC_NA);
    proto_item_set_text(pds_item, "%s", "PDS");
    pds_tree = proto_item_add_subtree(pds_item, ett_uet_pds_proto);

    /* Validate header size (4 bytes) */
    if (tvb_reported_length_remaining(tvb, offset) < UET_COMMON_HDR_SIZE) {
        expert_add_info_format(pinfo, pds_item, &ei_uet_pds_hdr_len_invalid, "PDS header must be at least 4 bytes");
        return (offset - orig_offset);
    }

    type_nh_ctl_flags = tvb_get_bits16(tvb, offset * 8, 16, ENC_BIG_ENDIAN);

    type = type_nh_ctl_flags >> 11;
    nh_ctl_type = (type_nh_ctl_flags >> 7) & 0xF;
    flags = type_nh_ctl_flags & 0x7F;

    proto_tree_add_item(pds_tree, hf_uet_pds_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (type == UET_PDS_TYPE_CTRL) {
        proto_tree_add_item(pds_tree, hf_uet_pds_ctl_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(pds_tree, hf_uet_pds_nh, tvb, offset, 2, ENC_BIG_ENDIAN);
    }

    dissect_pds_flags(pds_tree, tvb, offset, type);
    offset += 2;

    proto_item_append_text(uet_item, ", PDS: %s", val_to_str(pinfo->pool, type, uet_pds_opcode_type_vals, "Unknown (%u)"));
    proto_item_append_text(pds_item, ": %s", val_to_str(pinfo->pool, type, uet_pds_opcode_type_vals, "Unknown (%u)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, "_%s", val_to_str(pinfo->pool, type, uet_pds_opcode_type_vals_for_info, "Unknown (%u)"));

    switch (type) {
    case UET_PDS_TYPE_RESERVED:
        break;
    case UET_PDS_TYPE_RUD_REQ:
    case UET_PDS_TYPE_ROD_REQ:
    case UET_PDS_TYPE_RUD_CC_REQ:
    case UET_PDS_TYPE_ROD_CC_REQ:
    {
        offset += dissect_pds_rud_rod_req(tvb, pinfo, pds_tree, pds_item, offset, flags, type);

        //dissect SES layer
        ses_len = dissect_ses(tvb, pinfo, uet_tree, uet_item, offset, nh_ctl_type);
        break;
    }
    case UET_PDS_TYPE_RUDI_REQ:
    case UET_PDS_TYPE_RUDI_RESP:
        offset += dissect_pds_rudi_req_rsp(tvb, pds_tree, offset);

        //dissect SES layer
        ses_len = dissect_ses(tvb, pinfo, uet_tree, uet_item, offset, nh_ctl_type);
        break;
    case UET_PDS_TYPE_UUD_REQ:
        //no hdr, 2 bytes reserved
        offset += 2;

        //dissect SES layer
        ses_len = dissect_ses(tvb, pinfo, uet_tree, uet_item, offset, nh_ctl_type);
        break;
    case UET_PDS_TYPE_ACK:
    case UET_PDS_TYPE_ACK_CC:
    case UET_PDS_TYPE_ACK_CCX:
        offset += dissect_pds_ack(tvb, pinfo, pds_tree, offset, type);

        //dissect SES layer
        ses_len = dissect_ses(tvb, pinfo, uet_tree, uet_item, offset, nh_ctl_type);
        break;
    case UET_PDS_TYPE_NACK:
    case UET_PDS_TYPE_NACK_CCX:
        offset += dissect_pds_nack(tvb, pinfo, pds_tree, offset, type);

        //dissect SES layer
        ses_len = dissect_ses(tvb, pinfo, uet_tree, uet_item, offset, nh_ctl_type);
        break;
    case UET_PDS_TYPE_CTRL:
        offset += dissect_pds_ctl(tvb, pinfo, pds_tree, offset, nh_ctl_type);
        break;
    };
    proto_item_set_len(pds_item, offset - orig_offset);

    return (offset - orig_offset + ses_len);
}

static int
dissect_tss(tvbuff_t* tvb, packet_info* pinfo, proto_tree* uet_tree, proto_item* uet_item)
{
    proto_tree* tss_tree;
    proto_item* tss_item;
    int         offset = 0;
    uint8_t     type = 0;

    col_append_sep_str(pinfo->cinfo, COL_INFO, "", "TSS");

    tss_item = proto_tree_add_item(uet_tree, hf_uet_tss_prlg, tvb, offset, -1, ENC_NA);
    proto_item_set_text(tss_item, "%s", "TSS");
    tss_tree = proto_item_add_subtree(tss_item, ett_uet_tss_auth_proto);

    if (tvb_reported_length_remaining(tvb, offset) < UET_TSS_HDR_LEN) {
        expert_add_info_format(pinfo, tss_item, &ei_uet_tss_hdr_len_invalid, "TSS header must be %d bytes",
            UET_TSS_HDR_LEN);
    }

    type = tvb_get_bits8(tvb, offset * 8, 4);

    proto_tree_add_item(tss_tree, hf_uet_tss_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tss_tree, hf_uet_tss_nh, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tss_tree, hf_uet_tss_ver, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tss_tree, hf_uet_tss_sp, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tss_tree, hf_uet_tss_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_append_text(uet_item, ", TSS Type: %s", val_to_str(pinfo->pool, type, uet_tss_type_vals, "Unknown (%u)"));
    proto_item_append_text(tss_item, ", Type: %s", val_to_str(pinfo->pool, type, uet_tss_type_vals, "Unknown (%u)"));
    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", val_to_str(pinfo->pool, type, uet_tss_type_vals, "Unknown (%u)"));

    proto_tree_add_item(tss_tree, hf_uet_tss_an, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tss_tree, hf_uet_tss_sdi, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tss_tree, hf_uet_tss_ssi, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tss_tree, hf_uet_tss_tsc, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    //update length
    proto_item_set_len(tss_item, offset);

    //PDS is always the next layer of TSS layer
    dissect_pds(tvb, pinfo, uet_tree, uet_item, offset);

    return tvb_captured_length(tvb);
}

static int
dissect_uet_common(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, bool has_entropy)
{
    proto_tree* uet_tree = NULL;
    proto_item* uet_item = NULL;
    uint8_t     type = 0;
    int         offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UET");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Top Level Packet */
    uet_item = proto_tree_add_item(tree, proto_uet, tvb, offset, -1, ENC_NA);
    uet_tree = proto_item_add_subtree(uet_item, ett_all_layers);

    if (has_entropy) {
        proto_tree_add_item(uet_tree, hf_uet_pds_entropy, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(uet_tree, hf_uet_pds_entropy_rsvd, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    type = tvb_get_bits8(tvb, (offset * 8), 5);

    if (type == UET_TYPE_ENC) {
        offset += dissect_tss(tvb, pinfo, uet_tree, uet_item);
    } else {
        //PDS
        offset += dissect_pds(tvb, pinfo, uet_tree, uet_item, offset);
    }

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        //dump data
        call_data_dissector(tvb_new_subset_remaining(tvb, offset), pinfo, uet_tree);
    }

    return tvb_captured_length(tvb);
}

static int
dissect_uet(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    return dissect_uet_common(tvb, pinfo, tree, false);
}

static int
dissect_uet_entropy(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    return dissect_uet_common(tvb, pinfo, tree, true);
}

void
proto_register_uet(void)
{
    static hf_register_info hf_uet[] = {
        //TSS
        { &hf_uet_tss_prlg, {
            "TSS", "uet.tss",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_uet_tss_type,
            { "Type", "uet.tss.type",
                FT_UINT16, BASE_DEC | BASE_EXT_STRING, &uet_tss_type_vals_ext, 0xf000,
                NULL, HFILL }
        },
        { &hf_uet_tss_nh,
            { "Next Hdr", "uet.tss.nh",
                FT_UINT16, BASE_DEC, NULL, 0x0f80,
                NULL, HFILL }
        },
        { &hf_uet_tss_ver,
            { "Ver", "uet.tss.ver",
                FT_UINT16, BASE_DEC, NULL, 0x0060,
                NULL, HFILL }
        },
        { &hf_uet_tss_sp,
            { "SP", "uet.tss.sp",
                FT_UINT16, BASE_DEC, NULL, 0x0010,
                NULL, HFILL }
        },
        { &hf_uet_tss_reserved,
            { "Reserved", "uet.tss.reserved",
                FT_UINT16, BASE_HEX, NULL, 0x000f,
                NULL, HFILL }
        },

        { &hf_uet_tss_an,
            { "AN", "uet.tss.an",
                FT_UINT32, BASE_DEC, NULL, 0x80000000,
                NULL, HFILL }
        },
        { &hf_uet_tss_sdi,
            { "SDI", "uet.tss.sdi",
                FT_UINT32, BASE_DEC, NULL, 0x7FFFFFFF,
                NULL, HFILL }
        },
        { &hf_uet_tss_ssi,
            { "SSI", "uet.tss.ssi",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_tss_tsc,
            { "TSC", "uet.tss.tsc",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },

        //PDS
        { &hf_uet_pds_entropy,
            { "Entropy", "uet.pds.entropy",
                FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_entropy_rsvd,
            { "Reserved (entropy)", "uet.pds.entropy.rsvd",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_prlg, {
            "PDS Layer", "uet.pds",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        { &hf_uet_pds_type,
            { "Type", "uet.pds.type",
                FT_UINT16, BASE_DEC | BASE_EXT_STRING, &uet_pds_opcode_vals_ext, 0xf800,
                NULL, HFILL }
        },
        { &hf_uet_pds_nh,
            { "Next Hdr", "uet.pds.nh",
                FT_UINT16, BASE_DEC | BASE_EXT_STRING, &uet_pds_nh_vals_ext, 0x0780,
                NULL, HFILL }
        },
        { &hf_uet_pds_ctl_type,
            { "Ctl Type", "uet.pds.ctl_type",
                FT_UINT16, BASE_DEC | BASE_EXT_STRING, &uet_pds_ctl_type_vals_ext, 0x0780,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags,
            { "Flags", "uet.pds.flags",
                FT_UINT16, BASE_HEX, NULL, 0x007f,
                "Flags(7 bits)", HFILL}
        },
        { &hf_uet_pds_flags_m,
            { "ECN Marked (M)", "uet.pds.flags.m",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_retx,
            { "Retransmitted (RETX)", "uet.pds.flags.retx",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x10,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_ar,
            { "ACK Request (AR)", "uet.pds.flags.ar",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_p,
            { "Probe Packet (P)", "uet.pds.flags.p",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x08,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_nt,
            { "NACK Type (NT)", "uet.pds.flags.nt",
                FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x08,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_syn,
            { "New PDC (SYN)", "uet.pds.flags.syn",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_req,
            { "Request (REQ)", "uet.pds.flags.req",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_pds_flags_ack_req_vals_ext, 0x6,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_rsvd_rud_rod,
            { "Reserved", "uet.pds.flags.rsvd_rud_rod",
                FT_UINT8, BASE_HEX, NULL, 0x63,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_rsvd_uud,
            { "Reserved", "uet.pds.flags.rsvd_uud",
                FT_UINT16, BASE_HEX, NULL, 0x003F,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_rsvd_ctl,
            { "Reserved", "uet.pds.flags.rsvd_ctl",
                FT_UINT8, BASE_HEX, NULL, 0x63,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_rsvd_ack,
            { "Reserved", "uet.pds.flags.rsvd_ack",
                FT_UINT8, BASE_HEX, NULL, 0x41,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_rsvd_rudi,
            { "Reserved", "uet.pds.flags.rsvd_rudi",
                FT_UINT16, BASE_HEX, NULL, 0x004F,
                NULL, HFILL }
        },
        { &hf_uet_pds_flags_rsvd_nack,
            { "Reserved", "uet.pds.flags.rsvd_nack",
                FT_UINT8, BASE_HEX, NULL, 0x47,
                NULL, HFILL }
        },
        { &hf_uet_pds_clear_psn,
            { "Clear PSN", "uet.pds.clear_psn",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_psn,
            { "PSN", "uet.pds.psn",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_psn,
            { "ACK PSN", "uet.pds.ack_psn",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_cack_psn,
            { "Cumulative ACK PSN", "uet.pds.cack_psn",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_spdcid,
            { "Source PDC ID", "uet.pds.spdcid",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_dpdcid,
            { "Destination PDC ID", "uet.pds.dpdcid",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_nack_psn,
            { "NACK PSN", "uet.pds.nack.psn",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_nack_code,
            { "NACK Code", "uet.pds.nack.code",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_pds_nack_code_vals_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_nack_vendor_code,
            { "Vendor Code", "uet.pds.nack.vendor_code",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_nack_max_recv_psn,
            { "Payload (Max Recvd PSN + 1)", "uet.pds.nack.max_recv_psn_plus_1",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_pdc_mode,
            { "PDC Mode", "uet.pds.pdc_mode",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_pdc_mode_use_rsv,
            { "Use Reserved PDC", "uet.pds.pdc_mode_use_rsv",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
                NULL, HFILL }
        },
        { &hf_uet_pds_pdc_mode_rsv,
            { "Reserved", "uet.pds.pdc_mode_rsv",
                FT_UINT8, BASE_HEX, NULL, 0x70,
                NULL, HFILL }
        },
        { &hf_uet_pds_psn_offset,
            { "PSN offset", "uet.pds.psn_offset",
                FT_UINT16, BASE_DEC, NULL, 0x0fff,
                NULL, HFILL }
        },
        { &hf_uet_pds_start_psn,
            { "Start PSN", "uet.pds.start_psn",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_req_cc_state_ccc_id,
            { "CCC ID", "uet.pds.cc_state.ccc_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_req_cc_state_credit_target,
            { "Credit Target", "uet.pds.cc_state.credit_target",
                FT_UINT24, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ctl_probe_opaque,
            { "Probe Opaque", "uet.pds.ctrl_probe_opaque",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ctl_payload,
            { "Payload", "uet.pds.ctrl_payload",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_prlg,
            { "ACK Ext Hdr", "uet.pds.ack.prlg",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_cc_type,
            { "CC Type", "uet.pds.ack.cc_type",
                FT_UINT8, BASE_DEC, NULL, 0xf0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_mpr,
            { "Maximum PSN range (MPR)", "uet.pds.ack.mpr",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_sack_offset,
            { "SACK Offset", "uet.pds.ack.sack_offset",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_cc_state,
            { "CC State", "uet.pds.ack.cc_state",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_ccx_state,
            { "CCX State", "uet.pds.ack.ccx_state",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_sack_bitmap,
            { "SACK BITMAP", "uet.pds.ack.sack_bitmap",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_cc_state_service_time,
            { "Service Time", "uet.pds.ack.cc_state.service_time",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_cc_state_rc,
            { "Restore Cwnd", "uet.pds.ack.cc_state.rc",
                FT_BOOLEAN, 8, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_cc_state_rcv_cwnd_pend,
            { "Cwnd Penalty", "uet.pds.ack.cc_state.rcv_cwnd_pend",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_cc_state_credit,
            { "Credit", "uet.pds.ack.cc_state.credit",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_cc_state_rcvd_bytes,
            { "Received Byte Count", "uet.pds.ack.cc_state.rcvd_bytes",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_cc_state_reserved,
            { "Reserved", "uet.pds.ack.cc_state.reserved",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_ack_cc_state_ooo_count,
            { "Out Of Order Count", "uet.pds.ack.cc_state.ooo_count",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_pds_rudi_pkt_id,
            { "RUDI ID", "uet.pds.rudi.pkt_id",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },

        //UET SES
        { &hf_uet_ses_prlg,
            {"SES", "uet.ses",
                FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        //UET SES STD
        { &hf_uet_ses_std_flags,
            { "Flags", "uet.ses.std.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_rsv,
            { "Reserved(R)", "uet.ses.std.rsv",
                FT_UINT8, BASE_HEX, NULL, 0xc0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_opcode,
            { "Opcode", "uet.ses.std.opcode",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_ses_opcode_vals_ext, 0x3f,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_ver,
            { "Version", "uet.ses.std.ver",
                FT_UINT8, BASE_DEC, NULL, 0xC0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_dc,
            { "Delivery Complete (DC)", "uet.ses.std.dc",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_DC,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_ie,
            { "Initiator Error (IE)", "uet.ses.std.ie",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_IE,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_rel,
            { "Relative", "uet.ses.std.rel",
                FT_BOOLEAN, 8, TFS(&uet_ses_std_rel_str), UET_SES_REQ_FLAGS_REL,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_hd,
            { "Header Data", "uet.ses.std.hd",
                FT_BOOLEAN, 8, TFS(&tfs_present_not_present), UET_SES_REQ_FLAGS_HD,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_eom,
            { "End of Msg(EOM)", "uet.ses.std.eom",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_EOM,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_som,
            { "Start of Msg(SOM)", "uet.ses.std.som",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_SOM,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_message_id,
            { "Message ID", "uet.ses.std.message_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_index_generation,
            { "Index Generation", "uet.ses.std.index_generation",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_job_id,
            { "Job ID", "uet.ses.std.job_id",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_reserved2,
            { "Reserved", "uet.ses.std.reserved2",
                FT_UINT16, BASE_HEX, NULL, 0xf000,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_pidonfep,
            { "PIDonFEP", "uet.ses.std.pidonfep",
                FT_UINT16, BASE_DEC, NULL, 0x0fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_reserved3,
            { "Reserved", "uet.ses.std.reserved3",
                FT_UINT16, BASE_HEX, NULL, 0xf000,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_resource_index,
            { "Resource Index (RI)", "uet.ses.std.resource_index",
                FT_UINT16, BASE_DEC, NULL, 0x0fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_buffer_offset,
            { "Buffer Offset", "uet.ses.std.buffer_offset",
                FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_restart_token,
            { "Restart Token", "uet.ses.std.restart_token",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_uet_ses_std_initiator,
            { "Initiator", "uet.ses.std.initiator",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_mem_key_match_bits,
            { "Memory Key/Match Bits", "uet.ses.std.mem_key_match_bits",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_header_data,
            { "Header Data", "uet.ses.std.header_data",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_reserved4,
            { "Reserved", "uet.ses.std.reserved4",
                FT_UINT32, BASE_HEX, NULL, 0xffffc000,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_payload_length,
            { "Payload Length", "uet.ses.std.payload_length",
                FT_UINT32, BASE_DEC, NULL, 0x3fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_message_offset,
            { "Message Offset", "uet.ses.std.message_offset",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_std_request_length,
            { "Request Length", "uet.ses.std.request_length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },

        //Atomic Operation Extension Header
        { &hf_uet_ses_atomic_op_ext_hdr,
            { "Atomic Operation Extension Header", "uet.ses.atomic_op_ext_hdr",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_atomic_op_ext_hdr_atomic_opcode,
            { "Atomic Opcode", "uet.ses.atomic_op_ext_hdr.atomic_opcode",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_ses_atomic_op_ext_hdr_atomic_opcode_vals_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_atomic_op_ext_hdr_atomic_data_type,
            { "Atomic Data type", "uet.ses.atomic_op_ext_hdr.atomic_data_type",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_ses_atomic_op_ext_hdr_atomic_data_type_vals_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_atomic_op_ext_hdr_sem_ctl,
            { "Semantic Control", "uet.ses.atomic_op_ext_hdr.sem_ctl",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_ses_atomic_op_ext_hdr_sem_ctl_vals_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_atomic_op_ext_hdr_rsvd,
            { "Rsvd", "uet.ses.atomic_op_ext_hdr.rsvd",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },

        //Rendezvous Extension Header
        { &hf_uet_ses_rendv_ext_hdr,
            { "Rendezvous Extension Header", "uet.ses.rendv_ext_hdr",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rendv_ext_hdr_eager_length,
            { "Eager Length", "uet.ses.rendv_ext_hdr.eager_length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rendv_ext_hdr_reserved,
            { "Reserved", "uet.ses.rendv_ext_hdr.reserved",
                FT_UINT16, BASE_HEX, NULL, 0xc000,
                NULL, HFILL }
        },
        { &hf_uet_ses_rendv_ext_hdr_read_pid_on_fep,
            { "Read PIDonFEP", "uet.ses.rendv_ext_hdr.read_pid_on_fep",
                FT_UINT16, BASE_DEC, NULL, 0x3fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_rendv_ext_hdr_reserved2,
            { "Reserved", "uet.ses.rendv_ext_hdr.reserved2",
                FT_UINT16, BASE_HEX, NULL, 0xf000,
                NULL, HFILL }
        },
        { &hf_uet_ses_rendv_ext_hdr_read_resource_index,
            { "Read Resource Index", "uet.ses.rendv_ext_hdr.read_resource_index",
                FT_UINT16, BASE_DEC, NULL, 0x0fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_rendv_ext_hdr_read_offset,
            { "Read Offset", "uet.ses.rendv_ext_hdr.read_offset",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rendv_ext_hdr_read_match_bits,
            { "Read Match Bits", "uet.ses.rendv_ext_hdr.read_match_bits",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },

        //Compare and Swap Operation Atomic Header
        { &hf_uet_ses_comp_swap_ext_hdr,
            { "Compare and Swap Operation Atomic Header", "uet.ses.comp_swap_ext_hdr",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_comp_swap_ext_hdr_atomic_opcode,
            { "Atomic Opcode", "uet.ses.comp_swap_ext_hdr.atomic_opcode",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_ses_atomic_op_ext_hdr_atomic_opcode_vals_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_comp_swap_ext_hdr_atomic_data_type,
            { "Atomic Data type", "uet.ses.comp_swap_ext_hdr.atomic_data_type",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_ses_comp_swap_ext_hdr_atomic_data_type_vals_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_comp_swap_ext_hdr_sem_ctl,
            { "Semantic Control", "uet.ses.comp_swap_ext_hdr.sem_ctl",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_ses_comp_swap_ext_hdr_sem_ctl_vals_ext, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_comp_swap_ext_hdr_rsvd,
            { "Rsvd", "uet.ses.comp_swap_ext_hdr.rsvd",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_comp_swap_ext_hdr_comp_value,
            { "Compare Value", "uet.ses.comp_swap_ext_hdr.comp_value",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_comp_swap_ext_hdr_swap_value,
            { "Swap Value", "uet.ses.comp_swap_ext_hdr.swap_value",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_list,
            { "List", "uet.ses.rsp.list",
                FT_UINT8, BASE_DEC, NULL, 0xc0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_opcode,
            { "Opcode", "uet.ses.rsp.opcode",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_ses_rsp_opcode_vals_ext, 0x3f,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_ver,
            { "Version", "uet.ses.rsp.ver",
                FT_UINT8, BASE_DEC, NULL, 0xc0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_return_code,
            { "Return Code", "uet.ses.rsp.return_code",
                FT_UINT8, BASE_DEC | BASE_EXT_STRING, &uet_ses_rsp_return_code_vals_ext, 0x3f,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_message_id,
            { "Response Message ID", "uet.ses.rsp.message_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_resource_index_gen,
            { "Resource Index generation", "uet.ses.rsp.resource_index_gen",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_job_id,
            { "Job ID", "uet.ses.rsp.job_id",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_mod_length,
            { "Modified Length", "uet.ses.rsp.mod_length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_reserved,
            { "Reserved", "uet.ses.rsp.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_read_req_message_id,
            { "Message ID", "uet.ses.rsp.read_req_message_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_reserved2,
            { "Reserved", "uet.ses.rsp.reserved2",
                FT_UINT16, BASE_HEX, NULL, 0xc000,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_payload_length,
            { "Payload Length", "uet.ses.rsp.payload_length",
                FT_UINT16, BASE_DEC, NULL, 0x3fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_message_offset,
            { "Message Offset", "uet.ses.rsp.message_offset",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_rsp_reserved3,
            { "Rsv", "uet.ses.rsp.reserved3",
                FT_UINT16, BASE_HEX, NULL, 0xc000,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_rsv,
            { "Reserved", "uet.ses.small_req.rsv",
                FT_UINT8, BASE_HEX, NULL, 0xc0,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_flags,
            { "Flags", "uet.ses.small_req.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_flags_ver,
            { "Version", "uet.ses.small_req.flags.ver",
                FT_UINT8, BASE_DEC, NULL, 0xc0,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_flags_dc,
            { "Delivery Complete (DC)", "uet.ses.small_req.flags.dc",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_DC,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_flags_ie,
            { "Initiator Error (IE)", "uet.ses.small_req.flags.ie",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_IE,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_flags_rel,
            { "Relative", "uet.ses.small_req.flags.rel",
                FT_BOOLEAN, 8, TFS(&uet_ses_std_rel_str), UET_SES_REQ_FLAGS_REL,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_flags_rsvd,
            { "Reserved", "uet.ses.small_req.flags.rsvd",
                FT_UINT8, BASE_DEC, NULL, UET_SES_REQ_FLAGS_HD,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_flags_eom,
            { "End of Msg(EOM)", "uet.ses.small_req.eom",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_EOM,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_flags_som,
            { "Start of Msg(SOM)", "uet.ses.small_req.som",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_SOM,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_flags_rsv2,
            { "Reserved", "uet.ses.small_req.flags.rsv2",
                FT_UINT16, BASE_HEX, NULL, 0xc000,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_req_length,
            { "Request Length", "uet.ses.small_req.req_length",
                FT_UINT16, BASE_DEC, NULL, 0x3fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_index_generation,
            { "Index Generation", "uet.ses.small_req.index_generation",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_job_id,
            { "Job ID", "uet.ses.small_req.job_id",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_rsv3,
            { "Reserved", "uet.ses.small_req.rsv3",
                FT_UINT16, BASE_HEX, NULL, 0xf000,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_pidonfep,
            { "PIDonFEP", "uet.ses.small_req.pidonfep",
                FT_UINT16, BASE_DEC, NULL, 0x0fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_rsv4,
            { "Reserved", "uet.ses.small_req.rsv4",
                FT_UINT16, BASE_HEX, NULL, 0xf000,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_resource_index,
            { "Resource Index", "uet.ses.small_req.resource_index",
                FT_UINT16, BASE_DEC, NULL, 0x0fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_small_req_buffer_offset,
            { "Buffer Offset", "uet.ses.small_req.buffer_offset",
                FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },

        { &hf_uet_ses_med_req_rsv,
            { "Reserved", "uet.ses.med_req.rsv",
                FT_UINT8, BASE_HEX, NULL, 0xc0,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_flags,
            { "Flags", "uet.ses.med_req.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_flags_ver,
            { "Version", "uet.ses.med_req.flags.ver",
                FT_UINT8, BASE_DEC, NULL, 0xc0,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_flags_dc,
            { "Delivery Complete (DC)", "uet.ses.med_req.flags.dc",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_DC,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_flags_ie,
            { "Initiator Error (IE)", "uet.ses.med_req.flags.ie",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_IE,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_flags_rel,
            { "Relative", "uet.ses.med_req.flags.rel",
                FT_BOOLEAN, 8, TFS(&uet_ses_std_rel_str), UET_SES_REQ_FLAGS_REL,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_flags_hd,
            { "HD", "uet.ses.med_req.flags.hd",
                FT_BOOLEAN, 8, TFS(&tfs_present_not_present), UET_SES_REQ_FLAGS_HD,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_flags_eom,
            { "End of Msg(EOM)", "uet.ses.med_req.eom",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_EOM,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_flags_som,
            { "Start of Msg(SOM)", "uet.ses.med_req.som",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), UET_SES_REQ_FLAGS_SOM,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_flags_rsv2,
            { "Reserved", "uet.ses.med_req.flags.rsv2",
                FT_UINT16, BASE_HEX, NULL, 0xc000,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_req_length,
            { "Request Length", "uet.ses.med_req.req_length",
                FT_UINT16, BASE_DEC, NULL, 0x3fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_resource_index_generation,
            { "Resource Index Generation", "uet.ses.med_req.resource_index_generation",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_job_id,
            { "Job ID", "uet.ses.med_req.job_id",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_rsv3,
            { "Reserved", "uet.ses.med_req.rsv3",
                FT_UINT16, BASE_HEX, NULL, 0xf000,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_pidonfep,
            { "PIDonFEP", "uet.ses.med_req.pidonfep",
                FT_UINT16, BASE_DEC, NULL, 0x0fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_rsv4,
            { "Reserved", "uet.ses.med_req.rsv4",
                FT_UINT16, BASE_HEX, NULL, 0xf000,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_resource_index,
            { "Resource Index", "uet.ses.med_req.resource_index",
                FT_UINT16, BASE_DEC, NULL, 0x0fff,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_buffer_offset,
            { "Buffer Offset", "uet.ses.med_req.buffer_offset",
                FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_header_data,
            { "Header Data", "uet.ses.med_req.header_data",
                FT_UINT64, BASE_DEC_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_initiator,
            { "Initiator", "uet.ses.med_req.initiator",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_uet_ses_med_req_mem_key_match_bits,
            { "Match Bits/Memory Key", "uet.ses.med_req.mem_key_match_bits",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
    };

    /* Array to hold expansion options between dissections */
    static gint* ett_uet[] = {
        &ett_all_layers,
        &ett_uet_tss_auth_proto,
        &ett_uet_pds_proto,
        &ett_uet_pds_flags,
        &ett_uet_pds_ack_cc_flags,
        &ett_uet_pds_ack_cc_state,
        &ett_uet_pds_pdc_mode,
        &ett_uet_ses_proto,
        &ett_uet_ses_std_flags,
        &ett_uet_ses_atomic_op_ext_hdr,
        &ett_uet_ses_rendv_ext_hdr,
        &ett_uet_ses_comp_swap_ext_hdr,
        &ett_uet_ses_small_req_flags,
        &ett_uet_ses_med_req_flags
    };

    static ei_register_info ei_uet[] = {
        { &ei_uet_pds_hdr_len_invalid,
            { "uet.pds.invalid_header", PI_MALFORMED, PI_ERROR,
                "Invalid PDS header length", EXPFILL }
        },
        { &ei_uet_pds_rud_rod_hdr_len_invalid,
            { "uet.pds.rud_rod.invalid_header", PI_MALFORMED, PI_ERROR,
                "Invalid PDS RUD/ROD header length", EXPFILL }
        },
        { &ei_uet_pds_ack_ext_hdr_len_invalid,
            { "uet.pds.ack.invalid_header", PI_MALFORMED, PI_ERROR,
                "Invalid PDS ACK header length", EXPFILL }
        },
        { &ei_uet_ses_rsp_opcode_invalid,
            { "uet.ses.rsp.invalid_opcode", PI_MALFORMED, PI_ERROR,
                "Invalid SES Resp opcode", EXPFILL }
        },
        { &ei_uet_ses_hdr_len_invalid,
            { "uet.ses.invalid_header", PI_MALFORMED, PI_ERROR,
                "Invalid SES header length", EXPFILL }
        },
        { &ei_uet_tss_hdr_len_invalid,
            { "uet.tss.invalid_header", PI_MALFORMED, PI_ERROR,
                "Invalid TSS header length", EXPFILL }
        },

    };

    expert_module_t* expert_uet;

    proto_uet = proto_register_protocol("Ultra Ethernet Transport", "UET", "uet");
    uet_handle = register_dissector("uet", dissect_uet, proto_uet);
    uet_entropy_handle = register_dissector("uet.entropy", dissect_uet_entropy, proto_uet);

    proto_register_field_array(proto_uet, hf_uet, array_length(hf_uet));
    proto_register_subtree_array(ett_uet, array_length(ett_uet));

    expert_uet = expert_register_protocol(proto_uet);
    expert_register_field_array(expert_uet, ei_uet, array_length(ei_uet));
}

void
proto_reg_handoff_uet(void)
{
    dissector_add_for_decode_as_with_preference("ip.proto", uet_entropy_handle);
    dissector_add_for_decode_as_with_preference("udp.port", uet_handle);
    dissector_add_uint_with_preference("udp.port", UDP_PORT_UET, uet_handle);
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
