/* packet-gtp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_GTP_H
#define __PACKET_GTP_H
/*structure used to track responses to requests using sequence number*/
typedef struct gtp_msg_hash_entry {
    bool is_request;    /*true/false*/
    uint32_t req_frame;      /*frame with request */
    nstime_t req_time;      /*req time */
    uint32_t rep_frame;      /*frame with reply */
    int seq_nr;			/*sequence number*/
	unsigned msgtype; 			/*messagetype*/
} gtp_msg_hash_t;


typedef struct _gtp_hdr {
  uint8_t flags;  /* GTP header flags */
  uint8_t message; /* Message type */
  uint16_t length; /* Length of header */
  int64_t teid; /* Tunnel End-point ID */
} gtp_hdr_t;

/* definitions of GTP messages */
#define GTP_MSG_UNKNOWN             0x00
#define GTP_MSG_ECHO_REQ            0x01
#define GTP_MSG_ECHO_RESP           0x02
#define GTP_MSG_VER_NOT_SUPP        0x03
#define GTP_MSG_NODE_ALIVE_REQ      0x04
#define GTP_MSG_NODE_ALIVE_RESP     0x05
#define GTP_MSG_REDIR_REQ           0x06
#define GTP_MSG_REDIR_RESP          0x07
/*
 * 8-15 For future use. Shall not be sent. If received,
 * shall be treated as an Unknown message.
 */
#define GTP_MSG_CREATE_PDP_REQ      0x10
#define GTP_MSG_CREATE_PDP_RESP     0x11
#define GTP_MSG_UPDATE_PDP_REQ      0x12
#define GTP_MSG_UPDATE_PDP_RESP     0x13
#define GTP_MSG_DELETE_PDP_REQ      0x14
#define GTP_MSG_DELETE_PDP_RESP     0x15
#define GTP_MSG_INIT_PDP_CONTEXT_ACT_REQ   0x16    /* 2G */
#define GTP_MSG_INIT_PDP_CONTEXT_ACT_RESP  0x17    /* 2G */
/*
 * 24-25 For future use. Shall not be sent. If received,
 * shall be treated as an Unknown message.
 */
#define GTP_MSG_DELETE_AA_PDP_REQ   0x18    /* 2G */
#define GTP_MSG_DELETE_AA_PDP_RESP  0x19    /* 2G */
#define GTP_MSG_ERR_IND             0x1A
#define GTP_MSG_PDU_NOTIFY_REQ      0x1B
#define GTP_MSG_PDU_NOTIFY_RESP     0x1C
#define GTP_MSG_PDU_NOTIFY_REJ_REQ  0x1D
#define GTP_MSG_PDU_NOTIFY_REJ_RESP 0x1E
#define GTP_MSG_SUPP_EXT_HDR        0x1F
#define GTP_MSG_SEND_ROUT_INFO_REQ  0x20
#define GTP_MSG_SEND_ROUT_INFO_RESP 0x21
#define GTP_MSG_FAIL_REP_REQ        0x22
#define GTP_MSG_FAIL_REP_RESP       0x23
#define GTP_MSG_MS_PRESENT_REQ      0x24
#define GTP_MSG_MS_PRESENT_RESP     0x25
/*
 * 38-47 For future use. Shall not be sent. If received,
 * shall be treated as an Unknown message.
 */
#define GTP_MSG_IDENT_REQ           0x30
#define GTP_MSG_IDENT_RESP          0x31
#define GTP_MSG_SGSN_CNTXT_REQ      0x32
#define GTP_MSG_SGSN_CNTXT_RESP     0x33
#define GTP_MSG_SGSN_CNTXT_ACK      0x34
#define GTP_MSG_FORW_RELOC_REQ      0x35
#define GTP_MSG_FORW_RELOC_RESP     0x36
#define GTP_MSG_FORW_RELOC_COMP     0x37
#define GTP_MSG_RELOC_CANCEL_REQ    0x38
#define GTP_MSG_RELOC_CANCEL_RESP   0x39
#define GTP_MSG_FORW_SRNS_CNTXT     0x3A
#define GTP_MSG_FORW_RELOC_ACK      0x3B
#define GTP_MSG_FORW_SRNS_CNTXT_ACK 0x3C
#define GTP_MSG_UE_REG_QUERY_REQ    0x3D
#define GTP_MSG_UE_REG_QUERY_RESP   0x3E
/*
 * 63-69 For future use. Shall not be sent. If received,
 * shall be treated as an Unknown message.
 */
#define GTP_MSG_RAN_INFO_RELAY      70
/*
 * 71-95 For future use. Shall not be sent. If received,
 * shall be treated as an Unknown message.
 */
#define GTP_MBMS_NOTIFY_REQ         96
#define GTP_MBMS_NOTIFY_RES         97
#define GTP_MBMS_NOTIFY_REJ_REQ     98
#define GTP_MBMS_NOTIFY_REJ_RES     99
#define GTP_CREATE_MBMS_CNTXT_REQ   100
#define GTP_CREATE_MBMS_CNTXT_RES   101
#define GTP_UPD_MBMS_CNTXT_REQ      102
#define GTP_UPD_MBMS_CNTXT_RES      103
#define GTP_DEL_MBMS_CNTXT_REQ      104
#define GTP_DEL_MBMS_CNTXT_RES      105
/*
 * 106 - 111 For future use. Shall not be sent. If received,
 * shall be treated as an Unknown message.
 */
#define GTP_MBMS_REG_REQ            112
#define GTP_MBMS_REG_RES            113
#define GTP_MBMS_DE_REG_REQ         114
#define GTP_MBMS_DE_REG_RES         115
#define GTP_MBMS_SES_START_REQ      116
#define GTP_MBMS_SES_START_RES      117
#define GTP_MBMS_SES_STOP_REQ       118
#define GTP_MBMS_SES_STOP_RES       119
#define GTP_MBMS_SES_UPD_REQ        120
#define GTP_MBMS_SES_UPD_RES        121
/* 122-127  For future use. Shall not be sent.
 * If received, shall be treated as an Unknown message.
 */
#define GTP_MS_INFO_CNG_NOT_REQ     128
#define GTP_MS_INFO_CNG_NOT_RES     129
/* 130-239  For future use. Shall not be sent.
 * If received, shall be treated as an Unknown message.
 */
#define GTP_MSG_DATA_TRANSF_REQ     0xF0
#define GTP_MSG_DATA_TRANSF_RESP    0xF1
/* 242-253  For future use. Shall not be sent.
 * If received, shall be treated as an Unknown message.
 */
#define GTP_MSG_END_MARKER          0xFE /* 254 */
#define GTP_MSG_TPDU                0xFF

extern value_string_ext cause_type_ext;

/** GTP header extension info
* This structure is used to transfer infotmation to users of the "gtp.hdr_ext" dissector table
*/

typedef struct gtp_hdr_ext_info {
    proto_item* hdr_ext_item; /* The item created when adding the type of header to the tree,
                               * used to put the name in the tree
                               */
} gtp_hdr_ext_info_t;



/* Data structures to keep track of sessions */
extern uint32_t gtp_session_count;
extern bool g_gtp_session;

typedef struct session_args {
    wmem_list_t *teid_list;
    wmem_list_t *ip_list;
    uint32_t last_teid;
    address last_ip;
    uint8_t last_cause;
} session_args_t;

/* Relation between frame -> session */
extern wmem_map_t* session_table;

/* Relation between <teid,ip> -> frame */
extern wmem_map_t* frame_map;

uint32_t get_frame(address ip, uint32_t teid, uint32_t *frame);

void remove_frame_info(uint32_t f);

void add_gtp_session(uint32_t frame, uint32_t session);

bool teid_exists(uint32_t teid, wmem_list_t *teid_list);

bool ip_exists(address ip, wmem_list_t *ip_list);

void fill_map(wmem_list_t *teid_list, wmem_list_t *ip_list, uint32_t frame);

bool is_cause_accepted(uint8_t cause, uint32_t version);

int decode_qos_umts(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, const char * qos_str, uint8_t type);

void dissect_gtp_uli(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, session_args_t * args _U_);

#endif /* __PACKET_GTP_H*/
