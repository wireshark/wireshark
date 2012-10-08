/* packet-gtp.h
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_GTP_H
#define __PACKET_GTP_H
/*structure used to track responses to requests using sequence number*/
typedef struct gtp_msg_hash_entry {
    gboolean is_request;    /*TRUE/FALSE*/
    guint32 req_frame;      /*frame with request */
    nstime_t req_time;      /*req time */
    guint32 rep_frame;      /*frame with reply */
    gint seq_nr;			/*sequence number*/
	guint msgtype; 			/*messagetype*/
} gtp_msg_hash_t;


typedef struct _gtp_hdr {
  guint8 flags;  /* GTP header flags */ 
  guint8 message; /* Message type */
  guint16 length; /* Length of header */
  guint32 teid; /* Tunnel End-point ID */
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
/*
 * 61-69 For future use. Shall not be sent. If received,
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

#endif /* __PACKET_GTP_H*/
