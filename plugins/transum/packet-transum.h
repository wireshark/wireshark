/* packet-transum.h
* Header file for the TRANSUM response time analyzer post-dissector
* By Paul Offord <paul.offord@advance7.com>
* Copyright 2016 Advance Seven Limited
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

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86dd

#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

#define RRPD_STATE_DONT_CARE 0
#define RRPD_STATE_INIT 0
#define RRPD_STATE_1 1
#define RRPD_STATE_2 2
#define RRPD_STATE_3 3
#define RRPD_STATE_4 4
#define RRPD_STATE_5 5
#define RRPD_STATE_6 6
#define RRPD_STATE_7 7
#define RRPD_STATE_8 8

#define RTE_CALC_SYN    1
#define RTE_CALC_GTCP   2
#define RTE_CALC_GUDP   3
#define RTE_CALC_SMB1   4
#define RTE_CALC_SMB2   5
#define RTE_CALC_DCERPC 6
#define RTE_CALC_DNS    7

#define RRPD_SIZE 64

#define MAX_STREAMS_PER_PROTOCOL 256*1024
#define MAX_PACKETS 8000000  /* We support 8 million packets */
#define MAX_SUBPKTS_PER_PACKET 16
#define MAX_RRPDS 1000000  /* We support 4 million RRPDs */
#define SIZE_OF_TEMP_RSP_RRPD_LIST 1024

/*
    An RR pair is identified by a Fully Qualified Message ID (RRPD)
*/

typedef struct _RRPD
{
    /*
        When a c2s is set TRUE it means that the associated packet is going from
        client-to-service.  If this value is false the associated packet is going
        from service-to-client.

        This value is only valid for RRPDs imbedded in subpacket structures.
     */
    gboolean c2s;

    guint8   ip_proto;
    guint32  stream_no;
    guint64  session_id;
    guint64  msg_id;
    guint32  suffix;

    /*
        Some request-response pairs are demarked simple by a change in direction on a
        TCP or UDP stream from s2c to c2s.  This is true for the GTCP and GUDP
        calculations.  Other calculations (such as DCERPC) use application protocol
        values to detect the start and end of APDUs.  In this latter case decode_based
        is set to true.
     */
    gboolean decode_based;

    int      state;

    guint32  req_first_frame;
    nstime_t req_first_rtime;
    guint32  req_last_frame;
    nstime_t req_last_rtime;

    guint32  rsp_first_frame;
    nstime_t rsp_first_rtime;
    guint32  rsp_last_frame;
    nstime_t rsp_last_rtime;

    guint    calculation;
} RRPD;

typedef struct _PKT_INFO
{
    int frame_number;
    nstime_t relative_time;

    gboolean tcp_retran;  /* tcp.analysis.retransmission */
    gboolean tcp_keep_alive;  /* tcp.analysis.keep_alive */
    gboolean tcp_flags_syn;  /* tcp.flags.syn */
    gboolean tcp_flags_ack;  /* tcp.flags.ack */
    gboolean tcp_flags_reset;  /* tcp.flags.reset */
    guint32 tcp_flags_urg;  /* tcp.urgent_pointer */
    guint32 tcp_seq;  /* tcp.seq */

    /* Generic transport values */
    guint16 srcport;  /* tcp.srcport or udp.srcport*/
    guint16 dstport;  /* tcp.dstport or udp.dstport*/
    guint16 len;  /* tcp.len or udp.len */

    guint8  tds_type;  /*tds.type */
    guint16 tds_length;  /* tds.length */

    guint16 smb_mid;  /* smb.mid */

    guint64 smb2_sesid;  /* smb2.sesid */
    guint64 smb2_msg_id;  /* smb2.msg_id */
    guint16 smb2_cmd;  /* smb2.cmd */

    guint8 dcerpc_ver;  /* dcerpc.ver */
    guint8 dcerpc_pkt_type;  /* dcerpc.pkt_type */
    guint32 dcerpc_cn_call_id;  /* dcerpc.cn_call_id */
    guint16 dcerpc_cn_ctx_id;  /* dcerpc.cn_ctx_id */

    guint16 dns_id;  /* dns.id */

    /* The following values are calculated */
    gboolean pkt_of_interest;

    /* RRPD data for this packet */
    /* Complete this based on the detected protocol */
    RRPD rrpd;

} PKT_INFO;

typedef struct _HF_OF_INTEREST
{
    int ip_proto;
    int ipv6_nxt;

    int tcp_retran;
    int tcp_keep_alive;
    int tcp_flags_syn;
    int tcp_flags_ack;
    int tcp_flags_reset;
    int tcp_flags_urg;
    int tcp_seq;
    int tcp_srcport;
    int tcp_dstport;
    int tcp_stream;
    int tcp_len;

    int udp_srcport;
    int udp_dstport;
    int udp_stream;
    int udp_length;

    int tds_type;
    int tds_length;

    int smb_mid;

    int smb2_ses_id;
    int smb2_msg_id;
    int smb2_cmd;

    int dcerpc_ver;
    int dcerpc_pkt_type;
    int dcerpc_cn_call_id;
    int dcerpc_cn_ctx_id;

    int dns_id;

    int data_data;
} HF_OF_INTEREST;

void add_detected_tcp_svc(guint16 port);
