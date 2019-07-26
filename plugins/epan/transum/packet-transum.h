/* packet-transum.h
 * Header file for the TRANSUM response time analyzer post-dissector
 * By Paul Offord <paul.offord@advance7.com>
 * Copyright 2016 Advance Seven Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define ETH_TYPE_IPV4 0x0800
#define ETH_TYPE_IPV6 0x86dd

#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

#define RTE_CALC_SYN    1
#define RTE_CALC_GTCP   2
#define RTE_CALC_GUDP   3
#define RTE_CALC_SMB1   4
#define RTE_CALC_SMB2   5
#define RTE_CALC_DCERPC 6
#define RTE_CALC_DNS    7

#define MAX_SUBPKTS_PER_PACKET 16

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

    /*
        Some request-response pairs are demarked simple by a change in direction on a
        TCP or UDP stream from s2c to c2s.  This is true for the GTCP and GUDP
        calculations.  Other calculations (such as DCERPC) use application protocol
        values to detect the start and end of APDUs.  In this latter case decode_based
        is set to true.
     */
    gboolean decode_based;

    gboolean is_retrans;

    guint32  req_first_frame;
    nstime_t req_first_rtime;
    guint32  req_last_frame;
    nstime_t req_last_rtime;

    guint32  rsp_first_frame;
    nstime_t rsp_first_rtime;
    guint32  rsp_last_frame;
    nstime_t rsp_last_rtime;

    guint    calculation;

    /* The following numbers are for tuning purposes */
    guint32  req_search_total;  /* The total number of steps back through the rrpd_list when matching requests to this entry */
    guint32  rsp_search_total;  /* The total number of steps back through the rrpd_list when matching responses to this entry */
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

    guint8  ssl_content_type;  /*tls.record.content_type */

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

typedef enum {
    HF_INTEREST_IP_PROTO = 0,
    HF_INTEREST_IPV6_NXT,

    HF_INTEREST_TCP_RETRAN,
    HF_INTEREST_TCP_KEEP_ALIVE,
    HF_INTEREST_TCP_FLAGS_SYN,
    HF_INTEREST_TCP_FLAGS_ACK,
    HF_INTEREST_TCP_FLAGS_RESET,
    HF_INTEREST_TCP_FLAGS_URG,
    HF_INTEREST_TCP_SEQ,
    HF_INTEREST_TCP_SRCPORT,
    HF_INTEREST_TCP_DSTPORT,
    HF_INTEREST_TCP_STREAM,
    HF_INTEREST_TCP_LEN,

    HF_INTEREST_UDP_SRCPORT,
    HF_INTEREST_UDP_DSTPORT,
    HF_INTEREST_UDP_STREAM,
    HF_INTEREST_UDP_LENGTH,

    HF_INTEREST_SSL_CONTENT_TYPE,

    HF_INTEREST_TDS_TYPE,
    HF_INTEREST_TDS_LENGTH,

    HF_INTEREST_SMB_MID,

    HF_INTEREST_SMB2_SES_ID,
    HF_INTEREST_SMB2_MSG_ID,
    HF_INTEREST_SMB2_CMD,

    HF_INTEREST_DCERPC_VER,
    HF_INTEREST_DCERPC_PKT_TYPE,
    HF_INTEREST_DCERPC_CN_CALL_ID,
    HF_INTEREST_DCERPC_CN_CTX_ID,

    HF_INTEREST_DNS_ID,

    HF_INTEREST_END_OF_LIST
} ehf_of_interest;

typedef struct _HF_OF_INTEREST_INFO
{
    int hf;
    const char* proto_name;

} HF_OF_INTEREST_INFO;

extern HF_OF_INTEREST_INFO hf_of_interest[HF_INTEREST_END_OF_LIST];

void add_detected_tcp_svc(guint16 port);
extern gboolean is_dcerpc_context_zero(guint32 pkt_type);
extern gboolean is_dcerpc_req_pkt_type(guint32 pkt_type);


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
