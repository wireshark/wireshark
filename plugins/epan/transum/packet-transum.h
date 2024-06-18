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
        When a c2s is set true it means that the associated packet is going from
        client-to-service.  If this value is false the associated packet is going
        from service-to-client.

        This value is only valid for RRPDs imbedded in subpacket structures.
     */
    bool c2s;

    uint8_t  ip_proto;
    uint32_t stream_no;
    uint64_t session_id;
    uint64_t msg_id;

    /*
        Some request-response pairs are demarked simple by a change in direction on a
        TCP or UDP stream from s2c to c2s.  This is true for the GTCP and GUDP
        calculations.  Other calculations (such as DCERPC) use application protocol
        values to detect the start and end of APDUs.  In this latter case decode_based
        is set to true.
     */
    bool decode_based;

    bool is_retrans;

    uint32_t req_first_frame;
    nstime_t req_first_rtime;
    uint32_t req_last_frame;
    nstime_t req_last_rtime;

    uint32_t rsp_first_frame;
    nstime_t rsp_first_rtime;
    uint32_t rsp_last_frame;
    nstime_t rsp_last_rtime;

    unsigned calculation;

    /* The following numbers are for tuning purposes */
    uint32_t req_search_total;  /* The total number of steps back through the rrpd_list when matching requests to this entry */
    uint32_t rsp_search_total;  /* The total number of steps back through the rrpd_list when matching responses to this entry */
} RRPD;

typedef struct _PKT_INFO
{
    int frame_number;
    nstime_t relative_time;

    bool tcp_retran;  /* tcp.analysis.retransmission */
    bool tcp_keep_alive;  /* tcp.analysis.keep_alive */
    bool tcp_flags_syn;  /* tcp.flags.syn */
    bool tcp_flags_ack;  /* tcp.flags.ack */
    bool tcp_flags_reset;  /* tcp.flags.reset */
    uint32_t tcp_flags_urg;  /* tcp.urgent_pointer */
    uint32_t tcp_seq;  /* tcp.seq */

    /* Generic transport values */
    uint16_t srcport;  /* tcp.srcport or udp.srcport*/
    uint16_t dstport;  /* tcp.dstport or udp.dstport*/
    uint16_t len;  /* tcp.len or udp.len */

    uint8_t ssl_content_type;  /*tls.record.content_type */

    uint8_t tds_type;  /*tds.type */
    uint16_t tds_length;  /* tds.length */

    uint16_t smb_mid;  /* smb.mid */

    uint64_t smb2_sesid;  /* smb2.sesid */
    uint64_t smb2_msg_id;  /* smb2.msg_id */
    uint16_t smb2_cmd;  /* smb2.cmd */

    uint8_t dcerpc_ver;  /* dcerpc.ver */
    uint8_t dcerpc_pkt_type;  /* dcerpc.pkt_type */
    uint32_t dcerpc_cn_call_id;  /* dcerpc.cn_call_id */
    uint16_t dcerpc_cn_ctx_id;  /* dcerpc.cn_ctx_id */

    uint16_t dns_id;  /* dns.id */

    /* The following values are calculated */
    bool pkt_of_interest;

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

void add_detected_tcp_svc(uint16_t port);
extern bool is_dcerpc_context_zero(uint32_t pkt_type);
extern bool is_dcerpc_req_pkt_type(uint32_t pkt_type);


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
