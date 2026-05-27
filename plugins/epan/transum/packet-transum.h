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

/**
 * @brief Index constants for the table of protocol fields monitored by the
 *        follow-stream and conversation tracking infrastructure.
 */
typedef enum {
    HF_INTEREST_IP_PROTO = 0,    /**< IPv4 protocol number field (ip.proto) */
    HF_INTEREST_IPV6_NXT,        /**< IPv6 next header field (ipv6.nxt) */

    HF_INTEREST_TCP_RETRAN,      /**< TCP retransmission flag (tcp.analysis.retransmission) */
    HF_INTEREST_TCP_KEEP_ALIVE,  /**< TCP keep-alive flag (tcp.analysis.keep_alive) */
    HF_INTEREST_TCP_FLAGS_SYN,   /**< TCP SYN flag (tcp.flags.syn) */
    HF_INTEREST_TCP_FLAGS_ACK,   /**< TCP ACK flag (tcp.flags.ack) */
    HF_INTEREST_TCP_FLAGS_RESET, /**< TCP RST flag (tcp.flags.reset) */
    HF_INTEREST_TCP_FLAGS_URG,   /**< TCP URG flag (tcp.flags.urg) */
    HF_INTEREST_TCP_SEQ,         /**< TCP sequence number (tcp.seq) */
    HF_INTEREST_TCP_SRCPORT,     /**< TCP source port (tcp.srcport) */
    HF_INTEREST_TCP_DSTPORT,     /**< TCP destination port (tcp.dstport) */
    HF_INTEREST_TCP_STREAM,      /**< TCP stream index (tcp.stream) */
    HF_INTEREST_TCP_LEN,         /**< TCP segment length (tcp.len) */

    HF_INTEREST_UDP_SRCPORT,     /**< UDP source port (udp.srcport) */
    HF_INTEREST_UDP_DSTPORT,     /**< UDP destination port (udp.dstport) */
    HF_INTEREST_UDP_STREAM,      /**< UDP stream index (udp.stream) */
    HF_INTEREST_UDP_LENGTH,      /**< UDP datagram length (udp.length) */

    HF_INTEREST_SSL_CONTENT_TYPE, /**< TLS/SSL content type field (ssl.record.content_type) */

    HF_INTEREST_TDS_TYPE,        /**< TDS packet type field (tds.type) */
    HF_INTEREST_TDS_LENGTH,      /**< TDS packet length field (tds.length) */

    HF_INTEREST_SMB_MID,         /**< SMB multiplex ID field (smb.mid) */

    HF_INTEREST_SMB2_SES_ID,     /**< SMB2 session ID field (smb2.sesid) */
    HF_INTEREST_SMB2_MSG_ID,     /**< SMB2 message ID field (smb2.msg_id) */
    HF_INTEREST_SMB2_CMD,        /**< SMB2 command code field (smb2.cmd) */

    HF_INTEREST_DCERPC_VER,         /**< DCE/RPC version field (dcerpc.ver) */
    HF_INTEREST_DCERPC_PKT_TYPE,    /**< DCE/RPC packet type field (dcerpc.pkt_type) */
    HF_INTEREST_DCERPC_CN_CALL_ID,  /**< DCE/RPC connection-oriented call ID (dcerpc.cn_call_id) */
    HF_INTEREST_DCERPC_CN_CTX_ID,   /**< DCE/RPC connection-oriented context ID (dcerpc.cn_ctx_id) */

    HF_INTEREST_DNS_ID,          /**< DNS transaction ID field (dns.id) */

    HF_INTEREST_END_OF_LIST      /**< Sentinel: total number of fields of interest */
} ehf_of_interest;

/**
 * @brief Associates an ehf_of_interest slot with its registered header field ID and protocol name.
 */
typedef struct _HF_OF_INTEREST_INFO {
    int         hf;         /**< Registered header field ID (hfid) for this field of interest */
    const char *proto_name; /**< Dotted protocol field name string (e.g., "tcp.flags.syn") */
} HF_OF_INTEREST_INFO;

extern HF_OF_INTEREST_INFO hf_of_interest[HF_INTEREST_END_OF_LIST];

/**
 * @brief Adds a detected TCP service to the map.
 *
 * @param port The port number of the detected TCP service.
 */
void add_detected_tcp_svc(uint16_t port);

/**
 * @brief Checks if a given packet type is in the set of zeroed DCERPC contexts.
 *
 * @param pkt_type The packet type to check.
 * @return true If the packet type is found in the zeroed DCERPC context map.
 * @return false If the packet type is not found in the zeroed DCERPC context map.
 */
extern bool is_dcerpc_context_zero(uint32_t pkt_type);

/**
 * @brief Checks if the given packet type is a DCE/RPC request packet type.
 *
 * @param pkt_type The packet type to check.
 * @return true if the packet type is a DCE/RPC request, false otherwise.
 */
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
