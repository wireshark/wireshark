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

/**
 * @brief Fully Qualified Message ID representing a Request-Response Pair Descriptor (RRPD), used to correlate request and response frames across a conversation.
 */
typedef struct _RRPD
{
    /*
     * When c2s is true the associated packet is travelling client-to-service.
     * When false it is travelling service-to-client.
     * Only valid for RRPDs embedded in subpacket structures.
     */
    bool c2s; /**< True if the associated packet is client-to-service; false if service-to-client. Only valid when this RRPD is embedded in a subpacket structure. */

    uint8_t  ip_proto;   /**< IP protocol number (e.g. IPPROTO_TCP, IPPROTO_UDP) for this request-response pair. */
    uint32_t stream_no;  /**< Wireshark transport stream index identifying the TCP or UDP stream carrying this pair. */
    uint64_t session_id; /**< Application-layer session identifier, used by protocols that multiplex sessions over a single stream. */
    uint64_t msg_id;     /**< Application-layer message identifier uniquely distinguishing this request-response pair within the session. */

    /*
     * When decode_based is false, the RR boundary is detected by a direction
     * change (s2c -> c2s) on the stream, as used by GTCP and GUDP calculations.
     * When true, application-protocol values (e.g. DCERPC) are used to detect
     * APDU boundaries.
     */
    bool decode_based; /**< True if APDU boundaries are determined by application-protocol decoding (e.g. DCERPC); false if determined by a stream direction change. */

    bool is_retrans; /**< True if this RRPD was identified as a retransmission and should be excluded from response-time calculations. */

    uint32_t req_first_frame;  /**< Wireshark frame number of the first frame of the request APDU. */
    nstime_t req_first_rtime;  /**< Capture-relative timestamp of the first frame of the request APDU. */
    uint32_t req_last_frame;   /**< Wireshark frame number of the last frame of the request APDU. */
    nstime_t req_last_rtime;   /**< Capture-relative timestamp of the last frame of the request APDU. */

    uint32_t rsp_first_frame;  /**< Wireshark frame number of the first frame of the response APDU. */
    nstime_t rsp_first_rtime;  /**< Capture-relative timestamp of the first frame of the response APDU. */
    uint32_t rsp_last_frame;   /**< Wireshark frame number of the last frame of the response APDU. */
    nstime_t rsp_last_rtime;   /**< Capture-relative timestamp of the last frame of the response APDU. */

    unsigned calculation; /**< Identifier of the RR calculation method (e.g. GTCP, GUDP, DCERPC) used to detect this pair. */

    /* Tuning counters */
    uint32_t req_search_total; /**< Cumulative number of steps taken backwards through the rrpd_list when matching requests to this entry; used for performance tuning. */
    uint32_t rsp_search_total; /**< Cumulative number of steps taken backwards through the rrpd_list when matching responses to this entry; used for performance tuning. */
} RRPD;

/**
 * @brief Aggregates all per-packet field values extracted by the RR dissector, including transport, application-layer, and computed state.
 */
typedef struct _PKT_INFO
{
    int      frame_number;  /**< Wireshark frame number of this packet. */
    nstime_t relative_time; /**< Capture-relative timestamp of this packet. */

    /* TCP analysis flags */
    bool     tcp_retran;      /**< True if tcp.analysis.retransmission is set for this packet. */
    bool     tcp_keep_alive;  /**< True if tcp.analysis.keep_alive is set for this packet. */
    bool     tcp_flags_syn;   /**< True if the TCP SYN flag (tcp.flags.syn) is set. */
    bool     tcp_flags_ack;   /**< True if the TCP ACK flag (tcp.flags.ack) is set. */
    bool     tcp_flags_reset; /**< True if the TCP RST flag (tcp.flags.reset) is set. */
    uint32_t tcp_flags_urg;   /**< Value of the TCP urgent pointer (tcp.urgent_pointer); non-zero indicates urgent data. */
    uint32_t tcp_seq;         /**< TCP sequence number (tcp.seq) of this packet. */

    /* Generic transport values */
    uint16_t srcport; /**< Source port number from tcp.srcport or udp.srcport. */
    uint16_t dstport; /**< Destination port number from tcp.dstport or udp.dstport. */
    uint16_t len;     /**< Payload length in bytes from tcp.len or udp.len. */

    /* TLS */
    uint8_t ssl_content_type; /**< TLS record content type (tls.record.content_type), e.g. handshake, application data, alert. */

    /* TDS */
    uint8_t  tds_type;   /**< TDS packet type (tds.type) identifying the category of this TDS message. */
    uint16_t tds_length; /**< TDS packet length (tds.length) in bytes. */

    /* SMB */
    uint16_t smb_mid; /**< SMB multiplex ID (smb.mid) used to match SMB requests to their responses. */

    /* SMB2 */
    uint64_t smb2_sesid;  /**< SMB2 session ID (smb2.sesid) identifying the authenticated session. */
    uint64_t smb2_msg_id; /**< SMB2 message ID (smb2.msg_id) used to correlate SMB2 requests and responses. */
    uint16_t smb2_cmd;    /**< SMB2 command code (smb2.cmd) identifying the type of SMB2 operation. */

    /* DCERPC */
    uint8_t  dcerpc_ver;        /**< DCERPC major version number (dcerpc.ver). */
    uint8_t  dcerpc_pkt_type;   /**< DCERPC packet type (dcerpc.pkt_type), e.g. request, response, bind. */
    uint32_t dcerpc_cn_call_id; /**< DCERPC connection-oriented call ID (dcerpc.cn_call_id) matching requests to responses. */
    uint16_t dcerpc_cn_ctx_id;  /**< DCERPC connection-oriented context ID (dcerpc.cn_ctx_id) identifying the interface binding. */

    /* DNS */
    uint16_t dns_id; /**< DNS transaction ID (dns.id) used to match DNS queries to their answers. */

    /* Calculated values */
    bool pkt_of_interest; /**< True if this packet has been determined to be relevant to an RR calculation and should be processed further. */

    /* RRPD data for this packet; populated based on the detected application protocol */
    RRPD rrpd; /**< Request-response pair descriptor carrying the correlation state derived for this packet. */
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
