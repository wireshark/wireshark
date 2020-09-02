/* packet-srt.c
 * Routines for Secure Reliable Transport Protocol dissection
 * Copyright (c) 2018 Haivision Systems Inc. <info@srtalliance.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * SRT is an open source video transport protocol and technology stack
 * that optimizes streaming performance across unpredictable networks
 * with secure streams and easy firewall traversal, bringing the best
 * quality live video over the worst networks.
 *
 * http://www.srtalliance.org
 */

#include <config.h>
#include <wsutil/str_util.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/conversation.h>

/* Prototypes */
void proto_reg_handoff_srt(void);
void proto_register_srt(void);

/* Initialize the protocol */
static int proto_srt = -1;
static int hf_srt_iscontrol = -1;
static int hf_srt_type = -1;
static int hf_srt_exttype = -1;
static int hf_srt_exttype_none = -1;
static int hf_srt_seqno = -1;
static int hf_srt_ack_seqno = -1;
static int hf_srt_ackno = -1;
static int hf_srt_msgno = -1;
static int hf_srt_msgno_pb = -1;
static int hf_srt_msgno_inorder = -1;
static int hf_srt_msgno_enctypes = -1;
static int hf_srt_msgno_rexmit = -1;
static int hf_srt_timestamp = -1;
static int hf_srt_id = -1;
static int hf_srt_addinfo = -1;
static int hf_srt_rtt = -1;
static int hf_srt_rttvar = -1;
static int hf_srt_bufavail = -1;
static int hf_srt_rate = -1;
static int hf_srt_bandwidth = -1;
static int hf_srt_rcvrate = -1;

/* SRT Handshake */
static int hf_srt_handshake_version = -1;
static int hf_srt_handshake_type_v4 = -1;
static int hf_srt_handshake_enc_field_v5 = -1;
static int hf_srt_handshake_ext_field_v5 = -1;
static int hf_srt_handshake_ext_field_v5_flag_hsreq = -1;
static int hf_srt_handshake_ext_field_v5_flag_kmreq = -1;
static int hf_srt_handshake_ext_field_v5_flag_config = -1;
static int hf_srt_handshake_isn = -1;
static int hf_srt_handshake_mtu = -1;
static int hf_srt_handshake_flow_window = -1;
static int hf_srt_handshake_reqtype = -1;
static int hf_srt_handshake_id = -1;
static int hf_srt_handshake_cookie = -1;
static int hf_srt_handshake_peerip = -1;
/* SRT Handshake Extension */
static int hf_srt_handshake_ext_version = -1;
static int hf_srt_handshake_ext_flags = -1;
static int hf_srt_handshake_ext_flag_tsbpd_snd = -1;
static int hf_srt_handshake_ext_flag_tsbpd_rcv = -1;
static int hf_srt_handshake_ext_flag_haicrypt = -1;
static int hf_srt_handshake_ext_flag_tlpkt_drop = -1;
static int hf_srt_handshake_ext_flag_nak_report = -1;
static int hf_srt_handshake_ext_flag_rexmit = -1;
static int hf_srt_handshake_ext_flag_stream = -1;

static int hf_srt_srths_blocktype = -1;
static int hf_srt_srths_blocklen = -1;
static int hf_srt_srths_agent_latency = -1; // TSBPD delay
static int hf_srt_srths_peer_latency = -1; // TSBPD delay
static int hf_srt_srtkm_msg = -1;
static int hf_srt_srtkm_error = -1;
static int hf_srt_srths_sid = -1;
static int hf_srt_srths_conjestcontrol = -1;

static gint ett_srt = -1;
static gint ett_srt_handshake_ext_flags = -1;
static gint ett_srt_handshake_ext_field_flags = -1;

static expert_field ei_srt_nak_seqno = EI_INIT;
static expert_field ei_srt_hs_ext_hsreq_len = EI_INIT;
static expert_field ei_srt_hs_ext_type = EI_INIT;

static dissector_handle_t srt_udp_handle;


/* This defines the firstmost bit of the packet, so it can stay this way. */
#define SRT_TYPE_DATA            0
#define SRT_TYPE_CONTROL        1
#define SRT_CONTROL_MASK (~0x80000000)

#define SRT_LOSS_SEQUENCE_FIRST 0x80000000
#define SRT_LOSS_SEQUENCE_MASK  (~SRT_LOSS_SEQUENCE_FIRST)

enum UDTSockType
{
    SRT_UNDEFINED = 0, /* initial trap representation */
    SRT_STREAM = 1,
    SRT_DGRAM = 2,
    SRT_MAGIC_CODE = 0x4A17
};

/* Handshake Extended Field Flags */
#define SRT_OPT_FIELD_LEN            32
#define SRT_OPT_TSBPDSND        (1 << 0)
#define SRT_OPT_TSBPDRCV        (1 << 1)
#define SRT_OPT_HAICRYPT        (1 << 2)
#define SRT_OPT_TLPKTDROP       (1 << 3)
#define SRT_OPT_NAKREPORT       (1 << 4)
#define SRT_OPT_REXMITFLG       (1 << 5)
#define SRT_OPT_STREAM          (1 << 6)


/* Extended Handshake Flags */
#define SRT_HS_V5_EXT_FIELD_LEN                16
#define SRT_HS_V5_EXT_FIELD_HSREQ         (1 << 0)
#define SRT_HS_V5_EXT_FIELD_KMREQ         (1 << 1)
#define SRT_HS_V5_EXT_FIELD_CONFIG        (1 << 2)
#define SRT_HS_V5_EXT_FIELD_MAGIC   SRT_MAGIC_CODE

/* Message number field and single bit flags */
#define SRT_MSGNO_FF_FIRST_B (2 << (32-2))
#define SRT_MSGNO_FF_LAST_B (1 << (32-2))
#define SRT_MSGNO_FF_MASK (SRT_MSGNO_FF_FIRST_B | SRT_MSGNO_FF_LAST_B)

enum PacketBoundary
{
    PB_SUBSEQUENT = 0,
    /* 01: last packet of a message */
    PB_LAST = 1,
    /* 10: first packet of a message */
    PB_FIRST = 2,
    /* 11: solo message packet */
    PB_SOLO = 3,
};


#define SRT_MSGNO_INORDER (1 << (32-3))        /* 0x20000000 */

#define SRT_MSGNO_ENCTYPE (3 << (32-5))        /* 0x18000000 */

#define SRT_MSGNO_EK_NONE 0
#define SRT_MSGNO_EK_EVEN 1
#define SRT_MSGNO_EK_ODD  2

#define SRT_MSGNO_REXMIT  (1 << (32-6))        /* 0x04000000 */

/* Rest of the bits are for message sequence number */
#define SRT_MSGNO_MSGNO_MASK 0x03ffffff


/* The message types used by UDT protocol. This is a part of UDT
 * protocol and should never be changed.
 */
enum UDTMessageType
{
    UMSG_HANDSHAKE = 0, // Connection Handshake. Control: see @a CHandShake.
    UMSG_KEEPALIVE = 1, // Keep-alive.
    UMSG_ACK = 2, // Acknowledgement. Control: past-the-end sequence number up to which packets have been received.
    UMSG_LOSSREPORT = 3, // Negative Acknowledgement (NACK). Control: Loss list.
    UMSG_CGWARNING = 4, // Congestion warning.
    UMSG_SHUTDOWN = 5, // Shutdown.
    UMSG_ACKACK = 6, // Acknowledgement of Acknowledgement. Add info: The ACK sequence number
    UMSG_DROPREQ = 7, // Message Drop Request. Add info: Message ID. Control Info: (first, last) number of the message.
    UMSG_PEERERROR = 8, // Signal from the Peer side. Add info: Error code.
    /* ... add extra code types here */
    UMSG_END_OF_TYPES,
    UMSG_EXT = 0x7FFF // For the use of user-defined control packets.
};

// Adapted constants
#define SRT_CMD_HSREQ       1
#define SRT_CMD_HSRSP       2
#define SRT_CMD_KMREQ       3
#define SRT_CMD_KMRSP       4
#define SRT_CMD_SID         5
#define SRT_CMD_CONJESTCTRL 6

enum SrtDataStruct
{
    SRT_HS_VERSION = 0,
    SRT_HS_FLAGS,
    SRT_HS_EXTRAS,

    // Keep it always last
    SRT_HS__SIZE
};


enum UDTRequestType
{
    URQ_AGREEMENT     =   -2,
    URQ_CONCLUSION    =   -1,
    URQ_WAVEAHAND     =    0,
    URQ_INDUCTION     =    1,

    URQ_FAILURE_TYPES = 1000,
    URQ_REJECT        = 1002,
    URQ_INVALID       = 1004
};


enum SRT_KM_STATE
{
    SRT_KM_S_UNSECURED = 0,      ///< No encryption
    SRT_KM_S_SECURING  = 1,      ///< Stream encrypted, exchanging Keying Material
    SRT_KM_S_SECURED   = 2,      ///< Stream encrypted, keying Material exchanged, decrypting ok.
    SRT_KM_S_NOSECRET  = 3,      ///< Stream encrypted and no secret to decrypt Keying Material
    SRT_KM_S_BADSECRET = 4       ///< Stream encrypted and wrong secret, cannot decrypt Keying Material
};

static const value_string srt_ctrlmsg_types[] = {
    {UMSG_HANDSHAKE,  "UMSG_HANDSHAKE"},
    {UMSG_KEEPALIVE,  "UMSG_KEEPALIVE"},
    {UMSG_ACK,        "UMSG_ACK"},
    {UMSG_LOSSREPORT, "UMSG_LOSSREPORT"},
    {UMSG_CGWARNING,  "UMSG_CGWARNING"},
    {UMSG_SHUTDOWN,   "UMSG_SHUTDOWN"},
    {UMSG_ACKACK,     "UMSG_ACKACK"},
    {UMSG_DROPREQ,    "UMSG_DROPREQ"},
    {UMSG_PEERERROR,  "UMSG_PEERERROR"},
    {UMSG_EXT,        "UMSG_EXT"},

    {0, NULL},
};

static const value_string srt_ctrlmsg_exttypes[] = {
    {SRT_CMD_HSREQ,       "SRT_CMD_HSREQ"},
    {SRT_CMD_HSRSP,       "SRT_CMD_HSRSP"},
    {SRT_CMD_KMREQ,       "SRT_CMD_KMREQ"},
    {SRT_CMD_KMRSP,       "SRT_CMD_KMRSP"},
    {SRT_CMD_SID,         "SRT_CMD_SID"},
    {SRT_CMD_CONJESTCTRL, "SRT_CMD_CONJESTCTRL"},

    { 0, NULL },
};

static const value_string srt_hsv4_socket_types[] = {
    {SRT_STREAM,          "SRT_STREAM"},
    {SRT_DGRAM,           "SRT_DGRAM"},
    {0, NULL},
};


static const value_string srt_handshake_enc_field[] = {
    {0, "PBKEYLEN not advertised"},
    {2, "AES-128" },
    {3, "AES-192" },
    {4, "AES-256" },
    {0, NULL},
};


static const true_false_string srt_packet_types = {
    "CONTROL",  /* 1 */
    "DATA"      /* 0 */
};

static const value_string srt_pb_types[] = {
    {PB_SUBSEQUENT, "PB_SUBSEQUENT"},
    {PB_LAST,       "PB_LAST"},
    {PB_FIRST,      "PB_FIRST"},
    {PB_SOLO,       "PB_SOLO"},
    {0, NULL},
};

static const value_string srt_msgno_enctypes[] = {
    {SRT_MSGNO_EK_NONE, "Not encrypted"},
    {SRT_MSGNO_EK_EVEN, "Encrypted ith even key"},
    {SRT_MSGNO_EK_ODD,  "Encrypted with odd key"},
    {0, NULL},
};

static const true_false_string srt_msgno_rexmit = {
    "Retransmitted", /* 1 */
    "Original"      /* 0 */
};

static const value_string srt_hs_request_types[] = {
    {URQ_INDUCTION,  "URQ_INDUCTION (c/l invocation)"},
    {URQ_CONCLUSION, "URQ_CONCLUSION"},
    {URQ_WAVEAHAND,  "URQ_WAVEAHAND (rendezvous invocation)"},
    {URQ_AGREEMENT,  "URQ_AGREEMENT (rendezvous finalization)"},
    {URQ_REJECT,     "!REJECT"},
    {URQ_INVALID,    "!INVALID"},
    {0, NULL}
};

static const value_string srt_enc_kmstate[] = {
    {SRT_KM_S_UNSECURED, "UNSECURED"},
    {SRT_KM_S_SECURING,  "SECURING"},
    {SRT_KM_S_SECURED,   "SECURED"},
    {SRT_KM_S_NOSECRET,  "NOSECRET"},
    {SRT_KM_S_BADSECRET, "BADSECRET"},

    {0, NULL},
};


/*
 * XXX To be added later to extract correct IPv4/IPv6 address from 16 bytes of data
 * static void srt_tree_add_ipaddr( proto_tree *tree, const int hf, tvbuff_t *tvb, gint offset)
 * {
 *
 * }
 */

#define IP_BUFFER_SIZE 64

static void srt_format_ip_address(gchar* dest, size_t dest_size, const gchar* ptr)
{
    /* Initial IPv4 check.
     * The address is considered IPv4 if:
     * byte[0] and byte[3] != 0
     * bytes[4...16] == 0
     */

    ws_in4_addr ia4;
    ws_in6_addr ia6;
    guint32* p;
    int i, j;

    if (ptr[0] != 0 && ptr[3] != 0)
    {
        for (i = 4; i < 16; ++i)
        {
            if ( ptr[i] == 0 )
                continue;

            /* This is not an IP4 */
            p = (guint32*) &ia6;
            for (j = 0; j < 4; ++j)
                p[j] = g_ntohl(((guint32*)ptr)[j]);

            ws_inet_ntop6(&ia6, dest, (guint) dest_size);
            return;
        }
    }

    // There's one small problem: the contents of the handshake
    // goes in LITTLE ENDIAN. That's an initial problem of UDT.
    // The address must be inverted.

    // Here's IPv4, so invert only one l.
    ia4 = g_ntohl(*((const guint32*)ptr));

    ws_inet_ntop4(&ia4, dest, (guint) dest_size);
    return;
}


static void srt_format_hs_ext_hsreq(proto_tree* tree, tvbuff_t* tvb, int baseoff)
{
    proto_item* pi;
    guint32 version = 0;
    pi = proto_tree_add_item_ret_uint(tree, hf_srt_handshake_ext_version, tvb, baseoff, 4, ENC_BIG_ENDIAN, &version);

    const int vminor = (version >>  8) & 0xff;
    const int vmajor = (version >> 16) & 0xff;
    const int vpatch = version & 0xff;
    proto_item_append_text(pi, " (%d.%d.%d)", vmajor, vminor, vpatch);

    static int * const ext_hs_flags[] = {
        &hf_srt_handshake_ext_flag_tsbpd_snd,
        &hf_srt_handshake_ext_flag_tsbpd_rcv,
        &hf_srt_handshake_ext_flag_haicrypt,
        &hf_srt_handshake_ext_flag_tlpkt_drop,
        &hf_srt_handshake_ext_flag_nak_report,
        &hf_srt_handshake_ext_flag_rexmit,
        &hf_srt_handshake_ext_flag_stream,
        NULL
    };

    proto_tree_add_bitmask_with_flags(tree, tvb, baseoff + 4, hf_srt_handshake_ext_flags,
                                      ett_srt_handshake_ext_flags, ext_hs_flags, ENC_NA, BMT_NO_APPEND);

    proto_tree_add_item(tree, hf_srt_srths_peer_latency, tvb, baseoff+8, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_srt_srths_agent_latency, tvb, baseoff+10, 2, ENC_BIG_ENDIAN);
}

static void srt_format_kmx(proto_tree* tree, tvbuff_t* tvb, int baseoff, int blocklen)
{
    if (blocklen == 4)
    {
        // Error report. Format as KMX state.
        proto_tree_add_item(tree, hf_srt_srtkm_error, tvb, baseoff, 4, ENC_NA);
    }
    else
    {
        proto_tree_add_item(tree, hf_srt_srtkm_msg, tvb, baseoff, blocklen, ENC_NA);
    }
}

// Wireshark dissector doesn't have a possibility to format enum-collected flags.
static void dissect_srt_hs_ext_field(proto_tree* tree,
        tvbuff_t* tvb, int baseoff)
{
    static const gint ext_field_len = 2;

    const int bits = tvb_get_ntohs(tvb, baseoff);
    if (bits == SRT_HS_V5_EXT_FIELD_MAGIC)
    {
        proto_item* pi = proto_tree_add_item(tree, hf_srt_handshake_ext_field_v5,
                                             tvb, baseoff, ext_field_len, ENC_BIG_ENDIAN);
        proto_item_append_text(pi, ": HSv5 MAGIC");
        return;
    }

    static int * const ext_hs_ext_field_flags[] = {
        &hf_srt_handshake_ext_field_v5_flag_hsreq,
        &hf_srt_handshake_ext_field_v5_flag_kmreq,
        &hf_srt_handshake_ext_field_v5_flag_config,
        NULL
    };

    proto_tree_add_bitmask_with_flags(tree, tvb, baseoff, hf_srt_handshake_ext_field_v5,
                                      ett_srt_handshake_ext_field_flags, ext_hs_ext_field_flags, ENC_NA, BMT_NO_APPEND);

    return;
}


static void format_text_reorder_32(proto_tree* tree, tvbuff_t* tvb, int hfinfo, int baseoff, int blocklen)
{
    wmem_strbuf_t *sid = wmem_strbuf_new(wmem_packet_scope(), "");
    for (int ii = 0; ii < blocklen; ii += 4)
    {
        const guint32 u = tvb_get_ntohl(tvb, baseoff + ii);
        wmem_strbuf_append_c(sid, 0xFF & (u >>  0));
        wmem_strbuf_append_c(sid, 0xFF & (u >>  8));
        wmem_strbuf_append_c(sid, 0xFF & (u >> 16));
        wmem_strbuf_append_c(sid, 0xFF & (u >> 24));
    }
    proto_tree_add_string(tree, hfinfo, tvb,
                          baseoff, blocklen, wmem_strbuf_get_str(sid));
}


/* Code to actually dissect the packets
 *
 */
static void
dissect_srt_control_packet(tvbuff_t *tvb, packet_info* pinfo,
                           proto_tree *tree, proto_item *srt_item)
{
    guint32 type    = 0;
    guint32 exttype = 0;

    proto_tree_add_item_ret_uint(tree, hf_srt_type, tvb, 0, 2,
                                 ENC_BIG_ENDIAN, &type);

    if ( type != UMSG_EXT )
        proto_tree_add_item(tree, hf_srt_exttype_none, tvb, 2, 2,
                            ENC_BIG_ENDIAN);
    else
        proto_tree_add_item_ret_uint(tree, hf_srt_exttype, tvb, 2, 2,
                                     ENC_BIG_ENDIAN, &exttype);

    switch (type)
    {
    case UMSG_EXT:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Control/ext: %s  socket: 0x%x",
                        val_to_str(exttype, srt_ctrlmsg_exttypes,
                                   "Unknown SRT Control Type (0x%x)"),
                        tvb_get_ntohl(tvb, 12));
        break;
    case UMSG_ACK:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Control: UMSG_ACK %d ackseq: %d  socket: 0x%x",
                        tvb_get_ntohl(tvb, 4),
                        tvb_get_ntohl(tvb, 16),
                        tvb_get_ntohl(tvb, 12));
        break;
    case UMSG_ACKACK:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Control: UMSG_ACKACK %d socket: 0x%x",
                        tvb_get_ntohl(tvb, 4),
                        tvb_get_ntohl(tvb, 12));
        break;
    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Control: %s  socket: 0x%x",
                        val_to_str(type, srt_ctrlmsg_types,
                                   "Unknown UDT Control Type (%x)"),
                        tvb_get_ntohl(tvb, 12));
        break;
    }

    switch (type)
    {
    case UMSG_ACK:
    case UMSG_ACKACK:
        proto_tree_add_item(tree, hf_srt_ackno, tvb, 4, 4,
                            ENC_BIG_ENDIAN);
        break;
    case UMSG_DROPREQ:
        proto_tree_add_item(tree, hf_srt_msgno, tvb, 4, 4,
                            ENC_BIG_ENDIAN);
        break;
    default:
        proto_tree_add_item(tree, hf_srt_addinfo, tvb, 4, 4,
                            ENC_BIG_ENDIAN);
        break;
    }
    proto_tree_add_item(tree, hf_srt_timestamp, tvb, 8, 4,
                        ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_srt_id, tvb, 12, 4,
                        ENC_BIG_ENDIAN);

    switch (type)
    {
    case UMSG_HANDSHAKE:
        {
            char ipbuf[IP_BUFFER_SIZE];

            const int version = tvb_get_ntohl(tvb, 16);
            const int final_length = tvb_reported_length(tvb);
            int baselen = 64;

            /* This contains the handshake version (currently 4 or 5) */
            proto_tree_add_item(tree, hf_srt_handshake_version, tvb,
                                16,  4, ENC_BIG_ENDIAN);

            /* Version 4 embraces both HSv4 listener URQ_INDUCTION response
             * and HSv5 caller URQ_INDUCTION request. In both these cases the
             * value is interpreted as socket type (UDT legacy). With version 5
             * the first message is the listener's URQ_INDUCTION response, where
             * the layout in the type is already the MAGIC in the lower block,
             * and ENC FLAGS in the upper block. The next caller's URQ_CONCLUSION
             * will have SRT HS Extension block flags in the lower block.
             */
            if (version == 4)
            {
                proto_tree_add_item(tree, hf_srt_handshake_type_v4, tvb,
                                    20,  4, ENC_BIG_ENDIAN);
            }
            else
            {
                /* Both the PBKEYLEN-ad and magic are used in HSv5 induction. */
                proto_tree_add_item(tree, hf_srt_handshake_enc_field_v5, tvb,
                                    20, 2, ENC_BIG_ENDIAN);

                dissect_srt_hs_ext_field(tree, tvb, 22);    /* 2 bytes */
            }

            proto_tree_add_item(tree, hf_srt_handshake_isn, tvb,
                        24,  4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_srt_handshake_mtu, tvb,
                        28,  4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_srt_handshake_flow_window, tvb,
                        32,  4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_srt_handshake_reqtype, tvb,
                        36,  4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_srt_handshake_id, tvb,
                        40,  4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_srt_handshake_cookie, tvb,
                        44,  4, ENC_BIG_ENDIAN);

            srt_format_ip_address(ipbuf, sizeof ipbuf, (const gchar *)tvb_memdup(wmem_packet_scope(), tvb, 48, 16));

            proto_tree_add_string(tree, hf_srt_handshake_peerip, tvb,
                                  48, 16, ipbuf);
            if (final_length > baselen)
            {
                /* Extract SRT handshake extension blocks
                    * and increase baselen accordingly.
                    */
                int begin = baselen;
                for (;;)
                {
                    const guint16 blockid  = tvb_get_ntohs(tvb, begin);
                    const guint16 blocklen = tvb_get_ntohs(tvb, begin + 2);

                    proto_tree_add_item(tree, hf_srt_srths_blocktype, tvb,
                                        begin, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_srt_srths_blocklen, tvb,
                                        begin+2, 2, ENC_BIG_ENDIAN);

                    // Shift to the payload
                    begin += 4;

                    switch (blockid)
                    {
                    case SRT_CMD_HSREQ:
                    case SRT_CMD_HSRSP:
                        if (blocklen == 3)
                        {
                            srt_format_hs_ext_hsreq(tree, tvb, begin);
                        }
                        else
                        {
                            /* blocklen should be 3, that corresponds to (3 * 4) = 12 bytes.
                             * Otherwise the format is unknown.*/
                            proto_tree_add_expert_format(tree, pinfo, &ei_srt_hs_ext_hsreq_len,
                                    tvb, begin, 4 * blocklen, "Actual length is %u",
                                    blocklen);
                        }
                        break;

                    case SRT_CMD_KMREQ:
                    case SRT_CMD_KMRSP:
                        // Rely on the extracted blocklen
                        srt_format_kmx(tree, tvb, begin, blocklen*4);
                        break;

                    case SRT_CMD_SID:
                        format_text_reorder_32(tree, tvb, hf_srt_srths_sid, begin, 4 * blocklen);
                        break;

                    case SRT_CMD_CONJESTCTRL:
                        format_text_reorder_32(tree, tvb, hf_srt_srths_conjestcontrol, begin, 4 * blocklen);
                        break;

                    default:
                        proto_tree_add_expert_format(tree, pinfo, &ei_srt_hs_ext_type,
                                    tvb, begin, 4 * blocklen, "Ext Type value is %u",
                                    blockid);
                        break;
                    }

                    /* Move the index pointer past the block and repeat. */
                    begin += blocklen * 4;

                    /* OK, once one block is done, interrupt the loop. */
                    if (begin >= final_length)
                        break;
                }

                baselen = begin;
            }

            proto_item_set_len(srt_item, baselen);
        }
        break;
    case UMSG_ACK:
        {
            guint len = tvb_reported_length(tvb);

            proto_tree_add_item(tree, hf_srt_ack_seqno, tvb, 4 * 4, 4,
                                ENC_BIG_ENDIAN);

            // Check for "Lite ACK" (size 4)
            if (len <= (4 + 1) * 4)
            {
                proto_item_set_len(srt_item, (4 + 1) * 4);
            }
            else
            {
                proto_tree_add_item(tree, hf_srt_rtt,      tvb, (4+1)*4, 4,
                                    ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_srt_rttvar,   tvb, (4+2)*4, 4,
                                    ENC_BIG_ENDIAN);
                proto_tree_add_item(tree, hf_srt_bufavail, tvb, (4+3)*4, 4,
                                    ENC_BIG_ENDIAN);
                /* if not a light ack, decode the rate and link capacity */

                if (len > (4 + 4) * 4)
                {
                    proto_tree_add_item(tree, hf_srt_rate, tvb, (4 + 4) * 4, 4, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tree, hf_srt_bandwidth, tvb, (4 + 5) * 4, 4, ENC_BIG_ENDIAN);

                    // SRT Extra data. This can be version dependent, so
                    // test the length for each field.
                    if (len > (4 + 6) * 4)
                    {
                        proto_tree_add_item(tree, hf_srt_rcvrate, tvb, (4 + 6) * 4, 4, ENC_BIG_ENDIAN);
                        len = (4 + 7) * 4;
                    }

                    proto_item_set_len(srt_item, (gint) len);
                }
                else
                {
                    proto_item_set_len(srt_item, (4 + 4) * 4);
                }
            }
        }
        break;
    case UMSG_LOSSREPORT:
        {
            guint len = tvb_reported_length(tvb);
            guint pos;
            guint32 val;
            guint prev = 0;
            for (pos = 16; pos < len; pos += 4)
            {
                val = tvb_get_ntohl(tvb, pos);
                if (val & SRT_LOSS_SEQUENCE_FIRST) {
                    // Remember this as a beginning range
                    prev = val;
                    continue;
                }

                // We have either a single value, or end-range here.
                if (prev & SRT_LOSS_SEQUENCE_FIRST) {
                    // Was a range. Display as range and clear the state.
                    proto_tree_add_expert_format(tree, pinfo, &ei_srt_nak_seqno,
                                    tvb, pos-4, 8, "Loss sequence range: %u-%u",
                                    (prev & SRT_LOSS_SEQUENCE_MASK), val);
                    prev = 0;
                } else {
                    // No from, so this is a freestanding loss value
                    proto_tree_add_expert_format(tree, pinfo, &ei_srt_nak_seqno,
                                    tvb, pos, 4, "Loss sequence: %u", val);
                }
            }

            // Report possible errors
            if (prev)
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_srt_nak_seqno,
                                tvb, pos-4, 4, "ERROR: loss sequence range begin only: %u (%x)",
                                val & SRT_LOSS_SEQUENCE_MASK, val);
            }

            proto_item_set_len(srt_item, len);
        }
        break;

    case UMSG_EXT:
        switch (exttype)
        {
        case SRT_CMD_HSREQ:
        case SRT_CMD_HSRSP:
            srt_format_hs_ext_hsreq(tree, tvb, 16);
            break;

        case SRT_CMD_KMREQ:
        case SRT_CMD_KMRSP:
            {
                // This relies on value of HCRYPT_MSG_KM_MAX_SZ resulting from this above.
                // Too strongly dependent on devel API, so using explicit 104.
                int plen = tvb_reported_length(tvb) - 16;
                if (plen > 104)
                    plen = 104;
                srt_format_kmx(tree, tvb, 16, plen);
            }
            break;

        default:
            break;
        }
        break;

    default:
            // All other types have kinda "extra padding"
        proto_tree_add_item(tree, hf_srt_addinfo, tvb, 16, 4, ENC_BIG_ENDIAN);
        break;
    }
}


/* Code to actually dissect the packets
 *
 * @return the amount of data this dissector was able to dissect
 */
static int
dissect_srt_udp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *parent_tree,
                void *data _U_)
{
    /* Other misc. local variables. */
    gboolean is_control = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SRT");
    col_clear  (pinfo->cinfo, COL_INFO);

    proto_item *srt_item = proto_tree_add_item(parent_tree, proto_srt, tvb,
                                   0 /*start*/, -1 /*length*/, ENC_NA);
    proto_tree *tree = proto_item_add_subtree(srt_item, ett_srt);
    proto_tree_add_item_ret_boolean(tree, hf_srt_iscontrol, tvb, 0, 4, ENC_BIG_ENDIAN, &is_control);

    if (is_control)
    {
        dissect_srt_control_packet(tvb, pinfo, tree, srt_item);
    }
    else
    {
        /* otherwise, a data packet */
        tvbuff_t *next_tvb;

        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "DATA: seqno: %u  msgno: %u  socket: 0x%x",
                     tvb_get_ntohl(tvb, 0),
                     tvb_get_ntohl(tvb, 4) & SRT_MSGNO_MSGNO_MASK,
                     tvb_get_ntohl(tvb, 12));

        if (tree)
        {
            // Sequence number
            proto_tree_add_item(tree, hf_srt_seqno, tvb, 0, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(tree, hf_srt_msgno_pb, tvb, 4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_srt_msgno_inorder, tvb, 4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_srt_msgno_enctypes, tvb, 4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_srt_msgno_rexmit, tvb, 4, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_srt_msgno, tvb, 4, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(tree, hf_srt_timestamp, tvb, 8, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_srt_id,        tvb, 12, 4, ENC_BIG_ENDIAN);

        }

        next_tvb = tvb_new_subset_remaining(tvb, 16);
        call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_reported_length(tvb);
}


static gboolean
dissect_srt_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t *conv;

    /* Must have at least 24 captured bytes for heuristic check */
    if (tvb_captured_length(tvb) < 24)
        return FALSE;

    /* detect handshake control packet */
    if (tvb_get_ntohl(tvb, 0) != (0x80000000 | UMSG_HANDSHAKE))
        return FALSE;

    /* must be version 4 or 5*/
    const guint32 version = tvb_get_ntohl(tvb, 16);
    if (version != 4 && version != 5)
        return FALSE;

    /* SRT: must be DGRAM. STREAM is not supported in SRT */
    if (version == 4 && tvb_get_ntohl(tvb, 20) != SRT_DGRAM)
        return FALSE;

    conv = find_or_create_conversation(pinfo);
    conversation_set_dissector(conv, srt_udp_handle);
    dissect_srt_udp(tvb, pinfo, tree, data);

    return TRUE;
}


/* Register the protocol with Wireshark.
 *
 * This format is required because a script is used to build the C function that
 * calls all the protocol registration.
 */
void proto_register_srt(void)
{
    expert_module_t *expert_srt;

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        {&hf_srt_iscontrol, {
            "Content", "srt.iscontrol",
            FT_BOOLEAN, 32,
            TFS(&srt_packet_types), 0x80000000, NULL, HFILL }},

        {&hf_srt_type, {
            "Msg Type", "srt.type",
            FT_UINT16, BASE_HEX,
            VALS(srt_ctrlmsg_types), 0x7fff, NULL, HFILL}},

        {&hf_srt_exttype, {
            "Extended type", "srt.exttype",
            FT_UINT16, BASE_HEX,
            VALS(srt_ctrlmsg_exttypes), 0, NULL, HFILL}},

        {&hf_srt_exttype_none, {
            "(no extended type)", "srt.exttype_none",
            FT_UINT16, BASE_HEX,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_seqno, {
            "Sequence Number", "srt.seqno",
            FT_UINT32, BASE_DEC,
            NULL, SRT_CONTROL_MASK, NULL, HFILL}},

        {&hf_srt_addinfo, {
            "(Unused)", "srt.addinfo",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_msgno, {
            "Message Number", "srt.msgno",
            FT_UINT32, BASE_DEC,
            NULL, SRT_MSGNO_MSGNO_MASK, NULL, HFILL}},

        {&hf_srt_msgno_pb, {
            "Packet Boundary", "srt.pb",
                FT_UINT32, BASE_DEC,
            VALS(srt_pb_types), SRT_MSGNO_FF_MASK, NULL, HFILL}},

        {&hf_srt_msgno_inorder, {
            "In-Order Indicator", "srt.msg.order",
            FT_UINT32, BASE_DEC,
            NULL, SRT_MSGNO_INORDER, NULL, HFILL}},

        {&hf_srt_msgno_enctypes, {
            "Encryption Status", "srt.msg.enc",
            FT_UINT32, BASE_DEC,
            VALS(srt_msgno_enctypes), SRT_MSGNO_ENCTYPE, NULL, HFILL }},

        {&hf_srt_msgno_rexmit, {
            "Sent as", "srt.msg.rexmit",
            FT_BOOLEAN, 32,
            TFS(&srt_msgno_rexmit), SRT_MSGNO_REXMIT, NULL, HFILL }},

        {&hf_srt_timestamp, {
            "Time Stamp", "srt.timestamp",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_id, {
            "Destination Socket ID", "srt.id",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_ack_seqno, {
            "ACKD_RCVLASTACK", "srt.ack_seqno",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_ackno, {
            "Ack Number", "srt.ackno",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_rtt, {
            "ACKD_RTT", "srt.rtt",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING,
            &units_microseconds, 0, NULL, HFILL}},

        {&hf_srt_rttvar, {
            "ACKD_RTTVAR", "srt.rttvar",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING,
            &units_microseconds, 0, NULL, HFILL}},

        {&hf_srt_bufavail, {
            "ACKD_BUFFERLEFT", "srt.bufavail",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING,
            &units_pkts, 0, NULL, HFILL}},

        {&hf_srt_rate, {
            "ACKD_RCVSPEED", "srt.rate",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING,
            &units_pkts_per_sec, 0, NULL, HFILL}},

        {&hf_srt_bandwidth, {
            "ACKD_BANDWIDTH", "srt.bw",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING,
            &units_pkts_per_sec, 0, NULL, HFILL}},

        {&hf_srt_rcvrate, {
            "ACKD_RCVRATE", "srt.rcvrate",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING,
            &units_byte_bytespsecond, 0, NULL, HFILL}},

        {&hf_srt_handshake_version, {
            "Handshake Version", "srt.hs.version",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_handshake_type_v4, {
            "(Legacy) Socket type", "srt.hs.socktype",
            FT_UINT32, BASE_DEC,
            VALS(srt_hsv4_socket_types), 0, NULL,
            HFILL}},

        {&hf_srt_handshake_enc_field_v5, {
            "Encryption Field", "srt.hs.encfield",
            FT_UINT16, BASE_HEX,
            VALS(srt_handshake_enc_field), 0, NULL,
            HFILL}},

        {&hf_srt_handshake_ext_field_v5, {
            "Extended Field", "srt.hs.extfield",
            FT_UINT16, BASE_HEX,
            NULL, 0, NULL,
            HFILL}},

        {&hf_srt_handshake_ext_field_v5_flag_hsreq, {
            "HS_EXT_FIELD_HSREQ", "srt.hs.extfield.hsreq",
            FT_BOOLEAN, SRT_HS_V5_EXT_FIELD_LEN, TFS(&tfs_set_notset),
            SRT_HS_V5_EXT_FIELD_HSREQ,
            "Handshake request",
            HFILL}},

        {&hf_srt_handshake_ext_field_v5_flag_kmreq, {
            "HS_EXT_FIELD_KMREQ", "srt.hs.extfield.kmreq",
            FT_BOOLEAN, SRT_HS_V5_EXT_FIELD_LEN, TFS(&tfs_set_notset),
            SRT_HS_V5_EXT_FIELD_KMREQ,
            "KM request",
            HFILL}},

        {&hf_srt_handshake_ext_field_v5_flag_config, {
            "HS_EXT_FIELD_CONFIG", "srt.hs.extfield.config",
            FT_BOOLEAN, SRT_HS_V5_EXT_FIELD_LEN, TFS(&tfs_set_notset),
            SRT_HS_V5_EXT_FIELD_CONFIG,
            "Handshake has configuration",
            HFILL}},

        {&hf_srt_handshake_isn, {
            "Initial Sequence Number", "srt.hs.isn",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_handshake_mtu, {
            "MTU", "srt.hs.mtu",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_handshake_flow_window, {
            "Flow Window", "srt.hs.flow_window",
            FT_UINT32, BASE_DEC,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_handshake_reqtype, {
            "Handshake Type", "srt.hs.reqtype",
            FT_INT32, BASE_DEC,
            VALS(srt_hs_request_types), 0, NULL, HFILL}},

        {&hf_srt_handshake_id, {
            "Socket ID", "srt.hs.id",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_handshake_cookie, {
            "SYN Cookie", "srt.hs.cookie",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL}},
        {&hf_srt_handshake_peerip, {
            /* FT_STRINGZ is used because the value
             * is formatted to a temporary buffer first */
            "Peer IP Address", "srt.hs.peerip",
            FT_STRINGZ, BASE_NONE,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_handshake_ext_version, {
            "SRT Version", "srt.hs.version",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_handshake_ext_flags, {
            /* This uses custom format by appending the flag format string,
             * while the value in hex is still printed. */
            "SRT Flags", "srt.hs.srtflags",
            FT_UINT32, BASE_HEX,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_handshake_ext_flag_tsbpd_snd, {
            "TSBPDSND", "srt.hs.srtflags.tsbpd_snd",
            FT_BOOLEAN, SRT_OPT_FIELD_LEN, TFS(&tfs_set_notset),
            SRT_OPT_TSBPDSND,
            "The party will be sending in TSBPD (Time Stamp Based Packet Delivery) mode",
            HFILL}},

        {&hf_srt_handshake_ext_flag_tsbpd_rcv, {
            "TSBPDRCV", "srt.hs.srtflags.tsbpd_rcv",
            FT_BOOLEAN, SRT_OPT_FIELD_LEN, TFS(&tfs_set_notset),
            SRT_OPT_TSBPDRCV,
            "The party expects to receive in TSBPD (Time Stamp Based Packet Delivery) mode",
            HFILL}},

        {&hf_srt_handshake_ext_flag_haicrypt, {
            "HAICRYPT", "srt.hs.srtflags.haicrypt",
            FT_BOOLEAN, SRT_OPT_FIELD_LEN, TFS(&tfs_set_notset),
            SRT_OPT_HAICRYPT,
            "The party includes haicrypt (legacy flag)",
            HFILL}},

        {&hf_srt_handshake_ext_flag_tlpkt_drop, {
            "TLPKTDROP", "srt.hs.srtflags.tlpkt_drop",
            FT_BOOLEAN, SRT_OPT_FIELD_LEN, TFS(&tfs_set_notset),
            SRT_OPT_TLPKTDROP,
            "The party will do the Too-Late Packet Drop",
            HFILL}},

        {&hf_srt_handshake_ext_flag_nak_report, {
            "NAKREPORT", "srt.hs.srtflags.nak_report",
            FT_BOOLEAN, SRT_OPT_FIELD_LEN, TFS(&tfs_set_notset),
            SRT_OPT_NAKREPORT,
            "The party will do periodic NAK reporting",
            HFILL}},

        {&hf_srt_handshake_ext_flag_rexmit, {
            "REXMITFLG", "srt.hs.srtflags.rexmit",
            FT_BOOLEAN, SRT_OPT_FIELD_LEN, TFS(&tfs_set_notset),
            SRT_OPT_REXMITFLG,
            "The party uses the REXMIT flag",
            HFILL}},

        {&hf_srt_handshake_ext_flag_stream, {
            "STREAM", "srt.hs.srtflags.stream",
            FT_BOOLEAN, SRT_OPT_FIELD_LEN, TFS(&tfs_set_notset),
            SRT_OPT_STREAM,
            "The party uses stream type transmission",
            HFILL}},

        {&hf_srt_srths_blocktype, {
            "SRT HS Extension type", "srt.hs.blocktype",
            FT_UINT16, BASE_HEX,
            VALS(srt_ctrlmsg_exttypes), 0, NULL, HFILL}},

        {&hf_srt_srths_blocklen, {
            "SRT HS Extension size (4-byte blocks)", "srt.hs.blocklen",
            FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_srths_agent_latency, {
            "Latency", "srt.hs.agent_latency",
            FT_UINT16, BASE_DEC | BASE_UNIT_STRING,
            &units_milliseconds, 0, NULL, HFILL}},

        {&hf_srt_srths_peer_latency, {
            "Peer Latency", "srt.hs.peer_latency",
            FT_UINT16, BASE_DEC | BASE_UNIT_STRING,
            &units_milliseconds, 0, NULL, HFILL}},

        {&hf_srt_srtkm_msg, {
            "KMX Message (or KM State if 4 bytes)", "srt.km.msg",
            FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_srtkm_error, {
            "KM State", "srt.km.error",
            FT_UINT32, BASE_DEC,
            VALS(srt_enc_kmstate), 0, NULL, HFILL}},

        {&hf_srt_srths_sid, {
            "Stream ID", "srt.hs.sid",
            FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL}},

        {&hf_srt_srths_conjestcontrol, {
            "Congestion Control Type", "srt.hs.conjestctrl",
            FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL}}
    };

    static gint *ett[] = {
        &ett_srt,
        &ett_srt_handshake_ext_flags,
        &ett_srt_handshake_ext_field_flags
    };

    static ei_register_info ei[] = {
        { &ei_srt_nak_seqno,
            { "srt.nak_seqno", PI_SEQUENCE, PI_NOTE,
              "Missing Sequence Number(s)", EXPFILL }},

        { &ei_srt_hs_ext_hsreq_len,
            { "srt.hs.ext.hsreq", PI_PROTOCOL, PI_WARN,
              "Unknown HS Ext HSREQ length", EXPFILL }},

        { &ei_srt_hs_ext_type,
            { "srt.hs.ext.type", PI_PROTOCOL, PI_WARN,
              "Unknown HS Ext Type", EXPFILL }},
    };

    proto_srt = proto_register_protocol("SRT Protocol", "SRT", "srt");
    proto_register_field_array(proto_srt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_srt = expert_register_protocol(proto_srt);
    expert_register_field_array(expert_srt, ei, array_length(ei));

    register_dissector("srt", dissect_srt_udp, proto_srt);
}


void proto_reg_handoff_srt(void)
{
    srt_udp_handle  = create_dissector_handle(dissect_srt_udp, proto_srt);

    /* register as heuristic dissector for UDP */
    heur_dissector_add("udp", dissect_srt_heur_udp, "SRT over UDP",
                       "srt_udp", proto_srt, HEURISTIC_ENABLE);

    /* Add a handle to the list of handles that *could* be used with this
       table.  That list is used by the "Decode As"/"-d" code in the UI. */
    dissector_add_for_decode_as("udp.port", srt_udp_handle);
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
