/* packet-iperf3.c
 *
 * Routines for iPerf3 dissection
 * by Daniel Mendes <dmendes@redhat.com>,
 * Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * loosely based off iPerf2 dissector
 * by Anish Bhatt <anish@gatech.edu>
 * and the iperf3 source code at
 * https://github.com/esnet/iperf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <wireshark.h>
#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/wmem_scopes.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>

/* From iperf3 source code src/iperf_api.h */
#define TEST_START 1
#define TEST_RUNNING 2
#define RESULT_REQUEST 3 /* not used */
#define TEST_END 4
#define STREAM_BEGIN 5 /* not used */
#define STREAM_RUNNING 6 /* not used */
#define STREAM_END 7 /* not used */
#define ALL_STREAMS_END 8 /* not used */
#define PARAM_EXCHANGE 9
#define CREATE_STREAMS 10
#define SERVER_TERMINATE 11
#define CLIENT_TERMINATE 12
#define EXCHANGE_RESULTS 13
#define DISPLAY_RESULTS 14
#define IPERF_START 15
#define IPERF_DONE 16
#define ACCESS_DENIED (-1)
#define SERVER_ERROR (-2)

typedef enum
{
    INIT,
    GENERIC_STATE,
    PARAM_EXCHANGE_LENGTH,
    PARAM_EXCHANGE_JSON,
    EXCHANGE_RESULTS_LENGTH_1,
    EXCHANGE_RESULTS_JSON_1,
    EXCHANGE_RESULTS_LENGTH_2,
    EXCHANGE_RESULTS_JSON_2,
    DATA
} pdu_sequence;

void proto_register_iperf3(void);
void proto_reg_handoff_iperf3(void);

static int proto_iperf3;

static int hf_iperf3_sequence;
static int hf_iperf3_sec;
static int hf_iperf3_usec;
static int hf_iperf3_udp_init_msg;
static int hf_iperf3_state;
static int hf_iperf3_prejson;
static int hf_iperf3_cookie;

static int ett_iperf3;
static int ett_time;

static dissector_handle_t iperf3_handle_tcp;
static dissector_handle_t iperf3_handle_udp;
static dissector_handle_t json_handle;

static const value_string iperf3_state_vals[] = {
    { TEST_START,       "TEST_START" },
    { TEST_RUNNING,     "TEST_RUNNING" },
    { RESULT_REQUEST,   "RESULT_REQUEST" },
    { TEST_END,         "TEST_END" },
    { STREAM_BEGIN,     "STREAM_BEGIN" },
    { STREAM_RUNNING,   "STREAM_RUNNING" },
    { STREAM_END,       "STREAM_END" },
    { ALL_STREAMS_END,  "ALL_STREAMS_END" },
    { PARAM_EXCHANGE,   "PARAM_EXCHANGE" },
    { CREATE_STREAMS,   "CREATE_STREAMS" },
    { SERVER_TERMINATE, "SERVER_TERMINATE" },
    { CLIENT_TERMINATE, "CLIENT_TERMINATE" },
    { EXCHANGE_RESULTS, "EXCHANGE_RESULTS" },
    { DISPLAY_RESULTS,  "DISPLAY_RESULTS" },
    { IPERF_START,      "IPERF_START" },
    { IPERF_DONE,       "IPERF_DONE" },
    { ACCESS_DENIED,    "ACCESS_DENIED" },
    { SERVER_ERROR,     "SERVER_ERROR" },
    { 0, NULL }
};

/* TCP conversation */
typedef struct
{
    bool control_connection;
    // Ephemeral packet data
    unsigned pdu_size;
    pdu_sequence sequence;
} iperf3_tcp_conversation_data;

typedef struct
{
    unsigned pdu_size;
    pdu_sequence sequence;
} iperf3_tcp_packet_data;

/* UDP out-of-order tracking */
typedef struct {
    uint64_t prev_seq_no;
    wmem_map_t *out_of_order;
} udp_conversation_data;

static void udp_detect_and_report_out_of_order(packet_info *, proto_item *, uint64_t);
static udp_conversation_data *udp_set_conversation_data(packet_info *);


/* protocol preferences */
static bool iperf3_pref_64bit_seq_no;
static bool iperf3_pref_detect_udp_order = true;
/* expert info */
static expert_field ei_udp_out_of_order;

#define IPERF3_UDP_HDR_SIZE 12
#define COOKIE_SIZE 37

#define IPERF3_INIT_UDP_MSG_SIZE 4

#define UDP_CONNECT_MSG 0x36373839              // iperf3 doesn't htonl() convert either
#define UDP_CONNECT_REPLY 0x39383736            // the MSG or REPLY so we must accept
#define LEGACY_UDP_CONNECT_MSG 0x075bcd15       // accept either endian representation.
#define LEGACY_MSG_OPPOSITE_ENDIAN 0x15cd5b07   // luckily current msg and reply are
#define LEGACY_UDP_CONNECT_REPLY 0x3ade68b1     // already opposites. this is also why
#define LEGACY_REPLY_OPPOSITE_ENDIAN 0xb168de3a // we can't distinguish msg from reply


#define DEFINE_CONTROL_PREFACE(protocol)                                \
    static void col_info_preface_##protocol(packet_info *pinfo)         \
    {                                                                   \
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "iPerf3");              \
        col_clear(pinfo->cinfo, COL_INFO);                              \
        col_append_ports(pinfo->cinfo, COL_INFO, PT_##protocol,         \
                            pinfo->srcport, pinfo->destport);           \
    }

DEFINE_CONTROL_PREFACE(TCP) /* invoke as col_info_preface_TCP(pinfo) */
DEFINE_CONTROL_PREFACE(UDP) /* invoke as col_info_preface_UDP(pinfo) */

// Collection of cookies used to differentiate between control and data connections.
// See dissect_iperf3_tcp() for details.
static wmem_map_t *cookiejar;

static int
dissect_iperf3_control_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    iperf3_tcp_conversation_data *conversation_data = (iperf3_tcp_conversation_data *)data;

    proto_item *ti          = proto_tree_add_item(tree, proto_iperf3, tvb, 0, -1, ENC_NA);
    proto_tree *iperf3_tree = proto_item_add_subtree(ti, ett_iperf3);

    switch (conversation_data->sequence)
    {
        // ------
        case INIT:
        {
            const uint8_t *cookie;
            proto_tree_add_item_ret_string(iperf3_tree, hf_iperf3_cookie, tvb, 0, COOKIE_SIZE,
                                                        ENC_ASCII, pinfo->pool, &cookie);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Cookie: \"%s\"", cookie);

            conversation_data->pdu_size = 1;
            conversation_data->sequence = GENERIC_STATE;
            break;
        }
        case GENERIC_STATE:
        {
            int8_t state_code = tvb_get_int8(tvb, 0);
            const char *msg = val_to_str(state_code, iperf3_state_vals, "Unknown %d");
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s(%" PRIi8 ")", msg, state_code);
            col_set_fence(pinfo->cinfo, COL_INFO);
            proto_tree_add_item(iperf3_tree, hf_iperf3_state, tvb, 0, 1, ENC_BIG_ENDIAN);

            switch (state_code)
            {
                case PARAM_EXCHANGE:
                    conversation_data->pdu_size = 4;
                    conversation_data->sequence = PARAM_EXCHANGE_LENGTH;
                    break;
                case EXCHANGE_RESULTS:
                    conversation_data->pdu_size = 4;
                    conversation_data->sequence = EXCHANGE_RESULTS_LENGTH_1;
                    break;
                default:
                    break;
            }
            break;
        }
        // ------
        case PARAM_EXCHANGE_LENGTH:
        {
            uint32_t json_size = tvb_get_uint32(tvb, 0, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO,
                " Next message is JSON of this length: %" PRIu32 "", json_size);
            proto_tree_add_item(iperf3_tree, hf_iperf3_prejson, tvb, 0, 4, ENC_BIG_ENDIAN);

            conversation_data->pdu_size = json_size;
            conversation_data->sequence = PARAM_EXCHANGE_JSON;
            break;
        }
        case PARAM_EXCHANGE_JSON:
        {
            uint32_t nbytes = tvb_reported_length(tvb);
            uint8_t *buffer = tvb_get_string_enc(pinfo->pool, tvb, 0, (int)nbytes, ENC_UTF_8);
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", buffer);
            call_dissector(json_handle, tvb, pinfo, iperf3_tree);

            conversation_data->pdu_size = 1;
            conversation_data->sequence = GENERIC_STATE;
            break;
        }
        // ------
        case EXCHANGE_RESULTS_LENGTH_1:
        {
            uint32_t json_size = tvb_get_uint32(tvb, 0, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO,
                " Next message is JSON of this length: %" PRIu32 "", json_size);
            proto_tree_add_item(iperf3_tree, hf_iperf3_prejson, tvb, 0, 4, ENC_BIG_ENDIAN);

            conversation_data->pdu_size = json_size;
            conversation_data->sequence = EXCHANGE_RESULTS_JSON_1;
            break;
        }
        case EXCHANGE_RESULTS_JSON_1:
        {
            uint32_t nbytes = tvb_reported_length(tvb);
            uint8_t *buffer = tvb_get_string_enc(pinfo->pool, tvb, 0, (int)nbytes, ENC_UTF_8);
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", buffer);
            call_dissector(json_handle, tvb, pinfo, iperf3_tree);

            conversation_data->pdu_size = 4;
            conversation_data->sequence = EXCHANGE_RESULTS_LENGTH_2;
            break;
        }
        case EXCHANGE_RESULTS_LENGTH_2:
        {
            uint32_t json_size = tvb_get_uint32(tvb, 0, ENC_BIG_ENDIAN);
            col_append_fstr(pinfo->cinfo, COL_INFO,
                " Next message is JSON of this length: %" PRIu32 "", json_size);
            proto_tree_add_item(iperf3_tree, hf_iperf3_prejson, tvb, 0, 4, ENC_BIG_ENDIAN);

            conversation_data->pdu_size = json_size;
            conversation_data->sequence = EXCHANGE_RESULTS_JSON_2;
            break;
        }
        case EXCHANGE_RESULTS_JSON_2:
        {
            uint32_t nbytes = tvb_reported_length(tvb);
            uint8_t *buffer = tvb_get_string_enc(pinfo->pool, tvb, 0, (int)nbytes, ENC_UTF_8);
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s", buffer);
            call_dissector(json_handle, tvb, pinfo, iperf3_tree);

            conversation_data->pdu_size = 1;
            conversation_data->sequence = GENERIC_STATE;
            break;
        }
        // ------
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    return tvb_reported_length(tvb);
}

static int
dissect_iperf3_data_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    iperf3_tcp_conversation_data *conversation_data = (iperf3_tcp_conversation_data *)data;

    proto_item *ti          = proto_tree_add_item(tree, proto_iperf3, tvb, 0, -1, ENC_NA);
    proto_tree *iperf3_tree = proto_item_add_subtree(ti, ett_iperf3);

    switch (conversation_data->sequence)
    {
        case INIT:
        {
            const uint8_t *cookie;
            proto_tree_add_item_ret_string(iperf3_tree, hf_iperf3_cookie, tvb, 0, COOKIE_SIZE,
                                                        ENC_ASCII, pinfo->pool, &cookie);
            col_info_preface_TCP(pinfo);
            col_append_fstr(pinfo->cinfo, COL_INFO, " Cookie: \"%s\"", cookie);

            conversation_data->pdu_size = 0;  // The whole TVBuff
            conversation_data->sequence = DATA;
            break;
        }
        case DATA:
        {
            call_data_dissector(tvb, pinfo, tree);
            break;
        }
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    return tvb_reported_length(tvb);
}

static unsigned
get_iperf3_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb _U_, int offset _U_, void *data)
{
    iperf3_tcp_conversation_data *conversation_data = (iperf3_tcp_conversation_data *)data;

    return conversation_data->pdu_size ? conversation_data->pdu_size : tvb_reported_length(tvb);
}

static int
dissect_iperf3_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /*
     * Determine control connection for *any* packet
     *
     * - Get the conversation data
     * - If present, retrieve control connection status
     * - If missing, determine as follows:
     *   - Take cookie from the packet (which is assumed to be first in the data packet)
     *   - Lookup cookie in cookiejar
     *   - If cookie present in jar, this is not a control connection
     *   - If cookie abssent from jar, this is a control connection
     *     - Add cookie to jar
     *   - Create conversation data
     */

    uint8_t cookie[COOKIE_SIZE];

    iperf3_tcp_conversation_data *conversation_data = conversation_get_proto_data(find_conversation_pinfo(pinfo, 0), proto_iperf3);
    iperf3_tcp_packet_data       *packet_data       = p_get_proto_data(wmem_file_scope(), pinfo, proto_iperf3, 0);

    if (!conversation_data) {
        conversation_data = wmem_new0(wmem_file_scope(), iperf3_tcp_conversation_data);
        conversation_data->control_connection = false;
        // Data required for PDU determination
        conversation_data->pdu_size = COOKIE_SIZE;
        conversation_data->sequence = INIT;

        if (tvb_get_raw_bytes_as_stringz(tvb, 0, COOKIE_SIZE, cookie) == COOKIE_SIZE-1) {
            if (!wmem_map_contains(cookiejar, cookie)) {
                // This is a new control connection (or a data connection for which the control connection has not been seen, fail)
                char *cookie_save = wmem_strndup(wmem_file_scope(), cookie, COOKIE_SIZE);
                if (wmem_map_insert(cookiejar, cookie_save, NULL)) {  // No value to store, only the cookie
                    // We insert a new cookie in the jar, which now says there's already one.
                    DISSECTOR_ASSERT_NOT_REACHED();
                }
                conversation_data->control_connection = true;
            }
        }

        conversation_add_proto_data(find_conversation_pinfo(pinfo, 0), proto_iperf3, conversation_data);
    }

    /*
     * Determine the first PDU for *any* packet
     *
     * - If the packet has not been seen before, take PDU size and sequence from the conversation.
     *   (This either comes from a newly initialized conversation, or from
     *    the completion of the dissection of the payload of the previously dissected TCP packet.)
     *   - Store the PDU size and sequence with the packet.
     * - If the packet was seen before, take the PDU size and sequence from the stored packet data
     *   and store it with the conversation.
     *   (This guarantees that the PDU size and sequence for this particular packet is available,
     *    even if dissected out of order.)
     * - Call the dissection function with the conversation data, which is relevant for the
     *   current TCP payload.
     */

    if (!PINFO_FD_VISITED(pinfo)) {
        packet_data = wmem_new0(wmem_file_scope(), iperf3_tcp_packet_data);
        packet_data->pdu_size = conversation_data->pdu_size;
        packet_data->sequence = conversation_data->sequence;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_iperf3, 0, packet_data);
    } else {
        DISSECTOR_ASSERT(packet_data);

        conversation_data->pdu_size = packet_data->pdu_size;
        conversation_data->sequence = packet_data->sequence;
    }

    if (conversation_data->control_connection) {
        col_info_preface_TCP(pinfo);
        tcp_dissect_pdus(tvb, pinfo, tree, false, 1, get_iperf3_pdu_len, dissect_iperf3_control_pdu, conversation_data);
    } else {
        dissect_iperf3_data_pdu(tvb, pinfo, tree, conversation_data);
    }

    return tvb_reported_length(tvb);
}

static int
dissect_iperf3_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *iperf3_tree, *time_tree;
    uint32_t offset = 0;
    uint32_t nbytes = tvb_reported_length(tvb);

    uint64_t maybe_sequence_num;

    /************** UDP CONTROL *****************/
    if (nbytes == IPERF3_INIT_UDP_MSG_SIZE)
    {
        /* Due to the fact that UDP_CONNECT_MSG and UDP_CONNECT_REPLY are each others
           reverse it does not matter which endianness is used. */
        uint32_t init_cxn_msg = tvb_get_uint32(tvb, offset, ENC_HOST_ENDIAN);
        if (init_cxn_msg != UDP_CONNECT_MSG &&
                init_cxn_msg != UDP_CONNECT_REPLY &&
                init_cxn_msg != LEGACY_UDP_CONNECT_MSG &&
                init_cxn_msg != LEGACY_MSG_OPPOSITE_ENDIAN &&
                init_cxn_msg != LEGACY_UDP_CONNECT_REPLY &&
                init_cxn_msg != LEGACY_REPLY_OPPOSITE_ENDIAN)
            return 0;
        col_info_preface_UDP(pinfo);
        col_append_str(pinfo->cinfo, COL_INFO, " Establishing UDP connection...");

        ti = proto_tree_add_item(tree, proto_iperf3, tvb, offset, -1, ENC_NA);
        iperf3_tree = proto_item_add_subtree(ti, ett_iperf3);
        proto_tree_add_item(iperf3_tree, hf_iperf3_udp_init_msg, tvb, offset, 4, ENC_BIG_ENDIAN);

        return IPERF3_INIT_UDP_MSG_SIZE;
    }

    /************** UDP DATA ********************/

    if (tvb_reported_length(tvb) < IPERF3_UDP_HDR_SIZE)
        return 0;

    col_info_preface_UDP(pinfo);
    ti = proto_tree_add_item(tree, proto_iperf3, tvb, offset, -1, ENC_NA);
    iperf3_tree = proto_item_add_subtree(ti, ett_iperf3);

    time_tree = proto_tree_add_subtree(iperf3_tree, tvb, offset, 8, ett_time, &ti, "");

    int32_t seconds;
    uint32_t useconds;

    proto_tree_add_item_ret_int(time_tree, hf_iperf3_sec, tvb, offset, 4, ENC_BIG_ENDIAN, &seconds);
    offset += 4;
    proto_tree_add_item_ret_uint(time_tree, hf_iperf3_usec, tvb, offset, 4, ENC_BIG_ENDIAN, &useconds);
    offset += 4;

    proto_item_set_text(ti, "Time Sent: %.7f seconds", seconds + (useconds / 1000000.0));
    /* empirically: no precision below 7 digits */

    /* let users choose if they're using 64 bit sequence numbers, but still want sensible
        default... so we detect if the top 32 bits are all zero. if so then they must
        be using 64 bit numbers regardless */
    maybe_sequence_num = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
    if (iperf3_pref_64bit_seq_no || maybe_sequence_num == 0) {
        proto_tree_add_item_ret_uint64(iperf3_tree, hf_iperf3_sequence, tvb, offset, 8, ENC_BIG_ENDIAN, &maybe_sequence_num);
        offset += 8;
    } else {
        proto_tree_add_item(iperf3_tree, hf_iperf3_sequence, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, " [%" PRIu64 "] Time sent=%.7f length=%" PRIu32 " bytes",
        maybe_sequence_num, seconds + (useconds / 1000000.0), nbytes);

    if (iperf3_pref_detect_udp_order)
        udp_detect_and_report_out_of_order(pinfo, ti, maybe_sequence_num);

    tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, tree); /* deals with payload size = 0
                                 which happens with -l=16 and --udp-64bit-sequence number */

    return nbytes;
}

static void
udp_detect_and_report_out_of_order(packet_info *pinfo, proto_item *ti, uint64_t sequence_num)
{
    /*  Record out of order packets by keeping a per-conversation set of
        lost packets. The first time the packets are dissected we add them to the set
        based on the comparison to the per-conversation "prev_seq_no" variable that gets
        initialized to 0 when the connection is first seen

        per-conversation state works well with bidirectional and parallel connections
            and fast even with ~500k packets out-of-order */

    udp_conversation_data *conversation;
    conversation = conversation_get_proto_data(find_conversation_pinfo(pinfo, 0), proto_iperf3);
    if (!conversation)
        conversation = udp_set_conversation_data(pinfo);

    /* detect */
    if (!PINFO_FD_VISITED(pinfo)) {
        bool is_out_of_order = (sequence_num != conversation->prev_seq_no + 1);
        conversation->prev_seq_no = sequence_num;

        if (is_out_of_order) {
            wmem_map_insert(conversation->out_of_order, GUINT_TO_POINTER(pinfo->num), NULL);
        }
    }
    /* report */
    if (wmem_map_contains(conversation->out_of_order, GUINT_TO_POINTER(pinfo->num))) {
        col_prepend_fstr(pinfo->cinfo, COL_INFO, "(Loss or out-of-order delivery) ");
        expert_add_info(pinfo, ti, &ei_udp_out_of_order);
    }
}

static udp_conversation_data *
udp_set_conversation_data(packet_info *pinfo)
{
    udp_conversation_data *conversation;
    conversation = wmem_new0(wmem_file_scope(), udp_conversation_data);
    conversation->out_of_order = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    conversation->prev_seq_no = 0;
    conversation_add_proto_data(find_conversation_pinfo(pinfo, 0), proto_iperf3, conversation);
    return conversation;
    /* could (very improbably) run iperf3 test multiple times in same capture
        and get the same random port.. would be seen as the same conversation and so you'd
        over count out of order packets... they can just turn off out-of-order detection */
}

void proto_register_iperf3(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        // TCP
        {&hf_iperf3_state,
         {"State ID", "iperf3.state", FT_INT8, BASE_DEC, VALS(iperf3_state_vals),
         0, NULL, HFILL}},
        {&hf_iperf3_prejson,
         {"Pre-JSON length identifier", "iperf3.prejson", FT_UINT32, BASE_DEC,
          NULL, 0, NULL, HFILL}},
        {&hf_iperf3_cookie,
         {"Cookie", "iperf3.cookie", FT_STRINGZ, BASE_NONE,
          NULL, 0, NULL, HFILL}},
        // UDP
        {&hf_iperf3_sec,
         {"iPerf3 sec", "iperf3.sec", FT_INT32, BASE_DEC,
          NULL, 0, NULL, HFILL}},
        {&hf_iperf3_usec,
         {"iPerf3 usec", "iperf3.usec", FT_UINT32, BASE_DEC,
          NULL, 0, NULL, HFILL}},
        {&hf_iperf3_sequence,
         {"iPerf3 sequence", "iperf3.sequence", FT_UINT64, BASE_DEC,
          NULL, 0, NULL, HFILL}},
        {&hf_iperf3_udp_init_msg,
         {"UDP initialization message", "iperf3.init_msg", FT_UINT32, BASE_HEX,
          NULL, 0, NULL, HFILL}},
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_iperf3,
        &ett_time
    };

    /* Register the protocol name and description */
    proto_iperf3 = proto_register_protocol("iPerf3 Speed Test", "iPerf3", "iperf3");

    /* Register configuration preferences */
    module_t *iperf3_module = prefs_register_protocol(proto_iperf3, NULL);
    prefs_register_bool_preference(iperf3_module, "udp_sequence_64bit",
        "Use 64 bit sequence numbers for UDP data",
        "Whether iPerf3 was run with --udp-counters-64bit flag set",
        &iperf3_pref_64bit_seq_no);
    prefs_register_bool_preference(iperf3_module, "detect_udp_errors",
        "Detect packet loss and out of order delivery for UDP data",
        "Attempt to detect when a packets sequence number does not match the previous ones +1",
        &iperf3_pref_detect_udp_order);

    /* Setup list of expert warnings */
    static ei_register_info ei[] = {
        {&ei_udp_out_of_order,
        {"iperf3.outoforder", PI_SEQUENCE, PI_NOTE,
            "UDP packet loss or out of order delivery", EXPFILL}},
    };
    /* Register expert mode warnings */
    expert_module_t* expert_iperf3 = expert_register_protocol(proto_iperf3);
    expert_register_field_array(expert_iperf3, ei, array_length(ei));

    proto_register_field_array(proto_iperf3, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    iperf3_handle_tcp = register_dissector("iperf3_tcp", dissect_iperf3_tcp, proto_iperf3);
    iperf3_handle_udp = register_dissector("iperf3_udp", dissect_iperf3_udp, proto_iperf3);

    cookiejar = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), wmem_str_hash, g_str_equal);
}

void proto_reg_handoff_iperf3(void)
{
    json_handle = find_dissector("json");

    dissector_add_uint_range_with_preference("tcp.port", "5201", iperf3_handle_tcp);
    dissector_add_uint_range_with_preference("udp.port", "5201", iperf3_handle_udp);
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
