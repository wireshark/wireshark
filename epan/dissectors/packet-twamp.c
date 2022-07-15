/* packet-twamp.c
 * Routines for TWAMP packet dissection
 *
 * Murat Demirten <murat@debian.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Documentation:
 * RFC 4656: A One-way Active Measurement Protocol (OWAMP)
 * RFC 5357: A Two-Way Active Measurement Protocol (TWAMP)
 * RFC 5618: Mixed Security Mode for the TWAMP
 *           (not yet implemented)
 * RFC 5938: Individual Session Control Feature for the TWAMP
 *           (not yet implemented)
 * RFC 6038: TWAMP Reflect Octets and Symmetrical Size Features
 *           (not yet implemented)
 * RFC 8186: Support of the IEEE 1588 Timestamp Format in TWAMP
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include "packet-tcp.h"


void proto_reg_handoff_twamp(void);
void proto_register_twamp(void);

#define TWAMP_CONTROL_PORT 862
#define TWAMP_CONTROL_SERVER_GREETING_LEN 64
#define TWAMP_SESSION_ACCEPT_OK 0
/* Twamp times start from year 1900 */
#define TWAMP_FLOAT_DENOM 4294.967296

#define TWAMP_MODE_UNAUTHENTICATED  0x1
#define TWAMP_MODE_AUTHENTICATED    0x2
#define TWAMP_MODE_ENCRYPTED        0x4

#define TWAMP_ERROR_ESTIMATE_ZBIT   0x4000

enum twamp_control_state {
    CONTROL_STATE_UNKNOWN = 0,
    CONTROL_STATE_GREETING,
    CONTROL_STATE_SETUP_RESPONSE,
    CONTROL_STATE_SERVER_START,
    CONTROL_STATE_REQUEST_SESSION,
    CONTROL_STATE_ACCEPT_SESSION,
    CONTROL_STATE_START_SESSIONS,
    CONTROL_STATE_START_SESSIONS_ACK,
    CONTROL_STATE_TEST_RUNNING,
    CONTROL_STATE_STOP_SESSIONS,
    CONTROL_STATE_REQUEST_TW_SESSION
};

typedef struct _twamp_session {
    guint8 accepted;
    int padding;
    guint16 sender_port;
    guint16 receiver_port;
    guint32 sender_address[4];
    guint32 receiver_address[4];
    guint8 ipvn;
} twamp_session_t;

typedef struct twamp_control_packet {
    guint32 fd;
    enum twamp_control_state state;
    conversation_t *conversation;
} twamp_control_packet_t;

typedef struct twamp_control_transaction {
    enum twamp_control_state last_state;
    guint32 first_data_frame;
    GSList *sessions;
    proto_tree *tree;
} twamp_control_transaction_t;

static dissector_handle_t owamp_test_handle;
static dissector_handle_t twamp_test_handle;
static dissector_handle_t twamp_control_handle;

/* Protocol enabled flags */
static int proto_owamp_test = -1;
static int proto_twamp_test = -1;
static int proto_twamp_control = -1;
static gint ett_owamp_test = -1;
static gint ett_twamp_test = -1;
static gint ett_twamp_control = -1;
static gint ett_twamp_error_estimate = -1;

/* Twamp test fields */
static int hf_twamp_seq_number = -1;
static int hf_twamp_sender_timestamp = -1;
static int hf_twamp_error_estimate = -1;
static int hf_twamp_mbz1 = -1;
static int hf_twamp_receive_timestamp = -1;
static int hf_twamp_sender_seq_number = -1;
static int hf_twamp_timestamp = -1;
static int hf_twamp_sender_error_estimate = -1;
static int hf_twamp_mbz2 = -1;
static int hf_twamp_sender_ttl = -1;
static int hf_twamp_padding = -1;
static int hf_twamp_error_estimate_multiplier = -1;
static int hf_twamp_error_estimate_scale = -1;
static int hf_twamp_error_estimate_b14 = -1;
static int hf_twamp_error_estimate_b15 = -1;

/* Twamp control fields */
static int hf_twamp_control_unused = -1;
static int hf_twamp_control_command = -1;
static int hf_twamp_control_modes = -1;
static int hf_twamp_control_mode = -1;
static int hf_twamp_control_challenge = -1;
static int hf_twamp_control_salt   = -1;
static int hf_twamp_control_count  = -1;
static int hf_twamp_control_keyid  = -1;
static int hf_twamp_control_sessionid  = -1;
static int hf_twamp_control_iv = -1;
static int hf_twamp_control_ipvn = -1;
static int hf_twamp_control_conf_sender = -1;
static int hf_twamp_control_conf_receiver = -1;
static int hf_twamp_control_number_of_schedule_slots = -1;
static int hf_twamp_control_number_of_packets = -1;
static int hf_twamp_control_start_time = -1;
static int hf_twamp_control_accept = -1;
static int hf_twamp_control_timeout = -1;
static int hf_twamp_control_type_p = -1;
static int hf_twamp_control_mbz1   = -1;
static int hf_twamp_control_mbz2   = -1;
static int hf_twamp_control_hmac   = -1;
static int hf_twamp_control_num_sessions   = -1;
static int hf_twamp_control_sender_port    = -1;
static int hf_twamp_control_server_uptime  = -1;
static int hf_twamp_control_receiver_port  = -1;
static int hf_twamp_control_padding_length = -1;
static int hf_twamp_control_sender_ipv4 = -1;
static int hf_twamp_control_sender_ipv6 = -1;
static int hf_twamp_control_receiver_ipv4 = -1;
static int hf_twamp_control_receiver_ipv6 = -1;

static const value_string twamp_control_accept_vals[] = {
    { 0, "OK" },
    { 1, "Failure, reason unspecified (catch-all)" },
    { 2, "Internal error" },
    { 3, "Some aspect of request is not supported" },
    { 4, "Cannot perform request due to permanent resource limitations" },
    { 5, "Cannot perform request due to temporary resource limitations" },
    { 0, NULL }
};

static const value_string twamp_control_command_vals[] = {
    { 0, "Reserved" },
    { 1, "Forbidden" },
    { 2, "Start-Sessions" },
    { 3, "Stop-Sessions" },
    { 4, "Reserved" },
    { 5, "Request-TW-Session" },
    { 6, "Experimentation" },
    { 0, NULL }
};

static const value_string twamp_control_state_vals[] = {
    { CONTROL_STATE_UNKNOWN, "Unknown" },
    { CONTROL_STATE_GREETING, "Server Greeting" },
    { CONTROL_STATE_SETUP_RESPONSE, "Setup Response" },
    { CONTROL_STATE_SERVER_START, "Server Start" },
    { CONTROL_STATE_REQUEST_SESSION, "Request Session" },
    { CONTROL_STATE_ACCEPT_SESSION, "Accept Session" },
    { CONTROL_STATE_START_SESSIONS, "Start Sessions" },
    { CONTROL_STATE_START_SESSIONS_ACK, "Start Sessions ACK" },
    { CONTROL_STATE_TEST_RUNNING, "Test Running" },
    { CONTROL_STATE_STOP_SESSIONS, "Stop Session" },
    { CONTROL_STATE_REQUEST_TW_SESSION, "Request-TW-Session" },
    { 0, NULL }
};

static
gint find_twamp_session_by_sender_port (gconstpointer element, gconstpointer compared)
{
    const guint16 *sender_port = (const guint16*) compared;
    const twamp_session_t *session = (const twamp_session_t*) element;
    return !(session->sender_port == *sender_port);
}

static
gint find_twamp_session_by_first_accept_waiting (gconstpointer element, gconstpointer dummy _U_)
{
    const twamp_session_t *session = (const twamp_session_t*) element;
    if (session->accepted == 0)
        return 0;

    return 1;
}

static int
dissect_twamp_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    gboolean is_request;
    proto_item *twamp_tree;
    proto_tree *it;
    conversation_t *conversation;
    twamp_control_transaction_t *ct;
    twamp_control_packet_t *cp;
    twamp_session_t *session = NULL;
    guint8 accept;
    guint16 sender_port;
    guint16 receiver_port;
    GSList *list;
    nstime_t ts;
    proto_tree *item;
    guint32 modes;
    guint32 type_p;
    guint8 command_number;
    guint8 ipvn;

    if (pinfo->destport == TWAMP_CONTROL_PORT) {
        is_request = TRUE;
    } else {
        is_request = FALSE;
    }

    conversation = find_or_create_conversation(pinfo);
    ct = (twamp_control_transaction_t *) conversation_get_proto_data(conversation, proto_twamp_control);
    if (ct == NULL) {
        if (is_request == FALSE && tvb_reported_length(tvb) == TWAMP_CONTROL_SERVER_GREETING_LEN) {
            /* We got server greeting */
            ct = wmem_new0(wmem_file_scope(), twamp_control_transaction_t);
            conversation_add_proto_data(conversation, proto_twamp_control, ct);
            ct->last_state = CONTROL_STATE_UNKNOWN;
            ct->first_data_frame = pinfo->fd->num;
        } else {
            /* Can't do anything until we get a greeting */
            return 0;
        }
    }
    if ((cp = (twamp_control_packet_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_twamp_control, 0)) == NULL) {
        cp = wmem_new0(wmem_file_scope(), twamp_control_packet_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_twamp_control, 0, cp);

        /* detect state */
        if (pinfo->fd->num == ct->first_data_frame) {
            ct->last_state = CONTROL_STATE_GREETING;
        } else if (ct->last_state == CONTROL_STATE_GREETING) {
            ct->last_state = CONTROL_STATE_SETUP_RESPONSE;
        } else if (ct->last_state == CONTROL_STATE_SETUP_RESPONSE) {
            ct->last_state = CONTROL_STATE_SERVER_START;
        } else if (ct->last_state == CONTROL_STATE_SERVER_START) {
            ct->last_state = CONTROL_STATE_REQUEST_SESSION;
            sender_port = tvb_get_ntohs(tvb, 12);
            receiver_port = tvb_get_ntohs(tvb, 14);
            /* try to find session from past visits */
            if (g_slist_find_custom(ct->sessions, &sender_port,
                    (GCompareFunc) find_twamp_session_by_sender_port) == NULL) {
                session = g_new0(twamp_session_t, 1);
                session->sender_port = sender_port;
                session->receiver_port = receiver_port;
                session->accepted = 0;
                ipvn = tvb_get_guint8(tvb, 1) & 0x0F;

                if (ipvn == 6) {
                    tvb_get_ipv6(tvb, 16, (struct e_in6_addr*) &session->sender_address);
                    tvb_get_ipv6(tvb, 32, (struct e_in6_addr*) &session->receiver_address);

                } else {
                    session->sender_address[0] = tvb_get_ipv4(tvb, 16);
                    session->receiver_address[0] = tvb_get_ipv4(tvb, 32);
                }
                /*
                 * If ip addresses not specified in control protocol, we have to choose from IP header.
                 * It is a design decision by TWAMP and we need that ports for identifying future UDP conversations
                 */
                if (session->sender_address[0] == 0) {
                    memcpy(&session->sender_address[0], pinfo->src.data, pinfo->src.len);
                }
                if (session->receiver_address[0] == 0) {
                    memcpy(&session->receiver_address[0], pinfo->dst.data, pinfo->dst.len);
                }
                session->padding = tvb_get_ntohl(tvb, 64);
                ct->sessions = g_slist_append(ct->sessions, session);
            }
        } else if (ct->last_state == CONTROL_STATE_REQUEST_SESSION) {
            ct->last_state = CONTROL_STATE_ACCEPT_SESSION;
            accept = tvb_get_guint8(tvb, 0);
            if (accept == TWAMP_SESSION_ACCEPT_OK) {
                receiver_port = tvb_get_ntohs(tvb, 2);

                if ((list = g_slist_find_custom(ct->sessions, NULL,
                        find_twamp_session_by_first_accept_waiting)) == NULL) {
                    return 0;
                }
                session = (twamp_session_t*) list->data;
                session->receiver_port = receiver_port;

                cp->conversation = find_conversation(pinfo->fd->num, &pinfo->dst, &pinfo->src, ENDPOINT_UDP,
                        session->sender_port, session->receiver_port, 0);
                if (cp->conversation == NULL /*|| cp->conversation->dissector_handle != twamp_test_handle*/) {
                    cp->conversation = conversation_new(pinfo->fd->num, &pinfo->dst, &pinfo->src, ENDPOINT_UDP,
                            session->sender_port, session->receiver_port, 0);
                    if (cp->conversation) {
                        /* create conversation specific data for test sessions */
                        conversation_add_proto_data(cp->conversation, proto_twamp_test, session);
                        conversation_set_dissector(cp->conversation, twamp_test_handle);
                    }
                }
            }
        } else if (ct->last_state == CONTROL_STATE_ACCEPT_SESSION) {
            /* We shall check the Command Number to determine current CONTROL_STATE_XXX */
            command_number = tvb_get_guint8(tvb, 0);
            switch(command_number){
                case 2: /* Start-Sessions */
                    ct->last_state = CONTROL_STATE_START_SESSIONS;
                    break;
                case 3: /* Stop-Sessions */
                    ct->last_state = CONTROL_STATE_STOP_SESSIONS;
                    break;
                case 5: /* Request-Session */
                    ct->last_state = CONTROL_STATE_REQUEST_SESSION;
                    break;
            }
        } else if (ct->last_state == CONTROL_STATE_START_SESSIONS) {
            ct->last_state = CONTROL_STATE_START_SESSIONS_ACK;
        } else if (ct->last_state == CONTROL_STATE_START_SESSIONS_ACK) {
            ct->last_state = CONTROL_STATE_STOP_SESSIONS;
        } else {
            /* response */
        }
        cp->state = ct->last_state;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "TWAMP-Control");

    it = proto_tree_add_item(tree, proto_twamp_control, tvb, 0, -1, ENC_NA);
    twamp_tree = proto_item_add_subtree(it, ett_twamp_control);

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const(cp->state, twamp_control_state_vals, "Unknown"));

    switch (cp->state) {
    case CONTROL_STATE_GREETING:
        proto_tree_add_item(twamp_tree, hf_twamp_control_unused, tvb, offset, 12, ENC_NA);
        offset += 12;
        modes = tvb_get_ntohl(tvb, offset) & 0x00000007;
        item = proto_tree_add_item(twamp_tree, hf_twamp_control_modes, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, " (%s%s%s)",
                (modes & TWAMP_MODE_UNAUTHENTICATED) ? " Unauthenticated " : "",
                (modes & TWAMP_MODE_AUTHENTICATED) ? "Authenticated " : "",
                (modes & TWAMP_MODE_ENCRYPTED) ? "Encrypted " : "");
        offset += 4;
        proto_tree_add_item(twamp_tree, hf_twamp_control_challenge, tvb, offset, 16, ENC_NA);
        offset += 16;
        proto_tree_add_item(twamp_tree, hf_twamp_control_salt, tvb, offset, 16, ENC_NA);
        offset += 16;
        proto_tree_add_item(twamp_tree, hf_twamp_control_count, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(twamp_tree, hf_twamp_control_mbz1, tvb, offset, 12, ENC_NA);
        /* offset += 12; */
        break;

    case CONTROL_STATE_SETUP_RESPONSE:
        proto_tree_add_item(twamp_tree, hf_twamp_control_mode, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(twamp_tree, hf_twamp_control_keyid, tvb, offset, 40, ENC_NA);
        /* offset += 40; */
        break;

    case CONTROL_STATE_SERVER_START:
        proto_tree_add_item(twamp_tree, hf_twamp_control_mbz1, tvb, offset, 15, ENC_NA);
        offset += 15;
        accept = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(twamp_tree, hf_twamp_control_accept, tvb, offset, 1, accept);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", (%s%s)",
                (accept == 0) ? "" : "Error: ", val_to_str(accept, twamp_control_accept_vals, "%u"));
        offset += 1;
        proto_tree_add_item(twamp_tree, hf_twamp_control_iv, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item(twamp_tree, hf_twamp_control_server_uptime, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
        offset += 8;
        proto_tree_add_item(twamp_tree, hf_twamp_control_mbz2, tvb, offset, 8, ENC_NA);

        break;
    case CONTROL_STATE_REQUEST_SESSION:
        proto_tree_add_item(twamp_tree, hf_twamp_control_command, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        ipvn = tvb_get_guint8(tvb, offset) & 0x0F;
        proto_tree_add_uint(twamp_tree, hf_twamp_control_ipvn, tvb, offset, 1, ipvn);
        offset += 1;

        proto_tree_add_item(twamp_tree, hf_twamp_control_conf_sender, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(twamp_tree, hf_twamp_control_conf_receiver, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(twamp_tree, hf_twamp_control_number_of_schedule_slots, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(twamp_tree, hf_twamp_control_number_of_packets, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(twamp_tree, hf_twamp_control_sender_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(twamp_tree, hf_twamp_control_receiver_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        if (ipvn == 6) {
            proto_tree_add_item(twamp_tree, hf_twamp_control_sender_ipv6, tvb, offset, 16, ENC_NA);
        } else {
            proto_tree_add_item(twamp_tree, hf_twamp_control_sender_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset += 16;
        if (ipvn == 6) {
            proto_tree_add_item(twamp_tree, hf_twamp_control_receiver_ipv6, tvb, offset, 16, ENC_NA);
        } else {
            proto_tree_add_item(twamp_tree, hf_twamp_control_receiver_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
        }
        offset += 16;
        proto_tree_add_item(twamp_tree, hf_twamp_control_sessionid, tvb, offset, 16, ENC_NA);
        offset += 16;

        proto_tree_add_item(twamp_tree, hf_twamp_control_padding_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(twamp_tree, hf_twamp_control_start_time, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
        offset += 8;

        ts.secs = tvb_get_ntohl(tvb, offset);
        ts.nsecs = (int)(tvb_get_ntohl(tvb, offset + 4) / TWAMP_FLOAT_DENOM);
        proto_tree_add_time(twamp_tree, hf_twamp_control_timeout, tvb, offset, 8, &ts);
        offset += 8;

        type_p = tvb_get_ntohl(tvb, offset);
        item = proto_tree_add_item(twamp_tree, hf_twamp_control_type_p, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_item_append_text(item, " (DSCP: %d)", type_p);
        /* offset += 4; */
        break;

    case CONTROL_STATE_ACCEPT_SESSION:
        accept = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(twamp_tree, hf_twamp_control_accept, tvb, offset, 1, accept);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", (%s%s)",
                (accept == 0) ? "" : "Error: ", val_to_str(accept, twamp_control_accept_vals, "%u"));
        offset = 2;
        proto_tree_add_item(twamp_tree, hf_twamp_control_receiver_port, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(twamp_tree, hf_twamp_control_sessionid, tvb, offset, 16, ENC_NA);
        offset += 16;
        proto_tree_add_item(twamp_tree, hf_twamp_control_mbz1, tvb, offset, 12, ENC_NA);
        offset += 12;
        proto_tree_add_item(twamp_tree, hf_twamp_control_hmac, tvb, offset, 16, ENC_NA);
        break;
    case CONTROL_STATE_START_SESSIONS:
        proto_tree_add_item(twamp_tree, hf_twamp_control_command, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(twamp_tree, hf_twamp_control_mbz1, tvb, offset, 15, ENC_NA);
        offset += 15;
        proto_tree_add_item(twamp_tree, hf_twamp_control_hmac, tvb, offset, 16, ENC_NA);
        /* offset += 16; */
        break;
    case CONTROL_STATE_START_SESSIONS_ACK:
        accept = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint(twamp_tree, hf_twamp_control_accept, tvb, offset, 1, accept);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", (%s%s)",
                (accept == 0) ? "" : "Error: ", val_to_str(accept, twamp_control_accept_vals, "%u"));
        offset += 1;
        proto_tree_add_item(twamp_tree, hf_twamp_control_mbz1, tvb, offset, 15, ENC_NA);
        offset += 15;
        proto_tree_add_item(twamp_tree, hf_twamp_control_hmac, tvb, offset, 16, ENC_NA);
        /* offset += 16; */
        break;

    case CONTROL_STATE_STOP_SESSIONS:
        proto_tree_add_item(twamp_tree, hf_twamp_control_command, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(twamp_tree, hf_twamp_control_accept, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(twamp_tree, hf_twamp_control_mbz1, tvb, offset, 2, ENC_NA);
        offset += 2;
        proto_tree_add_item(twamp_tree, hf_twamp_control_num_sessions, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(twamp_tree, hf_twamp_control_mbz2, tvb, offset, 8, ENC_NA);
        offset += 8;
        proto_tree_add_item(twamp_tree, hf_twamp_control_hmac, tvb, offset, 16, ENC_NA);
        /* offset += 16; */
        break;
    default:
        break;

    }
    return tvb_captured_length(tvb);
}

static
guint get_server_greeting_len(packet_info *pinfo _U_, tvbuff_t *tvb _U_, int offset _U_, void *data _U_)
{
    conversation_t *conversation;
    twamp_control_transaction_t *ct;

    conversation = find_or_create_conversation(pinfo);
    ct = (twamp_control_transaction_t *) conversation_get_proto_data(conversation, proto_twamp_control);

    if (ct == NULL) {
        return TWAMP_CONTROL_SERVER_GREETING_LEN;
    } else {
        return tvb_captured_length(tvb);
    }
}

static int
dissect_twamp_server_greeting(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Try to reassemble server greeting message */
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 0, get_server_greeting_len, dissect_twamp_control, data);
    return tvb_captured_length(tvb);
}

static int * const twamp_error_estimate_flags[] = {
    &hf_twamp_error_estimate_b15,
    &hf_twamp_error_estimate_b14,
    &hf_twamp_error_estimate_scale,
    &hf_twamp_error_estimate_multiplier,
    NULL
};

static const true_false_string tfs_twamp_sbit_tfs = {
    "Synchronized to UTC using an external source",
    "No notion of external synchronization"
};

static const true_false_string tfs_twamp_zbit_tfs = {
    "Abbreviated PTP Timestamp (RFC8186)",
    "Always Zero (RFC5357) or NTP Timestamp (RFC8186)"
};

static int
dissect_owamp_test(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti = NULL;
    proto_item *owamp_tree = NULL;
    int offset = 0, padding = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OWAMP-Test");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_owamp_test, tvb, 0, -1, ENC_NA);
    owamp_tree = proto_item_add_subtree(ti, ett_owamp_test);

    col_append_str(pinfo->cinfo, COL_INFO, "Measurement packet");

    /* Sequence number ar in both packet types.*/
    proto_tree_add_item(owamp_tree, hf_twamp_seq_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(owamp_tree, hf_twamp_timestamp, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
    offset += 8;

    /*
     * 0                   1
     * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |S|Z|   Scale   |   Multiplier  |
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     */
    proto_tree_add_bitmask(owamp_tree, tvb, offset, hf_twamp_error_estimate, ett_twamp_error_estimate, twamp_error_estimate_flags, ENC_BIG_ENDIAN);
    offset += 2;

    padding = tvb_reported_length(tvb) - offset;
    if (padding > 0) {
        proto_tree_add_item(owamp_tree, hf_twamp_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }

    return offset;
}

static int
dissect_twamp_test(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    proto_item *ti = NULL;
    proto_item *twamp_tree = NULL;
    int padding = 0;

    col_set_str(pinfo-> cinfo, COL_PROTOCOL, "TWAMP-Test");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item (tree, proto_twamp_test, tvb, 0, -1, ENC_NA);
    twamp_tree = proto_item_add_subtree (ti, ett_twamp_test);

    col_append_str(pinfo->cinfo, COL_INFO, "Measurement packet");

    /* Sequence number are in both packet types.*/
    proto_tree_add_item(twamp_tree, hf_twamp_seq_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (tvb_get_ntohs(tvb, offset + 8) & TWAMP_ERROR_ESTIMATE_ZBIT)
        proto_tree_add_item(twamp_tree, hf_twamp_timestamp, tvb, offset, 8, ENC_TIME_SECS_NSECS | ENC_BIG_ENDIAN);
    else
        proto_tree_add_item(twamp_tree, hf_twamp_timestamp, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
    offset += 8;

    /*
    * 0                   1
    * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    * |S|Z|   Scale   |   Multiplier  |
    * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    *
    */
    proto_tree_add_bitmask(twamp_tree, tvb, offset, hf_twamp_error_estimate, ett_twamp_error_estimate, twamp_error_estimate_flags, ENC_BIG_ENDIAN);
    offset += 2;

    /* Responder sends TWAMP-Test packets with additional fields */
    if (tvb_reported_length(tvb) - offset >= 27) {
        proto_tree_add_item (twamp_tree, hf_twamp_mbz1, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        if (tvb_get_ntohs(tvb, offset - 4) & TWAMP_ERROR_ESTIMATE_ZBIT)
            proto_tree_add_item(twamp_tree, hf_twamp_receive_timestamp, tvb, offset, 8, ENC_TIME_SECS_NSECS | ENC_BIG_ENDIAN);
        else
            proto_tree_add_item(twamp_tree, hf_twamp_receive_timestamp, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_item (twamp_tree, hf_twamp_sender_seq_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (tvb_get_ntohs(tvb, offset) & TWAMP_ERROR_ESTIMATE_ZBIT)
            proto_tree_add_item(twamp_tree, hf_twamp_sender_timestamp, tvb, offset, 8, ENC_TIME_NTP | ENC_BIG_ENDIAN);
        else
            proto_tree_add_item(twamp_tree, hf_twamp_sender_timestamp, tvb, offset, 8, ENC_TIME_SECS_NSECS | ENC_BIG_ENDIAN);
        offset += 8;

        proto_tree_add_bitmask(twamp_tree, tvb, offset, hf_twamp_sender_error_estimate, ett_twamp_error_estimate, twamp_error_estimate_flags, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item (twamp_tree, hf_twamp_mbz2, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item (twamp_tree, hf_twamp_sender_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    padding = tvb_reported_length(tvb) - offset;
    if (padding > 0) {
        proto_tree_add_item (twamp_tree, hf_twamp_padding, tvb, offset, padding, ENC_NA);
        offset += padding;
    }

    /* Return the total length */
    return offset;
}

void proto_register_twamp(void)
{
    static hf_register_info hf_twamp_test[] = {
        {&hf_twamp_seq_number,
         {"Sequence Number", "twamp.test.seq_number", FT_UINT32,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_twamp_timestamp,
         {"Timestamp", "twamp.test.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
          NULL, 0x0, NULL, HFILL}},
        {&hf_twamp_error_estimate,
         {"Error Estimate", "twamp.test.error_estimate", FT_UINT16,
          BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_twamp_mbz1,
         {"MBZ", "twamp.test.mbz1", FT_UINT8, BASE_DEC_HEX,
          NULL, 0x0, NULL, HFILL}},
        {&hf_twamp_receive_timestamp,
         {"Receive Timestamp", "twamp.test.receive_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}},
        {&hf_twamp_sender_seq_number,
         {"Sender Sequence Number", "twamp.test.sender_seq_number",
          FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_twamp_sender_timestamp,
         {"Sender Timestamp", "twamp.test.sender_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}},
        {&hf_twamp_sender_error_estimate,
         {"Sender Error Estimate", "twamp.test.sender_error_estimate",
          FT_UINT16, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_twamp_mbz2,
         {"MBZ", "twamp.test.mbz2", FT_UINT8, BASE_DEC_HEX,
          NULL, 0x0, NULL, HFILL}},
        {&hf_twamp_sender_ttl,
         {"Sender TTL", "twamp.test.sender_ttl", FT_UINT8, BASE_DEC,
          NULL, 0x0, NULL, HFILL}},
        {&hf_twamp_padding,
         {"Packet Padding", "twamp.test.padding", FT_BYTES, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        { &hf_twamp_error_estimate_multiplier,
          { "Multiplier", "twamp.test.error_estimate.multiplier", FT_UINT16, BASE_DEC,
          NULL, 0x00ff, NULL, HFILL } },
        { &hf_twamp_error_estimate_scale,
          { "Scale", "twamp.test.error_estimate.scale", FT_UINT16, BASE_DEC,
          NULL, 0x3f00, NULL, HFILL } },
        { &hf_twamp_error_estimate_b14,
          { "Z", "twamp.test.error_estimate.z", FT_BOOLEAN, 16,
          TFS(&tfs_twamp_zbit_tfs), 0x4000, NULL, HFILL } },
        { &hf_twamp_error_estimate_b15,
          { "S", "twamp.test.error_estimate.s", FT_BOOLEAN, 16,
          TFS(&tfs_twamp_sbit_tfs), 0x8000, NULL, HFILL } },
    };

    static gint *ett_twamp_test_arr[] = {
        &ett_owamp_test,
        &ett_twamp_test
    };

    static hf_register_info hf_twamp_control[] = {
        {&hf_twamp_control_unused,
            {"Unused", "twamp.control.unused", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_command,
            {"Control Command", "twamp.control.command", FT_UINT8, BASE_DEC,
                    VALS(twamp_control_command_vals), 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_modes,
            {"Supported Modes", "twamp.control.modes", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_mode,
            {"Mode", "twamp.control.mode", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_keyid,
            {"Key ID", "twamp.control.keyid", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_challenge,
            {"Challenge", "twamp.control.challenge", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_salt,
            {"Salt", "twamp.control.salt", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_count,
            {"Count", "twamp.control.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_iv,
            {"Control IV", "twamp.control.iv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_sessionid,
            {"Session Id", "twamp.control.session_id", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_mbz1,
            {"MBZ", "twamp.control.mbz1", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_mbz2,
            {"MBZ", "twamp.control.mbz2", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_hmac,
            {"HMAC", "twamp.control.hmac", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_padding_length,
            {"Padding Length", "twamp.control.padding_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_start_time,
            {"Start Time", "twamp.control.start_time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_timeout,
            {"Timeout", "twamp.control.timeout", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_type_p,
            {"Type-P Descriptor", "twamp.control.type-p", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_num_sessions,
            {"Number of Sessions", "twamp.control.numsessions", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_server_uptime,
            {"Server Start Time", "twamp.control.server_uptime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_accept,
            {"Accept", "twamp.control.accept", FT_UINT8, BASE_DEC, VALS(twamp_control_accept_vals), 0x0,
                "Message acceptance by the other side", HFILL}
        },
        {&hf_twamp_control_sender_port,
            {"Sender Port", "twamp.control.sender_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_receiver_port,
            {"Receiver Port", "twamp.control.receiver_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_ipvn,
            {"IP Version", "twamp.control.ipvn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_conf_sender,
            {"Conf-Sender", "twamp.control.conf_sender", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_conf_receiver,
            {"Conf-Receiver", "twamp.control.conf_receiver", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_number_of_schedule_slots,
            {"Number of Schedule Slots", "twamp.control.number_of_schedule_slots", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_number_of_packets,
            {"Number of Packets", "twamp.control.number_of_packets", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
        },
        {&hf_twamp_control_sender_ipv4,
            {"Sender Address", "twamp.control.sender_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
                "IPv4 sender address want to use in test packets", HFILL}
        },
        {&hf_twamp_control_sender_ipv6,
            {"Sender Address", "twamp.control.sender_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
                "IPv6 sender address want to use in test packets", HFILL}
        },
        {&hf_twamp_control_receiver_ipv4,
            {"Receiver Address", "twamp.control.receiver_ipv4", FT_IPv4, BASE_NONE, NULL, 0x0,
                "IPv4 sender address want to use in test packets", HFILL}
        },
        {&hf_twamp_control_receiver_ipv6,
            {"Receiver Address", "twamp.control.receiver_ipv6", FT_IPv6, BASE_NONE, NULL, 0x0,
                "IPv6 receiver address want to use in test packets", HFILL}
        }
    };

    static gint *ett_twamp_control_arr[] = {
        &ett_twamp_control,
        &ett_twamp_error_estimate
    };


    /* Register the protocol */
    proto_twamp_test = proto_register_protocol(
        "TwoWay Active Measurement Test Protocol",
        "TWAMP-Test",
        "twamp.test");

    /* Register the field array */
    proto_register_field_array (proto_twamp_test, hf_twamp_test,
                    array_length(hf_twamp_test));

    /* Register the subtree array */
    proto_register_subtree_array (ett_twamp_test_arr,
                      array_length(ett_twamp_test_arr));

    /* Register the protocol */
    proto_twamp_control = proto_register_protocol(
        "TwoWay Active Measurement Control Protocol",
        "TWAMP-Control",
        "twamp.control");

    /* Register the field array */
    proto_register_field_array (proto_twamp_control, hf_twamp_control,
                    array_length(hf_twamp_control));

    /* Register the subtree array */
    proto_register_subtree_array (ett_twamp_control_arr,
                      array_length(ett_twamp_control_arr));

    proto_owamp_test = proto_register_protocol(
        "One-way Active Measurement Protocol",
        "OWAMP-Test",
        "owamp.test");

}

void proto_reg_handoff_twamp(void)
{
    twamp_test_handle = create_dissector_handle(dissect_twamp_test, proto_twamp_test);

    owamp_test_handle = create_dissector_handle(dissect_owamp_test, proto_owamp_test);

    twamp_control_handle = create_dissector_handle(dissect_twamp_server_greeting, proto_twamp_control);
    dissector_add_uint("tcp.port", TWAMP_CONTROL_PORT, twamp_control_handle);

    dissector_add_for_decode_as("udp.port", twamp_test_handle);
    dissector_add_for_decode_as("udp.port", owamp_test_handle);
}

/*
* Editor modelines
*
* Local Variables:
* c-basic-offset: 4
* tab-width: 8
* indent-tabs-mode: nil
* End:
*
* ex: set shiftwidth=4 tabstop=8 expandtab:
* :indentSize=4:tabSize=8:noTabs=true:
*/
