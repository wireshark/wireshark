/* packet-wireguard.c
 * Routines for WireGuard dissection
 * Copyright 2018, Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Protocol details: https://www.wireguard.com/protocol/
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>

void proto_reg_handoff_wg(void);
void proto_register_wg(void);

static int proto_wg = -1;
static int hf_wg_type = -1;
static int hf_wg_reserved = -1;
static int hf_wg_sender = -1;
static int hf_wg_ephemeral = -1;
static int hf_wg_encrypted_static = -1;
static int hf_wg_encrypted_timestamp = -1;
static int hf_wg_mac1 = -1;
static int hf_wg_mac2 = -1;
static int hf_wg_receiver = -1;
static int hf_wg_encrypted_empty = -1;
static int hf_wg_nonce = -1;
static int hf_wg_encrypted_cookie = -1;
static int hf_wg_counter = -1;
static int hf_wg_encrypted_packet = -1;
static int hf_wg_stream = -1;
static int hf_wg_response_in = -1;
static int hf_wg_response_to = -1;

static gint ett_wg = -1;

static expert_field ei_wg_bad_packet_length = EI_INIT;
static expert_field ei_wg_keepalive  = EI_INIT;


// Length of AEAD authentication tag
#define AUTH_TAG_LENGTH 16

typedef enum {
    WG_TYPE_HANDSHAKE_INITIATION = 1,
    WG_TYPE_HANDSHAKE_RESPONSE = 2,
    WG_TYPE_COOKIE_REPLY = 3,
    WG_TYPE_TRANSPORT_DATA = 4
} wg_message_type;

static const value_string wg_type_names[] = {
    { 0x01, "Handshake Initiation" },
    { 0x02, "Handshake Response" },
    { 0x03, "Cookie Reply" },
    { 0x04, "Transport Data" },
    { 0x00, NULL }
};

/*
 * Information required to process and link messages as required on the first
 * sequential pass. After that it can be erased.
 */
typedef struct {
    address     initiator_address;
    address     responder_address;
    guint16     initiator_port;
    guint16     responder_port;
} wg_initial_info_t;

/*
 * A "session" between two peer is identified by a "sender" id as independently
 * chosen by each side. In case both peer IDs collide, the source IP and UDP
 * port number could be used to distinguish sessions. As IDs can be recycled
 * over time, lookups should use the most recent initiation (or response).
 *
 * XXX record timestamps (time since last message, for validating timers).
 */
typedef struct {
    guint32     stream;             /* Session identifier (akin to udp.stream). */
    guint32     initiator_frame;
    guint32     response_frame;     /* Responder or Cookie Reply message. */
    wg_initial_info_t initial;      /* Valid only on the first pass. */
} wg_session_t;

/* Per-packet state. */
typedef struct {
    wg_session_t   *session;
} wg_packet_info_t;

/* Map from Sender/Receiver IDs to a list of session information. */
static wmem_map_t *sessions;
static guint32 wg_session_count;


static void
wg_sessions_insert(guint32 id, wg_session_t *session)
{
    wmem_list_t *list = (wmem_list_t *)wmem_map_lookup(sessions, GUINT_TO_POINTER(id));
    if (!list) {
        list = wmem_list_new(wmem_file_scope());
        wmem_map_insert(sessions, GUINT_TO_POINTER(id), list);
    }
    wmem_list_append(list, session);
}

static wg_session_t *
wg_session_new(void)
{
    wg_session_t *session = wmem_new0(wmem_file_scope(), wg_session_t);
    session->stream = wg_session_count++;
    return session;
}

/* Updates the peer address based on the source address. */
static void
wg_session_update_address(wg_session_t *session, packet_info *pinfo, gboolean sender_is_initiator)
{
    DISSECTOR_ASSERT(!PINFO_FD_VISITED(pinfo));

    if (sender_is_initiator) {
        copy_address_wmem(wmem_file_scope(), &session->initial.initiator_address, &pinfo->src);
        session->initial.initiator_port = (guint16)pinfo->srcport;
    } else {
        copy_address_wmem(wmem_file_scope(), &session->initial.responder_address, &pinfo->src);
        session->initial.responder_port = (guint16)pinfo->srcport;
    }
}

/* Finds an initiation message based on the given Receiver ID that was not
 * previously associated with a responder message. Returns the session if a
 * matching initation message can be found or NULL otherwise.
 */
static wg_session_t *
wg_sessions_lookup_initiation(packet_info *pinfo, guint32 receiver_id)
{
    DISSECTOR_ASSERT(!PINFO_FD_VISITED(pinfo));

    /* Look for the initiation message matching this Receiver ID. */
    wmem_list_t *list = (wmem_list_t *)wmem_map_lookup(sessions, GUINT_TO_POINTER(receiver_id));
    if (!list) {
        return NULL;
    }

    /* Walk backwards to find the most recent message first. All packets are
     * guaranteed to arrive before this frame because this is the first pass. */
    for (wmem_list_frame_t *item = wmem_list_tail(list); item; item = wmem_list_frame_prev(item)) {
        wg_session_t *session = (wg_session_t *)wmem_list_frame_data(item);
        if (session->initial.initiator_port != pinfo->destport ||
            !addresses_equal(&session->initial.initiator_address, &pinfo->dst)) {
            /* Responder messages are expected to be sent to the initiator. */
            continue;
        }
        if (session->response_frame && session->response_frame != pinfo->num) {
            /* This session was linked elsewhere. */
            continue;
        }

        /* This assumes no malicious messages and no contrived sequences:
         * Any initiator or responder message is not duplicated nor are these
         * mutated. If this must be detected, the caller could decrypt or check
         * mac1 to distinguish valid messages.
         */
        return session;
    }

    return NULL;
}

/* Finds a session with a completed handshake that matches the Receiver ID. */
static wg_session_t *
wg_sessions_lookup(packet_info *pinfo, guint32 receiver_id, gboolean *receiver_is_initiator)
{
    DISSECTOR_ASSERT(!PINFO_FD_VISITED(pinfo));

    wmem_list_t *list = (wmem_list_t *)wmem_map_lookup(sessions, GUINT_TO_POINTER(receiver_id));
    if (!list) {
        return NULL;
    }

    /* Walk backwards to find the most recent message first. */
    for (wmem_list_frame_t *item = wmem_list_tail(list); item; item = wmem_list_frame_prev(item)) {
        wg_session_t *session = (wg_session_t *)wmem_list_frame_data(item);
        if (!session->response_frame) {
            /* Ignore sessions that are not fully established. */
            continue;
        }
        if (session->initial.initiator_port == pinfo->destport &&
            addresses_equal(&session->initial.initiator_address, &pinfo->dst)) {
            *receiver_is_initiator = TRUE;
        } else if (session->initial.responder_port == pinfo->destport &&
                   addresses_equal(&session->initial.responder_address, &pinfo->dst)) {
            *receiver_is_initiator = FALSE;
        } else {
            /* Both peers do not match the destination, ignore. */
            continue;
        }
        return session;
    }

    return NULL;
}


static void
wg_dissect_pubkey(proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_ephemeral)
{
    const guint8 *pubkey = tvb_get_ptr(tvb, offset, 32);
    gchar *str = g_base64_encode(pubkey, 32);
    gchar *key_str = wmem_strdup(wmem_packet_scope(), str);
    g_free(str);

    int hf_id = is_ephemeral ? hf_wg_ephemeral : -1; // TODO extend for static keys
    proto_tree_add_string(tree, hf_id, tvb, offset, 32, key_str);
}

static int
wg_dissect_handshake_initiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree, wg_packet_info_t *wg_pinfo)
{
    guint32 sender_id;
    proto_item *ti;

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_sender, tvb, 4, 4, ENC_LITTLE_ENDIAN, &sender_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", sender=0x%08X", sender_id);
    wg_dissect_pubkey(wg_tree, tvb, 8, TRUE);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_static, tvb, 40, 32 + AUTH_TAG_LENGTH, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_timestamp, tvb, 88, 12 + AUTH_TAG_LENGTH, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_mac1, tvb, 116, 16, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_mac2, tvb, 132, 16, ENC_NA);

    if (!PINFO_FD_VISITED(pinfo)) {
        /* XXX should an initiation message with the same contents (except MAC2) be
         * considered part of the same "session"? */
        wg_session_t *session = wg_session_new();
        session->initiator_frame = pinfo->num;
        wg_session_update_address(session, pinfo, TRUE);
        wg_sessions_insert(sender_id, session);
        wg_pinfo->session = session;
    }
    wg_session_t *session = wg_pinfo->session;
    if (session) {
        ti = proto_tree_add_uint(wg_tree, hf_wg_stream, tvb, 0, 0, session->stream);
        PROTO_ITEM_SET_GENERATED(ti);
    }
    if (session && session->response_frame) {
        ti = proto_tree_add_uint(wg_tree, hf_wg_response_in, tvb, 0, 0, session->response_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    return 148;
}

static int
wg_dissect_handshake_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree, wg_packet_info_t *wg_pinfo)
{
    guint32 sender_id, receiver_id;
    proto_item *ti;

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_sender, tvb, 4, 4, ENC_LITTLE_ENDIAN, &sender_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", sender=0x%08X", sender_id);
    proto_tree_add_item_ret_uint(wg_tree, hf_wg_receiver, tvb, 8, 4, ENC_LITTLE_ENDIAN, &receiver_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", receiver=0x%08X", receiver_id);
    wg_dissect_pubkey(wg_tree, tvb, 12, TRUE);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_empty, tvb, 44, 16, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_mac1, tvb, 60, 16, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_mac2, tvb, 76, 16, ENC_NA);

    wg_session_t *session;
    if (!PINFO_FD_VISITED(pinfo)) {
        session = wg_sessions_lookup_initiation(pinfo, receiver_id);
        /* XXX should probably check whether decryption succeeds before linking
         * and somehow mark that this response is related but not correct. */
        if (session) {
            session->response_frame = pinfo->num;
            wg_session_update_address(session, pinfo, FALSE);
            wg_sessions_insert(sender_id, session);
            wg_pinfo->session = session;
        }
    } else {
        session = wg_pinfo->session;
    }
    if (session) {
        ti = proto_tree_add_uint(wg_tree, hf_wg_stream, tvb, 0, 0, session->stream);
        PROTO_ITEM_SET_GENERATED(ti);
        ti = proto_tree_add_uint(wg_tree, hf_wg_response_to, tvb, 0, 0, session->initiator_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    return 92;
}

static int
wg_dissect_handshake_cookie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree, wg_packet_info_t *wg_pinfo)
{
    guint32 receiver_id;
    proto_item *ti;

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_receiver, tvb, 4, 4, ENC_LITTLE_ENDIAN, &receiver_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", receiver=0x%08X", receiver_id);
    proto_tree_add_item(wg_tree, hf_wg_nonce, tvb, 8, 24, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_cookie, tvb, 32, 16 + AUTH_TAG_LENGTH, ENC_NA);

    wg_session_t *session;
    if (!PINFO_FD_VISITED(pinfo)) {
        /* Check for Cookie Reply from Responder to Initiator. */
        session = wg_sessions_lookup_initiation(pinfo, receiver_id);
        if (session) {
            session->response_frame = pinfo->num;
            wg_session_update_address(session, pinfo, FALSE);
            wg_pinfo->session = session;
        }
        /* XXX check for cookie reply from Initiator to Responder */
    } else {
        session = wg_pinfo->session;
    }
    if (session) {
        ti = proto_tree_add_uint(wg_tree, hf_wg_stream, tvb, 0, 0, session->stream);
        PROTO_ITEM_SET_GENERATED(ti);
        /* XXX check for cookie reply from Initiator to Responder */
        ti = proto_tree_add_uint(wg_tree, hf_wg_response_to, tvb, 0, 0, session->initiator_frame);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    return 64;
}

static int
wg_dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree, wg_packet_info_t *wg_pinfo)
{
    guint32 receiver_id;
    guint64 counter;
    proto_item *ti;

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_receiver, tvb, 4, 4, ENC_LITTLE_ENDIAN, &receiver_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", receiver=0x%08X", receiver_id);
    proto_tree_add_item_ret_uint64(wg_tree, hf_wg_counter, tvb, 8, 8, ENC_LITTLE_ENDIAN, &counter);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", counter=%" G_GUINT64_FORMAT, counter);

    gint packet_length = tvb_captured_length_remaining(tvb, 16);
    if (packet_length < AUTH_TAG_LENGTH) {
        proto_tree_add_expert(wg_tree, pinfo, &ei_wg_bad_packet_length, tvb, 16, packet_length);
        return 16 + packet_length;
    } else if (packet_length != AUTH_TAG_LENGTH) {
        /* Keepalive messages are already marked, no need to append data length. */
        col_append_fstr(pinfo->cinfo, COL_INFO, ", datalen=%d", packet_length - AUTH_TAG_LENGTH);
    }
    ti = proto_tree_add_item(wg_tree, hf_wg_encrypted_packet, tvb, 16, packet_length, ENC_NA);

    if (packet_length == AUTH_TAG_LENGTH) {
        expert_add_info(pinfo, ti, &ei_wg_keepalive);
    }

    wg_session_t *session;
    if (!PINFO_FD_VISITED(pinfo)) {
        gboolean receiver_is_initiator;
        session = wg_sessions_lookup(pinfo, receiver_id, &receiver_is_initiator);
        if (session) {
            wg_session_update_address(session, pinfo, !receiver_is_initiator);
            wg_pinfo->session = session;
        }
    } else {
        session = wg_pinfo->session;
    }
    if (session) {
        ti = proto_tree_add_uint(wg_tree, hf_wg_stream, tvb, 0, 0, session->stream);
        PROTO_ITEM_SET_GENERATED(ti);
    }

    return 16 + packet_length;
}

static int
dissect_wg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *wg_tree;
    guint32     message_type;
    const char *message_type_str;
    wg_packet_info_t *wg_pinfo;

    /* Heuristics check: check for reserved bits (zeros) and message type. */
    if (tvb_reported_length(tvb) < 4 || tvb_get_ntoh24(tvb, 1) != 0)
        return 0;

    message_type = tvb_get_guint8(tvb, 0);
    message_type_str = try_val_to_str(message_type, wg_type_names);
    if (!message_type_str)
        return 0;

    /* Special case: zero-length data message is a Keepalive message. */
    if (message_type == WG_TYPE_TRANSPORT_DATA && tvb_reported_length(tvb) == 32) {
        message_type_str = "Keepalive";
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WireGuard");
    col_set_str(pinfo->cinfo, COL_INFO, message_type_str);

    ti = proto_tree_add_item(tree, proto_wg, tvb, 0, -1, ENC_NA);
    wg_tree = proto_item_add_subtree(ti, ett_wg);

    proto_tree_add_item(wg_tree, hf_wg_type, tvb, 0, 1, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_reserved, tvb, 1, 3, ENC_NA);

    if (!PINFO_FD_VISITED(pinfo)) {
        wg_pinfo = wmem_new0(wmem_file_scope(), wg_packet_info_t);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_wg, 0, wg_pinfo);
    } else {
        wg_pinfo = (wg_packet_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_wg, 0);
    }

    switch ((wg_message_type)message_type) {
    case WG_TYPE_HANDSHAKE_INITIATION:
        return wg_dissect_handshake_initiation(tvb, pinfo, wg_tree, wg_pinfo);
    case WG_TYPE_HANDSHAKE_RESPONSE:
        return wg_dissect_handshake_response(tvb, pinfo, wg_tree, wg_pinfo);
    case WG_TYPE_COOKIE_REPLY:
        return wg_dissect_handshake_cookie(tvb, pinfo, wg_tree, wg_pinfo);
    case WG_TYPE_TRANSPORT_DATA:
        return wg_dissect_data(tvb, pinfo, wg_tree, wg_pinfo);
    }

    DISSECTOR_ASSERT_NOT_REACHED();
}

static void
wg_init(void)
{
    wg_session_count = 0;
}

void
proto_register_wg(void)
{
    expert_module_t *expert_wg;

    static hf_register_info hf[] = {
        /* Initiation message */
        { &hf_wg_type,
          { "Type", "wg.type",
            FT_UINT8, BASE_DEC, VALS(wg_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_wg_reserved,
          { "Reserved", "wg.reserved",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wg_sender,
          { "Sender", "wg.sender",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Identifier as chosen by the sender", HFILL }
        },
        { &hf_wg_ephemeral,
          { "Ephemeral", "wg.ephemeral",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Ephemeral public key of sender", HFILL }
        },
        { &hf_wg_encrypted_static,
          { "Encrypted Static", "wg.encrypted_static",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Encrypted long-term static public key of sender", HFILL }
        },
        { &hf_wg_encrypted_timestamp,
          { "Encrypted Timestamp", "wg.encrypted_timestamp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wg_mac1,
          { "mac1", "wg.mac1",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wg_mac2,
          { "mac2", "wg.mac2",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* Response message */
        { &hf_wg_receiver,
          { "Receiver", "wg.receiver",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Identifier as chosen by receiver", HFILL }
        },
        { &hf_wg_encrypted_empty,
          { "Encrypted Empty", "wg.encrypted_empty",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Authenticated encryption of an empty string", HFILL }
        },

        /* Cookie message */
        { &hf_wg_nonce,
          { "Nonce", "wg.nonce",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wg_encrypted_cookie,
          { "Encrypted Cookie", "wg.encrypted_cookie",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        /* TODO decrypted cookie field. */

        /* Data message */
        { &hf_wg_counter,
          { "Counter", "wg.counter",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wg_encrypted_packet,
          { "Encrypted Packet", "wg.encrypted_packet",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        /* Association tracking. */
        { &hf_wg_stream,
          { "Stream index", "wg.stream",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "Identifies a session in this capture file", HFILL }
        },
        { &hf_wg_response_in,
          { "Response in Frame", "wg.response_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            "The response to this initiation message is in this frame", HFILL }
        },
        { &hf_wg_response_to,
          { "Response to Frame", "wg.response_to",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            "This is a response to the initiation message in this frame", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_wg,
    };

    static ei_register_info ei[] = {
        { &ei_wg_bad_packet_length,
          { "wg.bad_packet_length", PI_MALFORMED, PI_ERROR,
            "Packet length is too small", EXPFILL }
        },
        { &ei_wg_keepalive,
          { "wg.keepalive", PI_SEQUENCE, PI_CHAT,
            "This is a Keepalive message", EXPFILL }
        },
    };

    proto_wg = proto_register_protocol("WireGuard Protocol", "WireGuard", "wg");

    proto_register_field_array(proto_wg, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_wg = expert_register_protocol(proto_wg);
    expert_register_field_array(expert_wg, ei, array_length(ei));

    register_dissector("wg", dissect_wg, proto_wg);

    register_init_routine(wg_init);
    sessions = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
}

void
proto_reg_handoff_wg(void)
{
    heur_dissector_add("udp", dissect_wg, "WireGuard", "wg", proto_wg, HEURISTIC_ENABLE);
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
