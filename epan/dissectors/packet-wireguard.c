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
wg_dissect_handshake_initiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree)
{
    guint32 sender_id;

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_sender, tvb, 4, 4, ENC_LITTLE_ENDIAN, &sender_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", sender=0x%08X", sender_id);
    wg_dissect_pubkey(wg_tree, tvb, 8, TRUE);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_static, tvb, 40, 32 + AUTH_TAG_LENGTH, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_timestamp, tvb, 88, 12 + AUTH_TAG_LENGTH, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_mac1, tvb, 116, 16, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_mac2, tvb, 132, 16, ENC_NA);

    return 148;
}

static int
wg_dissect_handshake_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree)
{
    guint32 sender_id, receiver_id;

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_sender, tvb, 4, 4, ENC_LITTLE_ENDIAN, &sender_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", sender=0x%08X", sender_id);
    proto_tree_add_item_ret_uint(wg_tree, hf_wg_receiver, tvb, 8, 4, ENC_LITTLE_ENDIAN, &receiver_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", receiver=0x%08X", receiver_id);
    wg_dissect_pubkey(wg_tree, tvb, 12, TRUE);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_empty, tvb, 44, 16, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_mac1, tvb, 60, 16, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_mac2, tvb, 76, 16, ENC_NA);

    return 92;
}

static int
wg_dissect_handshake_cookie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree)
{
    guint32 receiver_id;

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_receiver, tvb, 4, 4, ENC_LITTLE_ENDIAN, &receiver_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", receiver=0x%08X", receiver_id);
    proto_tree_add_item(wg_tree, hf_wg_nonce, tvb, 8, 24, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_cookie, tvb, 32, 16 + AUTH_TAG_LENGTH, ENC_NA);

    return 64;
}

static int
wg_dissect_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree)
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

    return 16 + packet_length;
}

static int
dissect_wg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *wg_tree;
    guint32     message_type;
    const char *message_type_str;

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

    switch ((wg_message_type)message_type) {
    case WG_TYPE_HANDSHAKE_INITIATION:
        return wg_dissect_handshake_initiation(tvb, pinfo, wg_tree);
    case WG_TYPE_HANDSHAKE_RESPONSE:
        return wg_dissect_handshake_response(tvb, pinfo, wg_tree);
    case WG_TYPE_COOKIE_REPLY:
        return wg_dissect_handshake_cookie(tvb, pinfo, wg_tree);
    case WG_TYPE_TRANSPORT_DATA:
        return wg_dissect_data(tvb, pinfo, wg_tree);
    }

    DISSECTOR_ASSERT_NOT_REACHED();
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
