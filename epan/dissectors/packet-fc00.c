/* packet-fc00.c
 * Routines for fc00/cjdns dissection
 * Copyright 2015, Emery Hemingway <emery@v36.spacet>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * https://github.com/hyperboria/cjdns
 */

#include <config.h>

#include <epan/expert.h>
#include <epan/packet.h>
#include <wsutil/base32.h>

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_fc00(void);
void proto_register_fc00(void);

/* Initialize the protocol and registered fields */
static int proto_fc00 = -1;
static int hf_fc00_session_state    = -1;
static int hf_fc00_session_nonce    = -1;
static int hf_fc00_auth_challenge   = -1;
static int hf_fc00_auth_type        = -1;
static int hf_fc00_auth_hash_code   = -1;
static int hf_fc00_auth_poly        = -1;
static int hf_fc00_auth_derivations = -1;
static int hf_fc00_auth_additional  = -1;
static int hf_fc00_random_nonce     = -1;
static int hf_fc00_public_key       = -1;
static int hf_fc00_ip_address       = -1;
static int hf_fc00_authenticator    = -1;
static int hf_fc00_temp_publicy_key = -1;
static int hf_fc00_payload          = -1;

static expert_field ei_fc00_chksum_unsupported = EI_INIT;

/* Cjdns constants */
#define SESSION_STATE_OFF 0
#define SESSION_STATE_LEN 4
#define CHALLENGE_OFF 4
#define CHALLENGE_LEN 12
#define NONCE_OFF 16
#define NONCE_LEN 24
#define PUBLIC_KEY_OFF 40
#define PUBLIC_KEY_LEN 32
#define POLY_AUTH_OFF 72
#define POLY_AUTH_LEN 16
#define TEMP_KEY_OFF 88
#define TEMP_KEY_LEN 32
#define CRYPTO_HEADER_LEN 120

/* Initialize the subtree pointers */
static gint ett_fc00      = -1;
static gint ett_fc00_auth = -1;
static gint ett_fc00_key  = -1;

static const value_string session_states[] = {
    { G_MAXUINT32, "Connect To Me" },
    { 0, "Hello" },
    { 1, "Hello" },
    { 2, "repeated Hello" },
    { 3, "Key" },
    { 4, "repeated Key" },
    { 0, NULL }
};

/* Code to actually dissect the packets */
static int
dissect_cryptoauth(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint32 session_state;
    proto_item *ti = NULL;
    proto_tree *fc00_tree = NULL;
    guint payload_len = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "fc00");
    col_clear(pinfo->cinfo, COL_INFO);

    session_state = tvb_get_ntohl(tvb, SESSION_STATE_OFF);

    if ((session_state > 3) && (session_state < G_MAXUINT32)) {
        ti = proto_tree_add_item(tree, proto_fc00, tvb, 0, SESSION_STATE_LEN, ENC_NA);
        fc00_tree = proto_item_add_subtree(ti, ett_fc00);
        proto_tree_add_item(fc00_tree, hf_fc00_session_nonce, tvb,
                SESSION_STATE_OFF, SESSION_STATE_LEN, ENC_BIG_ENDIAN);

        payload_len = tvb_reported_length(tvb)-SESSION_STATE_LEN;

        proto_tree_add_item(fc00_tree, hf_fc00_payload, tvb,
                SESSION_STATE_LEN, payload_len, ENC_NA);

        return SESSION_STATE_LEN;
    }

    ti = proto_tree_add_item(tree, proto_fc00, tvb, 0, 120, ENC_NA);
    fc00_tree = proto_item_add_subtree(ti, ett_fc00);

    proto_tree_add_item(fc00_tree, hf_fc00_session_state, tvb,
            SESSION_STATE_OFF, SESSION_STATE_LEN, ENC_NA);

    ti = proto_tree_add_item(fc00_tree, hf_fc00_auth_challenge, tvb,
            CHALLENGE_OFF, CHALLENGE_LEN, ENC_NA);
    {
        proto_tree *auth_tree = proto_item_add_subtree(ti, ett_fc00_auth);
        proto_tree_add_item(auth_tree, hf_fc00_auth_type, tvb, CHALLENGE_OFF, 1, ENC_NA);
        proto_tree_add_item(auth_tree, hf_fc00_auth_hash_code, tvb, CHALLENGE_OFF+1, 7, ENC_NA);
        proto_tree_add_item(auth_tree, hf_fc00_auth_poly, tvb, CHALLENGE_OFF+8, 1, ENC_NA);
        proto_tree_add_item(auth_tree, hf_fc00_auth_derivations, tvb, CHALLENGE_OFF+8, 2, ENC_NA);
        proto_tree_add_item(auth_tree, hf_fc00_auth_additional, tvb, CHALLENGE_OFF+10, 2, ENC_NA);
    }

    proto_tree_add_item(fc00_tree, hf_fc00_random_nonce, tvb,
            NONCE_OFF, NONCE_LEN, ENC_NA);

#if GLIB_CHECK_VERSION(2, 36, 0)  /* sha512 support was added in glib 2.36 */
    if (fc00_tree)
    {
        GChecksum *hash  = g_checksum_new(G_CHECKSUM_SHA512);
        gsize digest_len = g_checksum_type_get_length(G_CHECKSUM_SHA512);
        proto_tree *key_tree;

        guint8 *raw_key    = (guint8*)wmem_alloc(wmem_packet_scope(), PUBLIC_KEY_LEN);
        char *encoded_key = (char*)wmem_alloc(wmem_packet_scope(), 53);
        guint8 *ip_buf    = (guint8*)wmem_alloc(wmem_packet_scope(), digest_len);

        tvb_memcpy(tvb, raw_key, PUBLIC_KEY_OFF, PUBLIC_KEY_LEN);

        ws_base32_decode((guint8*)encoded_key, 53, raw_key, PUBLIC_KEY_LEN);

        g_checksum_update(hash, (guchar*)raw_key, PUBLIC_KEY_LEN);
        g_checksum_get_digest(hash, ip_buf, &digest_len);
        g_checksum_free(hash);

        hash = g_checksum_new(G_CHECKSUM_SHA512);
        g_checksum_update(hash, (guchar*)ip_buf, digest_len);
        g_checksum_get_digest(hash, ip_buf, &digest_len);
        g_checksum_free(hash);

        ti = proto_tree_add_none_format(fc00_tree, hf_fc00_public_key, tvb, PUBLIC_KEY_OFF, PUBLIC_KEY_LEN, "Public Key: %s.k", encoded_key);

        key_tree = proto_item_add_subtree(ti, ett_fc00_key);

        proto_tree_add_ipv6(key_tree, hf_fc00_ip_address, tvb, PUBLIC_KEY_OFF, PUBLIC_KEY_LEN, (ws_in6_addr*)ip_buf);
    }
#else
    proto_tree_add_expert(fc00_tree, pinfo, &ei_fc00_chksum_unsupported, tvb, PUBLIC_KEY_OFF, PUBLIC_KEY_LEN);
#endif

    proto_tree_add_item(fc00_tree, hf_fc00_authenticator, tvb,
            POLY_AUTH_OFF, POLY_AUTH_LEN, ENC_NA);

    proto_tree_add_item(fc00_tree, hf_fc00_temp_publicy_key, tvb,
            TEMP_KEY_OFF, TEMP_KEY_LEN, ENC_NA);

    payload_len = tvb_reported_length(tvb)-(TEMP_KEY_OFF+TEMP_KEY_LEN);

    proto_tree_add_item(fc00_tree, hf_fc00_payload, tvb,
            CRYPTO_HEADER_LEN, payload_len, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 */
void
proto_register_fc00(void)
{
    static hf_register_info hf[] = {
        { &hf_fc00_session_state,
          { "Session State", "fc00.session_state",
            FT_UINT32, BASE_DEC, VALS(session_states), 0x0,
            NULL, HFILL }
        },

        { &hf_fc00_session_nonce,
          { "Session Nonce", "fc00.session_nonce",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_fc00_auth_challenge,
          { "Auth Challenge", "fc00.auth_challange",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_fc00_auth_type,
          { "Auth Type", "fc00.auth_challange.type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_fc00_auth_hash_code,
          { "Auth Hash Code", "fc00.auth_challange.hash_code",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_fc00_auth_poly,
          { "Poly1305 Authentication", "fc00.auth_challange.poly1305",
            FT_UINT8, BASE_DEC, NULL, 0x80,
            NULL, HFILL }
        },

        { &hf_fc00_auth_derivations,
          { "Auth Derivations", "fc00.auth_challange.derivations",
            FT_UINT16, BASE_DEC, NULL, 0x7F,
            NULL, HFILL }
        },

        { &hf_fc00_auth_additional,
          { "Auth Additional", "fc00.auth_challange.additional",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_fc00_random_nonce,
          { "Random Nonce", "fc00.random_nonce",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_fc00_public_key,
          { "Permanent Public Key", "fc00.public_key",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Base32 encoded public key", HFILL }
        },

        { &hf_fc00_ip_address,
          { "IPv6 Address", "fc00.ip",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            "Double SHA256 hash of public key", HFILL }
        },

        { &hf_fc00_authenticator,
          { "Poly1305 Authenticator", "fc00.authenticator",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_fc00_temp_publicy_key,
          { "Encrypted/Authenticated Temporary Public Key",
            "fc00.temp_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_fc00_payload,
          { "Encrypted Payload", "fc00.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_fc00_chksum_unsupported,
            { "fc00.chksum_unsupported", PI_DECRYPTION, PI_NOTE,
                "checksum calculation is not supported",
                EXPFILL }}
    };

    static gint *ett[] = {
        &ett_fc00,
        &ett_fc00_auth,
        &ett_fc00_key
    };

    expert_module_t *expert_fc00;

    proto_fc00 = proto_register_protocol("Fc00 CryptoAuth", "Fc00", "fc00");

    proto_register_field_array(proto_fc00, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_fc00 = expert_register_protocol(proto_fc00);
    expert_register_field_array(expert_fc00, ei, array_length(ei));
}

void
proto_reg_handoff_fc00(void)
{
    dissector_handle_t fc00_handle;

    fc00_handle = create_dissector_handle(dissect_cryptoauth, proto_fc00);
    dissector_add_for_decode_as_with_preference("udp.port", fc00_handle);
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
