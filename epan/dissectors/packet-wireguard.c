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
#include <epan/uat.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/curve25519.h>

#if GCRYPT_VERSION_NUMBER >= 0x010800 /* 1.8.0 */
/* Decryption requires Curve25519, ChaCha20-Poly1305 (1.7) and Blake2s (1.8). */
#define WG_DECRYPTION_SUPPORTED
#endif

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
static int hf_wg_receiver_pubkey = -1;
static int hf_wg_receiver_pubkey_known_privkey = -1;

static gint ett_wg = -1;
static gint ett_key_info = -1;

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

#ifdef WG_DECRYPTION_SUPPORTED
/* Decryption types. {{{ */
/*
 * Most operations operate on 32 byte units (keys and hash output).
 */
typedef struct {
#define WG_KEY_LEN  32
    guchar data[WG_KEY_LEN];
} wg_qqword;

/*
 * Static key with the MAC1 key pre-computed and an optional private key.
 */
typedef struct wg_skey {
    wg_qqword   pub_key;
    wg_qqword   mac1_key;
    wg_qqword   priv_key;   /* Optional, set to all zeroes if missing. */
} wg_skey_t;

/*
 * Set of (long-term) static keys (for guessing the peer based on MAC1).
 * Maps the public key to the "wg_skey_t" structure.
 * Keys are populated from the UAT and key log file.
 */
static GHashTable *wg_static_keys;

/* UAT adapter for populating wg_static_keys. */
enum { WG_KEY_UAT_PUBLIC, WG_KEY_UAT_PRIVATE };
static const value_string wg_key_uat_type_vals[] = {
    { WG_KEY_UAT_PUBLIC, "Public" },
    { WG_KEY_UAT_PRIVATE, "Private" },
    { 0, NULL }
};

typedef struct {
    guint   key_type;   /* See "wg_key_uat_type_vals". */
    char   *key;
} wg_key_uat_record_t;

static wg_key_uat_record_t *wg_key_records;
static guint num_wg_key_records;
/* Decryption types. }}} */
#endif /* WG_DECRYPTION_SUPPORTED */

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


#ifdef WG_DECRYPTION_SUPPORTED
/* Key conversion routines. {{{ */
/* Import external random data as private key. */
static void
set_private_key(wg_qqword *privkey, const wg_qqword *inkey)
{
    // The 254th bit of a Curve25519 secret will always be set in calculations,
    // use this property to recognize whether a private key is set.
    *privkey = *inkey;
    privkey->data[31] |= 64;
}

/* Whether a private key is initialized (see set_private_key). */
static inline gboolean
has_private_key(const wg_qqword *secret)
{
    return !!(secret->data[31] & 64);
}

/**
 * Compute the Curve25519 public key from a private key.
 */
static void
priv_to_pub(wg_qqword *pub, const wg_qqword *priv)
{
    int r = crypto_scalarmult_curve25519_base(pub->data, priv->data);
    /* The computation should always be possible. */
    DISSECTOR_ASSERT(r == 0);
}

/*
 * Returns the string representation (base64) of a public key.
 * The returned value is allocated with wmem_packet_scope.
 */
static const char *
pubkey_to_string(const wg_qqword *pubkey)
{
    gchar *str = g_base64_encode(pubkey->data, WG_KEY_LEN);
    gchar *ret = wmem_strdup(wmem_packet_scope(), str);
    g_free(str);
    return ret;
}

static gboolean
decode_base64_key(wg_qqword *out, const char *str)
{
    gsize out_len;
    gchar tmp[45];

    if (strlen(str) + 1 != sizeof(tmp)) {
        return FALSE;
    }
    memcpy(tmp, str, sizeof(tmp));
    g_base64_decode_inplace(tmp, &out_len);
    if (out_len != WG_KEY_LEN) {
        return FALSE;
    }
    memcpy(out->data, tmp, WG_KEY_LEN);
    return TRUE;
}
/* Key conversion routines. }}} */

static gboolean
wg_pubkey_equal(gconstpointer v1, gconstpointer v2)
{
    const wg_qqword *pubkey1 = (const wg_qqword *)v1;
    const wg_qqword *pubkey2 = (const wg_qqword *)v2;
    return !memcmp(pubkey1->data, pubkey2->data, WG_KEY_LEN);
}


/* Protocol-specific crypto routines. {{{ */
/**
 * Computes MAC1. Caller must ensure that GCRY_MD_BLAKE2S_256 is available.
 */
static void
wg_mac1_key(const wg_qqword *static_public, wg_qqword *mac_key_out)
{
    gcry_md_hd_t hd;
    if (gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0) == 0) {
        const char wg_label_mac1[] = "mac1----";
        gcry_md_write(hd, wg_label_mac1, strlen(wg_label_mac1));
        gcry_md_write(hd, static_public->data, sizeof(wg_qqword));
        memcpy(mac_key_out->data, gcry_md_read(hd, 0), sizeof(wg_qqword));
        gcry_md_close(hd);
        return;
    }
    // caller should have checked this.
    DISSECTOR_ASSERT_NOT_REACHED();
}

/*
 * Verify that MAC(mac_key, data) matches "mac_output".
 */
static gboolean
wg_mac_verify(const wg_qqword *mac_key,
              const guchar *data, guint data_len, const guint8 mac_output[16])
{
    gboolean ok = FALSE;
    gcry_md_hd_t hd;
    if (gcry_md_open(&hd, GCRY_MD_BLAKE2S_128, 0) == 0) {
        gcry_error_t r;
        // not documented by Libgcrypt, but required for keyed blake2s
        r = gcry_md_setkey(hd, mac_key->data, WG_KEY_LEN);
        DISSECTOR_ASSERT(r == 0);
        gcry_md_write(hd, data, data_len);
        ok = memcmp(mac_output, gcry_md_read(hd, 0), 16) == 0;
        gcry_md_close(hd);
    } else {
        // caller should have checked this.
        DISSECTOR_ASSERT_NOT_REACHED();
    }
    return ok;
}
/* Protocol-specific crypto routines. }}} */

/*
 * Add a static public or private key to "wg_static_keys".
 */
static void
wg_add_static_key(const wg_qqword *tmp_key, gboolean is_private)
{
    wg_skey_t *key = g_new0(wg_skey_t, 1);
    if (is_private) {
        set_private_key(&key->priv_key, tmp_key);
        priv_to_pub(&key->pub_key, tmp_key);
    } else {
        key->pub_key = *tmp_key;
    }

    // If a previous pubkey exists, skip adding the new key. Do add the
    // secret if it has become known in meantime.
    wg_skey_t *oldkey = (wg_skey_t *)g_hash_table_lookup(wg_static_keys, &key->pub_key);
    if (oldkey) {
        if (!has_private_key(&oldkey->priv_key) && is_private) {
            oldkey->priv_key = key->priv_key;
        }
        g_free(key);
        return;
    }

    // New key, precompute the MAC1 label.
    wg_mac1_key(&key->pub_key, &key->mac1_key);

    g_hash_table_insert(wg_static_keys, &key->pub_key, key);
}

/* UAT and key configuration. {{{ */
static gboolean
wg_key_uat_record_update_cb(void *r, char **error)
{
    wg_key_uat_record_t *rec = (wg_key_uat_record_t *)r;
    wg_qqword key;

    /* Check for valid base64-encoding. */
    if (!decode_base64_key(&key, rec->key)) {
        *error = g_strdup("Invalid key");
        return FALSE;
    }

    return TRUE;
}

static void
wg_key_uat_apply(void)
{
    if (!wg_static_keys) {
        // The first field of "wg_skey_t" is the pubkey (and the table key),
        // its initial four bytes should be good enough as key hash.
        wg_static_keys = g_hash_table_new_full(g_int_hash, wg_pubkey_equal, NULL, g_free);
    } else {
        g_hash_table_remove_all(wg_static_keys);
    }

    /* Convert base64-encoded strings to wg_skey_t and derive pubkey. */
    for (guint i = 0; i < num_wg_key_records; i++) {
        wg_key_uat_record_t *rec = &wg_key_records[i];
        wg_qqword tmp_key;  /* Either public or private, not sure yet. */

        /* Populate public (and private) keys. */
        gboolean decoded = decode_base64_key(&tmp_key, rec->key);
        DISSECTOR_ASSERT(decoded);
        wg_add_static_key(&tmp_key, rec->key_type == WG_KEY_UAT_PRIVATE);
    }
}

static void
wg_key_uat_reset(void)
{
    /* Erase keys when the UAT is unloaded. */
    g_hash_table_destroy(wg_static_keys);
    wg_static_keys = NULL;
}

UAT_VS_DEF(wg_key_uat, key_type, wg_key_uat_record_t, guint, WG_KEY_UAT_PUBLIC, "Public")
UAT_CSTRING_CB_DEF(wg_key_uat, key, wg_key_uat_record_t)
/* UAT and key configuration. }}} */
#endif /* WG_DECRYPTION_SUPPORTED */


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

#ifdef WG_DECRYPTION_SUPPORTED
/*
 * Finds the static public key for the receiver of this message based on the
 * MAC1 value.
 * TODO on PINFO_FD_VISITED, reuse previously discovered keys from session?
 */
static const wg_skey_t *
wg_mac1_key_probe(tvbuff_t *tvb, gboolean is_initiation)
{
    const int mac1_offset = is_initiation ? 116 : 60;

    // Shortcut: skip MAC1 validation if no pubkeys are configured.
    if (g_hash_table_size(wg_static_keys) == 0) {
        return NULL;
    }

    const guint8 *mac1_msgdata = tvb_get_ptr(tvb, 0, mac1_offset);
    const guint8 *mac1_output = tvb_get_ptr(tvb, mac1_offset, 16);
    // Find public key that matches the 16-byte MAC1 field.
    GHashTableIter iter;
    gpointer value;
    g_hash_table_iter_init(&iter, wg_static_keys);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        const wg_skey_t *skey = (wg_skey_t *)value;
        if (wg_mac_verify(&skey->mac1_key, mac1_msgdata, (guint)mac1_offset, mac1_output)) {
            return skey;
        }
    }

    return NULL;
}
#endif /* WG_DECRYPTION_SUPPORTED */


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

#ifdef WG_DECRYPTION_SUPPORTED
static void
wg_dissect_mac1_pubkey(proto_tree *tree, tvbuff_t *tvb, const wg_skey_t *skey)
{
    proto_item *ti;

    if (!skey) {
        return;
    }

    ti = proto_tree_add_string(tree, hf_wg_receiver_pubkey, tvb, 0, 0, pubkey_to_string(&skey->pub_key));
    PROTO_ITEM_SET_GENERATED(ti);
    proto_tree *key_tree = proto_item_add_subtree(ti, ett_key_info);
    ti = proto_tree_add_boolean(key_tree, hf_wg_receiver_pubkey_known_privkey, tvb, 0, 0, !!has_private_key(&skey->priv_key));
    PROTO_ITEM_SET_GENERATED(ti);
}
#endif /* WG_DECRYPTION_SUPPORTED */

static int
wg_dissect_handshake_initiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree, wg_packet_info_t *wg_pinfo)
{
    guint32 sender_id;
    proto_item *ti;

#ifdef WG_DECRYPTION_SUPPORTED
    const wg_skey_t *skey_r = wg_mac1_key_probe(tvb, TRUE);
#endif /* WG_DECRYPTION_SUPPORTED */

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_sender, tvb, 4, 4, ENC_LITTLE_ENDIAN, &sender_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", sender=0x%08X", sender_id);
    wg_dissect_pubkey(wg_tree, tvb, 8, TRUE);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_static, tvb, 40, 32 + AUTH_TAG_LENGTH, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_timestamp, tvb, 88, 12 + AUTH_TAG_LENGTH, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_mac1, tvb, 116, 16, ENC_NA);
#ifdef WG_DECRYPTION_SUPPORTED
    wg_dissect_mac1_pubkey(wg_tree, tvb, skey_r);
#endif /* WG_DECRYPTION_SUPPORTED */
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

#ifdef WG_DECRYPTION_SUPPORTED
    const wg_skey_t *skey_i = wg_mac1_key_probe(tvb, FALSE);
#endif /* WG_DECRYPTION_SUPPORTED */

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_sender, tvb, 4, 4, ENC_LITTLE_ENDIAN, &sender_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", sender=0x%08X", sender_id);
    proto_tree_add_item_ret_uint(wg_tree, hf_wg_receiver, tvb, 8, 4, ENC_LITTLE_ENDIAN, &receiver_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", receiver=0x%08X", receiver_id);
    wg_dissect_pubkey(wg_tree, tvb, 12, TRUE);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_empty, tvb, 44, 16, ENC_NA);
    proto_tree_add_item(wg_tree, hf_wg_mac1, tvb, 60, 16, ENC_NA);
#ifdef WG_DECRYPTION_SUPPORTED
    wg_dissect_mac1_pubkey(wg_tree, tvb, skey_i);
#endif /* WG_DECRYPTION_SUPPORTED */
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
#ifdef WG_DECRYPTION_SUPPORTED
    module_t        *wg_module;
#endif /* WG_DECRYPTION_SUPPORTED */
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

        /* Additional fields. */
        { &hf_wg_receiver_pubkey,
          { "Receiver Static Public Key", "wg.receiver_pubkey",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Public key of the receiver (matched based on MAC1)", HFILL }
        },
        { &hf_wg_receiver_pubkey_known_privkey,
          { "Has Private Key", "wg.receiver_pubkey.known_privkey",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Whether the corresponding private key is known (configured via prefs)", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_wg,
        &ett_key_info,
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

#ifdef WG_DECRYPTION_SUPPORTED
    /* UAT for header fields */
    static uat_field_t wg_key_uat_fields[] = {
        UAT_FLD_VS(wg_key_uat, key_type, "Key type", wg_key_uat_type_vals, "Public or Private"),
        UAT_FLD_CSTRING(wg_key_uat, key, "Key", "Base64-encoded key"),
        UAT_END_FIELDS
    };
#endif /* WG_DECRYPTION_SUPPORTED */

    proto_wg = proto_register_protocol("WireGuard Protocol", "WireGuard", "wg");

    proto_register_field_array(proto_wg, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_wg = expert_register_protocol(proto_wg);
    expert_register_field_array(expert_wg, ei, array_length(ei));

    register_dissector("wg", dissect_wg, proto_wg);

#ifdef WG_DECRYPTION_SUPPORTED
    wg_module = prefs_register_protocol(proto_wg, NULL);

    uat_t *wg_keys_uat = uat_new("WireGuard static keys",
            sizeof(wg_key_uat_record_t),
            "wg_keys",                      /* filename */
            TRUE,                           /* from_profile */
            &wg_key_records,                /* data_ptr */
            &num_wg_key_records,            /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
            NULL,                           /* Help section (currently a wiki page) */
            NULL,                           /* copy_cb */
            wg_key_uat_record_update_cb,    /* update_cb */
            NULL,                           /* free_cb */
            wg_key_uat_apply,               /* post_update_cb */
            wg_key_uat_reset,               /* reset_cb */
            wg_key_uat_fields);

    prefs_register_uat_preference(wg_module, "keys",
            "WireGuard static keys",
            "A table of long-term static keys to enable WireGuard peer identification or partial decryption",
            wg_keys_uat);
#endif /* WG_DECRYPTION_SUPPORTED */

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
