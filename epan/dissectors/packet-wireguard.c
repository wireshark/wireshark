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

#include <errno.h>
#include <stdbool.h>

#define WS_LOG_DOMAIN "packet-wireguard"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <epan/uat.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/curve25519.h>
#include <wsutil/wslog.h>
#include <epan/secrets.h>
#include <wiretap/secrets-types.h>

void proto_reg_handoff_wg(void);
void proto_register_wg(void);

static int proto_wg = -1;
static int hf_wg_type = -1;
static int hf_wg_reserved = -1;
static int hf_wg_sender = -1;
static int hf_wg_ephemeral = -1;
static int hf_wg_encrypted_static = -1;
static int hf_wg_static = -1;
static int hf_wg_encrypted_timestamp = -1;
static int hf_wg_timestamp_tai64_label = -1;
static int hf_wg_timestamp_nanoseconds = -1;
static int hf_wg_timestamp_value = -1;
static int hf_wg_mac1 = -1;
static int hf_wg_mac2 = -1;
static int hf_wg_receiver = -1;
static int hf_wg_encrypted_empty = -1;
static int hf_wg_handshake_ok = -1;
static int hf_wg_nonce = -1;
static int hf_wg_encrypted_cookie = -1;
static int hf_wg_counter = -1;
static int hf_wg_encrypted_packet = -1;
static int hf_wg_stream = -1;
static int hf_wg_response_in = -1;
static int hf_wg_response_to = -1;
static int hf_wg_receiver_pubkey = -1;
static int hf_wg_receiver_pubkey_known_privkey = -1;
static int hf_wg_ephemeral_known_privkey = -1;
static int hf_wg_static_known_pubkey = -1;
static int hf_wg_static_known_privkey = -1;

static gint ett_wg = -1;
static gint ett_timestamp = -1;
static gint ett_key_info = -1;

static expert_field ei_wg_bad_packet_length = EI_INIT;
static expert_field ei_wg_keepalive  = EI_INIT;
static expert_field ei_wg_decryption_error = EI_INIT;

static gboolean     pref_dissect_packet = TRUE;
static const char  *pref_keylog_file;

static dissector_handle_t ip_handle;
static dissector_handle_t wg_handle;


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
 * Pre-shared key, needed while processing the handshake response message. At
 * that point, ephemeral keys (from either the initiator or responder) should be
 * known. Thus link the PSK to such ephemeral keys.
 *
 * Usually a "wg_ekey_t" contains an empty list (if there is no PSK, i.e. an
 * all-zeroes PSK) or one item (if a PSK is configured). In the unlikely event
 * that an ephemeral key is reused, support more than one PSK.
 */
typedef struct wg_psk {
    wg_qqword psk_data;
    struct wg_psk *next;
} wg_psk_t;

/*
 * Ephemeral key.
 */
typedef struct wg_ekey {
    wg_qqword   pub_key;
    wg_qqword   priv_key;   /* Optional, set to all zeroes if missing. */
    wg_psk_t   *psk_list;   /* Optional, possible PSKs to try. */
} wg_ekey_t;

/*
 * Set of (long-term) static keys (for guessing the peer based on MAC1).
 * Maps the public key to the "wg_skey_t" structure.
 * Keys are populated from the UAT and key log file.
 */
static GHashTable *wg_static_keys = NULL;

/*
 * Set of ephemeral keys (for decryption). Maps the public key to the
 * "wg_ekey_t" structure. The private key MUST be available.
 * Keys are populated from the key log file and wmem_file_scope allocated.
 */
static wmem_map_t *wg_ephemeral_keys;

/*
 * Key log file handle. Opened on demand (when keys are actually looked up),
 * closed when the capture file closes.
 */
static FILE *wg_keylog_file;

/*
 * The most recently parsed ephemeral key. If a PSK is configured, the key log
 * file must have a PSK line after other keys. If not, then it is assumed that
 * the session does not use a PSK.
 *
 * This pointer is cleared when the key log file is reset (i.e. when the capture
 * file closes).
 */
static wg_ekey_t *wg_keylog_last_ekey;

enum wg_psk_iter_state {
    WG_PSK_ITER_STATE_ENTER = 0,
    WG_PSK_ITER_STATE_INITIATOR,
    WG_PSK_ITER_STATE_RESPONDER,
    WG_PSK_ITER_STATE_EXIT
};

/* See wg_psk_iter_next. */
typedef struct {
    enum wg_psk_iter_state state;
    wg_psk_t               *next_psk;
} wg_psk_iter_context;

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

/*
 * Input keying material for key derivation/decryption during the handshake.
 * For the Initiation message, Spub_r and either Spriv_r or Epriv_i must be set.
 * For the Response message, Epriv_r + Spriv_r or Epriv_r + Epub_i.
 *
 * The static and ephemeral keys are reset upon UAT changes or are invalidated
 * when the capture file closes.
 */
typedef struct {
    const wg_skey_t    *initiator_skey;     /* Spub_i based on Initiation.static (decrypted, null if decryption failed) */
    const wg_skey_t    *responder_skey;     /* Spub_r based on Initiation.MAC1 (+Spriv_r if available) */
    guint8              timestamp[12];      /* Initiation.timestamp (decrypted) */
    bool                timestamp_ok : 1;   /* Whether the timestamp was successfully decrypted */
    bool                empty_ok : 1;       /* Whether the empty field was successfully decrypted */

    /* The following fields are only valid on the initial pass. */
    const wg_ekey_t    *initiator_ekey;     /* Epub_i matching Initiation.Ephemeral (+Epriv_i if available) */
    const wg_ekey_t    *responder_ekey;     /* Epub_r matching Response.Ephemeral (+Epriv_r if available) */
    wg_qqword           handshake_hash;     /* Handshake hash H_i */
    wg_qqword           chaining_key;       /* Chaining key C_i */

    /* Transport ciphers. */
    gcry_cipher_hd_t    initiator_recv_cipher;
    gcry_cipher_hd_t    responder_recv_cipher;
} wg_handshake_state_t;

/** Hash(CONSTRUCTION), initialized by wg_decrypt_init. */
static wg_qqword hash_of_construction;
/** Hash(Hash(CONSTRUCTION) || IDENTIFIER), initialized by wg_decrypt_init. */
static wg_qqword hash_of_c_identifier;
/* Decryption types. }}} */

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
    wg_handshake_state_t *hs;       /* Handshake state to enable decryption. */
} wg_session_t;

/* Per-packet state. */
typedef struct {
    wg_session_t   *session;
    gboolean        receiver_is_initiator;  /* Whether this transport data packet is sent to an Initiator. */
} wg_packet_info_t;

/* Map from Sender/Receiver IDs to a list of session information. */
static wmem_map_t *sessions;
static guint32 wg_session_count;


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

static void
dh_x25519(wg_qqword *shared_secret, const wg_qqword *priv, const wg_qqword *pub)
{
    /*
     * If the point ("pub") is of small order, of if the result is all zeros, -1
     * could be returned with Sodium. We are just interpreting the trace, so
     * just ignore the condition for now.
     */
    (void)crypto_scalarmult_curve25519(shared_secret->data, priv->data, pub->data);
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

/**
 * Update the new chained hash value: h = Hash(h || data).
 */
static void
wg_mix_hash(wg_qqword *h, const void *data, size_t data_len)
{
    gcry_md_hd_t hd;
    if (gcry_md_open(&hd, GCRY_MD_BLAKE2S_256, 0)) {
        DISSECTOR_ASSERT_NOT_REACHED();
    }
    gcry_md_write(hd, h->data, sizeof(wg_qqword));
    gcry_md_write(hd, data, data_len);
    memcpy(h, gcry_md_read(hd, 0), sizeof(wg_qqword));
    gcry_md_close(hd);
}

/**
 * Computes KDF_n(key, input) where n is the number of derived keys.
 */
static void
wg_kdf(const wg_qqword *key, const guint8 *input, guint input_len, guint n, wg_qqword *out)
{
    guint8          prk[32];    /* Blake2s_256 hash output. */
    gcry_error_t    err;
    err = hkdf_extract(GCRY_MD_BLAKE2S_256, key->data, sizeof(wg_qqword), input, input_len, prk);
    DISSECTOR_ASSERT(err == 0);
    err = hkdf_expand(GCRY_MD_BLAKE2S_256, prk, sizeof(prk), NULL, 0, out->data, 32 * n);
    DISSECTOR_ASSERT(err == 0);
}

/*
 * Must be called before attempting decryption.
 */
static gboolean
wg_decrypt_init(void)
{
    if (gcry_md_test_algo(GCRY_MD_BLAKE2S_128) != 0 ||
        gcry_md_test_algo(GCRY_MD_BLAKE2S_256) != 0 ||
        gcry_cipher_test_algo(GCRY_CIPHER_CHACHA20) != 0) {
        return FALSE;
    }
    static const char construction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    gcry_md_hash_buffer(GCRY_MD_BLAKE2S_256, hash_of_construction.data, construction, strlen(construction));

    static const char wg_identifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    memcpy(&hash_of_c_identifier, hash_of_construction.data, sizeof(wg_qqword));
    wg_mix_hash(&hash_of_c_identifier, wg_identifier, strlen(wg_identifier));
    return TRUE;
}

static gcry_cipher_hd_t
wg_create_cipher(const wg_qqword *key)
{
    gcry_cipher_hd_t    hd;
    if (gcry_cipher_open(&hd, GCRY_CIPHER_CHACHA20, GCRY_CIPHER_MODE_POLY1305, 0)) {
        return NULL;
    }

    if (gcry_cipher_setkey(hd, key->data, sizeof(*key))) {
        gcry_cipher_close(hd);
        hd = NULL;
    }
    return hd;
}

static gboolean
wg_handshake_state_destroy_cb(wmem_allocator_t *allocator _U_, wmem_cb_event_t event _U_, void *user_data)
{
    wg_handshake_state_t *hs = (wg_handshake_state_t *)user_data;

    if (hs->initiator_recv_cipher) {
        gcry_cipher_close(hs->initiator_recv_cipher);
        hs->initiator_recv_cipher = NULL;
    }
    if (hs->responder_recv_cipher) {
        gcry_cipher_close(hs->responder_recv_cipher);
        hs->responder_recv_cipher = NULL;
    }
    return FALSE;
}

/*
 * Decrypt ciphertext using the ChaCha20-Poly1305 cipher. The auth tag must be
 * included with the ciphertext.
 */
static gboolean
wg_aead_decrypt(gcry_cipher_hd_t hd, guint64 counter, const guchar *ctext, guint ctext_len, const guchar *aad, guint aad_len, guchar *out, guint out_len)
{
    DISSECTOR_ASSERT(ctext_len >= AUTH_TAG_LENGTH);
    ctext_len -= AUTH_TAG_LENGTH;
    const guchar *auth_tag = ctext + ctext_len;

    counter = GUINT64_TO_LE(counter);
    guchar nonce[12] = { 0 };
    memcpy(nonce + 4, &counter, 8);

    return gcry_cipher_setiv(hd, nonce, sizeof(nonce)) == 0 &&
        gcry_cipher_authenticate(hd, aad, aad_len) == 0 &&
        gcry_cipher_decrypt(hd, out, out_len, ctext, ctext_len) == 0 &&
        gcry_cipher_checktag(hd, auth_tag, AUTH_TAG_LENGTH) == 0;
}

/**
 * Decrypt ciphertext using the ChaCha20-Poly1305 cipher. The auth tag must be
 * included with the ciphertext.
 */
static gboolean
aead_decrypt(const wg_qqword *key, guint64 counter, const guchar *ctext, guint ctext_len, const guchar *aad, guint aad_len, guchar *out, guint out_len)
{
    DISSECTOR_ASSERT(ctext_len >= AUTH_TAG_LENGTH);

    gcry_cipher_hd_t hd = wg_create_cipher(key);
    DISSECTOR_ASSERT(hd);
    gboolean ok = wg_aead_decrypt(hd, counter, ctext, ctext_len, aad, aad_len, out, out_len);
    gcry_cipher_close(hd);
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

/**
 * Stores the given ephemeral private key.
 */
static wg_ekey_t *
wg_add_ephemeral_privkey(const wg_qqword *priv_key)
{
    wg_qqword pub_key;
    priv_to_pub(&pub_key, priv_key);
    wg_ekey_t *key = (wg_ekey_t *)wmem_map_lookup(wg_ephemeral_keys, &pub_key);
    if (!key) {
        key = wmem_new0(wmem_file_scope(), wg_ekey_t);
        key->pub_key = pub_key;
        set_private_key(&key->priv_key, priv_key);
        wmem_map_insert(wg_ephemeral_keys, &key->pub_key, key);
    }
    return key;
}

/* PSK handling. {{{ */
static void
wg_add_psk(wg_ekey_t *ekey, const wg_qqword *psk)
{
    wg_psk_t *psk_entry = wmem_new0(wmem_file_scope(), wg_psk_t);
    psk_entry->psk_data = *psk;
    psk_entry->next = ekey->psk_list;
    ekey->psk_list = psk_entry;
}

/*
 * Retrieves the next PSK to try and returns TRUE if one is found or FALSE if
 * there are no more to try.
 */
static gboolean
wg_psk_iter_next(wg_psk_iter_context *psk_iter, const wg_handshake_state_t *hs,
                 wg_qqword *psk_out)
{
    wg_psk_t *psk = psk_iter->next_psk;
    while (!psk) {
        /*
         * Yield PSKs based on Epub_i, then those based on Epub_r, then yield an
         * all-zeroes key and finally fail in the terminating state.
         */
        switch (psk_iter->state) {
            case WG_PSK_ITER_STATE_ENTER:
                psk = hs->initiator_ekey->psk_list;
                psk_iter->state = WG_PSK_ITER_STATE_INITIATOR;
                break;
            case WG_PSK_ITER_STATE_INITIATOR:
                psk = hs->responder_ekey->psk_list;
                psk_iter->state = WG_PSK_ITER_STATE_RESPONDER;
                break;
            case WG_PSK_ITER_STATE_RESPONDER:
                memset(psk_out->data, 0, WG_KEY_LEN);
                psk_iter->state = WG_PSK_ITER_STATE_EXIT;
                return TRUE;
            case WG_PSK_ITER_STATE_EXIT:
                return FALSE;
        }
    }

    *psk_out = psk->psk_data;
    psk_iter->next_psk = psk->next;
    return TRUE;
}
/* PSK handling. }}} */

/* UAT and key configuration. {{{ */

static void
wg_keylog_reset(void)
{
    if (wg_keylog_file) {
        fclose(wg_keylog_file);
        wg_keylog_file = NULL;
        wg_keylog_last_ekey = NULL;
    }
}

static void wg_keylog_process_lines(const void *data, guint datalen);

static void
wg_keylog_read(void)
{
    if (!pref_keylog_file || !*pref_keylog_file) {
        return;
    }

    // Reopen file if it got deleted/overwritten.
    if (wg_keylog_file && file_needs_reopen(ws_fileno(wg_keylog_file), pref_keylog_file)) {
        ws_debug("Key log file got changed or deleted, trying to re-open.");
        wg_keylog_reset();
    }

    if (!wg_keylog_file) {
        wg_keylog_file = ws_fopen(pref_keylog_file, "r");
        if (!wg_keylog_file) {
            ws_debug("Failed to open key log file %s: %s", pref_keylog_file, g_strerror(errno));
            return;
        }
        ws_debug("Opened key log file %s", pref_keylog_file);
    }

    /* File format: each line follows the format "<type>=<key>" (leading spaces
     * and spaces around '=' as produced by extract-handshakes.sh are ignored).
     * For available <type>s, see below. <key> is the base64-encoded key (44
     * characters).
     *
     * Example:
     *  LOCAL_STATIC_PRIVATE_KEY = AKeZaHwBxjiKLFnkY2unvEdOTtg4AL+M9dQXfopFVFk=
     *  REMOTE_STATIC_PUBLIC_KEY = YDCttCs9e1J52/g9vEnwJJa+2x6RqaayAYMpSVQfGEY=
     *  LOCAL_EPHEMERAL_PRIVATE_KEY = sLGLJSOQfyz7JNJ5ZDzFf3Uz1rkiCMMjbWerNYcPFFU=
     *  PRESHARED_KEY = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
     */

    for (;;) {
        char buf[512];
        if (!fgets(buf, sizeof(buf), wg_keylog_file)) {
            if (feof(wg_keylog_file)) {
                clearerr(wg_keylog_file);
            } else if (ferror(wg_keylog_file)) {
                ws_debug("Error while reading %s, closing it.", pref_keylog_file);
                wg_keylog_reset();
            }
            break;
        }

        wg_keylog_process_lines((const guint8 *)buf, (guint)strlen(buf));
    }
}

static void
wg_keylog_process_lines(const void *data, guint datalen)
{
    const char *next_line = (const char *)data;
    const char *line_end = next_line + datalen;
    while (next_line && next_line < line_end) {
        /* Note: line is NOT nul-terminated. */
        const char *line = next_line;
        next_line = (const char *)memchr(line, '\n', line_end - line);
        gssize linelen;

        if (next_line) {
            linelen = next_line - line;
            next_line++;    /* drop LF */
        } else {
            linelen = (gssize)(line_end - line);
        }
        if (linelen > 0 && line[linelen - 1] == '\r') {
            linelen--;      /* drop CR */
        }

        ws_debug("Read WG key log line: %.*s", (int)linelen, line);

        /* Strip leading spaces. */
        const char *p = line;
        while (p < line_end && *p == ' ') {
            ++p;
        }
        char key_type[sizeof("LOCAL_EPHEMERAL_PRIVATE_KEY")];
        char key_value[45] = { 0 };
        const char *p0 = p;
        p = (const char *)memchr(p0, '=', line_end - p);
        if (p && p0 != p) {
            /* Extract "key-type" from "key-type = key-value" */
            gsize key_type_len = p - p0;
            while (key_type_len && p0[key_type_len - 1] == ' ') {
                --key_type_len;
            }
            if (key_type_len && key_type_len < sizeof(key_type)) {
                memcpy(key_type, p0, key_type_len);
                key_type[key_type_len] = '\0';

                /* Skip '=' and any spaces. */
                p = p + 1;
                while (p < line_end && *p == ' ') {
                    ++p;
                }
                gsize key_value_len = (line + linelen) - p;
                if (key_value_len && key_value_len < sizeof(key_value)) {
                    memcpy(key_value, p, key_value_len);
                }
            }
        }

        wg_qqword key;
        if (!key_value[0] || !decode_base64_key(&key, key_value)) {
            ws_debug("Unrecognized key log line: %.*s", (int)linelen, line);
            continue;
        }

        if (!strcmp(key_type, "LOCAL_STATIC_PRIVATE_KEY")) {
            wg_add_static_key(&key, TRUE);
        } else if (!strcmp(key_type, "REMOTE_STATIC_PUBLIC_KEY")) {
            wg_add_static_key(&key, FALSE);
        } else if (!strcmp(key_type, "LOCAL_EPHEMERAL_PRIVATE_KEY")) {
            wg_keylog_last_ekey = wg_add_ephemeral_privkey(&key);
        } else if (!strcmp(key_type, "PRESHARED_KEY")) {
            /* Link the PSK to the last ephemeral key. */
            if (wg_keylog_last_ekey) {
                wg_add_psk(wg_keylog_last_ekey, &key);
                wg_keylog_last_ekey = NULL;
            } else {
                ws_debug("Ignored PSK as no new ephemeral key was found");
            }
        } else {
            ws_debug("Unrecognized key log line: %.*s", (int)linelen, line);
        }
    }
}

static void*
wg_key_uat_record_copy_cb(void *dest, const void *source, size_t len _U_)
{
    const wg_key_uat_record_t* o = (const wg_key_uat_record_t*)source;
    wg_key_uat_record_t* d = (wg_key_uat_record_t*)dest;

    d->key_type = o->key_type;
    d->key = g_strdup(o->key);

    return dest;
}

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
wg_key_uat_record_free_cb(void *r)
{
    wg_key_uat_record_t *rec = (wg_key_uat_record_t *)r;
    g_free(rec->key);
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

    // As static keys from the key log file also end up in "wg_static_keys",
    // reset the file pointer such that it will be fully read later.
    wg_keylog_reset();

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
    if (wg_static_keys != NULL) {
        g_hash_table_destroy(wg_static_keys);
        wg_static_keys = NULL;
    }
}

UAT_VS_DEF(wg_key_uat, key_type, wg_key_uat_record_t, guint, WG_KEY_UAT_PUBLIC, "Public")
UAT_CSTRING_CB_DEF(wg_key_uat, key, wg_key_uat_record_t)
/* UAT and key configuration. }}} */

/**
 * Tries to decrypt the initiation message.
 * Assumes responder_skey and initiator_ekey to be set.
 */
static void
wg_process_initiation(tvbuff_t *tvb, wg_handshake_state_t *hs)
{
    DISSECTOR_ASSERT(hs->responder_skey);
    DISSECTOR_ASSERT(hs->initiator_ekey);
    DISSECTOR_ASSERT(hs->initiator_skey == NULL);

    wg_qqword decrypted_static = {{ 0 }};
    const gboolean has_Spriv_r = has_private_key(&hs->responder_skey->priv_key);
    const gboolean has_Epriv_i = has_private_key(&hs->initiator_ekey->priv_key);

    // Either Spriv_r or Epriv_i + Spriv_i are needed. If the first two are not
    // available, fail early. Spriv_i will be looked up later.
    if (!has_Spriv_r && !has_Epriv_i) {
        return;
    }

    const wg_qqword *ephemeral = (const wg_qqword *)tvb_get_ptr(tvb, 8, WG_KEY_LEN);
#define WG_ENCRYPTED_STATIC_LENGTH      (32 + AUTH_TAG_LENGTH)
    const guint8 *encrypted_static = (const guint8 *)tvb_get_ptr(tvb, 40, WG_ENCRYPTED_STATIC_LENGTH);
#define WG_ENCRYPTED_TIMESTAMP_LENGTH   (12 + AUTH_TAG_LENGTH)
    const guint8 *encrypted_timestamp = (const guint8 *)tvb_get_ptr(tvb, 88, WG_ENCRYPTED_TIMESTAMP_LENGTH);

    wg_qqword c_and_k[2], h;
    wg_qqword *c = &c_and_k[0], *k = &c_and_k[1];
    // c = Hash(CONSTRUCTION)
    memcpy(c->data, hash_of_construction.data, sizeof(wg_qqword));
    // h = Hash(c || IDENTIFIER)
    memcpy(h.data, hash_of_c_identifier.data, sizeof(wg_qqword));
    // h = Hash(h || Spub_r)
    wg_mix_hash(&h, hs->responder_skey->pub_key.data, sizeof(wg_qqword));
    // c = KDF1(c, msg.ephemeral)
    wg_kdf(c, ephemeral->data, WG_KEY_LEN, 1, c);
    // h = Hash(h || msg.ephemeral)
    wg_mix_hash(&h, ephemeral, WG_KEY_LEN);
    //  dh1 = DH(Spriv_r, msg.ephemeral)    if kType = R
    //  dh1 = DH(Epriv_i, Spub_r)           if kType = I
    wg_qqword dh1 = {{ 0 }};
    if (has_Spriv_r) {
        dh_x25519(&dh1, &hs->responder_skey->priv_key, ephemeral);
    } else {
        dh_x25519(&dh1, &hs->initiator_ekey->priv_key, &hs->responder_skey->pub_key);
    }
    // (c, k) = KDF2(c, dh1)
    wg_kdf(c, dh1.data, sizeof(dh1), 2, c_and_k);
    // Spub_i = AEAD-Decrypt(k, 0, msg.static, h)
    if (!aead_decrypt(k, 0, encrypted_static, WG_ENCRYPTED_STATIC_LENGTH, h.data, sizeof(wg_qqword), decrypted_static.data, sizeof(decrypted_static))) {
        return;
    }
    // Save static public key to the context and lookup private key if possible.
    wg_skey_t *skey_i = (wg_skey_t *)g_hash_table_lookup(wg_static_keys, &decrypted_static);
    if (!skey_i) {
        skey_i = wmem_new0(wmem_file_scope(), wg_skey_t);
        skey_i->pub_key = decrypted_static;
    }
    hs->initiator_skey = skey_i;
    // If Spriv_r is not available, then Epriv_i + Spriv_i must be available.
    if (!has_Spriv_r && !has_private_key(&hs->initiator_skey->priv_key)) {
        return;
    }

    // h = Hash(h || msg.static)
    wg_mix_hash(&h, encrypted_static, WG_ENCRYPTED_STATIC_LENGTH);
    //  dh2 = DH(Spriv_r, Spub_i)           if kType = R
    //  dh2 = DH(Spriv_i, Spub_r)           if kType = I
    wg_qqword dh2 = {{ 0 }};
    if (has_Spriv_r) {
        dh_x25519(&dh2, &hs->responder_skey->priv_key, &hs->initiator_skey->pub_key);
    } else {
        dh_x25519(&dh2, &hs->initiator_skey->priv_key, &hs->responder_skey->pub_key);
    }
    // (c, k) = KDF2(c, dh2)
    wg_kdf(c, dh2.data, sizeof(wg_qqword), 2, c_and_k);
    // timestamp = AEAD-Decrypt(k, 0, msg.timestamp, h)
    if (!aead_decrypt(k, 0, encrypted_timestamp, WG_ENCRYPTED_TIMESTAMP_LENGTH, h.data, sizeof(wg_qqword), hs->timestamp, sizeof(hs->timestamp))) {
        return;
    }
    hs->timestamp_ok = TRUE;
    // h = Hash(h || msg.timestamp)
    wg_mix_hash(&h, encrypted_timestamp, WG_ENCRYPTED_TIMESTAMP_LENGTH);

    // save (h, k) context for responder message processing
    hs->handshake_hash = h;
    hs->chaining_key = *c;
}

static void
wg_process_response(tvbuff_t *tvb, wg_handshake_state_t *hs)
{
    DISSECTOR_ASSERT(hs->initiator_ekey);
    DISSECTOR_ASSERT(hs->initiator_skey);
    DISSECTOR_ASSERT(hs->responder_ekey);
    DISSECTOR_ASSERT(hs->responder_skey);
    // XXX when multiple responses are linkable to a single handshake state,
    // they should probably fork into a new state or be discarded when equal.
    if (hs->initiator_recv_cipher || hs->responder_recv_cipher) {
        ws_warning("%s FIXME multiple responses linked to a single session", G_STRFUNC);
        return;
    }
    DISSECTOR_ASSERT(!hs->initiator_recv_cipher);
    DISSECTOR_ASSERT(!hs->responder_recv_cipher);

    const gboolean has_Epriv_i = has_private_key(&hs->initiator_ekey->priv_key);
    const gboolean has_Spriv_i = has_private_key(&hs->initiator_skey->priv_key);
    const gboolean has_Epriv_r = has_private_key(&hs->responder_ekey->priv_key);

    // Either Epriv_i + Spriv_i or Epriv_r + Epub_i + Spub_i are required.
    if (!(has_Epriv_i && has_Spriv_i) && !has_Epriv_r) {
        return;
    }

    const wg_qqword *ephemeral = (const wg_qqword *)tvb_get_ptr(tvb, 12, WG_KEY_LEN);
    const guint8 *encrypted_empty = (const guint8 *)tvb_get_ptr(tvb, 44, AUTH_TAG_LENGTH);

    wg_qqword ctk[3], h;
    wg_qqword *c = &ctk[0], *t = &ctk[1], *k = &ctk[2];
    h = hs->handshake_hash;
    *c = hs->chaining_key;

    // c = KDF1(c, msg.ephemeral)
    wg_kdf(c, ephemeral->data, WG_KEY_LEN, 1, c);
    // h = Hash(h || msg.ephemeral)
    wg_mix_hash(&h, ephemeral, WG_KEY_LEN);
    //  dh1 = DH(Epriv_i, msg.ephemeral)    if kType == I
    //  dh1 = DH(Epriv_r, Epub_i)           if kType == R
    wg_qqword dh1;
    if (has_Epriv_i && has_Spriv_i) {
        dh_x25519(&dh1, &hs->initiator_ekey->priv_key, ephemeral);
    } else {
        dh_x25519(&dh1, &hs->responder_ekey->priv_key, &hs->initiator_ekey->pub_key);
    }
    // c = KDF1(c, dh1)
    wg_kdf(c, dh1.data, sizeof(dh1), 1, c);
    //  dh2 = DH(Spriv_i, msg.ephemeral)    if kType == I
    //  dh2 = DH(Epriv_r, Spub_i)           if kType == R
    wg_qqword dh2;
    if (has_Epriv_i && has_Spriv_i) {
        dh_x25519(&dh2, &hs->initiator_skey->priv_key, ephemeral);
    } else {
        dh_x25519(&dh2, &hs->responder_ekey->priv_key, &hs->initiator_skey->pub_key);
    }
    // c = KDF1(c, dh2)
    wg_kdf(c, dh2.data, sizeof(dh2), 1, c);
    wg_qqword h_before_psk = h, c_before_psk = *c, psk;
    wg_psk_iter_context psk_iter = { WG_PSK_ITER_STATE_ENTER, NULL };
    while (wg_psk_iter_next(&psk_iter, hs, &psk)) {
        // c, t, k = KDF3(c, PSK)
        wg_kdf(c, psk.data, WG_KEY_LEN, 3, ctk);
        // h = Hash(h || t)
        wg_mix_hash(&h, t, sizeof(wg_qqword));
        // empty = AEAD-Decrypt(k, 0, msg.empty, h)
        if (!aead_decrypt(k, 0, encrypted_empty, AUTH_TAG_LENGTH, h.data, sizeof(wg_qqword), NULL, 0)) {
            /* Possibly bad PSK, reset and try another. */
            h = h_before_psk;
            *c = c_before_psk;
            continue;
        }
        hs->empty_ok = TRUE;
        break;
    }
    if (!hs->empty_ok) {
        return;
    }
    // h = Hash(h || msg.empty)
    wg_mix_hash(&h, encrypted_empty, AUTH_TAG_LENGTH);

    // Calculate transport keys and create ciphers.
    // (Tsend_i = Trecv_r, Trecv_i = Tsend_r) = KDF2(C, "")
    wg_qqword transport_keys[2];
    wg_kdf(c, NULL, 0, 2, transport_keys);

    hs->initiator_recv_cipher = wg_create_cipher(&transport_keys[1]);
    hs->responder_recv_cipher = wg_create_cipher(&transport_keys[0]);
}


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

    guint8 *mac1_msgdata = (guint8 *)tvb_memdup(wmem_packet_scope(), tvb, 0, mac1_offset);
    const guint8 *mac1_output = tvb_get_ptr(tvb, mac1_offset, 16);

    // MAC1 is computed over a message with three reserved bytes set to zero.
    mac1_msgdata[1] = mac1_msgdata[2] = mac1_msgdata[3] = 0;

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

/*
 * Builds the handshake decryption state when sufficient keying material is
 * available from the initiation message.
 */
static wg_handshake_state_t *
wg_prepare_handshake_keys(const wg_skey_t *skey_r, tvbuff_t *tvb)
{
    wg_handshake_state_t *hs;
    gboolean has_r_keys = skey_r && has_private_key(&skey_r->priv_key);
    wg_ekey_t *ekey_i = (wg_ekey_t *)wmem_map_lookup(wg_ephemeral_keys, tvb_get_ptr(tvb, 8, WG_KEY_LEN));

    // If neither private keys are available, do not create a session.
    if (!has_r_keys && !ekey_i) {
        return NULL;
    }

    // Even if Spriv_r is available, store Epub_i for Response decryption.
    if (!ekey_i) {
        ekey_i = wmem_new0(wmem_file_scope(), wg_ekey_t);
        tvb_memcpy(tvb, ekey_i->pub_key.data, 8, WG_KEY_LEN);
    }

    hs = wmem_new0(wmem_file_scope(), wg_handshake_state_t);
    hs->responder_skey = skey_r;
    hs->initiator_ekey = ekey_i;
    wmem_register_callback(wmem_file_scope(), wg_handshake_state_destroy_cb, hs);
    return hs;
}

/*
 * Processes a Response message, storing additional keys in the state.
 */
static void
wg_prepare_handshake_responder_keys(wg_handshake_state_t *hs, tvbuff_t *tvb)
{
    wg_ekey_t *ekey_r = (wg_ekey_t *)wmem_map_lookup(wg_ephemeral_keys, tvb_get_ptr(tvb, 12, WG_KEY_LEN));

    // Response decryption needs Epriv_r (or Epub_r + additional secrets).
    if (!ekey_r) {
        ekey_r = wmem_new0(wmem_file_scope(), wg_ekey_t);
        tvb_memcpy(tvb, ekey_r->pub_key.data, 12, WG_KEY_LEN);
    }

    hs->responder_ekey = ekey_r;
}

/* Converts a TAI64 label to the seconds since the Unix epoch.
 * See https://cr.yp.to/libtai/tai64.html */
static gboolean tai64n_to_unix(guint64 tai64_label, guint32 nanoseconds, nstime_t *nstime)
{
    const guint64 pow2_62 = 1ULL << 62;
    if (tai64_label < pow2_62 || tai64_label >= (1ULL << 63) || nanoseconds > 999999999) {
        // Seconds before 1970 and values larger than 2^63 (reserved) cannot
        // be represented. Nanoseconds must also be valid.
        return FALSE;
    }

    // TODO this can result in loss of precision
    nstime->secs = (time_t)(tai64_label - pow2_62);
    nstime->nsecs = (int)nanoseconds;
    return TRUE;
}

static void
wg_dissect_key_extra(proto_tree *tree, tvbuff_t *tvb, const wg_qqword *pubkey, gboolean is_ephemeral)
{
    guint32 has_private = FALSE;
    proto_item *ti;

    if (is_ephemeral) {
        wg_ekey_t *ekey = (wg_ekey_t *)wmem_map_lookup(wg_ephemeral_keys, pubkey->data);
        has_private = ekey && has_private_key(&ekey->priv_key);
    } else {
        wg_skey_t *skey = (wg_skey_t *)g_hash_table_lookup(wg_static_keys, pubkey->data);
        has_private = skey && has_private_key(&skey->priv_key);
        ti = proto_tree_add_boolean(tree, hf_wg_static_known_pubkey, tvb, 0, 0, !!skey);
        proto_item_set_generated(ti);
    }

    int hf_known_privkey = is_ephemeral ? hf_wg_ephemeral_known_privkey : hf_wg_static_known_privkey;
    ti = proto_tree_add_boolean(tree, hf_known_privkey, tvb, 0, 0, has_private);
    proto_item_set_generated(ti);
}


static void
wg_dissect_pubkey(proto_tree *tree, tvbuff_t *tvb, int offset, gboolean is_ephemeral)
{
    const guint8 *pubkey = tvb_get_ptr(tvb, offset, 32);
    gchar *str = g_base64_encode(pubkey, 32);
    gchar *key_str = wmem_strdup(wmem_packet_scope(), str);
    g_free(str);

    int hf_id = is_ephemeral ? hf_wg_ephemeral : hf_wg_static;
    proto_item *ti = proto_tree_add_string(tree, hf_id, tvb, offset, 32, key_str);
    proto_tree *key_tree = proto_item_add_subtree(ti, ett_key_info);
    wg_dissect_key_extra(key_tree, tvb, (const wg_qqword *)pubkey, is_ephemeral);
}

static void
wg_dissect_decrypted_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree, wg_handshake_state_t *hs)
{
    tvbuff_t   *new_tvb;

    if (!hs || !hs->initiator_skey) {
        return;
    }

    new_tvb = tvb_new_child_real_data(tvb, hs->initiator_skey->pub_key.data, WG_KEY_LEN, WG_KEY_LEN);
    add_new_data_source(pinfo, new_tvb, "Decrypted Static");
    wg_dissect_pubkey(wg_tree, new_tvb, 0, FALSE);
}

static void
wg_dissect_decrypted_timestamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, wg_handshake_state_t *hs)
{
    guint64     tai64_label;
    guint32     nanoseconds;
    nstime_t    nstime;
    proto_item *ti;
    tvbuff_t   *new_tvb;

    if (!hs || !hs->timestamp_ok) {
        return;
    }

    new_tvb = tvb_new_child_real_data(tvb, hs->timestamp, sizeof(hs->timestamp), sizeof(hs->timestamp));
    add_new_data_source(pinfo, new_tvb, "Decrypted Timestamp");

    tai64_label = tvb_get_guint64(new_tvb, 0, ENC_BIG_ENDIAN);
    nanoseconds = tvb_get_guint32(new_tvb, 8, ENC_BIG_ENDIAN);
    if (tai64n_to_unix(tai64_label, nanoseconds, &nstime)) {
        ti = proto_tree_add_time(tree, hf_wg_timestamp_value, new_tvb, 0, 12, &nstime);
        tree = proto_item_add_subtree(ti, ett_timestamp);
    }
    proto_tree_add_item(tree, hf_wg_timestamp_tai64_label, new_tvb, 0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_wg_timestamp_nanoseconds, new_tvb, 8, 4, ENC_BIG_ENDIAN);
}

static void
wg_dissect_decrypted_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree, wg_packet_info_t *wg_pinfo, guint64 counter, gint plain_length)
{
    wg_handshake_state_t *hs = wg_pinfo->session->hs;
    gcry_cipher_hd_t cipher = wg_pinfo->receiver_is_initiator ? hs->initiator_recv_cipher : hs->responder_recv_cipher;
    if (!cipher) {
        return;
    }

    DISSECTOR_ASSERT(plain_length >= 0);
    const gint ctext_len = plain_length + AUTH_TAG_LENGTH;
    const guchar *ctext = tvb_get_ptr(tvb, 16, ctext_len);
    guchar *plain = (guchar *)wmem_alloc0(pinfo->pool, (guint)plain_length);
    if (!wg_aead_decrypt(cipher, counter, ctext, (guint)ctext_len, NULL, 0, plain, (guint)plain_length)) {
        proto_tree_add_expert(wg_tree, pinfo, &ei_wg_decryption_error, tvb, 16, ctext_len);
        return;
    }
    if (plain_length == 0) {
        return;
    }

    tvbuff_t *new_tvb = tvb_new_child_real_data(tvb, plain, (guint)plain_length, plain_length);
    add_new_data_source(pinfo, new_tvb, "Decrypted Packet");

    proto_tree *tree = proto_item_get_parent(wg_tree);
    if (!pref_dissect_packet) {
        // (IP packet not shown, preference "Dissect transport data" is disabled)
        call_data_dissector(new_tvb, pinfo, tree);
    } else {
        call_dissector(ip_handle, new_tvb, pinfo, tree);
    }
}

static void
wg_dissect_mac1_pubkey(proto_tree *tree, tvbuff_t *tvb, const wg_skey_t *skey)
{
    proto_item *ti;

    if (!skey) {
        return;
    }

    ti = proto_tree_add_string(tree, hf_wg_receiver_pubkey, tvb, 0, 0, pubkey_to_string(&skey->pub_key));
    proto_item_set_generated(ti);
    proto_tree *key_tree = proto_item_add_subtree(ti, ett_key_info);
    ti = proto_tree_add_boolean(key_tree, hf_wg_receiver_pubkey_known_privkey, tvb, 0, 0, !!has_private_key(&skey->priv_key));
    proto_item_set_generated(ti);
}

static int
wg_dissect_handshake_initiation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree, wg_packet_info_t *wg_pinfo)
{
    guint32 sender_id;
    proto_item *ti;

    wg_keylog_read();
    const wg_skey_t *skey_r = wg_mac1_key_probe(tvb, TRUE);
    wg_handshake_state_t *hs = NULL;

    if (!PINFO_FD_VISITED(pinfo)) {
        if (skey_r) {
            hs = wg_prepare_handshake_keys(skey_r, tvb);
            if (hs) {
                wg_process_initiation(tvb, hs);
            }
        }
    } else if (wg_pinfo && wg_pinfo->session) {
        hs = wg_pinfo->session->hs;
    }

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_sender, tvb, 4, 4, ENC_LITTLE_ENDIAN, &sender_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", sender=0x%08X", sender_id);
    wg_dissect_pubkey(wg_tree, tvb, 8, TRUE);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_static, tvb, 40, 32 + AUTH_TAG_LENGTH, ENC_NA);
    wg_dissect_decrypted_static(tvb, pinfo, wg_tree, hs);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_timestamp, tvb, 88, 12 + AUTH_TAG_LENGTH, ENC_NA);
    wg_dissect_decrypted_timestamp(tvb, pinfo, wg_tree, hs);
    proto_tree_add_item(wg_tree, hf_wg_mac1, tvb, 116, 16, ENC_NA);
    wg_dissect_mac1_pubkey(wg_tree, tvb, skey_r);
    proto_tree_add_item(wg_tree, hf_wg_mac2, tvb, 132, 16, ENC_NA);

    if (!PINFO_FD_VISITED(pinfo)) {
        /* XXX should an initiation message with the same contents (except MAC2) be
         * considered part of the same "session"? */
        wg_session_t *session = wg_session_new();
        session->initiator_frame = pinfo->num;
        wg_session_update_address(session, pinfo, TRUE);
        session->hs = hs;
        wg_sessions_insert(sender_id, session);
        wg_pinfo->session = session;
    }
    wg_session_t *session = wg_pinfo ? wg_pinfo->session : NULL;
    if (session) {
        ti = proto_tree_add_uint(wg_tree, hf_wg_stream, tvb, 0, 0, session->stream);
        proto_item_set_generated(ti);
    }
    if (session && session->response_frame) {
        ti = proto_tree_add_uint(wg_tree, hf_wg_response_in, tvb, 0, 0, session->response_frame);
        proto_item_set_generated(ti);
    }

    return 148;
}

static int
wg_dissect_handshake_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wg_tree, wg_packet_info_t *wg_pinfo)
{
    guint32 sender_id, receiver_id;
    proto_item *ti;
    wg_session_t *session;

    wg_keylog_read();
    const wg_skey_t *skey_i = wg_mac1_key_probe(tvb, FALSE);

    proto_tree_add_item_ret_uint(wg_tree, hf_wg_sender, tvb, 4, 4, ENC_LITTLE_ENDIAN, &sender_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", sender=0x%08X", sender_id);
    proto_tree_add_item_ret_uint(wg_tree, hf_wg_receiver, tvb, 8, 4, ENC_LITTLE_ENDIAN, &receiver_id);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", receiver=0x%08X", receiver_id);

    if (!PINFO_FD_VISITED(pinfo)) {
        session = wg_sessions_lookup_initiation(pinfo, receiver_id);
        if (session && session->hs) {
            wg_prepare_handshake_responder_keys(session->hs, tvb);
            wg_process_response(tvb, session->hs);
        }
    } else {
        session = wg_pinfo ? wg_pinfo->session : NULL;
    }

    wg_dissect_pubkey(wg_tree, tvb, 12, TRUE);
    proto_tree_add_item(wg_tree, hf_wg_encrypted_empty, tvb, 44, 16, ENC_NA);
    if (session && session->hs) {
        ti = proto_tree_add_boolean(wg_tree, hf_wg_handshake_ok, tvb, 0, 0, !!session->hs->empty_ok);
        proto_item_set_generated(ti);
    }
    proto_tree_add_item(wg_tree, hf_wg_mac1, tvb, 60, 16, ENC_NA);
    wg_dissect_mac1_pubkey(wg_tree, tvb, skey_i);
    proto_tree_add_item(wg_tree, hf_wg_mac2, tvb, 76, 16, ENC_NA);

    if (!PINFO_FD_VISITED(pinfo)) {
        /* XXX should probably check whether decryption succeeds before linking
         * and somehow mark that this response is related but not correct. */
        if (session) {
            session->response_frame = pinfo->num;
            wg_session_update_address(session, pinfo, FALSE);
            wg_sessions_insert(sender_id, session);
            wg_pinfo->session = session;
        }
    }
    if (session) {
        ti = proto_tree_add_uint(wg_tree, hf_wg_stream, tvb, 0, 0, session->stream);
        proto_item_set_generated(ti);
        ti = proto_tree_add_uint(wg_tree, hf_wg_response_to, tvb, 0, 0, session->initiator_frame);
        proto_item_set_generated(ti);
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
        session = wg_pinfo ? wg_pinfo->session : NULL;
    }
    if (session) {
        ti = proto_tree_add_uint(wg_tree, hf_wg_stream, tvb, 0, 0, session->stream);
        proto_item_set_generated(ti);
        /* XXX check for cookie reply from Initiator to Responder */
        ti = proto_tree_add_uint(wg_tree, hf_wg_response_to, tvb, 0, 0, session->initiator_frame);
        proto_item_set_generated(ti);
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
    col_append_fstr(pinfo->cinfo, COL_INFO, ", counter=%" PRIu64, counter);

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
            wg_pinfo->receiver_is_initiator = receiver_is_initiator;
        }
    } else {
        session = wg_pinfo ? wg_pinfo->session : NULL;
    }
    if (session) {
        ti = proto_tree_add_uint(wg_tree, hf_wg_stream, tvb, 0, 0, session->stream);
        proto_item_set_generated(ti);
    }

    if (session && session->hs) {
        wg_dissect_decrypted_packet(tvb, pinfo, wg_tree, wg_pinfo, counter, packet_length - AUTH_TAG_LENGTH);
    }

    return 16 + packet_length;
}

static gboolean
wg_is_valid_message_length(guint8 message_type, guint length)
{
    switch (message_type) {
    case WG_TYPE_HANDSHAKE_INITIATION:
        return length == 148;
    case WG_TYPE_HANDSHAKE_RESPONSE:
        return length == 92;
    case WG_TYPE_COOKIE_REPLY:
        return length == 64;
    case WG_TYPE_TRANSPORT_DATA:
        return length >= 32;
    default:
        return FALSE;
    }
}

static int
dissect_wg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *wg_tree;
    guint32     message_type;
    const char *message_type_str;
    wg_packet_info_t *wg_pinfo;

    message_type = tvb_get_guint8(tvb, 0);
    message_type_str = try_val_to_str(message_type, wg_type_names);
    if (!message_type_str)
        return 0;

    if (!wg_is_valid_message_length(message_type, tvb_reported_length(tvb))) {
        return 0;
    }

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
        /*
         * Note: this may be NULL if the heuristics dissector sets a
         * conversation dissector later in the stream, for example due to a new
         * Handshake Initiation message. Previous messages are potentially
         * Transport Data messages which might not be detected through
         * heuristics.
         */
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

static gboolean
dissect_wg_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /*
     * Heuristics to detect the WireGuard protocol:
     * - The first byte must be one of the valid four messages.
     * - The total packet length depends on the message type, and is fixed for
     *   three of them. The Data type has a minimum length however.
     * - The next three bytes are reserved and zero in the official protocol.
     *   Cloudflare's implementation however uses this field for load balancing
     *   purposes, so this condition is not checked here for most messages.
     *   It is checked for data messages to avoid false positives.
     */
    guint32     message_type;
    gboolean    reserved_is_zeroes;

    if (tvb_reported_length(tvb) < 4)
        return FALSE;

    message_type = tvb_get_guint8(tvb, 0);
    reserved_is_zeroes = tvb_get_ntoh24(tvb, 1) == 0;

    if (!wg_is_valid_message_length(message_type, tvb_reported_length(tvb))) {
        return FALSE;
    }

    switch (message_type) {
        case WG_TYPE_COOKIE_REPLY:
        case WG_TYPE_TRANSPORT_DATA:
            if (!reserved_is_zeroes)
                return FALSE;
            break;
    }

    /*
     * Assuming that this is a new handshake, make sure that future messages are
     * directed to our dissector. This ensures that cookie replies and data
     * messages using non-zero reserved bytes are still properly recognized.
     * An edge case occurs when the address or port change. In that case, Data
     * messages using non-zero reserved bytes will not be recognized. The user
     * can use Decode As for this case.
     */
    if (message_type == WG_TYPE_HANDSHAKE_INITIATION) {
        conversation_t *conversation = find_or_create_conversation(pinfo);
        conversation_set_dissector(conversation, wg_handle);
    }

    dissect_wg(tvb, pinfo, tree, NULL);
    return TRUE;
}

static void
wg_init(void)
{
    wg_session_count = 0;
}

void
proto_register_wg(void)
{
    module_t        *wg_module;
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
            FT_BYTES, BASE_NONE, NULL, 0x0,
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
        { &hf_wg_static,
          { "Static Public Key", "wg.static",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Long-term static public key of sender", HFILL }
        },
        { &hf_wg_encrypted_timestamp,
          { "Encrypted Timestamp", "wg.encrypted_timestamp",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wg_timestamp_tai64_label,
          { "TAI64 Label", "wg.timestamp.tai64_label",
            FT_UINT64, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wg_timestamp_nanoseconds,
          { "Nanoseconds", "wg.timestamp.nanoseconds",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_wg_timestamp_value,
          { "Timestamp", "wg.timestamp.value",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
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
        { &hf_wg_handshake_ok,
          { "Handshake decryption successful", "wg.handshake_ok",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Whether decryption keys were successfully derived", HFILL }
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
        { &hf_wg_ephemeral_known_privkey,
          { "Has Private Key", "wg.ephemeral.known_privkey",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Whether the corresponding private key is known (configured via prefs)", HFILL }
        },
        { &hf_wg_static_known_pubkey,
          { "Known Public Key", "wg.static.known_pubkey",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Whether this public key is known (configured via prefs)", HFILL }
        },
        { &hf_wg_static_known_privkey,
          { "Has Private Key", "wg.static.known_privkey",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Whether the corresponding private key is known (configured via prefs)", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_wg,
        &ett_timestamp,
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
        { &ei_wg_decryption_error,
          { "wg.decryption_error", PI_DECRYPTION, PI_WARN,
            "Packet data decryption failed", EXPFILL }
        },
    };

    /* UAT for header fields */
    static uat_field_t wg_key_uat_fields[] = {
        UAT_FLD_VS(wg_key_uat, key_type, "Key type", wg_key_uat_type_vals, "Public or Private"),
        UAT_FLD_CSTRING(wg_key_uat, key, "Key", "Base64-encoded key"),
        UAT_END_FIELDS
    };

    proto_wg = proto_register_protocol("WireGuard Protocol", "WireGuard", "wg");

    proto_register_field_array(proto_wg, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_wg = expert_register_protocol(proto_wg);
    expert_register_field_array(expert_wg, ei, array_length(ei));

    wg_handle = register_dissector("wg", dissect_wg, proto_wg);

    wg_module = prefs_register_protocol(proto_wg, NULL);

    uat_t *wg_keys_uat = uat_new("WireGuard static keys",
            sizeof(wg_key_uat_record_t),
            "wg_keys",                      /* filename */
            TRUE,                           /* from_profile */
            &wg_key_records,                /* data_ptr */
            &num_wg_key_records,            /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
            NULL,                           /* Help section (currently a wiki page) */
            wg_key_uat_record_copy_cb,      /* copy_cb */
            wg_key_uat_record_update_cb,    /* update_cb */
            wg_key_uat_record_free_cb,      /* free_cb */
            wg_key_uat_apply,               /* post_update_cb */
            wg_key_uat_reset,               /* reset_cb */
            wg_key_uat_fields);

    prefs_register_uat_preference(wg_module, "keys",
            "WireGuard static keys",
            "A table of long-term static keys to enable WireGuard peer identification or partial decryption",
            wg_keys_uat);

    prefs_register_bool_preference(wg_module, "dissect_packet",
            "Dissect transport data",
            "Whether the IP dissector should dissect decrypted transport data.",
            &pref_dissect_packet);

    prefs_register_filename_preference(wg_module, "keylog_file", "Key log filename",
            "The path to the file which contains a list of secrets in the following format:\n"
            "\"<key-type> = <base64-encoded-key>\" (without quotes, leading spaces and spaces around '=' are ignored).\n"
            "<key-type> is one of: LOCAL_STATIC_PRIVATE_KEY, REMOTE_STATIC_PUBLIC_KEY, "
            "LOCAL_EPHEMERAL_PRIVATE_KEY or PRESHARED_KEY.",
            &pref_keylog_file, FALSE);

    if (!wg_decrypt_init()) {
        ws_warning("%s: decryption will not be possible due to lack of algorithms support", G_STRFUNC);
    }

    secrets_register_type(SECRETS_TYPE_WIREGUARD, wg_keylog_process_lines);

    wg_ephemeral_keys = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_int_hash, wg_pubkey_equal);

    register_init_routine(wg_init);
    register_cleanup_routine(wg_keylog_reset);
    sessions = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
}

void
proto_reg_handoff_wg(void)
{
    dissector_add_uint_with_preference("udp.port", 0, wg_handle);
    heur_dissector_add("udp", dissect_wg_heur, "WireGuard", "wg", proto_wg, HEURISTIC_ENABLE);

    ip_handle = find_dissector("ip");
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
