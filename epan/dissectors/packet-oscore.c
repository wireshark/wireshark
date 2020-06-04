/* packet-oscore.c
 * Routines for Object Security for Constrained RESTful Environments dissection
 * Copyright 2017, Malisa Vucinic <malishav@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 *  rfc8613
 */

#include <config.h>

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/proto_data.h>
#include <epan/expert.h>   /* Include only as needed */
#include <epan/uat.h>
#include <epan/strutil.h>
#include <epan/prefs.h>    /* Include only as needed */
#include <epan/to_str.h>

#include <wsutil/wsgcrypt.h>
#include "packet-ieee802154.h" /* We use CCM implementation available as part of 802.15.4 dissector */
#include "packet-coap.h" /* packet-coap.h includes packet-oscore.h */

/* Prototypes */
static guint oscore_alg_get_key_len(cose_aead_alg_t);
static guint oscore_alg_get_iv_len(cose_aead_alg_t);
static guint oscore_alg_get_tag_len(cose_aead_alg_t);
static gboolean oscore_context_derive_params(oscore_context_t *);

/* CBOR encoder prototypes */
static guint8 cborencoder_put_text(guint8 *buffer, const char *text, guint8 text_len);
static guint8 cborencoder_put_null(guint8 *buffer);
static guint8 cborencoder_put_unsigned(guint8 *buffer, guint8 value);
static guint8 cborencoder_put_bytes(guint8 *buffer, const guint8 *bytes, guint8 bytes_len);
static guint8 cborencoder_put_array(guint8 *buffer, guint8 elements);

/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_oscore(void);
void proto_register_oscore(void);

/* Initialize the protocol and registered fields */
static int proto_oscore                             = -1;
static int proto_coap                               = -1;

static int hf_oscore_tag                            = -1;

static COAP_COMMON_LIST_T(dissect_oscore_hf);

static expert_field ei_oscore_partial_iv_not_found    = EI_INIT;
static expert_field ei_oscore_context_not_set         = EI_INIT;
static expert_field ei_oscore_message_too_small       = EI_INIT;
static expert_field ei_oscore_truncated               = EI_INIT;
static expert_field ei_oscore_tag_check_failed        = EI_INIT;
static expert_field ei_oscore_decrypt_error           = EI_INIT;
static expert_field ei_oscore_cbc_mac_failed          = EI_INIT;
static expert_field ei_oscore_piv_len_invalid         = EI_INIT;
static expert_field ei_oscore_info_fetch_failed       = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_oscore                                = -1;

/* UAT variables */
static uat_t            *oscore_context_uat = NULL;
static oscore_context_t *oscore_contexts = NULL;
static guint            num_oscore_contexts = 0;

/* Enumeration for COSE algorithms used by OSCORE */
static const value_string oscore_context_alg_vals[] = {
    { COSE_AES_CCM_16_64_128, "AES-CCM-16-64-128 (CCM*)"},
    { 0, NULL }
};

/* Field callbacks. */
UAT_CSTRING_CB_DEF(oscore_context_uat, master_secret_prefs, oscore_context_t)
UAT_CSTRING_CB_DEF(oscore_context_uat, master_salt_prefs, oscore_context_t)
UAT_CSTRING_CB_DEF(oscore_context_uat, id_context_prefs, oscore_context_t)
UAT_CSTRING_CB_DEF(oscore_context_uat, sender_id_prefs, oscore_context_t)
UAT_CSTRING_CB_DEF(oscore_context_uat, recipient_id_prefs, oscore_context_t)
UAT_VS_DEF(oscore_context_uat, algorithm, oscore_context_t, cose_aead_alg_t, COSE_AES_CCM_16_64_128, "AES-CCM-16-64-128 (CCM*)")

#define OSCORE_MIN_LENGTH               9 /* 1 byte for code plus 8 bytes for shortest authentication tag */
#define OSCORE_VERSION                  1 /* rfc8613 */
#define TAG_MAX_LEN                     16
#define AES_128_BLOCK_LEN               16
#define NONCE_MAX_LEN                   13 /* longest nonce in RFC8152 is 13 bytes */

#define OSCORE_PIV_MAX_LEN              5 /* upper bound specified in the draft */
#define OSCORE_KID_MAX_LEN_CCM_STAR     7 /* upper bound on KID for AES-CCM-16-64-128 (CCM*) */
#define OSCORE_KID_MAX_LEN              OSCORE_KID_MAX_LEN_CCM_STAR /* upper bound on KID coming from the default algorithm implemented */
#define OSCORE_KID_CONTEXT_MAX_LEN      64

/* Helper macros to correctly size the statically allocated buffers and verify if an overflow occured */

#define OSCORE_INFO_MAX_LEN             (1 + /* max return of cborencoder_put_array() */             \
                                        2 + OSCORE_KID_MAX_LEN + /* max 2 to encode length, KID following */ \
                                        2 + OSCORE_KID_CONTEXT_MAX_LEN + /* length + KID CONTEXT */ \
                                        2 + /* max return of cborencoder_put_unsigned() */          \
                                        2 + 3 + /* max 2 to encode length, "Key" following */       \
                                        2 /* max return of cborencoder_put_unsigned() */            )

#define OSCORE_EXTERNAL_AAD_MAX_LEN     (1 + /* max return of cborencoder_put_array() */             \
                                        2 + /* max return of cborencoder_put_unsigned() */          \
                                        1 + /* max return of cborencoder_put_array() */             \
                                        2 + /* max return of cborencoder_put_unsigned() */          \
                                        2 + OSCORE_KID_MAX_LEN + /* max 2 to encode length, KID following */ \
                                        2 + OSCORE_PIV_MAX_LEN + /* max 2 to encode length, PIV following */ \
                                        1 + 0 /* 1 to encode length, 0 bytes following */           )

#define OSCORE_AAD_MAX_LEN              (1 + /* max return of cborencoder_put_array() */             \
                                        2 + 8 +/* max 2 to encode length, "Encrypt0" following */   \
                                        1 + 0 + /* 1 to encode length, 0 bytes following */         \
                                        2 + OSCORE_EXTERNAL_AAD_MAX_LEN /* max 2 to encode length, external_aad following */ )

static void oscore_context_free_byte_arrays(oscore_context_t *rec) {

    if (rec->master_secret) {
        g_byte_array_free(rec->master_secret, TRUE);
    }

    if (rec->master_salt) {
        g_byte_array_free(rec->master_salt, TRUE);
    }

    if (rec->id_context) {
        g_byte_array_free(rec->id_context, TRUE);
    }

    if (rec->sender_id) {
        g_byte_array_free(rec->sender_id, TRUE);
    }

    if (rec->recipient_id) {
        g_byte_array_free(rec->recipient_id, TRUE);
    }

    if (rec->request_decryption_key) {
        g_byte_array_free(rec->request_decryption_key, TRUE);
    }

    if (rec->response_decryption_key) {
        g_byte_array_free(rec->response_decryption_key, TRUE);
    }

    if (rec->common_iv) {
        g_byte_array_free(rec->common_iv, TRUE);
    }
}

static void oscore_context_post_update_cb(void) {
    guint i;
    guint key_len;
    guint iv_len;

    for (i = 0; i < num_oscore_contexts; i++) {

        /* Make sure to free the memory if it was allocated previously. */
        oscore_context_free_byte_arrays(&oscore_contexts[i]);

        oscore_contexts[i].master_secret    = g_byte_array_new();
        oscore_contexts[i].master_salt      = g_byte_array_new();
        oscore_contexts[i].id_context       = g_byte_array_new();
        oscore_contexts[i].sender_id        = g_byte_array_new();
        oscore_contexts[i].recipient_id     = g_byte_array_new();

        /* Convert strings to byte arrays */
        hex_str_to_bytes(oscore_contexts[i].sender_id_prefs, oscore_contexts[i].sender_id, FALSE);
        hex_str_to_bytes(oscore_contexts[i].recipient_id_prefs, oscore_contexts[i].recipient_id, FALSE);
        hex_str_to_bytes(oscore_contexts[i].id_context_prefs, oscore_contexts[i].id_context, FALSE);
        hex_str_to_bytes(oscore_contexts[i].master_secret_prefs, oscore_contexts[i].master_secret, FALSE);
        hex_str_to_bytes(oscore_contexts[i].master_salt_prefs, oscore_contexts[i].master_salt, FALSE);

        /* Algorithm-dependent key and IV length */
        key_len = oscore_alg_get_key_len(oscore_contexts[i].algorithm);
        iv_len = oscore_alg_get_iv_len(oscore_contexts[i].algorithm);

        /* Allocate memory for derived parameters */
        oscore_contexts[i].request_decryption_key = g_byte_array_sized_new(key_len);
        oscore_contexts[i].response_decryption_key = g_byte_array_sized_new(key_len);
        oscore_contexts[i].common_iv = g_byte_array_sized_new(iv_len);

        oscore_context_derive_params(&oscore_contexts[i]);
    }
}

/* Check user input, do not allocate any memory */
static gboolean oscore_context_update_cb(void *r, char **err) {
    oscore_context_t *rec = (oscore_context_t *) r;
    GByteArray *bytes; /* temp array to verify each parameter */

    bytes = g_byte_array_new();

    if (hex_str_to_bytes(rec->sender_id_prefs, bytes, FALSE) == FALSE) {
        *err = g_strdup("Sender ID is invalid.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (bytes->len > OSCORE_KID_MAX_LEN) {
        *err = g_strdup_printf("Should be %u bytes or less.", OSCORE_KID_MAX_LEN);
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (hex_str_to_bytes(rec->recipient_id_prefs, bytes, FALSE) == FALSE) {
        *err = g_strdup("Recipient ID is invalid.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (bytes->len > OSCORE_KID_MAX_LEN) {
        *err = g_strdup_printf("Should be %u bytes or less.", OSCORE_KID_MAX_LEN);
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (hex_str_to_bytes(rec->id_context_prefs, bytes, FALSE) == FALSE) {
        *err = g_strdup("ID Context is invalid.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (bytes->len > OSCORE_KID_CONTEXT_MAX_LEN) {
        *err = g_strdup_printf("Should be %u bytes or less.", OSCORE_KID_CONTEXT_MAX_LEN);
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (hex_str_to_bytes(rec->master_secret_prefs, bytes, FALSE) == FALSE) {
        *err = g_strdup("Master Secret is invalid.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    /* No max length check on Master Secret. We use GByteArray to allocate memory
     * and pass it to the context derivation routine */
    if (bytes->len == 0) {
        *err = g_strdup("Master Secret is mandatory.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    if (hex_str_to_bytes(rec->master_salt_prefs, bytes, FALSE) == FALSE) {
        *err = g_strdup("Master Salt is invalid.");
        g_byte_array_free(bytes, TRUE);
        return FALSE;
    }

    /* No (max) length check on optional Master Salt. We use GByteArray to allocate memory
     * and pass it to the context derivation routine */

     g_byte_array_free(bytes, TRUE);
     return TRUE;
}

static void* oscore_context_copy_cb(void *n, const void *o, size_t siz _U_) {
    oscore_context_t *new_record = (oscore_context_t *) n;
    const oscore_context_t *old_record = (const oscore_context_t *) o;

    /* Pre-Shared Parameters */
    new_record->master_secret_prefs = g_strdup(old_record->master_secret_prefs);
    new_record->master_salt_prefs = g_strdup(old_record->master_salt_prefs);
    new_record->id_context_prefs = g_strdup(old_record->id_context_prefs);
    new_record->sender_id_prefs = g_strdup(old_record->sender_id_prefs);
    new_record->recipient_id_prefs = g_strdup(old_record->recipient_id_prefs);
    new_record->algorithm = old_record->algorithm;

    /* Initialize all to NULL, overwrite as needed */
    new_record->master_secret = NULL;
    new_record->master_salt = NULL;
    new_record->id_context = NULL;
    new_record->sender_id = NULL;
    new_record->recipient_id = NULL;
    new_record->request_decryption_key = NULL;
    new_record->response_decryption_key = NULL;
    new_record->common_iv = NULL;

    /* We rely on oscore_context_post_update_cb() to convert strings to GByteArrays and derive params */

    return new_record;
}

static void oscore_context_free_cb(void *r) {
    oscore_context_t *rec = (oscore_context_t *) r;

    /* User-configured strings */
    g_free(rec->master_secret_prefs);
    g_free(rec->master_salt_prefs);
    g_free(rec->id_context_prefs);
    g_free(rec->sender_id_prefs);
    g_free(rec->recipient_id_prefs);

    /* Allocated byte arrays */
    oscore_context_free_byte_arrays(rec);
 }

/* GByteArrays within the oscore_context_t object should be initialized before calling this function */
static gboolean oscore_context_derive_params(oscore_context_t *context) {
    const char *iv_label = "IV";
    const char *key_label = "Key";
    guint8 prk[32]; /* Pseudo-random key from HKDF-Extract step. 32 for SHA256. */
    guint key_len;
    guint iv_len;
    guint8 info_buf[OSCORE_INFO_MAX_LEN];
    guint info_len;
    GByteArray *info;

    key_len = oscore_alg_get_key_len(context->algorithm);
    iv_len = oscore_alg_get_iv_len(context->algorithm);

    info = g_byte_array_new();

    /* Common HKDF-Extract step on master salt */
    hkdf_extract(GCRY_MD_SHA256, context->master_salt->data, context->master_salt->len, context->master_secret->data, context->master_secret->len, prk);

    /* Request Decryption Key */
    info_len = 0;
    info_len += cborencoder_put_array(&info_buf[info_len], 5);
    info_len += cborencoder_put_bytes(&info_buf[info_len], context->sender_id->data, context->sender_id->len);
    if (context->id_context->len) {
        info_len += cborencoder_put_bytes(&info_buf[info_len], context->id_context->data, context->id_context->len);
    } else {
        info_len += cborencoder_put_null(&info_buf[info_len]);
    }
    info_len += cborencoder_put_unsigned(&info_buf[info_len], context->algorithm);
    info_len += cborencoder_put_text(&info_buf[info_len], key_label, 3);
    info_len += cborencoder_put_unsigned(&info_buf[info_len], key_len);
    /* sender_id->len comes from user input, it is validated by the UAT callback and the max length is accounted for
     * in OSCORE_INFO_MAX_LEN */
    DISSECTOR_ASSERT(info_len < OSCORE_INFO_MAX_LEN);
    g_byte_array_append(info, info_buf, info_len);
    g_byte_array_set_size(context->request_decryption_key, key_len);
    hkdf_expand(GCRY_MD_SHA256, prk, sizeof(prk), info->data, info->len, context->request_decryption_key->data, key_len); /* 32 for SHA256 */



    /* Response Decryption Key */
    info_len = 0;
    g_byte_array_set_size(info, 0);
    info_len += cborencoder_put_array(&info_buf[info_len], 5);
    info_len += cborencoder_put_bytes(&info_buf[info_len], context->recipient_id->data, context->recipient_id->len);
    if (context->id_context->len) {
        info_len += cborencoder_put_bytes(&info_buf[info_len], context->id_context->data, context->id_context->len);
    } else {
        info_len += cborencoder_put_null(&info_buf[info_len]);
    }
    info_len += cborencoder_put_unsigned(&info_buf[info_len], context->algorithm);
    info_len += cborencoder_put_text(&info_buf[info_len], key_label, 3);
    info_len += cborencoder_put_unsigned(&info_buf[info_len], key_len);
    /* recipient_id->len comes from user input, it is validated by the UAT callback and the max length is accounted for
     * in OSCORE_INFO_MAX_LEN */
    DISSECTOR_ASSERT(info_len < OSCORE_INFO_MAX_LEN);
    g_byte_array_append(info, info_buf, info_len);
    g_byte_array_set_size(context->response_decryption_key, key_len);
    hkdf_expand(GCRY_MD_SHA256, prk, sizeof(prk), info->data, info->len, context->response_decryption_key->data, key_len); /* 32 for SHA256 */

    /* Common IV */
    info_len = 0;
    g_byte_array_set_size(info, 0);
    info_len += cborencoder_put_array(&info_buf[info_len], 5);
    info_len += cborencoder_put_bytes(&info_buf[info_len], NULL, 0);
    if (context->id_context->len) {
        info_len += cborencoder_put_bytes(&info_buf[info_len], context->id_context->data, context->id_context->len);
    } else {
        info_len += cborencoder_put_null(&info_buf[info_len]);
    }
    info_len += cborencoder_put_unsigned(&info_buf[info_len], context->algorithm);
    info_len += cborencoder_put_text(&info_buf[info_len], iv_label, 2);
    info_len += cborencoder_put_unsigned(&info_buf[info_len], iv_len);
    /* all static lengths, accounted for in OSCORE_INFO_MAX_LEN */
    DISSECTOR_ASSERT(info_len < OSCORE_INFO_MAX_LEN);
    g_byte_array_append(info, info_buf, info_len);
    g_byte_array_set_size(context->common_iv, iv_len);
    hkdf_expand(GCRY_MD_SHA256, prk, sizeof(prk), info->data, info->len, context->common_iv->data, iv_len); /* 32 for SHA256 */

    g_byte_array_free(info, TRUE);
    return TRUE;
}

static guint oscore_alg_get_key_len(cose_aead_alg_t algorithm) {
    switch(algorithm) {
        case COSE_AES_CCM_16_64_128:
            return 16; /* RFC8152 */
        /* unsupported */
        default:
            return 0;
    }
}

static guint oscore_alg_get_tag_len(cose_aead_alg_t algorithm) {
    switch(algorithm) {
        case COSE_AES_CCM_16_64_128:
            return 8; /* RFC8152 */
        /* unsupported */
        default:
            return 0;
    }
}

static guint oscore_alg_get_iv_len(cose_aead_alg_t algorithm) {
    switch(algorithm) {
        case COSE_AES_CCM_16_64_128:
            return 13; /* RFC8152 */
        /* unsupported */
        default:
            return 0;
    }
}

static oscore_context_t * oscore_find_context(oscore_info_t *info) {
    guint i;

    for (i = 0; i < num_oscore_contexts; i++) {
        if ((info->kid_len == oscore_contexts[i].sender_id->len) &&
                memcmp(oscore_contexts[i].sender_id->data, info->kid, info->kid_len) == 0 &&
                (info->kid_context_len == oscore_contexts[i].id_context->len) &&
                memcmp(oscore_contexts[i].id_context->data, info->kid_context, info->kid_context_len) == 0) {
            return &oscore_contexts[i];
        }
    }
    return NULL;
}

/**
CBOR encoding functions needed to construct HKDF info and aad.
Author Martin Gunnarsson <martin.gunnarsson@ri.se>
Modified by Malisa Vucinic <malishav@gmail.com>
*/
static guint8
cborencoder_put_text(guint8 *buffer, const char *text, guint8 text_len) {
    guint8 ret = 0;

    if(text_len > 23 ){
        buffer[ret++] = 0x78;
        buffer[ret++] = text_len;
    } else {
        buffer[ret++] = (0x60 | text_len);
    }

    if (text_len != 0 && text != NULL) {
        memcpy(&buffer[ret], text, text_len);
        ret += text_len;
    }

    return ret;
}

static guint8
cborencoder_put_array(guint8 *buffer, guint8 elements) {
    guint8 ret = 0;

    if(elements > 15){
        return 0;
    }

    buffer[ret++] = (0x80 | elements);
    return ret;
}

static guint8
cborencoder_put_bytes(guint8 *buffer, const guint8 *bytes, guint8 bytes_len) {
    guint8 ret = 0;

    if(bytes_len > 23){
        buffer[ret++] = 0x58;
        buffer[ret++] = bytes_len;
    } else {
        buffer[ret++] = (0x40 | bytes_len);
    }

    if (bytes_len != 0 && bytes != NULL){
        memcpy(&buffer[ret], bytes, bytes_len);
        ret += bytes_len;
    }

    return ret;
}

static guint8
cborencoder_put_unsigned(guint8 *buffer, guint8 value) {
    guint8 ret = 0;

    if(value > 0x17 ){
        buffer[ret++] = 0x18;
        buffer[ret++] = value;
        return ret;
    }

    buffer[ret++] = value;
    return ret;
}

static guint8
cborencoder_put_null(guint8 *buffer) {
    guint8 ret = 0;

    buffer[ret++] = 0xf6;
    return ret;
}

/* out should hold NONCE_MAX_LEN bytes at most */
static void
oscore_create_nonce(guint8 *out,
        oscore_context_t *context,
        oscore_info_t *info) {

    guint i = 0;
    gchar piv_extended[NONCE_MAX_LEN] = { 0 };
    guint nonce_len;
    guint8 *piv;
    guint8 piv_len;
    GByteArray *piv_generator;

    DISSECTOR_ASSERT(out != NULL);
    DISSECTOR_ASSERT(context != NULL);
    DISSECTOR_ASSERT(info != NULL);

    nonce_len = oscore_alg_get_iv_len(context->algorithm);
    DISSECTOR_ASSERT(nonce_len <= NONCE_MAX_LEN);

    /* Recipient ID is the PIV generator ID if the PIV is present in the response */
    if (info->response && info->piv_len) {
        piv_generator = context->recipient_id;
        piv = info->piv;
        piv_len = info->piv_len;
    } else {
        piv_generator = context->sender_id;
        piv = info->request_piv;
        piv_len = info->request_piv_len;
    }

    /* AEAD nonce is the XOR of Common IV left-padded to AEAD nonce length and the concatenation of:
     * Step 3: Size of ID of the entity that generated PIV (1 byte),
     * Step 2: ID of the entity that generated PIV (left-padded to "AEAD nonce length - 6 bytes"),
     * Step 1: Partial IV (left-padded to OSCORE_PIV_MAX_LEN bytes).
     */

    /* Step 1 */
    DISSECTOR_ASSERT(piv_len <= OSCORE_PIV_MAX_LEN);
    memcpy(&piv_extended[nonce_len - piv_len], piv, piv_len);

    /* Step 2 */
    DISSECTOR_ASSERT(piv_generator->len <= nonce_len - 6);
    memcpy(&piv_extended[nonce_len - OSCORE_PIV_MAX_LEN - piv_generator->len], piv_generator->data, piv_generator->len);

    /* Step 3 */
    piv_extended[0] = piv_generator->len;

    /* Now XOR with Common IV */
    for (i = 0; i < nonce_len; i++) {
        out[i] = piv_extended[i] ^ context->common_iv->data[i];
    }

}

static oscore_decryption_status_t
oscore_decrypt_and_verify(tvbuff_t *tvb_ciphertext,
        packet_info *pinfo,
        gint *offset,
        proto_tree *tree,
        oscore_context_t *context,
        oscore_info_t *info,
        tvbuff_t **tvb_plaintext) {

    gboolean have_tag = FALSE;
    guint8 nonce[NONCE_MAX_LEN];
    guint8 tmp[AES_128_BLOCK_LEN];
    guint8 *text;
    guint8 rx_tag[TAG_MAX_LEN];
    guint tag_len = 0;
    guint8 gen_tag[TAG_MAX_LEN];
    guint8 external_aad[OSCORE_EXTERNAL_AAD_MAX_LEN];
    guint8 external_aad_len = 0;
    guint8 aad[OSCORE_AAD_MAX_LEN];
    guint8 aad_len = 0;
    guint8 *decryption_key;
    gint ciphertext_captured_len;
    gint ciphertext_reported_len;
    const char *encrypt0 = "Encrypt0";
    proto_item *item = NULL;

    tag_len = oscore_alg_get_tag_len(context->algorithm);

    ciphertext_reported_len = tvb_reported_length_remaining(tvb_ciphertext, *offset + tag_len);

    if (ciphertext_reported_len == 0) {
        return STATUS_ERROR_MESSAGE_TOO_SMALL;
    }

    /* Check if the payload is truncated.  */
    if (tvb_bytes_exist(tvb_ciphertext, *offset, ciphertext_reported_len)) {
        ciphertext_captured_len = ciphertext_reported_len;
    }
    else {
        ciphertext_captured_len = tvb_captured_length_remaining(tvb_ciphertext, *offset);
    }

    /* Check if the tag is present in the captured data. */
    have_tag = tvb_bytes_exist(tvb_ciphertext, *offset + ciphertext_reported_len, tag_len);
    if (have_tag) {
        DISSECTOR_ASSERT(tag_len <= sizeof(rx_tag));
        tvb_memcpy(tvb_ciphertext, rx_tag, *offset + ciphertext_reported_len, tag_len);
    }

    if (info->response) {
        decryption_key = context->response_decryption_key->data;
    } else {
        decryption_key = context->request_decryption_key->data;
    }

    /* Create nonce to use for decryption and authenticity check */
    oscore_create_nonce(nonce, context, info);

    /*
     * Create the CCM* initial block for decryption (Adata=0, M=0, counter=0).
     * XXX: This only handles AES-CCM-16-64-128, add generic algorithm handling
     * */
    ccm_init_block(tmp, FALSE, 0, 0, 0, 0, 0, nonce);

    /*
    * Make a copy of the ciphertext in heap memory.
    *
    * We will decrypt the message in-place and then use the buffer as the
    * real data for the new tvb.
    */
    text = (guint8 *)tvb_memdup(pinfo->pool, tvb_ciphertext, *offset, ciphertext_captured_len);

    /*
     * Perform CTR-mode transformation and decrypt the tag.
     * XXX: This only handles AES-CCM-16-64-128, add generic algorithm handling
     * */
    if(ccm_ctr_encrypt(decryption_key, tmp, rx_tag, text, ciphertext_captured_len) == FALSE) {
        return STATUS_ERROR_DECRYPT_FAILED;
    }

    /* Create a tvbuff for the plaintext. */
    *tvb_plaintext = tvb_new_real_data(text, ciphertext_captured_len, ciphertext_reported_len);
    tvb_set_child_real_data_tvbuff(tvb_ciphertext, *tvb_plaintext);
    add_new_data_source(pinfo, *tvb_plaintext, "Decrypted OSCORE");

    if (have_tag) {
        /* Construct external_aad to be able to verify the tag */

        /* Note that OSCORE_EXTERNAL_AAD_MAX_LEN calculation depends on the following construct.
         * If this is updated - e.g. due to spec changes, added support for Class I options, or added
         * support for other algorithms which would change max length of KID - do not forget to update the macro.
         * */
        external_aad_len += cborencoder_put_array(&external_aad[external_aad_len], 5); /* 5 elements in the array */
        external_aad_len += cborencoder_put_unsigned(&external_aad[external_aad_len], OSCORE_VERSION);
        external_aad_len += cborencoder_put_array(&external_aad[external_aad_len], 1);
        external_aad_len += cborencoder_put_unsigned(&external_aad[external_aad_len], context->algorithm);
        external_aad_len += cborencoder_put_bytes(&external_aad[external_aad_len], info->kid, info->kid_len);
        external_aad_len += cborencoder_put_bytes(&external_aad[external_aad_len], info->request_piv, info->request_piv_len);
        external_aad_len += cborencoder_put_bytes(&external_aad[external_aad_len], NULL, 0); // Class I options not implemented/standardized yet

        /* info->kid_len and info->piv_len come from the lower layer, other parameters are local.
         * we end up here only if kid_len is matched to the one from the configured context through oscore_find_context()
         * and piv_len is verified in the main dissection routine */
        DISSECTOR_ASSERT(external_aad_len < OSCORE_EXTERNAL_AAD_MAX_LEN);

        /* Note that OSCORE_AAD_MAX_LEN calculation depends on the following construct.
         * If the construct below is modified, do not forget to update the macro.
         * */
        aad_len += cborencoder_put_array(&aad[aad_len], 3); // COSE Encrypt0 structure with 3 elements
        aad_len += cborencoder_put_text(&aad[aad_len], encrypt0, 8); /* Text string "Encrypt0" */
        aad_len += cborencoder_put_bytes(&aad[aad_len], NULL, 0);  /* Empty byte string */
        aad_len += cborencoder_put_bytes(&aad[aad_len], external_aad, external_aad_len); /* OSCORE external_aad */

        DISSECTOR_ASSERT(aad_len < OSCORE_AAD_MAX_LEN);

        /* Compute CBC-MAC authentication tag. */

        /*
        * Create the CCM* initial block for authentication (Adata!=0, M!=0, counter=l(m)).
        * XXX: This only handles AES-CCM-16-64-128, add generic algorithm handling
        * */
        DISSECTOR_ASSERT(tag_len <= sizeof(gen_tag));
        ccm_init_block(tmp, TRUE, tag_len, 0, 0, 0, ciphertext_captured_len, nonce);
        /* text is already a raw buffer containing the plaintext since we just decrypted it in-place */
        if (!ccm_cbc_mac(decryption_key, tmp, aad, aad_len, text, ciphertext_captured_len, gen_tag)) {
            return STATUS_ERROR_CBCMAC_FAILED;
        }
        /* Compare the received tag with the one we generated. */
        else if (memcmp(gen_tag, rx_tag, tag_len) != 0) {
            return STATUS_ERROR_TAG_CHECK_FAILED;
        }

        /* Display the tag. */
        if (tag_len) {
            item = proto_tree_add_bytes(tree, hf_oscore_tag, tvb_ciphertext, ciphertext_captured_len, tag_len, rx_tag);
            proto_item_set_generated(item);
        }

        return STATUS_SUCCESS_DECRYPTED_TAG_CHECKED;
    } /* if (have_tag) */

    return STATUS_SUCCESS_DECRYPTED_TAG_TRUNCATED;
}

/* Code to actually dissect the packets */
static int
oscore_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *oscore_tree;
    /* Other misc. local variables. */
    gint offset = 0;
    oscore_info_t *info = (oscore_info_t *) data;
    oscore_context_t *context = NULL;
    oscore_decryption_status_t status;
    tvbuff_t *tvb_decrypted = NULL;
    coap_info *coinfo;
    gint oscore_length;
    guint8 code_class;

    /* Check that the packet is long enough for it to belong to us. */
    if (tvb_reported_length(tvb) < OSCORE_MIN_LENGTH) {
        return 0;
    }


    /* Set the Protocol column to the constant string of oscore */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OSCORE");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_oscore, tvb, 0, -1, ENC_NA);

    oscore_tree = proto_item_add_subtree(ti, ett_oscore);

    if (info->piv == NULL && info->request_piv == NULL) {
        expert_add_info(pinfo, oscore_tree, &ei_oscore_partial_iv_not_found);
        return tvb_reported_length(tvb);
    }

    if ((context = oscore_find_context(info)) == NULL) {
        expert_add_info(pinfo, oscore_tree, &ei_oscore_context_not_set);
        return tvb_reported_length(tvb);
    }

    if (info->piv_len > OSCORE_PIV_MAX_LEN) {
        expert_add_info(pinfo, oscore_tree, &ei_oscore_piv_len_invalid);
        return tvb_reported_length(tvb);
    }

    status = oscore_decrypt_and_verify(tvb, pinfo, &offset, oscore_tree, context, info, &tvb_decrypted);

    switch (status) {
        case STATUS_ERROR_DECRYPT_FAILED:
            expert_add_info(pinfo, oscore_tree, &ei_oscore_decrypt_error);
            return tvb_reported_length(tvb);
        case STATUS_ERROR_CBCMAC_FAILED:
            expert_add_info(pinfo, oscore_tree, &ei_oscore_cbc_mac_failed);
            return tvb_reported_length(tvb);
        case STATUS_ERROR_TAG_CHECK_FAILED:
            expert_add_info(pinfo, oscore_tree, &ei_oscore_tag_check_failed);
            return tvb_reported_length(tvb);
        case STATUS_ERROR_MESSAGE_TOO_SMALL:
            expert_add_info(pinfo, oscore_tree, &ei_oscore_message_too_small);
            return tvb_reported_length(tvb);
        case STATUS_SUCCESS_DECRYPTED_TAG_TRUNCATED:
            expert_add_info(pinfo, oscore_tree, &ei_oscore_truncated);
            /* do not return, attempt dissection */
            break;
        case STATUS_SUCCESS_DECRYPTED_TAG_CHECKED:
            break;
    }

    DISSECTOR_ASSERT(tvb_decrypted);

    oscore_length = tvb_reported_length(tvb_decrypted);

    /* Fetch CoAP info */
    coinfo = (coap_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_coap, 0);

    if (coinfo) {
        dissect_coap_code(tvb_decrypted, oscore_tree, &offset, &dissect_oscore_hf, &code_class);
        offset = dissect_coap_options(tvb_decrypted, pinfo, oscore_tree, offset, oscore_length, code_class, coinfo, &dissect_oscore_hf);
        if (oscore_length > offset) {
            dissect_coap_payload(tvb_decrypted, pinfo, oscore_tree, tree, offset, oscore_length, code_class, coinfo, &dissect_oscore_hf, TRUE);
        }
    } else {
        /* We don't support OSCORE over HTTP at the moment, where coinfo fetch will fail */
        expert_add_info(pinfo, oscore_tree, &ei_oscore_info_fetch_failed);
    }

    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_oscore(void)
{
    module_t        *oscore_module;
    expert_module_t *expert_oscore;

    static hf_register_info hf[] = {
        { &hf_oscore_tag,
          { "Decrypted Authentication Tag", "oscore.tag", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        COAP_COMMON_HF_LIST(dissect_oscore_hf, "oscore")
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_oscore,
        COAP_COMMON_ETT_LIST(dissect_oscore_hf)
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_oscore_partial_iv_not_found,
          { "oscore.partial_iv_not_found", PI_UNDECODED, PI_WARN,
            "Partial IV not found - can't decrypt", EXPFILL
          }
        },
        { &ei_oscore_context_not_set,
          { "oscore.context_not_set", PI_UNDECODED, PI_WARN,
            "Security context not set - can't decrypt", EXPFILL
          }
        },
        { &ei_oscore_message_too_small,
          { "oscore.message_too_small", PI_UNDECODED, PI_WARN,
            "Message too small", EXPFILL
          }
        },
        { &ei_oscore_truncated,
          { "oscore.truncated", PI_UNDECODED, PI_WARN,
            "Message truncated, cannot verify authentication tag, but decryption is attempted", EXPFILL
          }
        },
        { &ei_oscore_cbc_mac_failed,
          { "oscore.cbc_mac_failed", PI_UNDECODED, PI_WARN,
            "Call to CBC-MAC failed", EXPFILL
          }
        },
        { &ei_oscore_tag_check_failed,
          { "oscore.tag_check_failed", PI_UNDECODED, PI_WARN,
            "Authentication tag check failed", EXPFILL
          }
        },
        { &ei_oscore_decrypt_error,
          { "oscore.decrypt_error", PI_UNDECODED, PI_WARN,
            "Decryption error", EXPFILL
          }
        },
        { &ei_oscore_info_fetch_failed,
          { "oscore.info_fetch_failed", PI_UNDECODED, PI_WARN,
            "Failed to fetch info from the lower layer - OSCORE over HTTP is not supported", EXPFILL
          }
        },
        { &ei_oscore_piv_len_invalid,
          { "oscore.piv_len_invalid", PI_UNDECODED, PI_WARN,
            "Partial IV length from the lower layer is invalid", EXPFILL
          }
        },
        COAP_COMMON_EI_LIST(dissect_oscore_hf, "oscore")
    };

    static uat_field_t oscore_context_uat_flds[] = {
        UAT_FLD_CSTRING(oscore_context_uat,sender_id_prefs,"Sender ID",
                "Sender ID as HEX string. Should be 7 bytes or less. Mandatory."),
        UAT_FLD_CSTRING(oscore_context_uat,recipient_id_prefs,"Recipient ID",
                "Recipient ID as HEX string. Should be 7 bytes or less. Mandatory."),
        UAT_FLD_CSTRING(oscore_context_uat,master_secret_prefs,"Master Secret",
                "Master Secret as HEX string. Mandatory."),
        UAT_FLD_CSTRING(oscore_context_uat,master_salt_prefs,"Master Salt",
                "Master Salt as HEX string. Optional."),
        UAT_FLD_CSTRING(oscore_context_uat,id_context_prefs,"ID Context",
                "ID Context as HEX string. Optional."),
        UAT_FLD_VS(oscore_context_uat, algorithm, "Algorithm", oscore_context_alg_vals, "Decryption algorithm."),
        UAT_END_FIELDS
    };

    /* Register the protocol name and description */
    proto_oscore = proto_register_protocol("Object Security for Constrained RESTful Environments",
            "OSCORE", "oscore");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_oscore, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_oscore = expert_register_protocol(proto_oscore);
    expert_register_field_array(expert_oscore, ei, array_length(ei));

    oscore_module = prefs_register_protocol(proto_oscore, NULL);

    /* Create a UAT for security context management. */
    oscore_context_uat = uat_new("Security Contexts",
            sizeof(oscore_context_t),       /* record size */
            "oscore_contexts",              /* filename */
            TRUE,                           /* from_profile */
            &oscore_contexts,               /* data_ptr */
            &num_oscore_contexts,           /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
            NULL,                           /* help */
            oscore_context_copy_cb,         /* copy callback */
            oscore_context_update_cb,       /* update callback */
            oscore_context_free_cb,         /* free callback */
            oscore_context_post_update_cb,  /* post update callback */
            NULL,                           /* reset callback */
            oscore_context_uat_flds);       /* UAT field definitions */

    prefs_register_uat_preference(oscore_module, "contexts",
                "Security Contexts",
                "Security context configuration data",
                oscore_context_uat);

    register_dissector("oscore", oscore_dissect, proto_oscore);

    proto_coap = proto_get_id_by_short_name("CoAP");
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
