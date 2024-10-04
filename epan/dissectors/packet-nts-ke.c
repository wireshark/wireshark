/* packet-nts-ke.c
 * Dissector for Network Time Security Key Establishment Protocol (RFC 8915)
 *
 * Copyright (c) 2024 by Martin Mayer <martin.mayer@m2-it-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "packet-tcp.h"
#include "packet-tls.h"
#include "packet-nts-ke.h"
#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <wsutil/str_util.h>
#include <epan/expert.h>
#include <epan/conversation.h>

#define TLS_PORT              4460
#define CRIT_TYPE_BODY_LEN       4
#define TYPE_MASK           0x7FFF
#define CRITICAL_MASK       0x8000

#define NTS_KE_EXPORTER_LABEL "EXPORTER-network-time-security"
#define NTS_KE_ALPN           "ntske/1"

void proto_register_nts_ke(void);
void proto_reg_handoff_nts_ke(void);

static dissector_handle_t nts_ke_handle;

static int proto_nts_ke;

/* Fields */
static int hf_nts_ke_record;
static int hf_nts_ke_critical_bit;
static int hf_nts_ke_record_type;
static int hf_nts_ke_body_length;
static int hf_nts_ke_next_proto;
static int hf_nts_ke_error;
static int hf_nts_ke_warning;
static int hf_nts_ke_aead_algo;
static int hf_nts_ke_cookie;
static int hf_nts_ke_cookie_used_frame;
static int hf_nts_ke_server;
static int hf_nts_ke_port;
static int hf_nts_ke_response_in;
static int hf_nts_ke_response_to;

/* Expert fields */
static expert_field ei_nts_ke_critical_bit_missing;
static expert_field ei_nts_ke_record_after_end;
static expert_field ei_nts_ke_end_missing;
static expert_field ei_nts_ke_next_proto_illegal_count;
static expert_field ei_nts_ke_body_illegal;
static expert_field ei_nts_ke_body_length_illegal;
static expert_field ei_nts_ke_alpn_mismatch;

/* Prefs */
static bool nts_ke_extract_keys = true;
static bool nts_ke_chrony_compat_mode = false;

/* Trees */
static int ett_nts_ke;
static int ett_nts_ke_record;

#define RECORD_TYPE_END             0
#define RECORD_TYPE_NEXT            1
#define RECORD_TYPE_ERR             2
#define RECORD_TYPE_WARN            3
#define RECORD_TYPE_AEAD            4
#define RECORD_TYPE_COOKIE          5
#define RECORD_TYPE_NEG_SRV         6
#define RECORD_TYPE_NEG_PORT        7
#define RECORD_TYPE_UA_1_LOW        8
#define RECORD_TYPE_UA_1_HIGH    1023
#define RECORD_TYPE_COMP_GCM     1024
#define RECORD_TYPE_UA_2_LOW     1025
#define RECORD_TYPE_UA_2_HIGH   16383
#define RECORD_TYPE_RES_LOW     16384
#define RECORD_TYPE_RES_HIGH    32767

/* https://www.iana.org/assignments/nts/nts.xhtml#nts-key-establishment-record-types */
static const range_string nts_ke_record_types[] = {
    { RECORD_TYPE_END,      RECORD_TYPE_END,       "End of Message" },
    { RECORD_TYPE_NEXT,     RECORD_TYPE_NEXT,      "NTS Next Protocol Negotiation" },
    { RECORD_TYPE_ERR,      RECORD_TYPE_ERR,       "Error" },
    { RECORD_TYPE_WARN,     RECORD_TYPE_WARN,      "Warning" },
    { RECORD_TYPE_AEAD,     RECORD_TYPE_AEAD,      "AEAD Algorithm Negotiation" },
    { RECORD_TYPE_COOKIE,   RECORD_TYPE_COOKIE,    "New Cookie for NTPv4" },
    { RECORD_TYPE_NEG_SRV,  RECORD_TYPE_NEG_SRV,   "NTPv4 Server Negotiation" },
    { RECORD_TYPE_NEG_PORT, RECORD_TYPE_NEG_PORT,  "NTPv4 Port Negotiation" },
    { RECORD_TYPE_UA_1_LOW, RECORD_TYPE_UA_1_HIGH, "Unassigned" },
    { RECORD_TYPE_COMP_GCM, RECORD_TYPE_COMP_GCM,  "Compliant AES-128-GCM-SIV Exporter Context" },
    { RECORD_TYPE_UA_2_LOW, RECORD_TYPE_UA_2_HIGH, "Unassigned" },
    { RECORD_TYPE_RES_LOW,  RECORD_TYPE_RES_HIGH,  "Reserved" },
    { 0,                    0,                     NULL }
};

/* https://www.iana.org/assignments/nts/nts.xhtml#nts-error-codes */
static const range_string nts_ke_error_codes[] = {
    {     0,     0, "Unrecognized Critical Record" },
    {     1,     1, "Bad Request" },
    {     2,     2, "Internal Server Error" },
    {     3, 32767, "Unassigned" },
    { 32768, 65535, "Reserved" },
    {     0,     0, NULL }
};

/* https://www.iana.org/assignments/nts/nts.xhtml#nts-warning-codes */
static const range_string nts_ke_warning_codes[] = {
    {     0, 32767, "Unassigned" },
    { 32768, 65535, "Reserved" },
    {     0,     0, NULL }
};

/* https://www.iana.org/assignments/nts/nts.xhtml#nts-next-protocols */
static const range_string nts_ke_next_proto_rvals[] = {
    {     0,     0, "NTPv4" },
    {     1, 32767, "Unassigned" },
    { 32768, 65535, "Reserved" },
    {     0,     0, NULL }
};

/* https://www.iana.org/assignments/aead-parameters/ */
static const range_string nts_ke_aead_rvals[] = {
    {     1,     1, "AEAD_AES_128_GCM" },
    {     2,     2, "AEAD_AES_256_GCM" },
    {     3,     3, "AEAD_AES_128_CCM" },
    {     4,     4, "AEAD_AES_256_CCM" },
    {     5,     5, "AEAD_AES_128_GCM_8" },
    {     6,     6, "AEAD_AES_256_GCM_8" },
    {     7,     7, "AEAD_AES_128_GCM_12" },
    {     8,     8, "AEAD_AES_256_GCM_12" },
    {     9,     9, "AEAD_AES_128_CCM_SHORT" },
    {    10,    10, "AEAD_AES_256_CCM_SHORT" },
    {    11,    11, "AEAD_AES_128_CCM_SHORT_8" },
    {    12,    12, "AEAD_AES_256_CCM_SHORT_8" },
    {    13,    13, "AEAD_AES_128_CCM_SHORT_12" },
    {    14,    14, "AEAD_AES_256_CCM_SHORT_12" },
    {    15,    15, "AEAD_AES_SIV_CMAC_256" },
    {    16,    16, "AEAD_AES_SIV_CMAC_384" },
    {    17,    17, "AEAD_AES_SIV_CMAC_512" },
    {    18,    18, "AEAD_AES_128_CCM_8" },
    {    19,    19, "AEAD_AES_256_CCM_8" },
    {    20,    20, "AEAD_AES_128_OCB_TAGLEN128" },
    {    21,    21, "AEAD_AES_128_OCB_TAGLEN96" },
    {    22,    22, "AEAD_AES_128_OCB_TAGLEN64" },
    {    23,    23, "AEAD_AES_192_OCB_TAGLEN128" },
    {    24,    24, "AEAD_AES_192_OCB_TAGLEN96" },
    {    25,    25, "AEAD_AES_192_OCB_TAGLEN64" },
    {    26,    26, "AEAD_AES_256_OCB_TAGLEN128" },
    {    27,    27, "AEAD_AES_256_OCB_TAGLEN96" },
    {    28,    28, "AEAD_AES_256_OCB_TAGLEN64" },
    {    29,    29, "AEAD_CHACHA20_POLY1305" },
    {    30,    30, "AEAD_AES_128_GCM_SIV" },
    {    31,    31, "AEAD_AES_256_GCM_SIV" },
    {    32,    32, "AEAD_AEGIS128L" },
    {    33,    33, "AEAD_AEGIS256" },
    {    34, 32767, "Unassigned" },
    { 32768, 65535, "Reserved for Private Use" },
    {     0,     0, NULL }
};

/* All supported AEAD
 * Note: Key length is limited in NTS_KE_TLS13_KEY_MAX_LEN
 *
 * Only the following algos have been seen in the wild and were tested.
 * Extending the supported algos can be easily done by extending this list.
 * Think of looking at NTP ntp_decrypt_nts() when adding new algos, because
 * different GCRY modes may require different handling.
 *
 * All crypto functions will need GCRYPT >= 1.10.0 because
 * GCRY_CIPHER_MODE_SIV is a mandatory algorithm. If'ing out SIV algos
 * to compile sucessfully without GCRYPT support.
 */
static const nts_aead nts_ke_aead_gcry_map[] = {
#if GCRYPT_VERSION_NUMBER >= 0x010a00
    { 15, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_SIV,     32, 16 },
    { 16, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_SIV,     48, 16 },
    { 17, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_SIV,     64, 16 },
    { 30, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_GCM_SIV, 16, 16 },
#endif
    {  0, 0,                  0,                         0,  0 }
};

const nts_aead *
nts_find_aead(uint16_t id)
{
    const nts_aead *c;
    for(c = nts_ke_aead_gcry_map; c->id !=0 ; c++){
        if(c->id == id){
            return c;
        }
    }
    return NULL;
}

/* Request/response tracking */
typedef struct _nts_ke_req_resp_t {
    uint32_t req_frame;
    uint32_t resp_frame;
} nts_ke_req_resp_t;

/* Cookie map */
static wmem_map_t *nts_cookies;

struct nts_ke_uid_lookup {
    uint32_t uid_hash;
    nts_cookie_t *cookie;
};

static int
nts_find_list_callback(const void *a, const void *b)
{
    const uint32_t *x = (const uint32_t*)a;
    if(*x == GPOINTER_TO_UINT(b)) return 0; else return -1;
}

static void
nts_uid_lookup_callback(void *key _U_, void *val, void *userdata)
{
    nts_cookie_t *current_cookie = (nts_cookie_t *)val;
    struct nts_ke_uid_lookup *func_data = (struct nts_ke_uid_lookup *)userdata;

    if(wmem_list_find_custom(current_cookie->frames_used_uid, GUINT_TO_POINTER(func_data->uid_hash), nts_find_list_callback))
        func_data->cookie = current_cookie;
}

void
nts_append_used_frames_to_tree(void *data, void *user_data)
{
    proto_item *ct;

    uint32_t *pnum = (uint32_t *)data;
    nts_used_frames_lookup_t *func_data = (nts_used_frames_lookup_t *)user_data;

    ct = proto_tree_add_uint(func_data->tree, func_data->hfindex, func_data->tvb, 0, 0, *pnum);
    proto_item_set_generated(ct);
}

nts_cookie_t*
nts_new_cookie(tvbuff_t *tvb, uint16_t aead, packet_info *pinfo)
{
    unsigned int cookie_len = tvb_reported_length(tvb);
    unsigned char *key_c2s = (char *)wmem_alloc0(pinfo->pool, NTS_KE_TLS13_KEY_MAX_LEN);
    unsigned char *key_s2c = (char *)wmem_alloc0(pinfo->pool, NTS_KE_TLS13_KEY_MAX_LEN);
    uint8_t *tvb_bytes;
    nts_cookie_t *cookie;
    uint32_t strong_hash;
    const nts_aead *aead_entry;
    bool k1, k2;
    uint8_t ex_context_s2c[5], ex_context_c2s[5];

    /* Build exporter context
     * We only support NTPv4 - Context begins with 0x0000 (NTPv4 protocol ID)
     * Followed by two bytes = AEAD ID
     * Followed by one byte (0x00 = C2S key, 0x01 = S2C key)
     *
     * RFC 8915 5.1:
     * The per-association context value [RFC5705] SHALL consist of the following five octets:
     *
     * - The first two octets SHALL be zero (the Protocol ID for NTPv4).
     * - The next two octets SHALL be the Numeric Identifier of the negotiated AEAD algorithm in network byte order.
     * - The final octet SHALL be 0x00 for the C2S key and 0x01 for the S2C key.
     *
     * Chrony is using a hard-coded context of AEAD_AES_SIV_CMAC_256 while also supporting AEAD_AES_128_GCM_SIV:
     * - C2S 0x0000000F00
     * - S2C 0x0000000F01
     *
     * As this is a breaking compatibility bug, offer a compatibility mode as preference.
     * See: https://gitlab.com/chrony/chrony/-/issues/12
     */
    ex_context_c2s[0] = 0x00;
    ex_context_c2s[1] = 0x00;
    ex_context_c2s[2] = (uint8_t)(aead >> 8);
    ex_context_c2s[3] = (uint8_t)aead;
    ex_context_c2s[4] = 0x00;

    ex_context_s2c[0] = 0x00;
    ex_context_s2c[1] = 0x00;
    ex_context_s2c[2] = (uint8_t)(aead >> 8);
    ex_context_s2c[3] = (uint8_t)aead;
    ex_context_s2c[4] = 0x01;

    if(nts_ke_chrony_compat_mode && aead == 30) {
        ex_context_c2s[2] = 0x00;
        ex_context_c2s[3] = 0x0F;
        ex_context_s2c[2] = 0x00;
        ex_context_s2c[3] = 0x0F;
    }

    aead_entry = nts_find_aead(aead);

    if(cookie_len < 1 || !aead_entry)
        return NULL;

    tvb_bytes = (uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, cookie_len);
    strong_hash = wmem_strong_hash(tvb_bytes, cookie_len);

    cookie = (nts_cookie_t*) wmem_map_lookup(nts_cookies, GUINT_TO_POINTER(strong_hash));

    /* Cookie was not found, add it */
    if(!cookie) {

        /* Extract keys */
        k1 = tls13_exporter(pinfo, false,
                NTS_KE_EXPORTER_LABEL, ex_context_c2s,
                sizeof(ex_context_c2s), aead_entry->key_len, &key_c2s);
        k2 = tls13_exporter(pinfo, false,
                NTS_KE_EXPORTER_LABEL, ex_context_s2c,
                sizeof(ex_context_s2c), aead_entry->key_len, &key_s2c);

        cookie = wmem_new(wmem_file_scope(), nts_cookie_t);

        cookie->frame_received  = pinfo->num;
        cookie->frames_used     = wmem_list_new(wmem_file_scope());
        cookie->frames_used_uid = wmem_list_new(wmem_file_scope());
        cookie->aead            = aead;
        if(k1 && k2) {
            cookie->keys_present = true;
            memcpy(cookie->key_c2s, key_c2s, aead_entry->key_len);
            memcpy(cookie->key_s2c, key_s2c, aead_entry->key_len);
        } else {
            cookie->keys_present = false;
        }

        wmem_map_insert(nts_cookies, GUINT_TO_POINTER(strong_hash), cookie);
    }

    return cookie;
}

nts_cookie_t*
nts_new_cookie_copy(tvbuff_t *tvb, nts_cookie_t *ref_cookie, packet_info *pinfo)
{
    unsigned int cookie_len = tvb_reported_length(tvb);
    uint8_t *tvb_bytes;
    nts_cookie_t *cookie;
    uint32_t strong_hash;
    const nts_aead *aead_entry;

    aead_entry = nts_find_aead(ref_cookie->aead);

    if(cookie_len < 1 || !aead_entry)
        return NULL;

    tvb_bytes = (uint8_t *)tvb_memdup(pinfo->pool, tvb, 0, cookie_len);
    strong_hash = wmem_strong_hash(tvb_bytes, cookie_len);

    cookie = (nts_cookie_t*) wmem_map_lookup(nts_cookies, GUINT_TO_POINTER(strong_hash));

    /* Cookie was not found, add it */
    if(!cookie) {

        cookie = wmem_new(wmem_file_scope(), nts_cookie_t);

        cookie->frame_received  = pinfo->num;
        cookie->frames_used     = wmem_list_new(wmem_file_scope());
        cookie->frames_used_uid = wmem_list_new(wmem_file_scope());
        cookie->aead            = ref_cookie->aead;
        if(ref_cookie->keys_present) {
            cookie->keys_present = true;
            memcpy(cookie->key_c2s, ref_cookie->key_c2s, aead_entry->key_len);
            memcpy(cookie->key_s2c, ref_cookie->key_s2c, aead_entry->key_len);
        } else {
            cookie->keys_present = false;
        }

        wmem_map_insert(nts_cookies, GUINT_TO_POINTER(strong_hash), cookie);
    }

    return cookie;
}

nts_cookie_t* nts_use_cookie(tvbuff_t *tvb_cookie, tvbuff_t *tvb_uid, packet_info *pinfo)
{
    unsigned int cookie_len = tvb_reported_length(tvb_cookie);
    unsigned int uid_len = tvb_reported_length(tvb_uid);

    uint8_t *tvb_cookie_bytes, *tvb_uid_bytes;
    nts_cookie_t *cookie;

    uint32_t strong_hash_cookie, strong_hash_uid;
    uint32_t *pnum, *uid;

    if(cookie_len < 1 || uid_len < 1)
        return NULL;

    /* Hash cookie and UID */
    tvb_cookie_bytes = (uint8_t *)tvb_memdup(pinfo->pool, tvb_cookie, 0, cookie_len);
    strong_hash_cookie = wmem_strong_hash(tvb_cookie_bytes, cookie_len);

    tvb_uid_bytes = (uint8_t *)tvb_memdup(pinfo->pool, tvb_uid, 0, uid_len);
    strong_hash_uid = wmem_strong_hash(tvb_uid_bytes, uid_len);

    /* Find cookie by hash */
    cookie = (nts_cookie_t*) wmem_map_lookup(nts_cookies, GUINT_TO_POINTER(strong_hash_cookie));

    if(cookie) {
        /* In theory a cookie can be used multiple times, so remember all packets which used it */
        if(!wmem_list_find_custom(cookie->frames_used, GUINT_TO_POINTER(pinfo->num), nts_find_list_callback)) {
            pnum = wmem_new0(wmem_file_scope(), uint32_t);
            wmem_list_append(cookie->frames_used, pnum);
            *pnum = pinfo->num;
        }

        if(!wmem_list_find_custom(cookie->frames_used_uid, GUINT_TO_POINTER(strong_hash_uid), nts_find_list_callback)) {
            uid = wmem_new0(wmem_file_scope(), uint32_t);
            wmem_list_append(cookie->frames_used_uid, uid);
            *uid = strong_hash_uid;
        }
    }

    return cookie;
}

nts_cookie_t*
nts_find_cookie_by_uid(tvbuff_t *tvb_uid)
{
    unsigned int uid_len = tvb_reported_length(tvb_uid);

    uint8_t *tvb_uid_bytes;
    struct nts_ke_uid_lookup lookup;

    if(uid_len < 1)
        return NULL;

    /* Hash UID */
    tvb_uid_bytes = (uint8_t *)tvb_memdup(wmem_packet_scope(), tvb_uid, 0, uid_len);
    lookup.uid_hash = wmem_strong_hash(tvb_uid_bytes, uid_len);
    lookup.cookie = NULL;

    /* Find cookie by UID hash */
    wmem_map_foreach(nts_cookies, nts_uid_lookup_callback, &lookup);

    return lookup.cookie;
}

static int
dissect_nts_ke(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset;
    uint16_t critical, type;
    uint32_t body_length, body_counter, aead = 0;
    uint32_t counter_next_proto_recs = 0, counter_aead = 0, counter_cookies = 0;
    uint32_t *next_proto_list_item;
    proto_item *ti, *ti_record, *rt;
    proto_tree *nts_ke_tree, *record_tree;
    bool critical_bool, end_record = false;
    bool request, direction_determined = false;
    wmem_list_t *next_protos = wmem_list_new(pinfo->pool);
    conversation_t *conv;
    nts_ke_req_resp_t *conv_data;
    nts_cookie_t *cookie;
    struct tcp_analysis *tcp_conv;
    nts_used_frames_lookup_t lookup_data = {.tvb = tvb, .hfindex = hf_nts_ke_cookie_used_frame};

    offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NTS-KE");
    col_clear(pinfo->cinfo,COL_INFO);

    ti = proto_tree_add_item(tree, proto_nts_ke, tvb, 0, 0, ENC_NA);
    nts_ke_tree = proto_item_add_subtree(ti, ett_nts_ke);

    /* Error on ALPN mismatch */
    if(strcmp(tls_get_alpn(pinfo), NTS_KE_ALPN) != 0)
        expert_add_info(pinfo, nts_ke_tree, &ei_nts_ke_alpn_mismatch);

    /* Conversation init */
    conv = find_or_create_conversation(pinfo);
    conv_data = (nts_ke_req_resp_t *)conversation_get_proto_data(conv, proto_nts_ke);

    /* As NTS-KE has no client/server distinction. We need to rely on TCP.
     * We can be sure that TCP has identified the server port,
     * so we just need to compare it with our packet's destination port
     * to identify the direction.
     */
    tcp_conv = get_tcp_conversation_data_idempotent(conv);
    if(tcp_conv && pinfo->destport == tcp_conv->server_port) {
        direction_determined = true;
        request = true;
    } else if (tcp_conv && pinfo->srcport == tcp_conv->server_port) {
        direction_determined = true;
        request = false;
    }

    if (direction_determined) {
        if (!conv_data) {
            conv_data = wmem_new(wmem_file_scope(), nts_ke_req_resp_t);
            conv_data->req_frame = request ? pinfo->num : 0;
            conv_data->resp_frame = !request ? pinfo->num : 0;
            conversation_add_proto_data(conv, proto_nts_ke, conv_data);
        } else {
            conv_data->req_frame = request ? pinfo->num : conv_data->req_frame;
            conv_data->resp_frame = !request ? pinfo->num : conv_data->resp_frame;
        }
    }

    while(tvb_reported_length_remaining(tvb, offset) >= CRIT_TYPE_BODY_LEN) {

        /* Reset pointer */
        cookie = NULL;

        ti_record = proto_tree_add_item(nts_ke_tree, hf_nts_ke_record, tvb, offset, 0, ENC_NA);
        record_tree = proto_item_add_subtree(ti_record, ett_nts_ke_record);

        critical = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) & CRITICAL_MASK;
        critical_bool = (bool)(critical >> 15);
        proto_tree_add_boolean(record_tree, hf_nts_ke_critical_bit, tvb, offset, 2, critical);

        type = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) & TYPE_MASK;
        proto_tree_add_uint(record_tree, hf_nts_ke_record_type, tvb, offset, 2, type);
        proto_item_append_text(ti_record, " (%s)", rval_to_str_const(type, nts_ke_record_types, "Unknown Record Type"));
        offset += 2;

        proto_tree_add_item_ret_uint(record_tree, hf_nts_ke_body_length, tvb, offset, 2, ENC_BIG_ENDIAN, &body_length);
        offset += 2;

        if(end_record)
            expert_add_info(pinfo, record_tree, &ei_nts_ke_record_after_end);

        body_counter = 0;

        switch (type) {
            case RECORD_TYPE_END:

                /* No body allowed */
                if(body_length > 0) {
                    call_data_dissector(tvb_new_subset_length(tvb, offset, body_length), pinfo, record_tree);
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_body_illegal);
                    offset += body_length;
                }

                /* Critical bit is mandatory for this type */
                if(!critical_bool)
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_critical_bit_missing);

                /* Mark end record as seen */
                end_record = true;

                break;

            case RECORD_TYPE_NEXT:

                while(body_counter < body_length) {
                    uint32_t next_proto;
                    proto_tree_add_item_ret_uint(record_tree, hf_nts_ke_next_proto, tvb, offset, 2, ENC_BIG_ENDIAN, &next_proto);
                    offset += 2;
                    body_counter += 2;

                    /* Store list of offered/accepted next protocols */
                    next_proto_list_item = wmem_new0(pinfo->pool, uint32_t);
                    wmem_list_append(next_protos, next_proto_list_item);
                    *next_proto_list_item = next_proto;

                    col_append_str(pinfo->cinfo, COL_INFO, rval_to_str_const(next_proto, nts_ke_next_proto_rvals, "Unknown Proto"));
                }

                /* Critical bit is mandatory for this type */
                if(!critical_bool)
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_critical_bit_missing);

                counter_next_proto_recs++;

                break;

            case RECORD_TYPE_ERR:

                /* Fixed body length */
                if(body_length == 2) {
                    proto_tree_add_item(record_tree, hf_nts_ke_error, tvb, offset, body_length, ENC_BIG_ENDIAN);
                } else {
                    call_data_dissector(tvb_new_subset_length(tvb, offset, body_length), pinfo, record_tree);
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_body_length_illegal);
                }
                offset += body_length;

                /* Critical bit is mandatory for this type */
                if(!critical_bool)
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_critical_bit_missing);

                break;

            case RECORD_TYPE_WARN:

                /* Fixed body length */
                if(body_length == 2) {
                    proto_tree_add_item(record_tree, hf_nts_ke_warning, tvb, offset, body_length, ENC_BIG_ENDIAN);
                } else {
                    call_data_dissector(tvb_new_subset_length(tvb, offset, body_length), pinfo, record_tree);
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_body_length_illegal);
                }
                offset += body_length;

                /* Critical bit is mandatory for this type */
                if(!critical_bool)
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_critical_bit_missing);

                break;

            case RECORD_TYPE_AEAD:

                while(body_counter < body_length) {

                    proto_tree_add_item_ret_uint(record_tree, hf_nts_ke_aead_algo, tvb, offset, 2, ENC_BIG_ENDIAN, &aead);
                    offset += 2;
                    body_counter += 2;
                    counter_aead++;
                }

                break;

            case RECORD_TYPE_COOKIE:

                /* Arbitrary body data
                 *
                 * Other dissectors (e.g. NTP) need to access this data along it's extracted keys.
                 * Add NTS cookies if NTP (0x00) is part of next protos
                 */
                if (
                    nts_ke_extract_keys &&
                    aead > 0 &&
                    wmem_list_find_custom(next_protos, GUINT_TO_POINTER(0x00), nts_find_list_callback)
                ) {
                    cookie = nts_new_cookie(tvb_new_subset_length(tvb, offset, body_length), (uint16_t)aead, pinfo);
                }
                proto_tree_add_item(record_tree, hf_nts_ke_cookie, tvb, offset, body_length, ENC_NA);
                offset += body_length;
                counter_cookies++;

                if(cookie) {
                    /* List all packets which made use of that cookie */
                    lookup_data.tree = record_tree;
                    wmem_list_foreach(cookie->frames_used, nts_append_used_frames_to_tree, &lookup_data);
                }

                break;

            case RECORD_TYPE_NEG_SRV:

                /* Arbitrary string */
                proto_tree_add_item(record_tree, hf_nts_ke_server, tvb, offset, body_length, ENC_ASCII);
                offset += body_length;

                break;

            case RECORD_TYPE_NEG_PORT:

                /* Fixed body length */
                if(body_length == 2) {
                    proto_tree_add_item(record_tree, hf_nts_ke_port, tvb, offset, body_length, ENC_BIG_ENDIAN);
                } else {
                    call_data_dissector(tvb_new_subset_length(tvb, offset, body_length), pinfo, record_tree);
                    expert_add_info(pinfo, record_tree, &ei_nts_ke_body_length_illegal);
                }
                offset += body_length;

                break;

            default:

                call_data_dissector(tvb_new_subset_length(tvb, offset, body_length), pinfo, record_tree);
                offset += body_length;

                break;
        }

        proto_item_set_end(ti_record, tvb, offset);
    }

    /* Request/Response */
    if(conv_data && direction_determined) {
        if(request && conv_data->resp_frame > 0) {
            rt = proto_tree_add_uint(nts_ke_tree, hf_nts_ke_response_in, tvb, 0, 0, conv_data->resp_frame);
            proto_item_set_generated(rt);
        } else if (!request && conv_data->req_frame > 0) {
            rt = proto_tree_add_uint(nts_ke_tree, hf_nts_ke_response_to, tvb, 0, 0, conv_data->req_frame);
            proto_item_set_generated(rt);
        }
    }

    /* Info columns text */
    if(counter_aead > 0)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%u AEAD Algorithm%s", counter_aead, plurality(counter_aead, "", "s"));

    if(counter_cookies > 0)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%u Cookie%s", counter_cookies, plurality(counter_cookies, "", "s"));

    /* No end record found */
    if(!end_record)
        expert_add_info(pinfo, nts_ke_tree, &ei_nts_ke_end_missing);

    /* Illegal AEAD record count */
    if(counter_next_proto_recs != 1)
        expert_add_info(pinfo, nts_ke_tree, &ei_nts_ke_next_proto_illegal_count);

    proto_item_set_end(ti, tvb, offset);

    return offset;
}

static unsigned
get_nts_ke_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{

    bool another_record = true;
    unsigned size = 0;

    /* Concat multiple records into one protocol tree */
    while(another_record) {

        /* Size is body length + 4 byte (CRIT_TYPE_BODY_LEN) */
        unsigned pdu_size = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN) + CRIT_TYPE_BODY_LEN;
        size += pdu_size;

        if (tvb_captured_length_remaining(tvb, offset + pdu_size) < CRIT_TYPE_BODY_LEN)
            another_record = false;

        offset += pdu_size;
    }

    return size;

}

static int
dissect_nts_ke_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!tvb_bytes_exist(tvb, 0, CRIT_TYPE_BODY_LEN))
        return 0;

    tcp_dissect_pdus(tvb, pinfo, tree, true, CRIT_TYPE_BODY_LEN, get_nts_ke_message_len, dissect_nts_ke, data);
    return tvb_reported_length(tvb);
}

void
proto_register_nts_ke(void)
{
    static hf_register_info hf[] = {
        { &hf_nts_ke_record,
            { "NTS-KE Record", "nts-ke.record",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_critical_bit,
            { "Critical Bit", "nts-ke.critical_bit",
            FT_BOOLEAN, 16,
            TFS(&tfs_set_notset), CRITICAL_MASK,
            NULL, HFILL }
        },
        { &hf_nts_ke_record_type,
            { "Record Type", "nts-ke.type",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
            RVALS(nts_ke_record_types), TYPE_MASK,
            NULL, HFILL }
        },
        { &hf_nts_ke_body_length,
            { "Body Length", "nts-ke.body_length",
            FT_UINT16, BASE_DEC | BASE_UNIT_STRING,
            UNS(&units_byte_bytes), 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_next_proto,
            { "Next Protocol ID", "nts-ke.next_proto",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
            RVALS(nts_ke_next_proto_rvals), 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_error,
            { "Error Code", "nts-ke.error",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
            RVALS(nts_ke_error_codes), 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_warning,
            { "Warning Code", "nts-ke.warning",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
            RVALS(nts_ke_warning_codes), 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_aead_algo,
            { "AEAD Algorithm", "nts-ke.aead_algo",
            FT_UINT16, BASE_DEC | BASE_RANGE_STRING,
            RVALS(nts_ke_aead_rvals), 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_cookie,
            { "Cookie Data", "nts-ke.cookie",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_cookie_used_frame, {
            "Used cookie in", "nts-ke.cookie.use_frame",
            FT_FRAMENUM, BASE_NONE,
            NULL, 0,
            NULL, HFILL }},
        { &hf_nts_ke_server,
            { "Server", "nts-ke.server",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_port,
            { "Port", "nts-ke.port",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_response_in,
            { "Response In", "nts-ke.response_in",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            NULL, HFILL }
        },
        { &hf_nts_ke_response_to,
            { "Response To", "nts-ke.response_to",
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_nts_ke_critical_bit_missing,
            { "nts-ke.critical_bit.missing", PI_MALFORMED, PI_ERROR,
                "Critical bit must be set for this record type", EXPFILL }
        },
        { &ei_nts_ke_record_after_end,
            { "nts-ke.record.after_end", PI_MALFORMED, PI_ERROR,
                "Illegal record after end of message", EXPFILL }
        },
        { &ei_nts_ke_end_missing,
            { "nts-ke.end.missing", PI_MALFORMED, PI_ERROR,
                "No end of message present", EXPFILL }
        },
        { &ei_nts_ke_body_illegal,
            { "nts-ke.body.illegal", PI_MALFORMED, PI_ERROR,
                "Illegal body data present", EXPFILL }
        },
        { &ei_nts_ke_body_length_illegal,
            { "nts-ke.body_length.illegal", PI_MALFORMED, PI_ERROR,
                "Illegal body length", EXPFILL }
        },
        { &ei_nts_ke_next_proto_illegal_count,
            { "nts-ke.next_proto.illegal_count", PI_MALFORMED, PI_ERROR,
                "Illegal Next Protocol record count", EXPFILL }
        },
        { &ei_nts_ke_alpn_mismatch,
            { "nts-ke.alpn_mismatch", PI_DECRYPTION, PI_ERROR,
                "TLS ALPN mismatch", EXPFILL }
        }
    };

    static int *ett[] = {
        &ett_nts_ke,
        &ett_nts_ke_record
    };

    expert_module_t* expert_nts_ke;
    module_t *nts_ke_module;

    nts_cookies = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);

    proto_nts_ke = proto_register_protocol ("NTS Key Establishment Protocol", "NTS-KE", "nts-ke");

    proto_register_field_array(proto_nts_ke, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_nts_ke = expert_register_protocol(proto_nts_ke);
    expert_register_field_array(expert_nts_ke, ei, array_length(ei));

    nts_ke_module = prefs_register_protocol(proto_nts_ke, NULL);
    prefs_register_bool_preference(nts_ke_module, "extract_keys",
        "Extract S2C and C2S keys",
        "Whether to extract client-to-server and server-to-client "
        "keys for crypto-processing.",
        &nts_ke_extract_keys);
    prefs_register_bool_preference(nts_ke_module, "chrony_compat_mode",
        "Chrony Compatibility Mode",
        "Allows AEAD_AES_128_GCM_SIV key extraction for Chrony-based "
        "NTP clients and servers.",
        &nts_ke_chrony_compat_mode);

    nts_ke_handle = register_dissector("nts-ke", dissect_nts_ke_tcp, proto_nts_ke);
}

void
proto_reg_handoff_nts_ke(void)
{
    dissector_add_uint_with_preference("tls.port", TLS_PORT, nts_ke_handle);
    dissector_add_string("tls.alpn", NTS_KE_ALPN, nts_ke_handle);
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
