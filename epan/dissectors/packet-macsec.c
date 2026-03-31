/* packet-macsec.c
 * Routines for IEEE 802.1AE MACsec dissection
 * Copyright 2013, Allan W. Nielsen <anielsen@vitesse.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "MACsec"
#include <wireshark.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/etypes.h>
#include <epan/proto_data.h>
#include <epan/uat.h>
#include <epan/tfs.h>

#include "packet-mka.h"

#include <wsutil/wsgcrypt.h>
#include <wsutil/pint.h>
#include <wsutil/to_str.h>

void proto_register_macsec(void);
void proto_reg_handoff_macsec(void);

static dissector_handle_t macsec_handle;
static dissector_handle_t ethertype_handle;

/* TCI/AN field masks */
#define TCI_MASK     0xFC
#define TCI_V_MASK   0x80
#define TCI_ES_MASK  0x40
#define TCI_SC_MASK  0x20
#define TCI_SCB_MASK 0x10
#define TCI_E_MASK   0x08
#define TCI_C_MASK   0x04

#define AN_MASK      0x03
#define SL_MASK      0x3F

#define SAK128_LEN            (16)
#define PSK128_LEN            (16)
#define SAK256_LEN            (32)
#define PSK256_LEN            (32)

#define ICV_LEN               (16)
#define IV_LEN                (12)

#define HWADDR_LEN            (6)
#define ETHERTYPE_LEN         (2)
#define ETHHDR_LEN            ((HWADDR_LEN * 2) + ETHERTYPE_LEN)

#define SECTAG_LEN_WITH_SC    (14)
#define SECTAG_LEN_WITHOUT_SC (6)

#define AAD_ENCRYPTED_LEN     (28)

// XXX - MACsec now supports jumbo frames, this assumption is not valid
#define MAX_PAYLOAD_LEN       (1514)

/* keys for p_[add|get]_proto_data */
#define XPN_KEY 0

static int proto_macsec;
static int hf_macsec_TCI;
static int hf_macsec_TCI_V;
static int hf_macsec_TCI_ES;
static int hf_macsec_TCI_SC;
static int hf_macsec_TCI_SCB;
static int hf_macsec_TCI_E;
static int hf_macsec_TCI_C;
static int hf_macsec_AN;
static int hf_macsec_SL;
static int hf_macsec_PN;
static int hf_macsec_XPN;
static int hf_macsec_SCI;
static int hf_macsec_SCI_system_identifier;
static int hf_macsec_SCI_port_identifier;
static int hf_macsec_etype;
static int hf_macsec_eth_padding;
static int hf_macsec_decrypted_data;
static int hf_macsec_ICV;
static int hf_macsec_verify_info;
static int hf_macsec_ICV_check_success;
static int hf_macsec_ckn_info;
static int hf_macsec_sak;
static int hf_macsec_psk_info;
static int hf_macsec_psk;
static int hf_macsec_ckn_table_index;
static int hf_macsec_psk_table_index;

/* Initialize the subtree pointers */
static int ett_macsec;
static int ett_macsec_tci;
static int ett_macsec_sci;
static int ett_macsec_verify;

static expert_field ei_macsec_not_processed;
static expert_field ei_macsec_nonstandard_cipher;
static expert_field ei_macsec_payload_too_large;

/* Decrypting payload buffer */
static uint8_t macsec_payload[MAX_PAYLOAD_LEN];
static unsigned macsec_payload_len = 0;

/* AAD buffer */
static uint8_t aad[MAX_PAYLOAD_LEN];
static unsigned aad_len = 0;

/* IV buffer */
static uint8_t iv[IV_LEN];
static unsigned iv_len = IV_LEN;

/* ICV buffer */
static uint8_t icv[ICV_LEN];
static unsigned icv_len = ICV_LEN;

/* PSK/SAK that was used for successful decode */
static uint8_t *sak_for_decode = NULL;
static unsigned sak_for_decode_len = 0;

/* if set, try to use the EAPOL-MKA CKN table as well */
static bool try_mka = true;

/* PSK key config data */
typedef struct _psk_info {
    unsigned char *key;
    unsigned  key_len;
} psk_info_t;

typedef struct _psk_config {
  psk_info_t keydata;
  char *name;
} psk_config_t;

static psk_config_t *psk_config_data = NULL;
static unsigned psk_config_data_count = 0;

UAT_BUFFER_CB_DEF(psk_config_data, key, psk_config_t, keydata.key, keydata.key_len)
UAT_CSTRING_CB_DEF(psk_config_data, name, psk_config_t)

static void *
copy_psk_config_cb(void *n, const void *o, size_t size _U_) {
    psk_config_t *new_rec = (psk_config_t *)n;
    const psk_config_t *old_rec = (const psk_config_t *)o;

    new_rec->keydata.key = (unsigned char *)g_memdup2(old_rec->keydata.key, old_rec->keydata.key_len);
    new_rec->keydata.key_len = old_rec->keydata.key_len;

    new_rec->name = g_strdup(old_rec->name);

    return new_rec;
}

static bool
update_psk_config(void *r, char **err) {
    psk_config_t *rec = (psk_config_t *)r;

    ws_debug("psk_config_data_count :%u\n", psk_config_data_count);

    // Validate the key input
    if ((PSK128_LEN != rec->keydata.key_len) && (PSK256_LEN != rec->keydata.key_len)) {
        *err = ws_strdup("Only AES-128 (16 byte) or AES-256 (32 byte) keys are supported");
        return false;
    }

    if (0 == strlen(rec->name)) {
        // This field is called "name" internally and called "Info" in the UAT,
        // wth tooltip "PSK info to display". Calling it "PSK ID" here might
        // be confusing.
        *err = ws_strdup("Missing PSK ID!");
        return false;
    }

    return true;
}

static void
free_psk_config_cb(void *r) {
    psk_config_t *rec = (psk_config_t *)r;

    ws_debug("psk_config_data_count :%u\n", psk_config_data_count);

    g_free(rec->keydata.key);
    g_free(rec->name);
}

static void
post_update_psk_config_cb(void) {
    ws_debug("psk_config_data_count :%u\n", psk_config_data_count);

    if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
        for (unsigned i = 0; i < psk_config_data_count; i++) {
            psk_config_t *c = &psk_config_data[i];
            unsigned char *key = c->keydata.key;
            ws_debug("id: %s\n", c->name);

            char *psk_str = bytes_to_str_maxlen(NULL, key, c->keydata.key_len, 0);
            ws_debug("psk: %s", psk_str);
            g_free(psk_str);
        }
    }
}

static psk_config_t *
get_psk_config_table(void) {
    return psk_config_data;
}

static unsigned
get_psk_config_table_count(void) {
    return psk_config_data_count;
}

/* Test if a key has all 0s (invalid) */
static bool
macsec_is_valid_key(const uint8_t *sak_to_check) {
    /* memcmp of 0 against previous byte over the range of the SAK length is an easy test for all 0s */
    if ((NULL == sak_to_check) || ( (0 == sak_to_check[0]) && (0 == memcmp(sak_to_check, sak_to_check + 1, (MKA_MAX_SAK_LEN - 1))) ) ) {
        return false;
    }

    return true;
}

/* Common decode routine */
static proto_checksum_enum_e
attempt_packet_decode(bool encrypted, uint8_t *key, unsigned key_len, const uint8_t *payload, unsigned payload_len) {
    proto_checksum_enum_e result = PROTO_CHECKSUM_E_GOOD;
    gcry_cipher_hd_t handle = NULL;

    if (gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0)) {
        ws_warning("failed to open cipher context");
    } else {
        if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
            char *key_str = bytes_to_str_maxlen(NULL, key, key_len, 0);
            ws_debug("key    : %s", key_str);
            g_free(key_str);
        }

        if (false == macsec_is_valid_key(key)) {
            ws_debug("skipping invalid key");
            result = PROTO_CHECKSUM_E_BAD;
        }

        if (PROTO_CHECKSUM_E_GOOD == result) {
            if (gcry_cipher_setkey(handle, key, key_len)) {
                ws_warning("failed to set cipher key");
                result = PROTO_CHECKSUM_E_BAD;
            }
        }

        if (PROTO_CHECKSUM_E_GOOD == result) {
            if (gcry_cipher_setiv(handle, iv, iv_len)) {
                ws_warning("failed to set cipher IV");
                result = PROTO_CHECKSUM_E_BAD;
            }
        }

        if (PROTO_CHECKSUM_E_GOOD == result) {
            /* Authenticate with the AAD. */
            if (gcry_cipher_authenticate(handle, aad, aad_len)) {
                ws_warning("failed to authenticate");
                result = PROTO_CHECKSUM_E_BAD;
            }
        }

        if ((PROTO_CHECKSUM_E_GOOD == result) && (true == encrypted)) {
            if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
                char *payload_str = bytes_to_str_maxlen(NULL, payload, payload_len, 16);
                ws_debug("payload : %s (len: %u)", payload_str, payload_len);
                g_free(payload_str);
            }

            /* Attempt to decrypt the data from the payload buffer into the decode buffer. */
            if (gcry_cipher_decrypt(handle, macsec_payload, payload_len, payload, payload_len)) {
                ws_warning("failed to decrypt");
                result = PROTO_CHECKSUM_E_BAD;
            }

            if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
                char *payload_str = bytes_to_str_maxlen(NULL, macsec_payload, payload_len, 16);
                ws_debug("payload : %s (len: %u)", payload_str, payload_len);
                g_free(payload_str);
            }
        }

        if (PROTO_CHECKSUM_E_GOOD == result) {
            /* Use the previously extracted ICV to verify the decrypted data. */
            if (gcry_cipher_checktag(handle, icv, icv_len)) {
                ws_debug("failed to verify icv");
                result = PROTO_CHECKSUM_E_BAD;
            } else {
                /* Save the payload length for future processing. */
                macsec_payload_len = payload_len;
            }
        }
    }

    if (NULL != handle) {
        gcry_cipher_close(handle);
    }

    return result;
}

/* Attempt to decode the packet using PSKs from the PSK table */
static int
attempt_packet_decode_with_psks(bool encrypted, const uint8_t *payload, unsigned payload_len) {
    proto_checksum_enum_e result = PROTO_CHECKSUM_E_UNVERIFIED;
    int table_index = 0;

    /* Get the PSK table and its size. */
    const psk_config_t *psk_table = get_psk_config_table();
    int psk_table_count = get_psk_config_table_count();
    ws_debug("PSK table size: %u", psk_table_count);

    /* Iterate through the PSK table and use each PSK to attempt to decode the packet. */
    for (table_index = 0; table_index < psk_table_count; table_index++) {
        const psk_info_t *info = &psk_table[table_index].keydata;

        sak_for_decode = (uint8_t *)info->key;
        sak_for_decode_len = info->key_len;

        result = attempt_packet_decode(encrypted, sak_for_decode, sak_for_decode_len, payload, payload_len);
        if (PROTO_CHECKSUM_E_GOOD == result) {
            ws_debug("packet decoded with PSK at PSK table index %u", table_index);
            break;
        } else {
            ws_debug("failed to decode packet with PSK at PSK table index %u", table_index);
        }
    }

    /* On failure, clear the key used for decode. */
    if (PROTO_CHECKSUM_E_GOOD != result) {
        table_index = -1;
        sak_for_decode = NULL;
        sak_for_decode_len = 0;
    }

    return table_index;
}

struct decode_user_data {
    mka_sak_info_key_t *sak_info;
    const uint8_t *payload;
    unsigned payload_len;
    bool encrypted;
    unsigned ssci;
};

static gboolean
saks_find_cb(void *key, void *value _U_, void *user_data)
{
    struct decode_user_data *decode_params = (struct decode_user_data*)user_data;

    uint8_t *sci = (uint8_t*)key;
    /* This is a generic function, but in practice only used on
     * GCM_AES_128 and GCM_AES_256. */
    /* Don't use the SSCI value because this would only be called when
     * iterating over the entire map when the correct SSCI is unknown. */
    //uint8_t ssci = GPOINTER_TO_UINT(value);

    mka_sak_info_key_t *sak_info = decode_params->sak_info;
    uint8_t *salt = sak_info->salt;

    switch(sak_info->cipher_suite) {
    case MACSEC_GCM_AES_128:
    case MACSEC_GCM_AES_256:
        memcpy(iv, sci, MACSEC_SCI_LEN);
        break;
    case MACSEC_GCM_AES_XPN_128:
    case MACSEC_GCM_AES_XPN_256:
        // 802.1X-2020 9.10 SAK installation and use
        iv[3] = salt[3] ^ decode_params->ssci++;
        break;
    default:
        return false;
    }

    proto_checksum_enum_e result = attempt_packet_decode(decode_params->encrypted, sak_for_decode, sak_for_decode_len, decode_params->payload, decode_params->payload_len);
    if (PROTO_CHECKSUM_E_GOOD == result) {
        return true;
    }
    return false;
}

static proto_checksum_enum_e
attempt_packet_decode_with_xpn(packet_info *pinfo, struct decode_user_data *ud, bool sci_known) {
    proto_checksum_enum_e result = PROTO_CHECKSUM_E_UNVERIFIED;

    mka_sak_info_key_t *sak_info = ud->sak_info;
    bool ssci_known = sci_known;
    uint8_t saved_iv[IV_LEN];
    uint32_t pn, pn_msb;
    uint64_t lpn;

    /* The global IV is 96 bits, where the 64 most significant bits
     * are the SCI (if known) and the 32 least significant bits are
     * the 32 least significant bits of the PN. */
    pn = pntohu32(iv + MACSEC_SCI_LEN);
    memcpy(saved_iv, iv, IV_LEN);

    uint8_t *salt = sak_info->salt;
    memcpy(iv, salt, 4);

    /* We still need to XOR the upper 32 bits with the SSCI (depends
     * on the SCI) and XOR the middle 32 bits of the salt with the
     * upper 32 bits of the PN (also depends on the SCI.) */

    /* Note the first eight bytes of the saved IV are the SCI. */
    if (sci_known) {
        lpn = mka_get_lpn(sak_info, saved_iv, pinfo->num);
        /* The SSCI is technically a 32-bit quantity, but according to
         * how it is derived, cannot be larger then 8 bits (10.7.13,
         * also IEEE 802.1X-2020 9.10). */
        uint8_t ssci = GPOINTER_TO_UINT(wmem_map_lookup(sak_info->sci_map, saved_iv));
        if (ssci) {
            iv[3] ^= ssci;
        } else {
            // We know the SCI, but not what SSCI that corresponds to.
            ssci_known = false;
        }
    } else {
        lpn = mka_get_lpn(sak_info, NULL, pinfo->num);
    }

    /* Reconstruct the 64-bit PN.
     *
     * Each SecY has its own lowest acceptable PN for this SAK. The Key
     * Server observes all and issues a fresh SAK if any member of the CA
     * has an LPN greater than 0xC000 0000 for 32-bit PNs and
     * 0xC000 0000 0000 0000 for 64-bit PNs. (802.1X-2020 9.8)
     * If we do not know the SCI, we can't determine the appropriate
     * LPN with certainty, though all members should be fairly close,
     * so we get a generic number (passing in NULL for the sci above.)
     */
    pn_msb = lpn >> 32;
    if (lpn & 0x80000000 && !(pn & 0x80000000)) {
        pn_msb++;
    }
    phtonu32(&iv[4], pn_msb);

    for (unsigned i = 4; i < IV_LEN; ++i) {
        iv[i] ^= salt[i];
    }
    /* We really only need to return the MSB, but we use a pointer
     * anyway to distinguish "32 MSB are 0" from no proto data for
     * that key (i.e., not XPN). */
    uint64_t *xpn = wmem_new(pinfo->pool, uint64_t);
    *xpn = ((uint64_t)pn_msb << 32) | pn;
    p_add_proto_data(pinfo->pool, pinfo, proto_macsec, XPN_KEY, xpn);

    if (ssci_known) {
        result = attempt_packet_decode(ud->encrypted, sak_for_decode, sak_for_decode_len, ud->payload, ud->payload_len);
    } else {
        // We don't know the SSCI, but the SSCI range from 1 to the number of MI
        // Try them all.
        for (unsigned ssci = 1; ssci <= wmem_array_get_count(sak_info->mi_array); ++ssci) {
            // Again, assume SSCI can't be too large
            iv[3] = salt[3] ^ ssci;
            result = attempt_packet_decode(ud->encrypted, sak_for_decode, sak_for_decode_len, ud->payload, ud->payload_len);
            if (PROTO_CHECKSUM_E_GOOD == result) {
                break;
            }
            result = PROTO_CHECKSUM_E_BAD;
        }
    }

    memcpy(iv, saved_iv, MACSEC_XPN_SALT_LEN);

    return result;
}

static proto_checksum_enum_e
attempt_packet_decode_with_default_suite(struct decode_user_data *ud, bool sci_known) {
    proto_checksum_enum_e result = PROTO_CHECKSUM_E_UNVERIFIED;
    mka_sak_info_key_t *sak_info = ud->sak_info;

    if (sci_known) {
        result = attempt_packet_decode(ud->encrypted, sak_for_decode, sak_for_decode_len, ud->payload, ud->payload_len);
    } else {
        uint32_t ssci = GPOINTER_TO_UINT(wmem_map_find(sak_info->sci_map, saks_find_cb, ud));
        if (ssci) {
            result = PROTO_CHECKSUM_E_GOOD;
        } else if (wmem_map_size(sak_info->sci_map)) {
            // Otherwise, we didn't actually try any
            result = PROTO_CHECKSUM_E_BAD;
        }
    }

    return result;
}

/* Attempt to decode the packet using SAKs from the CKN table */
static int
attempt_packet_decode_with_saks(packet_info *pinfo, bool encrypted, unsigned an, const uint8_t *payload, unsigned payload_len, bool sci_known) {
    proto_checksum_enum_e result = PROTO_CHECKSUM_E_UNVERIFIED;
    int table_index = 0;

    /* Get the CKN table and its size. */
    const mka_ckn_info_t *ckn_table = get_mka_ckn_table();
    int ckn_table_count = get_mka_ckn_table_count();
    ws_debug("CKN table size: %u", ckn_table_count);

    ws_debug("AN: %u", an);

    struct decode_user_data ud = {NULL, payload, payload_len, encrypted, 1};

    /* Iterate through the CKN table and use each SAK for the given AN to attempt to decode the packet. */
    for (table_index = 0; table_index < ckn_table_count; table_index++) {
        const mka_ckn_info_t *info = &ckn_table[table_index];

        mka_sak_info_key_t *sak_info = mka_get_sak_info(info, an, pinfo->num);

        if ((!sak_info) || (sak_info->sak_len == 0)) continue;

        ud.ssci = 1; // 0 not legal
        ud.sak_info = sak_info;
        sak_for_decode = (uint8_t *)sak_info->sak;
        sak_for_decode_len = sak_info->sak_len;

        switch (sak_info->cipher_suite) {
        case MACSEC_GCM_AES_128:
        case MACSEC_GCM_AES_256:
            result = attempt_packet_decode_with_default_suite(&ud, sci_known);
            break;
        case MACSEC_GCM_AES_XPN_128:
        case MACSEC_GCM_AES_XPN_256:
            result = attempt_packet_decode_with_xpn(pinfo, &ud, sci_known);
            break;
        default:
            ws_debug("Unsupported Cipher Suite at CKN table index %u", table_index);
            continue;
        }

        if (PROTO_CHECKSUM_E_GOOD == result) {
            ws_debug("packet decoded with SAK[%u] at CKN table index %u", an, table_index);
            break;
        } else {
            ws_debug("failed to decode packet with SAK[%u] at CKN table index %u", an, table_index);
        }
    }

    /* On failure, clear the key used for decode. */
    if (PROTO_CHECKSUM_E_GOOD != result) {
        table_index = -1;
        sak_for_decode = NULL;
        sak_for_decode_len = 0;
    }

    return table_index;
}

/* Code to actually dissect the packets */
static int
dissect_macsec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {

    unsigned    sectag_length, data_length;
    unsigned    fcs_length = 0;
    unsigned    data_offset, icv_offset;
    uint8_t     tci_an_field, short_length;
    uint8_t     an = 0;

    proto_checksum_enum_e icv_check_success = PROTO_CHECKSUM_E_BAD;
    bool        encrypted = false;

    proto_item *macsec_item;
    proto_tree *macsec_tree = NULL;

    proto_item *sci_item;
    proto_tree *sci_tree = NULL;

    proto_item *verify_item;
    proto_tree *verify_tree = NULL;

    proto_item *ti, *pn_item;

    tvbuff_t   *next_tvb;

    tci_an_field = tvb_get_uint8(tvb, 0);

    /* "If the Encryption (E) bit is set and the Changed Text (C) bit is clear,
     * the frame is not processed by the SecY (10.6) but is reserved for use by
     * the KaY. Otherwise, the E bit is set if and only if confidentiality is
     * being provided and is clear if integrity only is being provided and the
     * C bit is clear if and only if the Secure Data is exactly the same as the
     * User Data and the ICV is 16 octets long.
     *
     * When the Default Cipher Suite (14.5) is used for integrity protection
     * only, the Secure Data is the unmodified User Data, and a 16 octet ICV
     * is used. Both the E bit and the C bit are therefore clear... Other
     * Cipher Suites may also integrity protect data without modifying it,
     * and use a 16 octet ICV... The E and C bits are also clear for such
     * Cipher Suites when integrity only is provided.
     *
     * Some cryptographic algorithms modify or add to the data even when
     * integrity only is being provided, or use an ICV that is not 16 octets
     * long. The C bit is never clear for such an algorithm, even if the E bit
     * is clear to indicate that confidentiality is not provided. Recovery of
     * the data from a MACsec frame with the E bit clear and the C bit set
     * requires knowledge of the Cipher Suite at a minimum. That information
     * is not provided in the MACsec frame."
     *
     * However, no such Cipher Suites are defined as of IEEE 802.1AE-2018
     * (14 Cipher Suites), so if the E bit is clear and the C bit set we
     * will not know how to decrypt. If the E bit is set and the C bit clear,
     * then we will not know how to decrypt either, as those are not processed
     * by the algorithms here either.
     */
    /* if the frame is an encrypted MACsec frame, remember that */
    if (((tci_an_field & TCI_E_MASK) == TCI_E_MASK) || ((tci_an_field & TCI_C_MASK) == TCI_C_MASK)) {
        ws_debug("MACsec encrypted frame");
        encrypted = true;
    }

    if ((tci_an_field & TCI_V_MASK) != 0) {  /* version must be zero */
        return 0;
    }

    if (tci_an_field & TCI_SC_MASK) {
        sectag_length = SECTAG_LEN_WITH_SC;  /* optional SCI present */
    } else {
        sectag_length = SECTAG_LEN_WITHOUT_SC;
    }

    icv_len = ICV_LEN;

    /* Check for length too short */
    /* XXX - Fix this so we can handle frames with captured length less
     * than reported length in a sensible way. */
    if (tvb_captured_length(tvb) <= (sectag_length + icv_len)) {
        return 0;
    }

    an = tci_an_field & AN_MASK;
    ws_debug("AN : %u", an);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MACSEC");
    col_set_str(pinfo->cinfo, COL_INFO, "MACsec frame");

    unsigned offset = 0;

    if (true == encrypted) {
        macsec_item = proto_tree_add_item(tree, proto_macsec, tvb, 0, sectag_length, ENC_NA);
    } else {
        /* Add the EtherType too since this is authentication only. */
        macsec_item = proto_tree_add_item(tree, proto_macsec, tvb, 0, sectag_length + ETHERTYPE_LEN, ENC_NA);
    }

    macsec_tree = proto_item_add_subtree(macsec_item, ett_macsec);

    static int * const flags[] = {
        &hf_macsec_TCI_V,
        &hf_macsec_TCI_ES,
        &hf_macsec_TCI_SC,
        &hf_macsec_TCI_SCB,
        &hf_macsec_TCI_E,
        &hf_macsec_TCI_C,
        NULL
    };

    ti = proto_tree_add_bitmask_with_flags(macsec_tree, tvb, 0,
            hf_macsec_TCI, ett_macsec_tci, flags, ENC_NA, BMT_NO_TFS);
    if ((tci_an_field & (TCI_E_MASK|TCI_C_MASK)) == TCI_E_MASK) {
        ws_debug("Frame not processed by SecY but reserved for use by KaY");
        expert_add_info(pinfo, ti, &ei_macsec_not_processed);
        icv_len = 0;
    } else if ((tci_an_field & (TCI_E_MASK|TCI_C_MASK)) == TCI_C_MASK) {
        ws_debug("Non standard cipher suite");
        expert_add_info(pinfo, ti, &ei_macsec_nonstandard_cipher);
        icv_len = 0;
    }
    /* XXX - Expert info for more illegal combinations of flags (ES/SC) */

    proto_tree_add_item(macsec_tree, hf_macsec_AN, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* short length field: 1..47 bytes, 0 means 48 bytes or more */
    proto_tree_add_item_ret_uint8(macsec_tree, hf_macsec_SL, tvb, offset, 1, ENC_NA, &short_length);
    /* XXX - expert info if > 47 */
    offset += 1;

    pn_item = proto_tree_add_item(macsec_tree, hf_macsec_PN, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (sectag_length == SECTAG_LEN_WITH_SC) {
        sci_item = proto_tree_add_item(macsec_tree, hf_macsec_SCI, tvb, offset, HWADDR_LEN + 2, ENC_NA);
        sci_tree = proto_item_add_subtree(sci_item, ett_macsec_sci);

        proto_tree_add_item(sci_tree, hf_macsec_SCI_system_identifier, tvb, offset, HWADDR_LEN, ENC_NA);
        offset += HWADDR_LEN;

        proto_tree_add_item(sci_tree, hf_macsec_SCI_port_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
    }

    /* Get the payload section */
    if (short_length != 0) {
        data_length = short_length;
        fcs_length = tvb_reported_length_remaining(tvb, sectag_length + short_length + icv_len);

        /*
         * We know the length, so set it here for the previous ethertype
         * dissector. This will allow us to calculate the FCS correctly.
         *
         * Note set_actual_length does nothing if the parameter is greater
         * than the current reported length, so we don't need to check that.
         */
        set_actual_length(tvb, short_length + sectag_length + icv_len);
    } else {
        /*
         * This assumes that no FCS is present after the ICV, which might not be true!
         * Workaround: turn Ethernet "Assume packets have FCS" = Always, when FCS present.
         * If there's another (non FCS) trailer afterwards, set Ethernet
         * "Fixed ethernet trailer length".
         *
         * TODO: Find better heuristic to detect presence of FCS / trailers.
         */
        data_length = tvb_reported_length_remaining(tvb, sectag_length + icv_len);
    }

    data_offset = sectag_length;
    icv_offset  = data_length + data_offset;

    next_tvb = tvb_new_subset_length(tvb, data_offset, data_length);

    /* Payload from the packet. */
    uint8_t *payload = NULL;
    unsigned payload_len = 0;

    // Fill in the first 14 bytes of the aad from the Ethernet header,
    // if we have it.
    memset(aad, 0, ETHHDR_LEN);
    aad_len = 0;

    /* For authentication and decryption, we can either save everything on
     * the first pass, or store the SAK info in a multimap with the packet
     * number, because new SAKs can be distributed for the same AN in a
     * long enough capture. Right now we do the latter, which uses somewhat
     * less memory at the cost of CPU. */
    if (icv_len != 0 && pinfo->dl_dst.type == AT_ETHER && pinfo->dl_src.type == AT_ETHER) {
        memcpy(aad, pinfo->dl_dst.data, HWADDR_LEN);
        memcpy((aad + HWADDR_LEN), pinfo->dl_src.data, HWADDR_LEN);

        uint16_t etype = ETHERTYPE_MACSEC;
        // Cisco at least allows the EtherType for MACsec to be changed from
        // the default to avoid conflicts with provider bridges.
        if (pinfo->match_uint >= ETHERNET_II_MIN_LEN &&
            pinfo->match_uint <= UINT16_MAX) {

            etype = pinfo->match_uint;
        }
        phtonu16(aad + (ETHHDR_LEN - ETHERTYPE_LEN), etype);

        if (true == encrypted) {
            /* Save the payload length.  Payload will be decrypted later. */
            payload_len = tvb_captured_length(next_tvb);

            if (payload_len <= MAX_PAYLOAD_LEN) {

                /* Fetch the payload into a buffer to pass for decode. */
                payload = tvb_memdup(pinfo->pool, next_tvb, 0, payload_len);

                /* For authenticated and encrypted data, the AAD consists of the header data and security tag. */
                tvb_memcpy(tvb, &aad[ETHHDR_LEN], 0, sectag_length);

                aad_len = (sectag_length + ETHHDR_LEN);
            }

        } else {
            /* The frame length for the AAD is the complete frame including ethernet header but without the ICV */
            unsigned frame_len = (ETHHDR_LEN + tvb_captured_length(tvb)) - icv_len;

            /* For authenticated-only data, the AAD is the entire frame minus the ICV.
                We have to build the AAD since the incoming TVB payload does not have the Ethernet header. */
            payload_len = frame_len - ETHHDR_LEN;

            if (payload_len <= MAX_PAYLOAD_LEN) {
                /* Copy the frame data up to the ICV. */
                tvb_memcpy(tvb, &aad[ETHHDR_LEN], 0, payload_len);

                aad_len = frame_len;
            }
        }
    }

    int table_index = -1;
    bool use_mka_table = false;

    if (aad_len != 0) {

        /* Build the IV. */
        /* XXX - The IV depends on the Cipher Suite. If this is one of the
         * GCM-AES-XPN Cipher Suites, then the IV is different. We need to
         * save that information from MKA. Using static SAKs (PSKs) with
         * those suites is not possible due to how the Salt and also SSCI
         * are calculated. */
        /* Copy the packet number. */
        tvb_memcpy(tvb, iv + MACSEC_SCI_LEN, 2, 4);

        /* 9.5 TAG Control Information
         * "If the ES bit is set, bit 6 (the SC bit) shall not be set...
         * If an SCI is explicitly encoded in the SecTAG, bit 6 (the SC bit)
         * of the TCI shall be set. The SC bit shall be clear if an SCI is
         * not present in the SecTAG."
         *
         * If both the ES and SC bit are set but the SCI in the SecTAG and
         * the source address are the same, it's at least consistent even if
         * it violates the spec. If they're different, it's inconsistent.
         */
        /* If there is an SCI, use it; if not, fill out the default */
        bool sci_known = true;
        if (SECTAG_LEN_WITH_SC == sectag_length) {
            tvb_memcpy(tvb, iv,     6,  HWADDR_LEN); // SI System identifier (source MAC)
            tvb_memcpy(tvb, iv + 6, 12, 2);          // PI Port identifier
        } else if (tci_an_field & TCI_ES_MASK) {
            /* With no SC, fetch the eth src address and set the PI to the Common Port identifier of 0x0001 */
            if (pinfo->dl_src.type == AT_ETHER) {
                memcpy(iv, pinfo->dl_src.data, HWADDR_LEN);
            } else {
                ws_warning("No Ethernet source address");
            }

            /* 9.5 TAG Control Information
             * "If the ES bit is set and the SCB is not set, the SCI comprises
             * a Port Identifier component of 00-01. If the SCB bit is set, the
             * Port Identifier has the reserved SCB value of 00-00."
             */
            iv[6] = 0x00;
            iv[7] = (tci_an_field & TCI_SCB_MASK) ? 0x00 : 0x01;
        } else {
            /* It's odd for both to be unset, but we've seen that with Arista
             * routers where there's a chassis MAC address different from the
             * MAC address used on a port, and the SCI used is one associated
             * with a different MAC address on that side of the point to point
             * connection.
             */
            sci_known = false;
        }

        /* Fetch the ICV. */
        tvb_memcpy(tvb, icv, icv_offset, icv_len);

        /* Attempt to authenticate/decode the packet using the stored keys in the PSK table. */
        if (sci_known) {
            table_index = attempt_packet_decode_with_psks(encrypted, payload, payload_len);
        }

        /* Upon failure to decode with PSKs, and when told to also try with the CKN table,
           attempt to authenticate/decode the packet using the stored SAKs in the CKN table. */
        if ((true == try_mka) && (0 > table_index)) {
            use_mka_table = true;
            ws_debug("also using MKA for decode");
            table_index = attempt_packet_decode_with_saks(pinfo, encrypted, an, payload, payload_len, sci_known);
        }

        if (0 <= table_index) {
            icv_check_success = PROTO_CHECKSUM_E_GOOD;
            uint64_t *xpn = p_get_proto_data(pinfo->pool, pinfo, proto_macsec, XPN_KEY);
            if (xpn) {
                proto_item *xpn_item = proto_tree_add_uint64(macsec_tree, hf_macsec_XPN, tvb, 0, 0, *xpn);
                proto_item_set_generated(xpn_item);
                proto_tree_move_item(macsec_tree, pn_item, xpn_item);
            }
        }
    }

    ethertype_data_t ethertype_data;

    /* If the data's ok, attempt to continue dissection. */
    if (encrypted == false) {
        /* The ethertype is the original from the unencrypted data. */
        proto_tree_add_item_ret_uint16(macsec_tree, hf_macsec_etype, tvb, data_offset, 2, ENC_BIG_ENDIAN, &ethertype_data.etype);

        /* also trim off the Ethertype */
        /* This won't overflow because otherwise there would be an exception
         * adding the Ethertype to the tree. */
        next_tvb = tvb_new_subset_length(tvb, data_offset + 2, data_length - 2);
    } else if (PROTO_CHECKSUM_E_GOOD == icv_check_success) {
        tvbuff_t *plain_tvb;

        plain_tvb = tvb_new_child_real_data(next_tvb, (uint8_t *)wmem_memdup(pinfo->pool, macsec_payload, macsec_payload_len),
                                            macsec_payload_len, macsec_payload_len);

        /* add the decrypted data as a data source for the next dissectors */
        add_new_data_source(pinfo, plain_tvb, "Decrypted Data");

        /* The ethertype is the one from the start of the decrypted data. */
        proto_tree_add_item_ret_uint16(macsec_tree, hf_macsec_etype, plain_tvb, 0, 2, ENC_BIG_ENDIAN, &ethertype_data.etype);

        /* also trim off the Ethertype */
        /* This won't overflow because otherwise there would be an exception
         * adding the Ethertype to the tree. */
        next_tvb = tvb_new_subset_length(plain_tvb, 2, macsec_payload_len - 2);

        /* show the decrypted data and original ethertype */
        /* XXX - Why include the ethertype here? Why not just the payload?
         * Should this be added to macsec_tree as well? */
        proto_tree_add_item(tree, hf_macsec_decrypted_data, plain_tvb, 0, macsec_payload_len, ENC_NA);
    }

    /* Add the ICV to the sectag subtree. */
    if (icv_len) {
        proto_tree_add_item(macsec_tree, hf_macsec_ICV, tvb, icv_offset, icv_len, ENC_NA);
        proto_tree_set_appendix(macsec_tree, tvb, icv_offset, icv_len);
    }

    verify_item = proto_tree_add_item(macsec_tree, hf_macsec_verify_info, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(verify_item);

    /* Add a subtree for verification information. */
    verify_tree = proto_item_add_subtree(verify_item, ett_macsec_verify);

    /* Add a flag indicating the frame is or is not verified. */
    verify_item = proto_tree_add_boolean(verify_tree, hf_macsec_ICV_check_success, tvb, 0, 0, PROTO_CHECKSUM_E_GOOD == icv_check_success);
    proto_item_set_generated(verify_item);

    if (PROTO_CHECKSUM_E_GOOD == icv_check_success) {
        DISSECTOR_ASSERT_CMPINT(table_index, >=, 0);
        if (true == use_mka_table) {
            const mka_ckn_info_t *ckn_table = get_mka_ckn_table();
            char *name = ckn_table[table_index].name;

            /* add the SAK and name identifier. */
            verify_item = proto_tree_add_bytes_with_length(verify_tree, hf_macsec_sak, tvb, 0, 0, sak_for_decode, sak_for_decode_len);
            proto_item_set_generated(verify_item);

            verify_item = proto_tree_add_string(verify_tree, hf_macsec_ckn_info, tvb, 0, 0, name);
            proto_item_set_generated(verify_item);

            /* add the table index for filtering. */
            verify_item = proto_tree_add_int(verify_tree, hf_macsec_ckn_table_index, tvb, 0, 0, table_index);
            proto_item_set_generated(verify_item);

        } else {
            const psk_config_t *psk_table = get_psk_config_table();
            char *name = psk_table[table_index].name;

            /* add the PSK and name identifier. */
            verify_item = proto_tree_add_bytes_with_length(verify_tree, hf_macsec_psk, tvb, 0, 0, sak_for_decode, sak_for_decode_len);
            proto_item_set_generated(verify_item);

            verify_item = proto_tree_add_string(verify_tree, hf_macsec_psk_info, tvb, 0, 0, name);
            proto_item_set_generated(verify_item);

            /* add the table index for filtering. */
            verify_item = proto_tree_add_int(verify_tree, hf_macsec_psk_table_index, tvb, 0, 0, table_index);
            proto_item_set_generated(verify_item);
        }
    }


    /* If the frame decoded, or was not encrypted, continue dissection */
    if ((PROTO_CHECKSUM_E_GOOD == icv_check_success) || (false == encrypted)) {
        /* help eth padding calculation by subtracting length of the sectag, ethertype, icv, and fcs */
        /* XXX - This might not be necessary after calling set_actual_length
         * the short data case above (which is most of the cases where there
         * is padding.) */
        int pkt_len_saved = pinfo->fd->pkt_len;

        pinfo->fd->pkt_len -= (sectag_length + 2 + icv_len + fcs_length);

        /* continue dissection */
        ethertype_data.payload_offset = 0; // 0 because Ethertype trimmed off above
        ethertype_data.fh_tree = macsec_tree;
        /* XXX: This could be another trailer, a FCS, or the Ethernet dissector
            * incorrectly detecting padding if we don't have short_length. */
        ethertype_data.trailer_id = hf_macsec_eth_padding;
        ethertype_data.fcs_len = 0;

        // XXX - Do we need TRY...EXCEPT to restore pinfo->fd->pkt_len ?
        call_dissector_with_data(ethertype_handle, next_tvb, pinfo, tree, &ethertype_data);

        /* restore original value */
        pinfo->fd->pkt_len = pkt_len_saved;
    } else {
        if (payload_len > MAX_PAYLOAD_LEN) {
            proto_tree_add_expert_remaining(macsec_tree, pinfo, &ei_macsec_payload_too_large, next_tvb, 0);
        }

        /* Show the encrypted, undissected data as data. */
        call_data_dissector(next_tvb, pinfo, tree);
    }

    if (PROTO_CHECKSUM_E_BAD == icv_check_success) {
        col_append_str(pinfo->cinfo, COL_INFO, " [UNVERIFIED]");
    }

    /* We called set_actual length if fcs_length !=0, so length is adjusted. */
    return tvb_captured_length(tvb);
}

void
proto_register_macsec(void)
{
    uat_t *psk_config_uat = NULL;

    module_t *module;
    expert_module_t *expert_macsec;

    static hf_register_info hf[] = {
        { &hf_macsec_TCI,
            { "TCI", "macsec.TCI", FT_UINT8, BASE_HEX,
              NULL, TCI_MASK, "TAG Control Information", HFILL }
        },
        { &hf_macsec_TCI_V,
            { "VER", "macsec.TCI.V", FT_UINT8, BASE_HEX,
              NULL, TCI_V_MASK, "Version", HFILL }
        },
        { &hf_macsec_TCI_ES,
            { "ES", "macsec.TCI.ES", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), TCI_ES_MASK, "End Station", HFILL }
        },
        { &hf_macsec_TCI_SC,
            { "SC", "macsec.TCI.SC", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), TCI_SC_MASK, "Secure Channel", HFILL }
        },
        { &hf_macsec_TCI_SCB,
            { "SCB", "macsec.TCI.SCB", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), TCI_SCB_MASK, "Single Copy Broadcast", HFILL }
        },
        { &hf_macsec_TCI_E,
            { "E", "macsec.TCI.E", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), TCI_E_MASK, "Encryption", HFILL }
        },
        { &hf_macsec_TCI_C,
            { "C", "macsec.TCI.C", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), TCI_C_MASK, "Changed Text", HFILL }
        },
        { &hf_macsec_AN,
            { "AN", "macsec.AN", FT_UINT8, BASE_HEX,
              NULL, AN_MASK, "Association Number", HFILL }
        },
        { &hf_macsec_SL,
            { "Short length", "macsec.SL", FT_UINT8, BASE_DEC,
              NULL, SL_MASK, NULL, HFILL }
        },
        { &hf_macsec_PN,
            { "Packet number", "macsec.PN", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_XPN,
            { "Extended packet number", "macsec.XPN", FT_UINT64, BASE_DEC,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_SCI,
            { "SCI", "macsec.SCI", FT_BYTES, BASE_NONE,
                NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_SCI_system_identifier,
            { "System Identifier", "macsec.SCI.system_identifier", FT_ETHER, BASE_NONE,
                NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_SCI_port_identifier,
            { "Port Identifier", "macsec.SCI.port_identifier", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_etype,
            { "Ethertype", "macsec.etype", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
              NULL, HFILL }
        },
        { &hf_macsec_eth_padding,
            { "Padding", "macsec.eth_padding", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_ICV,
            { "ICV", "macsec.ICV", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_verify_info,
            { "Verification Info", "macsec.verify_info", FT_NONE, BASE_NONE,
            NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_ICV_check_success,
            { "Frame Verification Successful", "macsec.verify_info.verified", FT_BOOLEAN, BASE_NONE,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_ckn_info,
            { "CAK Name Info", "macsec.verify_info.cak_name.info", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_ckn_table_index,
            { "CKN Table Index", "macsec.verify_info.cak_name.index", FT_INT16, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_sak,
            { "SAK", "macsec.verify_info.sak", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_psk_info,
            { "PSK Name Info", "macsec.verify_info.psk_name.info", FT_STRING, BASE_NONE,
            NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_psk_table_index,
            { "PSK Table Index", "macsec.verify_info.psk_name.index", FT_INT16, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_psk,
            { "PSK", "macsec.verify_info.psk", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_decrypted_data,
            { "Decrypted Data", "macsec.decrypted_data", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_macsec_not_processed, {
            "macsec.not_processed", PI_UNDECODED, PI_NOTE, "E bit set and C bit clear indicates frames not to be delivered to the Controlled Port (Reserved for use by the KaY)", EXPFILL }},
        { &ei_macsec_nonstandard_cipher, {
            "macsec.nonstandard_cipher", PI_UNDECODED, PI_NOTE, "E bit clear and C bit set indicates a non-standard cipher that modifies the data or uses a ICV other than 16 octets long even in integrity-only mode", EXPFILL }},
        { &ei_macsec_payload_too_large, {
            "macsec.payload_too_large", PI_UNDECODED, PI_NOTE, "Payload is larger than can currently be handled. Contact Wireshark developers if you want this supported", EXPFILL }},
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_macsec,
        &ett_macsec_tci,
        &ett_macsec_sci,
        &ett_macsec_verify
    };

    /* Register the protocol name and description */
    proto_macsec = proto_register_protocol("802.1AE Security Tag", "MACsec", "macsec");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_macsec, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_macsec = expert_register_protocol(proto_macsec);
    expert_register_field_array(expert_macsec, ei, array_length(ei));

    /* Register the dissector */
    macsec_handle = register_dissector("macsec", dissect_macsec, proto_macsec);

    /* Register the UAT to enter the pre-shared keys */
    module = prefs_register_protocol(proto_macsec, NULL);

    static uat_field_t psk_macsec_uat_fields[] = {
        UAT_FLD_BUFFER(psk_config_data, key, "Key", "Pre-Shared Key (AES-GCM-128 or AES-GCM-256) as byte array"),
        UAT_FLD_CSTRING(psk_config_data, name, "Info", "PSK info to display"),
        UAT_END_FIELDS
    };

    psk_config_uat = uat_new("Pre-Shared Key List",
        sizeof(psk_config_t),   /* record size           */
        "psk_config_data",      /* filename              */
        true,                   /* from profile          */
        &psk_config_data,       /* data_ptr              */
        &psk_config_data_count, /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION, /* but not fields        */
        NULL,                   /* help                  */
        copy_psk_config_cb,     /* copy callback         */
        update_psk_config,      /* update callback       */
        free_psk_config_cb,     /* free callback         */
        post_update_psk_config_cb, /* post update callback  */
        NULL,                   /* reset callback        */
        psk_macsec_uat_fields   /* UAT field definitions */
    );

    /* The PSK entry is obsolete in favor of the PSK table */
    prefs_register_obsolete_preference(module, "psk");

    /* XXX - "PSK" is a bad name here. They're all keys, and if pre-shared
     * they're PSKs; these are static pre-shared SAKs; the table in the MKA
     * dissector is of static pre-shared CAKs/CKNs used to derive SAKs.
     * 802.1X-2020 uses "PSK" extensively to refer to pre-shared CAKs.
     * 802.1AE-2018 uses "PSK" exactly once to refer to pre-shared SAKs,
     * referring to them as "inadvisabl[e]." */
    prefs_register_uat_preference(module, "psk_list", "Pre-Shared Key List",
        "A list of AES-GCM Pre-Shared Keys (PSKs) as HEX (16 or 32 bytes).", psk_config_uat);

    /* XXX - Why does this need to be a preference? We can only try SAKs
     * obtained from CKNs that were actually seen in EAPOL-MKA in the capture,
     * so there's no harm in always doing so. It would make more sense to
     * conversely have a preference for using the pre shared SAKs, where
     * we try them all. */
    prefs_register_bool_preference(module, "mka", "Also Use MKA For Decode",
                                     "Also attempt to use EAPOL-MKA Distributed SAKs to decode MACsec packets.",
                                     &try_mka);
}

void
proto_reg_handoff_macsec(void)
{
    dissector_add_uint("ethertype", ETHERTYPE_MACSEC, macsec_handle);

    ethertype_handle = find_dissector("ethertype");
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

