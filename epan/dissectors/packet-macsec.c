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

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/uat.h>
#include <epan/tfs.h>

#include "packet-mka.h"

#define WS_LOG_DOMAIN "MACsec"

#include <wireshark.h>
#include <wsutil/wsgcrypt.h>

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

#define MAX_PAYLOAD_LEN       (1500)


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
static int ett_macsec_verify;

/* Decrypting payload buffer */
static uint8_t macsec_payload[MAX_PAYLOAD_LEN];

/* AAD buffer */
static uint8_t aad[MAX_PAYLOAD_LEN];

/* if set, try to use the EAPOL-MKA CKN table as well */
static bool try_mka = false;

/* PSK key config data */
typedef struct _psk_info {
    unsigned char *key;
    unsigned  key_len;
} psk_info_t;

typedef struct _psk_config {
  psk_info_t keydata;
  unsigned char *name;
  unsigned name_len;
} psk_config_t;

static psk_config_t *psk_config_data = NULL;
static unsigned psk_config_data_count = 0;

UAT_BUFFER_CB_DEF(psk_config_data, key, psk_config_t, keydata.key, keydata.key_len)
UAT_LSTRING_CB_DEF(psk_config_data, name, psk_config_t, name, name_len)

static void *
copy_psk_config_cb(void *n, const void *o, size_t size _U_) {
    psk_config_t *new_rec = (psk_config_t *)n;
    const psk_config_t *old_rec = (const psk_config_t *)o;

    new_rec->keydata.key = (guchar *)g_memdup2(old_rec->keydata.key, old_rec->keydata.key_len);
    new_rec->keydata.key_len = old_rec->keydata.key_len;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->name_len = old_rec->name_len;

    return new_rec;
}

static bool
update_psk_config(void *r, char **err) {
    psk_config_t *rec = (psk_config_t *)r;

    ws_debug("update_psk_config\n");
    ws_debug("psk_config_data_count :%d\n", psk_config_data_count);

    // Validate the key input
    if ((PSK128_LEN != rec->keydata.key_len) && (PSK256_LEN != rec->keydata.key_len)) {
        *err = ws_strdup_printf("Only AES-128 (16 byte) or AES-256 (32 byte) keys are supported");
        return false;
    }

    if (0 == rec->name_len) {
        *err = ws_strdup_printf("Missing PSK ID!");
        return false;
    }

    return true;
}

static void
free_psk_config_cb(void *r) {
    psk_config_t *rec = (psk_config_t *)r;

    ws_debug("free_psk_config_cb\n");
    ws_debug("psk_config_data_count :%d\n", psk_config_data_count);

    g_free(rec->keydata.key);
    g_free(rec->name);
}

static void
post_update_psk_config_cb(void) {
    ws_debug("post_update_psk_config_cb\n");
    ws_debug("psk_config_data_count :%d\n", psk_config_data_count);

    if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
        uint8_t i;

        for (i = 0; i < psk_config_data_count; i++) {
            psk_config_t *c = &psk_config_data[i];
            unsigned char *key = c->keydata.key;
            ws_debug("id: %s\n", c->name);

            if (PSK256_LEN == c->keydata.key_len) {
                ws_debug("psk: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                                key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
                                key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
                                key[16], key[17], key[18], key[19], key[20], key[21], key[22], key[23],
                                key[24], key[25], key[26], key[27], key[28], key[29], key[30], key[31]);
            } else {
                ws_debug("psk: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
                        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]);
            }
        }
    }
}

static psk_config_t *
get_psk_config_table(void) {
    return psk_config_data;
}

static guint
get_psk_config_table_count(void) {
    return psk_config_data_count;
}

/* test if a SAK has all 0s (invalid )*/
static bool
macsec_is_valid_sak(const guint8 *sak) {
    /* memcmp of 0 against previous byte over the range of the SAK length is an easy test for all 0s */
    if ((0 == sak[0]) && (0 == memcmp(sak, sak + 1, (MKA_MAX_SAK_LEN - 1))) ) {
        return false;
    }

    return true;
}

/* Code to actually dissect the packets */
static int
dissect_macsec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    // Construct the 14-byte ethernet header (6-byte dst MAC, 6-byte src MAC, 2-byte ethernet type)(part of aad)
    // Maybe there's a better way to get the header directly from pinfo
    uint8_t header[ETHHDR_LEN] = {0};
    if (pinfo->dl_dst.data != NULL) {
        memcpy(header, pinfo->dl_dst.data, HWADDR_LEN);
    }
    if (pinfo->dl_src.data != NULL) {
        memcpy((header + HWADDR_LEN), pinfo->dl_src.data, HWADDR_LEN);
    }

    uint8_t e_type[ETHERTYPE_LEN] = {(uint8_t)(ETHERTYPE_MACSEC >> 8), (uint8_t)(ETHERTYPE_MACSEC & 0xff)};
    memcpy(header + (ETHHDR_LEN - ETHERTYPE_LEN), &e_type, ETHERTYPE_LEN);

    unsigned    sectag_length, data_length, short_length, icv_length;
    unsigned    fcs_length = 0;
    unsigned    data_offset, icv_offset;
    uint8_t     tci_an_field;
    uint8_t     an = 0;

    int         icv_check_success = PROTO_CHECKSUM_E_BAD;
    bool        encrypted = false;
    unsigned    payload_len;

    gcry_cipher_hd_t handle = 0;

    proto_item *macsec_item;
    proto_tree *macsec_tree = NULL;

    proto_item *verify_item;
    proto_tree *verify_tree = NULL;

    tvbuff_t   *next_tvb;

    tci_an_field = tvb_get_uint8(tvb, 0);
    an = tci_an_field & AN_MASK;
    ws_debug("an : %u", an);

    /* if the frame is an encrypted MACsec frame, remember that */
    if (((tci_an_field & TCI_E_MASK) == TCI_E_MASK) || ((tci_an_field & TCI_C_MASK) == TCI_C_MASK)) {
        ws_debug("MACsec encrypted frame");
        encrypted = true;
    }

    if ((tci_an_field & TCI_V_MASK) != 0) {  /* version must be zero */
        return 0;
    }

    icv_length = ICV_LEN;  /* Fixed size for version 0 */

    if (tci_an_field & TCI_SC_MASK) {
        sectag_length = SECTAG_LEN_WITH_SC;  /* optional SCI present */
    } else {
        sectag_length = SECTAG_LEN_WITHOUT_SC;
    }

    /* Check for length too short */
    if (tvb_captured_length(tvb) <= (sectag_length + icv_length)) {
        return 0;
    }

    /* short length field: 1..47 bytes, 0 means 48 bytes or more */
    short_length = (uint32_t)tvb_get_uint8(tvb, 1);

    /* Get the payload section */
    if (short_length != 0) {
        data_length = short_length;
        fcs_length = tvb_reported_length(tvb) - sectag_length - icv_length - short_length;

        /*
         * We know the length, so set it here for the previous ethertype
         * dissector. This will allow us to calculate the FCS correctly.
         */
        set_actual_length(tvb, short_length + sectag_length + icv_length);
    } else {
        /*
         * This assumes that no FCS is present after the ICV, which might not be true!
         * Workaround: turn Ethernet "Assume packets have FCS" = Always, when FCS present.
         * If there's another (non FCS) trailer afterwards, set Ethernet
         * "Fixed ethernet trailer length".
         *
         * TODO: Find better heuristic to detect presence of FCS / trailers.
         */
        data_length = tvb_reported_length(tvb) - sectag_length - icv_length;
    }

    data_offset = sectag_length;
    icv_offset  = data_length + data_offset;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MACSEC");
    col_set_str(pinfo->cinfo, COL_INFO, "MACsec frame");

    if (tree) {
        unsigned offset;

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

        proto_tree_add_bitmask_with_flags(macsec_tree, tvb, 0,
                hf_macsec_TCI, ett_macsec_tci, flags, ENC_NA, BMT_NO_TFS);

        offset = 0;
        proto_tree_add_item(macsec_tree, hf_macsec_AN, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(macsec_tree, hf_macsec_SL, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(macsec_tree, hf_macsec_PN, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (sectag_length == SECTAG_LEN_WITH_SC) {
            proto_tree_add_item(macsec_tree, hf_macsec_SCI_system_identifier, tvb, offset, HWADDR_LEN, ENC_NA);
            offset += HWADDR_LEN;

            proto_tree_add_item(macsec_tree, hf_macsec_SCI_port_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
    }

    next_tvb = tvb_new_subset_length(tvb, data_offset, data_length);

    /* Build the IV. */
    uint8_t iv[IV_LEN] = {0};

    /* fetch packet number */
    tvb_memcpy(tvb, iv + 8, 2,  4);

    /* If there is an SCI, use it; if not, fill out the default */
    if (SECTAG_LEN_WITH_SC == sectag_length) {
        tvb_memcpy(tvb, iv,     6,  HWADDR_LEN); // SI System identifier (source MAC)
        tvb_memcpy(tvb, iv + 6, 12, 2);          // PI Port identifier
    } else {
        /* With no SC, fetch the eth src address and set the PI to the Common Port identifier of 0x0001 */
        if (pinfo->dl_src.data != NULL) {
            memcpy(iv, pinfo->dl_src.data, HWADDR_LEN);
        } else {
            ws_warning("No Ethernet source address");
        }

        iv[6] = 0x00;
        iv[7] = 0x01;
    }

    ws_debug("iv: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11]);

    int total_count = 0;
    bool use_mka_table = false;

    const uint8_t *sak = NULL;
    const uint8_t *name = NULL;
    unsigned name_len = 0;
    unsigned key_len = 0;
    int table_index = 0;

    /* Get the PSK table and its size. */
    const psk_config_t *psk_table = get_psk_config_table();
    int psk_table_count = get_psk_config_table_count();
    ws_debug("PSK table size: %u", psk_table_count);

    if ((true == try_mka) && (0 == psk_table_count)) {
        /* If the PSK table is empty, and EAPOL-MKA usage is requested, start there. */
        ws_debug("psk table is empty, using mka table");
        use_mka_table = true;
    } else {
        ws_debug("starting with psk table");
    }

    total_count = psk_table_count;

    /* If EAPOL-MKA usage is requested, fetch its table and size and add to the total entries to check. */
    const mka_ckn_info_t *ckn_table = NULL;
    if (true == try_mka) {
        int ckn_table_count = 0;

        ws_debug("also using MKA for decode");

        ckn_table = get_mka_ckn_table();
        ckn_table_count = get_mka_ckn_table_count();

        ws_debug("CKN table size: %u", ckn_table_count);
        total_count += ckn_table_count;
    }

    /* Cannot decode if there are no keys. */
    if (0 == total_count) {
        ws_debug("tables are empty");
        goto skip_decode;
    }

    if (gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0)) {
        ws_warning("failed to open cipher context");
    } else {
        /* Start at the first index of the first table to use. */
        table_index = 0;

        /* Iterate through the tables until the packet authenticates successfully or we run out of entries. */
        for (int tc = 1; tc <= total_count; tc++) {
            if (true == use_mka_table) {
                /* If using the CKN table, fetch the SAK at this CKN table index. */
                const mka_ckn_info_key_t *key = &ckn_table[table_index].key;

                sak = key->saks[an];
                name = ckn_table[table_index].name;
                name_len = ckn_table[table_index].name_len;
                key_len = ckn_table[table_index].cak_len;
            } else {
                /* If using the PSK table, fetch the PSK at this PSK table index. */
                const psk_info_t *info = &psk_table[table_index].keydata;

                sak = info->key;
                name = psk_table[table_index].name;
                name_len = psk_table[table_index].name_len;
                key_len = psk_table[table_index].keydata.key_len;
            }

            if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
                if (PSK256_LEN == key_len) {
                    ws_debug("key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                                    sak[0], sak[1], sak[2], sak[3], sak[4], sak[5], sak[6], sak[7],
                                    sak[8], sak[9], sak[10], sak[11], sak[12], sak[13], sak[14], sak[15],
                                    sak[16], sak[17], sak[18], sak[19], sak[20], sak[21], sak[22], sak[23],
                                    sak[24], sak[25], sak[26], sak[27], sak[28], sak[29], sak[30], sak[31]);
                } else {
                    ws_debug("key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                            sak[0], sak[1], sak[2], sak[3], sak[4], sak[5], sak[6], sak[7],
                            sak[8], sak[9], sak[10], sak[11], sak[12], sak[13], sak[14], sak[15]);
                }
            }

            if (false == macsec_is_valid_sak(sak)) {
                ws_debug("skipping invalid sak");
                goto next_index;
            }

            if (gcry_cipher_setkey(handle, sak, key_len)) {
                ws_warning("failed to set cipher key");
                goto next_index;
            }

            if (gcry_cipher_setiv(handle, iv, sizeof(iv))) {
                ws_warning("failed to set cipher IV");
                goto next_index;
            }

            /* For authenticated and encrypted data, we try to decrypt the data if a key is supplied. */
            if (true == encrypted) {
                payload_len = tvb_captured_length(next_tvb);

                /* For authenticated and encrypted data, the AAD consists of the header data and security tag. */
                const uint8_t *buf = tvb_get_ptr(tvb, 0, sectag_length);

                memcpy(aad, header, ETHHDR_LEN);
                memcpy(aad + ETHHDR_LEN, buf, sectag_length);

                /* Authenticate with the AAD. */
                if (gcry_cipher_authenticate(handle, aad, (ETHHDR_LEN + sectag_length))) {
                    ws_debug("failed to authenticate with key at index %u", table_index);
                    goto next_index;
                }

                tvb_memcpy(next_tvb, macsec_payload, 0, payload_len);

                /* Attempt to decrypt into the local buffer. */
                if (gcry_cipher_decrypt(handle, macsec_payload, payload_len, NULL, 0)) {
                    ws_debug("failed to decrypt with key at index %u", table_index);
                    goto next_index;
                }

            } else {
                /* The frame length for the AAD is the complete frame including ethernet header but without the ICV */
                unsigned frame_len = (ETHHDR_LEN + tvb_captured_length(tvb)) - ICV_LEN;

                /* For authenticated-only data, the AAD is the entire frame minus the ICV.
                   We have to build the AAD since the incoming TVB payload does not have the Ethernet header. */
                payload_len = frame_len - ETHHDR_LEN;

                /* Copy the header we built previously, then the frame data up to the ICV. */
                memcpy(aad, header, ETHHDR_LEN);
                memcpy((aad + ETHHDR_LEN), tvb_get_ptr(tvb, 0, payload_len), payload_len);

                /* Authenticate with the AAD. */
                if (gcry_cipher_authenticate(handle, aad, frame_len)) {
                    ws_debug("failed to authenticate with key at index %u", table_index);
                    goto next_index;
                }
            }

            /* Fetch the ICV and use it to verify the decrypted data. */
            uint8_t icv[ICV_LEN] = {0};
            tvb_memcpy(tvb, icv, icv_offset, icv_length);
            if (gcry_cipher_checktag(handle, icv, sizeof(icv))) {
                ws_debug("failed to verify ICV with key at index %u", table_index);
                goto next_index;
            }

            /* Everything checks out! */
            icv_check_success = PROTO_CHECKSUM_E_GOOD;
            ws_debug("ICV verified with key at index %u", table_index);
            break;

next_index:
            if (tc == psk_table_count) {
                /* Switch to the MKA table. */
                use_mka_table = true;
                table_index = 0;
                ws_debug("using mka table");
            } else {
                /* Move to the next table index. */
                table_index++;
            }
        }
    }

    if (0 != handle) {
        gcry_cipher_close(handle);
    }

skip_decode:
    verify_item = proto_tree_add_item(macsec_tree, hf_macsec_verify_info, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(verify_item);

    /* add a subtree for verification information. */
    verify_tree = proto_item_add_subtree(verify_item, ett_macsec_verify);

    /* add a flag indicating the frame is or is not verified. */
    verify_item = proto_tree_add_boolean(verify_tree, hf_macsec_ICV_check_success, tvb, 0, 0, icv_check_success);
    proto_item_set_generated(verify_item);

    if (PROTO_CHECKSUM_E_GOOD == icv_check_success) {
        unsigned char *namestr = g_malloc(name_len + 1);
        memcpy(namestr, name, name_len);
        namestr[name_len] = 0;

        if (true == use_mka_table) {
            /* add the SAK and name identifier. */
            verify_item = proto_tree_add_bytes_with_length(verify_tree, hf_macsec_sak, tvb, 0, 0, sak, key_len);
            proto_item_set_generated(verify_item);

            verify_item = proto_tree_add_string(verify_tree, hf_macsec_ckn_info, tvb, 0, 0, namestr);
            proto_item_set_generated(verify_item);

            /* add the table index for filtering. */
            verify_item = proto_tree_add_int(verify_tree, hf_macsec_ckn_table_index, tvb, 0, 0, table_index);
            proto_item_set_generated(verify_item);

        } else {
            /* add the PSK and name identifier. */
            verify_item = proto_tree_add_bytes_with_length(verify_tree, hf_macsec_psk, tvb, 0, 0, sak, key_len);
            proto_item_set_generated(verify_item);

            verify_item = proto_tree_add_string(verify_tree, hf_macsec_psk_info, tvb, 0, 0, namestr);
            proto_item_set_generated(verify_item);

            /* add the table index for filtering. */
            verify_item = proto_tree_add_int(verify_tree, hf_macsec_psk_table_index, tvb, 0, 0, table_index);
            proto_item_set_generated(verify_item);
        }

        g_free(namestr);
    }

    // Show the original data.
    call_data_dissector(next_tvb, pinfo, tree);

    ethertype_data_t ethertype_data;

    /* default the next tv_buff to remove ICV */
    /* lets hand over a buffer without ICV to limit effect of wrong padding calculation */
    next_tvb = tvb_new_subset_length(tvb, data_offset + 2, data_length - 2);
    ethertype_data.etype = tvb_get_ntohs(tvb, data_offset);

    /* If the data's ok, attempt to continue dissection. */
    if (PROTO_CHECKSUM_E_GOOD == icv_check_success) {
        if (true == encrypted) {
            tvbuff_t *plain_tvb;

            plain_tvb = tvb_new_child_real_data(next_tvb, (guint8 *)wmem_memdup(pinfo->pool, macsec_payload, payload_len),
                                                payload_len, payload_len);
            ethertype_data.etype = tvb_get_ntohs(plain_tvb, 0);

            /* lets hand over a buffer without ICV to limit effect of wrong padding calculation */
            next_tvb = tvb_new_subset_length(plain_tvb, 2, payload_len - 2);

            /* show the decrypted data and original ethertype */
            proto_tree_add_item(tree, hf_macsec_decrypted_data, plain_tvb, 0, payload_len, ENC_NA);

            /* add the decrypted data as a data source for the next dissectors */
            add_new_data_source(pinfo, plain_tvb, "Decrypted Data");

            /* The ethertype is the one from the start of the decrypted data. */
            proto_tree_add_item(tree, hf_macsec_etype, plain_tvb, 0, 2, ENC_BIG_ENDIAN);

        } else {
            /* lets hand over a buffer without ICV to limit effect of wrong padding calculation */
            next_tvb = tvb_new_subset_length(tvb, data_offset + 2, data_length - 2);

            /* The ethertype is the original from the unencrypted data. */
            proto_tree_add_item(tree, hf_macsec_etype, tvb, data_offset, 2, ENC_BIG_ENDIAN);
        }
    }

    /* add the ICV to the sectag subtree */
    proto_tree_add_item(macsec_tree, hf_macsec_ICV, tvb, icv_offset, icv_length, ENC_NA);
    proto_tree_set_appendix(macsec_tree, tvb, icv_offset, icv_length);

    /* If the frame decoded, or was not encrypted, continue dissection */
    if ((PROTO_CHECKSUM_E_GOOD == icv_check_success) || (false == encrypted)) {
        /* help eth padding calculation by subtracting length of the sectag, ethertype, icv, and fcs */
        int pkt_len_saved = pinfo->fd->pkt_len;

        pinfo->fd->pkt_len -= (sectag_length + 2 + icv_length + fcs_length);

        /* continue dissection */
        ethertype_data.payload_offset = 0;
        ethertype_data.fh_tree = macsec_tree;
        /* XXX: This could be another trailer, a FCS, or the Ethernet dissector
            * incorrectly detecting padding if we don't have short_length. */
        ethertype_data.trailer_id = hf_macsec_eth_padding;
        ethertype_data.fcs_len = 0;

        call_dissector_with_data(ethertype_handle, next_tvb, pinfo, tree, &ethertype_data);

        /* restore original value */
        pinfo->fd->pkt_len = pkt_len_saved;
    }

    /* If the frame was not verified correctly, append this string to the info line
     * after dissection completes.
     */
    if (PROTO_CHECKSUM_E_GOOD != icv_check_success) {
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
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_PN,
            { "Packet number", "macsec.PN", FT_UINT32, BASE_DEC,
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
            { "Frame Verified", "macsec.verify_info.verified", FT_BOOLEAN, BASE_NONE,
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

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_macsec,
        &ett_macsec_tci
    };

    /* Register the protocol name and description */
    proto_macsec = proto_register_protocol("802.1AE Security Tag", "MACsec", "macsec");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_macsec, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the dissector */
    macsec_handle = register_dissector("macsec", dissect_macsec, proto_macsec);

    /* Register the UAT to enter the pre-shared keys */
    module = prefs_register_protocol(proto_macsec, NULL);

    static uat_field_t psk_macsec_uat_fields[] = {
        UAT_FLD_BUFFER(psk_config_data, key, "Key", "Pre-Shared Key (AES-GCM-128 only) as byte array"),
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

    prefs_register_uat_preference(module, "psk_list", "Pre-Shared Key List",
        "A list of AES-GCM Pre-Shared Keys (PSKs) as HEX (16 or 32 bytes).", psk_config_uat);

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

