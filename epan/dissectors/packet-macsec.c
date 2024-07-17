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

#define AES_KEY_LEN           (16)
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
static int hf_macsec_ICV;
static int hf_macsec_ICV_check_success;
static int hf_macsec_decrypted_data;

/* Initialize the subtree pointers */
static int ett_macsec;
static int ett_macsec_tci;

/* Decrypting payload buffer */
static uint8_t macsec_payload[MAX_PAYLOAD_LEN];

/* AAD buffer */
static uint8_t aad[MAX_PAYLOAD_LEN];

static const char *psk = NULL;
static unsigned char *psk_bin = NULL;

/* convert a 0-terminated preference key_string that contains a hex number
 *  into its binary representation
 * e.g. key_string "abcd" will be converted into two bytes 0xab, 0xcd
 * return the number of binary bytes or -1 for error */
static int
pref_key_string_to_bin(const char *key_string, unsigned char **key_bin)
{
    int key_string_len;
    int i, j;
    char input[3];

    ws_return_val_if(key_bin == NULL, -1);

    if (NULL == key_string) {
        *key_bin = NULL;
        return -1;
    }

    key_string_len = (int)strlen(key_string);
    if (key_string_len != 2 * AES_KEY_LEN) {
        *key_bin = NULL;
        return (key_string_len / 2);
    }

    *key_bin = (unsigned char *)g_malloc(key_string_len / 2);

    input[2] = '\0';
    for (i = 0, j = 0; i < (key_string_len - 1); i += 2, j++) {
        input[0] = key_string[0 + i];
        input[1] = key_string[1 + i];

        /* attention, brackets are required */
        (*key_bin)[j] = (unsigned char)strtoul((const char *)&input, NULL, 16);
    }

    return (key_string_len / 2);
}

/* Code to actually dissect the packets */
static int dissect_macsec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    unsigned    sectag_length, data_length, short_length, icv_length;
    unsigned    fcs_length = 0;
    unsigned    data_offset, icv_offset;
    uint8_t     tci_an_field;

    int         icv_check_success = PROTO_CHECKSUM_E_BAD;
    bool        key_provided = false;
    bool        encrypted = false;
    unsigned    payload_len;
    unsigned    offset;

    gcry_cipher_hd_t handle = 0;

    proto_item *macsec_item;
    proto_tree *macsec_tree = NULL;

    tvbuff_t *next_tvb;

    /* Construct the 14-byte ethernet header (6-byte dst MAC, 6-byte src MAC, 2-byte ethernet type)(part of aad) */
    uint8_t header[ETHHDR_LEN] = {0};
    if (pinfo->dl_dst.data != NULL)
    {
        memcpy(header, pinfo->dl_dst.data, HWADDR_LEN);
    }
    if (pinfo->dl_src.data != NULL)
    {
        memcpy((header + HWADDR_LEN), pinfo->dl_src.data, HWADDR_LEN);
    }

    uint8_t e_type[ETHERTYPE_LEN] = {(uint8_t)(ETHERTYPE_MACSEC >> 8), (uint8_t)(ETHERTYPE_MACSEC & 0xff)};
    memcpy(header + (ETHHDR_LEN - ETHERTYPE_LEN), &e_type, ETHERTYPE_LEN);

    /* Parse the encryption key, and set the flag to indicate if the key is provided*/
    if (pref_key_string_to_bin(psk, &psk_bin) == AES_KEY_LEN) {
        key_provided = true;
    }

    tci_an_field = tvb_get_uint8(tvb, 0);

    /* if the frame is an encrypted MACsec frame, remember that */
    if (((tci_an_field & TCI_E_MASK) == TCI_E_MASK) || ((tci_an_field & TCI_C_MASK) == TCI_C_MASK)) {
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
        if (encrypted) {
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

    /* Try to decrypt/authenticate the data if a key is provided */
    if (key_provided) {
        /* Build the IV */
        uint8_t iv[IV_LEN] = {0};
        tvb_memcpy(tvb, iv,     6,  HWADDR_LEN); // SI System identifier (source MAC)
        tvb_memcpy(tvb, iv + 6, 12, 2);          // PI Port identifier
        tvb_memcpy(tvb, iv + 8, 2,  4);          // PN Packet number

        if (gcry_cipher_open(&handle, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_GCM, 0))
        {
            ws_warning("gcry_cipher_open fail");
            goto out;
        }

        if (gcry_cipher_setkey(handle, psk_bin, AES_KEY_LEN))
        {
            ws_warning("gcry_cipher_setkey fail");
            goto out;
        }

        if (gcry_cipher_setiv(handle, iv, sizeof(iv)))
        {
            ws_warning("gcry_cipher_setiv fail");
            goto out;
        }

        if (encrypted) {
            payload_len = tvb_captured_length(next_tvb);

            /* For authenticated and encrypted data, the AAD is always 28 bytes and consists of the
            header data and security tag. */
            const uint8_t *buf = tvb_get_ptr(tvb, 0, SECTAG_LEN_WITH_SC);

            memcpy(aad, header, ETHHDR_LEN);
            memcpy(aad + ETHHDR_LEN, buf, SECTAG_LEN_WITH_SC);

            /* Authenticate with the AAD. */
            if (gcry_cipher_authenticate(handle, aad, AAD_ENCRYPTED_LEN))
            {
                ws_warning("gcry_cipher_authenticate fail");
                goto out;
            }

            tvb_memcpy(next_tvb, macsec_payload, 0, payload_len);

            /* Attempt to decrypt into the local buffer. */
            if (gcry_cipher_decrypt(handle, macsec_payload, payload_len, NULL, 0))
            {
                ws_warning("gcry_cipher_decrypt fail");
                goto out;
            }

        } else {
            /* the frame length for the AAD is the complete frame including ethernet header but without the ICV */
            unsigned frame_len = (ETHHDR_LEN + tvb_captured_length(tvb)) - ICV_LEN;

            // For authenticated-only data, the aad is the frame minus the ICV
            // We have to build the AAD since the incoming TVB payload does not have the Ethernet header.
            payload_len = frame_len - ETHHDR_LEN;

            // Copy the header we built previously, then the frame data up to the ICV.
            memcpy(aad, header, ETHHDR_LEN);
            memcpy((aad + ETHHDR_LEN), tvb_get_ptr(tvb, 0, payload_len), payload_len);

            /* Authenticate with the AAD. */
            if (gcry_cipher_authenticate(handle, aad, frame_len))
            {
                ws_warning("gcry_cipher_authenticate fail");
                goto out;
            }
        }

        /* Fetch the ICV and use it to verify the decrypted data. */
        uint8_t icv[ICV_LEN] = {0};
        tvb_memcpy(tvb, icv, icv_offset, icv_length);
        if (gcry_cipher_checktag(handle, icv, sizeof(icv)))
        {
            ws_info("gcry_cipher_checktag fail");
            goto out;
        }

        /* Everything checks out! */
        icv_check_success = PROTO_CHECKSUM_E_GOOD;
    }

out:
    if (0 != handle) {
        gcry_cipher_close(handle);
    }
    // Show the original data.
    call_data_dissector(next_tvb, pinfo, tree);

    ethertype_data_t ethertype_data;

    /* default the next tv_buff to remove ICV */
    /* lets hand over a buffer without ICV to limit effect of wrong padding calculation */
    next_tvb = tvb_new_subset_length(tvb, data_offset + 2, data_length - 2);
    ethertype_data.etype = tvb_get_ntohs(tvb, data_offset);

    // If the data are ok, attempt to continue dissection.
    if (PROTO_CHECKSUM_E_GOOD == icv_check_success)
    {
        if (encrypted) {
            tvbuff_t *plain_tvb;

            plain_tvb = tvb_new_child_real_data(next_tvb, (uint8_t *)wmem_memdup(pinfo->pool, macsec_payload, payload_len),
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

    /* Set icv_check_success to the correct status */
    if (!key_provided) {
        icv_check_success = PROTO_CHECKSUM_E_UNVERIFIED;
    }

    /* If the frame was not verified correctly, append this string to the info line
     * after dissection completes.
     */
    if (PROTO_CHECKSUM_E_BAD == icv_check_success) {
        col_append_str(pinfo->cinfo, COL_INFO, " [Authentication fail]");
    }

    /* add a flag indicating the frame is or is not verified. */
    macsec_item = proto_tree_add_uint(macsec_tree, hf_macsec_ICV_check_success, tvb, 0, 0, icv_check_success);
    proto_item_set_generated(macsec_item);

    /* We called set_actual length if fcs_length !=0, so length is adjusted. */
    return tvb_captured_length(tvb);
}

void
proto_register_macsec(void)
{
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
            { "Ethertype", "macsec.etype", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_eth_padding,
            { "Padding", "macsec.eth_padding", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_ICV,
            { "ICV", "macsec.ICV", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_ICV_check_success,
            { "Frame authentication status", "macsec.auth_status", FT_UINT8, BASE_DEC,
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
    proto_macsec = proto_register_protocol("802.1AE Security tag", "MACsec", "macsec");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_macsec, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register the dissector */
    macsec_handle = register_dissector("macsec", dissect_macsec, proto_macsec);

    /* Register the text box to enter the pre-shared key */
    module = prefs_register_protocol(proto_macsec, NULL);
    prefs_register_string_preference(module, "psk", "MACsec Pre-Shared Key",
                                     "Pre-Shared AES-GCM-128 Key as a HEX string (16 bytes).",
                                     &psk);
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

