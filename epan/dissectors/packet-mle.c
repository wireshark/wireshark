/* packet-mle.c
 * Routines for MLE packet dissection
 *
 * Colin O'Flynn <coflynn@newae.com>
 *
 * The entire security section of this is lifted from the IEEE 802.15.4
 * dissectory, as this is done the same way. Should eventually make the
 * two use some common functions or something. But that section is:
 * By Owen Kirby <osk@exegin.com>
 * Copyright 2007 Exegin Technologies Limited
 *
 * Thread parts added by Robert Cragie <robert.cragie@arm.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <math.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/wmem/wmem.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include "packet-ieee802154.h"
#include "packet-mle.h"

#define MLE_32768_TO_NSEC_FACTOR ((double)30517.578125)

/* Forward declarations */
void proto_register_mle(void);
void proto_reg_handoff_mle(void);

static int proto_mle = -1;
static int proto_ieee802154 = -1; /* cache 802.15.4 protocol ID */

/*  Registered fields for Auxiliary Security Header */
static int hf_mle_security_suite = -1;
static int hf_mle_mic = -1;

static int hf_mle_command = -1;
static int hf_mle_tlv = -1;
static int hf_mle_tlv_type = -1;
static int hf_mle_tlv_length = -1;
static int hf_mle_tlv_source_addr = -1;
static int hf_mle_tlv_mode_device_type = -1;
static int hf_mle_tlv_mode_idle_rx = -1;
static int hf_mle_tlv_mode_sec_data_req = -1;
static int hf_mle_tlv_mode_nwk_data = -1;
static int hf_mle_tlv_timeout = -1;
static int hf_mle_tlv_challenge = -1;
static int hf_mle_tlv_response = -1;
static int hf_mle_tlv_ll_frm_cntr = -1;
static int hf_mle_tlv_lqi_c = -1;
static int hf_mle_tlv_lqi_size = -1;
static int hf_mle_tlv_neighbor = -1;
static int hf_mle_tlv_neighbor_flagI = -1;
static int hf_mle_tlv_neighbor_flagO = -1;
static int hf_mle_tlv_neighbor_flagP = -1;
static int hf_mle_tlv_neighbor_idr = -1;
static int hf_mle_tlv_neighbor_addr = -1;
static int hf_mle_tlv_network_param_id = -1;
static int hf_mle_tlv_network_delay = -1;
static int hf_mle_tlv_network_channel = -1;
static int hf_mle_tlv_network_pan_id = -1;
static int hf_mle_tlv_network_pmt_join = -1;
static int hf_mle_tlv_network_bcn_payload = -1;
static int hf_mle_tlv_network_unknown = -1;
static int hf_mle_tlv_mle_frm_cntr = -1;
static int hf_mle_tlv_unknown = -1;
static int hf_mle_tlv_route64_id_seq = -1;
static int hf_mle_tlv_route64_id_mask = -1;
static int hf_mle_tlv_route64_entry = -1;
static int hf_mle_tlv_route64_nbr_out = -1;
static int hf_mle_tlv_route64_nbr_in = -1;
static int hf_mle_tlv_route64_cost = -1;
#if 0
static int hf_mle_tlv_route64_unknown = -1;
#endif
static int hf_mle_tlv_addr16 = -1;
static int hf_mle_tlv_leader_data_partition_id = -1;
static int hf_mle_tlv_leader_data_weighting = -1;
static int hf_mle_tlv_leader_data_version = -1;
static int hf_mle_tlv_leader_data_stable_version = -1;
static int hf_mle_tlv_leader_data_router_id = -1;
#if 0
static int hf_mle_tlv_network_data = -1;
#endif
static int hf_mle_tlv_scan_mask_r = -1;
static int hf_mle_tlv_scan_mask_e = -1;
static int hf_mle_tlv_conn_flags = -1;
static int hf_mle_tlv_conn_flags_pp = -1;
static int hf_mle_tlv_conn_lq3 = -1;
static int hf_mle_tlv_conn_lq2 = -1;
static int hf_mle_tlv_conn_lq1 = -1;
static int hf_mle_tlv_conn_leader_cost = -1;
static int hf_mle_tlv_conn_id_seq = -1;
static int hf_mle_tlv_conn_active_rtrs = -1;
static int hf_mle_tlv_conn_sed_buf_size = -1;
static int hf_mle_tlv_conn_sed_dgram_cnt = -1;
static int hf_mle_tlv_link_margin = -1;
static int hf_mle_tlv_status = -1;
static int hf_mle_tlv_version = -1;
static int hf_mle_tlv_addr_reg_entry = -1;
static int hf_mle_tlv_addr_reg_iid_type = -1;
static int hf_mle_tlv_addr_reg_cid = -1;
static int hf_mle_tlv_addr_reg_iid = -1;
static int hf_mle_tlv_addr_reg_ipv6 = -1;
#if 0
static int hf_mle_tlv_hold_time = -1;
#endif
static int hf_mle_tlv_channel_page = -1; /* v1.1-draft-2 */
static int hf_mle_tlv_channel = -1; /* v1.1-draft-2 */
static int hf_mle_tlv_pan_id = -1; /* v1.1-draft-2 */
static int hf_mle_tlv_active_tstamp = -1; /* SPEC-472 */
static int hf_mle_tlv_pending_tstamp = -1; /* SPEC-472 */
#if 0
static int hf_mle_tlv_active_op_dataset = -1; /* SPEC-472 */
static int hf_mle_tlv_pending_op_dataset = -1; /* SPEC-472 */
#endif

static gint ett_mle = -1;
static gint ett_mle_tlv = -1;
static gint ett_mle_neighbor = -1;
static gint ett_mle_router = -1;
static gint ett_mle_addr_reg = -1;
static gint ett_mle_conn_flg = -1;
static gint ett_mle_thread_nwd = -1;
static gint ett_mle_auxiliary_security = -1;
static gint ett_mle_aux_sec_control = -1;
static gint ett_mle_aux_sec_key_id = -1;

static expert_field ei_mle_cbc_mac_failed = EI_INIT;
static expert_field ei_mle_packet_too_small = EI_INIT;
static expert_field ei_mle_no_key = EI_INIT;
static expert_field ei_mle_decrypt_failed = EI_INIT;
static expert_field ei_mle_mic_check_failed = EI_INIT;
static expert_field ei_mle_tlv_length_failed = EI_INIT;
static expert_field ei_mle_len_size_mismatch = EI_INIT;

static dissector_handle_t mle_handle;
static dissector_handle_t thread_nwd_handle;
static dissector_handle_t thread_mc_handle;

#define UDP_PORT_MLE_RANGE    "19788" /* IANA registered */

/* boolean value set if the MIC must be ok before payload is dissected */
static gboolean mle_mic_ok = FALSE;

static wmem_tree_t* mle_key_hash_handlers;

static const value_string mle_sec_suite_names[] = {
    { 0,   "802.15.4 Security" },
    { 255, "No Security" },
    { 0, NULL }
};

static const value_string mle_status_tlv_enums[] = {
    { 1, "Error" },
    { 2, "Duplicate Address Detected" },
    { 0, NULL }
};

static const value_string mle_conn_tlv_flags_pp_enums[] = {
    { 1, "High" },
    { 0, "Medium" },
    { -1, "Low" },
    { 0, NULL }
};

#define MLE_CMD_REQUEST               0
#define MLE_CMD_ACCEPT                1
#define MLE_CMD_ACCEPTREQ             2
#define MLE_CMD_REJECT                3
#define MLE_CMD_ADVERTISE             4
#define MLE_CMD_UPDATE                5
#define MLE_CMD_UPDATE_REQUEST        6
#define MLE_CMD_DATA_REQUEST          7
#define MLE_CMD_DATA_RESPONSE         8
#define MLE_CMD_PARENT_REQUEST        9
#define MLE_CMD_PARENT_RESPONSE       10
#define MLE_CMD_CHILD_ID_REQUEST      11
#define MLE_CMD_CHILD_ID_RESPONSE     12
#define MLE_CMD_CHILD_UPDATE_REQUEST  13
#define MLE_CMD_CHILD_UPDATE_RESPONSE 14
#define MLE_CMD_ANNOUNCE              15
#define MLE_CMD_DISCOVERY_REQUEST     16
#define MLE_CMD_DISCOVERY_RESPONSE    17

static const value_string mle_command_vals[] = {
    { MLE_CMD_REQUEST,                  "Link Request" },
    { MLE_CMD_ACCEPT,                   "Link Accept" },
    { MLE_CMD_ACCEPTREQ,                "Link Accept and Request" },
    { MLE_CMD_REJECT,                   "Link Reject" },
    { MLE_CMD_ADVERTISE,                "Advertisement" },
    { MLE_CMD_UPDATE,                   "Update" },
    { MLE_CMD_UPDATE_REQUEST,           "Update Request" },
    { MLE_CMD_DATA_REQUEST,             "Data Request" },
    { MLE_CMD_DATA_RESPONSE,            "Data Response" },
    { MLE_CMD_PARENT_REQUEST,           "Parent Request" },
    { MLE_CMD_PARENT_RESPONSE,          "Parent Response" },
    { MLE_CMD_CHILD_ID_REQUEST,         "Child ID Request" },
    { MLE_CMD_CHILD_ID_RESPONSE,        "Child ID Response" },
    { MLE_CMD_CHILD_UPDATE_REQUEST,     "Child Update Request" },
    { MLE_CMD_CHILD_UPDATE_RESPONSE,    "Child Update Response" },
    { MLE_CMD_ANNOUNCE,                 "Announce" },
    { MLE_CMD_DISCOVERY_REQUEST,        "Discovery Request" },
    { MLE_CMD_DISCOVERY_RESPONSE,       "Discovery Response" },
    { 0, NULL}
};

#define MLE_TLV_SOURCE_ADDRESS              0
#define MLE_TLV_MODE                        1  /* Modified in Ch04_Mesh Link Establishment */
#define MLE_TLV_TIMEOUT                     2
#define MLE_TLV_CHALLENGE                   3
#define MLE_TLV_RESPONSE                    4
#define MLE_TLV_LINK_LAYER_FRAME_COUNTER    5
#define MLE_TLV_LINK_QUALITY                6
#define MLE_TLV_NETWORK_PARAMETER           7
#define MLE_TLV_MLE_FRAME_COUNTER           8
#define MLE_TLV_ROUTE64                     9  /* Defined in Ch05_Network Layer v1.1-rc1 */
#define MLE_TLV_ADDRESS16                   10 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_LEADER_DATA                 11 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_NETWORK_DATA                12 /* Defined in Ch05_Network Layer v1.1-rc1 */
#define MLE_TLV_TLV_REQUEST                 13 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_SCAN_MASK                   14 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_CONNECTIVITY                15 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_LINK_MARGIN                 16 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_STATUS                      17 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_VERSION                     18 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_ADDRESS_REGISTRATION        19 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_CHANNEL                     20 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_PAN_ID                      21 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_ACTIVE_TSTAMP               22 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_PENDING_TSTAMP              23 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_ACTIVE_OP_DATASET           24 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_PENDING_OP_DATASET          25 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */
#define MLE_TLV_THREAD_DISCOVERY            26 /* Defined in Ch04_Mesh Link Establishment v1.1-rc1 */

static const value_string mle_tlv_vals[] = {
    { MLE_TLV_SOURCE_ADDRESS,           "Source Address" },
    { MLE_TLV_MODE,                     "Mode" },
    { MLE_TLV_TIMEOUT,                  "Timeout" },
    { MLE_TLV_CHALLENGE,                "Challenge" },
    { MLE_TLV_RESPONSE,                 "Response" },
    { MLE_TLV_LINK_LAYER_FRAME_COUNTER, "Link Layer Frame Counter"},
    { MLE_TLV_LINK_QUALITY,             "Link Quality"},
    { MLE_TLV_NETWORK_PARAMETER,        "Network Parameter"},
    { MLE_TLV_MLE_FRAME_COUNTER,        "MLE Frame Counter"},
    { MLE_TLV_ROUTE64,                  "Route64"},
    { MLE_TLV_ADDRESS16,                "Address16"},
    { MLE_TLV_LEADER_DATA,              "Leader Data"},
    { MLE_TLV_NETWORK_DATA,             "Network Data"},
    { MLE_TLV_TLV_REQUEST,              "TLV Request"},
    { MLE_TLV_SCAN_MASK,                "Scan Mask"},
    { MLE_TLV_CONNECTIVITY,             "Connectivity"},
    { MLE_TLV_LINK_MARGIN,              "Link Margin"},
    { MLE_TLV_STATUS,                   "Status"},
    { MLE_TLV_VERSION,                  "Version"},
    { MLE_TLV_ADDRESS_REGISTRATION,     "Address Registration"},
    { MLE_TLV_CHANNEL,                  "Channel"},
    { MLE_TLV_PAN_ID,                   "PAN ID"},
    { MLE_TLV_ACTIVE_TSTAMP,            "Active Timestamp"},
    { MLE_TLV_PENDING_TSTAMP,           "Pending Timestamp"},
    { MLE_TLV_ACTIVE_OP_DATASET,        "Active Operational Dataset"},
    { MLE_TLV_PENDING_OP_DATASET,       "Pending Operational Dataset"},
    { MLE_TLV_THREAD_DISCOVERY,         "Thread Discovery"},
    { 0, NULL}
};

#define LQI_FLAGS_C         0x80
#define LQI_FLAGS_SIZE      0x0F

#define NEIGHBOR_FLAG_I     0x80
#define NEIGHBOR_FLAG_O     0x40
#define NEIGHBOR_FLAG_P     0x20

#define NETWORK_PARAM_ID_CHANNEL        0
#define NETWORK_PARAM_ID_PAN_ID         1
#define NETWORK_PARAM_ID_PERMIT_JOIN    2
#define NETWORK_PARAM_ID_BCN_PAYLOAD    3

static const value_string mle_tlv_nwk_param_vals[] = {
    { NETWORK_PARAM_ID_CHANNEL,     "Channel" },
    { NETWORK_PARAM_ID_PAN_ID,      "PAN ID" },
    { NETWORK_PARAM_ID_PERMIT_JOIN, "Permit Join" },
    { NETWORK_PARAM_ID_BCN_PAYLOAD, "Beacon Payload" },
    { 0, NULL}
};

static const true_false_string mle_tlv_mode_device_type = {
    "FFD",
    "RFD"
};
static const true_false_string mle_tlv_mode_nwk_data = {
    "Full",
    "Stable"
};
static const true_false_string mle_tlv_addr_reg_iid_type = {
    "Compressed",
    "Full"
};

#define ROUTE_TBL_OUT_MASK          0xC0
#define ROUTE_TBL_IN_MASK           0x30
#define ROUTE_TBL_COST_MASK         0x0F

#define SCAN_MASK_R_MASK            0x80
#define SCAN_MASK_D_MASK            0x40

#define CONN_MASK_FLAGS_PP_MASK     0xC0

#define ADDR_REG_MASK_IID_TYPE_MASK 0x80
#define ADDR_REG_MASK_CID_MASK      0x0F

#define MLE_CMD_CINFO_SEC_DATA_REQ  0x04
#define MLE_CMD_CINFO_NWK_DATA      0x01

/*FUNCTION:------------------------------------------------------
 *  NAME
 *      dissect_mle_decrypt
 *  DESCRIPTION
 *      MLE dissector.
 *  PARAMETERS
 *      tvbuff_t *tvb               - IEEE 802.15.4 packet.
 *      packet_info * pinfo         - Packet info structure.
 *      guint offset                - Offset where the ciphertext 'c' starts.
 *      ieee802154_packet *packet   - IEEE 802.15.4 packet information.
 *      ws_decrypt_status *status   - status of decryption returned through here on failure.
 *  RETURNS
 *      tvbuff_t *                  - Decrypted payload.
 *---------------------------------------------------------------
 */
static tvbuff_t *
dissect_mle_decrypt(tvbuff_t * tvb,
                    guint offset,
                    packet_info * pinfo,
                    ieee802154_packet * packet,
                    ieee802154_decrypt_info_t* decrypt_info)
{
    tvbuff_t *          ptext_tvb;
    gboolean            have_mic = FALSE;
    guint64             srcAddr;
    unsigned char       tmp[16];
    guint               M;
    gint                captured_len;
    gint                reported_len;

    *decrypt_info->rx_mic_length = 0;
    memset(decrypt_info->rx_mic, 0, 16);

    /* Get the captured and on-the-wire length of the payload. */
    if (packet->security_level > 0) {
        M = IEEE802154_MIC_LENGTH(packet->security_level);
    }
    else {
        M = 0;
    }

    reported_len = tvb_reported_length_remaining(tvb, offset) - M;
    if (reported_len < 0) {
        *decrypt_info->status = DECRYPT_PACKET_TOO_SMALL;
        return NULL;
    }
    /* Check if the payload is truncated.  */
    if (tvb_bytes_exist(tvb, offset, reported_len)) {
        captured_len = reported_len;
    }
    else {
        captured_len = tvb_captured_length_remaining(tvb, offset);
    }

    if (packet->security_level > 0) {
        /* Check if the MIC is present in the captured data. */
        have_mic = tvb_bytes_exist(tvb, offset + reported_len, M);
        if (have_mic) {
            tvb_memcpy(tvb, decrypt_info->rx_mic, offset + reported_len, M);
        }
    }

    /*=====================================================
     * Key Lookup - Need to find the appropriate key.
     *=====================================================
     */
    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        /* The source EUI-64 is included in the headers. */
        srcAddr = packet->src64; /* GUINT64_SWAP_LE_BE(packet->src64); */
    }
    else {
        /* Lookup failed.  */
        *decrypt_info->status = DECRYPT_PACKET_NO_EXT_SRC_ADDR;
        return NULL;
    }

    /*=====================================================
     * CCM* - CTR mode payload encryption
     *=====================================================
     */
    /* Create the CCM* initial block for decryption (Adata=0, M=0, counter=0). */
    ccm_init_block(tmp, FALSE, 0, srcAddr, packet->frame_counter, packet->security_level, 0, NULL);

    /* Decrypt the ciphertext, and place the plaintext in a new tvb. */
    if (IEEE802154_IS_ENCRYPTED(packet->security_level) && captured_len) {
        gchar *text;

        /*
         * Make a copy of the ciphertext in heap memory.
         *
         * We will decrypt the message in-place and then use the buffer as the
         * real data for the new tvb.
         */
        text = (gchar *)tvb_memdup(pinfo->pool, tvb, offset, captured_len);

        /* Perform CTR-mode transformation. Try both the likely key and the alternate key */
        if (!ccm_ctr_encrypt(decrypt_info->key, tmp, decrypt_info->rx_mic, text, captured_len)) {
            *decrypt_info->status = DECRYPT_PACKET_DECRYPT_FAILED;
            return NULL;
        }

        /* Create a tvbuff for the plaintext. */
        ptext_tvb = tvb_new_real_data((const guint8 *)text, captured_len, reported_len);
        tvb_set_child_real_data_tvbuff(tvb, ptext_tvb);
        add_new_data_source(pinfo, ptext_tvb, "Decrypted MLE payload");
        *decrypt_info->status = DECRYPT_PACKET_SUCCEEDED;
    }
    /* There is no ciphertext. Wrap the plaintext in a new tvb. */
    else {
        /* Decrypt the MIC (if present). */
        if (have_mic) {
            if (!ccm_ctr_encrypt(decrypt_info->key, tmp, decrypt_info->rx_mic, NULL, 0)) {
                *decrypt_info->status = DECRYPT_PACKET_DECRYPT_FAILED;
                return NULL;
            }
        }

        /* Create a tvbuff for the plaintext. This might result in a zero-length tvbuff. */
        ptext_tvb = tvb_new_subset_length_caplen(tvb, offset, captured_len, reported_len);
        *decrypt_info->status = DECRYPT_PACKET_SUCCEEDED;
    }

    /*=====================================================
     * CCM* - CBC-mode message authentication
     *=====================================================
     */
    /* We can only verify the message if the MIC wasn't truncated. */
    if (have_mic) {
        unsigned char           dec_mic[16];
        guint                   l_m = captured_len;
        guint                   l_a;
        guint8                  d_a[256];

        DISSECTOR_ASSERT(pinfo->src.len == 16);
        DISSECTOR_ASSERT(pinfo->dst.len == 16);
        memcpy(d_a, pinfo->src.data, pinfo->src.len);
        memcpy(d_a+16, pinfo->dst.data, pinfo->dst.len);

        tvb_memcpy(tvb, d_a+32, decrypt_info->aux_offset, decrypt_info->aux_length);
        l_a = 32 + decrypt_info->aux_length;

        /* Adjust the lengths of the plantext and additional data if unencrypted. */
        if (!IEEE802154_IS_ENCRYPTED(packet->security_level)) {
            l_a += l_m;
            l_m = 0;
        }

        /* Create the CCM* initial block for authentication (Adata!=0, M!=0, counter=l(m)). */
        ccm_init_block(tmp, TRUE, M, srcAddr, packet->frame_counter, packet->security_level, l_m, NULL);

        /* Compute CBC-MAC authentication tag. */
        /*
         * And yes, despite the warning in tvbuff.h, I think tvb_get_ptr is the
         * right function here since either A) the payload wasn't encrypted, in
         * which case l_m is zero, or B) the payload was encrypted, and the tvb
         * already points to contiguous memory, since we just allocated it in
         * decryption phase.
         */
        if (!ccm_cbc_mac(decrypt_info->key, tmp, d_a, l_a, tvb_get_ptr(ptext_tvb, 0, l_m), l_m, dec_mic)) {
            *decrypt_info->status = DECRYPT_PACKET_MIC_CHECK_FAILED;
        }
        /* Compare the received MIC with the one we generated. */
        else if (memcmp(decrypt_info->rx_mic, dec_mic, M) != 0) {
            *decrypt_info->status = DECRYPT_PACKET_MIC_CHECK_FAILED;
        }
    }

    *decrypt_info->rx_mic_length = M;

    /* Done! */
    return ptext_tvb;
} /* dissect_mle_decrypt */

void register_mle_key_hash_handler(guint hash_identifier, ieee802154_set_key_func key_func)
{
    /* Ensure no duplication */
    DISSECTOR_ASSERT(wmem_tree_lookup32(mle_key_hash_handlers, hash_identifier) == NULL);

    wmem_tree_insert32(mle_key_hash_handlers, hash_identifier, (void*)key_func);
}

/* Set MLE key function. */
static guint ieee802154_set_mle_key(ieee802154_packet *packet, unsigned char *key, unsigned char *alt_key, ieee802154_key_t *uat_key)
{
    ieee802154_set_key_func func = (ieee802154_set_key_func)wmem_tree_lookup32(mle_key_hash_handlers, uat_key->hash_type);

    if (func != NULL)
        return func(packet, key, alt_key, uat_key);

    /* Right now, KEY_HASH_NONE and KEY_HASH_ZIP are not registered because they
        work with this "default" behavior */
    if (packet->key_index == uat_key->key_index)
    {
        memcpy(key, uat_key->key, IEEE802154_CIPHER_SIZE);
        return 1;
    }

    return 0;
}

static int
dissect_mle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    tvbuff_t                *volatile payload_tvb = NULL;
    proto_tree              *volatile mle_tree = NULL;
    proto_item              *volatile proto_root = NULL;

    guint                   offset = 0;
    guint                   aux_header_offset = 0;
    ieee802154_decrypt_status status;

    proto_item              *ti;
    proto_item              *mic_item = NULL;
    proto_tree              *header_tree = NULL;
    guint8                  security_suite;
    guint                   aux_length = 0;
    ieee802154_packet       *packet;
    ieee802154_packet       *original_packet;
    ieee802154_decrypt_info_t decrypt_info;
    ieee802154_hints_t      *ieee_hints;
    gboolean                mic_ok=TRUE;

    unsigned char           rx_mic[16];
    unsigned int            rx_mic_len = 0;

    guint8                  cmd;
    guint8                  tlv_type, tlv_len;
    proto_tree              *tlv_tree;

    ieee_hints = (ieee802154_hints_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_ieee802154, 0);
    if (ieee_hints == NULL) {
        /* For now, MLE only supported with IEEE802.15.4 as an underlying layer */
        return 0;
    }
    original_packet = (ieee802154_packet *)ieee_hints->packet;

    packet = wmem_new0(wmem_packet_scope(), ieee802154_packet);

    /* Copy IEEE 802.15.4 Source Address */
    packet->src_addr_mode = original_packet->src_addr_mode;
    if (packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) {
        packet->src64 = original_packet->src64;
    } else {
        packet->src16 = original_packet->src16;
    }

    /* Copy IEEE 802.15.4 Source PAN ID */
    packet->src_pan = original_packet->src_pan;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MLE");
    col_clear(pinfo->cinfo,   COL_INFO);

    /* Create the protocol tree. */
    proto_root = proto_tree_add_item(tree, proto_mle, tvb, 0, tvb_reported_length(tvb), ENC_NA);
    mle_tree = proto_item_add_subtree(proto_root, ett_mle);

    /* Parse the security suite field. */
    /* Security Suite Field */
    security_suite = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(mle_tree, hf_mle_security_suite, tvb, offset, 1, ENC_NA);
    offset++;

    aux_header_offset = offset;

    /* Security material present if security suite = 0 */
    if (security_suite == 0) {
        dissect_ieee802154_aux_sec_header_and_key(tvb, pinfo, mle_tree, packet, &offset);
        aux_length = offset-aux_header_offset;
    } else {
        packet->security_level = SECURITY_LEVEL_NONE;
    }

    decrypt_info.key_number = 0;

    /* Add additional fields for security level > SECURITY_LEVEL_NONE */
    if (packet->security_level > SECURITY_LEVEL_NONE) {

        /* Pass to decryption process */
        decrypt_info.rx_mic = rx_mic;
        decrypt_info.rx_mic_length = &rx_mic_len;
        decrypt_info.aux_offset = aux_header_offset;
        decrypt_info.aux_length = aux_length;
        decrypt_info.status = &status;
        decrypt_info.key = NULL; /* payload function will fill that in */

        payload_tvb = decrypt_ieee802154_payload(tvb, offset, pinfo, header_tree, packet, &decrypt_info,
                                     ieee802154_set_mle_key, dissect_mle_decrypt);
        if (status == DECRYPT_PACKET_MIC_CHECK_FAILED)
            expert_add_info(pinfo, proto_root, &ei_mle_cbc_mac_failed);

        /* MIC */
        if (rx_mic_len) {
            mic_item = proto_tree_add_bytes(header_tree, hf_mle_mic, tvb, 0, rx_mic_len, rx_mic);
            proto_item_set_generated(mic_item);
        }
    } else {
        status = DECRYPT_NOT_ENCRYPTED;
    }

    /* Get the unencrypted data if decryption failed.  */
    if (!payload_tvb) {
        /* Deal with possible truncation and the FCS field at the end. */
        gint reported_len = tvb_reported_length_remaining(tvb, offset);
        gint captured_len = tvb_captured_length_remaining(tvb, offset);
        if (reported_len < captured_len) captured_len = reported_len;
        payload_tvb = tvb_new_subset_length_caplen(tvb, offset, captured_len, reported_len);
    }

    /* Display the reason for failure, and abort if the error was fatal. */
    switch (status) {
    case DECRYPT_PACKET_SUCCEEDED:
        /* No problem. */
        proto_item_append_text(mic_item, " [correct (key no. %d)]", decrypt_info.key_number);
        break;

    case DECRYPT_PACKET_TOO_SMALL:
        expert_add_info(pinfo, proto_root, &ei_mle_packet_too_small);
        call_data_dissector(payload_tvb, pinfo, tree);
        return tvb_captured_length(tvb);

    case DECRYPT_PACKET_NO_KEY:
        expert_add_info(pinfo, proto_root, &ei_mle_no_key);
        call_data_dissector(payload_tvb, pinfo, tree);
        return tvb_captured_length(tvb);

    case DECRYPT_PACKET_DECRYPT_FAILED:
        expert_add_info(pinfo, proto_root, &ei_mle_decrypt_failed);
        call_data_dissector(payload_tvb, pinfo, tree);
        return tvb_captured_length(tvb);

    case DECRYPT_PACKET_MIC_CHECK_FAILED:
        expert_add_info(pinfo, proto_root, &ei_mle_mic_check_failed);
        proto_item_append_text(mic_item, " [incorrect]");
        /*
         * Abort only if the payload was encrypted, in which case we
         * probably didn't decrypt the packet right (eg: wrong key).
         */
        if (IEEE802154_IS_ENCRYPTED(packet->security_level)) {
            mic_ok = FALSE;
        }
        break;
    case DECRYPT_NOT_ENCRYPTED:
    default:
        break;
    }
    /* This can cause a lot of problems so remove it by default */
    if (!mic_ok && mle_mic_ok) {
        call_data_dissector(payload_tvb, pinfo, tree);
        col_add_fstr(pinfo->cinfo, COL_INFO, "MIC Failed");
        return tvb_captured_length(tvb);
    }

    /***** NEW CODE HERE ****/
    /* If we're good, carry on and display the MLE payload */
    offset = 0;

    /* MLE Command */
    proto_tree_add_item(mle_tree, hf_mle_command, payload_tvb, offset, 1, ENC_BIG_ENDIAN);

    cmd = tvb_get_guint8(payload_tvb, offset);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(cmd, mle_command_vals, "Unknown (%x)"));

    offset++;

    /* MLE TLVs */
    while (tvb_offset_exists(payload_tvb, offset)) {

        /* Get the length ahead of time to pass to next function so we can highlight
           proper amount of bytes */
        tlv_len = tvb_get_guint8(payload_tvb, offset+1);

        ti = proto_tree_add_item(mle_tree, hf_mle_tlv, payload_tvb, offset, tlv_len+2, ENC_NA);
        tlv_tree = proto_item_add_subtree(ti, ett_mle_tlv);

        /* Type */
        proto_tree_add_item(tlv_tree, hf_mle_tlv_type, payload_tvb, offset, 1, ENC_NA);
        tlv_type = tvb_get_guint8(payload_tvb, offset);
        offset++;

        /* Add value name to value root label */
        proto_item_append_text(ti, " (%s", val_to_str(tlv_type, mle_tlv_vals, "Unknown (%d)"));

        /* Length */
        proto_tree_add_item(tlv_tree, hf_mle_tlv_length, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        switch(tlv_type){
            case MLE_TLV_SOURCE_ADDRESS:
                {
                    gboolean haveShortTLV = FALSE;
                    guint16 shortAddr = 0;

                    if (!((tlv_len == 2) || (tlv_len == 8))) {
                        /* TLV Length must be 2 or 8 */
                        expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                        offset += tlv_len;
                    } else {
                        if (tlv_len == 2) {
                            haveShortTLV = TRUE;
                            shortAddr = tvb_get_ntohs(payload_tvb, offset);
                        }

                        proto_tree_add_item(tlv_tree, hf_mle_tlv_source_addr, payload_tvb, offset, tlv_len, ENC_NA);
                        proto_item_append_text(ti, " = ");
                        while (tlv_len) {
                            guint8 addr;
                            addr = tvb_get_guint8(payload_tvb, offset);
                            proto_item_append_text(ti, "%02x", addr);
                            if (--tlv_len) {
                                proto_item_append_text(ti, ":");
                            }
                            offset++;
                        }
                        if ((original_packet->src_addr_mode == IEEE802154_FCF_ADDR_EXT) && haveShortTLV) {
                            /* Source TLV: use this to update src/long mapping */
                            ieee802154_addr_update(&ieee802154_map, shortAddr, original_packet->src_pan, original_packet->src64, pinfo->current_proto, pinfo->fd->num);
                        }
                    }
                    proto_item_append_text(ti, ")");
                }
                break;

            case MLE_TLV_MODE:
                if (tlv_len == 1) {
                    guint8 capability;

                    capability = tvb_get_guint8(payload_tvb, offset);
                    proto_item_append_text(ti, " = %02x)", capability);
                    /* Get and display capability info. (blatantly plagiarised from packet-ieee802154.c */
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_mode_nwk_data, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_mode_device_type, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_mode_sec_data_req, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_mode_idle_rx, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                }
                else {
                    /* TLV Length must be 1 */
                    expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                }
                offset += tlv_len;
                break;

            case MLE_TLV_TIMEOUT:
                if (tlv_len != 4) {
                    /* TLV Length must be 4 */
                    expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                } else {
                    guint32 to_data = 0;
                    proto_tree_add_item_ret_uint(tlv_tree, hf_mle_tlv_timeout, payload_tvb, offset, 4, ENC_BIG_ENDIAN, &to_data);
                    proto_item_append_text(ti, " = %d", (guint16)to_data);
                }
                proto_item_append_text(ti, ")");
                offset += tlv_len;
                break;

            case MLE_TLV_CHALLENGE:
                proto_tree_add_item(tlv_tree, hf_mle_tlv_challenge, payload_tvb, offset, tlv_len, ENC_NA);
                proto_item_append_text(ti, " = %s)", tvb_bytes_to_str(wmem_packet_scope(), payload_tvb, offset, tlv_len));
                offset += tlv_len;
                break;

            case MLE_TLV_RESPONSE:
                proto_tree_add_item(tlv_tree, hf_mle_tlv_response, payload_tvb, offset, tlv_len, ENC_NA);
                proto_item_append_text(ti, " = %s)", tvb_bytes_to_str(wmem_packet_scope(), payload_tvb, offset, tlv_len));
                offset += tlv_len;
                break;

            case MLE_TLV_LINK_LAYER_FRAME_COUNTER:
            case MLE_TLV_MLE_FRAME_COUNTER:
                if (tlv_len != 4) {
                    /* TLV Length must be 4 */
                    expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                } else {
                    guint32 cntr;

                    if (tlv_type == MLE_TLV_LINK_LAYER_FRAME_COUNTER) {
                        proto_tree_add_item_ret_uint(tlv_tree, hf_mle_tlv_ll_frm_cntr, payload_tvb, offset, tlv_len, ENC_BIG_ENDIAN, &cntr);
                    } else {
                        proto_tree_add_item_ret_uint(tlv_tree, hf_mle_tlv_mle_frm_cntr, payload_tvb, offset, tlv_len, ENC_BIG_ENDIAN, &cntr);
                    }
                    proto_item_append_text(ti, " = %u", cntr);
                }
                proto_item_append_text(ti, ")");
                offset += tlv_len;
                break;

            case MLE_TLV_LINK_QUALITY:
                {
                    guint numNeighbors;
                    guint8 size = tvb_get_guint8(payload_tvb, offset) & LQI_FLAGS_SIZE;
                    proto_tree *neig_tree;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_lqi_c, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_lqi_size, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;

                    if ((tlv_len - 1) % (size + 3)) {
                        expert_add_info(pinfo, proto_root, &ei_mle_len_size_mismatch);
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                        numNeighbors = 0;
                    } else {
                        numNeighbors = (tlv_len - 1) / (size + 3);
                    }

                    if (numNeighbors == 0) {
                        proto_item_append_text(ti, ")");
                    } else if (numNeighbors == 1) {
                        proto_item_append_text(ti, ": 1 Neighbor)");
                    } else {
                        proto_item_append_text(ti, ": %d Neighbors)", numNeighbors);
                    }

                    /* Add subtrees */

                    //Size is off by 1
                    size++;

                    while (numNeighbors) {
                        ti = proto_tree_add_item(tlv_tree, hf_mle_tlv_neighbor, payload_tvb, offset, size+2, ENC_NA);
                        neig_tree = proto_item_add_subtree(ti, ett_mle_neighbor);

                        proto_tree_add_item(neig_tree, hf_mle_tlv_neighbor_flagI, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(neig_tree, hf_mle_tlv_neighbor_flagO, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                        proto_tree_add_item(neig_tree, hf_mle_tlv_neighbor_flagP, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;

                        proto_tree_add_item(neig_tree, hf_mle_tlv_neighbor_idr, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;

                        proto_tree_add_item(neig_tree, hf_mle_tlv_neighbor_addr, payload_tvb, offset,size, ENC_NA);
                        offset += size;

                        numNeighbors--;
                    }
                }
                break;

            case MLE_TLV_NETWORK_PARAMETER:
                {
                    guint8 param_id = tvb_get_guint8(payload_tvb, offset);

                    proto_item_append_text(ti, " = %s)", val_to_str(param_id, mle_tlv_nwk_param_vals, "Unknown (%d)"));

                    proto_tree_add_item(tlv_tree, hf_mle_tlv_network_param_id, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_network_delay, payload_tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;

                    switch (param_id) {
                    case NETWORK_PARAM_ID_CHANNEL:
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_network_channel, payload_tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        break;
                    case NETWORK_PARAM_ID_PAN_ID:
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_network_pan_id, payload_tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        break;
                    case NETWORK_PARAM_ID_PERMIT_JOIN:
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_network_pmt_join, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                        break;
                    case NETWORK_PARAM_ID_BCN_PAYLOAD:
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_network_bcn_payload, payload_tvb, offset, tlv_len-5, ENC_NA);
                        offset += tlv_len-5;
                        break;
                    default:
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_network_unknown, payload_tvb, offset, tlv_len-5, ENC_NA);
                        offset += tlv_len-5;
                        break;
                    }
                }
                break;

            case MLE_TLV_ROUTE64:
                {
                    proto_tree *rtr_tree;
                    guint i, j;
                    guint8 count;
                    guint64 id_mask, test_mask;

                    proto_item_append_text(ti, ")");
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_route64_id_seq, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;

                    /* Count number of table entries */
                    count = 0;
                    for (i = 0; i < 8; i++) { /* TODO magic - number of routers/8 */
                        guint8 id_mask_octet = tvb_get_guint8(payload_tvb, offset + i);
                        for (j = 0; j < 8; j++) {
                            if (id_mask_octet & (1 << j)) {
                                count++;
                            }
                        }
                    }

                    /*
                     * | | | | | | | | | | |1|1|1|1|1|1|...|6|
                     * |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|...|3|
                     * ---------------------------------------
                     * |1|0|1|1|1|0|0|0|1|1|0|0|0|1|0|1|...
                     *
                     * is sent as 0xb8, 0xc5
                     * and represents table entry for routers 0, 2, 3, 4, 8, 9, 13, 15...
                     */
                    /* Get the ID mask as a 64-bit number (BE) */
                    id_mask = tvb_get_ntoh64(payload_tvb, offset);

                    /* Just show the string of octets - best representation for a bit mask */
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_route64_id_mask, payload_tvb, offset, 8, ENC_NA);
                    offset += 8;

                    if (count != (tlv_len - 9))
                    {
                        expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                        offset += (tlv_len - 9);
                    } else {
                        /* Add subtrees */
                        for (i = 0; i < count; i++) {
                            /* Find first bit set */
                            for (j = 0, test_mask = (G_GUINT64_CONSTANT(1) << 63); test_mask != 1; test_mask >>= 1, j++) {
                                if (test_mask & id_mask) {
                                    id_mask &= ~test_mask;
                                    break;
                                }
                            }
                            ti = proto_tree_add_item(tlv_tree, hf_mle_tlv_route64_entry, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_item_append_text(ti, " (%d)", j);
                            rtr_tree = proto_item_add_subtree(ti, ett_mle_router);

                            proto_tree_add_item(rtr_tree, hf_mle_tlv_route64_nbr_out, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(rtr_tree, hf_mle_tlv_route64_nbr_in, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(rtr_tree, hf_mle_tlv_route64_cost, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset++;
                        }
                    }
                }
                break;

            case MLE_TLV_ADDRESS16:
                if (tlv_len != 2) {
                    /* TLV Length must be 2 */
                    expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                } else {
                    guint16 addr16 = tvb_get_ntohs(payload_tvb, offset);
                    proto_item_append_text(ti, " = ");
                    {
                        guint8 a16_len = 2; /* Fix it at 2 */
                        guint stroffset = offset;

                        while (a16_len) {
                            guint8 a16_data;
                            a16_data = tvb_get_guint8(payload_tvb, stroffset);
                            proto_item_append_text(ti, "%02x", a16_data);
                            if (--a16_len) {
                                proto_item_append_text(ti, ":");
                            }
                            stroffset++;
                        }
                    }
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_addr16, payload_tvb, offset, 2, ENC_NA);
                    if (original_packet->dst_addr_mode == IEEE802154_FCF_ADDR_EXT) {
                        /* Allocated Address16 TLV: use this to update dst/long mapping */
                        ieee802154_addr_update(&ieee802154_map, addr16, original_packet->dst_pan, original_packet->dst64, pinfo->current_proto, pinfo->fd->num);
                    }
                }
                proto_item_append_text(ti, ")");
                offset += tlv_len;
                break;

            case MLE_TLV_LEADER_DATA:
                proto_item_append_text(ti, ")");
                if (tlv_len != 8) {
                    /* TLV Length must be 8 */
                    expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                    offset += tlv_len;
                } else {
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_leader_data_partition_id, payload_tvb, offset, 4, ENC_BIG_ENDIAN);
                    offset += 4;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_leader_data_weighting, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_leader_data_version, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_leader_data_stable_version, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_leader_data_router_id, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                }
                break;

            case MLE_TLV_NETWORK_DATA:
                {
                    tvbuff_t *sub_tvb;
                    proto_item_append_text(ti, ")");
                    if (tlv_len > 0) {
                        sub_tvb = tvb_new_subset_length(payload_tvb, offset, tlv_len);
                        call_dissector(thread_nwd_handle, sub_tvb, pinfo, tlv_tree);
                    }
                    offset += tlv_len;
                }
                break;

            case MLE_TLV_ACTIVE_OP_DATASET:
            case MLE_TLV_PENDING_OP_DATASET:
            case MLE_TLV_THREAD_DISCOVERY:
                {
                    tvbuff_t *sub_tvb;
                    proto_item_append_text(ti, ")");
                    if (tlv_len > 0) {
                        sub_tvb = tvb_new_subset_length(payload_tvb, offset, tlv_len);
                        call_dissector(thread_mc_handle, sub_tvb, pinfo, tlv_tree);
                    }
                    offset += tlv_len;
                }
                break;

            case MLE_TLV_TLV_REQUEST:
                proto_item_append_text(ti, ")");
                while (tlv_len) {
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_type, payload_tvb, offset, 1, ENC_NA);
                    offset++;
                    tlv_len--;
                }
                break;

            case MLE_TLV_SCAN_MASK:
                if (tlv_len != 1) {
                    /* TLV Length must be 1 */
                    proto_item_append_text(ti, ")");
                    expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                } else {
                    guint8 mask;

                    mask = tvb_get_guint8(payload_tvb, offset);
                    proto_item_append_text(ti, " = %02x)", mask);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_scan_mask_r, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_scan_mask_e, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                }
                offset += tlv_len;
                break;

            case MLE_TLV_CONNECTIVITY:
                proto_item_append_text(ti, ")");
                if ((tlv_len == 7) || (tlv_len == 10)) {
                    proto_tree *fl_tree;

                    ti = proto_tree_add_item(tlv_tree, hf_mle_tlv_conn_flags, payload_tvb, offset, 1, ENC_NA);
                    fl_tree = proto_item_add_subtree(ti, ett_mle_conn_flg);
                    proto_tree_add_item(fl_tree, hf_mle_tlv_conn_flags_pp, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_conn_lq3, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_conn_lq2, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_conn_lq1, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_conn_leader_cost, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_conn_id_seq, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_conn_active_rtrs, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                    offset++;
                    if (tlv_len == 10) {
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_conn_sed_buf_size, payload_tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_conn_sed_dgram_cnt, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset++;
                    }
                } else {
                    /* TLV Length must be 7 (old style) or 10 */
                    expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                    offset += tlv_len;
                }
                break;

            case MLE_TLV_LINK_MARGIN:
                if (tlv_len != 1) {
                    /* TLV Length must be 1 */
                    proto_item_append_text(ti, ")");
                    expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                } else {
                    guint8 link_margin;

                    link_margin = tvb_get_guint8(payload_tvb, offset);
                    proto_item_append_text(ti, " = %udB)", link_margin);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_link_margin, payload_tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                }
                offset += tlv_len;
                break;

            case MLE_TLV_STATUS:
                if (tlv_len != 1) {
                    /* TLV Length must be 1 */
                    proto_item_append_text(ti, ")");
                    expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                } else {
                    guint8 stat;

                    stat = tvb_get_guint8(payload_tvb, offset);
                    proto_item_append_text(ti, " = %d)", stat);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_status, payload_tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                }
                offset += tlv_len;
                break;

            case MLE_TLV_VERSION:
                if (tlv_len != 2) {
                    /* TLV Length must be 2 */
                    proto_item_append_text(ti, ")");
                    expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                } else {
                    guint16 version;

                    version = tvb_get_ntohs(payload_tvb, offset);
                    proto_item_append_text(ti, " = %d)", version);
                    proto_tree_add_item(tlv_tree, hf_mle_tlv_version, payload_tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                }
                offset += tlv_len;
                break;

            case MLE_TLV_ADDRESS_REGISTRATION:
                {
                    guint8 iid_type, i;
                    guint8 entries = 0;
                    gint16 check_len = tlv_len;
                    guint check_offset = offset;

                    /* Check consistency of entries */
                    while (check_len > 0) {
                        guint8 ar_len;

                        iid_type = tvb_get_guint8(payload_tvb, check_offset);
                        if (iid_type & ADDR_REG_MASK_IID_TYPE_MASK) {
                            ar_len = 9;
                        } else {
                            ar_len = 17;
                        }
                        check_offset += ar_len;
                        check_len -= ar_len;
                        entries++;
                    }

                    proto_item_append_text(ti, ")");
                    if (check_len != 0) {
                        /* Not an integer number of entries */
                        expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                        offset += tlv_len;
                    } else {
                        for (i = 0; i < entries; i++) {
                            proto_tree *ar_tree;

                            ti = proto_tree_add_item(tlv_tree, hf_mle_tlv_addr_reg_entry, payload_tvb, offset, 1, ENC_NA);
                            ar_tree = proto_item_add_subtree(ti, ett_mle_addr_reg);
                            iid_type = tvb_get_guint8(payload_tvb, offset);
                            if (iid_type & ADDR_REG_MASK_IID_TYPE_MASK) {
                                proto_tree_add_item(ar_tree, hf_mle_tlv_addr_reg_iid_type, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                                proto_tree_add_item(ar_tree, hf_mle_tlv_addr_reg_cid, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                                offset++;
                                proto_tree_add_item(ar_tree, hf_mle_tlv_addr_reg_iid, payload_tvb, offset, 8, ENC_NA);
                                offset += 8;
                            } else {
                                proto_tree_add_item(ar_tree, hf_mle_tlv_addr_reg_iid_type, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                                offset++;
                                proto_tree_add_item(ar_tree, hf_mle_tlv_addr_reg_ipv6, payload_tvb, offset, 16, ENC_NA);
                                offset += 16;
                            }
                        }
                    }
                }
                break;

            case MLE_TLV_CHANNEL:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 3) {
                        expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Channel page */
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_channel_page, payload_tvb, offset, 1, ENC_BIG_ENDIAN);
                        /* Channel */
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_channel, payload_tvb, offset+1, 2, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case MLE_TLV_PAN_ID:
                {
                    proto_item_append_text(ti, ")");

                    /* Check length is consistent */
                    if (tlv_len != 2) {
                        expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* PAN ID */
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_pan_id, payload_tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    }
                    offset += tlv_len;
                }
                break;

            case MLE_TLV_ACTIVE_TSTAMP:
            case MLE_TLV_PENDING_TSTAMP:
                {
                    nstime_t timestamp;

                    proto_item_append_text(ti, ")");

                    if (tlv_len != 8) {
                        expert_add_info(pinfo, proto_root, &ei_mle_tlv_length_failed);
                        proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                    } else {
                        /* Fill in the nstime_t structure */
                        timestamp.secs = (time_t)tvb_get_ntoh48(payload_tvb, offset);
                        timestamp.nsecs = (int)lround((double)(tvb_get_ntohs(payload_tvb, offset + 6) >> 1) * MLE_32768_TO_NSEC_FACTOR);
                        if (tlv_type == MLE_TLV_ACTIVE_TSTAMP) {
                            proto_tree_add_time(tlv_tree, hf_mle_tlv_active_tstamp, payload_tvb, offset, 8, &timestamp);
                        } else {
                            proto_tree_add_time(tlv_tree, hf_mle_tlv_pending_tstamp, payload_tvb, offset, 8, &timestamp);
                        }
                    }
                    offset += tlv_len;
                }
                break;

            default:
                proto_item_append_text(ti, ")");
                proto_tree_add_item(tlv_tree, hf_mle_tlv_unknown, payload_tvb, offset, tlv_len, ENC_NA);
                offset += tlv_len;
        }
    }

    return tvb_captured_length(tvb);
}

void
proto_register_mle(void)
{
  static hf_register_info hf[] = {

    /* Auxiliary Security Header Fields */
    /*----------------------------------*/
    { &hf_mle_security_suite,
      { "Security Suite",
        "mle.sec_suite",
        FT_UINT8, BASE_HEX, VALS(mle_sec_suite_names), 0x0,
        "The Security Suite of the frame",
        HFILL
      }
    },

    { &hf_mle_mic,
      { "Decrypted MIC",
        "mle.mic",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "The decrypted MIC",
        HFILL
      }
    },

    /*MLE Command*/
    { &hf_mle_command,
      { "Command",
        "mle.cmd",
        FT_UINT8, BASE_DEC, VALS(mle_command_vals), 0x0,
        "MLE command type",
        HFILL
      }
    },

    /* Generic TLV */
    { &hf_mle_tlv,
      { "TLV",
        "mle.tlv",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Type-Length-Value",
        HFILL
      }
    },

    { &hf_mle_tlv_type,
      { "Type",
        "mle.tlv.type",
        FT_UINT8, BASE_DEC, VALS(mle_tlv_vals), 0x0,
        "Type of value",
        HFILL
      }
    },

    { &hf_mle_tlv_length,
      { "Length",
        "mle.tlv.len",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Length of value",
        HFILL
      }
    },

    /* Type-Specific TLV Fields */
    { &hf_mle_tlv_source_addr,
      { "Address",
        "mle.tlv.source_addr",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Source address",
        HFILL
      }
    },

    /*  Capability Information Fields */
    { &hf_mle_tlv_mode_nwk_data,
      { "Network Data",
        "mle.tlv.mode.nwk_data",
        FT_BOOLEAN, 8, TFS(&mle_tlv_mode_nwk_data), MLE_CMD_CINFO_NWK_DATA,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_mode_device_type,
      { "Device Type",
        "mle.tlv.mode.device_type",
        FT_BOOLEAN, 8, TFS(&mle_tlv_mode_device_type), IEEE802154_CMD_CINFO_DEVICE_TYPE,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_mode_sec_data_req,
      { "Secure Data Requests",
        "mle.tlv.mode.sec_data_req",
        FT_BOOLEAN, 8, NULL, MLE_CMD_CINFO_SEC_DATA_REQ,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_mode_idle_rx,
      { "Receive On When Idle",
        "mle.tlv.mode.idle_rx",
        FT_BOOLEAN, 8, NULL, IEEE802154_CMD_CINFO_IDLE_RX,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_timeout,
      { "Timeout",
        "mle.tlv.timeout",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Expected interval between transmissions in seconds",
        HFILL
      }
    },

    { &hf_mle_tlv_challenge,
      { "Challenge",
        "mle.tlv.challenge",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Challenge to be echoed back",
        HFILL
      }
    },

    { &hf_mle_tlv_response,
      { "Response",
        "mle.tlv.response",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Response to a challenge",
        HFILL
      }
    },

    { &hf_mle_tlv_ll_frm_cntr,
      { "Link Layer Frame Counter",
        "mle.tlv.ll_frm_cntr",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "The Link layer frame counter",
        HFILL
      }
    },

    { &hf_mle_tlv_mle_frm_cntr,
      { "MLE Frame Counter",
        "mle.tlv.mle_frm_cntr",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "The MLE frame counter",
        HFILL
      }
    },

    { &hf_mle_tlv_unknown,
      { "Unknown",
        "mle.tlv.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Unknown TLV, raw value",
        HFILL
      }
    },

    { &hf_mle_tlv_lqi_c,
      { "Complete Flag",
        "mle.tlv.lqi.complete",
        FT_BOOLEAN, 8, NULL, LQI_FLAGS_C,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_lqi_size,
      { "Address Size",
        "mle.tlv.lqi.size",
        FT_UINT8, BASE_DEC, NULL, LQI_FLAGS_SIZE,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_neighbor,
      { "Neighbor Record",
        "mle.tlv.neighbor",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_neighbor_flagI,
      { "Incoming",
        "mle.tlv.neighbor.flagI",
        FT_BOOLEAN, 8, NULL, NEIGHBOR_FLAG_I,
        "Set if the sender has configured its link with this neighbor and will accept incoming messages from them.",
        HFILL
      }
    },

    { &hf_mle_tlv_neighbor_flagO,
      { "Outgoing",
        "mle.tlv.neighbor.flagO",
        FT_BOOLEAN, 8, NULL, NEIGHBOR_FLAG_O,
        "Set if the sender believes that the neighbor has configured its link with the sender and will accept incoming messages from the sender.",
        HFILL
      }
    },

    { &hf_mle_tlv_neighbor_flagP,
      { "Priority",
        "mle.tlv.neighbor.flagP",
        FT_BOOLEAN, 8, NULL, NEIGHBOR_FLAG_P,
        "Set if the sender expects to use this link for sending messages to this neighbor.",
        HFILL
      }
    },

    { &hf_mle_tlv_neighbor_idr,
      { "Inverse Delivery Ratio",
        "mle.tlv.neighbor.idr",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_neighbor_addr,
      { "Address",
        "mle.tlv.neighbor.addr",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_network_param_id,
      { "Parameter ID",
        "mle.tlv.network.param_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_network_delay,
      { "Delay",
        "mle.tlv.network.delay",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_network_channel,
      { "Channel",
        "mle.tlv.network.channel",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_network_pan_id,
      { "PAN ID",
        "mle.tlv.network.pan_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_network_pmt_join,
      { "Permit Join",
        "mle.tlv.network.pmt_join",
        FT_BOOLEAN, 8, NULL, 0x1,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_network_bcn_payload,
      { "Beacon Payload",
        "mle.tlv.network.bcn_payload",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_route64_id_seq,
      { "ID Sequence",
        "mle.tlv.route64.id_seq",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_route64_id_mask,
      { "Assigned Router ID Mask",
        "mle.tlv.route64.id_mask",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_route64_entry,
      { "Routing Table Entry",
        "mle.tlv.route64",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_route64_nbr_out,
      { "Neighbor Out Link Quality",
        "mle.tlv.route64.nbr_out",
        FT_UINT8, BASE_DEC, NULL, ROUTE_TBL_OUT_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_route64_nbr_in,
      { "Neighbor In Link Quality",
        "mle.tlv.route64.nbr_in",
        FT_UINT8, BASE_DEC, NULL, ROUTE_TBL_IN_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_route64_cost,
      { "Router Cost",
        "mle.tlv.route64.cost",
        FT_UINT8, BASE_DEC, NULL, ROUTE_TBL_COST_MASK,
        NULL,
        HFILL
      }
    },
#if 0
    { &hf_mle_tlv_route64_unknown,
      { "(unknown)",
        "mle.tlv.route64.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },
#endif
    { &hf_mle_tlv_addr16,
      { "Address16",
        "mle.tlv.addr16",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_leader_data_partition_id,
      { "Partition ID",
        "mle.tlv.leader_data.partition_id",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_leader_data_weighting,
      { "Weighting",
        "mle.tlv.leader_data.weighting",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_leader_data_version,
      { "Data Version",
        "mle.tlv.leader_data.data_version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_leader_data_stable_version,
      { "Stable Data Version",
        "mle.tlv.leader_data.stable_data_version",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_leader_data_router_id,
      { "Leader Router ID",
        "mle.tlv.leader_data.router_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },
#if 0
    { &hf_mle_tlv_network_data,
      { "Network Data",
        "mle.tlv.network_data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Network data (opaque data)",
        HFILL
      }
    },
#endif
    { &hf_mle_tlv_scan_mask_r,
      { "Router",
        "mle.tlv.scan_mask.r",
        FT_BOOLEAN, 8, NULL, SCAN_MASK_R_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_scan_mask_e,
      { "End Device",
        "mle.tlv.scan_mask.e",
        FT_BOOLEAN, 8, NULL, SCAN_MASK_D_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_conn_flags,
      { "Flags",
        "mle.tlv.conn.flags",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_conn_flags_pp,
      { "Parent Priority",
        "mle.tlv.conn.flags.pp",
        FT_INT8, BASE_DEC, VALS(mle_conn_tlv_flags_pp_enums), CONN_MASK_FLAGS_PP_MASK,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_conn_lq3,
      { "Link Quality 3",
        "mle.tlv.conn.lq3",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_conn_lq2,
      { "Link Quality 2",
        "mle.tlv.conn.lq2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_conn_lq1,
      { "Link Quality 1",
        "mle.tlv.conn.lq1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_conn_leader_cost,
      { "Leader Cost",
        "mle.tlv.conn.leader_cost",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_conn_id_seq,
      { "ID Sequence",
        "mle.tlv.conn.id_seq",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_conn_active_rtrs,
      { "Active Routers",
        "mle.tlv.conn.active_rtrs",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_conn_sed_buf_size,
      { "SED Buffer Size",
        "mle.tlv.conn.sed_buf_size",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_conn_sed_dgram_cnt,
      { "SED Datagram Count",
        "mle.tlv.conn.sed_dgram_cnt",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_link_margin,
      { "Link Margin",
        "mle.tlv.link_margin",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Link margin in dB",
        HFILL
      }
    },

    { &hf_mle_tlv_status,
      { "Status",
        "mle.tlv.status",
        FT_UINT8, BASE_DEC, VALS(mle_status_tlv_enums), 0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_version,
      { "Version",
        "mle.tlv.version",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_addr_reg_entry,
      { "Address Registration Entry",
        "mle.tlv.addr_reg",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_addr_reg_iid_type,
      { "IID type",
        "mle.tlv.addr_reg_iid_type",
        FT_BOOLEAN, 8, TFS(&mle_tlv_addr_reg_iid_type), ADDR_REG_MASK_IID_TYPE_MASK,
        "Context ID",
        HFILL
      }
    },

    { &hf_mle_tlv_addr_reg_cid,
      { "Context ID",
        "mle.tlv.addr_reg_cid",
        FT_UINT8, BASE_DEC, NULL, ADDR_REG_MASK_CID_MASK,
        "6LoWPAN Context ID",
        HFILL
      }
    },

    { &hf_mle_tlv_addr_reg_iid,
      { "IID",
        "mle.tlv.addr_reg_iid",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Interface identifier",
        HFILL
      }
    },

    { &hf_mle_tlv_addr_reg_ipv6,
      { "IPv6 Address",
        "mle.tlv.addr_reg_ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        "IID",
        HFILL
      }
    },
#if 0
    { &hf_mle_tlv_hold_time,
      { "Hold Time",
        "mle.tlv.hold_time",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL,
        HFILL
      }
    },
#endif
    { &hf_mle_tlv_network_unknown,
      { "(unknown)",
        "mle.tlv.network.unknown",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_channel_page,
      { "Channel Page",
        "mle.tlv.channel_page",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_channel,
      { "Channel",
        "mle.tlv.channel",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_pan_id,
      { "PAN ID",
        "mle.tlv.pan_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_active_tstamp,
      { "Active Timestamp",
        "mle.tlv.active_tstamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL,
        HFILL
      }
    },

    { &hf_mle_tlv_pending_tstamp,
      { "Pending Timestamp",
        "mle.tlv.pending_tstamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL,
        HFILL
      }
    },
#if 0
    { &hf_mle_tlv_active_op_dataset,
      { "Active Operational Dataset",
        "mle.tlv.active_op_dataset",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Thread Active Operational Dataset",
        HFILL
      }
    },
    { &hf_mle_tlv_pending_op_dataset,
      { "Pending Operational Dataset",
        "mle.tlv.active_op_dataset",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "Thread Pending Operational Dataset",
        HFILL
      }
    },
#endif
  };

  static gint *ett[] = {
    &ett_mle,
    &ett_mle_auxiliary_security,
    &ett_mle_aux_sec_control,
    &ett_mle_aux_sec_key_id,
    &ett_mle_tlv,
    &ett_mle_neighbor,
    &ett_mle_router,
    &ett_mle_addr_reg,
    &ett_mle_conn_flg,
    &ett_mle_thread_nwd
};

  static ei_register_info ei[] = {
    { &ei_mle_cbc_mac_failed, { "mle.cbc_mac_failed", PI_UNDECODED, PI_WARN, "Call to ccm_cbc_mac() failed", EXPFILL }},
    { &ei_mle_packet_too_small, { "mle.packet_too_small", PI_UNDECODED, PI_WARN, "Packet was too small to include the CRC and MIC", EXPFILL }},
    { &ei_mle_no_key, { "mle.no_key", PI_UNDECODED, PI_WARN, "No encryption key set - can't decrypt", EXPFILL }},
    { &ei_mle_decrypt_failed, { "mle.decrypt_failed", PI_UNDECODED, PI_WARN, "Decrypt failed", EXPFILL }},
    { &ei_mle_mic_check_failed, { "mle.mic_check_failed", PI_UNDECODED, PI_WARN, "MIC check failed", EXPFILL }},
    { &ei_mle_tlv_length_failed, { "mle.tlv_length_failed", PI_UNDECODED, PI_WARN, "TLV Length inconsistent", EXPFILL }},
    { &ei_mle_len_size_mismatch, { "mle.len_size_mismatch", PI_UNDECODED, PI_WARN, "TLV Length & Size field disagree", EXPFILL }},
  };

  module_t *mle_module;
  expert_module_t* expert_mle;

  proto_mle = proto_register_protocol("Mesh Link Establishment", "MLE", "mle");
  proto_register_field_array(proto_mle, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_mle = expert_register_protocol(proto_mle);
  expert_register_field_array(expert_mle, ei, array_length(ei));

  mle_handle = register_dissector("mle", dissect_mle, proto_mle);

  mle_module = prefs_register_protocol(proto_mle, NULL);

  prefs_register_bool_preference(mle_module, "meshlink_mic_ok",
                  "Dissect only good MIC",
                  "Dissect payload only if MIC is valid.",
                   &mle_mic_ok);

    /* setup registration for other dissectors to provide mle key hash algorithms */
    mle_key_hash_handlers = wmem_tree_new(wmem_epan_scope());
}

void
proto_reg_handoff_mle(void)
{
    thread_nwd_handle = find_dissector_add_dependency("thread_nwd", proto_mle);
    thread_mc_handle = find_dissector_add_dependency("thread_meshcop", proto_mle);

    //heur_dissector_add("stun", dissect_embeddedmle_heur, proto_mle);

    dissector_add_uint_range_with_preference("udp.port", UDP_PORT_MLE_RANGE, mle_handle);

    proto_ieee802154 = proto_get_id_by_filter_name(IEEE802154_PROTOABBREV_WPAN);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab
 * :indentSize=2:tabSize=8:noTabs=true:
 */
