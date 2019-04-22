/* packet-btmesh.c
 * Routines for Bluetooth mesh dissection
 *
 * Copyright 2017, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref: Mesh Profile v1.0
 */

#include "config.h"
#include "packet-btmesh.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <wsutil/wsgcrypt.h>
#include <epan/expert.h>
#include <stdio.h>
#include <epan/uat.h>
#include <epan/reassemble.h>

#define BTMESH_NOT_USED 0

void proto_register_btmesh(void);

gint net_mic_size_chosen = 1;

static int proto_btmesh = -1;

/*-------------------------------------
 * UAT for BT Mesh
 *-------------------------------------
 */

static uat_t * btmesh_uat = NULL;
static guint num_btmesh_uat = 0;

/* UAT entry structure. */
typedef struct {
    gchar *network_key_string;
    guint8 *network_key;
    gint network_key_length;
    gchar *ivindex_string;
    gint ivindex_string_length;
    guint8 *ivindex;
    guint8 *privacykey;
    guint8 *encryptionkey;
    guint8 nid;
} uat_btmesh_record_t;

static uat_btmesh_record_t *uat_btmesh_records = NULL;

static int hf_btmesh_ivi = -1;
static int hf_btmesh_nid = -1;
static int hf_btmesh_obfuscated = -1;
static int hf_btmesh_encrypted = -1;
static int hf_btmesh_netmic = -1;

static int hf_btmesh_ctl = -1;
static int hf_btmesh_ttl = -1;
static int hf_btmesh_seq = -1;
static int hf_btmesh_src = -1;
static int hf_btmesh_dst = -1;

static int hf_btmesh_transp_pdu = -1;
static int hf_btmesh_cntr_seg = -1;
static int hf_btmesh_acc_seg = -1;
static int hf_btmesh_cntr_opcode = -1;
static int hf_btmesh_acc_akf = -1;
static int hf_btmesh_acc_aid = -1;
static int hf_btmesh_obo = -1;
static int hf_btmesh_seqzero = -1;
static int hf_btmesh_rfu = -1;
static int hf_btmesh_blockack = -1;
static int hf_btmesh_cntr_criteria_rfu = -1;
static int hf_btmesh_cntr_padding = -1;
static int hf_btmesh_cntr_fsn = -1;

static int hf_btmesh_cntr_key_refresh_flag = -1;
static int hf_btmesh_cntr_iv_update_flag = -1;
static int hf_btmesh_cntr_flags_rfu = -1;
static int hf_btmesh_cntr_iv_index = -1;
static int hf_btmesh_cntr_md = -1;

static int hf_btmesh_cntr_heartbeat_rfu = -1;
static int hf_btmesh_cntr_init_ttl = -1;
static int hf_btmesh_cntr_feature_relay = -1;
static int hf_btmesh_cntr_feature_proxy = -1;
static int hf_btmesh_cntr_feature_friend = -1;
static int hf_btmesh_cntr_feature_low_power = -1;
static int hf_btmesh_cntr_feature_rfu = -1;

static int hf_btmesh_cntr_criteria_rssifactor = -1;
static int hf_btmesh_cntr_criteria_receivewindowfactor = -1;
static int hf_btmesh_cntr_criteria_minqueuesizelog = -1;
static int hf_btmesh_cntr_receivedelay = -1;
static int hf_btmesh_cntr_polltimeout = -1;
static int hf_btmesh_cntr_previousaddress = -1;
static int hf_btmesh_cntr_numelements = -1;
static int hf_btmesh_cntr_lpncounter = -1;
static int hf_btmesh_cntr_receivewindow = -1;
static int hf_btmesh_cntr_queuesize = -1;
static int hf_btmesh_cntr_subscriptionlistsize = -1;
static int hf_btmesh_cntr_rssi = -1;
static int hf_btmesh_cntr_friendcounter = -1;
static int hf_btmesh_cntr_lpnaddress = -1;
static int hf_btmesh_cntr_transactionnumber = -1;
static int hf_btmesh_enc_access_pld = -1;
static int hf_btmesh_transtmic = -1;
static int hf_btmesh_szmic = -1;
static int hf_btmesh_seqzero_data = -1;
static int hf_btmesh_sego = -1;
static int hf_btmesh_segn = -1;
static int hf_btmesh_seg_rfu = -1;
static int hf_btmesh_segment = -1;
static int hf_btmesh_cntr_unknown_payload = -1;

static int hf_btmesh_segmented_access_fragments = -1;
static int hf_btmesh_segmented_access_fragment = -1;
static int hf_btmesh_segmented_access_fragment_overlap = -1;
static int hf_btmesh_segmented_access_fragment_overlap_conflict = -1;
static int hf_btmesh_segmented_access_fragment_multiple_tails = -1;
static int hf_btmesh_segmented_access_fragment_too_long_fragment = -1;
static int hf_btmesh_segmented_access_fragment_error = -1;
static int hf_btmesh_segmented_access_fragment_count = -1;
static int hf_btmesh_segmented_access_reassembled_length = -1;

static int ett_btmesh = -1;
static int ett_btmesh_net_pdu = -1;
static int ett_btmesh_transp_pdu = -1;
static int ett_btmesh_transp_ctrl_msg = -1;
static int ett_btmesh_upper_transp_acc_pdu = -1;
static int ett_btmesh_segmented_access_fragments = -1;
static int ett_btmesh_segmented_access_fragment = -1;

static expert_field ei_btmesh_not_decoded_yet = EI_INIT;

static const value_string btmesh_ctl_vals[] = {
    { 0, "Access Message" },
    { 1, "Control Message" },
    { 0, NULL }
};

static const value_string btmesh_ctrl_seg_vals[] = {
    { 0, "Unsegmented Control Message" },
    { 1, "Segmented Control Message" },
    { 0, NULL }
};

static const value_string btmesh_acc_seg_vals[] = {
    { 0, "Unsegmented Access Message" },
    { 1, "Segmented Access Message" },
    { 0, NULL }
};

static const value_string btmesh_acc_akf_vals[] = {
    { 0, "Device key" },
    { 1, "Application key" },
    { 0, NULL }
};

static const value_string btmesh_ctrl_opcode_vals[] = {
    { 0x0, "Segment Acknowledgment" }, /* Reserved for lower transport layer */
    { 0x1, "Friend Poll" },
    { 0x2, "Friend Update" },
    { 0x3, "Friend Request" },
    { 0x4, "Friend Offer" },
    { 0x5, "Friend Clear" },
    { 0x6, "Friend Clear Confirm" },
    { 0x7, "Friend Subscription List Add" },
    { 0x8, "Friend Subscription List Remove" },
    { 0x9, "Friend Subscription List Confirm" },
    { 0xa, "Heartbeat" },
    { 0, NULL }
};

static const value_string btmesh_cntr_key_refresh_flag_vals[] = {
    { 0x0, "Not-In-Phase2" },
    { 0x1, "In-Phase2" },
    { 0, NULL }
};

static const value_string btmesh_cntr_iv_update_flag_vals[] = {
    { 0x0, "Normal operation" },
    { 0x1, "IV Update active" },
    { 0, NULL }
};

static const value_string btmesh_cntr_md_vals[] = {
    { 0x0, "Friend Queue is empty" },
    { 0x1, "Friend Queue is not empty" },
    { 0, NULL }
};

static const true_false_string  btmesh_obo = {
    "Friend node that is acknowledging this message on behalf of a Low Power node",
    "Node that is directly addressed by the received message"
};

static const value_string btmesh_criteria_rssifactor_vals[] = {
    { 0x0, "1" },
    { 0x1, "1.5" },
    { 0x2, "2" },
    { 0x3, "2.5" },
    { 0, NULL }
};

static const value_string btmesh_criteria_receivewindowfactor_vals[] = {
    { 0x0, "1" },
    { 0x1, "1.5" },
    { 0x2, "2" },
    { 0x3, "2.5" },
    { 0, NULL }
};

static const value_string btmesh_criteria_minqueuesizelog_vals[] = {
    { 0x0, "Prohibited" },
    { 0x1, "N = 2" },
    { 0x2, "N = 4" },
    { 0x3, "N = 8" },
    { 0x4, "N = 16" },
    { 0x5, "N = 32" },
    { 0x6, "N = 64" },
    { 0x7, "N = 128" },
    { 0, NULL }
};

static const value_string btmesh_szmic_vals[] = {
{ 0x0, "32-bit" },
{ 0x1, "64-bit" },
{ 0, NULL }
};

/* Upper Transport Message reassembly */

static reassembly_table upper_transport_reassembly_table;

static const fragment_items btmesh_segmented_access_frag_items = {
    &ett_btmesh_segmented_access_fragments,
    &ett_btmesh_segmented_access_fragment,

    &hf_btmesh_segmented_access_fragments,
    &hf_btmesh_segmented_access_fragment,
    &hf_btmesh_segmented_access_fragment_overlap,
    &hf_btmesh_segmented_access_fragment_overlap_conflict,
    &hf_btmesh_segmented_access_fragment_multiple_tails,
    &hf_btmesh_segmented_access_fragment_too_long_fragment,
    &hf_btmesh_segmented_access_fragment_error,
    &hf_btmesh_segmented_access_fragment_count,
    NULL,
    &hf_btmesh_segmented_access_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

static int hf_btmesh_segmented_control_fragments = -1;
static int hf_btmesh_segmented_control_fragment = -1;
static int hf_btmesh_segmented_control_fragment_overlap = -1;
static int hf_btmesh_segmented_control_fragment_overlap_conflict = -1;
static int hf_btmesh_segmented_control_fragment_multiple_tails = -1;
static int hf_btmesh_segmented_control_fragment_too_long_fragment = -1;
static int hf_btmesh_segmented_control_fragment_error = -1;
static int hf_btmesh_segmented_control_fragment_count = -1;
static int hf_btmesh_segmented_control_reassembled_length = -1;

static int ett_btmesh_segmented_control_fragments = -1;
static int ett_btmesh_segmented_control_fragment = -1;

static const fragment_items btmesh_segmented_control_frag_items = {
    &ett_btmesh_segmented_control_fragments,
    &ett_btmesh_segmented_control_fragment,

    &hf_btmesh_segmented_control_fragments,
    &hf_btmesh_segmented_control_fragment,
    &hf_btmesh_segmented_control_fragment_overlap,
    &hf_btmesh_segmented_control_fragment_overlap_conflict,
    &hf_btmesh_segmented_control_fragment_multiple_tails,
    &hf_btmesh_segmented_control_fragment_too_long_fragment,
    &hf_btmesh_segmented_control_fragment_error,
    &hf_btmesh_segmented_control_fragment_count,
    NULL,
    &hf_btmesh_segmented_control_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

typedef struct _upper_transport_fragment_key {
    guint16 src;
    guint16 seq0;
} upper_transport_fragment_key;

static guint
upper_transport_fragment_hash(gconstpointer k)
{
    const upper_transport_fragment_key* key = (const upper_transport_fragment_key*) k;
    guint hash_val;

    hash_val = key->src;
    hash_val += ( ((guint)key->seq0) << 16);
    return hash_val;
}

static gint
upper_transport_fragment_equal(gconstpointer k1, gconstpointer k2)
{
    const upper_transport_fragment_key* key1 = (const upper_transport_fragment_key*) k1;
    const upper_transport_fragment_key* key2 = (const upper_transport_fragment_key*) k2;

    return ((key1->src == key2->src) && (key1->seq0 == key2->seq0)
            ? TRUE : FALSE);
}

static void *
upper_transport_fragment_temporary_key(const packet_info *pinfo _U_, const guint32 id _U_,
                              const void *data)
{
    upper_transport_fragment_key *key = g_slice_new(upper_transport_fragment_key);
    const upper_transport_fragment_key *pkt = (const upper_transport_fragment_key *)data;

    key->src = pkt->src;
    key->seq0 = pkt->seq0;

    return key;
}

static void
upper_transport_fragment_free_temporary_key(gpointer ptr)
{
    upper_transport_fragment_key *key = (upper_transport_fragment_key *)ptr;

    g_slice_free(upper_transport_fragment_key, key);
}

static void *
upper_transport_fragment_persistent_key(const packet_info *pinfo _U_, const guint32 id _U_,
                              const void *data)
{
    upper_transport_fragment_key *key = g_slice_new(upper_transport_fragment_key);
    const upper_transport_fragment_key *pkt = (const upper_transport_fragment_key *)data;

    key->src = pkt->src;
    key->seq0 = pkt->seq0;

    return key;
}

static void
upper_transport_fragment_free_persistent_key(gpointer ptr)
{
    upper_transport_fragment_key *key = (upper_transport_fragment_key *)ptr;
    if (key) {
        g_slice_free(upper_transport_fragment_key, key);
    }
}

static const reassembly_table_functions upper_transport_reassembly_table_functions = {
    upper_transport_fragment_hash,
    upper_transport_fragment_equal,
    upper_transport_fragment_temporary_key,
    upper_transport_fragment_persistent_key,
    upper_transport_fragment_free_temporary_key,
    upper_transport_fragment_free_persistent_key
};

static void
upper_transport_init_routine(void)
{
    reassembly_table_register(&upper_transport_reassembly_table, &upper_transport_reassembly_table_functions);
}


/* A BT Mesh dissector is not realy useful without decryption as all packets are encrypted. Just leave a stub dissector outside of*/
#if GCRYPT_VERSION_NUMBER >= 0x010600 /* 1.6.0 */

/* BT Mesh s1 function */
static gboolean
s1(guint8 *m, size_t mlen, guint8 *salt)
{

    gcry_mac_hd_t mac_hd;
    int gcrypt_err;
    size_t read_digest_length = 16;
    guint8  zero[16] = { 0 };

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &zero, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, m, mlen);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return 0;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, salt, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return 0;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    return TRUE;
}

/* BT Mesh K2 function
 * Allow plen up to 9 char
 *
 * The key (T) is computed as follows:
 * T = AES-CMACSALT (N)
 * SALT is the 128-bit value computed as follows
 * SALT = s1("smk2")
 * The output of the key generation function k2 is as follows:
 * T0 = empty string (zero length)
 * T1 = AES-CMACT (T0 || P || 0x01)
 * T2 = AES-CMACT (T1 || P || 0x02)
 * T3 = AES-CMACT (T2 || P || 0x03)
 * k2(N, P) = (T1 || T2 || T3) mod 2(pow)263
 */
static gboolean
k2(uat_btmesh_record_t * net_key_set, guint8 *p, size_t plen)
{
    gcry_mac_hd_t mac_hd;
    int gcrypt_err;

    guint8 smk2[4] = { 's', 'm', 'k', '2' };
    size_t mlen = 4;
    guint8 salt[16];
    guint8 t[16];
    guint8 t1[16];
    guint8 p_t1[9 + 1];
    guint8 p_t2[16 + 9 + 1];
    guint8 p_t3[16 + 9 + 1];

    size_t read_digest_length = 16;

    if (plen > 8) {
        return FALSE;
    }

    /* SALT = s1("smk2") */
    if (s1(smk2, mlen, salt) == FALSE) {
        return FALSE;
    }

    /* T = AES-CMAC_SALT(N) */
    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &salt, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, net_key_set->network_key, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, t, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    // T0 = empty string (zero length)
    // T1 = AES-CMAC_T(T0 || P || 0x01)
    memcpy(p_t1, p, plen);
    p_t1[plen] = 0x01;

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, &p_t1, plen + 1);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, t1, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }
    net_key_set->nid = (t1[15] & 0x7f);
    /* T2 = AES-CMAC_T(T1 || P || 0x02)
     * (EncryptionKey)
     */

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    memcpy(p_t2, t1, 16);
    memcpy(&p_t2[16], p, plen);
    p_t2[16 + plen] = 0x02;

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, &t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, &p_t2, 16 + plen + 1);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, net_key_set->encryptionkey, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    /* T3 = AES-CMAC_T(T2 || P || 0x03) */
    /* PrivacyKey */
    memcpy(p_t3, net_key_set->encryptionkey, 16);
    memcpy(&p_t3[16], p, plen);
    p_t3[16 + plen] = 0x03;

    /* Open gcrypt handle */
    gcrypt_err = gcry_mac_open(&mac_hd, GCRY_MAC_CMAC_AES, 0, NULL);
    if (gcrypt_err != 0) {
        return FALSE;
    }

    /* Set the key */
    gcrypt_err = gcry_mac_setkey(mac_hd, t, 16);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    gcrypt_err = gcry_mac_write(mac_hd, p_t3, 16 + plen + 1);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Read out the digest */
    gcrypt_err = gcry_mac_read(mac_hd, net_key_set->privacykey, &read_digest_length);
    if (gcrypt_err != 0) {
        gcry_mac_close(mac_hd);
        return FALSE;
    }

    /* Now close the mac handle */
    gcry_mac_close(mac_hd);

    return TRUE;
}

static gboolean
create_master_security_keys(uat_btmesh_record_t * net_key_set)
{
    guint8 p[1] = { 0 };
    size_t plen = 1;

    k2(net_key_set, p, plen);

    return TRUE;
}

static tvbuff_t *
btmesh_deobfuscate(tvbuff_t *tvb, packet_info *pinfo, int offset _U_, uat_btmesh_record_t *net_key_set)
{
    tvbuff_t *de_obf_tvb = NULL;

    /* Decode ObfuscatedData
     * Privacy Random = (EncDST || EncTransportPDU || NetMIC)[0-6]
     * PECB = e ((PrivacyKey, 0x0000000000 || IV Index || Privacy Random)
     * (CTL || TTL || SEQ || SRC) = ObfuscatedData
     */
    guint8 in[16]; /*  0x0000000000 || IV Index || Privacy Random */
    gcry_cipher_hd_t cipher_hd;
    guint8 pecb[16];
    guint8 *plaintextnetworkheader = (guint8 *)wmem_alloc(pinfo->pool, 6);
    int i;

    /* at least 1 + 6 + 2 + 1 + 4 + 4 = 18 octets must be present in tvb to decrypt */
    if (!tvb_bytes_exist(tvb, 0, 18)) {
        return NULL;
    }

    memset(in, 0x00, 5);
    memcpy((guint8 *)&in + 5, net_key_set->ivindex, 4);

    /* Privacy random */
    tvb_memcpy(tvb, (guint8 *)&in + 9, 7, 7);

    if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_ECB, 0)) {
        return NULL;
    }

    if (gcry_cipher_setkey(cipher_hd, net_key_set->privacykey, 16)) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Decrypt */
    if (gcry_cipher_encrypt(cipher_hd, &pecb, 16, &in, 16)) {
        gcry_cipher_close(cipher_hd);
        return NULL;
    }

    /* Now close the mac handle */
    gcry_cipher_close(cipher_hd);

    for ( i = 0; i < 6; i++) {
        plaintextnetworkheader[i] = tvb_get_guint8(tvb, i + 1) ^ pecb[i];
    }

    de_obf_tvb = tvb_new_child_real_data(tvb, plaintextnetworkheader, 6, 6);
    return de_obf_tvb;
}

static void
dissect_btmesh_transport_control_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, guint32 opcode)
{
    proto_tree *sub_tree;

    sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_btmesh_transp_ctrl_msg, NULL, "Transport Control Message %s",
        val_to_str_const(opcode, btmesh_ctrl_opcode_vals, "Unknown"));

    switch (opcode) {
    case 1:
        /* 3.6.5.1 Friend Poll */
        /* Padding 7 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_padding, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* FSN 1 bit*/
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_fsn, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 2:
        /* 3.6.5.2 Friend Update */
        /* Flags 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_key_refresh_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_iv_update_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_flags_rfu, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* IV Index 4 octets*/
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_iv_index, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset+=4;
        /* MD 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_md, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        break;
    case 3:
        /* Friend Request */
        /* Criteria 1 octet */
        /* RFU 1 bit */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_rfu, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* RSSIFactor 2 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_rssifactor, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* ReceiveWindowFactor 2 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_receivewindowfactor, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* MinQueueSizeLog 3 bits */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_criteria_minqueuesizelog, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* ReceiveDelay 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_receivedelay, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* PollTimeout 3 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_polltimeout, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset+=3;
        /* PreviousAddress 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_previousaddress, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset+=2;
        /* NumElements 1 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_numelements, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        /* LPNCounter 1 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpncounter, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 4:
        /* 3.6.5.4 Friend Offer */
        /* ReceiveWindow 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_receivewindow, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* QueueSize 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_queuesize, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* SubscriptionListSize 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_subscriptionlistsize, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* RSSI 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_rssi, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* FriendCounter 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_friendcounter, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 5:
        /* 3.6.5.5 Friend Clear */
        /* LPNAddress 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpnaddress, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 2;
        /* LPNCounter 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpncounter, tvb, offset, 1, ENC_BIG_ENDIAN);
        break;
    case 6:
        /* 3.6.5.6 Friend Clear Confirm */
        /* LPNAddress 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpnaddress, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 2;
        /* LPNCounter 2 octets */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_lpncounter, tvb, offset, 1, ENC_BIG_ENDIAN);

        break;
    case 7:
        /* 3.6.5.7 Friend Subscription List Add */
        /* TransactionNumber 1 octet */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_transactionnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* AddressList 2 * N */
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_not_decoded_yet, tvb, offset, -1);
        break;
    case 8:
        /* 3.6.5.8 Friend Subscription List Remove */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_transactionnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* AddressList 2 * N */
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_not_decoded_yet, tvb, offset, -1);
        break;
    case 9:
        /* 3.6.5.9 Friend Subscription List Confirm */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_transactionnumber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        break;
    case 10:
        /* 3.6.5.10 Heartbeat */
        /* RFU & InitTTL */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_heartbeat_rfu, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_init_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        /* Features */
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_relay, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_proxy, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_friend, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_low_power, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_feature_rfu, tvb, offset, 2, ENC_BIG_ENDIAN);
        break;
    default:
        //Payload
        proto_tree_add_item(sub_tree, hf_btmesh_cntr_unknown_payload, tvb, offset, -1, ENC_NA);
        proto_tree_add_expert(sub_tree, pinfo, &ei_btmesh_not_decoded_yet, tvb, offset, -1);
        break;
    }
}

static void
dissect_btmesh_transport_access_message(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, int transmic_size)
{
    proto_tree *sub_tree;
    int length = tvb_reported_length_remaining(tvb, offset);

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_upper_transp_acc_pdu, NULL, "Upper Transport Access PDU");

    proto_tree_add_item(sub_tree, hf_btmesh_enc_access_pld, tvb, offset, length - transmic_size, ENC_NA);
    offset += (length - transmic_size);

    proto_tree_add_item(sub_tree, hf_btmesh_transtmic, tvb, offset, transmic_size, ENC_NA);
}

static void
dissect_btmesh_transport_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean cntrl, guint32 src)
{
    proto_tree *sub_tree;
    proto_item *ti;
    int offset = 0;
    guint32 seg, opcode, rfu;
    guint32 seqzero, sego, segn;

    /* We receive the full decrypted buffer including DST, skip to opcode */
    offset += 2;
    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_btmesh_transp_pdu, &ti, "Lower Transport PDU");
    if (cntrl) {
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_cntr_seg, tvb, offset, 1, ENC_BIG_ENDIAN, &seg);
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_cntr_opcode, tvb, offset, 1, ENC_BIG_ENDIAN, &opcode);
        offset++;

        if (seg) {
            /* Segmented */
            fragment_head *fd_head = NULL;

            /* RFU */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seg_rfu, tvb, offset, 3, ENC_BIG_ENDIAN, &rfu);
            /* SeqZero 13 */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seqzero_data, tvb, offset, 3, ENC_BIG_ENDIAN, &seqzero);
            /* SegO 5 Segment Offset number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sego, tvb, offset, 3, ENC_BIG_ENDIAN, &sego);
            /* SegN 5 Last Segment number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_segn, tvb, offset, 3, ENC_BIG_ENDIAN, &segn);
            offset += 3;

            /* Segment */
            proto_tree_add_item(sub_tree, hf_btmesh_segment, tvb, offset, -1, ENC_NA);

            upper_transport_fragment_key frg_key;
            /* src is 15 bit, seqzero is 13 bit*/
            frg_key.src = src;
            frg_key.seq0 = seqzero;

            if (!pinfo->fd->visited) {
                guint32 total_length = 0;
                if (segn == sego) {
                    total_length = segn * 8 + tvb_captured_length_remaining(tvb, offset);
                }

                /* Last fragment can be delivered out of order, and can be the first one. */
                fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);

                if ((fd_head) && (total_length)) {
                    fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                }
                fd_head = fragment_add(&upper_transport_reassembly_table,
                            tvb, offset, pinfo,
                            BTMESH_NOT_USED, &frg_key,
                            8 * sego,
                            tvb_captured_length_remaining(tvb, offset),
                            ( segn == 0 ? FALSE : TRUE) );

                if ((!fd_head) && (total_length)) {
                    fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                }
            } else {
                fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);
                if (fd_head && (fd_head->flags&FD_DEFRAGMENTED)) {
                    tvbuff_t *next_tvb;
                    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Control PDU", fd_head, &btmesh_segmented_control_frag_items, NULL, sub_tree);
                    if (next_tvb) {
                        col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
                        dissect_btmesh_transport_control_message(next_tvb, pinfo, tree, 0, opcode);
                    } else {
                        col_append_fstr(pinfo->cinfo, COL_INFO," (Message fragment %u)", sego);
                    }
                }
            }

        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
                val_to_str_const(opcode, btmesh_ctrl_opcode_vals, "Unknown"));
            if (opcode == 0) {
                /* OBO 1 */
                proto_tree_add_item(sub_tree, hf_btmesh_obo, tvb, offset, 2, ENC_BIG_ENDIAN);
                /* SeqZero 13 */
                proto_tree_add_item(sub_tree, hf_btmesh_seqzero, tvb, offset, 2, ENC_BIG_ENDIAN);
                /* RFU 2 */
                proto_tree_add_item(sub_tree, hf_btmesh_rfu, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                /* BlockAck 32 */
                proto_tree_add_item(sub_tree, hf_btmesh_blockack, tvb, offset, 4, ENC_BIG_ENDIAN);
                return;
            }
            dissect_btmesh_transport_control_message(tvb, pinfo, tree, offset, opcode);
        }
    } else {
        /* Access message */
        guint32 afk, aid, szmic;
        /* Access message */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_acc_seg, tvb, offset, 1, ENC_BIG_ENDIAN, &seg);
        /* AKF 1 Application Key Flag */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_acc_akf, tvb, offset, 1, ENC_BIG_ENDIAN, &afk);
        /* AID 6 Application key identifier */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_acc_aid, tvb, offset, 1, ENC_BIG_ENDIAN, &aid);
        offset++;
        if (seg) {
            /* Segmented */
            fragment_head *fd_head = NULL;

            /* SZMIC 1 Size of TransMIC */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_szmic, tvb, offset, 3, ENC_BIG_ENDIAN, &szmic);
            /* SeqZero 13 Least significant bits of SeqAuth */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seqzero_data, tvb, offset, 3, ENC_BIG_ENDIAN, &seqzero);
            /* SegO 5 Segment Offset number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_sego, tvb, offset, 3, ENC_BIG_ENDIAN, &sego);
            /* SegN 5 Last Segment number */
            proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_segn, tvb, offset, 3, ENC_BIG_ENDIAN, &segn);
            offset += 3;

            /* Segment m 8 to 96 Segment m of the Upper Transport Access PDU */
            proto_tree_add_item(sub_tree, hf_btmesh_segment, tvb, offset, -1, ENC_NA);

            upper_transport_fragment_key frg_key;
            /* src is 15 bit, seqzero is 13 bit*/
            frg_key.src = src;
            frg_key.seq0 = seqzero;

            if (!pinfo->fd->visited) {
                guint32 total_length = 0;
                if (segn == sego) {
                    total_length = segn * 12 + tvb_captured_length_remaining(tvb, offset);
                }

                /* Last fragment can be delivered out of order, and can be the first one. */
                fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);

                if ((fd_head) && (total_length)) {
                    fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                }
                fd_head = fragment_add(&upper_transport_reassembly_table,
                            tvb, offset, pinfo,
                            BTMESH_NOT_USED, &frg_key,
                            12 * sego,
                            tvb_captured_length_remaining(tvb, offset),
                            ( segn == 0 ? FALSE : TRUE) );

                if ((!fd_head) && (total_length)) {
                    fragment_set_tot_len(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key, total_length);
                }
            } else {
                fd_head = fragment_get(&upper_transport_reassembly_table, pinfo, BTMESH_NOT_USED, &frg_key);
                if (fd_head && (fd_head->flags&FD_DEFRAGMENTED)) {
                    tvbuff_t *next_tvb;
                    next_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Access PDU", fd_head, &btmesh_segmented_access_frag_items, NULL, sub_tree);
                    if (next_tvb) {
                        col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled)");
                        dissect_btmesh_transport_access_message(next_tvb, pinfo, tree, 0, (szmic ? 8 : 4 ));
                    } else {
                        col_append_fstr(pinfo->cinfo, COL_INFO," (Message fragment %u)", sego);
                    }
                }
            }
        } else {
            proto_item_set_len(ti, 1);
            dissect_btmesh_transport_access_message(tvb, pinfo, tree, offset, 4/*TransMic is 32 bits*/);
        }
    }
}

tvbuff_t *
btmesh_network_find_key_and_decrypt(tvbuff_t *tvb, packet_info *pinfo, guint8 **decrypted_data, int *enc_data_len, guint8 nonce_type) {
    guint i;
    guint8 nid;
    int offset = 0;
    tvbuff_t *de_obf_tvb;
    guint8 networknonce[13];
    uat_btmesh_record_t *record;
    gcry_cipher_hd_t cipher_hd;
    guint32 net_mic_size;
    gboolean cry_error;
    guint64 ccm_lengths[3];
    int enc_offset;

    nid = tvb_get_guint8(tvb, offset) & 0x7f;

    /* Get the next record to try */
    for (i = 0; i < num_btmesh_uat; i++) {
        record = &uat_btmesh_records[i];
        if (nid == record->nid) {
            offset = 1;
            de_obf_tvb = btmesh_deobfuscate(tvb, pinfo, offset, record);

            if (de_obf_tvb == NULL) {
                continue;
            }
            net_mic_size = (((tvb_get_guint8(de_obf_tvb, 0) & 0x80) >> 7 ) + 1 ) * 4; /* CTL */
            offset +=6;

            (*enc_data_len) = tvb_reported_length(tvb) - offset - net_mic_size;
            enc_offset = offset;

            /* Start setting network nounce.*/
            networknonce[0] = nonce_type; /* Nonce Type */

            tvb_memcpy(de_obf_tvb, (guint8 *)&networknonce + 1, 0, 6);
            if (nonce_type == MESH_NONCE_TYPE_PROXY) {
                networknonce[1] = 0x00;    /*Pad*/
            }
            networknonce[7] = 0x00;    /*Pad*/
            networknonce[8] = 0x00;    /*Pad*/

            memcpy((guint8 *)&networknonce + 9, record->ivindex, 4);
            /* Decrypt packet EXPERIMENTAL CODE */
            if (gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CCM, 0)) {
                return NULL;
            }

            cry_error = gcry_cipher_setkey(cipher_hd, record->encryptionkey, 16);
            if (cry_error) {
                gcry_cipher_close(cipher_hd);
                continue;
            }

            /* Load nonce */
            cry_error = gcry_cipher_setiv(cipher_hd, &networknonce, 13);
            if (cry_error) {
                gcry_cipher_close(cipher_hd);
                continue;
            }
            /* */
            ccm_lengths[0] = (*enc_data_len);
            ccm_lengths[1] = 0; /* aad */
            ccm_lengths[2] = net_mic_size; /* icv NOT SURE ABOUT THIS ONE */

            cry_error = gcry_cipher_ctl(cipher_hd, GCRYCTL_SET_CCM_LENGTHS, ccm_lengths, sizeof(ccm_lengths));
            if (cry_error) {
                gcry_cipher_close(cipher_hd);
                continue;
            }

            (*decrypted_data) = (guint8 *)wmem_alloc(pinfo->pool, *enc_data_len);
            /* Decrypt */
            cry_error = gcry_cipher_decrypt(cipher_hd, (*decrypted_data), *enc_data_len, tvb_get_ptr(tvb, enc_offset, *enc_data_len), *enc_data_len);
            if (cry_error) {
                gcry_cipher_close(cipher_hd);
                continue;
            }

            guint8 *tag;
            tag = (guint8 *)wmem_alloc(wmem_packet_scope(), net_mic_size);
            cry_error = gcry_cipher_gettag(cipher_hd, tag, net_mic_size);

            if (cry_error == 0 && !memcmp(tag, tvb_get_ptr(tvb, enc_offset + (*enc_data_len), net_mic_size), net_mic_size)) {
                /* Tag authenticated, now close the cypher handle */
                gcry_cipher_close(cipher_hd);
                return de_obf_tvb;
            }  else {
                /* Now close the cypher handle */
                gcry_cipher_close(cipher_hd);

                /* Tag mismatch or cipher error */
                continue;
            }
        }
    }
    return NULL;
}

static gint
dissect_btmesh_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *netw_tree, *sub_tree;
    int offset = 0;
    guint32 net_mic_size, seq, src;
    int enc_data_len = 0;
    tvbuff_t *de_obf_tvb;
    tvbuff_t *de_cry_tvb;
    int decry_off;
    guint8 *decrypted_data = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT Mesh");
    col_clear(pinfo->cinfo, COL_INFO);

    item = proto_tree_add_item(tree, proto_btmesh, tvb, offset, -1, ENC_NA);
    netw_tree = proto_item_add_subtree(item, ett_btmesh);

    sub_tree = proto_tree_add_subtree(netw_tree, tvb, offset, -1, ett_btmesh_net_pdu, NULL, "Network PDU");
    /* Check length >= , if not error packet */
    /* First byte in plaintext */
    /* IVI 1 bit Least significant bit of IV Index */
    proto_tree_add_item(sub_tree, hf_btmesh_ivi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_btmesh_nid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    de_obf_tvb = btmesh_network_find_key_and_decrypt(tvb, pinfo, &decrypted_data, &enc_data_len, MESH_NONCE_TYPE_NETWORK);

    if (de_obf_tvb) {
        add_new_data_source(pinfo, de_obf_tvb, "Deobfuscated data");

        gboolean cntrl;

        /* CTL 1 bit Network Control*/
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_ctl, de_obf_tvb, 0, 1, ENC_BIG_ENDIAN, &net_mic_size);
        /* 32 or 64 bits ( 0 or 1 )*/
        cntrl = net_mic_size;
        net_mic_size = (net_mic_size + 1) * 4;
        /* The TTL field is a 7-bit field */
        proto_tree_add_item(sub_tree, hf_btmesh_ttl, de_obf_tvb, 0, 1, ENC_BIG_ENDIAN);

        /* SEQ field is a 24-bit integer */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_seq, de_obf_tvb, 1, 3, ENC_BIG_ENDIAN, &seq);

        /* SRC field is a 16-bit value */
        proto_tree_add_item_ret_uint(sub_tree, hf_btmesh_src, de_obf_tvb, 4, 2, ENC_BIG_ENDIAN, &src);
        offset += 6;

        de_cry_tvb = tvb_new_child_real_data(tvb, decrypted_data, enc_data_len, enc_data_len);
        add_new_data_source(pinfo, de_cry_tvb, "Decrypted data");

        decry_off = 0;
        proto_tree_add_item(sub_tree, hf_btmesh_dst, de_cry_tvb, decry_off, 2, ENC_BIG_ENDIAN);
        decry_off += 2;
        /* TransportPDU */
        proto_tree_add_item(sub_tree, hf_btmesh_transp_pdu, de_cry_tvb, decry_off, enc_data_len-2, ENC_NA);
        offset += enc_data_len;

        proto_tree_add_item(sub_tree, hf_btmesh_netmic, tvb, offset, net_mic_size, ENC_BIG_ENDIAN);
        offset += net_mic_size;

        if (de_cry_tvb) {
            dissect_btmesh_transport_pdu(de_cry_tvb, pinfo, netw_tree, cntrl, src);
        }
    } else {
        proto_tree_add_item(sub_tree, hf_btmesh_obfuscated, tvb, offset, 6, ENC_NA);
        offset += 6;

        proto_tree_add_item(sub_tree, hf_btmesh_encrypted, tvb, offset, -1, ENC_NA);
        offset = tvb_reported_length(tvb);
    }

    return offset;
}

#else /* GCRYPT_VERSION_NUMBER >= 0x010600 */

static gboolean
create_master_security_keys(uat_btmesh_record_t * net_key_set _U_)
{
    return TRUE;
}

/* Stub dissector if decryption not available on build system */
static gint
dissect_btmesh_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BT Mesh");
    col_clear(pinfo->cinfo, COL_INFO);

    item = proto_tree_add_item(tree, proto_btmesh, tvb, offset, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(item, ett_btmesh);

    /* First byte in plaintext */
    /* IVI 1 bit Least significant bit of IV Index */
    proto_tree_add_item(sub_tree, hf_btmesh_ivi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(sub_tree, hf_btmesh_nid, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(sub_tree, hf_btmesh_obfuscated, tvb, offset, 6, ENC_NA);
    offset += 6;

    proto_tree_add_item(sub_tree, hf_btmesh_encrypted, tvb, offset, -1, ENC_NA);

    return tvb_reported_length(tvb);
}

#endif /* GCRYPT_VERSION_NUMBER >= 0x010600 */

static gint
compute_ascii_key(guchar **ascii_key, const gchar *key)
{
    guint key_len = 0, raw_key_len;
    gint hex_digit;
    guchar key_byte;
    guint i, j;

    if (key != NULL)
    {
        raw_key_len = (guint)strlen(key);
        if ((raw_key_len > 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
        {
            /*
             * Key begins with "0x" or "0X"; skip that and treat the rest
             * as a sequence of hex digits.
             */
            i = 2;    /* first character after "0[Xx]" */
            j = 0;
            if (raw_key_len % 2 == 1)
            {
                /*
                 * Key has an odd number of characters; we act as if the
                 * first character had a 0 in front of it, making the
                 * number of characters even.
                 */
                key_len = (raw_key_len - 2) / 2 + 1;
                *ascii_key = (gchar *)g_malloc((key_len + 1) * sizeof(gchar));
                hex_digit = g_ascii_xdigit_value(key[i]);
                i++;
                if (hex_digit == -1)
                {
                    g_free(*ascii_key);
                    *ascii_key = NULL;
                    return -1;    /* not a valid hex digit */
                }
                (*ascii_key)[j] = (guchar)hex_digit;
                j++;
            }
            else
            {
                /*
                 * Key has an even number of characters, so we treat each
                 * pair of hex digits as a single byte value.
                 */
                key_len = (raw_key_len - 2) / 2;
                *ascii_key = (gchar *)g_malloc((key_len + 1) * sizeof(gchar));
            }

            while (i < (raw_key_len - 1))
            {
                hex_digit = g_ascii_xdigit_value(key[i]);
                i++;
                if (hex_digit == -1)
                {
                    g_free(*ascii_key);
                    *ascii_key = NULL;
                    return -1;    /* not a valid hex digit */
                }
                key_byte = ((guchar)hex_digit) << 4;
                hex_digit = g_ascii_xdigit_value(key[i]);
                i++;
                if (hex_digit == -1)
                {
                    g_free(*ascii_key);
                    *ascii_key = NULL;
                    return -1;    /* not a valid hex digit */
                }
                key_byte |= (guchar)hex_digit;
                (*ascii_key)[j] = key_byte;
                j++;
            }
            (*ascii_key)[j] = '\0';
        }

        else if ((raw_key_len == 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
        {
            return 0;
        }
        else
        {
            key_len = raw_key_len;
            *ascii_key = g_strdup(key);
        }
    }

    return key_len;
}

static gboolean
uat_btmesh_record_update_cb(void *r, char **err _U_)
{
    uat_btmesh_record_t *rec = (uat_btmesh_record_t *)r;

    /* Compute keys & lengths once and for all */
    if (rec->network_key_string) {
        g_free(rec->network_key);
        rec->network_key_length = compute_ascii_key(&rec->network_key, rec->network_key_string);
        g_free(rec->encryptionkey);
        rec->encryptionkey = (guint8 *)g_malloc(16 * sizeof(guint8));
        g_free(rec->privacykey);
        rec->privacykey = (guint8 *)g_malloc(16 * sizeof(guint8));
        create_master_security_keys(rec);
    }
    else {
        rec->network_key_length = 0;
        rec->network_key = NULL;
    }
    if (rec->ivindex_string) {
        g_free(rec->ivindex);
        rec->ivindex_string_length = compute_ascii_key(&rec->ivindex, rec->ivindex_string);
    }
    return TRUE;
}

static void *
uat_btmesh_record_copy_cb(void *n, const void *o, size_t siz _U_)
{
    uat_btmesh_record_t *new_rec = (uat_btmesh_record_t *)n;
    const uat_btmesh_record_t* old_rec = (const uat_btmesh_record_t *)o;

    /* Copy UAT fields */
    new_rec->network_key_string = g_strdup(old_rec->network_key_string);
    new_rec->ivindex_string = g_strdup(old_rec->ivindex_string);

    /* Parse keys as in an update */
    uat_btmesh_record_update_cb(new_rec, NULL);

    return new_rec;
}

static void
uat_btmesh_record_free_cb(void *r)
{
    uat_btmesh_record_t *rec = (uat_btmesh_record_t *)r;

    g_free(rec->network_key_string);
    g_free(rec->network_key);
    g_free(rec->ivindex_string);
    g_free(rec->ivindex);
    g_free(rec->privacykey);
    g_free(rec->encryptionkey);
}

UAT_CSTRING_CB_DEF(uat_btmesh_records, network_key_string, uat_btmesh_record_t)
UAT_CSTRING_CB_DEF(uat_btmesh_records, ivindex_string, uat_btmesh_record_t)

void
proto_register_btmesh(void)
{
    static hf_register_info hf[] = {
        { &hf_btmesh_ivi,
            { "IVI", "btmesh.ivi",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_nid,
            { "NID", "btmesh.nid",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_obfuscated,
            { "Obfuscated", "btmesh.obfuscated",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_encrypted,
            { "Encrypted data and NetMIC", "btmesh.encrypted",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_netmic,
            { "NetMIC", "btmesh.netmic",
                FT_UINT64, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_ctl,
            { "CTL", "btmesh.ctl",
                FT_UINT8, BASE_DEC, VALS(btmesh_ctl_vals), 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_ttl,
            { "TTL", "btmesh.ttl",
                FT_UINT8, BASE_DEC, NULL, 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_seq,
            { "SEQ", "btmesh.seq",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_src,
            { "SRC", "btmesh.src",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_dst,
            { "DST", "btmesh.dst",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_transp_pdu,
            { "TransportPDU", "btmesh.transp_pdu",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_seg,
            { "SEG", "btmesh.cntr.seg",
                FT_UINT8, BASE_DEC, VALS(btmesh_ctrl_seg_vals), 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_acc_seg,
            { "SEG", "btmesh.acc.seg",
                FT_UINT8, BASE_DEC, VALS(btmesh_acc_seg_vals), 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_opcode,
            { "Opcode", "btmesh.cntr.opcode",
                FT_UINT8, BASE_DEC, VALS(btmesh_ctrl_opcode_vals), 0x7f,
                NULL, HFILL }
        },
        { &hf_btmesh_acc_akf,
            { "AKF", "btmesh.acc.akf",
                FT_UINT8, BASE_DEC, VALS(btmesh_acc_akf_vals), 0x40,
                NULL, HFILL }
        },
        { &hf_btmesh_acc_aid,
            { "AID", "btmesh.acc.aid",
                FT_UINT8, BASE_DEC, NULL, 0x3f,
                NULL, HFILL }
        },
        { &hf_btmesh_obo,
            { "OBO", "btmesh.obo",
                FT_BOOLEAN, 16, TFS(&btmesh_obo), 0x8000,
                NULL, HFILL }
        },
        { &hf_btmesh_seqzero,
            { "SeqZero", "btmesh.seqzero",
                FT_UINT16, BASE_DEC, NULL, 0x7ffc,
                NULL, HFILL }
        },
        { &hf_btmesh_rfu,
            { "Reserved for Future Use", "btmesh.rfu",
                FT_UINT16, BASE_DEC, NULL, 0x0003,
                NULL, HFILL }
        },
        { &hf_btmesh_blockack,
            { "BlockAck", "btmesh.blockack",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_rfu,
            { "RFU", "btmesh.cntr.criteria.rfu",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_padding,
            { "Padding", "btmesh.cntr.padding",
                FT_UINT8, BASE_DEC, NULL, 0xfe,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_fsn,
            { "Friend Sequence Number(FSN)", "btmesh.cntr.fsn",
                FT_UINT8, BASE_DEC, NULL, 0x01,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_key_refresh_flag,
            { "Key Refresh Flag", "btmesh.cntr.keyrefreshflag",
                FT_UINT8, BASE_DEC, VALS(btmesh_cntr_key_refresh_flag_vals), 0x01,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_iv_update_flag,
            { "IV Update Flag", "btmesh.cntr.ivupdateflag",
                FT_UINT8, BASE_DEC, VALS(btmesh_cntr_iv_update_flag_vals), 0x02,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_flags_rfu,
            { "IV Update Flag", "btmesh.cntr.flagsrfu",
                FT_UINT8, BASE_DEC, NULL, 0xFC,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_iv_index,
            { "IV Index", "btmesh.cntr.ivindex",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_md,
            { "MD (More Data)", "btmesh.cntr.md",
                FT_UINT8, BASE_DEC, VALS(btmesh_cntr_md_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_rssifactor,
            { "RSSIFactor", "btmesh.cntr.criteria.rssifactor",
                FT_UINT8, BASE_DEC, VALS(btmesh_criteria_rssifactor_vals), 0x60,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_receivewindowfactor,
            { "ReceiveWindowFactor", "btmesh.cntr.criteria.receivewindowfactor",
                FT_UINT8, BASE_DEC, VALS(btmesh_criteria_receivewindowfactor_vals), 0x18,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_criteria_minqueuesizelog,
            { "MinQueueSizeLog", "btmesh.cntr.criteria.minqueuesizelog",
                FT_UINT8, BASE_DEC, VALS(btmesh_criteria_minqueuesizelog_vals), 0x07,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_receivedelay,
            { "ReceiveDelay", "btmesh.cntr.receivedelay",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_polltimeout,
            { "PollTimeout", "btmesh.cntr.polltimeout",
                FT_UINT24, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_previousaddress,
            { "PreviousAddress", "btmesh.cntr.previousaddress",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_numelements,
            { "NumElements", "btmesh.cntr.numelements",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_lpncounter,
            { "LPNCounter", "btmesh.cntr.lpncounter",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_receivewindow,
            { "ReceiveWindow", "btmesh.cntr.receivewindow",
                FT_UINT8, BASE_DEC | BASE_UNIT_STRING, &units_milliseconds, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_queuesize,
            { "QueueSize", "btmesh.cntr.queuesize",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_subscriptionlistsize,
            { "SubscriptionListSize", "btmesh.cntr.subscriptionlistsize",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_rssi,
            { "RSSI", "btmesh.cntr.rssi",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_friendcounter,
            { "FriendCounter", "btmesh.cntr.friendcounter",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_lpnaddress,
            { "LPNAddress", "btmesh.cntr.lpnaddress",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_transactionnumber,
            { "TransactionNumber", "btmesh.cntr.transactionnumber",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_heartbeat_rfu,
            { "Reserved for Future Use", "btmesh.cntr.heartbeatrfu",
                FT_UINT8, BASE_DEC, NULL, 0x80,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_init_ttl,
            { "InitTTL", "btmesh.cntr.initttl",
                FT_UINT8, BASE_DEC, NULL, 0x7F,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_relay,
            { "Relay feature in use", "btmesh.cntr.feature.relay",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0001,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_proxy,
            { "Proxy feature in use", "btmesh.cntr.feature.proxy",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0002,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_friend,
            { "Friend feature in use", "btmesh.cntr.feature.friend",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0004,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_low_power,
            { "Low Power feature in use", "btmesh.cntr.feature.lowpower",
                FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x0008,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_feature_rfu,
            { "Reserved for Future Use", "btmesh.cntr.feature.rfu",
                FT_UINT16, BASE_DEC, NULL, 0xfff0,
                NULL, HFILL }
        },
        { &hf_btmesh_cntr_unknown_payload,
        { "Unknown Control Message payload", "btmesh.cntr.unknownpayload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_enc_access_pld,
        { "Encrypted Access Payload", "btmesh.enc_access_pld",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_transtmic,
        { "TransMIC", "btmesh.transtmic",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btmesh_szmic,
        { "SZMIC", "btmesh.szmic",
            FT_UINT24, BASE_DEC, VALS(btmesh_szmic_vals), 0x800000,
            NULL, HFILL }
        },
        { &hf_btmesh_seqzero_data,
        { "SeqZero", "btmesh.seqzero_data",
            FT_UINT24, BASE_DEC, NULL, 0x7ffc00,
            NULL, HFILL }
        },
        { &hf_btmesh_sego,
        { "Segment Offset number(SegO)", "btmesh.sego",
            FT_UINT24, BASE_DEC, NULL, 0x0003e0,
            NULL, HFILL }
        },
        { &hf_btmesh_segn,
        { "Last Segment number(SegN)", "btmesh.segn",
            FT_UINT24, BASE_DEC, NULL, 0x00001f,
            NULL, HFILL }
        },
        { &hf_btmesh_seg_rfu,
        { "RFU", "btmesh.seg.rfu",
            FT_UINT24, BASE_DEC, NULL, 0x800000,
            NULL, HFILL }
        },
        { &hf_btmesh_segment,
        { "Segment", "btmesh.segment",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        //Access Message Reassembly
        { &hf_btmesh_segmented_access_fragments,
            { "Reassembled Segmented Access Message Fragments", "btmesh.segmented.access.fragments",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Segmented Access Message Fragments", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment,
            { "Segmented Access Message Fragment", "btmesh.segmented.access.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_overlap,
            { "Fragment overlap", "btmesh.segmented.access.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "btmesh.segmented.access.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_multiple_tails,
            { "Multiple tail fragments found", "btmesh.segmented.access.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_too_long_fragment,
            { "Fragment too long", "btmesh.segmented.access.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_error,
            { "Defragmentation error", "btmesh.segmented.access.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_btmesh_segmented_access_fragment_count,
            { "Fragment count", "btmesh.segmented.access.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_access_reassembled_length,
            { "Reassembled Segmented Access Message length", "btmesh.segmented.access.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }
        },
        //Control Message Reassembly
        { &hf_btmesh_segmented_control_fragments,
            { "Reassembled Segmented Control Message Fragments", "btmesh.segmented.control.fragments",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "Segmented Access Message Fragments", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment,
            { "Segmented Control Message Fragment", "btmesh.segmented.control.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_overlap,
            { "Fragment overlap", "btmesh.segmented.control.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_overlap_conflict,
            { "Conflicting data in fragment overlap", "btmesh.segmented.control.fragment.overlap.conflict",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_multiple_tails,
            { "Multiple tail fragments found", "btmesh.segmented.control.fragment.multipletails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_too_long_fragment,
            { "Fragment too long", "btmesh.segmented.control.fragment.toolongfragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "Fragment contained data past end of packet", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_error,
            { "Defragmentation error", "btmesh.segmented.control.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0,
                "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_btmesh_segmented_control_fragment_count,
            { "Fragment count", "btmesh.segmented.control.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btmesh_segmented_control_reassembled_length,
            { "Reassembled Segmented Control Message length", "btmesh.segmented.control.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                "The total length of the reassembled payload", HFILL }
        },
    };

    static gint *ett[] = {
        &ett_btmesh,
        &ett_btmesh_net_pdu,
        &ett_btmesh_transp_pdu,
        &ett_btmesh_transp_ctrl_msg,
        &ett_btmesh_upper_transp_acc_pdu,
        &ett_btmesh_segmented_access_fragments,
        &ett_btmesh_segmented_access_fragment,
        &ett_btmesh_segmented_control_fragments,
        &ett_btmesh_segmented_control_fragment,
    };

    static ei_register_info ei[] = {
        { &ei_btmesh_not_decoded_yet,{ "btmesh.not_decoded_yet", PI_PROTOCOL, PI_NOTE, "Not decoded yet", EXPFILL } },
    };

    expert_module_t* expert_btmesh;

    module_t *btmesh_module;

    /* UAT defenitions */
    static uat_field_t btmesh_uat_flds[] = {
        UAT_FLD_CSTRING(uat_btmesh_records, network_key_string, "Network Key", "Network Key"),
        UAT_FLD_CSTRING(uat_btmesh_records, ivindex_string, "IVindex", "IVindex"),
        UAT_END_FIELDS
    };

    proto_btmesh = proto_register_protocol("Bluetooth Mesh", "BT Mesh", "btmesh");

    proto_register_field_array(proto_btmesh, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_btmesh = expert_register_protocol(proto_btmesh);
    expert_register_field_array(expert_btmesh, ei, array_length(ei));

    btmesh_module = prefs_register_protocol_subtree("Bluetooth", proto_btmesh, NULL);

    prefs_register_static_text_preference(btmesh_module, "version",
            "Bluetooth Mesh Profile v1.0",
            "Version of protocol supported by this dissector.");

    btmesh_uat = uat_new("BTMesh Network keys",
        sizeof(uat_btmesh_record_t),    /* record size */
        "btmesh_nw_keys",               /* filename */
        TRUE,                           /* from_profile */
        &uat_btmesh_records,            /* data_ptr */
        &num_btmesh_uat,                /* numitems_ptr */
        UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
        NULL,                           /* help */
        uat_btmesh_record_copy_cb,      /* copy callback */
        uat_btmesh_record_update_cb,    /* update callback */
        uat_btmesh_record_free_cb,      /* free callback */
        NULL,                           /* post update callback */
        NULL,                           /* reset callback */
        btmesh_uat_flds);               /* UAT field definitions */

    prefs_register_uat_preference(btmesh_module,
        "newtwork_key_table",
        "Network keys",
        "Preconfigured Network keys",
        btmesh_uat);

    register_dissector("btmesh.msg", dissect_btmesh_msg, proto_btmesh);

    register_init_routine(&upper_transport_init_routine);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
