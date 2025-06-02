/* packet-mka.c
 * Routines for EAPOL-MKA IEEE 802.1X-2010 / IEEE 802.1bx-2014 /
 * IEEE Std 802.1Xck-2018 / IEEE 802.1X-2020 MKPDU dissection
 * Copyright 2014, Hitesh K Maisheri <maisheri.hitesh@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/uat.h>

#include <wsutil/wsgcrypt.h>
#include <wsutil/ws_padding_to.h>

#include "packet-eapol.h"
#include "packet-mka.h"

#define WS_LOG_DOMAIN "MKA"

/*** UAT: CKN INFO ***/
#define DATAFILE_CKN_INFO "mka_ckn_info"

#define LIVE_PEER_LIST_TYPE          1
#define POTENTIAL_PEER_LIST_TYPE     2
#define MACSEC_SAK_USE_TYPE          3
#define DISTRIBUTED_SAK_TYPE         4
#define DISTRIBUTED_CAK_TYPE         5
#define KMD_TYPE                     6
#define ANNOUNCEMENT_TYPE            7
#define XPN_TYPE                     8
#define ICV_TYPE                     255

#define CIPHER_SUITE_LEN             8
#define AES_CMAC_LEN                 16
#define WRAPPED_KEY_IV_LEN           8
#define WRAPPED_KEY_LEN(kl)          ((kl) + WRAPPED_KEY_IV_LEN)

#define MKA_MAX_CKN_LEN              32

#define BASIC_PARAMSET_BODY_LENGTH   28
#define DISTRIBUTED_SAK_AES128_BODY_LEN 28
#define DISTRIBUTED_SAK_AES256_BODY_LEN 52

void proto_register_mka(void);
void proto_reg_handoff_mka(void);

static int proto_mka;

static int hf_mka_version_id;
static int hf_mka_basic_param_set;
static int hf_mka_live_peer_list_set;
static int hf_mka_potential_peer_list_set;
static int hf_mka_macsec_sak_use_set;
static int hf_mka_distributed_sak_set;
static int hf_mka_distributed_cak_set;
static int hf_mka_kmd_set;
static int hf_mka_announcement_set;
static int hf_mka_xpn_set;
static int hf_mka_unknown_set;
static int hf_mka_unknown_param_set;
static int hf_mka_icv_set;
static int hf_mka_param_set_type;

static int hf_mka_keyserver_priority;
static int hf_mka_key_server;
static int hf_mka_macsec_desired;
static int hf_mka_macsec_capability;
static int hf_mka_param_body_length;
static int hf_mka_sci;
static int hf_mka_actor_mi;
static int hf_mka_actor_mn;
static int hf_mka_algo_agility;
static int hf_mka_cak_name;
static int hf_mka_cak_name_info;

static int hf_mka_padding;

static int hf_mka_key_server_ssci;
static int hf_mka_peer_mi;
static int hf_mka_peer_mn;

static int hf_mka_latest_key_an;
static int hf_mka_latest_key_tx;
static int hf_mka_latest_key_rx;
static int hf_mka_old_key_an;
static int hf_mka_old_key_tx;
static int hf_mka_old_key_rx;
static int hf_mka_plain_tx;
static int hf_mka_plain_rx;
static int hf_mka_delay_protect;
static int hf_mka_latest_key_server_mi;
static int hf_mka_latest_key_number;
static int hf_mka_latest_lowest_acceptable_pn;
static int hf_mka_old_key_server_mi;
static int hf_mka_old_key_number;
static int hf_mka_old_lowest_acceptable_pn;

static int hf_mka_distributed_an;
static int hf_mka_confidentiality_offset;
static int hf_mka_key_number;
static int hf_mka_aes_key_wrap_sak;
static int hf_mka_aes_key_wrap_unwrapped_sak;
static int hf_mka_macsec_cipher_suite;
static int hf_mka_aes_key_wrap_cak;

static int hf_mka_kmd;

static int hf_mka_suspension_time;

static int hf_mka_icv;

static int hf_mka_tlv_entry;
static int hf_mka_tlv_type;
static int hf_mka_tlv_info_string_length;
static int hf_mka_tlv_data;
static int hf_mka_tlv_cipher_suite_impl_cap;

static expert_field ei_mka_undecoded;
static expert_field ei_unexpected_data;
static expert_field ei_mka_unimplemented;

static int ett_mka;
static int ett_mka_basic_param_set;
static int ett_mka_peer_list_set;
static int ett_mka_sak_use_set;
static int ett_mka_distributed_sak_set;
static int ett_mka_distributed_cak_set;
static int ett_mka_kmd_set;
static int ett_mka_announcement_set;
static int ett_mka_xpn_set;
static int ett_mka_unknown_set;
static int ett_mka_icv_set;
static int ett_mka_tlv;
static int ett_mka_cipher_suite_entry;

static const value_string param_set_type_vals[] = {
  { LIVE_PEER_LIST_TYPE,       "Live Peer List" },
  { POTENTIAL_PEER_LIST_TYPE,  "Potential Peer List" },
  { MACSEC_SAK_USE_TYPE,       "MACsec SAK Use" },
  { DISTRIBUTED_SAK_TYPE,      "Distributed SAK" },
  { DISTRIBUTED_CAK_TYPE,      "Distributed CAK" },
  { KMD_TYPE,                  "KMD" },
  { ANNOUNCEMENT_TYPE,         "Announcement" },
  { XPN_TYPE,                  "XPN" },
  { ICV_TYPE,                  "ICV Indicator" },
  { 0, NULL }
};

static const value_string macsec_capability_type_vals[] = {
  { 0,                     "MACsec not implemented" },
  { 1,                     "MACsec Integrity without confidentiality" },
  { 2,                     "MACsec Integrity with/without confidentiality, no confidentiality offset" },
  { 3,                     "MACsec Integrity with/without confidentiality, confidentiality offset 0, 30, or 50" },
  { 0, NULL }
};

static const value_string algo_agility_vals[] = {
  { 0x0080C201, "IEEE Std 802.1X-2010" },
  { 0, NULL }
};

static const value_string confidentiality_offset_vals[] = {
  { 0, "No confidentiality" },
  { 1, "No confidentiality offset" },
  { 2, "Confidentiality offset 30 octets" },
  { 3, "Confidentiality offset 50 octets" },
  { 0, NULL }
};

static const val64_string macsec_cipher_suite_vals[] = {
  { INT64_C(0x0080020001000001),           "GCM-AES-128" }, // Original, incorrect value in IEEE 802.1AE-2006 and IEEE 802.1X-2010
  { INT64_C(0x0080C20001000001),           "GCM-AES-128" },
  { INT64_C(0x0080C20001000002),           "GCM-AES-256" },
  { INT64_C(0x0080C20001000003),           "GCM-AES-XPN-128" },
  { INT64_C(0x0080C20001000004),           "GCM-AES-XPN-256" },
  { 0, NULL }
};


static const value_string macsec_tlvs[] = {
  // 0 - 110 reserved
  { 111, "Access Information" },
  { 112, "MACsec Cipher Suites" },
  { 113, "Key Management Domain" },
  { 114, "NID (Network Identifier)" },
  // 115 - 125 reserved
  { 126, "Organizationally Specific Set TLV" },
  { 127, "Organizationally Specific TLVs" },
  { 0, NULL }
};

static const char *mka_ckn_info_uat_defaults_[] = { NULL, "", "" };

static mka_ckn_info_t *mka_ckn_uat_data = NULL;
static unsigned num_mka_ckn_uat_data = 0;
static GHashTable *ht_mka_ckn = NULL;

UAT_BUFFER_CB_DEF(mka_ckn_uat_data, cak, mka_ckn_info_t, cak, cak_len)
UAT_BUFFER_CB_DEF(mka_ckn_uat_data, ckn, mka_ckn_info_t, ckn, ckn_len)
UAT_CSTRING_CB_DEF(mka_ckn_uat_data, name, mka_ckn_info_t)

/* Derive the ICK or KEK from the CAK and label. */
static unsigned
mka_derive_key(uint8_t * label, uint8_t *out, void * k) {
  mka_ckn_info_t *rec = (mka_ckn_info_t *)k;
  uint8_t *cak = (uint8_t *)rec->cak;
  uint8_t *ckn = (uint8_t *)rec->ckn;

  unsigned ckn_len = rec->ckn_len;
  unsigned cak_len = rec->cak_len;

  /* Build context. */
  /* Context is the first 16 bytes of the CAK name. */
  uint8_t context[16] = {0};
  memcpy(context, ckn, (ckn_len > 16) ? 16 : ckn_len);

  gcry_mac_hd_t hd;

  if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
    if (AES256_KEY_LEN == cak_len) {
        ws_debug("cak: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                        cak[0], cak[1], cak[2], cak[3], cak[4], cak[5], cak[6], cak[7],
                        cak[8], cak[9], cak[10], cak[11], cak[12], cak[13], cak[14], cak[15],
                        cak[16], cak[17], cak[18], cak[19], cak[20], cak[21], cak[22], cak[23],
                        cak[24], cak[25], cak[26], cak[27], cak[28], cak[29], cak[30], cak[31]);
    } else {
        ws_debug("cak: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                cak[0], cak[1], cak[2], cak[3], cak[4], cak[5], cak[6], cak[7],
                cak[8], cak[9], cak[10], cak[11], cak[12], cak[13], cak[14], cak[15]);
    }

    ws_debug("lbl: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    label[0], label[1], label[2], label[3], label[4], label[5], label[6], label[7],
                    label[8], label[9], label[10], label[11]);

    ws_debug("ctx: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    context[0], context[1], context[2], context[3], context[4], context[5], context[6], context[7],
                    context[8], context[9], context[10], context[11], context[12], context[13], context[14], context[15]);
  }

  /* Format input data for cmac.
     Input data length is (1 byte counter + 12 bytes label + 1 byte for 0x00 + 16 bytes for context + 2 bytes for length) = 32 */
  #define INPUT_DATA_LENGTH (1 + 12 + 1 + 16 + 2)
  uint8_t inputdata[INPUT_DATA_LENGTH];

  size_t clen = AES_CMAC_LEN;
  unsigned klen = cak_len * 8;
  unsigned iterations = cak_len / AES_CMAC_LEN;
  unsigned outlen = 0;

  for (unsigned i = 0; i < iterations; i++)
  {
    /* Open the cmac context. */
    if (gcry_mac_open(&hd, GCRY_MAC_CMAC_AES, 0, NULL)) {
      ws_warning("failed to open CMAC context");
      return 0;
    }

    /* Set key to use. */
    if (gcry_mac_setkey(hd, cak, cak_len)) {
      ws_warning("failed to set CMAC key");
      gcry_mac_close(hd);
      return 0;
    }

    inputdata[0] = (i + 1);               // Iteration
    memcpy(&inputdata[1], label, 12);     // Key label - must be 12 bytes
    inputdata[13] = 0x00;                 // Always 0x00
    memcpy(&inputdata[14], context, 16);  // Context data
    inputdata[30] = (klen & 0xFF00) >> 8; // MSB of key length in bits
    inputdata[31] = (klen & 0xFF);        // LSB of key length in bits

    /* Write the formatted input data to the CMAC. */
    if (gcry_mac_write(hd, inputdata, INPUT_DATA_LENGTH)) {
      ws_warning("failed CMAC write");
      gcry_mac_close(hd);
      return 0;
    }

    /* Read the CMAC result. */
    gcry_mac_read(hd, (out + (i * clen)), &clen);
    outlen += (unsigned)clen;

    /* Close the context. */
    gcry_mac_close(hd);
  }

  if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
    if (AES256_KEY_LEN == cak_len) {
      ws_debug("key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                      out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
                      out[8], out[9], out[10], out[11], out[12], out[13], out[14], out[15],
                      out[16], out[17], out[18], out[19], out[20], out[21], out[22], out[23],
                      out[24], out[25], out[26], out[27], out[28], out[29], out[30], out[31]);
    } else {
        ws_debug("key: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7],
                out[8], out[9], out[10], out[11], out[12], out[13], out[14], out[15]);
    }
  }

  return outlen;
}

static void
mka_derive_kek(void * k) {
  mka_ckn_info_t *rec = (mka_ckn_info_t *)k;

  uint8_t *label = "IEEE8021 KEK";
  rec->key.kek_len = mka_derive_key(label, rec->key.kek, rec);
}

static void
mka_derive_ick(void * k) {
  mka_ckn_info_t *rec = (mka_ckn_info_t *)k;

  uint8_t *label = "IEEE8021 ICK";
  rec->key.kek_len = mka_derive_key(label, rec->key.kek, rec);
}

static unsigned
ckn_key_hash_func(const void *k) {
  const mka_ckn_info_t *rec = (const mka_ckn_info_t *)k;
  size_t i;
  unsigned hash = 0;
  uint8_t *tmp = (uint8_t *)rec->ckn;

  /* Reduce to uint32_t by XOR */
  for (i = 0; i < rec->ckn_len; i++) {
    hash ^= tmp[i] << 8 * (i % 4);
  }

  return hash;
}

static int
ckn_key_equal_func(const void *c1, const void *c2) {
  const mka_ckn_info_t *ckn1 = (const mka_ckn_info_t *)c1;
  const mka_ckn_info_t *ckn2 = (const mka_ckn_info_t *)c2;
  if (ckn1->ckn_len != ckn2->ckn_len) return 0;
  if (memcmp(ckn1->ckn, ckn2->ckn, ckn1->ckn_len) != 0) return 0;

  return 1;
}

static void *
ckn_info_copy_cb(void *n, const void *o, size_t size _U_) {
  mka_ckn_info_t       *new_rec = (mka_ckn_info_t *)n;
  const mka_ckn_info_t *old_rec = (const mka_ckn_info_t *)o;

  new_rec->cak = (unsigned char *)g_memdup2(old_rec->cak, old_rec->cak_len);
  new_rec->cak_len = old_rec->cak_len;
  new_rec->ckn = (unsigned char *)g_memdup2(old_rec->ckn, old_rec->ckn_len);
  new_rec->ckn_len = old_rec->ckn_len;
  new_rec->name = g_strdup(old_rec->name);

  return new_rec;
}

static bool
ckn_info_update_cb(void *r, char **err) {
  mka_ckn_info_t *rec = (mka_ckn_info_t *)r;

  if ((0 != rec->cak_len) && ((AES128_KEY_LEN != rec->cak_len) && (AES256_KEY_LEN != rec->cak_len))) {
    *err = ws_strdup("Invalid CAK length! CAKs need to be 16 or 32 bytes when specified.");
    return false;
  }

  if ((0 == rec->ckn_len) || (rec->ckn_len > 32)) {
    *err = ws_strdup("Invalid CKN length! CKNs need to be between 1 and 32 bytes.");
    return false;
  }

  if (0 == strlen(rec->name)) {
    *err = ws_strdup("Missing name! A name must be specified for this CAK/CKN entry.");
    return false;
  }

  return true;
}

static void
ckn_info_free_cb(void *r) {
  mka_ckn_info_t *rec = (mka_ckn_info_t *)r;

  g_free(rec->cak);
  g_free(rec->ckn);
  g_free(rec->name);
}

static void
ckn_info_reset_cb(void) {
  if (NULL != ht_mka_ckn) {
    g_hash_table_destroy(ht_mka_ckn);
    ht_mka_ckn = NULL;
  }
}

static void
ckn_info_post_update_cb(void) {
  unsigned i;

  ckn_info_reset_cb();

  ht_mka_ckn = g_hash_table_new(&ckn_key_hash_func, &ckn_key_equal_func);

  for (i = 0; i < num_mka_ckn_uat_data; i++) {
    /* Derive the KEK and ICK and store with the CAK/CKN for this table entry. */
    ws_info("deriving ICK for CKN table entry %u (%s)", i, mka_ckn_uat_data[i].name);
    mka_derive_ick(&(mka_ckn_uat_data[i]));

    ws_info("deriving KEK for CKN table entry %u (%s)", i, mka_ckn_uat_data[i].name);
    mka_derive_kek(&(mka_ckn_uat_data[i]));

    g_hash_table_insert(ht_mka_ckn, &(mka_ckn_uat_data[i]), &(mka_ckn_uat_data[i]));
  }
}


/* Find a table entry for the given CKN string */
static mka_ckn_info_t *
ckn_info_lookup(uint8_t ckn[], uint32_t ckn_len) {
  mka_ckn_info_t tmp_key = { .ckn = ckn, .ckn_len = ckn_len };

  if (ht_mka_ckn == NULL) {
    ws_debug("No hash table");
    return NULL;
  }

  return (mka_ckn_info_t *)g_hash_table_lookup(ht_mka_ckn, &tmp_key);
}

/* Get the entire table's contents. */
const mka_ckn_info_t *
get_mka_ckn_table(void) {
  return (const mka_ckn_info_t *)mka_ckn_uat_data;
}

/* Get the size of the table. */
unsigned
get_mka_ckn_table_count(void) {
  return num_mka_ckn_uat_data;
}

static void
mka_add_ckn_info(proto_tree *tree, tvbuff_t *tvb, int offset, uint16_t ckn_len) {
  proto_item *ti;

  uint8_t ckn[MKA_MAX_CKN_LEN]; /* Only accept CKN between 1 and 32 bytes! */
  if (1 <= ckn_len && ckn_len <= MKA_MAX_CKN_LEN) {
    tvb_memcpy(tvb, ckn, offset, ckn_len);

    const mka_ckn_info_t *rec = ckn_info_lookup(ckn, ckn_len);
    if (rec != NULL) {
      ti = proto_tree_add_string(tree, hf_mka_cak_name_info, tvb, offset, ckn_len, rec->name);
      proto_item_set_generated(ti);
    }
  }
}


static void
dissect_basic_paramset(proto_tree *mka_tree, packet_info *pinfo, tvbuff_t *tvb, int *offset_ptr) {
  int offset = *offset_ptr;
  proto_tree *basic_param_set_tree;
  proto_item *ti;
  uint16_t basic_param_set_len;
  uint16_t ckn_len;

  basic_param_set_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_basic_param_set, tvb, offset, basic_param_set_len + 4, ENC_NA);
  basic_param_set_tree = proto_item_add_subtree(ti, ett_mka_basic_param_set);

  proto_tree_add_item(basic_param_set_tree, hf_mka_version_id, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(basic_param_set_tree, hf_mka_keyserver_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(basic_param_set_tree, hf_mka_key_server, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(basic_param_set_tree, hf_mka_macsec_desired, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(basic_param_set_tree, hf_mka_macsec_capability, tvb, offset, 1, ENC_BIG_ENDIAN);

  if (tvb_get_uint8(tvb, offset) & 0x80)
  {
    col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Key Server");
  }

  proto_tree_add_uint(basic_param_set_tree, hf_mka_param_body_length, tvb, offset, 2, basic_param_set_len);
  offset += 2;

  proto_tree_add_item(basic_param_set_tree, hf_mka_sci, tvb, offset, 8, ENC_NA);
  offset += 8;

  proto_tree_add_item(basic_param_set_tree, hf_mka_actor_mi, tvb, offset, 12, ENC_NA);
  offset += 12;

  proto_tree_add_item(basic_param_set_tree, hf_mka_actor_mn, tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(basic_param_set_tree, hf_mka_algo_agility, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  ckn_len = basic_param_set_len - BASIC_PARAMSET_BODY_LENGTH;
  proto_tree_add_item(basic_param_set_tree, hf_mka_cak_name, tvb, offset, ckn_len, ENC_NA);

  mka_add_ckn_info(basic_param_set_tree, tvb, offset, ckn_len);

  /* initialize the private_info hash if not already initialized */
  if (NULL == pinfo->private_table) {
      pinfo->private_table = g_hash_table_new(g_str_hash, g_str_equal);
  }

  /* look up the CAK/CKN in the CKN table, and add a private hash table entry if it does not yet exist there */
  const uint8_t *ckn = tvb_memdup(NULL, tvb, offset, ckn_len);
  if (NULL != ckn) {
    mka_ckn_info_t *rec = ckn_info_lookup((uint8_t *)ckn, ckn_len);
    if (NULL != rec) {
      /* add the record to the private hash table for this packet to tell ourselves about the CKN and its keys later on */
      g_hash_table_insert(pinfo->private_table, "ckn", rec);
    }

    g_free((void *)ckn);
  }

  offset += ckn_len;

  unsigned padding_len = WS_PADDING_TO_4(basic_param_set_len);
  if (padding_len != 0) {
    proto_tree_add_item(basic_param_set_tree, hf_mka_padding, tvb, offset, padding_len, ENC_NA);

    offset += padding_len;
  }

  *offset_ptr = offset;
}

static void
dissect_peer_list(proto_tree *mka_tree, packet_info *pinfo, tvbuff_t *tvb, int *offset_ptr, bool key_server_ssci_flag) {
  int offset = *offset_ptr;
  proto_tree *peer_list_set_tree;
  proto_item *ti;
  int hf_peer;
  int16_t peer_list_len;

  if (tvb_get_uint8(tvb, offset) == LIVE_PEER_LIST_TYPE) {
    hf_peer = hf_mka_live_peer_list_set;
  } else {
    hf_peer = hf_mka_potential_peer_list_set;
  }

  peer_list_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_peer, tvb, offset, peer_list_len + 4, ENC_NA);
  peer_list_set_tree = proto_item_add_subtree(ti, ett_mka_peer_list_set);

  proto_tree_add_item(peer_list_set_tree, hf_mka_param_set_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (key_server_ssci_flag && (hf_peer == hf_mka_live_peer_list_set))
  {
    /* XXX - The presence of this field is non-trivial to find out. See IEEE 802.1X-2020, Section 11.11.3
     * Only present in MKPDU's with:
     * - MKA version 3 (that's covered), and
     * - In Live Peer list parameter set (that's covered), and
     * - A Distributed SAK parameter set present (which could be before or after this parameter set), but only
     * - A Distributed SAK parameter set with XPN Cipher suites (requires to look into the contents),
     * otherwise 0.
     */
    proto_tree_add_item(peer_list_set_tree, hf_mka_key_server_ssci, tvb, offset, 1, ENC_BIG_ENDIAN);
  }

  offset += 1;

  proto_tree_add_uint(peer_list_set_tree, hf_mka_param_body_length, tvb, offset, 2, peer_list_len);
  offset += 2;

  while (peer_list_len >= 16) {
    proto_tree_add_item(peer_list_set_tree, hf_mka_peer_mi, tvb, offset, 12, ENC_NA);
    offset += 12;

    proto_tree_add_item(peer_list_set_tree, hf_mka_peer_mn, tvb, offset, 4, ENC_NA);
    offset += 4;

    peer_list_len -= 16;
  }

  if (peer_list_len != 0) {
    proto_tree_add_expert(peer_list_set_tree, pinfo, &ei_mka_undecoded, tvb, offset, peer_list_len);
    offset += peer_list_len;
  }

  *offset_ptr = offset;
}

static void
dissect_sak_use(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr) {
  int offset = *offset_ptr;
  proto_tree *sak_use_set_tree;
  proto_item *ti;
  uint16_t sak_use_len;

  sak_use_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_macsec_sak_use_set, tvb, offset, sak_use_len + 4, ENC_NA);
  sak_use_set_tree = proto_item_add_subtree(ti, ett_mka_sak_use_set);

  proto_tree_add_item(sak_use_set_tree, hf_mka_param_set_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(sak_use_set_tree, hf_mka_latest_key_an, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_latest_key_tx, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_latest_key_rx, tvb, offset, 1, ENC_BIG_ENDIAN);

  proto_tree_add_item(sak_use_set_tree, hf_mka_old_key_an, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_old_key_tx, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_old_key_rx, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(sak_use_set_tree, hf_mka_plain_tx, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_plain_rx, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(sak_use_set_tree, hf_mka_delay_protect, tvb, offset, 1, ENC_BIG_ENDIAN);

  proto_tree_add_uint(sak_use_set_tree, hf_mka_param_body_length, tvb, offset, 2, sak_use_len);
  offset += 2;

  /*
   * 802.1X-2020 specifies only 0 or 40 are valid! See Figure 11-10 Note d
   */
  if (sak_use_len == 0) /* MACsec not supported */
  {
    /* Nothing */
  }
  else if (sak_use_len == 40) /* MACsec supported */
  {
    proto_tree_add_item(sak_use_set_tree, hf_mka_latest_key_server_mi, tvb, offset, 12, ENC_NA);
    offset += 12;

    proto_tree_add_item(sak_use_set_tree, hf_mka_latest_key_number, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(sak_use_set_tree, hf_mka_latest_lowest_acceptable_pn, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(sak_use_set_tree, hf_mka_old_key_server_mi, tvb, offset, 12, ENC_NA);
    offset += 12;

    proto_tree_add_item(sak_use_set_tree, hf_mka_old_key_number, tvb, offset, 4, ENC_NA);
    offset += 4;

    proto_tree_add_item(sak_use_set_tree, hf_mka_old_lowest_acceptable_pn, tvb, offset, 4, ENC_NA);
    offset += 4;
  }
  else
  {
    proto_tree_add_expert(sak_use_set_tree, pinfo, &ei_mka_undecoded, tvb, offset, sak_use_len);
    offset += sak_use_len;
  }

  *offset_ptr = offset;
}

static void
dissect_distributed_sak(proto_tree *mka_tree, packet_info *pinfo, tvbuff_t *tvb, int *offset_ptr) {
  int offset = *offset_ptr;
  uint16_t distributed_sak_len;
  proto_tree *distributed_sak_tree;
  proto_item *ti;
  unsigned padding_len;

  distributed_sak_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_distributed_sak_set, tvb, offset, distributed_sak_len + 4, ENC_NA);
  distributed_sak_tree = proto_item_add_subtree(ti, ett_mka_distributed_sak_set);

  proto_tree_add_item(distributed_sak_tree, hf_mka_param_set_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  /* distributed AN is used later if use of MKA is enabled */
  uint8_t distributed_an = ((tvb_get_uint8(tvb, offset) & 0xC0) >> 6);

  proto_tree_add_item(distributed_sak_tree, hf_mka_distributed_an, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(distributed_sak_tree, hf_mka_confidentiality_offset, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_uint(distributed_sak_tree, hf_mka_param_body_length, tvb, offset, 2, distributed_sak_len);
  offset += 2;

  if (distributed_sak_len == 0) // Plain text
  {
      // Nothing
  }
  else if ((DISTRIBUTED_SAK_AES128_BODY_LEN == distributed_sak_len) || (DISTRIBUTED_SAK_AES256_BODY_LEN == distributed_sak_len)) { // GCM-AES-128, GCM-AES-256
    uint16_t wrappedlen = WRAPPED_KEY_LEN(AES128_KEY_LEN);

    proto_tree_add_item(distributed_sak_tree, hf_mka_key_number, tvb, offset, 4, ENC_NA);
    offset += 4;

    /* For AES256, the wrapped key is longer and an 8 byte cipher suite is inserted before the wrapped key data. */
    if (distributed_sak_len == DISTRIBUTED_SAK_AES256_BODY_LEN) {
      wrappedlen = WRAPPED_KEY_LEN(AES256_KEY_LEN);

      proto_tree_add_item(distributed_sak_tree, hf_mka_macsec_cipher_suite, tvb, offset, CIPHER_SUITE_LEN, ENC_NA);
      offset += CIPHER_SUITE_LEN;
    }

    /* Add the wrapped key data. */
    const uint8_t *wrappedkey = tvb_get_ptr(tvb, offset, wrappedlen);
    proto_tree_add_item(distributed_sak_tree, hf_mka_aes_key_wrap_sak, tvb, offset, wrappedlen, ENC_NA);
    offset += wrappedlen;

    /* Attempt to unwrap the key using the KEK for the CKN. */
    /* Fetch the KEK for the CKN in the basic parameter set. */
    if (NULL != pinfo->private_table) {
      mka_ckn_info_t *rec = g_hash_table_lookup(pinfo->private_table, "ckn");
      if (NULL == rec) {
        ws_info("no record for CKN");
        goto out;
      }

      /* Look up the CKN and if found in the table, use the KEK associated with it. */
      ws_debug("CKN entry name: %s", rec->name);

      /* If no KEK available, skip the decode. */
      mka_ckn_info_key_t *key = &(rec->key);
      if ((NULL == key) || (0 == key->kek_len)) {
        goto out;
      }

      /* Open the cipher context. */
      gcry_cipher_hd_t hd;
      if (gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_AESWRAP, 0)) {
        ws_warning("failed to open cipher context");
        goto out;
      }

      if (gcry_cipher_setkey(hd, key->kek, key->kek_len)) {
          ws_warning("failed to set KEK");
          gcry_cipher_close(hd);
          goto out;
      }

      /* Unwrap the key with the KEK. */
      uint8_t *sak = key->saks[distributed_an];
      if (gcry_cipher_decrypt(hd, sak, key->kek_len, wrappedkey, (key->kek_len + 8)) ) {
        ws_info("failed to unwrap SAK");
        memset(sak, 0, MKA_MAX_SAK_LEN);
        gcry_cipher_close(hd);
        goto out;
      }

      /* Close the cipher context. */
      gcry_cipher_close(hd);

      if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
        if (AES256_KEY_LEN == key->kek_len) {
          ws_debug("unwrapped sak: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                          sak[0], sak[1], sak[2], sak[3], sak[4], sak[5], sak[6], sak[7],
                          sak[8], sak[9], sak[10], sak[11], sak[12], sak[13], sak[14], sak[15],
                          sak[16], sak[17], sak[18], sak[19], sak[20], sak[21], sak[22], sak[23],
                          sak[24], sak[25], sak[26], sak[27], sak[28], sak[29], sak[30], sak[31]);
        } else {
            ws_debug("unwrapped sak: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    sak[0], sak[1], sak[2], sak[3], sak[4], sak[5], sak[6], sak[7],
                    sak[8], sak[9], sak[10], sak[11], sak[12], sak[13], sak[14], sak[15]);
        }
      }

      /* Add the unwrapped SAK to the output. */
      proto_tree_add_bytes_with_length(distributed_sak_tree, hf_mka_aes_key_wrap_unwrapped_sak, tvb, offset, 0, sak, key->kek_len);  //works, no highlights
    }
  }
  else
  {
    proto_tree_add_expert(distributed_sak_tree, pinfo, &ei_mka_undecoded, tvb, offset, distributed_sak_len);
    offset += distributed_sak_len;
  }

out:
  padding_len = WS_PADDING_TO_4(distributed_sak_len);
  if (padding_len != 0) {
    proto_tree_add_item(distributed_sak_tree, hf_mka_padding, tvb, offset, padding_len, ENC_NA);

    offset += padding_len;
  }

  *offset_ptr = offset;
}

static void
dissect_distributed_cak(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr) {
  int offset = *offset_ptr;
  uint16_t distributed_cak_len;
  proto_tree *distributed_cak_tree;
  proto_item *ti;
  uint16_t cak_len;

  distributed_cak_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_distributed_cak_set, tvb, offset, distributed_cak_len + 4, ENC_NA);
  distributed_cak_tree = proto_item_add_subtree(ti, ett_mka_distributed_cak_set);

  proto_tree_add_item(distributed_cak_tree, hf_mka_param_set_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(distributed_cak_tree, hf_mka_param_body_length, tvb, offset, 2, distributed_cak_len);
  offset += 2;

  proto_tree_add_item(distributed_cak_tree, hf_mka_aes_key_wrap_cak, tvb, offset, 24, ENC_NA);
  offset += 24;

  cak_len = distributed_cak_len - 24;
  proto_tree_add_item(distributed_cak_tree, hf_mka_cak_name, tvb, offset, cak_len, ENC_NA);
  mka_add_ckn_info(distributed_cak_tree, tvb, offset, cak_len);
  offset += cak_len;

  unsigned padding_len = WS_PADDING_TO_4(distributed_cak_len);
  if (padding_len != 0) {
    proto_tree_add_item(distributed_cak_tree, hf_mka_padding, tvb, offset, padding_len, ENC_NA);

    offset += padding_len;
  }

  *offset_ptr = offset;
}

static void
dissect_kmd(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr)
{
  int offset = *offset_ptr;
  uint16_t kmd_len;
  proto_tree *kmd_set_tree;
  proto_item *ti;

  kmd_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_kmd_set, tvb, offset, kmd_len + 4, ENC_NA);
  kmd_set_tree = proto_item_add_subtree(ti, ett_mka_kmd_set);

  proto_tree_add_item(kmd_set_tree, hf_mka_param_set_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(kmd_set_tree, hf_mka_param_body_length, tvb, offset, 2, kmd_len);
  offset += 2;

  proto_tree_add_item(kmd_set_tree, hf_mka_kmd, tvb, offset, kmd_len, ENC_NA);
  offset += kmd_len;

  *offset_ptr = offset;
}

static void
dissect_announcement(proto_tree *mka_tree, packet_info *pinfo, tvbuff_t *tvb, int *offset_ptr) {
  int offset = *offset_ptr;
  uint16_t announcement_len;
  proto_tree *announcement_set_tree;
  proto_item *ti;
  int offset2;

  announcement_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_announcement_set, tvb, offset, announcement_len + 4, ENC_NA);
  announcement_set_tree = proto_item_add_subtree(ti, ett_mka_announcement_set);

  proto_tree_add_item(announcement_set_tree, hf_mka_param_set_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(announcement_set_tree, hf_mka_param_body_length, tvb, offset, 2, announcement_len);
  offset += 2;

  offset2 = 0;
  while (offset2 + 2 <= announcement_len) {
    proto_tree *tlv_tree;
    uint8_t tlv_type = ((tvb_get_uint8(tvb, offset + offset2)) & 0xfe ) >> 1;
    uint16_t tlv_length = (tvb_get_ntohs(tvb, offset + offset2)) & 0x01ff;
    uint16_t tlv_item_offset;

    if (offset2 + 2 + tlv_length > announcement_len) {
      break;
    }

    ti = proto_tree_add_none_format(announcement_set_tree, hf_mka_tlv_entry, tvb, offset + offset2, tlv_length + 2, "TLV entry: %s",
                                    val_to_str(tlv_type, macsec_tlvs, "unknown TLV type: %d"));
    tlv_tree = proto_item_add_subtree(ti, ett_mka_tlv);

    proto_tree_add_item(tlv_tree, hf_mka_tlv_type, tvb, offset + offset2, 1, ENC_NA);
    proto_tree_add_item(tlv_tree, hf_mka_tlv_info_string_length, tvb, offset + offset2, 2, ENC_NA);
    offset2 += 2;

    if (tlv_length > 0) {
      switch (tlv_type) {
      case 112: // MACsec Cipher Suites
        tlv_item_offset = 0;
        while (tlv_item_offset + 10 <= tlv_length) {
          proto_tree *cipher_suite_entry;
          uint64_t cipher_suite_id = tvb_get_uint64(tvb, offset + offset2 + tlv_item_offset + 2, ENC_BIG_ENDIAN);
          uint16_t cipher_suite_cap = tvb_get_uint16(tvb, offset + offset2 + tlv_item_offset, ENC_BIG_ENDIAN) & 0x0003;

          ti = proto_tree_add_none_format(tlv_tree, hf_mka_tlv_entry, tvb, offset + offset2, tlv_length + 2, "Cipher Suite: %s, %s",
                                          val64_to_str(cipher_suite_id, macsec_cipher_suite_vals, "Unknown Cipher Suite (0x%" PRIx64 ")"),
                                          val_to_str(cipher_suite_cap, macsec_capability_type_vals, "Unknown Capability (%d)"));
          cipher_suite_entry = proto_item_add_subtree(ti, ett_mka_cipher_suite_entry);

          proto_tree_add_item(cipher_suite_entry, hf_mka_tlv_cipher_suite_impl_cap, tvb, offset + offset2 + tlv_item_offset, 2, ENC_NA);
          tlv_item_offset += 2;
          proto_tree_add_item(cipher_suite_entry, hf_mka_macsec_cipher_suite, tvb, offset + offset2 + tlv_item_offset, 8, ENC_NA);
          tlv_item_offset += 8;
        }
        break;

      case 111: // Access Information
      case 113: // Key Management Domain
      case 114: // NID (Network Identifier)
        // See IEEE 802.1X-2010, Section 11.11.1, Figure 11-15 and Section 11.12
        proto_tree_add_expert(tlv_tree, pinfo, &ei_mka_unimplemented, tvb, offset + offset2, tlv_length);
        proto_tree_add_item(tlv_tree, hf_mka_tlv_data, tvb, offset + offset2, tlv_length, ENC_NA);
        break;

      default:
        proto_tree_add_item(tlv_tree, hf_mka_tlv_data, tvb, offset + offset2, tlv_length, ENC_NA);
      }
      offset2 += tlv_length;
    }
  }

  offset += announcement_len;

  unsigned padding_len = WS_PADDING_TO_4(announcement_len);
  if (padding_len != 0) {
    proto_tree_add_item(announcement_set_tree, hf_mka_padding, tvb, offset, padding_len, ENC_NA);
    offset += padding_len;
  }

  *offset_ptr = offset;
}

static void
dissect_xpn(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr) {
  int offset = *offset_ptr;
  uint16_t xpn_len;
  proto_tree *xpn_set_tree;
  proto_item *ti;

  xpn_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_xpn_set, tvb, offset, xpn_len + 4, ENC_NA);
  xpn_set_tree = proto_item_add_subtree(ti, ett_mka_xpn_set);

  proto_tree_add_item(xpn_set_tree, hf_mka_param_set_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  proto_tree_add_item(xpn_set_tree, hf_mka_suspension_time, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_uint(xpn_set_tree, hf_mka_param_body_length, tvb, offset, 2, xpn_len);
  offset += 2;

  proto_tree_add_item(xpn_set_tree, hf_mka_latest_lowest_acceptable_pn, tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(xpn_set_tree, hf_mka_old_lowest_acceptable_pn, tvb, offset, 4, ENC_NA);
  offset += 4;

  *offset_ptr = offset;
}

static void
dissect_icv(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr, uint16_t *icv_len)
{
  int offset = *offset_ptr;
  proto_tree *icv_set_tree;
  proto_item *ti;

  *icv_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_icv_set, tvb, offset, 4, ENC_NA);
  icv_set_tree = proto_item_add_subtree(ti, ett_mka_icv_set);

  proto_tree_add_item(icv_set_tree, hf_mka_param_set_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(icv_set_tree, hf_mka_param_body_length, tvb, offset, 2, *icv_len);
  offset += 2;

  *offset_ptr = offset;
}

static void
dissect_unknown_param_set(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr) {
  int offset = *offset_ptr;
  uint16_t param_set_len;
  proto_tree *param_set_tree;
  proto_item *ti;

  param_set_len = (tvb_get_ntohs(tvb, offset + 2)) & 0x0fff;
  ti = proto_tree_add_item(mka_tree, hf_mka_unknown_set, tvb, offset, param_set_len + 4, ENC_NA);
  param_set_tree = proto_item_add_subtree(ti, ett_mka_unknown_set);

  proto_tree_add_item(param_set_tree, hf_mka_param_set_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_uint(param_set_tree, hf_mka_param_body_length, tvb, offset, 2, param_set_len);
  offset += 2;

  proto_tree_add_item(param_set_tree, hf_mka_unknown_param_set, tvb, offset, param_set_len, ENC_NA);

  offset += param_set_len;

  unsigned padding_len = WS_PADDING_TO_4(param_set_len);
  if (padding_len != 0) {
    proto_tree_add_item(param_set_tree, hf_mka_padding, tvb, offset, padding_len, ENC_NA);
    offset += padding_len;
  }

  *offset_ptr = offset;
}

static int
dissect_mka(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  int         offset = 0;
  uint8_t     mka_version_type;
  uint16_t    icv_len = 16; // Default ICV length, see IEEE 802.1X-2010, Section 11.11
  proto_item *ti;
  proto_tree *mka_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAPOL-MKA");
  col_clear(pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item(tree, proto_mka, tvb, 0, -1, ENC_NA);
  mka_tree = proto_item_add_subtree(ti, ett_mka);

  /*
   * The 802.1X-2010 spec specifies support for MKA version 1 only.
   * The 802.1Xbx-2014 spec specifies support for MKA version 2.
   * The 802.1Xck-2018 spec specifies support for MKA version 3.
   */
  mka_version_type = tvb_get_uint8(tvb, offset);
  if ((mka_version_type < 1) || (mka_version_type > 3)) {
    expert_add_info(pinfo, ti, &ei_unexpected_data);
  }

  /*
   * Basic Parameter set is always the first parameter set, dissect it first !
   */
  dissect_basic_paramset(mka_tree, pinfo, tvb, &offset);

  while(tvb_reported_length_remaining(tvb, offset) > icv_len) {
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
                        val_to_str_const(tvb_get_uint8(tvb, offset), param_set_type_vals, "Unknown"));
    switch (tvb_get_uint8(tvb, offset)) {
    case LIVE_PEER_LIST_TYPE:
    case POTENTIAL_PEER_LIST_TYPE:
      dissect_peer_list(mka_tree, pinfo, tvb, &offset, (mka_version_type == 3));
      break;

    case MACSEC_SAK_USE_TYPE:
      dissect_sak_use(mka_tree, pinfo, tvb, &offset);
      break;

    case DISTRIBUTED_SAK_TYPE:
      dissect_distributed_sak(mka_tree, pinfo, tvb, &offset);
      break;

    case DISTRIBUTED_CAK_TYPE:
      dissect_distributed_cak(mka_tree, pinfo, tvb, &offset);
      break;

    case KMD_TYPE:
      dissect_kmd(mka_tree, pinfo, tvb, &offset);
      break;

    case ANNOUNCEMENT_TYPE:
      dissect_announcement(mka_tree, pinfo, tvb, &offset);
      break;

    case XPN_TYPE:
      dissect_xpn(mka_tree, pinfo, tvb, &offset);
      break;

    case ICV_TYPE:
      // This ICV indicator does not include the ICV itself, see IEEE 802.1X-2010, Section 11.11.1
      dissect_icv(mka_tree, pinfo, tvb, &offset, &icv_len);
      break;

    default:
      dissect_unknown_param_set(mka_tree, pinfo, tvb, &offset);
      break;
    }
  }

  proto_tree_add_item(mka_tree, hf_mka_icv, tvb, offset, icv_len, ENC_NA);

  /* free any allocated entries in the private table containing CKN info */
  if (NULL != pinfo->private_table) {
      /* destroy the hash table that may have been created */
      g_hash_table_destroy(pinfo->private_table);
  }

  return tvb_captured_length(tvb);
}

void
proto_register_mka(void) {
  module_t         *mka_module;
  expert_module_t  *expert_mka = NULL;

  uat_t *mka_ckn_info_uat = NULL;

  static ei_register_info ei[] = {
    { &ei_mka_undecoded, {
        "mka.expert.undecoded_data", PI_UNDECODED, PI_WARN, "Undecoded data", EXPFILL }},
    { &ei_unexpected_data, {
        "mka.expert.unexpected_data", PI_PROTOCOL, PI_WARN, "Unexpected data", EXPFILL }},
    { &ei_mka_unimplemented, {
        "mka.expert.unimplemented", PI_UNDECODED, PI_WARN, "Announcement TLV not handled, if you want this implemented please contact the wireshark developers", EXPFILL }}
  };

  static hf_register_info hf[] = {
    { &hf_mka_version_id,                   { "MKA Version Identifier", "mka.version_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_basic_param_set,              { "Basic Parameter set", "mka.basic_param_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_live_peer_list_set,           { "Live Peer List Parameter set", "mka.live_peer_list_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_potential_peer_list_set,      { "Potential Peer List Parameter set", "mka.potential_peer_list_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_macsec_sak_use_set,           { "MACsec SAK Use parameter set", "mka.macsec_sak_use_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_distributed_sak_set,          { "Distributed SAK parameter set", "mka.distributed_sak_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_distributed_cak_set,          { "Distributed CAK parameter set", "mka.distributed_cak_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_kmd_set,                      { "Key Management Domain set", "mka.kmd_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_announcement_set,             { "Announcement parameter set", "mka.announcement_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_xpn_set,                      { "Extended Packet Numbering set", "mka.xpn_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_unknown_set,                  { "Unknown parameter set", "mka.unknown_set", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_unknown_param_set,            { "Unknown parameter set", "mka.unknown_param_set", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_icv_set,                      { "Integrity Check Value Indicator", "mka.icv_indicator", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_param_set_type,               { "Parameter set type", "mka.param_set_type", FT_UINT8, BASE_DEC, VALS(param_set_type_vals), 0x0, NULL, HFILL }},

    { &hf_mka_keyserver_priority,           { "Key Server Priority", "mka.ks_prio", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_key_server,                   { "Key Server", "mka.key_server", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
    { &hf_mka_macsec_desired,               { "MACsec Desired", "mka.macsec_desired", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
    { &hf_mka_macsec_capability,            { "MACsec Capability", "mka.macsec_capability", FT_UINT8, BASE_DEC, VALS(macsec_capability_type_vals), 0x30, NULL, HFILL }},
    { &hf_mka_param_body_length,            { "Parameter set body length", "mka.param_body_length", FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL }},
    { &hf_mka_sci,                          { "SCI", "mka.sci", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_actor_mi,                     { "Actor Member Identifier", "mka.actor_mi", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_actor_mn,                     { "Actor Message Number", "mka.actor_mn", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_algo_agility,                 { "Algorithm Agility", "mka.algo_agility", FT_UINT32, BASE_HEX, VALS(algo_agility_vals), 0x0, NULL, HFILL }},
    { &hf_mka_cak_name,                     { "CAK Name", "mka.cak_name", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_cak_name_info,                { "CAK Name Info", "mka.cak_name.info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_mka_padding,                      { "Padding", "mka.padding", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_mka_key_server_ssci,              { "Key Server SSCI (LSB)", "mka.key_server_ssci", FT_UINT8, BASE_HEX, NULL, 0x0, "Only present combined with Distributed SAK parameter set with XPN cipher suite", HFILL }},
    { &hf_mka_peer_mi,                      { "Peer Member Identifier", "mka.peer_mi", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_peer_mn,                      { "Peer Message Number", "mka.peer_mn", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_mka_latest_key_an,                { "Latest Key AN", "mka.latest_key_an", FT_UINT8, BASE_DEC, NULL, 0xc0, NULL, HFILL }},
    { &hf_mka_latest_key_tx,                { "Latest Key tx", "mka.latest_key_tx", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
    { &hf_mka_latest_key_rx,                { "Latest Key rx", "mka.latest_key_rx", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
    { &hf_mka_old_key_an,                   { "Old Key AN", "mka.old_key_an", FT_UINT8, BASE_DEC, NULL, 0x0c, NULL, HFILL }},
    { &hf_mka_old_key_tx,                   { "Old Key tx", "mka.old_key_tx", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
    { &hf_mka_old_key_rx,                   { "Old Key rx", "mka.old_key_rx", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
    { &hf_mka_plain_tx,                     { "Plain tx", "mka.plain_tx", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
    { &hf_mka_plain_rx,                     { "Plain rx", "mka.plain_rx", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
    { &hf_mka_delay_protect,                { "Delay protect", "mka.delay_protect", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
    { &hf_mka_latest_key_server_mi,         { "Latest Key: Key Server Member Identifier", "mka.latest_key_server_mi", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_latest_key_number,            { "Latest Key: Key Number", "mka.latest_key_number", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_latest_lowest_acceptable_pn,  { "Latest Key: Lowest Acceptable PN (32 MSB)", "mka.latest_lowest_acceptable_pn", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_old_key_server_mi,            { "Old Key: Key Server Member Identifier", "mka.old_key_server_mi", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_old_key_number,               { "Old Key: Key Number", "mka.old_key_number", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_old_lowest_acceptable_pn,     { "Old Key: Lowest Acceptable PN (32 MSB)", "mka.old_lowest_acceptable_pn", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_mka_distributed_an,               { "Distributed AN", "mka.distributed_an", FT_UINT8, BASE_DEC, NULL, 0xc0, NULL, HFILL }},
    { &hf_mka_confidentiality_offset,       { "Confidentiality Offset", "mka.confidentiality_offset", FT_UINT8, BASE_DEC, VALS(confidentiality_offset_vals), 0x30, NULL, HFILL }},
    { &hf_mka_key_number,                   { "Key Number", "mka.key_number", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_aes_key_wrap_sak,             { "AES Key Wrap of SAK", "mka.aes_key_wrap_sak", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_aes_key_wrap_unwrapped_sak,   { "Unwrapped SAK", "mka.aes_key_wrap_unwrapped_sak", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_aes_key_wrap_cak,             { "AES Key Wrap of CAK", "mka.aes_key_wrap_cak", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_macsec_cipher_suite,          { "MACsec Cipher Suite", "mka.macsec_cipher_suite", FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(macsec_cipher_suite_vals), 0x0, NULL, HFILL }},

    { &hf_mka_kmd,                          { "Key Management Domain", "mka.kmd", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_mka_suspension_time,              { "Suspension time", "mka.suspension_time", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

    { &hf_mka_icv,                          { "Integrity Check Value", "mka.icv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_mka_tlv_entry,                    { "TLV Entry", "mka.tlv_entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_tlv_type,                     { "TLV Type", "mka.tlv_type", FT_UINT8, BASE_DEC, VALS(macsec_tlvs), 0xfe, NULL, HFILL }},
    { &hf_mka_tlv_info_string_length,       { "TLV Info String Length", "mka.tlv_info_string_len", FT_UINT16, BASE_DEC, NULL, 0x01ff, NULL, HFILL }},
    { &hf_mka_tlv_data,                     { "TLV Data", "mka.tlv_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_tlv_cipher_suite_impl_cap,    { "Cipher Suite Implementation Capabilities", "mka.tlv.cipher_suite_impl_cap", FT_UINT16, BASE_DEC, VALS(macsec_capability_type_vals), 0x0003, NULL, HFILL }},
  };

  static int *ett[] = {
    &ett_mka,
    &ett_mka_basic_param_set,
    &ett_mka_peer_list_set,
    &ett_mka_sak_use_set,
    &ett_mka_distributed_sak_set,
    &ett_mka_distributed_cak_set,
    &ett_mka_kmd_set,
    &ett_mka_announcement_set,
    &ett_mka_xpn_set,
    &ett_mka_unknown_set,
    &ett_mka_icv_set,
    &ett_mka_tlv,
    &ett_mka_cipher_suite_entry
  };

  proto_mka = proto_register_protocol("MACsec Key Agreement", "EAPOL-MKA", "mka");
  register_dissector("mka", dissect_mka, proto_mka);

  proto_register_field_array(proto_mka, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  expert_mka = expert_register_protocol(proto_mka);
  expert_register_field_array(expert_mka, ei, array_length(ei));

  mka_module = prefs_register_protocol(proto_mka, NULL);

  /* UAT: CKN info */
  static uat_field_t mka_ckn_uat_fields[] = {
    UAT_FLD_BUFFER(mka_ckn_uat_data, ckn, "CKN", "The CKN as byte array"),
    UAT_FLD_CSTRING(mka_ckn_uat_data, name, "Info", "CKN information string to be displayed"),
    UAT_FLD_BUFFER(mka_ckn_uat_data, cak, "CAK", "The CAK as byte array"),
    UAT_END_FIELDS
  };

  mka_ckn_info_uat = uat_new("CKN/CAK Info",
    sizeof(mka_ckn_info_t),                 /* record size           */
    DATAFILE_CKN_INFO,                      /* filename              */
    true,                                   /* from profile          */
    (void **) &mka_ckn_uat_data,            /* data_ptr              */
    &num_mka_ckn_uat_data,                  /* numitems_ptr          */
    UAT_AFFECTS_DISSECTION,                 /* but not fields        */
    NULL,                                   /* help                  */
    ckn_info_copy_cb,                       /* copy callback         */
    ckn_info_update_cb,                     /* update callback       */
    ckn_info_free_cb,                       /* free callback         */
    ckn_info_post_update_cb,                /* post update callback  */
    ckn_info_reset_cb,                      /* reset callback        */
    mka_ckn_uat_fields                      /* UAT field definitions */
  );

  uat_set_default_values(mka_ckn_info_uat, mka_ckn_info_uat_defaults_);
  prefs_register_uat_preference(mka_module, "ckn_info", "CKN/CAK Info", "A table to define CKNs and CAKs", mka_ckn_info_uat);
}

void
proto_reg_handoff_mka(void) {
  static dissector_handle_t mka_handle;

  mka_handle = create_dissector_handle(dissect_mka, proto_mka);
  dissector_add_uint("eapol.type", EAPOL_MKA, mka_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
