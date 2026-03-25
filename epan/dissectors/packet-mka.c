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
#define WS_LOG_DOMAIN "MKA"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/uat.h>
#include <epan/etypes.h>

#include <wsutil/pint.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/ws_padding_to.h>
#include <wsutil/to_str.h>

#include "packet-eapol.h"
#include "packet-mka.h"

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

#define MKA_MI_LEN                   12U
#define MKA_MAX_CKN_LEN              32

#define KDF_LABEL_LEN                12
#define KDF_CTX_LEN                  16

#define DEFAULT_ICV_LEN              16

#define BASIC_PARAMSET_BODY_LENGTH   28
#define DISTRIBUTED_SAK_AES128_BODY_LEN 28
#define DISTRIBUTED_SAK_AES256_BODY_LEN 52
#define DISTRIBUTED_SAK_AES128_XPN_BODY_LEN 36

/* keys for p_[add|get]_proto_data */
#define CKN_KEY 0
#define ICV_KEY 1
#define MI_KEY 2
#define SAK_KEY 3
#define PEER_SCI_KEY 4
#define PEER_MI_KEY 5

void proto_register_mka(void);
void proto_reg_handoff_mka(void);

static int proto_mka;
static int proto_eapol;

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
static int hf_mka_sci_system_identifier;
static int hf_mka_sci_port_identifier;
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
static int hf_mka_latest_lowest_accept_pn_msb;
static int hf_mka_old_lowest_accept_pn_msb;

static int hf_mka_icv;
static int hf_mka_icv_status;

static int hf_mka_tlv_entry;
static int hf_mka_tlv_type;
static int hf_mka_tlv_info_string_length;
static int hf_mka_tlv_data;
static int hf_mka_tlv_cipher_suite_impl_cap;

static expert_field ei_mka_icv_bad;
static expert_field ei_mka_undecoded;
static expert_field ei_unexpected_data;
static expert_field ei_mka_unimplemented;

static int ett_mka;
static int ett_mka_sci;
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
  { 0x0080C201, "IEEE Std 802.1X-2020" },
  { 0, NULL }
};

static const value_string confidentiality_offset_vals[] = {
  { 0, "No confidentiality" },
  { 1, "No confidentiality offset" },
  { 2, "Confidentiality offset 30 octets" },
  { 3, "Confidentiality offset 50 octets" },
  { 0, NULL }
};

#define MACSEC_GCM_AES_128      UINT64_C(0x0080C20001000001)
#define MACSEC_GCM_AES_256      UINT64_C(0x0080C20001000002)
#define MACSEC_GCM_AES_XPN_128  UINT64_C(0x0080C20001000003)
#define MACSEC_GCM_AES_XPN_256  UINT64_C(0x0080C20001000004)

static const val64_string macsec_cipher_suite_vals[] = {
  { INT64_C(0x0080020001000001),  "GCM-AES-128" }, // Original, incorrect value in IEEE 802.1AE-2006 and IEEE 802.1X-2010
  { MACSEC_GCM_AES_128,           "GCM-AES-128" },
  { MACSEC_GCM_AES_256,           "GCM-AES-256" },
  { MACSEC_GCM_AES_XPN_128,       "GCM-AES-XPN-128" },
  { MACSEC_GCM_AES_XPN_256,       "GCM-AES-XPN-256" },
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

static wmem_map_t *mka_mi_sci_map;
static wmem_multimap_t *mka_ckn_sak_map;

static const char *mka_ckn_info_uat_defaults_[] = { NULL, "", "" };

static mka_ckn_info_t *mka_ckn_uat_data = NULL;
static unsigned num_mka_ckn_uat_data = 0;
static GHashTable *ht_mka_ckn = NULL;

UAT_BUFFER_CB_DEF(mka_ckn_uat_data, cak, mka_ckn_info_t, cak, cak_len)
UAT_BUFFER_CB_DEF(mka_ckn_uat_data, ckn, mka_ckn_info_t, ckn, ckn_len)
UAT_CSTRING_CB_DEF(mka_ckn_uat_data, name, mka_ckn_info_t)

/* Derive the ICK or KEK from the CAK and label. */
static unsigned
mka_derive_key(const uint8_t *label, uint8_t *out, void *k) {
  mka_ckn_info_t *rec = (mka_ckn_info_t *)k;
  uint8_t *cak = (uint8_t *)rec->cak;
  uint8_t *ckn = (uint8_t *)rec->ckn;

  unsigned ckn_len = rec->ckn_len;
  unsigned cak_len = rec->cak_len;

  /* Build context. */
  /* Context is the first 16 bytes of the CAK name. */
  uint8_t context[16] = {0};
  memcpy(context, ckn, MIN(ckn_len, 16));

  gcry_mac_hd_t hd;

  if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
    char *cak_str = bytes_to_str_maxlen(NULL, cak, cak_len, 0);
    ws_debug("cak: %s", cak_str);
    g_free(cak_str);

    char *lbl_str = bytes_to_str_maxlen(NULL, label, KDF_LABEL_LEN, 0);
    ws_debug("lbl: %s", lbl_str);
    g_free(lbl_str);

    char *ctx_str = bytes_to_str_maxlen(NULL, context, KDF_CTX_LEN, 0);
    ws_debug("ctx: %s", ctx_str);
    g_free(ctx_str);
  }

  /* Format input data for cmac.
     Input data length is (1 byte counter + 12 bytes label + 1 byte for 0x00 + 16 bytes for context + 2 bytes for length) = 32 */
  #define INPUT_DATA_LENGTH (1 + KDF_LABEL_LEN + 1 + KDF_CTX_LEN + 2)
  uint8_t inputdata[INPUT_DATA_LENGTH];

  size_t clen = AES_CMAC_LEN;
  unsigned klen = cak_len * 8;
  unsigned iterations = cak_len / AES_CMAC_LEN;
  unsigned outlen = 0;

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

  for (unsigned i = 0; i < iterations; i++)
  {
    /* Reset cmac context, if needed */
    if ((i > 0) && gcry_mac_reset(hd)) {
      ws_warning("failed CMAC reset");
      gcry_mac_close(hd);
      return 0;
    }

    inputdata[0] = (i + 1);                       // Iteration
    memcpy(&inputdata[1], label, KDF_LABEL_LEN);  // Key label - must be 12 bytes
    inputdata[13] = 0x00;                         // Always 0x00
    memcpy(&inputdata[14], context, KDF_CTX_LEN); // Context data - must be 16 bytes
    inputdata[30] = (klen & 0xFF00) >> 8;         // MSB of key length in bits
    inputdata[31] = (klen & 0xFF);                // LSB of key length in bits

    /* Write the formatted input data to the CMAC. */
    if (gcry_mac_write(hd, inputdata, INPUT_DATA_LENGTH)) {
      ws_warning("failed CMAC write");
      gcry_mac_close(hd);
      return 0;
    }

    /* Read the CMAC result. */
    gcry_mac_read(hd, (out + (i * clen)), &clen);
    outlen += (unsigned)clen;
  }

  /* Close the context. */
  gcry_mac_close(hd);

  if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
    char *key_str = bytes_to_str_maxlen(NULL, out, cak_len, 0);
    ws_debug("key: %s", key_str);
    g_free(key_str);
  }

  return outlen;
}

static void
mka_derive_kek(void * k) {
  mka_ckn_info_t *rec = (mka_ckn_info_t *)k;

  const uint8_t label[KDF_LABEL_LEN + 1] = "IEEE8021 KEK";
  rec->key.kek_len = mka_derive_key(label, rec->key.kek, rec);
}

static void
mka_derive_ick(void * k) {
  mka_ckn_info_t *rec = (mka_ckn_info_t *)k;

  const uint8_t label[KDF_LABEL_LEN + 1] = "IEEE8021 ICK";
  rec->key.ick_len = mka_derive_key(label, rec->key.ick, rec);
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

  if ((0 == rec->ckn_len) || (rec->ckn_len > MKA_MAX_CKN_LEN)) {
    *err = ws_strdup("Invalid CKN length! CKNs need to be from 1 to 32 bytes.");
    return false;
  }

  if (0 == strlen(rec->name)) {
    *err = ws_strdup("Missing name! A name must be specified for this CAK/CKN entry.");
    return false;
  }

  /* XXX - The CKN must be unique for pre-shared CAKs (IEEE 802.1X-2020 6.3.3,
   * 9.3.1). Can that be validated here? */

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
  ckn_info_reset_cb();

  ht_mka_ckn = g_hash_table_new(&ckn_key_hash_func, &ckn_key_equal_func);

  for (size_t i = 0; i < num_mka_ckn_uat_data; i++) {
    /* Derive the KEK and ICK and store with the CAK/CKN for this table entry. */
    ws_info("deriving ICK for CKN table entry %zu (%s)", i, mka_ckn_uat_data[i].name);
    mka_derive_ick(&(mka_ckn_uat_data[i]));

    ws_info("deriving KEK for CKN table entry %zu (%s)", i, mka_ckn_uat_data[i].name);
    mka_derive_kek(&(mka_ckn_uat_data[i]));

    /* The disadvantage of using hash tables like this is that it's not
     * possible to have multiple entries with the same CKN without more
     * changes.  */
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

static unsigned
mka_sci_hash(const void *key) {
  return wmem_strong_hash(key, MACSEC_SCI_LEN);
}

static gboolean
mka_sci_equal(const void *k1, const void *k2) {
  return memcmp(k1, k2, MACSEC_SCI_LEN) == 0;
}

static unsigned
mka_mi_hash(const void *key) {
  return wmem_strong_hash(key, MKA_MI_LEN);
}

static gboolean
mka_mi_equal(const void *k1, const void *k2) {
  return memcmp(k1, k2, MKA_MI_LEN) == 0;
}

typedef struct _mka_sak_key_t {
  const mka_ckn_info_t *ckn_info;
  uint8_t an;
} mka_sak_key_t;

static unsigned
mka_sak_key_hash(const void *k) {
  const mka_sak_key_t *key = (const mka_sak_key_t*)k;

  return ckn_key_hash_func(key->ckn_info) ^ key->an;
}

static gboolean
mka_sak_key_equal(const void *k1, const void *k2) {
  const mka_sak_key_t *key1 = (const mka_sak_key_t*)k1;
  const mka_sak_key_t *key2 = (const mka_sak_key_t*)k2;

  return (key1->an == key2->an) &&
    ckn_key_equal_func(key1->ckn_info, key2->ckn_info);
}

/* For use by other dissectors (MACsec), this looks for the most recent
 * SAK with a given CKN and AN. */
mka_sak_info_key_t *
mka_get_sak_info(const mka_ckn_info_t *ckn, unsigned an, uint32_t frame_num) {
  mka_sak_key_t key = {ckn, an};
  return wmem_multimap_lookup32_le(mka_ckn_sak_map, &key, frame_num);
}

/* This static function is used internally on the second pass and requires an
 * exact match on the frame number. */
static mka_sak_info_key_t *
get_sak_info(const mka_ckn_info_t *ckn, unsigned an, uint32_t frame_num) {
  mka_sak_key_t tmp_key = {ckn, an};
  mka_sak_info_key_t *sak_info = wmem_multimap_lookup32(mka_ckn_sak_map, &tmp_key, frame_num);
  return sak_info;
}

static mka_sak_info_key_t *
get_or_create_sak_info(const mka_ckn_info_t *ckn, unsigned an, uint32_t frame_num) {
  mka_sak_info_key_t *sak_info = get_sak_info(ckn, an, frame_num);
  if (sak_info == NULL) {
    mka_sak_key_t *perm_key = wmem_new(wmem_file_scope(), mka_sak_key_t);
    perm_key->ckn_info = ckn;
    perm_key->an = an;
    sak_info = wmem_new0(wmem_file_scope(), mka_sak_info_key_t);
    sak_info->sci_map = wmem_map_new(wmem_file_scope(), mka_sci_hash, mka_sci_equal);
    sak_info->mi_array = wmem_array_new(wmem_file_scope(), MKA_MI_LEN);
    wmem_multimap_insert32(mka_ckn_sak_map, perm_key, frame_num, sak_info);
  }
  return sak_info;
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
  unsigned sci_offset;
  proto_tree *basic_param_set_tree, *sci_tree;
  proto_item *ti;
  uint16_t basic_param_set_len;
  uint16_t ckn_len;
  uint8_t *mi, *sci;

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

  ti = proto_tree_add_item(basic_param_set_tree, hf_mka_sci, tvb, offset, 8, ENC_NA);
  sci_offset = offset;
  sci_tree = proto_item_add_subtree(ti, ett_mka_sci);
  proto_tree_add_item(sci_tree, hf_mka_sci_system_identifier, tvb, offset, 6, ENC_NA);
  offset += 6;
  proto_tree_add_item(sci_tree, hf_mka_sci_port_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(basic_param_set_tree, hf_mka_actor_mi, tvb, offset, MKA_MI_LEN, ENC_NA);
  mi = tvb_memdup(pinfo->pool, tvb, offset, MKA_MI_LEN);
  p_add_proto_data(pinfo->pool, pinfo, proto_mka, MI_KEY, mi);
  if (!wmem_map_contains(mka_mi_sci_map, mi)) {
    /* We will assume that the 96-bit randomly chosen MIs do not collide.
     * However note that an SCI can choose multiple MI over a lifetime if
     * the Message Number would wrap. (IEEE 802.1X-2020 9.4.2) */
    mi = tvb_memdup(wmem_file_scope(), tvb, offset, MKA_MI_LEN);
    sci = tvb_memdup(wmem_file_scope(), tvb, sci_offset, MACSEC_SCI_LEN);
    wmem_map_insert(mka_mi_sci_map, mi, sci);
  }
  offset += MKA_MI_LEN;

  proto_tree_add_item(basic_param_set_tree, hf_mka_actor_mn, tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(basic_param_set_tree, hf_mka_algo_agility, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  ckn_len = basic_param_set_len - BASIC_PARAMSET_BODY_LENGTH;
  proto_tree_add_item(basic_param_set_tree, hf_mka_cak_name, tvb, offset, ckn_len, ENC_NA);

  mka_add_ckn_info(basic_param_set_tree, tvb, offset, ckn_len);

  /* look up the CAK/CKN in the CKN table, and add a private hash table entry if it does not yet exist there */
  const uint8_t *ckn = tvb_memdup(pinfo->pool, tvb, offset, ckn_len);
  if (NULL != ckn) {
    mka_ckn_info_t *rec = ckn_info_lookup((uint8_t *)ckn, ckn_len);
    if (NULL != rec) {
      /* add the record to the private hash table for this packet to tell ourselves about the CKN and its keys later on */
      p_add_proto_data(pinfo->pool, pinfo, proto_mka, CKN_KEY, rec);
    }
  }

  offset += ckn_len;

  unsigned padding_len = WS_PADDING_TO_4(basic_param_set_len);
  if (padding_len != 0) {
    proto_tree_add_item(basic_param_set_tree, hf_mka_padding, tvb, offset, padding_len, ENC_NA);

    offset += padding_len;
  }

  *offset_ptr = offset;
}

static int
sort_mi_by_sci(const void* a, const void* b) {
  uint8_t *sci_a = wmem_map_lookup(mka_mi_sci_map, a);
  uint8_t *sci_b = wmem_map_lookup(mka_mi_sci_map, b);

  DISSECTOR_ASSERT(sci_a && sci_b);
  // Numerically greates SCI uses the SSCI value 0x01, etc.
  return -memcmp(sci_a, sci_b, MACSEC_SCI_LEN);
}

static void
dissect_peer_list(proto_tree *mka_tree, packet_info *pinfo, tvbuff_t *tvb, int *offset_ptr, bool key_server_ssci_flag) {
  int offset = *offset_ptr;
  proto_tree *peer_list_set_tree;
  proto_item *ti;
  int hf_peer;
  int16_t peer_list_len;
  mka_sak_info_key_t *sak_info = NULL;
  uint32_t ssci;
  uint8_t  server_ssci = 0;
  uint8_t *mi = NULL;
  uint8_t *sci = NULL;

  wmem_map_t *sci_map = NULL;
  wmem_array_t *mi_array = NULL;

  if (tvb_get_uint8(tvb, offset) == LIVE_PEER_LIST_TYPE) {
    hf_peer = hf_mka_live_peer_list_set;
    sak_info = p_get_proto_data(pinfo->pool, pinfo, proto_mka, SAK_KEY);
    mi = p_get_proto_data(pinfo->pool, pinfo, proto_mka, MI_KEY);
    sci = wmem_map_lookup(mka_mi_sci_map, mi);
    DISSECTOR_ASSERT(sci);
    if (sak_info) {
      // Distributed SAK parameter set already processed.
      sci_map = sak_info->sci_map;
      mi_array = sak_info->mi_array;
    } else {
      // Distributed SAK parameter set not already processed.
      // It should not appear later, per 11.11.3, but in practice
      // in many implementations it does.
      sci_map = wmem_map_new(pinfo->pool, mka_sci_hash, mka_sci_equal);
      p_add_proto_data(pinfo->pool, pinfo, proto_mka, PEER_SCI_KEY, sci_map);
      mi_array = wmem_array_new(pinfo->pool, MKA_MI_LEN);
      p_add_proto_data(pinfo->pool, pinfo, proto_mka, PEER_MI_KEY, mi_array);
    }
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
     * - A Distributed SAK parameter set present (which could be before or after this parameter set*), but only
     * - A Distributed SAK parameter set with XPN Cipher suites (requires to look into the contents),
     * otherwise 0.
     *
     * * - 802.1X-2010 and 802.1X-2020 both specify (11.11.3 Encoding MKPDUs)
     * that implementations with a MKA Version Identifier of 1, 2, or 3 all
     * shall encode the protocol parameters as follows:
     * a) The Basic Parameter Set is encoded first.
     * b) The remaining parameter sets, except for the Live Peer List,
     *    Potential Peer List, and ICV Indicator are then encoded in
     *    parameter set type ascending order.
     * c) The Live Peer List, if present, is encoded next.
     * d) The Potential Peer List, if present, is encoded next.
     * e) The ICV Indicator, if present (i.e. the Algorithm Agility
     *    parameter indicates an ICV of length other than 16 octets)
     *    is encoded last.
     * That would make our lives easier, but in practice, implementations
     * do not do this. A common approach is to order *all* the parameter
     * sets other than the Basic Parameter Set in ascending type order,
     * which puts the Live Peer List before the Distributed SAK. Some
     * implementations include the ICV Indicator even when not necessary.
     *
     * Since 0 is not used as an SSCI and even though the SSCI is 32-bits
     * in practice it cannot be larger than 255 (9.10) or even 100 or less
     * (see the NOTE in IEEE 802.1AE-2018 10.7.13), it suffices in normal
     * operation to add it here iff the value is nonzero.
     */
    server_ssci = tvb_get_uint8(tvb, offset);
    if (server_ssci) {
      proto_tree_add_item(peer_list_set_tree, hf_mka_key_server_ssci, tvb, offset, 1, ENC_NA);
    }
  }

  if (sci_map) {
    if (server_ssci) {
      wmem_map_insert(sci_map, sci, GUINT_TO_POINTER(server_ssci));
    } else {
      wmem_map_insert(sci_map, sci, GUINT_TO_POINTER(UINT32_MAX));
    }
    if (server_ssci > 1) {
      uint8_t *zeroes = wmem_alloc0(pinfo->pool, MKA_MI_LEN * (server_ssci - 1));
      wmem_array_append(mi_array, zeroes, server_ssci - 1);
    }
    wmem_array_append(mi_array, mi, 1);
  }

  offset += 1;

  proto_tree_add_uint(peer_list_set_tree, hf_mka_param_body_length, tvb, offset, 2, peer_list_len);
  offset += 2;

  bool know_all_sci = true;
  unsigned index = 1; // SSCIs start at 1
  while (peer_list_len >= 16) {
    /* If this is MKA version 3 and a Live Peer List in a MKPDU that contains
     * a Distributed SAK, then the MIs are ordered in order of their SCI. This,
     * combined with the SSCI least significant octet of the Key Server (see
     * above) can be used to determine the SCI->SSCI mapping for XPN cipher
     * suites, provided that the MI->SCI mapping was also recorded from the
     * MKPDUs sent by those actors.
     *
     * In practice, since the SSCIs are assigned incrementing from 1, we can
     * record the number of peers in the Live Peer List (plus the Key Server
     * itself) and try all of them in the MACsec dissector, if necessary.
     */
    proto_tree_add_item(peer_list_set_tree, hf_mka_peer_mi, tvb, offset, MKA_MI_LEN, ENC_NA);
    if (sci_map) {
      mi = tvb_memdup(pinfo->pool, tvb, offset, MKA_MI_LEN);
      if (index >= server_ssci) {
        // This is the correct 1-indexed position if server_ssci is 0
        // Because the server SCI was put at the first position.
        ssci = index + 1;
      } else {
        ssci = index;
      }
      // Do we know the SCI for this MI?
      sci = wmem_map_lookup(mka_mi_sci_map, mi);
      if (sci) {
        if (server_ssci) {
          wmem_map_insert(sci_map, sci, GUINT_TO_POINTER(ssci));
        } else {
          /* This value is to get around wmem_map_find() not being able to
           * distinguish between finding 0 and not finding a result.
           * (There's no equivalent of wmem_map_lookup_extended.)
           */
          wmem_map_insert(sci_map, sci, GUINT_TO_POINTER(UINT32_MAX));
        }
      } else {
        know_all_sci = false;
      }
      if (ssci == wmem_array_get_count(mi_array) + 1) {
        wmem_array_append(mi_array, mi, 1);
      } else if (ssci < wmem_array_get_count(mi_array)) {
        memcpy(wmem_array_index(mi_array, ssci - 1), mi, MKA_MI_LEN);
      } else {
        DISSECTOR_ASSERT_NOT_REACHED();
      }
    }
    offset += MKA_MI_LEN;

    proto_tree_add_item(peer_list_set_tree, hf_mka_peer_mn, tvb, offset, 4, ENC_NA);
    offset += 4;

    peer_list_len -= 16;
    index++;
  }

  if (mi_array && know_all_sci && !server_ssci) {
    // For the case before MKA version 3, we manually sort these.
    // XXX - Should we try sorting them anyway?
    wmem_array_sort(mi_array, sort_mi_by_sci);
    for (ssci = 1; ssci <= wmem_array_get_count(mi_array); ++ssci) {
      mi = wmem_array_index(mi_array, ssci - 1);
      sci = wmem_map_lookup(mka_mi_sci_map, mi);
      wmem_map_insert(sci_map, sci, GUINT_TO_POINTER(ssci));
    }
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
mka_sci_map_copy(void *key, void *value, void *user_data)
{
  wmem_map_t *target_map = (wmem_map_t*)user_data;
  uint8_t *sci = (uint8_t*)key;

  // The key here (SCI) is already in file scope (a pointer to a result in
  // the dissector global MI->SCI map), and the value is a GUINT_TO_POINTER,
  // so we don't need to wmem_memdup anything.
  wmem_map_insert(target_map, sci, value);
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
  else if ((DISTRIBUTED_SAK_AES128_BODY_LEN == distributed_sak_len) || (DISTRIBUTED_SAK_AES128_XPN_BODY_LEN <= distributed_sak_len)) { // GCM-AES-128, GCM-AES-XPN-128, GCM-AES-256, GCM-AES-XPN-256
    uint64_t cipher_suite = MACSEC_GCM_AES_128; // Default if not specified
    uint16_t wrappedlen = WRAPPED_KEY_LEN(AES128_KEY_LEN);
    uint32_t kn;
    mka_sak_info_key_t *sak_info;
    uint8_t *sak;

    proto_tree_add_item_ret_uint(distributed_sak_tree, hf_mka_key_number, tvb, offset, 4, ENC_NA, &kn);
    offset += 4;

    /* For AES256, the wrapped key is longer and an 8 byte cipher suite is inserted before the wrapped key data. */
    if (DISTRIBUTED_SAK_AES128_XPN_BODY_LEN <= distributed_sak_len) {
      proto_tree_add_item_ret_uint64(distributed_sak_tree, hf_mka_macsec_cipher_suite, tvb, offset, CIPHER_SUITE_LEN, ENC_BIG_ENDIAN, &cipher_suite);
      offset += CIPHER_SUITE_LEN;
      switch (cipher_suite) {
      case MACSEC_GCM_AES_XPN_128:
        break;

      case MACSEC_GCM_AES_XPN_256:
      case MACSEC_GCM_AES_256:
        wrappedlen = WRAPPED_KEY_LEN(AES256_KEY_LEN);
        break;
      default:
        proto_tree_add_expert(distributed_sak_tree, pinfo, &ei_mka_undecoded, tvb, offset, distributed_sak_len - 12);
        offset += distributed_sak_len - 12;
        goto out;
      }
    }

    /* Add the wrapped key data. */
    const uint8_t *wrappedkey = tvb_memdup(pinfo->pool, tvb, offset, wrappedlen);
    proto_tree_add_item(distributed_sak_tree, hf_mka_aes_key_wrap_sak, tvb, offset, wrappedlen, ENC_NA);
    offset += wrappedlen;

      /* Attempt to unwrap the key using the KEK for the CKN. */
      /* Fetch the KEK for the CKN in the basic parameter set. */
      mka_ckn_info_t *rec = p_get_proto_data(pinfo->pool, pinfo, proto_mka, CKN_KEY);
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

    if (!PINFO_FD_VISITED(pinfo)) {
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
      sak_info = get_or_create_sak_info(rec, distributed_an, pinfo->num);
      sak = sak_info->sak;
      sak_info->sak_len = wrappedlen - WRAPPED_KEY_IV_LEN;
      if (gcry_cipher_decrypt(hd, sak, sak_info->sak_len, wrappedkey, wrappedlen) ) {
        ws_info("failed to unwrap SAK");
        memset(sak, 0, MKA_MAX_SAK_LEN);
        sak_info->sak_len = 0;
        gcry_cipher_close(hd);
        goto out;
      }

      sak_info->cipher_suite = cipher_suite;
      wmem_map_t *sci_map = p_get_proto_data(pinfo->pool, pinfo, proto_mka, PEER_SCI_KEY);
      if (sci_map) {
        wmem_map_foreach(sci_map, mka_sci_map_copy, sak_info->sci_map);
      }
      wmem_array_t *mi_array = p_get_proto_data(pinfo->pool, pinfo, proto_mka, PEER_MI_KEY);
      if (mi_array) {
        wmem_array_append(sak_info->mi_array, wmem_array_get_raw(mi_array), wmem_array_get_count(mi_array));
      }
      uint8_t *mi = p_get_proto_data(pinfo->pool, pinfo, proto_mka, MI_KEY);
      if (cipher_suite == MACSEC_GCM_AES_XPN_128 || cipher_suite == MACSEC_GCM_AES_XPN_256) {
        if (mi) {
          /* 802.1AE-2018 10.7.8 SAK creation
           * "The 64 least significant bits of the Salt are the 64 least significant
           * bits of the MKA Key Server’s Member Identifier (MI), the 16 next most
           * significant bits of the Salt comprise the exclusive-or of the 16 next
           * most significant bits of that MI with the 16 most significant bits of
           * the 32-bit MKA Key Number (KN), and the 16 most significant bits of
           * the Salt comprise the exclusive-or of the 16 most significant bits of
           * that MI with the 16 least significant bits of the KN.
           */
          uint32_t mi_upper = pntohu32(mi);
          mi_upper ^= (kn >> 16);
          mi_upper ^= (kn & UINT16_MAX) << 16;
          phtonu32(mi, mi_upper);
          memcpy(sak_info->salt, mi, MACSEC_XPN_SALT_LEN);
        }
      }

      /* Close the cipher context. */
      gcry_cipher_close(hd);

      p_add_proto_data(pinfo->pool, pinfo, proto_mka, SAK_KEY, sak_info);

      if (ws_log_msg_is_active(WS_LOG_DOMAIN, LOG_LEVEL_DEBUG)) {
        char *sak_str = bytes_to_str_maxlen(pinfo->pool, sak, sak_info->sak_len, 0);
        ws_debug("unwrapped sak: %s", sak_str);
      }
    } else {
      /* Do not try to create on the second pass, only retrieve. */
      sak_info = get_sak_info(rec, distributed_an, pinfo->num);
      if (!sak_info)
        goto out;
    }

    /* Add the unwrapped SAK to the output. */
    tvbuff_t *sak_tvb = tvb_new_child_real_data(tvb, sak_info->sak, sak_info->sak_len, sak_info->sak_len);
    add_new_data_source(pinfo, sak_tvb, "Unwrapped SAK");
    proto_tree_add_item(distributed_sak_tree, hf_mka_aes_key_wrap_unwrapped_sak, sak_tvb, 0, sak_info->sak_len, ENC_NA);
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

    if (offset2 + 2 + tlv_length > announcement_len) {
      break;
    }

    ti = proto_tree_add_none_format(announcement_set_tree, hf_mka_tlv_entry, tvb, offset + offset2, tlv_length + 2, "TLV entry: %s",
                                    val_to_str(pinfo->pool, tlv_type, macsec_tlvs, "unknown TLV type: %d"));
    tlv_tree = proto_item_add_subtree(ti, ett_mka_tlv);

    proto_tree_add_item(tlv_tree, hf_mka_tlv_type, tvb, offset + offset2, 1, ENC_NA);
    proto_tree_add_item(tlv_tree, hf_mka_tlv_info_string_length, tvb, offset + offset2, 2, ENC_BIG_ENDIAN);
    offset2 += 2;

    if (tlv_length > 0) {
      switch (tlv_type) {
      case 112: // MACsec Cipher Suites
        for (uint16_t tlv_item_offset = 0; tlv_item_offset + 10 <= tlv_length; tlv_item_offset += 8) {
          proto_tree *cipher_suite_entry;
          uint64_t cipher_suite_id = tvb_get_uint64(tvb, offset + offset2 + tlv_item_offset + 2, ENC_BIG_ENDIAN);
          uint16_t cipher_suite_cap = tvb_get_uint16(tvb, offset + offset2 + tlv_item_offset, ENC_BIG_ENDIAN) & 0x0003;

          ti = proto_tree_add_none_format(tlv_tree, hf_mka_tlv_entry, tvb, offset + offset2, tlv_length + 2, "Cipher Suite: %s, %s",
                                          val64_to_str_wmem(pinfo->pool, cipher_suite_id, macsec_cipher_suite_vals, "Unknown Cipher Suite (0x%" PRIx64 ")"),
                                          val_to_str(pinfo->pool, cipher_suite_cap, macsec_capability_type_vals, "Unknown Capability (%d)"));
          cipher_suite_entry = proto_item_add_subtree(ti, ett_mka_cipher_suite_entry);

          proto_tree_add_item(cipher_suite_entry, hf_mka_tlv_cipher_suite_impl_cap, tvb, offset + offset2 + tlv_item_offset, 2, ENC_BIG_ENDIAN);
          tlv_item_offset += 2;
          proto_tree_add_item(cipher_suite_entry, hf_mka_macsec_cipher_suite, tvb, offset + offset2 + tlv_item_offset, 8, ENC_BIG_ENDIAN);
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

  proto_tree_add_item(xpn_set_tree, hf_mka_latest_lowest_accept_pn_msb, tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(xpn_set_tree, hf_mka_old_lowest_accept_pn_msb, tvb, offset, 4, ENC_NA);
  offset += 4;

  *offset_ptr = offset;
}

static void
dissect_icv(proto_tree *mka_tree, packet_info *pinfo _U_, tvbuff_t *tvb, int *offset_ptr, uint16_t *icv_len)
{
  int offset = *offset_ptr;
  proto_tree *icv_set_tree;
  proto_item *ti;

  ti = proto_tree_add_item(mka_tree, hf_mka_icv_set, tvb, offset, 4, ENC_NA);
  icv_set_tree = proto_item_add_subtree(ti, ett_mka_icv_set);

  proto_tree_add_item(icv_set_tree, hf_mka_param_set_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item_ret_uint16(icv_set_tree, hf_mka_param_body_length, tvb, offset, 2, ENC_BIG_ENDIAN, icv_len);
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

static uint8_t*
calculate_icv(packet_info *pinfo, size_t icv_len)
{
  /* IEEE Std 802.1X-2020 9.4.1 Message authentication
   *
   * Each protocol data unit (MKPDU) transmitted is integrity protected by an
   * 128 bit ICV, generated by AES-CMAC using the ICK (9.3):
   *
   *    ICV = AES-CMAC(ICK, M, 128)
   *    M = DA + SA + (MSDU – ICV)
   *
   * In other words, M comprises the concatenation of the destination and source
   * MAC addresses, each represented by a sequence of 6 octets in canonical
   * format order, with the MSDU (MAC Service Data Unit) of the MKPDU including
   * the allocated Ethertype, and up to but not including, the generated ICV.
   *
   * NOTE—M comprises the whole of what is often referred to as ‘the frame’
   * considered from the point of view of the MAC Service provided by Common
   * Port of the SecY (Figure 6-2) or PAC (Figure 6-6) supporting MKPDU
   * transmission. The description does not use the term ‘frame’, because that
   * Common Port could be supported by additional VLAN tags or other tags
   * (consider the upper SecY shown in Figure 7-17) prior to transmission of a
   * MAC frame by a system. Any such additional tags would not be covered by
   * the ICV, and would be removed prior to MKPDU reception by a peer PAE.
   */

  if (PINFO_FD_VISITED(pinfo)) {
    return p_get_proto_data(wmem_file_scope(), pinfo, proto_mka, ICV_KEY);
  }

  gcry_error_t err;
  mka_ckn_info_t *rec = p_get_proto_data(pinfo->pool, pinfo, proto_mka, CKN_KEY);
  proto_eapol_key_frame_t *eapol_frame = p_get_proto_data(pinfo->pool, pinfo, proto_eapol, EAPOL_KEY_FRAME_KEY);

  if (rec == NULL || eapol_frame == NULL || pinfo->dl_dst.type != AT_ETHER || pinfo->dl_src.type != AT_ETHER) {
    return NULL;
  }

  if (eapol_frame->len < icv_len) {
    return NULL;
  }

  /* Look up the CKN and if found, use the ICK associated with it. */
  ws_debug("CKN entry name: %s", rec->name);

  /* If no ICK available, skip the calculation. */
  mka_ckn_info_key_t *key = &(rec->key);
  if ((NULL == key) || (0 == key->ick_len)) {
    return NULL;
  }

  /* Open the MAC context. */
  gcry_mac_hd_t hd;
  if ((err = gcry_mac_open(&hd, GCRY_MAC_CMAC_AES, 0, NULL))) {
    ws_warning("failed to open MAC context: %s", gcry_strerror(err));
    return NULL;
  }

  if ((err = gcry_mac_setkey(hd, key->ick, key->ick_len))) {
    ws_warning("failed to set ICK: %s", gcry_strerror(err));
    goto failed;
  }

  uint8_t *icv_calc = (uint8_t*)wmem_alloc0(wmem_file_scope(), icv_len);
  uint8_t eapol_ethertype[2];
  phtonu16(eapol_ethertype, ETHERTYPE_EAPOL);
  wmem_array_t *ethhdr = wmem_array_sized_new(pinfo->pool, sizeof(uint8_t), pinfo->dst.len + pinfo->src.len + 2);
  wmem_array_append(ethhdr, pinfo->dst.data, pinfo->dst.len);
  wmem_array_append(ethhdr, pinfo->src.data, pinfo->src.len);
  wmem_array_append(ethhdr, eapol_ethertype, sizeof(eapol_ethertype));
  if ((err = gcry_mac_write(hd, wmem_array_get_raw(ethhdr), wmem_array_get_count(ethhdr)))) {
    ws_warning("failed to update MAC: %s", gcry_strerror(err));
    goto failed;
  }
  if ((err = gcry_mac_write(hd, eapol_frame->data, eapol_frame->len - icv_len))) {
    ws_warning("failed to update MAC: %s", gcry_strerror(err));
    goto failed;
  }
  if ((err = gcry_mac_read(hd, icv_calc, &icv_len))) {
    ws_warning("failed to read MAC: %s", gcry_strerror(err));
    goto failed;
  }

  /* Close the MAC context. */
  gcry_mac_close(hd);
  p_add_proto_data(wmem_file_scope(), pinfo, proto_mka, ICV_KEY, icv_calc);
  return icv_calc;

failed:
  gcry_mac_close(hd);
  return NULL;
}

static int
dissect_mka(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  int         offset = 0;
  uint8_t     mka_version_type;
  uint16_t    icv_len = DEFAULT_ICV_LEN;
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

  const uint8_t *icv_calc = calculate_icv(pinfo, icv_len);
  proto_tree_add_checksum_bytes(mka_tree, tvb, offset, hf_mka_icv, hf_mka_icv_status, &ei_mka_icv_bad, pinfo, icv_calc, icv_len, icv_calc ? PROTO_CHECKSUM_VERIFY : PROTO_CHECKSUM_NO_FLAGS);

  return tvb_captured_length(tvb);
}

void
proto_register_mka(void) {
  module_t         *mka_module;
  expert_module_t  *expert_mka = NULL;

  uat_t *mka_ckn_info_uat = NULL;

  static ei_register_info ei[] = {
    { &ei_mka_icv_bad, {
        "mka.icv.bad", PI_CHECKSUM, PI_ERROR, "Bad ICV", EXPFILL }},

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
    { &hf_mka_sci_system_identifier,        { "System Identifier", "mka.sci.system_identifier", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_sci_port_identifier,          { "Port Identifier", "mka.sci.port_identifier", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
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
    { &hf_mka_latest_lowest_acceptable_pn,  { "Latest Key: Lowest Acceptable PN (32 LSB)", "mka.latest_lowest_acceptable_pn", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_old_key_server_mi,            { "Old Key: Key Server Member Identifier", "mka.old_key_server_mi", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_old_key_number,               { "Old Key: Key Number", "mka.old_key_number", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_old_lowest_acceptable_pn,     { "Old Key: Lowest Acceptable PN (32 LSB)", "mka.old_lowest_acceptable_pn", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_mka_distributed_an,               { "Distributed AN", "mka.distributed_an", FT_UINT8, BASE_DEC, NULL, 0xc0, NULL, HFILL }},
    { &hf_mka_confidentiality_offset,       { "Confidentiality Offset", "mka.confidentiality_offset", FT_UINT8, BASE_DEC, VALS(confidentiality_offset_vals), 0x30, NULL, HFILL }},
    { &hf_mka_key_number,                   { "Key Number", "mka.key_number", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_aes_key_wrap_sak,             { "AES Key Wrap of SAK", "mka.aes_key_wrap_sak", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_aes_key_wrap_unwrapped_sak,   { "Unwrapped SAK", "mka.aes_key_wrap_unwrapped_sak", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_aes_key_wrap_cak,             { "AES Key Wrap of CAK", "mka.aes_key_wrap_cak", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_macsec_cipher_suite,          { "MACsec Cipher Suite", "mka.macsec_cipher_suite", FT_UINT64, BASE_HEX|BASE_VAL64_STRING, VALS64(macsec_cipher_suite_vals), 0x0, NULL, HFILL }},

    { &hf_mka_kmd,                          { "Key Management Domain", "mka.kmd", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_mka_suspension_time,              { "Suspension time", "mka.suspension_time", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_latest_lowest_accept_pn_msb,  { "Latest Key: Lowest Acceptable PN (32 MSB)", "mka.latest_lowest_acceptable_pn_msb", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_old_lowest_accept_pn_msb,     { "Old Key: Lowest Acceptable PN (32 MSB)", "mka.old_lowest_acceptable_pn_msb", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

    { &hf_mka_icv,                          { "Integrity Check Value", "mka.icv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_icv_status,                   { "ICV Status", "mka.icv.status", FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0, NULL, HFILL }},

    { &hf_mka_tlv_entry,                    { "TLV Entry", "mka.tlv_entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_tlv_type,                     { "TLV Type", "mka.tlv_type", FT_UINT8, BASE_DEC, VALS(macsec_tlvs), 0xfe, NULL, HFILL }},
    { &hf_mka_tlv_info_string_length,       { "TLV Info String Length", "mka.tlv_info_string_len", FT_UINT16, BASE_DEC, NULL, 0x01ff, NULL, HFILL }},
    { &hf_mka_tlv_data,                     { "TLV Data", "mka.tlv_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_mka_tlv_cipher_suite_impl_cap,    { "Cipher Suite Implementation Capabilities", "mka.tlv.cipher_suite_impl_cap", FT_UINT16, BASE_DEC, VALS(macsec_capability_type_vals), 0x0003, NULL, HFILL }},
  };

  static int *ett[] = {
    &ett_mka,
    &ett_mka_sci,
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

  mka_mi_sci_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), mka_mi_hash, mka_mi_equal);

  mka_ckn_sak_map = wmem_multimap_new_autoreset(wmem_epan_scope(), wmem_file_scope(), mka_sak_key_hash, mka_sak_key_equal);

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

  proto_eapol = proto_get_id_by_filter_name("eapol");
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
