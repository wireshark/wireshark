/* packet-mka.h
 * Routines for MKA packet dissection
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MKA_H__
#define __PACKET_MKA_H__

#include <epan/packet.h>

#define MKA_MI_LEN_PUB                  12U
#define MKA_MAX_CKN_LEN_PUB             32U

#define AES128_KEY_LEN                  16
#define AES256_KEY_LEN                  32

#define MKA_KI_LEN                      16U

#define MACSEC_SCI_LEN                  8U
#define MACSEC_XPN_SALT_LEN             12U

#define MACSEC_GCM_AES_128      UINT64_C(0x0080C20001000001)
#define MACSEC_GCM_AES_256      UINT64_C(0x0080C20001000002)
#define MACSEC_GCM_AES_XPN_128  UINT64_C(0x0080C20001000003)
#define MACSEC_GCM_AES_XPN_256  UINT64_C(0x0080C20001000004)

#define MKA_CAK_AES_GCM_128_LEN (AES128_KEY_LEN)
#define MKA_CAK_AES_GCM_256_LEN (AES256_KEY_LEN)
#define MKA_MAX_CAK_LEN (MKA_CAK_AES_GCM_256_LEN)

#define MKA_MAX_KEK_LEN (MKA_CAK_AES_GCM_256_LEN)
#define MKA_MAX_ICK_LEN (MKA_CAK_AES_GCM_256_LEN)
#define MKA_MAX_SAK_LEN (MKA_CAK_AES_GCM_256_LEN)

typedef struct _mka_sak_info_key {
  /* the SAK unwrapped by the KEK */
  unsigned char sak[MKA_MAX_SAK_LEN];

  /* the Key Identifier (Server MI + Key Number) */
  uint8_t ki[MKA_KI_LEN];

  /* SCIs of active participants (those that have sent MKPDUs) for the
   * CA using this CKN. Note there can be passive participants, see
   * IEEE 802.1X-2020 9.4.6 */
  wmem_map_t *sci_map;
  wmem_array_t *mi_array;

  unsigned char salt[MACSEC_XPN_SALT_LEN];

  uint64_t cipher_suite;
  unsigned sak_len;
} mka_sak_info_key_t;

typedef struct _mka_ckn_info_key {
  /* The KEK derived from the CAK */
  unsigned char kek[MKA_MAX_KEK_LEN];
  unsigned kek_len;

  /* The ICK derived from the CAK */
  unsigned char ick[MKA_MAX_ICK_LEN];
  unsigned ick_len;
} mka_ckn_info_key_t;

typedef struct _mka_ckn_info {
  /* CKN: a byte array of 0 to 32 bytes. */
  unsigned char *ckn;
  unsigned ckn_len;

  /* CAK: a byte array of 0 to 32 bytes. */
  unsigned char *cak;
  unsigned cak_len;

  /* Identifier for the name of the entry. */
  char *name;

  /* KEK/ICK data for this entry */
  mka_ckn_info_key_t key;
} mka_ckn_info_t;

/* Tap record emitted once per MKPDU carrying a CKN (known or not). */
typedef struct _mka_ca_tap {
  /* CA this MKPDU belongs to. ckn_info is NULL for a CKN not in the table
   * (its MKPDUs cannot be authenticated and its SAK cannot be unwrapped). */
  const mka_ckn_info_t *ckn_info;
  /* Raw CKN bytes from the Basic Parameter Set, identifying the CA even when
   * ckn_info is NULL. */
  uint8_t ckn[MKA_MAX_CKN_LEN_PUB];
  unsigned ckn_len;

  uint32_t frame_num;
  nstime_t abs_ts;

  /* Actor identity from the Basic Parameter Set. */
  uint8_t actor_sci[MACSEC_SCI_LEN];
  uint8_t actor_mi[MKA_MI_LEN_PUB];
  uint32_t actor_mn;
  uint8_t mka_version;
  bool key_server;

  /* Distributed SAK parameter set, if present. */
  bool has_dist_sak;
  uint8_t dist_sak_an;
  uint32_t dist_sak_kn;
  uint8_t dist_sak_ki[MKA_KI_LEN];   /* server MI + key number */
  uint8_t dist_sak[MKA_MAX_SAK_LEN]; /* unwrapped SAK (if KEK known) */
  unsigned dist_sak_len;             /* 0 if the SAK was not unwrapped */

  /* MACsec SAK Use parameter set, if present. */
  bool has_sak_use;
  uint8_t latest_an;
  bool latest_tx;                    /* ltx */
  bool latest_rx;                    /* lrx */
  bool latest_ki_valid;
  uint8_t latest_ki[MKA_KI_LEN];     /* latest key server MI + key number */
  uint8_t old_an;
  bool old_tx;                       /* otx */
  bool old_rx;                       /* orx */
  bool old_ki_valid;
  uint8_t old_ki[MKA_KI_LEN];        /* old key server MI + key number */

  /* Peer lists: arrays of MKA_MI_LEN_PUB-byte MIs. */
  wmem_array_t *live_peers;
  wmem_array_t *potential_peers;
} mka_ca_tap_t;

/* access to the table data from macsec dissector */
const mka_ckn_info_t * get_mka_ckn_table(void);
unsigned get_mka_ckn_table_count(void);

mka_sak_info_key_t *mka_get_sak_info(const mka_ckn_info_t *ckn_info, unsigned an, uint32_t frame_num);

/* This LPN is only guaranteed to be accurate to the upper 33 bits, as that
 * is all that is required for the recovery algorithm in 802.1AE-2018 10.6.2
 * sci is allowed to be NULL, in which case the largest value for any
 * SCI for this SAK is returned. */
uint64_t mka_get_lpn(const mka_sak_info_key_t *sak_info, const uint8_t *sci, uint32_t frame_num);

#endif
