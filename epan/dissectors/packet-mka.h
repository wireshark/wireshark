/* packet-mka.h
 * Routines for MKA packet dissection
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_MKA_H__
#define __PACKET_MKA_H__

#include <epan/packet.h>

#define AES128_KEY_LEN                  16
#define AES256_KEY_LEN                  32

#define MACSEC_AN_COUNT                 4

#define MKA_CAK_AES_GCM_128_LEN (AES128_KEY_LEN)
#define MKA_CAK_AES_GCM_256_LEN (AES256_KEY_LEN)
#define MKA_MAX_CAK_LEN (MKA_CAK_AES_GCM_256_LEN)

#define MKA_MAX_KEK_LEN (MKA_CAK_AES_GCM_256_LEN)
#define MKA_MAX_ICK_LEN (MKA_CAK_AES_GCM_256_LEN)
#define MKA_MAX_SAK_LEN (MKA_CAK_AES_GCM_256_LEN)

typedef struct _mka_ckn_info_key {
  /* The KEK derived from the CAK */
  unsigned char kek[MKA_MAX_KEK_LEN];
  unsigned kek_len;

  /* The ICK derived from the CAK */
  unsigned char ick[MKA_MAX_ICK_LEN];
  unsigned ick_len;

  /* the SAKs unwrapped by the KEK for each AN
   * index is the AN to which the SAK belongs */
  unsigned char saks[MACSEC_AN_COUNT][MKA_MAX_SAK_LEN];

} mka_ckn_info_key_t;

typedef struct _mka_ckn_info {
  /* CKN: a byte array of 0 to 32 bytes. */
  unsigned char *ckn;
  unsigned ckn_len;

  /* CAK: a byte array of 0 to 32 bytes. */
  unsigned char *cak;
  unsigned cak_len;

  /* Identifier for the name of the entry. */
  unsigned char *name;

  /* KEK/ICK/SAK data for this entry */
  mka_ckn_info_key_t key;
} mka_ckn_info_t;

/* access to the table data from macsec dissector */
const mka_ckn_info_t * get_mka_ckn_table(void);
unsigned get_mka_ckn_table_count(void);

#endif
