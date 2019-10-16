/* packet-knxip_decrypt.h
 * Decryption keys and decryption functions for KNX/IP Dissector
 * Copyright 2018, ise GmbH <Ralf.Nasilowski@ise.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef KNXIP_CRYPT_H
#define KNXIP_CRYPT_H

#define KNX_KEY_LENGTH  16

// Calculate MAC for KNX IP Security or KNX Data Security
void knx_ccm_calc_cbc_mac( guint8 p_mac[ KNX_KEY_LENGTH ], const guint8 key[ KNX_KEY_LENGTH ],
  const guint8* a_bytes, gint a_length, const guint8* p_bytes, gint p_length,
  const guint8 b_0[ KNX_KEY_LENGTH ] );

// Calculate MAC for KNX IP Security
void knxip_ccm_calc_cbc_mac( guint8 p_mac[ KNX_KEY_LENGTH ], const guint8 key[ KNX_KEY_LENGTH ],
  const guint8* a_bytes, gint a_length, const guint8* p_bytes, gint p_length,
  const guint8* nonce, guint8 nonce_length );

// Encrypt for KNX IP Security or KNX Data Security
guint8* knx_ccm_encrypt( guint8* p_result, const guint8 key[ KNX_KEY_LENGTH ], const guint8* p_bytes, gint p_length,
  const guint8* mac, guint8 mac_length, const guint8 ctr_0[ KNX_KEY_LENGTH ], guint8 s0_bytes_used_for_mac);

// Encrypt for KNX IP Security
guint8* knxip_ccm_encrypt( guint8* p_result, const guint8 key[ KNX_KEY_LENGTH ], const guint8* p_bytes, gint p_length,
  const guint8 mac[ KNX_KEY_LENGTH ], const guint8* nonce, guint8 nonce_length );

// Decrypt for KNX IP Security
guint8* knxip_ccm_decrypt( guint8* p_result, const guint8 key[ KNX_KEY_LENGTH ], const guint8* crypt, gint crypt_length,
  const guint8* nonce, guint8 nonce_length );

// For importing keyring.XML file exported from ETS:

struct knx_keyring_mca_keys
{
  struct knx_keyring_mca_keys* next;
  guint8 mca[ 4 ];  // IP multicast address
  guint8 key[ KNX_KEY_LENGTH ];  // encryption key
};

struct knx_keyring_ga_keys
{
  struct knx_keyring_ga_keys* next;
  guint16 ga;  // KNX GA
  guint8 key[ KNX_KEY_LENGTH ];  // encryption key
};

struct knx_keyring_ga_senders
{
  struct knx_keyring_ga_senders* next;
  guint16 ga;  // KNX GA
  guint16 ia;  // sending KNX IA
};

struct knx_keyring_ia_keys
{
  struct knx_keyring_ia_keys* next;
  guint16 ia;  // KNX IA
  guint8 key[ KNX_KEY_LENGTH ];  // encryption key
};

struct knx_keyring_ia_seqs
{
  struct knx_keyring_ia_seqs* next;
  guint16 ia;  // KNX IA
  guint64 seq;  // 6-byte sequence number
};

extern struct knx_keyring_mca_keys* knx_keyring_mca_keys;
extern struct knx_keyring_ga_keys* knx_keyring_ga_keys;
extern struct knx_keyring_ga_senders* knx_keyring_ga_senders;
extern struct knx_keyring_ia_keys* knx_keyring_ia_keys;
extern struct knx_keyring_ia_seqs* knx_keyring_ia_seqs;

// Read KNX security keys from keyring XML file (exported from ETS)
void read_knx_keyring_xml_file( const gchar* key_file, const gchar* password, const gchar* key_info_file );

#endif // KNXIP_CRYPT_H

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
