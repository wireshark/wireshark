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
void knx_ccm_calc_cbc_mac( uint8_t p_mac[ KNX_KEY_LENGTH ], const uint8_t key[ KNX_KEY_LENGTH ],
  const uint8_t* a_bytes, int a_length, const uint8_t* p_bytes, int p_length,
  const uint8_t b_0[ KNX_KEY_LENGTH ] );

// Calculate MAC for KNX IP Security
void knxip_ccm_calc_cbc_mac( uint8_t p_mac[ KNX_KEY_LENGTH ], const uint8_t key[ KNX_KEY_LENGTH ],
  const uint8_t* a_bytes, int a_length, const uint8_t* p_bytes, int p_length,
  const uint8_t* nonce, uint8_t nonce_length );

// Encrypt for KNX IP Security or KNX Data Security
uint8_t* knx_ccm_encrypt( uint8_t* p_result, const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t* p_bytes, int p_length,
  const uint8_t* mac, uint8_t mac_length, const uint8_t ctr_0[ KNX_KEY_LENGTH ], uint8_t s0_bytes_used_for_mac);

// Encrypt for KNX IP Security
uint8_t* knxip_ccm_encrypt( uint8_t* p_result, const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t* p_bytes, int p_length,
  const uint8_t mac[ KNX_KEY_LENGTH ], const uint8_t* nonce, uint8_t nonce_length );

// Decrypt for KNX IP Security
uint8_t* knxip_ccm_decrypt( uint8_t* p_result, const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t* crypt, int crypt_length,
  const uint8_t* nonce, uint8_t nonce_length );

// For importing keyring.XML file exported from ETS:

struct knx_keyring_mca_keys
{
  struct knx_keyring_mca_keys* next;
  uint8_t mca[ 4 ];  // IP multicast address
  uint8_t key[ KNX_KEY_LENGTH ];  // encryption key
};

struct knx_keyring_ga_keys
{
  struct knx_keyring_ga_keys* next;
  uint16_t ga;  // KNX GA
  uint8_t key[ KNX_KEY_LENGTH ];  // encryption key
};

struct knx_keyring_ga_senders
{
  struct knx_keyring_ga_senders* next;
  uint16_t ga;  // KNX GA
  uint16_t ia;  // sending KNX IA
};

struct knx_keyring_ia_keys
{
  struct knx_keyring_ia_keys* next;
  uint16_t ia;  // KNX IA
  uint8_t key[ KNX_KEY_LENGTH ];  // encryption key
};

struct knx_keyring_ia_seqs
{
  struct knx_keyring_ia_seqs* next;
  uint16_t ia;  // KNX IA
  uint64_t seq;  // 6-byte sequence number
};

extern struct knx_keyring_mca_keys* knx_keyring_mca_keys;
extern struct knx_keyring_ga_keys* knx_keyring_ga_keys;
extern struct knx_keyring_ga_senders* knx_keyring_ga_senders;
extern struct knx_keyring_ia_keys* knx_keyring_ia_keys;
extern struct knx_keyring_ia_seqs* knx_keyring_ia_seqs;

// Read KNX security keys from keyring XML file (exported from ETS)
void read_knx_keyring_xml_file( const char* key_file, const char* password, const char* key_info_file );

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
