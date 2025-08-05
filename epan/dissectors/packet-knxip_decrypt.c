/* packet-knxip_decrypt.c
 * Decryption keys and decryption functions for KNX/IP Dissector
 * Copyright 2018, ise GmbH <Ralf.Nasilowski@ise.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#define WS_LOG_DOMAIN "packet-knxip"

#include <wsutil/file_util.h>
#include <epan/proto.h>
#include "packet-knxip_decrypt.h"
#include <epan/wmem_scopes.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/strtoi.h>
#include <wsutil/wslog.h>
#include <wsutil/inet_addr.h>
#include <libxml/tree.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#define TEXT_BUFFER_SIZE  128

#define IPA_SIZE  4  // = size of IPv4 address

#define BASE64_KNX_KEY_LENGTH  24  // = length of base64 encoded KNX key

struct knx_keyring_mca_keys* knx_keyring_mca_keys;
struct knx_keyring_ga_keys* knx_keyring_ga_keys;
struct knx_keyring_ga_senders* knx_keyring_ga_senders;
struct knx_keyring_ia_keys* knx_keyring_ia_keys;
struct knx_keyring_ia_seqs* knx_keyring_ia_seqs;

// Encrypt 16-byte block via AES
static void encrypt_block( const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t plain[ KNX_KEY_LENGTH ], uint8_t p_crypt[ KNX_KEY_LENGTH ] )
{
  gcry_cipher_hd_t cryptor = NULL;
  gcry_cipher_open( &cryptor, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0 );
  gcry_cipher_setkey( cryptor, key, KNX_KEY_LENGTH );
  gcry_cipher_encrypt( cryptor, p_crypt, KNX_KEY_LENGTH, plain, KNX_KEY_LENGTH );
  gcry_cipher_close( cryptor );
}

// Create B_0 for CBC-MAC
static void build_b0( uint8_t p_result[ KNX_KEY_LENGTH ], const uint8_t* nonce, uint8_t nonce_length )
{
  DISSECTOR_ASSERT( nonce_length <= KNX_KEY_LENGTH );
  if( nonce_length ) memcpy( p_result, nonce, nonce_length );
  memset( p_result + nonce_length, 0, KNX_KEY_LENGTH - nonce_length );
}

// Create Ctr_0 for CCM encryption/decryption
static void build_ctr0( uint8_t p_result[ KNX_KEY_LENGTH ], const uint8_t* nonce, uint8_t nonce_length )
{
  build_b0( p_result, nonce, nonce_length );
  p_result[ KNX_KEY_LENGTH - 2 ] = 0xFF;
}

// Calculate MAC for KNX IP Security or KNX Data Security
void knx_ccm_calc_cbc_mac(uint8_t p_mac[ KNX_KEY_LENGTH ], const uint8_t key[ KNX_KEY_LENGTH ],
  const uint8_t* a_bytes, int a_length, const uint8_t* p_bytes, int p_length,
  const uint8_t b_0[ KNX_KEY_LENGTH ] )
{
  uint8_t plain[ KNX_KEY_LENGTH ];
  uint8_t b_pos;

  // Add B_0
  memcpy( plain, b_0, KNX_KEY_LENGTH );
  encrypt_block( key, plain, p_mac );

  // Add a_length
  plain[ 0 ] = (uint8_t) ((a_length >> 8) ^ p_mac[ 0 ]);
  plain[ 1 ] = (uint8_t) ((a_length & 0xFF) ^ p_mac[ 1 ]);
  b_pos = 2;

  // Add a_bytes directly followed by p_bytes
  while( a_length || p_length )
  {
    while( a_length && b_pos < KNX_KEY_LENGTH )
    {
      plain[ b_pos ] = *a_bytes++ ^ p_mac[ b_pos ];
      --a_length;
      ++b_pos;
    }

    while( p_length && b_pos < KNX_KEY_LENGTH )
    {
      plain[ b_pos ] = *p_bytes++ ^ p_mac[ b_pos ];
      --p_length;
      ++b_pos;
    }

    while( b_pos < KNX_KEY_LENGTH )
    {
      plain[ b_pos ] = p_mac[ b_pos ];
      ++b_pos;
    }

    encrypt_block( key, plain, p_mac );

    b_pos = 0;
  }
}

// Calculate MAC for KNX IP Security, using 6-byte Sequence ID
void knxip_ccm_calc_cbc_mac( uint8_t p_mac[ KNX_KEY_LENGTH ], const uint8_t key[ KNX_KEY_LENGTH ],
  const uint8_t* a_bytes, int a_length, const uint8_t* p_bytes, int p_length,
  const uint8_t* nonce, uint8_t nonce_length )
{
  uint8_t b_0[ KNX_KEY_LENGTH ];
  build_b0( b_0, nonce, nonce_length );
  b_0[ KNX_KEY_LENGTH - 2 ] = (uint8_t) (p_length >> 8);
  b_0[ KNX_KEY_LENGTH - 1 ] = (uint8_t) (p_length & 0xFF);
  knx_ccm_calc_cbc_mac( p_mac, key, a_bytes, a_length, p_bytes, p_length, b_0 );
}

// Encrypt for KNX IP Security or KNX Data Security
uint8_t* knx_ccm_encrypt(wmem_allocator_t* scope, uint8_t* p_result, const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t* p_bytes, int p_length,
  const uint8_t* mac, uint8_t mac_length, const uint8_t ctr_0[ KNX_KEY_LENGTH ], uint8_t s0_bytes_used_for_mac )
{
  if( p_length >= 0 && !(p_length && !p_bytes) )
  {
    // NB: mac_length = 16 (for IP Security), or 4 (for Data Security)

    uint8_t* result = p_result ? p_result : (uint8_t*) wmem_alloc(scope, p_length + mac_length );

    uint8_t* dest = result;

    uint8_t ctr[ KNX_KEY_LENGTH ];
    uint8_t mask[ KNX_KEY_LENGTH ];
    uint8_t mask_0[ KNX_KEY_LENGTH ];
    uint8_t b_pos;

    // Encrypt ctr_0 for mac
    memcpy( ctr, ctr_0, KNX_KEY_LENGTH );
    encrypt_block( key, ctr, mask_0 );

    // Encrypt p_bytes with rest of S_0, only if mac_length < 16.
    b_pos = s0_bytes_used_for_mac;
    while (p_length && b_pos < KNX_KEY_LENGTH )
    {
      *dest++ = mask_0[b_pos++] ^ *p_bytes++;
      --p_length;
    }

    // Encrypt p_bytes
    while( p_length )
    {
      // Increment and encrypt ctr
      ++ctr[ KNX_KEY_LENGTH - 1 ];
      encrypt_block( key, ctr, mask );

      // Encrypt input block via encrypted ctr
      b_pos = 0;
      while( p_length && b_pos < KNX_KEY_LENGTH )
      {
        *dest++ = mask[ b_pos++] ^ *p_bytes++;
        --p_length;
      }
    }

    if( mac )
    {
      if( mac_length > KNX_KEY_LENGTH )
      {
        mac_length = KNX_KEY_LENGTH;
      }

      // Encrypt and append mac
      b_pos = 0;
      while( mac_length )
      {
        *dest++ = mask_0[ b_pos++] ^ *mac++;
        --mac_length;
      }
    }

    return result;
  }

  return NULL;
}

// Encrypt for KNX IP Security (with 16-byte MAC and Nonce based on 6-byte Sequence ID)
uint8_t* knxip_ccm_encrypt(wmem_allocator_t* scope, uint8_t* p_result, const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t* p_bytes, int p_length,
  const uint8_t mac[KNX_KEY_LENGTH], const uint8_t* nonce, uint8_t nonce_length )
{
  uint8_t ctr_0[ KNX_KEY_LENGTH ];
  build_ctr0( ctr_0, nonce, nonce_length );
  return knx_ccm_encrypt(scope, p_result, key, p_bytes, p_length, mac, KNX_KEY_LENGTH, ctr_0, KNX_KEY_LENGTH );
}

// Decrypt for KNX-IP Security (with 16-byte MAC and Nonce based on 6-byte Sequence ID)
uint8_t* knxip_ccm_decrypt(wmem_allocator_t* scope, uint8_t* p_result, const uint8_t key[ KNX_KEY_LENGTH ], const uint8_t* crypt, int crypt_length,
  const uint8_t* nonce, uint8_t nonce_length )
{
  int p_length = crypt_length - KNX_KEY_LENGTH;
  uint8_t ctr_0[ KNX_KEY_LENGTH ];
  build_ctr0( ctr_0, nonce, nonce_length );
  return knx_ccm_encrypt(scope, p_result, key, crypt, p_length, crypt + p_length, KNX_KEY_LENGTH, ctr_0, KNX_KEY_LENGTH );
}

static void fprintf_hex( FILE* f, const uint8_t* data, uint8_t length )
{
  for( ; length; --length ) fprintf( f, " %02X", *data++ );
  fputc( '\n', f );
}

static void clear_keyring_data( void )
{
  while( knx_keyring_mca_keys )
  {
    struct knx_keyring_mca_keys* mca_key = knx_keyring_mca_keys;
    knx_keyring_mca_keys = mca_key->next;
    wmem_free( wmem_epan_scope(), mca_key );
  }

  while( knx_keyring_ga_keys )
  {
    struct knx_keyring_ga_keys* ga_key = knx_keyring_ga_keys;
    knx_keyring_ga_keys = ga_key->next;
    wmem_free( wmem_epan_scope(), ga_key );
  }

  while( knx_keyring_ga_senders )
  {
    struct knx_keyring_ga_senders* ga_sender = knx_keyring_ga_senders;
    knx_keyring_ga_senders = ga_sender->next;
    wmem_free( wmem_epan_scope(), ga_sender );
  }

  while( knx_keyring_ia_keys )
  {
    struct knx_keyring_ia_keys* ia_key = knx_keyring_ia_keys;
    knx_keyring_ia_keys = ia_key->next;
    wmem_free( wmem_epan_scope(), ia_key );
  }

  while( knx_keyring_ia_seqs )
  {
    struct knx_keyring_ia_seqs* ia_seq = knx_keyring_ia_seqs;
    knx_keyring_ia_seqs = ia_seq->next;
    wmem_free( wmem_epan_scope(), ia_seq );
  }
}

// Read IP address
static void read_ip_addr( uint8_t result[ 4 ], const char* text )
{
  ws_in4_addr value = 0;
  if( ws_inet_pton4( text, &value ) )
    memcpy( result, &value, 4 );
  else
    memset( result, 0, 4 );
}

// Read KNX group address
static uint16_t read_ga( const char* text )
{
  unsigned a[ 3 ];
  int n = sscanf( text, "%u/%u/%u", a, a + 1, a + 2 );
  return
    (n == 1) ? (uint16_t) a[ 0 ] :
    (n == 2) ? (uint16_t) ((a[ 0 ] << 11) | a[ 1 ]) :
    (n == 3) ? (uint16_t) ((a[ 0 ] << 11) | (a[ 1 ] << 8) | a[ 2 ]) :
    0;
}

// Read KNX individual address
static uint16_t read_ia( const char* text )
{
  unsigned a[ 3 ];
  int n = sscanf( text, "%u.%u.%u", a, a + 1, a + 2 );
  return
    (n == 1) ? (uint16_t) a[ 0 ] :
    (n == 2) ? (uint16_t) ((a[ 0 ] << 8) | a[ 1 ]) :
    (n == 3) ? (uint16_t) ((a[ 0 ] << 12) | (a[ 1 ] << 8) | a[ 2 ]) :
    0;
}

// Read 6-byte sequence number from decimal representation
static uint64_t read_seq( const char* text )
{
  uint64_t result;
  return ws_strtou64( text, NULL, &result ) ? result : 0;
}

// Decrypt key
static void decrypt_key( uint8_t key[] _U_, uint8_t password_hash[] _U_, uint8_t created_hash[] _U_ )
{
  // TODO: decrypt as AES128-CBC(key, password_hash, created_hash)
}

// Decode and decrypt key
static void decode_and_decrypt_key( uint8_t key[ BASE64_KNX_KEY_LENGTH + 1 ], const char* text, uint8_t password_hash[], uint8_t created_hash[] )
{
  size_t out_len;
  snprintf( (char*) key, BASE64_KNX_KEY_LENGTH + 1, "%s", text );
  g_base64_decode_inplace( (char*) key, &out_len );
  decrypt_key( key, password_hash, created_hash );
}

// Add MCA <-> key association
static void add_mca_key( const uint8_t mca[ IPA_SIZE ], const char* text, uint8_t password_hash[], uint8_t created_hash[], FILE* f2 )
{
  int text_length = (int) strlen( text );

  if( text_length == BASE64_KNX_KEY_LENGTH )
  {
    uint8_t key[ BASE64_KNX_KEY_LENGTH + 1 ];
    struct knx_keyring_mca_keys** mca_keys_next;
    struct knx_keyring_mca_keys* mca_key;

    decode_and_decrypt_key( key, text, password_hash, created_hash );

    mca_keys_next = &knx_keyring_mca_keys;

    while( (mca_key = *mca_keys_next) != NULL )
    {
      if( memcmp( mca_key->mca, mca, IPA_SIZE ) == 0 )
      {
        if( memcmp( mca_key->key, key, KNX_KEY_LENGTH ) == 0 )
        {
          return;
        }
      }

      mca_keys_next = &mca_key->next;
    }

    if( f2 )
    {
      fprintf( f2, "MCA %u.%u.%u.%u key", mca[ 0 ], mca[ 1 ], mca[ 2 ], mca[ 3 ] );
      fprintf_hex( f2, key, KNX_KEY_LENGTH );
    }

    mca_key = wmem_new(wmem_epan_scope(), struct knx_keyring_mca_keys);

    if( mca_key )
    {
      mca_key->next = NULL;
      memcpy( mca_key->mca, mca, IPA_SIZE );
      memcpy( mca_key->key, key, KNX_KEY_LENGTH );

      *mca_keys_next = mca_key;
    }
  }
}

// Add GA <-> key association
static void add_ga_key( uint16_t ga, const char* text, uint8_t password_hash[], uint8_t created_hash[], FILE* f2 )
{
  int text_length = (int) strlen( text );

  if( text_length == BASE64_KNX_KEY_LENGTH )
  {
    uint8_t key[ BASE64_KNX_KEY_LENGTH + 1 ];
    struct knx_keyring_ga_keys** ga_keys_next;
    struct knx_keyring_ga_keys* ga_key;

    decode_and_decrypt_key( key, text, password_hash, created_hash );

    ga_keys_next = &knx_keyring_ga_keys;

    while( (ga_key = *ga_keys_next) != NULL )
    {
      if( ga_key->ga == ga )
      {
        if( memcmp( ga_key->key, key, KNX_KEY_LENGTH ) == 0 )
        {
          return;
        }
      }

      ga_keys_next = &ga_key->next;
    }

    if( f2 )
    {
      fprintf( f2, "GA %u/%u/%u key", (ga >> 11) & 0x1F, (ga >> 8) & 0x7, ga & 0xFF );
      fprintf_hex( f2, key, KNX_KEY_LENGTH );
    }

    ga_key = wmem_new(wmem_epan_scope(), struct knx_keyring_ga_keys);

    if( ga_key )
    {
      ga_key->next = NULL;
      ga_key->ga = ga;
      memcpy( ga_key->key, key, KNX_KEY_LENGTH );

      *ga_keys_next = ga_key;
    }
  }
}

// Add GA <-> sender association
static void add_ga_sender( uint16_t ga, const char* text, FILE* f2 )
{
  uint16_t ia = read_ia( text );
  struct knx_keyring_ga_senders** ga_senders_next = &knx_keyring_ga_senders;
  struct knx_keyring_ga_senders* ga_sender;

  while( (ga_sender = *ga_senders_next) != NULL )
  {
    if( ga_sender->ga == ga )
    {
      if( ga_sender->ia == ia )
      {
        return;
      }
    }

    ga_senders_next = &ga_sender->next;
  }

  if( f2 )
  {
    fprintf( f2, "GA %u/%u/%u sender %u.%u.%u\n", (ga >> 11) & 0x1F, (ga >> 8) & 0x7, ga & 0xFF, (ia >> 12) & 0xF, (ia >> 8) & 0xF, ia & 0xFF );
  }

  ga_sender = wmem_new(wmem_epan_scope(), struct knx_keyring_ga_senders);

  if( ga_sender )
  {
    ga_sender->next = NULL;
    ga_sender->ga = ga;
    ga_sender->ia = ia;

    *ga_senders_next = ga_sender;
  }
}

// Add IA <-> key association
static void add_ia_key( uint16_t ia, const char* text, uint8_t password_hash[], uint8_t created_hash[], FILE* f2 )
{
  int text_length = (int) strlen( text );

  if( text_length == BASE64_KNX_KEY_LENGTH )
  {
    uint8_t key[ BASE64_KNX_KEY_LENGTH + 1 ];
    struct knx_keyring_ia_keys** ia_keys_next;
    struct knx_keyring_ia_keys* ia_key;

    decode_and_decrypt_key( key, text, password_hash, created_hash );

    ia_keys_next = &knx_keyring_ia_keys;

    while( (ia_key = *ia_keys_next) != NULL )
    {
      if( ia_key->ia == ia )
      {
        if( memcmp( ia_key->key, key, KNX_KEY_LENGTH ) == 0 )
        {
          return;
        }
      }

      ia_keys_next = &ia_key->next;
    }

    if( f2 )
    {
      fprintf( f2, "IA %u.%u.%u key", (ia >> 12) & 0xF, (ia >> 8) & 0xF, ia & 0xFF );
      fprintf_hex( f2, key, KNX_KEY_LENGTH );
    }

    ia_key = wmem_new(wmem_epan_scope(), struct knx_keyring_ia_keys);

    if( ia_key )
    {
      ia_key->next = NULL;
      ia_key->ia = ia;
      memcpy( ia_key->key, key, KNX_KEY_LENGTH );

      *ia_keys_next = ia_key;
    }
  }
}

// Add IA <-> sequence number association
static void add_ia_seq( uint16_t ia, const char* text, FILE* f2 )
{
  uint64_t seq = read_seq( text );

  struct knx_keyring_ia_seqs** ia_seqs_next = &knx_keyring_ia_seqs;
  struct knx_keyring_ia_seqs* ia_seq;

  while( (ia_seq = *ia_seqs_next) != NULL )
  {
    if( ia_seq->ia == ia )
    {
      if( ia_seq->seq == seq )
      {
        return;
      }
    }

    ia_seqs_next = &ia_seq->next;
  }

  if( f2 )
  {
    fprintf( f2, "IA %u.%u.%u SeqNr %" PRIu64 "\n", (ia >> 12) & 0xF, (ia >> 8) & 0xF, ia & 0xFF, seq );
  }

  ia_seq = wmem_new(wmem_epan_scope(), struct knx_keyring_ia_seqs);

  if( ia_seq )
  {
    ia_seq->next = NULL;
    ia_seq->ia = ia;
    ia_seq->seq = seq;

    *ia_seqs_next = ia_seq;
  }
}

// Calculate PBKDF2(HMAC-SHA256, password, "1.keyring.ets.knx.org", 65536, 128)
static void make_password_hash( uint8_t password_hash[] _U_, const char* password _U_ )
{
  // TODO: password_hash = PBKDF2(HMAC-SHA256, password, "1.keyring.ets.knx.org", 65536, 128)
}

// Calculate MSB128(SHA256(created))
static void make_created_hash( uint8_t created_hash[] _U_, const char* created _U_ )
{
  // TODO: created_hash = MSB128(SHA256(created))
}

static void read_knx_keyring_xml_backbone_element(xmlNodePtr backbone, uint8_t password_hash[], uint8_t created_hash[], FILE* f2)
{
  bool address_valid = false;
  uint8_t multicast_address[IPA_SIZE] = { 0 };

  /* Parse out the attributes of the Backbone element */
  for (xmlAttrPtr attr = backbone->properties; attr; attr = attr->next)
  {
    if (xmlStrcmp(attr->name, (const xmlChar*)"MulticastAddress") == 0)
    {
      xmlChar* str_address = xmlNodeListGetString(backbone->doc, attr->children, 1);
      if (str_address != NULL)
      {
        read_ip_addr(multicast_address, str_address);
        address_valid = true;
        xmlFree(str_address);
      }
    }
    else if (xmlStrcmp(attr->name, (const xmlChar*)"Key") == 0)
    {
      if (address_valid)
      {
        xmlChar* str_key = xmlNodeListGetString(backbone->doc, attr->children, 1);
        if (str_key != NULL)
        {
          add_mca_key(multicast_address, str_key, password_hash, created_hash, f2);
          xmlFree(str_key);
        }
      }
    }
  }

}

static void read_knx_keyring_xml_group_element(xmlNodePtr group, uint8_t password_hash[], uint8_t created_hash[], FILE* f2)
{
  bool address_valid = false;
  uint16_t addr = 0;

  /* Parse out the attributes of the Group element */
  for (xmlAttrPtr attr = group->properties; attr; attr = attr->next)
  {
      if (xmlStrcmp(attr->name, (const xmlChar*)"Address") == 0)
      {
        xmlChar* str_address = xmlNodeListGetString(group->doc, attr->children, 1);
        if (str_address != NULL)
        {
          addr = read_ga(str_address);
          address_valid = true;
          xmlFree(str_address);
        }
      }
      else if (xmlStrcmp(attr->name, (const xmlChar*)"Key") == 0)
      {
        if (address_valid)
        {
          xmlChar* str_key = xmlNodeListGetString(group->doc, attr->children, 1);
          add_ga_key(addr, str_key, password_hash, created_hash, f2);
          xmlFree(str_key);
          }
        }
        else if (xmlStrcmp(attr->name, (const xmlChar*)"Senders") == 0)
        {
          if (address_valid)
          {
            xmlChar* str_senders = xmlNodeListGetString(group->doc, attr->children, 1);
            if (str_senders != NULL)
            {
              // Add senders given by space separated list of KNX IAs
              static const char delim[] = " ,";
              const char* token = strtok(str_senders, delim);
              while (token)
              {
                add_ga_sender(addr, token, f2);
                token = strtok(NULL, delim);
              }
              xmlFree(str_senders);
          }
        }
      }
    }

}

static void read_knx_keyring_xml_device_element(xmlNodePtr device, uint8_t password_hash[], uint8_t created_hash[], FILE* f2)
{
  bool address_valid = false;
  uint16_t addr = 0;

  /* Parse out the attributes of the Device element */
  for (xmlAttrPtr attr = device->properties; attr; attr = attr->next)
  {
    if (xmlStrcmp(attr->name, (const xmlChar*)"IndividualAddress") == 0)
    {
      xmlChar* str_address = xmlNodeListGetString(device->doc, attr->children, 1);
      if (str_address != NULL)
      {
        addr = read_ia(str_address);
        address_valid = true;
        xmlFree(str_address);
      }
    }
    else if (xmlStrcmp(attr->name, (const xmlChar*)"ToolKey") == 0)
    {
      if (address_valid)
      {
        xmlChar* str_key = xmlNodeListGetString(device->doc, attr->children, 1);
        if (str_key != NULL)
        {
          add_ia_key(addr, str_key, password_hash, created_hash, f2);
          xmlFree(str_key);
        }
      }
    }
    else if (xmlStrcmp(attr->name, (const xmlChar*)"SequenceNumber") == 0)
    {
      if (address_valid)
      {
        xmlChar* str_seq = xmlNodeListGetString(device->doc, attr->children, 1);
        if (str_seq != NULL)
        {
          add_ia_seq(addr, str_seq, f2);
          xmlFree(str_seq);
        }
      }
    }
  }
}

// Read KNX security key info from keyring XML file.
//
// An example keyring XML file is
//   "test/keys/knx_keyring.xml".
//
// Corresponding test is
//   suite_decryption.case_decrypt_knxip.test_knxip_keyring_xml_import
//
// Resulting decoded and decrypted 16-byte keys with context info are optionally written to a "key info" text file.
// This may be useful, as these keys are not directly available from the keyring XML file .
void read_knx_keyring_xml_file(const char* key_file, const char* password, const char* key_info_file)
{
  xmlDocPtr doc;
  xmlNodePtr root_element = NULL;
  xmlNodePtr key_ring = NULL;
  uint8_t password_hash[KNX_KEY_LENGTH] = { 0 };
  uint8_t created_hash[KNX_KEY_LENGTH] = {0};

  // Clear old keyring data
  clear_keyring_data();

  doc = xmlReadFile(key_file, NULL, 0);
  if (doc == NULL)
    return;

  root_element = xmlDocGetRootElement(doc);
  if (root_element == NULL)
  {
    xmlFreeDoc(doc);
    return;
  }

  /* Find the Keyring element */
  if (xmlStrcmp(root_element->name, (const xmlChar*)"Keyring") == 0)
  {
    key_ring = root_element;
  }
  else
  {
    for (xmlNodePtr cur = root_element->children; cur != NULL; cur = cur->next)
    {
      if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, (const xmlChar*)"Keyring") == 0)
      {
        key_ring = cur;
        break;
      }
    }
  }

  if (key_ring == NULL) {
    xmlFreeDoc(doc);
    return;
  }

  // Optionally write extracted data to key info file
  FILE* f2 = (!key_info_file || !*key_info_file) ? NULL :
    (strcmp( key_info_file, "-" ) == 0) ? stdout :
    ws_fopen( key_info_file, "w" );

  make_password_hash(password_hash, password);

  /* Parse out the attributes of the Keyring element */
  for (xmlAttrPtr attr = key_ring->properties; attr; attr = attr->next)
  {
    if (xmlStrcmp(attr->name, (const xmlChar*)"Created") == 0)
    {
      xmlChar* str_created = xmlNodeListGetString(key_ring->doc, attr->children, 1);
      if (str_created != NULL)
       {
         make_created_hash(created_hash, str_created);
         xmlFree(str_created);
       }
    }
  }

  /* Parse out subelements of Keyring element */
  for (xmlNodePtr cur = key_ring->children; cur != NULL; cur = cur->next)
  {
    if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, (const xmlChar*)"Backbone") == 0)
    {
      read_knx_keyring_xml_backbone_element(cur, password_hash, created_hash, f2);
    }
    else if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, (const xmlChar*)"Interface") == 0)
    {
      for (xmlNodePtr group = cur->children; group != NULL; group = group->next)
      {
        if (group->type == XML_ELEMENT_NODE && xmlStrcmp(group->name, (const xmlChar*)"Group") == 0)
        {
          read_knx_keyring_xml_group_element(group, password_hash, created_hash, f2);
        }
      }
    }
    else if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, (const xmlChar*)"GroupAddresses") == 0)
    {
      for (xmlNodePtr group = cur->children; group != NULL; group = group->next)
      {
        if (group->type == XML_ELEMENT_NODE && xmlStrcmp(group->name, (const xmlChar*)"Group") == 0)
        {
          read_knx_keyring_xml_group_element(group, password_hash, created_hash, f2);
        }
      }
    }
    else if (cur->type == XML_ELEMENT_NODE && xmlStrcmp(cur->name, (const xmlChar*)"Devices") == 0)
    {
      for (xmlNodePtr device = cur->children; device != NULL; device = device->next)
      {
        if (device->type == XML_ELEMENT_NODE && xmlStrcmp(device->name, (const xmlChar*)"Device") == 0)
        {
          read_knx_keyring_xml_device_element(device, password_hash, created_hash, f2);
        }
      }
    }
  }

  if (f2 && f2 != stdout)
    fclose(f2);
  xmlFreeDoc(doc);
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
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
