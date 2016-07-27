/* packet-ipsec.c
 * Routines for IPsec/IPComp packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


/*

Addon: ESP Decryption and Authentication Checking

Frederic ROUDAUT (frederic.roudaut@free.fr)
Copyright 2006 Frederic ROUDAUT

- Decrypt ESP Payload for the following Algorithms defined in RFC 4305:

Encryption Algorithm
--------------------
NULL
TripleDES-CBC [RFC2451] : keylen 192 bits.
AES-CBC with 128-bit keys [RFC3602] : keylen 128 and 192/256 bits.
AES-CTR [RFC3686] : keylen 160/224/288 bits. The remaining 32 bits will be used as nonce.
DES-CBC [RFC2405] : keylen 64 bits

- Add ESP Payload Decryption support for the following Encryption Algorithms :
BLOWFISH-CBC : keylen 128 bits.
TWOFISH-CBC : keylen 128/256 bits.
CAST5-CBC :  keylen 128

- Check ESP Authentication for the following Algorithms defined in RFC 4305:

Authentication Algorithm
------------------------
NULL
HMAC-SHA1-96 [RFC2404] : any keylen
HMAC-MD5-96 [RFC2403] : any keylen
AES-XCBC-MAC-96 [RFC3566] : Not available because no implementation found.

- Add ESP Authentication checking for the following Authentication Algorithm :
HMAC-SHA256 : any keylen
HMAC-RIPEMD160-96 [RFC2857] : any keylen

- Added/Modified Authentication checking (David Dahlberg <dahlberg@fgan.de>):
CHG: HMAC-SHA256 is now HMAC-SHA-256-96 [draft-ietf-ipsec-ciph-sha-256-00]
     -> It is implemented this way in USAGI/KAME (Linux/BSD).
ADD: HMAC-SHA-256-128 [RFC4868]
     ICV length of HMAC-SHA-256 was changed in draft-ietf-ipsec-ciph-sha-256-01
     to 128 bit. This is "SHOULD" be the standard now!
ADD: Additional generic (non-checked) ICV length of 128, 192 and 256.
     This follows RFC 4868 for the SHA-256+ family.

*/

#include "config.h"


#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/exported_pdu.h>
#include <epan/proto_data.h>

/* If you want to be able to decrypt or Check Authentication of ESP packets you MUST define this : */
#ifdef HAVE_LIBGCRYPT
#include <stdio.h>
#include <epan/uat.h>
#include <wsutil/wsgcrypt.h>
#endif /* HAVE_LIBGCRYPT */

#include "packet-ipsec.h"

void proto_register_ipsec(void);
void proto_reg_handoff_ipsec(void);

static int proto_ah = -1;
static int hf_ah_next_header = -1;
static int hf_ah_length = -1;
static int hf_ah_reserved = -1;
static int hf_ah_spi = -1;
static int hf_ah_iv = -1;
static int hf_ah_sequence = -1;
static int proto_esp = -1;
static int hf_esp_spi = -1;
static int hf_esp_iv = -1;
static int hf_esp_icv_good = -1;
static int hf_esp_icv_bad = -1;
static int hf_esp_sequence = -1;
static int hf_esp_pad = -1;
static int hf_esp_pad_len = -1;
static int hf_esp_protocol = -1;
static int hf_esp_authentication_data = -1;
static int hf_esp_sequence_analysis_expected_sn = -1;
static int hf_esp_sequence_analysis_previous_frame = -1;

static int proto_ipcomp = -1;
static int hf_ipcomp_next_header = -1;
static int hf_ipcomp_flags = -1;
static int hf_ipcomp_cpi = -1;

static gint ett_ah = -1;
static gint ett_esp = -1;
static gint ett_esp_icv = -1;
static gint ett_ipcomp = -1;

static expert_field ei_esp_sequence_analysis_wrong_sequence_number = EI_INIT;


static gint exported_pdu_tap = -1;

static dissector_handle_t data_handle;

static dissector_table_t ip_dissector_table;

#ifdef  HAVE_LIBGCRYPT
/* Encryption algorithms defined in RFC 4305 */
#define IPSEC_ENCRYPT_NULL 0
#define IPSEC_ENCRYPT_3DES_CBC 1
#define IPSEC_ENCRYPT_AES_CBC 2
#define IPSEC_ENCRYPT_AES_CTR 3
#define IPSEC_ENCRYPT_DES_CBC 4
#define IPSEC_ENCRYPT_BLOWFISH_CBC 5
#define IPSEC_ENCRYPT_TWOFISH_CBC 6

/* Encryption algorithm defined in RFC 2144 */
#define IPSEC_ENCRYPT_CAST5_CBC 7

/* Encryption algorithm defined in RFC 4106 */
#define IPSEC_ENCRYPT_AES_GCM 8

/* Authentication algorithms defined in RFC 4305 */
#define IPSEC_AUTH_NULL 0
#define IPSEC_AUTH_HMAC_SHA1_96 1
#define IPSEC_AUTH_HMAC_SHA256_96 2
#define IPSEC_AUTH_HMAC_SHA256_128 3
#define IPSEC_AUTH_HMAC_SHA384_192 4
#define IPSEC_AUTH_HMAC_SHA512_256 5
#define IPSEC_AUTH_HMAC_MD5_96 6
#define IPSEC_AUTH_HMAC_RIPEMD160_96 7
/* define IPSEC_AUTH_AES_XCBC_MAC_96 6 */
#define IPSEC_AUTH_ANY_64BIT 8
#define IPSEC_AUTH_ANY_96BIT 9
#define IPSEC_AUTH_ANY_128BIT 10
#define IPSEC_AUTH_ANY_192BIT 11
#define IPSEC_AUTH_ANY_256BIT 12

#define IPSEC_IPV6_ADDR_LEN 128
#define IPSEC_IPV4_ADDR_LEN 32
#define IPSEC_STRLEN_IPV6 32
#define IPSEC_STRLEN_IPV4 8
#define IPSEC_SA_IPV4 1
#define IPSEC_SA_IPV6 2
#define IPSEC_SA_UNKNOWN -1
#define IPSEC_SA_WILDCARDS_ANY '*'
/* the maximum number of bytes (10)(including the terminating nul character(11)) */
#define IPSEC_SPI_LEN_MAX 11

#endif

/* well-known algorithm number (in CPI), from RFC2409 */
#define IPCOMP_OUI      1       /* vendor specific */
#define IPCOMP_DEFLATE  2       /* RFC2394 */
#define IPCOMP_LZS      3       /* RFC2395 */
#define IPCOMP_MAX      4


static const value_string cpi2val[] = {
  { IPCOMP_OUI, "OUI" },
  { IPCOMP_DEFLATE, "DEFLATE" },
  { IPCOMP_LZS, "LZS" },
  { 0, NULL },
};

#define NEW_ESP_DATA_SIZE       8

#ifdef HAVE_LIBGCRYPT
/*-------------------------------------
 * UAT for ESP
 *-------------------------------------
 */
/* UAT entry structure. */
typedef struct {
  guint8 protocol;
  gchar *srcIP;
  gchar *dstIP;
  gchar *spi;

  guint8 encryption_algo;
  gchar *encryption_key_string;
  gchar *encryption_key;
  gint encryption_key_length;
  gboolean         cipher_hd_created;
  gcry_cipher_hd_t cipher_hd;     /* Key is stored here and closed with the SA */

  guint8 authentication_algo;
  gchar *authentication_key_string;
  gchar *authentication_key;
  gint authentication_key_length;
} uat_esp_sa_record_t;

static uat_esp_sa_record_t *uat_esp_sa_records = NULL;

/* Extra SA records that may be set programmatically */
/* 'records' array is now allocated on the heap */
#define MAX_EXTRA_SA_RECORDS 16
typedef struct extra_esp_sa_records_t {
  guint num_records;
  uat_esp_sa_record_t *records;
} extra_esp_sa_records_t;
static extra_esp_sa_records_t extra_esp_sa_records;

static uat_t * esp_uat = NULL;
static guint num_sa_uat = 0;

/*
   Name : static gint compute_ascii_key(gchar **ascii_key, gchar *key)
   Description : Allocate memory for the key and transform the key if it is hexadecimal
   Return : Return the key length
   Params:
      - gchar **ascii_key : the resulting ascii key allocated here
      - gchar *key : the key to compute
*/
static gint
compute_ascii_key(gchar **ascii_key, const gchar *key)
{
  guint key_len = 0, raw_key_len;
  gint hex_digit;
  guchar key_byte;
  guint i, j;

  if(key != NULL)
  {
    raw_key_len = (guint)strlen(key);
    if((raw_key_len > 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
    {
      /*
       * Key begins with "0x" or "0X"; skip that and treat the rest
       * as a sequence of hex digits.
       */
      i = 2;    /* first character after "0[Xx]" */
      j = 0;
      if(raw_key_len %2  == 1)
      {
        /*
         * Key has an odd number of characters; we act as if the
         * first character had a 0 in front of it, making the
         * number of characters even.
         */
        key_len = (raw_key_len - 2) / 2 + 1;
        *ascii_key = (gchar *) g_malloc ((key_len + 1)* sizeof(gchar));
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
        *ascii_key = (gchar *) g_malloc ((key_len + 1)* sizeof(gchar));
      }

      while(i < (raw_key_len -1))
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

    else if((raw_key_len == 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
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


static gboolean uat_esp_sa_record_update_cb(void* r, char** err _U_) {
  uat_esp_sa_record_t* rec = (uat_esp_sa_record_t *)r;

  /* Compute keys & lengths once and for all */
  if (rec->encryption_key_string) {
    rec->encryption_key_length = compute_ascii_key(&rec->encryption_key, rec->encryption_key_string);
    rec->cipher_hd_created = FALSE;
  }
  else {
    rec->encryption_key_length = 0;
    rec->encryption_key = NULL;
  }

  if (rec->authentication_key_string) {
    rec->authentication_key_length = compute_ascii_key(&rec->authentication_key, rec->authentication_key_string);
  }
  else {
    rec->authentication_key_length = 0;
    rec->authentication_key = NULL;
  }
  return TRUE;
}

static void* uat_esp_sa_record_copy_cb(void* n, const void* o, size_t siz _U_) {
  uat_esp_sa_record_t* new_rec = (uat_esp_sa_record_t *)n;
  const uat_esp_sa_record_t* old_rec = (const uat_esp_sa_record_t *)o;

  /* Copy UAT fields */
  new_rec->protocol = old_rec->protocol;
  new_rec->srcIP = (old_rec->srcIP) ? g_strdup(old_rec->srcIP) : NULL;
  new_rec->dstIP = (old_rec->dstIP) ? g_strdup(old_rec->dstIP) : NULL;
  new_rec->spi = (old_rec->spi) ? g_strdup(old_rec->spi) : NULL;
  new_rec->encryption_algo = old_rec->encryption_algo;
  new_rec->encryption_key_string = (old_rec->encryption_key_string) ? g_strdup(old_rec->encryption_key_string) : NULL;
  new_rec->authentication_algo = old_rec->authentication_algo;
  new_rec->authentication_key_string = (old_rec->authentication_key_string) ? g_strdup(old_rec->authentication_key_string) : NULL;

  /* Parse keys as in an update */
  uat_esp_sa_record_update_cb(new_rec, NULL);

  return new_rec;
}

static void uat_esp_sa_record_free_cb(void*r) {
  uat_esp_sa_record_t* rec = (uat_esp_sa_record_t*)r;

  g_free(rec->srcIP);
  g_free(rec->dstIP);
  g_free(rec->spi);
  g_free(rec->encryption_key_string);
  g_free(rec->encryption_key);
  g_free(rec->authentication_key_string);
  g_free(rec->authentication_key);

  if (rec->cipher_hd_created) {
    gcry_cipher_close(rec->cipher_hd);
    rec->cipher_hd_created = FALSE;
  }
}

UAT_VS_DEF(uat_esp_sa_records, protocol, uat_esp_sa_record_t, guint8, IPSEC_SA_IPV4, "IPv4")
UAT_CSTRING_CB_DEF(uat_esp_sa_records, srcIP, uat_esp_sa_record_t)
UAT_CSTRING_CB_DEF(uat_esp_sa_records, dstIP, uat_esp_sa_record_t)
UAT_CSTRING_CB_DEF(uat_esp_sa_records, spi, uat_esp_sa_record_t)
UAT_VS_DEF(uat_esp_sa_records, encryption_algo, uat_esp_sa_record_t, guint8, 0, "FIXX")
UAT_CSTRING_CB_DEF(uat_esp_sa_records, encryption_key_string, uat_esp_sa_record_t)
UAT_VS_DEF(uat_esp_sa_records, authentication_algo, uat_esp_sa_record_t, guint8, 0, "FIXX")
UAT_CSTRING_CB_DEF(uat_esp_sa_records, authentication_key_string, uat_esp_sa_record_t)


/* Configure a new SA (programmatically, most likely from a private dissector).
   The arguments here are deliberately in the same string formats as the UAT fields
   in order to keep code paths common.
   Note that an attempt to match with these entries will be made *before* entries
   added through the UAT entry interface/file. */
void esp_sa_record_add_from_dissector(guint8 protocol, const gchar *srcIP, const char *dstIP,
                                      gchar *spi,
                                      guint8 encryption_algo, const gchar *encryption_key,
                                      guint8 authentication_algo, const gchar *authentication_key)
{
   uat_esp_sa_record_t* record = NULL;
   if (extra_esp_sa_records.num_records == 0) {
      extra_esp_sa_records.records = (uat_esp_sa_record_t *)g_malloc(sizeof(uat_esp_sa_record_t)*MAX_EXTRA_SA_RECORDS);
   }
   if (extra_esp_sa_records.num_records < MAX_EXTRA_SA_RECORDS) {
      record = &extra_esp_sa_records.records[extra_esp_sa_records.num_records++];
   }
   else {
      /* No room left!! */
      fprintf(stderr, "<IPsec/ESP Dissector> Failed to add UE as already have max (%d) configured\n",
              MAX_EXTRA_SA_RECORDS);
      return;
   }

   /* Copy key fields */
   record->protocol = protocol;
   record->srcIP = g_strdup(srcIP);
   record->dstIP = g_strdup(dstIP);
   record->spi = g_strdup(spi);

   /* Encryption */
   record->encryption_algo = encryption_algo;
   record->encryption_key_string = g_strdup(encryption_key);

   /* Authentication */
   record->authentication_algo = authentication_algo;
   if (authentication_key) {
      record->authentication_key_string = g_strdup(authentication_key);
   }
   else {
      record->authentication_key_string = NULL;
   }

   /* Parse keys */
   uat_esp_sa_record_update_cb(record, NULL);
}

/*************************************/
/* Preference settings               */

/* Default ESP payload decode to off */
static gboolean g_esp_enable_encryption_decode = FALSE;

/* Default ESP payload Authentication Checking to off */
static gboolean g_esp_enable_authentication_check = FALSE;
#endif

/**************************************************/
/* Sequence number analysis                       */

/* SPI state, key is just 32-bit SPI */
typedef struct
{
    guint32  previousSequenceNumber;
    guint32  previousFrameNum;
} spi_status;

/* The sequence analysis SPI hash table.
   Maps SPI -> spi_status */
static GHashTable *esp_sequence_analysis_hash = NULL;

/* Results are stored here: framenum -> spi_status */
/* N.B. only store entries for out-of-order frames, if there is no entry for
   a given frame, it was found to be in-order */
static GHashTable *esp_sequence_analysis_report_hash = NULL;

/* During the first pass, update the SPI state.  If the sequence numbers
   are out of order, add an entry to the report table */
static void check_esp_sequence_info(guint32 spi, guint32 sequence_number, packet_info *pinfo)
{
  /* Do the table lookup */
  spi_status *status = (spi_status*)g_hash_table_lookup(esp_sequence_analysis_hash,
                                                        GUINT_TO_POINTER((guint)spi));
  if (status == NULL) {
    /* Create an entry for this SPI */
    status = wmem_new0(wmem_file_scope(), spi_status);
    status->previousSequenceNumber = sequence_number;
    status->previousFrameNum = pinfo->num;

    /* And add it to the table */
    g_hash_table_insert(esp_sequence_analysis_hash, GUINT_TO_POINTER((guint)spi), status);
  }
  else {
    spi_status *frame_status;

    /* Entry already existed, so check that we got the sequence number we expected. */
    if (sequence_number != status->previousSequenceNumber+1) {
      /* Create report entry */
      frame_status = wmem_new0(wmem_file_scope(), spi_status);
      /* Copy what was expected */
      *frame_status = *status;
      /* And add it into the report table */
      g_hash_table_insert(esp_sequence_analysis_report_hash, GUINT_TO_POINTER(pinfo->num), frame_status);
    }
    /* Adopt this setting as 'current' regardless of whether expected */
    status->previousSequenceNumber = sequence_number;
    status->previousFrameNum = pinfo->num;
  }
}

/* Check to see if there is a report stored for this frame.  If there is,
   add it to the tree and report using expert info */
static void show_esp_sequence_info(guint32 spi, guint32 sequence_number,
                                   tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo)
{
  /* Look up this frame in the report table. */
  spi_status *status = (spi_status*)g_hash_table_lookup(esp_sequence_analysis_report_hash,
                                                        GUINT_TO_POINTER(pinfo->num));
  if (status != NULL) {
    proto_item *sn_ti, *frame_ti;

    /* Expected sequence number */
    sn_ti = proto_tree_add_uint(tree, hf_esp_sequence_analysis_expected_sn,
                                tvb, 0, 0, status->previousSequenceNumber+1);
    if (sequence_number > (status->previousSequenceNumber+1)) {
      proto_item_append_text(sn_ti, " (%u SNs missing)",
                             sequence_number - (status->previousSequenceNumber+1));
    }
    PROTO_ITEM_SET_GENERATED(sn_ti);

    /* Link back to previous frame for SPI */
    frame_ti = proto_tree_add_uint(tree, hf_esp_sequence_analysis_previous_frame,
                                   tvb, 0, 0, status->previousFrameNum);
    PROTO_ITEM_SET_GENERATED(frame_ti);

    /* Expert info */
    if (sequence_number == status->previousSequenceNumber) {
      expert_add_info_format(pinfo, sn_ti, &ei_esp_sequence_analysis_wrong_sequence_number,
                             "Wrong Sequence Number for SPI %08x - %u repeated",
                             spi, sequence_number);
    }
    else if (sequence_number > status->previousSequenceNumber+1) {
      expert_add_info_format(pinfo, sn_ti, &ei_esp_sequence_analysis_wrong_sequence_number,
                             "Wrong Sequence Number for SPI %08x - %u missing",
                             spi,
                             sequence_number - (status->previousSequenceNumber+1));
    }
    else {
      expert_add_info_format(pinfo, sn_ti, &ei_esp_sequence_analysis_wrong_sequence_number,
                             "Wrong Sequence Number for SPI %08x - %u less than expected",
                             spi,
                             (status->previousSequenceNumber+1) - sequence_number);
    }
  }
}

/*
   Default ESP payload heuristic decode to off
   (only works if payload is NULL encrypted and ESP payload decode is off or payload is NULL encrypted
   and the packet does not match a Security Association).
*/
static gboolean g_esp_enable_null_encryption_decode_heuristic = FALSE;

/* Default to doing ESP sequence analysis */
static gboolean g_esp_do_sequence_analysis = TRUE;



#ifdef HAVE_LIBGCRYPT
#if 0

/*
   Name : static int get_ipv6_suffix(char* ipv6_suffix, char *ipv6_address)
   Description : Get the extended IPv6 Suffix of an IPv6 Address
   Return : Return the number of char of the IPv6 address suffix parsed
   Params:
      - char *ipv6_address : the valid ipv6 address to parse in char *
      - char *ipv6_suffix : the ipv6 suffix associated in char *

      ex: if IPv6 address is "3ffe::1" the IPv6 suffix will be "0001" and the function will return 3
*/
static int get_ipv6_suffix(char* ipv6_suffix, char *ipv6_address)
{
  char suffix[IPSEC_STRLEN_IPV6 + 1];
  int cpt = 0;
  int cpt_suffix = 0;
  int cpt_seg = 0;
  int j =0;
  int ipv6_len = 0;
  gboolean found = FALSE;

  ipv6_len = (int) strlen(ipv6_address);
  if(ipv6_len  == 0)
    {
      /* Found a suffix */
      found = TRUE;
    }
  else
    {
      while ( (cpt_suffix < IPSEC_STRLEN_IPV6) && (ipv6_len - cpt -1 >= 0) && (found == FALSE))
        {
          if(ipv6_address[ipv6_len - cpt - 1] == ':')
            {
              /* Add some 0 to the prefix; */
              for(j = cpt_seg; j < 4; j++)
                {
                  suffix[IPSEC_STRLEN_IPV6 -1 -cpt_suffix] = '0';
                  cpt_suffix ++;
                }
              cpt_seg = 0;

              if(ipv6_len - cpt - 1 == 0)
                {
                  /* Found a suffix */
                  found = TRUE;
                }
              else
                if(ipv6_address[ipv6_len - cpt - 2] == ':')
                  {
                    /* found a suffix */
                    cpt +=2;
                    found = TRUE;
                  }

                else
                  {
                    cpt++;
                  }
            }
          else
            {
              suffix[IPSEC_STRLEN_IPV6 -1 -cpt_suffix] = g_ascii_toupper(ipv6_address[ipv6_len - cpt - 1]);
              cpt_seg ++;
              cpt_suffix ++;
              cpt++;
            }
        }

      if(cpt_suffix % 4 != 0)
        {
          for(j = cpt_seg; j < 4; j++)
            {
              suffix[IPSEC_STRLEN_IPV6 -1 -cpt_suffix] = '0';
              cpt_suffix ++;
            }
          cpt_seg = 0;
        }

    }

  for(j = 0 ; j < cpt_suffix ; j ++)
    {
      suffix[j] = suffix[j + IPSEC_STRLEN_IPV6 - cpt_suffix] ;
    }

  suffix[j] = '\0';
  memcpy(ipv6_suffix,suffix,j + 1);
  return cpt;
}

/*
   Name : static int get_full_ipv6_addr(char* ipv6_addr_expanded, char *ipv6_addr)
   Description : Get the extended IPv6 Address of an IPv6 Address
   Return : Return the remaining number of char of the IPv6 address parsed
   Params:
      - char *ipv6_addr : the valid ipv6 address to parse in char *
      - char *ipv6_addr_expanded : the expanded ipv6 address associated in char *

      ex: if IPv6 address is "3ffe::1" the IPv6 expanded address
            will be "3FFE0000000000000000000000000001" and the function will return 0
          if IPV6 address is "3ffe::*" the IPv6 expanded address
            will be "3FFE000000000000000000000000****" and the function will return 0
*/
static int
get_full_ipv6_addr(char* ipv6_addr_expanded, char *ipv6_addr)
{
  char suffix[IPSEC_STRLEN_IPV6 + 1];
  char prefix[IPSEC_STRLEN_IPV6 + 1];
  char *prefix_addr;

  int suffix_cpt = 0;
  int suffix_len = 0;
  int prefix_remaining = 0;
  int prefix_len = 0;
  int j = 0;


  if((ipv6_addr == NULL) || (strcmp(ipv6_addr, "") == 0))  return -1;
  if((strlen(ipv6_addr) == 1) && (ipv6_addr[0] == IPSEC_SA_WILDCARDS_ANY))
    {
      for(j = 0; j <= IPSEC_STRLEN_IPV6; j++)
        {
          ipv6_addr_expanded[j] = IPSEC_SA_WILDCARDS_ANY;
        }
      ipv6_addr_expanded[IPSEC_STRLEN_IPV6] = '\0';
      return 0;
    }

  suffix_cpt = get_ipv6_suffix(suffix,ipv6_addr);
  suffix_len = (int) strlen(suffix);

  if(suffix_len <  IPSEC_STRLEN_IPV6)
    {
      prefix_addr = wmem_strndup(wmem_packet_scope(), ipv6_addr,strlen(ipv6_addr) - suffix_cpt);
      prefix_remaining = get_ipv6_suffix(prefix,prefix_addr);
      prefix_len = (int) strlen(prefix);
      memcpy(ipv6_addr_expanded,prefix,prefix_len);
    }


  for(j = 0; j <= IPSEC_STRLEN_IPV6 - prefix_len - suffix_len; j++)
    {
      ipv6_addr_expanded[j + prefix_len] = '0';
    }

  memcpy(ipv6_addr_expanded + IPSEC_STRLEN_IPV6 - suffix_len, suffix,suffix_len + 1);

  if(suffix_len < IPSEC_STRLEN_IPV6)
    return (prefix_len - prefix_remaining);
  else
    return (int) strlen(ipv6_addr) - suffix_cpt;
}


/*
   Name : static gboolean get_full_ipv4_addr(char* ipv4_addr_expanded, char *ipv4_addr)
   Description : Get the extended IPv4 Address of an IPv4 Address
   Return : Return true if it can derive an IPv4 address. It does not mean that
            the previous one was valid.
   Params:
      - char *ipv4_addr : the valid ipv4 address to parse in char *
      - char *ipv4_addr_expanded : the expanded ipv4 address associated in char *

      ex: if IPv4 address is "190.*.*.1" the IPv4 expanded address will be "BE****01" and
            the function will return 0
          if IPv4 address is "*" the IPv4 expanded address will be "********" and
            the function will return 0
*/
static gboolean
get_full_ipv4_addr(char* ipv4_address_expanded, char *ipv4_address)
{
  char addr_byte_string_tmp[4];
  char addr_byte_string[4];

  guint addr_byte = 0;
  guint i = 0;
  guint j = 0;
  guint k = 0;
  guint cpt = 0;
  gboolean done_flag = FALSE;

  if((ipv4_address == NULL) || (strcmp(ipv4_address, "") == 0))  return done_flag;

  if((strlen(ipv4_address) == 1) && (ipv4_address[0] == IPSEC_SA_WILDCARDS_ANY))
  {
    for(i = 0; i <= IPSEC_STRLEN_IPV4; i++)
    {
      ipv4_address_expanded[i] = IPSEC_SA_WILDCARDS_ANY;
    }
    ipv4_address_expanded[IPSEC_STRLEN_IPV4] = '\0';
    done_flag = TRUE;
  }

  else {
    j = 0;
    cpt = 0;
    k = 0;
    while((done_flag == FALSE) && (j <= strlen(ipv4_address)) && (cpt < IPSEC_STRLEN_IPV4))
    {
      if(j == strlen(ipv4_address))
      {
        addr_byte_string_tmp[k] = '\0';
        if((strlen(addr_byte_string_tmp) == 1) && (addr_byte_string_tmp[0] == IPSEC_SA_WILDCARDS_ANY))
        {
          for(i = 0; i < 2; i++)
          {
            ipv4_address_expanded[cpt] = IPSEC_SA_WILDCARDS_ANY;
            cpt ++;
          }
        }
        else
        {
          if (sscanf(addr_byte_string_tmp,"%u",&addr_byte) == EOF)
            return FALSE;

          if(addr_byte < 16)
            g_snprintf(addr_byte_string,4,"0%X",addr_byte);
          else
            g_snprintf(addr_byte_string,4,"%X",addr_byte);
          for(i = 0; i < strlen(addr_byte_string); i++)
          {
            ipv4_address_expanded[cpt] = addr_byte_string[i];
            cpt ++;
          }
        }
        done_flag = TRUE;
      }

      else if(ipv4_address[j] == '.')
      {
        addr_byte_string_tmp[k] = '\0';
        if((strlen(addr_byte_string_tmp) == 1) && (addr_byte_string_tmp[0] == IPSEC_SA_WILDCARDS_ANY))
        {
          for(i = 0; i < 2; i++)
          {
            ipv4_address_expanded[cpt] = IPSEC_SA_WILDCARDS_ANY;
            cpt ++;
          }
        }
        else
        {
          if (sscanf(addr_byte_string_tmp,"%u",&addr_byte) == EOF)
            return FALSE;

          if(addr_byte < 16)
            g_snprintf(addr_byte_string,4,"0%X",addr_byte);
          else
            g_snprintf(addr_byte_string,4,"%X",addr_byte);
          for(i = 0; i < strlen(addr_byte_string); i++)
          {
            ipv4_address_expanded[cpt] = addr_byte_string[i];
            cpt ++;
          }
        }
        k = 0;
        j++;
      }
      else
      {
        if(k >= 3)
        {
          /* Incorrect IPv4 Address. Erase previous Values in the Byte. (LRU mechanism) */
          addr_byte_string_tmp[0] = ipv4_address[j];
          k = 1;
          j++;
        }
        else
        {
          addr_byte_string_tmp[k] = ipv4_address[j];
          k++;
          j++;
        }
      }

    }

    ipv4_address_expanded[cpt] = '\0';
  }

  return done_flag;
}
#endif

/*
   Name : static goolean filter_address_match(gchar *addr, gchar *filter, gint len, gint typ)
   Description : check the matching of an address with a filter
   Return : Return TRUE if the filter and the address match
   Params:
      - gchar *addr : the address to check
      - gchar *filter : the filter
      - gint typ : the Address type : either IPv6 or IPv4 (IPSEC_SA_IPV6, IPSEC_SA_IPV4)
*/
static gboolean
filter_address_match(gchar *addr, gchar *filter, gint typ)
{
  guint i;
  guint filter_tmp = 0;
  guint addr_tmp = 0;
  char filter_string_tmp[3];
  char addr_string_tmp[3];
  guint addr_len;
  guint filter_len = (guint)strlen(filter);

  if((filter_len == 1) && (filter[0] == IPSEC_SA_WILDCARDS_ANY))
      return TRUE;

  addr_len = (guint)strlen(addr);
  if(addr_len != filter_len)
          return FALSE;

  /* No length specified */
   if( ((typ == IPSEC_SA_IPV6) && (filter_len > IPSEC_IPV6_ADDR_LEN)) ||
       ((typ == IPSEC_SA_IPV4) && (filter_len > IPSEC_IPV4_ADDR_LEN)))
   {
      /* Filter is longer than address can be... */
      for(i = 0; i < addr_len; i++)
      {
         if((filter[i] != IPSEC_SA_WILDCARDS_ANY) && (filter[i] != addr[i]))
            return FALSE;
      }
      return TRUE;
   }
   else
   {
      for(i = 0; i < (filter_len/4); i++)
      {
         if((filter[i] != IPSEC_SA_WILDCARDS_ANY) && (filter[i] != addr[i]))
            return FALSE;
      }

      if(filter[i] == IPSEC_SA_WILDCARDS_ANY)
         return TRUE;
      else if (filter_len  % 4 != 0)
      {
         /* take the end of the Netmask/Prefixlen into account */
         filter_string_tmp[0] = filter[i];
         filter_string_tmp[1] = '\0';
         addr_string_tmp[0] = addr[i];
         addr_string_tmp[1] = '\0';

         if (sscanf(filter_string_tmp,"%x",&filter_tmp) == EOF)
             return FALSE;
         if (sscanf(addr_string_tmp,"%x",&addr_tmp) == EOF)
             return FALSE;
         for(i = 0; i < (filter_len % 4); i++)
         {
            if(((filter_tmp >> (4 -i -1)) & 1) != ((addr_tmp >> (4 -i -1)) & 1))
               return FALSE;
         }
      }
   }

  return TRUE;

}


/*
   Name : static goolean filter_spi_match(gchar *spi, gchar *filter)
   Description : check the matching of a spi with a filter
   Return : Return TRUE if the filter matches the spi.
   Params:
      - guint spi : the spi to check
      - gchar *filter : the filter
*/
static gboolean
filter_spi_match(guint spi, gchar *filter)
{
  guint i;
  guint filter_len = (guint)strlen(filter);

  /* "*" matches against anything */
  if((filter_len == 1) && (filter[0] == IPSEC_SA_WILDCARDS_ANY))
    return TRUE;

  /* If the filter has a wildcard, treat SPI as a string */
  if (strchr(filter, IPSEC_SA_WILDCARDS_ANY) != NULL) {
    gchar spi_string[IPSEC_SPI_LEN_MAX];

    g_snprintf(spi_string, IPSEC_SPI_LEN_MAX,"0x%08x", spi);

    /* Lengths need to match exactly... */
    if(strlen(spi_string) != filter_len)
      return FALSE;

    /* ... which means '*' can only appear in the last position of the filter? */
    /* Start at 2, don't compare "0x" each time */
    for(i = 2; filter[i]; i++)
      if((filter[i] != IPSEC_SA_WILDCARDS_ANY) && (filter[i] != spi_string[i]))
        return FALSE;
  } else if (strtoul(filter, NULL, 0) != spi) {
    return FALSE;
  }
  return TRUE;
}


/*
   Name : static goolean get_esp_sa(g_esp_sa_database *sad, gint protocol_typ, gchar *src,  gchar *dst,  guint spi,
           gint *encryption_algo,
           gint *authentication_algo,
           gchar **encryption_key,
           guint *encryption_key_len,
           gchar **authentication_key,
           guint *authentication_key_len,
           gcry_cipher_hd_t **cipher_hd,
           gboolean **cipher_hd_created

   Description : Give Encryption Algo, Key and Authentication Algo for a Packet if a corresponding SA is available in a Security Association database
   Return: If the SA is not present, FALSE is then returned.
   Params:
      - g_esp_sa_database *sad : the Security Association Database
      - gint *pt_protocol_typ : the protocol type
      - gchar *src : the source address
      - gchar *dst : the destination address
      - gchar *spi : the spi of the SA
      - gint *encryption_algo : the Encryption Algorithm to apply the packet
      - gint *authentication_algo : the Authentication Algorithm to apply to the packet
      - gchar **encryption_key : the Encryption Key to apply to the packet
      - guint *encryption_key_len : the Encryption Key length to apply to the packet
      - gchar **authentication_key : the Authentication Key to apply to the packet
      - guint *authentication_key_len : the Authentication Key len to apply to the packet
      - gcry_cipher_hd_t **cipher_hd : pointer handle to be used for ciphering
      - gboolean **cipher_hd_created: points to boolean indicating that cipher handle has
                                      been created.  If FALSE, should assign handle to
                                      *cipher_hd and set this to TRUE.

*/
static gboolean
get_esp_sa(gint protocol_typ, gchar *src,  gchar *dst,  guint spi,
           gint *encryption_algo,
           gint *authentication_algo,
           gchar **encryption_key,
           guint *encryption_key_len,
           gchar **authentication_key,
           guint *authentication_key_len,
           gcry_cipher_hd_t **cipher_hd,
           gboolean **cipher_hd_created
  )
{
  gboolean found = FALSE;
  guint i, j;

  *cipher_hd = NULL;
  *cipher_hd_created = NULL;

  /* Check each known SA in turn */
  for (i = 0, j=0; (found == FALSE) && ((i < num_sa_uat) || (j < extra_esp_sa_records.num_records)); )
  {
    /* Get the next record to try */
    uat_esp_sa_record_t *record;
    if (j < extra_esp_sa_records.num_records) {
      /* Extra ones checked first */
      record = &extra_esp_sa_records.records[j++];
    }
    else {
      /* Then UAT ones */
      record = &uat_esp_sa_records[i++];
    }

    if((protocol_typ == record->protocol)
       && filter_address_match(src, record->srcIP, protocol_typ)
       && filter_address_match(dst, record->dstIP, protocol_typ)
       && filter_spi_match(spi, record->spi))
    {
      found = TRUE;

      *encryption_algo = record->encryption_algo;
      *authentication_algo = record->authentication_algo;
      *authentication_key = record->authentication_key;
      if (record->authentication_key_length == -1)
      {
        /* Bad key; XXX - report this */
        *authentication_key_len = 0;
        found = FALSE;
      }
      else {
        *authentication_key_len = record->authentication_key_length;
      }

      *encryption_key = record->encryption_key;
      if (record->encryption_key_length == -1)
      {
        /* Bad key; XXX - report this */
        *encryption_key_len = 0;
        found = FALSE;
      }
      else {
        *encryption_key_len = record->encryption_key_length;
      }

      /* Tell the caller whether cipher_hd has been created yet and a pointer.
         Pass pointer to created flag so that caller can set if/when
         it opens the cipher_hd. */
      *cipher_hd = &record->cipher_hd;
      *cipher_hd_created = &record->cipher_hd_created;
    }
  }

  return found;
}
#endif

static void
export_ipsec_pdu(dissector_handle_t dissector_handle, packet_info *pinfo, tvbuff_t *tvb)
{
  if (have_tap_listener(exported_pdu_tap)) {
    exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, dissector_handle_get_dissector_name(dissector_handle), EXP_PDU_TAG_PROTO_NAME);

    exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
    exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
    exp_pdu_data->pdu_tvb = tvb;

    tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
  }
}

static int
dissect_ah_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *ah_tree;
  proto_item *pi, *ti;
  guint8      ah_len;         /* Length of header in 32bit words minus 2 */
  guint       ah_hdr_len;     /* Length of header in octets */
  guint       ah_icv_len;     /* Length of ICV header field in octets */
  guint32     ah_spi;         /* Security parameter index */

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AH");
  col_clear(pinfo->cinfo, COL_INFO);

  pi = proto_tree_add_item(tree, proto_ah, tvb, 0, -1, ENC_NA);
  ah_tree = proto_item_add_subtree(pi, ett_ah);

  ah_len = tvb_get_guint8(tvb, 1);
  ah_hdr_len = (ah_len + 2) * 4;
  ah_icv_len = ah_len ? (ah_len - 1) * 4 : 0;

  proto_tree_add_item(ah_tree, hf_ah_next_header, tvb, 0, 1, ENC_BIG_ENDIAN);
  ti = proto_tree_add_item(ah_tree, hf_ah_length, tvb, 1, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(ti, " (%u bytes)", ah_hdr_len);
  proto_tree_add_item(ah_tree, hf_ah_reserved, tvb, 2, 2, ENC_NA);
  proto_tree_add_item_ret_uint(ah_tree, hf_ah_spi, tvb, 4, 4, ENC_BIG_ENDIAN, &ah_spi);

  col_add_fstr(pinfo->cinfo, COL_INFO, "AH (SPI=0x%08x)", ah_spi);

  proto_tree_add_item(ah_tree, hf_ah_sequence, tvb, 8, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(ah_tree, hf_ah_iv, tvb, 12, ah_icv_len, ENC_NA);

  proto_item_set_len(pi, ah_hdr_len);

  /* start of the new header (could be a extension header) */
  return ah_hdr_len;
}

static int
dissect_ah(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  guint8      ah_nxt;
  tvbuff_t *next_tvb;
  int advance;
  dissector_handle_t dissector_handle;
  guint32 saved_match_uint;

  advance = dissect_ah_header(tvb, pinfo, tree, NULL);

  ah_nxt = tvb_get_guint8(tvb, 0);
  next_tvb = tvb_new_subset_remaining(tvb, advance);

  /* do lookup with the subdissector table */
  saved_match_uint  = pinfo->match_uint;
  dissector_handle = dissector_get_uint_handle(ip_dissector_table, ah_nxt);
  if (dissector_handle) {
    pinfo->match_uint = ah_nxt;
  } else {
    dissector_handle = data_handle;
  }
  export_ipsec_pdu(dissector_handle, pinfo, next_tvb);
  call_dissector(dissector_handle, next_tvb, pinfo, tree);
  pinfo->match_uint = saved_match_uint;
  return tvb_captured_length(tvb);
}

/*
Name : dissect_esp_authentication(proto_tree *tree, tvbuff_t *tvb, gint len, gint esp_auth_len, guint8 *authenticator_data_computed,
gboolean authentication_ok, gboolean authentication_checking_ok)
Description : used to print Authenticator field when linked with libgcrypt. Print the expected authenticator value
if requested and if it is wrong.
Return : void
Params:
- proto_tree *tree : the current tree
- tvbuff_t *tvb : the tvbuffer
- gint len : length of the data available in tvbuff
- gint esp_auth_len : size of authenticator field
- guint8 *authenticator_data_computed : give the authenticator computed (only needed when authentication_ok and !authentication_checking_ok
- gboolean authentication_ok : set to true if the authentication checking has been run successfully
- gboolean authentication_checking_ok : set to true if the authentication was the one expected
*/
#ifdef HAVE_LIBGCRYPT
static void
dissect_esp_authentication(proto_tree *tree, tvbuff_t *tvb, gint len, gint esp_auth_len, guint8 *authenticator_data_computed,
                           gboolean authentication_ok, gboolean authentication_checking_ok)
{
  proto_item *item;
  proto_tree *icv_tree;
  gboolean good = FALSE, bad = FALSE;

  if(esp_auth_len == 0)
  {
    icv_tree = proto_tree_add_subtree(tree, tvb, len, 0,
                               ett_esp_icv, NULL, "NULL Authentication");
    good = TRUE;
  }

  /* Make sure we have the auth trailer data */
  else if(tvb_bytes_exist(tvb, len - esp_auth_len, esp_auth_len))
  {
    if((authentication_ok) && (authentication_checking_ok))
    {
      icv_tree = proto_tree_add_subtree(tree, tvb, len - esp_auth_len, esp_auth_len,
                                 ett_esp_icv, NULL, "Authentication Data [correct]");
      good = TRUE;
    }

    else if((authentication_ok) && (!authentication_checking_ok))
    {
      icv_tree = proto_tree_add_subtree_format(tree, tvb, len - esp_auth_len, esp_auth_len,
                                 ett_esp_icv, NULL, "Authentication Data [incorrect, should be 0x%s]", authenticator_data_computed);
      bad = TRUE;
    }

    else
        icv_tree = proto_tree_add_subtree(tree, tvb, len - esp_auth_len, esp_auth_len,
                                    ett_esp_icv, NULL, "Authentication Data");
  }
  else
  {
    /* Truncated so just display what we have */
    icv_tree = proto_tree_add_subtree(tree, tvb, len - esp_auth_len, esp_auth_len - (len - tvb_captured_length(tvb)),
                               ett_esp_icv, NULL, "Authentication Data (truncated)");
    bad = TRUE;
  }

  item = proto_tree_add_boolean(icv_tree, hf_esp_icv_good,
                                tvb, len - esp_auth_len, esp_auth_len, good);
  PROTO_ITEM_SET_GENERATED(item);

  item = proto_tree_add_boolean(icv_tree, hf_esp_icv_bad,
                                tvb, len - esp_auth_len, esp_auth_len, bad);
  PROTO_ITEM_SET_GENERATED(item);
}
#endif

static int
dissect_esp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *esp_tree = NULL;
  proto_item *ti;
  gint len = 0;

#ifdef HAVE_LIBGCRYPT
  gint i;

  /* Packet Variables related */
  gchar *ip_src = NULL;
  gchar *ip_dst = NULL;
#endif

  guint32 spi = 0;
  guint encapsulated_protocol = 0;
  gboolean decrypt_dissect_ok = FALSE;
  tvbuff_t *next_tvb;
  dissector_handle_t dissector_handle;
  guint32 saved_match_uint;

#ifdef HAVE_LIBGCRYPT
  gboolean null_encryption_decode_heuristic = FALSE;
  guint8 *decrypted_data = NULL;
  guint8 *authenticator_data = NULL;
  guint8 *esp_data = NULL;
  tvbuff_t *tvb_decrypted;

  /* IPSEC encryption Variables related */
  gint protocol_typ = IPSEC_SA_UNKNOWN;
  gint esp_crypt_algo = IPSEC_ENCRYPT_NULL;
  gint esp_auth_algo = IPSEC_AUTH_NULL;
  gchar *esp_crypt_key = NULL;
  gchar *esp_auth_key = NULL;
  guint esp_crypt_key_len = 0;
  guint esp_auth_key_len = 0;
  gcry_cipher_hd_t *cipher_hd;
  gboolean         *cipher_hd_created;

  gint esp_iv_len = 0;
  gint esp_auth_len = 0;
  gint decrypted_len = 0;
  gboolean decrypt_ok = FALSE;
  gboolean decrypt_using_libgcrypt = FALSE;
  gboolean authentication_check_using_hmac_libgcrypt = FALSE;
  gboolean authentication_ok = FALSE;
  gboolean authentication_checking_ok = FALSE;
  gboolean sad_is_present = FALSE;
#endif
  gint esp_pad_len = 0;

#ifdef HAVE_LIBGCRYPT

  /* Variables for decryption and authentication checking used for libgrypt */
  int decrypted_len_alloc = 0;
  gcry_md_hd_t md_hd;
  int md_len = 0;
  gcry_error_t err = 0;
  int crypt_algo_libgcrypt = 0;
  int crypt_mode_libgcrypt = 0;
  int auth_algo_libgcrypt = 0;
  unsigned char *authenticator_data_computed = NULL;
  unsigned char *authenticator_data_computed_md;

  unsigned char ctr_block[16];

#endif

  guint32 sequence_number;

  /*
   * load the top pane info. This should be overwritten by
   * the next protocol in the stack
   */

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESP");
  col_clear(pinfo->cinfo, COL_INFO);

  /*
   * populate a tree in the second pane with the status of the link layer
   * (ie none)
   */
  len = 0, encapsulated_protocol = 0;
  decrypt_dissect_ok = FALSE;

  ti = proto_tree_add_item(tree, proto_esp, tvb, 0, -1, ENC_NA);
  esp_tree = proto_item_add_subtree(ti, ett_esp);
  proto_tree_add_item_ret_uint(esp_tree, hf_esp_spi, tvb,
                      0, 4, ENC_BIG_ENDIAN, &spi);
  proto_tree_add_item_ret_uint(esp_tree, hf_esp_sequence, tvb,
                      4, 4, ENC_BIG_ENDIAN, &sequence_number);

  col_add_fstr(pinfo->cinfo, COL_INFO, "ESP (SPI=0x%08x)", spi);

  /* Sequence number analysis */
  if (g_esp_do_sequence_analysis) {
    if (!pinfo->fd->flags.visited) {
      check_esp_sequence_info(spi, sequence_number, pinfo);
    }
    show_esp_sequence_info(spi, sequence_number,
                           tvb, esp_tree, pinfo);
  }

#ifdef HAVE_LIBGCRYPT
  /* The SAD is not activated */
  if(g_esp_enable_null_encryption_decode_heuristic &&
     !g_esp_enable_encryption_decode)
    null_encryption_decode_heuristic = TRUE;

  if(g_esp_enable_encryption_decode || g_esp_enable_authentication_check)
  {
    /* Get Source & Destination Addresses in gchar * with all the bytes available.  */

    if (pinfo->src.type == AT_IPv4){
      protocol_typ = IPSEC_SA_IPV4;
    }else if (pinfo->src.type == AT_IPv6){
      protocol_typ = IPSEC_SA_IPV6;
    }

    /* Create strings for src, dst addresses */
    ip_src = address_to_str(wmem_packet_scope(), &pinfo->src);
    ip_dst = address_to_str(wmem_packet_scope(), &pinfo->dst);

    /* Get the SPI */
    if (tvb_captured_length(tvb) >= 4)
    {
      spi = tvb_get_ntohl(tvb, 0);
    }


    /*
      PARSE the SAD and fill it. It may take some time since it will
      be called every times an ESP Payload is found.
    */

    if((sad_is_present = get_esp_sa(protocol_typ, ip_src, ip_dst, spi,
                                    &esp_crypt_algo, &esp_auth_algo,
                                    &esp_crypt_key, &esp_crypt_key_len, &esp_auth_key, &esp_auth_key_len,
                                    &cipher_hd, &cipher_hd_created)))
    {
      /* Get length of whole ESP packet. */
      len = tvb_reported_length(tvb);

      switch(esp_auth_algo)
      {
      case IPSEC_AUTH_NULL:
        esp_auth_len = 0;
        break;

      case IPSEC_AUTH_ANY_64BIT:
        esp_auth_len = 8;
        break;

      case IPSEC_AUTH_HMAC_SHA256_128:
      case IPSEC_AUTH_ANY_128BIT:
        esp_auth_len = 16;
        break;

      case IPSEC_AUTH_HMAC_SHA512_256:
      case IPSEC_AUTH_ANY_256BIT:
        esp_auth_len = 32;
        break;

      case IPSEC_AUTH_HMAC_SHA384_192:
      case IPSEC_AUTH_ANY_192BIT:
        esp_auth_len = 24;
        break;

      case IPSEC_AUTH_HMAC_SHA1_96:
      case IPSEC_AUTH_HMAC_SHA256_96:
        /*             case IPSEC_AUTH_AES_XCBC_MAC_96: */
      case IPSEC_AUTH_HMAC_MD5_96:
      case IPSEC_AUTH_HMAC_RIPEMD160_96:
      case IPSEC_AUTH_ANY_96BIT:
      default:
        esp_auth_len = 12;
        break;
      }

      if(g_esp_enable_authentication_check)
      {
        switch(esp_auth_algo)
        {
        case IPSEC_AUTH_HMAC_SHA1_96:
          /*
            RFC 2404 : HMAC-SHA-1-96 is a secret key algorithm.
            While no fixed key length is specified in [RFC-2104],
            for use with either ESP or AH a fixed key length of
            160-bits MUST be supported.  Key lengths other than
            160-bits MUST NOT be supported (i.e. only 160-bit keys
            are to be used by HMAC-SHA-1-96).  A key length of
            160-bits was chosen based on the recommendations in
            [RFC-2104] (i.e. key lengths less than the
            authenticator length decrease security strength and
            keys longer than the authenticator length do not
            significantly increase security strength).
          */
          auth_algo_libgcrypt = GCRY_MD_SHA1;
          authentication_check_using_hmac_libgcrypt = TRUE;
          break;

        case IPSEC_AUTH_NULL:
          authentication_check_using_hmac_libgcrypt = FALSE;
          authentication_checking_ok = TRUE;
          authentication_ok = TRUE;
          break;

          /*
            case IPSEC_AUTH_AES_XCBC_MAC_96:
            auth_algo_libgcrypt =
            authentication_check_using_libgcrypt = TRUE;
            break;
          */

        case IPSEC_AUTH_HMAC_SHA256_96:
        case IPSEC_AUTH_HMAC_SHA256_128:
          auth_algo_libgcrypt = GCRY_MD_SHA256;
          authentication_check_using_hmac_libgcrypt = TRUE;
          break;

        case IPSEC_AUTH_HMAC_SHA384_192:
          auth_algo_libgcrypt = GCRY_MD_SHA384;
          authentication_check_using_hmac_libgcrypt = TRUE;
          break;

        case IPSEC_AUTH_HMAC_SHA512_256:
          auth_algo_libgcrypt = GCRY_MD_SHA512;
          authentication_check_using_hmac_libgcrypt = TRUE;
          break;

        case IPSEC_AUTH_HMAC_MD5_96:
          /*
            RFC 2403 : HMAC-MD5-96 is a secret key algorithm.
            While no fixed key length is specified in [RFC-2104],
            for use with either ESP or AH a fixed key length of
            128-bits MUST be supported.  Key lengths other than
            128-bits MUST NOT be supported (i.e. only 128-bit keys
            are to be used by HMAC-MD5-96).  A key length of
            128-bits was chosen based on the recommendations in
            [RFC-2104] (i.e. key lengths less than the
            authenticator length decrease security strength and
            keys longer than the authenticator length do not
            significantly increase security strength).
          */
          auth_algo_libgcrypt = GCRY_MD_MD5;
          authentication_check_using_hmac_libgcrypt = TRUE;
          break;

        case IPSEC_AUTH_HMAC_RIPEMD160_96:
          /*
            RFC 2857 : HMAC-RIPEMD-160-96 produces a 160-bit
            authenticator value.  This 160-bit value can be
            truncated as described in RFC2104.  For use with
            either ESP or AH, a truncated value using the first
            96 bits MUST be supported.
          */
          auth_algo_libgcrypt = GCRY_MD_RMD160;
          authentication_check_using_hmac_libgcrypt = TRUE;
          break;

        case IPSEC_AUTH_ANY_64BIT:
        case IPSEC_AUTH_ANY_96BIT:
        case IPSEC_AUTH_ANY_128BIT:
        case IPSEC_AUTH_ANY_192BIT:
        case IPSEC_AUTH_ANY_256BIT:
        default:
          authentication_ok = FALSE;
          authentication_check_using_hmac_libgcrypt = FALSE;
          break;

        }

        if((authentication_check_using_hmac_libgcrypt) && (!authentication_ok))
        {
          gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
          gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

          /* Allocate Buffers for Authenticator Field  */
          authenticator_data = (guint8 *)wmem_alloc0(wmem_packet_scope(), esp_auth_len + 1);
          tvb_memcpy(tvb, authenticator_data, len - esp_auth_len, esp_auth_len);

          esp_data = (guint8 *)wmem_alloc0(wmem_packet_scope(), len - esp_auth_len + 1);
          tvb_memcpy(tvb, esp_data, 0, len - esp_auth_len);

          err = gcry_md_open (&md_hd, auth_algo_libgcrypt, GCRY_MD_FLAG_HMAC);
          if (err)
          {
            fprintf (stderr, "<IPsec/ESP Dissector> Error in Algorithm %s, gcry_md_open failed: %s\n",
                     gcry_md_algo_name(auth_algo_libgcrypt), gpg_strerror (err));
            authentication_ok = FALSE;
          }
          else
          {
            md_len = gcry_md_get_algo_dlen (auth_algo_libgcrypt);
            if (md_len < 1 || md_len < esp_auth_len)
            {
              fprintf (stderr, "<IPsec/ESP Dissector> Error in Algorithm %s, grcy_md_get_algo_dlen failed: %d\n",
                       gcry_md_algo_name(auth_algo_libgcrypt), md_len);
              authentication_ok = FALSE;
            }
            else
            {
              gcry_md_setkey( md_hd, esp_auth_key, esp_auth_key_len );

              gcry_md_write (md_hd, esp_data, len - esp_auth_len);

              authenticator_data_computed_md = gcry_md_read (md_hd, auth_algo_libgcrypt);
              if (authenticator_data_computed_md == 0)
              {
                fprintf (stderr, "<IPsec/ESP Dissector> Error in Algorithm %s, gcry_md_read failed\n",
                         gcry_md_algo_name(auth_algo_libgcrypt));
                authentication_ok = FALSE;
              }
              else
              {
                if(memcmp (authenticator_data_computed_md, authenticator_data, esp_auth_len))
                {
                  /* XXX - just use bytes_to_str() or is string too big? */
                  unsigned char authenticator_data_computed_car[3];
                  authenticator_data_computed = (guint8 *)wmem_alloc(wmem_packet_scope(), esp_auth_len * 2 + 1);
                  for (i = 0; i < esp_auth_len; i++)
                  {
                    g_snprintf((char *)authenticator_data_computed_car, 3,
                               "%02X", authenticator_data_computed_md[i] & 0xFF);
                    authenticator_data_computed[i*2] = authenticator_data_computed_car[0];
                    authenticator_data_computed[i*2 + 1] = authenticator_data_computed_car[1];
                  }

                  authenticator_data_computed[esp_auth_len * 2] ='\0';

                  authentication_ok = TRUE;
                  authentication_checking_ok = FALSE;
                }
                else
                {
                  authentication_ok = TRUE;
                  authentication_checking_ok = TRUE;
                }
              }
            }

            gcry_md_close (md_hd);
          }
        }
      }

      if(g_esp_enable_encryption_decode)
      {
        /* Deactivation of the Heuristic to decrypt using the NULL encryption algorithm since the packet is matching a SA */
        null_encryption_decode_heuristic = FALSE;

        switch(esp_crypt_algo)
        {
        case IPSEC_ENCRYPT_3DES_CBC :
          /* RFC 2451 says :
             3DES CBC uses a key of 192 bits.
             The first 3DES key is taken from the first 64 bits,
             the second from the next 64 bits, and the third
             from the last 64 bits.
             Implementations MUST take into consideration the
             parity bits when initially accepting a new set of
             keys.  Each of the three keys is really 56 bits in
             length with the extra 8 bits used for parity. */

          /* Fix parameters for 3DES-CBC */
          esp_iv_len = 8;
          crypt_algo_libgcrypt = GCRY_CIPHER_3DES;
          crypt_mode_libgcrypt = GCRY_CIPHER_MODE_CBC;

          decrypted_len = len - 8;

          if (decrypted_len <= 0)
            decrypt_ok = FALSE;
          else
          {
            if(decrypted_len % esp_iv_len  == 0)
              decrypted_len_alloc = decrypted_len;
            else
              decrypted_len_alloc = (decrypted_len / esp_iv_len) * esp_iv_len + esp_iv_len;

            if (esp_crypt_key_len != gcry_cipher_get_algo_keylen (crypt_algo_libgcrypt))
            {
              fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm 3DES-CBC : Bad Keylen (got %u Bits, need %lu)\n",
                       esp_crypt_key_len * 8,
                       (unsigned long) gcry_cipher_get_algo_keylen (crypt_algo_libgcrypt) * 8);
              decrypt_ok = FALSE;
            }
            else
              decrypt_using_libgcrypt = TRUE;
          }
          break;

        case IPSEC_ENCRYPT_AES_CBC :
          /* RFC 3602 says :
             AES supports three key sizes: 128 bits, 192 bits,
             and 256 bits.  The default key size is 128 bits,
             and all implementations MUST support this key size.
             Implementations MAY also support key sizes of 192
             bits and 256 bits. */

          /* Fix parameters for AES-CBC */
          esp_iv_len = 16;
          crypt_mode_libgcrypt = GCRY_CIPHER_MODE_CBC;

          decrypted_len = len - 8;

          if (decrypted_len <= 0)
            decrypt_ok = FALSE;
          else
          {
            if(decrypted_len % esp_iv_len  == 0)
              decrypted_len_alloc = decrypted_len;
            else
              decrypted_len_alloc = (decrypted_len / esp_iv_len) * esp_iv_len + esp_iv_len;

            switch(esp_crypt_key_len * 8)
            {
            case 128:
              crypt_algo_libgcrypt = GCRY_CIPHER_AES128;
              decrypt_using_libgcrypt = TRUE;
              break;

            case 192:
              crypt_algo_libgcrypt = GCRY_CIPHER_AES192;
              decrypt_using_libgcrypt = TRUE;
              break;

            case 256:
              crypt_algo_libgcrypt = GCRY_CIPHER_AES256;
              decrypt_using_libgcrypt = TRUE;
              break;

            default:
              fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm AES-CBC : Bad Keylen (%u Bits)\n",
                       esp_crypt_key_len * 8);
              decrypt_ok = FALSE;
            }
          }
          break;

        case IPSEC_ENCRYPT_CAST5_CBC :
          /* RFC 2144 says :
             The CAST-128 encryption algorithm has been designed to allow a key
             size that can vary from 40 bits to 128 bits, in 8-bit increments
             (that is, the allowable key sizes are 40, 48, 56, 64, ..., 112, 120,
             and 128 bits.
             We support only 128 bits. */

          /* Fix parameters for CAST5-CBC */
          esp_iv_len = 8;
          crypt_mode_libgcrypt = GCRY_CIPHER_MODE_CBC;

          decrypted_len = len - 8;

          if (decrypted_len <= 0)
            decrypt_ok = FALSE;
          else
          {
            if(decrypted_len % esp_iv_len  == 0)
              decrypted_len_alloc = decrypted_len;
            else
              decrypted_len_alloc = (decrypted_len / esp_iv_len) * esp_iv_len + esp_iv_len;

            switch(esp_crypt_key_len * 8)
            {
            case 128:
              crypt_algo_libgcrypt = GCRY_CIPHER_CAST5;
              decrypt_using_libgcrypt = TRUE;
              break;
            default:
              fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm CAST5-CBC : Bad Keylen (%u Bits)\n",
                       esp_crypt_key_len * 8);
              decrypt_ok = FALSE;
            }
          }
          break;

        case IPSEC_ENCRYPT_DES_CBC :
          /* RFC 2405 says :
             DES-CBC is a symmetric secret key algorithm.
             The key size is 64-bits.
             [It is commonly known as a 56-bit key as the key
             has 56 significant bits; the least significant
             bit in every byte is the parity bit.] */

          /* Fix parameters for DES-CBC */
          esp_iv_len = 8;
          crypt_algo_libgcrypt = GCRY_CIPHER_DES;
          crypt_mode_libgcrypt = GCRY_CIPHER_MODE_CBC;
          decrypted_len = len - 8;

          if (decrypted_len <= 0)
            decrypt_ok = FALSE;
          else
          {
            if(decrypted_len % esp_iv_len == 0)
              decrypted_len_alloc = decrypted_len;
            else
              decrypted_len_alloc = (decrypted_len / esp_iv_len) * esp_iv_len + esp_iv_len;

            if (esp_crypt_key_len != gcry_cipher_get_algo_keylen (crypt_algo_libgcrypt))
            {
              fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm DES-CBC : Bad Keylen (%u Bits, need %lu)\n",
                       esp_crypt_key_len * 8, (unsigned long) gcry_cipher_get_algo_keylen (crypt_algo_libgcrypt) * 8);
              decrypt_ok = FALSE;
            }
            else
              decrypt_using_libgcrypt = TRUE;
          }
          break;

        case IPSEC_ENCRYPT_AES_CTR :
        case IPSEC_ENCRYPT_AES_GCM :
          /* RFC 3686 says :
             AES supports three key sizes: 128 bits, 192 bits,
             and 256 bits.  The default key size is 128 bits,
             and all implementations MUST support this key
             size.  Implementations MAY also support key sizes
             of 192 bits and 256 bits. The remaining 32 bits
             will be used as nonce. */

          /* Fix parameters for AES-CTR */
          esp_iv_len = 8;
          crypt_mode_libgcrypt = GCRY_CIPHER_MODE_CTR;

          decrypted_len = len - 8;

          if (decrypted_len <= 0)
            decrypt_ok = FALSE;
          else
          {
            if(decrypted_len % esp_iv_len  == 0)
              decrypted_len_alloc = decrypted_len;
            else
              decrypted_len_alloc = (decrypted_len / esp_iv_len) * esp_iv_len + esp_iv_len;

            switch(esp_crypt_key_len * 8)
            {
            case 160:
              crypt_algo_libgcrypt = GCRY_CIPHER_AES128;
              decrypt_using_libgcrypt = TRUE;
              break;

            case 224:
              crypt_algo_libgcrypt = GCRY_CIPHER_AES192;
              decrypt_using_libgcrypt = TRUE;
              break;

            case 288:
              crypt_algo_libgcrypt = GCRY_CIPHER_AES256;
              decrypt_using_libgcrypt = TRUE;
              break;

            default:
              fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm AES-CTR / AES-GCM : Bad Keylen (%u Bits)\n",
                       esp_crypt_key_len * 8);
              decrypt_ok = FALSE;
            }
          }
          break;

        case IPSEC_ENCRYPT_TWOFISH_CBC :
          /*  Twofish is a 128-bit block cipher developed by
              Counterpane Labs that accepts a variable-length
              key up to 256 bits.
              We will only accept key sizes of 128 and 256 bits.
          */

          /* Fix parameters for TWOFISH-CBC */
          esp_iv_len = 16;
          crypt_mode_libgcrypt = GCRY_CIPHER_MODE_CBC;

          decrypted_len = len - 8;

          if (decrypted_len <= 0)
            decrypt_ok = FALSE;
          else
          {
            if(decrypted_len % esp_iv_len  == 0)
              decrypted_len_alloc = decrypted_len;
            else
              decrypted_len_alloc = (decrypted_len / esp_iv_len) * esp_iv_len + esp_iv_len;

            switch(esp_crypt_key_len * 8)
            {
            case 128:
              crypt_algo_libgcrypt = GCRY_CIPHER_TWOFISH128;
              decrypt_using_libgcrypt = TRUE;
              break;

            case 256:
              crypt_algo_libgcrypt = GCRY_CIPHER_TWOFISH;
              decrypt_using_libgcrypt = TRUE;
              break;

            default:
              fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm TWOFISH-CBC : Bad Keylen (%u Bits)\n",
                       esp_crypt_key_len * 8);
              decrypt_ok = FALSE;
            }
          }

          break;

        case IPSEC_ENCRYPT_BLOWFISH_CBC :
          /* Bruce Schneier of Counterpane Systems developed
             the Blowfish block cipher algorithm.
             RFC 2451 shows that Blowfish uses key sizes from
             40 to 448 bits. The Default size is 128 bits.
             We will only accept key sizes of 128 bits, because
             libgrypt only accept this key size.
          */

          /* Fix parameters for BLOWFISH-CBC */
          esp_iv_len = 8;
          crypt_algo_libgcrypt = GCRY_CIPHER_BLOWFISH;
          crypt_mode_libgcrypt = GCRY_CIPHER_MODE_CBC;

          decrypted_len = len - 8;

          if (decrypted_len <= 0)
            decrypt_ok = FALSE;
          else
          {
            if(decrypted_len % esp_iv_len  == 0)
              decrypted_len_alloc = decrypted_len;
            else
              decrypted_len_alloc = (decrypted_len / esp_iv_len) * esp_iv_len + esp_iv_len;

            if (esp_crypt_key_len != gcry_cipher_get_algo_keylen (crypt_algo_libgcrypt))
            {
              fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm BLOWFISH-CBC : Bad Keylen (%u Bits, need %lu)\n",
                       esp_crypt_key_len * 8, (unsigned long) gcry_cipher_get_algo_keylen (crypt_algo_libgcrypt) * 8);
              decrypt_ok = FALSE;
            }
            else
              decrypt_using_libgcrypt = TRUE;
          }
          break;

        case IPSEC_ENCRYPT_NULL :
        default :
          /* Fix parameters */
          esp_iv_len = 0;
          decrypted_len = len - 8;

          if (decrypted_len <= 0)
            decrypt_ok = FALSE;
          else
          {
            /* Allocate Buffers for Encrypted and Decrypted data  */
            decrypted_data = (guint8 *)wmem_alloc(wmem_packet_scope(), decrypted_len + 1);
            tvb_memcpy(tvb, decrypted_data, NEW_ESP_DATA_SIZE, decrypted_len);

            decrypt_ok = TRUE;
          }
          break;
        }

        if (decrypt_using_libgcrypt)
        {
          /* Allocate Buffers for Encrypted and Decrypted data  */
          decrypted_data = (guint8 *)wmem_alloc(wmem_packet_scope(), decrypted_len_alloc + esp_iv_len);
          tvb_memcpy(tvb, decrypted_data, NEW_ESP_DATA_SIZE, decrypted_len);

          /* (Lazily) create the cipher_hd */
          if (!(*cipher_hd_created)) {
            err = gcry_cipher_open(cipher_hd, crypt_algo_libgcrypt, crypt_mode_libgcrypt, 0);
            if (err)
            {
              fprintf(stderr, "<IPsec/ESP Dissector> Error in Algorithm %s Mode %d, grcy_open_cipher failed: %s\n",
                      gcry_cipher_algo_name(crypt_algo_libgcrypt), crypt_mode_libgcrypt, gpg_strerror(err));
            }
            else
            {
              /* OK, set the key */
              if (*cipher_hd_created == FALSE)
              {
                if (crypt_mode_libgcrypt == GCRY_CIPHER_MODE_CTR)
                {
                  /* Counter mode key includes a 4 byte, (32 bit), nonce following the key */
                  err = gcry_cipher_setkey(*cipher_hd, esp_crypt_key, esp_crypt_key_len - 4);
                }
                else
                {
                  err = gcry_cipher_setkey(*cipher_hd, esp_crypt_key, esp_crypt_key_len);
                }

                if (err)
                {
                  fprintf(stderr, "<IPsec/ESP Dissector> Error in Algorithm %s Mode %d, gcry_cipher_setkey(key_len=%u) failed: %s\n",
                          gcry_cipher_algo_name(crypt_algo_libgcrypt), crypt_mode_libgcrypt, esp_crypt_key_len, gpg_strerror (err));
                  gcry_cipher_close(*cipher_hd);
                }
              }

              /* Key is created and has its key set now */
              *cipher_hd_created = TRUE;
            }
          }

          /* Now try to decrypt */
          if (crypt_mode_libgcrypt == GCRY_CIPHER_MODE_CTR)
          {
            /* Set CTR first */
            memset(ctr_block, 0, 16);
            memcpy(ctr_block, esp_crypt_key + esp_crypt_key_len - 4, 4);
            memcpy(ctr_block + 4, decrypted_data, 8);
            ctr_block[15] = 1;
            if (esp_crypt_algo == IPSEC_ENCRYPT_AES_GCM) {
              ctr_block[15]++;
            }
            err = gcry_cipher_setctr(*cipher_hd, ctr_block, 16);
            if (!err)
            {
              err = gcry_cipher_decrypt(*cipher_hd, decrypted_data + esp_iv_len, decrypted_len_alloc, NULL, 0);
            }
          }
          else
          {
            err = gcry_cipher_decrypt(*cipher_hd, decrypted_data, decrypted_len_alloc + esp_iv_len, NULL, 0);
          }

          if (err)
          {
            fprintf(stderr, "<IPsec/ESP Dissector> Error in Algorithm %s, Mode %d, gcry_cipher_decrypt failed: %s\n",
                    gcry_cipher_algo_name(crypt_algo_libgcrypt), crypt_mode_libgcrypt, gpg_strerror (err));
            gcry_cipher_close(*cipher_hd);
            decrypt_ok = FALSE;
          }
          else
          {
            /* Copy back the Authentication which was not encrypted */
            if(decrypted_len >= esp_auth_len)
            {
              tvb_memcpy(tvb, decrypted_data+decrypted_len-esp_auth_len, (gint)(NEW_ESP_DATA_SIZE+decrypted_len-esp_auth_len), esp_auth_len);
            }

            /* Decryption has finished */
            decrypt_ok = TRUE;
          }
        }
      }
    }
    else if(g_esp_enable_null_encryption_decode_heuristic)
    {
      /* The packet does not belong to a Security Association */
      null_encryption_decode_heuristic = TRUE;
    }

    if(decrypt_ok && (decrypted_len > esp_iv_len))
    {
      tvb_decrypted = tvb_new_child_real_data(tvb, (guint8 *)g_memdup(decrypted_data+sizeof(guint8)*esp_iv_len,
                                                                      decrypted_len - esp_iv_len),
                                              decrypted_len - esp_iv_len, decrypted_len - esp_iv_len);

      add_new_data_source(pinfo, tvb_decrypted, "Decrypted Data");

      /* Handler to free the Decrypted Data Buffer. */
      tvb_set_free_cb(tvb_decrypted,g_free);

      if(tvb_bytes_exist(tvb, 8, esp_iv_len))
      {
        if(esp_iv_len > 0)
          proto_tree_add_item(esp_tree, hf_esp_iv, tvb, 8, esp_iv_len, ENC_NA);
      }
      else
      {
          proto_tree_add_bytes_format(esp_tree, hf_esp_iv, tvb, 8, -1, NULL, "IV (truncated)");
      }

      /* Make sure the packet is not truncated before the fields
       * we need to read to determine the encapsulated protocol */
      if(tvb_bytes_exist(tvb_decrypted, decrypted_len - esp_iv_len - esp_auth_len - 2, 2))
      {
        esp_pad_len = tvb_get_guint8(tvb_decrypted, decrypted_len - esp_iv_len - esp_auth_len - 2);

        if(decrypted_len - esp_iv_len - esp_auth_len - esp_pad_len - 2 >= 0)
        {
          /* Get the encapsulated protocol */
          encapsulated_protocol = tvb_get_guint8(tvb_decrypted, decrypted_len - esp_iv_len - esp_auth_len - 1);

          dissector_handle = dissector_get_uint_handle(ip_dissector_table, encapsulated_protocol);
          if (dissector_handle) {
            saved_match_uint  = pinfo->match_uint;
            pinfo->match_uint = encapsulated_protocol;
            next_tvb = tvb_new_subset_length(tvb_decrypted, 0,
                                      decrypted_len - esp_auth_len - esp_pad_len - esp_iv_len - 2);
            export_ipsec_pdu(dissector_handle, pinfo, next_tvb);
            call_dissector(dissector_handle, next_tvb, pinfo, tree);
            pinfo->match_uint = saved_match_uint;
            decrypt_dissect_ok = TRUE;
          }
        }
      }

      if(decrypt_dissect_ok)
      {
        if(esp_tree)
        {
          if(esp_pad_len !=0)
            proto_tree_add_item(esp_tree, hf_esp_pad,
                                tvb_decrypted,
                                decrypted_len - esp_iv_len - esp_auth_len - 2 - esp_pad_len,
                                esp_pad_len, ENC_NA);

          proto_tree_add_uint(esp_tree, hf_esp_pad_len, tvb_decrypted,
                              decrypted_len - esp_iv_len - esp_auth_len - 2, 1,
                              esp_pad_len);

          proto_tree_add_uint_format(esp_tree, hf_esp_protocol, tvb_decrypted,
                                     decrypted_len - esp_iv_len - esp_auth_len - 1, 1,
                                     encapsulated_protocol,
                                     "Next header: %s (0x%02x)",
                                     ipprotostr(encapsulated_protocol), encapsulated_protocol);

          dissect_esp_authentication(esp_tree,
                                     tvb_decrypted,
                                     decrypted_len - esp_iv_len,
                                     esp_auth_len,
                                     authenticator_data_computed,
                                     authentication_ok,
                                     authentication_checking_ok );
        }
      }
      else
      {
        next_tvb = tvb_new_subset_length(tvb_decrypted, 0,
                                  decrypted_len - esp_iv_len - esp_auth_len);
        export_ipsec_pdu(data_handle, pinfo, next_tvb);
        call_dissector(data_handle, next_tvb, pinfo, esp_tree);

        dissect_esp_authentication(esp_tree,
                                     tvb_decrypted,
                                     decrypted_len - esp_iv_len, esp_auth_len,
                                     authenticator_data_computed, authentication_ok,
                                     authentication_checking_ok );
      }
    }
  }

  /*
    If the packet is present in the security association database and the field g_esp_enable_authentication_check set.
  */
  if(!g_esp_enable_encryption_decode && g_esp_enable_authentication_check && sad_is_present)
  {
    next_tvb = tvb_new_subset(tvb, 8, len - 8 - esp_auth_len, -1);
    export_ipsec_pdu(data_handle, pinfo, next_tvb);
    call_dissector(data_handle, next_tvb, pinfo, esp_tree);

    dissect_esp_authentication(esp_tree, tvb, len ,
                                 esp_auth_len, authenticator_data_computed,
                                 authentication_ok, authentication_checking_ok );
  }

  /* The packet does not belong to a security association and the field g_esp_enable_null_encryption_decode_heuristic is set */
  else if(null_encryption_decode_heuristic)
  {
#endif
    if(g_esp_enable_null_encryption_decode_heuristic)
    {
      /* Get length of whole ESP packet. */
      len = tvb_reported_length(tvb);

      /* Make sure the packet is not truncated before the fields
       * we need to read to determine the encapsulated protocol */
      if(tvb_bytes_exist(tvb, len - 14, 2))
      {
        esp_pad_len = tvb_get_guint8(tvb, len - 14);
        encapsulated_protocol = tvb_get_guint8(tvb, len - 13);
        dissector_handle = dissector_get_uint_handle(ip_dissector_table, encapsulated_protocol);
        if (dissector_handle) {
          saved_match_uint  = pinfo->match_uint;
          pinfo->match_uint = encapsulated_protocol;
          next_tvb = tvb_new_subset_length(tvb, 8, len - 8 - 14 - esp_pad_len);
          export_ipsec_pdu(dissector_handle, pinfo, next_tvb);
          call_dissector(dissector_handle, next_tvb, pinfo, tree);
          pinfo->match_uint = saved_match_uint;
          decrypt_dissect_ok = TRUE;
        }
      }
    }

    if(decrypt_dissect_ok)
    {
      if(esp_tree)
      {
        proto_tree_add_uint(esp_tree, hf_esp_pad_len, tvb,
                            len - 14, 1,
                            esp_pad_len);

        proto_tree_add_uint_format(esp_tree, hf_esp_protocol, tvb,
                                   len - 13, 1,
                                   encapsulated_protocol,
                                   "Next header: %s (0x%02x)",
                                   ipprotostr(encapsulated_protocol), encapsulated_protocol);

        /* Make sure we have the auth trailer data */
        if(tvb_bytes_exist(tvb, len - 12, 12))
        {
          proto_tree_add_item(esp_tree, hf_esp_authentication_data, tvb, len - 12, 12, ENC_NA);
        }
        else
        {
          /* Truncated so just display what we have */
          proto_tree_add_bytes_format(esp_tree, hf_esp_authentication_data, tvb, len - 12, 12 - (len - tvb_captured_length(tvb)),
                              NULL, "Authentication Data (truncated)");
        }
      }
    }
#ifdef HAVE_LIBGCRYPT
  }
#endif
  return tvb_captured_length(tvb);
}


static int
dissect_ipcomp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* dissector_data _U_)
{
  proto_tree *ipcomp_tree;
  proto_item *ti;
  guint8 comp_nxt;      /* Next Header */
  guint32 comp_cpi;     /* Compression parameter index */
  dissector_handle_t dissector_handle;
  guint32 saved_match_uint;
  tvbuff_t *data, *decomp;

  /*
   * load the top pane info. This should be overwritten by
   * the next protocol in the stack
   */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPComp");
  col_clear(pinfo->cinfo, COL_INFO);

  comp_nxt = tvb_get_guint8(tvb, 0);

  /*
   * populate a tree in the second pane with the status of the link layer
   * (ie none)
   */
    ti = proto_tree_add_item(tree, proto_ipcomp, tvb, 0, -1, ENC_NA);
    ipcomp_tree = proto_item_add_subtree(ti, ett_ipcomp);

    proto_tree_add_uint_format_value(ipcomp_tree, hf_ipcomp_next_header, tvb,
                        0, 1, comp_nxt, "%s (0x%02x)", ipprotostr(comp_nxt), comp_nxt);
    proto_tree_add_item(ipcomp_tree, hf_ipcomp_flags, tvb, 1, 1, ENC_NA);
    proto_tree_add_item_ret_uint(ipcomp_tree, hf_ipcomp_cpi, tvb, 2, 2, ENC_BIG_ENDIAN, &comp_cpi);

    col_add_fstr(pinfo->cinfo, COL_INFO, "IPComp (CPI=%s)", val_to_str(comp_cpi, cpi2val, "0x%04x"));

    data = tvb_new_subset_remaining(tvb, 4);
    export_ipsec_pdu(data_handle, pinfo, data);
    call_dissector(data_handle, data, pinfo, ipcomp_tree);

    /*
     * try to uncompress as if it were DEFLATEd.  With negotiated
     * CPIs, we don't know the algorithm beforehand; if we get it
     * wrong, tvb_uncompress() returns NULL and nothing is displayed.
     */
    decomp = tvb_child_uncompress(data, data, 0, tvb_captured_length(data));
    if (decomp) {
        add_new_data_source(pinfo, decomp, "IPcomp inflated data");
        saved_match_uint  = pinfo->match_uint;
        dissector_handle = dissector_get_uint_handle(ip_dissector_table, comp_nxt);
        if (dissector_handle) {
          pinfo->match_uint = comp_nxt;
        } else {
          dissector_handle = data_handle;
        }
        export_ipsec_pdu(dissector_handle, pinfo, decomp);
        call_dissector(dissector_handle, decomp, pinfo, tree);
        pinfo->match_uint = saved_match_uint;
    }

	return tvb_captured_length(tvb);
}

static void ipsec_init_protocol(void)
{
  esp_sequence_analysis_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
  esp_sequence_analysis_report_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void ipsec_cleanup_protocol(void)
{
#ifdef HAVE_LIBGCRYPT
  /* Free any SA records added by other dissectors */
  guint n;
  for (n=0; n < extra_esp_sa_records.num_records; n++) {
    uat_esp_sa_record_free_cb(&(extra_esp_sa_records.records[n]));
  }

  /* Free overall block of records */
  g_free(extra_esp_sa_records.records);
  extra_esp_sa_records.records = NULL;
  extra_esp_sa_records.num_records = 0;
#endif

  g_hash_table_destroy(esp_sequence_analysis_hash);
  g_hash_table_destroy(esp_sequence_analysis_report_hash);
}

void
proto_register_ipsec(void)
{
  static hf_register_info hf_ah[] = {
    { &hf_ah_next_header,
      { "Next header", "ah.next_header", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
        NULL, HFILL }},
    { &hf_ah_length,
      { "Length", "ah.length", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_ah_reserved,
      { "Reserved", "ah.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_ah_spi,
      { "AH SPI", "ah.spi", FT_UINT32, BASE_HEX, NULL, 0x0,
        "IP Authentication Header Security Parameters Index", HFILL }},
    { &hf_ah_iv,
      { "AH ICV", "ah.icv", FT_BYTES, BASE_NONE, NULL, 0x0,
        "IP Authentication Header Integrity Check Value", HFILL }},
    { &hf_ah_sequence,
      { "AH Sequence", "ah.sequence", FT_UINT32, BASE_DEC, NULL, 0x0,
        "IP Authentication Header Sequence Number", HFILL }}
  };

  static hf_register_info hf_esp[] = {
    { &hf_esp_spi,
      { "ESP SPI", "esp.spi", FT_UINT32, BASE_HEX_DEC, NULL, 0x0,
        "IP Encapsulating Security Payload Security Parameters Index", HFILL }},
    { &hf_esp_sequence,
      { "ESP Sequence", "esp.sequence", FT_UINT32, BASE_DEC, NULL, 0x0,
        "IP Encapsulating Security Payload Sequence Number", HFILL }},
    { &hf_esp_pad,
      { "Pad", "esp.pad", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_esp_pad_len,
      { "ESP Pad Length", "esp.pad_len", FT_UINT8, BASE_DEC, NULL, 0x0,
        "IP Encapsulating Security Payload Pad Length", HFILL }},
    { &hf_esp_protocol,
      { "ESP Next Header", "esp.protocol", FT_UINT8, BASE_HEX, NULL, 0x0,
        "IP Encapsulating Security Payload Next Header", HFILL }},
    { &hf_esp_authentication_data,
      { "Authentication Data", "esp.authentication_data", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_esp_iv,
      { "ESP IV", "esp.iv", FT_BYTES, BASE_NONE, NULL, 0x0,
        "IP Encapsulating Security Payload", HFILL }},

    { &hf_esp_icv_good,
      { "Good", "esp.icv_good", FT_BOOLEAN, BASE_NONE,  NULL, 0x0,
        "True: ICV matches packet content; False: doesn't match content or not checked", HFILL }},
    { &hf_esp_icv_bad,
      { "Bad", "esp.icv_bad", FT_BOOLEAN, BASE_NONE,  NULL, 0x0,
        "True: ICV doesn't match packet content; False: matches content or not checked", HFILL }},
    { &hf_esp_sequence_analysis_expected_sn,
      { "Expected SN", "esp.sequence-analysis.expected-sn", FT_UINT32, BASE_DEC,  NULL, 0x0,
        NULL, HFILL }},
    { &hf_esp_sequence_analysis_previous_frame,
      { "Previous Frame", "esp.sequence-analysis.previous-frame", FT_FRAMENUM, BASE_NONE,  NULL, 0x0,
        NULL, HFILL }},
  };

  static hf_register_info hf_ipcomp[] = {
    { &hf_ipcomp_next_header,
      { "Next Header", "ipcomp.next_header", FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_ipcomp_flags,
      { "IPComp Flags", "ipcomp.flags", FT_UINT8, BASE_HEX, NULL, 0x0,
        "IP Payload Compression Protocol Flags", HFILL }},
    { &hf_ipcomp_cpi,
      { "IPComp CPI", "ipcomp.cpi", FT_UINT16, BASE_HEX, VALS(cpi2val), 0x0,
        "IP Payload Compression Protocol Compression Parameter Index", HFILL }},
  };

  static gint *ett[] = {
    &ett_ah,
    &ett_esp,
    &ett_esp_icv,
    &ett_ipcomp,
  };

  static ei_register_info ei[] = {
    { &ei_esp_sequence_analysis_wrong_sequence_number, { "esp.sequence-analysis.wrong-sequence-number", PI_SEQUENCE, PI_WARN, "Wrong Sequence Number", EXPFILL }}
  };

#ifdef HAVE_LIBGCRYPT

  static const value_string esp_proto_type_vals[] = {
    { IPSEC_SA_IPV4, "IPv4" },
    { IPSEC_SA_IPV6, "IPv6" },
    { 0x00, NULL }
  };

  static const value_string esp_encryption_type_vals[] = {
    { IPSEC_ENCRYPT_NULL, "NULL" },
    { IPSEC_ENCRYPT_3DES_CBC, "TripleDES-CBC [RFC2451]" },
    { IPSEC_ENCRYPT_AES_CBC, "AES-CBC [RFC3602]" },
    { IPSEC_ENCRYPT_AES_CTR, "AES-CTR [RFC3686]" },
    { IPSEC_ENCRYPT_DES_CBC, "DES-CBC [RFC2405]" },
    { IPSEC_ENCRYPT_CAST5_CBC, "CAST5-CBC [RFC2144]" },
    { IPSEC_ENCRYPT_BLOWFISH_CBC, "BLOWFISH-CBC [RFC2451]" },
    { IPSEC_ENCRYPT_TWOFISH_CBC, "TWOFISH-CBC" },
    { IPSEC_ENCRYPT_AES_GCM, "AES-GCM [RFC4106]" },
    { 0x00, NULL }
  };

  static const value_string esp_authentication_type_vals[] = {
    { IPSEC_AUTH_NULL, "NULL" },
    { IPSEC_AUTH_HMAC_SHA1_96, "HMAC-SHA-1-96 [RFC2404]" },
    { IPSEC_AUTH_HMAC_SHA256_96, "HMAC-SHA-256-96 [draft-ietf-ipsec-ciph-sha-256-00]" },
    { IPSEC_AUTH_HMAC_SHA256_128, "HMAC-SHA-256-128 [RFC4868]" },
    { IPSEC_AUTH_HMAC_SHA384_192, "HMAC-SHA-384-192 [RFC4868]" },
    { IPSEC_AUTH_HMAC_SHA512_256, "HMAC-SHA-512-256 [RFC4868]" },
    { IPSEC_AUTH_HMAC_MD5_96, "HMAC-MD5-96 [RFC2403]" },
    { IPSEC_AUTH_HMAC_RIPEMD160_96, "MAC-RIPEMD-160-96 [RFC2857]" },
/*    { IPSEC_AUTH_AES_XCBC_MAC_96, "AES-XCBC-MAC-96 [RFC3566]" }, */
    { IPSEC_AUTH_ANY_64BIT, "ANY 64 bit authentication [no checking]" },
    { IPSEC_AUTH_ANY_96BIT, "ANY 96 bit authentication [no checking]" },
    { IPSEC_AUTH_ANY_128BIT, "ANY 128 bit authentication [no checking]" },
    { IPSEC_AUTH_ANY_192BIT, "ANY 192 bit authentication [no checking]" },
    { IPSEC_AUTH_ANY_256BIT, "ANY 256 bit authentication [no checking]" },
    { 0x00, NULL }
  };

  static uat_field_t esp_uat_flds[] = {
      UAT_FLD_VS(uat_esp_sa_records, protocol, "Protocol", esp_proto_type_vals, "Protocol used"),
      UAT_FLD_CSTRING(uat_esp_sa_records, srcIP, "Src IP", "Source Address"),
      UAT_FLD_CSTRING(uat_esp_sa_records, dstIP, "Dest IP", "Destination Address"),
      UAT_FLD_CSTRING(uat_esp_sa_records, spi, "SPI", "SPI"),
      UAT_FLD_VS(uat_esp_sa_records, encryption_algo, "Encryption", esp_encryption_type_vals, "Encryption algorithm"),
      UAT_FLD_CSTRING(uat_esp_sa_records, encryption_key_string, "Encryption Key", "Encryption Key"),
      UAT_FLD_VS(uat_esp_sa_records, authentication_algo, "Authentication", esp_authentication_type_vals, "Authentication algorithm"),
      UAT_FLD_CSTRING(uat_esp_sa_records, authentication_key_string, "Authentication Key", "Authentication Key"),
      UAT_END_FIELDS
    };
#endif

  module_t *ah_module;
  module_t *esp_module;

  expert_module_t* expert_esp;

  proto_ah = proto_register_protocol("Authentication Header", "AH", "ah");
  proto_register_field_array(proto_ah, hf_ah, array_length(hf_ah));

  proto_esp = proto_register_protocol("Encapsulating Security Payload",
                                      "ESP", "esp");
  proto_register_field_array(proto_esp, hf_esp, array_length(hf_esp));

  proto_ipcomp = proto_register_protocol("IP Payload Compression",
                                         "IPComp", "ipcomp");
  proto_register_field_array(proto_ipcomp, hf_ipcomp, array_length(hf_ipcomp));

  proto_register_subtree_array(ett, array_length(ett));

  expert_esp = expert_register_protocol(proto_esp);
  expert_register_field_array(expert_esp, ei, array_length(ei));

  ah_module = prefs_register_protocol(proto_ah, NULL);

  prefs_register_obsolete_preference(ah_module, "place_ah_payload_in_subtree");

  esp_module = prefs_register_protocol(proto_esp, NULL);

  prefs_register_bool_preference(esp_module, "enable_null_encryption_decode_heuristic",
                                 "Attempt to detect/decode NULL encrypted ESP payloads",
                                 "This is done only if the Decoding is not SET or the packet does not belong to a SA. "
                                 "Assumes a 12 byte auth (HMAC-SHA1-96/HMAC-MD5-96/AES-XCBC-MAC-96) "
                                 "and attempts decode based on the ethertype 13 bytes from packet end",
                                 &g_esp_enable_null_encryption_decode_heuristic);

  prefs_register_bool_preference(esp_module, "do_esp_sequence_analysis",
                                 "Check sequence numbers of ESP frames",
                                 "Check that successive frames increase sequence number by 1 within an SPI.  This should work OK when only one host is sending frames on an SPI",
                                 &g_esp_do_sequence_analysis);

#ifdef HAVE_LIBGCRYPT
  prefs_register_bool_preference(esp_module, "enable_encryption_decode",
                                 "Attempt to detect/decode encrypted ESP payloads",
                                 "Attempt to decode based on the SAD described hereafter.",
                                 &g_esp_enable_encryption_decode);

  prefs_register_bool_preference(esp_module, "enable_authentication_check",
                                 "Attempt to Check ESP Authentication",
                                 "Attempt to Check ESP Authentication based on the SAD described hereafter.",
                                 &g_esp_enable_authentication_check);

  esp_uat = uat_new("ESP SAs",
            sizeof(uat_esp_sa_record_t),    /* record size */
            "esp_sa",                       /* filename */
            TRUE,                           /* from_profile */
            &uat_esp_sa_records,            /* data_ptr */
            &num_sa_uat,                    /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
            NULL,                           /* help */
            uat_esp_sa_record_copy_cb,      /* copy callback */
            uat_esp_sa_record_update_cb,    /* update callback */
            uat_esp_sa_record_free_cb,      /* free callback */
            NULL,                           /* post update callback */
            esp_uat_flds);                  /* UAT field definitions */

  prefs_register_uat_preference(esp_module,
                                "sa_table",
                                "ESP SAs",
                                "Preconfigured ESP Security Associations",
                                esp_uat);
#endif

  register_init_routine(&ipsec_init_protocol);
  register_cleanup_routine(&ipsec_cleanup_protocol);

  register_dissector("esp", dissect_esp, proto_esp);
  register_dissector("ah", dissect_ah, proto_ah);
}

void
proto_reg_handoff_ipsec(void)
{
  dissector_handle_t esp_handle, ah_handle, ipv6_ah_handle, ipcomp_handle;

  data_handle = find_dissector("data");
  ah_handle = find_dissector("ah");
  dissector_add_uint("ip.proto", IP_PROTO_AH, ah_handle);
  esp_handle = find_dissector("esp");
  dissector_add_uint("ip.proto", IP_PROTO_ESP, esp_handle);
  ipcomp_handle = create_dissector_handle(dissect_ipcomp, proto_ipcomp);
  dissector_add_uint("ip.proto", IP_PROTO_IPCOMP, ipcomp_handle);
  ipv6_ah_handle = create_dissector_handle(dissect_ah_header, proto_ah );
  dissector_add_uint("ipv6.nxt", IP_PROTO_AH, ipv6_ah_handle);

  ip_dissector_table = find_dissector_table("ip.proto");

  exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_3);
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
