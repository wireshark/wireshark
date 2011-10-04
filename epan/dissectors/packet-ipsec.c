/* packet-ipsec.c
 * Routines for IPsec/IPComp packet disassembly
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include "packet-ipsec.h"
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>

#include <ctype.h>

/* If you want to be able to decrypt or Check Authentication of ESP packets you MUST define this : */
#ifdef HAVE_LIBGCRYPT
#include <epan/uat.h>
#include <gcrypt.h>
#endif /* HAVE_LIBGCRYPT */


static int proto_ah = -1;
static int hf_ah_spi = -1;
static int hf_ah_iv = -1;
static int hf_ah_sequence = -1;
static int proto_esp = -1;
static int hf_esp_spi = -1;
static int hf_esp_iv = -1;
static int hf_esp_sequence = -1;
static int hf_esp_pad_len = -1;
static int hf_esp_protocol = -1;
static int proto_ipcomp = -1;
static int hf_ipcomp_flags = -1;
static int hf_ipcomp_cpi = -1;

static gint ett_ah = -1;
static gint ett_esp = -1;
static gint ett_ipcomp = -1;

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

/* Authentication algorithms defined in RFC 4305 */
#define IPSEC_AUTH_NULL 0
#define IPSEC_AUTH_HMAC_SHA1_96 1
#define IPSEC_AUTH_HMAC_SHA256_96 2
#define IPSEC_AUTH_HMAC_SHA256_128 3
#define IPSEC_AUTH_HMAC_MD5_96 4
#define IPSEC_AUTH_HMAC_RIPEMD160_96 5
/* define IPSEC_AUTH_AES_XCBC_MAC_96 6 */
#define IPSEC_AUTH_ANY_96BIT 7
#define IPSEC_AUTH_ANY_128BIT 8
#define IPSEC_AUTH_ANY_192BIT 9
#define IPSEC_AUTH_ANY_256BIT 10

#define IPSEC_IPV6_ADDR_LEN 128
#define IPSEC_IPV4_ADDR_LEN 32
#define IPSEC_STRLEN_IPV6 32
#define IPSEC_STRLEN_IPV4 8
#define IPSEC_SA_IPV4 1
#define IPSEC_SA_IPV6 2
#define IPSEC_SA_UNKNOWN -1
#define IPSEC_SA_WILDCARDS_ANY '*'
#define IPSEC_SPI_LEN_MAX 10

#endif

/* well-known algorithm number (in CPI), from RFC2409 */
#define IPCOMP_OUI	1	/* vendor specific */
#define IPCOMP_DEFLATE	2	/* RFC2394 */
#define IPCOMP_LZS	3	/* RFC2395 */
#define IPCOMP_MAX	4


static const value_string cpi2val[] = {
  { IPCOMP_OUI, "OUI" },
  { IPCOMP_DEFLATE, "DEFLATE" },
  { IPCOMP_LZS, "LZS" },
  { 0, NULL },
};

struct newah {
  guint8	ah_nxt;		/* Next Header */
  guint8	ah_len;		/* Length of data + 1, in 32bit */
  guint16	ah_reserve;	/* Reserved for future use */
  guint32	ah_spi;		/* Security parameter index */
  guint32	ah_seq;		/* Sequence number field */
  /* variable size, 32bit bound*/	/* Authentication data */
};

struct newesp {
  guint32	esp_spi;	/* ESP */
  guint32	esp_seq;	/* Sequence number */
  /*variable size*/		/* (IV and) Payload data */
  /*variable size*/		/* padding */
  /*8bit*/			/* pad size */
  /*8bit*/			/* next header */
  /*8bit*/			/* next header */
  /*variable size, 32bit bound*/	/* Authentication data */
};

struct ipcomp {
  guint8 comp_nxt;	/* Next Header */
  guint8 comp_flags;	/* Must be zero */
  guint16 comp_cpi;	/* Compression parameter index */
};

#ifdef HAVE_LIBGCRYPT
/*-------------------------------------
 * UAT for ESP
 *-------------------------------------
 */
/* UAT entry structure. */
typedef struct {
   guint8 protocol;
   gchar *srcIP;
   gchar *srcFilter;
   gchar *dstIP;
   gchar *dstFilter;
   gchar *spi;
   guint8 encryption_algo;
   gchar *encryption_key;
   guint8 authentication_algo;
   gchar *authentication_key;
} uat_esp_sa_record_t;

static uat_esp_sa_record_t *uat_esp_sa_records = NULL;

static uat_t * esp_uat = NULL;
static guint num_sa_uat = 0;

static void* uat_esp_sa_record_copy_cb(void* n, const void* o, size_t siz _U_) {
    uat_esp_sa_record_t* new_rec = (uat_esp_sa_record_t *)n;
    const uat_esp_sa_record_t* old_rec = (uat_esp_sa_record_t *)o;

    new_rec->srcIP = (old_rec->srcIP) ? g_strdup(old_rec->srcIP) : NULL;
    new_rec->srcFilter = (old_rec->srcFilter) ? g_strdup(old_rec->srcFilter) : NULL;
    new_rec->dstIP = (old_rec->dstIP) ? g_strdup(old_rec->dstIP) : NULL;
    new_rec->dstFilter = (old_rec->dstFilter) ? g_strdup(old_rec->dstFilter) : NULL;
    new_rec->spi = (old_rec->spi) ? g_strdup(old_rec->spi) : NULL;
    new_rec->encryption_key = (old_rec->encryption_key) ? g_strdup(old_rec->encryption_key) : NULL;
    new_rec->authentication_key = (old_rec->authentication_key) ? g_strdup(old_rec->authentication_key) : NULL;

    return new_rec;
}

#if 0
static int get_full_ipv6_addr(char* ipv6_addr_expanded, char *ipv6_addr);
static int get_full_ipv4_addr(char* ipv4_addr_expanded, char *ipv4_addr);
#endif

static void uat_esp_sa_record_update_cb(void* r, const char** err _U_) {
    uat_esp_sa_record_t* rec = (uat_esp_sa_record_t *)r;

    /* Generate the real filter strings that will be used for decryption*/
    g_free(rec->srcFilter);
    g_free(rec->dstFilter);

    switch(rec->protocol)
    {
    case IPSEC_SA_IPV4:
      rec->srcFilter = (gchar *)g_malloc((IPSEC_STRLEN_IPV6 + 1) * sizeof(gchar));
      rec->dstFilter = (gchar *)g_malloc((IPSEC_STRLEN_IPV6 + 1) * sizeof(gchar));
      break;
    case IPSEC_SA_IPV6:
      rec->srcFilter = (gchar *)g_malloc((IPSEC_STRLEN_IPV6 + 1) * sizeof(gchar));
      rec->dstFilter = (gchar *)g_malloc((IPSEC_STRLEN_IPV6 + 1) * sizeof(gchar));
      break;
    }
}

static void uat_esp_sa_record_free_cb(void*r) {
    uat_esp_sa_record_t* rec = (uat_esp_sa_record_t*)r;

    g_free(rec->srcIP);
    g_free(rec->srcFilter);
    g_free(rec->dstIP);
    g_free(rec->dstFilter);
    g_free(rec->spi);
    g_free(rec->encryption_key);
    g_free(rec->authentication_key);
}

UAT_VS_DEF(uat_esp_sa_records, protocol, uat_esp_sa_record_t, IPSEC_SA_IPV4, "IPv4")
UAT_CSTRING_CB_DEF(uat_esp_sa_records, srcIP, uat_esp_sa_record_t)
UAT_CSTRING_CB_DEF(uat_esp_sa_records, dstIP, uat_esp_sa_record_t)
UAT_CSTRING_CB_DEF(uat_esp_sa_records, spi, uat_esp_sa_record_t)
UAT_VS_DEF(uat_esp_sa_records, encryption_algo, uat_esp_sa_record_t, 0, "FIXX")
UAT_CSTRING_CB_DEF(uat_esp_sa_records, encryption_key, uat_esp_sa_record_t)
UAT_VS_DEF(uat_esp_sa_records, authentication_algo, uat_esp_sa_record_t, 0, "FIXX")
UAT_CSTRING_CB_DEF(uat_esp_sa_records, authentication_key, uat_esp_sa_record_t)

/* Default ESP payload decode to off */
static gboolean g_esp_enable_encryption_decode = FALSE;

/* Default ESP payload Authentication Checking to off */
static gboolean g_esp_enable_authentication_check = FALSE;
#endif

/*
   Default ESP payload heuristic decode to off
   (only works if payload is NULL encrypted and ESP payload decode is off or payload is NULL encrypted
   and the packet does not match a Security Association).
*/
static gboolean g_esp_enable_null_encryption_decode_heuristic = FALSE;

/* Place AH payload in sub tree */
static gboolean g_ah_payload_in_subtree = FALSE;

#ifndef offsetof
#define	offsetof(type, member)	((size_t)(&((type *)0)->member))
#endif




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
	      suffix[IPSEC_STRLEN_IPV6 -1 -cpt_suffix] = toupper(ipv6_address[ipv6_len - cpt - 1]);
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
      - char *ipv6_addr_expansed : the expanded ipv6 address associated in char *

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
      prefix_addr = ep_strndup(ipv6_addr,strlen(ipv6_addr) - suffix_cpt);
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
      - char *ipv4_addr_expansed : the expanded ipv4 address associated in char *

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
		sscanf(addr_byte_string_tmp,"%u",&addr_byte);
		if(addr_byte < 16) g_snprintf(addr_byte_string,4,"0%X",addr_byte);
		else g_snprintf(addr_byte_string,4,"%X",addr_byte);
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
		sscanf(addr_byte_string_tmp,"%u",&addr_byte);
		if(addr_byte < 16) g_snprintf(addr_byte_string,4,"0%X",addr_byte);
		else g_snprintf(addr_byte_string,4,"%X",addr_byte);
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
  guint addr_len = (guint)strlen(addr);
  guint filter_len = (guint)strlen(filter);

  if(addr_len != filter_len) 
     return FALSE;

  /* No length specified */
   if( ((typ == IPSEC_SA_IPV6) && (filter_len > IPSEC_IPV6_ADDR_LEN))
      || ((typ == IPSEC_SA_IPV4) && (filter_len > IPSEC_IPV4_ADDR_LEN)))
   {
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

         sscanf(filter_string_tmp,"%x",&filter_tmp);
         sscanf(addr_string_tmp,"%x",&addr_tmp);
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
   Return : Return TRUE if the filter match the spi.
   Params:
      - gchar *spi : the spi to check
      - gchar *filter : the filter
*/
static gboolean
filter_spi_match(gchar *spi, gchar *filter)
{
   guint i;
   guint filter_len = (guint)strlen(filter);

   if((filter_len == 1) && (filter[0] == IPSEC_SA_WILDCARDS_ANY))
      return TRUE;
   else if(strlen(spi) != filter_len)
      return FALSE;

   for(i = 0; filter[i]; i++)
      if((filter[i] != IPSEC_SA_WILDCARDS_ANY) && (filter[i] != spi[i])) 
         return FALSE;

   return TRUE;
}


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
  guint key_len = 0;
  gint hex_digit;
  guchar key_byte;
  guint i, j;

  if(key != NULL)
    {
      if((strlen(key) > 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
	{
	  /*
	   * Key begins with "0x" or "0X"; skip that and treat the rest
	   * as a sequence of hex digits.
	   */
	  i = 2;	/* first character after "0[Xx]" */
	  j = 0;
	  if(strlen(key) %2  == 1)
	    {
	      /*
	       * Key has an odd number of characters; we act as if the
	       * first character had a 0 in front of it, making the
	       * number of characters even.
	       */
	      key_len = ((guint) strlen(key) - 2) / 2 + 1;
	      *ascii_key = (gchar *) g_malloc ((key_len + 1)* sizeof(gchar));
	      hex_digit = g_ascii_xdigit_value(key[i]);
	      i++;
	      if (hex_digit == -1)
		{
		  g_free(*ascii_key);
		  *ascii_key = NULL;
		  return -1;	/* not a valid hex digit */
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
	      key_len = ((guint) strlen(key) - 2) / 2;
	      *ascii_key = (gchar *) g_malloc ((key_len + 1)* sizeof(gchar));
	    }

	  while(i < (strlen(key) -1))
	    {
	      hex_digit = g_ascii_xdigit_value(key[i]);
	      i++;
	      if (hex_digit == -1)
	        {
		  g_free(*ascii_key);
		  *ascii_key = NULL;
		  return -1;	/* not a valid hex digit */
		}
	      key_byte = ((guchar)hex_digit) << 4;
	      hex_digit = g_ascii_xdigit_value(key[i]);
	      i++;
	      if (hex_digit == -1)
	        {
		  g_free(*ascii_key);
		  *ascii_key = NULL;
		  return -1;	/* not a valid hex digit */
		}
	      key_byte |= (guchar)hex_digit;
	      (*ascii_key)[j] = key_byte;
	      j++;
	    }
	  (*ascii_key)[j] = '\0';
	}

      else if((strlen(key) == 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
	{
	  return 0;
	}

      else
	{
	  key_len = (guint) strlen(key);
	  *ascii_key = g_strdup(key);
	}
    }

  return key_len;
}

/*
   Name : static goolean get_esp_sa(g_esp_sa_database *sad, gint protocol_typ, gchar *src,  gchar *dst,  gint spi,
	   gint *encryption_algo,
	   gint *authentication_algo,
	   gchar **encryption_key,
	   guint *encryption_key_len,
	   gchar **authentication_key,
	   guint *authentication_key_len

   Description : Give Encryption Algo, Key and Authentification Algo for a Packet if a corresponding SA is available in a Security Association database
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

*/
static gboolean
get_esp_sa(gint protocol_typ, gchar *src,  gchar *dst,  gint spi,
	   gint *encryption_algo,
	   gint *authentication_algo,
	   gchar **encryption_key,
	   guint *encryption_key_len,
	   gchar **authentication_key,
	   guint *authentication_key_len
	   )

{
   gboolean found = FALSE;
   guint i;
   gchar spi_string[IPSEC_SPI_LEN_MAX];
   gint key_len;

   g_snprintf(spi_string, IPSEC_SPI_LEN_MAX,"%i", spi);

   for (i = 0; (found == FALSE) && (i < num_sa_uat); i++)
   {
      if((protocol_typ == uat_esp_sa_records[i].protocol)
           && filter_address_match(src, uat_esp_sa_records[i].srcFilter, protocol_typ)
           && filter_address_match(dst, uat_esp_sa_records[i].dstFilter, protocol_typ)
           && filter_spi_match(spi_string, uat_esp_sa_records[i].spi))
      {
         found = TRUE;

         *encryption_algo = uat_esp_sa_records[i].encryption_algo;
         *authentication_algo = uat_esp_sa_records[i].authentication_algo;
         key_len = compute_ascii_key(authentication_key, uat_esp_sa_records[i].authentication_key);
         if (key_len == -1)
         {
            /* Bad key; XXX - report this */
            *authentication_key_len = 0;
            found = FALSE;
         }
         else
            *authentication_key_len = (guint)key_len;

         key_len = compute_ascii_key(encryption_key, uat_esp_sa_records[i].encryption_key);
         if (key_len == -1)
         {
            /* Bad key; XXX - report this */
            *encryption_key_len = 0;
            found = FALSE;
         }
         else
            *encryption_key_len = key_len;
      }
   }

   return found;
}
#endif

static void
dissect_ah(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *next_tree;
  guint8 nxt;
  tvbuff_t *next_tvb;
  int advance;

  advance = dissect_ah_header(tvb, pinfo, tree, &nxt, &next_tree);
  next_tvb = tvb_new_subset_remaining(tvb, advance);

  if (g_ah_payload_in_subtree) {
    col_set_writable(pinfo->cinfo, FALSE);
  }

  /* do lookup with the subdissector table */
  if (!dissector_try_uint(ip_dissector_table, nxt, next_tvb, pinfo, tree)) {
    call_dissector(data_handle,next_tvb, pinfo, next_tree);
  }
}

int
dissect_ah_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		  guint8 *nxt_p, proto_tree **next_tree_p)
{
  proto_tree *ah_tree;
  proto_item *ti;
  struct newah ah;
  int advance;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "AH");
  col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb, (guint8 *)&ah, 0, sizeof(ah));
  advance = sizeof(ah) + ((ah.ah_len - 1) << 2);

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "AH (SPI=0x%08x)",
		 (guint32)g_ntohl(ah.ah_spi));
  }

  if (tree) {
    /* !!! specify length */
    ti = proto_tree_add_item(tree, proto_ah, tvb, 0, advance, FALSE);
    ah_tree = proto_item_add_subtree(ti, ett_ah);

    proto_tree_add_text(ah_tree, tvb,
			offsetof(struct newah, ah_nxt), 1,
			"Next Header: %s (0x%02x)",
			ipprotostr(ah.ah_nxt), ah.ah_nxt);
    proto_tree_add_text(ah_tree, tvb,
			offsetof(struct newah, ah_len), 1,
			"Length: %u", (ah.ah_len + 2) << 2);
    proto_tree_add_uint(ah_tree, hf_ah_spi, tvb,
			offsetof(struct newah, ah_spi), 4,
			(guint32)g_ntohl(ah.ah_spi));
    proto_tree_add_uint(ah_tree, hf_ah_sequence, tvb,
			offsetof(struct newah, ah_seq), 4,
			(guint32)g_ntohl(ah.ah_seq));
    proto_tree_add_item(ah_tree, hf_ah_iv, tvb,
			sizeof(ah), (ah.ah_len) ? (ah.ah_len - 1) << 2 : 0,
			ENC_NA);

    if (next_tree_p != NULL) {
      /* Decide where to place next protocol decode */
      if (g_ah_payload_in_subtree) {
	*next_tree_p = ah_tree;
      }
      else {
	*next_tree_p = tree;
      }
    }
  } else {
    if (next_tree_p != NULL)
      *next_tree_p = NULL;
  }

  if (nxt_p != NULL)
    *nxt_p = ah.ah_nxt;

  /* start of the new header (could be a extension header) */
  return advance;
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
      - gint len : length of the data availabale in tvbuff
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
  if(esp_auth_len == 0)
    {
      proto_tree_add_text(tree, tvb, len, 0,
			  "NULL Authentication");
    }

  /* Make sure we have the auth trailer data */
  else if(tvb_bytes_exist(tvb, len - esp_auth_len, esp_auth_len))
    {
      if((authentication_ok) && (authentication_checking_ok))
	{
	  proto_tree_add_text(tree, tvb, len - esp_auth_len, esp_auth_len,
			      "Authentication Data [correct]");
	}

      else if((authentication_ok) && (!authentication_checking_ok))
	{
	  proto_tree_add_text(tree, tvb, len - esp_auth_len, esp_auth_len,
			      "Authentication Data [incorrect, should be 0x%s]", authenticator_data_computed);

	  g_free(authenticator_data_computed);
	}

      else proto_tree_add_text(tree, tvb, len - esp_auth_len, esp_auth_len,
			       "Authentication Data");
    }
  else
    {
      /* Truncated so just display what we have */
      proto_tree_add_text(tree, tvb, len - esp_auth_len, esp_auth_len - (len - tvb_length(tvb)),
			  "Authentication Data (truncated)");
    }
}
#endif

static void
dissect_esp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *esp_tree = NULL;
  proto_item *ti;
  struct newesp esp;

  gint len = 0;
  gint i = 0;

#ifdef HAVE_LIBGCRYPT
  char res[3];

  /* Packet Variables related */
  gchar *ip_src = NULL;
  gchar *ip_dst = NULL;
  guint32 spi = 0;
#endif

  guint encapsulated_protocol = 0;
  gboolean decrypt_dissect_ok = FALSE;

#ifdef HAVE_LIBGCRYPT
  gboolean get_address_ok = FALSE;
  gboolean null_encryption_decode_heuristic = FALSE;
  guint8 *decrypted_data = NULL;
  guint8 *encrypted_data = NULL;
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
  gcry_cipher_hd_t cypher_hd;
  gcry_md_hd_t md_hd;
  int md_len = 0;
  gcry_error_t err = 0;
  int crypt_algo_libgcrypt = 0;
  int crypt_mode_libgcrypt = 0;
  int auth_algo_libgcrypt = 0;
  unsigned char *authenticator_data_computed = NULL;
  unsigned char *authenticator_data_computed_md;

  unsigned char ctr_block[16];

  /*
   * load the top pane info. This should be overwritten by
   * the next protocol in the stack
   */

#endif

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESP");
  col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb, (guint8 *)&esp, 0, sizeof(esp));

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "ESP (SPI=0x%08x)",
		 (guint32)g_ntohl(esp.esp_spi));
  }


  /*
   * populate a tree in the second pane with the status of the link layer
   * (ie none)
   */

  if(tree) {
    len = 0, encapsulated_protocol = 0;
    decrypt_dissect_ok = FALSE;
    i = 0;

    ti = proto_tree_add_item(tree, proto_esp, tvb, 0, -1, FALSE);
    esp_tree = proto_item_add_subtree(ti, ett_esp);
    proto_tree_add_uint(esp_tree, hf_esp_spi, tvb,
			offsetof(struct newesp, esp_spi), 4,
			(guint32)g_ntohl(esp.esp_spi));
    proto_tree_add_uint(esp_tree, hf_esp_sequence, tvb,
			offsetof(struct newesp, esp_seq), 4,
			(guint32)g_ntohl(esp.esp_seq));
  }


#ifdef HAVE_LIBGCRYPT
  /* The SAD is not activated */
  if(g_esp_enable_null_encryption_decode_heuristic &&
    !g_esp_enable_encryption_decode)
    null_encryption_decode_heuristic = TRUE;

  if(g_esp_enable_encryption_decode || g_esp_enable_authentication_check)
  {
      /* Get Source & Destination Addresses in gchar * with all the bytes available.  */
      switch (pinfo -> src.type)
      {

      case AT_IPv4 :
      {
         const guint8 *srcaddr = pinfo -> src.data;
         const guint8 *dstaddr = pinfo -> dst.data;

         ip_src = (gchar *) g_malloc((IPSEC_STRLEN_IPV4 + 1) * sizeof(gchar));
         ip_dst = (gchar *) g_malloc((IPSEC_STRLEN_IPV4 + 1) * sizeof(gchar));
         protocol_typ = IPSEC_SA_IPV4;

         for(i = 0 ; i < pinfo -> src.len; i++)
         {
            if(srcaddr[i] < 16)
            {
               g_snprintf(res,3,"0%X ", srcaddr[i]);
            }
            else
            {
               g_snprintf(res,3,"%X ", srcaddr[i]);
            }
            memcpy(ip_src + i*2, res, 2);
         }
         ip_src[IPSEC_STRLEN_IPV4] = '\0';

         for(i = 0 ; i < pinfo -> dst.len; i++)
         {
            if(dstaddr[i] < 16)
            {
               g_snprintf(res,3,"0%X ", dstaddr[i]);
            }
            else
            {
               g_snprintf(res,3,"%X ", dstaddr[i]);
            }
            memcpy(ip_dst + i*2, res, 2);
         }
	      ip_dst[IPSEC_STRLEN_IPV4] = '\0';

         get_address_ok = TRUE;
         break;
      }

      case AT_IPv6 :
      {
         const guint8 *srcaddr = pinfo -> src.data;
         const guint8 *dstaddr = pinfo -> dst.data;

         ip_src = (gchar *) g_malloc((IPSEC_STRLEN_IPV6 + 1) * sizeof(gchar));
         ip_dst = (gchar *) g_malloc((IPSEC_STRLEN_IPV6 + 1) * sizeof(gchar));
         protocol_typ = IPSEC_SA_IPV6;

         for(i = 0 ; i < pinfo -> src.len; i++)
         {
            if(srcaddr[i] < 16)
            {
               g_snprintf(res,3,"0%X ", srcaddr[i]);
            }
            else
            {
               g_snprintf(res,3,"%X ", srcaddr[i]);
            }
            memcpy(ip_src + i*2, res, 2);
         }
         ip_src[IPSEC_STRLEN_IPV6] = '\0';

         for(i = 0 ; i < pinfo -> dst.len; i++)
         {
            if(dstaddr[i] < 16)
            {
               g_snprintf(res,3,"0%X ", dstaddr[i]);
            }
            else
            {
               g_snprintf(res,3,"%X ", dstaddr[i]);
            }
            memcpy(ip_dst + i*2, res, 2);
         }
         ip_dst[IPSEC_STRLEN_IPV6] = '\0';

         get_address_ok = TRUE;
         break;
      default:
	/* Probably some error display should go in here??? */
	;
      }
      }

   /* The packet cannot be decoded using the SAD */
   if(g_esp_enable_null_encryption_decode_heuristic && !get_address_ok)
      null_encryption_decode_heuristic = TRUE;

   if(get_address_ok)
	{
      /* Get the SPI */
      if (tvb_length(tvb) >= 4)
      {
         spi = tvb_get_ntohl(tvb, 0);
      }


	  /*
	    PARSE the SAD and fill it. It may take some time since it will
	    be called every times an ESP Payload is found.
	  */

	  if((sad_is_present = get_esp_sa(protocol_typ, ip_src, ip_dst, spi,
					  &esp_crypt_algo, &esp_auth_algo,
					  &esp_crypt_key, &esp_crypt_key_len, &esp_auth_key, &esp_auth_key_len)))
	  {

	      /* Get length of whole ESP packet. */
	      len = tvb_reported_length(tvb);

	      switch(esp_auth_algo)
         {
         case IPSEC_AUTH_NULL:
            esp_auth_len = 0;
            break;

         case IPSEC_AUTH_HMAC_SHA256_128:
         case IPSEC_AUTH_ANY_128BIT:
            esp_auth_len = 16;
            break;

         case IPSEC_AUTH_ANY_256BIT:
            esp_auth_len = 32;
            break;

         case IPSEC_AUTH_ANY_192BIT:
            esp_auth_len = 24;
            break;

         case IPSEC_AUTH_HMAC_SHA1_96:
   		case IPSEC_AUTH_HMAC_SHA256_96:
/*		   case IPSEC_AUTH_AES_XCBC_MAC_96: */
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
               authenticator_data = (guint8 *) g_malloc0 (( esp_auth_len + 1) * sizeof(guint8));
               tvb_memcpy(tvb, authenticator_data, len - esp_auth_len, esp_auth_len);

               esp_data = (guint8 *) g_malloc0 (( len - esp_auth_len + 1) * sizeof(guint8));
               tvb_memcpy(tvb, esp_data, 0, len - esp_auth_len);

               err = gcry_md_open (&md_hd, auth_algo_libgcrypt, GCRY_MD_FLAG_HMAC);
               if (err)
               {
                  fprintf (stderr, "<IPsec/ESP Dissector> Error in Algorithm %s, gcry_md_open failed: %s\n",
                                    gcry_md_algo_name(auth_algo_libgcrypt), gpg_strerror (err));
                  authentication_ok = FALSE;
                  g_free(authenticator_data);
                  g_free(esp_data);
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
                           unsigned char authenticator_data_computed_car[3];
                           authenticator_data_computed = (guint8 *) g_malloc (( esp_auth_len * 2 + 1) * sizeof(guint8));
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
                  g_free(authenticator_data);
                  g_free(esp_data);
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

               decrypted_len = len - sizeof(struct newesp);

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
                     fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm 3DES-CBC : Bad Keylen (got %i Bits, need %lu)\n",
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

               decrypted_len = len - sizeof(struct newesp);

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
                        fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm AES-CBC : Bad Keylen (%i Bits)\n",
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

               decrypted_len = len - sizeof(struct newesp);

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
                     fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm CAST5-CBC : Bad Keylen (%i Bits)\n",
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
               decrypted_len = len - sizeof(struct newesp);

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
                     fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm DES-CBC : Bad Keylen (%i Bits, need %lu)\n",
                                       esp_crypt_key_len * 8, (unsigned long) gcry_cipher_get_algo_keylen (crypt_algo_libgcrypt) * 8);
                     decrypt_ok = FALSE;
                  }
                  else
                     decrypt_using_libgcrypt = TRUE;
               }
               break;

		      case IPSEC_ENCRYPT_AES_CTR :
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

               decrypted_len = len - sizeof(struct newesp);

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
                        fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm AES-CTR : Bad Keylen (%i Bits)\n",
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

               decrypted_len = len - sizeof(struct newesp);

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
                     fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm TWOFISH-CBC : Bad Keylen (%i Bits)\n",
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

               decrypted_len = len - sizeof(struct newesp);

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
                     fprintf (stderr, "<ESP Preferences> Error in Encryption Algorithm BLOWFISH-CBC : Bad Keylen (%i Bits, need %lu)\n",
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
               decrypted_len = len - sizeof(struct newesp);

               if (decrypted_len <= 0)
                  decrypt_ok = FALSE;
               else
               {
                  /* Allocate Buffers for Encrypted and Decrypted data  */
                  decrypted_data = (guint8 *) g_malloc ((decrypted_len + 1)* sizeof(guint8));
                  tvb_memcpy(tvb, decrypted_data , sizeof(struct newesp), decrypted_len);

                  decrypt_ok = TRUE;
               }
               break;
		      }

            if(decrypt_using_libgcrypt)
            {
               /* Allocate Buffers for Encrypted and Decrypted data  */
               encrypted_data = (guint8 *) g_malloc0 ((decrypted_len_alloc) * sizeof(guint8));
               decrypted_data = (guint8 *) g_malloc ((decrypted_len_alloc + esp_iv_len)* sizeof(guint8));
               tvb_memcpy(tvb, encrypted_data , sizeof(struct newesp), decrypted_len);

               err = gcry_cipher_open (&cypher_hd, crypt_algo_libgcrypt, crypt_mode_libgcrypt, 0);
               if (err)
               {
                  fprintf(stderr, "<IPsec/ESP Dissector> Error in Algorithm %s Mode %d, grcy_open_cipher failed: %s\n",
                                 gcry_cipher_algo_name(crypt_algo_libgcrypt), crypt_mode_libgcrypt, gpg_strerror (err));
                  g_free(encrypted_data);
                  g_free(decrypted_data);
                  decrypt_ok = FALSE;
			      }
               else
               {
                  if (crypt_mode_libgcrypt == GCRY_CIPHER_MODE_CTR)
                  {
                     /* Counter mode key includes a 4 byte, (32 bit), nonce following the key */
                     err = gcry_cipher_setkey (cypher_hd, esp_crypt_key, esp_crypt_key_len - 4);
                  }
                  else
                  {
                     err = gcry_cipher_setkey (cypher_hd, esp_crypt_key, esp_crypt_key_len);
                  }

                  if (err)
                  {
                     fprintf(stderr, "<IPsec/ESP Dissector> Error in Algorithm %s Mode %d, gcry_cipher_setkey(key_len=%d) failed: %s\n",
                        gcry_cipher_algo_name(crypt_algo_libgcrypt), crypt_mode_libgcrypt, esp_crypt_key_len, gpg_strerror (err));
                     gcry_cipher_close (cypher_hd);
                     g_free(encrypted_data);
                     g_free(decrypted_data);
                     decrypt_ok = FALSE;
                  }
                  else
                  {
                     if (crypt_mode_libgcrypt == GCRY_CIPHER_MODE_CTR)
                     {
                        memset(ctr_block, 0, 16);
                        memcpy(ctr_block, esp_crypt_key + esp_crypt_key_len - 4, 4);
                        memcpy(ctr_block + 4, encrypted_data, 8);
                        ctr_block[15] = 1;
                        err = gcry_cipher_setctr (cypher_hd, ctr_block, 16);
                        if (!err)
                        {
                           memcpy(decrypted_data, encrypted_data, esp_iv_len);
                           err = gcry_cipher_decrypt (cypher_hd, decrypted_data + esp_iv_len, decrypted_len_alloc,
                                                     encrypted_data + esp_iv_len, decrypted_len_alloc - esp_iv_len);
                        }
                     }
                     else
                     {
                        err = gcry_cipher_decrypt (cypher_hd, decrypted_data, decrypted_len_alloc + esp_iv_len,
                                                 encrypted_data, decrypted_len_alloc);
                     }

                     if (err)
                     {
                        fprintf(stderr, "<IPsec/ESP Dissector> Error in Algorithm %s, Mode %d, gcry_cipher_decrypt failed: %s\n",
                                         gcry_cipher_algo_name(crypt_algo_libgcrypt), crypt_mode_libgcrypt, gpg_strerror (err));
                        gcry_cipher_close (cypher_hd);
                        g_free(encrypted_data);
                        g_free(decrypted_data);
                        decrypt_ok = FALSE;
                     }
                     else
                     {
                        gcry_cipher_close (cypher_hd);

                        /* Add the Authentication which was not encrypted */
                        if(decrypted_len >= esp_auth_len)
                        {
                           for(i = 0; i <  esp_auth_len; i++)
                           {
                              decrypted_data[i + decrypted_len -esp_auth_len]
                                                = encrypted_data[i + decrypted_len - esp_auth_len];
                           }
                        }

                        fprintf(stderr,"\n\n ");
                        g_free(encrypted_data);
                        decrypt_ok = TRUE;
                     }
                  }
               }
            }

            if(decrypt_ok && (decrypted_len > esp_iv_len))
            {
               tvb_decrypted = tvb_new_child_real_data(tvb, g_memdup(decrypted_data+sizeof(guint8)*esp_iv_len,
                                                                (decrypted_len - esp_iv_len)*sizeof(guint8)),
                                                                decrypted_len - esp_iv_len, decrypted_len - esp_iv_len);
               g_free(decrypted_data);

               add_new_data_source(pinfo, tvb_decrypted, "Decrypted Data");

               /* Handler to free the Decrypted Data Buffer. */
               tvb_set_free_cb(tvb_decrypted,g_free);

               if(tvb_bytes_exist(tvb, 8, esp_iv_len))
               {
                  if(esp_iv_len > 0)
                     proto_tree_add_item(esp_tree, hf_esp_iv, tvb, 8, esp_iv_len, ENC_NA);
               }
   		      else
                  proto_tree_add_text(esp_tree, tvb, 8, -1, "IV (truncated)");

               /* Make sure the packet is not truncated before the fields
                * we need to read to determine the encapsulated protocol */
               if(tvb_bytes_exist(tvb_decrypted, decrypted_len - esp_iv_len - esp_auth_len - 2, 2))
               {
                  esp_pad_len = tvb_get_guint8(tvb_decrypted, decrypted_len - esp_iv_len - esp_auth_len - 2);

                  if(decrypted_len - esp_iv_len - esp_auth_len - esp_pad_len - 2 >= 0)
                  {
                     /* Get the encapsulated protocol */
                     encapsulated_protocol = tvb_get_guint8(tvb_decrypted, decrypted_len - esp_iv_len - esp_auth_len - 1);

                     if(dissector_try_uint(ip_dissector_table,
                            encapsulated_protocol,
                            tvb_new_subset(tvb_decrypted, 0,
		                           decrypted_len - esp_auth_len - esp_pad_len - esp_iv_len - 2,
		                           decrypted_len - esp_auth_len - esp_pad_len - esp_iv_len - 2),
                            pinfo,
                            tree))
                     {
                        decrypt_dissect_ok = TRUE;
                     }
                  }
               }

               if(decrypt_dissect_ok)
               {
                  if(esp_tree)
                  {
                     if(esp_pad_len !=0)
                        proto_tree_add_text(esp_tree,
                                            tvb_decrypted,
                                            decrypted_len - esp_iv_len - esp_auth_len - 2 - esp_pad_len,
                                            esp_pad_len,
                                            "Pad");

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
                  call_dissector(data_handle,
                                 tvb_new_subset(tvb_decrypted, 0,
                                                   decrypted_len - esp_iv_len - esp_auth_len,
                                                   decrypted_len - esp_iv_len - esp_auth_len),
                                 pinfo, esp_tree);

                  if(esp_tree)
                     dissect_esp_authentication(esp_tree,
                                                tvb_decrypted,
                                                decrypted_len - esp_iv_len, esp_auth_len,
                                                authenticator_data_computed, authentication_ok,
                                                authentication_checking_ok );
               }
            }
         }
	      else
         {
            /* The packet does not belong to a security Association */
            null_encryption_decode_heuristic = g_esp_enable_null_encryption_decode_heuristic;
         }

	      g_free(ip_src);
	      g_free(ip_dst);
	      if(esp_auth_key_len != 0) 
            g_free(esp_auth_key);
	      if(esp_crypt_key_len != 0) 
            g_free(esp_crypt_key);
      }
     }
   }

   /*
    If the packet is present in the security association database and the field g_esp_enable_authentication_check set.
   */
   if(!g_esp_enable_encryption_decode && g_esp_enable_authentication_check && sad_is_present)
   {
      sad_is_present = FALSE;
      call_dissector(data_handle,
           tvb_new_subset(tvb, sizeof(struct newesp), len - sizeof(struct newesp) - esp_auth_len, -1),
           pinfo, esp_tree);

      if(esp_tree)
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
            if(dissector_try_uint(ip_dissector_table,
		             encapsulated_protocol,
		             tvb_new_subset(tvb,
				            sizeof(struct newesp),
				            -1,
				            len - sizeof(struct newesp) - 14 - esp_pad_len),
		             pinfo,
		             tree))
            {
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
               proto_tree_add_text(esp_tree, tvb, len - 12, 12, "Authentication Data");
            }
            else
            {
               /* Truncated so just display what we have */
               proto_tree_add_text(esp_tree, tvb, len - 12, 12 - (len - tvb_length(tvb)),
	                        "Authentication Data (truncated)");
            }
         }
      }
#ifdef HAVE_LIBGCRYPT
   }
#endif
}


static void
dissect_ipcomp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *ipcomp_tree;
  proto_item *ti;
  struct ipcomp ipcomp;
  const char *p;

  /*
   * load the top pane info. This should be overwritten by
   * the next protocol in the stack
   */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPComp");
  col_clear(pinfo->cinfo, COL_INFO);

  tvb_memcpy(tvb, (guint8 *)&ipcomp, 0, sizeof(ipcomp));

  if (check_col(pinfo->cinfo, COL_INFO)) {
    p = match_strval(g_ntohs(ipcomp.comp_cpi), cpi2val);
    if (p == NULL) {
      col_add_fstr(pinfo->cinfo, COL_INFO, "IPComp (CPI=0x%04x)",
		   g_ntohs(ipcomp.comp_cpi));
    } else
      col_add_fstr(pinfo->cinfo, COL_INFO, "IPComp (CPI=%s)", p);
  }

  /*
   * populate a tree in the second pane with the status of the link layer
   * (ie none)
   */
  if (tree) {
    tvbuff_t *data, *decomp;

    ti = proto_tree_add_item(tree, proto_ipcomp, tvb, 0, -1, FALSE);
    ipcomp_tree = proto_item_add_subtree(ti, ett_ipcomp);

    proto_tree_add_text(ipcomp_tree, tvb,
			offsetof(struct ipcomp, comp_nxt), 1,
			"Next Header: %s (0x%02x)",
			ipprotostr(ipcomp.comp_nxt), ipcomp.comp_nxt);
    proto_tree_add_uint(ipcomp_tree, hf_ipcomp_flags, tvb,
			offsetof(struct ipcomp, comp_flags), 1,
			ipcomp.comp_flags);
    proto_tree_add_uint(ipcomp_tree, hf_ipcomp_cpi, tvb,
			offsetof(struct ipcomp, comp_cpi), 2,
			g_ntohs(ipcomp.comp_cpi));

    data = tvb_new_subset(tvb, sizeof(struct ipcomp), -1, -1);
    call_dissector(data_handle, data, pinfo, ipcomp_tree);

    /*
     * try to uncompress as if it were DEFLATEd.  With negotiated
     * CPIs, we don't know the algorithm beforehand; if we get it
     * wrong, tvb_uncompress() returns NULL and nothing is displayed.
     */
    decomp = tvb_uncompress(data, 0, tvb_length(data));
    if (decomp) {
        add_new_data_source(pinfo, decomp, "IPcomp inflated data");
        if (!dissector_try_uint(ip_dissector_table, ipcomp.comp_nxt, decomp, pinfo, tree))
            call_dissector(data_handle, decomp, pinfo, tree);
    }
  }
}

void
proto_register_ipsec(void)
{
  static hf_register_info hf_ah[] = {
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
      { "ESP SPI", "esp.spi", FT_UINT32, BASE_HEX, NULL, 0x0,
        "IP Encapsulating Security Payload Security Parameters Index", HFILL }},
    { &hf_esp_sequence,
      { "ESP Sequence", "esp.sequence", FT_UINT32, BASE_DEC, NULL, 0x0,
        "IP Encapsulating Security Payload Sequence Number", HFILL }},
    { &hf_esp_pad_len,
      { "ESP Pad Length", "esp.pad_len", FT_UINT8, BASE_DEC, NULL, 0x0,
        "IP Encapsulating Security Payload Pad Length", HFILL }},
    { &hf_esp_protocol,
      { "ESP Next Header", "esp.protocol", FT_UINT8, BASE_HEX, NULL, 0x0,
        "IP Encapsulating Security Payload Next Header", HFILL }},
    { &hf_esp_iv,
      { "ESP IV", "esp.iv", FT_BYTES, BASE_NONE, NULL, 0x0,
        "IP Encapsulating Security Payload", HFILL }}
  };

  static hf_register_info hf_ipcomp[] = {
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
    &ett_ipcomp,
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
    { 0x00, NULL }
  };

  static const value_string esp_authentication_type_vals[] = {
    { IPSEC_AUTH_NULL, "NULL" },
    { IPSEC_AUTH_HMAC_SHA1_96, "HMAC-SHA-1-96 [RFC2404]" },
    { IPSEC_AUTH_HMAC_SHA256_96, "HMAC-SHA-256-96 [draft-ietf-ipsec-ciph-sha-256-00]" },
    { IPSEC_AUTH_HMAC_SHA256_128, "HMAC-SHA-256-128 [RFC4868]" },
    { IPSEC_AUTH_HMAC_MD5_96, "HMAC-MD5-96 [RFC2403]" },
    { IPSEC_AUTH_HMAC_RIPEMD160_96, "MAC-RIPEMD-160-96 [RFC2857]" },
/*    { IPSEC_AUTH_AES_XCBC_MAC_96, "AES-XCBC-MAC-96 [RFC3566]" }, */
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
      UAT_FLD_CSTRING(uat_esp_sa_records, encryption_key, "Encryption Key", "Encryption Key"),
      UAT_FLD_VS(uat_esp_sa_records, authentication_algo, "Authentication", esp_authentication_type_vals, "Authentication algorithm"), 
      UAT_FLD_CSTRING(uat_esp_sa_records, authentication_key, "Authentication Key", "Authentication Key"),
      UAT_END_FIELDS
    };
#endif

  module_t *ah_module;
  module_t *esp_module;

  proto_ah = proto_register_protocol("Authentication Header", "AH", "ah");
  proto_register_field_array(proto_ah, hf_ah, array_length(hf_ah));

  proto_esp = proto_register_protocol("Encapsulating Security Payload",
				      "ESP", "esp");
  proto_register_field_array(proto_esp, hf_esp, array_length(hf_esp));

  proto_ipcomp = proto_register_protocol("IP Payload Compression",
					 "IPComp", "ipcomp");
  proto_register_field_array(proto_ipcomp, hf_ipcomp, array_length(hf_ipcomp));

  proto_register_subtree_array(ett, array_length(ett));

  /* Register a configuration option for placement of AH payload dissection */
  ah_module = prefs_register_protocol(proto_ah, NULL);
  prefs_register_bool_preference(ah_module, "place_ah_payload_in_subtree",
				 "Place AH payload in subtree",
				 "Whether the AH payload decode should be placed in a subtree",
				 &g_ah_payload_in_subtree);
  esp_module = prefs_register_protocol(proto_esp, NULL);

  prefs_register_bool_preference(esp_module, "enable_null_encryption_decode_heuristic",
				 "Attempt to detect/decode NULL encrypted ESP payloads",
				 "This is done only if the Decoding is not SET or the packet does not belong to a SA. "
                                 "Assumes a 12 byte auth (HMAC-SHA1-96/HMAC-MD5-96/AES-XCBC-MAC-96) "
                                 "and attempts decode based on the ethertype 13 bytes from packet end",
				 &g_esp_enable_null_encryption_decode_heuristic);


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
            sizeof(uat_esp_sa_record_t),  /* record size */
            "esp_sa",               /* filename */
            TRUE,                       /* from_profile */
            (void*) &uat_esp_sa_records,  /* data_ptr */
            &num_sa_uat,           /* numitems_ptr */
            UAT_CAT_CRYPTO,             /* category */
            NULL,                       /* help */
            uat_esp_sa_record_copy_cb,        /* copy callback */
            uat_esp_sa_record_update_cb,      /* update callback */
            uat_esp_sa_record_free_cb,        /* free callback */
            NULL,                       /* post update callback */
            esp_uat_flds);             /* UAT field definitions */

    prefs_register_uat_preference(esp_module, 
                                   "sa_table",
                                   "ESP SAs",
                                   "Preconfigured ESP Security Associations",
                                   esp_uat);


#endif

  register_dissector("esp", dissect_esp, proto_esp);
  register_dissector("ah", dissect_ah, proto_ah);

}

void
proto_reg_handoff_ipsec(void)
{
  dissector_handle_t esp_handle, ah_handle, ipcomp_handle;

  data_handle = find_dissector("data");
  ah_handle = find_dissector("ah");
  dissector_add_uint("ip.proto", IP_PROTO_AH, ah_handle);
  esp_handle = find_dissector("esp");
  dissector_add_uint("ip.proto", IP_PROTO_ESP, esp_handle);
  ipcomp_handle = create_dissector_handle(dissect_ipcomp, proto_ipcomp);
  dissector_add_uint("ip.proto", IP_PROTO_IPCOMP, ipcomp_handle);

  ip_dissector_table = find_dissector_table("ip.proto");
}



