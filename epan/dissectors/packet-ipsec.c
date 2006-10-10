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

- Check ESP Authentication for the following Algorithms defined in RFC 4305:

Authentication Algorithm
------------------------
NULL
HMAC-SHA1-96 [RFC2404] : any keylen
HMAC-MD5-96 [RFC2403] : any keylen
AES-XCBC-MAC-96 [RFC3566] : Not available because no implementation found.

- Add ESP Authentication checking for the following Authentication Algorithm :
HMAC-SHA256 : any keylen

*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

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

#ifdef _WIN32
#include <winposixtype.h>
#endif /* _WIN32 */

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

/* Authentication algorithms defined in RFC 4305 */
#define IPSEC_AUTH_NULL 0
#define IPSEC_AUTH_HMAC_SHA1_96 1
#define IPSEC_AUTH_HMAC_SHA256 2
#define IPSEC_AUTH_HMAC_MD5_96 3
#define IPSEC_AUTH_ANY_12BYTES 5
/* define IPSEC_AUTH_AES_XCBC_MAC_96 6 */
#endif

/* well-known algorithm number (in CPI), from RFC2409 */
#define IPCOMP_OUI	1	/* vendor specific */
#define IPCOMP_DEFLATE	2	/* RFC2394 */
#define IPCOMP_LZS	3	/* RFC2395 */
#define IPCOMP_MAX	4

#ifdef HAVE_LIBGCRYPT
#define IPSEC_IPV6_ADDR_LEN 128
#define IPSEC_IPV4_ADDR_LEN 32
#define IPSEC_STRLEN_IPV6 32
#define IPSEC_STRLEN_IPV4 8
#define IPSEC_SA_IPV4 1
#define IPSEC_SA_IPV6 2
#define IPSEC_SA_UNKNOWN -1
#define IPSEC_SA_WILDCARDS_ANY '*'
#define IPSEC_SA_SEPARATOR '|'
#define IPSEC_SA_ADDR_LEN_SEPARATOR '/'
#define IPSEC_IPV6_ADDR_MAX 40
#define IPSEC_IPV4_ADDR_MAX 16
#define IPSEC_SPI_LEN_MAX 10
#define IPSEC_TYP_LEN 4
#define IPSEC_ADDR_LEN_MAX 3

/* Number of Security Associations */
#define IPSEC_NB_SA 16
#endif

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
/* SA Paramaters and SAD */
static guint g_esp_nb_sa = IPSEC_NB_SA;
static guint g_max_esp_nb_sa = 100;

typedef struct  {
  const gchar *sa;
  gint typ;
  gchar *src;
  gint src_len;
  gchar *dst;
  gint dst_len;
  gchar *spi;
  gint encryption_algo;
  gint authentication_algo;
  const gchar *encryption_key;
  const gchar *authentication_key;
  gboolean is_valid;
} g_esp_sa;

typedef struct  {
  gint nb;
  g_esp_sa table[IPSEC_NB_SA];
} g_esp_sa_database;

static g_esp_sa_database g_esp_sad;


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




/*
   Name : static int get_ipv6_suffix(char* ipv6_suffix, char *ipv6_address)
   Description : Get the extended IPv6 Suffix of an IPv6 Address
   Return : Return the number of char of the IPv6 address suffix parsed
   Params:
      - char *ipv6_address : the valid ipv6 address to parse in char *
      - char *ipv6_suffix : the ipv6 suffix associated in char *

      ex: if IPv6 address is "3ffe::1" the IPv6 suffix will be "0001" and the function will return 3
*/
#ifdef HAVE_LIBGCRYPT
static int get_ipv6_suffix(char* ipv6_suffix, char *ipv6_address)
{
  char suffix[IPSEC_STRLEN_IPV6 + 1];
  int cpt = 0;
  int cpt_suffix = 0;
  int cpt_seg = 0;
  int j =0;
  int ipv6_len = 0;
  gboolean found = FALSE;

  ipv6_len = strlen(ipv6_address);
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
#endif



/*
   Name : static int get_full_ipv6_addr(char* ipv6_addr_expanded, char *ipv6_addr)
   Description : Get the extended IPv6 Address of an IPv6 Address
   Return : Return the remaining number of char of the IPv6 address parsed
   Params:
      - char *ipv6_addr : the valid ipv6 address to parse in char *
      - char *ipv6_addr_expansed : the expanded ipv6 address associated in char *

      ex: if IPv6 address is "3ffe::1" the IPv6 expanded address will be "3FFE0000000000000000000000000001" and the function will return 0
          if IPV6 address is "3ffe::*" the IPv6 expanded address will be "3FFE000000000000000000000000****" and the function will return 0
*/
#ifdef HAVE_LIBGCRYPT
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
  suffix_len = strlen(suffix);

  if(suffix_len <  IPSEC_STRLEN_IPV6)
    {
      prefix_addr = ep_alloc(strlen(ipv6_addr) - suffix_cpt + 1);
      memcpy(prefix_addr,ipv6_addr,strlen(ipv6_addr) - suffix_cpt);
      prefix_addr[strlen(ipv6_addr) - suffix_cpt] = '\0';
      prefix_remaining = get_ipv6_suffix(prefix,prefix_addr);
      prefix_len = strlen(prefix);
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
    return strlen(ipv6_addr) - suffix_cpt;
}
#endif



/*
   Name : static gboolean get_full_ipv4_addr(char* ipv4_addr_expanded, char *ipv4_addr)
   Description : Get the extended IPv4 Address of an IPv4 Address
   Return : Return true if it can derive an IPv4 address. It does not mean that the previous one was valid.
   Params:
      - char *ipv4_addr : the valid ipv4 address to parse in char *
      - char *ipv4_addr_expansed : the expanded ipv4 address associated in char *

      ex: if IPv4 address is "190.*.*.1" the IPv4 expanded address will be "BE****01" and the function will return 0
          if IPv4 address is "*" the IPv4 expanded address will be "********" and the function will return 0
*/
#ifdef HAVE_LIBGCRYPT
static gboolean
get_full_ipv4_addr(char* ipv4_addr_expanded, char *ipv4_addr)
{
  char addr_byte_string_tmp[4];
  char addr_byte_string[4];

  guint addr_byte = 0;
  guint i = 0;
  guint j = 0;
  guint k = 0;
  guint cpt = 0;
  gboolean done_flag = FALSE;

  if((ipv4_addr == NULL) || (strcmp(ipv4_addr, "") == 0))  return done_flag;

  if((strlen(ipv4_addr) == 1) && (ipv4_addr[0] == IPSEC_SA_WILDCARDS_ANY))
    {
      for(i = 0; i <= IPSEC_STRLEN_IPV4; i++)
	{
	  ipv4_addr_expanded[i] = IPSEC_SA_WILDCARDS_ANY;
	}
      ipv4_addr_expanded[IPSEC_STRLEN_IPV4] = '\0';
      done_flag = TRUE;
    }

  else {
    j = 0;
    cpt = 0;
    k = 0;
    while((done_flag == FALSE) && (j <= strlen(ipv4_addr)) && (cpt < IPSEC_STRLEN_IPV4))
      {
	if(j == strlen(ipv4_addr))
	  {
	    addr_byte_string_tmp[k] = '\0';
	    if((strlen(addr_byte_string_tmp) == 1) && (addr_byte_string_tmp[0] == IPSEC_SA_WILDCARDS_ANY))
	      {
		for(i = 0; i < 2; i++)
		  {
		    ipv4_addr_expanded[cpt] = IPSEC_SA_WILDCARDS_ANY;
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
		    ipv4_addr_expanded[cpt] = addr_byte_string[i];
		    cpt ++;
		  }
	      }
	    done_flag = TRUE;
	  }

	else if(ipv4_addr[j] == '.')
	  {
	    addr_byte_string_tmp[k] = '\0';
	    if((strlen(addr_byte_string_tmp) == 1) && (addr_byte_string_tmp[0] == IPSEC_SA_WILDCARDS_ANY))
	      {
		for(i = 0; i < 2; i++)
		  {
		    ipv4_addr_expanded[cpt] = IPSEC_SA_WILDCARDS_ANY;
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
		    ipv4_addr_expanded[cpt] = addr_byte_string[i];
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
		addr_byte_string_tmp[0] = ipv4_addr[j];
		k = 1;
		j++;
	      }
	    else
	      {
		addr_byte_string_tmp[k] = ipv4_addr[j];
		k++;
		j++;
	      }
	  }

      }

    ipv4_addr_expanded[cpt] = '\0';
  }

  return done_flag;
}
#endif



/*
   Name : static gboolean esp_sa_parse_ipv6addr(const gchar *sa, guint index_start, gchar **pt_ipv6addr, guint *index_end)
   Description : Get the IPv6 address of a Security Association
   Return : Return true if it can get an address. It does not mean that the address is valid.
   Params:
      - char *sa : the Security Association in char *
      - guint index_start : the index to start to find the address
      - gchar **pt_ipv6addr : the address found. The Allocation is done here !
      - guint *index_end : the last index of the address
*/
#ifdef HAVE_LIBGCRYPT
static gboolean
esp_sa_parse_ipv6addr(const gchar *sa, guint index_start, gchar **pt_ipv6addr, guint *index_end)
{
  guint cpt = 0;

  char addr_string[IPSEC_IPV6_ADDR_MAX + 1];
  gboolean done_flag = FALSE;

  if((sa == NULL) || (strcmp(sa, "") == 0))  
    return FALSE;

  /* Get Address */
  while(((cpt + index_start) < strlen(sa)) && (done_flag == FALSE) && (cpt <= IPSEC_IPV6_ADDR_MAX))
    {
      if((sa[cpt + index_start] == IPSEC_SA_SEPARATOR)  || (sa[cpt + index_start] == IPSEC_SA_ADDR_LEN_SEPARATOR))
	{
	  if(cpt == 0) return FALSE;
	  *index_end = cpt + index_start;
	  addr_string[cpt] = '\0';
	  done_flag = TRUE;
	}

      else
	{
	  if((cpt >= IPSEC_IPV6_ADDR_MAX - 1) && ((cpt  + index_start) < strlen(sa)) && (sa[cpt + index_start + 1] != IPSEC_SA_ADDR_LEN_SEPARATOR) && (sa[cpt + index_start + 1] != IPSEC_SA_SEPARATOR)) 
	    return FALSE;
	  addr_string[cpt] = toupper(sa[cpt + index_start]);
	  cpt ++;
	}
    }

  if(done_flag)
    {
      *pt_ipv6addr = (gchar *)g_malloc((strlen(addr_string) + 1) * sizeof(gchar));
      memcpy(*pt_ipv6addr,addr_string,strlen(addr_string) + 1);
    }

  return done_flag;
}
#endif


/*
   Name : static gboolean esp_sa_parse_ipv4addr(const gchar *sa, guint index_start, gchar **pt_ipv4addr, guint *index_end)
   Description : Get the IPv4 address of a Security Association
   Return : Return true if it can get an address. It does not mean that the address is valid.
   Params:
      - char *sa : the Security Association in char *
      - guint index_start : the index to start to find the address
      - gchar **pt_ipv4addr : the address found. The Allocation is done here !
      - guint *index_end : the last index of the address
*/
#ifdef HAVE_LIBGCRYPT
static gboolean
esp_sa_parse_ipv4addr(const gchar *sa, guint index_start, gchar **pt_ipv4addr, guint *index_end)
{
  guint cpt = 0;

  char addr_string[IPSEC_IPV4_ADDR_MAX + 1];
  gboolean done_flag = FALSE;

  if((sa == NULL) || (strcmp(sa, "") == 0))
    return FALSE;

  /* Get Address */
  while(((cpt + index_start) < strlen(sa)) && (done_flag == FALSE) && (cpt <= IPSEC_IPV4_ADDR_MAX))
    {
      if((sa[cpt + index_start] == IPSEC_SA_SEPARATOR)  || (sa[cpt + index_start] == IPSEC_SA_ADDR_LEN_SEPARATOR))
	{
	  if(cpt == 0) return FALSE;
	  *index_end = cpt + index_start;
	  addr_string[cpt] = '\0';
	  done_flag = TRUE;
	}

      else
	{
	  if((cpt == IPSEC_IPV4_ADDR_MAX - 1) && ((cpt  + index_start) < strlen(sa)) && (sa[cpt + index_start + 1] != IPSEC_SA_ADDR_LEN_SEPARATOR) && (sa[cpt + index_start + 1] != IPSEC_SA_SEPARATOR)) 
	    return FALSE;
	  addr_string[cpt] = toupper(sa[cpt + index_start]);
	  cpt ++;
	}
    }

  if(done_flag)
    {
      *pt_ipv4addr = (gchar *)g_malloc((strlen(addr_string) + 1) * sizeof(gchar));
      memcpy(*pt_ipv4addr,addr_string,strlen(addr_string) + 1);
    }

  return done_flag;
}
#endif


/*
   Name : static gboolean esp_sa_parse_spi(const gchar *sa, guint index_start, gchar **pt_spi, guint *index_end)
   Description : Get the SPI of a Security Association
   Return : Return true if it can get a SPI. It does not mean that the SPI is valid.
   Params:
      - char *sa : the Security Association in char *
      - guint index_start : the index to start to find the spi
      - gchar **pt_spi : the spi found. The Allocation is done here !
      - guint *index_end : the last index of the address
*/
#ifdef HAVE_LIBGCRYPT
static gboolean
esp_sa_parse_spi(const gchar *sa, guint index_start, gchar **pt_spi, guint *index_end)
{
  guint cpt = 0;
  guint32 spi = 0;
  guint i = 0;

  gchar spi_string[IPSEC_SPI_LEN_MAX + 1];
  gchar spi_string_tmp[IPSEC_SPI_LEN_MAX + 1];
  gboolean done_flag = FALSE;

  if((sa == NULL) || (strcmp(sa, "") == 0))  return FALSE;

  while(((cpt + index_start) < strlen(sa)) && (cpt < IPSEC_SPI_LEN_MAX))
    {
      spi_string[cpt] = toupper(sa[cpt + index_start]);
      cpt ++;
    }

  if(cpt == 0)
    done_flag = FALSE;
  else
    {
      spi_string[cpt] = '\0';
      if((cpt >= 2) &&
	 (spi_string[0] == '0') &&
	 (spi_string[1] == 'X'))
	{
	  for(i = 0; i <= cpt - 2; i++) spi_string_tmp[i] = spi_string[i+2];
	  sscanf(spi_string_tmp,"%x",&spi);
	  g_snprintf(spi_string, IPSEC_SPI_LEN_MAX, "%i", spi);
	}

      *index_end = cpt + index_start - 1;
      *pt_spi = (gchar *)g_malloc((strlen(spi_string) + 1) * sizeof(gchar));
      memcpy(*pt_spi, spi_string, strlen(spi_string) + 1);

      done_flag = TRUE;
    }

  return done_flag;
}
#endif


/*
   Name : static gboolean esp_sa_parse_protocol_typ(const gchar *sa, guint index_start, gint *pt_protocol_typ, guint *index_end)
   Description : Get the Protocol Type of a Security Association
   Return : Return true if it can get a valid protocol type.
   Params:
      - char *sa : the Security Association in char *
      - guint index_start : the index to start to find the protocol type
      - gint *pt_protocol_typ : the protocl type found. Either IPv4, Either IPv6 (IPSEC_SA_IPV4, IPSEC_SA_IPV6)
      - guint *index_end : the last index of the protocol type
*/
#ifdef HAVE_LIBGCRYPT
static gboolean
esp_sa_parse_protocol_typ(const gchar *sa, guint index_start, gint *pt_protocol_typ, guint *index_end)
{
  gboolean done_flag = FALSE;

  *pt_protocol_typ = IPSEC_SA_UNKNOWN;
  if((sa == NULL) || (strlen(&sa[index_start]) <= IPSEC_TYP_LEN) ||
      (sa[index_start + IPSEC_TYP_LEN] != IPSEC_SA_SEPARATOR))
    return FALSE;

  if(g_strncasecmp(&sa[index_start], "IPV6", IPSEC_TYP_LEN) == 0)
    {
      *pt_protocol_typ = IPSEC_SA_IPV6;
      done_flag = TRUE;
    }
  else if (g_strncasecmp(&sa[index_start], "IPV4", IPSEC_TYP_LEN) == 0)
    {
      *pt_protocol_typ = IPSEC_SA_IPV4;
      done_flag = TRUE;
    }
  else
    {
      *pt_protocol_typ = IPSEC_SA_UNKNOWN;
      done_flag = FALSE;
    }

  *index_end = IPSEC_TYP_LEN + index_start + 1;

g_warning("For %s returning %d, %c, %d", sa, *pt_protocol_typ, sa[*index_end], *index_end);
  return done_flag;
}
#endif


/*
   Name : static gboolean esp_sa_parse_addr_len(const gchar *sa, guint index_start, guint *len, guint *index_end)
   Description : Get the Address Length of an address (IPv4/IPv6)
   Return : Return true if it can get an Address Length. It does not mean that the length is valid
   Params:
      - char *sa : the Security Association in char *
      - guint index_start : the index to start to find the length
      - guint *len : the address length found. If none -1 is given.
      - guint *index_end : the last index of the address length in the SA
*/
#ifdef HAVE_LIBGCRYPT
static gboolean
esp_sa_parse_addr_len(const gchar *sa, guint index_start, gint *len, guint *index_end)
{
  guint cpt = 0;
  char len_string[IPSEC_ADDR_LEN_MAX + 1];
  gboolean done_flag = FALSE;

  *len = -1;

  if((sa == NULL) || (strcmp(sa, "") == 0))  return FALSE;

  if(sa[index_start] == IPSEC_SA_SEPARATOR)
    {
      *index_end = index_start + 1;
      *len = -1;
      done_flag = TRUE;
    }

  else if(sa[index_start] == IPSEC_SA_ADDR_LEN_SEPARATOR)
    {
      cpt ++;
      while(((cpt + index_start) < strlen(sa)) && (done_flag == FALSE) && (cpt < IPSEC_ADDR_LEN_MAX))
	{
	  if(sa[cpt + index_start] == IPSEC_SA_SEPARATOR)
	    {
	      if(cpt == 1)
		{
		  *index_end = index_start + cpt + 1;
		  *len = -1;
		  done_flag = TRUE;

		}
	      else
		{
		  *index_end = cpt + index_start + 1;
		  len_string[cpt - 1] = '\0';
		  *len = atoi(len_string);
		  done_flag = TRUE;
		}
	    }

	  else
	    {
	      if((cpt == IPSEC_ADDR_LEN_MAX) && ((cpt  + index_start) < strlen(sa)) && (sa[cpt + index_start + 1] != IPSEC_SA_ADDR_LEN_SEPARATOR) && (sa[cpt + index_start + 1] != IPSEC_SA_SEPARATOR)) 
		return FALSE;
	      len_string[cpt -1] = sa[cpt + index_start];
	      cpt ++;
	    }
	}
    }

  return done_flag;
}
#endif


/*
   Name : esp_sa_remove_white(const gchar *sa, gchar **sa_bis)
   Description : Remote White Space in a SA
                 Parse a Security Association and give the SA without space.
		 There is no need to allocate memory before the call. All is done !

   Return : Void
   Params:
      - char *sa : the Security Association in char *
      - char **sa_bis : the Security Association in char * without white space
*/

#ifdef HAVE_LIBGCRYPT
static void
esp_sa_remove_white(const gchar *sa, gchar **sa_bis)
{
  guint i = 0;
  guint cpt = 0;
  gchar *sa_tmp;

  if((sa == NULL) || (strcmp(sa, "") == 0))
    {
      *sa_bis = NULL;
      return;
    }

  sa_tmp = ep_alloc(strlen(sa) + 1);
  for(i = 0; i < strlen(sa); i++)
    {

      if((sa[i] != ' ') && (sa[i] != '\t'))
	{
	  sa_tmp[cpt] = sa[i];
	  cpt ++;
	}
    }
  sa_tmp[cpt] = '\0';

  /* XXX - Should this be se_allocated instead? */
  *sa_bis = (gchar *)g_malloc((cpt +1) * sizeof(gchar));
  memcpy(*sa_bis,sa_tmp,cpt);
  (*sa_bis)[cpt] = '\0';
}
#endif



/*
   Name : static goolean esp_sa_parse_filter(const gchar *sa, gint *pt_protocol_typ, gchar **pt_src, gint *pt_src_len,  gchar **pt_dst, gint *pt_dst_len,  gchar **pt_spi)
   Description : Parse a Security Association.
                 Parse a Security Association and give the correspondings parameter : SPI, Source, Destination, Source Length, Destination Length, Protocol Type
		 There is no need to allocate memory before the call. All is done !
		 If the SA is not correct FALSE is returned.
		 This security association Must have the following format :

		 "Type/Source IPv6 or IPv4/Destination IPv6 or IPv4/SPI"

		 Where Type is either IPv4 either IPv6
		 - source And destination Must have a correct IPv6/IPv4 Address Format.
		 - SPI is an integer on 4 bytes.
		 Any element may use the following wildcard :

		 "*" : for an IPv4 Address, it allows all bytes until the next ".". For IPv6 it is the same until the next ":".
		 For SPI it allows any SPI.

		 ex:
		 a) IPV4/131.254.200.* /131.254.*.123/ *
		 b) IPv6/3ffe:*:1/2001::200:* / 456

   Return : Return true if the parsing is correct.
   Params:
      - char *sa : the Security Association in char *
      - gint *pt_protocol_typ : the protocol type
      - gchar **pt_src : the source address
      - gint *pt_src_len : the source address length
      - gchar **pt_dst : the destination address
      - gint *pt_dst_len : the destination address length
      - gchar **pt_spi : the spi of the SA
*/
#ifdef HAVE_LIBGCRYPT
static gboolean
esp_sa_parse_filter(const gchar *sa_src, gint *pt_protocol_typ, gchar **pt_src, gint *pt_src_len,  gchar **pt_dst, gint *pt_dst_len,  gchar **pt_spi)
{
  gchar *src_string;
  gchar *dst_string;
  gchar *spi_string;
  gint src_len = 0;
  gint dst_len = 0;
  gchar *src;
  gchar *dst;
  gchar *sa;

  guint index_end1 = 0;
  guint index_end2 = 0;

  esp_sa_remove_white(sa_src,&sa);
  if(!esp_sa_parse_protocol_typ(sa, 0, pt_protocol_typ, &index_end1)) return FALSE;

  switch(*pt_protocol_typ)
    {

    case IPSEC_SA_IPV4 :
      {
	if(esp_sa_parse_ipv4addr(sa, index_end1, &src_string, &index_end2))
	  {
	    if(esp_sa_parse_addr_len(sa, index_end2, pt_src_len, &index_end1))
	      {
		if(esp_sa_parse_ipv4addr(sa, index_end1, &dst_string, &index_end2))
		  {
		    if(esp_sa_parse_addr_len(sa, index_end2, pt_dst_len, &index_end1))
		      {
			if(!esp_sa_parse_spi(sa, index_end1, &spi_string, &index_end2))
			  {
			    g_free(src_string);
			    g_free(dst_string);
			    g_free(spi_string);
			    g_free(sa);
			    return FALSE;
			  }
		      }
		    else
		      {
			g_free(src_string);
			g_free(dst_string);
			g_free(sa);
			return FALSE;
		      }
		  }
		else
		  {
		    g_free(src_string);
		    g_free(sa);
		    return FALSE;
		  }
	      }
	    else
	      {
		g_free(src_string);
		g_free(sa);
		return FALSE;
	      }
	  }
	else
	  {
	    g_free(sa);
	    return FALSE;
	  }


	/* Fill the Source Filter */
	src = (gchar *)g_malloc((IPSEC_STRLEN_IPV4 + 1) * sizeof(gchar));
	get_full_ipv4_addr(src, src_string);
	g_free(src_string);

	/* Fill the Destination Filter */
	dst = (gchar *)g_malloc((IPSEC_STRLEN_IPV4 + 1) * sizeof(gchar));
	get_full_ipv4_addr(dst, dst_string);
	g_free(dst_string);

	g_free(sa);
	break;
      }

    case IPSEC_SA_IPV6 :
      {
	if(esp_sa_parse_ipv6addr(sa, index_end1, &src_string, &index_end2))
	  {
	    if(esp_sa_parse_addr_len(sa, index_end2, &src_len, &index_end1))
	      {
		if(esp_sa_parse_ipv6addr(sa, index_end1, &dst_string, &index_end2))
		  {
		    if(esp_sa_parse_addr_len(sa, index_end2, &dst_len, &index_end1))
		      {
			if(!esp_sa_parse_spi(sa, index_end1, &spi_string, &index_end2))
			  {
			    g_free(src_string);
			    g_free(dst_string);
			    g_free(spi_string);
			    g_free(sa);
			    return FALSE;
			  }
		      }
		    else
		      {
			g_free(src_string);
			g_free(dst_string);
			g_free(sa);
			return FALSE;
		      }
		  }
		else
		  {
		    g_free(src_string);
		    g_free(sa);
		    return FALSE;
		  }
	      }
	    else
	      {
		g_free(src_string);
		g_free(sa);
		return FALSE;
	      }
	  }
	else
	  {
	    g_free(sa);
	    return FALSE;
	  }

	/* Fill the Source Filter */
	src = (gchar *)g_malloc((IPSEC_STRLEN_IPV6 + 1) * sizeof(gchar));
	get_full_ipv6_addr(src, src_string);
	g_free(src_string);

	/* Fill the Destination Filter */
	dst = (gchar *)g_malloc((IPSEC_STRLEN_IPV6 + 1) * sizeof(gchar));
	get_full_ipv6_addr(dst, dst_string);
	g_free(dst_string);

	g_free(sa);
	break;
      }

    default:
      {
	g_free(sa);
	return FALSE;
      }
    }

  *pt_spi = spi_string;
  *pt_src = src;
  *pt_dst = dst;

  return TRUE;
}
#endif


/*
   Name : static goolean filter_address_match(gchar *address, gchar *filter, gint len, gint typ)
   Description : check the matching of an address with a filter
   Return : Return TRUE if the filter and the address match
   Params:
      - gchar *address : the address to check
      - gchar *filter : the filter
      - gint len : the len of the address that should match the filter
      - gint typ : the Address type : either IPv6 or IPv4 (IPSEC_SA_IPV6, IPSEC_SA_IPV4)
*/
#ifdef HAVE_LIBGCRYPT
static gboolean
filter_address_match(gchar *address, gchar *filter, gint len, gint typ)
{
  gint i = 0;
  guint filter_tmp = 0;
  guint addr_tmp = 0;
  char filter_string_tmp[3];
  char addr_string_tmp[3];

  if(strlen(address) != strlen(filter)) return FALSE;
  /* No length specified */
  if((len < 0) || ((typ == IPSEC_SA_IPV6) && (len > IPSEC_IPV6_ADDR_LEN)) || ((typ == IPSEC_SA_IPV4) && (len > IPSEC_IPV4_ADDR_LEN)))
    {
      for(i = 0; (guint)i < strlen(address); i++)
	{
	  if((filter[i] != IPSEC_SA_WILDCARDS_ANY) && (filter[i] != address[i])) return FALSE;
	}
      return TRUE;
    }
  else
    {
      for(i = 0; i < (len/ 4); i++)
	{
	  if((filter[i] != IPSEC_SA_WILDCARDS_ANY) && (filter[i] != address[i])) return FALSE;
	}

      if(filter[i] == IPSEC_SA_WILDCARDS_ANY) return TRUE;
      else if (len  % 4 != 0)
	{
	  /* take the end of the Netmask/Prefixlen into account */
	  filter_string_tmp[0] = filter[i];
	  filter_string_tmp[1] = '\0';
	  addr_string_tmp[0] = address[i];
	  addr_string_tmp[1] = '\0';

	  sscanf(filter_string_tmp,"%x",&filter_tmp);
	  sscanf(addr_string_tmp,"%x",&addr_tmp);
	  for(i = 0; i < (len % 4); i++)
	    {
	      if(((filter_tmp >> (4 -i -1)) & 1) != ((addr_tmp >> (4 -i -1)) & 1))
		{
		  return FALSE;
		}
	    }
	}
    }

  return TRUE;

}
#endif



/*
   Name : static goolean filter_spi_match(gchar *spi, gchar *filter)
   Description : check the matching of a spi with a filter
   Return : Return TRUE if the filter match the spi.
   Params:
      - gchar *spi : the spi to check
      - gchar *filter : the filter
*/
#ifdef HAVE_LIBGCRYPT
static gboolean
filter_spi_match(gchar *spi, gchar *filter)
{
  guint i = 0;

  if((strlen(filter) == 1) && (filter[0] == IPSEC_SA_WILDCARDS_ANY)) {
    return TRUE;
  }

  else if(strlen(spi) != strlen(filter)) {
    return FALSE;
  }

  for(i = 0; i < strlen(filter); i++)
    {
      if((filter[i] != IPSEC_SA_WILDCARDS_ANY) && (filter[i] != spi[i])) return FALSE;
    }

  return TRUE;
}
#endif


/*
   Name : static gint compute_ascii_key(gchar **ascii_key, gchar *key)
   Description : Allocate memory for the key and transform the key if it is hexadecimal
   Return : Return the key length 
   Params:
      - gchar **ascii_key : the resulting ascii key allocated here
      - gchar *key : the key to compute
*/
#ifdef HAVE_LIBGCRYPT
static gint
compute_ascii_key(gchar **ascii_key, gchar *key)
{
  guint key_len = 0;
  gchar key_char[5];
  guint i = 0;

  if(key != NULL)
    {
      if((strlen(key) > 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
	{
	  if(strlen(key) %2  == 0)
	    {
	      key_len = (strlen(key) - 2) / 2;
	      *ascii_key = (gchar *) g_malloc ((key_len + 1)* sizeof(gchar));		       
	      for(i = 2; i < (strlen(key) -1) ; i+=2)
		{
		  key_char[0] = key[i];
		  key_char[1] = key[i+1];
		  key_char[2] = '\0';
		  sprintf(*ascii_key + (i - 2)/2, "%c", (int)strtoul(key_char,(char **)NULL,16));			  			  
		}	  
	    }

	  else
	    /* give a chance to omit the first 0, in order to have a key in 8-bit unit  */ 
	    {
	      key_len = (strlen(key) - 2) / 2 + 1;
	      *ascii_key = (gchar *) g_malloc ((key_len + 1)* sizeof(gchar));		       
	      key_char[0] = '0';
	      key_char[1] = key[2];
	      key_char[2] = '\0';
	      sprintf(*ascii_key, "%c", (int)strtoul(key_char,(char **)NULL,16));			  			  
	      for(i = 3; i < (strlen(key) -1) ; i+=2)
		{
		  key_char[0] = key[i];
		  key_char[1] = key[i+1];
		  key_char[2] = '\0';
		  sprintf(*ascii_key + 1 + (i - 2)/2, "%c", (int)strtoul(key_char,(char **)NULL,16));			  			  
		}	  
	    }	    
	}
      
      else if((strlen(key) == 2) && (key[0] == '0') && ((key[1] == 'x') || (key[1] == 'X')))
	{
	  return 0;
	}
      
      else
	{
	  key_len = strlen(key);
	  *ascii_key = (gchar *) g_malloc ((key_len + 1)* sizeof(gchar));		       
	  memcpy(*ascii_key, key, key_len + 1);
	}
    }

  return key_len;
}
#endif


/*
   Name : static goolean get_esp_sa(g_esp_sa_database *sad, gint protocol_typ, gchar *src,  gchar *dst,  gint spi,
           gint *entry_index
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
      - gint *entry_index : the index of the SA that matches
      - gint *encryption_algo : the Encryption Algorithm to apply the packet
      - gint *authentication_algo : the Authentication Algorithm to apply to the packet
      - gchar **encryption_key : the Encryption Key to apply to the packet
      - guint *encryption_key_len : the Encryption Key length to apply to the packet 
      - gchar **authentication_key : the Authentication Key to apply to the packet
      - guint *authentication_key_len : the Authentication Key len to apply to the packet

*/
#ifdef HAVE_LIBGCRYPT
static gboolean
get_esp_sa(g_esp_sa_database *sad, gint protocol_typ, gchar *src,  gchar *dst,  gint spi, gint *entry_index,
	   gint *encryption_algo,
	   gint *authentication_algo,
	   gchar **encryption_key,
	   guint *encryption_key_len, 
	   gchar **authentication_key,
	   guint *authentication_key_len
	   )

{
  gboolean found = FALSE;
  gint i = 0;
  gchar spi_string[IPSEC_SPI_LEN_MAX];
  *entry_index = -1;

  g_snprintf(spi_string, IPSEC_SPI_LEN_MAX,"%i", spi);

  while((found == FALSE) && (i < sad -> nb))
    {
      if(esp_sa_parse_filter(sad -> table[i].sa, &sad -> table[i].typ, &sad -> table[i].src, &sad -> table[i].src_len,
			     &sad -> table[i].dst, &sad -> table[i].dst_len, &sad -> table[i].spi))
	{
	  g_esp_sad.table[i].is_valid = TRUE;

	  /* Debugging Purpose */
	  /*
	  fprintf(stderr, "VALID SA => <SA : %s> <Filter Source : %s/%i> <Filter Destination : %s/%i> <SPI : %s>\n", g_esp_sad.table[i].sa, g_esp_sad.table[i].src, g_esp_sad.table[i].src_len,
		  g_esp_sad.table[i].dst, g_esp_sad.table[i].dst_len, g_esp_sad.table[i].spi);
	  */

	  if((protocol_typ == sad -> table[i].typ)
	     && filter_address_match(src,sad -> table[i].src, sad -> table[i].src_len, protocol_typ)
	     && filter_address_match(dst,sad -> table[i].dst, sad -> table[i].dst_len, protocol_typ)
	     && filter_spi_match(spi_string, sad -> table[i].spi))
	    {
	      *entry_index = i;
	      *encryption_algo = sad -> table[i].encryption_algo;
	      *authentication_algo = sad -> table[i].authentication_algo;
	      *authentication_key_len = compute_ascii_key(authentication_key, (gchar *)sad -> table[i].authentication_key);
	      *encryption_key_len = compute_ascii_key(encryption_key, (gchar *)sad -> table[i].encryption_key);	      	      

	      found = TRUE;

	      /* Debugging Purpose */
	      /*
	      fprintf(stderr,"MATCHING SA => <IP Source : %s> <IP Destination : %s> <SPI : %s>\n\
            => <FILTER Source : %s/%i> <FILTER Destination : %s/%i> <FILTER SPI : %s>\n\
            => <Encryption Algo : %i> <Encryption Key: %s> <Authentication Algo : %i>\n",
		      src,dst,spi_string,
		      sad -> table[i].src, sad -> table[i].src_len,
		      sad -> table[i].dst, sad -> table[i].dst_len,
		      sad -> table[i].spi,
		      *encryption_algo, *encryption_key, *authentication_algo);
		      */
	    }

	  /* We free the Src, Dst and Spi in the SA, but perhaps to allocate it again with the same value !!! */
	  g_free(g_esp_sad.table[i].src);
	  g_free(g_esp_sad.table[i].dst);
	  g_free(g_esp_sad.table[i].spi);
	  g_esp_sad.table[i].is_valid = FALSE;

	}

      else
	{
	  /* Debugging Purpose */
	  /* fprintf(stderr, "INVALID SA => %s \n", g_esp_sad.table[i].sa); */
	}

      i++;
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
  next_tvb = tvb_new_subset(tvb, advance, -1, -1);

  if (g_ah_payload_in_subtree) {
    col_set_writable(pinfo->cinfo, FALSE);
  }

  /* do lookup with the subdissector table */
  if (!dissector_try_port(ip_dissector_table, nxt, next_tvb, pinfo, tree)) {
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

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AH");
  if (check_col(pinfo->cinfo, COL_INFO))
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
			FALSE);

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
  gint entry_index;

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


  /*
   * load the top pane info. This should be overwritten by
   * the next protocol in the stack
   */

#endif

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESP");
  if (check_col(pinfo->cinfo, COL_INFO))
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
	    ip_src = (gchar *) g_malloc((IPSEC_STRLEN_IPV4 + 1) * sizeof(gchar));
	    ip_dst = (gchar *) g_malloc((IPSEC_STRLEN_IPV4 + 1) * sizeof(gchar));
	    protocol_typ = IPSEC_SA_IPV4;

	    for(i = 0 ; i < pinfo -> src.len; i++)
	      {
		if(((guint8 *)(pinfo -> src.data))[i] < 16)
		  {
		    g_snprintf(res,3,"0%X ", (pinfo -> src.data)[i]);
		  }
		else
		  {
		    g_snprintf(res,3,"%X ", (pinfo -> src.data)[i]);
		  }
		memcpy(ip_src + i*2, res, 2);
	      }
	    ip_src[IPSEC_STRLEN_IPV4] = '\0';

	    for(i = 0 ; i < pinfo -> dst.len; i++)
	      {
		if(((guint8 *)(pinfo -> dst.data))[i] < 16)
		  {
		    g_snprintf(res,3,"0%X ", (pinfo -> dst.data)[i]);
		  }
		else
		  {
		    g_snprintf(res,3,"%X ", (pinfo -> dst.data)[i]);
		  }
		memcpy(ip_dst + i*2, res, 2);
	      }
	    ip_dst[IPSEC_STRLEN_IPV4] = '\0';

	    get_address_ok = TRUE;
	  break;
	  }

	case AT_IPv6 :
	  {
	    ip_src = (gchar *) g_malloc((IPSEC_STRLEN_IPV6 + 1) * sizeof(gchar));
	    ip_dst = (gchar *) g_malloc((IPSEC_STRLEN_IPV6 + 1) * sizeof(gchar));
	    protocol_typ = IPSEC_SA_IPV6;

	    for(i = 0 ; i < pinfo -> src.len; i++)
	      {
		if(((guint8 *)(pinfo -> src.data))[i] < 16)
		  {
		    g_snprintf(res,3,"0%X ", (pinfo -> src.data)[i]);
		  }
		else
		  {
		    g_snprintf(res,3,"%X ", (pinfo -> src.data)[i]);
		  }
		memcpy(ip_src + i*2, res, 2);
	      }
	    ip_src[IPSEC_STRLEN_IPV6] = '\0';

	    for(i = 0 ; i < pinfo -> dst.len; i++)
	      {
		if(((guint8 *)(pinfo -> dst.data))[i] < 16)
		  {
		    g_snprintf(res,3,"0%X ", (pinfo -> dst.data)[i]);
		  }
		else
		  {
		    g_snprintf(res,3,"%X ", (pinfo -> dst.data)[i]);
		  }
		memcpy(ip_dst + i*2, res, 2);
	      }
	    ip_dst[IPSEC_STRLEN_IPV6] = '\0';

	    get_address_ok = TRUE;
	    break;
	  }

	default :
	  {
	    get_address_ok = FALSE;
	    break;
	  }
	}

      /* The packet cannot be decoded using the SAD */
      if(g_esp_enable_null_encryption_decode_heuristic && !get_address_ok)
	null_encryption_decode_heuristic = TRUE;

      if(get_address_ok)
	{
	  /* Get the SPI */
	  if(tvb_bytes_exist(tvb, 0, 4))
	    {
	      spi = tvb_get_ntohl(tvb, 0);
	    }


	  /*
	    PARSE the SAD and fill it. It may take some time since it will
	    be called every times an ESP Payload is found.
	  */

	  if((sad_is_present = get_esp_sa(&g_esp_sad, protocol_typ, ip_src, ip_dst, spi, &entry_index, 
					  &esp_crypt_algo, &esp_auth_algo, 
					  &esp_crypt_key, &esp_crypt_key_len, &esp_auth_key, &esp_auth_key_len)))
	    {

	      /* Get length of whole ESP packet. */
	      len = tvb_reported_length(tvb);
	  
	      switch(esp_auth_algo)
		{

		case IPSEC_AUTH_HMAC_SHA1_96:
		  {
		    esp_auth_len = 12;
		    break;
		  }

		case IPSEC_AUTH_HMAC_SHA256:
		  {
		    esp_auth_len = 12;
		    break;
		  }

		case IPSEC_AUTH_NULL:
		  {
		    esp_auth_len = 0;
		    break;
		  }

		  /*
		    case IPSEC_AUTH_AES_XCBC_MAC_96:
		    {
		    esp_auth_len = 12;
		    break;
		    }
		  */

		case IPSEC_AUTH_HMAC_MD5_96:
		  {
		    esp_auth_len = 12;
		    break;
		  }

		case IPSEC_AUTH_ANY_12BYTES:
		default:
		  {
		    esp_auth_len = 12;
		    break;
		  }

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
		      {
			auth_algo_libgcrypt = GCRY_MD_SHA1;
			authentication_check_using_hmac_libgcrypt = TRUE;
			break;
		      }

		    case IPSEC_AUTH_NULL:
		      {
			authentication_check_using_hmac_libgcrypt = FALSE;
			authentication_checking_ok = TRUE;
			authentication_ok = TRUE;
			break;
		      }

		      /*
			case IPSEC_AUTH_AES_XCBC_MAC_96:
			{
			auth_algo_libgcrypt =
			authentication_check_using_libgcrypt = TRUE;
			break;
			}
		      */

		    case IPSEC_AUTH_HMAC_SHA256:
		      {
			auth_algo_libgcrypt = GCRY_MD_SHA256;
			authentication_check_using_hmac_libgcrypt = TRUE;
			break;
		      }

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
		      {
			auth_algo_libgcrypt = GCRY_MD_MD5;
			authentication_check_using_hmac_libgcrypt = TRUE;
			break;
		      }

		    case IPSEC_AUTH_ANY_12BYTES:
		    default:
		      {
			authentication_ok = FALSE;
			authentication_check_using_hmac_libgcrypt = FALSE;
			break;
		      }

		      }

		  if((authentication_check_using_hmac_libgcrypt) && (!authentication_ok))
		    {
		      gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
		      gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

		      /* Allocate Buffers for Authenticator Field  */
		      authenticator_data = (guint8 *) g_malloc (( esp_auth_len + 1) * sizeof(guint8));
		      memset(authenticator_data,0, esp_auth_len + 1);
		      tvb_memcpy(tvb, authenticator_data, len - esp_auth_len, esp_auth_len);

		      esp_data = (guint8 *) g_malloc (( len - esp_auth_len + 1) * sizeof(guint8));
		      memset(esp_data,0,  len - esp_auth_len + 1);
		      tvb_memcpy(tvb, esp_data, 0, len - esp_auth_len);

		      err = gcry_md_open (&md_hd, auth_algo_libgcrypt, GCRY_MD_FLAG_HMAC);
		      if (err)
			{
			  fprintf (stderr,"<IPsec/ESP Dissector> Error in Algorithm %s, gcry_md_open failed: %s\n", gcry_md_algo_name(auth_algo_libgcrypt), gpg_strerror (err));
			  authentication_ok = FALSE;
			  g_free(authenticator_data);
			  g_free(esp_data);
			}

		      else
			{
			  md_len = gcry_md_get_algo_dlen (auth_algo_libgcrypt);
			  if (md_len < 1 || md_len < esp_auth_len)
			    {
			      fprintf (stderr,"<IPsec/ESP Dissector> Error in Algorithm %s, grcy_md_get_algo_dlen failed: %d\n", gcry_md_algo_name(auth_algo_libgcrypt), md_len);
			      authentication_ok = FALSE;
			    }

			  else
			    {
			      gcry_md_setkey( md_hd, esp_auth_key, esp_auth_key_len );

			      gcry_md_write (md_hd, esp_data, len - esp_auth_len);

			      authenticator_data_computed_md = gcry_md_read (md_hd, auth_algo_libgcrypt);
			      if (authenticator_data_computed_md == 0)
				{
				  fprintf (stderr,"<IPsec/ESP Dissector> Error in Algorithm %s, gcry_md_read failed\n", gcry_md_algo_name(auth_algo_libgcrypt));
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
					  g_snprintf((char *)authenticator_data_computed_car, 3, "%02X", authenticator_data_computed_md[i] & 0xFF);
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
		  /* Desactivation of the Heuristic to decrypt using the NULL encryption algorithm since the packet is matching a SA */
		  null_encryption_decode_heuristic = FALSE;

		  switch(esp_crypt_algo)
		    {

		    case IPSEC_ENCRYPT_3DES_CBC :
		      {
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
				fprintf (stderr,"<ESP Preferences> Error in Encryption Algorithm 3DES-CBC : Bad Keylen (%i Bits)\n",esp_crypt_key_len * 8);
				decrypt_ok = FALSE;
			      }
			    else
			      decrypt_using_libgcrypt = TRUE;
			  }

			break;
		      }

		    case IPSEC_ENCRYPT_AES_CBC :
		      {
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
				{
				  crypt_algo_libgcrypt = GCRY_CIPHER_AES128;
				  decrypt_using_libgcrypt = TRUE;
				  break;
				}
			      case 192:
				{
				  crypt_algo_libgcrypt = GCRY_CIPHER_AES192;
				  decrypt_using_libgcrypt = TRUE;
				  break;
				}
			      case 256:
				{
				  crypt_algo_libgcrypt = GCRY_CIPHER_AES256;
				  decrypt_using_libgcrypt = TRUE;
				  break;
				}
			      default:
				{
				  fprintf (stderr,"<ESP Preferences> Error in Encryption Algorithm AES-CBC : Bad Keylen (%i Bits)\n",esp_crypt_key_len * 8);
				  decrypt_ok = FALSE;
				}
			      }
			  }
			break;
		      }


		    case IPSEC_ENCRYPT_DES_CBC :
		      {
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
				fprintf (stderr,"<ESP Preferences> Error in Encryption Algorithm DES-CBC : Bad Keylen (%i Bits)\n",esp_crypt_key_len * 8);
				decrypt_ok = FALSE;
			      }
			    else
			      decrypt_using_libgcrypt = TRUE;
			  }

			break;
		      }


		    case IPSEC_ENCRYPT_AES_CTR :
		      {
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
				{
				  crypt_algo_libgcrypt = GCRY_CIPHER_AES128;
				  decrypt_using_libgcrypt = TRUE;
				  break;
				}
			      case 224:
				{
				  crypt_algo_libgcrypt = GCRY_CIPHER_AES192;
				  decrypt_using_libgcrypt = TRUE;
				  break;
				}
			      case 288:
				{
				  crypt_algo_libgcrypt = GCRY_CIPHER_AES256;
				  decrypt_using_libgcrypt = TRUE;
				  break;
				}
			      default:
				{
				  fprintf (stderr,"<ESP Preferences> Error in Encryption Algorithm AES-CTR : Bad Keylen (%i Bits)\n",esp_crypt_key_len * 8);
				  decrypt_ok = FALSE;
				}
			      }
			  }

			break;
		      }

		    case IPSEC_ENCRYPT_TWOFISH_CBC :
		      {
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
				{
				  crypt_algo_libgcrypt = GCRY_CIPHER_TWOFISH128;
				  decrypt_using_libgcrypt = TRUE;
				  break;
				}
			      case 256:
				{
				  crypt_algo_libgcrypt = GCRY_CIPHER_TWOFISH;
				  decrypt_using_libgcrypt = TRUE;
				  break;
				}
			      default:
				{
				  fprintf (stderr,"<ESP Preferences> Error in Encryption Algorithm TWOFISH-CBC : Bad Keylen (%i Bits)\n",esp_crypt_key_len * 8);
				  decrypt_ok = FALSE;
				}
			      }
			  }

			break;
		      }


		    case IPSEC_ENCRYPT_BLOWFISH_CBC :
		      {
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
				fprintf (stderr,"<ESP Preferences> Error in Encryption Algorithm BLOWFISH-CBC : Bad Keylen (%i Bits)\n",esp_crypt_key_len * 8);
				decrypt_ok = FALSE;
			      }
			    else
			      decrypt_using_libgcrypt = TRUE;
			  }

			break;

		      }


		    case IPSEC_ENCRYPT_NULL :
		    default :
		      {
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
		    }

		  if(decrypt_using_libgcrypt)
		    {
		      /* Allocate Buffers for Encrypted and Decrypted data  */
		      encrypted_data = (guint8 *) g_malloc ((decrypted_len_alloc) * sizeof(guint8));
		      memset(encrypted_data,0,decrypted_len_alloc);
		      decrypted_data = (guint8 *) g_malloc ((decrypted_len_alloc + esp_iv_len)* sizeof(guint8));
		      tvb_memcpy(tvb, encrypted_data , sizeof(struct newesp), decrypted_len);

		      err = gcry_cipher_open (&cypher_hd, crypt_algo_libgcrypt, crypt_mode_libgcrypt, 0);
		      if (err)
			{
			  fprintf(stderr,"<IPsec/ESP Dissector> Error in Algorithm %s Mode %d, grcy_open_cipher failed: %s\n",
			          gcry_cipher_algo_name(crypt_algo_libgcrypt), crypt_mode_libgcrypt, gpg_strerror (err));
			  g_free(encrypted_data);
			  g_free(decrypted_data);
			  decrypt_ok = FALSE;
			}

		      else
			{
			  err = gcry_cipher_setkey (cypher_hd, esp_crypt_key, esp_crypt_key_len);
			  if (err)
			    {
			      fprintf(stderr,"<IPsec/ESP Dissector> Error in Algorithm %s Mode %d, gcry_cipher_setkey failed: %s\n",
				      gcry_cipher_algo_name(crypt_algo_libgcrypt), crypt_mode_libgcrypt, gpg_strerror (err));
			      gcry_cipher_close (cypher_hd);
			      g_free(encrypted_data);
			      g_free(decrypted_data);
			      decrypt_ok = FALSE;
			    }
			  else
			    {
			      err = gcry_cipher_decrypt (cypher_hd, decrypted_data, decrypted_len_alloc + esp_iv_len, encrypted_data, decrypted_len_alloc);
			      if (err)
				{
				  fprintf(stderr,"<IPsec/ESP Dissector> Error in Algorithm %s, Mode %d, gcry_cipher_decrypt failed: %s\n",
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
					  decrypted_data[i + decrypted_len -esp_auth_len] = encrypted_data[i + decrypted_len - esp_auth_len];
					}
				    }

				  fprintf(stderr,"\n\n ");
				  g_free(encrypted_data);
				  decrypt_ok = TRUE;
				}
			    }
			}
		    }

		  if(decrypt_ok)
		    {
		      tvb_decrypted = tvb_new_real_data(decrypted_data, decrypted_len, decrypted_len);
		      tvb_set_child_real_data_tvbuff(tvb, tvb_decrypted);

		      add_new_data_source(pinfo,
					  tvb_decrypted,
					  "Decrypted Data");

		      /* Handler to free the Decrypted Data Buffer. */
		      tvb_set_free_cb(tvb_decrypted,g_free);

		      if(tvb_bytes_exist(tvb_decrypted, 0, esp_iv_len))
			{
			  if(esp_iv_len > 0)
			    proto_tree_add_item(esp_tree, hf_esp_iv, 
						tvb_decrypted,
						0, esp_iv_len,
						FALSE);
			}

		      else
			proto_tree_add_text(esp_tree, tvb_decrypted,
					    0, -1,
					    "IV (truncated)");

		      /* Make sure the packet is not truncated before the fields
		       * we need to read to determine the encapsulated protocol */
		      if(tvb_bytes_exist(tvb_decrypted, decrypted_len - esp_auth_len - 2, 2))
			{
			  esp_pad_len = tvb_get_guint8(tvb_decrypted, decrypted_len - esp_auth_len - 2);

			  if(decrypted_len - esp_auth_len - esp_pad_len - esp_iv_len - 2 >= esp_iv_len)
			    {
			      /* Get the encapsulated protocol */
			      encapsulated_protocol = tvb_get_guint8(tvb_decrypted, decrypted_len - esp_auth_len - 1);

			      if(dissector_try_port(ip_dissector_table,
						    encapsulated_protocol,
						    tvb_new_subset(tvb_decrypted, esp_iv_len,
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
				proto_tree_add_text(esp_tree, tvb_decrypted, decrypted_len - esp_auth_len - 2 - esp_pad_len, esp_pad_len,"Pad");

			      proto_tree_add_uint(esp_tree, hf_esp_pad_len, tvb_decrypted,
						  decrypted_len - esp_auth_len - 2, 1,
						  esp_pad_len);

			      proto_tree_add_uint_format(esp_tree, hf_esp_protocol, tvb_decrypted,
					 decrypted_len - esp_auth_len - 1, 1,
					 encapsulated_protocol,
					"Next header: %s (0x%02x)",
					 ipprotostr(encapsulated_protocol), encapsulated_protocol);

			      dissect_esp_authentication(esp_tree, tvb_decrypted, decrypted_len, esp_auth_len, authenticator_data_computed, authentication_ok, authentication_checking_ok );

			    }
			}
		      else
			{
			  call_dissector(data_handle,
					 tvb_new_subset(tvb_decrypted, 0, decrypted_len - esp_auth_len, decrypted_len - esp_auth_len),
					 pinfo, esp_tree);

			  if(esp_tree)
			    dissect_esp_authentication(esp_tree, tvb_decrypted, decrypted_len, esp_auth_len, authenticator_data_computed, authentication_ok, authentication_checking_ok );

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
	      if(esp_auth_key_len != 0) g_free(esp_auth_key);
	      if(esp_crypt_key_len != 0) g_free(esp_crypt_key);		
	    
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
	dissect_esp_authentication(esp_tree, tvb, len , esp_auth_len, authenticator_data_computed, authentication_ok, authentication_checking_ok );

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
	      if(dissector_try_port(ip_dissector_table,
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
		  proto_tree_add_text(esp_tree, tvb, len - 12, 12,
				      "Authentication Data");
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
  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPComp");
  if (check_col(pinfo->cinfo, COL_INFO))
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
    call_dissector(data_handle,
		   tvb_new_subset(tvb, sizeof(struct ipcomp), -1, -1), pinfo,
		   ipcomp_tree);
  }
}

void
proto_register_ipsec(void)
{

#ifdef HAVE_LIBGCRYPT
  guint i=0;
#endif

  static hf_register_info hf_ah[] = {
    { &hf_ah_spi,
      { "SPI",		"ah.spi",	FT_UINT32,	BASE_HEX, NULL, 0x0,
      	"", HFILL }},
    { &hf_ah_iv,
      { "IV",		"ah.iv",	FT_BYTES,	BASE_HEX, NULL, 0x0,
      	"", HFILL }},
    { &hf_ah_sequence,
      { "Sequence",     "ah.sequence",	FT_UINT32,	BASE_DEC, NULL, 0x0,
      	"", HFILL }}
  };

  static hf_register_info hf_esp[] = {
    { &hf_esp_spi,
      { "SPI",		"esp.spi",	FT_UINT32,	BASE_HEX, NULL, 0x0,
      	"", HFILL }},
    { &hf_esp_sequence,
      { "Sequence",     "esp.sequence",	FT_UINT32,	BASE_DEC, NULL, 0x0,
      	"", HFILL }},
    { &hf_esp_pad_len,
      { "Pad Length",	"esp.pad_len",	FT_UINT8,	BASE_DEC, NULL, 0x0,
      	"", HFILL }},
    { &hf_esp_protocol,
      { "Next Header",	"esp.protocol",	FT_UINT8,	BASE_HEX, NULL, 0x0,
      	"", HFILL }},
    { &hf_esp_iv,
      { "IV",		"esp.iv",	FT_BYTES,	BASE_HEX, NULL, 0x0,
      	"", HFILL }}
  };

  static hf_register_info hf_ipcomp[] = {
    { &hf_ipcomp_flags,
      { "Flags",	"ipcomp.flags",	FT_UINT8,	BASE_HEX, NULL, 0x0,
      	"", HFILL }},
    { &hf_ipcomp_cpi,
      { "CPI",		"ipcomp.cpi",	FT_UINT16,	BASE_HEX,
        VALS(cpi2val),	0x0,      	"", HFILL }},
  };
  static gint *ett[] = {
    &ett_ah,
    &ett_esp,
    &ett_ipcomp,
  };

#ifdef HAVE_LIBGCRYPT
  GString *name_str, *title_str;

#define PREF_STR_INIT() \
  name_str = g_string_new(""); \
  title_str = g_string_new("")

#define PREF_STR_FREE() \
  g_string_free(name_str, FALSE); \
  g_string_free(title_str, FALSE)

  static enum_val_t esp_encryption_algo[] = {

    {"null", "NULL", IPSEC_ENCRYPT_NULL},
    {"3descbc", "TripleDES-CBC [RFC2451]", IPSEC_ENCRYPT_3DES_CBC},
    {"aescbc", "AES-CBC [RFC3602]", IPSEC_ENCRYPT_AES_CBC},
    {"aesctr", "AES-CTR [RFC3686]", IPSEC_ENCRYPT_AES_CTR},
    {"descbc", "DES-CBC [RFC2405]", IPSEC_ENCRYPT_DES_CBC},
    {"blowfishcbc","BLOWFISH-CBC [RFC2451]", IPSEC_ENCRYPT_BLOWFISH_CBC},
    {"twofishcbc","TWOFISH-CBC", IPSEC_ENCRYPT_TWOFISH_CBC},
    {NULL,NULL,0}
  };

  static enum_val_t esp_authentication_algo[] = {

    {"null", "NULL", IPSEC_AUTH_NULL},
    {"hmacsha196", "HMAC-SHA1-96 [RFC2404]", IPSEC_AUTH_HMAC_SHA1_96},
    {"hmacsha256", "HMAC-SHA256", IPSEC_AUTH_HMAC_SHA256},
    {"hmacmd596", "HMAC-MD5-96 [RFC2403]", IPSEC_AUTH_HMAC_MD5_96},
    /*    {"aesxcbcmac96", "AES-XCBC-MAC-96 [RFC3566]", IPSEC_AUTH_AES_XCBC_MAC_96}, */
    {"any12bytes", "ANY 12-bytes of Authentication [No Checking]", IPSEC_AUTH_ANY_12BYTES},
    {NULL,NULL,0}
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

#ifdef HAVE_LIBGCRYPT
  /* Register SA configuration options for ESP decryption */
  g_esp_sad.nb = g_esp_nb_sa;
  for(i = 0; i < g_esp_nb_sa; i++)
    {
      g_esp_sad.table[i].sa = NULL;
      g_esp_sad.table[i].typ = IPSEC_SA_UNKNOWN;
      g_esp_sad.table[i].src = NULL;
      g_esp_sad.table[i].dst = NULL;
      g_esp_sad.table[i].spi = NULL;
      g_esp_sad.table[i].src_len = -1;
      g_esp_sad.table[i].dst_len = -1;
      g_esp_sad.table[i].encryption_algo = IPSEC_ENCRYPT_NULL;
      g_esp_sad.table[i].authentication_algo = IPSEC_AUTH_NULL;
      g_esp_sad.table[i].encryption_key = NULL;
      g_esp_sad.table[i].authentication_key = NULL;
      g_esp_sad.table[i].is_valid = FALSE;
    }
#endif

  prefs_register_bool_preference(esp_module, "enable_null_encryption_decode_heuristic",
				 "Attempt to detect/decode NULL encrypted ESP payloads",
				 "This is done only if the Decoding is not SET or the packet does not belong to a SA. Assumes a 12 byte auth (HMAC-SHA1-96/HMAC-MD5-96/AES-XCBC-MAC-96) and attempts decode based on the ethertype 13 bytes from packet end",
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


  /* prefs_register_uint_preference(esp_module, "nb_sa",
     "Number of Security Associations",
     "Number of Security Associations in the SAD",
     10, &g_esp_nb_sa); */

  for (i = 0; i < g_esp_nb_sa; i++)
    {

      if (i >=  g_max_esp_nb_sa)
	{
	  break;
	}

      PREF_STR_INIT();
      g_string_sprintf(name_str,"sa_%d", i + 1);
      g_string_sprintf(title_str,"SA #%d", i + 1);

      prefs_register_string_preference(esp_module, name_str->str, title_str->str,
			"SA identifier.  Must have the form "
			"\"Protocol|Source Address|Destination Adress|SPI\". "
			"Example: \"IPv4|192.168.0.45|10.1.2.7|*\" "
			"See the ESP Preferences page on the Wireshark wiki "
			"(http://wiki.wireshark.org/ESP_Preferences) for "
			"more details.",
			&g_esp_sad.table[i].sa);
      PREF_STR_FREE();


      PREF_STR_INIT();
      g_string_sprintf(name_str, "encryption_algorithm_%d", i + 1);
      g_string_sprintf(title_str, "Encryption Algorithm #%d", i + 1);

      prefs_register_enum_preference(esp_module, name_str->str, title_str->str,
			"Encryption algorithm",
			&g_esp_sad.table[i].encryption_algo, esp_encryption_algo, FALSE);
      PREF_STR_FREE();

      PREF_STR_INIT();
      g_string_sprintf(name_str, "authentication_algorithm_%d", i + 1);
      g_string_sprintf(title_str, "Authentication Algorithm #%d", i + 1);

      prefs_register_enum_preference(esp_module, name_str->str, title_str->str,
			"Authentication algorithm",
			&g_esp_sad.table[i].authentication_algo, esp_authentication_algo, FALSE);
      PREF_STR_FREE();


      PREF_STR_INIT();
      g_string_sprintf(name_str, "encryption_key_%d", i + 1);
      g_string_sprintf(title_str, "Encryption Key #", i + 1);

      prefs_register_string_preference(esp_module, name_str->str, title_str->str,
			"Encryption key. May be ASCII or hexadecimal (if "
			"prepended with 0x)."
			"See the ESP Preferences page on the Wireshark wiki "
			"(http://wiki.wireshark.org/ESP_Preferences) for "
			"supported sizes.",
			&g_esp_sad.table[i].encryption_key);
      PREF_STR_FREE();


      PREF_STR_INIT();
      g_string_sprintf(name_str, "authentication_key_%d", i + 1);
      g_string_sprintf(title_str, "Authentication Key #%d", i + 1);

      prefs_register_string_preference(esp_module, name_str->str, title_str->str,
			"Authentication key. May be ASCII or hexadecimal (if "
			"prepended with 0x)."
			"See the ESP Preferences page on the Wireshark wiki "
			"(http://wiki.wireshark.org/ESP_Preferences) for "
			"supported sizes.",
			&g_esp_sad.table[i].authentication_key);
      PREF_STR_FREE();

    }


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
  dissector_add("ip.proto", IP_PROTO_AH, ah_handle);
  esp_handle = find_dissector("esp");
  dissector_add("ip.proto", IP_PROTO_ESP, esp_handle);
  ipcomp_handle = create_dissector_handle(dissect_ipcomp, proto_ipcomp);
  dissector_add("ip.proto", IP_PROTO_IPCOMP, ipcomp_handle);

  ip_dissector_table = find_dissector_table("ip.proto");
}



