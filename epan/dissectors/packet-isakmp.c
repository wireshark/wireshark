/* packet-isakmp.c
 * Routines for the Internet Security Association and Key Management Protocol
 * (ISAKMP) (RFC 2408) and the Internet IP Security Domain of Interpretation
 * for ISAKMP (RFC 2407)
 * Brad Robel-Forrest <brad.robel-forrest@watchguard.com>
 *
 * Added routines for the Internet Key Exchange (IKEv2) Protocol
 * (draft-ietf-ipsec-ikev2-17.txt)
 * Shoichi Sakane <sakane@tanu.org>
 *
 * Added routines for RFC3947 Negotiation of NAT-Traversal in the IKE
 *   ronnie sahlberg
 * 
 * 04/2009 Added routines for decryption of IKEv2 Encrypted Payload
 *   Naoyoshi Ueda <piyomaru3141@gmail.com>
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
 *
 * References:
 * IKEv2 http://www.ietf.org/rfc/rfc4306.txt?number=4306
 * http://www.iana.org/assignments/ikev2-parameters
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>

#ifdef HAVE_LIBGCRYPT
#ifdef _WIN32
#include <winposixtype.h>
#endif /* _WIN32 */
#include <gcrypt.h>
#include <epan/strutil.h>
#include <wsutil/file_util.h>
#include <epan/uat.h>
#endif

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/asn1.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-x509if.h>
#include <epan/dissectors/packet-x509af.h>
#include <epan/dissectors/packet-isakmp.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#define isakmp_min(a, b)  ((a<b) ? a : b)

#define ARLEN(a) (sizeof(a)/sizeof(a[0]))

static int proto_isakmp = -1;
static int hf_isakmp_certificate_authority = -1;
static int hf_isakmp_v2_certificate_authority = -1;
static int hf_isakmp_nat_keepalive = -1;

static int hf_isakmp_icookie         = -1;
static int hf_isakmp_rcookie         = -1;
static int hf_isakmp_nextpayload     = -1;
static int hf_isakmp_version         = -1;
static int hf_isakmp_exchangetype    = -1;
static int hf_isakmp_flags           = -1;
static int hf_isakmp_messageid       = -1;
static int hf_isakmp_length          = -1;
static int hf_isakmp_payloadlen      = -1;
static int hf_isakmp_doi             = -1;
static int hf_isakmp_sa_situation    = -1;
static int hf_isakmp_prop_number     = -1;
static int hf_isakmp_spisize         = -1;
static int hf_isakmp_prop_transforms = -1;
static int hf_isakmp_trans_number    = -1;
static int hf_isakmp_trans_id        = -1;
static int hf_isakmp_id_type         = -1;
static int hf_isakmp_protoid         = -1;
static int hf_isakmp_id_port         = -1;
static int hf_isakmp_cert_encoding   = -1;
static int hf_isakmp_certreq_type    = -1;
static int hf_isakmp_certificate     = -1;
static int hf_isakmp_notify_msgtype  = -1;
static int hf_isakmp_num_spis        = -1;

static int hf_isakmp_fragments = -1;
static int hf_isakmp_fragment = -1;
static int hf_isakmp_fragment_overlap = -1;
static int hf_isakmp_fragment_overlap_conflicts = -1;
static int hf_isakmp_fragment_multiple_tails = -1;
static int hf_isakmp_fragment_too_long_fragment = -1;
static int hf_isakmp_fragment_error = -1;
static int hf_isakmp_reassembled_in = -1;

static int hf_isakmp_cisco_frag_packetid      = -1;
static int hf_isakmp_cisco_frag_seq     = -1;
static int hf_isakmp_cisco_frag_last    = -1;

static gint ett_isakmp = -1;
static gint ett_isakmp_flags = -1;
static gint ett_isakmp_payload = -1;
static gint ett_isakmp_fragment = -1;
static gint ett_isakmp_fragments = -1;
#ifdef HAVE_LIBGCRYPT
/* For decrypted IKEv2 Encrypted payload*/
static gint ett_isakmp_decrypted_data = -1;
static gint ett_isakmp_decrypted_payloads = -1;
#endif /* HAVE_LIBGCRYPT */

static dissector_handle_t eap_handle = NULL;

static GHashTable *isakmp_fragment_table = NULL;
static GHashTable *isakmp_reassembled_table = NULL;

static const fragment_items isakmp_frag_items = {
        /* Fragment subtrees */
        &ett_isakmp_fragment,
        &ett_isakmp_fragments,
        /* Fragment fields */
        &hf_isakmp_fragments,
        &hf_isakmp_fragment,
        &hf_isakmp_fragment_overlap,
        &hf_isakmp_fragment_overlap_conflicts,
        &hf_isakmp_fragment_multiple_tails,
        &hf_isakmp_fragment_too_long_fragment,
        &hf_isakmp_fragment_error,
        /* Reassembled in field */
        &hf_isakmp_reassembled_in,
        /* Tag */
        "Message fragments"
};
/* IKE port number assigned by IANA */
#define UDP_PORT_ISAKMP	500
#define TCP_PORT_ISAKMP 500

/*
 * Identifier Type
 *   RFC2407 for IKEv1
 *   draft-ietf-ipsec-ikev2-17.txt for IKEv2
 */
#define IKE_ID_IPV4_ADDR		1
#define IKE_ID_FQDN			2
#define IKE_ID_USER_FQDN		3
#define IKE_ID_IPV4_ADDR_SUBNET		4
#define IKE_ID_IPV6_ADDR		5
#define IKE_ID_IPV6_ADDR_SUBNET		6
#define IKE_ID_IPV4_ADDR_RANGE		7
#define IKE_ID_IPV6_ADDR_RANGE		8
#define IKE_ID_DER_ASN1_DN		9
#define IKE_ID_DER_ASN1_GN		10
#define IKE_ID_KEY_ID			11

/*
 * Traffic Selector Type
 *   Not in use for IKEv1
 */
#define IKEV2_TS_IPV4_ADDR_RANGE	7
#define IKEV2_TS_IPV6_ADDR_RANGE	8

static const value_string frag_last_vals[] = {
  { 0,	"More fragments" },
  { 1,	"Last fragment" },
  { 0,  NULL },
};

static const value_string vs_proto[] = {
  { 0,	"RESERVED" },
  { 1,	"ISAKMP" },
  { 2,	"IPSEC_AH" },
  { 3,	"IPSEC_ESP" },
  { 4,	"IPCOMP" },
  { 0,	NULL },
};

#define COOKIE_SIZE 8

typedef struct isakmp_hdr {
  guint8	next_payload;
  guint8	version;
  guint8	exch_type;
  guint8	flags;
#define E_FLAG		0x01
#define C_FLAG		0x02
#define A_FLAG		0x04
#define I_FLAG		0x08
#define V_FLAG		0x10
#define R_FLAG		0x20
  guint32	message_id;
  guint32	length;
} isakmp_hdr_t;

#define ISAKMP_HDR_SIZE (sizeof(struct isakmp_hdr) + (2 * COOKIE_SIZE))

#define ENC_DES_CBC		1
#define ENC_IDEA_CBC		2
#define ENC_BLOWFISH_CBC	3
#define ENC_RC5_R16_B64_CBC	4
#define ENC_3DES_CBC		5
#define ENC_CAST_CBC		6
#define ENC_AES_CBC		7

#define HMAC_MD5	1
#define HMAC_SHA	2
#define HMAC_TIGER	3
#define HMAC_SHA2_256	4
#define HMAC_SHA2_384	5
#define HMAC_SHA2_512	6

#ifdef HAVE_LIBGCRYPT

#define MAIN_MODE 2
#define AGGRESSIVE_MODE 4
#define MAX_KEY_SIZE 256
#define MAX_DIGEST_SIZE 64
#define MAX_OAKLEY_KEY_LEN 32

typedef struct decrypt_key {
  guchar        secret[MAX_KEY_SIZE];
  guint         secret_len;
} decrypt_key_t;

typedef struct iv_data {
  guchar iv[MAX_DIGEST_SIZE];
  guint  iv_len;
  guint32 frame_num;
} iv_data_t;

typedef struct decrypt_data {
  gboolean       is_psk;
  address	 initiator;
  guint          encr_alg;
  guint          hash_alg;
  guint          group;
  gchar         *gi;
  guint          gi_len;
  gchar         *gr;
  guint          gr_len;
  guchar         secret[MAX_KEY_SIZE];
  guint          secret_len;
  GList         *iv_list;
  gchar          last_cbc[MAX_DIGEST_SIZE];
  guint          last_cbc_len;
  gchar          last_p1_cbc[MAX_DIGEST_SIZE];
  guint          last_p1_cbc_len;
  guint32        last_message_id;
} decrypt_data_t;

static GHashTable *isakmp_hash = NULL;
static GMemChunk *isakmp_key_data = NULL;
static GMemChunk *isakmp_decrypt_data = NULL;
static FILE *logf = NULL;
static const char *pluto_log_path = "insert pluto log path here";

/* Specifications of encryption algorithms for IKEv2 decryption */
typedef struct _ikev2_encr_alg_spec {
  guint number;
  /* Length of encryption key */
  guint key_len;
  /* Block size of the cipher */
  guint block_len;
  /* Length of initialization vector */
  guint iv_len;
  /* Encryption algorithm ID to be passed to gcry_cipher_open() */
  gint gcry_alg;
  /* Cipher mode to be passed to gcry_cipher_open() */
  gint gcry_mode; 
} ikev2_encr_alg_spec_t;

#define IKEV2_ENCR_NULL 1
#define IKEV2_ENCR_3DES 2
#define IKEV2_ENCR_AES_CBC_128 3
#define IKEV2_ENCR_AES_CBC_192 4
#define IKEV2_ENCR_AES_CBC_256 5

static ikev2_encr_alg_spec_t ikev2_encr_algs[] = {
  {IKEV2_ENCR_NULL, 0, 1, 0, GCRY_CIPHER_NONE, GCRY_CIPHER_MODE_NONE},
  {IKEV2_ENCR_3DES, 24, 8, 8, GCRY_CIPHER_3DES, GCRY_CIPHER_MODE_CBC},
  {IKEV2_ENCR_AES_CBC_128, 16, 16, 16, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC},
  {IKEV2_ENCR_AES_CBC_192, 24, 16, 16, GCRY_CIPHER_AES192, GCRY_CIPHER_MODE_CBC},
  {IKEV2_ENCR_AES_CBC_256, 32, 16, 16, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC}, 
  {0, 0, 0, 0, 0, 0}
};

/*
 * Specifications of authentication algorithms for 
 * decryption and/or ICD (Integrity Checksum Data) checking of IKEv2
 */
typedef struct _ikev2_auth_alg_spec {
  guint number;
  /* Output length of the hash algorithm */
  guint output_len;
  /* Length of the hash key */
  guint key_len;
  /* Actual ICD length after truncation */
  guint trunc_len;
  /* Hash algorithm ID to be passed to gcry_md_open() */
  gint gcry_alg;
  /* Flags to be passed to gcry_md_open() */
  guint gcry_flag;
} ikev2_auth_alg_spec_t;

#define IKEV2_AUTH_NONE 1
#define IKEV2_AUTH_HMAC_MD5_96 2
#define IKEV2_AUTH_HMAC_SHA1_96 3
#define IKEV2_AUTH_ANY_96BITS 4
#define IKEV2_AUTH_ANY_128BITS 5
#define IKEV2_AUTH_ANY_160BITS 6
#define IKEV2_AUTH_ANY_192BITS 7
#define IKEV2_AUTH_ANY_256BITS 8

static ikev2_auth_alg_spec_t ikev2_auth_algs[] = {
  {IKEV2_AUTH_NONE, 0, 0, 0, GCRY_MD_NONE, 0},
  {IKEV2_AUTH_HMAC_MD5_96, 16, 16, 12, GCRY_MD_MD5, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_HMAC_SHA1_96, 20, 20, 12, GCRY_MD_SHA1, GCRY_MD_FLAG_HMAC},
  {IKEV2_AUTH_ANY_96BITS, 0, 0, 12, 0, 0},
  {IKEV2_AUTH_ANY_128BITS, 0, 0, 16, 0, 0},
  {IKEV2_AUTH_ANY_160BITS, 0, 0, 20, 0, 0},
  {IKEV2_AUTH_ANY_192BITS, 0, 0, 24, 0, 0},
  {IKEV2_AUTH_ANY_256BITS, 0, 0, 32, 0, 0},
  {0, 0, 0, 0, 0, 0}
};

typedef struct _ikev2_decrypt_data {
  guchar *encr_key;
  guchar *auth_key;
  ikev2_encr_alg_spec_t *encr_spec;
  ikev2_auth_alg_spec_t *auth_spec;
} ikev2_decrypt_data_t;

typedef struct _ikev2_uat_data_key {
  guchar *spii;
  guint spii_len;
  guchar *spir;
  guint spir_len;
} ikev2_uat_data_key_t; 

typedef struct _ikev2_uat_data {
  ikev2_uat_data_key_t key;
  guint encr_alg;
  guint auth_alg;
  guchar *sk_ei;
  guint sk_ei_len;
  guchar *sk_er;
  guint sk_er_len;
  guchar *sk_ai;
  guint sk_ai_len;
  guchar *sk_ar;
  guint sk_ar_len;
  ikev2_encr_alg_spec_t *encr_spec;
  ikev2_auth_alg_spec_t *auth_spec;
} ikev2_uat_data_t;

static ikev2_uat_data_t* ikev2_uat_data = NULL;
static guint num_ikev2_uat_data = 0;
static uat_t* ikev2_uat;

static GHashTable *ikev2_key_hash = NULL;

static const value_string vs_ikev2_encr_algs[] = {
  {IKEV2_ENCR_3DES, "3DES [RFC2451]"},
  {IKEV2_ENCR_AES_CBC_128, "AES-CBC-128 [RFC3602]"},
  {IKEV2_ENCR_AES_CBC_192, "AES-CBC-192 [RFC3602]"},
  {IKEV2_ENCR_AES_CBC_256, "AES-CBC-256 [RFC3602]"},
  {IKEV2_ENCR_NULL, "NULL [RFC2410]"},
  {0, NULL}
};

static const value_string vs_ikev2_auth_algs[] = {
  {IKEV2_AUTH_HMAC_MD5_96, "HMAC_MD5_96 [RFC2403]"},
  {IKEV2_AUTH_HMAC_SHA1_96, "HMAC_SHA1_96 [RFC2404]"},
  {IKEV2_AUTH_NONE, "NONE [RFC4306]"},
  {IKEV2_AUTH_ANY_96BITS, "ANY 96-bits of Authentication [No Checking]"},
  {IKEV2_AUTH_ANY_128BITS, "ANY 128-bits of Authentication [No Checking]"},
  {IKEV2_AUTH_ANY_160BITS, "ANY 160-bits of Authentication [No Checking]"},
  {IKEV2_AUTH_ANY_192BITS, "ANY 192-bits of Authentication [No Checking]"},
  {IKEV2_AUTH_ANY_256BITS, "ANY 256-bits of Authentication [No Checking]"},
  {0, NULL}
};

ikev2_encr_alg_spec_t* ikev2_decrypt_find_encr_spec(guint num) {
  ikev2_encr_alg_spec_t *e;

  for (e = ikev2_encr_algs; e->number != 0; e++) {
    if (e->number == num) {
      return e;
    }
  }
  return NULL;
}

ikev2_auth_alg_spec_t* ikev2_decrypt_find_auth_spec(guint num) {
  ikev2_auth_alg_spec_t *a;

  for (a = ikev2_auth_algs; a->number != 0; a++) {
    if (a->number == num) {
      return a;
    }
  }
  return NULL;
}

static void
scan_pluto_log(void) {
#define MAX_PLUTO_LINE 500
  decrypt_data_t *decr;
  gchar    line[MAX_PLUTO_LINE];
  guint8   i_cookie[COOKIE_SIZE], *ic_key;
  gboolean got_cookie = FALSE;
  guchar   secret[MAX_KEY_SIZE];
  guint    secret_len = 0;
  gchar   *icookie_pfx = "| ICOOKIE: ";
  gchar   *enc_key_pfx = "| enc key: ";
  gchar   *pos, *endpos;
  gint     icpfx_len = strlen(icookie_pfx);
  gint     ec_len = strlen(enc_key_pfx);
  gint     i;
  address  null_addr;
  unsigned long hexval;

  SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

  if (logf) {
    while (fgets(line, MAX_PLUTO_LINE, logf)) {
      if (strncmp(line, icookie_pfx, icpfx_len) == 0) {
        secret_len = 0;
	pos = line + icpfx_len;
	for (i = 0; i < COOKIE_SIZE; i++) {
	  hexval = strtoul(pos, &endpos, 16);
	  if (endpos == pos)
	    break;
	  i_cookie[i] = (guint8) hexval;
	  pos = endpos;
        }
        if (i == COOKIE_SIZE)
          got_cookie = TRUE;
      } else if (strncmp(line, enc_key_pfx, ec_len) == 0) {
	pos = line + ec_len;
	for (; secret_len < MAX_KEY_SIZE; secret_len++) {
	  hexval = strtoul(pos, &endpos, 16);
	  if (endpos == pos)
	    break;
	  secret[secret_len] = (guint8) hexval;
	  pos = endpos;
        }
      } else if (got_cookie && secret_len > 1) {
        decr = (decrypt_data_t*) g_hash_table_lookup(isakmp_hash, i_cookie);

        if (! decr) {
	  ic_key = g_mem_chunk_alloc(isakmp_key_data);
	  memcpy(ic_key, i_cookie, COOKIE_SIZE);
          decr = g_mem_chunk_alloc(isakmp_decrypt_data);
          memset(decr, 0, sizeof(decrypt_data_t));

          g_hash_table_insert(isakmp_hash, ic_key, decr);
        }

        memcpy(decr->secret, secret, secret_len);
        decr->secret_len = secret_len;
      }
    }
  }
}

static void
set_transform_vals(decrypt_data_t *decr, int ike_p1, guint16 type, guint32 val) {
  if (! ike_p1)
    return;

  if (decr != NULL) {
    switch (type) {
      case 1:
        decr->encr_alg = val;
        break;
      case 2:
        decr->hash_alg = val;
        break;
      case 3:
        if (val == 1)
          decr->is_psk = TRUE;
        break;
      case 4:
        decr->group = val;
        break;
    }
  }
}

static tvbuff_t *
decrypt_payload(tvbuff_t *tvb, packet_info *pinfo, const guint8 *buf, guint buf_len, isakmp_hdr_t *hdr) {
  decrypt_data_t *decr = (decrypt_data_t *) pinfo->private_data;
  gchar *decrypted_data = NULL;
  gint gcry_md_algo, gcry_cipher_algo;
  gcry_md_hd_t md_ctx;
  gcry_cipher_hd_t decr_ctx;
  tvbuff_t *encr_tvb;
  iv_data_t *ivd = NULL;
  GList *ivl;
  guchar iv[MAX_DIGEST_SIZE];
  guint iv_len = 0;
  guint32 message_id, cbc_block_size, digest_size;

  if (!decr ||
  	decr->is_psk == FALSE ||
  	decr->gi_len == 0 ||
  	decr->gr_len == 0)
    return NULL;

  switch(decr->encr_alg) {
    case ENC_3DES_CBC:
      gcry_cipher_algo = GCRY_CIPHER_3DES;
      break;
    case ENC_DES_CBC:
      gcry_cipher_algo = GCRY_CIPHER_DES;
      break;
    default:
      return NULL;
      break;
  }
  if (decr->secret_len < gcry_cipher_get_algo_keylen(gcry_cipher_algo))
    return NULL;
  cbc_block_size = gcry_cipher_get_algo_blklen(gcry_cipher_algo);

  switch(decr->hash_alg) {
    case HMAC_MD5:
      gcry_md_algo = GCRY_MD_MD5;
      break;
    case HMAC_SHA:
      gcry_md_algo = GCRY_MD_SHA1;
      break;
    default:
      return NULL;
      break;
  }
  digest_size = gcry_md_get_algo_dlen(gcry_md_algo);

  for (ivl = g_list_first(decr->iv_list); ivl != NULL; ivl = g_list_next(ivl)) {
    ivd = (iv_data_t *) ivl->data;
    if (ivd->frame_num == pinfo->fd->num) {
      iv_len = ivd->iv_len;
      memcpy(iv, ivd->iv, iv_len);
    }
  }

  /*
   * Set our initialization vector as follows:
   * - If the IV list is empty, assume we have the first packet in a phase 1
   *   exchange.  The IV is built from DH values.
   * - If our message ID changes, assume we're entering a new mode.  The IV
   *   is built from the message ID and the last phase 1 CBC.
   * - Otherwise, use the last CBC.
   */
  if (iv_len == 0) {
    if (gcry_md_open(&md_ctx, gcry_md_algo, 0) != GPG_ERR_NO_ERROR)
      return NULL;
    if (decr->iv_list == NULL) {
      /* First packet */
      ivd = g_malloc(sizeof(iv_data_t));
      ivd->frame_num = pinfo->fd->num;
      ivd->iv_len = digest_size;
      decr->last_message_id = hdr->message_id;
      gcry_md_reset(md_ctx);
      gcry_md_write(md_ctx, decr->gi, decr->gi_len);
      gcry_md_write(md_ctx, decr->gr, decr->gr_len);
      gcry_md_final(md_ctx);
      memcpy(ivd->iv, gcry_md_read(md_ctx, gcry_md_algo), digest_size);
      decr->iv_list = g_list_append(decr->iv_list, ivd);
      iv_len = ivd->iv_len;
      memcpy(iv, ivd->iv, iv_len);
    } else if (decr->last_cbc_len >= cbc_block_size) {
      ivd = g_malloc(sizeof(iv_data_t));
      ivd->frame_num = pinfo->fd->num;
      if (hdr->message_id != decr->last_message_id) {
	if (decr->last_p1_cbc_len == 0) {
	  memcpy(decr->last_p1_cbc, decr->last_cbc, cbc_block_size);
	  decr->last_p1_cbc_len = cbc_block_size;
        }
        ivd->iv_len = digest_size;
	decr->last_message_id = hdr->message_id;
	message_id = g_htonl(decr->last_message_id);
        gcry_md_reset(md_ctx);
        gcry_md_write(md_ctx, decr->last_p1_cbc, cbc_block_size);
        gcry_md_write(md_ctx, &message_id, sizeof(message_id));
        memcpy(ivd->iv, gcry_md_read(md_ctx, gcry_md_algo), digest_size);
      } else {
        ivd->iv_len = cbc_block_size;
        memcpy(ivd->iv, decr->last_cbc, ivd->iv_len);
      }
      decr->iv_list = g_list_append(decr->iv_list, ivd);
      iv_len = ivd->iv_len;
      memcpy(iv, ivd->iv, iv_len);
    }
    gcry_md_close(md_ctx);
  }

  if (ivd == NULL) return NULL;

  if (gcry_cipher_open(&decr_ctx, gcry_cipher_algo, GCRY_CIPHER_MODE_CBC, 0) != GPG_ERR_NO_ERROR)
    return NULL;
  if (iv_len > cbc_block_size)
      iv_len = cbc_block_size; /* gcry warns otherwise */
  if (gcry_cipher_setiv(decr_ctx, iv, iv_len))
    return NULL;
  if (gcry_cipher_setkey(decr_ctx, decr->secret, decr->secret_len))
    return NULL;
      
  decrypted_data = g_malloc(buf_len);

  if (gcry_cipher_decrypt(decr_ctx, decrypted_data, buf_len, buf, buf_len) != GPG_ERR_NO_ERROR) {
      g_free(decrypted_data);
      return NULL;
  }
  gcry_cipher_close(decr_ctx);

  encr_tvb = tvb_new_child_real_data(tvb, decrypted_data, buf_len, buf_len);

  /* Add the decrypted data to the data source list. */
  add_new_data_source(pinfo, encr_tvb, "Decrypted IKE");

  /* Fill in the next IV */
  if (tvb_length(tvb) > cbc_block_size) {
    decr->last_cbc_len = cbc_block_size;
    memcpy(decr->last_cbc, buf + buf_len - cbc_block_size, cbc_block_size);
  } else {
    decr->last_cbc_len = 0;
  }

  return encr_tvb;
}

#endif /* HAVE_LIBGCRYPT */

static const char* vid_to_str(tvbuff_t *, int, int);
static proto_tree *dissect_payload_header(tvbuff_t *, int, int, int, guint8,
    guint8 *, guint16 *, proto_tree *);

static void dissect_sa(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_proposal(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_transform(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_transform2(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_key_exch(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_id(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_cert(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_certreq_v1(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_certreq_v2(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_hash(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_auth(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_sig(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_nonce(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_notif(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_delete(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_vid(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_config(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_nat_discovery(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_nat_original_address(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_ts(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_enc(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_eap(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);
static void dissect_cisco_fragmentation(tvbuff_t *, int, int, proto_tree *,
    proto_tree *, packet_info *, int, int, guint8);

static const char *payloadtype2str(int, guint8);
static const char *exchtype2str(int, guint8);
static const char *doitype2str(guint32);
static const char *msgtype2str(int, guint16);
static const char *situation2str(guint32);
static const char *v1_attrval2str(int, guint16, guint32);
static const char *v2_attrval2str(guint16, guint32);
static const char *cfgtype2str(int, guint8);
static const char *cfgattr2str(int, guint16);
static const char *id2str(int, guint8);
static const char *v2_tstype2str(guint8);
static const char *v2_auth2str(guint8);
static const char *certtype2str(int, guint8);

static gboolean get_num(tvbuff_t *, int, guint16, guint32 *);

#define LOAD_TYPE_NONE		0	/* payload type for None */
#define LOAD_TYPE_PROPOSAL	2	/* payload type for Proposal */
#define	LOAD_TYPE_TRANSFORM	3	/* payload type for Transform */

struct payload_func {
  guint8 type;
  const char *	str;
  void (*func)(tvbuff_t *, int, int, proto_tree *, proto_tree *, packet_info *,
		int, int, guint8);
};

static struct payload_func v1_plfunc[] = {
  {  0, "NONE",			NULL              },
  {  1, "Security Association",	dissect_sa        },
  {  2, "Proposal",		dissect_proposal  },
  {  3, "Transform",		dissect_transform },
  {  4, "Key Exchange",		dissect_key_exch  },
  {  5, "Identification",	dissect_id        },
  {  6, "Certificate",		dissect_cert      },
  {  7, "Certificate Request",	dissect_certreq_v1},
  {  8, "Hash",			dissect_hash      },
  {  9, "Signature",		dissect_sig       },
  { 10, "Nonce",		dissect_nonce     },
  { 11, "Notification",		dissect_notif     },
  { 12, "Delete",		dissect_delete    },
  { 13, "Vendor ID",		dissect_vid       },
  { 14, "Attrib",		dissect_config	  },
  { 15, "NAT-Discovery",	dissect_nat_discovery }, /* draft-ietf-ipsec-nat-t-ike-04 */
  { 16, "NAT-Original Address",	dissect_nat_original_address }, /* draft-ietf-ipsec-nat-t-ike */
  { 20, "NAT-D (RFC 3947)",	dissect_nat_discovery },
  { 21, "NAT-OA (RFC 3947)",	dissect_nat_original_address },
  { 130, "NAT-D (draft-ietf-ipsec-nat-t-ike-01 to 03)",		dissect_nat_discovery },
  { 131, "NAT-OA (draft-ietf-ipsec-nat-t-ike-01 to 04)",	dissect_nat_original_address },
  { 132, "Cisco-Fragmentation",	dissect_cisco_fragmentation },
};

static struct payload_func v2_plfunc[] = {
  {  0, "NONE",			NULL },
  {  2, "Proposal",		dissect_proposal  },
  {  3, "Transform",		dissect_transform2 },
  { 33, "Security Association",	dissect_sa        },
  { 34, "Key Exchange",		dissect_key_exch  },
  { 35, "Identification - I",	dissect_id        },
  { 36, "Identification - R",	dissect_id        },
  { 37, "Certificate",		dissect_cert      },
  { 38, "Certificate Request",	dissect_certreq_v2},
  { 39, "Authentication",	dissect_auth      },
  { 40, "Nonce",		dissect_nonce     },
  { 41, "Notification",		dissect_notif     },
  { 42, "Delete",		dissect_delete    },
  { 43, "Vendor ID",		dissect_vid       },
  { 44, "Traffic Selector - I",	dissect_ts       },
  { 45, "Traffic Selector - R",	dissect_ts       },
  { 46, "Encrypted",		dissect_enc       },
  { 47, "Configuration",	dissect_config	  },
  { 48, "Extensible Authentication",	dissect_eap	  },
};

static struct payload_func * getpayload_func(guint8, int);

#define VID_LEN 16
#define VID_MS_LEN 20
#define VID_CISCO_FRAG_LEN 20

static const guint8 VID_CISCO_FRAG[VID_CISCO_FRAG_LEN] = {0x40, 0x48, 0xB7, 0xD5, 0x6E, 0xBC, 0xE8, 0x85, 0x25, 0xE7, 0xDE, 0x7F, 0x00, 0xD6, 0xC2, 0xD3, 0x80, 0x00, 0x00, 0x00};

static const guint8 VID_MS_W2K_WXP[VID_MS_LEN] = {0x1E, 0x2B, 0x51, 0x69, 0x5, 0x99, 0x1C, 0x7D, 0x7C, 0x96, 0xFC, 0xBF, 0xB5, 0x87, 0xE4, 0x61, 0x0, 0x0, 0x0, 0x2}; /* according to http://www.microsoft.com/technet/treeview/default.asp?url=/technet/columns/cableguy/cg0602.asp */

#define VID_CP_LEN 20
static const guint8 VID_CP[VID_CP_LEN] = {0xF4, 0xED, 0x19, 0xE0, 0xC1, 0x14, 0xEB, 0x51, 0x6F, 0xAA, 0xAC, 0x0E, 0xE3, 0x7D, 0xAF, 0x28, 0x7, 0xB4, 0x38, 0x1F};

static const guint8 VID_CYBERGUARD[VID_LEN] = {0x9A, 0xA1, 0xF3, 0xB4, 0x34, 0x72, 0xA4, 0x5D, 0x5F, 0x50, 0x6A, 0xEB, 0x26, 0xC, 0xF2, 0x14};

static const guint8 VID_rfc3947[VID_LEN] = {0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f}; /* RFC 3947 Negotiation of NAT-Traversal in the IKE*/

static const guint8 VID_SSH_IPSEC_EXPRESS_1_1_0[VID_LEN] = {0xfB, 0xF4, 0x76, 0x14, 0x98, 0x40, 0x31, 0xFA, 0x8E, 0x3B, 0xB6, 0x19, 0x80, 0x89, 0xB2, 0x23}; /* Ssh Communications Security IPSEC Express version 1.1.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_1_1_1[VID_LEN] = {0x19, 0x52, 0xDC, 0x91, 0xAC, 0x20, 0xF6, 0x46, 0xFB, 0x01, 0xCF, 0x42, 0xA3, 0x3A, 0xEE, 0x30}; /* Ssh Communications Security IPSEC Express version 1.1.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_1_1_2[VID_LEN] = {0xE8, 0xBF, 0xFA, 0x64, 0x3E, 0x5C, 0x8F, 0x2C, 0xD1, 0x0F, 0xDA, 0x73, 0x70, 0xB6, 0xEB, 0xE5}; /* Ssh Communications Security IPSEC Express version 1.1.2 */

static const guint8 VID_SSH_IPSEC_EXPRESS_1_2_1[VID_LEN] = {0xC1, 0x11, 0x1B, 0x2D, 0xEE, 0x8C, 0xBC, 0x3D, 0x62, 0x05, 0x73, 0xEC, 0x57, 0xAA, 0xB9, 0xCB}; /* Ssh Communications Security IPSEC Express version 1.2.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_1_2_2[VID_LEN] = {0x09, 0xEC, 0x27, 0xBF, 0xBC, 0x09, 0xC7, 0x58, 0x23, 0xCF, 0xEC, 0xBF, 0xFE, 0x56, 0x5A, 0x2E}; /* Ssh Communications Security IPSEC Express version 1.2.2 */

static const guint8 VID_SSH_IPSEC_EXPRESS_2_0_0[VID_LEN] = {0x7F, 0x21, 0xA5, 0x96, 0xE4, 0xE3, 0x18, 0xF0, 0xB2, 0xF4, 0x94, 0x4C, 0x23, 0x84, 0xCB, 0x84};  /* SSH Communications Security IPSEC Express version 2.0.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_2_1_0[VID_LEN] = {0x28, 0x36, 0xD1, 0xFD, 0x28, 0x07, 0xBC, 0x9E, 0x5A, 0xE3, 0x07, 0x86, 0x32, 0x04, 0x51, 0xEC}; /* SSH Communications Security IPSEC Express version 2.1.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_2_1_1[VID_LEN] = {0xA6, 0x8D, 0xE7, 0x56, 0xA9, 0xC5, 0x22, 0x9B, 0xAE, 0x66, 0x49, 0x80, 0x40, 0x95, 0x1A, 0xD5}; /* SSH Communications Security IPSEC Express version 2.1.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_2_1_2[VID_LEN] = {0x3F, 0x23, 0x72, 0x86, 0x7E, 0x23, 0x7C, 0x1C, 0xD8, 0x25, 0x0A, 0x75, 0x55, 0x9C, 0xAE, 0x20}; /* SSH Communications Security IPSEC Express version 2.1.2 */

static const guint8 VID_SSH_IPSEC_EXPRESS_3_0_0[VID_LEN] = {0x0E, 0x58, 0xD5, 0x77, 0x4D, 0xF6, 0x02, 0x00, 0x7D, 0x0B, 0x02, 0x44, 0x36, 0x60, 0xF7, 0xEB}; /* SSH Communications Security IPSEC Express version 3.0.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_3_0_1[VID_LEN] = {0xF5, 0xCE, 0x31, 0xEB, 0xC2, 0x10, 0xF4, 0x43, 0x50, 0xCF, 0x71, 0x26, 0x5B, 0x57, 0x38, 0x0F}; /* SSH Communications Security IPSEC Express version 3.0.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_4_0_0[VID_LEN] = {0xF6, 0x42, 0x60, 0xAF, 0x2E, 0x27, 0x42, 0xDA, 0xDD, 0xD5, 0x69, 0x87, 0x06, 0x8A, 0x99, 0xA0}; /* SSH Communications Security IPSEC Express version 4.0.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_4_0_1[VID_LEN] = {0x7A, 0x54, 0xD3, 0xBD, 0xB3, 0xB1, 0xE6, 0xD9, 0x23, 0x89, 0x20, 0x64, 0xBE, 0x2D, 0x98, 0x1C}; /* SSH Communications Security IPSEC Express version 4.0.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_4_1_0[VID_LEN] = {0x9A, 0xA1, 0xF3, 0xB4, 0x34, 0x72, 0xA4, 0x5D, 0x5F, 0x50, 0x6A, 0xEB, 0x26, 0x0C, 0xF2, 0x14}; /* SSH Communications Security IPSEC Express version 4.1.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_4_1_1[VID_LEN] = {0x89, 0xF7, 0xB7, 0x60, 0xD8, 0x6B, 0x01, 0x2A, 0xCF, 0x26, 0x33, 0x82, 0x39, 0x4D, 0x96, 0x2F}; /* SSH Communications Security IPSEC Express version 4.1.1 */

static const guint8 VID_SSH_IPSEC_EXPRESS_5_0[VID_LEN] = {0xB0, 0x37, 0xA2, 0x1A, 0xCE, 0xCC, 0xB5, 0x57, 0x0F, 0x60, 0x25, 0x46, 0xF9, 0x7B, 0xDE, 0x8C}; /* SSH Communications Security IPSEC Express version 5.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_5_0_0[VID_LEN] = {0x2B, 0x2D, 0xAD, 0x97, 0xC4, 0xD1, 0x40, 0x93, 0x00, 0x53, 0x28, 0x7F, 0x99, 0x68, 0x50, 0xB0}; /* SSH Communications Security IPSEC Express version 5.0.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_5_1_0[VID_LEN] = {0x45, 0xE1, 0x7F, 0x3A, 0xBE, 0x93, 0x94, 0x4C, 0xB2, 0x02, 0x91, 0x0C, 0x59, 0xEF, 0x80, 0x6B}; /* SSH Communications Security IPSEC Express version 5.1.0 */

static const guint8 VID_SSH_IPSEC_EXPRESS_5_1_1[VID_LEN] = {0x59, 0x25, 0x85, 0x9F, 0x73, 0x77, 0xED, 0x78, 0x16, 0xD2, 0xFB, 0x81, 0xC0, 0x1F, 0xA5, 0x51}; /* SSH Communications Security IPSEC Express version 5.1.1 */

static const guint8 VID_SSH_SENTINEL[VID_LEN] = {0x05, 0x41, 0x82, 0xA0, 0x7C, 0x7A, 0xE2, 0x06, 0xF9, 0xD2, 0xCF, 0x9D, 0x24, 0x32, 0xC4, 0x82}; /* SSH Sentinel */

static const guint8 VID_SSH_SENTINEL_1_1[VID_LEN] = {0xB9, 0x16, 0x23, 0xE6, 0x93, 0xCA, 0x18, 0xA5, 0x4C, 0x6A, 0x27, 0x78, 0x55, 0x23, 0x05, 0xE8}; /* SSH Sentinel 1.1 */

static const guint8 VID_SSH_SENTINEL_1_2[VID_LEN] = {0x54, 0x30, 0x88, 0x8D, 0xE0, 0x1A, 0x31, 0xA6, 0xFA, 0x8F, 0x60, 0x22, 0x4E, 0x44, 0x99, 0x58}; /* SSH Sentinel 1.2 */

static const guint8 VID_SSH_SENTINEL_1_3[VID_LEN] = {0x7E, 0xE5, 0xCB, 0x85, 0xF7, 0x1C, 0xE2, 0x59, 0xC9, 0x4A, 0x5C, 0x73, 0x1E, 0xE4, 0xE7, 0x52}; /* SSH Sentinel 1.3 */

static const guint8 VID_SSH_QUICKSEC_0_9_0[VID_LEN] = {0x37, 0xEB, 0xA0, 0xC4, 0x13, 0x61, 0x84, 0xE7, 0xDA, 0xF8, 0x56, 0x2A, 0x77, 0x06, 0x0B, 0x4A}; /* SSH Communications Security QuickSec 0.9.0 */

static const guint8 VID_SSH_QUICKSEC_1_1_0[VID_LEN] = {0x5D, 0x72, 0x92, 0x5E, 0x55, 0x94, 0x8A, 0x96, 0x61, 0xA7, 0xFC, 0x48, 0xFD, 0xEC, 0x7F, 0xF9}; /* SSH Communications Security QuickSec 1.1.0 */

static const guint8 VID_SSH_QUICKSEC_1_1_1[VID_LEN] = {0x77, 0x7F, 0xBF, 0x4C, 0x5A, 0xF6, 0xD1, 0xCD, 0xD4, 0xB8, 0x95, 0xA0, 0x5B, 0xF8, 0x25, 0x94}; /* SSH Communications Security QuickSec 1.1.1 */

static const guint8 VID_SSH_QUICKSEC_1_1_2[VID_LEN] = {0x2C, 0xDF, 0x08, 0xE7, 0x12, 0xED, 0xE8, 0xA5, 0x97, 0x87, 0x61, 0x26, 0x7C, 0xD1, 0x9B, 0x91}; /* SSH Communications Security QuickSec 1.1.2 */

static const guint8 VID_SSH_QUICKSEC_1_1_3[VID_LEN] = {0x59, 0xE4, 0x54, 0xA8, 0xC2, 0xCF, 0x02, 0xA3, 0x49, 0x59, 0x12, 0x1F, 0x18, 0x90, 0xBC, 0x87}; /* SSH Communications Security QuickSec 1.1.3 */

static const guint8 VID_draft_huttunen_ipsec_esp_in_udp_01[VID_LEN] = {0x50, 0x76, 0x0F, 0x62, 0x4C, 0x63, 0xE5, 0xC5, 0x3E, 0xEA, 0x38, 0x6C, 0x68, 0x5C, 0xA0, 0x83}; /* draft-huttunen-ipsec-esp-in-udp-01.txt */

static const guint8 VID_draft_stenberg_ipsec_nat_traversal_01[VID_LEN] = {0x27, 0xBA, 0xB5, 0xDC, 0x01, 0xEA, 0x07, 0x60, 0xEA, 0x4E, 0x31, 0x90, 0xAC, 0x27, 0xC0, 0xD0}; /* draft-stenberg-ipsec-nat-traversal-01 */

static const guint8 VID_draft_stenberg_ipsec_nat_traversal_02[VID_LEN]= {0x61, 0x05, 0xC4, 0x22, 0xE7, 0x68, 0x47, 0xE4, 0x3F, 0x96, 0x84, 0x80, 0x12, 0x92, 0xAE, 0xCD}; /* draft-stenberg-ipsec-nat-traversal-02 */

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_00[VID_LEN]= {0x44, 0x85, 0x15, 0x2D, 0x18, 0xB6, 0xBB, 0xCD, 0x0B, 0xE8, 0xA8, 0x46, 0x95, 0x79, 0xDD, 0xCC}; /* draft-ietf-ipsec-nat-t-ike-00 */

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_01[VID_LEN]= {0x16, 0xf6, 0xca, 0x16, 0xe4, 0xa4, 0x06, 0x6d, 0x83, 0x82, 0x1a, 0x0f, 0x0a, 0xea, 0xa8, 0x62 }; /* "draft-ietf-ipsec-nat-t-ike-01" */

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_02a[VID_LEN]= {0xCD, 0x60, 0x46, 0x43, 0x35, 0xDF, 0x21, 0xF8, 0x7C, 0xFD, 0xB2, 0xFC, 0x68, 0xB6, 0xA4, 0x48}; /* draft-ietf-ipsec-nat-t-ike-02 */

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_02b[VID_LEN]= {0x90, 0xCB, 0x80, 0x91, 0x3E, 0xBB, 0x69, 0x6E, 0x08, 0x63, 0x81, 0xB5, 0xEC, 0x42, 0x7B, 0x1F}; /* draft-ietf-ipsec-nat-t-ike-02 */

static const guint8 VID_draft_ietf_ipsec_nat_t_ike_03[VID_LEN] = {0x7D, 0x94, 0x19, 0xA6, 0x53, 0x10, 0xCA, 0x6F, 0x2C, 0x17, 0x9D, 0x92, 0x15, 0x52, 0x9d, 0x56}; /* according to http://www.ietf.org/internet-drafts/draft-ietf-ipsec-nat-t-ike-03.txt */

static const guint8 VID_draft_beaulieu_ike_xauth_02[VID_LEN]= {0x09, 0x00, 0x26, 0x89, 0xDF, 0xD6, 0xB7, 0x12, 0x80, 0xA2, 0x24, 0xDE, 0xC3, 0x3B, 0x81, 0xE5}; /* draft-beaulieu-ike-xauth-02.txt */


static const guint8 VID_rfc3706_dpd[VID_LEN]= {0xAF, 0xCA,0xD7, 0x13, 0x68, 0xA1, 0xF1, 0xC9, 0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57, 0x01, 0x00}; /* RFC 3706 */

static const guint8 VID_IKE_CHALLENGE_RESPONSE_1[VID_LEN]= {0xBA, 0x29, 0x04, 0x99, 0xC2, 0x4E, 0x84, 0xE5, 0x3A, 0x1D, 0x83, 0xA0, 0x5E, 0x5F, 0x00, 0xC9}; /* IKE Challenge/Response for Authenticated Cryptographic Keys */

static const guint8 VID_IKE_CHALLENGE_RESPONSE_2[VID_LEN]= {0x0D, 0x33, 0x61, 0x1A, 0x5D, 0x52, 0x1B, 0x5E, 0x3C, 0x9C, 0x03, 0xD2, 0xFC, 0x10, 0x7E, 0x12}; /* IKE Challenge/Response for Authenticated Cryptographic Keys */

static const guint8 VID_IKE_CHALLENGE_RESPONSE_REV_1[VID_LEN]= {0xAD, 0x32, 0x51, 0x04, 0x2C, 0xDC, 0x46, 0x52, 0xC9, 0xE0, 0x73, 0x4C, 0xE5, 0xDE, 0x4C, 0x7D}; /* IKE Challenge/Response for Authenticated Cryptographic Keys (Revised) */

static const guint8 VID_IKE_CHALLENGE_RESPONSE_REV_2[VID_LEN]= {0x01, 0x3F, 0x11, 0x82, 0x3F, 0x96, 0x6F, 0xA9, 0x19, 0x00, 0xF0, 0x24, 0xBA, 0x66, 0xA8, 0x6B}; /* IKE Challenge/Response for Authenticated Cryptographic Keys (Revised) */

static const guint8 VID_MS_L2TP_IPSEC_VPN_CLIENT[VID_LEN]= {0x40, 0x48, 0xB7, 0xD5, 0x6E, 0xBC, 0xE8, 0x85, 0x25, 0xE7, 0xDE, 0x7F, 0x00, 0xD6, 0xC2, 0xD3}; /* Microsoft L2TP/IPSec VPN Client */

static const guint8 VID_GSS_API_1[VID_LEN]= {0xB4, 0x6D, 0x89, 0x14, 0xF3, 0xAA, 0xA3, 0xF2, 0xFE, 0xDE, 0xB7, 0xC7, 0xDB, 0x29, 0x43, 0xCA}; /* A GSS-API Authentication Method for IKE */

static const guint8 VID_GSS_API_2[VID_LEN]= {0xAD, 0x2C, 0x0D, 0xD0, 0xB9, 0xC3, 0x20, 0x83, 0xCC, 0xBA, 0x25, 0xB8, 0x86, 0x1E, 0xC4, 0x55}; /* A GSS-API Authentication Method for IKE */

static const guint8 VID_GSSAPI[VID_LEN]= {0x62, 0x1B, 0x04, 0xBB, 0x09, 0x88, 0x2A, 0xC1, 0xE1, 0x59, 0x35, 0xFE, 0xFA, 0x24, 0xAE, 0xEE}; /* GSSAPI */

static const guint8 VID_MS_NT5_ISAKMPOAKLEY[VID_LEN]= {0x1E, 0x2B, 0x51, 0x69, 0x05, 0x99, 0x1C, 0x7D, 0x7C, 0x96, 0xFC, 0xBF, 0xB5, 0x87, 0xE4, 0x61}; /* MS NT5 ISAKMPOAKLEY */

static const guint8 VID_CISCO_UNITY[VID_LEN]= {0x12, 0xF5, 0xF2, 0x8C, 0x45, 0x71, 0x68, 0xA9, 0x70, 0x2D, 0x9F, 0xE2, 0x74, 0xCC, 0x02, 0xD4}; /* CISCO-UNITY */

static const guint8 VID_CISCO_UNITY_10[VID_LEN]= {0x12, 0xF5, 0xF2, 0x8C, 0x45, 0x71, 0x68, 0xA9, 0x70, 0x2D, 0x9F, 0xE2, 0x74, 0xCC, 0x01, 0x00}; /* CISCO-UNITY 1.0 */

static const guint8 VID_CISCO_CONCENTRATOR[VID_LEN]= {0x1F, 0x07, 0xF7, 0x0E, 0xAA, 0x65, 0x14, 0xD3, 0xB0, 0xFA, 0x96, 0x54, 0x2A, 0x50, 0x01, 0x00}; /* CISCO-CONCENTRATOR */

#define VID_LEN_8 8
static const guint8 VID_draft_ietf_ipsec_antireplay_00[VID_LEN_8]= {0x32, 0x5D, 0xF2, 0x9A, 0x23, 0x19, 0xF2, 0xDD}; /* draft-ietf-ipsec-antireplay-00.txt */

static const guint8 VID_draft_ietf_ipsec_heartbeats_00[VID_LEN_8]= {0x8D, 0xB7, 0xA4, 0x18, 0x11, 0x22, 0x16, 0x60}; /* draft-ietf-ipsec-heartbeats-00.txt */

/*
*  Seen in Netscreen. Suppose to be ASCII HeartBeat_Notify - but I don't know the rest yet. I suspect it then proceeds with
*  8k10, which means every 8K (?), and version 1.0 of the protocol (?). I won't add it to the code, until I know what it really
*  means. ykaul-at-bezeqint.net
*/
static const guint8 VID_HeartBeat_Notify[VID_LEN] _U_ = {0x48, 0x65, 0x61, 0x72, 0x74, 0x42, 0x65, 0x61, 0x74, 0x5f, 0x4e, 0x6f, 0x74, 0x69, 0x66, 0x79};

static void
dissect_payloads(tvbuff_t *tvb, proto_tree *tree, proto_tree *parent_tree,
		int isakmp_version, guint8 initial_payload, int offset, int length,
		packet_info *pinfo)
{
  guint8 payload, next_payload;
  guint16		payload_length;
  proto_tree *		ntree;
  struct payload_func *	f;

  for (payload = initial_payload; length > 0; payload = next_payload) {
    if (payload == LOAD_TYPE_NONE) {
      /*
       * What?  There's more stuff in this chunk of data, but the
       * previous payload had a "next payload" type of None?
       */
      proto_tree_add_text(tree, tvb, offset, length,
			  "Extra data: %s",
			  tvb_bytes_to_str(tvb, offset, length));
      break;
    }
    ntree = dissect_payload_header(tvb, offset, length, isakmp_version,
      payload, &next_payload, &payload_length, tree);
    if (ntree == NULL)
      break;
    if (payload_length >= 4) {	/* XXX = > 4? */
      tvb_ensure_bytes_exist(tvb, offset + 4, payload_length - 4);
      if ((f = getpayload_func(payload, isakmp_version)) != NULL && f->func != NULL)
        (*f->func)(tvb, offset + 4, payload_length - 4, ntree, parent_tree,
		pinfo, isakmp_version, -1, next_payload);
      else {
        proto_tree_add_text(ntree, tvb, offset + 4, payload_length - 4,
                            "Payload");
      }
    }
    else if (payload_length > length) {
        proto_tree_add_text(ntree, tvb, 0, 0,
            "Payload (bogus, length is %u, greater than remaining length %d",
            payload_length, length);
        return;
    }
    else {
        proto_tree_add_text(ntree, tvb, 0, 0,
            "Payload (bogus, length is %u, must be at least 4)",
            payload_length);
        payload_length = 4;
    }
    offset += payload_length;
    length -= payload_length;
  }
}

void
isakmp_dissect_payloads(tvbuff_t *tvb, proto_tree *tree, int isakmp_version,
			guint8 initial_payload, int offset, int length,
			packet_info *pinfo)
{
  dissect_payloads(tvb, tree, tree, isakmp_version, initial_payload, offset, length,
		   pinfo);
}

static struct payload_func *
getpayload_func(guint8 payload, int isakmp_version)
{
  struct payload_func *f = 0;
  int i, len;

  if (isakmp_version == 1) {
    f = v1_plfunc;
    len = ARLEN(v1_plfunc);
  } else if (isakmp_version == 2) {
    f = v2_plfunc;
    len = ARLEN(v2_plfunc);
  } else
    return NULL;
  for (i = 0; i < len; i++) {
    if (f[i].type == payload)
      return &f[i];
  }
  return NULL;
}

static void
dissect_isakmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int			offset = 0, len;
  isakmp_hdr_t		hdr;
  proto_item *		ti;
  proto_tree *		isakmp_tree = NULL;
  int			isakmp_version;
#ifdef HAVE_LIBGCRYPT
  guint8                i_cookie[COOKIE_SIZE], *ic_key;
  decrypt_data_t       *decr = NULL;
  tvbuff_t             *decr_tvb;
  proto_tree           *decr_tree;
  address               null_addr;
  void                 *pd_save = NULL;
  gboolean             pd_changed = FALSE;
#endif /* HAVE_LIBGCRYPT */

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISAKMP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_isakmp, tvb, offset, -1, FALSE);
    isakmp_tree = proto_item_add_subtree(ti, ett_isakmp);
  }

  /* RFC3948 2.3 NAT Keepalive packet:
   * 1 byte payload with the value 0xff.
   */
  if( (tvb_length(tvb)==1) && (tvb_get_guint8(tvb, offset)==0xff) ){
    if (check_col(pinfo->cinfo, COL_INFO)){
      col_set_str(pinfo->cinfo, COL_INFO, "NAT Keepalive");
    }
    proto_tree_add_item(isakmp_tree, hf_isakmp_nat_keepalive, tvb, offset, 1, FALSE);
    return;
  }

  hdr.length = tvb_get_ntohl(tvb, offset + ISAKMP_HDR_SIZE - sizeof(hdr.length));
  hdr.exch_type = tvb_get_guint8(tvb, COOKIE_SIZE + COOKIE_SIZE + sizeof(hdr.next_payload) + sizeof(hdr.version));
  hdr.version = tvb_get_guint8(tvb, COOKIE_SIZE + COOKIE_SIZE + sizeof(hdr.next_payload));
  isakmp_version = hi_nibble(hdr.version);	/* save the version */
  hdr.flags = tvb_get_guint8(tvb, COOKIE_SIZE + COOKIE_SIZE + sizeof(hdr.next_payload) + sizeof(hdr.version) + sizeof(hdr.exch_type));
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
                exchtype2str(isakmp_version, hdr.exch_type));

#ifdef HAVE_LIBGCRYPT
  if (isakmp_version == 1) {
    SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

    tvb_memcpy(tvb, i_cookie, offset, COOKIE_SIZE);
    decr = (decrypt_data_t*) g_hash_table_lookup(isakmp_hash, i_cookie);

    if (! decr) {
      ic_key = g_mem_chunk_alloc(isakmp_key_data);
      memcpy(ic_key, i_cookie, COOKIE_SIZE);
      decr = g_mem_chunk_alloc(isakmp_decrypt_data);
      memset(decr, 0, sizeof(decrypt_data_t));
      SET_ADDRESS(&decr->initiator, AT_NONE, 0, NULL);

      g_hash_table_insert(isakmp_hash, ic_key, decr);
    }

    if (ADDRESSES_EQUAL(&decr->initiator, &null_addr)) {
      /* XXX - We assume that we're seeing the second packet in an exchange here.
       * Is there a way to verify this? */
      SE_COPY_ADDRESS(&decr->initiator, &pinfo->src);
    }

    pd_save = pinfo->private_data;
    pinfo->private_data = decr;
    pd_changed = TRUE;
  } else if (isakmp_version == 2) {
    ikev2_uat_data_key_t hash_key;
    ikev2_uat_data_t *ike_sa_data = NULL;
    ikev2_decrypt_data_t *ikev2_dec_data;
    guchar spii[COOKIE_SIZE], spir[COOKIE_SIZE];

    tvb_memcpy(tvb, spii, offset, COOKIE_SIZE);
    tvb_memcpy(tvb, spir, offset + COOKIE_SIZE, COOKIE_SIZE);
    hash_key.spii = spii;
    hash_key.spir = spir;
    hash_key.spii_len = COOKIE_SIZE;
    hash_key.spir_len = COOKIE_SIZE;

    ike_sa_data = g_hash_table_lookup(ikev2_key_hash, &hash_key);
    if (ike_sa_data) {
      guint8 initiator_flag;
      initiator_flag = hdr.flags & I_FLAG;
      ikev2_dec_data = ep_alloc(sizeof(ikev2_decrypt_data_t));
      ikev2_dec_data->encr_key = initiator_flag ? ike_sa_data->sk_ei : ike_sa_data->sk_er;
      ikev2_dec_data->auth_key = initiator_flag ? ike_sa_data->sk_ai : ike_sa_data->sk_ar;
      ikev2_dec_data->encr_spec = ike_sa_data->encr_spec;
      ikev2_dec_data->auth_spec = ike_sa_data->auth_spec;

      pd_save = pinfo->private_data;
      pinfo->private_data = ikev2_dec_data;
      pd_changed = TRUE;
    }
  }
#endif /* HAVE_LIBGCRYPT */

  if (tree) {
    proto_tree_add_item(isakmp_tree, hf_isakmp_icookie, tvb, offset, COOKIE_SIZE, FALSE);
    offset += COOKIE_SIZE;

    proto_tree_add_item(isakmp_tree, hf_isakmp_rcookie, tvb, offset, COOKIE_SIZE, FALSE);
    offset += COOKIE_SIZE;

    hdr.next_payload = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format(isakmp_tree, hf_isakmp_nextpayload, tvb, offset,
			sizeof(hdr.next_payload), hdr.next_payload,
			"Next payload: %s (%u)",
			payloadtype2str(isakmp_version, hdr.next_payload),
			hdr.next_payload);
    offset += sizeof(hdr.next_payload);

    proto_tree_add_uint_format(isakmp_tree, hf_isakmp_version, tvb, offset,
			sizeof(hdr.version), hdr.version, "Version: %u.%u",
			hi_nibble(hdr.version), lo_nibble(hdr.version));
    offset += sizeof(hdr.version);

    hdr.exch_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format(isakmp_tree, hf_isakmp_exchangetype, tvb, offset,
			sizeof(hdr.exch_type), hdr.exch_type,
			"Exchange type: %s (%u)",
			exchtype2str(isakmp_version, hdr.exch_type),
			hdr.exch_type);
    offset += sizeof(hdr.exch_type);

    {
      proto_item *	fti;
      proto_tree *	ftree;

      fti   = proto_tree_add_item(isakmp_tree, hf_isakmp_flags, tvb, offset, sizeof(hdr.flags), FALSE);
      ftree = proto_item_add_subtree(fti, ett_isakmp_flags);

      if (isakmp_version == 1) {
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, E_FLAG, sizeof(hdr.flags)*8,
						  "Encrypted", "Not encrypted"));
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, C_FLAG, sizeof(hdr.flags)*8,
						  "Commit", "No commit"));
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, A_FLAG, sizeof(hdr.flags)*8,
						  "Authentication", "No authentication"));
      } else if (isakmp_version == 2) {
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, I_FLAG, sizeof(hdr.flags)*8,
						  "Initiator", "Responder"));
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, V_FLAG, sizeof(hdr.flags)*8,
						  "A higher version enabled", ""));
        proto_tree_add_text(ftree, tvb, offset, 1, "%s",
			  decode_boolean_bitfield(hdr.flags, R_FLAG, sizeof(hdr.flags)*8,
						  "Response", "Request"));
      }
      offset += sizeof(hdr.flags);
    }

    hdr.message_id = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(isakmp_tree, hf_isakmp_messageid, tvb, offset, sizeof(hdr.message_id), FALSE);
    offset += sizeof(hdr.message_id);

    if (hdr.length < ISAKMP_HDR_SIZE) {
        proto_tree_add_uint_format(isakmp_tree, hf_isakmp_length, tvb, offset, sizeof(hdr.length),
			    hdr.length, "Length: (bogus, length is %u, should be at least %lu)",
			    hdr.length, (unsigned long)ISAKMP_HDR_SIZE);
#ifdef HAVE_LIBGCRYPT
        if (pd_changed) pinfo->private_data = pd_save;
#endif /* HAVE_LIBGCRYPT */
        return;
    }

    len = hdr.length - ISAKMP_HDR_SIZE;

    if (len < 0) {
        proto_tree_add_uint_format(isakmp_tree, hf_isakmp_length, tvb, offset, sizeof(hdr.length),
			    hdr.length, "Length: (bogus, length is %u, which is too large)",
			    hdr.length);
#ifdef HAVE_LIBGCRYPT
        if (pd_changed) pinfo->private_data = pd_save;
#endif /* HAVE_LIBGCRYPT */
        return;
    }

    proto_tree_add_item(isakmp_tree, hf_isakmp_length, tvb, offset, sizeof(hdr.length), FALSE);
    offset += sizeof(hdr.length);

    if (hdr.flags & E_FLAG) {
      if (len && isakmp_tree) {
        ti = proto_tree_add_text(isakmp_tree, tvb, offset, len,
			"Encrypted payload (%d byte%s)",
			len, plurality(len, "", "s"));
#ifdef HAVE_LIBGCRYPT

	if (decr) {
	  decr_tvb = decrypt_payload(tvb, pinfo, tvb_get_ptr(tvb, offset, len), len, &hdr);
	  if (decr_tvb) {
            decr_tree = proto_item_add_subtree(ti, ett_isakmp);
            dissect_payloads(decr_tvb, decr_tree, tree, isakmp_version,
                   hdr.next_payload, 0, tvb_length(decr_tvb), pinfo);
	  }
	}
#endif /* HAVE_LIBGCRYPT */
      }
    } else
      dissect_payloads(tvb, isakmp_tree, tree, isakmp_version, hdr.next_payload,
		       offset, len, pinfo);
  }
#ifdef HAVE_LIBGCRYPT
  if (pd_changed) pinfo->private_data = pd_save;
#endif /* HAVE_LIBGCRYPT */
}

static proto_tree *
dissect_payload_header(tvbuff_t *tvb, int offset, int length,
    int isakmp_version, guint8 payload, guint8 *next_payload_p,
    guint16 *payload_length_p, proto_tree *tree)
{
  guint8		next_payload;
  guint16		payload_length;
  proto_item *		ti;
  proto_tree *		ntree;

  if (length < 4) {
    proto_tree_add_text(tree, tvb, offset, length,
          "Not enough room in payload for all transforms");
    return NULL;
  }
  next_payload = tvb_get_guint8(tvb, offset);
  payload_length = tvb_get_ntohs(tvb, offset + 2);

  /* This is ugly, but the code is too inflexible to handle this at the
   * proper place (dissect_vid)
   */
  if (payload == 13) { /* Vendor ID */
	ti = proto_tree_add_text(tree, tvb, offset, payload_length,
		"%s: %s", payloadtype2str(isakmp_version, payload),
		vid_to_str(tvb, offset + 4, payload_length - 4));
  } else {
  	ti = proto_tree_add_text(tree, tvb, offset, payload_length,
        	"%s payload", payloadtype2str(isakmp_version, payload));
  }
  ntree = proto_item_add_subtree(ti, ett_isakmp_payload);

  proto_tree_add_uint_format(ntree, hf_isakmp_nextpayload, tvb, offset, 1,
			next_payload, "Next payload: %s (%u)",
			payloadtype2str(isakmp_version, next_payload),
			next_payload);
  if (isakmp_version == 2) {
    proto_tree_add_text(ntree, tvb, offset + 1, 1, "%s",
        	decode_boolean_bitfield(tvb_get_guint8(tvb, offset + 1), 0x80,
        	8, "Critical", "Not critical"));
  }
  proto_tree_add_item(ntree, hf_isakmp_payloadlen, tvb, offset + 2, 2, FALSE);

  *next_payload_p = next_payload;
  *payload_length_p = payload_length;
  return ntree;
}

static void
dissect_sa(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo, int isakmp_version, int unused _U_, guint8 inner_payload _U_)
{
  guint32		doi;
  guint32		situation;

  if (length < 4) {
    proto_tree_add_text(tree, tvb, offset, length,
			"DOI %s (length is %u, should be >= 4)",
			tvb_bytes_to_str(tvb, offset, length), length);
    return;
  }
  if (isakmp_version == 1) {
    doi = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint_format(tree, hf_isakmp_doi, tvb, offset, 4,
			doi, "Domain of interpretation: %s (%u)",
			doitype2str(doi), doi);
    offset += 4;
    length -= 4;

    if (doi == 1) {
      /* IPSEC */
      if (length < 4) {
        proto_tree_add_bytes_format(tree, hf_isakmp_sa_situation, tvb, offset, length,
			  tvb_get_ptr(tvb, offset, length),
			  "Situation: %s (length is %u, should be >= 4)",
			  tvb_bytes_to_str(tvb, offset, length), length);
        return;
      }
      situation = tvb_get_ntohl(tvb, offset);
      proto_tree_add_bytes_format(tree, hf_isakmp_sa_situation, tvb, offset, 4,
			tvb_get_ptr(tvb, offset, 4), "Situation: %s (%u)",
			situation2str(situation), situation);
      offset += 4;
      length -= 4;

      dissect_payloads(tvb, tree, tree, isakmp_version, LOAD_TYPE_PROPOSAL, offset,
		       length, pinfo);
    } else {
      /* Unknown */
      proto_tree_add_item(tree, hf_isakmp_sa_situation, tvb, offset, length, FALSE);
    }
  } else if (isakmp_version == 2) {
    dissect_payloads(tvb, tree, tree, isakmp_version, LOAD_TYPE_PROPOSAL, offset,
		     length, pinfo);
  }
}

static void
dissect_proposal(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_,  packet_info *pinfo _U_, int isakmp_version, int unused _U_, guint8 inner_payload _U_)
{
  guint8		protocol_id;
  guint8		spi_size;
  guint8		num_transforms;
  guint8		next_payload;
  guint16		payload_length;
  proto_tree *		ntree;
  guint8		proposal_num;

  proposal_num = tvb_get_guint8(tvb, offset);

  proto_item_append_text(tree, " # %d", proposal_num);

  proto_tree_add_item(tree, hf_isakmp_prop_number, tvb, offset, 1, FALSE);
  offset += 1;
  length -= 1;

  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint_format(tree, hf_isakmp_protoid, tvb, offset, 1,
			protocol_id, "Protocol ID: %s (%u)",
			val_to_str(protocol_id, vs_proto, "UNKNOWN-PROTO-TYPE"), protocol_id);
  offset += 1;
  length -= 1;

  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_spisize, tvb, offset, 1, FALSE);
  offset += 1;
  length -= 1;

  num_transforms = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_prop_transforms, tvb, offset, 1, FALSE);
  offset += 1;
  length -= 1;

  if (spi_size) {
    proto_tree_add_text(tree, tvb, offset, spi_size, "SPI: 0x%s",
			tvb_bytes_to_str(tvb, offset, spi_size));
    offset += spi_size;
    length -= spi_size;
  }

  while (num_transforms > 0) {
    ntree = dissect_payload_header(tvb, offset, length, isakmp_version,
      LOAD_TYPE_TRANSFORM, &next_payload, &payload_length, tree);
    if (ntree == NULL)
      break;
    if (length < payload_length) {
      proto_tree_add_text(tree, tvb, offset + 4, length,
          "Not enough room in payload for all transforms");
      break;
    }
    if (payload_length >= 4) {
      if (isakmp_version == 1)
        dissect_transform(tvb, offset + 4, payload_length - 4, ntree,
			ntree, pinfo, isakmp_version, protocol_id, 0);
      else if (isakmp_version == 2)
        dissect_transform2(tvb, offset + 4, payload_length - 4, ntree,
			ntree, pinfo, isakmp_version, protocol_id, 0);
    }
    else
      proto_tree_add_text(ntree, tvb, offset + 4, payload_length - 4, "Payload");
    offset += payload_length;
    length -= payload_length;
    num_transforms--;
  }
}

static void
dissect_transform(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int protocol_id, guint8 inner_payload _U_)
{
  static const value_string vs_v1_attr[] = {
    { 1,	"Encryption-Algorithm" },
    { 2,	"Hash-Algorithm" },
    { 3,	"Authentication-Method" },
    { 4,	"Group-Description" },
    { 5,	"Group-Type" },
    { 6,	"Group-Prime" },
    { 7,	"Group-Generator-One" },
    { 8,	"Group-Generator-Two" },
    { 9,	"Group-Curve-A" },
    { 10,	"Group-Curve-B" },
    { 11,	"Life-Type" },
    { 12,	"Life-Duration" },
    { 13,	"PRF" },
    { 14,	"Key-Length" },
    { 15,	"Field-Size" },
    { 16,	"Group-Order" },
    { 0,	NULL },
  };

  static const value_string vs_v2_sttr[] = {
    { 1,	"SA-Life-Type" },
    { 2,	"SA-Life-Duration" },
    { 3,	"Group-Description" },
    { 4,	"Encapsulation-Mode" },
    { 5,	"Authentication-Algorithm" },
    { 6,	"Key-Length" },
    { 7,	"Key-Rounds" },
    { 8,	"Compress-Dictionary-Size" },
    { 9,	"Compress-Private-Algorithm" },
    { 10,	"ECN Tunnel" },
    { 0,	NULL },
  };

  static const value_string vs_v1_trans_isakmp[] = {
    { 0,	"RESERVED" },
    { 1,	"KEY_IKE" },
    { 0,	NULL },
  };

  static const value_string vs_v1_trans_ah[] = {
    { 0,	"RESERVED" },
    { 1,	"RESERVED" },
    { 2,	"MD5" },
    { 3,	"SHA" },
    { 4,	"DES" },
    { 5,	"SHA2-256" },
    { 6,	"SHA2-384" },
    { 7,	"SHA2-512" },
    { 0,	NULL },
  };

  static const value_string vs_v1_trans_esp[] = {
    { 0,	"RESERVED" },
    { 1,	"DES-IV64" },
    { 2,	"DES" },
    { 3,	"3DES" },
    { 4,	"RC5" },
    { 5,	"IDEA" },
    { 6,	"CAST" },
    { 7,	"BLOWFISH" },
    { 8,	"3IDEA" },
    { 9,	"DES-IV32" },
    { 10,	"RC4" },
    { 11,	"NULL" },
    { 12,	"AES" },
    { 0,	NULL },
  };

  static const value_string vs_v1_trans_ipcomp[] = {
    { 0,	"RESERVED" },
    { 1,	"OUI" },
    { 2,	"DEFLATE" },
    { 3,	"LZS" },
    { 4,	"LZJH" },
    { 0,	NULL },
  };

  guint8		transform_id;
  guint8		transform_num;
#ifdef HAVE_LIBGCRYPT
  decrypt_data_t *decr = (decrypt_data_t *) pinfo->private_data;
#endif /* HAVE_LIBGCRYPT */

  transform_num = tvb_get_guint8(tvb, offset);
  proto_item_append_text(tree," # %d",transform_num);
  proto_tree_add_item(tree, hf_isakmp_trans_number, tvb, offset, 1, FALSE);
  offset += 1;
  length -= 1;

  transform_id = tvb_get_guint8(tvb, offset);
  switch (protocol_id) {
  default:
    proto_tree_add_item(tree, hf_isakmp_trans_id, tvb, offset, 1, FALSE);
    break;
  case 1:	/* ISAKMP */
    proto_tree_add_uint_format(tree, hf_isakmp_trans_id, tvb, offset, 1,
			transform_id, "Transform ID: %s (%u)",
			val_to_str(transform_id, vs_v1_trans_isakmp, "UNKNOWN-TRANS-TYPE"), transform_id);
    break;
  case 2:	/* AH */
    proto_tree_add_uint_format(tree, hf_isakmp_trans_id, tvb, offset, 1,
			transform_id, "Transform ID: %s (%u)",
			val_to_str(transform_id, vs_v1_trans_ah, "UNKNOWN-AH-TRANS-TYPE"), transform_id);
    break;
  case 3:	/* ESP */
    proto_tree_add_uint_format(tree, hf_isakmp_trans_id, tvb, offset, 1,
			transform_id, "Transform ID: %s (%u)",
			val_to_str(transform_id, vs_v1_trans_esp, "UNKNOWN-ESP-TRANS-TYPE"), transform_id);
    break;
  case 4:	/* IPCOMP */
    proto_tree_add_uint_format(tree, hf_isakmp_trans_id, tvb, offset, 1,
			transform_id, "Transform ID: %s (%u)",
			val_to_str(transform_id, vs_v1_trans_ipcomp, "UNKNOWN-IPCOMP-TRANS-TYPE"), transform_id);
    break;
  }
  offset += 3;
  length -= 3;

  while (length>0) {
    const char *str;
    int ike_phase1 = 0;
    guint16 aft     = tvb_get_ntohs(tvb, offset);
    guint16 type    = aft & 0x7fff;
    guint16 len;
    guint32 val;
    guint pack_len;

    /* XXX - Add header fields */
    if (protocol_id == 1 && transform_id == 1) {
      ike_phase1 = 1;
      str = val_to_str(type, vs_v1_attr, "UNKNOWN-ATTRIBUTE-TYPE");
    }
    else {
      str = val_to_str(type, vs_v2_sttr, "UNKNOWN-ATTRIBUTE-TYPE");
    }

    if (aft & 0x8000) {
      val = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset, 4,
			  "%s (%u): %s (%u)",
			  str, type,
			  v1_attrval2str(ike_phase1, type, val), val);
#ifdef HAVE_LIBGCRYPT
      set_transform_vals(decr, ike_phase1, type, val);
#endif
      offset += 4;
      length -= 4;
    }
    else {
      len = tvb_get_ntohs(tvb, offset + 2);
      pack_len = 4 + len;
      if (!get_num(tvb, offset + 4, len, &val)) {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s (%u): <too big (%u bytes)>",
			    str, type, len);
      } else {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s (%u): %s (%u)",
			    str, type,
			    v1_attrval2str(ike_phase1, type, val), val);
#ifdef HAVE_LIBGCRYPT
        set_transform_vals(decr, ike_phase1, type, val);
#endif
      }
      offset += pack_len;
      length -= pack_len;
    }
  }
}

/* For Transform Type 1 (Encryption Algorithm), defined Transform IDs */
static const char *
v2_tid2encstr(guint16 tid)
{
  static const value_string vs_v2_trans_enc[] = {
    { 0,	"RESERVED" },
    { 1,	"ENCR_DES_IV64" },
    { 2,	"ENCR_DES" },
    { 3,	"ENCR_3DES" },
    { 4,	"ENCR_RC5" },
    { 5,	"ENCR_IDEA" },
    { 6,	"ENCR_CAST" },
    { 7,	"ENCR_BLOWFISH" },
    { 8,	"ENCR_3IDEA" },
    { 9,	"ENCR_DES_IV32" },
    { 10,	"RESERVED" },
    { 11,	"ENCR_NULL" },
    { 12,	"ENCR_AES_CBC" },
    { 13,	"ENCR_AES_CTR" },					/* [RFC3686] */
    { 14,	"ENCR_AES-CCM_8" },					/* [RFC4309] */
    { 15,	"ENCR-AES-CCM_12" },				/* [RFC4309] */
    { 16,	"ENCR-AES-CCM_16" },				/* [RFC4309] */
    { 17,	"UNASSIGNED" },
    { 18,	"AES-GCM with a 8 octet ICV" },		/* [RFC4106] */
    { 19,	"AES-GCM with a 12 octet ICV" },	/* [RFC4106] */
    { 20,	"AES-GCM with a 16 octet ICV" },	/* [RFC4106] */
    { 21,	"ENCR_NULL_AUTH_AES_GMAC" },		/* [RFC4543] */
/*
 *		22-1023    RESERVED TO IANA                    [RFC4306]
 *		1024-65535    PRIVATE USE                      [RFC4306]
 */
    { 0,	NULL },
  };

  return val_to_str(tid, vs_v2_trans_enc, "UNKNOWN-ENC-ALG");
}

/* For Transform Type 2 (Pseudo-random Function), defined Transform IDs */
static const char *
v2_tid2prfstr(guint16 tid)
{
  static const value_string vs_v2_trans_prf[] = {
    { 0,	"RESERVED" },
    { 1,	"PRF_HMAC_MD5" },
    { 2,	"PRF_HMAC_SHA1" },
    { 3,	"PRF_HMAC_TIGER" },
    { 4,	"PRF_AES128_CBC" },
    { 5,	"RESERVED TO IANA" },				/* [RFC4306] */
    { 6,	"RESERVED TO IANA" },				/* [RFC4306] */
    { 7,	"RESERVED TO IANA" },				/* [RFC4306] */
    { 8,	"PRF_AES128_CMAC6" },				/* [RFC4615] */
	/*
     9-1023    RESERVED TO IANA							[RFC4306]
	 1024-65535    PRIVATE USE							[RFC4306]
	 */
    { 0,	NULL },
  };
  return val_to_str(tid, vs_v2_trans_prf, "UNKNOWN-PRF");
}

/* For Transform Type 3 (Integrity Algorithm), defined Transform IDs */
static const char *
v2_tid2iastr(guint16 tid)
{
  static const value_string vs_v2_trans_integrity[] = {
    { 0,	"NONE" },
    { 1,	"AUTH_HMAC_MD5_96" },
    { 2,	"AUTH_HMAC_SHA1_96" },
    { 3,	"AUTH_DES_MAC" },
    { 4,	"AUTH_KPDK_MD5" },
    { 5,	"AUTH_AES_XCBC_96" },
    { 6,	"AUTH_HMAC_MD5_128" },				/* [RFC-maino-fcsp-02.txt] */
    { 7,	"AUTH_HMAC_SHA1_160" },				/* [RFC-maino-fcsp-02.txt] */
    { 8,	"AUTH_AES_CMAC_96" },				/* [RFC4494] */
    { 9,	"AUTH_AES_128_GMAC" },				/* [RFC4543] */
    { 10,	"AUTH_AES_192_GMAC" },				/* [RFC4543] */
    { 11,	"AUTH_AES_256_GMAC" },				/* [RFC4543] */
	/*
    12-1023    RESERVED TO IANA                    [RFC4306]
 1024-65535    PRIVATE USE                         [RFC4306]
 */
    { 0,	NULL },
  };
  return val_to_str(tid, vs_v2_trans_integrity, "UNKNOWN-INTEGRITY-ALG");
}

/* For Transform Type 4 (Diffie-Hellman Group), defined Transform IDs */
static const char *
v2_tid2dhstr(guint16 tid)
{
  static const value_string vs_v2_trans_dhgroup[] = {
    {  0,	"NONE" },
    {  1,	"Group 1 - 768 Bit MODP" },
    {  2,	"Group 2 - 1024 Bit MODP" },
    {  3,	"RESERVED" },
    {  4,	"RESERVED" },
    {  5,	"group 5 - 1536 Bit MODP" },
	/* 6-13    RESERVED TO IANA                    [RFC4306] */
    { 14,	"2048-bit MODP Group" },
    { 15,	"3072-bit MODP Group" },
    { 16,	"4096-bit MODP Group" },
    { 17,	"6144-bit MODP Group" },
    { 18,	"8192-bit MODP Group" },
    { 19,	"256-bit random ECP group" },			/* [RFC-ietf-ipsec-ike-ecp-groups-02.txt]*/
    { 20,	"384-bit random ECP group" },			/* [RFC-ietf-ipsec-ike-ecp-groups-02.txt]*/
    { 21,	"521-bit random ECP group" },			/* [RFC-ietf-ipsec-ike-ecp-groups-02.txt]*/
	/*
    22-1023    RESERVED TO IANA                    [RFC4306]
 1024-65535    PRIVATE USE                         [RFC4306]
 */
    { 0,	NULL },
  };

  if ((tid >= 6 && tid <= 13) || (tid >= 22 && tid <= 1023))
    return "RESERVED TO IANA";
  if (tid >= 1024)
    return "PRIVATE USE";
  return val_to_str(tid, vs_v2_trans_dhgroup, "UNKNOWN-DH-GROUP");
}

/* For Transform Type 5 (Extended Sequence Numbers), defined Transform */
static const char *
v2_tid2esnstr(guint16 tid)
{
  static const value_string vs_v2_trans_esn[] = {
    { 0,	"No Extended Sequence Numbers" },
    { 1,	"Extended Sequence Numbers" },
    { 0,	NULL },
  };

  return val_to_str(tid, vs_v2_trans_esn, "UNKNOWN-ESN-TYPE");
}

static struct {
  const gint8 type;
  const char *str;
  const char *(*func)(guint16);
} v2_tid_func[] = {
  { 0,	"RESERVED", NULL, },
  { 1,	"Encryption Algorithm (ENCR)", v2_tid2encstr },
  { 2,	"Pseudo-random Function (PRF)", v2_tid2prfstr },
  { 3,	"Integrity Algorithm (INTEG)", v2_tid2iastr },
  { 4,	"Diffie-Hellman Group (D-H)", v2_tid2dhstr },
  { 5,	"Extended Sequence Numbers (ESN)", v2_tid2esnstr },
};

static const char *
v2_trans2str(guint8 type)
{
  if (type < ARLEN(v2_tid_func)) return v2_tid_func[type].str;
  if (type < 240) return "RESERVED TO IANA";
  return "PRIVATE USE";
}

static const char *
v2_tid2str(guint8 type, guint16 tid)
{
  if (type < ARLEN(v2_tid_func) && v2_tid_func[type].func != NULL) {
    return (v2_tid_func[type].func)(tid);
  }
  return "RESERVED";
}

static const char *
v2_aft2str(guint16 aft)
{
    if (aft < 14 || (aft > 14 && aft < 18)) return "RESERVED";
    if (aft == 14) return "Key Length (in bits)";
    if (aft >= 18 && aft < 16384) return "RESERVED TO IANA";
    return "PRIVATE USE";
}

static void
dissect_transform2(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{
  guint8 transform_type;
  guint16 transform_id;

  transform_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
    "Transform type: %s (%u)", v2_trans2str(transform_type), transform_type);
  offset += 2;
  length -= 2;

  transform_id = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 2,
    "Transform ID: %s (%u)", v2_tid2str(transform_type, transform_id),
    transform_id);
  offset += 2;
  length -= 2;

  while (length>0) {
    const char *str;
    guint16 aft     = tvb_get_ntohs(tvb, offset);
    guint16 type    = aft & 0x7fff;
    guint16 len;
    guint32 val;
    guint pack_len;

    str = v2_aft2str(type);

    if (aft & 0x8000) {
      val = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset, 4,
			  "%s (%u): %s (%u)",
			  str, type,
			  v2_attrval2str(type, val), val);
      offset += 4;
      length -= 4;
    }
    else {
      len = tvb_get_ntohs(tvb, offset + 2);
      pack_len = 4 + len;
      if (!get_num(tvb, offset + 4, len, &val)) {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s (%u): <too big (%u bytes)>",
			    str, type, len);
      } else {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s (%u): %s (%u)",
			    str, type,
			    v2_attrval2str(type, val), val);
      }
      offset += pack_len;
      length -= pack_len;
    }
  }
}

static void
dissect_key_exch(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version, int unused _U_, guint8 inner_payload _U_)
{
  guint16 dhgroup;
#ifdef HAVE_LIBGCRYPT
  decrypt_data_t *decr = (decrypt_data_t *) pinfo->private_data;
#endif /* HAVE_LIBGCRYPT */

  if (isakmp_version == 2) {
    dhgroup = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2,
  		      "DH Group #: %u", dhgroup);
    offset += 4;
    length -= 4;
  }

  proto_tree_add_text(tree, tvb, offset, length, "Key Exchange Data (%d bytes / %d bits)",
	length, length * 8);

#ifdef HAVE_LIBGCRYPT
  if (decr && decr->gi_len == 0 && ADDRESSES_EQUAL(&decr->initiator, &pinfo->src)) {
    decr->gi = g_malloc(length);
    tvb_memcpy(tvb, decr->gi, offset, length);
    decr->gi_len = length;
  } else if (decr && decr->gr_len == 0 && !ADDRESSES_EQUAL(&decr->initiator, &pinfo->src)) {
    decr->gr = g_malloc(length);
    tvb_memcpy(tvb, decr->gr, offset, length);
    decr->gr_len = length;
  }
#endif /* HAVE_LIBGCRYPT */
}

static void
dissect_id(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo, int isakmp_version, int unused _U_, guint8 inner_payload _U_)
{
  guint8		id_type;
  guint8		protocol_id;
  guint16		port;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  id_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_id_type, tvb, offset, 1, FALSE);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "ID type: %s (%u)",
		      id2str(isakmp_version, id_type), id_type);
  offset += 1;
  length -= 1;

  protocol_id = tvb_get_guint8(tvb, offset);
  if (protocol_id == 0) {
    proto_tree_add_uint_format(tree, hf_isakmp_protoid, tvb, offset, 1,
			protocol_id, "Protocol ID: Unused");
  } else {
    proto_tree_add_uint_format(tree, hf_isakmp_protoid, tvb, offset, 1,
			protocol_id, "Protocol ID: %s (%u)",
			ipprotostr(protocol_id), protocol_id);
  }
  offset += 1;
  length -= 1;

  port = tvb_get_ntohs(tvb, offset);
  if (port == 0)
    proto_tree_add_uint_format(tree, hf_isakmp_id_port, tvb, offset, 2,
			port, "Port: Unused");
  else
    proto_tree_add_item(tree, hf_isakmp_id_port, tvb, offset, 2, FALSE);
  offset += 2;
  length -= 2;

  /*
   * It shows strings of all types though some of types are not
   * supported in IKEv2 specification actually.
   */
  switch (id_type) {
    case IKE_ID_IPV4_ADDR:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s",
			  ip_to_str(tvb_get_ptr(tvb, offset, 4)));
      break;
    case IKE_ID_FQDN:
    case IKE_ID_USER_FQDN:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %.*s", length,
			  tvb_get_ptr(tvb, offset, length));
      break;
    case IKE_ID_IPV4_ADDR_SUBNET:
    case IKE_ID_IPV4_ADDR_RANGE:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s/%s",
			  ip_to_str(tvb_get_ptr(tvb, offset, 4)),
			  ip_to_str(tvb_get_ptr(tvb, offset+4, 4)));
      break;
    case IKE_ID_IPV6_ADDR:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s",
			  ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset, 16)));
      break;
    case IKE_ID_IPV6_ADDR_SUBNET:
    case IKE_ID_IPV6_ADDR_RANGE:
      proto_tree_add_text(tree, tvb, offset, length,
			  "Identification data: %s/%s",
			  ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset, 16)),
			  ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset+16, 16)));
      break;
    case IKE_ID_DER_ASN1_DN:
      dissect_x509if_Name(FALSE, tvb, offset, &asn1_ctx, tree,
			  hf_isakmp_certificate_authority);
      break;
    default:
      proto_tree_add_text(tree, tvb, offset, length, "Identification Data");
      break;
  }
}

static void
dissect_cert(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo, int isakmp_version, int unused _U_, guint8 inner_payload _U_)
{
  guint8		cert_enc;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);

  cert_enc = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint_format(tree, hf_isakmp_cert_encoding, tvb, offset, 1,
			cert_enc, "Certificate encoding: %u - %s",
			cert_enc, certtype2str(isakmp_version, cert_enc));
  offset += 1;
  length -= 1;

  dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, tree, hf_isakmp_certificate);
}

static void
dissect_certreq_v1(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo, int isakmp_version, int unused _U_, guint8 inner_payload _U_)
{
  guint8		cert_type;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  cert_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint_format(tree, hf_isakmp_certreq_type, tvb, offset, 1,
			cert_type, "Certificate type: %u - %s",
			cert_type, certtype2str(isakmp_version, cert_type));
  offset += 1;
  length -= 1;

  if (length) {
    if (cert_type == 4){
      dissect_x509if_Name(FALSE, tvb, offset, &asn1_ctx, tree, hf_isakmp_certificate_authority);
    } else {
      proto_tree_add_text(tree, tvb, offset, length, "Certificate Authority");
    }
  }
  else
    proto_tree_add_text(tree, tvb, offset, length, "Certificate Authority (empty)");
}

static void
dissect_certreq_v2(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version, int unused _U_, guint8 inner_payload _U_)
{
  guint8		cert_type;

  cert_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "Certificate type: %u - %s",
		      cert_type, certtype2str(isakmp_version, cert_type));
  offset += 1;
  length -= 1;

  /* this is a list of 20 byte SHA-1 hashes */
  while (length > 0) {
    proto_tree_add_item(tree, hf_isakmp_v2_certificate_authority, tvb, offset, 20, FALSE);
    offset+=20;
    length-=20;
  }
}

static void
dissect_hash(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "Hash Data");
}

static void
dissect_auth(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{
  guint8 auth;

  auth = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
  		      "Auth Method: %s (%u)", v2_auth2str(auth), auth);
  offset += 4;
  length -= 4;

  proto_tree_add_text(tree, tvb, offset, length, "Authentication Data");
}

static void
dissect_sig(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "Signature Data");
}

static void
dissect_cisco_fragmentation(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *ptree, packet_info *pinfo, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{

  guint8 seq; /* Packet sequence number, starting from 1 */
  guint8 last;

  if (length < 4)
    return;

  proto_tree_add_item(tree, hf_isakmp_cisco_frag_packetid, tvb, offset, 2, FALSE);
  offset += 2;
  seq = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_cisco_frag_seq, tvb, offset, 1, FALSE);
  offset += 1;
  last = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_cisco_frag_last, tvb, offset, 1, FALSE);
  offset += 1;
  length-=4;

  /* Start Reassembly stuff for Cisco IKE fragmentation */
  {
        gboolean save_fragmented;
        tvbuff_t *defrag_isakmp_tvb = NULL;
        fragment_data *frag_msg = NULL;

	save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        frag_msg = fragment_add_seq_check(tvb, offset, pinfo,
                12345, /*FIXME:  Fragmented packet id, guint16, somehow get CKY here */
                isakmp_fragment_table, /* list of message fragments */
                isakmp_reassembled_table, /* list of reassembled messages */
                seq-1, /* fragment sequence number, starting from 0 */
                tvb_length_remaining(tvb, offset), /* fragment length - to the end */
                last); /* More fragments? */
        defrag_isakmp_tvb = process_reassembled_data(tvb, offset, pinfo,
                "Reassembled Message", frag_msg, &isakmp_frag_items,
                NULL, ptree);

        if (defrag_isakmp_tvb) { /* take it all */
                dissect_isakmp(defrag_isakmp_tvb, pinfo, ptree);
        }
        if (check_col(pinfo->cinfo, COL_INFO))
                col_append_fstr(pinfo->cinfo, COL_INFO,
                       " (%sMessage fragment %u%s)",
			(frag_msg ? "Reassembled + " : ""),
			seq, (last ? " - last" : ""));
        pinfo->fragmented = save_fragmented;
  }
  /* End Reassembly stuff for Cisco IKE fragmentation */

}

static void
dissect_nonce(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{
  proto_tree_add_text(tree, tvb, offset, length, "Nonce Data");
}

static const char *
v2_ipcomptype2str(guint8 type)
{
  static const value_string vs_v2_ipcomptype[] = {
    { 0,	"RESERVED" },
    { 1,	"IPCOMP_OUI" },
    { 2,	"IPCOMP_DEFLATE" },
    { 3,	"IPCOMP_LZS" },
    { 4,	"IPCOMP_LZJH" },
    { 0,	NULL },
  };

  if (type >= 5 && type <= 240)
    return "RESERVED TO IANA";
  if (type >= 241)
    return "PRIVATE USE";
  return val_to_str(type, vs_v2_ipcomptype, "UNKNOWN-IPCOMP-TYPE");
}

static void
dissect_notif(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version, int unused _U_, guint8 inner_payload _U_)
{
  guint32		doi;
  guint8		protocol_id;
  guint8		spi_size;
  guint16		msgtype;
  guint8		ipcomptype;

  if (isakmp_version == 1) {
    doi = tvb_get_ntohl(tvb, offset);
    proto_tree_add_uint_format(tree, hf_isakmp_doi, tvb, offset, 4,
			doi, "Domain of interpretation: %s (%u)",
			doitype2str(doi), doi);
    offset += 4;
    length -= 4;
  }

  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint_format(tree, hf_isakmp_protoid, tvb, offset, 1,
			protocol_id, "Protocol ID: %s (%u)",
			val_to_str(protocol_id, vs_proto, "UNKNOWN-PROTO-TYPE"), protocol_id);
  offset += 1;
  length -= 1;

  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_spisize, tvb, offset, 1, FALSE);
  offset += 1;
  length -= 1;

  msgtype = tvb_get_ntohs(tvb, offset);
  proto_tree_add_uint_format(tree, hf_isakmp_notify_msgtype, tvb, offset, 2,
			msgtype, "Message type: %s (%u)",
			msgtype2str(isakmp_version, msgtype), msgtype);
  offset += 2;
  length -= 2;

  if (spi_size) {
    proto_tree_add_text(tree, tvb, offset, spi_size, "SPI: 0x%s",
			tvb_bytes_to_str(tvb, offset, spi_size));
    offset += spi_size;
    length -= spi_size;
  }

  if (length > 0) {
    proto_tree_add_text(tree, tvb, offset, length, "Notification Data");

    /* notification data */
    if (isakmp_version == 2 && msgtype == 16387) {
      /* IPCOMP_SUPPORTED */
      proto_tree_add_text(tree, tvb, offset, 2,
      			"IPComp CPI (%u)", tvb_get_ntohs(tvb, offset));
      ipcomptype = tvb_get_guint8(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset + 2, 1,
      			"Transform ID: %s (%u)",
      			v2_ipcomptype2str(ipcomptype), ipcomptype);
      offset += 3;
      length -= 3;
    }
  }
}

static void
dissect_delete(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{
  guint32		doi;
  guint8		protocol_id;
  guint8		spi_size;
  guint16		num_spis;
  guint16		i;

  if (isakmp_version == 1) {
    doi = tvb_get_ntohl(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4,
		        "Domain of Interpretation: %s (%u)",
		        doitype2str(doi), doi);
    offset += 4;
    length -= 4;
  }

  protocol_id = tvb_get_guint8(tvb, offset);
  proto_tree_add_uint_format(tree, hf_isakmp_protoid, tvb, offset, 1,
			protocol_id, "Protocol ID: %s (%u)",
			val_to_str(protocol_id, vs_proto, "UNKNOWN-PROTO-TYPE"), protocol_id);
  offset += 1;
  length -= 1;

  spi_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_spisize, tvb, offset, 1, FALSE);
  offset += 1;
  length -= 1;

  num_spis = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_isakmp_num_spis, tvb, offset, 2, FALSE);
  offset += 2;
  length -= 2;

  for (i = 0; i < num_spis; ++i) {
    if (length < spi_size) {
      proto_tree_add_text(tree, tvb, offset, length,
          "Not enough room in payload for all SPI's");
      break;
    }
    proto_tree_add_text(tree, tvb, offset, spi_size, "SPI: 0x%s",
			tvb_bytes_to_str(tvb, offset, spi_size));
    offset += spi_size;
    length -= spi_size;
  }
}

static const char*
vid_to_str(tvbuff_t* tvb, int offset, int length)
{
  const char * vendorstring;
  const guint8 * pVID;

  pVID = tvb_get_ptr(tvb, offset, length);

  if (length == VID_CISCO_FRAG_LEN
	&& memcmp(pVID, VID_CISCO_FRAG, length) == 0)
	vendorstring = "Cisco Fragmentation";
  else
  if (length == VID_MS_LEN
	&& memcmp(pVID, VID_MS_W2K_WXP, length) == 0)
	vendorstring = "Microsoft Win2K/WinXP";
  else
  if (memcmp(pVID, VID_CP, isakmp_min(VID_CP_LEN, length)) == 0)
	vendorstring = "Check Point";
  else
  if (memcmp(pVID, VID_CYBERGUARD, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Cyber Guard";
  else
  if (memcmp(pVID,  VID_rfc3947, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "RFC 3947 Negotiation of NAT-Traversal in the IKE";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_1_1_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 1.1.0";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_1_1_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 1.1.1";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_1_1_2, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 1.1.2";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_1_2_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 1.2.1";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_1_2_2, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 1.2.2";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_2_0_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 2.0.0";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_2_1_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 2.1.0";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_2_1_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 2.1.1";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_2_1_2, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 2.1.2";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_3_0_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 3.0.0";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_3_0_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 3.0.1";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_4_0_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 4.0.0";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_4_0_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 4.0.1";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_4_1_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 4.1.0";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_4_1_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 4.1.1";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_5_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 5.0";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_5_0_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 5.0.0";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_5_1_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 5.1.0";
  else
  if (memcmp(pVID,  VID_SSH_IPSEC_EXPRESS_5_1_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Ssh Communications Security IPSEC Express version 5.1.1";
  else
  if (memcmp(pVID,  VID_SSH_SENTINEL, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "SSH Sentinel";
  else
  if (memcmp(pVID,  VID_SSH_SENTINEL_1_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "SSH Sentinel 1.1";
  else
  if (memcmp(pVID,  VID_SSH_SENTINEL_1_2, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "SSH Sentinel 1.2";
  else
  if (memcmp(pVID,  VID_SSH_SENTINEL_1_3, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "SSH Sentinel 1.3";
  else
  if (memcmp(pVID,  VID_SSH_QUICKSEC_0_9_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "SSH Communications Security QuickSec 0.9.0";
  else
  if (memcmp(pVID,  VID_SSH_QUICKSEC_1_1_0, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "SSH Communications Security QuickSec 1.1.0";
  else
  if (memcmp(pVID,  VID_SSH_QUICKSEC_1_1_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "SSH Communications Security QuickSec 1.1.1";
  else
  if (memcmp(pVID,  VID_SSH_QUICKSEC_1_1_2, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "SSH Communications Security QuickSec 1.1.2";
  else
  if (memcmp(pVID,  VID_SSH_QUICKSEC_1_1_3, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "SSH Communications Security QuickSec 1.1.3";
  else
  if (memcmp(pVID,  VID_draft_huttunen_ipsec_esp_in_udp_01, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "draft-huttunen-ipsec-esp-in-udp-01.txt";
  else
  if (memcmp(pVID,  VID_draft_stenberg_ipsec_nat_traversal_01, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "draft-stenberg-ipsec-nat-traversal-01";
  else
  if (memcmp(pVID,  VID_draft_stenberg_ipsec_nat_traversal_02, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "draft-stenberg-ipsec-nat-traversal-02";
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_nat_t_ike_00, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "draft-ietf-ipsec-nat-t-ike-00";
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_nat_t_ike_01, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "draft-ietf-ipsec-nat-t-ike-01";
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_nat_t_ike_02a, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "draft-ietf-ipsec-nat-t-ike-02";
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_nat_t_ike_02b, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "draft-ietf-ipsec-nat-t-ike-02\\n"; /* \n intentional */
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_nat_t_ike_03, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "draft-ietf-ipsec-nat-t-ike-03";
  else
  if (memcmp(pVID,  VID_draft_beaulieu_ike_xauth_02, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "draft-beaulieu-ike-xauth-02.txt";
  else
  if (memcmp(pVID,  VID_rfc3706_dpd, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "RFC 3706 Detecting Dead IKE Peers (DPD)";
  else
  if (memcmp(pVID,  VID_IKE_CHALLENGE_RESPONSE_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "IKE Challenge/Response for Authenticated Cryptographic Keys";
  else
  if (memcmp(pVID,  VID_IKE_CHALLENGE_RESPONSE_2, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "IKE Challenge/Response for Authenticated Cryptographic Keys";
  else
  if (memcmp(pVID,  VID_IKE_CHALLENGE_RESPONSE_REV_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)";
  else
  if (memcmp(pVID,  VID_IKE_CHALLENGE_RESPONSE_REV_2, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "IKE Challenge/Response for Authenticated Cryptographic Keys (Revised)";
  else
  if (memcmp(pVID,  VID_MS_L2TP_IPSEC_VPN_CLIENT, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "Microsoft L2TP/IPSec VPN Client";
  else
  if (memcmp(pVID,  VID_GSS_API_1, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "A GSS-API Authentication Method for IKE";
  else
  if (memcmp(pVID,  VID_GSS_API_2, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "A GSS-API Authentication Method for IKE";
  else
  if (memcmp(pVID,  VID_GSSAPI, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "GSSAPI";
  else
  if (memcmp(pVID,  VID_MS_NT5_ISAKMPOAKLEY, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "MS NT5 ISAKMPOAKLEY";
  else
  if (memcmp(pVID,  VID_CISCO_CONCENTRATOR, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "CISCO-CONCENTRATOR";
  else
  if (memcmp(pVID,  VID_CISCO_UNITY_10, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "CISCO-UNITY-1.0";
  else
  if (memcmp(pVID,  VID_CISCO_UNITY, isakmp_min(VID_LEN, length)) == 0)
        vendorstring = "CISCO-UNITY";
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_antireplay_00, isakmp_min(VID_LEN_8, length)) == 0)
        vendorstring = "draft-ietf-ipsec-antireplay-00.txt";
  else
  if (memcmp(pVID,  VID_draft_ietf_ipsec_heartbeats_00, isakmp_min(VID_LEN_8, length)) == 0)
        vendorstring = "draft-ietf-ipsec-heartbeats-00.txt";
  else
        vendorstring = tvb_bytes_to_str(tvb, offset, length);

  return vendorstring;
}

static void
dissect_vid(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{
  guint32 CPproduct, CPversion;
  const guint8 * pVID;
  proto_item * pt;
  proto_tree * ntree;

  pVID = tvb_get_ptr(tvb, offset, length);
  pt = proto_tree_add_text(tree, tvb, offset, length, "Vendor ID: %s",
	vid_to_str(tvb, offset, length));

  if (memcmp(pVID, VID_CP, isakmp_min(VID_CP_LEN, length)) == 0)
  {
	offset += VID_CP_LEN;
	CPproduct = tvb_get_ntohl(tvb, offset);
	ntree = proto_item_add_subtree(pt, ett_isakmp_payload);
	pt = proto_tree_add_text(ntree, tvb, offset, sizeof(CPproduct), "Check Point Product: ");
	switch (CPproduct) {
		case 1: proto_item_append_text(pt, "VPN-1");
			break;
		case 2: proto_item_append_text(pt, "SecuRemote/SecureClient");
			break;
		default: proto_item_append_text(pt, "Unknown CP product!");
			break;
	}
	offset += sizeof(CPproduct);
	CPversion = tvb_get_ntohl(tvb, offset);
	pt = proto_tree_add_text(ntree, tvb, offset, sizeof(CPversion), "Version: ");
	switch (CPversion) {
		case 2: proto_item_append_text(pt, "4.1");
			break;
		case 3: proto_item_append_text(pt, "4.1 SP-1");
			break;
		case 4002: proto_item_append_text(pt, "4.1 (SP-2 or above)");
			break;
		case 5000: proto_item_append_text(pt, "NG");
			break;
		case 5001: proto_item_append_text(pt, "NG Feature Pack 1");
			break;
		case 5002: proto_item_append_text(pt, "NG Feature Pack 2");
			break;
		case 5003: proto_item_append_text(pt, "NG Feature Pack 3");
			break;
		case 5004: proto_item_append_text(pt, "NG with Application Intelligence");
			break;
		case 5005: proto_item_append_text(pt, "NG with Application Intelligence R55");
			break;
		default: proto_item_append_text(pt, " Unknown CP version!");
			break;
	}
	offset += sizeof(CPversion);
	proto_tree_add_text(ntree, tvb, offset, length - VID_CP_LEN - sizeof(CPproduct) - sizeof(CPversion),"Check Point Vendor ID parameters");
  }
}

static void
dissect_config(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version, int unused _U_, guint8 inner_payload _U_)
{
  guint8		type;

  if (isakmp_version == 1) {
    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
    			"Type %s (%u)",
    			cfgtype2str(isakmp_version, type), type);
    offset += 2;
    length -= 2;

    proto_tree_add_text(tree, tvb, offset, 2,
    			"Identifier: %u", tvb_get_ntohs(tvb, offset));
    offset += 2;
    length -= 2;
  } else if (isakmp_version == 2) {
    type = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
    			"CFG Type %s (%u)",
    			cfgtype2str(isakmp_version, type), type);
    offset += 4;
    length -= 4;
  }

  while(length>0) {
    guint16 aft     = tvb_get_ntohs(tvb, offset);
    guint16 type    = aft & 0x7fff;
    guint16 len;
    guint32 val;
    guint pack_len;

    if (aft & 0x8000) {
      val = tvb_get_ntohs(tvb, offset + 2);
      proto_tree_add_text(tree, tvb, offset, 4,
			  "%s (%u)",
			  cfgattr2str(isakmp_version, type), val);
      offset += 4;
      length -= 4;
    }
    else {
      len = tvb_get_ntohs(tvb, offset + 2);
      pack_len = 4 + len;
      if (!get_num(tvb, offset + 4, len, &val)) {
        proto_tree_add_text(tree, tvb, offset, pack_len,
			    "%s: <too big (%u bytes)>",
			    cfgattr2str(isakmp_version, type), len);
      } else {
        proto_tree_add_text(tree, tvb, offset, 4,
			    "%s (%ue)",
			    cfgattr2str(isakmp_version, type), val);
      }
      offset += pack_len;
      length -= pack_len;
    }
  }
}

static void
dissect_nat_discovery(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{
  proto_tree_add_text(tree, tvb, offset, length,
		      "Hash of address and port: %s",
		      tvb_bytes_to_str(tvb, offset, length));
}

static void
dissect_nat_original_address(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version, int unused _U_, guint8 inner_payload _U_)
{
  guint8 id_type;
  guint32 addr_ipv4;
  struct e_in6_addr addr_ipv6;

  id_type = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1,
		      "ID type: %s (%u)",
		      id2str(isakmp_version, id_type), id_type);
  offset += 1;
  length -= 1;

  offset += 3;		/* reserved */
  length -= 3;

  switch (id_type) {

  case IKE_ID_IPV4_ADDR:
    if (length == 4) {
      addr_ipv4 = tvb_get_ipv4(tvb, offset);
      proto_tree_add_text(tree, tvb, offset, length,
			  "Original address: %s",
			  ip_to_str((guint8 *)&addr_ipv4));
    } else {
      proto_tree_add_text(tree, tvb, offset, length,
			  "Original address: bad length, should be 4, is %u",
			  length);
    }
    break;

  case IKE_ID_IPV6_ADDR:
    if (length == 16) {
      tvb_get_ipv6(tvb, offset, &addr_ipv6);
      proto_tree_add_text(tree, tvb, offset, length,
			  "Original address: %s",
			  ip6_to_str(&addr_ipv6));
    } else {
      proto_tree_add_text(tree, tvb, offset, length,
			  "Original address: bad length, should be 16, is %u",
			  length);
    }
    break;

  default:
    proto_tree_add_text(tree, tvb, offset, length,
			"Original address: bad address type");
    break;
  }
}

static void
dissect_ts(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{
  guint8	num, tstype, protocol_id, addrlen;
  guint16	len, port;

  proto_tree_add_text(tree, tvb, offset, length, "Traffic Selector");

  num = tvb_get_guint8(tvb, offset);
  proto_item_append_text(tree," # %d", num);
  proto_tree_add_text(tree, tvb, offset, 1,
  		      "Number of TSs: %u", num);
  offset += 4;
  length -= 4;

  while (length > 0) {
    tstype = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
  		      "TS Type: %s (%u)",
  		      v2_tstype2str(tstype), tstype);
    switch (tstype) {
    case IKEV2_TS_IPV4_ADDR_RANGE:
      addrlen = 4;
      break;
    case IKEV2_TS_IPV6_ADDR_RANGE:
      addrlen = 16;
      break;
    default:
      proto_item_append_text(tree, "unknown TS data (aborted decoding): 0x%s",
			tvb_bytes_to_str(tvb, offset, length));
      return;
    }

    /*
     * XXX should the remaining of the length check be done here ?
     * it seems other routines don't check the length.
     */
    if (length < (8 + addrlen * 2)) {
      proto_tree_add_text(tree, tvb, offset, length,
			  "Length mismatch (%u)", length);
      return;
    }
    offset += 1;
    length -= 1;

    protocol_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 1,
  		      "Protocol ID: (%u)", protocol_id);
    offset += 1;
    length -= 1;

    len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2,
  		      "Selector Length: %u", len);
    offset += 2;
    length -= 2;

    port = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2,
  		      "Start Port: (%u)", port);
    offset += 2;
    length -= 2;

    port = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 2,
  		      "End Port: (%u)", port);
    offset += 2;
    length -= 2;

    switch (tstype) {
    case IKEV2_TS_IPV4_ADDR_RANGE:
	proto_tree_add_text(tree, tvb, offset, length,
			  "Starting Address: %s",
			  ip_to_str(tvb_get_ptr(tvb, offset, addrlen)));
	offset += addrlen;
	length -= addrlen;
	proto_tree_add_text(tree, tvb, offset, length,
  			  "Ending Address: %s",
  			  ip_to_str(tvb_get_ptr(tvb, offset, addrlen)));
	offset += addrlen;
	length -= addrlen;
	break;
    case IKEV2_TS_IPV6_ADDR_RANGE:
	proto_tree_add_text(tree, tvb, offset, length,
			  "Starting Address: %s",
			  ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset, addrlen)));
	offset += addrlen;
	length -= addrlen;
	proto_tree_add_text(tree, tvb, offset, length,
  			  "Ending Address: %s",
  			  ip6_to_str((const struct e_in6_addr *)tvb_get_ptr(tvb, offset, addrlen)));
	offset += addrlen;
	length -= addrlen;
	break;
    }
  }
}

static void
dissect_enc(tvbuff_t *tvb,
            int offset,
            int length,
            proto_tree *tree,
            proto_tree *p _U_,
#ifdef HAVE_LIBGCRYPT
            packet_info *pinfo,
#else
            packet_info *pinfo _U_,
#endif
            int isakmp_version _U_,
            int unused _U_,
#ifdef HAVE_LIBGCRYPT
            guint8 inner_payload)
#else
            guint8 inner_payload _U_)
#endif
{
#ifdef HAVE_LIBGCRYPT
  ikev2_decrypt_data_t *key_info = NULL;
  gint iv_len, encr_data_len, icd_len, encr_key_len, decr_data_len, md_len;
  guint8 pad_len;
  guchar *iv = NULL, *encr_data = NULL, *decr_data = NULL, *entire_message = NULL, *md = NULL;
  gcry_cipher_hd_t cipher_hd;
  gcry_md_hd_t md_hd;
  gcry_error_t err = 0;
  proto_item *item = NULL, *icd_item = NULL, *encr_data_item = NULL, *padlen_item = NULL;
  tvbuff_t *decr_tvb = NULL;
  gint payloads_len;
  proto_tree *decr_tree = NULL, *decr_payloads_tree = NULL;


  if (pinfo->private_data) {
    key_info = (ikev2_decrypt_data_t*)(pinfo->private_data);
    encr_key_len = key_info->encr_spec->key_len;
    iv_len = key_info->encr_spec->iv_len;
    icd_len = key_info->auth_spec->trunc_len;
    encr_data_len = length - iv_len - icd_len;

    /*
     * Zero or negative length of encrypted data shows that the user specified
     * wrong encryption algorithm and/or authentication algorithm.
     */
    if (encr_data_len <= 0) {
      item = proto_tree_add_text(tree, tvb, offset, length, "Not enough data for IV, Encrypted data and ICD.");
      expert_add_info_format(pinfo, item, PI_MALFORMED, PI_WARN, "Not enough data in IKEv2 Encrypted payload");
      PROTO_ITEM_SET_GENERATED(item);
      return;
    }

    /*
     * Add the IV to the tree and store it in a packet scope buffer for later decryption 
     * if the specified encryption algorithm uses IV.
     */  
    if (iv_len) {
      proto_tree_add_text(tree, tvb, offset, iv_len, "Initialization Vector (%d bytes): 0x%s",
        iv_len, tvb_bytes_to_str(tvb, offset, iv_len));
      iv = ep_tvb_memdup(tvb, offset, iv_len);

      offset += iv_len;
    }

    /*
     * Add the encrypted portion to the tree and store it in a packet scope buffer for later decryption.
     */
    encr_data_item = proto_tree_add_text(tree, tvb, offset, encr_data_len, "Encrypted Data (%d bytes)", encr_data_len);
    encr_data = ep_tvb_memdup(tvb, offset, encr_data_len);
    offset += encr_data_len;

    /*
     * Add the ICD (Integrity Checksum Data) to the tree before decryption to ensure 
     * the ICD be displayed even if the decryption fails.
     */ 
    if (icd_len) {
      icd_item = proto_tree_add_text(tree, tvb, offset, icd_len, "Integrity Checksum Data (%d bytes) ", icd_len);

      /*
       * Recalculate ICD value if the specified authentication algorithm allows it.
       */ 
      if (key_info->auth_spec->gcry_alg) {
        err = gcry_md_open(&md_hd, key_info->auth_spec->gcry_alg, key_info->auth_spec->gcry_flag);
        if (err) {
          REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 hashing error: algorithm %d: gcry_md_open failed: %s",
            key_info->auth_spec->gcry_alg, gcry_strerror(err)));
        }
        err = gcry_md_setkey(md_hd, key_info->auth_key, key_info->auth_spec->key_len);
        if (err) {
          REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 hashing error: algorithm %s, key length %u: gcry_md_setkey failed: %s",
            gcry_md_algo_name(key_info->auth_spec->gcry_alg), key_info->auth_spec->key_len, gcry_strerror(err)));
        }

        /* Calculate hash over the bytes from the beginning of the ISAKMP header to the right before the ICD. */
        entire_message = ep_tvb_memdup(tvb, 0, offset);
        gcry_md_write(md_hd, entire_message, offset);
        md = gcry_md_read(md_hd, 0);
        md_len = gcry_md_get_algo_dlen(key_info->auth_spec->gcry_alg);
        if (md_len < icd_len) {
          gcry_md_close(md_hd);
          REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 hashing error: algorithm %s: gcry_md_get_algo_dlen returned %d which is smaller than icd length %d",
            gcry_md_algo_name(key_info->auth_spec->gcry_alg), md_len, icd_len));
        }
        if (tvb_memeql(tvb, offset, md, icd_len) == 0) {
          proto_item_append_text(icd_item, "[correct]");
        } else {
          proto_item_append_text(icd_item, "[incorrect, should be %s]", bytes_to_str(md, icd_len));
          expert_add_info_format(pinfo, icd_item, PI_CHECKSUM, PI_WARN, "IKEv2 Integrity Checksum Data is incorrect");
        }
        gcry_md_close(md_hd);
      } else {
        proto_item_append_text(icd_item, "[not validated]");
      }
      offset += icd_len;
    }

    /*
     * Confirm encrypted data length is multiple of block size.
     */ 
    if (encr_data_len % key_info->encr_spec->block_len != 0) {
      proto_item_append_text(encr_data_item, "[Invalid length, should be a multiple of block size (%u)]",
        key_info->encr_spec->block_len);
      expert_add_info_format(pinfo, encr_data_item, PI_MALFORMED, PI_WARN, "Encrypted data length isn't a multiple of block size");
      return;
    }

    /*
     * Allocate buffer for decrypted data.
     */ 
    decr_data = (guchar*)g_malloc(encr_data_len);
    decr_data_len = encr_data_len;

    /*
     * If the cipher is NULL, just copy the encrypted data to the decrypted data buffer. 
     * And otherwise perform decryption with libgcrypt.
     */  
    if (key_info->encr_spec->number == IKEV2_ENCR_NULL) {
      memcpy(decr_data, encr_data, decr_data_len);
    } else {
      err = gcry_cipher_open(&cipher_hd, key_info->encr_spec->gcry_alg, key_info->encr_spec->gcry_mode, 0);
      if (err) {
        g_free(decr_data);
        REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 decryption error: algorithm %d, mode %d: gcry_cipher_open failed: %s",
          key_info->encr_spec->gcry_alg, key_info->encr_spec->gcry_mode, gcry_strerror(err)));
      }
      err = gcry_cipher_setkey(cipher_hd, key_info->encr_key, key_info->encr_spec->key_len);
      if (err) {
        g_free(decr_data);
        REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 decryption error: algorithm %d, key length %d:  gcry_cipher_setkey failed: %s",
          key_info->encr_spec->gcry_alg, key_info->encr_spec->key_len, gcry_strerror(err)));
      }
      err = gcry_cipher_setiv(cipher_hd, iv, iv_len);
      if (err) {
        g_free(decr_data);
        REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 decryption error: algorithm %d, iv length %d:  gcry_cipher_setiv failed: %s",
          key_info->encr_spec->gcry_alg, iv_len, gcry_strerror(err)));
      }
      err = gcry_cipher_decrypt(cipher_hd, decr_data, decr_data_len, encr_data, encr_data_len);
      if (err) {
        g_free(decr_data);
        REPORT_DISSECTOR_BUG(ep_strdup_printf("IKEv2 decryption error: algorithm %d:  gcry_cipher_decrypt failed: %s",
          key_info->encr_spec->gcry_alg, gcry_strerror(err)));
      }
      gcry_cipher_close(cipher_hd);
    }

 
    decr_tvb = tvb_new_real_data(decr_data, decr_data_len, decr_data_len);
    tvb_set_free_cb(decr_tvb, g_free);
    tvb_set_child_real_data_tvbuff(tvb, decr_tvb);
    add_new_data_source(pinfo, decr_tvb, "Decrypted Data");
    item = proto_tree_add_text(tree, decr_tvb, 0, decr_data_len, "Decrypted Data (%d bytes)", decr_data_len);
    /* Move the ICD item to the bottom of the tree. */
    if (icd_item) {
      proto_tree_move_item(tree, item, icd_item);
    }
    decr_tree = proto_item_add_subtree(item, ett_isakmp_decrypted_data);

    pad_len = tvb_get_guint8(decr_tvb, decr_data_len - 1);
    payloads_len = decr_data_len - 1 - pad_len;

    if (payloads_len > 0) {
      item = proto_tree_add_text(decr_tree, decr_tvb, 0, payloads_len, "Contained Payloads (total %d bytes)", payloads_len);
      decr_payloads_tree = proto_item_add_subtree(item, ett_isakmp_decrypted_payloads);
    }

    padlen_item = proto_tree_add_text(decr_tree, decr_tvb, payloads_len + pad_len, 1, "Pad Length: %d", pad_len);
    if (pad_len > 0) {
      if (payloads_len < 0) {
        proto_item_append_text(padlen_item, " [too long]");
        expert_add_info_format(pinfo, padlen_item, PI_MALFORMED, PI_WARN, "Pad length is too big");
      } else {
        item = proto_tree_add_text(decr_tree, decr_tvb, payloads_len, pad_len, "Padding (%d bytes)", pad_len);
        proto_tree_move_item(decr_tree, item, padlen_item);
      }
    }

    /*
     * We dissect the inner payloads at last in order to ensure displaying Padding, Pad Length and ICD 
     * even if the dissection fails. This may occur when the user specify wrong encryption key.
     */
    if (decr_payloads_tree) {
      dissect_payloads(decr_tvb, decr_payloads_tree, decr_tree, isakmp_version, inner_payload, 0, payloads_len, pinfo);
    }
  }else{
#endif /* HAVE_LIBGCRYPT */
    proto_tree_add_text(tree, tvb, offset, 4, "Initialization Vector: 0x%s",
                        tvb_bytes_to_str(tvb, offset, 4));
    proto_tree_add_text(tree, tvb, offset + 4, length, "Encrypted Data");
#ifdef HAVE_LIBGCRYPT
  }
#endif /* HAVE_LIBGCRYPT */
}

static void
dissect_eap(tvbuff_t *tvb, int offset, int length, proto_tree *tree,
    proto_tree *p _U_, packet_info *pinfo _U_, int isakmp_version _U_, int unused _U_, guint8 inner_payload _U_)
{
  tvbuff_t *eap_tvb = NULL;

  eap_tvb = tvb_new_subset(tvb, offset,length, length );
  if ((eap_tvb != NULL)&& eap_handle != NULL){
	  call_dissector(eap_handle, eap_tvb, pinfo, tree);
  }else{
	  proto_tree_add_text(tree, tvb, offset, length, "EAP Message");
  }
}

static const char *
payloadtype2str(int isakmp_version, guint8 type)
{
  struct payload_func *f;

  if ((f = getpayload_func(type, isakmp_version)) != NULL)
      return f->str;

  if (isakmp_version == 1) {
    if (type < 128)
      return "RESERVED";
    return "Private USE";
  } else if (isakmp_version == 2) {
    if (type > 127)
      return "PRIVATE USE";
    if (type > 48)
      return "RESERVED TO IANA";
    return "RESERVED";
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
exchtype2str(int isakmp_version, guint8 type)
{
  static const value_string vs_v1_exchange[] = {
    { 0,	"NONE" },
    { 1,	"Base" },
    { 2,	"Identity Protection (Main Mode)" },
    { 3,	"Authentication Only" },
    { 4,	"Aggressive" },
    { 5,	"Informational" },
    { 6,	"Transaction (Config Mode)" },
    { 32,	"Quick Mode" },
    { 33,	"New Group Mode" },
    { 0,	NULL },
  };

  static const value_string vs_v2_exchange[] = {
    { 34,	"IKE_SA_INIT" },
    { 35,	"IKE_AUTH " },
    { 36,	"CREATE_CHILD_SA" },
    { 37,	"INFORMATIONAL" },
    { 0,	NULL },
  };

  if (isakmp_version == 1) {
    if (type > 6 && type < 32)
      return "ISAKMP Future Use";
    if (type > 33 && type < 240)
      return "DOI Specific Use";
    return val_to_str(type, vs_v1_exchange, "Private Use");
  } else if (isakmp_version == 2) {
    if (type < 34)
      return "RESERVED";
    if (type > 37 && type < 240)
      return "Reserved for IKEv2+";
    return val_to_str(type, vs_v2_exchange, "Reserved for private use");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
doitype2str(guint32 type)
{
  if (type == 1) return "IPSEC";
  return "Unknown DOI Type";
}

static const char *
msgtype2str(int isakmp_version, guint16 type)
{
  static const value_string vs_v1_notifmsg[] = {
    { 0,	"<UNKNOWN>" },
    { 1,	"INVALID-PAYLOAD-TYPE" },
    { 2,	"DOI-NOT-SUPPORTED" },
    { 3,	"SITUATION-NOT-SUPPORTED" },
    { 4,	"INVALID-COOKIE" },
    { 5,	"INVALID-MAJOR-VERSION" },
    { 6,	"INVALID-MINOR-VERSION" },
    { 7,	"INVALID-EXCHANGE-TYPE" },
    { 8,	"INVALID-FLAGS" },
    { 9,	"INVALID-MESSAGE-ID" },
    { 10,	"INVALID-PROTOCOL-ID" },
    { 11,	"INVALID-SPI" },
    { 12,	"INVALID-TRANSFORM-ID" },
    { 13,	"ATTRIBUTES-NOT-SUPPORTED" },
    { 14,	"NO-PROPOSAL-CHOSEN" },
    { 15,	"BAD-PROPOSAL-SYNTAX" },
    { 16,	"PAYLOAD-MALFORMED" },
    { 17,	"INVALID-KEY-INFORMATION" },
    { 18,	"INVALID-ID-INFORMATION" },
    { 19,	"INVALID-CERT-ENCODING" },
    { 20,	"INVALID-CERTIFICATE" },
    { 21,	"CERT-TYPE-UNSUPPORTED" },
    { 22,	"INVALID-CERT-AUTHORITY" },
    { 23,	"INVALID-HASH-INFORMATION" },
    { 24,	"AUTHENTICATION-FAILED" },
    { 25,	"INVALID-SIGNATURE" },
    { 26,	"ADDRESS-NOTIFICATION" },
    { 27,	"NOTIFY-SA-LIFETIME" },
    { 28,	"CERTIFICATE-UNAVAILABLE" },
    { 29,	"UNSUPPORTED-EXCHANGE-TYPE" },
    { 30,	"UNEQUAL-PAYLOAD-LENGTHS" },
    { 8192,	"RESERVED" },
    { 16384,	"CONNECTED" },
    { 24576,	"RESPONDER-LIFETIME" },
    { 24577,	"REPLAY-STATUS" },
    { 24578,	"INITIAL-CONTACT" },
    { 0,	NULL },
  };

  static const value_string vs_v2_notifmsg[] = {
    {     0,	"RESERVED" },
    {     4,	"INVALID_IKE_SPI" },
    {     5,	"INVALID_MAJOR_VERSION" },
    {     7,	"INVALID_SYNTAX" },
    {     9,	"INVALID_MESSAGE_ID" },
    {    11,	"INVALID_SPI" },
    {    14,	"NO_PROPOSAL_CHOSEN" },
    {    17,	"INVALID_KE_PAYLOAD" },
    {    24,	"AUTHENTICATION_FAILED" },
    {    34,	"SINGLE_PAIR_REQUIRED" },
    {    35,	"NO_ADDITIONAL_SAS" },
    {    36,	"INTERNAL_ADDRESS_FAILURE" },
    {    37,	"FAILED_CP_REQUIRED" },
    {    38,	"TS_UNACCEPTABLE" },
    {    39,	"INVALID_SELECTORS" },
    {    40,	"UNACCEPTABLE_ADDRESSES" },
    {    41,	"UNEXPECTED_NAT_DETECTED" },
    { 16384,	"INITIAL_CONTACT" },
    { 16385,	"SET_WINDOW_SIZE" },
    { 16386,	"ADDITIONAL_TS_POSSIBLE" },
    { 16387,	"IPCOMP_SUPPORTED" },
    { 16388,	"NAT_DETECTION_SOURCE_IP" },
    { 16389,	"NAT_DETECTION_DESTINATION_IP" },
    { 16390,	"COOKIE" },
    { 16391,	"USE_TRANSPORT_MODE" },
    { 16392,	"HTTP_CERT_LOOKUP_SUPPORTED" },
    { 16393,	"REKEY_SA" },
    { 16394,	"ESP_TFC_PADDING_NOT_SUPPORTED" },
    { 16395,	"NON_FIRST_FRAGMENTS_ALSO" },
    { 16396,	"MOBIKE_SUPPORTED" },
    { 16397,	"ADDITIONAL_IP4_ADDRESS" },
    { 16398,	"ADDITIONAL_IP6_ADDRESS" },
    { 16399,	"NO_ADDITIONAL_ADDRESSES" },
    { 16400,	"UPDATE_SA_ADDRESSES" },
    { 16401,	"COOKIE2" },
    { 16402,	"NO_NATS_ALLOWED" },
    { 0,	NULL },
  };

  if (isakmp_version == 1) {
    if (type > 30 && type < 8192)
      return "RESERVED (Future Use)";
    if (type > 8192 && type < 16384)
      return "Private Use";
    if (type > 16384 && type < 24576)
      return "RESERVED (Future Use) - status";
    if (type > 24578 && type < 32768)
      return "DOI-specific codes";
    if (type > 32767 && type < 40960)
      return "Private Use - status";
    if (type > 40959 && type < 65535)
      return "RESERVED (Future Use) - status (2)";
    return val_to_str(type, vs_v1_notifmsg, "UNKNOWN-NOTIFY-MESSAGE-TYPE");
  } else if (isakmp_version == 2) {
    if (type >= 42 && type <= 8191)
      return "RESERVED TO IANA - Error types";
    if (type >= 16403 && type <= 40959)
      return "RESERVED TO IANA - STATUS TYPES";
    if (type >= 8192 && type <= 16383)
      return "Private Use - Errors";
    if (type >= 40960)
      return "Private Use - STATUS TYPES";
    return val_to_str(type, vs_v2_notifmsg, "UNKNOWN-NOTIFY-MESSAGE-TYPE");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
situation2str(guint32 type)
{

#define SIT_MSG_NUM	1024
#define SIT_IDENTITY	0x01
#define SIT_SECRECY	0x02
#define SIT_INTEGRITY	0x04

  static char	msg[SIT_MSG_NUM];
  int		n = 0;
  const char *	sep = "";
  int		ret;

  if (type & SIT_IDENTITY) {
    ret = g_snprintf(msg, SIT_MSG_NUM-n, "%sIDENTITY", sep);
    if (ret >= SIT_MSG_NUM-n) {
      /* Truncated. */
      return msg;
    }
    n += ret;
    sep = " & ";
  }
  if (type & SIT_SECRECY) {
    if (n >= SIT_MSG_NUM) {
      /* No more room. */
      return msg;
    }
    ret = g_snprintf(msg, SIT_MSG_NUM-n, "%sSECRECY", sep);
    if (ret >= SIT_MSG_NUM-n) {
      /* Truncated. */
      return msg;
    }
    n += ret;
    sep = " & ";
  }
  if (type & SIT_INTEGRITY) {
    if (n >= SIT_MSG_NUM) {
      /* No more room. */
      return msg;
    }
    ret = g_snprintf(msg, SIT_MSG_NUM-n, "%sINTEGRITY", sep);
    if (ret >= SIT_MSG_NUM-n) {
      /* Truncated. */
      return msg;
    }
    n += ret;
    sep = " & ";
  }

  return msg;
}

static const char *
v2_attrval2str(guint16 att_type, guint32 value)
{
  value = 0;	/* dummy to be less warning in compiling it */
  switch (att_type) {
  case 14:
    return "Key-Length";
  default:
    return "UNKNOWN-ATTRIBUTE-TYPE";
  }
}

static const char *
v1_attrval2str(int ike_p1, guint16 att_type, guint32 value)
{
  static const value_string vs_v1_attrval_lttype[] = {
    { 0,	"RESERVED" },
    { 1,	"Seconds" },
    { 2,	"Kilobytes" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_encap[] = {
    { 0,	"RESERVED" },
    { 1,	"Tunnel" },
    { 2,	"Transport" },
    { 3,	"UDP-Encapsulated-Tunnel" }, /* http://www.ietf.org/internet-drafts/draft-ietf-ipsec-nat-t-ike-05.txt */
    { 4,	"UDP-Encapsulated-Transport" }, /* http://www.ietf.org/internet-drafts/draft-ietf-ipsec-nat-t-ike-05.txt */
    { 61440,	"Check Point IPSec UDP Encapsulation" },
    { 61443,	"UDP-Encapsulated-Tunnel (draft)" },
    { 61444,	"UDP-Encapsulated-Transport (draft)" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_auth[] = {
    { 0,	"RESERVED" },
    { 1,	"HMAC-MD5" },
    { 2,	"HMAC-SHA" },
    { 3,	"DES-MAC" },
    { 4,	"KPDK" },
    { 5,	"HMAC-SHA2-256" },
    { 6,	"HMAC-SHA2-384" },
    { 7,	"HMAC-SHA2-512" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_enc[] = {
    { 0,			"RESERVED" },
    { ENC_DES_CBC,		"DES-CBC" },
    { ENC_IDEA_CBC,		"IDEA-CBC" },
    { ENC_BLOWFISH_CBC,		"BLOWFISH-CBC" },
    { ENC_RC5_R16_B64_CBC,	"RC5-R16-B64-CBC" },
    { ENC_3DES_CBC,		"3DES-CBC" },
    { ENC_CAST_CBC,		"CAST-CBC" },
    { ENC_AES_CBC,		"AES-CBC" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_hash[] = {
    { 0,		"RESERVED" },
    { HMAC_MD5,		"MD5" },
    { HMAC_SHA,		"SHA" },
    { HMAC_TIGER,	"TIGER" },
    { HMAC_SHA2_256,	"SHA2-256" },
    { HMAC_SHA2_384,	"SHA2-384" },
    { HMAC_SHA2_512,	"SHA2-512" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_authmeth[] = {
    { 0,	"RESERVED" },
    { 1,	"PSK" },
    { 2,	"DSS-SIG" },
    { 3,	"RSA-SIG" },
    { 4,	"RSA-ENC" },
    { 5,	"RSA-Revised-ENC" },
    { 6,	"Encryption with El-Gamal" },
    { 7,	"Revised encryption with El-Gamal" },
    { 8,	"ECDSA signatures" },
    { 9,	"AES-XCBC-MAC" },
    { 64221,	"HybridInitRSA" },
    { 64222,	"HybridRespRSA" },
    { 64223,	"HybridInitDSS" },
    { 64224,	"HybridRespDSS" },
    { 65001,	"XAUTHInitPreShared" },
    { 65002,	"XAUTHRespPreShared" },
    { 65003,	"XAUTHInitDSS" },
    { 65004,	"XAUTHRespDSS" },
    { 65005,	"XAUTHInitRSA" },
    { 65006,	"XAUTHRespRSA" },
    { 65007,	"XAUTHInitRSAEncryption" },
    { 65008,	"XAUTHRespRSAEncryption" },
    { 65009,	"XAUTHInitRSARevisedEncryption" },
    { 65010,	"XAUTHRespRSARevisedEncryption" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_grpdesc[] = {
    { 0,	"UNDEFINED - 0" },
    { 1,	"Default 768-bit MODP group" },
    { 2,	"Alternate 1024-bit MODP group" },
    { 3,	"EC2N group on GP[2^155] group" },
    { 4,	"EC2N group on GP[2^185] group" },
    { 5,	"1536 bit MODP group" },
    { 6,	"EC2N group over GF[2^163]" },
    { 7,	"EC2N group over GF[2^163]" },
    { 8,	"EC2N group over GF[2^283]" },
    { 9,	"EC2N group over GF[2^283]" },
    { 10,	"EC2N group over GF[2^409]" },
    { 11,	"EC2N group over GF[2^409]" },
    { 12,	"EC2N group over GF[2^571]" },
    { 13,	"EC2N group over GF[2^571]" },
    { 14,	"2048 bit MODP group" },
    { 15,	"3072 bit MODP group" },
    { 16,	"4096 bit MODP group" },
    { 17,	"6144 bit MODP group" },
    { 18,	"8192 bit MODP group" },
    { 19,       "256-bit random curve group" },
    { 20,       "384-bit random curve group" },
    { 21,       "521-bit random curve group" },
    { 22,       "192-bit random curve group" },
    { 23,       "EC2N group over GF[2^163]" },
    { 24,       "224-bit random curve group" },
    { 25,       "EC2N group over GF[2^233]" },
    { 26,       "EC2N group over GF[2^233]" },
    { 0,	NULL }
  };

  static const value_string vs_v1_attrval_grptype[] = {
    { 0,	"UNDEFINED - 0" },
    { 1,	"MODP" },
    { 2,	"ECP" },
    { 3,	"EC2N" },
    { 0,	NULL },
  };

  static const value_string vs_v1_attrval_lifetype[] = {
    { 0,	"UNDEFINED - 0" },
    { 1,	"Seconds" },
    { 2,	"Kilobytes" },
    { 0,	NULL },
  };

  if (value == 0) return "RESERVED";

  if (!ike_p1) {
    switch (att_type) {
      case 1:
        return val_to_str(value, vs_v1_attrval_lttype, "UNKNOWN-LIFETIME-TYPE");
      case 2:
        return "Duration-Value";
      case 3:
        return "Group-Value";
      case 4:
        return val_to_str(value, vs_v1_attrval_encap, "UNKNOWN-ENCAPSULATION-VALUE");
      case 5:
        return val_to_str(value, vs_v1_attrval_auth, "UNKNOWN-AUTHENTICATION-VALUE");
      case 6:
        return "Key-Length";
      case 7:
        return "Key-Rounds";
      case 8:
        return "Compress-Dictionary-size";
      case 9:
        return "Compress Private Algorithm";
      default:
        return "UNKNOWN-ATTRIBUTE-TYPE";
    }
  }
  else {
    switch (att_type) {
      case 1:
        return val_to_str(value, vs_v1_attrval_enc, "UNKNOWN-ENCRYPTION-ALG");
      case 2:
        return val_to_str(value, vs_v1_attrval_hash, "UNKNOWN-HASH-ALG");
      case 3:
        return val_to_str(value, vs_v1_attrval_authmeth, "UNKNOWN-AUTH-METHOD");
      case 4:
        return val_to_str(value, vs_v1_attrval_grpdesc, "UNKNOWN-GROUP-DESCRIPTION");
      case 6:
      case 7:
      case 8:
      case 9:
      case 10:
      case 16:
        return "Group-Value";
      case 5:
        return val_to_str(value, vs_v1_attrval_grptype, "UNKNOWN-GROUP-TYPE");
      case 11:
        return val_to_str(value, vs_v1_attrval_lifetype, "UNKNOWN-LIFE-TYPE");
      case 12:
        return "Duration-Value";
      case 13:
        return "PRF-Value";
      case 14:
        return "Key-Length";
      case 15:
        return "Field-Size";
      default:
        return "UNKNOWN-ATTRIBUTE-TYPE";
    }
  }
}

static const char *
cfgtype2str(int isakmp_version, guint8 type)
{
  static const value_string vs_v1_cfgtype[] = {
    { 0,	"Reserved" },
    { 1,	"ISAKMP_CFG_REQUEST" },
    { 2,	"ISAKMP_CFG_REPLY" },
    { 3,	"ISAKMP_CFG_SET" },
    { 4,	"ISAKMP_CFG_ACK" },
    { 0,	NULL },
  };

#if 0
  static const value_string vs_v2_cfgtype[] = {
    { 0,	"RESERVED" },
    { 1,	"CFG_REQUEST" },
    { 2,	"CFG_REPLY" },
    { 3,	"CFG_SET" },
    { 4,	"CFG_ACK" },
    { 0,	NULL },
  };
#endif

  if (isakmp_version == 1) {
    if (type >= 5 && type <= 127)
      return "Future use";
    if (type >= 128)
      return "Private Use";
    return val_to_str(type, vs_v1_cfgtype, "UNKNOWN-CFG-TYPE");
  } else if (isakmp_version == 2) {
    if (type >= 5 && type <= 127)
      return "RESERVED TO IANA";
    if (type >= 128)
      return "PRIVATE USE";
    return val_to_str(type, vs_v1_cfgtype, "UNKNOWN-CFG-TYPE");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
id2str(int isakmp_version, guint8 type)
{
  static const value_string vs_ident[] = {
    { IKE_ID_IPV4_ADDR,			"IPV4_ADDR" },
    { IKE_ID_FQDN,				"FQDN" },
    { IKE_ID_USER_FQDN,			"USER_FQDN" },
    { IKE_ID_IPV4_ADDR_SUBNET,	"IPV4_ADDR_SUBNET" },
    { IKE_ID_IPV6_ADDR,			"IPV6_ADDR" },
    { IKE_ID_IPV6_ADDR_SUBNET,	"IPV6_ADDR_SUBNET" },
    { IKE_ID_IPV4_ADDR_RANGE,	"IPV4_ADDR_RANGE" },
    { IKE_ID_IPV6_ADDR_RANGE,	"IPV6_ADDR_RANGE" },
    { IKE_ID_DER_ASN1_DN,		"DER_ASN1_DN" },
    { IKE_ID_DER_ASN1_GN,		"DER_ASN1_GN" },
    { IKE_ID_KEY_ID,			"KEY_ID" },
    { 0,			NULL },
  };

  if (isakmp_version == 1) {
    if (type == 0)
      return "RESERVED";
    return val_to_str(type, vs_ident, "UNKNOWN-ID-TYPE");
  } else if (isakmp_version == 2) {
    if (type == 4 || (type >= 6 && type <=8) || (type >= 12 && type <= 200))
      return "Reserved to IANA";
    if (type >= 201)
      return "Reserved for private use";
    if (type == IKE_ID_USER_FQDN)
      return "RFC822_ADDR";
    return val_to_str(type, vs_ident, "UNKNOWN-ID-TYPE");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
v2_tstype2str(guint8 type)
{
  static const value_string vs_v2_tstype[] = {
    { IKEV2_TS_IPV4_ADDR_RANGE,	"TS_IPV4_ADDR_RANGE" },
    { IKEV2_TS_IPV6_ADDR_RANGE,	"TS_IPV6_ADDR_RANGE" },
    { 0,	NULL },
  };

  if (type <= 6)
    return "RESERVED";
  if (type >= 9 && type <= 240)
    return "RESERVED TO IANA";
  if (type >= 241)
    return "PRIVATE USE";
  return val_to_str(type, vs_v2_tstype, "UNKNOWN-TS-TYPE");
}

static const char *
v2_auth2str(guint8 type)
{
  static const value_string vs_v2_authmeth[] = {
    { 0,	"RESERVED TO IANA" },
    { 1,	"RSA Digital Signature" },
    { 2,	"Shared Key Message Integrity Code" },
    { 3,	"DSS Digital Signature" },
    { 0,	NULL },
  };

  if (type >= 4 && type <= 200)
    return "RESERVED TO IANA";
  if (type >= 201)
    return "PRIVATE USE";
  return val_to_str(type, vs_v2_authmeth, "UNKNOWN-AUTHMETHOD-TYPE");
}

static const char *
cfgattr2str(int isakmp_version, guint16 ident)
{
  static const value_string vs_v1_cfgattr[] = {
    { 0,	"RESERVED" },
    { 1,	"INTERNAL_IP4_ADDRESS" },
    { 2,	"INTERNAL_IP4_NETMASK" },
    { 3,	"INTERNAL_IP4_DNS" },
    { 4,	"INTERNAL_IP4_NBNS" },
    { 5,	"INTERNAL_ADDRESS_EXPIREY" },
    { 6,	"INTERNAL_IP4_DHCP" },
    { 7,	"APPLICATION_VERSION" },
    { 8,	"INTERNAL_IP6_ADDRESS" },
    { 9,	"INTERNAL_IP6_NETMASK" },
    { 10,	"INTERNAL_IP6_DNS" },
    { 11,	"INTERNAL_IP6_NBNS" },
    { 12,	"INTERNAL_IP6_DHCP" },
    { 13,	"INTERNAL_IP4_SUBNET" },
    { 14,	"SUPPORTED_ATTRIBUTES" },
    { 16520,	"XAUTH_TYPE" },
    { 16521,	"XAUTH_USER_NAME" },
    { 16522,	"XAUTH_USER_PASSWORD" },
    { 16523,	"XAUTH_PASSCODE" },
    { 16524,	"XAUTH_MESSAGE" },
    { 16525,	"XAUTH_CHALLANGE" },
    { 16526,	"XAUTH_DOMAIN" },
    { 16527,	"XAUTH_STATUS" },
    { 16528,	"XAUTH_NEXT_PIN" },
    { 16529,	"XAUTH_ANSWER" },
    { 0,	NULL },
  };

  static const value_string vs_v2_cfgattr[] = {
    { 0,	"RESERVED" },
    { 1,	"INTERNAL_IP4_ADDRESS" },
    { 2,	"INTERNAL_IP4_NETMASK" },
    { 3,	"INTERNAL_IP4_DNS" },
    { 4,	"INTERNAL_IP4_NBNS" },
    { 5,	"INTERNAL_ADDRESS_EXPIREY" },
    { 6,	"INTERNAL_IP4_DHCP" },
    { 7,	"APPLICATION_VERSION" },
    { 8,	"INTERNAL_IP6_ADDRESS" },
    { 9,	"RESERVED" },
    { 10,	"INTERNAL_IP6_DNS" },
    { 11,	"INTERNAL_IP6_NBNS" },
    { 12,	"INTERNAL_IP6_DHCP" },
    { 13,	"INTERNAL_IP4_SUBNET" },
    { 14,	"SUPPORTED_ATTRIBUTES" },
    { 15,	"INTERNAL_IP6_SUBNET" },
    { 0,	NULL },
  };

  if (isakmp_version == 1) {
    if (ident >= 15 && ident <= 16383)
      return "Future use";
    if (ident >= 16384 && ident <= 16519)
      return "PRIVATE USE";
    if (ident >= 16530 && ident <= 32767)
      return "PRIVATE USE";
    return val_to_str(ident, vs_v1_cfgattr, "UNKNOWN-CFG-ATTRIBUTE");
  } else if (isakmp_version == 2) {
    if (ident >= 16 && ident <= 16383)
      return "RESERVED TO IANA";
    if (ident >= 16384 && ident <= 32767)
      return "PRIVATE USE";
    return val_to_str(ident, vs_v2_cfgattr, "UNKNOWN-CFG-ATTRIBUTE");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static const char *
certtype2str(int isakmp_version, guint8 type)
{
  static const value_string vs_v1_certtype[] = {
    { 0,	"NONE" },
    { 1,	"PKCS #7 wrapped X.509 certificate" },
    { 2,	"PGP Certificate" },
    { 3,	"DNS Signed Key" },
    { 4,	"X.509 Certificate - Signature" },
    { 5,	"X.509 Certificate - Key Exchange" },
    { 6,	"Kerberos Tokens" },
    { 7,	"Certificate Revocation List (CRL)" },
    { 8,	"Authority Revocation List (ARL)" },
    { 9,	"SPKI Certificate" },
    { 10,	"X.509 Certificate - Attribute" },
    { 0,	NULL },
  };

  static const value_string vs_v2_certtype[] = {
    { 0,	"RESERVED" },
    { 1,	"PKCS #7 wrapped X.509 certificate" },
    { 2,	"PGP Certificate" },
    { 3,	"DNS Signed Key" },
    { 4,	"X.509 Certificate - Signature" },
    { 5,	"*undefined by any document*" },
    { 6,	"Kerberos Tokens" },
    { 7,	"Certificate Revocation List (CRL)" },
    { 8,	"Authority Revocation List (ARL)" },
    { 9,	"SPKI Certificate" },
    { 10,	"X.509 Certificate - Attribute" },
    { 11,	"Raw RSA Key" },
    { 12,	"Hash and URL of X.509 certificate" },
    { 13,	"Hash and URL of X.509 bundle" },
    { 0,	NULL },
  };

  if (isakmp_version == 1)
    return val_to_str(type, vs_v1_certtype, "RESERVED");
  else if (isakmp_version == 2) {
    if (type >= 14 && type <= 200)
      return "RESERVED to IANA";
    if (type >= 201)
      return "PRIVATE USE";
    return val_to_str(type, vs_v2_certtype, "RESERVED");
  }
  return "UNKNOWN-ISAKMP-VERSION";
}

static gboolean
get_num(tvbuff_t *tvb, int offset, guint16 len, guint32 *num_p)
{
  switch (len) {
  case 1:
    *num_p = tvb_get_guint8(tvb, offset);
    break;
  case 2:
    *num_p = tvb_get_ntohs(tvb, offset);
    break;
  case 3:
    *num_p = tvb_get_ntoh24(tvb, offset);
    break;
  case 4:
    *num_p = tvb_get_ntohl(tvb, offset);
    break;
  default:
    return FALSE;
  }

  return TRUE;
}

/*
 * Protocol initialization
 */

#ifdef HAVE_LIBGCRYPT
static guint
isakmp_hash_func(gconstpointer c) {
  guint8 *i_cookie = (guint8 *) c;
  guint   val = 0, keychunk, i;

  /* XOR our icookie down to the size of a guint */
  for (i = 0; i < COOKIE_SIZE - (COOKIE_SIZE % sizeof(keychunk)); i += sizeof(keychunk)) {
    memcpy(&keychunk, &i_cookie[i], sizeof(keychunk));
    val ^= keychunk;
  }

  return val;
}

static gint
isakmp_equal_func(gconstpointer ic1, gconstpointer ic2) {

  if (memcmp(ic1, ic2, COOKIE_SIZE) == 0)
    return 1;

  return 0;
}

static guint ikev2_key_hash_func(gconstpointer k) {
  const ikev2_uat_data_key_t *key = (const ikev2_uat_data_key_t*)k;
  guint hash = 0, keychunk, i;

  /* XOR our icookie down to the size of a guint */
  for (i = 0; i < key->spii_len - (key->spii_len % sizeof(keychunk)); i += sizeof(keychunk)) {
    memcpy(&keychunk, &key->spii[i], sizeof(keychunk));
    hash ^= keychunk;
  }
  for (i = 0; i < key->spir_len - (key->spir_len % sizeof(keychunk)); i += sizeof(keychunk)) {
    memcpy(&keychunk, &key->spir[i], sizeof(keychunk));
    hash ^= keychunk;
  }

  return hash;
}

static gint ikev2_key_equal_func(gconstpointer k1, gconstpointer k2) {
  const ikev2_uat_data_key_t *key1 = k1, *key2 = k2;
  if (key1->spii_len != key2->spii_len) return 0;
  if (key1->spir_len != key2->spir_len) return 0;
  if (memcmp(key1->spii, key2->spii, key1->spii_len) != 0) return 0;
  if (memcmp(key1->spir, key2->spir, key1->spir_len) != 0) return 0;

  return 1;
}
#endif /* HAVE_LIBGCRYPT */

static void
isakmp_init_protocol(void) {
#ifdef HAVE_LIBGCRYPT
  guint i;
#endif /* HAVE_LIBGCRYPT */
  fragment_table_init(&isakmp_fragment_table);
  reassembled_table_init(&isakmp_reassembled_table);

#ifdef HAVE_LIBGCRYPT
  if (isakmp_hash) {
    g_hash_table_destroy(isakmp_hash);
  }
  if (isakmp_key_data)
    g_mem_chunk_destroy(isakmp_key_data);
  if (isakmp_decrypt_data)
    g_mem_chunk_destroy(isakmp_decrypt_data);

  isakmp_hash = g_hash_table_new(isakmp_hash_func, isakmp_equal_func);
  isakmp_key_data = g_mem_chunk_new("isakmp_key_data",
	COOKIE_SIZE, 5 * COOKIE_SIZE,
	G_ALLOC_AND_FREE);
  isakmp_decrypt_data = g_mem_chunk_new("isakmp_decrypt_data",
	sizeof(decrypt_data_t), 5 * sizeof(decrypt_data_t),
	G_ALLOC_AND_FREE);
  if (logf)
    fclose(logf);
  logf = ws_fopen(pluto_log_path, "r");

  scan_pluto_log();

  if (ikev2_key_hash) {
    g_hash_table_destroy(ikev2_key_hash);
  }

  ikev2_key_hash = g_hash_table_new(ikev2_key_hash_func, ikev2_key_equal_func);
  for (i = 0; i < num_ikev2_uat_data; i++) {
    g_hash_table_insert(ikev2_key_hash, &(ikev2_uat_data[i].key), &(ikev2_uat_data[i]));
  }
#endif /* HAVE_LIBGCRYPT */
}

static void
isakmp_prefs_apply_cb(void) {
#ifdef HAVE_LIBGCRYPT
  isakmp_init_protocol();
#endif /* HAVE_LIBGCRYPT */
}

#ifdef HAVE_LIBGCRYPT
UAT_BUFFER_CB_DEF(ikev2_users, spii, ikev2_uat_data_t, key.spii, key.spii_len)
UAT_BUFFER_CB_DEF(ikev2_users, spir, ikev2_uat_data_t, key.spir, key.spir_len)
UAT_BUFFER_CB_DEF(ikev2_users, sk_ei, ikev2_uat_data_t, sk_ei, sk_ei_len)
UAT_BUFFER_CB_DEF(ikev2_users, sk_er, ikev2_uat_data_t, sk_er, sk_er_len)
UAT_VS_DEF(ikev2_users, encr_alg, ikev2_uat_data_t, IKEV2_ENCR_3DES, "3DES")
UAT_BUFFER_CB_DEF(ikev2_users, sk_ai, ikev2_uat_data_t, sk_ai, sk_ai_len)
UAT_BUFFER_CB_DEF(ikev2_users, sk_ar, ikev2_uat_data_t, sk_ar, sk_ar_len)
UAT_VS_DEF(ikev2_users, auth_alg, ikev2_uat_data_t, IKEV2_AUTH_HMAC_SHA1_96, "HMAC_SHA1_96") 

static void ikev2_uat_data_update_cb(void* p, const char** err) {
  ikev2_uat_data_t *ud = p;

  if (ud->key.spii_len != COOKIE_SIZE) {
    *err = ep_strdup_printf("Length of Initiator's SPI must be %d octets (%d hex charactors).", COOKIE_SIZE, COOKIE_SIZE * 2);
    return;
  }

  if (ud->key.spir_len != COOKIE_SIZE) {
    *err = ep_strdup_printf("Length of Responder's SPI must be %d octets (%d hex charactors).", COOKIE_SIZE, COOKIE_SIZE * 2);
    return;
  }

  if ((ud->encr_spec = ikev2_decrypt_find_encr_spec(ud->encr_alg)) == NULL) {
    REPORT_DISSECTOR_BUG("Couldn't get IKEv2 encryption algorithm spec.");
  }

  if ((ud->auth_spec = ikev2_decrypt_find_auth_spec(ud->auth_alg)) == NULL) {
    REPORT_DISSECTOR_BUG("Couldn't get IKEv2 authentication algorithm spec.");
  }

  if (ud->sk_ei_len != ud->encr_spec->key_len) {
    *err = ep_strdup_printf("Length of SK_ei (%u octets) does not match the key length (%u octets) of the selected encryption algorithm.",
             ud->sk_ei_len, ud->encr_spec->key_len);
    return;
  }

  if (ud->sk_er_len != ud->encr_spec->key_len) {
    *err = ep_strdup_printf("Length of SK_er (%u octets) does not match the key length (%u octets) of the selected encryption algorithm.",
             ud->sk_er_len, ud->encr_spec->key_len);
    return;
  }

  if (ud->sk_ai_len != ud->auth_spec->key_len) {
    *err = ep_strdup_printf("Length of SK_ai (%u octets) does not match the key length (%u octets) of the selected integrity algorithm.",
             ud->sk_ai_len, ud->auth_spec->key_len);
    return;
  }

  if (ud->sk_ar_len != ud->auth_spec->key_len) {
    *err = ep_strdup_printf("Length of SK_ar (%u octets) does not match the key length (%u octets) of the selected integrity algorithm.",
             ud->sk_ar_len, ud->auth_spec->key_len);
    return;
  }
}
#endif /* HAVE_LIBGCRYPT */

void
proto_register_isakmp(void)
{
  module_t *isakmp_module;

  static hf_register_info hf[] = {
    { &hf_isakmp_icookie,
      { "Initiator cookie", "isakmp.icookie",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "ISAKMP Initiator Cookie", HFILL }},
    { &hf_isakmp_rcookie,
      { "Responder cookie", "isakmp.rcookie",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "ISAKMP Responder Cookie", HFILL }},
    { &hf_isakmp_nextpayload,
      { "Next payload", "isakmp.nextpayload",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Next Payload", HFILL }},
    { &hf_isakmp_version,
      { "Version", "isakmp.version",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "ISAKMP Version (major + minor)", HFILL }},
    { &hf_isakmp_exchangetype,
      { "Exchange type", "isakmp.exchangetype",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Exchange Type", HFILL }},
    { &hf_isakmp_flags,
      { "Flags", "isakmp.flags",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        "ISAKMP Flags", HFILL }},
    { &hf_isakmp_messageid,
      { "Message ID", "isakmp.messageid",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        "ISAKMP Message ID", HFILL }},
    { &hf_isakmp_length,
      { "Length", "isakmp.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "ISAKMP Length", HFILL }},
    { &hf_isakmp_payloadlen,
      { "Payload length", "isakmp.payloadlength",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ISAKMP Payload Length", HFILL }},
    { &hf_isakmp_doi,
      { "Domain of interpretation", "isakmp.doi",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "ISAKMP Domain of Interpretation", HFILL }},
    { &hf_isakmp_sa_situation,
      { "Situation", "isakmp.sa.situation",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        "ISAKMP SA Situation", HFILL }},
    { &hf_isakmp_prop_number,
      { "Proposal number", "isakmp.prop.number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Proposal Number", HFILL }},
    { &hf_isakmp_spisize,
      { "SPI Size", "isakmp.spisize",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP SPI Size", HFILL }},
    { &hf_isakmp_prop_transforms,
      { "Proposal transforms", "isakmp.prop.transforms",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Proposal Transforms", HFILL }},
    { &hf_isakmp_trans_number,
      { "Transform number", "isakmp.trans.number",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Transform Number", HFILL }},
    { &hf_isakmp_trans_id,
      { "Transform ID", "isakmp.trans.id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Transform ID", HFILL }},
    { &hf_isakmp_id_type,
      { "ID type", "isakmp.id.type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP ID Type", HFILL }},
    { &hf_isakmp_protoid,
      { "Protocol ID", "isakmp.protoid",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Protocol ID", HFILL }},
    { &hf_isakmp_id_port,
      { "Port", "isakmp.id.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ISAKMP ID Port", HFILL }},
    { &hf_isakmp_cert_encoding,
      { "Port", "isakmp.cert.encoding",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Certificate Encoding", HFILL }},
    { &hf_isakmp_certificate,
      { "Certificate", "isakmp.certificate",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "ISAKMP Certificate Encoding", HFILL }},
    { &hf_isakmp_certreq_type,
      { "Port", "isakmp.certreq.type",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Certificate Request Type", HFILL }},
    { &hf_isakmp_notify_msgtype,
      { "Port", "isakmp.notify.msgtype",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP Notify Message Type", HFILL }},
    { &hf_isakmp_num_spis,
      { "Port", "isakmp.spinum",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        "ISAKMP Number of SPIs", HFILL }},
    { &hf_isakmp_cisco_frag_packetid,
      { "Frag ID", "isakmp.frag.packetid",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        "ISAKMP fragment packet-id", HFILL }},
    { &hf_isakmp_cisco_frag_seq,
      { "Frag seq", "isakmp.frag.packetid",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "ISAKMP fragment number", HFILL }},
    { &hf_isakmp_cisco_frag_last,
      { "Frag last", "isakmp.frag.last",
        FT_UINT8, BASE_DEC, VALS(frag_last_vals), 0x0,
        "ISAKMP last fragment", HFILL }},
    { &hf_isakmp_fragments,
            {"Message fragments", "msg.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_isakmp_fragment,
            {"Message fragment", "msg.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_isakmp_fragment_overlap,
            {"Message fragment overlap", "msg.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_isakmp_fragment_overlap_conflicts,
            {"Message fragment overlapping with conflicting data",
            "msg.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_isakmp_fragment_multiple_tails,
            {"Message has multiple tail fragments",
            "msg.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_isakmp_fragment_too_long_fragment,
            {"Message fragment too long", "msg.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_isakmp_fragment_error,
            {"Message defragmentation error", "msg.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_isakmp_reassembled_in,
            {"Reassembled in", "msg.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_isakmp_certificate_authority,
      { "Certificate Authority Distinguished Name", "ike.cert_authority_dn", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
    },
    { &hf_isakmp_v2_certificate_authority,
      { "Certificate Authority", "ike.cert_authority", FT_BYTES, BASE_NONE, NULL, 0x0, "SHA-1 hash of the Certificate Authority", HFILL }
    },
    { &hf_isakmp_nat_keepalive,
      { "NAT Keepalive", "ike.nat_keepalive", FT_NONE, BASE_NONE, NULL, 0x0, "NAT Keepalive packet", HFILL }
    },
  };


  static gint *ett[] = {
    &ett_isakmp,
    &ett_isakmp_flags,
    &ett_isakmp_payload,
    &ett_isakmp_fragment,
    &ett_isakmp_fragments,
#ifdef HAVE_LIBGCRYPT
    &ett_isakmp_decrypted_data,
    &ett_isakmp_decrypted_payloads
#endif /* HAVE_LIBGCRYPT */
  };
#ifdef HAVE_LIBGCRYPT
  static uat_field_t ikev2_uat_flds[] = {
    UAT_FLD_BUFFER(ikev2_users, spii, "Initiator's SPI", "Initiator's SPI value of the IKE_SA"),
    UAT_FLD_BUFFER(ikev2_users, spir, "Responder's SPI", "Responder's SPI value of the IKE_SA"),
    UAT_FLD_BUFFER(ikev2_users, sk_ei, "SK_ei", "Key used to encrypt/decrypt IKEv2 packets from initiator to responder"),
    UAT_FLD_BUFFER(ikev2_users, sk_er, "SK_er", "Key used to encrypt/decrypt IKEv2 packets from responder to initiator"),
    UAT_FLD_VS(ikev2_users, encr_alg, "Encryption algorithm", vs_ikev2_encr_algs, "Encryption algorithm of IKE_SA"),
    UAT_FLD_BUFFER(ikev2_users, sk_ai, "SK_ai", "Key used to calculate Integrity Checksum Data for IKEv2 packets from initiator to responder"),
    UAT_FLD_BUFFER(ikev2_users, sk_ar, "SK_ar", "Key used to calculate Integrity Checksum Data for IKEv2 packets from responder to initiator"),
    UAT_FLD_VS(ikev2_users, auth_alg, "Integrity algorithm", vs_ikev2_auth_algs, "Integrity algorithm of IKE_SA"),
    UAT_END_FIELDS
  };
#endif /* HAVE_LIBGCRYPT */
  proto_isakmp = proto_register_protocol("Internet Security Association and Key Management Protocol",
					       "ISAKMP", "isakmp");
  proto_register_field_array(proto_isakmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine(&isakmp_init_protocol);

  register_dissector("isakmp", dissect_isakmp, proto_isakmp);

  isakmp_module = prefs_register_protocol(proto_isakmp, isakmp_prefs_apply_cb);
#ifdef HAVE_LIBGCRYPT
  prefs_register_string_preference(isakmp_module, "log",
    "Log Filename",
    "Path to a pluto log file containing DH secret information",
    &pluto_log_path);

  ikev2_uat = uat_new("IKEv2 Decryption Table",
      sizeof(ikev2_uat_data_t),
      "ikev2_decryption_table",
      TRUE,
      (void*)&ikev2_uat_data,
      &num_ikev2_uat_data,
      UAT_CAT_CRYPTO,
      "ChIKEv2DecryptionSection",
      NULL,
      ikev2_uat_data_update_cb,
      NULL,
      ikev2_uat_flds);

  prefs_register_uat_preference(isakmp_module,
      "ikev2_decryption_table",
      "IKEv2 Decryption Table",
      "Table of IKE_SA security parameters for decryption of IKEv2 packets",
      ikev2_uat);

#endif /* HAVE_LIBGCRYPT */
}

void
proto_reg_handoff_isakmp(void)
{
  dissector_handle_t isakmp_handle;

  isakmp_handle = find_dissector("isakmp");
  eap_handle = find_dissector("eap");
  dissector_add("udp.port", UDP_PORT_ISAKMP, isakmp_handle);
  dissector_add("tcp.port", TCP_PORT_ISAKMP, isakmp_handle);
}
