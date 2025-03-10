/* packet-pkcs12.c
 * Routines for PKCS#12: Personal Information Exchange packet dissection
 * Graeme Lunt 2006
 *
 * See "PKCS #12 v1.1: Personal Information Exchange Syntax":
 *
 *    http://www.emc.com/emc-plus/rsa-labs/pkcs/files/h11301-wp-pkcs-12v1-1-personal-information-exchange-syntax.pdf
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <wsutil/array.h>

#include "packet-akp.h"
#include "packet-ber.h"
#include "packet-pkcs12.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-cms.h"

#include <wsutil/wsgcrypt.h>

#define PNAME  "PKCS#12: Personal Information Exchange"
#define PSNAME "PKCS12"
#define PFNAME "pkcs12"

#define PKCS12_PBE_ARCFOUR_SHA1_OID     "1.2.840.113549.1.12.1.1"
#define PKCS12_PBE_3DES_SHA1_OID	"1.2.840.113549.1.12.1.3"
#define PKCS12_PBE_RC2_40_SHA1_OID	"1.2.840.113549.1.12.1.6"

void proto_register_pkcs12(void);
void proto_reg_handoff_pkcs12(void);

/* Initialize the protocol and registered fields */
static int proto_pkcs12;

static int hf_pkcs12_X509Certificate_PDU;
static int hf_pkcs12_AuthenticatedSafe_PDU;  /* AuthenticatedSafe */
static int ett_decrypted_pbe;

static expert_field ei_pkcs12_octet_string_expected;


static const char *object_identifier_id;
static int iteration_count;
static tvbuff_t *salt;
static const char *password;
static bool try_null_password;

static int dissect_AuthenticatedSafe_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
static int dissect_SafeContents_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

#include "packet-pkcs12-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkcs12-ett.c"

static void append_oid(wmem_allocator_t *pool, proto_tree *tree, const char *oid)
{
  	const char *name = NULL;

	name = oid_resolved_from_string(pool, oid);
	proto_item_append_text(tree, " (%s)", name ? name : oid);
}

static int
generate_key_or_iv(packet_info *pinfo, unsigned int id, tvbuff_t *salt_tvb, unsigned int iter,
		       const char *pw, unsigned int req_keylen, char * keybuf)
{
  int rc;
  unsigned int i, j;
  gcry_md_hd_t md;
  gcry_mpi_t num_b1 = NULL;
  size_t pwlen;
  char hash[20], buf_b[64], buf_i[128], *p;
  char *salt_p;
  int salt_size;
  size_t cur_keylen;
  size_t n;
  gcry_error_t	err;

  cur_keylen = 0;

  salt_size = tvb_captured_length(salt_tvb);
  salt_p = (char *)tvb_memdup(pinfo->pool, salt_tvb, 0, salt_size);

  if (pw == NULL)
    pwlen = 0;
  else
    pwlen = strlen(pw);

  if (pwlen > 63 / 2) {
    return false;
  }

  /* Store salt and password in BUF_I */
  p = buf_i;
  for (i = 0; i < 64; i++)
    *p++ = salt_p[i % salt_size];

  if (pw) {
    for (i = j = 0; i < 64; i += 2) {
      *p++ = 0;
      *p++ = pw[j];
      if (++j > pwlen)	/* Note, that we include the trailing zero */
        j = 0;
    }
  }
  else
    memset (p, 0, 64);

  for (;;) {
      err = gcry_md_open(&md, GCRY_MD_SHA1, 0);
      if (gcry_err_code(err)) {
        return false;
      }
      for (i = 0; i < 64; i++) {
        unsigned char lid = id & 0xFF;
        gcry_md_write (md, &lid, 1);
      }

      gcry_md_write(md, buf_i, pw ? 128 : 64);

      gcry_md_final (md);
      memcpy (hash, gcry_md_read (md, 0), 20);

      gcry_md_close (md);

      for (i = 1; i < iter; i++)
        gcry_md_hash_buffer (GCRY_MD_SHA1, hash, hash, 20);

      for (i = 0; i < 20 && cur_keylen < req_keylen; i++)
        keybuf[cur_keylen++] = hash[i];

      if (cur_keylen == req_keylen) {
        gcry_mpi_release (num_b1);
        return true;		/* ready */
      }

      /* need more bytes. */
      for (i = 0; i < 64; i++)
        buf_b[i] = hash[i % 20];

      n = 64;

      rc = gcry_mpi_scan (&num_b1, GCRYMPI_FMT_USG, buf_b, n, &n);

      if (rc != 0) {
        return false;
      }

      gcry_mpi_add_ui (num_b1, num_b1, 1);

      for (i = 0; i < 128; i += 64) {
        gcry_mpi_t num_ij;

        n = 64;
        rc = gcry_mpi_scan (&num_ij, GCRYMPI_FMT_USG, buf_i + i, n, &n);

        if (rc != 0) {
          return false;
        }

        gcry_mpi_add (num_ij, num_ij, num_b1);
        gcry_mpi_clear_highbit (num_ij, 64 * 8);

        n = 64;

        rc = gcry_mpi_print (GCRYMPI_FMT_USG, buf_i + i, n, &n, num_ij);
        if (rc != 0) {
          return false;
        }

        gcry_mpi_release (num_ij);
      }
  }
}

void PBE_reset_parameters(void)
{
	iteration_count = 0;
	salt = NULL;
}

int PBE_decrypt_data(dissector_t dissector, const char *description, tvbuff_t *encrypted_tvb, packet_info *pinfo, asn1_ctx_t *actx, proto_item *item)
{
	const char	*encryption_algorithm;
	gcry_cipher_hd_t cipher;
	gcry_error_t	err;
	int		algo;
	int		mode;
	int		ivlen = 0;
	int		keylen = 0;
	int		datalen = 0;
	char		*key = NULL;
	char		*iv = NULL;
	char		*clear_data = NULL;
	tvbuff_t	*clear_tvb = NULL;
	GString		*name;
	proto_tree	*tree;
	char		byte;
	bool	decrypt_ok = true;

	if(((password == NULL) || (*password == '\0')) && (try_null_password == false)) {
		/* we are not configured to decrypt */
		return false;
	}

	encryption_algorithm = x509af_get_last_algorithm_id();

	/* these are the only encryption schemes we understand for now */
	if(!strcmp(encryption_algorithm, PKCS12_PBE_3DES_SHA1_OID)) {
		ivlen = 8;
		keylen = 24;
		algo = GCRY_CIPHER_3DES;
		mode = GCRY_CIPHER_MODE_CBC;
	} else if(!strcmp(encryption_algorithm, PKCS12_PBE_ARCFOUR_SHA1_OID)) {
		ivlen = 0;
		keylen = 16;
		algo = GCRY_CIPHER_ARCFOUR;
		mode = GCRY_CIPHER_MODE_NONE;
	} else if(!strcmp(encryption_algorithm, PKCS12_PBE_RC2_40_SHA1_OID)) {
		ivlen = 8;
		keylen = 5;
		algo = GCRY_CIPHER_RFC2268_40;
		mode = GCRY_CIPHER_MODE_CBC;
	} else {
		/* we don't know how to decrypt this */

		proto_item_append_text(item, " [Unsupported encryption algorithm]");
		return false;
	}

	if((iteration_count == 0) || (salt == NULL)) {
		proto_item_append_text(item, " [Insufficient parameters]");
		return false;
	}

	/* allocate buffers */
	key = (char *)wmem_alloc(pinfo->pool, keylen);

	if(!generate_key_or_iv(pinfo, 1 /*LEY */, salt, iteration_count, password, keylen, key))
		return false;

	if(ivlen) {

		iv = (char *)wmem_alloc(pinfo->pool, ivlen);

		if(!generate_key_or_iv(pinfo, 2 /* IV */, salt, iteration_count, password, ivlen, iv))
			return false;
	}

	/* now try an internal function */
	err = gcry_cipher_open(&cipher, algo, mode, 0);
	if (gcry_err_code (err))
			return false;

	err = gcry_cipher_setkey (cipher, key, keylen);
	if (gcry_err_code (err)) {
			gcry_cipher_close (cipher);
			return false;
	}

	if(ivlen) {
		  err = gcry_cipher_setiv (cipher, iv, ivlen);
		  if (gcry_err_code (err)) {
			  gcry_cipher_close (cipher);
			  return false;
		  }
	}

	datalen = tvb_captured_length(encrypted_tvb);
	clear_data = (char *)wmem_alloc(pinfo->pool, datalen);

	err = gcry_cipher_decrypt (cipher, clear_data, datalen, (char *)tvb_memdup(pinfo->pool, encrypted_tvb, 0, datalen), datalen);
	if (gcry_err_code (err)) {

		proto_item_append_text(item, " [Failed to decrypt with password preference]");

		gcry_cipher_close (cipher);
		return false;
	}

	gcry_cipher_close (cipher);

	/* We don't know if we have successfully decrypted the data or not so we:
		a) check the trailing bytes
		b) see if we start with a sequence or a set (is this too constraining?
		*/

	/* first the trailing bytes */
	byte = clear_data[datalen-1];
	if(byte <= 0x08) {
		int i;

		for(i = (int)byte; i > 0 ; i--) {
			if(clear_data[datalen - i] != byte) {
				decrypt_ok = false;
				break;
			}
		}
	} else {
		/* XXX: is this a failure? */
	}

	/* we assume the result is ASN.1 - check it is a SET or SEQUENCE */
	byte = clear_data[0];
	if((byte != 0x30) && (byte != 0x31)) { /* do we need more here? OCTET STRING? */
		decrypt_ok = false;
	}

	if(!decrypt_ok) {
		proto_item_append_text(item, " [Failed to decrypt with supplied password]");

		return false;
	}

	proto_item_append_text(item, " [Decrypted successfully]");

	tree = proto_item_add_subtree(item, ett_decrypted_pbe);

	/* OK - so now clear_data contains the decrypted data */

	clear_tvb = tvb_new_child_real_data(encrypted_tvb,(const uint8_t *)clear_data, datalen, datalen);

	name = g_string_new("");
	g_string_printf(name, "Decrypted %s", description);

	/* add it as a new source */
	add_new_data_source(actx->pinfo, clear_tvb, name->str);

	g_string_free(name, TRUE);

	/* now try and decode it */
	dissector(clear_tvb, actx->pinfo, tree, NULL);

	return true;
}

#include "packet-pkcs12-fn.c"

static int strip_octet_string(tvbuff_t *tvb)
{
  int8_t ber_class;
  bool pc, ind;
  int32_t tag;
  uint32_t len;
  int offset = 0;

  /* PKCS#7 encodes the content as OCTET STRING, whereas CMS is just any ANY */
  /* if we use CMS (rather than PKCS#7) - which we are - we need to strip the OCTET STRING tag */
  /* before proceeding */

  offset = get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);
  offset = get_ber_length(tvb, offset, &len, &ind);

  if((ber_class == BER_CLASS_UNI) && (tag == BER_UNI_TAG_OCTETSTRING))
    return offset;

  return 0;

}

static int dissect_AuthenticatedSafe_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

  if((offset = strip_octet_string(tvb)) > 0)
    dissect_pkcs12_AuthenticatedSafe(false, tvb, offset, &asn1_ctx, tree, hf_pkcs12_AuthenticatedSafe_PDU);
  else
    proto_tree_add_expert(tree, pinfo, &ei_pkcs12_octet_string_expected, tvb, 0, 1);
  return tvb_captured_length(tvb);
}

static int dissect_SafeContents_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

  offset = strip_octet_string(tvb);

  dissect_pkcs12_SafeContents(false, tvb, offset, &asn1_ctx, tree, hf_pkcs12_SafeContents_PDU);
  return tvb_captured_length(tvb);
}

static int dissect_X509Certificate_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

  if((offset = strip_octet_string(tvb)) > 0)
	dissect_x509af_Certificate(false, tvb, offset, &asn1_ctx, tree, hf_pkcs12_X509Certificate_PDU);
  else
	proto_tree_add_expert(tree, pinfo, &ei_pkcs12_octet_string_expected, tvb, 0, 1);

  return tvb_captured_length(tvb);
}

/*--- proto_register_pkcs12 ----------------------------------------------*/
void proto_register_pkcs12(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_pkcs12_X509Certificate_PDU,
      { "X509Certificate", "pkcs12.X509Certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.X509Certificate", HFILL }},
    { &hf_pkcs12_AuthenticatedSafe_PDU,
      { "AuthenticatedSafe", "pkcs12.AuthenticatedSafe",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},

#include "packet-pkcs12-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
	  &ett_decrypted_pbe,
#include "packet-pkcs12-ettarr.c"
  };
  static ei_register_info ei[] = {
      { &ei_pkcs12_octet_string_expected, { "pkcs12.octet_string_expected", PI_PROTOCOL, PI_WARN, "BER Error: OCTET STRING expected", EXPFILL }},
  };

  module_t *pkcs12_module;
  expert_module_t* expert_pkcs12;

  /* Register protocol */
  proto_pkcs12 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkcs12, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_pkcs12 = expert_register_protocol(proto_pkcs12);
  expert_register_field_array(expert_pkcs12, ei, array_length(ei));

  /* Register preferences */
  pkcs12_module = prefs_register_protocol(proto_pkcs12, NULL);

  prefs_register_string_preference(pkcs12_module, "password",
	"Password to decrypt the file with",
	"The password to used to decrypt the encrypted elements within"
	" the PKCS#12 file", &password);

  prefs_register_bool_preference(pkcs12_module, "try_null_password",
	"Try to decrypt with a empty password",
	"Whether to try and decrypt the encrypted data within the"
	" PKCS#12 with a NULL password", &try_null_password);

  register_ber_syntax_dissector("PKCS#12", proto_pkcs12, dissect_PFX_PDU);
  register_ber_oid_syntax(".p12", NULL, "PKCS#12");
  register_ber_oid_syntax(".pfx", NULL, "PKCS#12");
}


/*--- proto_reg_handoff_pkcs12 -------------------------------------------*/
void proto_reg_handoff_pkcs12(void) {
#include "packet-pkcs12-dis-tab.c"

	register_ber_oid_dissector("1.2.840.113549.1.9.22.1", dissect_X509Certificate_OCTETSTRING_PDU, proto_pkcs12, "x509Certificate");

	register_ber_oid_dissector("1.2.840.113549.2.7", dissect_ber_oid_NULL_callback, proto_pkcs12, "id-hmacWithSHA1");
	register_ber_oid_dissector("1.2.840.113549.2.8", dissect_ber_oid_NULL_callback, proto_pkcs12, "id-hmacWithSHA224");
	register_ber_oid_dissector("1.2.840.113549.2.9", dissect_ber_oid_NULL_callback, proto_pkcs12, "id-hmacWithSHA256");
	register_ber_oid_dissector("1.2.840.113549.2.10", dissect_ber_oid_NULL_callback, proto_pkcs12, "id-hmacWithSHA384");
	register_ber_oid_dissector("1.2.840.113549.2.11", dissect_ber_oid_NULL_callback, proto_pkcs12, "id-hmacWithSHA512");
	register_ber_oid_dissector("1.2.840.113549.2.12", dissect_ber_oid_NULL_callback, proto_pkcs12, "id-hmacWithSHA512-224");
	register_ber_oid_dissector("1.2.840.113549.2.13", dissect_ber_oid_NULL_callback, proto_pkcs12, "id-hmacWithSHA512-256");
}

