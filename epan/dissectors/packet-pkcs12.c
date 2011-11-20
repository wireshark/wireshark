/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-pkcs12.c                                                            */
/* ../../tools/asn2wrs.py -b -p pkcs12 -c ./pkcs12.cnf -s ./packet-pkcs12-template -D . -O ../../epan/dissectors pkcs12.asn */

/* Input file: packet-pkcs12-template.c */

#line 1 "../../asn1/pkcs12/packet-pkcs12-template.c"
/* packet-pkcs12.c
 * Routines for PKCS#12: Personal Information Exchange packet dissection
 * Graeme Lunt 2006
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/prefs.h>

#include "packet-ber.h"
#include "packet-pkcs12.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-cms.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#define PNAME  "PKCS#12: Personal Information Exchange"
#define PSNAME "PKCS12"
#define PFNAME "pkcs12"

#define PKCS12_PBE_ARCFOUR_SHA1_OID     "1.2.840.113549.1.12.1.1"
#define PKCS12_PBE_3DES_SHA1_OID	"1.2.840.113549.1.12.1.3"
#define PKCS12_PBE_RC2_40_SHA1_OID	"1.2.840.113549.1.12.1.6"

/* Initialize the protocol and registered fields */
static int proto_pkcs12 = -1;

static int hf_pkcs12_X509Certificate_PDU = -1;
static gint ett_decrypted_pbe = -1;

static const char *object_identifier_id = NULL;
static int iteration_count = 0;
static tvbuff_t *salt = NULL;
static const char *password = NULL;
static gboolean try_null_password = FALSE;

static void dissect_AuthenticatedSafe_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_SafeContents_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_PrivateKeyInfo_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/*--- Included file: packet-pkcs12-hf.c ---*/
#line 1 "../../asn1/pkcs12/packet-pkcs12-hf.c"
static int hf_pkcs12_PFX_PDU = -1;                /* PFX */
static int hf_pkcs12_AuthenticatedSafe_PDU = -1;  /* AuthenticatedSafe */
static int hf_pkcs12_SafeContents_PDU = -1;       /* SafeContents */
static int hf_pkcs12_KeyBag_PDU = -1;             /* KeyBag */
static int hf_pkcs12_PKCS8ShroudedKeyBag_PDU = -1;  /* PKCS8ShroudedKeyBag */
static int hf_pkcs12_CertBag_PDU = -1;            /* CertBag */
static int hf_pkcs12_CRLBag_PDU = -1;             /* CRLBag */
static int hf_pkcs12_SecretBag_PDU = -1;          /* SecretBag */
static int hf_pkcs12_PrivateKeyInfo_PDU = -1;     /* PrivateKeyInfo */
static int hf_pkcs12_EncryptedPrivateKeyInfo_PDU = -1;  /* EncryptedPrivateKeyInfo */
static int hf_pkcs12_PBEParameter_PDU = -1;       /* PBEParameter */
static int hf_pkcs12_PBKDF2Params_PDU = -1;       /* PBKDF2Params */
static int hf_pkcs12_PBES2Params_PDU = -1;        /* PBES2Params */
static int hf_pkcs12_PBMAC1Params_PDU = -1;       /* PBMAC1Params */
static int hf_pkcs12_version = -1;                /* T_version */
static int hf_pkcs12_authSafe = -1;               /* ContentInfo */
static int hf_pkcs12_macData = -1;                /* MacData */
static int hf_pkcs12_mac = -1;                    /* DigestInfo */
static int hf_pkcs12_macSalt = -1;                /* OCTET_STRING */
static int hf_pkcs12_iterations = -1;             /* INTEGER */
static int hf_pkcs12_digestAlgorithm = -1;        /* DigestAlgorithmIdentifier */
static int hf_pkcs12_digest = -1;                 /* Digest */
static int hf_pkcs12_AuthenticatedSafe_item = -1;  /* ContentInfo */
static int hf_pkcs12_SafeContents_item = -1;      /* SafeBag */
static int hf_pkcs12_bagId = -1;                  /* T_bagId */
static int hf_pkcs12_bagValue = -1;               /* T_bagValue */
static int hf_pkcs12_bagAttributes = -1;          /* SET_OF_PKCS12Attribute */
static int hf_pkcs12_bagAttributes_item = -1;     /* PKCS12Attribute */
static int hf_pkcs12_certId = -1;                 /* T_certId */
static int hf_pkcs12_certValue = -1;              /* T_certValue */
static int hf_pkcs12_crlId = -1;                  /* T_crlId */
static int hf_pkcs12_crlValue = -1;               /* T_crlValue */
static int hf_pkcs12_secretTypeId = -1;           /* T_secretTypeId */
static int hf_pkcs12_secretValue = -1;            /* T_secretValue */
static int hf_pkcs12_attrId = -1;                 /* T_attrId */
static int hf_pkcs12_attrValues = -1;             /* T_attrValues */
static int hf_pkcs12_attrValues_item = -1;        /* T_attrValues_item */
static int hf_pkcs12_privateKeyVersion = -1;      /* Version */
static int hf_pkcs12_privateKeyAlgorithm = -1;    /* AlgorithmIdentifier */
static int hf_pkcs12_privateKey = -1;             /* PrivateKey */
static int hf_pkcs12_attributes = -1;             /* Attributes */
static int hf_pkcs12_Attributes_item = -1;        /* Attribute */
static int hf_pkcs12_encryptionAlgorithm = -1;    /* AlgorithmIdentifier */
static int hf_pkcs12_encryptedData = -1;          /* EncryptedData */
static int hf_pkcs12_salt = -1;                   /* OCTET_STRING */
static int hf_pkcs12_iterationCount = -1;         /* INTEGER */
static int hf_pkcs12_saltChoice = -1;             /* T_saltChoice */
static int hf_pkcs12_specified = -1;              /* OCTET_STRING */
static int hf_pkcs12_otherSource = -1;            /* AlgorithmIdentifier */
static int hf_pkcs12_keyLength = -1;              /* INTEGER_1_MAX */
static int hf_pkcs12_prf = -1;                    /* AlgorithmIdentifier */
static int hf_pkcs12_keyDerivationFunc = -1;      /* AlgorithmIdentifier */
static int hf_pkcs12_encryptionScheme = -1;       /* AlgorithmIdentifier */
static int hf_pkcs12_messageAuthScheme = -1;      /* AlgorithmIdentifier */

/*--- End of included file: packet-pkcs12-hf.c ---*/
#line 79 "../../asn1/pkcs12/packet-pkcs12-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-pkcs12-ett.c ---*/
#line 1 "../../asn1/pkcs12/packet-pkcs12-ett.c"
static gint ett_pkcs12_PFX = -1;
static gint ett_pkcs12_MacData = -1;
static gint ett_pkcs12_DigestInfo = -1;
static gint ett_pkcs12_AuthenticatedSafe = -1;
static gint ett_pkcs12_SafeContents = -1;
static gint ett_pkcs12_SafeBag = -1;
static gint ett_pkcs12_SET_OF_PKCS12Attribute = -1;
static gint ett_pkcs12_CertBag = -1;
static gint ett_pkcs12_CRLBag = -1;
static gint ett_pkcs12_SecretBag = -1;
static gint ett_pkcs12_PKCS12Attribute = -1;
static gint ett_pkcs12_T_attrValues = -1;
static gint ett_pkcs12_PrivateKeyInfo = -1;
static gint ett_pkcs12_Attributes = -1;
static gint ett_pkcs12_EncryptedPrivateKeyInfo = -1;
static gint ett_pkcs12_PBEParameter = -1;
static gint ett_pkcs12_PBKDF2Params = -1;
static gint ett_pkcs12_T_saltChoice = -1;
static gint ett_pkcs12_PBES2Params = -1;
static gint ett_pkcs12_PBMAC1Params = -1;

/*--- End of included file: packet-pkcs12-ett.c ---*/
#line 82 "../../asn1/pkcs12/packet-pkcs12-template.c"

static void append_oid(proto_tree *tree, const char *oid)
{
  	const char *name = NULL;

	name = oid_resolved_from_string(oid);
	proto_item_append_text(tree, " (%s)", name ? name : oid);
}

#ifdef HAVE_LIBGCRYPT

static int
generate_key_or_iv(unsigned int id, tvbuff_t *salt_tvb, unsigned int iter,
		       const char *pw, unsigned int req_keylen, char * keybuf)
{
  int rc;
  unsigned int i, j;
  gcry_md_hd_t md;
  gcry_mpi_t num_b1 = NULL;
  size_t pwlen;
  char hash[20], buf_b[64], buf_i[128], *p;
  char *salt;
  int salt_size;
  size_t cur_keylen;
  size_t n;
  gcry_error_t	err;

  cur_keylen = 0;

  salt_size = tvb_length(salt_tvb);
  salt = tvb_get_ephemeral_string(salt_tvb, 0, salt_size);

  if (pw == NULL)
    pwlen = 0;
  else
    pwlen = strlen (pw);

  if (pwlen > 63 / 2)
    {
      return FALSE;
    }

  /* Store salt and password in BUF_I */
  p = buf_i;
  for (i = 0; i < 64; i++)
    *p++ = salt[i % salt_size];
  if (pw)
    {
      for (i = j = 0; i < 64; i += 2)
	{
	  *p++ = 0;
	  *p++ = pw[j];
	  if (++j > pwlen)	/* Note, that we include the trailing zero */
	    j = 0;
	}
    }
  else
    memset (p, 0, 64);

  for (;;){
      err = gcry_md_open(&md, GCRY_MD_SHA1, 0);
      if (gcry_err_code(err)) {
		  return FALSE;
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
		  return TRUE;		/* ready */
	  }

      /* need more bytes. */
      for (i = 0; i < 64; i++)
		  buf_b[i] = hash[i % 20];

	  n = 64;

	  rc = gcry_mpi_scan (&num_b1, GCRYMPI_FMT_USG, buf_b, n, &n);

	  if (rc != 0) {
		  return FALSE;
	  }

	  gcry_mpi_add_ui (num_b1, num_b1, 1);

	  for (i = 0; i < 128; i += 64)	{
		  gcry_mpi_t num_ij;

		  n = 64;
		  rc = gcry_mpi_scan (&num_ij, GCRYMPI_FMT_USG, buf_i + i, n, &n);

		  if (rc != 0) {
			  return FALSE;
		  }

		  gcry_mpi_add (num_ij, num_ij, num_b1);
		  gcry_mpi_clear_highbit (num_ij, 64 * 8);

		  n = 64;

		  rc = gcry_mpi_print (GCRYMPI_FMT_USG, buf_i + i, n, &n, num_ij);
		  if (rc != 0){
			  return FALSE;
		  }

		  gcry_mpi_release (num_ij);
	  }
  }
}

#endif

void PBE_reset_parameters(void)
{
	iteration_count = 0;
	salt = NULL;
}

int PBE_decrypt_data(const char *object_identifier_id _U_, tvbuff_t *encrypted_tvb _U_, asn1_ctx_t *actx _U_, proto_item *item _U_)
{
#ifdef HAVE_LIBGCRYPT
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
	const gchar     *oidname;
	GString		*name;
	proto_tree	*tree;
	char		byte;
	gboolean	decrypt_ok = TRUE;

	if(((password == NULL) || (*password == '\0')) && (try_null_password == FALSE)) {
		/* we are not configured to decrypt */
		return FALSE;
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
		return FALSE;
	}

	if((iteration_count == 0) || (salt == NULL)) {
		proto_item_append_text(item, " [Insufficient parameters]");
		return FALSE;
	}

	/* allocate buffers */
	key = ep_alloc(keylen);

	if(!generate_key_or_iv(1 /*LEY */, salt, iteration_count, password, keylen, key))
		return FALSE;

	if(ivlen) {

		iv = ep_alloc(ivlen);

		if(!generate_key_or_iv(2 /* IV */, salt, iteration_count, password, ivlen, iv))
			return FALSE;
	}

	/* now try an internal function */
	err = gcry_cipher_open(&cipher, algo, mode, 0);
	if (gcry_err_code (err))
			return FALSE;

	err = gcry_cipher_setkey (cipher, key, keylen);
	if (gcry_err_code (err)) {
			gcry_cipher_close (cipher);
			return FALSE;
	}

	if(ivlen) {
		  err = gcry_cipher_setiv (cipher, iv, ivlen);
		  if (gcry_err_code (err)) {
			  gcry_cipher_close (cipher);
			  return FALSE;
		  }
	}

	datalen = tvb_length(encrypted_tvb);
	clear_data = g_malloc(datalen);

	err = gcry_cipher_decrypt (cipher, clear_data, datalen, tvb_get_ephemeral_string(encrypted_tvb, 0, datalen), datalen);
	if (gcry_err_code (err)) {

		proto_item_append_text(item, " [Failed to decrypt with password preference]");

		gcry_cipher_close (cipher);
		g_free(clear_data);
		return FALSE;
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
				decrypt_ok = FALSE;
				break;
			}
		}
	} else {
		/* XXX: is this a failure? */
	}

	/* we assume the result is ASN.1 - check it is a SET or SEQUENCE */
	byte = clear_data[0];
	if((byte != 0x30) && (byte != 0x31)) { /* do we need more here? OCTET STRING? */
		decrypt_ok = FALSE;
	}

	if(!decrypt_ok) {
		g_free(clear_data);
		proto_item_append_text(item, " [Failed to decrypt with supplied password]");

		return FALSE;
	}

	proto_item_append_text(item, " [Decrypted successfully]");

	tree = proto_item_add_subtree(item, ett_decrypted_pbe);

	/* OK - so now clear_data contains the decrypted data */

	clear_tvb = tvb_new_child_real_data(encrypted_tvb,(const guint8 *)clear_data, datalen, datalen);
	tvb_set_free_cb(clear_tvb, g_free);

	name = g_string_new("");
	oidname = oid_resolved_from_string(object_identifier_id);
	g_string_printf(name, "Decrypted %s", oidname ? oidname : object_identifier_id);

	/* add it as a new source */
	add_new_data_source(actx->pinfo, clear_tvb, name->str);

	g_string_free(name, TRUE);

	/* now try and decode it */
	call_ber_oid_callback(object_identifier_id, clear_tvb, 0, actx->pinfo, tree);

	return TRUE;
#else
	/* we cannot decrypt */
	return FALSE;

#endif
}


/*--- Included file: packet-pkcs12-fn.c ---*/
#line 1 "../../asn1/pkcs12/packet-pkcs12-fn.c"

static const value_string pkcs12_T_version_vals[] = {
  {   3, "v3" },
  { 0, NULL }
};


static int
dissect_pkcs12_T_version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DigestInfo_sequence[] = {
  { &hf_pkcs12_digestAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_DigestAlgorithmIdentifier },
  { &hf_pkcs12_digest       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_Digest },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_DigestInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DigestInfo_sequence, hf_index, ett_pkcs12_DigestInfo);

  return offset;
}



static int
dissect_pkcs12_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       (hf_index == hf_pkcs12_salt ? &salt : NULL));

  return offset;
}



static int
dissect_pkcs12_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                (hf_index == hf_pkcs12_iterationCount ? &iteration_count : NULL));

  return offset;
}


static const ber_sequence_t MacData_sequence[] = {
  { &hf_pkcs12_mac          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkcs12_DigestInfo },
  { &hf_pkcs12_macSalt      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkcs12_OCTET_STRING },
  { &hf_pkcs12_iterations   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkcs12_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_MacData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MacData_sequence, hf_index, ett_pkcs12_MacData);

  return offset;
}


static const ber_sequence_t PFX_sequence[] = {
  { &hf_pkcs12_version      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs12_T_version },
  { &hf_pkcs12_authSafe     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_ContentInfo },
  { &hf_pkcs12_macData      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkcs12_MacData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PFX(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 60 "../../asn1/pkcs12/pkcs12.cnf"
	dissector_handle_t dissector_handle;

	/* we change the CMS id-data dissector to dissect as AuthenticatedSafe
	   not sure why PKCS#12 couldn't have used its own content type OID for AuthenticatedSafe */
	dissector_handle=create_dissector_handle(dissect_AuthenticatedSafe_OCTETSTRING_PDU, proto_pkcs12);
	dissector_change_string("ber.oid", "1.2.840.113549.1.7.1", dissector_handle);

	  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PFX_sequence, hf_index, ett_pkcs12_PFX);


	/* restore the original dissector */
	dissector_reset_string("ber.oid", "1.2.840.113549.1.7.1");



  return offset;
}


static const ber_sequence_t AuthenticatedSafe_sequence_of[1] = {
  { &hf_pkcs12_AuthenticatedSafe_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_ContentInfo },
};

static int
dissect_pkcs12_AuthenticatedSafe(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 73 "../../asn1/pkcs12/pkcs12.cnf"
	dissector_handle_t dissector_handle;

	/* we change the CMS id-data dissector to dissect as SafeContents */
	dissector_handle=create_dissector_handle(dissect_SafeContents_OCTETSTRING_PDU, proto_pkcs12);
	dissector_change_string("ber.oid", "1.2.840.113549.1.7.1", dissector_handle);

	  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AuthenticatedSafe_sequence_of, hf_index, ett_pkcs12_AuthenticatedSafe);


	/* restore the original dissector */
	dissector_reset_string("ber.oid", "1.2.840.113549.1.7.1");



  return offset;
}



static int
dissect_pkcs12_T_bagId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

#line 86 "../../asn1/pkcs12/pkcs12.cnf"
  append_oid(tree, object_identifier_id);

  return offset;
}



static int
dissect_pkcs12_T_bagValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 110 "../../asn1/pkcs12/pkcs12.cnf"
	if(object_identifier_id)
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}



static int
dissect_pkcs12_T_attrId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

#line 106 "../../asn1/pkcs12/pkcs12.cnf"
  append_oid(tree, object_identifier_id);

  return offset;
}



static int
dissect_pkcs12_T_attrValues_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 114 "../../asn1/pkcs12/pkcs12.cnf"
	if(object_identifier_id)
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t T_attrValues_set_of[1] = {
  { &hf_pkcs12_attrValues_item, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_pkcs12_T_attrValues_item },
};

static int
dissect_pkcs12_T_attrValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_attrValues_set_of, hf_index, ett_pkcs12_T_attrValues);

  return offset;
}


static const ber_sequence_t PKCS12Attribute_sequence[] = {
  { &hf_pkcs12_attrId       , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkcs12_T_attrId },
  { &hf_pkcs12_attrValues   , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_pkcs12_T_attrValues },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PKCS12Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKCS12Attribute_sequence, hf_index, ett_pkcs12_PKCS12Attribute);

  return offset;
}


static const ber_sequence_t SET_OF_PKCS12Attribute_set_of[1] = {
  { &hf_pkcs12_bagAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkcs12_PKCS12Attribute },
};

static int
dissect_pkcs12_SET_OF_PKCS12Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_PKCS12Attribute_set_of, hf_index, ett_pkcs12_SET_OF_PKCS12Attribute);

  return offset;
}


static const ber_sequence_t SafeBag_sequence[] = {
  { &hf_pkcs12_bagId        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkcs12_T_bagId },
  { &hf_pkcs12_bagValue     , BER_CLASS_CON, 0, 0, dissect_pkcs12_T_bagValue },
  { &hf_pkcs12_bagAttributes, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkcs12_SET_OF_PKCS12Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_SafeBag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SafeBag_sequence, hf_index, ett_pkcs12_SafeBag);

  return offset;
}


static const ber_sequence_t SafeContents_sequence_of[1] = {
  { &hf_pkcs12_SafeContents_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkcs12_SafeBag },
};

static int
dissect_pkcs12_SafeContents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SafeContents_sequence_of, hf_index, ett_pkcs12_SafeContents);

  return offset;
}


static const value_string pkcs12_Version_vals[] = {
  {   0, "v1" },
  { 0, NULL }
};


static int
dissect_pkcs12_Version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_pkcs12_PrivateKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t Attributes_set_of[1] = {
  { &hf_pkcs12_Attributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

static int
dissect_pkcs12_Attributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Attributes_set_of, hf_index, ett_pkcs12_Attributes);

  return offset;
}


static const ber_sequence_t PrivateKeyInfo_sequence[] = {
  { &hf_pkcs12_privateKeyVersion, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs12_Version },
  { &hf_pkcs12_privateKeyAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_pkcs12_privateKey   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkcs12_PrivateKey },
  { &hf_pkcs12_attributes   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkcs12_Attributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PrivateKeyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrivateKeyInfo_sequence, hf_index, ett_pkcs12_PrivateKeyInfo);

  return offset;
}



static int
dissect_pkcs12_KeyBag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkcs12_PrivateKeyInfo(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pkcs12_EncryptedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 141 "../../asn1/pkcs12/pkcs12.cnf"
	tvbuff_t *encrypted_tvb;
	dissector_handle_t dissector_handle;
	

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &encrypted_tvb);

#line 147 "../../asn1/pkcs12/pkcs12.cnf"

	

	dissector_handle=create_dissector_handle(dissect_PrivateKeyInfo_PDU, proto_pkcs12);
	dissector_change_string("ber.oid", object_identifier_id, dissector_handle);
	
	PBE_decrypt_data(object_identifier_id, encrypted_tvb, actx, actx->created_item);
	
	/* restore the original dissector */
	dissector_reset_string("ber.oid", object_identifier_id);
	

  return offset;
}


static const ber_sequence_t EncryptedPrivateKeyInfo_sequence[] = {
  { &hf_pkcs12_encryptionAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_pkcs12_encryptedData, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkcs12_EncryptedData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_EncryptedPrivateKeyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedPrivateKeyInfo_sequence, hf_index, ett_pkcs12_EncryptedPrivateKeyInfo);

  return offset;
}



static int
dissect_pkcs12_PKCS8ShroudedKeyBag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkcs12_EncryptedPrivateKeyInfo(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pkcs12_T_certId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

#line 91 "../../asn1/pkcs12/pkcs12.cnf"
  append_oid(tree, object_identifier_id);

  return offset;
}



static int
dissect_pkcs12_T_certValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 118 "../../asn1/pkcs12/pkcs12.cnf"
	if(object_identifier_id)
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t CertBag_sequence[] = {
  { &hf_pkcs12_certId       , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkcs12_T_certId },
  { &hf_pkcs12_certValue    , BER_CLASS_CON, 0, 0, dissect_pkcs12_T_certValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_CertBag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertBag_sequence, hf_index, ett_pkcs12_CertBag);

  return offset;
}



static int
dissect_pkcs12_T_crlId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

#line 96 "../../asn1/pkcs12/pkcs12.cnf"
  append_oid(tree, object_identifier_id);

  return offset;
}



static int
dissect_pkcs12_T_crlValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 122 "../../asn1/pkcs12/pkcs12.cnf"
	if(object_identifier_id)
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t CRLBag_sequence[] = {
  { &hf_pkcs12_crlId        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkcs12_T_crlId },
  { &hf_pkcs12_crlValue     , BER_CLASS_CON, 0, 0, dissect_pkcs12_T_crlValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_CRLBag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CRLBag_sequence, hf_index, ett_pkcs12_CRLBag);

  return offset;
}



static int
dissect_pkcs12_T_secretTypeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

#line 101 "../../asn1/pkcs12/pkcs12.cnf"
  append_oid(tree, object_identifier_id);

  return offset;
}



static int
dissect_pkcs12_T_secretValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 126 "../../asn1/pkcs12/pkcs12.cnf"
	if(object_identifier_id)
		offset = call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);
		


  return offset;
}


static const ber_sequence_t SecretBag_sequence[] = {
  { &hf_pkcs12_secretTypeId , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkcs12_T_secretTypeId },
  { &hf_pkcs12_secretValue  , BER_CLASS_CON, 0, 0, dissect_pkcs12_T_secretValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_SecretBag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecretBag_sequence, hf_index, ett_pkcs12_SecretBag);

  return offset;
}


static const ber_sequence_t PBEParameter_sequence[] = {
  { &hf_pkcs12_salt         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkcs12_OCTET_STRING },
  { &hf_pkcs12_iterationCount, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs12_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PBEParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 130 "../../asn1/pkcs12/pkcs12.cnf"
	/* initialise the encryption parameters */
	PBE_reset_parameters();


  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PBEParameter_sequence, hf_index, ett_pkcs12_PBEParameter);

  return offset;
}


static const value_string pkcs12_T_saltChoice_vals[] = {
  {   0, "specified" },
  {   1, "otherSource" },
  { 0, NULL }
};

static const ber_choice_t T_saltChoice_choice[] = {
  {   0, &hf_pkcs12_specified    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkcs12_OCTET_STRING },
  {   1, &hf_pkcs12_otherSource  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_T_saltChoice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_saltChoice_choice, hf_index, ett_pkcs12_T_saltChoice,
                                 NULL);

  return offset;
}



static int
dissect_pkcs12_INTEGER_1_MAX(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PBKDF2Params_sequence[] = {
  { &hf_pkcs12_saltChoice   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pkcs12_T_saltChoice },
  { &hf_pkcs12_iterationCount, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs12_INTEGER },
  { &hf_pkcs12_keyLength    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkcs12_INTEGER_1_MAX },
  { &hf_pkcs12_prf          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PBKDF2Params(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PBKDF2Params_sequence, hf_index, ett_pkcs12_PBKDF2Params);

  return offset;
}


static const ber_sequence_t PBES2Params_sequence[] = {
  { &hf_pkcs12_keyDerivationFunc, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_pkcs12_encryptionScheme, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PBES2Params(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PBES2Params_sequence, hf_index, ett_pkcs12_PBES2Params);

  return offset;
}


static const ber_sequence_t PBMAC1Params_sequence[] = {
  { &hf_pkcs12_keyDerivationFunc, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_pkcs12_messageAuthScheme, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs12_PBMAC1Params(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PBMAC1Params_sequence, hf_index, ett_pkcs12_PBMAC1Params);

  return offset;
}

/*--- PDUs ---*/

static void dissect_PFX_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_PFX(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_PFX_PDU);
}
static void dissect_AuthenticatedSafe_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_AuthenticatedSafe(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_AuthenticatedSafe_PDU);
}
static void dissect_SafeContents_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_SafeContents(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_SafeContents_PDU);
}
static void dissect_KeyBag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_KeyBag(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_KeyBag_PDU);
}
static void dissect_PKCS8ShroudedKeyBag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_PKCS8ShroudedKeyBag(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_PKCS8ShroudedKeyBag_PDU);
}
static void dissect_CertBag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_CertBag(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_CertBag_PDU);
}
static void dissect_CRLBag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_CRLBag(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_CRLBag_PDU);
}
static void dissect_SecretBag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_SecretBag(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_SecretBag_PDU);
}
static void dissect_PrivateKeyInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_PrivateKeyInfo(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_PrivateKeyInfo_PDU);
}
static void dissect_EncryptedPrivateKeyInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_EncryptedPrivateKeyInfo(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_EncryptedPrivateKeyInfo_PDU);
}
static void dissect_PBEParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_PBEParameter(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_PBEParameter_PDU);
}
static void dissect_PBKDF2Params_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_PBKDF2Params(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_PBKDF2Params_PDU);
}
static void dissect_PBES2Params_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_PBES2Params(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_PBES2Params_PDU);
}
static void dissect_PBMAC1Params_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs12_PBMAC1Params(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs12_PBMAC1Params_PDU);
}


/*--- End of included file: packet-pkcs12-fn.c ---*/
#line 383 "../../asn1/pkcs12/packet-pkcs12-template.c"

static int strip_octet_string(tvbuff_t *tvb)
{
  gint8 ber_class;
  gboolean pc, ind;
  gint32 tag;
  guint32 len;
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

static void dissect_AuthenticatedSafe_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  if((offset = strip_octet_string(tvb)) > 0)
    dissect_pkcs12_AuthenticatedSafe(FALSE, tvb, offset, &asn1_ctx, tree, hf_pkcs12_AuthenticatedSafe_PDU);
  else
	proto_tree_add_text(tree, tvb, 0, 1, "BER Error: OCTET STRING expected");
}

static void dissect_SafeContents_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  offset = strip_octet_string(tvb);

  dissect_pkcs12_SafeContents(FALSE, tvb, offset, &asn1_ctx, tree, hf_pkcs12_SafeContents_PDU);
}

static void dissect_X509Certificate_OCTETSTRING_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  if((offset = strip_octet_string(tvb)) > 0)
	dissect_x509af_Certificate(FALSE, tvb, offset, &asn1_ctx, tree, hf_pkcs12_X509Certificate_PDU);
  else
	proto_tree_add_text(tree, tvb, 0, 1, "BER Error: OCTET STRING expected");
}

/*--- proto_register_pkcs12 ----------------------------------------------*/
void proto_register_pkcs12(void) {

  /* List of fields */
  static hf_register_info hf[] = {
	{ &hf_pkcs12_X509Certificate_PDU,
      { "X509Certificate", "pkcs12.X509Certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs12.X509Certificate", HFILL }},

/*--- Included file: packet-pkcs12-hfarr.c ---*/
#line 1 "../../asn1/pkcs12/packet-pkcs12-hfarr.c"
    { &hf_pkcs12_PFX_PDU,
      { "PFX", "pkcs12.PFX",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_AuthenticatedSafe_PDU,
      { "AuthenticatedSafe", "pkcs12.AuthenticatedSafe",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_SafeContents_PDU,
      { "SafeContents", "pkcs12.SafeContents",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_KeyBag_PDU,
      { "KeyBag", "pkcs12.KeyBag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_PKCS8ShroudedKeyBag_PDU,
      { "PKCS8ShroudedKeyBag", "pkcs12.PKCS8ShroudedKeyBag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_CertBag_PDU,
      { "CertBag", "pkcs12.CertBag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_CRLBag_PDU,
      { "CRLBag", "pkcs12.CRLBag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_SecretBag_PDU,
      { "SecretBag", "pkcs12.SecretBag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_PrivateKeyInfo_PDU,
      { "PrivateKeyInfo", "pkcs12.PrivateKeyInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_EncryptedPrivateKeyInfo_PDU,
      { "EncryptedPrivateKeyInfo", "pkcs12.EncryptedPrivateKeyInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_PBEParameter_PDU,
      { "PBEParameter", "pkcs12.PBEParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_PBKDF2Params_PDU,
      { "PBKDF2Params", "pkcs12.PBKDF2Params",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_PBES2Params_PDU,
      { "PBES2Params", "pkcs12.PBES2Params",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_PBMAC1Params_PDU,
      { "PBMAC1Params", "pkcs12.PBMAC1Params",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_version,
      { "version", "pkcs12.version",
        FT_UINT32, BASE_DEC, VALS(pkcs12_T_version_vals), 0,
        NULL, HFILL }},
    { &hf_pkcs12_authSafe,
      { "authSafe", "pkcs12.authSafe",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentInfo", HFILL }},
    { &hf_pkcs12_macData,
      { "macData", "pkcs12.macData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_mac,
      { "mac", "pkcs12.mac",
        FT_NONE, BASE_NONE, NULL, 0,
        "DigestInfo", HFILL }},
    { &hf_pkcs12_macSalt,
      { "macSalt", "pkcs12.macSalt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_pkcs12_iterations,
      { "iterations", "pkcs12.iterations",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs12_digestAlgorithm,
      { "digestAlgorithm", "pkcs12.digestAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "DigestAlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_digest,
      { "digest", "pkcs12.digest",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_AuthenticatedSafe_item,
      { "ContentInfo", "pkcs12.ContentInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_SafeContents_item,
      { "SafeBag", "pkcs12.SafeBag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_bagId,
      { "bagId", "pkcs12.bagId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_bagValue,
      { "bagValue", "pkcs12.bagValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_bagAttributes,
      { "bagAttributes", "pkcs12.bagAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_PKCS12Attribute", HFILL }},
    { &hf_pkcs12_bagAttributes_item,
      { "PKCS12Attribute", "pkcs12.PKCS12Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_certId,
      { "certId", "pkcs12.certId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_certValue,
      { "certValue", "pkcs12.certValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_crlId,
      { "crlId", "pkcs12.crlId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_crlValue,
      { "crlValue", "pkcs12.crlValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_secretTypeId,
      { "secretTypeId", "pkcs12.secretTypeId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_secretValue,
      { "secretValue", "pkcs12.secretValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_attrId,
      { "attrId", "pkcs12.attrId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_attrValues,
      { "attrValues", "pkcs12.attrValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_attrValues_item,
      { "attrValues item", "pkcs12.attrValues_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_privateKeyVersion,
      { "version", "pkcs12.version",
        FT_UINT32, BASE_DEC, VALS(pkcs12_Version_vals), 0,
        NULL, HFILL }},
    { &hf_pkcs12_privateKeyAlgorithm,
      { "privateKeyAlgorithm", "pkcs12.privateKeyAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_privateKey,
      { "privateKey", "pkcs12.privateKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_attributes,
      { "attributes", "pkcs12.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_Attributes_item,
      { "Attribute", "pkcs12.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_encryptionAlgorithm,
      { "encryptionAlgorithm", "pkcs12.encryptionAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_encryptedData,
      { "encryptedData", "pkcs12.encryptedData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs12_salt,
      { "salt", "pkcs12.salt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_pkcs12_iterationCount,
      { "iterationCount", "pkcs12.iterationCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs12_saltChoice,
      { "salt", "pkcs12.salt",
        FT_UINT32, BASE_DEC, VALS(pkcs12_T_saltChoice_vals), 0,
        "T_saltChoice", HFILL }},
    { &hf_pkcs12_specified,
      { "specified", "pkcs12.specified",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_pkcs12_otherSource,
      { "otherSource", "pkcs12.otherSource",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_keyLength,
      { "keyLength", "pkcs12.keyLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_MAX", HFILL }},
    { &hf_pkcs12_prf,
      { "prf", "pkcs12.prf",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_keyDerivationFunc,
      { "keyDerivationFunc", "pkcs12.keyDerivationFunc",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_encryptionScheme,
      { "encryptionScheme", "pkcs12.encryptionScheme",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_pkcs12_messageAuthScheme,
      { "messageAuthScheme", "pkcs12.messageAuthScheme",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},

/*--- End of included file: packet-pkcs12-hfarr.c ---*/
#line 450 "../../asn1/pkcs12/packet-pkcs12-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_decrypted_pbe,

/*--- Included file: packet-pkcs12-ettarr.c ---*/
#line 1 "../../asn1/pkcs12/packet-pkcs12-ettarr.c"
    &ett_pkcs12_PFX,
    &ett_pkcs12_MacData,
    &ett_pkcs12_DigestInfo,
    &ett_pkcs12_AuthenticatedSafe,
    &ett_pkcs12_SafeContents,
    &ett_pkcs12_SafeBag,
    &ett_pkcs12_SET_OF_PKCS12Attribute,
    &ett_pkcs12_CertBag,
    &ett_pkcs12_CRLBag,
    &ett_pkcs12_SecretBag,
    &ett_pkcs12_PKCS12Attribute,
    &ett_pkcs12_T_attrValues,
    &ett_pkcs12_PrivateKeyInfo,
    &ett_pkcs12_Attributes,
    &ett_pkcs12_EncryptedPrivateKeyInfo,
    &ett_pkcs12_PBEParameter,
    &ett_pkcs12_PBKDF2Params,
    &ett_pkcs12_T_saltChoice,
    &ett_pkcs12_PBES2Params,
    &ett_pkcs12_PBMAC1Params,

/*--- End of included file: packet-pkcs12-ettarr.c ---*/
#line 456 "../../asn1/pkcs12/packet-pkcs12-template.c"
  };
  module_t *pkcs12_module;

  /* Register protocol */
  proto_pkcs12 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkcs12, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

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

/*--- Included file: packet-pkcs12-dis-tab.c ---*/
#line 1 "../../asn1/pkcs12/packet-pkcs12-dis-tab.c"
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.1", dissect_KeyBag_PDU, proto_pkcs12, "keyBag");
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.2", dissect_PKCS8ShroudedKeyBag_PDU, proto_pkcs12, "pkcs8ShroudedKeyBag");
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.3", dissect_CertBag_PDU, proto_pkcs12, "certBag");
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.4", dissect_SecretBag_PDU, proto_pkcs12, "secretBag");
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.5", dissect_CRLBag_PDU, proto_pkcs12, "crlBag");
  register_ber_oid_dissector("1.2.840.113549.1.12.10.1.6", dissect_SafeContents_PDU, proto_pkcs12, "safeContentsBag");
  register_ber_oid_dissector("2.16.840.1.113730.3.1.216", dissect_PFX_PDU, proto_pkcs12, "pkcs-9-at-PKCS12");
  register_ber_oid_dissector("1.2.840.113549.1.9.25.2", dissect_EncryptedPrivateKeyInfo_PDU, proto_pkcs12, "pkcs-9-at-encryptedPrivateKeyInfo");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.1", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd128BitRC4");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.2", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd40BitRC4");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.3", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd3-KeyTripleDES-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.4", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd2-KeyTripleDES-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.5", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd128BitRC2-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.12.1.6", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHAAnd128BitRC2-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.1", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithMD2AndDES-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.3", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithMD5AndDES-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.4", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithMD2AndRC2-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.6", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithMD5AndRC2-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.10", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHA1AndDES-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.11", dissect_PBEParameter_PDU, proto_pkcs12, "pbeWithSHA1AndRC2-CBC");
  register_ber_oid_dissector("1.2.840.113549.1.5.12", dissect_PBKDF2Params_PDU, proto_pkcs12, "id-PBKDF2");
  register_ber_oid_dissector("1.2.840.113549.1.5.13", dissect_PBES2Params_PDU, proto_pkcs12, "id-PBES2");
  register_ber_oid_dissector("1.2.840.113549.1.5.14", dissect_PBMAC1Params_PDU, proto_pkcs12, "id-PBMAC1");


/*--- End of included file: packet-pkcs12-dis-tab.c ---*/
#line 488 "../../asn1/pkcs12/packet-pkcs12-template.c"

	register_ber_oid_dissector("1.2.840.113549.1.9.22.1", dissect_X509Certificate_OCTETSTRING_PDU, proto_pkcs12, "x509Certificate");

}

