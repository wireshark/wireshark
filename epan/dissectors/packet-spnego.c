/* packet-spnego.c
 * Routines for the simple and protected GSS-API negotiation mechanism
 * as described in RFC 2478.
 * Copyright 2002, Tim Potter <tpot@samba.org>
 * Copyright 2002, Richard Sharpe <rsharpe@ns.aus.com>
 * Copyright 2003, Richard Sharpe <rsharpe@richardsharpe.com>
 * Copyright 2005, Ronnie Sahlberg (krb decryption)
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
/* The heimdal code for decryption of GSSAPI wrappers using heimdal comes from
   Heimdal 1.6 and has been modified for ethereal's requirements.
*/
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

#include <epan/asn1.h>
#include "format-oid.h"
#include "packet-ber.h"
#include "packet-dcerpc.h"
#include "packet-gssapi.h"
#include "packet-kerberos.h"
#include <epan/crypt-rc4.h>
#include <epan/conversation.h>
#include <epan/emem.h>

#define SPNEGO_negTokenInit 0
#define SPNEGO_negTokenTarg 1
#define SPNEGO_mechTypes 0
#define SPNEGO_reqFlags 1
#define SPNEGO_mechToken 2
#define SPNEGO_mechListMIC 3
#define SPNEGO_negResult 0
#define SPNEGO_supportedMech 1
#define SPNEGO_responseToken 2
#define SPNEGO_negResult_accept_completed 0
#define SPNEGO_negResult_accept_incomplete 1
#define SPNEGO_negResult_accept_reject 2

static int proto_spnego = -1;
static int proto_spnego_krb5 = -1;

static int hf_spnego = -1;
static int hf_spnego_mech = -1;
static int hf_spnego_this_mech = -1;
static int hf_spnego_negtokeninit = -1;
static int hf_spnego_negtokentarg = -1;
static int hf_spnego_mechtype = -1;
static int hf_spnego_mechtoken = -1;
static int hf_spnego_negtokentarg_negresult = -1;
static int hf_spnego_mechlistmic = -1;
static int hf_spnego_responsetoken = -1;
static int hf_spnego_reqflags = -1;
static int hf_spnego_wraptoken = -1;
static int hf_spnego_krb5 = -1;
static int hf_spnego_krb5_tok_id = -1;
static int hf_spnego_krb5_sgn_alg = -1;
static int hf_spnego_krb5_seal_alg = -1;
static int hf_spnego_krb5_snd_seq = -1;
static int hf_spnego_krb5_sgn_cksum = -1;
static int hf_spnego_krb5_confounder = -1;
static int hf_gssapi_reqflags_deleg = -1;
static int hf_gssapi_reqflags_mutual = -1;
static int hf_gssapi_reqflags_replay = -1;
static int hf_gssapi_reqflags_sequence = -1;
static int hf_gssapi_reqflags_anon = -1;
static int hf_gssapi_reqflags_conf = -1;
static int hf_gssapi_reqflags_integ = -1;

static gint ett_spnego = -1;
static gint ett_spnego_negtokeninit = -1;
static gint ett_spnego_negtokentarg = -1;
static gint ett_spnego_mechtype = -1;
static gint ett_spnego_mechtoken = -1;
static gint ett_spnego_mechlistmic = -1;
static gint ett_spnego_responsetoken = -1;
static gint ett_spnego_wraptoken = -1;
static gint ett_spnego_krb5 = -1;
static gint ett_spnego_reqflags = -1;

static const value_string spnego_negResult_vals[] = {
  { SPNEGO_negResult_accept_completed,   "Accept Completed" },
  { SPNEGO_negResult_accept_incomplete,  "Accept Incomplete" },
  { SPNEGO_negResult_accept_reject,      "Accept Reject"},
  { 0, NULL}
};

/*
 * These should be in the GSSAPI dissector ... XXX
 */

static const true_false_string tfs_reqflags_deleg = {
  "Delegation Requested",
  "Delegation NOT Requested"
};

static const true_false_string tfs_reqflags_mutual = {
  "Mutual Authentication Requested",
  "Mutual Authentication NOT Requested"
};

static const true_false_string tfs_reqflags_replay = {
  "Replay Detection Requested",
  "Replay Detection NOT Requested"
};

static const true_false_string tfs_reqflags_sequence = {
  "Out-of-sequence Detection Requested",
  "Out-of-sequence Detection NOT Requested"
};

static const true_false_string tfs_reqflags_anon = {
  "Anonymous Authentication Requested",
  "Anonymous Authentication NOT Requested"
};

static const true_false_string tfs_reqflags_conf = {
  "Per-message Confidentiality Requested",
  "Per-message Confidentiality NOT Requested"
};

static const true_false_string tfs_reqflags_integ = {
  "Per-message Integrity Requested",
  "Per-message Integrity NOT Requested"
};

/*
 * This takes an OID in binary form, not an OID as a text string, as
 * an argument.
 */
static gssapi_oid_value *
gssapi_lookup_oid(subid_t *oid, guint oid_len)
{
	gchar *oid_key;
	gchar *p;
	unsigned int i;
	int len;
	gssapi_oid_value *value;

	/*
	 * Convert the OID to a string, as text strings are used as
	 * keys in the OID hash table.
	 */
	oid_key = ep_alloc(oid_len * 22 + 1);
	p = oid_key;
	len = g_snprintf(p, oid_len * 22 + 1, "%lu", (unsigned long)oid[0]);
	p += len;
	for (i = 1; i < oid_len;i++) {
		len = g_snprintf(p, oid_len * 22 + 1 -(p-oid_key),".%lu", (unsigned long)oid[i]);
		p += len;
	}

	value = gssapi_lookup_oid_str(oid_key);
	return value;
}


/* Display an ASN1 parse error.  Taken from packet-snmp.c */

static dissector_handle_t data_handle;

static dissector_handle_t
gssapi_dissector_handle(gssapi_oid_value *next_level_value) {
	if (next_level_value == NULL) {
		return NULL;
	}
	return next_level_value->handle;
}

static void
dissect_parse_error(tvbuff_t *tvb, int offset, packet_info *pinfo,
		    proto_tree *tree, const char *field_name, int ret)
{
	const char *errstr;

	errstr = asn1_err_to_str(ret);

	if (tree != NULL) {
		proto_tree_add_text(tree, tvb, offset, 0,
		    "ERROR: Couldn't parse %s: %s", field_name, errstr);
		call_dissector(data_handle,
		    tvb_new_subset(tvb, offset, -1, -1), pinfo, tree);
	}
}

/*
 * This is the SPNEGO KRB5 dissector. It is not true KRB5, but some ASN.1
 * wrapped blob with an OID, USHORT token ID, and a Ticket, that is also 
 * ASN.1 wrapped by the looks of it. It conforms to RFC1964.
 */ 

#define KRB_TOKEN_AP_REQ		0x0001
#define KRB_TOKEN_AP_REP		0x0002
#define KRB_TOKEN_AP_ERR		0x0003
#define KRB_TOKEN_GETMIC		0x0101
#define KRB_TOKEN_WRAP			0x0102
#define KRB_TOKEN_DELETE_SEC_CONTEXT	0x0201

static const value_string spnego_krb5_tok_id_vals[] = {
  { KRB_TOKEN_AP_REQ,             "KRB5_AP_REQ"},
  { KRB_TOKEN_AP_REP,             "KRB5_AP_REP"},
  { KRB_TOKEN_AP_ERR,             "KRB5_ERROR"},
  { KRB_TOKEN_GETMIC,             "KRB5_GSS_GetMIC" },
  { KRB_TOKEN_WRAP,               "KRB5_GSS_Wrap" },
  { KRB_TOKEN_DELETE_SEC_CONTEXT, "KRB5_GSS_Delete_sec_context" },
  { 0, NULL}
};

#define KRB_SGN_ALG_DES_MAC_MD5	0x0000
#define KRB_SGN_ALG_MD2_5	0x0001
#define KRB_SGN_ALG_DES_MAC	0x0002
#define KRB_SGN_ALG_HMAC	0x0011

static const value_string spnego_krb5_sgn_alg_vals[] = {
  { KRB_SGN_ALG_DES_MAC_MD5, "DES MAC MD5"},
  { KRB_SGN_ALG_MD2_5,       "MD2.5"},
  { KRB_SGN_ALG_DES_MAC,     "DES MAC"},
  { KRB_SGN_ALG_HMAC,        "HMAC"},
  { 0, NULL}
};

#define KRB_SEAL_ALG_DES_CBC	0x0000
#define KRB_SEAL_ALG_RC4	0x0010
#define KRB_SEAL_ALG_NONE	0xffff

static const value_string spnego_krb5_seal_alg_vals[] = {
  { KRB_SEAL_ALG_DES_CBC, "DES CBC"},
  { KRB_SEAL_ALG_RC4,     "RC4"},
  { KRB_SEAL_ALG_NONE,    "None"},
  { 0, NULL}
};

/*
 * XXX - is this for SPNEGO or just GSS-API?
 * RFC 1964 is "The Kerberos Version 5 GSS-API Mechanism"; presumably one
 * can directly designate Kerberos V5 as a mechanism in GSS-API, rather
 * than designating SPNEGO as the mechanism, offering Kerberos V5, and
 * getting it accepted.
 */
static int
dissect_spnego_krb5_getmic_base(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int
dissect_spnego_krb5_wrap_base(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, guint16 token_id);

static void
dissect_spnego_krb5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	int ret, offset = 0;
	ASN1_SCK hnd;
	gboolean def;
	guint len1, cls, con, tag, oid_len, nbytes;
	guint16 token_id;
	subid_t *oid;
	gchar *oid_string;
	gssapi_oid_value *value;
	tvbuff_t *krb5_tvb;

	item = proto_tree_add_item(tree, hf_spnego_krb5, tvb, offset, 
				   -1, FALSE);

	subtree = proto_item_add_subtree(item, ett_spnego_krb5);

	/*
	 * The KRB5 blob conforms to RFC1964:
	 * [APPLICATION 0] {
	 *   OID,
	 *   USHORT (0x0001 == AP-REQ, 0x0002 == AP-REP, 0x0003 == ERROR),
	 *   OCTET STRING } 
         *
         * However, for some protocols, the KRB5 blob starts at the SHORT
	 * and has no DER encoded header etc.
	 *
	 * It appears that for some other protocols the KRB5 blob is just
	 * a Kerberos message, with no [APPLICATION 0] header, no OID,
	 * and no USHORT.
	 *
	 * So:
	 *
	 *	If we see an [APPLICATION 0] HEADER, we show the OID and
	 *	the USHORT, and then dissect the rest as a Kerberos message.
	 *
	 *	If we see an [APPLICATION 14] or [APPLICATION 15] header,
	 *	we assume it's an AP-REQ or AP-REP message, and dissect
	 *	it all as a Kerberos message.
	 *
	 *	Otherwise, we show the USHORT, and then dissect the rest
	 *	as a Kerberos message.
	 */

	asn1_open(&hnd, tvb, offset);

	/*
	 * Get the first header ...
	 */

	ret = asn1_header_decode(&hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO KRB5 Header", ret);
		goto done;
	}

	if (cls == ASN1_APL && con == ASN1_CON) {
	    /*
	     * [APPLICATION <tag>]
	     */
	    switch (tag) {

	    case 0:
		/*
		 * [APPLICATION 0]
		 */

		offset = hnd.offset;

		/* Next, the OID */

		ret = asn1_oid_decode(&hnd, &oid, &oid_len, &nbytes);

		if (ret != ASN1_ERR_NOERROR) {
		    dissect_parse_error(tvb, offset, pinfo, subtree,
			 	        "SPNEGO supportedMech token", ret);
		    goto done;
		}

		oid_string = format_oid(oid, oid_len);

		value = gssapi_lookup_oid(oid, oid_len);

		if (value) 
		    proto_tree_add_text(subtree, tvb, offset, nbytes, 
					"OID: %s (%s)",
					oid_string, value->comment);
		else
		    proto_tree_add_text(subtree, tvb, offset, nbytes,
					"OID: %s",
					oid_string);
	  
		offset += nbytes;

		/* Next, the token ID ... */

		token_id = tvb_get_letohs(tvb, offset);
		proto_tree_add_uint(subtree, hf_spnego_krb5_tok_id, tvb, offset, 2,
				    token_id);

		hnd.offset += 2;

		offset += 2;

		break;

	    case 14:	/* [APPLICATION 14] */
	    case 15:	/* [APPLICATION 15] */
		/*
		 * No token ID - just dissect as a Kerberos message and
		 * return.
		 */
		krb5_tvb = tvb_new_subset(tvb, offset, -1, -1); 
		offset = dissect_kerberos_main(krb5_tvb, pinfo, subtree, FALSE, NULL);
		return;

	    default:
		proto_tree_add_text(subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	    }
	} else {
	    /* Next, the token ID ... */

	    token_id = tvb_get_letohs(tvb, offset);
	    proto_tree_add_uint(subtree, hf_spnego_krb5_tok_id, tvb, offset, 2,
				token_id);

	    hnd.offset += 2;

	    offset += 2;
	}

	switch (token_id) {

	case KRB_TOKEN_AP_REQ:
	case KRB_TOKEN_AP_REP:
	case KRB_TOKEN_AP_ERR:
	  krb5_tvb = tvb_new_subset(tvb, offset, -1, -1); 
	  offset = dissect_kerberos_main(krb5_tvb, pinfo, subtree, FALSE, NULL);
	  break;

	case KRB_TOKEN_GETMIC:
	  offset = dissect_spnego_krb5_getmic_base(tvb, offset, pinfo, subtree); 
	  break;

	case KRB_TOKEN_WRAP:
          offset = dissect_spnego_krb5_wrap_base(tvb, offset, pinfo, subtree, token_id);
	  break;

	case KRB_TOKEN_DELETE_SEC_CONTEXT:

	  break;

	default:

	  break;
	}

 done:
	return;
}

#ifdef HAVE_KERBEROS
#include <epan/crypt-md5.h>

#ifndef KEYTYPE_ARCFOUR_56
# define KEYTYPE_ARCFOUR_56 24
#endif
/* XXX - We should probably do a configure-time check for this instead */
#ifndef KRB5_KU_USAGE_SEAL
# define KRB5_KU_USAGE_SEAL 22
#endif

static int
arcfour_mic_key(void *key_data, size_t key_size, int key_type,
		void *cksum_data, size_t cksum_size,
		void *key6_data)
{
    guint8 k5_data[16];
    guint8 T[4];

    memset(T, 0, 4);

    if (key_type == KEYTYPE_ARCFOUR_56) {
	guint8 L40[14] = "fortybits";

	memcpy(L40 + 10, T, sizeof(T));
	md5_hmac(
                L40, 14,  
                key_data,
                key_size, 
	    	k5_data);
	memset(&k5_data[7], 0xAB, 9);
    } else {
	md5_hmac(
                T, 4,  
                key_data,
                key_size,
	    	k5_data);
    }

    md5_hmac(
	cksum_data, cksum_size,  
	k5_data,
	16, 
	key6_data);

    return 0;
}

static int
usage2arcfour(int usage)
{
    switch (usage) {
    case 3: /*KRB5_KU_AS_REP_ENC_PART 3 */
    case 9: /*KRB5_KU_TGS_REP_ENC_PART_SUB_KEY 9 */
	return 8;
    case 22: /*KRB5_KU_USAGE_SEAL 22 */
	return 13;
    case 23: /*KRB5_KU_USAGE_SIGN 23 */
        return 15;
    case 24: /*KRB5_KU_USAGE_SEQ 24 */
	return 0;
    default :
	return 0;
    }
}

static int
arcfour_mic_cksum(guint8 *key_data, int key_length,
		  unsigned usage,
		  u_char sgn_cksum[8],
		  const void *v1, size_t l1,
		  const void *v2, size_t l2,
		  const void *v3, size_t l3)
{
    const guint8 signature[] = "signaturekey";
    guint8 ksign_c[16];
    unsigned char t[4];
    md5_state_t ms;
    unsigned char digest[16];
    int rc4_usage;
    guint8 cksum[16];
    
    rc4_usage=usage2arcfour(usage);
    md5_hmac(signature, sizeof(signature), 
		key_data, key_length, 
		ksign_c);
    md5_init(&ms);
    t[0] = (rc4_usage >>  0) & 0xFF;
    t[1] = (rc4_usage >>  8) & 0xFF;
    t[2] = (rc4_usage >> 16) & 0xFF;
    t[3] = (rc4_usage >> 24) & 0xFF;
    md5_append(&ms, t, 4);
    md5_append(&ms, v1, l1);
    md5_append(&ms, v2, l2);
    md5_append(&ms, v3, l3);
    md5_finish(&ms, digest);
    md5_hmac(digest, 16, ksign_c, 16, cksum);

    memcpy(sgn_cksum, cksum, 8);

    return 0;
}

/*
 * Verify padding of a gss wrapped message and return its length.
 */
static int
gssapi_verify_pad(unsigned char *wrapped_data, int wrapped_length, 
		   size_t datalen,
		   size_t *padlen)
{
    unsigned char *pad;
    size_t padlength;
    int i;

    pad = wrapped_data + wrapped_length - 1;
    padlength = *pad;

    if (padlength > datalen)
	return 1;

    for (i = padlength; i > 0 && *pad == padlength; i--, pad--)
	;
    if (i != 0)
	return 2;

    *padlen = padlength;

    return 0;
}

static int
decrypt_arcfour(packet_info *pinfo,
	 guint8 *input_message_buffer,
	 guint8 *output_message_buffer,
	 guint8 *key_value, int key_size, int key_type)
{
    guint8 Klocaldata[16];
    int ret;
    gint32 seq_number;
    size_t datalen;
    guint8 k6_data[16], SND_SEQ[8], Confounder[8];
    guint8 cksum_data[8];
    int cmp;
    int conf_flag;
    size_t padlen = 0;

    datalen = tvb_length(pinfo->gssapi_encrypted_tvb);

    if(tvb_get_ntohs(pinfo->gssapi_wrap_tvb, 4)==0x1000){
	conf_flag=1;
    } else if (tvb_get_ntohs(pinfo->gssapi_wrap_tvb, 4)==0xffff){
	conf_flag=0;
    } else {
	return -3;
    }

    if(tvb_get_ntohs(pinfo->gssapi_wrap_tvb, 6)!=0xffff){
	return -4;
    }

    ret = arcfour_mic_key(key_value, key_size, key_type,
			  (void *)tvb_get_ptr(pinfo->gssapi_wrap_tvb, 16, 8),
			  8, /* SGN_CKSUM */
			  k6_data);
    if (ret) {
	return -5;
    }

    {
	rc4_state_struct rc4_state;
	
	crypt_rc4_init(&rc4_state, k6_data, sizeof(k6_data));
	memcpy(SND_SEQ, (unsigned char *)tvb_get_ptr(pinfo->gssapi_wrap_tvb, 8, 8), 8);
	crypt_rc4(&rc4_state, SND_SEQ, 8);

	memset(k6_data, 0, sizeof(k6_data));
    }

    seq_number=g_ntohl(*((guint32 *)SND_SEQ));

    cmp = memcmp(&SND_SEQ[4], "\xff\xff\xff\xff", 4);
    if(cmp){
	cmp = memcmp(&SND_SEQ[4], "\x00\x00\x00\x00", 4);
    }

    if (cmp != 0) {
	return -6;
    }

    {
	int i;

	for (i = 0; i < 16; i++)
	    Klocaldata[i] = ((u_char *)key_value)[i] ^ 0xF0;
    }
    ret = arcfour_mic_key(Klocaldata,sizeof(Klocaldata),key_type,
			  SND_SEQ, 4,
			  k6_data);
    memset(Klocaldata, 0, sizeof(Klocaldata));
    if (ret) {
	return -7;
    }

    if(conf_flag) {
	rc4_state_struct rc4_state;

	crypt_rc4_init(&rc4_state, k6_data, sizeof(k6_data));
	memcpy(Confounder, (unsigned char *)tvb_get_ptr(pinfo->gssapi_wrap_tvb, 24, 8), 8);
	crypt_rc4(&rc4_state, Confounder, 8);
	memcpy(output_message_buffer, input_message_buffer, datalen);
	crypt_rc4(&rc4_state, output_message_buffer, datalen);
    } else {
	memcpy(Confounder, 
		tvb_get_ptr(pinfo->gssapi_wrap_tvb, 24, 8), 
		8); /* Confounder */
	memcpy(output_message_buffer, 
		input_message_buffer, 
	        datalen);
    }
    memset(k6_data, 0, sizeof(k6_data));

    /* only normal (i.e. non DCE style  wrapping use padding ? */
    if(pinfo->decrypt_gssapi_tvb==DECRYPT_GSSAPI_NORMAL){
	ret = gssapi_verify_pad(output_message_buffer,datalen,datalen, &padlen);
    	if (ret) {
	    return -9;
	}
	datalen -= padlen;
    }

    /* dont know what the checksum looks like for dce style gssapi */
    if(pinfo->decrypt_gssapi_tvb==DECRYPT_GSSAPI_NORMAL){
	ret = arcfour_mic_cksum(key_value, key_size,
			    KRB5_KU_USAGE_SEAL,
			    cksum_data, 
			    tvb_get_ptr(pinfo->gssapi_wrap_tvb, 0, 8), 8,
			    Confounder, sizeof(Confounder),
			    output_message_buffer, 
			    datalen + padlen);
	if (ret) {
	    return -10;
	}

	cmp = memcmp(cksum_data, 
	    tvb_get_ptr(pinfo->gssapi_wrap_tvb, 16, 8),
	    8); /* SGN_CKSUM */
	if (cmp) {
	    return -11;
	}
    }

    return datalen;
}



#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)

static void
decrypt_gssapi_krb_arcfour_wrap(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int keytype)
{
	int ret;
	enc_key_t *ek;
	int length;
	const guint8 *original_data;

	static int omb_index=0;
	static guint8 *omb_arr[4]={NULL,NULL,NULL,NULL};
	static guint8 *cryptocopy=NULL; /* workaround for pre-0.6.1 heimdal bug */
	guint8 *output_message_buffer;

	omb_index++;
	if(omb_index>=4){
		omb_index=0;
	}
	output_message_buffer=omb_arr[omb_index];


	length=tvb_length(pinfo->gssapi_encrypted_tvb);
	original_data=tvb_get_ptr(pinfo->gssapi_encrypted_tvb, 0, length);

	/* dont do anything if we are not attempting to decrypt data */
/*
	if(!krb_decrypt){
		return;
	}
*/
	/* XXX we should only do this for first time, then store somewhere */
	/* XXX We also need to re-read the keytab when the preference changes */

	cryptocopy=ep_alloc(length);
	if(output_message_buffer){
		g_free(output_message_buffer);
		output_message_buffer=NULL;
	}
	output_message_buffer=g_malloc(length);

	for(ek=enc_key_list;ek;ek=ek->next){
		/* shortcircuit and bail out if enctypes are not matching */
		if(ek->keytype!=keytype){
			continue;
		}

		/* pre-0.6.1 versions of Heimdal would sometimes change
		  the cryptotext data even when the decryption failed.
		  This would obviously not work since we iterate over the
		  keys. So just give it a copy of the crypto data instead.
		  This has been seen for RC4-HMAC blobs.
		*/
		memcpy(cryptocopy, original_data, length);
		ret=decrypt_arcfour(pinfo,
				cryptocopy,
				output_message_buffer,
				ek->keyvalue,
				ek->keylength,
				ek->keytype
					    );
		if (ret >= 0) {
			proto_tree_add_text(tree, NULL, 0, 0, "[Decrypted using: %s]", ek->key_origin);
			pinfo->gssapi_decrypted_tvb=tvb_new_real_data(
				output_message_buffer,
				ret, ret);
			tvb_set_child_real_data_tvbuff(tvb, pinfo->gssapi_decrypted_tvb);
			add_new_data_source(pinfo, pinfo->gssapi_decrypted_tvb, "Decrypted GSS-Krb5");
			return;
		}
	}
	return;
}
#endif /* HAVE_HEIMDAL_KERBEROS || HAVE_MIT_KERBEROS */


#endif

/*
 * XXX - This is for GSSAPI Wrap tokens ...
 */
static int
dissect_spnego_krb5_wrap_base(tvbuff_t *tvb, int offset, packet_info *pinfo
#ifndef HAVE_KERBEROS
	_U_
#endif
    , proto_tree *tree, guint16 token_id
#ifndef HAVE_KERBEROS
	_U_
#endif
    )
{
	guint16 sgn_alg, seal_alg;
#ifdef HAVE_KERBEROS
	int start_offset=offset;
#endif

	/*
	 * The KRB5 blob conforms to RFC1964:
	 *   USHORT (0x0102 == GSS_Wrap)
	 *   and so on } 
	 */

	/* Now, the sign and seal algorithms ... */

	sgn_alg = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_spnego_krb5_sgn_alg, tvb, offset, 2,
			    sgn_alg);

	offset += 2;

	seal_alg = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_spnego_krb5_seal_alg, tvb, offset, 2,
			    seal_alg);

	offset += 2;

	/* Skip the filler */

	offset += 2;

	/* Encrypted sequence number */

	proto_tree_add_item(tree, hf_spnego_krb5_snd_seq, tvb, offset, 8,
			    TRUE);

	offset += 8;

	/* Checksum of plaintext padded data */

	proto_tree_add_item(tree, hf_spnego_krb5_sgn_cksum, tvb, offset, 8,
			    TRUE);

	offset += 8;

	/*
	 * At least according to draft-brezak-win2k-krb-rc4-hmac-04,
	 * if the signing algorithm is KRB_SGN_ALG_HMAC, there's an
	 * extra 8 bytes of "Random confounder" after the checksum.
	 * It certainly confounds code expecting all Kerberos 5
	 * GSS_Wrap() tokens to look the same....
	 */
	if (sgn_alg == KRB_SGN_ALG_HMAC) {
	  proto_tree_add_item(tree, hf_spnego_krb5_confounder, tvb, offset, 8,
			      TRUE);
	  offset += 8;
	}

	/* Is the data encrypted? */
	pinfo->gssapi_data_encrypted=(seal_alg!=KRB_SEAL_ALG_NONE);

#ifdef HAVE_KERBEROS
#define GSS_ARCFOUR_WRAP_TOKEN_SIZE 32
	if(pinfo->decrypt_gssapi_tvb){
		/* if the caller did not provide a tvb, then we just use
		   whatever is left of our current tvb.
		*/
		if(!pinfo->gssapi_encrypted_tvb){
			int len;
			len=tvb_reported_length_remaining(tvb,offset);
			if(len>tvb_length_remaining(tvb, offset)){
				/* no point in trying to decrypt, 
				   we dont have the full pdu.
				*/
				return offset;
			}
			pinfo->gssapi_encrypted_tvb = tvb_new_subset(
					tvb, offset, len, len);
		}
			
		/* if this is KRB5 wrapped rc4-hmac */
		if((token_id==KRB_TOKEN_WRAP)
		 &&(sgn_alg==KRB_SGN_ALG_HMAC)
		 &&(seal_alg==KRB_SEAL_ALG_RC4)){
			/* do we need to create a tvb for the wrapper
			   as well ?
			*/
			if(!pinfo->gssapi_wrap_tvb){
				pinfo->gssapi_wrap_tvb = tvb_new_subset(
					tvb, start_offset-2,
					GSS_ARCFOUR_WRAP_TOKEN_SIZE,
					GSS_ARCFOUR_WRAP_TOKEN_SIZE);
			}
#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
			decrypt_gssapi_krb_arcfour_wrap(tree,
				pinfo,
				tvb,
				23 /* rc4-hmac */);
#endif /* HAVE_HEIMDAL_KERBEROS || HAVE_MIT_KERBEROS */
		}
	}	
#endif
	/*
	 * Return the offset past the checksum, so that we know where
	 * the data we're wrapped around starts.  Also, set the length
	 * of our top-level item to that offset, so it doesn't cover
	 * the data we're wrapped around.
	 * 
	 * Note that for DCERPC the GSSAPI blobs comes after the data it wraps,
	 * not before.
	 */
	return offset;
}

/*
 * XXX - This is for GSSAPI GetMIC tokens ...
 */
static int
dissect_spnego_krb5_getmic_base(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint16 sgn_alg;

	/*
	 * The KRB5 blob conforms to RFC1964:
	 *   USHORT (0x0101 == GSS_GetMIC)
	 *   and so on } 
	 */

	/* Now, the sign algorithm ... */

	sgn_alg = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_spnego_krb5_sgn_alg, tvb, offset, 2,
			    sgn_alg);

	offset += 2;

	/* Skip the filler */

	offset += 4;

	/* Encrypted sequence number */

	proto_tree_add_item(tree, hf_spnego_krb5_snd_seq, tvb, offset, 8,
			    TRUE);

	offset += 8;

	/* Checksum of plaintext padded data */

	proto_tree_add_item(tree, hf_spnego_krb5_sgn_cksum, tvb, offset, 8,
			    TRUE);

	offset += 8;

	/*
	 * At least according to draft-brezak-win2k-krb-rc4-hmac-04,
	 * if the signing algorithm is KRB_SGN_ALG_HMAC, there's an
	 * extra 8 bytes of "Random confounder" after the checksum.
	 * It certainly confounds code expecting all Kerberos 5
	 * GSS_Wrap() tokens to look the same....
	 */
	if (sgn_alg == KRB_SGN_ALG_HMAC) {
	  proto_tree_add_item(tree, hf_spnego_krb5_confounder, tvb, offset, 8,
			      TRUE);

	  offset += 8;
	}

	/*
	 * Return the offset past the checksum, so that we know where
	 * the data we're wrapped around starts.  Also, set the length
	 * of our top-level item to that offset, so it doesn't cover
	 * the data we're wrapped around.
	 */

	return offset;
}

/*
 * XXX - is this for SPNEGO or just GSS-API?
 * RFC 1964 is "The Kerberos Version 5 GSS-API Mechanism"; presumably one
 * can directly designate Kerberos V5 as a mechanism in GSS-API, rather
 * than designating SPNEGO as the mechanism, offering Kerberos V5, and
 * getting it accepted.
 */
static int
dissect_spnego_krb5_wrap(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	int offset = 0;
	guint16 token_id;

	item = proto_tree_add_item(tree, hf_spnego_krb5, tvb, 0, -1, FALSE);

	subtree = proto_item_add_subtree(item, ett_spnego_krb5);

	/*
	 * The KRB5 blob conforms to RFC1964:
	 *   USHORT (0x0102 == GSS_Wrap)
	 *   and so on } 
	 */

	/* First, the token ID ... */

	token_id = tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(subtree, hf_spnego_krb5_tok_id, tvb, offset, 2,
			    token_id);

	offset += 2;

        offset = dissect_spnego_krb5_wrap_base(tvb, offset, pinfo, subtree, token_id);

        /*
	 * Return the offset past the checksum, so that we know where
	 * the data we're wrapped around starts.  Also, set the length
	 * of our top-level item to that offset, so it doesn't cover
	 * the data we're wrapped around.
	 */
	proto_item_set_len(item, offset);
	return offset;
}

/* Spnego stuff from here */

static int
dissect_spnego_mechTypes(tvbuff_t *tvb, int offset, packet_info *pinfo,
			 proto_tree *tree,
			 gssapi_oid_value **next_level_value_p)
{
	proto_item *item = NULL;
	proto_tree *subtree = NULL;
	gboolean saw_mechanism = FALSE;
	int start_offset, start_oid_offset, end_oid_offset;
	gint8 class;
	gboolean pc, ind_field;
	gint32 tag;
	guint32 len1;
	gchar oid[MAX_OID_STR_LEN];

	start_offset=offset;
	/*
	 * MechTypeList ::= SEQUENCE OF MechType
	 */
	offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset = get_ber_length(tree, tvb, offset, &len1, &ind_field);

	if (!(class == BER_CLASS_UNI && pc && tag == BER_UNI_TAG_SEQUENCE)) {
	  proto_tree_add_text(
			      tree, tvb, offset, 0,
			      "Unknown header (class=%d, pc=%d, tag=%d)",
			      class, pc, tag);
	  goto done;
	}

	item = proto_tree_add_item(tree, hf_spnego_mechtype, tvb, 
				start_offset, len1, FALSE);
	subtree = proto_item_add_subtree(item, ett_spnego_mechtype);

	/*
	 * Now, the object IDs ...
	 */
	start_oid_offset=offset;
	end_oid_offset = start_oid_offset+len1;
	while (offset<end_oid_offset) {
	  gssapi_oid_value *value;

	  offset=dissect_ber_object_identifier(FALSE, pinfo, subtree, tvb, offset, hf_spnego_mech, oid);
	  value = gssapi_lookup_oid_str(oid);

	  /*
	   * Tell our caller the first mechanism we see, so that if
	   * this is a negTokenInit with a mechToken, it can interpret
	   * the mechToken according to the first mechType.  (There
	   * might not have been any indication of the mechType
	   * in prior frames, so we can't necessarily use the
	   * mechanism from the conversation; i.e., a negTokenInit
	   * can contain the initial security token for the desired
	   * mechanism of the initiator - that's the first mechanism
	   * in the list.)
	   */
	  if (!saw_mechanism) {
	    if (value)
	      *next_level_value_p = value;
	    saw_mechanism = TRUE;
	  }
	}

 done:

	return offset;

}

static int
dissect_spnego_reqFlags(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			proto_tree *tree, ASN1_SCK *hnd)
{
	gboolean def;
	guint len1, cls, con, tag, flags;
	int ret;
        proto_item *item;
        proto_tree *subtree;

 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, tree,
				    "SPNEGO reqFlags header", ret);
		goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_BTS)) {
		proto_tree_add_text(
			tree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	/* We must have a Bit String ... insert it */ 

	offset = hnd->offset;

        flags = tvb_get_guint8(tvb, offset);

	item = proto_tree_add_item(tree, hf_spnego_reqflags, tvb, offset, len1,
            FALSE);

        subtree = proto_item_add_subtree(item, ett_spnego_reqflags);

        /*
         * Now, the bits. XXX: Assume 8 bits. FIXME.
         */

        proto_tree_add_boolean(subtree, hf_gssapi_reqflags_deleg, tvb, offset, len1, flags);
        proto_tree_add_boolean(subtree, hf_gssapi_reqflags_mutual, tvb, offset, len1, flags);
        proto_tree_add_boolean(subtree, hf_gssapi_reqflags_replay, tvb, offset, len1, flags);
        proto_tree_add_boolean(subtree, hf_gssapi_reqflags_sequence, tvb, offset, len1, flags);
        proto_tree_add_boolean(subtree, hf_gssapi_reqflags_anon, tvb, offset, len1, flags);
        proto_tree_add_boolean(subtree, hf_gssapi_reqflags_conf, tvb, offset, len1, flags);
        proto_tree_add_boolean(subtree, hf_gssapi_reqflags_integ, tvb, offset, len1, flags);

	hnd->offset += len1;

 done:
	return offset + len1;

}

static int
dissect_spnego_mechToken(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			 proto_tree *tree, ASN1_SCK *hnd,
			 dissector_handle_t next_level_dissector)
{
        proto_item *item;
	proto_tree *subtree;
	gboolean def;
	int ret;
	guint cls, con, tag, nbytes = 0;
	gint length_remaining, reported_length_remaining;
	tvbuff_t *token_tvb;

	/*
	 * This appears to be a simple octet string ...
	 */

 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &nbytes);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, tree,
				    "SPNEGO sequence header", ret);
		goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_OTS)) {
		proto_tree_add_text(
			tree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd->offset;


	/* Dont try to create an item with more bytes than remains in the
	 * frame or we will not even attempt to dissect those bytes we
	 * do have. (since there will be an exception)
	 *
	 * We use "tvb_ensure_length_remaining()" so that we throw
	 * an exception if there's nothing to dissect.
	 */
	length_remaining = tvb_ensure_length_remaining(tvb,offset);
	reported_length_remaining = tvb_reported_length_remaining(tvb,offset);
	if ((guint)length_remaining > nbytes)
		length_remaining = nbytes;
	if ((guint)reported_length_remaining > nbytes)
		reported_length_remaining = nbytes;
	item = proto_tree_add_item(tree, hf_spnego_mechtoken, tvb, offset, 
				   length_remaining, FALSE);
	subtree = proto_item_add_subtree(item, ett_spnego_mechtoken);

	/*
	 * Now, we should be able to dispatch after creating a new TVB.
	 */

	token_tvb = tvb_new_subset(tvb, offset, length_remaining,
	    reported_length_remaining);
	if (next_level_dissector)
	  call_dissector(next_level_dissector, token_tvb, pinfo, subtree);

	hnd->offset += nbytes; /* Update this ... */

done:
	return offset + nbytes;
}

static int
dissect_spnego_mechListMIC(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			   proto_tree *tree, ASN1_SCK *hnd,
			   dissector_handle_t next_level_dissector)
{
	guint len1, cls, con, tag;
	int ret;
	gboolean def;
	proto_tree *subtree = NULL;

	/*
	 * Add the mechListMIC [3] Octet String or General String ...
	 */
 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO sequence header", ret);
		goto done;
	}

	offset = hnd->offset;

	if (cls == ASN1_UNI && con == ASN1_CON && tag == ASN1_SEQ) {

	  /*
	   * There seems to be two different forms this can take
	   * One as an Octet string, and one as a general string in a 
	   * sequence ... We will have to dissect this later
	   */
	 
	  proto_tree_add_text(tree, tvb, offset + 4, len1 - 4,
			      "mechListMIC: %s",
			      tvb_format_text(tvb, offset + 4, len1 - 4));

	  /* Naughty ... but we have to adjust for what we never took */

	  hnd->offset += len1;
	  offset += len1;

	}
	else if (cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_OTS) {
	  tvbuff_t *token_tvb;
	  proto_item *item;
	  proto_tree *subtree;

	  item = proto_tree_add_item(tree, hf_spnego_mechlistmic, tvb, offset, 
			      len1, FALSE); 
	  subtree = proto_item_add_subtree(item, ett_spnego_mechlistmic);
	  
	/*
	 * Now, we should be able to dispatch after creating a new TVB.
	 */

	  token_tvb = tvb_new_subset(tvb, offset, len1, -1);
	  if (next_level_dissector)
	    call_dissector(next_level_dissector, token_tvb, pinfo, subtree);

	  hnd->offset += len1; /* Update this ... */
	  offset += len1;

	}
	else {

	  proto_tree_add_text(subtree, tvb, offset, 0,
			      "Unknown header (cls=%d, con=%d, tag=%d)",
			      cls, con, tag);
	  goto done;
	}

 done:

	return offset;

}

static int
dissect_spnego_negTokenInit(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree, ASN1_SCK *hnd,
			    gssapi_oid_value **next_level_value_p)
{
	proto_item *item;
	proto_tree *subtree;
	gboolean def;
	guint len1, len, cls, con, tag;
	int ret;

	item = proto_tree_add_item( tree, hf_spnego_negtokeninit, tvb, offset,
				    -1, FALSE);
	subtree = proto_item_add_subtree(item, ett_spnego_negtokeninit);

	/*
	 * Here is what we need to get ...
	 * NegTokenInit ::= SEQUENCE {
	 *          mechTypes [0] MechTypeList OPTIONAL,
	 *          reqFlags [1] ContextFlags OPTIONAL,
	 *          mechToken [2] OCTET STRING OPTIONAL,
	 *          mechListMIC [3] OCTET STRING OPTIONAL }

	 */

 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO sequence header", ret);
		goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_CON && tag == ASN1_SEQ)) {
		proto_tree_add_text(
			subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd->offset;

	while (len1) {
	  int hdr_ofs;

	  hdr_ofs = hnd->offset;

	  ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len);

	  if (ret != ASN1_ERR_NOERROR) {
	    dissect_parse_error(tvb, offset, pinfo, subtree,
				"SPNEGO context header", ret);
	    goto done;
	  }

	  if (!(cls == ASN1_CTX && con == ASN1_CON)) {
	    proto_tree_add_text(subtree, tvb, offset, 0,
				"Unknown header (cls=%d, con=%d, tag=%d)",
				cls, con, tag);
	    goto done;
	  }

	  /* Adjust for the length of the header */

	  len1 -= (hnd->offset - hdr_ofs);

	  /* Should be one of the fields */

	  switch (tag) {

	  case SPNEGO_mechTypes:

	    offset = dissect_spnego_mechTypes(tvb, hnd->offset, pinfo,
					      subtree,
					      next_level_value_p);
	    hnd->offset=offset;

	    break;

	  case SPNEGO_reqFlags:

	    offset = dissect_spnego_reqFlags(tvb, offset, pinfo, subtree, hnd);

	    break;

	  case SPNEGO_mechToken:

	    offset = dissect_spnego_mechToken(tvb, offset, pinfo, subtree, 
					      hnd, gssapi_dissector_handle(*next_level_value_p));
	    break;

	  case SPNEGO_mechListMIC:

	    offset = dissect_spnego_mechListMIC(tvb, offset, pinfo, subtree,
						hnd, gssapi_dissector_handle(*next_level_value_p));
	    break;

	  default:

	    break;
	  }

	  len1 -= len;

	}

 done:

	return offset; /* Not sure this is right */
}

static int
dissect_spnego_negResult(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree, ASN1_SCK *hnd)
{
        gboolean def;
	int ret;
	guint len, cls, con, tag, val;

	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len);

	if (ret != ASN1_ERR_NOERROR) {
	  dissect_parse_error(tvb, offset, pinfo, tree,
			      "SPNEGO context header", ret);
	  goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_ENUM)) {
	  proto_tree_add_text(
			      tree, tvb, offset, 0,
			      "Unknown header (cls=%d, con=%d, tag=%d) xxx",
			      cls, con, tag);
	  goto done;
	}

	offset = hnd->offset;

	/* Now, get the value */

	ret = asn1_uint32_value_decode(hnd, len, &val);

	if (ret != ASN1_ERR_NOERROR) {
	  dissect_parse_error(tvb, offset, pinfo, tree,
			      "SPNEGO negResult value", ret);
	  goto done;
	}
	
	proto_tree_add_item(tree, hf_spnego_negtokentarg_negresult, tvb, 
			    offset, 1, FALSE);

	offset = hnd->offset;

 done:
	return offset;
}

static int
dissect_spnego_supportedMech(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree, ASN1_SCK *hnd,
			     gssapi_oid_value **next_level_value_p)
{
	int ret;
	guint oid_len, nbytes;
	subid_t *oid;
	gchar *oid_string;
	gssapi_oid_value *value;
	conversation_t *conversation;

	/*
	 * Now, get the OID, and find the handle, if any
	 */

	offset = hnd->offset;

	ret = asn1_oid_decode(hnd, &oid, &oid_len, &nbytes);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, tree,
				    "SPNEGO supportedMech token", ret);
		goto done;
	}

	oid_string = format_oid(oid, oid_len);
	value = gssapi_lookup_oid(oid, oid_len);

	if (value)
	  proto_tree_add_text(tree, tvb, offset, nbytes, 
			      "supportedMech: %s (%s)",
			      oid_string, value->comment);
	else
	  proto_tree_add_text(tree, tvb, offset, nbytes, "supportedMech: %s",
			      oid_string);

	offset += nbytes;

	/* Should check for an unrecognized OID ... */

	if (value)
	  *next_level_value_p = value;

	/*
	 * Now, we need to save this in per proto info in the
	 * conversation if it exists. We also should create a 
	 * conversation if one does not exist. FIXME!
	 * Hmmm, might need to be smarter, because there can be
	 * multiple mechTypes in a negTokenInit with one being the
	 * default used in the Token if present. Then the negTokenTarg
	 * could override that. :-(
	 */

	if ((conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
					     pinfo->ptype, pinfo->srcport,
					     pinfo->destport, 0))) {


	  conversation_add_proto_data(conversation, proto_spnego, 
				      *next_level_value_p);
	}
	else {

	}

 done:
	return offset;
}

static int
dissect_spnego_responseToken(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			     proto_tree *tree, ASN1_SCK *hnd,
			     dissector_handle_t next_level_dissector)
{
	gboolean def;
	int ret;
	guint cls, con, tag, nbytes;
	tvbuff_t *token_tvb;
	proto_item *item;
	proto_tree *subtree;

 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &nbytes);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, tree,
				    "SPNEGO sequence header", ret);
		goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_OTS)) {
		proto_tree_add_text(
			tree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd->offset;

	item = proto_tree_add_item(tree, hf_spnego_responsetoken, tvb, offset -2 , 
				   nbytes + 2, FALSE); 

	subtree = proto_item_add_subtree(item, ett_spnego_responsetoken);


	/*
	 * Now, we should be able to dispatch after creating a new TVB.
	 * However, we should make sure that there is something in the 
	 * response token ...
	 */

	if (nbytes) {
	  token_tvb = tvb_new_subset(tvb, offset, nbytes, -1);
	  if (next_level_dissector)
	    call_dissector(next_level_dissector, token_tvb, pinfo, subtree);
	}
	else {
	  proto_tree_add_text(subtree, tvb, offset-2, 2, "<Empty String>");
	}
	hnd->offset += nbytes; /* Update this ... */

 done:
	return offset + nbytes;
}

static int
dissect_spnego_negTokenTarg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_,
			    proto_tree *tree, ASN1_SCK *hnd,
			    gssapi_oid_value **next_level_value_p)

{
	proto_item *item;
	proto_tree *subtree;
	gboolean def;
	int ret;
	guint len1, len, cls, con, tag;

	item = proto_tree_add_item( tree, hf_spnego_negtokentarg, tvb, offset,
				    -1, FALSE);
	subtree = proto_item_add_subtree(item, ett_spnego_negtokentarg);

	/* 
	 * Here is what we need to get ...
         * NegTokenTarg ::= SEQUENCE {
	 *          negResult [0] ENUMERATED {
	 *              accept_completed (0),
	 *              accept_incomplete (1),
	 *              reject (2) } OPTIONAL,
         *          supportedMech [1] MechType OPTIONAL,
         *          responseToken [2] OCTET STRING OPTIONAL,
         *          mechListMIC [3] OCTET STRING OPTIONAL }
	 */

 	ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO sequence header", ret);
		goto done;
	}

	if (!(cls == ASN1_UNI && con == ASN1_CON && tag == ASN1_SEQ)) {
		proto_tree_add_text(
			subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd->offset;

	while (len1) {
	  int hdr_ofs;

	  hdr_ofs = hnd->offset; 

	  ret = asn1_header_decode(hnd, &cls, &con, &tag, &def, &len);

	  if (ret != ASN1_ERR_NOERROR) {
	    dissect_parse_error(tvb, offset, pinfo, subtree,
				"SPNEGO context header", ret);
	    goto done;
	  }

	  if (!(cls == ASN1_CTX && con == ASN1_CON)) {
	    proto_tree_add_text(
				subtree, tvb, offset, 0,
				"Unknown header (cls=%d, con=%d, tag=%d)",
				cls, con, tag);
	    goto done;
	  }

	  /* Adjust for the length of the header */

	  len1 -= (hnd->offset - hdr_ofs);

	  /* Should be one of the fields */

	  switch (tag) {

	  case SPNEGO_negResult:

	    offset = dissect_spnego_negResult(tvb, offset, pinfo, subtree, 
					      hnd);
	    break;

	  case SPNEGO_supportedMech:

	    offset = dissect_spnego_supportedMech(tvb, offset, pinfo, subtree,
						  hnd, next_level_value_p);

	    break;

	  case SPNEGO_responseToken:

	    offset = dissect_spnego_responseToken(tvb, offset, pinfo, subtree,
						  hnd, gssapi_dissector_handle(*next_level_value_p));
	    break;

	  case SPNEGO_mechListMIC:

	    offset = dissect_spnego_mechListMIC(tvb, offset, pinfo, subtree, 
						hnd, gssapi_dissector_handle(*next_level_value_p));
	    break;

	  default:

	    break;
	  }

	  len1 -= len;

	}

 done:
	return offset;

}

static void
dissect_spnego(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	int ret, offset = 0;
	ASN1_SCK hnd;
	gboolean def;
	guint len1, cls, con, tag;
	conversation_t *conversation;
	gssapi_oid_value *next_level_value;

	/*
	 * We need this later, so lets get it now ...
	 * It has to be per-frame as there can be more than one GSS-API
	 * negotiation in a conversation.
	 */

	next_level_value = p_get_proto_data(pinfo->fd, proto_spnego);
	if (!next_level_value && !pinfo->fd->flags.visited) {
	    /*
	     * No handle attached to this frame, but it's the first
	     * pass, so it'd be attached to the conversation.
	     * If we have a conversation, try to get the handle,
	     * and if we get one, attach it to the frame.
	     */
	    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
					     pinfo->ptype, pinfo->srcport,
					     pinfo->destport, 0);

	    if (conversation) {
		next_level_value = conversation_get_proto_data(conversation, 
							       proto_spnego);
		if (next_level_value)
		    p_add_proto_data(pinfo->fd, proto_spnego, next_level_value);
	    }
	}

	item = proto_tree_add_item(tree, hf_spnego, tvb, offset, 
				   -1, FALSE);

	subtree = proto_item_add_subtree(item, ett_spnego);

	/*
	 * The TVB contains a [0] header and a sequence that consists of an
	 * object ID and a blob containing the data ...
	 * Actually, it contains, according to RFC2478:
         * NegotiationToken ::= CHOICE {
	 *          negTokenInit [0] NegTokenInit,
	 *          negTokenTarg [1] NegTokenTarg }
	 * NegTokenInit ::= SEQUENCE {
	 *          mechTypes [0] MechTypeList OPTIONAL,
	 *          reqFlags [1] ContextFlags OPTIONAL,
	 *          mechToken [2] OCTET STRING OPTIONAL,
	 *          mechListMIC [3] OCTET STRING OPTIONAL }
         * NegTokenTarg ::= SEQUENCE {
	 *          negResult [0] ENUMERATED {
	 *              accept_completed (0),
	 *              accept_incomplete (1),
	 *              reject (2) } OPTIONAL,
         *          supportedMech [1] MechType OPTIONAL,
         *          responseToken [2] OCTET STRING OPTIONAL,
         *          mechListMIC [3] OCTET STRING OPTIONAL }
         *
	 * Windows typically includes mechTypes and mechListMic ('NONE'
	 * in the case of NTLMSSP only).
         * It seems to duplicate the responseToken into the mechListMic field
         * as well. Naughty, naughty.
         *
	 */

	asn1_open(&hnd, tvb, offset);

	/*
	 * Get the first header ...
	 */

	ret = asn1_header_decode(&hnd, &cls, &con, &tag, &def, &len1);

	if (ret != ASN1_ERR_NOERROR) {
		dissect_parse_error(tvb, offset, pinfo, subtree,
				    "SPNEGO context header", ret);
		goto done;
	}

	if (!(cls == ASN1_CTX && con == ASN1_CON)) {
		proto_tree_add_text(
			subtree, tvb, offset, 0,
			"Unknown header (cls=%d, con=%d, tag=%d)",
			cls, con, tag);
		goto done;
	}

	offset = hnd.offset;

	/*
	 * The Tag is one of negTokenInit or negTokenTarg
	 */

	switch (tag) {

	case SPNEGO_negTokenInit:

	  offset = dissect_spnego_negTokenInit(tvb, offset, pinfo,
					       subtree, &hnd,
					       &next_level_value);

	  break;

	case SPNEGO_negTokenTarg:

	  offset = dissect_spnego_negTokenTarg(tvb, offset, pinfo,
					       subtree, &hnd,
					       &next_level_value);
	  break;

	default: /* Broken, what to do? */

	  break;
	}


 done:
	asn1_close(&hnd, &offset);

}

static int
dissect_spnego_wrap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	int return_offset;
	conversation_t *conversation;
	gssapi_oid_value *next_level_value;
	tvbuff_t *token_tvb;
	int len, offset, start_offset;
	gint8 class;
	gboolean pc, ind_field;
	gint32 tag;
	guint32 len1;
	gchar oid[MAX_OID_STR_LEN];

	start_offset=0;
	offset=start_offset;

	/*
	 * We need this later, so lets get it now ...
	 * It has to be per-frame as there can be more than one GSS-API
	 * negotiation in a conversation.
	 */

	next_level_value = p_get_proto_data(pinfo->fd, proto_spnego);
	if (!next_level_value && !pinfo->fd->flags.visited) {
	    /*
	     * No handle attached to this frame, but it's the first
	     * pass, so it'd be attached to the conversation.
	     * If we have a conversation, try to get the handle,
	     * and if we get one, attach it to the frame.
	     */
	    conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
					     pinfo->ptype, pinfo->srcport,
					     pinfo->destport, 0);

	    if (conversation) {
		next_level_value = conversation_get_proto_data(conversation, 
							       proto_spnego);
		if (next_level_value)
		    p_add_proto_data(pinfo->fd, proto_spnego, next_level_value);
	    }
	}

	item = proto_tree_add_item(tree, hf_spnego, tvb, offset, 
				   -1, FALSE);

	subtree = proto_item_add_subtree(item, ett_spnego);

	/*
	 * The TVB contains a [0] header and a sequence that consists of an
	 * object ID and a blob containing the data ...
	 * XXX - is this RFC 2743's "Mechanism-Independent Token Format",
	 * with the "optional" "use in non-initial tokens" being chosen.
	 */

	/*
	 * Get the first header ...
	 */
	offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset = get_ber_length(tree, tvb, offset, &len1, &ind_field);

	if (!(class == BER_CLASS_APP && pc && tag == 0)) {
		proto_tree_add_text(
			subtree, tvb, start_offset, 0,
			"Unknown header (class=%d, pc=%d, tag=%d)",
			class, pc, tag);
		return_offset = tvb_length(tvb);
		goto done;
	}

	/*
	 * Get the OID, and find the handle, if any
 	 *
	 * XXX - what should we do if this OID doesn't match the value
	 * attached to the frame or conversation?  (That would be
	 * bogus, but that's not impossible - some broken implementation
	 * might negotiate some security mechanism but put the OID
	 * for some other security mechanism in GSS_Wrap tokens.)
	 */
	offset=dissect_ber_object_identifier(FALSE, pinfo, subtree, tvb, offset, hf_spnego_this_mech, oid);
	next_level_value = gssapi_lookup_oid_str(oid);

	/*
	 * Now dissect the GSS_Wrap token; it's assumed to be in the
	 * rest of the tvbuff.
	 */
	item = proto_tree_add_item(tree, hf_spnego_wraptoken, tvb, offset, 
				   -1, FALSE); 

	subtree = proto_item_add_subtree(item, ett_spnego_wraptoken);

	/*
	 * Now, we should be able to dispatch after creating a new TVB.
	 * The subdissector must return the length of the part of the
	 * token it dissected, so we can return the length of the part
	 * we (and it) dissected.
	 */

	token_tvb = tvb_new_subset(tvb, offset, -1, -1);
	if (next_level_value->wrap_handle) {
	  len = call_dissector(next_level_value->wrap_handle, token_tvb, pinfo, subtree);
	  if (len == 0)
	    return_offset = tvb_length(tvb);
	  else
	    return_offset = offset + len;
	} else
	  return_offset = tvb_length(tvb);
 done:

	return return_offset;
}

void
proto_register_spnego(void)
{
	static hf_register_info hf[] = {
		{ &hf_spnego,
		  { "SPNEGO", "spnego", FT_NONE, BASE_NONE, NULL, 0x0,
		    "SPNEGO", HFILL }},
		{ &hf_spnego_mech, {
		    "Mech", "spnego.mech", FT_STRING, BASE_NONE,
		    NULL, 0, "This is a SPNEGO Object Identifier", HFILL }},
		{ &hf_spnego_this_mech, {
		    "thisMech", "spnego.this_mech", FT_STRING, BASE_NONE,
		    NULL, 0, "This is a SPNEGO Object Identifier", HFILL }},
		{ &hf_spnego_negtokeninit,
		  { "negTokenInit", "spnego.negtokeninit", FT_NONE, BASE_NONE,
		    NULL, 0x0, "SPNEGO negTokenInit", HFILL}},
		{ &hf_spnego_negtokentarg,
		  { "negTokenTarg", "spnego.negtokentarg", FT_NONE, BASE_NONE,
		    NULL, 0x0, "SPNEGO negTokenTarg", HFILL}},
		{ &hf_spnego_mechtype,
		  { "mechType", "spnego.negtokeninit.mechtype", FT_NONE,
		    BASE_NONE, NULL, 0x0, "SPNEGO negTokenInit mechTypes", HFILL}},
		{ &hf_spnego_mechtoken,
		  { "mechToken", "spnego.negtokeninit.mechtoken", FT_NONE,
		    BASE_NONE, NULL, 0x0, "SPNEGO negTokenInit mechToken", HFILL}},
		{ &hf_spnego_mechlistmic,
		  { "mechListMIC", "spnego.mechlistmic", FT_NONE,
		    BASE_NONE, NULL, 0x0, "SPNEGO mechListMIC", HFILL}}, 
		{ &hf_spnego_responsetoken,
		  { "responseToken", "spnego.negtokentarg.responsetoken",
		    FT_NONE, BASE_NONE, NULL, 0x0, "SPNEGO responseToken",
		    HFILL}},
		{ &hf_spnego_negtokentarg_negresult,
		  { "negResult", "spnego.negtokeninit.negresult", FT_UINT16,
		    BASE_HEX, VALS(spnego_negResult_vals), 0, "negResult", HFILL}},
		{ &hf_spnego_reqflags, 
		  { "reqFlags", "spnego.negtokeninit.reqflags", FT_BYTES,
		    BASE_HEX, NULL, 0, "reqFlags", HFILL }},
                { &hf_gssapi_reqflags_deleg,
                  { "Delegation", "gssapi.reqflags.deleg", FT_BOOLEAN, 8,
                    TFS(&tfs_reqflags_deleg), 0x01, "Delegation", HFILL }},
                { &hf_gssapi_reqflags_mutual,
                  { "Mutual Authentication", "gssapi.reqflags.mutual", FT_BOOLEAN,
                    8, TFS(&tfs_reqflags_mutual), 0x02, "Mutual Authentication", HFILL}},
                { &hf_gssapi_reqflags_replay,
                  { "Replay Detection", "gssapi.reqflags.replay", FT_BOOLEAN,
                    8, TFS(&tfs_reqflags_replay), 0x04, "Replay Detection", HFILL}},
                { &hf_gssapi_reqflags_sequence,
                  { "Out-of-sequence Detection", "gssapi.reqflags.sequence",
                    FT_BOOLEAN, 8, TFS(&tfs_reqflags_sequence), 0x08, 
                    "Out-of-sequence Detection", HFILL}},
                { &hf_gssapi_reqflags_anon,
                  { "Anonymous Authentication", "gssapi.reqflags.anon", 
                    FT_BOOLEAN, 8, TFS(&tfs_reqflags_anon), 0x10,
                    "Anonymous Authentication", HFILL}},
                { &hf_gssapi_reqflags_conf,
                  { "Per-message Confidentiality", "gssapi.reqflags.conf",
                    FT_BOOLEAN, 8, TFS(&tfs_reqflags_conf), 0x20, 
                    "Per-message Confidentiality", HFILL}},
                { &hf_gssapi_reqflags_integ,
                  { "Per-message Integrity", "gssapi.reqflags.integ", 
                    FT_BOOLEAN, 8, TFS(&tfs_reqflags_integ), 0x40,
                    "Per-message Integrity", HFILL}},
		{ &hf_spnego_wraptoken,
		  { "wrapToken", "spnego.wraptoken",
		    FT_NONE, BASE_NONE, NULL, 0x0, "SPNEGO wrapToken",
		    HFILL}},
		{ &hf_spnego_krb5,
		  { "krb5_blob", "spnego.krb5.blob", FT_BYTES,
		    BASE_NONE, NULL, 0, "krb5_blob", HFILL }},
		{ &hf_spnego_krb5_tok_id,
		  { "krb5_tok_id", "spnego.krb5.tok_id", FT_UINT16, BASE_HEX,
		    VALS(spnego_krb5_tok_id_vals), 0, "KRB5 Token Id", HFILL}},
		{ &hf_spnego_krb5_sgn_alg,
		  { "krb5_sgn_alg", "spnego.krb5.sgn_alg", FT_UINT16, BASE_HEX,
		    VALS(spnego_krb5_sgn_alg_vals), 0, "KRB5 Signing Algorithm", HFILL}},
		{ &hf_spnego_krb5_seal_alg,
		  { "krb5_seal_alg", "spnego.krb5.seal_alg", FT_UINT16, BASE_HEX,
		    VALS(spnego_krb5_seal_alg_vals), 0, "KRB5 Sealing Algorithm", HFILL}},
		{ &hf_spnego_krb5_snd_seq,
		  { "krb5_snd_seq", "spnego.krb5.snd_seq", FT_BYTES, BASE_NONE,
		    NULL, 0, "KRB5 Encrypted Sequence Number", HFILL}},
		{ &hf_spnego_krb5_sgn_cksum,
		  { "krb5_sgn_cksum", "spnego.krb5.sgn_cksum", FT_BYTES, BASE_NONE,
		    NULL, 0, "KRB5 Data Checksum", HFILL}},
		{ &hf_spnego_krb5_confounder,
		  { "krb5_confounder", "spnego.krb5.confounder", FT_BYTES, BASE_NONE,
		    NULL, 0, "KRB5 Confounder", HFILL}},
	};

	static gint *ett[] = {
		&ett_spnego,
		&ett_spnego_negtokeninit,
		&ett_spnego_negtokentarg,
		&ett_spnego_mechtype,
		&ett_spnego_mechtoken,
		&ett_spnego_mechlistmic,
		&ett_spnego_responsetoken,
		&ett_spnego_wraptoken,
		&ett_spnego_krb5,
	};

	proto_spnego = proto_register_protocol(
		"Spnego", "Spnego", "spnego");
	proto_spnego_krb5 = proto_register_protocol("SPNEGO-KRB5",
						    "SPNEGO-KRB5",
						    "spnego-krb5");

	proto_register_field_array(proto_spnego, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_spnego(void)
{
	dissector_handle_t spnego_handle, spnego_wrap_handle;
	dissector_handle_t spnego_krb5_handle, spnego_krb5_wrap_handle;

	/* Register protocol with GSS-API module */

	spnego_handle = create_dissector_handle(dissect_spnego, proto_spnego);
	spnego_wrap_handle = new_create_dissector_handle(dissect_spnego_wrap,
							 proto_spnego);
	gssapi_init_oid("1.3.6.1.5.5.2", proto_spnego, ett_spnego,
	    spnego_handle, spnego_wrap_handle,
	    "SPNEGO - Simple Protected Negotiation");

	/* Register both the one MS created and the real one */
	/*
	 * Thanks to Jean-Baptiste Marchand and Richard B Ward, the
	 * mystery of the MS KRB5 OID is cleared up. It was due to a library
	 * that did not handle OID components greater than 16 bits, and was
	 * fixed in Win2K SP2 as well as WinXP.
	 * See the archive of <ietf-krb-wg@anl.gov> for the thread topic
	 * SPNEGO implementation issues. 3-Dec-2002.
	 */
	spnego_krb5_handle = create_dissector_handle(dissect_spnego_krb5,
						     proto_spnego_krb5);
	spnego_krb5_wrap_handle = new_create_dissector_handle(dissect_spnego_krb5_wrap,
							      proto_spnego_krb5);
	gssapi_init_oid("1.2.840.48018.1.2.2", proto_spnego_krb5, ett_spnego_krb5,
			spnego_krb5_handle, spnego_krb5_wrap_handle,
			"MS KRB5 - Microsoft Kerberos 5");
	gssapi_init_oid("1.2.840.113554.1.2.2", proto_spnego_krb5, ett_spnego_krb5,
			spnego_krb5_handle, spnego_krb5_wrap_handle,
			"KRB5 - Kerberos 5");
	gssapi_init_oid("1.2.840.113554.1.2.2.3", proto_spnego_krb5, ett_spnego_krb5,
			spnego_krb5_handle, spnego_krb5_wrap_handle,
			"KRB5 - Kerberos 5 - User to User");

	/*
	 * Find the data handle for some calls
	 */
	data_handle = find_dissector("data");
}
