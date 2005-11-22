/* packet-kerberos.c
 * Routines for Kerberos
 * Wes Hardaker (c) 2000
 * wjhardaker@ucdavis.edu
 * Richard Sharpe (C) 2002, rsharpe@samba.org, modularized a bit more and
 *                          added AP-REQ and AP-REP dissection
 *
 * Ronnie Sahlberg (C) 2004, major rewrite for new ASN.1/BER API.
 *                           decryption of kerberos blobs if keytab is provided
 *
 * See RFC 1510, and various I-Ds and other documents showing additions,
 * e.g. ones listed under
 *
 *	http://www.isi.edu/people/bcn/krb-revisions/
 *
 * and
 *
 *	http://www.ietf.org/internet-drafts/draft-ietf-krb-wg-kerberos-clarifications-07.txt
 *
 * and
 *
 *      http://www.ietf.org/internet-drafts/draft-ietf-krb-wg-kerberos-referrals-05.txt
 *
 * Some structures from RFC2630
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

/*
 * Some of the development of the Kerberos protocol decoder was sponsored by
 * Cable Television Laboratories, Inc. ("CableLabs") based upon proprietary
 * CableLabs' specifications. Your license and use of this protocol decoder
 * does not mean that you are licensed to use the CableLabs'
 * specifications.  If you have questions about this protocol, contact
 * jf.mule [AT] cablelabs.com or c.stuart [AT] cablelabs.com for additional
 * information.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_LIBNETTLE
#define HAVE_KERBEROS
#ifdef _WIN32
#include <des.h>
#include <cbc.h>
#else
#include <nettle/des.h>
#include <nettle/cbc.h>
#endif
#include "crypt-md5.h"
#include <sys/stat.h>	/* For keyfile manipulation */
#endif

#include <glib.h>

#include <epan/packet.h>

#include <epan/strutil.h>

#include <epan/conversation.h>
#include <epan/dissectors/packet-kerberos.h>
#include <epan/dissectors/packet-netbios.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-ber.h>
#include <epan/dissectors/packet-pkinit.h>
#include <epan/dissectors/packet-cms.h>
#include <epan/dissectors/packet-windows-common.h>

#include <epan/dissectors/packet-dcerpc-netlogon.h>
#include <epan/dissectors/packet-dcerpc.h>

#include <epan/dissectors/packet-gssapi.h>
#include <epan/emem.h>

#define UDP_PORT_KERBEROS		88
#define TCP_PORT_KERBEROS		88

static dissector_handle_t kerberos_handle_udp;

/* Desegment Kerberos over TCP messages */
static gboolean krb_desegment = TRUE;

static gint proto_kerberos = -1;
static gint hf_krb_rm_reserved = -1;
static gint hf_krb_rm_reclen = -1;

static gint hf_krb_pac_signature_type = -1;
static gint hf_krb_pac_signature_signature = -1;
static gint hf_krb_pac_clientid = -1;
static gint hf_krb_pac_namelen = -1;
static gint hf_krb_pac_clientname = -1;
static gint hf_krb_w2k_pac_entries = -1;
static gint hf_krb_w2k_pac_version = -1;
static gint hf_krb_w2k_pac_type = -1;
static gint hf_krb_w2k_pac_size = -1;
static gint hf_krb_w2k_pac_offset = -1;
static gint hf_krb_padata = -1;
static gint hf_krb_error_code = -1;
static gint hf_krb_ticket = -1;
static gint hf_krb_AP_REP_enc = -1;
static gint hf_krb_KDC_REP_enc = -1;
static gint hf_krb_tkt_vno = -1;
static gint hf_krb_e_data = -1;
static gint hf_krb_TransitedEncoding = -1;
static gint hf_krb_PA_PAC_REQUEST_flag = -1;
static gint hf_krb_encrypted_authenticator_data = -1;
static gint hf_krb_PAC_LOGON_INFO = -1;
static gint hf_krb_PAC_CREDENTIAL_TYPE = -1;
static gint hf_krb_PAC_SERVER_CHECKSUM = -1;
static gint hf_krb_PAC_PRIVSVR_CHECKSUM = -1;
static gint hf_krb_PAC_CLIENT_INFO_TYPE = -1;
static gint hf_krb_encrypted_PA_ENC_TIMESTAMP = -1;
static gint hf_krb_checksum_checksum = -1;
static gint hf_krb_encrypted_PRIV = -1;
static gint hf_krb_encrypted_Ticket_data = -1;
static gint hf_krb_encrypted_AP_REP_data = -1;
static gint hf_krb_encrypted_KDC_REP_data = -1;
static gint hf_krb_PA_DATA_type = -1;
static gint hf_krb_PA_DATA_value = -1;
static gint hf_krb_etype_info_salt = -1;
static gint hf_krb_etype_info2_salt = -1;
static gint hf_krb_etype_info2_s2kparams = -1;
static gint hf_krb_SAFE_BODY_user_data = -1;
static gint hf_krb_PRIV_BODY_user_data = -1;
static gint hf_krb_realm = -1;
static gint hf_krb_crealm = -1;
static gint hf_krb_sname = -1;
static gint hf_krb_cname = -1;
static gint hf_krb_name_string = -1;
static gint hf_krb_provsrv_location = -1;
static gint hf_krb_e_text = -1;
static gint hf_krb_name_type = -1;
static gint hf_krb_lr_type = -1;
static gint hf_krb_from = -1;
static gint hf_krb_till = -1;
static gint hf_krb_authtime = -1;
static gint hf_krb_patimestamp = -1;
static gint hf_krb_SAFE_BODY_timestamp = -1;
static gint hf_krb_pausec = -1;
static gint hf_krb_lr_time = -1;
static gint hf_krb_starttime = -1;
static gint hf_krb_endtime = -1;
static gint hf_krb_key_expire = -1;
static gint hf_krb_renew_till = -1;
static gint hf_krb_rtime = -1;
static gint hf_krb_ctime = -1;
static gint hf_krb_cusec = -1;
static gint hf_krb_stime = -1;
static gint hf_krb_susec = -1;
static gint hf_krb_SAFE_BODY_usec = -1;
static gint hf_krb_nonce = -1;
static gint hf_krb_transitedtype = -1;
static gint hf_krb_transitedcontents = -1;
static gint hf_krb_keytype = -1;
static gint hf_krb_keyvalue = -1;
static gint hf_krb_IF_RELEVANT_type = -1;
static gint hf_krb_IF_RELEVANT_value = -1;
static gint hf_krb_adtype = -1;
static gint hf_krb_advalue = -1;
static gint hf_krb_etype = -1;
static gint hf_krb_etypes = -1;
static gint hf_krb_LastReqs = -1;
static gint hf_krb_IF_RELEVANT = -1;
static gint hf_krb_addr_type = -1;
static gint hf_krb_address_ip = -1;
static gint hf_krb_address_netbios = -1;
static gint hf_krb_msg_type = -1;
static gint hf_krb_pvno = -1;
static gint hf_krb_kvno = -1;
static gint hf_krb_checksum_type = -1;
static gint hf_krb_authenticator_vno = -1;
static gint hf_krb_AuthorizationData = -1;
static gint hf_krb_key = -1;
static gint hf_krb_subkey = -1;
static gint hf_krb_seq_number = -1;
static gint hf_krb_EncTicketPart = -1;
static gint hf_krb_EncAPRepPart = -1;
static gint hf_krb_EncKrbPrivPart = -1;
static gint hf_krb_EncKDCRepPart = -1;
static gint hf_krb_LastReq = -1;
static gint hf_krb_Authenticator = -1;
static gint hf_krb_Checksum = -1;
static gint hf_krb_s_address = -1;
static gint hf_krb_HostAddress = -1;
static gint hf_krb_HostAddresses = -1;
static gint hf_krb_APOptions = -1;
static gint hf_krb_APOptions_use_session_key = -1;
static gint hf_krb_APOptions_mutual_required = -1;
static gint hf_krb_TicketFlags = -1;
static gint hf_krb_TicketFlags_forwardable = -1;
static gint hf_krb_TicketFlags_forwarded = -1;
static gint hf_krb_TicketFlags_proxyable = -1;
static gint hf_krb_TicketFlags_proxy = -1;
static gint hf_krb_TicketFlags_allow_postdate = -1;
static gint hf_krb_TicketFlags_postdated = -1;
static gint hf_krb_TicketFlags_invalid = -1;
static gint hf_krb_TicketFlags_renewable = -1;
static gint hf_krb_TicketFlags_initial = -1;
static gint hf_krb_TicketFlags_pre_auth = -1;
static gint hf_krb_TicketFlags_hw_auth = -1;
static gint hf_krb_TicketFlags_transited_policy_checked = -1;
static gint hf_krb_TicketFlags_ok_as_delegate = -1;
static gint hf_krb_KDCOptions = -1;
static gint hf_krb_KDCOptions_forwardable = -1;
static gint hf_krb_KDCOptions_forwarded = -1;
static gint hf_krb_KDCOptions_proxyable = -1;
static gint hf_krb_KDCOptions_proxy = -1;
static gint hf_krb_KDCOptions_allow_postdate = -1;
static gint hf_krb_KDCOptions_postdated = -1;
static gint hf_krb_KDCOptions_renewable = -1;
static gint hf_krb_KDCOptions_canonicalize = -1;
static gint hf_krb_KDCOptions_opt_hardware_auth = -1;
static gint hf_krb_KDCOptions_disable_transited_check = -1;
static gint hf_krb_KDCOptions_renewable_ok = -1;
static gint hf_krb_KDCOptions_enc_tkt_in_skey = -1;
static gint hf_krb_KDCOptions_renew = -1;
static gint hf_krb_KDCOptions_validate = -1;
static gint hf_krb_KDC_REQ_BODY = -1;
static gint hf_krb_PRIV_BODY = -1;
static gint hf_krb_ENC_PRIV = -1;
static gint hf_krb_authenticator_enc = -1;
static gint hf_krb_ticket_enc = -1;
static gint hf_krb_e_checksum = -1;

static gint ett_krb_kerberos = -1;
static gint ett_krb_TransitedEncoding = -1;
static gint ett_krb_PAC_LOGON_INFO = -1;
static gint ett_krb_PAC_CREDENTIAL_TYPE = -1;
static gint ett_krb_PAC_SERVER_CHECKSUM = -1;
static gint ett_krb_PAC_PRIVSVR_CHECKSUM = -1;
static gint ett_krb_PAC_CLIENT_INFO_TYPE = -1;
static gint ett_krb_KDC_REP_enc = -1;
static gint ett_krb_EncTicketPart = -1;
static gint ett_krb_EncAPRepPart = -1;
static gint ett_krb_EncKrbPrivPart = -1;
static gint ett_krb_EncKDCRepPart = -1;
static gint ett_krb_LastReq = -1;
static gint ett_krb_Authenticator = -1;
static gint ett_krb_Checksum = -1;
static gint ett_krb_key = -1;
static gint ett_krb_subkey = -1;
static gint ett_krb_AuthorizationData = -1;
static gint ett_krb_sname = -1;
static gint ett_krb_cname = -1;
static gint ett_krb_AP_REP_enc = -1;
static gint ett_krb_padata = -1;
static gint ett_krb_etypes = -1;
static gint ett_krb_LastReqs = -1;
static gint ett_krb_IF_RELEVANT = -1;
static gint ett_krb_PA_DATA_tree = -1;
static gint ett_krb_PAC = -1;
static gint ett_krb_s_address = -1;
static gint ett_krb_HostAddress = -1;
static gint ett_krb_HostAddresses = -1;
static gint ett_krb_authenticator_enc = -1;
static gint ett_krb_AP_Options = -1;
static gint ett_krb_KDC_Options = -1;
static gint ett_krb_Ticket_Flags = -1;
static gint ett_krb_request = -1;
static gint ett_krb_recordmark = -1;
static gint ett_krb_ticket = -1;
static gint ett_krb_ticket_enc = -1;
static gint ett_krb_PRIV = -1;
static gint ett_krb_PRIV_enc = -1;
static gint ett_krb_e_checksum = -1;

guint32 krb5_errorcode;


dissector_handle_t krb4_handle=NULL;

static gboolean do_col_info;


static void
call_kerberos_callbacks(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int tag)
{
	kerberos_callbacks *cb=(kerberos_callbacks *)pinfo->private_data;

	if(!cb){
		return;
	}

	while(cb->tag){
		if(cb->tag==tag){
			cb->callback(pinfo, tvb, tree);
			return;
		}
		cb++;
	}
	return;
}



#ifdef HAVE_KERBEROS

/* Decrypt Kerberos blobs */
static gboolean krb_decrypt = FALSE;

/* keytab filename */
static const char *keytab_filename = "insert filename here";

#endif

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
#include <krb5.h>
enc_key_t *enc_key_list=NULL;

static void
add_encryption_key(packet_info *pinfo, int keytype, int keylength, const char *keyvalue, const char *origin)
{
	enc_key_t *new_key;

	if(pinfo->fd->flags.visited){
		return;
	}
printf("added key in %d\n",pinfo->fd->num);

	new_key=g_malloc(sizeof(enc_key_t));
	g_snprintf(new_key->key_origin, KRB_MAX_ORIG_LEN, "%s learnt from frame %d",origin,pinfo->fd->num);
	new_key->next=enc_key_list;
	enc_key_list=new_key;
	new_key->keytype=keytype;
	new_key->keylength=keylength;
	/*XXX this needs to be freed later */
	new_key->keyvalue=g_memdup(keyvalue, keylength);
}
#endif /* HAVE_HEIMDAL_KERBEROS || HAVE_MIT_KERBEROS */


#ifdef HAVE_MIT_KERBEROS

static void
read_keytab_file(const char *filename, krb5_context *context)
{
	krb5_keytab keytab;
	krb5_keytab_entry key;
	krb5_error_code ret;
	krb5_kt_cursor cursor;
	enc_key_t *new_key;

	/* should use a file in the ethereal users dir */
	ret = krb5_kt_resolve(*context, filename, &keytab);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not open keytab file :%s\n",filename);

		return;
	}

	ret = krb5_kt_start_seq_get(*context, keytab, &cursor);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not read from keytab file :%s\n",filename);
		return;
	}

	do{
		new_key=g_malloc(sizeof(enc_key_t));
		new_key->next=enc_key_list;
		ret = krb5_kt_next_entry(*context, keytab, &key, &cursor);
		if(ret==0){
			int i;
			char *pos;

			/* generate origin string, describing where this key came from */
			pos=new_key->key_origin;
			pos+=g_snprintf(pos, KRB_MAX_ORIG_LEN, "keytab principal ");
			for(i=0;i<key.principal->length;i++){
				pos+=g_snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "%s%s",(i?"/":""),(key.principal->data[i]).data);
			}
			pos+=g_snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "@%s",key.principal->realm.data);
			*pos=0;
/*printf("added key for principal :%s\n", new_key->key_origin);*/
			new_key->keytype=key.key.enctype;
			new_key->keylength=key.key.length;
			new_key->keyvalue=g_memdup(key.key.contents, key.key.length);
			enc_key_list=new_key;
		}
	}while(ret==0);

	ret = krb5_kt_end_seq_get(*context, keytab, &cursor);
	if(ret){
		krb5_kt_close(*context, keytab);
	}

}


guint8 *
decrypt_krb5_data(proto_tree *tree, packet_info *pinfo,
			int usage,
			int length,
			const guint8 *cryptotext,
			int keytype)
{
	static int first_time=1;
	static krb5_context context;
	krb5_error_code ret;
	enc_key_t *ek;
	static krb5_data data = {0,0,NULL};
	krb5_keytab_entry key;

	/* dont do anything if we are not attempting to decrypt data */
	if(!krb_decrypt){
		return NULL;
	}

	/* XXX we should only do this for first time, then store somewhere */
	/* XXX We also need to re-read the keytab when the preference changes */

	/* should this have a destroy context ?  MIT people would know */
	if(first_time){
		first_time=0;
		ret = krb5_init_context(&context);
		if(ret){
			return NULL;
		}
		read_keytab_file(keytab_filename, &context);
	}

	for(ek=enc_key_list;ek;ek=ek->next){
		krb5_enc_data input;

		/* shortcircuit and bail out if enctypes are not matching */
		if(ek->keytype!=keytype){
			continue;
		}

		input.enctype = ek->keytype;
		input.ciphertext.length = length;
		input.ciphertext.data = (guint8 *)cryptotext;

		data.length = length;
		if(data.data){
			g_free(data.data);
		}
		data.data = g_malloc(length);

		key.key.enctype=ek->keytype;
		key.key.length=ek->keylength;
		key.key.contents=ek->keyvalue;
		ret = krb5_c_decrypt(context, &(key.key), usage, 0, &input, &data);
		if (ret == 0) {
printf("woohoo decrypted keytype:%d in frame:%d\n", keytype, pinfo->fd->num);
			proto_tree_add_text(tree, NULL, 0, 0, "[Decrypted using: %s]", ek->key_origin);
			return data.data;
		}
	}

	return NULL;
}

#elif defined(HAVE_HEIMDAL_KERBEROS)
static void
read_keytab_file(const char *filename, krb5_context *context)
{
	krb5_keytab keytab;
	krb5_keytab_entry key;
	krb5_error_code ret;
	krb5_kt_cursor cursor;
	enc_key_t *new_key;

	/* should use a file in the ethereal users dir */
	ret = krb5_kt_resolve(*context, filename, &keytab);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not open keytab file :%s\n",filename);

		return;
	}

	ret = krb5_kt_start_seq_get(*context, keytab, &cursor);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not read from keytab file :%s\n",filename);
		return;
	}

	do{
		new_key=g_malloc(sizeof(enc_key_t));
		new_key->next=enc_key_list;
		ret = krb5_kt_next_entry(*context, keytab, &key, &cursor);
		if(ret==0){
			unsigned int i;
			char *pos;

			/* generate origin string, describing where this key came from */
			pos=new_key->key_origin;
			pos+=g_snprintf(pos, KRB_MAX_ORIG_LEN, "keytab principal ");
			for(i=0;i<key.principal->name.name_string.len;i++){
				pos+=g_snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "%s%s",(i?"/":""),key.principal->name.name_string.val[i]);
			}
			pos+=g_snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "@%s",key.principal->realm);
			*pos=0;
			new_key->keytype=key.keyblock.keytype;
			new_key->keylength=key.keyblock.keyvalue.length;
			new_key->keyvalue=g_memdup(key.keyblock.keyvalue.data, key.keyblock.keyvalue.length);
			enc_key_list=new_key;
		}
	}while(ret==0);

	ret = krb5_kt_end_seq_get(*context, keytab, &cursor);
	if(ret){
		krb5_kt_close(*context, keytab);
	}

}


guint8 *
decrypt_krb5_data(proto_tree *tree, packet_info *pinfo,
			int usage,
			int length,
			const guint8 *cryptotext,
			int keytype)
{
	static int first_time=1;
	static krb5_context context;
	krb5_error_code ret;
	krb5_data data;
	enc_key_t *ek;

	/* dont do anything if we are not attempting to decrypt data */
	if(!krb_decrypt){
		return NULL;
	}

	/* XXX we should only do this for first time, then store somewhere */
	/* XXX We also need to re-read the keytab when the preference changes */

	/* should this have a destroy context ?  Heimdal people would know */
	if(first_time){
		first_time=0;
		ret = krb5_init_context(&context);
		if(ret){
			return NULL;
		}
		read_keytab_file(keytab_filename, &context);
	}

	for(ek=enc_key_list;ek;ek=ek->next){
		krb5_keytab_entry key;
		krb5_crypto crypto;
		guint8 *cryptocopy; /* workaround for pre-0.6.1 heimdal bug */

		/* shortcircuit and bail out if enctypes are not matching */
		if(ek->keytype!=keytype){
			continue;
		}

		key.keyblock.keytype=ek->keytype;
		key.keyblock.keyvalue.length=ek->keylength;
		key.keyblock.keyvalue.data=ek->keyvalue;
		ret = krb5_crypto_init(context, &(key.keyblock), 0, &crypto);
		if(ret){
			return NULL;
		}

		/* pre-0.6.1 versions of Heimdal would sometimes change
		  the cryptotext data even when the decryption failed.
		  This would obviously not work since we iterate over the
		  keys. So just give it a copy of the crypto data instead.
		  This has been seen for RC4-HMAC blobs.
		*/
		cryptocopy=g_malloc(length);
		memcpy(cryptocopy, cryptotext, length);
		ret = krb5_decrypt_ivec(context, crypto, usage,
				cryptocopy, length,
				&data,
				NULL);
		g_free(cryptocopy);
		if (ret == 0) {
printf("woohoo decrypted keytype:%d in frame:%d\n", keytype, pinfo->fd->num);
			proto_tree_add_text(tree, NULL, 0, 0, "[Decrypted using: %s]", ek->key_origin);
			krb5_crypto_destroy(context, crypto);
			return data.data;
		}
		krb5_crypto_destroy(context, crypto);
	}
	return NULL;
}

#elif defined (HAVE_LIBNETTLE)

#define SERVICE_KEY_SIZE (DES3_KEY_SIZE + 2)
#define KEYTYPE_DES3_CBC_MD5 5	/* Currently the only one supported */

typedef struct _service_key_t {
    guint16 kvno;
    int     keytype;
    int     length;
    guint8 *contents;
    char    origin[KRB_MAX_ORIG_LEN+1];
} service_key_t;
GSList *service_key_list = NULL;


static void
add_encryption_key(packet_info *pinfo, int keytype, int keylength, const char *keyvalue, const char *origin)
{
	service_key_t *new_key;

	if(pinfo->fd->flags.visited){
		return;
	}
printf("added key in %d\n",pinfo->fd->num);

	new_key = g_malloc(sizeof(service_key_t));
	new_key->kvno = 0;
	new_key->keytype = keytype;
	new_key->length = keylength;
	new_key->contents = g_malloc(keylength);
	memcpy(new_key->contents, keyvalue, keylength);
	g_snprintf(new_key->origin, KRB_MAX_ORIG_LEN, "%s learnt from frame %d", origin, pinfo->fd->num);
	service_key_list = g_slist_append(service_key_list, (gpointer) new_key);
}

static void
clear_keytab(void) {
	GSList *ske;
	service_key_t *sk;

	for(ske = service_key_list; ske != NULL; ske = g_slist_next(ske)){
		sk = (service_key_t *) ske->data;
		if (sk && sk->contents) g_free(sk->contents);
		if (sk) g_free(sk);
	}
	g_slist_free(service_key_list);
	service_key_list = NULL;
}

static void
read_keytab_file(const char *service_key_file)
{
	FILE *skf;
	struct stat st;
	service_key_t *sk;
	unsigned char buf[SERVICE_KEY_SIZE];
	int newline_skip = 0, count = 0;

	if (service_key_file != NULL && stat (service_key_file, &st) == 0) {

		/* The service key file contains raw 192-bit (24 byte) 3DES keys.
		 * There can be zero, one (\n), or two (\r\n) characters between
		 * keys.  Trailing characters are ignored.
		 */

		/* XXX We should support the standard keytab format instead */
		if (st.st_size > SERVICE_KEY_SIZE) {
			if ( (st.st_size % (SERVICE_KEY_SIZE + 1) == 0) ||
			     (st.st_size % (SERVICE_KEY_SIZE + 1) == SERVICE_KEY_SIZE) ) {
			    newline_skip = 1;
			} else if ( (st.st_size % (SERVICE_KEY_SIZE + 2) == 0) ||
			     (st.st_size % (SERVICE_KEY_SIZE + 2) == SERVICE_KEY_SIZE) ) {
			    newline_skip = 2;
			}
		}

		skf = eth_fopen(service_key_file, "rb");
		if (! skf) return;

		while (fread(buf, SERVICE_KEY_SIZE, 1, skf) == 1) {
			sk = g_malloc(sizeof(service_key_t));
			sk->kvno = buf[0] << 8 | buf[1];
			sk->keytype = KEYTYPE_DES3_CBC_MD5;
			sk->length = DES3_KEY_SIZE;
			sk->contents = g_malloc(DES3_KEY_SIZE);
			memcpy(sk->contents, buf + 2, DES3_KEY_SIZE);
			g_snprintf(sk->origin, KRB_MAX_ORIG_LEN, "3DES service key file, key #%d, offset %ld", count, ftell(skf));
			service_key_list = g_slist_append(service_key_list, (gpointer) sk);
			fseek(skf, newline_skip, SEEK_CUR);
			count++;
g_warning("added key: %s", sk->origin);
		}
		fclose(skf);
	}
}

#define CONFOUNDER_PLUS_CHECKSUM 24

guint8 *
decrypt_krb5_data(proto_tree *tree, packet_info *pinfo,
			int _U_ usage,
			int length,
			const guint8 *cryptotext,
			int keytype)
{
	tvbuff_t *encr_tvb;
	guint8 *decrypted_data = NULL, *plaintext = NULL;
	int res;
	guint8 cls;
	gboolean pc;
	guint32 tag, item_len, data_len;
	int id_offset, offset;
	guint8 key[DES3_KEY_SIZE];
	guint8 initial_vector[DES_BLOCK_SIZE];
	md5_state_t md5s;
	md5_byte_t digest[16];
	md5_byte_t zero_fill[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	md5_byte_t confounder[8];
	gboolean ind;
	GSList *ske;
	service_key_t *sk;
	struct des3_ctx ctx;


	/* dont do anything if we are not attempting to decrypt data */
	if(!krb_decrypt){
		return NULL;
	}

	if (keytype != KEYTYPE_DES3_CBC_MD5 || service_key_list == NULL) {
		return NULL;
	}

	decrypted_data = g_malloc(length);
	for(ske = service_key_list; ske != NULL; ske = g_slist_next(ske)){
		sk = (service_key_t *) ske->data;

		des_fix_parity(DES3_KEY_SIZE, key, sk->contents);

		md5_init(&md5s);
		memset(initial_vector, 0, DES_BLOCK_SIZE);
		res = des3_set_key(&ctx, key);
		cbc_decrypt(&ctx, des3_decrypt, DES_BLOCK_SIZE, initial_vector,
		    length, decrypted_data, cryptotext);
		encr_tvb = tvb_new_real_data(decrypted_data, length, length);

		tvb_memcpy(encr_tvb, confounder, 0, 8);

		/* We have to pull the decrypted data length from the decrypted
		 * content.  If the key doesn't match or we otherwise get garbage,
		 * an exception may get thrown while decoding the ASN.1 header.
		 * Catch it, just in case.
		 */
		TRY {
			id_offset = get_ber_identifier(encr_tvb, CONFOUNDER_PLUS_CHECKSUM, &cls, &pc, &tag);
			offset = get_ber_length(tree, encr_tvb, id_offset, &item_len, &ind);
		}
		CATCH (BoundsError) {
			tvb_free(encr_tvb);
			continue;
		}
		ENDTRY;

		data_len = item_len + offset - CONFOUNDER_PLUS_CHECKSUM;
		if ((int) item_len + offset > length) {
			tvb_free(encr_tvb);
			continue;
		}

		md5_append(&md5s, confounder, 8);
		md5_append(&md5s, zero_fill, 16);
		md5_append(&md5s, decrypted_data + CONFOUNDER_PLUS_CHECKSUM, data_len);
		md5_finish(&md5s, digest);

		if (tvb_memeql (encr_tvb, 8, digest, 16) == 0) {
g_warning("woohoo decrypted keytype:%d in frame:%d\n", keytype, pinfo->fd->num);
			plaintext = g_malloc(data_len);
			tvb_memcpy(encr_tvb, plaintext, CONFOUNDER_PLUS_CHECKSUM, data_len);
			tvb_free(encr_tvb);

			g_free(decrypted_data);
			return(plaintext);
		}
	}

	g_free(decrypted_data);
	return NULL;
}


#endif	/* HAVE_MIT_KERBEROS / HAVE_HEIMDAL_KERBEROS / HAVE_LIBNETTLE */



/* TCP Record Mark */
#define	KRB_RM_RESERVED	0x80000000L
#define	KRB_RM_RECLEN	0x7fffffffL

#define KRB5_MSG_TICKET			1	/* Ticket */
#define KRB5_MSG_AUTHENTICATOR		2	/* Authenticator */
#define KRB5_MSG_ENC_TICKET_PART	3	/* EncTicketPart */
#define KRB5_MSG_AS_REQ   		10	/* AS-REQ type */
#define KRB5_MSG_AS_REP   		11	/* AS-REP type */
#define KRB5_MSG_TGS_REQ  		12	/* TGS-REQ type */
#define KRB5_MSG_TGS_REP  		13	/* TGS-REP type */
#define KRB5_MSG_AP_REQ   		14	/* AP-REQ type */
#define KRB5_MSG_AP_REP   		15	/* AP-REP type */

#define KRB5_MSG_SAFE     		20	/* KRB-SAFE type */
#define KRB5_MSG_PRIV     		21	/* KRB-PRIV type */
#define KRB5_MSG_CRED     		22	/* KRB-CRED type */
#define KRB5_MSG_ENC_AS_REP_PART	25	/* EncASRepPart */
#define KRB5_MSG_ENC_TGS_REP_PART	26	/* EncTGSRepPart */
#define KRB5_MSG_ENC_AP_REP_PART     	27	/* EncAPRepPart */
#define KRB5_MSG_ENC_KRB_PRIV_PART     	28	/* EncAPRepPart */
#define KRB5_MSG_ERROR    		30	/* KRB-ERROR type */

/* address type constants */
#define KRB5_ADDR_IPv4       0x02
#define KRB5_ADDR_CHAOS      0x05
#define KRB5_ADDR_XEROX      0x06
#define KRB5_ADDR_ISO        0x07
#define KRB5_ADDR_DECNET     0x0c
#define KRB5_ADDR_APPLETALK  0x10
#define KRB5_ADDR_NETBIOS    0x14
#define KRB5_ADDR_IPv6       0x18

/* encryption type constants */
#define KRB5_ENCTYPE_NULL                0
#define KRB5_ENCTYPE_DES_CBC_CRC         1
#define KRB5_ENCTYPE_DES_CBC_MD4         2
#define KRB5_ENCTYPE_DES_CBC_MD5         3
#define KRB5_ENCTYPE_DES_CBC_RAW         4
#define KRB5_ENCTYPE_DES3_CBC_SHA        5
#define KRB5_ENCTYPE_DES3_CBC_RAW        6
#define KRB5_ENCTYPE_DES_HMAC_SHA1       8
#define KRB5_ENCTYPE_DSA_SHA1_CMS        9
#define KRB5_ENCTYPE_RSA_MD5_CMS         10
#define KRB5_ENCTYPE_RSA_SHA1_CMS        11
#define KRB5_ENCTYPE_RC2_CBC_ENV         12
#define KRB5_ENCTYPE_RSA_ENV             13
#define KRB5_ENCTYPE_RSA_ES_OEAP_ENV     14
#define KRB5_ENCTYPE_DES_EDE3_CBC_ENV    15
#define KRB5_ENCTYPE_DES3_CBC_SHA1       16
#define KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96 17
#define KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96 18
#define KRB5_ENCTYPE_DES_CBC_MD5_NT      20
#define KERB_ENCTYPE_RC4_HMAC            23
#define KERB_ENCTYPE_RC4_HMAC_EXP        24
#define KRB5_ENCTYPE_UNKNOWN                0x1ff
#define KRB5_ENCTYPE_LOCAL_DES3_HMAC_SHA1   0x7007
#define KRB5_ENCTYPE_RC4_PLAIN_EXP	0xffffff73
#define KRB5_ENCTYPE_RC4_PLAIN		0xffffff74
#define KRB5_ENCTYPE_RC4_PLAIN_OLD_EXP	0xffffff78
#define KRB5_ENCTYPE_RC4_HMAC_OLD_EXP	0xffffff79
#define KRB5_ENCTYPE_RC4_PLAIN_OLD	0xffffff7a
#define KRB5_ENCTYPE_RC4_HMAC_OLD	0xffffff7b
#define KRB5_ENCTYPE_DES_PLAIN		0xffffff7c
#define KRB5_ENCTYPE_RC4_SHA		0xffffff7d
#define KRB5_ENCTYPE_RC4_LM		0xffffff7e
#define KRB5_ENCTYPE_RC4_PLAIN2		0xffffff7f
#define KRB5_ENCTYPE_RC4_MD4		0xffffff80

/* checksum types */
#define KRB5_CHKSUM_NONE                0
#define KRB5_CHKSUM_CRC32               1
#define KRB5_CHKSUM_MD4                 2
#define KRB5_CHKSUM_KRB_DES_MAC         4
#define KRB5_CHKSUM_KRB_DES_MAC_K       5
#define KRB5_CHKSUM_MD5                 7
#define KRB5_CHKSUM_MD5_DES             8
/* the following four comes from packetcable */
#define KRB5_CHKSUM_MD5_DES3            9
#define KRB5_CHKSUM_HMAC_SHA1_DES3_KD   12
#define KRB5_CHKSUM_HMAC_SHA1_DES3      13
#define KRB5_CHKSUM_SHA1_UNKEYED        14
#define KRB5_CHKSUM_HMAC_MD5            0xffffff76
#define KRB5_CHKSUM_MD5_HMAC            0xffffff77
#define KRB5_CHKSUM_RC4_MD5             0xffffff78
#define KRB5_CHKSUM_MD25                0xffffff79
#define KRB5_CHKSUM_DES_MAC_MD5         0xffffff7a
#define KRB5_CHKSUM_DES_MAC             0xffffff7b
#define KRB5_CHKSUM_REAL_CRC32          0xffffff7c
#define KRB5_CHKSUM_SHA1                0xffffff7d
#define KRB5_CHKSUM_LM                  0xffffff7e
#define KRB5_CHKSUM_GSSAPI		0x8003

/*
 * For KERB_ENCTYPE_RC4_HMAC and KERB_ENCTYPE_RC4_HMAC_EXP, see
 *
 *	http://www.ietf.org/internet-drafts/draft-brezak-win2k-krb-rc4-hmac-04.txt
 *
 * unless it's expired.
 */

/* pre-authentication type constants */
#define KRB5_PA_TGS_REQ                1
#define KRB5_PA_ENC_TIMESTAMP          2
#define KRB5_PA_PW_SALT                3
#define KRB5_PA_ENC_ENCKEY             4
#define KRB5_PA_ENC_UNIX_TIME          5
#define KRB5_PA_ENC_SANDIA_SECURID     6
#define KRB5_PA_SESAME                 7
#define KRB5_PA_OSF_DCE                8
#define KRB5_PA_CYBERSAFE_SECUREID     9
#define KRB5_PA_AFS3_SALT              10
#define KRB5_PA_ENCTYPE_INFO           11
#define KRB5_PA_SAM_CHALLENGE          12
#define KRB5_PA_SAM_RESPONSE           13
#define KRB5_PA_PK_AS_REQ              14
#define KRB5_PA_PK_AS_REP              15
#define KRB5_PA_DASS                   16
#define KRB5_PA_ENCTYPE_INFO2          19
#define KRB5_PA_USE_SPECIFIED_KVNO     20
#define KRB5_PA_SAM_REDIRECT           21
#define KRB5_PA_GET_FROM_TYPED_DATA    22
#define KRB5_PA_SAM_ETYPE_INFO         23
#define KRB5_PA_ALT_PRINC              24
#define KRB5_PA_SAM_CHALLENGE2         30
#define KRB5_PA_SAM_RESPONSE2          31
#define KRB5_TD_PKINIT_CMS_CERTIFICATES 101
#define KRB5_TD_KRB_PRINCIPAL          102
#define KRB5_TD_KRB_REALM              103
#define KRB5_TD_TRUSTED_CERTIFIERS     104
#define KRB5_TD_CERTIFICATE_INDEX      105
#define KRB5_TD_APP_DEFINED_ERROR      106
#define KRB5_TD_REQ_NONCE              107
#define KRB5_TD_REQ_SEQ                108
/* preauthentication types >127 (i.e. negative ones) are app specific.
   hopefully there will be no collissions here or we will have to
   come up with something better
*/
#define KRB5_PA_PAC_REQUEST            128	/* MS extension */
#define KRB5_PA_PROV_SRV_LOCATION      255	/* packetcable stuff */

/* Principal name-type */
#define KRB5_NT_UNKNOWN        0
#define KRB5_NT_PRINCIPAL      1
#define KRB5_NT_SRV_INST       2
#define KRB5_NT_SRV_HST        3
#define KRB5_NT_SRV_XHST       4
#define KRB5_NT_UID            5
#define KRB5_NT_X500_PRINCIPAL 6
#define KRB5_NT_SMTP_NAME      7
#define KRB5_NT_ENTERPRISE    10

/*
 * MS specific name types, from
 *
 *	http://msdn.microsoft.com/library/en-us/security/security/kerb_external_name.asp
 */
#define KRB5_NT_MS_PRINCIPAL		-128
#define KRB5_NT_MS_PRINCIPAL_AND_SID	-129
#define KRB5_NT_ENT_PRINCIPAL_AND_SID	-130
#define KRB5_NT_PRINCIPAL_AND_SID 	-131
#define KRB5_NT_SRV_INST_AND_SID	-132

/* error table constants */
/* I prefixed the krb5_err.et constant names with KRB5_ET_ for these */
#define KRB5_ET_KRB5KDC_ERR_NONE                         0
#define KRB5_ET_KRB5KDC_ERR_NAME_EXP                     1
#define KRB5_ET_KRB5KDC_ERR_SERVICE_EXP                  2
#define KRB5_ET_KRB5KDC_ERR_BAD_PVNO                     3
#define KRB5_ET_KRB5KDC_ERR_C_OLD_MAST_KVNO              4
#define KRB5_ET_KRB5KDC_ERR_S_OLD_MAST_KVNO              5
#define KRB5_ET_KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN          6
#define KRB5_ET_KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN          7
#define KRB5_ET_KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE         8
#define KRB5_ET_KRB5KDC_ERR_NULL_KEY                     9
#define KRB5_ET_KRB5KDC_ERR_CANNOT_POSTDATE              10
#define KRB5_ET_KRB5KDC_ERR_NEVER_VALID                  11
#define KRB5_ET_KRB5KDC_ERR_POLICY                       12
#define KRB5_ET_KRB5KDC_ERR_BADOPTION                    13
#define KRB5_ET_KRB5KDC_ERR_ETYPE_NOSUPP                 14
#define KRB5_ET_KRB5KDC_ERR_SUMTYPE_NOSUPP               15
#define KRB5_ET_KRB5KDC_ERR_PADATA_TYPE_NOSUPP           16
#define KRB5_ET_KRB5KDC_ERR_TRTYPE_NOSUPP                17
#define KRB5_ET_KRB5KDC_ERR_CLIENT_REVOKED               18
#define KRB5_ET_KRB5KDC_ERR_SERVICE_REVOKED              19
#define KRB5_ET_KRB5KDC_ERR_TGT_REVOKED                  20
#define KRB5_ET_KRB5KDC_ERR_CLIENT_NOTYET                21
#define KRB5_ET_KRB5KDC_ERR_SERVICE_NOTYET               22
#define KRB5_ET_KRB5KDC_ERR_KEY_EXP                      23
#define KRB5_ET_KRB5KDC_ERR_PREAUTH_FAILED               24
#define KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED             25
#define KRB5_ET_KRB5KDC_ERR_SERVER_NOMATCH               26
#define KRB5_ET_KRB5KDC_ERR_MUST_USE_USER2USER           27
#define KRB5_ET_KRB5KDC_ERR_PATH_NOT_ACCEPTED            28
#define KRB5_ET_KRB5KDC_ERR_SVC_UNAVAILABLE              29
#define KRB5_ET_KRB5KRB_AP_ERR_BAD_INTEGRITY             31
#define KRB5_ET_KRB5KRB_AP_ERR_TKT_EXPIRED               32
#define KRB5_ET_KRB5KRB_AP_ERR_TKT_NYV                   33
#define KRB5_ET_KRB5KRB_AP_ERR_REPEAT                    34
#define KRB5_ET_KRB5KRB_AP_ERR_NOT_US                    35
#define KRB5_ET_KRB5KRB_AP_ERR_BADMATCH                  36
#define KRB5_ET_KRB5KRB_AP_ERR_SKEW                      37
#define KRB5_ET_KRB5KRB_AP_ERR_BADADDR                   38
#define KRB5_ET_KRB5KRB_AP_ERR_BADVERSION                39
#define KRB5_ET_KRB5KRB_AP_ERR_MSG_TYPE                  40
#define KRB5_ET_KRB5KRB_AP_ERR_MODIFIED                  41
#define KRB5_ET_KRB5KRB_AP_ERR_BADORDER                  42
#define KRB5_ET_KRB5KRB_AP_ERR_ILL_CR_TKT                43
#define KRB5_ET_KRB5KRB_AP_ERR_BADKEYVER                 44
#define KRB5_ET_KRB5KRB_AP_ERR_NOKEY                     45
#define KRB5_ET_KRB5KRB_AP_ERR_MUT_FAIL                  46
#define KRB5_ET_KRB5KRB_AP_ERR_BADDIRECTION              47
#define KRB5_ET_KRB5KRB_AP_ERR_METHOD                    48
#define KRB5_ET_KRB5KRB_AP_ERR_BADSEQ                    49
#define KRB5_ET_KRB5KRB_AP_ERR_INAPP_CKSUM               50
#define KRB5_ET_KRB5KDC_AP_PATH_NOT_ACCEPTED             51
#define KRB5_ET_KRB5KRB_ERR_RESPONSE_TOO_BIG             52
#define KRB5_ET_KRB5KRB_ERR_GENERIC                      60
#define KRB5_ET_KRB5KRB_ERR_FIELD_TOOLONG                61
#define KRB5_ET_KDC_ERROR_CLIENT_NOT_TRUSTED             62
#define KRB5_ET_KDC_ERROR_KDC_NOT_TRUSTED                63
#define KRB5_ET_KDC_ERROR_INVALID_SIG                    64
#define KRB5_ET_KDC_ERR_KEY_TOO_WEAK                     65
#define KRB5_ET_KDC_ERR_CERTIFICATE_MISMATCH             66
#define KRB5_ET_KRB_AP_ERR_NO_TGT                        67
#define KRB5_ET_KDC_ERR_WRONG_REALM                      68
#define KRB5_ET_KRB_AP_ERR_USER_TO_USER_REQUIRED         69
#define KRB5_ET_KDC_ERR_CANT_VERIFY_CERTIFICATE          70
#define KRB5_ET_KDC_ERR_INVALID_CERTIFICATE              71
#define KRB5_ET_KDC_ERR_REVOKED_CERTIFICATE              72
#define KRB5_ET_KDC_ERR_REVOCATION_STATUS_UNKNOWN        73
#define KRB5_ET_KDC_ERR_REVOCATION_STATUS_UNAVAILABLE    74
#define KRB5_ET_KDC_ERR_CLIENT_NAME_MISMATCH             75
#define KRB5_ET_KDC_ERR_KDC_NAME_MISMATCH                76

static const value_string krb5_error_codes[] = {
	{ KRB5_ET_KRB5KDC_ERR_NONE, "KRB5KDC_ERR_NONE" },
	{ KRB5_ET_KRB5KDC_ERR_NAME_EXP, "KRB5KDC_ERR_NAME_EXP" },
	{ KRB5_ET_KRB5KDC_ERR_SERVICE_EXP, "KRB5KDC_ERR_SERVICE_EXP" },
	{ KRB5_ET_KRB5KDC_ERR_BAD_PVNO, "KRB5KDC_ERR_BAD_PVNO" },
	{ KRB5_ET_KRB5KDC_ERR_C_OLD_MAST_KVNO, "KRB5KDC_ERR_C_OLD_MAST_KVNO" },
	{ KRB5_ET_KRB5KDC_ERR_S_OLD_MAST_KVNO, "KRB5KDC_ERR_S_OLD_MAST_KVNO" },
	{ KRB5_ET_KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN, "KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN" },
	{ KRB5_ET_KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN, "KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN" },
	{ KRB5_ET_KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE, "KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE" },
	{ KRB5_ET_KRB5KDC_ERR_NULL_KEY, "KRB5KDC_ERR_NULL_KEY" },
	{ KRB5_ET_KRB5KDC_ERR_CANNOT_POSTDATE, "KRB5KDC_ERR_CANNOT_POSTDATE" },
	{ KRB5_ET_KRB5KDC_ERR_NEVER_VALID, "KRB5KDC_ERR_NEVER_VALID" },
	{ KRB5_ET_KRB5KDC_ERR_POLICY, "KRB5KDC_ERR_POLICY" },
	{ KRB5_ET_KRB5KDC_ERR_BADOPTION, "KRB5KDC_ERR_BADOPTION" },
	{ KRB5_ET_KRB5KDC_ERR_ETYPE_NOSUPP, "KRB5KDC_ERR_ETYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_SUMTYPE_NOSUPP, "KRB5KDC_ERR_SUMTYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_PADATA_TYPE_NOSUPP, "KRB5KDC_ERR_PADATA_TYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_TRTYPE_NOSUPP, "KRB5KDC_ERR_TRTYPE_NOSUPP" },
	{ KRB5_ET_KRB5KDC_ERR_CLIENT_REVOKED, "KRB5KDC_ERR_CLIENT_REVOKED" },
	{ KRB5_ET_KRB5KDC_ERR_SERVICE_REVOKED, "KRB5KDC_ERR_SERVICE_REVOKED" },
	{ KRB5_ET_KRB5KDC_ERR_TGT_REVOKED, "KRB5KDC_ERR_TGT_REVOKED" },
	{ KRB5_ET_KRB5KDC_ERR_CLIENT_NOTYET, "KRB5KDC_ERR_CLIENT_NOTYET" },
	{ KRB5_ET_KRB5KDC_ERR_SERVICE_NOTYET, "KRB5KDC_ERR_SERVICE_NOTYET" },
	{ KRB5_ET_KRB5KDC_ERR_KEY_EXP, "KRB5KDC_ERR_KEY_EXP" },
	{ KRB5_ET_KRB5KDC_ERR_PREAUTH_FAILED, "KRB5KDC_ERR_PREAUTH_FAILED" },
	{ KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED, "KRB5KDC_ERR_PREAUTH_REQUIRED" },
	{ KRB5_ET_KRB5KDC_ERR_SERVER_NOMATCH, "KRB5KDC_ERR_SERVER_NOMATCH" },
	{ KRB5_ET_KRB5KDC_ERR_MUST_USE_USER2USER, "KRB5KDC_ERR_MUST_USE_USER2USER" },
	{ KRB5_ET_KRB5KDC_ERR_PATH_NOT_ACCEPTED, "KRB5KDC_ERR_PATH_NOT_ACCEPTED" },
	{ KRB5_ET_KRB5KDC_ERR_SVC_UNAVAILABLE, "KRB5KDC_ERR_SVC_UNAVAILABLE" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BAD_INTEGRITY, "KRB5KRB_AP_ERR_BAD_INTEGRITY" },
	{ KRB5_ET_KRB5KRB_AP_ERR_TKT_EXPIRED, "KRB5KRB_AP_ERR_TKT_EXPIRED" },
	{ KRB5_ET_KRB5KRB_AP_ERR_TKT_NYV, "KRB5KRB_AP_ERR_TKT_NYV" },
	{ KRB5_ET_KRB5KRB_AP_ERR_REPEAT, "KRB5KRB_AP_ERR_REPEAT" },
	{ KRB5_ET_KRB5KRB_AP_ERR_NOT_US, "KRB5KRB_AP_ERR_NOT_US" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADMATCH, "KRB5KRB_AP_ERR_BADMATCH" },
	{ KRB5_ET_KRB5KRB_AP_ERR_SKEW, "KRB5KRB_AP_ERR_SKEW" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADADDR, "KRB5KRB_AP_ERR_BADADDR" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADVERSION, "KRB5KRB_AP_ERR_BADVERSION" },
	{ KRB5_ET_KRB5KRB_AP_ERR_MSG_TYPE, "KRB5KRB_AP_ERR_MSG_TYPE" },
	{ KRB5_ET_KRB5KRB_AP_ERR_MODIFIED, "KRB5KRB_AP_ERR_MODIFIED" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADORDER, "KRB5KRB_AP_ERR_BADORDER" },
	{ KRB5_ET_KRB5KRB_AP_ERR_ILL_CR_TKT, "KRB5KRB_AP_ERR_ILL_CR_TKT" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADKEYVER, "KRB5KRB_AP_ERR_BADKEYVER" },
	{ KRB5_ET_KRB5KRB_AP_ERR_NOKEY, "KRB5KRB_AP_ERR_NOKEY" },
	{ KRB5_ET_KRB5KRB_AP_ERR_MUT_FAIL, "KRB5KRB_AP_ERR_MUT_FAIL" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADDIRECTION, "KRB5KRB_AP_ERR_BADDIRECTION" },
	{ KRB5_ET_KRB5KRB_AP_ERR_METHOD, "KRB5KRB_AP_ERR_METHOD" },
	{ KRB5_ET_KRB5KRB_AP_ERR_BADSEQ, "KRB5KRB_AP_ERR_BADSEQ" },
	{ KRB5_ET_KRB5KRB_AP_ERR_INAPP_CKSUM, "KRB5KRB_AP_ERR_INAPP_CKSUM" },
	{ KRB5_ET_KRB5KDC_AP_PATH_NOT_ACCEPTED, "KRB5KDC_AP_PATH_NOT_ACCEPTED" },
	{ KRB5_ET_KRB5KRB_ERR_RESPONSE_TOO_BIG, "KRB5KRB_ERR_RESPONSE_TOO_BIG"},
	{ KRB5_ET_KRB5KRB_ERR_GENERIC, "KRB5KRB_ERR_GENERIC" },
	{ KRB5_ET_KRB5KRB_ERR_FIELD_TOOLONG, "KRB5KRB_ERR_FIELD_TOOLONG" },
	{ KRB5_ET_KDC_ERROR_CLIENT_NOT_TRUSTED, "KDC_ERROR_CLIENT_NOT_TRUSTED" },
	{ KRB5_ET_KDC_ERROR_KDC_NOT_TRUSTED, "KDC_ERROR_KDC_NOT_TRUSTED" },
	{ KRB5_ET_KDC_ERROR_INVALID_SIG, "KDC_ERROR_INVALID_SIG" },
	{ KRB5_ET_KDC_ERR_KEY_TOO_WEAK, "KDC_ERR_KEY_TOO_WEAK" },
	{ KRB5_ET_KDC_ERR_CERTIFICATE_MISMATCH, "KDC_ERR_CERTIFICATE_MISMATCH" },
	{ KRB5_ET_KRB_AP_ERR_NO_TGT, "KRB_AP_ERR_NO_TGT" },
	{ KRB5_ET_KDC_ERR_WRONG_REALM, "KDC_ERR_WRONG_REALM" },
	{ KRB5_ET_KRB_AP_ERR_USER_TO_USER_REQUIRED, "KRB_AP_ERR_USER_TO_USER_REQUIRED" },
	{ KRB5_ET_KDC_ERR_CANT_VERIFY_CERTIFICATE, "KDC_ERR_CANT_VERIFY_CERTIFICATE" },
	{ KRB5_ET_KDC_ERR_INVALID_CERTIFICATE, "KDC_ERR_INVALID_CERTIFICATE" },
	{ KRB5_ET_KDC_ERR_REVOKED_CERTIFICATE, "KDC_ERR_REVOKED_CERTIFICATE" },
	{ KRB5_ET_KDC_ERR_REVOCATION_STATUS_UNKNOWN, "KDC_ERR_REVOCATION_STATUS_UNKNOWN" },
	{ KRB5_ET_KDC_ERR_REVOCATION_STATUS_UNAVAILABLE, "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE" },
	{ KRB5_ET_KDC_ERR_CLIENT_NAME_MISMATCH, "KDC_ERR_CLIENT_NAME_MISMATCH" },
	{ KRB5_ET_KDC_ERR_KDC_NAME_MISMATCH, "KDC_ERR_KDC_NAME_MISMATCH" },
	{ 0, NULL }
};


#define PAC_LOGON_INFO		1
#define PAC_CREDENTIAL_TYPE	2
#define PAC_SERVER_CHECKSUM	6
#define PAC_PRIVSVR_CHECKSUM	7
#define PAC_CLIENT_INFO_TYPE	10
static const value_string w2k_pac_types[] = {
    { PAC_LOGON_INFO		, "Logon Info" },
    { PAC_CREDENTIAL_TYPE	, "Credential Type" },
    { PAC_SERVER_CHECKSUM	, "Server Checksum" },
    { PAC_PRIVSVR_CHECKSUM	, "Privsvr Checksum" },
    { PAC_CLIENT_INFO_TYPE	, "Client Info Type" },
    { 0, NULL },
};



static const value_string krb5_princ_types[] = {
    { KRB5_NT_UNKNOWN              , "Unknown" },
    { KRB5_NT_PRINCIPAL            , "Principal" },
    { KRB5_NT_SRV_INST             , "Service and Instance" },
    { KRB5_NT_SRV_HST              , "Service and Host" },
    { KRB5_NT_SRV_XHST             , "Service and Host Components" },
    { KRB5_NT_UID                  , "Unique ID" },
    { KRB5_NT_X500_PRINCIPAL       , "Encoded X.509 Distinguished Name" },
    { KRB5_NT_SMTP_NAME            , "SMTP Name" },
    { KRB5_NT_ENTERPRISE           , "Enterprise Name" },
    { KRB5_NT_MS_PRINCIPAL         , "NT 4.0 style name (MS specific)" },
    { KRB5_NT_MS_PRINCIPAL_AND_SID , "NT 4.0 style name with SID (MS specific)"},
    { KRB5_NT_ENT_PRINCIPAL_AND_SID, "UPN and SID (MS specific)"},
    { KRB5_NT_PRINCIPAL_AND_SID    , "Principal name and SID (MS specific)"},
    { KRB5_NT_SRV_INST_AND_SID     , "SPN and SID (MS specific)"},
    { 0                            , NULL },
};

static const value_string krb5_preauthentication_types[] = {
    { KRB5_PA_TGS_REQ              , "PA-TGS-REQ" },
    { KRB5_PA_ENC_TIMESTAMP        , "PA-ENC-TIMESTAMP" },
    { KRB5_PA_PW_SALT              , "PA-PW-SALT" },
    { KRB5_PA_ENC_ENCKEY           , "PA-ENC-ENCKEY" },
    { KRB5_PA_ENC_UNIX_TIME        , "PA-ENC-UNIX-TIME" },
    { KRB5_PA_ENC_SANDIA_SECURID   , "PA-PW-SALT" },
    { KRB5_PA_SESAME               , "PA-SESAME" },
    { KRB5_PA_OSF_DCE              , "PA-OSF-DCE" },
    { KRB5_PA_CYBERSAFE_SECUREID   , "PA-CYBERSAFE-SECURID" },
    { KRB5_PA_AFS3_SALT            , "PA-AFS3-SALT" },
    { KRB5_PA_ENCTYPE_INFO         , "PA-ENCTYPE-INFO" },
    { KRB5_PA_ENCTYPE_INFO2         , "PA-ENCTYPE-INFO2" },
    { KRB5_PA_SAM_CHALLENGE        , "PA-SAM-CHALLENGE" },
    { KRB5_PA_SAM_RESPONSE         , "PA-SAM-RESPONSE" },
    { KRB5_PA_PK_AS_REQ            , "PA-PK-AS-REQ" },
    { KRB5_PA_PK_AS_REP            , "PA-PK-AS-REP" },
    { KRB5_PA_DASS                 , "PA-DASS" },
    { KRB5_PA_USE_SPECIFIED_KVNO   , "PA-USE-SPECIFIED-KVNO" },
    { KRB5_PA_SAM_REDIRECT         , "PA-SAM-REDIRECT" },
    { KRB5_PA_GET_FROM_TYPED_DATA  , "PA-GET-FROM-TYPED-DATA" },
    { KRB5_PA_SAM_ETYPE_INFO       , "PA-SAM-ETYPE-INFO" },
    { KRB5_PA_ALT_PRINC            , "PA-ALT-PRINC" },
    { KRB5_PA_SAM_CHALLENGE2       , "PA-SAM-CHALLENGE2" },
    { KRB5_PA_SAM_RESPONSE2        , "PA-SAM-RESPONSE2" },
    { KRB5_TD_PKINIT_CMS_CERTIFICATES, "TD-PKINIT-CMS-CERTIFICATES" },
    { KRB5_TD_KRB_PRINCIPAL        , "TD-KRB-PRINCIPAL" },
    { KRB5_TD_KRB_REALM , "TD-KRB-REALM" },
    { KRB5_TD_TRUSTED_CERTIFIERS   , "TD-TRUSTED-CERTIFIERS" },
    { KRB5_TD_CERTIFICATE_INDEX    , "TD-CERTIFICATE-INDEX" },
    { KRB5_TD_APP_DEFINED_ERROR    , "TD-APP-DEFINED-ERROR" },
    { KRB5_TD_REQ_NONCE            , "TD-REQ-NONCE" },
    { KRB5_TD_REQ_SEQ              , "TD-REQ-SEQ" },
    { KRB5_PA_PAC_REQUEST          , "PA-PAC-REQUEST" },
    { KRB5_PA_PROV_SRV_LOCATION    , "PA-PROV-SRV-LOCATION" },
    { 0                            , NULL },
};

static const value_string krb5_encryption_types[] = {
    { KRB5_ENCTYPE_NULL           , "NULL" },
    { KRB5_ENCTYPE_DES_CBC_CRC    , "des-cbc-crc" },
    { KRB5_ENCTYPE_DES_CBC_MD4    , "des-cbc-md4" },
    { KRB5_ENCTYPE_DES_CBC_MD5    , "des-cbc-md5" },
    { KRB5_ENCTYPE_DES_CBC_RAW    , "des-cbc-raw" },
    { KRB5_ENCTYPE_DES3_CBC_SHA   , "des3-cbc-sha" },
    { KRB5_ENCTYPE_DES3_CBC_RAW   , "des3-cbc-raw" },
    { KRB5_ENCTYPE_DES_HMAC_SHA1  , "des-hmac-sha1" },
    { KRB5_ENCTYPE_DSA_SHA1_CMS   , "dsa-sha1-cms" },
    { KRB5_ENCTYPE_RSA_MD5_CMS    , "rsa-md5-cms" },
    { KRB5_ENCTYPE_RSA_SHA1_CMS   , "rsa-sha1-cms" },
    { KRB5_ENCTYPE_RC2_CBC_ENV    , "rc2-cbc-env" },
    { KRB5_ENCTYPE_RSA_ENV        , "rsa-env" },
    { KRB5_ENCTYPE_RSA_ES_OEAP_ENV, "rsa-es-oeap-env" },
    { KRB5_ENCTYPE_DES_EDE3_CBC_ENV, "des-ede3-cbc-env" },
    { KRB5_ENCTYPE_DES3_CBC_SHA1  , "des3-cbc-sha1" },
    { KRB5_ENCTYPE_AES128_CTS_HMAC_SHA1_96  , "aes128-cts-hmac-sha1-96" },
    { KRB5_ENCTYPE_AES256_CTS_HMAC_SHA1_96  , "aes256-cts-hmac-sha1-96" },
    { KRB5_ENCTYPE_DES_CBC_MD5_NT  , "des-cbc-md5-nt" },
    { KERB_ENCTYPE_RC4_HMAC       , "rc4-hmac" },
    { KERB_ENCTYPE_RC4_HMAC_EXP   , "rc4-hmac-exp" },
    { KRB5_ENCTYPE_UNKNOWN        , "unknown" },
    { KRB5_ENCTYPE_LOCAL_DES3_HMAC_SHA1    , "local-des3-hmac-sha1" },
    { KRB5_ENCTYPE_RC4_PLAIN_EXP  , "rc4-plain-exp" },
    { KRB5_ENCTYPE_RC4_PLAIN      , "rc4-plain" },
    { KRB5_ENCTYPE_RC4_PLAIN_OLD_EXP, "rc4-plain-old-exp" },
    { KRB5_ENCTYPE_RC4_HMAC_OLD_EXP, "rc4-hmac-old-exp" },
    { KRB5_ENCTYPE_RC4_PLAIN_OLD  , "rc4-plain-old" },
    { KRB5_ENCTYPE_RC4_HMAC_OLD   , "rc4-hmac-old" },
    { KRB5_ENCTYPE_DES_PLAIN      , "des-plain" },
    { KRB5_ENCTYPE_RC4_SHA        , "rc4-sha" },
    { KRB5_ENCTYPE_RC4_LM         , "rc4-lm" },
    { KRB5_ENCTYPE_RC4_PLAIN2     , "rc4-plain2" },
    { KRB5_ENCTYPE_RC4_MD4        , "rc4-md4" },
    { 0                           , NULL },
};

static const value_string krb5_checksum_types[] = {
    { KRB5_CHKSUM_NONE            , "none" },
    { KRB5_CHKSUM_CRC32           , "crc32" },
    { KRB5_CHKSUM_MD4             , "md4" },
    { KRB5_CHKSUM_KRB_DES_MAC     , "krb-des-mac" },
    { KRB5_CHKSUM_KRB_DES_MAC_K   , "krb-des-mac-k" },
    { KRB5_CHKSUM_MD5             , "md5" },
    { KRB5_CHKSUM_MD5_DES         , "md5-des" },
    { KRB5_CHKSUM_MD5_DES3        , "md5-des3" },
    { KRB5_CHKSUM_HMAC_SHA1_DES3_KD, "hmac-sha1-des3-kd" },
    { KRB5_CHKSUM_HMAC_SHA1_DES3  , "hmac-sha1-des3" },
    { KRB5_CHKSUM_SHA1_UNKEYED    , "sha1 (unkeyed)" },
    { KRB5_CHKSUM_HMAC_MD5        , "hmac-md5" },
    { KRB5_CHKSUM_MD5_HMAC        , "md5-hmac" },
    { KRB5_CHKSUM_RC4_MD5         , "rc5-md5" },
    { KRB5_CHKSUM_MD25            , "md25" },
    { KRB5_CHKSUM_DES_MAC_MD5     , "des-mac-md5" },
    { KRB5_CHKSUM_DES_MAC         , "des-mac" },
    { KRB5_CHKSUM_REAL_CRC32      , "real-crc32" },
    { KRB5_CHKSUM_SHA1            , "sha1" },
    { KRB5_CHKSUM_LM              , "lm" },
    { KRB5_CHKSUM_GSSAPI	  , "gssapi-8003" },
    { 0                           , NULL },
};

#define KRB5_AD_IF_RELEVANT			1
#define KRB5_AD_INTENDED_FOR_SERVER		2
#define KRB5_AD_INTENDED_FOR_APPLICATION_CLASS	3
#define KRB5_AD_KDC_ISSUED			4
#define KRB5_AD_OR				5
#define KRB5_AD_MANDATORY_TICKET_EXTENSIONS	6
#define KRB5_AD_IN_TICKET_EXTENSIONS		7
#define KRB5_AD_MANDATORY_FOR_KDC		8
#define KRB5_AD_OSF_DCE				64
#define KRB5_AD_SESAME				65
#define KRB5_AD_OSF_DCE_PKI_CERTID		66
#define KRB5_AD_WIN2K_PAC				128
static const value_string krb5_ad_types[] = {
    { KRB5_AD_IF_RELEVANT	  		, "AD-IF-RELEVANT" },
    { KRB5_AD_INTENDED_FOR_SERVER		, "AD-Intended-For-Server" },
    { KRB5_AD_INTENDED_FOR_APPLICATION_CLASS	, "AD-Intended-For-Application-Class" },
    { KRB5_AD_KDC_ISSUED			, "AD-KDCIssued" },
    { KRB5_AD_OR 				, "AD-AND-OR" },
    { KRB5_AD_MANDATORY_TICKET_EXTENSIONS	, "AD-Mandatory-Ticket-Extensions" },
    { KRB5_AD_IN_TICKET_EXTENSIONS		, "AD-IN-Ticket-Extensions" },
    { KRB5_AD_MANDATORY_FOR_KDC			, "AD-MANDATORY-FOR-KDC" },
    { KRB5_AD_OSF_DCE				, "AD-OSF-DCE" },
    { KRB5_AD_SESAME				, "AD-SESAME" },
    { KRB5_AD_OSF_DCE_PKI_CERTID		, "AD-OSF-DCE-PKI-CertID" },
    { KRB5_AD_WIN2K_PAC				, "AD-Win2k-PAC" },
    { 0	, NULL },
};

static const value_string krb5_transited_types[] = {
    { 1                           , "DOMAIN-X500-COMPRESS" },
    { 0                           , NULL }
};

static const value_string krb5_address_types[] = {
    { KRB5_ADDR_IPv4,		"IPv4"},
    { KRB5_ADDR_CHAOS,		"CHAOS"},
    { KRB5_ADDR_XEROX,		"XEROX"},
    { KRB5_ADDR_ISO,		"ISO"},
    { KRB5_ADDR_DECNET,		"DECNET"},
    { KRB5_ADDR_APPLETALK,	"APPLETALK"},
    { KRB5_ADDR_NETBIOS,     	"NETBIOS"},
    { KRB5_ADDR_IPv6,		"IPv6"},
    { 0,                        NULL },
};

static const value_string krb5_msg_types[] = {
	{ KRB5_MSG_TICKET,		"Ticket" },
	{ KRB5_MSG_AUTHENTICATOR,	"Authenticator" },
	{ KRB5_MSG_ENC_TICKET_PART,	"EncTicketPart" },
	{ KRB5_MSG_TGS_REQ,		"TGS-REQ" },
	{ KRB5_MSG_TGS_REP,		"TGS-REP" },
	{ KRB5_MSG_AS_REQ,		"AS-REQ" },
	{ KRB5_MSG_AS_REP,		"AS-REP" },
	{ KRB5_MSG_AP_REQ,		"AP-REQ" },
	{ KRB5_MSG_AP_REP,		"AP-REP" },
	{ KRB5_MSG_SAFE,		"KRB-SAFE" },
	{ KRB5_MSG_PRIV,		"KRB-PRIV" },
	{ KRB5_MSG_CRED,		"KRB-CRED" },
	{ KRB5_MSG_ENC_AS_REP_PART,	"EncASRepPart" },
	{ KRB5_MSG_ENC_TGS_REP_PART,	"EncTGSRepPart" },
	{ KRB5_MSG_ENC_AP_REP_PART,	"EncAPRepPart" },
	{ KRB5_MSG_ENC_KRB_PRIV_PART,	"EncKrbPrivPart" },
	{ KRB5_MSG_ERROR,		"KRB-ERROR" },
        { 0, NULL },
};




static int dissect_krb5_application_choice(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_Application_1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_Authenticator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_EncTicketPart(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_EncAPRepPart(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_EncKrbPrivPart(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_EncKDCRepPart(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_KDC_REQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_KDC_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_AP_REQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_AP_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_SAFE(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_PRIV(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_krb5_ERROR(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

static const ber_choice_t kerberos_applications_choice[] = {
	{ KRB5_MSG_TICKET, 	BER_CLASS_APP,	KRB5_MSG_TICKET,	0, dissect_krb5_Application_1 },
	{ KRB5_MSG_AUTHENTICATOR, 	BER_CLASS_APP,	KRB5_MSG_AUTHENTICATOR,	0, dissect_krb5_Authenticator },
	{ KRB5_MSG_ENC_TICKET_PART, BER_CLASS_APP,	KRB5_MSG_ENC_TICKET_PART, 0, dissect_krb5_EncTicketPart },
	{ KRB5_MSG_AS_REQ,	BER_CLASS_APP,	KRB5_MSG_AS_REQ,	0,	dissect_krb5_KDC_REQ },
	{ KRB5_MSG_AS_REP,	BER_CLASS_APP,	KRB5_MSG_AS_REP,	0,	dissect_krb5_KDC_REP },
	{ KRB5_MSG_TGS_REQ,	BER_CLASS_APP,	KRB5_MSG_TGS_REQ,	0,	dissect_krb5_KDC_REQ },
	{ KRB5_MSG_TGS_REP,	BER_CLASS_APP,	KRB5_MSG_TGS_REP,	0,	dissect_krb5_KDC_REP },
	{ KRB5_MSG_AP_REQ,	BER_CLASS_APP,	KRB5_MSG_AP_REQ,	0,	dissect_krb5_AP_REQ },
	{ KRB5_MSG_AP_REP,	BER_CLASS_APP,	KRB5_MSG_AP_REP,	0,	dissect_krb5_AP_REP },
	{ KRB5_MSG_ENC_AS_REP_PART, BER_CLASS_APP, KRB5_MSG_ENC_AS_REP_PART, 0, dissect_krb5_EncKDCRepPart },
	{ KRB5_MSG_ENC_TGS_REP_PART, BER_CLASS_APP, KRB5_MSG_ENC_TGS_REP_PART, 0, dissect_krb5_EncKDCRepPart },
	{ KRB5_MSG_ENC_AP_REP_PART, BER_CLASS_APP, KRB5_MSG_ENC_AP_REP_PART, 0, dissect_krb5_EncAPRepPart },
	{ KRB5_MSG_ENC_KRB_PRIV_PART, BER_CLASS_APP, KRB5_MSG_ENC_KRB_PRIV_PART, 0, dissect_krb5_EncKrbPrivPart },
	{ KRB5_MSG_SAFE,	BER_CLASS_APP,	KRB5_MSG_SAFE,		0,	dissect_krb5_SAFE },
	{ KRB5_MSG_PRIV,	BER_CLASS_APP,	KRB5_MSG_PRIV,		0,	dissect_krb5_PRIV },
	{ KRB5_MSG_ERROR,	BER_CLASS_APP,	KRB5_MSG_ERROR,		0,	dissect_krb5_ERROR },
	{ 0, 0, 0, 0, NULL }
};


static int
dissect_krb5_application_choice(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_choice(pinfo, tree, tvb, offset, kerberos_applications_choice, -1, -1, NULL);
	return offset;
}


static const true_false_string krb5_apoptions_use_session_key = {
	"USE SESSION KEY to encrypt the ticket",
	"Do NOT use the session key to encrypt the ticket"
};
static const true_false_string krb5_apoptions_mutual_required = {
	"MUTUAL authentication is REQUIRED",
	"Mutual authentication is NOT required"
};

static int *APOptions_bits[] = {
  &hf_krb_APOptions_use_session_key,
  &hf_krb_APOptions_mutual_required,
  NULL
};
static int
dissect_krb5_APOptions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_bitstring32(FALSE, pinfo, tree, tvb, offset, APOptions_bits, hf_krb_APOptions, ett_krb_AP_Options, NULL);
	return offset;
}



static const true_false_string krb5_kdcoptions_forwardable = {
	"FORWARDABLE tickets are allowed/requested",
	"Do NOT use forwardable tickets"
};
static const true_false_string krb5_kdcoptions_forwarded = {
	"This ticket has been FORWARDED",
	"This is NOT a forwarded ticket"
};
static const true_false_string krb5_kdcoptions_proxyable = {
	"PROXIABLE tickets are allowed/requested",
	"Do NOT use proxiable tickets"
};
static const true_false_string krb5_kdcoptions_proxy = {
	"This is a PROXY ticket",
	"This ticket has NOT been proxied"
};
static const true_false_string krb5_kdcoptions_allow_postdate = {
	"We allow the ticket to be POSTDATED",
	"We do NOT allow the ticket to be postdated"
};
static const true_false_string krb5_kdcoptions_postdated = {
	"This ticket is POSTDATED",
	"This ticket is NOT postdated"
};
static const true_false_string krb5_kdcoptions_renewable = {
	"This ticket is RENEWABLE",
	"This ticket is NOT renewable"
};
static const true_false_string krb5_kdcoptions_canonicalize = {
	"This is a request for a CANONICALIZED ticket",
	"This is NOT a canonicalized ticket request"
};
static const true_false_string krb5_kdcoptions_disable_transited_check = {
	"Transited checking is DISABLED",
	"Transited checking is NOT disabled"
};
static const true_false_string krb5_kdcoptions_renewable_ok = {
	"We accept RENEWED tickets",
	"We do NOT accept renewed tickets"
};
static const true_false_string krb5_kdcoptions_enc_tkt_in_skey = {
	"ENCrypt TKT in SKEY",
	"Do NOT encrypt the tkt inside the skey"
};
static const true_false_string krb5_kdcoptions_renew = {
	"This is a request to RENEW a ticket",
	"This is NOT a request to renew a ticket"
};
static const true_false_string krb5_kdcoptions_validate = {
	"This is a request to VALIDATE a postdated ticket",
	"This is NOT a request to validate a postdated ticket"
};

static int* KDCOptions_bits[] = {
  &hf_krb_KDCOptions_forwardable,
  &hf_krb_KDCOptions_forwarded,
  &hf_krb_KDCOptions_proxyable,
  &hf_krb_KDCOptions_proxy,
  &hf_krb_KDCOptions_allow_postdate,
  &hf_krb_KDCOptions_postdated,
  &hf_krb_KDCOptions_renewable,
  &hf_krb_KDCOptions_opt_hardware_auth,
  &hf_krb_KDCOptions_canonicalize,
  &hf_krb_KDCOptions_disable_transited_check,
  &hf_krb_KDCOptions_renewable_ok,
  &hf_krb_KDCOptions_enc_tkt_in_skey,
  &hf_krb_KDCOptions_renew,
  &hf_krb_KDCOptions_validate,
  NULL
};

static int
dissect_krb5_KDCOptions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_bitstring32(FALSE, pinfo, tree, tvb, offset, KDCOptions_bits, hf_krb_KDCOptions, ett_krb_KDC_Options, NULL);
	return offset;
}

static int
dissect_krb5_rtime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_rtime);
	return offset;
}

int
dissect_krb5_ctime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_ctime);
	return offset;
}
static int
dissect_krb5_cusec(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_cusec, NULL);
	return offset;
}

static int
dissect_krb5_stime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_stime);
	return offset;
}
static int
dissect_krb5_susec(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_susec, NULL);
	return offset;
}


static int
dissect_krb5_error_code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_error_code, &krb5_errorcode);
	if(krb5_errorcode && check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
			"KRB Error: %s",
			val_to_str(krb5_errorcode, krb5_error_codes,
			"Unknown error code %#x"));
	}

	return offset;
}


static int
dissect_krb5_till(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_till);
	return offset;
}
static int
dissect_krb5_from(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_from);
	return offset;
}



static int
dissect_krb5_nonce(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_nonce, NULL);
	return offset;
}


/*
 *          etype[8]             SEQUENCE OF INTEGER, -- EncryptionType,
 */
static int
dissect_krb5_etype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint32 etype;

	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_etype, &etype);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(etype, krb5_encryption_types,
			"%d"));
	}
	return offset;
}
static ber_sequence_t etype_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_krb5_etype },
};
static int
dissect_krb5_etype_sequence_of(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(FALSE, pinfo, tree, tvb, offset, etype_sequence_of, hf_krb_etypes, ett_krb_etypes);

	return offset;
}
static guint32 authenticator_etype;
static int
dissect_krb5_authenticator_etype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_etype, &authenticator_etype);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(authenticator_etype, krb5_encryption_types,
			"%#x"));
	}
	return offset;
}
static guint32 Ticket_etype;
static int
dissect_krb5_Ticket_etype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_etype, &Ticket_etype);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(Ticket_etype, krb5_encryption_types,
			"%#x"));
	}
	return offset;
}
static guint32 AP_REP_etype;
static int
dissect_krb5_AP_REP_etype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_etype, &AP_REP_etype);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(AP_REP_etype, krb5_encryption_types,
			"%#x"));
	}
	return offset;
}
static guint32 PA_ENC_TIMESTAMP_etype;
static int
dissect_krb5_PA_ENC_TIMESTAMP_etype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_etype, &PA_ENC_TIMESTAMP_etype);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(PA_ENC_TIMESTAMP_etype, krb5_encryption_types,
			"%#x"));
	}
	return offset;
}


/*
 *  HostAddress ::=    SEQUENCE  {
 *                     addr-type[0]             INTEGER,
 *                     address[1]               OCTET STRING
 *  }
 */
static guint32 addr_type;
static int dissect_krb5_addr_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_addr_type, &addr_type);
	return offset;
}
static int dissect_krb5_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	gint8 class;
	gboolean pc;
	gint32 tag;
	guint32 len;
	char *address_str;
	proto_item *it=NULL;

	/* read header and len for the octet string */
	offset=dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
	offset=dissect_ber_length(pinfo, tree, tvb, offset, &len, NULL);

	address_str=ep_alloc(256);
	address_str[0]=0;
	address_str[255]=0;
	switch(addr_type){
	case KRB5_ADDR_IPv4:
		it=proto_tree_add_item(tree, hf_krb_address_ip, tvb, offset, 4, FALSE);
		g_snprintf(address_str,256,"%d.%d.%d.%d",tvb_get_guint8(tvb, offset),tvb_get_guint8(tvb, offset+1),tvb_get_guint8(tvb, offset+2),tvb_get_guint8(tvb, offset+3));
		break;
	case KRB5_ADDR_NETBIOS:
		{
		char netbios_name[(NETBIOS_NAME_LEN - 1)*4 + 1];
		int netbios_name_type;

		netbios_name_type = process_netbios_name(tvb_get_ptr(tvb, offset, 16), netbios_name);
		g_snprintf(address_str, 255, "%s<%02x>", netbios_name, netbios_name_type);
		it=proto_tree_add_string_format(tree, hf_krb_address_netbios, tvb, offset, 16, netbios_name, "NetBIOS Name: %s (%s)", address_str, netbios_name_type_descr(netbios_name_type));
		}
		break;
	default:
		proto_tree_add_text(tree, tvb, offset, len, "KRB Address: I dont know how to parse this type of address yet");

	}

	/* push it up two levels in the decode pane */
	if(it){
		proto_item_append_text(proto_item_get_parent(it), " %s",address_str);
		proto_item_append_text(proto_item_get_parent_nth(it, 2), " %s",address_str);
	}

	offset+=len;
	return offset;
}
static ber_sequence_t HostAddress_sequence[] = {
	{ BER_CLASS_CON, 0, 0, dissect_krb5_addr_type },
	{ BER_CLASS_CON, 1, 0, dissect_krb5_address },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_HostAddress(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, HostAddress_sequence, hf_krb_HostAddress, ett_krb_HostAddress);

	return offset;
}
static int
dissect_krb5_s_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, HostAddress_sequence, hf_krb_s_address, ett_krb_s_address);

	return offset;
}

/*
 *  HostAddresses ::=   SEQUENCE OF SEQUENCE {
 *                      addr-type[0]             INTEGER,
 *                      address[1]               OCTET STRING
 *  }
 *
 */
static ber_sequence_t HostAddresses_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_krb5_HostAddress },
};
static int
dissect_krb5_HostAddresses(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(FALSE, pinfo, tree, tvb, offset, HostAddresses_sequence_of, hf_krb_HostAddresses, ett_krb_HostAddresses);

	return offset;
}



static int
dissect_krb5_msg_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint32 msgtype;

	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_msg_type, &msgtype);

	if (do_col_info & check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO,
			val_to_str(msgtype, krb5_msg_types,
			"Unknown msg type %#x"));
	}
	do_col_info=FALSE;

	/* append the application type to the subtree */
	proto_item_append_text(tree, " %s", val_to_str(msgtype, krb5_msg_types, "Unknown:0x%x"));

	return offset;
}



static int
dissect_krb5_pvno(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_pvno, NULL);

	return offset;
}


/*
 * PrincipalName ::=   SEQUENCE {
 *                     name-type[0]     INTEGER,
 *                     name-string[1]   SEQUENCE OF GeneralString
 * }
 */
guint32 name_type;
static int
dissect_krb5_name_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_name_type, &name_type);
	if(tree){
		proto_item_append_text(tree, " (%s):",
			val_to_str(name_type, krb5_princ_types,
			"Unknown:%d"));
	}
	return offset;
}
static char name_string_separator;
static int
dissect_krb5_name_string(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	char name_string[256];

	offset=dissect_ber_GeneralString(pinfo, tree, tvb, offset, hf_krb_name_string, name_string, 255);
	if(tree){
		proto_item_append_text(tree, "%c%s", name_string_separator, name_string);
		name_string_separator='/';
	}

	return offset;
}
static ber_sequence_t name_stringe_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_NOOWNTAG, dissect_krb5_name_string },
};
static int
dissect_krb5_name_strings(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	name_string_separator=' ';
	offset=dissect_ber_sequence_of(FALSE, pinfo, tree, tvb, offset, name_stringe_sequence_of, -1, -1);

	return offset;
}
static ber_sequence_t PrincipalName_sequence[] = {
	{ BER_CLASS_CON, 0, 0, dissect_krb5_name_type },
	{ BER_CLASS_CON, 1, 0, dissect_krb5_name_strings },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_sname(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, PrincipalName_sequence, hf_krb_sname, ett_krb_sname);

	return offset;
}
int
dissect_krb5_cname(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, PrincipalName_sequence, hf_krb_cname, ett_krb_cname);

	return offset;
}


int
dissect_krb5_realm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralString(pinfo, tree, tvb, offset, hf_krb_realm, NULL, 0);
	return offset;
}

static int
dissect_krb5_crealm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralString(pinfo, tree, tvb, offset, hf_krb_crealm, NULL, 0);
	return offset;
}



static int
dissect_krb5_PA_PAC_REQUEST_flag(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_boolean(FALSE, pinfo, tree, tvb, offset, hf_krb_PA_PAC_REQUEST_flag);
	return offset;
}


static ber_sequence_t PA_PAC_REQUEST_sequence[] = {
	{ BER_CLASS_CON, 0, 0, dissect_krb5_PA_PAC_REQUEST_flag },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_PA_PAC_REQUEST(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, PA_PAC_REQUEST_sequence, -1, -1);

	return offset;
}




static int
dissect_krb5_PA_PROV_SRV_LOCATION(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralString(pinfo, tree, tvb, offset, hf_krb_provsrv_location, NULL, 0);

	return offset;
}



static int
dissect_krb5_kvno(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_kvno, NULL);

	return offset;
}



static int
dissect_krb5_seq_number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_seq_number, NULL);

	return offset;
}



static int
dissect_krb5_patimestamp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_patimestamp);
	return offset;
}
#ifdef HAVE_KERBEROS
static int
dissect_krb5_pausec(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_pausec, NULL);
	return offset;
}
static const ber_sequence_t PA_ENC_TS_ENC_sequence[] = {
	{ BER_CLASS_CON, 0, 0, dissect_krb5_patimestamp },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_krb5_pausec },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_decrypt_PA_ENC_TIMESTAMP (packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint8 *plaintext=NULL;
	int length;

	length=tvb_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * AS-REQ PA_ENC_TIMESTAMP are encrypted with usage
	 * == 1
	 */
	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, pinfo, 1, length, tvb_get_ptr(tvb, offset, length), PA_ENC_TIMESTAMP_etype);
	}

	if(plaintext){
		tvbuff_t *next_tvb;
		next_tvb = tvb_new_real_data (plaintext,
                                          length,
                                          length);
		tvb_set_child_real_data_tvbuff(tvb, next_tvb);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(pinfo, next_tvb, "Decrypted Krb5");


		offset=dissect_ber_sequence(FALSE, pinfo, tree, next_tvb, 0, PA_ENC_TS_ENC_sequence, -1, -1);

	}
	return offset;
}
#endif


static int
dissect_krb5_encrypted_PA_ENC_TIMESTAMP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_PA_ENC_TIMESTAMP, dissect_krb5_decrypt_PA_ENC_TIMESTAMP);
#else
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_PA_ENC_TIMESTAMP, NULL);
#endif
	return offset;
}
static ber_sequence_t PA_ENC_TIMESTAMP_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_PA_ENC_TIMESTAMP_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_PA_ENC_TIMESTAMP },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_PA_ENC_TIMESTAMP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, PA_ENC_TIMESTAMP_sequence, -1, -1);

	return offset;
}



static int
dissect_krb5_etype_info_salt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_krb_etype_info_salt, NULL);
	return offset;
}

static int
dissect_krb5_etype_info2_salt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralString(pinfo, tree, tvb, offset, hf_krb_etype_info2_salt, NULL, 0);
	return offset;
}

static int
dissect_krb5_etype_info2_s2kparams(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_krb_etype_info2_s2kparams, NULL);
	return offset;
}

static ber_sequence_t PA_ENCTYPE_INFO_ENTRY_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_etype_info_salt },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_PA_ENCTYPE_INFO_ENTRY(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, PA_ENCTYPE_INFO_ENTRY_sequence, -1, -1);

	return offset;
}

static ber_sequence_t PA_ENCTYPE_INFO_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_krb5_PA_ENCTYPE_INFO_ENTRY },
};
static int
dissect_krb5_PA_ENCTYPE_INFO(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(FALSE, pinfo, tree, tvb, offset, PA_ENCTYPE_INFO_sequence_of, -1, -1);

	return offset;
}

static ber_sequence_t PA_ENCTYPE_INFO2_ENTRY_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_etype_info2_salt },
	{ BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL,
		dissect_krb5_etype_info2_s2kparams },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_PA_ENCTYPE_INFO2_ENTRY(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, PA_ENCTYPE_INFO2_ENTRY_sequence, -1, -1);

	return offset;
}

static ber_sequence_t PA_ENCTYPE_INFO2_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_krb5_PA_ENCTYPE_INFO2_ENTRY },
};
static int
dissect_krb5_PA_ENCTYPE_INFO2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(FALSE, pinfo, tree, tvb, offset, PA_ENCTYPE_INFO2_sequence_of, -1, -1);

	return offset;
}

/*
 * PA-DATA ::=        SEQUENCE {
 *          padata-type[1]        INTEGER,
 *          padata-value[2]       OCTET STRING,
 *                        -- might be encoded AP-REQ
 * }
 */
guint32 krb_PA_DATA_type;
static int
dissect_krb5_PA_DATA_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_PA_DATA_type, &krb_PA_DATA_type);
	krb_PA_DATA_type&=0xff; /*this is really just one single byte */

	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(krb_PA_DATA_type, krb5_preauthentication_types,
			"Unknown:%d"));
	}
	return offset;
}
static int
dissect_krb5_PA_DATA_value(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_tree *tree=parent_tree;

	if(ber_last_created_item){
		tree=proto_item_add_subtree(ber_last_created_item, ett_krb_PA_DATA_tree);
	}


	switch(krb_PA_DATA_type){
	case KRB5_PA_TGS_REQ:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_krb5_application_choice);
 		break;
	case KRB5_PA_PK_AS_REQ:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_pkinit_PA_PK_AS_REQ);
 		break;
	case KRB5_PA_PK_AS_REP:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_pkinit_PA_PK_AS_REP);
 		break;
	case KRB5_PA_PAC_REQUEST:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_krb5_PA_PAC_REQUEST);
 		break;
	case KRB5_PA_PROV_SRV_LOCATION:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_krb5_PA_PROV_SRV_LOCATION);
 		break;
	case KRB5_PA_ENC_TIMESTAMP:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_krb5_PA_ENC_TIMESTAMP);
 		break;
	case KRB5_PA_ENCTYPE_INFO:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_krb5_PA_ENCTYPE_INFO);
 		break;
	case KRB5_PA_ENCTYPE_INFO2:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, dissect_krb5_PA_ENCTYPE_INFO2);
 		break;
	default:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset,hf_krb_PA_DATA_value, NULL);
	}
	return offset;
/*qqq*/
}

static ber_sequence_t PA_DATA_sequence[] = {
	{ BER_CLASS_CON, 1, 0, dissect_krb5_PA_DATA_type },
	{ BER_CLASS_CON, 2, 0, dissect_krb5_PA_DATA_value },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_PA_DATA(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, PA_DATA_sequence, -1, -1);

	return offset;
}




/*
 * padata[3]             SEQUENCE OF PA-DATA OPTIONAL,
 *
 */
static ber_sequence_t PA_DATA_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_krb5_PA_DATA },
};
static int
dissect_krb5_padata(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(FALSE, pinfo, tree, tvb, offset, PA_DATA_sequence_of, hf_krb_padata, ett_krb_padata);

	return offset;
}




static const true_false_string krb5_ticketflags_forwardable = {
	"FORWARDABLE tickets are allowed/requested",
	"Do NOT use forwardable tickets"
};
static const true_false_string krb5_ticketflags_forwarded = {
	"This ticket has been FORWARDED",
	"This is NOT a forwarded ticket"
};
static const true_false_string krb5_ticketflags_proxyable = {
	"PROXIABLE tickets are allowed/requested",
	"Do NOT use proxiable tickets"
};
static const true_false_string krb5_ticketflags_proxy = {
	"This is a PROXY ticket",
	"This ticket has NOT been proxied"
};
static const true_false_string krb5_ticketflags_allow_postdate = {
	"We allow the ticket to be POSTDATED",
	"We do NOT allow the ticket to be postdated"
};
static const true_false_string krb5_ticketflags_postdated = {
	"This ticket is POSTDATED",
	"This ticket is NOT postdated"
};
static const true_false_string krb5_ticketflags_invalid = {
	"This ticket is INVALID",
	"This ticket is NOT invalid"
};
static const true_false_string krb5_ticketflags_renewable = {
	"This ticket is RENEWABLE",
	"This ticket is NOT renewable"
};
static const true_false_string krb5_ticketflags_initial = {
	"This ticket was granted by AS and not TGT protocol",
	"This ticket was granted by TGT and not as protocol"
};
static const true_false_string krb5_ticketflags_pre_auth = {
	"The client was PRE-AUTHenticated",
	"The client was NOT pre-authenticated"
};
static const true_false_string krb5_ticketflags_hw_auth = {
	"The client was authenticated by HardWare",
	"The client was NOT authenticated using hardware"
};
static const true_false_string krb5_ticketflags_transited_policy_checked = {
	"Kdc has performed TRANSITED POLICY CHECKING",
	"Kdc has NOT performed transited policy checking"
};
static const true_false_string krb5_ticketflags_ok_as_delegate = {
	"This ticket is OK AS a DELEGATED ticket",
	"This ticket is NOT ok as a delegated ticket"
};

static int* TicketFlags_bits[] = {
  &hf_krb_TicketFlags_forwardable,
  &hf_krb_TicketFlags_forwarded,
  &hf_krb_TicketFlags_proxyable,
  &hf_krb_TicketFlags_proxy,
  &hf_krb_TicketFlags_allow_postdate,
  &hf_krb_TicketFlags_postdated,
  &hf_krb_TicketFlags_invalid,
  &hf_krb_TicketFlags_renewable,
  &hf_krb_TicketFlags_initial,
  &hf_krb_TicketFlags_pre_auth,
  &hf_krb_TicketFlags_hw_auth,
  &hf_krb_TicketFlags_transited_policy_checked,
  &hf_krb_TicketFlags_ok_as_delegate,
  NULL
};

static int
dissect_krb5_TicketFlags(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_bitstring32(FALSE, pinfo, tree, tvb, offset, TicketFlags_bits, hf_krb_TicketFlags, ett_krb_Ticket_Flags, NULL);
	return offset;
}


static guint32 keytype;
static int
dissect_krb5_keytype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_keytype, &keytype);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(keytype, krb5_encryption_types,
			"%#x"));
	}
	return offset;
}
static int keylength;
static const guint8 *keyvalue;
static int
store_keyvalue(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb, int offset)
{
	keylength=tvb_length_remaining(tvb, offset);
	keyvalue=tvb_get_ptr(tvb, offset, keylength);
	return 0;
}
static int
dissect_krb5_keyvalue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_keyvalue, store_keyvalue);
	return offset;
}


/*
 * EncryptionKey ::=        SEQUENCE {
 *     keytype  [0] int32
 *     keyvalue [1] octet string
 */
static ber_sequence_t EncryptionKey_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_keytype },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_keyvalue },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_key(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, EncryptionKey_sequence, hf_krb_key, ett_krb_key);

#ifdef HAVE_KERBEROS
	add_encryption_key(pinfo, keytype, keylength, keyvalue, "key");
#endif
	return offset;
}
static int
dissect_krb5_subkey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, EncryptionKey_sequence, hf_krb_subkey, ett_krb_subkey);
#ifdef HAVE_KERBEROS
	add_encryption_key(pinfo, keytype, keylength, keyvalue, "subkey");
#endif
	return offset;
}



static int
dissect_krb5_PAC_LOGON_INFO(packet_info *pinfo, proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint8 drep[4] = { 0x10, 0x00, 0x00, 0x00}; /* fake DREP struct */
	dcerpc_info di;	/* fake dcerpc_info struct */
	void *old_private_data;

	item=proto_tree_add_item(parent_tree, hf_krb_PAC_LOGON_INFO, tvb, offset, tvb_length_remaining(tvb, offset), FALSE);
	if(parent_tree){
		tree=proto_item_add_subtree(item, ett_krb_PAC_LOGON_INFO);
	}

	/* skip the first 20 bytes, they look like a unique ndr pointer
	   followed by (where did it come from?) a contect_handle ?*/
	proto_tree_add_text(tree, tvb, offset, 20, "unknown: is this an undocumented policy handle?");
	offset+=20;


	/* the PAC_LOGON_INFO blob */
	/* fake whatever state the dcerpc runtime support needs */
	di.conformant_run=0;
	di.call_data=NULL;
	old_private_data=pinfo->private_data;
	pinfo->private_data=&di;
	init_ndr_pointer_list(pinfo);
	offset = dissect_ndr_pointer(tvb, offset, pinfo, tree, drep,
		netlogon_dissect_PAC_LOGON_INFO, NDR_POINTER_REF,
		"PAC_LOGON_INFO:", -1);
	pinfo->private_data=old_private_data;

	return offset;
}

static int
dissect_krb5_PAC_CREDENTIAL_TYPE(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	item=proto_tree_add_item(parent_tree, hf_krb_PAC_CREDENTIAL_TYPE, tvb, offset, tvb_length_remaining(tvb, offset), FALSE);
	if(parent_tree){
		tree=proto_item_add_subtree(item, ett_krb_PAC_CREDENTIAL_TYPE);
	}

/*qqq*/
	return offset;
}

static int
dissect_krb5_PAC_SERVER_CHECKSUM(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	item=proto_tree_add_item(parent_tree, hf_krb_PAC_SERVER_CHECKSUM, tvb, offset, tvb_length_remaining(tvb, offset), FALSE);
	if(parent_tree){
		tree=proto_item_add_subtree(item, ett_krb_PAC_SERVER_CHECKSUM);
	}

	/* signature type */
	proto_tree_add_item(tree, hf_krb_pac_signature_type, tvb, offset, 4, TRUE);
	offset+=4;

	/* signature data */
	proto_tree_add_item(tree, hf_krb_pac_signature_signature, tvb, offset, tvb_length_remaining(tvb, offset), FALSE);

	return offset;
}

static int
dissect_krb5_PAC_PRIVSVR_CHECKSUM(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	item=proto_tree_add_item(parent_tree, hf_krb_PAC_PRIVSVR_CHECKSUM, tvb, offset, tvb_length_remaining(tvb, offset), FALSE);
	if(parent_tree){
		tree=proto_item_add_subtree(item, ett_krb_PAC_PRIVSVR_CHECKSUM);
	}

	/* signature type */
	proto_tree_add_item(tree, hf_krb_pac_signature_type, tvb, offset, 4, TRUE);
	offset+=4;

	/* signature data */
	proto_tree_add_item(tree, hf_krb_pac_signature_signature, tvb, offset, tvb_length_remaining(tvb, offset), FALSE);

	return offset;
}

static int
dissect_krb5_PAC_CLIENT_INFO_TYPE(packet_info *pinfo _U_, proto_tree *parent_tree, tvbuff_t *tvb, int offset)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	guint16 namelen;
	char *name;

	item=proto_tree_add_item(parent_tree, hf_krb_PAC_CLIENT_INFO_TYPE, tvb, offset, tvb_length_remaining(tvb, offset), FALSE);
	if(parent_tree){
		tree=proto_item_add_subtree(item, ett_krb_PAC_CLIENT_INFO_TYPE);
	}

	/* clientid */
	offset = dissect_nt_64bit_time(tvb, tree, offset,
		       	hf_krb_pac_clientid);

	/* name length */
	namelen=tvb_get_letohs(tvb, offset);
	proto_tree_add_uint(tree, hf_krb_pac_namelen, tvb, offset, 2, namelen);
	offset+=2;

	/* client name */
	name=tvb_get_ephemeral_faked_unicode(tvb, offset, namelen/2, TRUE);
	proto_tree_add_string(tree, hf_krb_pac_clientname, tvb, offset, namelen, name);
	offset+=namelen;

	return offset;
}

static int
dissect_krb5_AD_WIN2K_PAC_struct(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint32 pac_type;
	guint32 pac_size;
	guint32 pac_offset;
	proto_item *it=NULL;
	proto_tree *tr=NULL;
	tvbuff_t *next_tvb;

	/* type of pac data */
	pac_type=tvb_get_letohl(tvb, offset);
	it=proto_tree_add_uint(tree, hf_krb_w2k_pac_type, tvb, offset, 4, pac_type);
	if(it){
		tr=proto_item_add_subtree(it, ett_krb_PAC);
	}

	offset += 4;

	/* size of pac data */
	pac_size=tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tr, hf_krb_w2k_pac_size, tvb, offset, 4, pac_size);
	offset += 4;

	/* offset to pac data */
	pac_offset=tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tr, hf_krb_w2k_pac_offset, tvb, offset, 4, pac_offset);
	offset += 8;


	next_tvb=tvb_new_subset(tvb, pac_offset, pac_size, pac_size);
	switch(pac_type){
	case PAC_LOGON_INFO:
		dissect_krb5_PAC_LOGON_INFO(pinfo, tr, next_tvb, 0);
		break;
	case PAC_CREDENTIAL_TYPE:
		dissect_krb5_PAC_CREDENTIAL_TYPE(pinfo, tr, next_tvb, 0);
		break;
	case PAC_SERVER_CHECKSUM:
		dissect_krb5_PAC_SERVER_CHECKSUM(pinfo, tr, next_tvb, 0);
		break;
	case PAC_PRIVSVR_CHECKSUM:
		dissect_krb5_PAC_PRIVSVR_CHECKSUM(pinfo, tr, next_tvb, 0);
		break;
	case PAC_CLIENT_INFO_TYPE:
		dissect_krb5_PAC_CLIENT_INFO_TYPE(pinfo, tr, next_tvb, 0);
		break;
	default:;
/*qqq*/
	}
	return offset;
}

static int
dissect_krb5_AD_WIN2K_PAC(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint32 entries;
	guint32 version;
	guint32 i;

	/* first in the PAC structure comes the number of entries */
	entries=tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_krb_w2k_pac_entries, tvb, offset, 4, entries);
	offset += 4;

	/* second comes the version */
	version=tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tree, hf_krb_w2k_pac_version, tvb, offset, 4, version);
	offset += 4;

	for(i=0;i<entries;i++){
		offset=dissect_krb5_AD_WIN2K_PAC_struct(pinfo, tree, tvb, offset);
	}

	return offset;
}

static guint32 IF_RELEVANT_type;
static int
dissect_krb5_IF_RELEVANT_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_IF_RELEVANT_type, &IF_RELEVANT_type);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(IF_RELEVANT_type, krb5_ad_types,
			"%#x"));
	}
	return offset;
}
static int
dissect_krb5_IF_RELEVANT_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	switch(IF_RELEVANT_type){
	case KRB5_AD_WIN2K_PAC:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_advalue, dissect_krb5_AD_WIN2K_PAC);
		break;
	default:
		offset=dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_krb_IF_RELEVANT_value, NULL);
	}
	return offset;
}
static ber_sequence_t IF_RELEVANT_item_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_IF_RELEVANT_type },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_IF_RELEVANT_value },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_IF_RELEVANT_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, IF_RELEVANT_item_sequence, hf_krb_IF_RELEVANT, ett_krb_IF_RELEVANT);

	return offset;
}

static ber_sequence_t IF_RELEVANT_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_krb5_IF_RELEVANT_item },
};

static int
dissect_krb5_IF_RELEVANT(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(FALSE, pinfo, tree, tvb, offset, IF_RELEVANT_sequence_of, -1, -1);

	return offset;
}

static guint32 adtype;
static int
dissect_krb5_adtype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_adtype, &adtype);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(adtype, krb5_ad_types,
			"%#x"));
	}
	return offset;
}
static int
dissect_krb5_advalue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	switch(adtype){
	case KRB5_AD_IF_RELEVANT:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_advalue, dissect_krb5_IF_RELEVANT);
		break;
	default:
		offset=dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_krb_advalue, NULL);
	}
	return offset;
}
/*
 * AuthorizationData ::=        SEQUENCE {
 *     ad-type  [0] int32
 *     ad-data  [1] octet string
 */
static ber_sequence_t AuthorizationData_item_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_adtype },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_advalue },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_AuthorizationData_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, AuthorizationData_item_sequence, hf_krb_AuthorizationData, ett_krb_AuthorizationData);

	return offset;
}

static ber_sequence_t AuthorizationData_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_krb5_AuthorizationData_item },
};
static int
dissect_krb5_AuthorizationData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(FALSE, pinfo, tree, tvb, offset, AuthorizationData_sequence_of, -1, -1);

	return offset;
}


static int
dissect_krb5_transited_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint32 trtype;

	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_transitedtype, &trtype);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(trtype, krb5_transited_types,
			"%#x"));
	}
	return offset;
}

static int
dissect_krb5_transited_contents(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_krb_transitedcontents, NULL);
	return offset;
}

/*
 * TransitedEncoding ::=        SEQUENCE {
 *     tr-type  [0] int32
 *     contents [1] octet string
 */
static ber_sequence_t TransitedEncoding_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_transited_type },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_transited_contents },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_transited(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, TransitedEncoding_sequence, hf_krb_TransitedEncoding, ett_krb_TransitedEncoding);

	return offset;
}


static int
dissect_krb5_authtime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_authtime);
	return offset;
}
static int
dissect_krb5_starttime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_starttime);
	return offset;
}
static int
dissect_krb5_endtime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_endtime);
	return offset;
}
static int
dissect_krb5_renew_till(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_renew_till);
	return offset;
}

/*
 * EncTicketPart ::=        SEQUENCE {
 *      flags                   [0] TicketFlags,
 *      key                     [1] EncryptionKey,
 *      crealm                  [2] Realm,
 *      cname                   [3] PrincipalName,
 *      transited               [4] TransitedEncoding,
 *      authtime                [5] KerberosTime,
 *      starttime               [6] KerberosTime OPTIONAL,
 *      endtime                 [7] KerberosTime,
 *      renew-till              [8] KerberosTime OPTIONAL,
 *      caddr                   [9] HostAddresses OPTIONAL,
 *      authorization-data      [10] AuthorizationData OPTIONAL
 * }
 */
static ber_sequence_t EncTicketPart_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_TicketFlags },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_key },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_crealm },
	{ BER_CLASS_CON, 3, 0,
		dissect_krb5_cname },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_transited },
	{ BER_CLASS_CON, 5, 0,
		dissect_krb5_authtime },
	{ BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL,
		dissect_krb5_starttime },
	{ BER_CLASS_CON, 7, 0,
		dissect_krb5_endtime },
	{ BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL,
		dissect_krb5_renew_till },
	{ BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL,
		dissect_krb5_HostAddresses },
	{ BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL,
		dissect_krb5_AuthorizationData },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_EncTicketPart(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, EncTicketPart_sequence, hf_krb_EncTicketPart, ett_krb_EncTicketPart);

	return offset;
}






/*
 * EncAPRepPart ::=        SEQUENCE {
 *     ctime                    [0] KerberosTime
 *     cusec                    [1] Microseconds
 *     subkey                   [2] encryptionKey OPTIONAL
 *     seq-number               [3] uint32 OPTIONAL
 * }
 */
static ber_sequence_t EncAPRepPart_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_ctime },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_cusec },
	{ BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL,
		dissect_krb5_subkey },
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_seq_number },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_EncAPRepPart(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, EncAPRepPart_sequence, hf_krb_EncAPRepPart, ett_krb_EncAPRepPart);

	return offset;
}



static guint32 lr_type;
static const value_string krb5_lr_types[] = {
    { 0              , "No information available" },
    { 1              , "Time of last initial TGT request" },
    { 2              , "Time of last initial request" },
    { 3              , "Time of issue of latest TGT ticket" },
    { 4              , "Time of last renewal" },
    { 5              , "Time of last request" },
    { 6              , "Time when password will expire" },
    { 7              , "Time when account will expire" },
    { 0, NULL }
};
static int
dissect_krb5_lr_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_lr_type, &lr_type);

	return offset;
}
static int
dissect_krb5_lr_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_lr_time);

	return offset;
}

static ber_sequence_t LastReq_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_lr_type },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_lr_value },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_LastReq(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, LastReq_sequence, hf_krb_LastReq, ett_krb_LastReq);

	return offset;
}
static ber_sequence_t LastReq_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_krb5_LastReq },
};
static int
dissect_krb5_LastReq_sequence_of(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence_of(FALSE, pinfo, tree, tvb, offset, LastReq_sequence_of, hf_krb_LastReqs, ett_krb_LastReqs);

	return offset;
}

static int
dissect_krb5_key_expiration(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_key_expire);
	return offset;
}

static ber_sequence_t EncKDCRepPart_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_key },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_LastReq_sequence_of },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_nonce },
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_key_expiration },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_TicketFlags },
	{ BER_CLASS_CON, 5, 0,
		dissect_krb5_authtime },
	{ BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL,
		dissect_krb5_starttime },
	{ BER_CLASS_CON, 7, 0,
		dissect_krb5_endtime },
	{ BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL,
		dissect_krb5_renew_till },
	{ BER_CLASS_CON, 9, 0,
		dissect_krb5_realm },
	{ BER_CLASS_CON, 10, 0,
		dissect_krb5_sname },
	{ BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL,
		dissect_krb5_HostAddresses },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_EncKDCRepPart(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, EncKDCRepPart_sequence, hf_krb_EncKDCRepPart, ett_krb_EncKDCRepPart);

	return offset;
}


static int
dissect_krb5_authenticator_vno(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_authenticator_vno, NULL);

	return offset;
}


static int
dissect_krb5_checksum_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_checksum_type, NULL);

	return offset;
}
static int
dissect_krb5_checksum_checksum(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_krb_checksum_checksum, NULL);
	return offset;
}

/*
 * Checksum ::=        SEQUENCE {
 * }
 */
static ber_sequence_t Checksum_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_checksum_type },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_checksum_checksum },
	{ 0, 0, 0, NULL }
};
int
dissect_krb5_Checksum(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, Checksum_sequence, hf_krb_Checksum, ett_krb_Checksum);

	return offset;
}

/*
 * Authenticator ::=        SEQUENCE {
 *     authenticator-vno	[0] integer
 *     crealm                   [1] Realm
 *     cname                    [2] PrincipalName
 *     cksum                    [3] Checksum OPTIONAL
 *     cusec                    [4] Microseconds
 *     ctime                    [5] KerberosTime
 *     subkey                   [6] encryptionKey OPTIONAL
 *     seq-number               [7] uint32 OPTIONAL
 *     authorization-data       [8] AuthorizationData OPTIONAL
 * }
 */
static ber_sequence_t Authenticator_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_authenticator_vno },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_crealm },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_cname },
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_Checksum },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_cusec },
	{ BER_CLASS_CON, 5, 0,
		dissect_krb5_ctime },
	{ BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL,
		dissect_krb5_subkey },
	{ BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL,
		dissect_krb5_seq_number },
	{ BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL,
		dissect_krb5_AuthorizationData },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_Authenticator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, Authenticator_sequence, hf_krb_Authenticator, ett_krb_Authenticator);

	return offset;
}


static int
dissect_krb5_PRIV_BODY_user_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	tvbuff_t *new_tvb;
	offset=dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_krb_PRIV_BODY_user_data, &new_tvb);

	if (new_tvb)
		call_kerberos_callbacks(pinfo, tree, new_tvb, KRB_CBTAG_PRIV_USER_DATA);

	return offset;
}

static ber_sequence_t EncKrbPrivPart_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_PRIV_BODY_user_data },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_patimestamp },
	{ BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL,
		dissect_krb5_cusec },
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_seq_number },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_s_address },
	{ BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL,
		dissect_krb5_HostAddresses },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_EncKrbPrivPart(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, EncKrbPrivPart_sequence, hf_krb_EncKrbPrivPart, ett_krb_EncKrbPrivPart);

	return offset;
}

static guint32 PRIV_etype;
static int
dissect_krb5_PRIV_etype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_etype, &PRIV_etype);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(PRIV_etype, krb5_encryption_types,
			"%#x"));
	}
	return offset;
}

#ifdef HAVE_KERBEROS
static int
dissect_krb5_decrypt_PRIV (packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint8 *plaintext=NULL;
	int length;

	length=tvb_length_remaining(tvb, offset);

	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, pinfo, 13, length, tvb_get_ptr(tvb, offset, length), PRIV_etype);
	}

	if(plaintext){
		tvbuff_t *next_tvb;
		next_tvb = tvb_new_real_data (plaintext,
                                          length,
                                          length);
		tvb_set_child_real_data_tvbuff(tvb, next_tvb);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(pinfo, next_tvb, "Decrypted Krb5");

		offset=dissect_ber_choice(pinfo, tree, next_tvb, 0, kerberos_applications_choice, -1, -1, NULL);

	}
	return offset;
}
#endif

/*
 * PRIV-BODY ::=   SEQUENCE {
 *  KRB-PRIV ::=         [APPLICATION 21] SEQUENCE {
 *               pvno[0]                   INTEGER,
 *               msg-type[1]               INTEGER,
 *               enc-part[3]               EncryptedData
 *  }
 */
static int
dissect_krb5_encrypted_PRIV(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_PRIV, dissect_krb5_decrypt_PRIV);
#else
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_PRIV, NULL);
#endif
	return offset;
}
static ber_sequence_t ENC_PRIV_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_PRIV_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_PRIV },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_ENC_PRIV(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, ENC_PRIV_sequence, hf_krb_ENC_PRIV, ett_krb_PRIV_enc);
	return offset;
}
static ber_sequence_t PRIV_BODY_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 3, 0,
		dissect_krb5_ENC_PRIV },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_PRIV(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, PRIV_BODY_sequence, hf_krb_PRIV_BODY, ett_krb_PRIV);

	return offset;
}


static int
dissect_krb5_SAFE_BODY_user_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	tvbuff_t *new_tvb;
	offset=dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_krb_SAFE_BODY_user_data, &new_tvb);
	if (new_tvb)
		call_kerberos_callbacks(pinfo, tree, new_tvb, KRB_CBTAG_SAFE_USER_DATA);
	return offset;
}
static int
dissect_krb5_SAFE_BODY_timestamp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralizedTime(FALSE, pinfo, tree, tvb, offset, hf_krb_SAFE_BODY_timestamp);
	return offset;
}

static int
dissect_krb5_SAFE_BODY_usec(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_SAFE_BODY_usec, NULL);
	return offset;
}

static ber_sequence_t SAFE_BODY_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_SAFE_BODY_user_data },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_SAFE_BODY_timestamp },
	{ BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL,
		dissect_krb5_SAFE_BODY_usec },
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_seq_number },
	/*XXX this one is OPTIONAL in packetcable?  but mandatory in kerberos */
	{ BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL,
		dissect_krb5_s_address },
	{ BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL,
		dissect_krb5_HostAddresses },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_SAFE_BODY(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, SAFE_BODY_sequence, -1, -1);

	return offset;
}



static ber_sequence_t SAFE_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_SAFE_BODY },
	{ BER_CLASS_CON, 3, 0,
		dissect_krb5_Checksum },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_SAFE(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{

	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, SAFE_sequence, -1, -1);

	return offset;
}


/*
 * KDC-REQ-BODY ::=   SEQUENCE {
 *           kdc-options[0]       KDCOptions,
 *           cname[1]             PrincipalName OPTIONAL,
 *                        -- Used only in AS-REQ
 *           realm[2]             Realm, -- Server's realm
 *                        -- Also client's in AS-REQ
 *           sname[3]             PrincipalName OPTIONAL,
 *           from[4]              KerberosTime OPTIONAL,
 *           till[5]              KerberosTime,
 *           rtime[6]             KerberosTime OPTIONAL,
 *           nonce[7]             INTEGER,
 *           etype[8]             SEQUENCE OF INTEGER, -- EncryptionType,
 *                        -- in preference order
 *           addresses[9]         HostAddresses OPTIONAL,
 *           enc-authorization-data[10]   EncryptedData OPTIONAL,
 *                        -- Encrypted AuthorizationData encoding
 *           additional-tickets[11]       SEQUENCE OF Ticket OPTIONAL
 * }
 *
 */
static ber_sequence_t KDC_REQ_BODY_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_KDCOptions },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_cname },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_realm},
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_sname },
	{ BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL,
		dissect_krb5_from },
		/* this field is not optional in the kerberos spec,
		 * however, in the packetcable spec it is optional.
		 * make it optional here since normal kerberos will
		 * still decode the pdu correctly.
		 */
	{ BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL,
		dissect_krb5_till },
	{ BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL,
		dissect_krb5_rtime },
	{ BER_CLASS_CON, 7, 0,
		dissect_krb5_nonce },
	{ BER_CLASS_CON, 8, 0,
		dissect_krb5_etype_sequence_of },
	{ BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL,
		dissect_krb5_HostAddresses },
/* XXX [10] and [11] enc-authorization-data and additional-tickets should be added */
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_KDC_REQ_BODY(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	conversation_t *conversation;

	/*
	 * UDP replies to KDC_REQs are sent from the server back to the client's
	 * source port, similar to the way TFTP works.  Set up a conversation
	 * accordingly.
	 *
	 * Ref: Section 7.2.1 of
	 * http://www.ietf.org/internet-drafts/draft-ietf-krb-wg-kerberos-clarifications-07.txt
	 */
	if (pinfo->destport == UDP_PORT_KERBEROS && pinfo->ptype == PT_UDP) {
		conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
			pinfo->srcport, 0, NO_PORT_B);
		if (conversation == NULL) {
			conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
				pinfo->srcport, 0, NO_PORT2);
			conversation_set_dissector(conversation, kerberos_handle_udp);
		}
	}

	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, KDC_REQ_BODY_sequence, hf_krb_KDC_REQ_BODY, ett_krb_request);

	return offset;
}



/*
 * KDC-REQ ::=        SEQUENCE {
 *          pvno[1]               INTEGER,
 *          msg-type[2]           INTEGER,
 *          padata[3]             SEQUENCE OF PA-DATA OPTIONAL,
 *          req-body[4]           KDC-REQ-BODY
 * }
 */
static ber_sequence_t KDC_REQ_sequence[] = {
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_padata },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_KDC_REQ_BODY },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_KDC_REQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, KDC_REQ_sequence, -1, -1);

	return offset;
}


#ifdef HAVE_KERBEROS
static int
dissect_krb5_decrypt_authenticator_data (packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint8 *plaintext=NULL;
	int length;

	length=tvb_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * Authenticators are encrypted with usage
	 * == 7 or
	 * == 11
	 */
	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, pinfo, 7, length, tvb_get_ptr(tvb, offset, length), authenticator_etype);
	}
	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, pinfo, 11, length, tvb_get_ptr(tvb, offset, length), authenticator_etype);
	}

	if(plaintext){
		tvbuff_t *next_tvb;
		next_tvb = tvb_new_real_data (plaintext,
                                          length,
                                          length);
		tvb_set_child_real_data_tvbuff(tvb, next_tvb);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(pinfo, next_tvb, "Decrypted Krb5");


		offset=dissect_ber_choice(pinfo, tree, next_tvb, 0, kerberos_applications_choice, -1, -1, NULL);

	}
	return offset;
}
#endif


/*
 *  EncryptedData ::=   SEQUENCE {
 *                      etype[0]     INTEGER, -- EncryptionType
 *                      kvno[1]      INTEGER OPTIONAL,
 *                      cipher[2]    OCTET STRING -- ciphertext
 *  }
 */
static int
dissect_krb5_encrypted_authenticator_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_authenticator_data, dissect_krb5_decrypt_authenticator_data);
#else
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_authenticator_data, NULL);
#endif
	return offset;
}
static ber_sequence_t encrypted_authenticator_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_authenticator_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_authenticator_data },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_encrypted_authenticator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, encrypted_authenticator_sequence, hf_krb_authenticator_enc, ett_krb_authenticator_enc);

	return offset;
}




static int
dissect_krb5_tkt_vno(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_tkt_vno, NULL);
	return offset;
}


#ifdef HAVE_KERBEROS
static int
dissect_krb5_decrypt_Ticket_data (packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint8 *plaintext;
	int length;

	length=tvb_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * All Ticket encrypted parts use usage == 2
	 */
	if( (plaintext=decrypt_krb5_data(tree, pinfo, 2, length, tvb_get_ptr(tvb, offset, length), Ticket_etype)) ){
		tvbuff_t *next_tvb;
		next_tvb = tvb_new_real_data (plaintext,
                                          length,
                                          length);
		tvb_set_child_real_data_tvbuff(tvb, next_tvb);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(pinfo, next_tvb, "Decrypted Krb5");


		offset=dissect_ber_choice(pinfo, tree, next_tvb, 0, kerberos_applications_choice, -1, -1, NULL);

	}
	return offset;
}
#endif

static int
dissect_krb5_encrypted_Ticket_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_Ticket_data, dissect_krb5_decrypt_Ticket_data);
#else
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_Ticket_data, NULL);
#endif
	return offset;
}
static ber_sequence_t encrypted_Ticket_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_Ticket_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_Ticket_data },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_Ticket_encrypted(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, encrypted_Ticket_sequence, hf_krb_ticket_enc, ett_krb_ticket_enc);

	return offset;
}

static ber_sequence_t Application_1_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_tkt_vno },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_realm },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_sname },
	{ BER_CLASS_CON, 3, 0,
		dissect_krb5_Ticket_encrypted },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_Application_1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, Application_1_sequence, hf_krb_ticket, ett_krb_ticket);

	return offset;
}



static const ber_choice_t Ticket_choice[] = {
	{ 1, BER_CLASS_APP, 1,  0,
		dissect_krb5_Application_1 },
	{ 0, 0, 0, 0, NULL }
};
static int
dissect_krb5_Ticket(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_choice(pinfo, tree, tvb, offset, Ticket_choice, -1, -1, NULL);

	return offset;
}




/*
 *  AP-REQ ::=      [APPLICATION 14] SEQUENCE {
 *                  pvno[0]                       INTEGER,
 *                  msg-type[1]                   INTEGER,
 *                  ap-options[2]                 APOptions,
 *                  ticket[3]                     Ticket,
 *                  authenticator[4]              EncryptedData
 *  }
 */
static ber_sequence_t AP_REQ_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_APOptions },
	{ BER_CLASS_CON, 3, 0,
		dissect_krb5_Ticket },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_encrypted_authenticator },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_AP_REQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, AP_REQ_sequence, -1, -1);

	return offset;
}




#ifdef HAVE_KERBEROS
static int
dissect_krb5_decrypt_AP_REP_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint8 *plaintext=NULL;
	int length;

	length=tvb_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * Authenticators are encrypted with usage
	 * == 7 or
	 * == 11
	 */
	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, pinfo, 12, length, tvb_get_ptr(tvb, offset, length), AP_REP_etype);
	}

	if(plaintext){
		tvbuff_t *next_tvb;
		next_tvb = tvb_new_real_data (plaintext,
                                          length,
                                          length);
		tvb_set_child_real_data_tvbuff(tvb, next_tvb);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(pinfo, next_tvb, "Decrypted Krb5");


		offset=dissect_ber_choice(pinfo, tree, next_tvb, 0, kerberos_applications_choice, -1, -1, NULL);

	}
	return offset;
}
#endif


static int
dissect_krb5_encrypted_AP_REP_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_AP_REP_data, dissect_krb5_decrypt_AP_REP_data);
#else
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_AP_REP_data, NULL);
#endif
	return offset;
}
static ber_sequence_t encrypted_AP_REP_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_AP_REP_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_AP_REP_data },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_encrypted_AP_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, encrypted_AP_REP_sequence, hf_krb_AP_REP_enc, ett_krb_AP_REP_enc);

	return offset;
}

/*
 *  AP-REP ::=         [APPLICATION 15] SEQUENCE {
 *             pvno[0]                   INTEGER,
 *             msg-type[1]               INTEGER,
 *             enc-part[2]               EncryptedData
 *  }
 */
static ber_sequence_t AP_REP_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_AP_REP },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_AP_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, AP_REP_sequence, -1, -1);

	return offset;
}





static guint32 KDC_REP_etype;
static int
dissect_krb5_KDC_REP_etype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_krb_etype, &KDC_REP_etype);
	if(tree){
		proto_item_append_text(tree, " %s",
			val_to_str(KDC_REP_etype, krb5_encryption_types,
			"%#x"));
	}
	return offset;
}

#ifdef HAVE_KERBEROS
static int
dissect_krb5_decrypt_KDC_REP_data (packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	guint8 *plaintext=NULL;
	int length;

	length=tvb_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * ASREP/TGSREP encryptedparts are encrypted with usage
	 * == 3 or
	 * == 8 or
         * == 9
	 */
	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, pinfo, 3, length, tvb_get_ptr(tvb, offset, length), KDC_REP_etype);
	}
	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, pinfo, 8, length, tvb_get_ptr(tvb, offset, length), KDC_REP_etype);
	}
	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, pinfo, 9, length, tvb_get_ptr(tvb, offset, length), KDC_REP_etype);
	}

	if(plaintext){
		tvbuff_t *next_tvb;
		next_tvb = tvb_new_real_data (plaintext,
                                          length,
                                          length);
		tvb_set_child_real_data_tvbuff(tvb, next_tvb);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(pinfo, next_tvb, "Decrypted Krb5");


		offset=dissect_ber_choice(pinfo, tree, next_tvb, 0, kerberos_applications_choice, -1, -1, NULL);

	}
	return offset;
}
#endif


static int
dissect_krb5_encrypted_KDC_REP_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
#ifdef HAVE_KERBEROS
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_KDC_REP_data, dissect_krb5_decrypt_KDC_REP_data);
#else
	offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_encrypted_KDC_REP_data, NULL);
#endif
	return offset;
}
static ber_sequence_t encrypted_KDC_REP_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_KDC_REP_etype },
	{ BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL,
		dissect_krb5_kvno },
	{ BER_CLASS_CON, 2, 0,
		dissect_krb5_encrypted_KDC_REP_data },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_encrypted_KDC_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, encrypted_KDC_REP_sequence, hf_krb_KDC_REP_enc, ett_krb_KDC_REP_enc);

	return offset;
}

/*
 *  KDC-REP ::=   SEQUENCE {
 *                pvno[0]                    INTEGER,
 *                msg-type[1]                INTEGER,
 *                padata[2]                  SEQUENCE OF PA-DATA OPTIONAL,
 *                crealm[3]                  Realm,
 *                cname[4]                   PrincipalName,
 *                ticket[5]                  Ticket,
 *                enc-part[6]                EncryptedData
 *  }
 */
static ber_sequence_t KDC_REP_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL,
		dissect_krb5_padata },
	{ BER_CLASS_CON, 3, 0,
		dissect_krb5_crealm },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_cname },
	{ BER_CLASS_CON, 5, 0,
		dissect_krb5_Ticket },
	{ BER_CLASS_CON, 6, 0,
		dissect_krb5_encrypted_KDC_REP },
	{ 0, 0, 0, NULL }
};
static int
dissect_krb5_KDC_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, KDC_REP_sequence, -1, -1);

	return offset;
}




static int
dissect_krb5_e_text(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_GeneralString(pinfo, tree, tvb, offset, hf_krb_e_text, NULL, 0);
	return offset;
}

static int
dissect_krb5_e_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	switch(krb5_errorcode){
	case KRB5_ET_KRB5KDC_ERR_PREAUTH_REQUIRED:
		offset=dissect_ber_octet_string_wcb(FALSE, pinfo, tree, tvb, offset, hf_krb_e_data, dissect_krb5_padata);

		break;
	default:
		offset=dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_krb_e_data, NULL);
	}
	return offset;
}


/* This optional field in KRB_ERR is used by the early drafts which
 * PacketCable still use.
 */
static int
dissect_krb5_e_checksum(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, Checksum_sequence, hf_krb_e_checksum, ett_krb_e_checksum);

	return offset;
}


/*
 *  KRB-ERROR ::=   [APPLICATION 30] SEQUENCE {
 *                  pvno[0]               INTEGER,
 *                  msg-type[1]           INTEGER,
 *                  ctime[2]              KerberosTime OPTIONAL,
 *                  cusec[3]              INTEGER OPTIONAL,
 *                  stime[4]              KerberosTime,
 *                  susec[5]              INTEGER,
 *                  error-code[6]         INTEGER,
 *                  crealm[7]             Realm OPTIONAL,
 *                  cname[8]              PrincipalName OPTIONAL,
 *                  realm[9]              Realm, -- Correct realm
 *                  sname[10]             PrincipalName, -- Correct name
 *                  e-text[11]            GeneralString OPTIONAL,
 *                  e-data[12]            OCTET STRING OPTIONAL
 *  }
 *
 *  e-data    This field contains additional data about the error for use
 *            by the application to help it recover from or handle the
 *            error.  If the errorcode is KDC_ERR_PREAUTH_REQUIRED, then
 *            the e-data field will contain an encoding of a sequence of
 *            padata fields, each corresponding to an acceptable pre-
 *            authentication method and optionally containing data for
 *            the method:
 */
static ber_sequence_t ERROR_sequence[] = {
	{ BER_CLASS_CON, 0, 0,
		dissect_krb5_pvno },
	{ BER_CLASS_CON, 1, 0,
		dissect_krb5_msg_type },
	{ BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL,
		dissect_krb5_ctime },
	{ BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL,
		dissect_krb5_cusec },
	{ BER_CLASS_CON, 4, 0,
		dissect_krb5_stime },
	{ BER_CLASS_CON, 5, 0,
		dissect_krb5_susec },
	{ BER_CLASS_CON, 6, 0,
		dissect_krb5_error_code },
	{ BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL,
		dissect_krb5_crealm },
	{ BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL,
		dissect_krb5_cname },
	{ BER_CLASS_CON, 9, 0,
		dissect_krb5_realm },
	{ BER_CLASS_CON, 10, 0,
		dissect_krb5_sname },
	{ BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL,
		dissect_krb5_e_text },
	{ BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL,
		dissect_krb5_e_data },
	{ BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL,
		dissect_krb5_e_checksum }, /* used by PacketCable */
	{ 0, 0, 0, NULL }
};
int
dissect_krb5_ERROR(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset)
{
	offset=dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset, ERROR_sequence, -1, -1);

	return offset;
}



static struct { const char *set; const char *unset; } bitval = { "Set", "Not set" };

static gint dissect_kerberos_udp(tvbuff_t *tvb, packet_info *pinfo,
				 proto_tree *tree);
static void dissect_kerberos_tcp(tvbuff_t *tvb, packet_info *pinfo,
				 proto_tree *tree);
static gint dissect_kerberos_common(tvbuff_t *tvb, packet_info *pinfo,
					proto_tree *tree, gboolean do_col_info,
					gboolean do_col_protocol,
					gboolean have_rm,
					kerberos_callbacks *cb);
static gint kerberos_rm_to_reclen(guint krb_rm);
static void dissect_kerberos_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo,
				proto_tree *tree);
static guint get_krb_pdu_len(tvbuff_t *tvb, int offset);



gint
dissect_kerberos_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int do_col_info, kerberos_callbacks *cb)
{
    return (dissect_kerberos_common(tvb, pinfo, tree, do_col_info, FALSE, FALSE, cb));
}

guint32 
kerberos_output_keytype(void)
{
  return keytype;
}

static gint
dissect_kerberos_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    /* Some weird kerberos implementation apparently do krb4 on the krb5 port.
       Since all (except weirdo transarc krb4 stuff) use 
       an opcode <=16 in the first byte, use this to see if it might
       be krb4.
       All krb5 commands start with an APPL tag and thus is >=0x60
       so if first byte is <=16  just blindly assume it is krb4 then
    */
    if(tvb_bytes_exist(tvb, 0, 1) && tvb_get_guint8(tvb, 0)<=0x10){
      if(krb4_handle){ 
	return call_dissector(krb4_handle, tvb, pinfo, tree);
      }else{
        return 0;
      }
    }


    return dissect_kerberos_common(tvb, pinfo, tree, TRUE, TRUE, FALSE, NULL);
}

static gint
kerberos_rm_to_reclen(guint krb_rm)
{
    return (krb_rm & KRB_RM_RECLEN);
}

static guint
get_krb_pdu_len(tvbuff_t *tvb, int offset)
{
    guint krb_rm;
    gint pdulen;

    krb_rm = tvb_get_ntohl(tvb, offset);
    pdulen = kerberos_rm_to_reclen(krb_rm);
    return (pdulen + 4);
}

static void
dissect_kerberos_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    pinfo->fragmented = TRUE;
    if (dissect_kerberos_common(tvb, pinfo, tree, TRUE, TRUE, TRUE, NULL) < 0) {
	/*
	 * The dissector failed to recognize this as a valid
	 * Kerberos message.  Mark it as a continuation packet.
	 */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
	}
    }
}

static void
dissect_kerberos_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");
    if (check_col(pinfo->cinfo, COL_INFO))
        col_clear(pinfo->cinfo, COL_INFO);

    tcp_dissect_pdus(tvb, pinfo, tree, krb_desegment, 4, get_krb_pdu_len,
	dissect_kerberos_tcp_pdu);
}

/*
 * Display the TCP record mark.
 */
static void
show_krb_recordmark(proto_tree *tree, tvbuff_t *tvb, gint start, guint32 krb_rm)
{
    gint rec_len;
    proto_item *rm_item;
    proto_tree *rm_tree;

    if (tree == NULL)
	return;

    rec_len = kerberos_rm_to_reclen(krb_rm);
    rm_item = proto_tree_add_text(tree, tvb, start, 4,
	"Record Mark: %u %s", rec_len, plurality(rec_len, "byte", "bytes"));
    rm_tree = proto_item_add_subtree(rm_item, ett_krb_recordmark);
    proto_tree_add_boolean(rm_tree, hf_krb_rm_reserved, tvb, start, 4, krb_rm);
    proto_tree_add_uint(rm_tree, hf_krb_rm_reclen, tvb, start, 4, krb_rm);
}


static gint
dissect_kerberos_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean dci, gboolean do_col_protocol, gboolean have_rm,
    kerberos_callbacks *cb)
{
    int offset = 0;
    proto_tree *kerberos_tree = NULL;
    proto_item *item = NULL;
    void *saved_private_data;

    /* TCP record mark and length */
    guint32 krb_rm = 0;
    gint krb_reclen = 0;

    saved_private_data=pinfo->private_data;
    pinfo->private_data=cb;
    do_col_info=dci;

    if (have_rm) {
	krb_rm = tvb_get_ntohl(tvb, offset);
	krb_reclen = kerberos_rm_to_reclen(krb_rm);
	/*
	 * What is a reasonable size limit?
	 */
	if (krb_reclen > 10 * 1024 * 1024) {
	    pinfo->private_data=saved_private_data;
	    return (-1);
	}
	if (do_col_protocol) {
            if (check_col(pinfo->cinfo, COL_PROTOCOL))
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");
	}
        if (tree) {
            item = proto_tree_add_item(tree, proto_kerberos, tvb, 0, -1, FALSE);
            kerberos_tree = proto_item_add_subtree(item, ett_krb_kerberos);
        }
	show_krb_recordmark(kerberos_tree, tvb, offset, krb_rm);
	offset += 4;
    } else {
        /* Do some sanity checking here, 
         * All krb5 packets start with a TAG class that is BER_CLASS_APP
         * and a tag value that is either of the values below:
         * If it doesnt look like kerberos, return 0 and let someone else have
         * a go at it.
         */
        gint8 tmp_class;
        gboolean tmp_pc;
        gint32 tmp_tag;

	get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);
        if(tmp_class!=BER_CLASS_APP){
            return 0;
        }
        switch(tmp_tag){
            case KRB5_MSG_TICKET:
            case KRB5_MSG_AUTHENTICATOR:
            case KRB5_MSG_ENC_TICKET_PART:
            case KRB5_MSG_AS_REQ:
            case KRB5_MSG_AS_REP:
            case KRB5_MSG_TGS_REQ:
            case KRB5_MSG_TGS_REP:
            case KRB5_MSG_AP_REQ:
            case KRB5_MSG_AP_REP:
            case KRB5_MSG_ENC_AS_REP_PART:
            case KRB5_MSG_ENC_TGS_REP_PART:
            case KRB5_MSG_ENC_AP_REP_PART:
            case KRB5_MSG_ENC_KRB_PRIV_PART:
            case KRB5_MSG_SAFE:
            case KRB5_MSG_PRIV:
            case KRB5_MSG_ERROR:
                break;
            default:
                return 0;
        }
	if (do_col_protocol) {
            if (check_col(pinfo->cinfo, COL_PROTOCOL))
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");
	}
	if (do_col_info) {
            if (check_col(pinfo->cinfo, COL_INFO))
                col_clear(pinfo->cinfo, COL_INFO);
        }
        if (tree) {
            item = proto_tree_add_item(tree, proto_kerberos, tvb, 0, -1, FALSE);
            kerberos_tree = proto_item_add_subtree(item, ett_krb_kerberos);
        }
    }

    TRY {
	offset=dissect_ber_choice(pinfo, kerberos_tree, tvb, offset, kerberos_applications_choice, -1, -1, NULL);
    } CATCH_ALL {
	pinfo->private_data=saved_private_data;
	RETHROW;
    } ENDTRY;

    proto_item_set_len(item, offset);
    pinfo->private_data=saved_private_data;
    return offset;
}

static void
kerberos_prefs_apply_cb(void) {
#ifdef HAVE_LIBNETTLE
	clear_keytab();
	read_keytab_file(keytab_filename);
#endif
}

void
proto_register_kerberos(void)
{
    static hf_register_info hf[] = {
	{ &hf_krb_rm_reserved, {
	    "Reserved", "kerberos.rm.reserved", FT_BOOLEAN, 32,
	    &bitval, KRB_RM_RESERVED, "Record mark reserved bit", HFILL }},
	{ &hf_krb_rm_reclen, {
	    "Record Length", "kerberos.rm.length", FT_UINT32, BASE_DEC,
	    NULL, KRB_RM_RECLEN, "Record length", HFILL }},
	{ &hf_krb_transitedtype, {
	    "Type", "kerberos.transited.type", FT_UINT32, BASE_DEC,
	    VALS(krb5_transited_types), 0, "Transited Type", HFILL }},
	{ &hf_krb_transitedcontents, {
	    "Contents", "kerberos.transited.contents", FT_BYTES, BASE_HEX,
	    NULL, 0, "Transitent Contents string", HFILL }},
	{ &hf_krb_keytype, {
	    "Key type", "kerberos.keytype", FT_UINT32, BASE_DEC,
	    VALS(krb5_encryption_types), 0, "Key Type", HFILL }},
	{ &hf_krb_keyvalue, {
	    "Key value", "kerberos.keyvalue", FT_BYTES, BASE_HEX,
	    NULL, 0, "Key value (encryption key)", HFILL }},
	{ &hf_krb_adtype, {
	    "Type", "kerberos.adtype", FT_UINT32, BASE_DEC,
	    VALS(krb5_ad_types), 0, "Authorization Data Type", HFILL }},
	{ &hf_krb_IF_RELEVANT_type, {
	    "Type", "kerberos.IF_RELEVANT.type", FT_UINT32, BASE_DEC,
	    VALS(krb5_ad_types), 0, "IF-RELEVANT Data Type", HFILL }},
	{ &hf_krb_advalue, {
	    "Data", "kerberos.advalue", FT_BYTES, BASE_HEX,
	    NULL, 0, "Authentication Data", HFILL }},
	{ &hf_krb_IF_RELEVANT_value, {
	    "Data", "kerberos.IF_RELEVANT.value", FT_BYTES, BASE_HEX,
	    NULL, 0, "IF_RELEVANT Data", HFILL }},
	{ &hf_krb_etype, {
	    "Encryption type", "kerberos.etype", FT_INT32, BASE_DEC,
	    VALS(krb5_encryption_types), 0, "Encryption Type", HFILL }},
	{ &hf_krb_addr_type, {
	    "Addr-type", "kerberos.addr_type", FT_UINT32, BASE_DEC,
	    VALS(krb5_address_types), 0, "Address Type", HFILL }},
	{ &hf_krb_pac_signature_type, {
	    "Type", "kerberos.pac.signature.type", FT_INT32, BASE_DEC,
	    NULL, 0, "PAC Signature Type", HFILL }},
	{ &hf_krb_name_type, {
	    "Name-type", "kerberos.name_type", FT_INT32, BASE_DEC,
	    VALS(krb5_princ_types), 0, "Type of principal name", HFILL }},
	{ &hf_krb_lr_type, {
	    "Lr-type", "kerberos.lr_type", FT_UINT32, BASE_DEC,
	    VALS(krb5_lr_types), 0, "Type of lastreq value", HFILL }},
	{ &hf_krb_address_ip, {
	    "IP Address", "kerberos.addr_ip", FT_IPv4, BASE_NONE,
	    NULL, 0, "IP Address", HFILL }},
	{ &hf_krb_address_netbios, {
	    "NetBIOS Address", "kerberos.addr_nb", FT_STRING, BASE_NONE,
	    NULL, 0, "NetBIOS Address and type", HFILL }},
	{ &hf_krb_authtime, {
	    "Authtime", "kerberos.authtime", FT_STRING, BASE_NONE,
	    NULL, 0, "Time of initial authentication", HFILL }},
	{ &hf_krb_SAFE_BODY_timestamp, {
	    "Timestamp", "kerberos.SAFE_BODY.timestamp", FT_STRING, BASE_NONE,
	    NULL, 0, "Timestamp of this SAFE_BODY", HFILL }},
	{ &hf_krb_patimestamp, {
	    "patimestamp", "kerberos.patimestamp", FT_STRING, BASE_NONE,
	    NULL, 0, "Time of client", HFILL }},
	{ &hf_krb_pausec, {
	    "pausec", "kerberos.pausec", FT_UINT32, BASE_DEC,
	    NULL, 0, "Microsecond component of client time", HFILL }},
	{ &hf_krb_lr_time, {
	    "Lr-time", "kerberos.lr_time", FT_STRING, BASE_NONE,
	    NULL, 0, "Time of LR-entry", HFILL }},
	{ &hf_krb_starttime, {
	    "Start time", "kerberos.starttime", FT_STRING, BASE_NONE,
	    NULL, 0, "The time after which the ticket is valid", HFILL }},
	{ &hf_krb_endtime, {
	    "End time", "kerberos.endtime", FT_STRING, BASE_NONE,
	    NULL, 0, "The time after which the ticket has expired", HFILL }},
	{ &hf_krb_key_expire, {
	    "Key Expiration", "kerberos.key_expiration", FT_STRING, BASE_NONE,
	    NULL, 0, "The time after which the key will expire", HFILL }},
	{ &hf_krb_renew_till, {
	    "Renew-till", "kerberos.renenw_till", FT_STRING, BASE_NONE,
	    NULL, 0, "The maximum time we can renew the ticket until", HFILL }},
	{ &hf_krb_rtime, {
	    "rtime", "kerberos.rtime", FT_STRING, BASE_NONE,
	    NULL, 0, "Renew Until timestamp", HFILL }},
	{ &hf_krb_ctime, {
	    "ctime", "kerberos.ctime", FT_STRING, BASE_NONE,
	    NULL, 0, "Current Time on the client host", HFILL }},
	{ &hf_krb_cusec, {
	    "cusec", "kerberos.cusec", FT_UINT32, BASE_DEC,
	    NULL, 0, "micro second component of client time", HFILL }},
	{ &hf_krb_SAFE_BODY_usec, {
	    "usec", "kerberos.SAFE_BODY.usec", FT_UINT32, BASE_DEC,
	    NULL, 0, "micro second component of SAFE_BODY time", HFILL }},
	{ &hf_krb_stime, {
	    "stime", "kerberos.stime", FT_STRING, BASE_NONE,
	    NULL, 0, "Current Time on the server host", HFILL }},
	{ &hf_krb_susec, {
	    "susec", "kerberos.susec", FT_UINT32, BASE_DEC,
	    NULL, 0, "micro second component of server time", HFILL }},
	{ &hf_krb_error_code, {
	    "error_code", "kerberos.error_code", FT_UINT32, BASE_DEC,
	    VALS(krb5_error_codes), 0, "Kerberos error code", HFILL }},
	{ &hf_krb_from, {
	    "from", "kerberos.from", FT_STRING, BASE_NONE,
	    NULL, 0, "From when the ticket is to be valid (postdating)", HFILL }},
	{ &hf_krb_till, {
	    "till", "kerberos.till", FT_STRING, BASE_NONE,
	    NULL, 0, "When the ticket will expire", HFILL }},
	{ &hf_krb_name_string, {
	    "Name", "kerberos.name_string", FT_STRING, BASE_NONE,
	    NULL, 0, "String component that is part of a PrincipalName", HFILL }},
	{ &hf_krb_provsrv_location, {
	    "PROVSRV Location", "kerberos.provsrv_location", FT_STRING, BASE_NONE,
	    NULL, 0, "PacketCable PROV SRV Location", HFILL }},
	{ &hf_krb_e_text, {
	    "e-text", "kerberos.e_text", FT_STRING, BASE_NONE,
	    NULL, 0, "Additional (human readable) error description", HFILL }},
	{ &hf_krb_realm, {
	    "Realm", "kerberos.realm", FT_STRING, BASE_NONE,
	    NULL, 0, "Name of the Kerberos Realm", HFILL }},
	{ &hf_krb_crealm, {
	    "Client Realm", "kerberos.crealm", FT_STRING, BASE_NONE,
	    NULL, 0, "Name of the Clients Kerberos Realm", HFILL }},
	{ &hf_krb_pac_clientname, {
	    "Name", "kerberos.pac.name", FT_STRING, BASE_NONE,
	    NULL, 0, "Name of the Client in the PAC structure", HFILL }},
	{ &hf_krb_msg_type, {
	    "MSG Type", "kerberos.msg.type", FT_UINT32, BASE_DEC,
	    VALS(krb5_msg_types), 0, "Kerberos Message Type", HFILL }},
	{ &hf_krb_APOptions, {
	    "APOptions", "kerberos.apoptions", FT_BYTES, BASE_HEX,
	    NULL, 0, "Kerberos APOptions bitstring", HFILL }},
	{ &hf_krb_APOptions_use_session_key, {
	    "Use Session Key", "kerberos.apoptions.use_session_key", FT_BOOLEAN, 32,
	    TFS(&krb5_apoptions_use_session_key), 0x40000000, "", HFILL }},
	{ &hf_krb_APOptions_mutual_required, {
	    "Mutual required", "kerberos.apoptions.mutual_required", FT_BOOLEAN, 32,
	    TFS(&krb5_apoptions_mutual_required), 0x20000000, "", HFILL }},
	{ &hf_krb_KDCOptions, {
	    "KDCOptions", "kerberos.kdcoptions", FT_BYTES, BASE_HEX,
	    NULL, 0, "Kerberos KDCOptions bitstring", HFILL }},
	{ &hf_krb_TicketFlags, {
	    "Ticket Flags", "kerberos.ticketflags", FT_NONE, BASE_NONE,
	    NULL, 0, "Kerberos Ticket Flags", HFILL }},
	{ &hf_krb_TicketFlags_forwardable, {
	    "Forwardable", "kerberos.ticketflags.forwardable", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_forwardable), 0x40000000, "Flag controlling whether the tickes are forwardable or not", HFILL }},
	{ &hf_krb_TicketFlags_forwarded, {
	    "Forwarded", "kerberos.ticketflags.forwarded", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_forwarded), 0x20000000, "Has this ticket been forwarded?", HFILL }},
	{ &hf_krb_TicketFlags_proxyable, {
	    "Proxyable", "kerberos.ticketflags.proxyable", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_proxyable), 0x10000000, "Flag controlling whether the tickes are proxyable or not", HFILL }},
	{ &hf_krb_TicketFlags_proxy, {
	    "Proxy", "kerberos.ticketflags.proxy", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_proxy), 0x08000000, "Has this ticket been proxied?", HFILL }},
	{ &hf_krb_TicketFlags_allow_postdate, {
	    "Allow Postdate", "kerberos.ticketflags.allow_postdate", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_allow_postdate), 0x04000000, "Flag controlling whether we allow postdated tickets or not", HFILL }},
	{ &hf_krb_TicketFlags_postdated, {
	    "Postdated", "kerberos.ticketflags.postdated", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_postdated), 0x02000000, "Whether this ticket is postdated or not", HFILL }},
	{ &hf_krb_TicketFlags_invalid, {
	    "Invalid", "kerberos.ticketflags.invalid", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_invalid), 0x01000000, "Whether this ticket is invalid or not", HFILL }},
	{ &hf_krb_TicketFlags_renewable, {
	    "Renewable", "kerberos.ticketflags.renewable", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_renewable), 0x00800000, "Whether this ticket is renewable or not", HFILL }},
	{ &hf_krb_TicketFlags_initial, {
	    "Initial", "kerberos.ticketflags.initial", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_initial), 0x00400000, "Whether this ticket is an initial ticket or not", HFILL }},
	{ &hf_krb_TicketFlags_pre_auth, {
	    "Pre-Auth", "kerberos.ticketflags.pre_auth", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_pre_auth), 0x00200000, "Whether this ticket is pre-authenticated or not", HFILL }},
	{ &hf_krb_TicketFlags_hw_auth, {
	    "HW-Auth", "kerberos.ticketflags.hw_auth", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_hw_auth), 0x00100000, "Whether this ticket is hardware-authenticated or not", HFILL }},
	{ &hf_krb_TicketFlags_transited_policy_checked, {
	    "Transited Policy Checked", "kerberos.ticketflags.transited_policy_checked", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_transited_policy_checked), 0x00080000, "Whether this ticket is transited policy checked or not", HFILL }},
	{ &hf_krb_TicketFlags_ok_as_delegate, {
	    "Ok As Delegate", "kerberos.ticketflags.ok_as_delegate", FT_BOOLEAN, 32,
	    TFS(&krb5_ticketflags_ok_as_delegate), 0x00040000, "Whether this ticket is Ok As Delegate or not", HFILL }},
	{ &hf_krb_KDC_REQ_BODY, {
	    "KDC_REQ_BODY", "kerberos.kdc_req_body", FT_NONE, BASE_NONE,
	    NULL, 0, "Kerberos KDC REQuest BODY", HFILL }},
	{ &hf_krb_PRIV_BODY, {
	    "PRIV_BODY", "kerberos.priv_body", FT_NONE, BASE_NONE,
	    NULL, 0, "Kerberos PRIVate BODY", HFILL }},
	{ &hf_krb_encrypted_PRIV, {
	    "Encrypted PRIV", "kerberos.enc_priv", FT_NONE, BASE_NONE,
	    NULL, 0, "Kerberos Encrypted PRIVate blob data", HFILL }},
	{ &hf_krb_KDCOptions_forwardable, {
	    "Forwardable", "kerberos.kdcoptions.forwardable", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_forwardable), 0x40000000, "Flag controlling whether the tickes are forwardable or not", HFILL }},
	{ &hf_krb_KDCOptions_forwarded, {
	    "Forwarded", "kerberos.kdcoptions.forwarded", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_forwarded), 0x20000000, "Has this ticket been forwarded?", HFILL }},
	{ &hf_krb_KDCOptions_proxyable, {
	    "Proxyable", "kerberos.kdcoptions.proxyable", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_proxyable), 0x10000000, "Flag controlling whether the tickes are proxyable or not", HFILL }},
	{ &hf_krb_KDCOptions_proxy, {
	    "Proxy", "kerberos.kdcoptions.proxy", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_proxy), 0x08000000, "Has this ticket been proxied?", HFILL }},
	{ &hf_krb_KDCOptions_allow_postdate, {
	    "Allow Postdate", "kerberos.kdcoptions.allow_postdate", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_allow_postdate), 0x04000000, "Flag controlling whether we allow postdated tickets or not", HFILL }},
	{ &hf_krb_KDCOptions_postdated, {
	    "Postdated", "kerberos.kdcoptions.postdated", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_postdated), 0x02000000, "Whether this ticket is postdated or not", HFILL }},
	{ &hf_krb_KDCOptions_renewable, {
	    "Renewable", "kerberos.kdcoptions.renewable", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_renewable), 0x00800000, "Whether this ticket is renewable or not", HFILL }},
	{ &hf_krb_KDCOptions_canonicalize, {
	    "Canonicalize", "kerberos.kdcoptions.canonicalize", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_canonicalize), 0x00010000, "Do we want the KDC to canonicalize the principal or not", HFILL }},
	{ &hf_krb_KDCOptions_opt_hardware_auth, {
	    "Opt HW Auth", "kerberos.kdcoptions.opt_hardware_auth", FT_BOOLEAN, 32,
	    NULL, 0x00100000, "Opt HW Auth flag", HFILL }},
	{ &hf_krb_KDCOptions_disable_transited_check, {
	    "Disable Transited Check", "kerberos.kdcoptions.disable_transited_check", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_disable_transited_check), 0x00000020, "Whether we should do transited checking or not", HFILL }},
	{ &hf_krb_KDCOptions_renewable_ok, {
	    "Renewable OK", "kerberos.kdcoptions.renewable_ok", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_renewable_ok), 0x00000010, "Whether we accept renewed tickets or not", HFILL }},
	{ &hf_krb_KDCOptions_enc_tkt_in_skey, {
	    "Enc-Tkt-in-Skey", "kerberos.kdcoptions.enc_tkt_in_skey", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_enc_tkt_in_skey), 0x00000008, "Whether the ticket is encrypted in the skey or not", HFILL }},
	{ &hf_krb_KDCOptions_renew, {
	    "Renew", "kerberos.kdcoptions.renew", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_renew), 0x00000002, "Is this a request to renew a ticket?", HFILL }},
	{ &hf_krb_KDCOptions_validate, {
	    "Validate", "kerberos.kdcoptions.validate", FT_BOOLEAN, 32,
	    TFS(&krb5_kdcoptions_validate), 0x00000001, "Is this a request to validate a postdated ticket?", HFILL }},
	{ &hf_krb_pvno, {
	    "Pvno", "kerberos.pvno", FT_UINT32, BASE_DEC,
	    NULL, 0, "Kerberos Protocol Version Number", HFILL }},
	{ &hf_krb_kvno, {
	    "Kvno", "kerberos.kvno", FT_UINT32, BASE_DEC,
	    NULL, 0, "Version Number for the encryption Key", HFILL }},
	{ &hf_krb_checksum_type, {
	    "Type", "kerberos.checksum.type", FT_UINT32, BASE_DEC,
	    VALS(krb5_checksum_types), 0, "Type of checksum", HFILL }},
	{ &hf_krb_authenticator_vno, {
	    "Authenticator vno", "kerberos.authenticator_vno", FT_UINT32, BASE_DEC,
	    NULL, 0, "Version Number for the Authenticator", HFILL }},
	{ &hf_krb_encrypted_authenticator_data, {
	    "Authenticator data", "kerberos.authenticator.data", FT_BYTES, BASE_HEX,
	    NULL, 0, "Data content of an encrypted authenticator", HFILL }},
	{ &hf_krb_encrypted_PA_ENC_TIMESTAMP, {
	    "enc PA_ENC_TIMESTAMP", "kerberos.PA_ENC_TIMESTAMP.encrypted", FT_BYTES, BASE_HEX,
	    NULL, 0, "Encrypted PA-ENC-TIMESTAMP blob", HFILL }},
	{ &hf_krb_PAC_LOGON_INFO, {
	    "PAC_LOGON_INFO", "kerberos.PAC_LOGON_INFO", FT_BYTES, BASE_HEX,
	    NULL, 0, "PAC_LOGON_INFO structure", HFILL }},
	{ &hf_krb_PAC_CREDENTIAL_TYPE, {
	    "PAC_CREDENTIAL_TYPE", "kerberos.PAC_CREDENTIAL_TYPE", FT_BYTES, BASE_HEX,
	    NULL, 0, "PAC_CREDENTIAL_TYPE structure", HFILL }},
	{ &hf_krb_PAC_SERVER_CHECKSUM, {
	    "PAC_SERVER_CHECKSUM", "kerberos.PAC_SERVER_CHECKSUM", FT_BYTES, BASE_HEX,
	    NULL, 0, "PAC_SERVER_CHECKSUM structure", HFILL }},
	{ &hf_krb_PAC_PRIVSVR_CHECKSUM, {
	    "PAC_PRIVSVR_CHECKSUM", "kerberos.PAC_PRIVSVR_CHECKSUM", FT_BYTES, BASE_HEX,
	    NULL, 0, "PAC_PRIVSVR_CHECKSUM structure", HFILL }},
	{ &hf_krb_PAC_CLIENT_INFO_TYPE, {
	    "PAC_CLIENT_INFO_TYPE", "kerberos.PAC_CLIENT_INFO_TYPE", FT_BYTES, BASE_HEX,
	    NULL, 0, "PAC_CLIENT_INFO_TYPE structure", HFILL }},
	{ &hf_krb_checksum_checksum, {
	    "checksum", "kerberos.checksum.checksum", FT_BYTES, BASE_HEX,
	    NULL, 0, "Kerberos Checksum", HFILL }},
	{ &hf_krb_ENC_PRIV, {
	    "enc PRIV", "kerberos.ENC_PRIV", FT_BYTES, BASE_HEX,
	    NULL, 0, "Encrypted PRIV blob", HFILL }},
	{ &hf_krb_encrypted_Ticket_data, {
	    "enc-part", "kerberos.ticket.data", FT_BYTES, BASE_HEX,
	    NULL, 0, "The encrypted part of a ticket", HFILL }},
	{ &hf_krb_encrypted_AP_REP_data, {
	    "enc-part", "kerberos.aprep.data", FT_BYTES, BASE_HEX,
	    NULL, 0, "The encrypted part of AP-REP", HFILL }},
	{ &hf_krb_encrypted_KDC_REP_data, {
	    "enc-part", "kerberos.kdcrep.data", FT_BYTES, BASE_HEX,
	    NULL, 0, "The encrypted part of KDC-REP", HFILL }},
	{ &hf_krb_PA_DATA_value, {
	    "Value", "kerberos.padata.value", FT_BYTES, BASE_HEX,
	    NULL, 0, "Content of the PADATA blob", HFILL }},
	{ &hf_krb_etype_info_salt, {
	    "Salt", "kerberos.etype_info.salt", FT_BYTES, BASE_HEX,
	    NULL, 0, "Salt", HFILL }},
	{ &hf_krb_etype_info2_salt, {
	    "Salt", "kerberos.etype_info2.salt", FT_BYTES, BASE_HEX,
	    NULL, 0, "Salt", HFILL }},
	{ &hf_krb_etype_info2_s2kparams, {
	    "Salt", "kerberos.etype_info.s2kparams", FT_BYTES, BASE_HEX,
	    NULL, 0, "S2kparams", HFILL }},
	{ &hf_krb_SAFE_BODY_user_data, {
	    "User Data", "kerberos.SAFE_BODY.user_data", FT_BYTES, BASE_HEX,
	    NULL, 0, "SAFE BODY userdata field", HFILL }},
	{ &hf_krb_PRIV_BODY_user_data, {
	    "User Data", "kerberos.PRIV_BODY.user_data", FT_BYTES, BASE_HEX,
	    NULL, 0, "PRIV BODY userdata field", HFILL }},
	{ &hf_krb_pac_signature_signature, {
	    "Signature", "kerberos.pac.signature.signature", FT_BYTES, BASE_HEX,
	    NULL, 0, "A PAC signature blob", HFILL }},
	{ &hf_krb_PA_DATA_type, {
	    "Type", "kerberos.padata.type", FT_UINT32, BASE_DEC,
	    VALS(krb5_preauthentication_types), 0, "Type of preauthentication data", HFILL }},
	{ &hf_krb_nonce, {
	    "Nonce", "kerberos.nonce", FT_UINT32, BASE_DEC,
	    NULL, 0, "Kerberos Nonce random number", HFILL }},
	{ &hf_krb_tkt_vno, {
	    "Tkt-vno", "kerberos.tkt_vno", FT_UINT32, BASE_DEC,
	    NULL, 0, "Version number for the Ticket format", HFILL }},
	{ &hf_krb_HostAddress, {
	    "HostAddress", "kerberos.hostaddress", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a Kerberos HostAddress sequence", HFILL }},
	{ &hf_krb_s_address, {
	    "S-Address", "kerberos.s_address", FT_NONE, BASE_DEC,
	    NULL, 0, "This is the Senders address", HFILL }},
	{ &hf_krb_key, {
	    "key", "kerberos.key", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a Kerberos EncryptionKey sequence", HFILL }},
	{ &hf_krb_subkey, {
	    "Subkey", "kerberos.subkey", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a Kerberos subkey", HFILL }},
	{ &hf_krb_seq_number, {
	    "Seq Number", "kerberos.seq_number", FT_UINT32, BASE_DEC,
	    NULL, 0, "This is a Kerberos sequence number", HFILL }},
	{ &hf_krb_AuthorizationData, {
	    "AuthorizationData", "kerberos.AuthorizationData", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a Kerberos AuthorizationData sequence", HFILL }},
	{ &hf_krb_EncTicketPart, {
	    "EncTicketPart", "kerberos.EncTicketPart", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a decrypted Kerberos EncTicketPart sequence", HFILL }},
	{ &hf_krb_EncAPRepPart, {
	    "EncAPRepPart", "kerberos.EncAPRepPart", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a decrypted Kerberos EncAPRepPart sequence", HFILL }},
	{ &hf_krb_EncKrbPrivPart, {
	    "EncKrbPrivPart", "kerberos.EncKrbPrivPart", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a decrypted Kerberos EncKrbPrivPart sequence", HFILL }},
	{ &hf_krb_EncKDCRepPart, {
	    "EncKDCRepPart", "kerberos.EncKDCRepPart", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a decrypted Kerberos EncKDCRepPart sequence", HFILL }},
	{ &hf_krb_LastReq, {
	    "LastReq", "kerberos.LastReq", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a LastReq sequence", HFILL }},
	{ &hf_krb_Authenticator, {
	    "Authenticator", "kerberos.Authenticator", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a decrypted Kerberos Authenticator sequence", HFILL }},
	{ &hf_krb_Checksum, {
	    "Checksum", "kerberos.Checksum", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a Kerberos Checksum sequence", HFILL }},
	{ &hf_krb_HostAddresses, {
	    "HostAddresses", "kerberos.hostaddresses", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a list of Kerberos HostAddress sequences", HFILL }},
	{ &hf_krb_IF_RELEVANT, {
	    "IF_RELEVANT", "kerberos.if_relevant", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a list of IF-RELEVANT sequences", HFILL }},
	{ &hf_krb_etypes, {
	    "Encryption Types", "kerberos.etypes", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a list of Kerberos encryption types", HFILL }},
	{ &hf_krb_LastReqs, {
	    "LastReqs", "kerberos.LastReqs", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a list of LastReq structures", HFILL }},
	{ &hf_krb_sname, {
	    "Server Name", "kerberos.sname", FT_NONE, BASE_DEC,
	    NULL, 0, "This is the name part server's identity", HFILL }},
	{ &hf_krb_cname, {
	    "Client Name", "kerberos.cname", FT_NONE, BASE_DEC,
	    NULL, 0, "The name part of the client principal identifier", HFILL }},
	{ &hf_krb_authenticator_enc, {
	    "Authenticator", "kerberos.authenticator", FT_NONE, BASE_DEC,
	    NULL, 0, "Encrypted authenticator blob", HFILL }},
	{ &hf_krb_ticket_enc, {
	    "enc-part", "kerberos.ticket.enc_part", FT_NONE, BASE_DEC,
	    NULL, 0, "The structure holding the encrypted part of a ticket", HFILL }},
	{ &hf_krb_AP_REP_enc, {
	    "enc-part", "kerberos.aprep.enc_part", FT_NONE, BASE_DEC,
	    NULL, 0, "The structure holding the encrypted part of AP-REP", HFILL }},
	{ &hf_krb_KDC_REP_enc, {
	    "enc-part", "kerberos.kdcrep.enc_part", FT_NONE, BASE_DEC,
	    NULL, 0, "The structure holding the encrypted part of KDC-REP", HFILL }},
	{ &hf_krb_e_data, {
	    "e-data", "kerberos.e_data", FT_NONE, BASE_DEC,
	    NULL, 0, "The e-data blob", HFILL }},
	{ &hf_krb_padata, {
	    "padata", "kerberos.padata", FT_NONE, BASE_DEC,
	    NULL, 0, "Sequence of preauthentication data", HFILL }},
	{ &hf_krb_ticket, {
	    "Ticket", "kerberos.ticket", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a Kerberos Ticket", HFILL }},
	{ &hf_krb_TransitedEncoding, {
	    "TransitedEncoding", "kerberos.TransitedEncoding", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a Kerberos TransitedEncoding sequence", HFILL }},
	{ &hf_krb_PA_PAC_REQUEST_flag, {
	    "PAC Request", "kerberos.pac_request.flag", FT_UINT32, BASE_DEC,
	    NULL, 0, "This is a MS PAC Request Flag", HFILL }},
	{ &hf_krb_w2k_pac_entries, {
	    "Num Entries", "kerberos.pac.entries", FT_UINT32, BASE_DEC,
	    NULL, 0, "Number of W2k PAC entries", HFILL }},
	{ &hf_krb_w2k_pac_version, {
	    "Version", "kerberos.pac.version", FT_UINT32, BASE_DEC,
	    NULL, 0, "Version of PAC structures", HFILL }},
	{ &hf_krb_w2k_pac_type, {
	    "Type", "kerberos.pac.type", FT_UINT32, BASE_DEC,
	    VALS(w2k_pac_types), 0, "Type of W2k PAC entry", HFILL }},
	{ &hf_krb_w2k_pac_size, {
	    "Size", "kerberos.pac.size", FT_UINT32, BASE_DEC,
	    NULL, 0, "Size of W2k PAC entry", HFILL }},
	{ &hf_krb_w2k_pac_offset, {
	    "Offset", "kerberos.pac.offset", FT_UINT32, BASE_DEC,
	    NULL, 0, "Offset to W2k PAC entry", HFILL }},
	{ &hf_krb_pac_clientid, {
	    "ClientID", "kerberos.pac.clientid", FT_ABSOLUTE_TIME, BASE_NONE,
	    NULL, 0, "ClientID Timestamp", HFILL }},
	{ &hf_krb_pac_namelen, {
	    "Name Length", "kerberos.pac.namelen", FT_UINT16, BASE_DEC,
	    NULL, 0, "Length of client name", HFILL }},
	{ &hf_krb_e_checksum, {
	    "e-checksum", "kerberos.e_checksum", FT_NONE, BASE_DEC,
	    NULL, 0, "This is a Kerberos e-checksum", HFILL }},
    };

    static gint *ett[] = {
        &ett_krb_kerberos,
	&ett_krb_KDC_REP_enc,
        &ett_krb_sname,
        &ett_krb_cname,
	&ett_krb_AP_REP_enc,
        &ett_krb_padata,
        &ett_krb_etypes,
        &ett_krb_LastReqs,
        &ett_krb_IF_RELEVANT,
	&ett_krb_PA_DATA_tree,
        &ett_krb_s_address,
        &ett_krb_HostAddress,
        &ett_krb_HostAddresses,
	&ett_krb_authenticator_enc,
        &ett_krb_AP_Options,
        &ett_krb_KDC_Options,
        &ett_krb_Ticket_Flags,
        &ett_krb_request,
        &ett_krb_recordmark,
        &ett_krb_ticket,
	&ett_krb_ticket_enc,
        &ett_krb_PRIV,
        &ett_krb_PRIV_enc,
        &ett_krb_EncTicketPart,
        &ett_krb_EncAPRepPart,
        &ett_krb_EncKrbPrivPart,
        &ett_krb_EncKDCRepPart,
        &ett_krb_LastReq,
        &ett_krb_Authenticator,
        &ett_krb_Checksum,
        &ett_krb_key,
        &ett_krb_subkey,
        &ett_krb_AuthorizationData,
	&ett_krb_TransitedEncoding,
	&ett_krb_PAC,
	&ett_krb_PAC_LOGON_INFO,
	&ett_krb_PAC_CREDENTIAL_TYPE,
	&ett_krb_PAC_SERVER_CHECKSUM,
	&ett_krb_PAC_PRIVSVR_CHECKSUM,
	&ett_krb_PAC_CLIENT_INFO_TYPE,
	&ett_krb_e_checksum,
    };
    module_t *krb_module;

    proto_kerberos = proto_register_protocol("Kerberos", "KRB5", "kerberos");
    proto_register_field_array(proto_kerberos, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register preferences */
    krb_module = prefs_register_protocol(proto_kerberos, kerberos_prefs_apply_cb);
    prefs_register_bool_preference(krb_module, "desegment",
	"Reassemble Kerberos over TCP messages spanning multiple TCP segments",
	"Whether the Kerberos dissector should reassemble messages spanning multiple TCP segments."
	" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &krb_desegment);
#ifdef HAVE_KERBEROS
    prefs_register_bool_preference(krb_module, "decrypt",
	"Try to decrypt Kerberos blobs",
	"Whether the dissector should try to decrypt "
	"encrypted Kerberos blobs. This requires that the proper "
	"keytab file is installed as well.", &krb_decrypt);

	prefs_register_string_preference(krb_module, "file",
				   "Kerberos keytab file",
				   "The keytab file containing all the secrets",
				   &keytab_filename);
#endif

}

static int wrap_dissect_gss_kerb(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, guint8 *drep _U_)
{
	tvbuff_t *auth_tvb;

	auth_tvb = tvb_new_subset(
		tvb, offset, tvb_length_remaining(tvb, offset),
		tvb_reported_length_remaining(tvb, offset));

	dissect_kerberos_main(auth_tvb, pinfo, tree, FALSE, NULL);

	return tvb_length_remaining(tvb, offset);
}


static dcerpc_auth_subdissector_fns gss_kerb_auth_fns = {
	wrap_dissect_gss_kerb,		        /* Bind */
	wrap_dissect_gss_kerb,	 	        /* Bind ACK */
	NULL,					/* AUTH3 */
	wrap_dissect_gssapi_verf, 		/* Request verifier */
	wrap_dissect_gssapi_verf,		/* Response verifier */
	wrap_dissect_gssapi_payload,            /* Request data */
	wrap_dissect_gssapi_payload             /* Response data */
};


void
proto_reg_handoff_kerberos(void)
{
    dissector_handle_t kerberos_handle_tcp;

    krb4_handle = find_dissector("krb4");

    kerberos_handle_udp = new_create_dissector_handle(dissect_kerberos_udp,
	proto_kerberos);
    kerberos_handle_tcp = create_dissector_handle(dissect_kerberos_tcp,
	proto_kerberos);
    dissector_add("udp.port", UDP_PORT_KERBEROS, kerberos_handle_udp);
    dissector_add("tcp.port", TCP_PORT_KERBEROS, kerberos_handle_tcp);

    register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_INTEGRITY,
				      DCE_C_RPC_AUTHN_PROTOCOL_GSS_KERBEROS,
				      &gss_kerb_auth_fns);

    register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_PRIVACY,
				      DCE_C_RPC_AUTHN_PROTOCOL_GSS_KERBEROS,
				      &gss_kerb_auth_fns);

}

/*

  MISC definitions from RFC1510:

   Realm ::=           GeneralString

   KerberosTime ::=   GeneralizedTime

   AuthorizationData ::=   SEQUENCE OF SEQUENCE {
                           ad-type[0]               INTEGER,
                           ad-data[1]               OCTET STRING
   }
                   APOptions ::=   BIT STRING {
                                   reserved(0),
                                   use-session-key(1),
                                   mutual-required(2)
                   }


                   TicketFlags ::=   BIT STRING {
                                     reserved(0),
                                     forwardable(1),
                                     forwarded(2),
                                     proxiable(3),
                                     proxy(4),
                                     may-postdate(5),
                                     postdated(6),
                                     invalid(7),
                                     renewable(8),
                                     initial(9),
                                     pre-authent(10),
                                     hw-authent(11)
                   }

                  KDCOptions ::=   BIT STRING {
                                   reserved(0),
                                   forwardable(1),
                                   forwarded(2),
                                   proxiable(3),
                                   proxy(4),
                                   allow-postdate(5),
                                   postdated(6),
                                   unused7(7),
                                   renewable(8),
                                   unused9(9),
                                   unused10(10),
                                   unused11(11),
                                   renewable-ok(27),
                                   enc-tkt-in-skey(28),
                                   renew(30),
                                   validate(31)
                  }


            LastReq ::=   SEQUENCE OF SEQUENCE {
                          lr-type[0]               INTEGER,
                          lr-value[1]              KerberosTime
            }

   Ticket ::=                    [APPLICATION 1] SEQUENCE {
                                 tkt-vno[0]                   INTEGER,
                                 realm[1]                     Realm,
                                 sname[2]                     PrincipalName,
                                 enc-part[3]                  EncryptedData
   }

  -- Encrypted part of ticket
  EncTicketPart ::=     [APPLICATION 3] SEQUENCE {
                        flags[0]             TicketFlags,
                        key[1]               EncryptionKey,
                        crealm[2]            Realm,
                        cname[3]             PrincipalName,
                        transited[4]         TransitedEncoding,
                        authtime[5]          KerberosTime,
                        starttime[6]         KerberosTime OPTIONAL,
                        endtime[7]           KerberosTime,
                        renew-till[8]        KerberosTime OPTIONAL,
                        caddr[9]             HostAddresses OPTIONAL,
                        authorization-data[10]   AuthorizationData OPTIONAL
  }

  -- encoded Transited field
  TransitedEncoding ::=         SEQUENCE {
                                tr-type[0]  INTEGER, -- must be registered
                                contents[1]          OCTET STRING
  }

  -- Unencrypted authenticator
  Authenticator ::=    [APPLICATION 2] SEQUENCE    {
                 authenticator-vno[0]          INTEGER,
                 crealm[1]                     Realm,
                 cname[2]                      PrincipalName,
                 cksum[3]                      Checksum OPTIONAL,
                 cusec[4]                      INTEGER,
                 ctime[5]                      KerberosTime,
                 subkey[6]                     EncryptionKey OPTIONAL,
                 seq-number[7]                 INTEGER OPTIONAL,
                 authorization-data[8]         AuthorizationData OPTIONAL
  }

  PA-DATA ::=        SEQUENCE {
           padata-type[1]        INTEGER,
           padata-value[2]       OCTET STRING,
                         -- might be encoded AP-REQ
  }

   padata-type     ::= PA-ENC-TIMESTAMP
   padata-value    ::= EncryptedData -- PA-ENC-TS-ENC

   PA-ENC-TS-ENC   ::= SEQUENCE {
           patimestamp[0]               KerberosTime, -- client's time
           pausec[1]                    INTEGER OPTIONAL
   }

   EncASRepPart ::=    [APPLICATION 25[25]] EncKDCRepPart
   EncTGSRepPart ::=   [APPLICATION 26] EncKDCRepPart

   EncKDCRepPart ::=   SEQUENCE {
               key[0]                       EncryptionKey,
               last-req[1]                  LastReq,
               nonce[2]                     INTEGER,
               key-expiration[3]            KerberosTime OPTIONAL,
               flags[4]                     TicketFlags,
               authtime[5]                  KerberosTime,
               starttime[6]                 KerberosTime OPTIONAL,
               endtime[7]                   KerberosTime,
               renew-till[8]                KerberosTime OPTIONAL,
               srealm[9]                    Realm,
               sname[10]                    PrincipalName,
               caddr[11]                    HostAddresses OPTIONAL
   }

   APOptions ::=   BIT STRING {
                   reserved(0),
                   use-session-key(1),
                   mutual-required(2)
   }

   EncAPRepPart ::=   [APPLICATION 27]     SEQUENCE {
              ctime[0]                  KerberosTime,
              cusec[1]                  INTEGER,
              subkey[2]                 EncryptionKey OPTIONAL,
              seq-number[3]             INTEGER OPTIONAL
   }

   KRB-SAFE ::=        [APPLICATION 20] SEQUENCE {
               pvno[0]               INTEGER,
               msg-type[1]           INTEGER,
               safe-body[2]          KRB-SAFE-BODY,
               cksum[3]              Checksum
   }

   KRB-SAFE-BODY ::=   SEQUENCE {
               user-data[0]          OCTET STRING,
               timestamp[1]          KerberosTime OPTIONAL,
               usec[2]               INTEGER OPTIONAL,
               seq-number[3]         INTEGER OPTIONAL,
               s-address[4]          HostAddress,
               r-address[5]          HostAddress OPTIONAL
   }

   KRB-PRIV ::=         [APPLICATION 21] SEQUENCE {
                pvno[0]                   INTEGER,
                msg-type[1]               INTEGER,
                enc-part[3]               EncryptedData
   }

   EncKrbPrivPart ::=   [APPLICATION 28] SEQUENCE {
                user-data[0]              OCTET STRING,
                timestamp[1]              KerberosTime OPTIONAL,
                usec[2]                   INTEGER OPTIONAL,
                seq-number[3]             INTEGER OPTIONAL,
                s-address[4]              HostAddress, -- sender's addr
                r-address[5]              HostAddress OPTIONAL
                                                      -- recip's addr
   }

   KRB-CRED         ::= [APPLICATION 22]   SEQUENCE {
                    pvno[0]                INTEGER,
                    msg-type[1]            INTEGER, -- KRB_CRED
                    tickets[2]             SEQUENCE OF Ticket,
                    enc-part[3]            EncryptedData
   }

   EncKrbCredPart   ::= [APPLICATION 29]   SEQUENCE {
                    ticket-info[0]         SEQUENCE OF KrbCredInfo,
                    nonce[1]               INTEGER OPTIONAL,
                    timestamp[2]           KerberosTime OPTIONAL,
                    usec[3]                INTEGER OPTIONAL,
                    s-address[4]           HostAddress OPTIONAL,
                    r-address[5]           HostAddress OPTIONAL
   }

   KrbCredInfo      ::=                    SEQUENCE {
                    key[0]                 EncryptionKey,
                    prealm[1]              Realm OPTIONAL,
                    pname[2]               PrincipalName OPTIONAL,
                    flags[3]               TicketFlags OPTIONAL,
                    authtime[4]            KerberosTime OPTIONAL,
                    starttime[5]           KerberosTime OPTIONAL,
                    endtime[6]             KerberosTime OPTIONAL
                    renew-till[7]          KerberosTime OPTIONAL,
                    srealm[8]              Realm OPTIONAL,
                    sname[9]               PrincipalName OPTIONAL,
                    caddr[10]              HostAddresses OPTIONAL
   }

      METHOD-DATA ::=    SEQUENCE of PA-DATA

   If the error-code is KRB_AP_ERR_METHOD, then the e-data field will
   contain an encoding of the following sequence:

      METHOD-DATA ::=    SEQUENCE {
                         method-type[0]   INTEGER,
                         method-data[1]   OCTET STRING OPTIONAL
      }

      EncryptionKey ::=   SEQUENCE {
                         keytype[0]    INTEGER,
                         keyvalue[1]   OCTET STRING
      }

      Checksum ::=   SEQUENCE {
                         cksumtype[0]   INTEGER,
                         checksum[1]    OCTET STRING
      }

*/
