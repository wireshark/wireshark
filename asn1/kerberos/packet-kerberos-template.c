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
 * Some of the development of the Kerberos protocol decoder was sponsored by
 * Cable Television Laboratories, Inc. ("CableLabs") based upon proprietary
 * CableLabs' specifications. Your license and use of this protocol decoder
 * does not mean that you are licensed to use the CableLabs'
 * specifications.  If you have questions about this protocol, contact
 * jf.mule [AT] cablelabs.com or c.stuart [AT] cablelabs.com for additional
 * information.
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include <wsutil/file_util.h>
#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/strutil.h>

#include <epan/conversation.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-kerberos.h>
#include <epan/dissectors/packet-netbios.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-ber.h>
#include <epan/dissectors/packet-pkinit.h>
#include <epan/dissectors/packet-cms.h>
#include <epan/dissectors/packet-windows-common.h>

#include <epan/dissectors/packet-dcerpc-netlogon.h>
#include <epan/dissectors/packet-dcerpc.h>

#include <epan/dissectors/packet-gssapi.h>
#include <epan/dissectors/packet-smb-common.h>

#define UDP_PORT_KERBEROS		88
#define TCP_PORT_KERBEROS		88

#define ADDRESS_STR_BUFSIZ 256

typedef struct kerberos_key {
	guint32 keytype;
	int keylength;
	const guint8 *keyvalue;
} kerberos_key_t;

typedef struct {
	guint32 etype;
	guint32 padata_type;
	guint32 enctype;
	kerberos_key_t key;
	guint32 ad_type;
	guint32 addr_type;
	guint32 checksum_type;
} kerberos_private_data_t;

static dissector_handle_t kerberos_handle_udp;

/* Forward declarations */
static int dissect_kerberos_Applications(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_ENC_TIMESTAMP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_KERB_PA_PAC_REQUEST(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_PA_S4U2Self(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_ETYPE_INFO(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_ETYPE_INFO2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_kerberos_AD_IF_RELEVANT(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);


/* Desegment Kerberos over TCP messages */
static gboolean krb_desegment = TRUE;

static gint proto_kerberos = -1;

static gint hf_krb_rm_reserved = -1;
static gint hf_krb_rm_reclen = -1;
static gint hf_krb_provsrv_location = -1;
static gint hf_krb_smb_nt_status = -1;
static gint hf_krb_smb_unknown = -1;
static gint hf_krb_address_ip = -1;
static gint hf_krb_address_netbios = -1;
static gint hf_krb_address_ipv6 = -1;
static gint hf_krb_gssapi_len = -1;
static gint hf_krb_gssapi_bnd = -1;
static gint hf_krb_gssapi_dlgopt = -1;
static gint hf_krb_gssapi_dlglen = -1;
static gint hf_krb_gssapi_c_flag_deleg = -1;
static gint hf_krb_gssapi_c_flag_mutual = -1;
static gint hf_krb_gssapi_c_flag_replay = -1;
static gint hf_krb_gssapi_c_flag_sequence = -1;
static gint hf_krb_gssapi_c_flag_conf = -1;
static gint hf_krb_gssapi_c_flag_integ = -1;
static gint hf_krb_gssapi_c_flag_dce_style = -1;
#include "packet-kerberos-hf.c"

/* Initialize the subtree pointers */
static gint ett_kerberos = -1;
static gint ett_krb_recordmark = -1;

#include "packet-kerberos-ett.c"

static expert_field ei_kerberos_decrypted_keytype = EI_INIT;

static dissector_handle_t krb4_handle=NULL;

/* Global variables */
static guint32 krb5_errorcode;
static guint32 gbl_keytype;
static gboolean gbl_do_col_info;

#include "packet-kerberos-val.h"

static void
call_kerberos_callbacks(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int tag, kerberos_callbacks *cb)
{
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

static kerberos_private_data_t*
kerberos_get_private_data(asn1_ctx_t *actx)
{
	if (!actx->private_data) {
		actx->private_data = wmem_new0(wmem_packet_scope(), kerberos_private_data_t);
	}
	return (kerberos_private_data_t *)(actx->private_data);
}

#ifdef HAVE_KERBEROS

/* Decrypt Kerberos blobs */
gboolean krb_decrypt = FALSE;

/* keytab filename */
static const char *keytab_filename = "";

WS_DLL_PUBLIC
void read_keytab_file(const char *);

void
read_keytab_file_from_preferences(void)
{
	static char *last_keytab = NULL;

	if (!krb_decrypt) {
		return;
	}

	if (keytab_filename == NULL) {
		return;
	}

	if (last_keytab && !strcmp(last_keytab, keytab_filename)) {
		return;
	}

	if (last_keytab != NULL) {
		g_free(last_keytab);
		last_keytab = NULL;
	}
	last_keytab = g_strdup(keytab_filename);

	read_keytab_file(last_keytab);
}

#elif defined(_WIN32)

/*
 * Dummy version to allow us to export this function -- even
 * on systems without KERBEROS.
 */
void
read_keytab_file_from_preferences(void)
{
}

#endif

#if defined(HAVE_HEIMDAL_KERBEROS) || defined(HAVE_MIT_KERBEROS)
#ifdef _WIN32
/* prevent redefinition warnings in kfw-2.5\inc\win_mac.h */
#undef HAVE_STDARG_H
#undef HAVE_SYS_TYPES_H
#endif
#include <krb5.h>
enc_key_t *enc_key_list=NULL;

static void
add_encryption_key(packet_info *pinfo, int keytype, int keylength, const char *keyvalue, const char *origin)
{
	enc_key_t *new_key;

	if(pinfo->fd->flags.visited){
		return;
	}
printf("added key in %u    keytype:%d len:%d\n",pinfo->fd->num, keytype, keylength);

	new_key=(enc_key_t *)g_malloc(sizeof(enc_key_t));
	g_snprintf(new_key->key_origin, KRB_MAX_ORIG_LEN, "%s learnt from frame %u",origin,pinfo->fd->num);
	new_key->fd_num = pinfo->fd->num;
	new_key->next=enc_key_list;
	enc_key_list=new_key;
	new_key->keytype=keytype;
	new_key->keylength=keylength;
	/*XXX this needs to be freed later */
	new_key->keyvalue=(char *)g_memdup(keyvalue, keylength);
}
#endif /* HAVE_HEIMDAL_KERBEROS || HAVE_MIT_KERBEROS */

#if defined(_WIN32) && !defined(HAVE_HEIMDAL_KERBEROS) && !defined(HAVE_MIT_KERBEROS) && !defined(HAVE_LIBNETTLE)
void
read_keytab_file(const char *filename _U_)
{
}
#endif

#ifdef HAVE_MIT_KERBEROS

static krb5_context krb5_ctx;

void
read_keytab_file(const char *filename)
{
	krb5_keytab keytab;
	krb5_error_code ret;
	krb5_keytab_entry key;
	krb5_kt_cursor cursor;
	enc_key_t *new_key;
	static gboolean first_time=TRUE;

	if (filename == NULL || filename[0] == 0) {
		return;
	}

	if(first_time){
		first_time=FALSE;
		ret = krb5_init_context(&krb5_ctx);
		if(ret && ret != KRB5_CONFIG_CANTOPEN){
			return;
		}
	}

	/* should use a file in the wireshark users dir */
	ret = krb5_kt_resolve(krb5_ctx, filename, &keytab);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Badly formatted keytab filename :%s\n",filename);

		return;
	}

	ret = krb5_kt_start_seq_get(krb5_ctx, keytab, &cursor);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not open or could not read from keytab file :%s\n",filename);
		return;
	}

	do{
		new_key=(enc_key_t *)g_malloc(sizeof(enc_key_t));
		new_key->fd_num = -1;
		new_key->next=enc_key_list;
		ret = krb5_kt_next_entry(krb5_ctx, keytab, &key, &cursor);
		if(ret==0){
			int i;
			char *pos;

			/* generate origin string, describing where this key came from */
			pos=new_key->key_origin;
			pos+=MIN(KRB_MAX_ORIG_LEN,
					 g_snprintf(pos, KRB_MAX_ORIG_LEN, "keytab principal "));
			for(i=0;i<key.principal->length;i++){
				pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
						 g_snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "%s%s",(i?"/":""),(key.principal->data[i]).data));
			}
			pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
					 g_snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "@%s",key.principal->realm.data));
			*pos=0;
/*printf("added key for principal :%s\n", new_key->key_origin);*/
			new_key->keytype=key.key.enctype;
			new_key->keylength=key.key.length;
			new_key->keyvalue=(char *)g_memdup(key.key.contents, key.key.length);
			enc_key_list=new_key;
		}
	}while(ret==0);

	ret = krb5_kt_end_seq_get(krb5_ctx, keytab, &cursor);
	if(ret){
		krb5_kt_close(krb5_ctx, keytab);
	}

}


guint8 *
decrypt_krb5_data(proto_tree *tree, packet_info *pinfo,
					int usage,
					tvbuff_t *cryptotvb,
					int keytype,
					int *datalen)
{
	krb5_error_code ret;
	enc_key_t *ek;
	krb5_data data = {0,0,NULL};
	krb5_keytab_entry key;
	int length = tvb_captured_length(cryptotvb);
	const guint8 *cryptotext = tvb_get_ptr(cryptotvb, 0, length);

	/* don't do anything if we are not attempting to decrypt data */
	if(!krb_decrypt || length < 1){
		return NULL;
	}

	/* make sure we have all the data we need */
	if (tvb_captured_length(cryptotvb) < tvb_reported_length(cryptotvb)) {
		return NULL;
	}

	read_keytab_file_from_preferences();
	data.data = (char *)g_malloc(length);
	data.length = length;

	for(ek=enc_key_list;ek;ek=ek->next){
		krb5_enc_data input;

		/* shortcircuit and bail out if enctypes are not matching */
		if((keytype != -1) && (ek->keytype != keytype)) {
			continue;
		}

		input.enctype = ek->keytype;
		input.ciphertext.length = length;
		input.ciphertext.data = (guint8 *)cryptotext;

		key.key.enctype=ek->keytype;
		key.key.length=ek->keylength;
		key.key.contents=ek->keyvalue;
		ret = krb5_c_decrypt(krb5_ctx, &(key.key), usage, 0, &input, &data);
		if(ret == 0){
			char *user_data;

			expert_add_info_format(pinfo, NULL, &ei_kerberos_decrypted_keytype,
								   "Decrypted keytype %d in frame %u using %s",
								   ek->keytype, pinfo->fd->num, ek->key_origin);

			proto_tree_add_text(tree, NULL, 0, 0, "[Decrypted using: %s]", ek->key_origin);
			/* return a private g_malloced blob to the caller */
			user_data=data.data;
			if (datalen) {
				*datalen = data.length;
			}
			return user_data;
		}
	}
	g_free(data.data);

	return NULL;
}

#elif defined(HAVE_HEIMDAL_KERBEROS)
static krb5_context krb5_ctx;

void
read_keytab_file(const char *filename)
{
	krb5_keytab keytab;
	krb5_error_code ret;
	krb5_keytab_entry key;
	krb5_kt_cursor cursor;
	enc_key_t *new_key;
	static gboolean first_time=TRUE;

	if (filename == NULL || filename[0] == 0) {
		return;
	}

	if(first_time){
		first_time=FALSE;
		ret = krb5_init_context(&krb5_ctx);
		if(ret){
			return;
		}
	}

	/* should use a file in the wireshark users dir */
	ret = krb5_kt_resolve(krb5_ctx, filename, &keytab);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not open keytab file :%s\n",filename);

		return;
	}

	ret = krb5_kt_start_seq_get(krb5_ctx, keytab, &cursor);
	if(ret){
		fprintf(stderr, "KERBEROS ERROR: Could not read from keytab file :%s\n",filename);
		return;
	}

	do{
		new_key=g_malloc(sizeof(enc_key_t));
		new_key->fd_num = -1;
		new_key->next=enc_key_list;
		ret = krb5_kt_next_entry(krb5_ctx, keytab, &key, &cursor);
		if(ret==0){
			unsigned int i;
			char *pos;

			/* generate origin string, describing where this key came from */
			pos=new_key->key_origin;
			pos+=MIN(KRB_MAX_ORIG_LEN,
					 g_snprintf(pos, KRB_MAX_ORIG_LEN, "keytab principal "));
			for(i=0;i<key.principal->name.name_string.len;i++){
				pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
						 g_snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "%s%s",(i?"/":""),key.principal->name.name_string.val[i]));
			}
			pos+=MIN(KRB_MAX_ORIG_LEN-(pos-new_key->key_origin),
					 g_snprintf(pos, KRB_MAX_ORIG_LEN-(pos-new_key->key_origin), "@%s",key.principal->realm));
			*pos=0;
			new_key->keytype=key.keyblock.keytype;
			new_key->keylength=key.keyblock.keyvalue.length;
			new_key->keyvalue=g_memdup(key.keyblock.keyvalue.data, key.keyblock.keyvalue.length);
			enc_key_list=new_key;
		}
	}while(ret==0);

	ret = krb5_kt_end_seq_get(krb5_ctx, keytab, &cursor);
	if(ret){
		krb5_kt_close(krb5_ctx, keytab);
	}

}


guint8 *
decrypt_krb5_data(proto_tree *tree, packet_info *pinfo,
					int usage,
					tvbuff_t *cryptotvb,
					int keytype,
					int *datalen)
{
	krb5_error_code ret;
	krb5_data data;
	enc_key_t *ek;
	int length = tvb_captured_length(cryptotvb);
	const guint8 *cryptotext = tvb_get_ptr(cryptotvb, 0, length);

	/* don't do anything if we are not attempting to decrypt data */
	if(!krb_decrypt){
		return NULL;
	}

	/* make sure we have all the data we need */
	if (tvb_captured_length(cryptotvb) < tvb_reported_length(cryptotvb)) {
		return NULL;
	}

	read_keytab_file_from_preferences();

	for(ek=enc_key_list;ek;ek=ek->next){
		krb5_keytab_entry key;
		krb5_crypto crypto;
		guint8 *cryptocopy; /* workaround for pre-0.6.1 heimdal bug */

		/* shortcircuit and bail out if enctypes are not matching */
		if((keytype != -1) && (ek->keytype != keytype)) {
			continue;
		}

		key.keyblock.keytype=ek->keytype;
		key.keyblock.keyvalue.length=ek->keylength;
		key.keyblock.keyvalue.data=ek->keyvalue;
		ret = krb5_crypto_init(krb5_ctx, &(key.keyblock), 0, &crypto);
		if(ret){
			return NULL;
		}

		/* pre-0.6.1 versions of Heimdal would sometimes change
		   the cryptotext data even when the decryption failed.
		   This would obviously not work since we iterate over the
		   keys. So just give it a copy of the crypto data instead.
		   This has been seen for RC4-HMAC blobs.
		*/
		cryptocopy=g_memdup(cryptotext, length);
		ret = krb5_decrypt_ivec(krb5_ctx, crypto, usage,
								cryptocopy, length,
								&data,
								NULL);
		g_free(cryptocopy);
		if((ret == 0) && (length>0)){
			char *user_data;

printf("woohoo decrypted keytype:%d in frame:%u\n", ek->keytype, pinfo->fd->num);
			proto_tree_add_text(tree, NULL, 0, 0, "[Decrypted using: %s]", ek->key_origin);
			krb5_crypto_destroy(krb5_ctx, crypto);
			/* return a private g_malloced blob to the caller */
			user_data=g_memdup(data.data, data.length);
			if (datalen) {
				*datalen = data.length;
			}
			return user_data;
		}
		krb5_crypto_destroy(krb5_ctx, crypto);
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
printf("added key in %u\n",pinfo->fd->num);

	new_key = g_malloc(sizeof(service_key_t));
	new_key->kvno = 0;
	new_key->keytype = keytype;
	new_key->length = keylength;
	new_key->contents = g_memdup(keyvalue, keylength);
	g_snprintf(new_key->origin, KRB_MAX_ORIG_LEN, "%s learnt from frame %u", origin, pinfo->fd->num);
	service_key_list = g_slist_append(service_key_list, (gpointer) new_key);
}

static void
clear_keytab(void) {
	GSList *ske;
	service_key_t *sk;

	for(ske = service_key_list; ske != NULL; ske = g_slist_next(ske)){
		sk = (service_key_t *) ske->data;
		if (sk) {
					g_free(sk->contents);
					g_free(sk);
				}
	}
	g_slist_free(service_key_list);
	service_key_list = NULL;
}

static void
read_keytab_file(const char *service_key_file)
{
	FILE *skf;
	ws_statb64 st;
	service_key_t *sk;
	unsigned char buf[SERVICE_KEY_SIZE];
	int newline_skip = 0, count = 0;

	if (service_key_file != NULL && ws_stat64 (service_key_file, &st) == 0) {

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

		skf = ws_fopen(service_key_file, "rb");
		if (! skf) return;

		while (fread(buf, SERVICE_KEY_SIZE, 1, skf) == 1) {
			sk = g_malloc(sizeof(service_key_t));
			sk->kvno = buf[0] << 8 | buf[1];
			sk->keytype = KEYTYPE_DES3_CBC_MD5;
			sk->length = DES3_KEY_SIZE;
			sk->contents = g_memdup(buf + 2, DES3_KEY_SIZE);
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
					tvbuff_t *cryptotvb,
					int keytype,
					int *datalen)
{
	tvbuff_t *encr_tvb;
	guint8 *decrypted_data = NULL, *plaintext = NULL;
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
	int length = tvb_captured_length(cryptotvb);
	const guint8 *cryptotext = tvb_get_ptr(cryptotvb, 0, length);


	/* don't do anything if we are not attempting to decrypt data */
	if(!krb_decrypt){
		return NULL;
	}

	/* make sure we have all the data we need */
	if (tvb_captured_length(cryptotvb) < tvb_reported_length(cryptotvb)) {
		return NULL;
	}

	if (keytype != KEYTYPE_DES3_CBC_MD5 || service_key_list == NULL) {
		return NULL;
	}

	decrypted_data = g_malloc(length);
	for(ske = service_key_list; ske != NULL; ske = g_slist_next(ske)){
		gboolean do_continue = FALSE;
		sk = (service_key_t *) ske->data;

		des_fix_parity(DES3_KEY_SIZE, key, sk->contents);

		md5_init(&md5s);
		memset(initial_vector, 0, DES_BLOCK_SIZE);
		des3_set_key(&ctx, key);
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
			offset = get_ber_length(encr_tvb, id_offset, &item_len, &ind);
		}
		CATCH_BOUNDS_ERRORS {
			tvb_free(encr_tvb);
			do_continue = TRUE;
		}
		ENDTRY;

		if (do_continue) continue;

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
g_warning("woohoo decrypted keytype:%d in frame:%u\n", keytype, pinfo->fd->num);
			plaintext = g_malloc(data_len);
			tvb_memcpy(encr_tvb, plaintext, CONFOUNDER_PLUS_CHECKSUM, data_len);
			tvb_free(encr_tvb);

			if (datalen) {
				*datalen = data_len;
			}
			g_free(decrypted_data);
			return(plaintext);
		}
		tvb_free(encr_tvb);
	}

	g_free(decrypted_data);
	return NULL;
}

#endif	/* HAVE_MIT_KERBEROS / HAVE_HEIMDAL_KERBEROS / HAVE_LIBNETTLE */

#define	INET6_ADDRLEN	16

/* TCP Record Mark */
#define	KRB_RM_RESERVED	0x80000000U
#define	KRB_RM_RECLEN	0x7fffffffU

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
#define KRB5_MSG_ENC_KRB_PRIV_PART     	28	/* EncKrbPrivPart */
#define KRB5_MSG_ENC_KRB_CRED_PART     	29	/* EncKrbCredPart */
#define KRB5_MSG_ERROR    		30	/* KRB-ERROR type */

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
/* the following four come from packetcable */
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
   however since Microsoft is the dominant(only?) user of types in this range
   we also treat the type as unsigned.
*/
#define KRB5_PA_PAC_REQUEST              128    /* (Microsoft extension) */
#define KRB5_PA_FOR_USER                 129    /* Impersonation (Microsoft extension) See [MS-SFU]. XXX - replaced by KRB5_PA_S4U2SELF */
#define KRB5_PA_S4U2SELF                 129

#define KRB5_PA_PROV_SRV_LOCATION 0xffffffff    /* (gint32)0xFF) packetcable stuff */
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


#if 0
#define PAC_LOGON_INFO		1
#define PAC_CREDENTIAL_TYPE	2
#define PAC_SERVER_CHECKSUM	6
#define PAC_PRIVSVR_CHECKSUM	7
#define PAC_CLIENT_INFO_TYPE	10
#define PAC_S4U_DELEGATION_INFO	11
#define PAC_UPN_DNS_INFO		12
static const value_string w2k_pac_types[] = {
    { PAC_LOGON_INFO		, "Logon Info" },
    { PAC_CREDENTIAL_TYPE	, "Credential Type" },
    { PAC_SERVER_CHECKSUM	, "Server Checksum" },
    { PAC_PRIVSVR_CHECKSUM	, "Privsvr Checksum" },
    { PAC_CLIENT_INFO_TYPE	, "Client Info Type" },
    { PAC_S4U_DELEGATION_INFO, "S4U Delegation Info" },
    { PAC_UPN_DNS_INFO		, "UPN DNS Info" },
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
#endif

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
    { KRB5_PA_FOR_USER             , "PA-FOR-USER" },
    { KRB5_PA_PROV_SRV_LOCATION    , "PA-PROV-SRV-LOCATION" },
    { 0                            , NULL },
};

#if 0
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
#endif

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
#define KRB5_AD_SIGNTICKET			0xffffffef
#if 0
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
    { KRB5_AD_SIGNTICKET			, "AD-SignTicket" },
    { 0	, NULL },
};

static const value_string krb5_transited_types[] = {
    { 1                           , "DOMAIN-X500-COMPRESS" },
    { 0                           , NULL }
};
#endif

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
	{ KRB5_MSG_ENC_KRB_CRED_PART,	"EncKrbCredPart" },
	{ KRB5_MSG_ERROR,		"KRB-ERROR" },
        { 0, NULL },
};

#define KRB5_GSS_C_DELEG_FLAG             0x01
#define KRB5_GSS_C_MUTUAL_FLAG            0x02
#define KRB5_GSS_C_REPLAY_FLAG            0x04
#define KRB5_GSS_C_SEQUENCE_FLAG          0x08
#define KRB5_GSS_C_CONF_FLAG              0x10
#define KRB5_GSS_C_INTEG_FLAG             0x20
#define KRB5_GSS_C_DCE_STYLE            0x1000

static const true_false_string tfs_gss_flags_deleg = {
	"Delegate credentials to remote peer",
	"Do NOT delegate"
};
static const true_false_string tfs_gss_flags_mutual = {
	"Request that remote peer authenticates itself",
	"Mutual authentication NOT required"
};
static const true_false_string tfs_gss_flags_replay = {
	"Enable replay protection for signed or sealed messages",
	"Do NOT enable replay protection"
};
static const true_false_string tfs_gss_flags_sequence = {
	"Enable Out-of-sequence detection for sign or sealed messages",
	"Do NOT enable out-of-sequence detection"
};
static const true_false_string tfs_gss_flags_conf = {
	"Confidentiality (sealing) may be invoked",
	"Do NOT use Confidentiality (sealing)"
};
static const true_false_string tfs_gss_flags_integ = {
	"Integrity protection (signing) may be invoked",
	"Do NOT use integrity protection"
};

static const true_false_string tfs_gss_flags_dce_style = {
	"DCE-STYLE",
	"Not using DCE-STYLE"
};

#ifdef HAVE_KERBEROS
static int
dissect_krb5_decrypt_ticket_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * All Ticket encrypted parts use usage == 2
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 2, next_tvb, private_data->etype, NULL);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_authenticator_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
											proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * Authenticators are encrypted with usage
	 * == 7 or
	 * == 11
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 7, next_tvb, private_data->etype, NULL);

	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, actx->pinfo, 11, next_tvb, private_data->etype, NULL);
	}

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_KDC_REP_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * ASREP/TGSREP encryptedparts are encrypted with usage
	 * == 3 or
	 * == 8 or
	 * == 9
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 3, next_tvb, private_data->etype, NULL);

	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, actx->pinfo, 8, next_tvb, private_data->etype, NULL);
	}

	if(!plaintext){
		plaintext=decrypt_krb5_data(tree, actx->pinfo, 9, next_tvb, private_data->etype, NULL);
	}

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_PA_ENC_TIMESTAMP (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
										proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * AS-REQ PA_ENC_TIMESTAMP are encrypted with usage
	 * == 1
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 1, next_tvb, private_data->etype, NULL);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_AP_REP_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* draft-ietf-krb-wg-kerberos-clarifications-05.txt :
	 * 7.5.1
	 * AP-REP are encrypted with usage == 12
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 12, next_tvb, private_data->etype, NULL);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_PRIV_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* RFC4120 :
	 * EncKrbPrivPart encrypted with usage
	 * == 13
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 13, next_tvb, private_data->etype, NULL);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}

static int
dissect_krb5_decrypt_CRED_data (gboolean imp_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx,
									proto_tree *tree, int hf_index _U_)
{
	guint8 *plaintext;
	int length;
	kerberos_private_data_t *private_data = kerberos_get_private_data(actx);
	tvbuff_t *next_tvb;

	next_tvb=tvb_new_subset_remaining(tvb, offset);
	length=tvb_captured_length_remaining(tvb, offset);

	/* RFC4120 :
	 * EncKrbCredPart encrypted with usage
	 * == 14
	 */
	plaintext=decrypt_krb5_data(tree, actx->pinfo, 14, next_tvb, private_data->etype, NULL);

	if(plaintext){
		tvbuff_t *child_tvb;
		child_tvb = tvb_new_child_real_data(tvb, plaintext, length, length);
		tvb_set_free_cb(child_tvb, g_free);

		/* Add the decrypted data to the data source list. */
		add_new_data_source(actx->pinfo, child_tvb, "Decrypted Krb5");

		offset=dissect_kerberos_Applications(FALSE, child_tvb, 0, actx , tree, /* hf_index*/ -1);
	}
	return offset;
}
#endif

/* Dissect a GSSAPI checksum as per RFC1964. This is NOT ASN.1 encoded.
 */
static int
dissect_krb5_rfc1964_checksum(asn1_ctx_t *actx _U_, proto_tree *tree, tvbuff_t *tvb)
{
	int offset=0;
	guint32 len;
	guint16 dlglen;

	/* Length of Bnd field */
	len=tvb_get_letohl(tvb, offset);
	proto_tree_add_item(tree, hf_krb_gssapi_len, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* Bnd field */
	proto_tree_add_item(tree, hf_krb_gssapi_bnd, tvb, offset, len, ENC_NA);
	offset += len;


	/* flags */
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_dce_style, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_integ, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_conf, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_sequence, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_replay, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_mutual, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_krb_gssapi_c_flag_deleg, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	/* the next fields are optional so we have to check that we have
	 * more data in our buffers */
	if(tvb_reported_length_remaining(tvb, offset)<2){
		return offset;
	}
	/* dlgopt identifier */
	proto_tree_add_item(tree, hf_krb_gssapi_dlgopt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	if(tvb_reported_length_remaining(tvb, offset)<2){
		return offset;
	}
	/* dlglen identifier */
	dlglen=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_krb_gssapi_dlglen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	if(dlglen!=tvb_reported_length_remaining(tvb, offset)){
		proto_tree_add_text(tree, tvb, 0, 0, "Error: DlgLen:%d is not the same as number of bytes remaining:%d", dlglen, tvb_captured_length_remaining(tvb, offset));
		return offset;
	}

	/* this should now be a KRB_CRED message */
	offset=dissect_kerberos_Applications(FALSE, tvb, offset, actx, tree, /* hf_index */ -1);

	return offset;
}

static int
dissect_krb5_PA_PROV_SRV_LOCATION(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
	offset=dissect_ber_GeneralString(actx, tree, tvb, offset, hf_krb_provsrv_location, NULL, 0);

	return offset;
}

static int
dissect_krb5_PW_SALT(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_)
{
	guint32 nt_status;

	/* Microsoft stores a special 12 byte blob here
	 * guint32 NT_status
	 * guint32 unknown
	 * guint32 unknown
	 * decode everything as this blob for now until we see if anyone
	 * else ever uses it   or we learn how to tell whether this
	 * is such an MS blob or not.
	 */
	proto_tree_add_item(tree, hf_krb_smb_nt_status, tvb, offset, 4,
			ENC_LITTLE_ENDIAN);
	nt_status=tvb_get_letohl(tvb, offset);
	if(nt_status) {
		col_append_fstr(actx->pinfo->cinfo, COL_INFO,
			" NT Status: %s",
			val_to_str(nt_status, NT_errors,
			"Unknown error code %#x"));
	}
	offset += 4;

	proto_tree_add_item(tree, hf_krb_smb_unknown, tvb, offset, 4,
			ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_krb_smb_unknown, tvb, offset, 4,
			ENC_LITTLE_ENDIAN);
	offset += 4;

	return offset;
}

#include "packet-kerberos-fn.c"

/* Make wrappers around exported functions for now */
int
dissect_krb5_Checksum(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_Checksum(FALSE, tvb, offset, actx, tree, hf_kerberos_cksum);

}

int
dissect_krb5_ctime(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_KerberosTime(FALSE, tvb, offset, actx, tree, hf_kerberos_ctime);
}


int
dissect_krb5_cname(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_PrincipalName(FALSE, tvb, offset, actx, tree, hf_kerberos_cname);
}
int
dissect_krb5_realm(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_)
{
	return dissect_kerberos_Realm(FALSE, tvb, offset, actx, tree, hf_kerberos_realm);
}


static gint
dissect_kerberos_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean dci, gboolean do_col_protocol, gboolean have_rm,
    kerberos_callbacks *cb)
{
	volatile int offset = 0;
	proto_tree *volatile kerberos_tree = NULL;
	proto_item *volatile item = NULL;
	asn1_ctx_t asn1_ctx;

	/* TCP record mark and length */
	guint32 krb_rm = 0;
	gint krb_reclen = 0;

	gbl_do_col_info=dci;

	if (have_rm) {
		krb_rm = tvb_get_ntohl(tvb, offset);
		krb_reclen = kerberos_rm_to_reclen(krb_rm);
		/*
		 * What is a reasonable size limit?
		 */
		if (krb_reclen > 10 * 1024 * 1024) {
			return (-1);
		}

		if (do_col_protocol) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");
		}

		if (tree) {
			item = proto_tree_add_item(tree, proto_kerberos, tvb, 0, -1, ENC_NA);
			kerberos_tree = proto_item_add_subtree(item, ett_kerberos);
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
			case KRB5_MSG_ENC_KRB_CRED_PART:
			case KRB5_MSG_SAFE:
			case KRB5_MSG_PRIV:
			case KRB5_MSG_ERROR:
				break;
			default:
				return 0;
		}
	if (do_col_protocol) {
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");
	}
	if (gbl_do_col_info) {
			col_clear(pinfo->cinfo, COL_INFO);
		}
		if (tree) {
			item = proto_tree_add_item(tree, proto_kerberos, tvb, 0, -1, ENC_NA);
			kerberos_tree = proto_item_add_subtree(item, ett_kerberos);
		}
	}
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
	asn1_ctx.private_data = cb;

	TRY {
		offset=dissect_kerberos_Applications(FALSE, tvb, offset, &asn1_ctx , kerberos_tree, /* hf_index */ -1);
	} CATCH_BOUNDS_ERRORS {
		RETHROW;
	} ENDTRY;

	proto_item_set_len(item, offset);
	return offset;
}

/*
 * Display the TCP record mark.
 */
void
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

gint
dissect_kerberos_main(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int do_col_info, kerberos_callbacks *cb)
{
	return (dissect_kerberos_common(tvb, pinfo, tree, do_col_info, FALSE, FALSE, cb));
}

guint32
kerberos_output_keytype(void)
{
	return gbl_keytype;
}

static gint
dissect_kerberos_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	/* Some weird kerberos implementation apparently do krb4 on the krb5 port.
	   Since all (except weirdo transarc krb4 stuff) use
	   an opcode <=16 in the first byte, use this to see if it might
	   be krb4.
	   All krb5 commands start with an APPL tag and thus is >=0x60
	   so if first byte is <=16  just blindly assume it is krb4 then
	*/
	if(tvb_captured_length(tvb) >= 1 && tvb_get_guint8(tvb, 0)<=0x10){
		if(krb4_handle){
			gboolean res;

			res=call_dissector_only(krb4_handle, tvb, pinfo, tree, NULL);
			return res;
		}else{
			return 0;
		}
	}


	return dissect_kerberos_common(tvb, pinfo, tree, TRUE, TRUE, FALSE, NULL);
}

gint
kerberos_rm_to_reclen(guint krb_rm)
{
    return (krb_rm & KRB_RM_RECLEN);
}

guint
get_krb_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint krb_rm;
	gint pdulen;

	krb_rm = tvb_get_ntohl(tvb, offset);
	pdulen = kerberos_rm_to_reclen(krb_rm);
	return (pdulen + 4);
}
static void
kerberos_prefs_apply_cb(void) {
#ifdef HAVE_LIBNETTLE
	clear_keytab();
	read_keytab_file(keytab_filename);
#endif
}

static int
dissect_kerberos_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	pinfo->fragmented = TRUE;
	if (dissect_kerberos_common(tvb, pinfo, tree, TRUE, TRUE, TRUE, NULL) < 0) {
		/*
		 * The dissector failed to recognize this as a valid
		 * Kerberos message.  Mark it as a continuation packet.
		 */
		col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
	}

	return tvb_captured_length(tvb);
}

static int
dissect_kerberos_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "KRB5");
	col_clear(pinfo->cinfo, COL_INFO);

	tcp_dissect_pdus(tvb, pinfo, tree, krb_desegment, 4, get_krb_pdu_len,
					 dissect_kerberos_tcp_pdu, data);
	return tvb_captured_length(tvb);
}

/*--- proto_register_kerberos -------------------------------------------*/
void proto_register_kerberos(void) {

	/* List of fields */

	static hf_register_info hf[] = {
	{ &hf_krb_rm_reserved, {
		"Reserved", "kerberos.rm.reserved", FT_BOOLEAN, 32,
		TFS(&tfs_set_notset), KRB_RM_RESERVED, "Record mark reserved bit", HFILL }},
	{ &hf_krb_rm_reclen, {
		"Record Length", "kerberos.rm.length", FT_UINT32, BASE_DEC,
		NULL, KRB_RM_RECLEN, NULL, HFILL }},
	{ &hf_krb_provsrv_location, {
		"PROVSRV Location", "kerberos.provsrv_location", FT_STRING, BASE_NONE,
		NULL, 0, "PacketCable PROV SRV Location", HFILL }},
	{ &hf_krb_smb_nt_status,
		{ "NT Status", "kerberos.smb.nt_status", FT_UINT32, BASE_HEX,
		VALS(NT_errors), 0, "NT Status code", HFILL }},
	{ &hf_krb_smb_unknown,
		{ "Unknown", "kerberos.smb.unknown", FT_UINT32, BASE_HEX,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_address_ip, {
		"IP Address", "kerberos.addr_ip", FT_IPv4, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_address_ipv6, {
		"IPv6 Address", "kerberos.addr_ipv6", FT_IPv6, BASE_NONE,
		NULL, 0, NULL, HFILL }},
	{ &hf_krb_address_netbios, {
		"NetBIOS Address", "kerberos.addr_nb", FT_STRING, BASE_NONE,
		NULL, 0, "NetBIOS Address and type", HFILL }},
	{ &hf_krb_gssapi_len, {
		"Length", "kerberos.gssapi.len", FT_UINT32, BASE_DEC,
		NULL, 0, "Length of GSSAPI Bnd field", HFILL }},
	{ &hf_krb_gssapi_bnd, {
		"Bnd", "kerberos.gssapi.bdn", FT_BYTES, BASE_NONE,
		NULL, 0, "GSSAPI Bnd field", HFILL }},
	{ &hf_krb_gssapi_c_flag_deleg, {
		"Deleg", "kerberos.gssapi.checksum.flags.deleg", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_deleg), KRB5_GSS_C_DELEG_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_mutual, {
		"Mutual", "kerberos.gssapi.checksum.flags.mutual", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_mutual), KRB5_GSS_C_MUTUAL_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_replay, {
		"Replay", "kerberos.gssapi.checksum.flags.replay", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_replay), KRB5_GSS_C_REPLAY_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_sequence, {
		"Sequence", "kerberos.gssapi.checksum.flags.sequence", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_sequence), KRB5_GSS_C_SEQUENCE_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_conf, {
		"Conf", "kerberos.gssapi.checksum.flags.conf", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_conf), KRB5_GSS_C_CONF_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_integ, {
		"Integ", "kerberos.gssapi.checksum.flags.integ", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_integ), KRB5_GSS_C_INTEG_FLAG, NULL, HFILL }},
	{ &hf_krb_gssapi_c_flag_dce_style, {
		"DCE-style", "kerberos.gssapi.checksum.flags.dce-style", FT_BOOLEAN, 32,
		TFS(&tfs_gss_flags_dce_style), KRB5_GSS_C_DCE_STYLE, NULL, HFILL }},
	{ &hf_krb_gssapi_dlgopt, {
		"DlgOpt", "kerberos.gssapi.dlgopt", FT_UINT16, BASE_DEC,
		NULL, 0, "GSSAPI DlgOpt", HFILL }},
	{ &hf_krb_gssapi_dlglen, {
		"DlgLen", "kerberos.gssapi.dlglen", FT_UINT16, BASE_DEC,
		NULL, 0, "GSSAPI DlgLen", HFILL }},

#include "packet-kerberos-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_kerberos,
	  &ett_krb_recordmark,
#include "packet-kerberos-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_kerberos_decrypted_keytype, { "kerberos.decrypted_keytype", PI_SECURITY, PI_CHAT, "Decryted keytype", EXPFILL }},
  };

	expert_module_t* expert_krb;
	module_t *krb_module;

	proto_kerberos = proto_register_protocol("Kerberos", "KRB5", "kerberos");
	proto_register_field_array(proto_kerberos, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_krb = expert_register_protocol(proto_kerberos);
	expert_register_field_array(expert_krb, ei, array_length(ei));

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

	prefs_register_filename_preference(krb_module, "file",
				   "Kerberos keytab file",
				   "The keytab file containing all the secrets",
				   &keytab_filename);
#endif

}
static int wrap_dissect_gss_kerb(tvbuff_t *tvb, int offset, packet_info *pinfo,
				 proto_tree *tree, dcerpc_info *di _U_,guint8 *drep _U_)
{
	tvbuff_t *auth_tvb;

	auth_tvb = tvb_new_subset_remaining(tvb, offset);

	dissect_kerberos_main(auth_tvb, pinfo, tree, FALSE, NULL);

	return tvb_captured_length_remaining(tvb, offset);
}


static dcerpc_auth_subdissector_fns gss_kerb_auth_connect_fns = {
	wrap_dissect_gss_kerb,                      /* Bind */
	wrap_dissect_gss_kerb,                      /* Bind ACK */
	wrap_dissect_gss_kerb,                      /* AUTH3 */
	NULL,                                       /* Request verifier */
	NULL,                                       /* Response verifier */
	NULL,                                       /* Request data */
	NULL                                        /* Response data */
};

static dcerpc_auth_subdissector_fns gss_kerb_auth_sign_fns = {
	wrap_dissect_gss_kerb,                      /* Bind */
	wrap_dissect_gss_kerb,                      /* Bind ACK */
	wrap_dissect_gss_kerb,                      /* AUTH3 */
	wrap_dissect_gssapi_verf,                   /* Request verifier */
	wrap_dissect_gssapi_verf,                   /* Response verifier */
	NULL,                                       /* Request data */
	NULL                                        /* Response data */
};

static dcerpc_auth_subdissector_fns gss_kerb_auth_seal_fns = {
	wrap_dissect_gss_kerb,                      /* Bind */
	wrap_dissect_gss_kerb,                      /* Bind ACK */
	wrap_dissect_gss_kerb,                      /* AUTH3 */
	wrap_dissect_gssapi_verf,                   /* Request verifier */
	wrap_dissect_gssapi_verf,                   /* Response verifier */
	wrap_dissect_gssapi_payload,                /* Request data */
	wrap_dissect_gssapi_payload                 /* Response data */
};



void
proto_reg_handoff_kerberos(void)
{
	dissector_handle_t kerberos_handle_tcp;

	krb4_handle = find_dissector("krb4");

	kerberos_handle_udp = new_create_dissector_handle(dissect_kerberos_udp,
	proto_kerberos);

	kerberos_handle_tcp = new_create_dissector_handle(dissect_kerberos_tcp,
	proto_kerberos);

	dissector_add_uint("udp.port", UDP_PORT_KERBEROS, kerberos_handle_udp);
	dissector_add_uint("tcp.port", TCP_PORT_KERBEROS, kerberos_handle_tcp);

	register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_CONNECT,
									  DCE_C_RPC_AUTHN_PROTOCOL_GSS_KERBEROS,
									  &gss_kerb_auth_connect_fns);

	register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_INTEGRITY,
									  DCE_C_RPC_AUTHN_PROTOCOL_GSS_KERBEROS,
									  &gss_kerb_auth_sign_fns);

	register_dcerpc_auth_subdissector(DCE_C_AUTHN_LEVEL_PKT_PRIVACY,
									  DCE_C_RPC_AUTHN_PROTOCOL_GSS_KERBEROS,
									  &gss_kerb_auth_seal_fns);
}


