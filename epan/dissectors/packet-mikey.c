/* packet-mikey.c
 * Routines for Multimedia Internet KEYing dissection
 * Copyright 2007, Mikael Magnusson <mikma@users.sourceforge.net>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Ref:
 * http://www.ietf.org/rfc/rfc3830.txt?number=3830
 */

/*
 * TODO
 * tvbuff offset in 32-bit variable.
 * Support CHASH
 * Decode Mikey-PK and Mikey-RSA-R with NULL encryption
 */


#include "config.h"

#include <glib.h>

#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-x509af.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif /* HAVE_LIBGCRYPT */

#define PORT_MIKEY 2269
static guint global_mikey_tcp_port = PORT_MIKEY;

static guint global_mikey_udp_port = PORT_MIKEY;


static const value_string on_off_vals[] = {
	{ 0, "Off" },
	{ 1, "On" },
	{ 0, NULL }
};

enum data_type_t {
	MIKEY_TYPE_PSK_INIT = 0,
	MIKEY_TYPE_PSK_RESP,
	MIKEY_TYPE_PK_INIT,
	MIKEY_TYPE_PK_RESP,
	MIKEY_TYPE_DH_INIT,
	MIKEY_TYPE_DH_RESP,
	MIKEY_TYPE_ERROR,
	MIKEY_TYPE_DHHMAC_INIT,
	MIKEY_TYPE_DHHMAC_RESP,
	MIKEY_TYPE_RSA_R_INIT,
	MIKEY_TYPE_RSA_R_RESP
};

static const value_string data_type_vals[] = {
	{ MIKEY_TYPE_PSK_INIT, "Pre-shared" },
	{ MIKEY_TYPE_PSK_RESP, "PSK ver msg" },
	{ MIKEY_TYPE_PK_INIT, "Public key" },
	{ MIKEY_TYPE_PK_RESP, "PK ver msg" },
	{ MIKEY_TYPE_DH_INIT, "D-H init" },
	{ MIKEY_TYPE_DH_RESP, "D-H resp" },
	{ MIKEY_TYPE_ERROR, "Error" },
	{ MIKEY_TYPE_DHHMAC_INIT, "DHHMAC init" },
	{ MIKEY_TYPE_DHHMAC_RESP, "DHHMAC resp" },
	{ MIKEY_TYPE_RSA_R_INIT, "RSA-R I_MSG" },
	{ MIKEY_TYPE_RSA_R_RESP, "RSA-R R_MSG" },
	{ 0, NULL }
};

enum cs_id_map_t {
	CS_ID_SRTP = 0
};

static const value_string cs_id_map_vals[] = {
	{ CS_ID_SRTP, "SRTP-ID" },
	{ 0, NULL }
};

enum payload_t {
	PL_HDR = -1,
	PL_LAST,
	PL_KEMAC,
	PL_PKE,
	PL_DH,
	PL_SIGN,
	PL_T,
	PL_ID,
	PL_CERT,
	PL_CHASH,
	PL_V,
	PL_SP,
	PL_RAND,
	PL_ERR,
	PL_KEY_DATA = 20,
	PL_GENERAL_EXT,
	PL_MAX
};

#define PL_HDR_TEXT "Common Header (HDR)"
#define PL_LAST_TEXT "Last payload"
#define PL_KEMAC_TEXT "Key Data Transport (KEMAC)"
#define PL_PKE_TEXT "Envelope Data (PKE)"
#define PL_DH_TEXT "DH Data (DH)"
#define PL_SIGN_TEXT "Signature (SIGN)"
#define PL_T_TEXT "Timestamp (T)"
#define PL_ID_TEXT "ID"
#define PL_CERT_TEXT "Certificate (CERT)"
#define PL_CHASH_TEXT "CHASH"
#define PL_V_TEXT "Ver msg (V)"
#define PL_SP_TEXT "Security Policy (SP)"
#define PL_RAND_TEXT "RAND"
#define PL_ERR_TEXT "Error (ERR)"
#define PL_KEY_DATA_TEXT "Key data (KEY)"
#define PL_GENERAL_EXT_TEXT "General Extension (EXT)"

static const value_string payload_vals[] = {
	{ PL_HDR, PL_HDR_TEXT },
	{ PL_LAST, PL_LAST_TEXT },
	{ PL_KEMAC, PL_KEMAC_TEXT },
	{ PL_PKE, PL_PKE_TEXT },
	{ PL_DH, PL_DH_TEXT },
	{ PL_SIGN, PL_SIGN_TEXT },
	{ PL_T, PL_T_TEXT },
	{ PL_ID, PL_ID_TEXT },
	{ PL_CERT, PL_CERT_TEXT },
	{ PL_CHASH, PL_CHASH_TEXT },
	{ PL_V, PL_V_TEXT },
	{ PL_SP, PL_SP_TEXT },
	{ PL_RAND, PL_RAND_TEXT },
	{ PL_ERR, PL_ERR_TEXT },
	{ PL_KEY_DATA, PL_KEY_DATA_TEXT },
	{ PL_GENERAL_EXT, PL_GENERAL_EXT_TEXT },
	{ 0, NULL }
};

enum ts_type_t {
	T_NTP_UTC = 0,
	T_NTP,
	T_COUNTER
};

static const value_string ts_type_vals[] = {
	{ T_NTP_UTC, "NTP-UTC" },
	{ T_NTP, "NTP" },
	{ T_COUNTER, "COUNTER" },
	{ 0, NULL }
};

enum encr_alg_t {
	ENCR_NULL = 0,
	ENCR_AES_CM_128,
	ENCR_AES_KW_128
};

static const value_string encr_alg_vals[] = {
	{ ENCR_NULL, "NULL" },
	{ ENCR_AES_CM_128, "AES-CM-128" },
	{ ENCR_AES_KW_128, "AES-KW-128" },
	{ 0, NULL }
};

enum oakley_t {
	DH_OAKLEY_5 = 0,
	DH_OAKLEY_1,
	DH_OAKLEY_2
};

static const value_string oakley_vals[] = {
	{ DH_OAKLEY_5, "OAKLEY 5" },
	{ DH_OAKLEY_1, "OAKLEY 1" },
	{ DH_OAKLEY_2, "OAKLEY 2" },
	{ 0, NULL }
};

enum mac_alg_t {
	MAC_NULL = 0,
	MAC_HMAC_SHA_1_160
};

static const value_string mac_alg_vals[] = {
	{ MAC_NULL, "NULL" },
	{ MAC_HMAC_SHA_1_160, "HMAC-SHA-1-160" },
	{ 0, NULL }
};

enum pke_c_t {
	PKE_C_NO_CACHE = 0,
	PKE_C_CACHE,
	PKE_C_CACHE_CSB
};

static const value_string pke_c_vals[] = {
	{ PKE_C_NO_CACHE, "No cache" },
	{ PKE_C_CACHE, "Cache" },
	{ PKE_C_CACHE_CSB, "Cache for CSB" },
	{ 0, NULL }
};

enum sign_s_t {
	SIGN_S_PKCS1 = 0,
	SIGN_S_PSS
};

static const value_string sign_s_vals[] = {
	{ SIGN_S_PKCS1, "RSA/PKCS#1/1.5" },
	{ SIGN_S_PSS, "RSA/PSS" },
	{ 0, NULL }
};

enum id_type_t {
	ID_TYPE_NAI = 0,
	ID_TYPE_URI
};

static const value_string id_type_vals[] = {
	{ ID_TYPE_NAI, "NAI" },
	{ ID_TYPE_URI, "URI" },
	{ 0, NULL }
};

enum cert_type_t {
	CERT_TYPE_X509V3 = 0,
	CERT_TYPE_X509V3_URL,
	CERT_TYPE_X509V3_SIGN,
	CERT_TYPE_X509V3_ENCR
};

static const value_string cert_type_vals[] = {
	{ CERT_TYPE_X509V3, "X.509v3" },
	{ CERT_TYPE_X509V3_URL, "X.509v3 URL" },
	{ CERT_TYPE_X509V3_SIGN, "X.509v3 Sign" },
	{ CERT_TYPE_X509V3_ENCR, "X.509v3 Encr" },
	{ 0, NULL }
};

enum srtp_policy_type_t {
	SP_ENCR_ALG,
	SP_ENCR_LEN,
	SP_AUTH_ALG,
	SP_AUTH_KEY_LEN,
	SP_SALT_LEN,
	SP_PRF,
	SP_KD_RATE,
	SP_SRTP_ENCR,
	SP_SRTCP_ENCR,
	SP_FEC,
	SP_SRTP_AUTH,
	SP_AUTH_TAG_LEN,
	SP_SRTP_PREFIX,
	SP_MAX
};

#define SP_TEXT_ENCR_ALG "Encryption algorithm"
#define SP_TEXT_ENCR_LEN "Session Encr. key length"
#define SP_TEXT_AUTH_ALG "Authentication algorithm"
#define SP_TEXT_AUTH_KEY_LEN "Session Auth. key length"
#define SP_TEXT_SALT_LEN "Session Salt key length"
#define SP_TEXT_PRF "SRTP Pseudo Random Function"
#define SP_TEXT_KD_RATE "Key derivation rate"
#define SP_TEXT_SRTP_ENCR "SRTP encryption"
#define SP_TEXT_SRTCP_ENCR "SRTCP encryption"
#define SP_TEXT_FEC "Sender's FEC order"
#define SP_TEXT_SRTP_AUTH "SRTP authentication"
#define SP_TEXT_AUTH_TAG_LEN "Authentication tag length"
#define SP_TEXT_SRTP_PREFIX "SRTP prefix length"

static const value_string srtp_policy_type_vals[] _U_ = {
	{ SP_ENCR_ALG, SP_TEXT_ENCR_ALG },
	{ SP_ENCR_LEN, SP_TEXT_ENCR_LEN },
	{ SP_AUTH_ALG, SP_TEXT_AUTH_ALG },
	{ SP_AUTH_KEY_LEN, SP_TEXT_AUTH_KEY_LEN },
	{ SP_SALT_LEN, SP_TEXT_SALT_LEN },
	{ SP_PRF, SP_TEXT_PRF },
	{ SP_KD_RATE, SP_TEXT_KD_RATE },
	{ SP_SRTP_ENCR, SP_TEXT_SRTP_ENCR },
	{ SP_SRTCP_ENCR, SP_TEXT_SRTCP_ENCR },
	{ SP_FEC, SP_TEXT_FEC },
	{ SP_SRTP_AUTH, SP_TEXT_SRTP_AUTH },
	{ SP_AUTH_TAG_LEN, SP_TEXT_AUTH_TAG_LEN },
	{ SP_SRTP_PREFIX, SP_TEXT_SRTP_PREFIX },
	{ 0, NULL }
};

enum sp_encr_alg_t {
	SP_ENCR_NULL = 0,
	SP_ENCR_AES_CM,
	SP_ENCR_AES_F8
};

static const value_string sp_encr_alg_vals[] = {
	{ SP_ENCR_NULL, "NULL" },
	{ SP_ENCR_AES_CM, "AES-CM" },
	{ SP_ENCR_AES_F8, "AES-F8" },
	{ 0, NULL }
};

enum sp_auth_alg_t {
	SP_AUTH_NULL = 0,
	SP_AUTH_HMAC_SHA_1
};

static const value_string sp_auth_alg_vals[] = {
	{ SP_AUTH_NULL, "NULL" },
	{ SP_AUTH_HMAC_SHA_1, "HMAC-SHA-1" },
	{ 0, NULL }
};

enum sp_prf_t {
	SP_PRF_AES_CM = 0
};

static const value_string sp_prf_vals[] = {
	{ SP_PRF_AES_CM, "AES-CM" },
	{ 0, NULL }
};

enum sp_fec_t {
	SP_FEC_SRTP = 0
};

static const value_string sp_fec_vals[] = {
	{ SP_FEC_SRTP, "FEC-SRTP" },
	{ 0, NULL }
};

enum sp_prot_t {
	SP_PROT_TYPE_SRTP = 0
};

static const value_string sp_prot_type_vals[] = {
	{ SP_PROT_TYPE_SRTP, "SRTP" },
	{ 0, NULL }
};

enum prf_func_t {
	PRF_FUNC_MIKEY_1 = 0
};

static const value_string prf_func_vals[] = {
	{ PRF_FUNC_MIKEY_1, "MIKEY-1" },
	{ 0, NULL }
};

enum kv_t {
	KV_NULL = 0,
	KV_SPI,
	KV_INTERVAL
};

static const value_string kv_vals[] = {
	{ KV_NULL, "Null" },
	{ KV_SPI, "SPI/MKI" },
	{ KV_INTERVAL, "Interval" },
	{ 0, NULL }
};

enum kd_t {
	KD_TGK = 0,
	KD_TGK_SALT,
	KD_TEK,
	KD_TEK_SALT
};

static const value_string kd_vals[] = {
	{ KD_TGK, "TGK" },
	{ KD_TGK_SALT, "TGK+SALT" },
	{ KD_TEK, "TEK" },
	{ KD_TEK_SALT, "TEK+SALT" },
	{ 0, NULL }
};

enum err_t {
	ERR_AUTH_FAILURE = 0,
	ERR_INVALID_TS,
	ERR_INVALID_PRF,
	ERR_INVALID_MAC,
	ERR_INVALID_EA,
	ERR_INVALID_HA,
	ERR_INVALID_DH,
	ERR_INVALID_ID,
	ERR_INVALID_CERT,
	ERR_INVALID_SP,
	ERR_INVALID_SPPAR,
	ERR_INVALID_DT,
	ERR_UNKNOWN
};

static const value_string err_vals[] = {
	{ ERR_AUTH_FAILURE, "Authentication failure" },
	{ ERR_INVALID_TS,   "Invalid timestamp" },
	{ ERR_INVALID_PRF,  "PRF function not supported" },
	{ ERR_INVALID_MAC,  "MAC algorithm not supported" },
	{ ERR_INVALID_EA,   "Encryption algorithm not supported" },
	{ ERR_INVALID_HA,   "Hash function not supported" },
	{ ERR_INVALID_DH,   "DH group not supported" },
	{ ERR_INVALID_ID,   "ID not supported" },
	{ ERR_INVALID_CERT, "Certificate not supported" },
	{ ERR_INVALID_SP,   "SP type not supported" },
	{ ERR_INVALID_SPPAR,"SP parameters not supported" },
	{ ERR_INVALID_DT,   "Data type not supported" },
	{ ERR_UNKNOWN,      "Unspecified error" },
	{ 0, NULL }
};

enum genext_t {
	GEN_EXT_VENDOR_ID = 0,
	GEN_EXT_SDP_ID
};

static const value_string genext_type_vals[] = {
	{ GEN_EXT_VENDOR_ID, "Vendor-ID" },
	{ GEN_EXT_SDP_ID, "SDP-IDs" },
	{ 0, NULL }
};

enum {
	/* HDR */
	POS_HDR_VERSION=0,
	POS_HDR_DATA_TYPE,
	POS_HDR_V,
	POS_HDR_PRF_FUNC,
	POS_HDR_CSB_ID,
	POS_HDR_CS_COUNT,
	POS_HDR_CS_ID_MAP_TYPE,
	POS_ID_SRTP,
	POS_ID_SRTP_NO,
	POS_ID_SRTP_SSRC,
	POS_ID_SRTP_ROC,

	/* KEMAC */
	POS_KEMAC_ENCR_ALG,
	POS_KEMAC_ENCR_DATA_LEN,
	POS_KEMAC_ENCR_DATA,
	POS_KEMAC_MAC_ALG,
	POS_KEMAC_MAC,

	/* PKE */
	POS_PKE_C,
	POS_PKE_DATA_LEN,
	POS_PKE_DATA,

	/* DH */
	POS_DH_GROUP,
	POS_DH_VALUE,
	POS_DH_RESERV,
	POS_DH_KV,

	/* SIGN */
	POS_SIGNATURE_LEN,
	POS_SIGNATURE,
	POS_SIGN_S_TYPE,

	/* T */
	POS_TS_TYPE,
	POS_TS_NTP,

	/* ID */
	POS_ID_TYPE,
	POS_ID_LEN,
	POS_ID,

	/* CERT */
	POS_CERT_TYPE,
	POS_CERT_LEN,
	POS_CERTIFICATE,

	/* V */
	POS_V_AUTH_ALG,
	POS_V_DATA,

	/* SP */
	POS_SP_NO,
	POS_SP_TYPE,
	POS_SP_PARAM_LEN,
/* 	POS_SP_PARAM, */

	/* SP param */
	POS_SP_PARAM_F,
	POS_SP_PARAM_F_TYPE,
	POS_SP_PARAM_F_LEN,
	POS_SP_PARAM_F_VALUE,

	/* RAND */
	POS_RAND_LEN,
	POS_RAND,

	/* Error */
	POS_ERR_NO,
	POS_ERR_RESERVED,

	/* Key data */
	POS_KEY_DATA_TYPE,
	POS_KEY_DATA_KV,
	POS_KEY_DATA_LEN,
	POS_KEY_DATA,
	POS_KEY_SALT_LEN,
	POS_KEY_SALT,
	POS_KEY_KV_FROM_LEN,
	POS_KEY_KV_FROM,
	POS_KEY_KV_TO_LEN,
	POS_KEY_KV_TO,
	POS_KEY_KV_SPI_LEN,
	POS_KEY_KV_SPI,

	/* General Ext. */
	POS_GENERAL_EXT_TYPE,
	POS_GENERAL_EXT_LEN,
	POS_GENERAL_EXT_DATA,
	POS_GENERAL_EXT_VALUE,

	/* MIKEY */
	POS_PAYLOAD_STR,
	POS_NEXT_PAYLOAD,

	/* Unused */
/* 	POS_PAYLOAD, */

	MAX_POS
};

typedef struct tag_mikey_t {
	guint8 type;
} mikey_t;

typedef int (*mikey_dissector_t)(mikey_t *, tvbuff_t *, packet_info *, proto_tree *);
struct mikey_dissector_entry {
	int type;
	mikey_dissector_t dissector;
};

/* Forward declaration we need below */
void proto_reg_handoff_mikey(void);
static int dissect_payload(enum payload_t payload, mikey_t *mikey, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static const struct mikey_dissector_entry *mikey_dissector_lookup(const struct mikey_dissector_entry *map, int type);


/* Initialize the protocol and registered fields */
static int proto_mikey = -1;
static int hf_mikey[MAX_POS+1];
static int hf_mikey_sp_param[SP_MAX+1];
static int hf_mikey_pl[PL_MAX];

/* Initialize the subtree pointers */
static gint ett_mikey = -1;
static gint ett_mikey_payload = -1;
static gint ett_mikey_sp_param = -1;
static gint ett_mikey_hdr_id = -1;
static gint ett_mikey_enc_data = -1;


static const struct mikey_dissector_entry *
mikey_dissector_lookup(const struct mikey_dissector_entry *map, int type)
{
	unsigned int i;
	for (i = 0; map[i].dissector != NULL; i++) {
		if (map[i].type == type) {
			return &map[i];
		}
	}

	return NULL;
}

static void
add_next_payload(tvbuff_t *tvb, proto_tree *tree, int offset)
{
	proto_tree_add_item(tree, hf_mikey[POS_NEXT_PAYLOAD], tvb, offset, 1, ENC_BIG_ENDIAN);
}


static int
dissect_payload_cs_id_srtp(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_,  proto_tree *tree)
{
	proto_item *id_ti;
	proto_tree *id_tree;
	guint8 no;
	guint32 ssrc;
	guint32 roc;

	tvb_ensure_bytes_exist(tvb, 0, 9);

	no = tvb_get_guint8(tvb, 0);
	ssrc = tvb_get_ntohl(tvb, 1);
	roc = tvb_get_ntohl(tvb, 5);

	if (tree) {
		id_ti = proto_tree_add_none_format(tree, hf_mikey[POS_ID_SRTP], tvb, 0, 9, "SRTP ID: Policy: %d, SSRC: 0x%x, ROC: 0x%x", no, ssrc, roc);
		id_tree = proto_item_add_subtree(id_ti, ett_mikey_hdr_id);

		proto_tree_add_item(id_tree, hf_mikey[POS_ID_SRTP_NO], tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(id_tree, hf_mikey[POS_ID_SRTP_SSRC], tvb, 1, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(id_tree, hf_mikey[POS_ID_SRTP_ROC], tvb, 5, 4, ENC_BIG_ENDIAN);
	}
	return 9;
}

static const struct mikey_dissector_entry cs_id_map[] = {
	{ CS_ID_SRTP, dissect_payload_cs_id_srtp },
	{ 0, NULL }
};

static int
dissect_payload_cs_id(enum cs_id_map_t type, mikey_t *mikey, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	const struct mikey_dissector_entry *entry;

	entry = mikey_dissector_lookup(cs_id_map, type);

	if (!entry || !entry->dissector) {
		return -1;
	}

	return entry->dissector(mikey, tvb, pinfo, tree);

}

static int
dissect_payload_hdr(mikey_t *mikey, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint8 cs_id_map_type;
	guint8 ncs;
	int i;
	proto_item* parent;


	tvb_ensure_bytes_exist(tvb, offset, 10);
	mikey->type = tvb_get_guint8(tvb, offset+1);
	ncs = tvb_get_guint8(tvb, offset+8);
	cs_id_map_type = tvb_get_guint8(tvb, offset+9);

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_HDR_VERSION],
					tvb, offset+0, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(tree, hf_mikey[POS_HDR_DATA_TYPE], tvb, offset+1, 1, ENC_BIG_ENDIAN);
		parent = proto_tree_get_parent(tree);
		proto_item_append_text(parent, " Type: %s", val_to_str_const(mikey->type, data_type_vals, "Unknown"));

		add_next_payload(tvb, tree, offset+2);

		proto_tree_add_item(tree, hf_mikey[POS_HDR_V], tvb, offset+3, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_HDR_PRF_FUNC], tvb, offset+3, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(tree, hf_mikey[POS_HDR_CSB_ID], tvb, offset+4, 4, ENC_BIG_ENDIAN);

		proto_tree_add_item(tree, hf_mikey[POS_HDR_CS_COUNT], tvb, offset+8, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_HDR_CS_ID_MAP_TYPE], tvb, offset+9, 1, ENC_BIG_ENDIAN);
	}

	offset += 10;
	for (i=0; i < ncs; i++) {
		tvbuff_t *sub_tvb;
		int len;

		sub_tvb = tvb_new_subset_remaining(tvb, offset);
		len = dissect_payload_cs_id(cs_id_map_type, mikey, sub_tvb, pinfo, tree);

		if (len < 0)
			return -1;

		offset += len;
	}

	return offset;
}

static int
dissect_payload_kemac(mikey_t *mikey, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint8 encr_alg;
	guint16 encr_length;
	guint16 mac_length;
	guint8 mac_alg;
	proto_item *key_data_item;
	proto_tree *key_data_tree;
	tvbuff_t *sub_tvb = NULL;

	tvb_ensure_bytes_exist(tvb, offset+0, 4);
	encr_alg = tvb_get_guint8(tvb, offset+1);
	encr_length = tvb_get_ntohs(tvb, offset+2);
	tvb_ensure_bytes_exist(tvb, offset+4, encr_length+1);
	mac_alg = tvb_get_guint8(tvb, offset+4+encr_length);

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_KEMAC_ENCR_ALG], tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_KEMAC_ENCR_DATA_LEN], tvb, 2, 2, ENC_BIG_ENDIAN);
		/* TODO: Add key decode for MIKEY_TYPE_PK_INIT and MIKEY_TYPE_RSA_R_RESP with NULL encryption */
		if (encr_alg == ENCR_NULL && mikey->type == MIKEY_TYPE_PSK_INIT && encr_length > 0) {
			/* We can decode easily the Key Data if NULL encryption is used */
			key_data_item = proto_tree_add_item(tree, hf_mikey_pl[PL_KEY_DATA], tvb, 4, encr_length, ENC_NA);
			key_data_tree = proto_item_add_subtree(key_data_item, ett_mikey_enc_data);

			sub_tvb = tvb_new_subset(tvb, offset+4, encr_length, encr_length);
			dissect_payload(PL_KEY_DATA, mikey, sub_tvb, pinfo, key_data_tree);
		} else {
			/* If Key Data is encrypted, show only the encr_data */
			proto_tree_add_item(tree, hf_mikey[POS_KEMAC_ENCR_DATA], tvb, 4, encr_length, ENC_NA);
		}
		proto_tree_add_item(tree, hf_mikey[POS_KEMAC_MAC_ALG], tvb, 4+encr_length, 1, ENC_BIG_ENDIAN);
	}

	switch (mac_alg) {
	case MAC_NULL:
		mac_length = 0;
		break;
	case MAC_HMAC_SHA_1_160:
		mac_length = 160/8;
		break;
	default:
		return -1;
	}

	tvb_ensure_bytes_exist(tvb, offset+4+encr_length+1, mac_length);
	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_KEMAC_MAC], tvb, 4+encr_length+1, mac_length, ENC_NA);
	}

	return 4+encr_length+1+mac_length;
}

static int
dissect_payload_pke(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint16 length;

	tvb_ensure_bytes_exist(tvb, offset+0, 3);
	length = ((tvb_get_guint8(tvb, offset+1) & 0x3f) << 8) |
		tvb_get_guint8(tvb, offset+2);

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_PKE_C], tvb, 1, 2, ENC_BIG_ENDIAN);

		proto_tree_add_item(tree, hf_mikey[POS_PKE_DATA_LEN], tvb, 1, 2, ENC_BIG_ENDIAN);
	}

	tvb_ensure_bytes_exist(tvb, offset+3, length);
	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_PKE_DATA], tvb, 3, length, ENC_NA);
	}
	return 3 + length;
}

static int
dissect_payload_dh(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint8 dh_group;
	int dh_length;
	guint8 kv;

	tvb_ensure_bytes_exist(tvb, offset+0, 2);
	dh_group = tvb_get_guint8(tvb, offset+1);

	switch (dh_group) {
	case DH_OAKLEY_5:
		dh_length = 1536/8;
		break;
	case DH_OAKLEY_1:
		dh_length = 768/8;
		break;
	case DH_OAKLEY_2:
		dh_length = 1024/8;
		break;
	default:
		return -1;
	}

	tvb_ensure_bytes_exist(tvb, offset+2, dh_length+1);
	kv = tvb_get_guint8(tvb, offset+2+dh_length) & 0x0f;

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_DH_GROUP], tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_DH_VALUE], tvb, 2, dh_length, ENC_NA);
		proto_tree_add_item(tree, hf_mikey[POS_DH_RESERV], tvb, 2+dh_length, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_DH_KV], tvb, 2+dh_length, 1, ENC_BIG_ENDIAN);
	}

	if (kv != 0) {
		return -1;
	}

	return 2+dh_length+1;
}

static int
dissect_payload_sign(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint16 length;

	tvb_ensure_bytes_exist(tvb, offset+0, 2);
	length = ((tvb_get_guint8(tvb, offset+0) & 0x0f) << 8) + tvb_get_guint8(tvb, offset+1);

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_SIGN_S_TYPE], tvb, 0, 2, ENC_BIG_ENDIAN);
		proto_tree_add_uint(tree, hf_mikey[POS_SIGNATURE_LEN], tvb, 0, 2, length);
	}

	tvb_ensure_bytes_exist(tvb, offset+2, length);
	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_SIGNATURE], tvb, 2, length, ENC_NA);
	}
	return 2 + length;
}

static int
dissect_payload_t(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint8 ts_type;
	int offset = 0;
	int len = 0;
	proto_tree* parent = NULL;

	tvb_ensure_bytes_exist(tvb, offset+0, 2);
	ts_type = tvb_get_guint8(tvb, offset+1);

	if (tree) {
		parent = proto_tree_get_parent(tree);
		proto_item_append_text(parent, " Type: %s", val_to_str_const(ts_type, ts_type_vals, "Unknown"));
		proto_tree_add_item(tree, hf_mikey[POS_TS_TYPE], tvb, offset+1, 1, ENC_BIG_ENDIAN);
	}

	switch (ts_type) {
	case T_NTP:
	case T_NTP_UTC:
		proto_tree_add_item(tree, hf_mikey[POS_TS_NTP], tvb, offset+2, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
		len = 10;
		break;
	case T_COUNTER:
		len = 6;
		break;
	default:
		len = -1;
		break;
	}

	return len;
}

static int
dissect_payload_id(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint8 type;
	guint16 length;
	proto_item* parent = NULL;

	tvb_ensure_bytes_exist(tvb, offset+0, 4);
	type = tvb_get_guint8(tvb, offset+1);
	length = tvb_get_ntohs(tvb, offset+2);
	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_ID_TYPE], tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_ID_LEN], tvb, 2, 2, ENC_BIG_ENDIAN);
	}

	tvb_ensure_bytes_exist(tvb, offset+4, length);
	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_ID], tvb, 4, length, ENC_ASCII|ENC_NA);

		parent = proto_tree_get_parent(tree);
		proto_item_append_text(parent, " %s: %s", val_to_str_const(type, id_type_vals, "Unknown"), tvb_get_ephemeral_string(tvb, 4, length));
	}

	return 4 + length;
}

static int
dissect_payload_cert(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint8 type;
	guint16 length;
	tvbuff_t *subtvb;
	proto_item* parent = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	tvb_ensure_bytes_exist(tvb, offset+0, 4);
	type = tvb_get_guint8(tvb, offset+1);
	length = tvb_get_ntohs(tvb, offset+2);

	tvb_ensure_bytes_exist(tvb, offset+4, length);

	if (tree) {
		parent = proto_tree_get_parent(tree);
		proto_tree_add_item(tree, hf_mikey[POS_CERT_TYPE], tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_CERT_LEN], tvb, 1, 2, ENC_BIG_ENDIAN);

		proto_item_append_text(parent, " Type: %s", val_to_str_const(type, cert_type_vals, "Unknown"));
	}

	subtvb = tvb_new_subset(tvb, offset+4, length, length);
	dissect_x509af_Certificate(FALSE, subtvb, 0, &asn1_ctx, tree, hf_mikey[POS_CERTIFICATE]);

	return 4 + length;
}

static int
dissect_payload_v(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint16 length;
	guint8 alg;

	tvb_ensure_bytes_exist(tvb, offset+0, 2);
	alg = tvb_get_guint8(tvb, offset+1);

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_V_AUTH_ALG], tvb, 1, 1, ENC_BIG_ENDIAN);
	}

	switch (alg) {
	case MAC_NULL:
		length = 0;
		break;
	case MAC_HMAC_SHA_1_160:
		length = 160/8;
		break;
	default:
		return -1;
	}

	tvb_ensure_bytes_exist(tvb, offset+2, length);
	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_V_DATA], tvb, 2, length, ENC_NA);
	}

	return 2 + length;
}

static int
dissect_payload_sp_param(enum sp_prot_t proto, tvbuff_t *tvb, proto_tree *tree)
{
	int offset = 0;
	guint8 type;
	guint8 length;
	proto_item *param_ti;
	proto_tree *param_tree;
	int hfindex;

	tvb_ensure_bytes_exist(tvb, offset+0, 2);
	type = tvb_get_guint8(tvb, offset+0);
	length = tvb_get_guint8(tvb, offset+1);
	tvb_ensure_bytes_exist(tvb, offset+2, length);

	/* Default */
	hfindex = hf_mikey[POS_SP_PARAM_F];

	switch(proto) {
	case SP_PROT_TYPE_SRTP:
		if (type < array_length(hf_mikey_sp_param))
			hfindex = hf_mikey_sp_param[type];
		break;
	}

	if (tree) {
		/*
		 * All the parameters in question are either FT_BYTES,
		 * in which case the byte order is inapplicable, or
		 * FT_UINT8, in which case it could be given as
		 * FT_BIG_ENDIAN as per bigger FT_UINT values, but
		 * ENC_NA also works, as there's only one byte.
		 */
		param_ti = proto_tree_add_item(tree, hfindex, tvb, 2, length, ENC_NA);
		param_tree = proto_item_add_subtree(param_ti, ett_mikey_sp_param);

		proto_tree_add_item(param_tree, hf_mikey[POS_SP_PARAM_F_TYPE], tvb, 0, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(param_tree, hf_mikey[POS_SP_PARAM_F_LEN], tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(param_tree, hf_mikey[POS_SP_PARAM_F_VALUE], tvb, 2, length, ENC_NA);
	}

	return 2+length;
}

static int
dissect_payload_sp(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint16 length;
	int sub_pos;
	guint8 no;
	enum sp_prot_t type;
	proto_item* parent = NULL;

	tvb_ensure_bytes_exist(tvb, offset+0, 5);
	length = tvb_get_ntohs(tvb, offset+3);
	no = tvb_get_guint8(tvb, offset+1);
	type = tvb_get_guint8(tvb, offset+2);

	if (tree) {
		parent = proto_tree_get_parent(tree);
		proto_tree_add_item(tree, hf_mikey[POS_SP_NO], tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_SP_TYPE], tvb, 2, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_SP_PARAM_LEN], tvb, 3, 2, ENC_BIG_ENDIAN);

		proto_item_append_text(parent, " No: %d, Type: %s", no, val_to_str_const(type, sp_prot_type_vals, "Unknown"));
	}

	tvb_ensure_bytes_exist(tvb, offset+5, length);
/* 	proto_tree_add_item(tree, hf_mikey[POS_SP_PARAM], tvb, 5, length, ENC_NA); */

	offset += 5;
	sub_pos = 0;

	while (sub_pos < length) {
		int param_len;
		tvbuff_t *subtvb;

		subtvb = tvb_new_subset(tvb, offset+sub_pos, length-sub_pos, length-sub_pos);
		param_len = dissect_payload_sp_param(type, subtvb, tree);

		if (param_len < 0)
			return -1;

		sub_pos += param_len;
	}

	return 5 + length;
}

static int
dissect_payload_rand(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	int offset = 0;
	guint16 length;

	tvb_ensure_bytes_exist(tvb, offset+0, 2);
	length = tvb_get_guint8(tvb, offset+1);

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_RAND_LEN], tvb, 1, 1, ENC_BIG_ENDIAN);
	}

	tvb_ensure_bytes_exist(tvb, offset+2, length);

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_RAND], tvb, 2, length, ENC_NA);
	}
	return 2 + length;
}

static int
dissect_payload_err(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *parent = NULL;
	guint8 err_no;

	tvb_ensure_bytes_exist(tvb, 0, 4);
	err_no = tvb_get_guint8(tvb, 1);

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_ERR_NO], tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_ERR_RESERVED], tvb, 2, 2, ENC_NA);
	}
	parent = proto_tree_get_parent(tree);
	proto_item_append_text(parent, ": %s", val_to_str_const(err_no, err_vals, "Unknown"));

	return 4;
}

static int
dissect_payload_keydata(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint16 offset;
	guint16 data_len;
	guint16 salt_len;
	guint16 kv_from_len;
	guint16 kv_to_len;
	guint16 kv_spi_len;
	guint8 key_type;
	guint8 kv_type;
	proto_item *parent = NULL;

	offset = 0;
	tvb_ensure_bytes_exist(tvb, 0, 4);
	key_type = tvb_get_guint8(tvb, 1) >> 4;
	kv_type  = tvb_get_guint8(tvb, 1) & 0x0f;
	data_len = tvb_get_ntohs(tvb, 2);

	tvb_ensure_bytes_exist(tvb, 4, data_len);
	offset += 4;

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_KEY_DATA_TYPE], tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_KEY_DATA_KV], tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_KEY_DATA_LEN], tvb, 2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_KEY_DATA], tvb, 4, data_len, ENC_NA);

		parent = proto_tree_get_parent(tree);
		proto_item_append_text(parent, " Type: %s", val_to_str_const(key_type, kd_vals, "Unknown"));
		offset += data_len;

		/* Dissect SALT key */
		if (key_type == KD_TGK_SALT || key_type == KD_TEK_SALT) {
			tvb_ensure_bytes_exist(tvb, offset, 2);
			salt_len = tvb_get_ntohs(tvb, offset);
			if (salt_len>0) {
				tvb_ensure_bytes_exist(tvb, offset+2, salt_len);
				proto_tree_add_item(tree, hf_mikey[POS_KEY_SALT_LEN], tvb, offset, 2, ENC_BIG_ENDIAN);
				proto_tree_add_item(tree, hf_mikey[POS_KEY_SALT], tvb, offset+2, salt_len, ENC_NA);
			}
			offset += 2+salt_len;
		}

		/* Dissect Key Validity */
		if (kv_type == KV_INTERVAL) {
			tvb_ensure_bytes_exist(tvb, offset, 1);
			kv_from_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_mikey[POS_KEY_KV_FROM_LEN], tvb, offset, 1, ENC_BIG_ENDIAN);
			if (kv_from_len > 0) {
				tvb_ensure_bytes_exist(tvb, offset+1, kv_from_len);
				proto_tree_add_item(tree, hf_mikey[POS_KEY_KV_FROM], tvb, offset+1, kv_from_len, ENC_NA);
			}
			offset += 1+kv_from_len;

			tvb_ensure_bytes_exist(tvb, offset, 1);
			kv_to_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_mikey[POS_KEY_KV_TO_LEN], tvb, offset, 1, ENC_BIG_ENDIAN);
			if (kv_to_len > 0) {
				tvb_ensure_bytes_exist(tvb, offset+1, kv_to_len);
				proto_tree_add_item(tree, hf_mikey[POS_KEY_KV_TO], tvb, offset+1, kv_to_len, ENC_NA);
			}
			offset += 1+kv_to_len;
		} else if (kv_type == KV_SPI) {
			tvb_ensure_bytes_exist(tvb, offset, 1);
			kv_spi_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_mikey[POS_KEY_KV_SPI_LEN], tvb, offset, 1, ENC_BIG_ENDIAN);
			if (kv_spi_len > 0) {
				tvb_ensure_bytes_exist(tvb, offset+1, kv_spi_len);
				proto_tree_add_item(tree, hf_mikey[POS_KEY_KV_SPI], tvb, offset+1, kv_spi_len, ENC_NA);
			}
			offset += 1+kv_spi_len;
		}
	}
	return offset;
}

static int
dissect_payload_general_ext(mikey_t *mikey _U_, tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *parent = NULL;
	int offset = 0;
	guint8 type;
	guint16 data_len;

	tvb_ensure_bytes_exist(tvb, offset+0, 4);
	type = tvb_get_guint8(tvb, offset+1);
	data_len = tvb_get_ntohs(tvb, offset+2);

	if (tree) {
		proto_tree_add_item(tree, hf_mikey[POS_GENERAL_EXT_TYPE], tvb, 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_mikey[POS_GENERAL_EXT_LEN], tvb, 2, 2, ENC_BIG_ENDIAN);
	}

	tvb_ensure_bytes_exist(tvb, offset+3, data_len);

	if (tree) {

		parent = proto_tree_get_parent(tree);
		if (type==1) {
			/* For SDP-IDs, show a string instead of raw bytes */
			proto_tree_add_item(tree, hf_mikey[POS_GENERAL_EXT_VALUE], tvb, 4, data_len, ENC_ASCII|ENC_NA);
		} else {
			proto_tree_add_item(tree, hf_mikey[POS_GENERAL_EXT_DATA], tvb, 4, data_len, ENC_NA);
		}
		proto_item_append_text(parent, " Type: %s", val_to_str_const(type, genext_type_vals, "Unknown"));
	}
	return 4 + data_len;
}

static const struct mikey_dissector_entry payload_map[] = {
	{ PL_HDR, dissect_payload_hdr },
	{ PL_KEMAC, dissect_payload_kemac },
	{ PL_PKE, dissect_payload_pke },
	{ PL_DH, dissect_payload_dh },
	{ PL_SIGN, dissect_payload_sign },
	{ PL_T, dissect_payload_t },
	{ PL_ID, dissect_payload_id },
	{ PL_CERT, dissect_payload_cert },
	{ PL_V, dissect_payload_v },
	{ PL_SP, dissect_payload_sp },
	{ PL_RAND, dissect_payload_rand },
	{ PL_ERR, dissect_payload_err },
	{ PL_KEY_DATA, dissect_payload_keydata },
	{ PL_GENERAL_EXT, dissect_payload_general_ext },
	{ 0, NULL }
};

static int
dissect_payload(enum payload_t payload, mikey_t *mikey, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	const struct mikey_dissector_entry *entry;

	entry = mikey_dissector_lookup(payload_map, payload);

	if (!entry || !entry->dissector) {
		return -1;
	}

	return entry->dissector(mikey, tvb, pinfo, tree);
}

/* MIKEY dissector */
static int
dissect_mikey(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti = NULL;
	proto_tree *mikey_tree = NULL;
	int offset = 0;
	int next_payload_offset;
	tvbuff_t *subtvb = NULL;
	int payload = -1;
	mikey_t *mikey;

	mikey = p_get_proto_data(pinfo->fd, proto_mikey);

	if (!mikey) {
		mikey = se_alloc0(sizeof(mikey_t));
		mikey->type = -1;
		p_add_proto_data(pinfo->fd, proto_mikey, mikey);
	}


	tvb_ensure_bytes_exist(tvb, offset, 3);
	next_payload_offset = offset+2;
	payload = -1;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_mikey, tvb, 0, -1, ENC_NA);
		mikey_tree = proto_item_add_subtree(ti, ett_mikey);
	}

	while (payload != 0) {
		int len;
		proto_item *sub_ti = NULL;
		proto_tree *mikey_payload_tree = NULL;
		int next_payload;

		next_payload = tvb_get_guint8(tvb, next_payload_offset);
		len = tvb_length_remaining(tvb, offset);
		subtvb = tvb_new_subset(tvb, offset, len, len);

		if (mikey_tree) {
			int hf = payload;

			if (hf >= PL_MAX)
				return -1;

			if (hf == -1)
				hf = 0;

			sub_ti = proto_tree_add_item(mikey_tree, hf_mikey_pl[hf], subtvb, 0, -1, ENC_NA);

			mikey_payload_tree = proto_item_add_subtree(sub_ti, ett_mikey_payload);
			if (payload != PL_HDR && payload != PL_SIGN)
				add_next_payload(tvb, mikey_payload_tree, next_payload_offset);
		}

		len = dissect_payload(payload, mikey, subtvb, pinfo, mikey_payload_tree);
		if (len < 0) {
			return -1;
		}

		if (sub_ti)
			proto_item_set_len(sub_ti, len);

		if (payload == PL_SIGN)
			break;

		payload = next_payload;
		offset += len;
		next_payload_offset = offset;
	}

	if (ti) {
		proto_item_append_text(ti, ": %s", val_to_str_const(mikey->type, data_type_vals, "Unknown"));
	}

	col_append_str(pinfo->cinfo, COL_PROTOCOL, "/MIKEY");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Mikey: %s", val_to_str_const(mikey->type, data_type_vals, "Unknown"));

	/* Return the amount of data this dissector was able to dissect */
	return tvb_length(tvb);
}


/* Register the protocol with Wireshark */

void
proto_register_mikey(void)
{

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		/* Payload types */
		{ &hf_mikey_pl[PL_HDR+1],
		  { PL_HDR_TEXT, "mikey.hdr",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_KEMAC],
		  { PL_KEMAC_TEXT, "mikey.kemac",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_PKE],
		  { PL_PKE_TEXT, "mikey.",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_DH],
		  { PL_DH_TEXT, "mikey.dh",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_SIGN],
		  { PL_SIGN_TEXT, "mikey.sign",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_T],
		  { PL_T_TEXT, "mikey.t",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_ID],
		  { PL_ID_TEXT, "mikey.id",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_CERT],
		  { PL_CERT_TEXT, "mikey.cert",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_CHASH],
		  { PL_CHASH_TEXT, "mikey.chash",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_V],
		  { PL_V_TEXT, "mikey.v",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_SP],
		  { PL_SP_TEXT, "mikey.sp",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_RAND],
		  { PL_RAND_TEXT, "mikey.rand",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_ERR],
		  { PL_ERR_TEXT, "mikey.err",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_KEY_DATA],
		  { PL_KEY_DATA_TEXT, "mikey.key",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_pl[PL_GENERAL_EXT],
		  { PL_GENERAL_EXT_TEXT, "mikey.ext",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* Common Header payload (HDR) */
		{ &hf_mikey[POS_HDR_VERSION],
		  { "Version", "mikey.version",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_HDR_DATA_TYPE],
		  { "Data Type", "mikey.type",
		    FT_UINT8, BASE_DEC, VALS(data_type_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_NEXT_PAYLOAD],
		  { "Next Payload", "mikey.next_payload",
		    FT_UINT8, BASE_DEC, VALS(payload_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_HDR_V],
		  { "V", "mikey.v",
		    FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
		    NULL, HFILL }},
		{ &hf_mikey[POS_HDR_PRF_FUNC],
		  { "PRF func", "mikey.prf_func",
		    FT_UINT8, BASE_DEC, VALS(prf_func_vals), 0x7f,
		    NULL, HFILL }},
		{ &hf_mikey[POS_HDR_CSB_ID],
		  { "CSB ID", "mikey.csb_id",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_HDR_CS_COUNT],
		  { "#CS", "mikey.cs_count",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_HDR_CS_ID_MAP_TYPE],
		  { "CS ID map type", "mikey.cs_id_map_type",
		    FT_UINT8, BASE_DEC, VALS(cs_id_map_vals), 0x0,
		    NULL, HFILL }},

		/* SRTP ID */
		{ &hf_mikey[POS_ID_SRTP],
		  { "SRTP ID", "mikey.srtp_id",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_ID_SRTP_NO],
		  { "Policy No", "mikey.srtp_id.policy_no",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_ID_SRTP_SSRC],
		  { "SSRC", "mikey.srtp_id.ssrc",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_ID_SRTP_ROC],
		  { "ROC", "mikey.srtp_id.roc",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		/* Key Data Transport payload (KEMAC) */
		{ &hf_mikey[POS_KEMAC_ENCR_ALG],
		  { "Encr alg", "mikey.kemac.encr_alg",
		    FT_UINT8, BASE_DEC, VALS(encr_alg_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEMAC_ENCR_DATA_LEN],
		  { "Key data len", "mikey.kemac.key_data_len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEMAC_ENCR_DATA],
		  { "Key data", "mikey.kemac.key_data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEMAC_MAC_ALG],
		  { "Mac alg", "mikey.kemac.mac_alg",
		    FT_UINT8, BASE_DEC, VALS(mac_alg_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEMAC_MAC],
		  { "MAC", "mikey.kemac.mac",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* Envelope Data payload (PKE) */
		{ &hf_mikey[POS_PKE_C],
		  { "C", "mikey.pke.c",
		    FT_UINT16, BASE_DEC, VALS(pke_c_vals), 0xc000,
		    NULL, HFILL }},
		{ &hf_mikey[POS_PKE_DATA_LEN],
		  { "Data len", "mikey.pke.len",
		    FT_UINT16, BASE_DEC, NULL, 0x3fff,
		    NULL, HFILL }},
		{ &hf_mikey[POS_PKE_DATA],
		  { "Data", "mikey.pke.data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* DH data payload (DH) */
		{ &hf_mikey[POS_DH_GROUP],
		  { "DH-Group", "mikey.dh.group",
		    FT_UINT8, BASE_DEC, VALS(oakley_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_DH_VALUE],
		  { "DH-Value", "mikey.dh.value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_DH_RESERV],
		  { "Reserv", "mikey.dh.reserv",
		    FT_UINT8, BASE_HEX, NULL, 0xf0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_DH_KV],
		  { "KV", "mikey.dh.kv",
		    FT_UINT8, BASE_DEC, VALS(kv_vals), 0x0f,
		    NULL, HFILL }},

		/* Signature payload (SIGN) */
		{ &hf_mikey[POS_SIGN_S_TYPE],
		  { "Signature type", "mikey.sign.type",
		    FT_UINT16, BASE_DEC, VALS(sign_s_vals), 0xf000,
		    NULL, HFILL }},
		{ &hf_mikey[POS_SIGNATURE_LEN],
		  { "Signature len", "mikey.sign.len",
		    FT_UINT16, BASE_DEC, NULL, 0x0fff,
		    NULL, HFILL }},
		{ &hf_mikey[POS_SIGNATURE],
		  { "Signature", "mikey.sign.data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* Timestamp payload (T) */
		{ &hf_mikey[POS_TS_TYPE],
		  { "TS type", "mikey.t.ts_type",
		    FT_UINT8, BASE_DEC, VALS(ts_type_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_TS_NTP],
		  { "NTP timestamp", "mikey.t.ntp",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_mikey[POS_PAYLOAD_STR],
		  { "Payload", "mikey.payload",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* ID payload (ID) */
		{ &hf_mikey[POS_ID_TYPE],
		  { "ID type", "mikey.id.type",
		    FT_UINT8, BASE_DEC, VALS(id_type_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_ID_LEN],
		  { "ID len", "mikey.id.len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_ID],
		  { "ID", "mikey.id.data",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* Certificate payload (CERT) */
		{ &hf_mikey[POS_CERT_LEN],
		  { "Certificate len", "mikey.cert.len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_CERT_TYPE],
		  { "Certificate type", "mikey.cert.type",
		    FT_UINT8, BASE_DEC, VALS(cert_type_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_CERTIFICATE],
		  { "Certificate", "mikey.cert.data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* Ver msg payload (V) */
		{ &hf_mikey[POS_V_AUTH_ALG],
		  { "Auth alg", "mikey.v.auth_alg",
		    FT_UINT8, BASE_DEC, VALS(mac_alg_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_V_DATA],
		  { "Ver data", "mikey.v.ver_data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* Security Policy payload (SP) */
		{ &hf_mikey[POS_SP_NO],
		  { "Policy No", "mikey.sp.no",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_SP_TYPE],
		  { "Protocol type", "mikey.sp.proto_type",
		    FT_UINT8, BASE_DEC, VALS(sp_prot_type_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_SP_PARAM_LEN],
		  { "Policy param length", "mikey.sp.param_len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		/* Security Policy param */
		{ &hf_mikey[POS_SP_PARAM_F],
		  { "Policy param", "mikey.sp.param",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_SP_PARAM_F_TYPE],
		  { "Type", "mikey.sp.param.type",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_SP_PARAM_F_LEN],
		  { "Length", "mikey.sp.param.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_SP_PARAM_F_VALUE],
		  { "Value", "mikey.sp.patam.value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* SRTP policy param */
		{ &hf_mikey_sp_param[SP_ENCR_ALG],
		  { SP_TEXT_ENCR_ALG, "mikey.sp.encr_alg",
		    FT_UINT8, BASE_DEC, VALS(sp_encr_alg_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_ENCR_LEN],
		  { SP_TEXT_ENCR_LEN, "mikey.sp.encr_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_AUTH_ALG],
		  { SP_TEXT_AUTH_ALG, "mikey.sp.auth_alg",
		    FT_UINT8, BASE_DEC, VALS(sp_auth_alg_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_AUTH_KEY_LEN],
		  { SP_TEXT_AUTH_KEY_LEN, "mikey.sp.auth_key_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_SALT_LEN],
		  { SP_TEXT_SALT_LEN, "mikey.sp.salt_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_PRF],
		  { SP_TEXT_PRF, "mikey.sp.prf",
		    FT_UINT8, BASE_DEC, VALS(sp_prf_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_KD_RATE],
		  { SP_TEXT_KD_RATE, "mikey.sp.kd_rate",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_SRTP_ENCR],
		  { SP_TEXT_SRTP_ENCR, "mikey.sp.srtp_encr",
		    FT_UINT8, BASE_DEC, VALS(on_off_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_SRTCP_ENCR],
		  { SP_TEXT_SRTCP_ENCR, "mikey.sp.srtcp_encr",
		    FT_UINT8, BASE_DEC, VALS(on_off_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_FEC],
		  { SP_TEXT_FEC, "mikey.sp.fec",
		    FT_UINT8, BASE_DEC, VALS(sp_fec_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_SRTP_AUTH],
		  { SP_TEXT_SRTP_AUTH, "mikey.sp.srtp_auth",
		    FT_UINT8, BASE_DEC, VALS(on_off_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_AUTH_TAG_LEN],
		  { SP_TEXT_AUTH_TAG_LEN, "mikey.sp.auth_tag_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey_sp_param[SP_SRTP_PREFIX],
		  { SP_TEXT_SRTP_PREFIX, "mikey.sp.srtp_prefix",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		/* RAND payload (RAND) */
		{ &hf_mikey[POS_RAND_LEN],
		  { "RAND len", "mikey.rand.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_RAND],
		  { "RAND", "mikey.rand.data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* Error payload (ERR) */
		{ &hf_mikey[POS_ERR_NO],
		  { "Error no.", "mikey.err.no",
		    FT_UINT8, BASE_DEC, VALS(err_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_ERR_RESERVED],
		  { "Reserved", "mikey.err.reserved",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* Key data sub-payload */
		{ &hf_mikey[POS_KEY_DATA_TYPE],
		  { "Type", "mikey.key.type",
		    FT_UINT8, BASE_DEC, VALS(kd_vals), 0xf0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_DATA_KV],
		  { "KV", "mikey.key.kv",
		    FT_UINT8, BASE_DEC, VALS(kv_vals), 0x0f,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_DATA_LEN],
		  { "Key len", "mikey.key.data.len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_DATA],
		  { "Key", "mikey.key.data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_SALT_LEN],
		  { "Salt key len", "mikey.key.salt.len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_SALT],
		  { "Salt key", "mikey.key.salt",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_KV_FROM_LEN],
		  { "Valid from len", "mikey.key.kv.from.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_KV_FROM],
		  { "Valid from", "mikey.key.kv.from",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_KV_TO_LEN],
		  { "Valid to len", "mikey.key.kv.to.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_KV_TO],
		  { "Valid to", "mikey.key.kv.to",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_KV_SPI_LEN],
		  { "Valid SPI len", "mikey.key.kv.spi.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_KEY_KV_SPI],
		  { "Valid SPI", "mikey.key.kv.spi",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		/* General Extension payload (GENERAL_EXT) */
		{ &hf_mikey[POS_GENERAL_EXT_TYPE],
		  { "Extension type", "mikey.ext.type",
		    FT_UINT8, BASE_DEC, VALS(genext_type_vals), 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_GENERAL_EXT_LEN],
		  { "Length", "mikey.ext.len",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_GENERAL_EXT_DATA],
		  { "Data", "mikey.ext.data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},
		{ &hf_mikey[POS_GENERAL_EXT_VALUE],
		  { "Value", "mikey.ext.value",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

/*
		{ &hf_mikey[POS_SP_PARAM],
		  { "Policy param", "mikey.policy_param",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_mikey[POS_PAYLOAD],
		  { "Payload", "mikey.payload",
		    FT_BYTES, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},
*/
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_mikey,
		&ett_mikey_payload,
		&ett_mikey_sp_param,
		&ett_mikey_hdr_id,
		&ett_mikey_enc_data
	};

	module_t *mikey_module;

	/* Register the protocol name and description */
	proto_mikey = proto_register_protocol("Multimedia Internet KEYing",
		"MIKEY", "mikey");
	new_register_dissector("mikey", dissect_mikey, proto_mikey);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_mikey, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register our configuration options */
	mikey_module = prefs_register_protocol(proto_mikey, proto_reg_handoff_mikey);

	prefs_register_uint_preference(mikey_module, "udp.port", "MIKEY UDP Port",
		"Set the port for MIKEY messages (if other than the default of 2269)",
		10, &global_mikey_udp_port);

	prefs_register_uint_preference(mikey_module, "tcp.port", "MIKEY TCP Port",
		"Set the port for MIKEY messages (if other than the default of 2269)",
		10, &global_mikey_tcp_port);

}


void
proto_reg_handoff_mikey(void)
{
	static gboolean inited = FALSE;
	static dissector_handle_t mikey_handle;
	static guint mikey_tcp_port;
	static guint mikey_udp_port;

	if (!inited) {
		mikey_handle = new_create_dissector_handle(dissect_mikey, proto_mikey);
		dissector_add_string("key_mgmt", "mikey", mikey_handle);
		inited = TRUE;
	} else {
		dissector_delete_uint("udp.port", mikey_udp_port, mikey_handle);
		dissector_delete_uint("tcp.port", mikey_tcp_port, mikey_handle);
	}

	dissector_add_uint("udp.port", global_mikey_udp_port, mikey_handle);
	dissector_add_uint("tcp.port", global_mikey_tcp_port, mikey_handle);

	mikey_udp_port = global_mikey_udp_port;
	mikey_tcp_port = global_mikey_tcp_port;
}
