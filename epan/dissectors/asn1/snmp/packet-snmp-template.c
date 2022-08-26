/* packet-snmp.c
 * Routines for SNMP (simple network management protocol)
 * Copyright (C) 1998 Didier Jorand
 *
 * See RFC 1157 for SNMPv1.
 *
 * See RFCs 1901, 1905, and 1906 for SNMPv2c.
 *
 * See RFCs 1905, 1906, 1909, and 1910 for SNMPv2u [historic].
 *
 * See RFCs 2570-2576 for SNMPv3
 * Updated to use the asn2wrs compiler made by Tomas Kukosa
 * Copyright (C) 2005 - 2006 Anders Broman [AT] ericsson.com
 *
 * See RFC 3414 for User-based Security Model for SNMPv3
 * See RFC 3826 for  (AES) Cipher Algorithm in the SNMP USM
 * See RFC 2578 for Structure of Management Information Version 2 (SMIv2)
 * Copyright (C) 2007 Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Some stuff from:
 *
 * GXSNMP -- An snmp mangament application
 * Copyright (C) 1998 Gregory McLean & Jochen Friedrich
 * Beholder RMON ethernet network monitor,Copyright (C) 1993 DNPAP group
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#if 0
#include <stdio.h>
#define D(args) do {printf args; fflush(stdout); } while(0)
#endif

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/next_tvb.h>
#include <epan/uat.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/srt_table.h>
#include <epan/tap.h>
#include "packet-ipx.h"
#include "packet-hpext.h"
#include "packet-ber.h"
#include "packet-snmp.h"
#include <wsutil/wsgcrypt.h>

#define PNAME  "Simple Network Management Protocol"
#define PSNAME "SNMP"
#define PFNAME "snmp"

#define UDP_PORT_SNMP		161
#define UDP_PORT_SNMP_TRAP	162
#define TCP_PORT_SNMP		161
#define TCP_PORT_SNMP_TRAP	162
#define TCP_PORT_SMUX		199
#define UDP_PORT_SNMP_PATROL 8161
#define SNMP_NUM_PROCEDURES 8

/* Initialize the protocol and registered fields */
static int snmp_tap = -1;
static int proto_snmp = -1;
static int proto_smux = -1;

static gboolean display_oid = TRUE;
static gboolean snmp_var_in_tree = TRUE;

void proto_register_snmp(void);
void proto_reg_handoff_snmp(void);
void proto_register_smux(void);
void proto_reg_handoff_smux(void);

static void snmp_usm_password_to_key(const snmp_usm_auth_model_t model, const guint8 *password, guint passwordlen,
	const guint8 *engineID, guint engineLength, guint8 *key);

static tvbuff_t* snmp_usm_priv_des(snmp_usm_params_t*, tvbuff_t*, packet_info *pinfo, gchar const**);
static tvbuff_t* snmp_usm_priv_aes128(snmp_usm_params_t*, tvbuff_t*, packet_info *pinfo, gchar const**);
static tvbuff_t* snmp_usm_priv_aes192(snmp_usm_params_t*, tvbuff_t*, packet_info *pinfo, gchar const**);
static tvbuff_t* snmp_usm_priv_aes256(snmp_usm_params_t*, tvbuff_t*, packet_info *pinfo, gchar const**);

static gboolean snmp_usm_auth(const packet_info *pinfo, const snmp_usm_auth_model_t model, snmp_usm_params_t* p, guint8**, guint*, gchar const**);

static const value_string auth_types[] = {
	{SNMP_USM_AUTH_MD5,"MD5"},
	{SNMP_USM_AUTH_SHA1,"SHA1"},
	{SNMP_USM_AUTH_SHA2_224,"SHA2-224"},
	{SNMP_USM_AUTH_SHA2_256,"SHA2-256"},
	{SNMP_USM_AUTH_SHA2_384,"SHA2-384"},
	{SNMP_USM_AUTH_SHA2_512,"SHA2-512"},
	{0,NULL}
};

static const guint auth_hash_len[] = {
	HASH_MD5_LENGTH,
	HASH_SHA1_LENGTH,
	HASH_SHA2_224_LENGTH,
	HASH_SHA2_256_LENGTH,
	HASH_SHA2_384_LENGTH,
	HASH_SHA2_512_LENGTH
};

static const guint auth_tag_len[] = {
	12,
	12,
	16,
	24,
	32,
	48
};

static const enum gcry_md_algos auth_hash_algo[] = {
	GCRY_MD_MD5,
	GCRY_MD_SHA1,
	GCRY_MD_SHA224,
	GCRY_MD_SHA256,
	GCRY_MD_SHA384,
	GCRY_MD_SHA512
};

#define PRIV_DES	0
#define PRIV_AES128	1
#define PRIV_AES192	2
#define PRIV_AES256	3

static const value_string priv_types[] = {
	{ PRIV_DES,    "DES" },
	{ PRIV_AES128, "AES" },
	{ PRIV_AES192, "AES192" },
	{ PRIV_AES256, "AES256" },
	{ 0, NULL}
};
static snmp_usm_decoder_t priv_protos[] = {
	snmp_usm_priv_des,
	snmp_usm_priv_aes128,
	snmp_usm_priv_aes192,
	snmp_usm_priv_aes256
};

static snmp_ue_assoc_t* ueas = NULL;
static guint num_ueas = 0;
static snmp_ue_assoc_t* localized_ues = NULL;
static snmp_ue_assoc_t* unlocalized_ues = NULL;
/****/

/* Variables used for handling enterprise specific trap types */
typedef struct _snmp_st_assoc_t {
	char *enterprise;
	guint trap;
	char *desc;
} snmp_st_assoc_t;
static guint num_specific_traps = 0;
static snmp_st_assoc_t *specific_traps = NULL;
static const char *enterprise_oid = NULL;
static guint generic_trap = 0;
static guint32 snmp_version = 0;
static guint32 RequestID = -1;

static snmp_usm_params_t usm_p = {FALSE,FALSE,0,0,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL,FALSE};

#define TH_AUTH   0x01
#define TH_CRYPT  0x02
#define TH_REPORT 0x04

/* desegmentation of SNMP-over-TCP */
static gboolean snmp_desegment = TRUE;

/* Global variables */

guint32 MsgSecurityModel;
tvbuff_t *oid_tvb=NULL;
tvbuff_t *value_tvb=NULL;

static dissector_handle_t snmp_handle;
static dissector_handle_t data_handle;

static next_tvb_list_t *var_list;

static int hf_snmp_response_in = -1;
static int hf_snmp_response_to = -1;
static int hf_snmp_time = -1;

static int hf_snmp_v3_flags_auth = -1;
static int hf_snmp_v3_flags_crypt = -1;
static int hf_snmp_v3_flags_report = -1;

static int hf_snmp_engineid_conform = -1;
static int hf_snmp_engineid_enterprise = -1;
static int hf_snmp_engineid_format = -1;
static int hf_snmp_engineid_ipv4 = -1;
static int hf_snmp_engineid_ipv6 = -1;
static int hf_snmp_engineid_cisco_type = -1;
static int hf_snmp_engineid_mac = -1;
static int hf_snmp_engineid_text = -1;
static int hf_snmp_engineid_time = -1;
static int hf_snmp_engineid_data = -1;
static int hf_snmp_decryptedPDU = -1;
static int hf_snmp_msgAuthentication = -1;

static int hf_snmp_noSuchObject = -1;
static int hf_snmp_noSuchInstance = -1;
static int hf_snmp_endOfMibView = -1;
static int hf_snmp_unSpecified = -1;

static int hf_snmp_integer32_value = -1;
static int hf_snmp_octetstring_value = -1;
static int hf_snmp_oid_value = -1;
static int hf_snmp_null_value = -1;
static int hf_snmp_ipv4_value = -1;
static int hf_snmp_ipv6_value = -1;
static int hf_snmp_anyaddress_value = -1;
static int hf_snmp_unsigned32_value = -1;
static int hf_snmp_unknown_value = -1;
static int hf_snmp_opaque_value = -1;
static int hf_snmp_nsap_value = -1;
static int hf_snmp_counter_value = -1;
static int hf_snmp_timeticks_value = -1;
static int hf_snmp_big_counter_value = -1;
static int hf_snmp_gauge32_value = -1;

static int hf_snmp_objectname = -1;
static int hf_snmp_scalar_instance_index = -1;

static int hf_snmp_var_bind_str = -1;
static int hf_snmp_agentid_trailer = -1;

#include "packet-snmp-hf.c"

/* Initialize the subtree pointers */
static gint ett_smux = -1;
static gint ett_snmp = -1;
static gint ett_engineid = -1;
static gint ett_msgFlags = -1;
static gint ett_encryptedPDU = -1;
static gint ett_decrypted = -1;
static gint ett_authParameters = -1;
static gint ett_internet = -1;
static gint ett_varbind = -1;
static gint ett_name = -1;
static gint ett_value = -1;
static gint ett_decoding_error = -1;

#include "packet-snmp-ett.c"

static expert_field ei_snmp_failed_decrypted_data_pdu = EI_INIT;
static expert_field ei_snmp_decrypted_data_bad_formatted = EI_INIT;
static expert_field ei_snmp_verify_authentication_error = EI_INIT;
static expert_field ei_snmp_authentication_ok = EI_INIT;
static expert_field ei_snmp_authentication_error = EI_INIT;
static expert_field ei_snmp_varbind_not_uni_class_seq = EI_INIT;
static expert_field ei_snmp_varbind_has_indicator = EI_INIT;
static expert_field ei_snmp_objectname_not_oid = EI_INIT;
static expert_field ei_snmp_objectname_has_indicator = EI_INIT;
static expert_field ei_snmp_value_not_primitive_encoding = EI_INIT;
static expert_field ei_snmp_invalid_oid = EI_INIT;
static expert_field ei_snmp_varbind_wrong_tag = EI_INIT;
static expert_field ei_snmp_varbind_response = EI_INIT;
static expert_field ei_snmp_no_instance_subid = EI_INIT;
static expert_field ei_snmp_wrong_num_of_subids = EI_INIT;
static expert_field ei_snmp_index_suboid_too_short = EI_INIT;
static expert_field ei_snmp_unimplemented_instance_index = EI_INIT;
static expert_field ei_snmp_index_suboid_len0 = EI_INIT;
static expert_field ei_snmp_index_suboid_too_long = EI_INIT;
static expert_field ei_snmp_index_string_too_long = EI_INIT;
static expert_field ei_snmp_column_parent_not_row = EI_INIT;
static expert_field ei_snmp_uint_too_large = EI_INIT;
static expert_field ei_snmp_int_too_large = EI_INIT;
static expert_field ei_snmp_integral_value0 = EI_INIT;
static expert_field ei_snmp_missing_mib = EI_INIT;
static expert_field ei_snmp_varbind_wrong_length_value = EI_INIT;
static expert_field ei_snmp_varbind_wrong_class_tag = EI_INIT;
static expert_field ei_snmp_rfc1910_non_conformant = EI_INIT;
static expert_field ei_snmp_rfc3411_non_conformant = EI_INIT;
static expert_field ei_snmp_version_unknown = EI_INIT;
static expert_field ei_snmp_trap_pdu_obsolete = EI_INIT;

static const true_false_string auth_flags = {
	"OK",
	"Failed"
};

/* Security Models */

#define SNMP_SEC_ANY			0
#define SNMP_SEC_V1			1
#define SNMP_SEC_V2C			2
#define SNMP_SEC_USM			3

static const value_string sec_models[] = {
	{ SNMP_SEC_ANY,			"Any" },
	{ SNMP_SEC_V1,			"V1" },
	{ SNMP_SEC_V2C,			"V2C" },
	{ SNMP_SEC_USM,			"USM" },
	{ 0,				NULL }
};

#if 0
/* SMUX PDU types */
#define SMUX_MSG_OPEN 		0
#define SMUX_MSG_CLOSE		1
#define SMUX_MSG_RREQ		2
#define SMUX_MSG_RRSP		3
#define SMUX_MSG_SOUT		4

static const value_string smux_types[] = {
	{ SMUX_MSG_OPEN,	"Open" },
	{ SMUX_MSG_CLOSE,	"Close" },
	{ SMUX_MSG_RREQ,	"Registration Request" },
	{ SMUX_MSG_RRSP,	"Registration Response" },
	{ SMUX_MSG_SOUT,	"Commit Or Rollback" },
	{ 0,			NULL }
};
#endif

/* Procedure names (used in Service Response Time) */
const value_string snmp_procedure_names[] = {
	{ 0,	"Get" },
	{ 1,	"GetNext" },
	{ 3,	"Set" },
	{ 4,	"Register" },
	{ 5,	"Bulk" },
	{ 6,	"Inform" },
	{ 0,	NULL }
};

#define SNMP_IPA    0		/* IP Address */
#define SNMP_CNT    1		/* Counter (Counter32) */
#define SNMP_GGE    2		/* Gauge (Gauge32) */
#define SNMP_TIT    3		/* TimeTicks */
#define SNMP_OPQ    4		/* Opaque */
#define SNMP_NSP    5		/* NsapAddress */
#define SNMP_C64    6		/* Counter64 */
#define SNMP_U32    7		/* Uinteger32 */

#define SERR_NSO    0
#define SERR_NSI    1
#define SERR_EOM    2


dissector_table_t value_sub_dissectors_table;

/*
 * Data structure attached to a conversation, request/response information
 */
typedef struct snmp_conv_info_t {
	wmem_map_t *request_response;
} snmp_conv_info_t;

static snmp_request_response_t *
snmp_get_request_response_pointer(wmem_map_t *map, guint32 requestId)
{
	snmp_request_response_t *srrp=(snmp_request_response_t *)wmem_map_lookup(map, &requestId);
	if (!srrp) {
		srrp=wmem_new0(wmem_file_scope(), snmp_request_response_t);
		srrp->requestId=requestId;
		wmem_map_insert(map, &(srrp->requestId), (void *)srrp);
	}

	return srrp;
}

static snmp_request_response_t*
snmp_match_request_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint requestId, guint procedure_id, snmp_conv_info_t *snmp_info)
{
	snmp_request_response_t *srrp=NULL;

	DISSECTOR_ASSERT_HINT(snmp_info, "No SNMP info from ASN1 context");

	/* get or create request/response pointer based on request id */
	srrp=(snmp_request_response_t *)snmp_get_request_response_pointer(snmp_info->request_response, requestId);

	// if not visited fill the request/response data
	if (!PINFO_FD_VISITED(pinfo)) {
		switch(procedure_id)
		{
			case SNMP_REQ_GET:
			case SNMP_REQ_GETNEXT:
			case SNMP_REQ_SET:
			case SNMP_REQ_GETBULK:
			case SNMP_REQ_INFORM:
				srrp->request_frame_id=pinfo->fd->num;
				srrp->response_frame_id=0;
				srrp->request_time=pinfo->abs_ts;
				srrp->request_procedure_id=procedure_id;
				break;
			case SNMP_RES_GET:
				srrp->response_frame_id=pinfo->fd->num;
				break;
			default:
				return NULL;
		}
	}

	/* if request and response was matched */
	if (srrp->request_frame_id!=0 && srrp->response_frame_id!=0)
	{
		proto_item *it;

		// if it is a request
		if (srrp->request_frame_id == pinfo->fd->num)
		{
			it=proto_tree_add_uint(tree, hf_snmp_response_in, tvb, 0, 0, srrp->response_frame_id);
			proto_item_set_generated(it);
		} else {
			nstime_t ns;
			it=proto_tree_add_uint(tree, hf_snmp_response_to, tvb, 0, 0, srrp->request_frame_id);
			proto_item_set_generated(it);
			nstime_delta(&ns, &pinfo->abs_ts, &srrp->request_time);
			it=proto_tree_add_time(tree, hf_snmp_time, tvb, 0, 0, &ns);
			proto_item_set_generated(it);

			return srrp;
		}
	}

	return NULL;
}

static void
snmpstat_init(struct register_srt* srt _U_, GArray* srt_array)
{
	srt_stat_table *snmp_srt_table;
	guint32 i;

	snmp_srt_table = init_srt_table("SNMP Commands", NULL, srt_array, SNMP_NUM_PROCEDURES, NULL, "snmp.data", NULL);
	for (i = 0; i < SNMP_NUM_PROCEDURES; i++)
	{
		init_srt_table_row(snmp_srt_table, i, val_to_str_const(i, snmp_procedure_names, "<unknown>"));
	}
}

/* This is called only if request and response was matched -> no need to return anything than TAP_PACKET_REDRAW */
static tap_packet_status
snmpstat_packet(void *psnmp, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi, tap_flags_t flags _U_)
{
	guint i = 0;
	srt_stat_table *snmp_srt_table;
	const snmp_request_response_t *snmp=(const snmp_request_response_t *)psi;
	srt_data_t *data = (srt_data_t *)psnmp;

	snmp_srt_table = g_array_index(data->srt_array, srt_stat_table*, i);

	add_srt_table_data(snmp_srt_table, snmp->request_procedure_id, &snmp->request_time, pinfo);
	return TAP_PACKET_REDRAW;
}

static const gchar *
snmp_lookup_specific_trap (guint specific_trap)
{
	guint i;

	for (i = 0; i < num_specific_traps; i++) {
		snmp_st_assoc_t *u = &(specific_traps[i]);

		if ((u->trap == specific_trap) &&
		    (strcmp (u->enterprise, enterprise_oid) == 0))
		{
			return u->desc;
		}
	}

	return NULL;
}

static int
dissect_snmp_variable_string(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{

	proto_tree_add_item(tree, hf_snmp_var_bind_str, tvb, 0, -1, ENC_ASCII);

	return tvb_captured_length(tvb);
}

/*
DateAndTime ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "2d-1d-1d,1d:1d:1d.1d,1a1d:1d"
    STATUS       current
    DESCRIPTION
            "A date-time specification.

            field  octets  contents                  range
            -----  ------  --------                  -----
              1      1-2   year*                     0..65536
              2       3    month                     1..12
              3       4    day                       1..31
              4       5    hour                      0..23
              5       6    minutes                   0..59
              6       7    seconds                   0..60
                           (use 60 for leap-second)
              7       8    deci-seconds              0..9
              8       9    direction from UTC        '+' / '-'
              9      10    hours from UTC*           0..13
             10      11    minutes from UTC          0..59

            * Notes:
            - the value of year is in network-byte order
            - daylight saving time in New Zealand is +13

            For example, Tuesday May 26, 1992 at 1:30:15 PM EDT would be
            displayed as:

                             1992-5-26,13:30:15.0,-4:0

            Note that if only local time is known, then timezone
            information (fields 8-10) is not present."
    SYNTAX       OCTET STRING (SIZE (8 | 11))
*/
static proto_item *
dissect_snmp_variable_date_and_time(proto_tree *tree, packet_info *pinfo, int hfid, tvbuff_t *tvb, int offset, int length)
{
	guint16 year;
	guint8 month;
	guint8 day;
	guint8 hour;
	guint8 minutes;
	guint8 seconds;
	guint8 deci_seconds;
	guint8 hour_from_utc;
	guint8 min_from_utc;
	gchar *str;

	year			= tvb_get_ntohs(tvb,offset);
	month			= tvb_get_guint8(tvb,offset+2);
	day			= tvb_get_guint8(tvb,offset+3);
	hour			= tvb_get_guint8(tvb,offset+4);
	minutes			= tvb_get_guint8(tvb,offset+5);
	seconds			= tvb_get_guint8(tvb,offset+6);
	deci_seconds		= tvb_get_guint8(tvb,offset+7);
	if(length > 8){
		hour_from_utc	= tvb_get_guint8(tvb,offset+9);
		min_from_utc	= tvb_get_guint8(tvb,offset+10);

		str = wmem_strdup_printf(pinfo->pool,
			 "%u-%u-%u, %u:%u:%u.%u UTC %s%u:%u",
			 year,
			 month,
			 day,
			 hour,
			 minutes,
			 seconds,
			 deci_seconds,
			 tvb_get_string_enc(pinfo->pool,tvb,offset+8,1,ENC_ASCII|ENC_NA),
			 hour_from_utc,
			 min_from_utc);
	}else{
		 str = wmem_strdup_printf(pinfo->pool,
			 "%u-%u-%u, %u:%u:%u.%u",
			 year,
			 month,
			 day,
			 hour,
			 minutes,
			 seconds,
			 deci_seconds);
	}

	return proto_tree_add_string(tree, hfid, tvb, offset, length, str);

}

/*
 *  dissect_snmp_VarBind
 *  this routine dissects variable bindings, looking for the oid information in our oid reporsitory
 *  to format and add the value adequatelly.
 *
 * The choice to handwrite this code instead of using the asn compiler is to avoid having tons
 * of uses of global variables distributed in very different parts of the code.
 * Other than that there's a cosmetic thing: the tree from ASN generated code would be so
 * convoluted due to the nesting of CHOICEs in the definition of VarBind/value.
 *
 * XXX: the length of this function (~400 lines) is an aberration!
 *  oid_key_t:key_type could become a series of callbacks instead of an enum
 *  the (! oid_info_is_ok) switch could be made into an array (would be slower)
 *

	NetworkAddress ::=  CHOICE { internet IpAddress }
	IpAddress ::= [APPLICATION 0] IMPLICIT OCTET STRING (SIZE (4))
	TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
	Integer32 ::= INTEGER (-2147483648..2147483647)
	ObjectName ::= OBJECT IDENTIFIER
	Counter32 ::= [APPLICATION 1] IMPLICIT INTEGER (0..4294967295)
	Gauge32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
	Unsigned32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
	Integer-value ::=  INTEGER (-2147483648..2147483647)
	Integer32 ::= INTEGER (-2147483648..2147483647)
	ObjectID-value ::= OBJECT IDENTIFIER
	Empty ::= NULL
	TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
	Opaque ::= [APPLICATION 4] IMPLICIT OCTET STRING
	Counter64 ::= [APPLICATION 6] IMPLICIT INTEGER (0..18446744073709551615)

	ObjectSyntax ::= CHOICE {
		 simple SimpleSyntax,
		 application-wide ApplicationSyntax
	}

	SimpleSyntax ::= CHOICE {
	   integer-value Integer-value,
	   string-value String-value,
	   objectID-value ObjectID-value,
	   empty  Empty
	}

	ApplicationSyntax ::= CHOICE {
	   ipAddress-value IpAddress,
	   counter-value Counter32,
	   timeticks-value TimeTicks,
	   arbitrary-value Opaque,
	   big-counter-value Counter64,
	   unsigned-integer-value Unsigned32
	}

	ValueType ::=  CHOICE {
	   value ObjectSyntax,
	   unSpecified NULL,
	   noSuchObject[0] IMPLICIT NULL,
	   noSuchInstance[1] IMPLICIT NULL,
	   endOfMibView[2] IMPLICIT NULL
	}

	VarBind ::= SEQUENCE {
	   name ObjectName,
	   valueType ValueType
	}

 */

static int
dissect_snmp_VarBind(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,
		     asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_)
{
	int seq_offset, name_offset, value_offset, value_start;
	guint32 seq_len, name_len, value_len;
	gint8 ber_class;
	gboolean pc;
	gint32 tag;
	gboolean ind;
	guint32* subids;
	guint8* oid_bytes;
	oid_info_t* oid_info = NULL;
	guint oid_matched, oid_left;
	proto_item *pi_name, *pi_varbind, *pi_value = NULL;
	proto_tree *pt, *pt_varbind, *pt_name, *pt_value;
	char label[ITEM_LABEL_LENGTH];
	const char* repr = NULL;
	const char* info_oid = NULL;
	char* valstr;
	int hfid = -1;
	int min_len = 0, max_len = 0;
	gboolean oid_info_is_ok;
	const char* oid_string = NULL;
	enum {BER_NO_ERROR, BER_WRONG_LENGTH, BER_WRONG_TAG} format_error = BER_NO_ERROR;

	seq_offset = offset;

	/* first have the VarBind's sequence header */
	offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &ber_class, &pc, &tag);
	offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &seq_len, &ind);

	if (!pc && ber_class==BER_CLASS_UNI && tag==BER_UNI_TAG_SEQUENCE) {
		proto_item* pi;
		pt = proto_tree_add_subtree(tree, tvb, seq_offset, seq_len + (offset - seq_offset),
				ett_decoding_error, &pi, "VarBind must be an universal class sequence");
		expert_add_info(actx->pinfo, pi, &ei_snmp_varbind_not_uni_class_seq);
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	if (ind) {
		proto_item* pi;
		pt = proto_tree_add_subtree(tree, tvb, seq_offset, seq_len + (offset - seq_offset),
					ett_decoding_error, &pi, "Indicator must be clear in VarBind");
		expert_add_info(actx->pinfo, pi, &ei_snmp_varbind_has_indicator);
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	/* we add the varbind tree root with a dummy label we'll fill later on */
	pt_varbind = proto_tree_add_subtree(tree,tvb,offset,seq_len,ett_varbind,&pi_varbind,"VarBind");
	*label = '\0';

	seq_len += offset - seq_offset;

	/* then we have the ObjectName's header */

	offset = dissect_ber_identifier(actx->pinfo, pt_varbind, tvb, offset, &ber_class, &pc, &tag);
	name_offset = offset = dissect_ber_length(actx->pinfo, pt_varbind, tvb, offset, &name_len, &ind);

	if (! ( !pc && ber_class==BER_CLASS_UNI && tag==BER_UNI_TAG_OID) ) {
		proto_item* pi;
		pt = proto_tree_add_subtree(tree, tvb, seq_offset, seq_len,
				ett_decoding_error, &pi, "ObjectName must be an OID in primitive encoding");
		expert_add_info(actx->pinfo, pi, &ei_snmp_objectname_not_oid);
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	if (ind) {
		proto_item* pi;
		pt = proto_tree_add_subtree(tree, tvb, seq_offset, seq_len,
				ett_decoding_error, &pi, "Indicator must be clear in ObjectName");
		expert_add_info(actx->pinfo, pi, &ei_snmp_objectname_has_indicator);
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	pi_name = proto_tree_add_item(pt_varbind,hf_snmp_objectname,tvb,name_offset,name_len,ENC_NA);
	pt_name = proto_item_add_subtree(pi_name,ett_name);

	offset += name_len;
	value_start = offset;
	/* then we have the value's header */
	offset = dissect_ber_identifier(actx->pinfo, pt_varbind, tvb, offset, &ber_class, &pc, &tag);
	value_offset = dissect_ber_length(actx->pinfo, pt_varbind, tvb, offset, &value_len, &ind);

	if (! (!pc) ) {
		proto_item* pi;
		pt = proto_tree_add_subtree(pt_varbind, tvb, value_start, value_len,
				ett_decoding_error, &pi, "the value must be in primitive encoding");
		expert_add_info(actx->pinfo, pi, &ei_snmp_value_not_primitive_encoding);
		return dissect_unknown_ber(actx->pinfo, tvb, value_start, pt);
	}

	/* Now, we know where everithing is */

	/* fetch ObjectName and its relative oid_info */
	oid_bytes = (guint8*)tvb_memdup(actx->pinfo->pool, tvb, name_offset, name_len);
	oid_info = oid_get_from_encoded(actx->pinfo->pool, oid_bytes, name_len, &subids, &oid_matched, &oid_left);

	add_oid_debug_subtree(oid_info,pt_name);

	if (!subids) {
		proto_item* pi;

		repr = oid_encoded2string(actx->pinfo->pool, oid_bytes, name_len);
		pt = proto_tree_add_subtree_format(pt_name,tvb, 0, 0, ett_decoding_error, &pi, "invalid oid: %s", repr);
		expert_add_info_format(actx->pinfo, pi, &ei_snmp_invalid_oid, "invalid oid: %s", repr);
		return dissect_unknown_ber(actx->pinfo, tvb, name_offset, pt);
	}

	if (oid_matched+oid_left) {
		oid_string = oid_subid2string(actx->pinfo->pool, subids,oid_matched+oid_left);
	}

	if (ber_class == BER_CLASS_CON) {
		/* if we have an error value just add it and get out the way ASAP */
		proto_item* pi;
		const char* note;

		if (value_len != 0) {
			min_len = max_len = 0;
			format_error = BER_WRONG_LENGTH;
		}

		switch (tag) {
			case SERR_NSO:
				hfid = hf_snmp_noSuchObject;
				note = "noSuchObject";
				break;
			case SERR_NSI:
				hfid = hf_snmp_noSuchInstance;
				note = "noSuchInstance";
				break;
			case SERR_EOM:
				hfid = hf_snmp_endOfMibView;
				note = "endOfMibView";
				break;
			default: {
				pt = proto_tree_add_subtree_format(pt_varbind,tvb,0,0,ett_decoding_error,&pi,
								"Wrong tag for Error Value: expected 0, 1, or 2 but got: %d",tag);
				expert_add_info(actx->pinfo, pi, &ei_snmp_varbind_wrong_tag);
				return dissect_unknown_ber(actx->pinfo, tvb, value_start, pt);
			}
		}

		pi = proto_tree_add_item(pt_varbind,hfid,tvb,value_offset,value_len,ENC_BIG_ENDIAN);
		expert_add_info_format(actx->pinfo, pi, &ei_snmp_varbind_response, "%s",note);
		(void) g_strlcpy (label, note, ITEM_LABEL_LENGTH);
		goto set_label;
	}

	/* now we'll try to figure out which are the indexing sub-oids and whether the oid we know about is the one oid we have to use */
	switch (oid_info->kind) {
		case OID_KIND_SCALAR:
			if (oid_left == 1) {
				/* OK: we got the instance sub-id */
				proto_tree_add_uint64(pt_name,hf_snmp_scalar_instance_index,tvb,name_offset,name_len,subids[oid_matched]);
				oid_info_is_ok = TRUE;
				goto indexing_done;
			} else if (oid_left == 0) {
				if (ber_class == BER_CLASS_UNI && tag == BER_UNI_TAG_NULL) {
					/* unSpecified  does not require an instance sub-id add the new value and get off the way! */
					pi_value = proto_tree_add_item(pt_varbind,hf_snmp_unSpecified,tvb,value_offset,value_len,ENC_NA);
					goto set_label;
				} else {
					proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_no_instance_subid,tvb,0,0);
					oid_info_is_ok = FALSE;
					goto indexing_done;
				}
			} else {
				proto_tree_add_expert_format(pt_name,actx->pinfo,&ei_snmp_wrong_num_of_subids,tvb,0,0,"A scalar should have only one instance sub-id this has: %d",oid_left);
				oid_info_is_ok = FALSE;
				goto indexing_done;
			}
		break;
		case OID_KIND_COLUMN:
			if ( oid_info->parent->kind == OID_KIND_ROW) {
				oid_key_t* k = oid_info->parent->key;
				guint key_start = oid_matched;
				guint key_len = oid_left;
				oid_info_is_ok = TRUE;

				if ( key_len == 0 && ber_class == BER_CLASS_UNI && tag == BER_UNI_TAG_NULL) {
					/* unSpecified  does not require an instance sub-id add the new value and get off the way! */
					pi_value = proto_tree_add_item(pt_varbind,hf_snmp_unSpecified,tvb,value_offset,value_len,ENC_NA);
					goto set_label;
				}

				if (k) {
					for (;k;k = k->next) {
						guint suboid_len;

						if (key_start >= oid_matched+oid_left) {
							proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_index_suboid_too_short,tvb,0,0);
							oid_info_is_ok = FALSE;
							goto indexing_done;
						}

						switch(k->key_type) {
							case OID_KEY_TYPE_WRONG: {
								proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_unimplemented_instance_index,tvb,0,0);
								oid_info_is_ok = FALSE;
								goto indexing_done;
							}
							case OID_KEY_TYPE_INTEGER: {
								if (IS_FT_INT(k->ft_type)) {
									proto_tree_add_int(pt_name,k->hfid,tvb,name_offset,name_len,(guint)subids[key_start]);
								} else { /* if it's not an unsigned int let proto_tree_add_uint throw a warning */
									proto_tree_add_uint64(pt_name,k->hfid,tvb,name_offset,name_len,(guint)subids[key_start]);
								}
								key_start++;
								key_len--;
								continue; /* k->next */
							}
							case OID_KEY_TYPE_IMPLIED_OID:
								suboid_len = key_len;

								goto show_oid_index;

							case OID_KEY_TYPE_OID: {
								guint8* suboid_buf;
								guint suboid_buf_len;
								guint32* suboid;

								suboid_len = subids[key_start++];
								key_len--;

show_oid_index:
								suboid = &(subids[key_start]);

								if( suboid_len == 0 ) {
									proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_index_suboid_len0,tvb,0,0);
									oid_info_is_ok = FALSE;
									goto indexing_done;
								}

								if( key_len < suboid_len ) {
									proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_index_suboid_too_long,tvb,0,0);
									oid_info_is_ok = FALSE;
									goto indexing_done;
								}

								suboid_buf_len = oid_subid2encoded(actx->pinfo->pool, suboid_len, suboid, &suboid_buf);

								DISSECTOR_ASSERT(suboid_buf_len);

								proto_tree_add_oid(pt_name,k->hfid,tvb,name_offset, suboid_buf_len, suboid_buf);

								key_start += suboid_len;
								key_len -= suboid_len + 1;
								continue; /* k->next */
							}
							default: {
								guint8* buf;
								guint buf_len;
								guint32* suboid;
								guint i;


								switch (k->key_type) {
									case OID_KEY_TYPE_IPADDR:
										suboid = &(subids[key_start]);
										buf_len = 4;
										break;
									case OID_KEY_TYPE_IMPLIED_STRING:
									case OID_KEY_TYPE_IMPLIED_BYTES:
									case OID_KEY_TYPE_ETHER:
										suboid = &(subids[key_start]);
										buf_len = key_len;
										break;
									default:
										buf_len = k->num_subids;
										suboid = &(subids[key_start]);

										if(!buf_len) {
											buf_len = *suboid++;
											key_len--;
											key_start++;
										}
										break;
								}

								if( key_len < buf_len ) {
									proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_index_string_too_long,tvb,0,0);
									oid_info_is_ok = FALSE;
									goto indexing_done;
								}

								buf = (guint8*)wmem_alloc(actx->pinfo->pool, buf_len+1);
								for (i = 0; i < buf_len; i++)
									buf[i] = (guint8)suboid[i];
								buf[i] = '\0';

								switch(k->key_type) {
									case OID_KEY_TYPE_STRING:
									case OID_KEY_TYPE_IMPLIED_STRING:
										proto_tree_add_string(pt_name,k->hfid,tvb,name_offset,buf_len, buf);
										break;
									case OID_KEY_TYPE_BYTES:
									case OID_KEY_TYPE_NSAP:
									case OID_KEY_TYPE_IMPLIED_BYTES:
										proto_tree_add_bytes(pt_name,k->hfid,tvb,name_offset,buf_len, buf);
										break;
									case OID_KEY_TYPE_ETHER:
										proto_tree_add_ether(pt_name,k->hfid,tvb,name_offset,buf_len, buf);
										break;
									case OID_KEY_TYPE_IPADDR: {
										guint32* ipv4_p = (guint32*)buf;
										proto_tree_add_ipv4(pt_name,k->hfid,tvb,name_offset,buf_len, *ipv4_p);
										}
										break;
									default:
										DISSECTOR_ASSERT_NOT_REACHED();
										break;
								}

								key_start += buf_len;
								key_len -= buf_len;
								continue; /* k->next*/
							}
						}
					}
					goto indexing_done;
				} else {
					proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_unimplemented_instance_index,tvb,0,0);
					oid_info_is_ok = FALSE;
					goto indexing_done;
				}
			} else {
				proto_tree_add_expert(pt_name,actx->pinfo,&ei_snmp_column_parent_not_row,tvb,0,0);
				oid_info_is_ok = FALSE;
				goto indexing_done;
			}
		default: {
/*			proto_tree_add_expert (pt_name,actx->pinfo,PI_MALFORMED, PI_WARN,tvb,0,0,"This kind OID should have no value"); */
			oid_info_is_ok = FALSE;
			goto indexing_done;
		}
	}
indexing_done:

	if (oid_info_is_ok && oid_info->value_type) {
		if (ber_class == BER_CLASS_UNI && tag == BER_UNI_TAG_NULL) {
			pi_value = proto_tree_add_item(pt_varbind,hf_snmp_unSpecified,tvb,value_offset,value_len,ENC_NA);
		} else {
			/* Provide a tree_item to attach errors to, if needed. */
			pi_value = pi_name;

			if ((oid_info->value_type->ber_class != BER_CLASS_ANY) &&
				(ber_class != oid_info->value_type->ber_class))
				format_error = BER_WRONG_TAG;
			else if ((oid_info->value_type->ber_tag != BER_TAG_ANY) &&
				(tag != oid_info->value_type->ber_tag))
				format_error = BER_WRONG_TAG;
			else {
				max_len = oid_info->value_type->max_len == -1 ? 0xffffff : oid_info->value_type->max_len;
				min_len = oid_info->value_type->min_len;

				if ((int)value_len < min_len || (int)value_len > max_len)
					format_error = BER_WRONG_LENGTH;
			}

			if (format_error == BER_NO_ERROR)
				pi_value = proto_tree_add_item(pt_varbind,oid_info->value_hfid,tvb,value_offset,value_len,ENC_BIG_ENDIAN);
		}
	} else {
		switch(ber_class|(tag<<4)) {
			case BER_CLASS_UNI|(BER_UNI_TAG_INTEGER<<4):
			{
				gint64 val=0;
				unsigned int int_val_offset = value_offset;
				unsigned int i;

				max_len = 4; min_len = 1;
				if (value_len > (guint)max_len || value_len < (guint)min_len) {
					hfid = hf_snmp_integer32_value;
					format_error = BER_WRONG_LENGTH;
					break;
				}

				if(value_len > 0) {
					/* extend sign bit */
					if(tvb_get_guint8(tvb, int_val_offset)&0x80) {
						val=-1;
					}
					for(i=0;i<value_len;i++) {
						val=(val<<8)|tvb_get_guint8(tvb, int_val_offset);
						int_val_offset++;
					}
				}
				pi_value = proto_tree_add_int64(pt_varbind, hf_snmp_integer32_value, tvb,value_offset,value_len, val);

				goto already_added;
			}
			case BER_CLASS_UNI|(BER_UNI_TAG_OCTETSTRING<<4):
				if(oid_info->value_hfid> -1){
					hfid = oid_info->value_hfid;
				}else{
					hfid = hf_snmp_octetstring_value;
				}
				break;
			case BER_CLASS_UNI|(BER_UNI_TAG_OID<<4):
				max_len = -1; min_len = 1;
				if (value_len < (guint)min_len) format_error = BER_WRONG_LENGTH;
				hfid = hf_snmp_oid_value;
				break;
			case BER_CLASS_UNI|(BER_UNI_TAG_NULL<<4):
				max_len = 0; min_len = 0;
				if (value_len != 0) format_error = BER_WRONG_LENGTH;
				hfid = hf_snmp_null_value;
				break;
			case BER_CLASS_APP: /* | (SNMP_IPA<<4)*/
				switch(value_len) {
					case 4: hfid = hf_snmp_ipv4_value; break;
					case 16: hfid = hf_snmp_ipv6_value; break;
					default: hfid = hf_snmp_anyaddress_value; break;
				}
				break;
			case BER_CLASS_APP|(SNMP_U32<<4):
				hfid = hf_snmp_unsigned32_value;
				break;
			case BER_CLASS_APP|(SNMP_GGE<<4):
				hfid = hf_snmp_gauge32_value;
				break;
			case BER_CLASS_APP|(SNMP_CNT<<4):
				hfid = hf_snmp_counter_value;
				break;
			case BER_CLASS_APP|(SNMP_TIT<<4):
				hfid = hf_snmp_timeticks_value;
				break;
			case BER_CLASS_APP|(SNMP_OPQ<<4):
				hfid = hf_snmp_opaque_value;
				break;
			case BER_CLASS_APP|(SNMP_NSP<<4):
				hfid = hf_snmp_nsap_value;
				break;
			case BER_CLASS_APP|(SNMP_C64<<4):
				hfid = hf_snmp_big_counter_value;
				break;
			default:
				hfid = hf_snmp_unknown_value;
				break;
		}
		if (value_len > 8) {
			/*
			 * Too long for an FT_UINT64 or an FT_INT64.
			 */
			header_field_info *hfinfo = proto_registrar_get_nth(hfid);
			if (hfinfo->type == FT_UINT64) {
				/*
				 * Check if this is an unsigned int64 with
				 * a big value.
				 */
				if (value_len > 9 || tvb_get_guint8(tvb, value_offset) != 0) {
					/* It is.  Fail. */
					proto_tree_add_expert_format(pt_varbind,actx->pinfo,&ei_snmp_uint_too_large,tvb,value_offset,value_len,"Integral value too large");
					goto already_added;
				}
				/* Cheat and skip the leading 0 byte */
				value_len--;
				value_offset++;
			} else if (hfinfo->type == FT_INT64) {
				/*
				 * For now, just reject these.
				 */
				proto_tree_add_expert_format(pt_varbind,actx->pinfo,&ei_snmp_int_too_large,tvb,value_offset,value_len,"Integral value too large or too small");
				goto already_added;
			}
		} else if (value_len == 0) {
			/*
			 * X.690 section 8.3.1 "Encoding of an integer value":
			 * "The encoding of an integer value shall be
			 * primitive. The contents octets shall consist of
			 * one or more octets."
			 *
			 * Zero is not "one or more".
			 */
			header_field_info *hfinfo = proto_registrar_get_nth(hfid);
			if (hfinfo->type == FT_UINT64 || hfinfo->type == FT_INT64) {
				proto_tree_add_expert_format(pt_varbind,actx->pinfo,&ei_snmp_integral_value0,tvb,value_offset,value_len,"Integral value is zero-length");
				goto already_added;
			}
		}
		/* Special case DATE AND TIME */
		if((oid_info->value_type)&&(oid_info->value_type->keytype == OID_KEY_TYPE_DATE_AND_TIME)&&(value_len > 7)){
			pi_value = dissect_snmp_variable_date_and_time(pt_varbind, actx->pinfo, hfid, tvb, value_offset, value_len);
		}else{
			pi_value = proto_tree_add_item(pt_varbind,hfid,tvb,value_offset,value_len,ENC_BIG_ENDIAN);
		}
		if (format_error != BER_NO_ERROR) {
			expert_add_info(actx->pinfo, pi_value, &ei_snmp_missing_mib);
		}

	}
already_added:
	pt_value = proto_item_add_subtree(pi_value,ett_value);

	if (value_len > 0 && oid_string) {
		tvbuff_t* sub_tvb = tvb_new_subset_length(tvb, value_offset, value_len);

		next_tvb_add_string(var_list, sub_tvb, (snmp_var_in_tree) ? pt_value : NULL, value_sub_dissectors_table, oid_string);
	}


set_label:
	if (pi_value) proto_item_fill_label(PITEM_FINFO(pi_value), label);

	if (oid_info && oid_info->name) {
		if (oid_left >= 1) {
			repr = wmem_strdup_printf(actx->pinfo->pool, "%s.%s (%s)", oid_info->name,
						oid_subid2string(actx->pinfo->pool, &(subids[oid_matched]),oid_left),
						oid_subid2string(actx->pinfo->pool, subids,oid_matched+oid_left));
			info_oid = wmem_strdup_printf(actx->pinfo->pool, "%s.%s", oid_info->name,
						oid_subid2string(actx->pinfo->pool, &(subids[oid_matched]),oid_left));
		} else {
			repr = wmem_strdup_printf(actx->pinfo->pool, "%s (%s)", oid_info->name,
						oid_subid2string(actx->pinfo->pool, subids,oid_matched));
			info_oid = oid_info->name;
		}
	} else if (oid_string) {
		repr = wmem_strdup(actx->pinfo->pool, oid_string);
		info_oid = oid_string;
	} else {
		repr = wmem_strdup(actx->pinfo->pool, "[Bad OID]");
	}

	valstr = strstr(label,": ");
	valstr = valstr ? valstr+2 : label;

	proto_item_set_text(pi_varbind,"%s: %s",repr,valstr);

	if (display_oid && info_oid) {
		col_append_fstr (actx->pinfo->cinfo, COL_INFO, " %s", info_oid);
	}

	switch (format_error) {
		case BER_WRONG_LENGTH: {
			proto_item* pi;
			proto_tree* p_tree = proto_item_add_subtree(pi_value,ett_decoding_error);
			pt = proto_tree_add_subtree_format(p_tree,tvb,0,0,ett_decoding_error,&pi,
							     "Wrong value length: %u  expecting: %u <= len <= %u",
							     value_len, min_len, max_len == -1 ? 0xFFFFFF : max_len);
			expert_add_info(actx->pinfo, pi, &ei_snmp_varbind_wrong_length_value);
			return dissect_unknown_ber(actx->pinfo, tvb, value_start, pt);
		}
		case BER_WRONG_TAG: {
			proto_item* pi;
			proto_tree* p_tree = proto_item_add_subtree(pi_value,ett_decoding_error);
			pt = proto_tree_add_subtree_format(p_tree,tvb,0,0,ett_decoding_error,&pi,
							     "Wrong class/tag for Value expected: %d,%d got: %d,%d",
							     oid_info->value_type->ber_class, oid_info->value_type->ber_tag,
							     ber_class, tag);
			expert_add_info(actx->pinfo, pi, &ei_snmp_varbind_wrong_class_tag);
			return dissect_unknown_ber(actx->pinfo, tvb, value_start, pt);
		}
		default:
			break;
	}

	return seq_offset + seq_len;
}


#define F_SNMP_ENGINEID_CONFORM 0x80
#define SNMP_ENGINEID_RFC1910 0x00
#define SNMP_ENGINEID_RFC3411 0x01

static const true_false_string tfs_snmp_engineid_conform = {
	"RFC3411 (SNMPv3)",
	"RFC1910 (Non-SNMPv3)"
};

#define SNMP_ENGINEID_FORMAT_IPV4 0x01
#define SNMP_ENGINEID_FORMAT_IPV6 0x02
#define SNMP_ENGINEID_FORMAT_MACADDRESS 0x03
#define SNMP_ENGINEID_FORMAT_TEXT 0x04
#define SNMP_ENGINEID_FORMAT_OCTETS 0x05

static const value_string snmp_engineid_format_vals[] = {
	{ SNMP_ENGINEID_FORMAT_IPV4,	"IPv4 address" },
	{ SNMP_ENGINEID_FORMAT_IPV6,	"IPv6 address" },
	{ SNMP_ENGINEID_FORMAT_MACADDRESS,	"MAC address" },
	{ SNMP_ENGINEID_FORMAT_TEXT,	"Text, administratively assigned" },
	{ SNMP_ENGINEID_FORMAT_OCTETS,	"Octets, administratively assigned" },
	{ 0,	NULL }
};

#define SNMP_ENGINEID_CISCO_AGENT 0x00
#define SNMP_ENGINEID_CISCO_MANAGER 0x01

static const value_string snmp_engineid_cisco_type_vals[] = {
	{ SNMP_ENGINEID_CISCO_AGENT,	"Agent" },
	{ SNMP_ENGINEID_CISCO_MANAGER,	"Manager" },
	{ 0,	NULL }
};

/*
 * SNMP Engine ID dissection according to RFC 3411 (SnmpEngineID TC)
 * or historic RFC 1910 (AgentID)
 */
int
dissect_snmp_engineid(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int len)
{
	proto_item *item = NULL;
	guint8 conformance, format;
	guint32 enterpriseid;
	time_t seconds;
	nstime_t ts;
	int len_remain = len;

	/* first bit: engine id conformance */
	if (len_remain<1) return offset;
	conformance = ((tvb_get_guint8(tvb, offset)>>7) & 0x01);
	proto_tree_add_item(tree, hf_snmp_engineid_conform, tvb, offset, 1, ENC_BIG_ENDIAN);

	/* 4-byte enterprise number/name */
	if (len_remain<4) return offset;
	enterpriseid = tvb_get_ntohl(tvb, offset);
	if (conformance)
		enterpriseid -= 0x80000000; /* ignore first bit */
	proto_tree_add_uint(tree, hf_snmp_engineid_enterprise, tvb, offset, 4, enterpriseid);
	offset+=4;
	len_remain-=4;

	switch(conformance) {

	case SNMP_ENGINEID_RFC1910:
		/* 12-byte AgentID w/ 8-byte trailer */
		if (len_remain==8) {
			proto_tree_add_item(tree, hf_snmp_agentid_trailer, tvb, offset, 8, ENC_NA);
			offset+=8;
			len_remain-=8;
		} else {
			proto_tree_add_expert(tree, pinfo, &ei_snmp_rfc1910_non_conformant, tvb, offset, len_remain);
			return offset;
		}
		break;

	case SNMP_ENGINEID_RFC3411: /* variable length: 5..32 */

		/* 1-byte format specifier */
		if (len_remain<1) return offset;
		format = tvb_get_guint8(tvb, offset);
		item = proto_tree_add_uint_format(tree, hf_snmp_engineid_format, tvb, offset, 1, format, "Engine ID Format: %s (%d)",
						  val_to_str(format, snmp_engineid_format_vals, "Reserved/Enterprise-specific"), format);
		offset+=1;
		len_remain-=1;

		switch(format) {
		case SNMP_ENGINEID_FORMAT_IPV4:
			/* 4-byte IPv4 address */
			if (len_remain==4) {
				proto_tree_add_item(tree, hf_snmp_engineid_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset+=4;
				len_remain=0;
			}
			break;
		case SNMP_ENGINEID_FORMAT_IPV6:
			/* 16-byte IPv6 address */
			if (len_remain==16) {
				proto_tree_add_item(tree, hf_snmp_engineid_ipv6, tvb, offset, 16, ENC_NA);
				offset+=16;
				len_remain=0;
			}
			break;
		case SNMP_ENGINEID_FORMAT_MACADDRESS:
			/* See: https://supportforums.cisco.com/message/3010617#3010617 for details. */
			if ((enterpriseid==9)&&(len_remain==7)) {
				proto_tree_add_item(tree, hf_snmp_engineid_cisco_type, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				len_remain--;
			}
			/* 6-byte MAC address */
			if (len_remain==6) {
				proto_tree_add_item(tree, hf_snmp_engineid_mac, tvb, offset, 6, ENC_NA);
				offset+=6;
				len_remain=0;
			}
			break;
		case SNMP_ENGINEID_FORMAT_TEXT:
			/* max. 27-byte string, administratively assigned */
			if (len_remain<=27) {
				proto_tree_add_item(tree, hf_snmp_engineid_text, tvb, offset, len_remain, ENC_ASCII);
				offset+=len_remain;
				len_remain=0;
			}
			break;
		case 128:
			/* most common enterprise-specific format: (ucd|net)-snmp random */
			if ((enterpriseid==2021)||(enterpriseid==8072)) {
				proto_item_append_text(item, (enterpriseid==2021) ? ": UCD-SNMP Random" : ": Net-SNMP Random");
				/* demystify: 4B random, 4B/8B epoch seconds */
				if ((len_remain==8) || (len_remain==12)) {
					proto_tree_add_item(tree, hf_snmp_engineid_data, tvb, offset, 4, ENC_NA);
					if (len_remain==8) {
						seconds = (time_t)tvb_get_letohl(tvb, offset + 4);
					} else {
						seconds = (time_t)tvb_get_letohi64(tvb, offset + 4);
					}
					ts.secs = seconds;
					ts.nsecs = 0;
					proto_tree_add_time_format_value(tree, hf_snmp_engineid_time, tvb, offset + 4, len_remain - 4,
									 &ts, "%s",
									 abs_time_secs_to_str(pinfo->pool, seconds, ABSOLUTE_TIME_LOCAL, TRUE));
					offset+=len_remain;
					len_remain=0;
				}
			break;
			}
		/* fall through */
		case SNMP_ENGINEID_FORMAT_OCTETS:
		default:
			/* max. 27 bytes, administratively assigned or unknown format */
			if (len_remain<=27) {
				proto_tree_add_item(tree, hf_snmp_engineid_data, tvb, offset, len_remain, ENC_NA);
				offset+=len_remain;
				len_remain=0;
			}
		break;
		}
	}

	if (len_remain>0) {
		proto_tree_add_expert(tree, pinfo, &ei_snmp_rfc3411_non_conformant, tvb, offset, len_remain);
		offset+=len_remain;
	}
	return offset;
}


static void set_ue_keys(snmp_ue_assoc_t* n ) {
	guint key_size = auth_hash_len[n->user.authModel];

	n->user.authKey.data = (guint8 *)g_malloc(key_size);
	n->user.authKey.len = key_size;
	snmp_usm_password_to_key(n->user.authModel,
				 n->user.authPassword.data,
				 n->user.authPassword.len,
				 n->engine.data,
				 n->engine.len,
				 n->user.authKey.data);

	if (n->priv_proto == PRIV_AES128 || n->priv_proto == PRIV_AES192 || n->priv_proto == PRIV_AES256) {
		guint need_key_len =
			(n->priv_proto == PRIV_AES128) ? 16 :
			(n->priv_proto == PRIV_AES192) ? 24 :
			(n->priv_proto == PRIV_AES256) ? 32 :
			0;

		guint key_len = key_size;

		while (key_len < need_key_len)
			key_len += key_size;

		n->user.privKey.data = (guint8 *)g_malloc(key_len);
		n->user.privKey.len  = need_key_len;

		snmp_usm_password_to_key(n->user.authModel,
					 n->user.privPassword.data,
					 n->user.privPassword.len,
					 n->engine.data,
					 n->engine.len,
					 n->user.privKey.data);

		key_len = key_size;

		/* extend key if needed */
		while (key_len < need_key_len) {
			snmp_usm_password_to_key(n->user.authModel,
						 n->user.privKey.data,
						 key_len,
						 n->engine.data,
						 n->engine.len,
						 n->user.privKey.data + key_len);

			key_len += key_size;
		}

	} else {
		n->user.privKey.data = (guint8 *)g_malloc(key_size);
		n->user.privKey.len = key_size;
		snmp_usm_password_to_key(n->user.authModel,
					 n->user.privPassword.data,
					 n->user.privPassword.len,
					 n->engine.data,
					 n->engine.len,
					 n->user.privKey.data);
	}
}

static snmp_ue_assoc_t*
ue_dup(snmp_ue_assoc_t* o)
{
	snmp_ue_assoc_t* d = (snmp_ue_assoc_t*)g_memdup2(o,sizeof(snmp_ue_assoc_t));

	d->user.authModel = o->user.authModel;

	d->user.privProtocol = o->user.privProtocol;

	d->user.userName.data = (guint8 *)g_memdup2(o->user.userName.data,o->user.userName.len);
	d->user.userName.len = o->user.userName.len;

	d->user.authPassword.data = o->user.authPassword.data ? (guint8 *)g_memdup2(o->user.authPassword.data,o->user.authPassword.len) : NULL;
	d->user.authPassword.len = o->user.authPassword.len;

	d->user.privPassword.data = o->user.privPassword.data ? (guint8 *)g_memdup2(o->user.privPassword.data,o->user.privPassword.len) : NULL;
	d->user.privPassword.len = o->user.privPassword.len;

	d->engine.len = o->engine.len;

	if (d->engine.len) {
		d->engine.data = (guint8 *)g_memdup2(o->engine.data,o->engine.len);
		set_ue_keys(d);
	}

	return d;

}

static void*
snmp_users_copy_cb(void* dest, const void* orig, size_t len _U_)
{
	const snmp_ue_assoc_t* o = (const snmp_ue_assoc_t*)orig;
	snmp_ue_assoc_t* d = (snmp_ue_assoc_t*)dest;

	d->auth_model = o->auth_model;
	d->user.authModel = (snmp_usm_auth_model_t) o->auth_model;

	d->priv_proto = o->priv_proto;
	d->user.privProtocol = priv_protos[o->priv_proto];

	d->user.userName.data = (guint8*)g_memdup2(o->user.userName.data,o->user.userName.len);
	d->user.userName.len = o->user.userName.len;

	d->user.authPassword.data = o->user.authPassword.data ? (guint8*)g_memdup2(o->user.authPassword.data,o->user.authPassword.len) : NULL;
	d->user.authPassword.len = o->user.authPassword.len;

	d->user.privPassword.data = o->user.privPassword.data ? (guint8*)g_memdup2(o->user.privPassword.data,o->user.privPassword.len) : NULL;
	d->user.privPassword.len = o->user.privPassword.len;

	d->engine.len = o->engine.len;
	if (o->engine.data) {
		d->engine.data = (guint8*)g_memdup2(o->engine.data,o->engine.len);
	}

	d->user.authKey.data = o->user.authKey.data ? (guint8*)g_memdup2(o->user.authKey.data,o->user.authKey.len) : NULL;
	d->user.authKey.len = o->user.authKey.len;

	d->user.privKey.data = o->user.privKey.data ? (guint8*)g_memdup2(o->user.privKey.data,o->user.privKey.len) : NULL;
	d->user.privKey.len = o->user.privKey.len;

	return d;
}

static void
snmp_users_free_cb(void* p)
{
	snmp_ue_assoc_t* ue = (snmp_ue_assoc_t*)p;
	g_free(ue->user.userName.data);
	g_free(ue->user.authPassword.data);
	g_free(ue->user.privPassword.data);
	g_free(ue->user.authKey.data);
	g_free(ue->user.privKey.data);
	g_free(ue->engine.data);
}

static gboolean
snmp_users_update_cb(void* p _U_, char** err)
{
	snmp_ue_assoc_t* ue = (snmp_ue_assoc_t*)p;
	GString* es = g_string_new("");
	unsigned int i;

	*err = NULL;

	if (! ue->user.userName.len) {
		g_string_append_printf(es,"no userName\n");
	} else if ((ue->engine.len > 0) && (ue->engine.len < 5 || ue->engine.len > 32)) {
		/* RFC 3411 section 5 */
		g_string_append_printf(es, "Invalid engineId length (%u). Must be between 5 and 32 (10 and 64 hex digits)\n", ue->engine.len);
	} else if (num_ueas) {
		for (i=0; i<num_ueas-1; i++) {
			snmp_ue_assoc_t* u = &(ueas[i]);

			if ( u->user.userName.len == ue->user.userName.len
				&& u->engine.len == ue->engine.len && (u != ue)) {

				if (u->engine.len > 0 && memcmp( u->engine.data, ue->engine.data, u->engine.len ) == 0) {
					if ( memcmp( u->user.userName.data, ue->user.userName.data, ue->user.userName.len ) == 0 ) {
						/* XXX: make a string for the engineId */
						g_string_append_printf(es,"Duplicate key (userName='%s')\n",ue->user.userName.data);
						break;
					}
				}

				if (u->engine.len == 0) {
					if ( memcmp( u->user.userName.data, ue->user.userName.data, ue->user.userName.len ) == 0 ) {
						g_string_append_printf(es,"Duplicate key (userName='%s' engineId=NONE)\n",ue->user.userName.data);
						break;
					}
				}
			}
		}
	}

	if (es->len) {
		es = g_string_truncate(es,es->len-1);
		*err = g_string_free(es, FALSE);
		return FALSE;
	}

	return TRUE;
}

static void
free_ue_cache(snmp_ue_assoc_t **cache)
{
	static snmp_ue_assoc_t *a, *nxt;

	for (a = *cache; a; a = nxt) {
		nxt = a->next;
		snmp_users_free_cb(a);
		g_free(a);
	}

	*cache = NULL;
}

#define CACHE_INSERT(c,a) if (c) { snmp_ue_assoc_t* t = c; c = a; c->next = t; } else { c = a; a->next = NULL; }

static void
init_ue_cache(void)
{
	guint i;

	for (i = 0; i < num_ueas; i++) {
		snmp_ue_assoc_t* a = ue_dup(&(ueas[i]));

		if (a->engine.len) {
			CACHE_INSERT(localized_ues,a);

		} else {
			CACHE_INSERT(unlocalized_ues,a);
		}

	}
}

static void
cleanup_ue_cache(void)
{
	free_ue_cache(&localized_ues);
	free_ue_cache(&unlocalized_ues);
}

/* Called when the user applies changes to UAT preferences. */
static void
renew_ue_cache(void)
{
	cleanup_ue_cache();
	init_ue_cache();
}


static snmp_ue_assoc_t*
localize_ue( snmp_ue_assoc_t* o, const guint8* engine, guint engine_len )
{
	snmp_ue_assoc_t* n = (snmp_ue_assoc_t*)g_memdup2(o,sizeof(snmp_ue_assoc_t));

	n->user.userName.data = (guint8*)g_memdup2(o->user.userName.data,o->user.userName.len);
	n->user.authModel = o->user.authModel;
	n->user.authPassword.data = (guint8*)g_memdup2(o->user.authPassword.data,o->user.authPassword.len);
	n->user.authPassword.len = o->user.authPassword.len;
	n->user.privPassword.data = (guint8*)g_memdup2(o->user.privPassword.data,o->user.privPassword.len);
	n->user.privPassword.len = o->user.privPassword.len;
	n->user.authKey.data = (guint8*)g_memdup2(o->user.authKey.data,o->user.authKey.len);
	n->user.privKey.data = (guint8*)g_memdup2(o->user.privKey.data,o->user.privKey.len);
	n->engine.data = (guint8*)g_memdup2(engine,engine_len);
	n->engine.len = engine_len;
	n->priv_proto = o->priv_proto;

	set_ue_keys(n);

	return n;
}


#define localized_match(a,u,ul,e,el) \
	( a->user.userName.len == ul \
	&& a->engine.len == el \
	&& memcmp( a->user.userName.data, u, ul ) == 0 \
	&& memcmp( a->engine.data,   e,  el ) == 0 )

#define unlocalized_match(a,u,l) \
	( a->user.userName.len == l && memcmp( a->user.userName.data, u, l) == 0 )

static snmp_ue_assoc_t*
get_user_assoc(tvbuff_t* engine_tvb, tvbuff_t* user_tvb, packet_info *pinfo)
{
	static snmp_ue_assoc_t* a;
	guint given_username_len;
	guint8* given_username;
	guint given_engine_len = 0;
	guint8* given_engine = NULL;

	if ( ! (localized_ues || unlocalized_ues ) ) return NULL;

	if (! ( user_tvb && engine_tvb ) ) return NULL;

	given_username_len = tvb_captured_length(user_tvb);
	given_engine_len = tvb_captured_length(engine_tvb);
	if (! ( given_engine_len && given_username_len ) ) return NULL;
	given_username = (guint8*)tvb_memdup(pinfo->pool,user_tvb,0,-1);
	given_engine = (guint8*)tvb_memdup(pinfo->pool,engine_tvb,0,-1);

	for (a = localized_ues; a; a = a->next) {
		if ( localized_match(a, given_username, given_username_len, given_engine, given_engine_len) ) {
			return a;
		}
	}

	for (a = unlocalized_ues; a; a = a->next) {
		if ( unlocalized_match(a, given_username, given_username_len) ) {
			snmp_ue_assoc_t* n = localize_ue( a, given_engine, given_engine_len );
			CACHE_INSERT(localized_ues,n);
			return n;
		}
	}

	return NULL;
}

static gboolean
snmp_usm_auth(const packet_info *pinfo, const snmp_usm_auth_model_t model, snmp_usm_params_t* p, guint8** calc_auth_p,
	guint* calc_auth_len_p, gchar const** error)
{
	gint msg_len;
	guint8* msg;
	guint auth_len;
	guint8* auth;
	guint8* key;
	guint key_len;
	guint8 *calc_auth;
	guint start;
	guint end;
	guint i;

	if (!p->auth_tvb) {
		*error = "No Authenticator";
		return FALSE;
	}

	key = p->user_assoc->user.authKey.data;
	key_len = p->user_assoc->user.authKey.len;

	if (! key ) {
		*error = "User has no authKey";
		return FALSE;
	}

	auth_len = tvb_captured_length(p->auth_tvb);

	if (auth_len != auth_tag_len[model]) {
		*error = "Authenticator length wrong";
		return FALSE;
	}

	msg_len = tvb_captured_length(p->msg_tvb);
	if (msg_len <= 0) {
		*error = "Not enough data remaining";
		return FALSE;
	}
	msg = (guint8*)tvb_memdup(pinfo->pool,p->msg_tvb,0,msg_len);

	auth = (guint8*)tvb_memdup(pinfo->pool,p->auth_tvb,0,auth_len);

	start = p->auth_offset - p->start_offset;
	end =   start + auth_len;

	/* fill the authenticator with zeros */
	for ( i = start ; i < end ; i++ ) {
		msg[i] = '\0';
	}

	calc_auth = (guint8*)wmem_alloc(pinfo->pool, auth_hash_len[model]);

	if (ws_hmac_buffer(auth_hash_algo[model], calc_auth, msg, msg_len, key, key_len)) {
		return FALSE;
	}

	if (calc_auth_p) *calc_auth_p = calc_auth;
	if (calc_auth_len_p) *calc_auth_len_p = auth_len;

	return ( memcmp(auth,calc_auth,auth_len) != 0 ) ? FALSE : TRUE;
}

static tvbuff_t*
snmp_usm_priv_des(snmp_usm_params_t* p, tvbuff_t* encryptedData, packet_info *pinfo, gchar const** error)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd = NULL;

	guint8* cleartext;
	guint8* des_key = p->user_assoc->user.privKey.data; /* first 8 bytes */
	guint8* pre_iv = &(p->user_assoc->user.privKey.data[8]); /* last 8 bytes */
	guint8* salt;
	gint salt_len;
	gint cryptgrm_len;
	guint8* cryptgrm;
	tvbuff_t* clear_tvb;
	guint8 iv[8];
	guint i;


	salt_len = tvb_captured_length(p->priv_tvb);

	if (salt_len != 8) {
		*error = "decryptionError: msgPrivacyParameters length != 8";
		return NULL;
	}

	salt = (guint8*)tvb_memdup(pinfo->pool,p->priv_tvb,0,salt_len);

	/*
	 The resulting "salt" is XOR-ed with the pre-IV to obtain the IV.
	 */
	for (i=0; i<8; i++) {
		iv[i] = pre_iv[i] ^ salt[i];
	}

	cryptgrm_len = tvb_captured_length(encryptedData);

	if ((cryptgrm_len <= 0) || (cryptgrm_len % 8)) {
		*error = "decryptionError: the length of the encrypted data is not a multiple of 8 octets";
		return NULL;
	}

	cryptgrm = (guint8*)tvb_memdup(pinfo->pool,encryptedData,0,-1);

	cleartext = (guint8*)wmem_alloc(pinfo->pool, cryptgrm_len);

	err = gcry_cipher_open(&hd, GCRY_CIPHER_DES, GCRY_CIPHER_MODE_CBC, 0);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_setiv(hd, iv, 8);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_setkey(hd,des_key,8);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_decrypt(hd, cleartext, cryptgrm_len, cryptgrm, cryptgrm_len);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	gcry_cipher_close(hd);

	clear_tvb = tvb_new_child_real_data(encryptedData, cleartext, cryptgrm_len, cryptgrm_len);

	return clear_tvb;

on_gcry_error:
	*error = (const gchar *)gcry_strerror(err);
	if (hd) gcry_cipher_close(hd);
	return NULL;
}

static tvbuff_t*
snmp_usm_priv_aes_common(snmp_usm_params_t* p, tvbuff_t* encryptedData, packet_info *pinfo, gchar const** error, int algo)
{
	gcry_error_t err;
	gcry_cipher_hd_t hd = NULL;

	guint8* cleartext;
	guint8* aes_key = p->user_assoc->user.privKey.data;
	int aes_key_len = p->user_assoc->user.privKey.len;
	guint8 iv[16];
	gint priv_len;
	gint cryptgrm_len;
	guint8* cryptgrm;
	tvbuff_t* clear_tvb;

	priv_len = tvb_captured_length(p->priv_tvb);

	if (priv_len != 8) {
		*error = "decryptionError: msgPrivacyParameters length != 8";
		return NULL;
	}

	iv[0] = (p->boots & 0xff000000) >> 24;
	iv[1] = (p->boots & 0x00ff0000) >> 16;
	iv[2] = (p->boots & 0x0000ff00) >> 8;
	iv[3] = (p->boots & 0x000000ff);
	iv[4] = (p->snmp_time & 0xff000000) >> 24;
	iv[5] = (p->snmp_time & 0x00ff0000) >> 16;
	iv[6] = (p->snmp_time & 0x0000ff00) >> 8;
	iv[7] = (p->snmp_time & 0x000000ff);
	tvb_memcpy(p->priv_tvb,&(iv[8]),0,8);

	cryptgrm_len = tvb_captured_length(encryptedData);
	if (cryptgrm_len <= 0) {
		*error = "Not enough data remaining";
		return NULL;
	}
	cryptgrm = (guint8*)tvb_memdup(pinfo->pool,encryptedData,0,-1);

	cleartext = (guint8*)wmem_alloc(pinfo->pool, cryptgrm_len);

	err = gcry_cipher_open(&hd, algo, GCRY_CIPHER_MODE_CFB, 0);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_setiv(hd, iv, 16);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_setkey(hd,aes_key,aes_key_len);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_decrypt(hd, cleartext, cryptgrm_len, cryptgrm, cryptgrm_len);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	gcry_cipher_close(hd);

	clear_tvb = tvb_new_child_real_data(encryptedData, cleartext, cryptgrm_len, cryptgrm_len);

	return clear_tvb;

on_gcry_error:
	*error = (const gchar *)gcry_strerror(err);
	if (hd) gcry_cipher_close(hd);
	return NULL;
}

static tvbuff_t*
snmp_usm_priv_aes128(snmp_usm_params_t* p, tvbuff_t* encryptedData, packet_info *pinfo, gchar const** error)
{
	return snmp_usm_priv_aes_common(p, encryptedData, pinfo, error, GCRY_CIPHER_AES);
}

static tvbuff_t*
snmp_usm_priv_aes192(snmp_usm_params_t* p, tvbuff_t* encryptedData, packet_info *pinfo, gchar const** error)
{
	return snmp_usm_priv_aes_common(p, encryptedData, pinfo, error, GCRY_CIPHER_AES192);
}

static tvbuff_t*
snmp_usm_priv_aes256(snmp_usm_params_t* p, tvbuff_t* encryptedData, packet_info *pinfo, gchar const** error)
{
	return snmp_usm_priv_aes_common(p, encryptedData, pinfo, error, GCRY_CIPHER_AES256);
}

static gboolean
check_ScopedPdu(tvbuff_t* tvb)
{
	int offset;
	gint8 ber_class;
	gboolean pc;
	gint32 tag;
	int hoffset, eoffset;
	guint32 len;

	offset = get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);
	offset = get_ber_length(tvb, offset, NULL, NULL);

	if ( ! (((ber_class!=BER_CLASS_APP) && (ber_class!=BER_CLASS_PRI) )
			&& ( (!pc) || (ber_class!=BER_CLASS_UNI) || (tag!=BER_UNI_TAG_ENUMERATED) )
			)) return FALSE;

	if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0))
		return TRUE;

	hoffset = offset;

	offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
	offset = get_ber_length(tvb, offset, &len, NULL);
	eoffset = offset + len;

	if (eoffset <= hoffset) return FALSE;

	if ((ber_class!=BER_CLASS_APP)&&(ber_class!=BER_CLASS_PRI))
		if( (ber_class!=BER_CLASS_UNI)
			||((tag<BER_UNI_TAG_NumericString)&&(tag!=BER_UNI_TAG_OCTETSTRING)&&(tag!=BER_UNI_TAG_UTF8String)) )
			return FALSE;

	return TRUE;

}

#include "packet-snmp-fn.c"

static snmp_conv_info_t*
snmp_find_conversation_and_get_conv_data(packet_info *pinfo) {

	conversation_t *conversation;
	snmp_conv_info_t *snmp_info = NULL;

	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype),
		pinfo->srcport, pinfo->destport, 0);

	if( (conversation == NULL) || (conversation_get_dissector(conversation, pinfo->num)!=snmp_handle) ) {
		conversation = conversation_new(pinfo->num, &pinfo->src, &pinfo->dst, conversation_pt_to_conversation_type(pinfo->ptype),
			pinfo->srcport, pinfo->destport, 0);
		conversation_set_dissector(conversation, snmp_handle);
	}

	snmp_info = (snmp_conv_info_t *)conversation_get_proto_data(conversation, proto_snmp);
	if (snmp_info == NULL) {
		snmp_info = wmem_new0(wmem_file_scope(), snmp_conv_info_t);
		snmp_info->request_response=wmem_map_new(wmem_file_scope(), g_int_hash, g_int_equal);

		conversation_add_proto_data(conversation, proto_snmp, snmp_info);
	}
	return snmp_info;
}

guint
dissect_snmp_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree, int proto, gint ett, gboolean is_tcp)
{

	guint length_remaining;
	gint8 ber_class;
	gboolean pc, ind = 0;
	gint32 tag;
	guint32 len;
	guint message_length;
	int start_offset = offset;
	guint32 version = 0;
	tvbuff_t	*next_tvb;

	proto_tree *snmp_tree = NULL;
	proto_item *item = NULL;

	snmp_conv_info_t *snmp_info = snmp_find_conversation_and_get_conv_data(pinfo);

	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	asn1_ctx.private_data = snmp_info;

	usm_p.msg_tvb = tvb;
	usm_p.start_offset = tvb_offset_from_real_beginning(tvb);
	usm_p.engine_tvb = NULL;
	usm_p.user_tvb = NULL;
	usm_p.auth_item = NULL;
	usm_p.auth_tvb = NULL;
	usm_p.auth_offset = 0;
	usm_p.priv_tvb = NULL;
	usm_p.user_assoc = NULL;
	usm_p.authenticated = FALSE;
	usm_p.encrypted = FALSE;
	usm_p.boots = 0;
	usm_p.snmp_time = 0;
	usm_p.authOK = FALSE;

	/*
	 * This will throw an exception if we don't have any data left.
	 * That's what we want.  (See "tcp_dissect_pdus()", which is
	 * similar, but doesn't have to deal with ASN.1.
	 * XXX - can we make "tcp_dissect_pdus()" provide enough
	 * information to the "get_pdu_len" routine so that we could
	 * have that routine deal with ASN.1, and just use
	 * "tcp_dissect_pdus()"?)
	 */
	length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

	/* NOTE: we have to parse the message piece by piece, since the
	 * capture length may be less than the message length: a 'global'
	 * parsing is likely to fail.
	 */

	/*
	 * If this is SNMP-over-TCP, we might have to do reassembly
	 * in order to read the "Sequence Of" header.
	 */
	if (is_tcp && snmp_desegment && pinfo->can_desegment) {
		/*
		 * This is TCP, and we should, and can, do reassembly.
		 *
		 * Is the "Sequence Of" header split across segment
		 * boundaries?  We require at least 6 bytes for the
		 * header, which allows for a 4-byte length (ASN.1
		 * BER).
		 */
		if (length_remaining < 6) {
			/*
			 * Yes.  Tell the TCP dissector where the data
			 * for this message starts in the data it handed
			 * us and that we need "some more data."  Don't tell
			 * it exactly how many bytes we need because if/when
			 * we ask for even more (after the header) that will
			 * break reassembly.
			 */
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
			return -1;
		}
	}

	/*
	 * OK, try to read the "Sequence Of" header; this gets the total
	 * length of the SNMP message.
	 */
	offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
	/*Get the total octet length of the SNMP data*/
	offset = get_ber_length(tvb, offset, &len, &ind);
	message_length = len + offset;

	/*Get the SNMP version data*/
	/*offset =*/ dissect_ber_integer(FALSE, &asn1_ctx, 0, tvb, offset, -1, &version);


	/*
	 * If this is SNMP-over-TCP, we might have to do reassembly
	 * to get all of this message.
	 */
	if (is_tcp && snmp_desegment && pinfo->can_desegment) {
		/*
		 * Yes - is the message split across segment boundaries?
		 */
		if (length_remaining < message_length) {
			/*
			 * Yes.  Tell the TCP dissector where the data
			 * for this message starts in the data it handed
			 * us, and how many more bytes we need, and
			 * return.
			 */
			pinfo->desegment_offset = start_offset;
			pinfo->desegment_len =
			message_length - length_remaining;

			/*
			 * Return 0, which means "I didn't dissect anything
			 * because I don't have enough data - we need
			 * to desegment".
			 */
			return 0;
		}
	}

	var_list = next_tvb_list_new(pinfo->pool);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_get_protocol_short_name(find_protocol_by_id(proto)));

	item = proto_tree_add_item(tree, proto, tvb, start_offset, message_length, ENC_BIG_ENDIAN);
	snmp_tree = proto_item_add_subtree(item, ett);

	switch (version) {
	case 0: /* v1 */
	case 1: /* v2c */
		offset = dissect_snmp_Message(FALSE , tvb, start_offset, &asn1_ctx, snmp_tree, -1);
		break;
	case 2: /* v2u */
		offset = dissect_snmp_Messagev2u(FALSE , tvb, start_offset, &asn1_ctx, snmp_tree, -1);
		break;
			/* v3 */
	case 3:
		offset = dissect_snmp_SNMPv3Message(FALSE , tvb, start_offset, &asn1_ctx, snmp_tree, -1);
		break;
	default:
		/*
		 * Return the length remaining in the tvbuff, so
		 * if this is SNMP-over-TCP, our caller thinks there's
		 * nothing left to dissect.
		 */
		expert_add_info(pinfo, item, &ei_snmp_version_unknown);
		return length_remaining;
		break;
	}

	/* There may be appended data after the SNMP data, so treat as raw
	 * data which needs to be dissected in case of UDP as UDP is PDU oriented.
 	 */
	if((!is_tcp) && (length_remaining > (guint)offset)) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		call_dissector(data_handle, next_tvb, pinfo, tree);
	} else {
		next_tvb_call(var_list, pinfo, tree, NULL, data_handle);
	}

	return offset;
}

static gint
dissect_snmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int offset;
	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;
	guint32 tmp_length;
	gboolean tmp_ind;

	/*
	 * See if this looks like SNMP or not. if not, return 0 so
	 * wireshark can try some other dissector instead.
	 */
	/* All SNMP packets are BER encoded and consist of a SEQUENCE
	 * that spans the entire PDU. The first item is an INTEGER that
	 * has the values 0-2 (version 1-3).
	 * if not it is not snmp.
	 */
	/* SNMP starts with a SEQUENCE */
	offset = get_ber_identifier(tvb, 0, &tmp_class, &tmp_pc, &tmp_tag);
	if((tmp_class!=BER_CLASS_UNI)||(tmp_tag!=BER_UNI_TAG_SEQUENCE)) {
		return 0;
	}
	/* then comes a length which spans the rest of the tvb */
	offset = get_ber_length(tvb, offset, &tmp_length, &tmp_ind);
	/* if(tmp_length!=(guint32)tvb_reported_length_remaining(tvb, offset)) {
	 * Loosen the heuristic a bit to handle the case where data has intentionally
	 * been added after the snmp PDU ( UDP case)
	 */
	if ( pinfo->ptype == PT_UDP ) {
		if(tmp_length>(guint32)tvb_reported_length_remaining(tvb, offset)) {
			return 0;
		}
	}else{
		if(tmp_length!=(guint32)tvb_reported_length_remaining(tvb, offset)) {
			return 0;
		}
	}
	/* then comes an INTEGER (version)*/
	get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);
	if((tmp_class!=BER_CLASS_UNI)||(tmp_tag!=BER_UNI_TAG_INTEGER)) {
		return 0;
	}
	/* do we need to test that version is 0 - 2 (version1-3) ? */


	/*
	 * The first SNMP packet goes to the SNMP port; the second one
	 * may come from some *other* port, but goes back to the same
	 * IP address and port as the ones from which the first packet
	 * came; all subsequent packets presumably go between those two
	 * IP addresses and ports.
	 *
	 * If this packet went to the SNMP port, we check to see if
	 * there's already a conversation with one address/port pair
	 * matching the source IP address and port of this packet,
	 * the other address matching the destination IP address of this
	 * packet, and any destination port.
	 *
	 * If not, we create one, with its address 1/port 1 pair being
	 * the source address/port of this packet, its address 2 being
	 * the destination address of this packet, and its port 2 being
	 * wildcarded, and give it the SNMP dissector as a dissector.
	 */

	return dissect_snmp_pdu(tvb, 0, pinfo, tree, proto_snmp, ett_snmp, FALSE);
}

static int
dissect_snmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int offset = 0;
	guint message_len;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		message_len = dissect_snmp_pdu(tvb, 0, pinfo, tree, proto_snmp, ett_snmp, TRUE);
		if (message_len == 0) {
			/*
			 * We don't have all the data for that message,
			 * so we need to do desegmentation;
			 * "dissect_snmp_pdu()" has set that up.
			 */
			break;
		}
		offset += message_len;
	}
	return tvb_captured_length(tvb);
}

static int
dissect_smux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_tree *smux_tree = NULL;
	proto_item *item = NULL;

	var_list = next_tvb_list_new(pinfo->pool);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMUX");

	item = proto_tree_add_item(tree, proto_smux, tvb, 0, -1, ENC_NA);
	smux_tree = proto_item_add_subtree(item, ett_smux);

	return dissect_SMUX_PDUs_PDU(tvb, pinfo, smux_tree, data);
}

/*
  MD5 Password to Key Algorithm from RFC 3414 A.2.1
  SHA1 Password to Key Algorithm from RFC 3414 A.2.2
  SHA2 Password to Key Algorithm from RFC 7860 9.3
*/
static void
snmp_usm_password_to_key(const snmp_usm_auth_model_t model, const guint8 *password,
	guint passwordlen, const guint8 *engineID, guint engineLength, guint8 *key)
{
	gcry_md_hd_t	hash_handle;
	guint8	  *cp, password_buf[64];
	guint32	 password_index = 0;
	guint32	 count = 0, i;
	guint	   hash_len;

	if (gcry_md_open(&hash_handle, auth_hash_algo[model], 0)) {
		return;
	}

	hash_len = auth_hash_len[model];

	/**********************************************/
	/* Use while loop until we've done 1 Megabyte */
	/**********************************************/
	while (count < 1048576) {
		cp = password_buf;
		if (passwordlen != 0) {
			for (i = 0; i < 64; i++) {
				/*************************************************/
				/* Take the next octet of the password, wrapping */
				/* to the beginning of the password as necessary.*/
				/*************************************************/
				*cp++ = password[password_index++ % passwordlen];
			}
		} else {
			*cp = 0;
		}
		gcry_md_write(hash_handle, password_buf, 64);
		count += 64;
	}
	memcpy(key, gcry_md_read(hash_handle, 0), hash_len);
	gcry_md_close(hash_handle);

	/*****************************************************/
	/* Now localise the key with the engineID and pass   */
	/* through hash function to produce final key        */
	/* We ignore invalid engineLengths here. More strict */
	/* checking is done in snmp_users_update_cb.         */
	/*****************************************************/
	if (gcry_md_open(&hash_handle, auth_hash_algo[model], 0)) {
		return;
	}
	gcry_md_write(hash_handle, key, hash_len);
	gcry_md_write(hash_handle, engineID, engineLength);
	gcry_md_write(hash_handle, key, hash_len);
	memcpy(key, gcry_md_read(hash_handle, 0), hash_len);
	gcry_md_close(hash_handle);
	return;
}

static void
process_prefs(void)
{
}

UAT_LSTRING_CB_DEF(snmp_users,userName,snmp_ue_assoc_t,user.userName.data,user.userName.len)
UAT_LSTRING_CB_DEF(snmp_users,authPassword,snmp_ue_assoc_t,user.authPassword.data,user.authPassword.len)
UAT_LSTRING_CB_DEF(snmp_users,privPassword,snmp_ue_assoc_t,user.privPassword.data,user.privPassword.len)
UAT_BUFFER_CB_DEF(snmp_users,engine_id,snmp_ue_assoc_t,engine.data,engine.len)
UAT_VS_DEF(snmp_users,auth_model,snmp_ue_assoc_t,guint,0,"MD5")
UAT_VS_DEF(snmp_users,priv_proto,snmp_ue_assoc_t,guint,0,"DES")

static void *
snmp_specific_trap_copy_cb(void *dest, const void *orig, size_t len _U_)
{
	snmp_st_assoc_t *u = (snmp_st_assoc_t *)dest;
	const snmp_st_assoc_t *o = (const snmp_st_assoc_t *)orig;

	u->enterprise = g_strdup(o->enterprise);
	u->trap = o->trap;
	u->desc = g_strdup(o->desc);

	return dest;
}

static void
snmp_specific_trap_free_cb(void *r)
{
	snmp_st_assoc_t *u = (snmp_st_assoc_t *)r;

	g_free(u->enterprise);
	g_free(u->desc);
}

UAT_CSTRING_CB_DEF(specific_traps, enterprise, snmp_st_assoc_t)
UAT_DEC_CB_DEF(specific_traps, trap, snmp_st_assoc_t)
UAT_CSTRING_CB_DEF(specific_traps, desc, snmp_st_assoc_t)

	/*--- proto_register_snmp -------------------------------------------*/
void proto_register_snmp(void) {
	/* List of fields */
	static hf_register_info hf[] = {
		{ &hf_snmp_response_in,
		{ "Response In", "snmp.response_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"The response to this SNMP request is in this frame", HFILL }},
		{ &hf_snmp_response_to,
		{ "Response To", "snmp.response_to", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This is a response to the SNMP request in this frame", HFILL }},
		{ &hf_snmp_time,
		{ "Time", "snmp.time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
			"The time between the Request and the Response", HFILL }},
		{ &hf_snmp_v3_flags_auth,
		{ "Authenticated", "snmp.v3.flags.auth", FT_BOOLEAN, 8,
		    TFS(&tfs_set_notset), TH_AUTH, NULL, HFILL }},
		{ &hf_snmp_v3_flags_crypt,
		{ "Encrypted", "snmp.v3.flags.crypt", FT_BOOLEAN, 8,
		    TFS(&tfs_set_notset), TH_CRYPT, NULL, HFILL }},
		{ &hf_snmp_v3_flags_report,
		{ "Reportable", "snmp.v3.flags.report", FT_BOOLEAN, 8,
		    TFS(&tfs_set_notset), TH_REPORT, NULL, HFILL }},
		{ &hf_snmp_engineid_conform, {
		    "Engine ID Conformance", "snmp.engineid.conform", FT_BOOLEAN, 8,
		    TFS(&tfs_snmp_engineid_conform), F_SNMP_ENGINEID_CONFORM, "Engine ID RFC3411 Conformance", HFILL }},
		{ &hf_snmp_engineid_enterprise, {
		    "Engine Enterprise ID", "snmp.engineid.enterprise", FT_UINT32, BASE_ENTERPRISES,
		    STRINGS_ENTERPRISES, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_format, {
		    "Engine ID Format", "snmp.engineid.format", FT_UINT8, BASE_DEC,
		    VALS(snmp_engineid_format_vals), 0, NULL, HFILL }},
		{ &hf_snmp_engineid_ipv4, {
		    "Engine ID Data: IPv4 address", "snmp.engineid.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_ipv6, {
		    "Engine ID Data: IPv6 address", "snmp.engineid.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_cisco_type, {
		    "Engine ID Data: Cisco type", "snmp.engineid.cisco.type", FT_UINT8, BASE_HEX,
		    VALS(snmp_engineid_cisco_type_vals), 0, NULL, HFILL }},
		{ &hf_snmp_engineid_mac, {
		    "Engine ID Data: MAC address", "snmp.engineid.mac", FT_ETHER, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_text, {
		    "Engine ID Data: Text", "snmp.engineid.text", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_time, {
		    "Engine ID Data: Creation Time", "snmp.engineid.time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_engineid_data, {
		    "Engine ID Data", "snmp.engineid.data", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_msgAuthentication, {
		    "Authentication", "snmp.v3.auth", FT_BOOLEAN, BASE_NONE,
		    TFS(&auth_flags), 0, NULL, HFILL }},
		{ &hf_snmp_decryptedPDU, {
		    "Decrypted ScopedPDU", "snmp.decrypted_pdu", FT_BYTES, BASE_NONE,
		    NULL, 0, "Decrypted PDU", HFILL }},
		{ &hf_snmp_noSuchObject, {
		    "noSuchObject", "snmp.noSuchObject", FT_NONE, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_noSuchInstance, {
		    "noSuchInstance", "snmp.noSuchInstance", FT_NONE, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_endOfMibView, {
		    "endOfMibView", "snmp.endOfMibView", FT_NONE, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_unSpecified, {
		    "unSpecified", "snmp.unSpecified", FT_NONE, BASE_NONE,
		    NULL, 0, NULL, HFILL }},

		{ &hf_snmp_integer32_value, {
		    "Value (Integer32)", "snmp.value.int", FT_INT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_octetstring_value, {
		    "Value (OctetString)", "snmp.value.octets", FT_BYTES, BASE_SHOW_ASCII_PRINTABLE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_oid_value, {
		    "Value (OID)", "snmp.value.oid", FT_OID, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_null_value, {
		    "Value (Null)", "snmp.value.null", FT_NONE, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_ipv4_value, {
		    "Value (IpAddress)", "snmp.value.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_ipv6_value, {
		    "Value (IpAddress)", "snmp.value.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_anyaddress_value, {
		    "Value (IpAddress)", "snmp.value.addr", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_unsigned32_value, {
		    "Value (Unsigned32)", "snmp.value.u32", FT_INT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_gauge32_value, {
		    "Value (Gauge32)", "snmp.value.g32", FT_INT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_unknown_value, {
		    "Value (Unknown)", "snmp.value.unk", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_counter_value, {
		    "Value (Counter32)", "snmp.value.counter", FT_UINT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_big_counter_value, {
		    "Value (Counter64)", "snmp.value.counter", FT_UINT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_nsap_value, {
		    "Value (NSAP)", "snmp.value.nsap", FT_UINT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_timeticks_value, {
		    "Value (Timeticks)", "snmp.value.timeticks", FT_UINT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_opaque_value, {
		    "Value (Opaque)", "snmp.value.opaque", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_objectname, {
		    "Object Name", "snmp.name", FT_OID, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_scalar_instance_index, {
		    "Scalar Instance Index", "snmp.name.index", FT_UINT64, BASE_DEC,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_var_bind_str, {
		    "Variable-binding-string", "snmp.var-bind_str", FT_STRING, BASE_NONE,
		    NULL, 0, NULL, HFILL }},
		{ &hf_snmp_agentid_trailer, {
		    "AgentID Trailer", "snmp.agentid_trailer", FT_BYTES, BASE_NONE,
		    NULL, 0, NULL, HFILL }},


#include "packet-snmp-hfarr.c"
	};

	/* List of subtrees */
	static gint *ett[] = {
		&ett_snmp,
		&ett_engineid,
		&ett_msgFlags,
		&ett_encryptedPDU,
		&ett_decrypted,
		&ett_authParameters,
		&ett_internet,
		&ett_varbind,
		&ett_name,
		&ett_value,
		&ett_decoding_error,
#include "packet-snmp-ettarr.c"
	};
	static ei_register_info ei[] = {
		{ &ei_snmp_failed_decrypted_data_pdu, { "snmp.failed_decrypted_data_pdu", PI_MALFORMED, PI_WARN, "Failed to decrypt encryptedPDU", EXPFILL }},
		{ &ei_snmp_decrypted_data_bad_formatted, { "snmp.decrypted_data_bad_formatted", PI_MALFORMED, PI_WARN, "Decrypted data not formatted as expected, wrong key?", EXPFILL }},
		{ &ei_snmp_verify_authentication_error, { "snmp.verify_authentication_error", PI_MALFORMED, PI_ERROR, "Error while verifying Message authenticity", EXPFILL }},
		{ &ei_snmp_authentication_ok, { "snmp.authentication_ok", PI_CHECKSUM, PI_CHAT, "SNMP Authentication OK", EXPFILL }},
		{ &ei_snmp_authentication_error, { "snmp.authentication_error", PI_CHECKSUM, PI_WARN, "SNMP Authentication Error", EXPFILL }},
		{ &ei_snmp_varbind_not_uni_class_seq, { "snmp.varbind.not_uni_class_seq", PI_MALFORMED, PI_WARN, "VarBind is not an universal class sequence", EXPFILL }},
		{ &ei_snmp_varbind_has_indicator, { "snmp.varbind.has_indicator", PI_MALFORMED, PI_WARN, "VarBind has indicator set", EXPFILL }},
		{ &ei_snmp_objectname_not_oid, { "snmp.objectname_not_oid", PI_MALFORMED, PI_WARN, "ObjectName not an OID", EXPFILL }},
		{ &ei_snmp_objectname_has_indicator, { "snmp.objectname_has_indicator", PI_MALFORMED, PI_WARN, "ObjectName has indicator set", EXPFILL }},
		{ &ei_snmp_value_not_primitive_encoding, { "snmp.value_not_primitive_encoding", PI_MALFORMED, PI_WARN, "value not in primitive encoding", EXPFILL }},
		{ &ei_snmp_invalid_oid, { "snmp.invalid_oid", PI_MALFORMED, PI_WARN, "invalid oid", EXPFILL }},
		{ &ei_snmp_varbind_wrong_tag, { "snmp.varbind.wrong_tag", PI_MALFORMED, PI_WARN, "Wrong tag for SNMP VarBind error value", EXPFILL }},
		{ &ei_snmp_varbind_response, { "snmp.varbind.response", PI_RESPONSE_CODE, PI_NOTE, "Response", EXPFILL }},
		{ &ei_snmp_no_instance_subid, { "snmp.no_instance_subid", PI_MALFORMED, PI_WARN, "No instance sub-id in scalar value", EXPFILL }},
		{ &ei_snmp_wrong_num_of_subids, { "snmp.wrong_num_of_subids", PI_MALFORMED, PI_WARN, "Wrong number of instance sub-ids in scalar value", EXPFILL }},
		{ &ei_snmp_index_suboid_too_short, { "snmp.index_suboid_too_short", PI_MALFORMED, PI_WARN, "index sub-oid shorter than expected", EXPFILL }},
		{ &ei_snmp_unimplemented_instance_index, { "snmp.unimplemented_instance_index", PI_UNDECODED, PI_WARN, "OID instaces not handled, if you want this implemented please contact the wireshark developers", EXPFILL }},
		{ &ei_snmp_index_suboid_len0, { "snmp.ndex_suboid_len0", PI_MALFORMED, PI_WARN, "an index sub-oid OID cannot be 0 bytes long!", EXPFILL }},
		{ &ei_snmp_index_suboid_too_long, { "snmp.index_suboid_too_long", PI_MALFORMED, PI_WARN, "index sub-oid should not be longer than remaining oid size", EXPFILL }},
		{ &ei_snmp_index_string_too_long, { "snmp.index_string_too_long", PI_MALFORMED, PI_WARN, "index string should not be longer than remaining oid size", EXPFILL }},
		{ &ei_snmp_column_parent_not_row, { "snmp.column_parent_not_row", PI_MALFORMED, PI_ERROR, "COLUMNS's parent is not a ROW", EXPFILL }},
		{ &ei_snmp_uint_too_large, { "snmp.uint_too_large", PI_UNDECODED, PI_NOTE, "Unsigned integer value > 2^64 - 1", EXPFILL }},
		{ &ei_snmp_int_too_large, { "snmp.int_too_large", PI_UNDECODED, PI_NOTE, "Signed integer value > 2^63 - 1 or <= -2^63", EXPFILL }},
		{ &ei_snmp_integral_value0, { "snmp.integral_value0", PI_UNDECODED, PI_NOTE, "Integral value is zero-length", EXPFILL }},
		{ &ei_snmp_missing_mib, { "snmp.missing_mib", PI_UNDECODED, PI_NOTE, "Unresolved value, Missing MIB", EXPFILL }},
		{ &ei_snmp_varbind_wrong_length_value, { "snmp.varbind.wrong_length_value", PI_MALFORMED, PI_WARN, "Wrong length for SNMP VarBind/value", EXPFILL }},
		{ &ei_snmp_varbind_wrong_class_tag, { "snmp.varbind.wrong_class_tag", PI_MALFORMED, PI_WARN, "Wrong class/tag for SNMP VarBind/value", EXPFILL }},
		{ &ei_snmp_rfc1910_non_conformant, { "snmp.rfc1910_non_conformant", PI_PROTOCOL, PI_WARN, "Data not conforming to RFC1910", EXPFILL }},
		{ &ei_snmp_rfc3411_non_conformant, { "snmp.rfc3411_non_conformant", PI_PROTOCOL, PI_WARN, "Data not conforming to RFC3411", EXPFILL }},
		{ &ei_snmp_version_unknown, { "snmp.version.unknown", PI_PROTOCOL, PI_WARN, "Unknown version", EXPFILL }},
		{ &ei_snmp_trap_pdu_obsolete, { "snmp.trap_pdu_obsolete", PI_PROTOCOL, PI_WARN, "Trap-PDU is obsolete in this SNMP version", EXPFILL }},

	};

	expert_module_t* expert_snmp;
	module_t *snmp_module;

	static uat_field_t users_fields[] = {
		UAT_FLD_BUFFER(snmp_users,engine_id,"Engine ID","Engine-id for this entry (empty = any)"),
		UAT_FLD_LSTRING(snmp_users,userName,"Username","The username"),
		UAT_FLD_VS(snmp_users,auth_model,"Authentication model",auth_types,"Algorithm to be used for authentication."),
		UAT_FLD_LSTRING(snmp_users,authPassword,"Password","The password used for authenticating packets for this entry"),
		UAT_FLD_VS(snmp_users,priv_proto,"Privacy protocol",priv_types,"Algorithm to be used for privacy."),
		UAT_FLD_LSTRING(snmp_users,privPassword,"Privacy password","The password used for encrypting packets for this entry"),
		UAT_END_FIELDS
	};

	uat_t *assocs_uat = uat_new("SNMP Users",
				    sizeof(snmp_ue_assoc_t),
				    "snmp_users",
				    TRUE,
				    &ueas,
				    &num_ueas,
				    UAT_AFFECTS_DISSECTION,	/* affects dissection of packets, but not set of named fields */
				    "ChSNMPUsersSection",
				    snmp_users_copy_cb,
				    snmp_users_update_cb,
				    snmp_users_free_cb,
				    renew_ue_cache,
				    NULL,
				    users_fields);

	static uat_field_t specific_traps_flds[] = {
		UAT_FLD_CSTRING(specific_traps,enterprise,"Enterprise OID","Enterprise Object Identifier"),
		UAT_FLD_DEC(specific_traps,trap,"Trap Id","The specific-trap value"),
		UAT_FLD_CSTRING(specific_traps,desc,"Description","Trap type description"),
		UAT_END_FIELDS
	};

	uat_t* specific_traps_uat = uat_new("SNMP Enterprise Specific Trap Types",
					    sizeof(snmp_st_assoc_t),
					    "snmp_specific_traps",
					    TRUE,
					    &specific_traps,
					    &num_specific_traps,
					    UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
					    "ChSNMPEnterpriseSpecificTrapTypes",
					    snmp_specific_trap_copy_cb,
					    NULL,
					    snmp_specific_trap_free_cb,
					    NULL,
					    NULL,
					    specific_traps_flds);

	/* Register protocol */
	proto_snmp = proto_register_protocol(PNAME, PSNAME, PFNAME);
	snmp_handle = register_dissector("snmp", dissect_snmp, proto_snmp);

	/* Register fields and subtrees */
	proto_register_field_array(proto_snmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_snmp = expert_register_protocol(proto_snmp);
	expert_register_field_array(expert_snmp, ei, array_length(ei));


	/* Register configuration preferences */
	snmp_module = prefs_register_protocol(proto_snmp, process_prefs);
	prefs_register_bool_preference(snmp_module, "display_oid",
			"Show SNMP OID in info column",
			"Whether the SNMP OID should be shown in the info column",
			&display_oid);

	prefs_register_obsolete_preference(snmp_module, "mib_modules");
	prefs_register_obsolete_preference(snmp_module, "users_file");

	prefs_register_bool_preference(snmp_module, "desegment",
			"Reassemble SNMP-over-TCP messages spanning multiple TCP segments",
			"Whether the SNMP dissector should reassemble messages spanning multiple TCP segments."
			" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
			&snmp_desegment);

	prefs_register_bool_preference(snmp_module, "var_in_tree",
			"Display dissected variables inside SNMP tree",
			"ON - display dissected variables inside SNMP tree, OFF - display dissected variables in root tree after SNMP",
			&snmp_var_in_tree);

	prefs_register_uat_preference(snmp_module, "users_table",
				"Users Table",
				"Table of engine-user associations used for authentication and decryption",
				assocs_uat);

	prefs_register_uat_preference(snmp_module, "specific_traps_table",
				"Enterprise Specific Trap Types",
				"Table of enterprise specific-trap type descriptions",
				specific_traps_uat);

#ifdef HAVE_LIBSMI
	prefs_register_static_text_preference(snmp_module, "info_mibs",
				"MIB settings can be changed in the Name Resolution preferences",
				"MIB settings can be changed in the Name Resolution preferences");
#endif

	value_sub_dissectors_table = register_dissector_table("snmp.variable_oid","SNMP Variable OID", proto_snmp, FT_STRING, BASE_NONE);

	register_init_routine(init_ue_cache);
	register_cleanup_routine(cleanup_ue_cache);

	register_ber_syntax_dissector("SNMP", proto_snmp, dissect_snmp_tcp);

	snmp_tap=register_tap("snmp");

	register_srt_table(proto_snmp, NULL, 1, snmpstat_packet, snmpstat_init, NULL);
}


/*--- proto_reg_handoff_snmp ---------------------------------------*/
void proto_reg_handoff_snmp(void) {
	dissector_handle_t snmp_tcp_handle;

	dissector_add_uint_with_preference("udp.port", UDP_PORT_SNMP, snmp_handle);
	dissector_add_uint("ethertype", ETHERTYPE_SNMP, snmp_handle);
	dissector_add_uint("ipx.socket", IPX_SOCKET_SNMP_AGENT, snmp_handle);
	dissector_add_uint("ipx.socket", IPX_SOCKET_SNMP_SINK, snmp_handle);
	dissector_add_uint("hpext.dxsap", HPEXT_SNMP, snmp_handle);

	snmp_tcp_handle = create_dissector_handle(dissect_snmp_tcp, proto_snmp);
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_SNMP, snmp_tcp_handle);
	/* Since "regular" SNMP port and "trap" SNMP port use the same handler,
	   the "trap" port doesn't really need a separate preference.  Just register
	   normally */
	dissector_add_uint("tcp.port", TCP_PORT_SNMP_TRAP, snmp_tcp_handle);
	dissector_add_uint("udp.port", UDP_PORT_SNMP_TRAP, snmp_handle);
	dissector_add_uint("udp.port", UDP_PORT_SNMP_PATROL, snmp_handle);

	data_handle = find_dissector("data");

	/* SNMPv2-MIB sysDescr "1.3.6.1.2.1.1.1.0" */
	dissector_add_string("snmp.variable_oid", "1.3.6.1.2.1.1.1.0",
		create_dissector_handle(dissect_snmp_variable_string, proto_snmp));
	/* SNMPv2-MIB::sysName.0 (1.3.6.1.2.1.1.5.0) */
	dissector_add_string("snmp.variable_oid", "1.3.6.1.2.1.1.5.0",
		create_dissector_handle(dissect_snmp_variable_string, proto_snmp));

	/*
	 * Process preference settings.
	 *
	 * We can't do this in the register routine, as preferences aren't
	 * read until all dissector register routines have been called (so
	 * that all dissector preferences have been registered).
	 */
	process_prefs();

}

void
proto_register_smux(void)
{
	static gint *ett[] = {
		&ett_smux,
	};

	proto_smux = proto_register_protocol("SNMP Multiplex Protocol",
	    "SMUX", "smux");

	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_smux(void)
{
	dissector_handle_t smux_handle;

	smux_handle = create_dissector_handle(dissect_smux, proto_smux);
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_SMUX, smux_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
