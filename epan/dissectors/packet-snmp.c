/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-snmp.c                                                              */
/* ../../tools/asn2wrs.py -b -p snmp -c ./snmp.cnf -s ./packet-snmp-template -D . -O ../../epan/dissectors snmp.asn */

/* Input file: packet-snmp-template.c */

#line 1 "../../asn1/snmp/packet-snmp-template.c"
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
 * $Id$
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

#define D(args) do {printf args; fflush(stdout); } while(0)

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include <epan/emem.h>
#include <epan/next_tvb.h>
#include <epan/uat.h>
#include <epan/asn1.h>
#include "packet-ipx.h"
#include "packet-hpext.h"


#include "packet-ber.h"

#include "packet-snmp.h"

#include <epan/crypt/crypt-sha1.h>
#include <epan/crypt/crypt-md5.h>
#include <epan/expert.h>
#include <epan/report_err.h>
#include <epan/oids.h>


#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

/* Take a pointer that may be null and return a pointer that's not null
   by turning null pointers into pointers to the above null string,
   and, if the argument pointer wasn't null, make sure we handle
   non-printable characters in the string by escaping them. */
#define	SAFE_STRING(s, l)	(((s) != NULL) ? format_text((s), (l)) : "")

#define PNAME  "Simple Network Management Protocol"
#define PSNAME "SNMP"
#define PFNAME "snmp"

#define UDP_PORT_SNMP		161
#define UDP_PORT_SNMP_TRAP	162
#define TCP_PORT_SNMP		161
#define TCP_PORT_SNMP_TRAP	162
#define TCP_PORT_SMUX		199
#define UDP_PORT_SNMP_PATROL 8161

/* Initialize the protocol and registered fields */
static int proto_snmp = -1;
static int proto_smux = -1;

static gboolean display_oid = TRUE;
static gboolean snmp_var_in_tree = TRUE;

static gboolean snmp_usm_auth_md5(snmp_usm_params_t* p, guint8**, guint*, gchar const**);
static gboolean snmp_usm_auth_sha1(snmp_usm_params_t* p, guint8**, guint*, gchar const**);

static tvbuff_t* snmp_usm_priv_des(snmp_usm_params_t*, tvbuff_t*, gchar const**);
static tvbuff_t* snmp_usm_priv_aes(snmp_usm_params_t*, tvbuff_t*, gchar const**);


static void snmp_usm_password_to_key_md5(const guint8 *password, guint passwordlen, const guint8 *engineID, guint engineLength, guint8 *key);
static void snmp_usm_password_to_key_sha1(const guint8 *password, guint passwordlen, const guint8 *engineID, guint engineLength, guint8 *key);


static snmp_usm_auth_model_t model_md5 = {snmp_usm_password_to_key_md5, snmp_usm_auth_md5, 16};
static snmp_usm_auth_model_t model_sha1 = {snmp_usm_password_to_key_sha1, snmp_usm_auth_sha1, 20};

static const value_string auth_types[] = {
	{0,"MD5"},
	{1,"SHA1"},
	{0,NULL}
};
static snmp_usm_auth_model_t* auth_models[] = {&model_md5,&model_sha1};


static const value_string priv_types[] = {
	{0,"DES"},
	{1,"AES"},
	{0,NULL}
};
static snmp_usm_decoder_t priv_protos[] = {snmp_usm_priv_des, snmp_usm_priv_aes};

static snmp_ue_assoc_t* ueas = NULL;
static guint num_ueas = 0;
static snmp_ue_assoc_t* localized_ues = NULL;
static snmp_ue_assoc_t* unlocalized_ues = NULL;
/****/

/* Variabled used for handling enterprise spesific trap types */
typedef struct _snmp_st_assoc_t {
	char *enterprise;
	guint trap;
	char *desc;
} snmp_st_assoc_t;
static guint num_specific_traps = 0;
static snmp_st_assoc_t *specific_traps = NULL;
static const char *enterprise_oid = NULL;
static guint generic_trap = 0;


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

static next_tvb_list_t var_list;

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



/*--- Included file: packet-snmp-hf.c ---*/
#line 1 "../../asn1/snmp/packet-snmp-hf.c"
static int hf_snmp_SMUX_PDUs_PDU = -1;            /* SMUX_PDUs */
static int hf_snmp_version = -1;                  /* Version */
static int hf_snmp_community = -1;                /* Community */
static int hf_snmp_data = -1;                     /* PDUs */
static int hf_snmp_parameters = -1;               /* OCTET_STRING */
static int hf_snmp_datav2u = -1;                  /* T_datav2u */
static int hf_snmp_v2u_plaintext = -1;            /* PDUs */
static int hf_snmp_encrypted = -1;                /* OCTET_STRING */
static int hf_snmp_msgAuthoritativeEngineID = -1;  /* T_msgAuthoritativeEngineID */
static int hf_snmp_msgAuthoritativeEngineBoots = -1;  /* T_msgAuthoritativeEngineBoots */
static int hf_snmp_msgAuthoritativeEngineTime = -1;  /* T_msgAuthoritativeEngineTime */
static int hf_snmp_msgUserName = -1;              /* T_msgUserName */
static int hf_snmp_msgAuthenticationParameters = -1;  /* T_msgAuthenticationParameters */
static int hf_snmp_msgPrivacyParameters = -1;     /* T_msgPrivacyParameters */
static int hf_snmp_msgVersion = -1;               /* Version */
static int hf_snmp_msgGlobalData = -1;            /* HeaderData */
static int hf_snmp_msgSecurityParameters = -1;    /* T_msgSecurityParameters */
static int hf_snmp_msgData = -1;                  /* ScopedPduData */
static int hf_snmp_msgID = -1;                    /* INTEGER_0_2147483647 */
static int hf_snmp_msgMaxSize = -1;               /* INTEGER_484_2147483647 */
static int hf_snmp_msgFlags = -1;                 /* T_msgFlags */
static int hf_snmp_msgSecurityModel = -1;         /* T_msgSecurityModel */
static int hf_snmp_plaintext = -1;                /* ScopedPDU */
static int hf_snmp_encryptedPDU = -1;             /* T_encryptedPDU */
static int hf_snmp_contextEngineID = -1;          /* SnmpEngineID */
static int hf_snmp_contextName = -1;              /* OCTET_STRING */
static int hf_snmp_get_request = -1;              /* GetRequest_PDU */
static int hf_snmp_get_next_request = -1;         /* GetNextRequest_PDU */
static int hf_snmp_get_response = -1;             /* GetResponse_PDU */
static int hf_snmp_set_request = -1;              /* SetRequest_PDU */
static int hf_snmp_trap = -1;                     /* Trap_PDU */
static int hf_snmp_getBulkRequest = -1;           /* GetBulkRequest_PDU */
static int hf_snmp_informRequest = -1;            /* InformRequest_PDU */
static int hf_snmp_snmpV2_trap = -1;              /* SNMPv2_Trap_PDU */
static int hf_snmp_report = -1;                   /* Report_PDU */
static int hf_snmp_request_id = -1;               /* INTEGER */
static int hf_snmp_error_status = -1;             /* T_error_status */
static int hf_snmp_error_index = -1;              /* INTEGER */
static int hf_snmp_variable_bindings = -1;        /* VarBindList */
static int hf_snmp_bulkPDU_request_id = -1;       /* Integer32 */
static int hf_snmp_non_repeaters = -1;            /* INTEGER_0_2147483647 */
static int hf_snmp_max_repetitions = -1;          /* INTEGER_0_2147483647 */
static int hf_snmp_enterprise = -1;               /* EnterpriseOID */
static int hf_snmp_agent_addr = -1;               /* NetworkAddress */
static int hf_snmp_generic_trap = -1;             /* GenericTrap */
static int hf_snmp_specific_trap = -1;            /* SpecificTrap */
static int hf_snmp_time_stamp = -1;               /* TimeTicks */
static int hf_snmp_name = -1;                     /* ObjectName */
static int hf_snmp_valueType = -1;                /* NULL */
static int hf_snmp_VarBindList_item = -1;         /* VarBind */
static int hf_snmp_open = -1;                     /* OpenPDU */
static int hf_snmp_close = -1;                    /* ClosePDU */
static int hf_snmp_registerRequest = -1;          /* RReqPDU */
static int hf_snmp_registerResponse = -1;         /* RegisterResponse */
static int hf_snmp_commitOrRollback = -1;         /* SOutPDU */
static int hf_snmp_rRspPDU = -1;                  /* RRspPDU */
static int hf_snmp_pDUs = -1;                     /* PDUs */
static int hf_snmp_smux_simple = -1;              /* SimpleOpen */
static int hf_snmp_smux_version = -1;             /* T_smux_version */
static int hf_snmp_identity = -1;                 /* OBJECT_IDENTIFIER */
static int hf_snmp_description = -1;              /* DisplayString */
static int hf_snmp_password = -1;                 /* OCTET_STRING */
static int hf_snmp_subtree = -1;                  /* ObjectName */
static int hf_snmp_priority = -1;                 /* INTEGER_M1_2147483647 */
static int hf_snmp_operation = -1;                /* T_operation */

/*--- End of included file: packet-snmp-hf.c ---*/
#line 221 "../../asn1/snmp/packet-snmp-template.c"

static int hf_smux_version = -1;
static int hf_smux_pdutype = -1;

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


/*--- Included file: packet-snmp-ett.c ---*/
#line 1 "../../asn1/snmp/packet-snmp-ett.c"
static gint ett_snmp_Message = -1;
static gint ett_snmp_Messagev2u = -1;
static gint ett_snmp_T_datav2u = -1;
static gint ett_snmp_UsmSecurityParameters = -1;
static gint ett_snmp_SNMPv3Message = -1;
static gint ett_snmp_HeaderData = -1;
static gint ett_snmp_ScopedPduData = -1;
static gint ett_snmp_ScopedPDU = -1;
static gint ett_snmp_PDUs = -1;
static gint ett_snmp_PDU = -1;
static gint ett_snmp_BulkPDU = -1;
static gint ett_snmp_Trap_PDU_U = -1;
static gint ett_snmp_VarBind = -1;
static gint ett_snmp_VarBindList = -1;
static gint ett_snmp_SMUX_PDUs = -1;
static gint ett_snmp_RegisterResponse = -1;
static gint ett_snmp_OpenPDU = -1;
static gint ett_snmp_SimpleOpen_U = -1;
static gint ett_snmp_RReqPDU_U = -1;

/*--- End of included file: packet-snmp-ett.c ---*/
#line 240 "../../asn1/snmp/packet-snmp-template.c"

static const true_false_string auth_flags = {
	"OK",
	"Failed"
};

/* Security Models */

#define SNMP_SEC_ANY			0
#define SNMP_SEC_V1				1
#define SNMP_SEC_V2C			2
#define SNMP_SEC_USM			3

static const value_string sec_models[] = {
	{ SNMP_SEC_ANY,			"Any" },
	{ SNMP_SEC_V1,			"V1" },
	{ SNMP_SEC_V2C,			"V2C" },
	{ SNMP_SEC_USM,			"USM" },
	{ 0,				NULL }
};

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

extern int
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
	offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
	offset = get_ber_length(tvb, offset, &seq_len, &ind);

	seq_len += offset - seq_offset;

	if (!pc && ber_class==BER_CLASS_UNI && tag==BER_UNI_TAG_SEQUENCE) {
		proto_item* pi = proto_tree_add_text(tree, tvb, seq_offset, seq_len,"VarBind must be an universal class sequence");
		pt = proto_item_add_subtree(pi,ett_decoding_error);
		expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "VarBind is not an universal class sequence");
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	if (ind) {
		proto_item* pi = proto_tree_add_text(tree, tvb, seq_offset, seq_len,"Indicator must be clear in VarBind");
		pt = proto_item_add_subtree(pi,ett_decoding_error);
		expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "VarBind has indicator set");
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	/* then we have the ObjectName's header */

	offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
	name_offset = offset = get_ber_length(tvb, offset, &name_len, &ind);

	if (! ( !pc && ber_class==BER_CLASS_UNI && tag==BER_UNI_TAG_OID) ) {
		proto_item* pi = proto_tree_add_text(tree, tvb, seq_offset, seq_len,"ObjectName must be an OID in primitive encoding");
		pt = proto_item_add_subtree(pi,ett_decoding_error);
		expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "ObjectName not an OID");
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	if (ind) {
		proto_item* pi = proto_tree_add_text(tree, tvb, seq_offset, seq_len,"Indicator must be clear in ObjectName");
		pt = proto_item_add_subtree(pi,ett_decoding_error);
		expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "ObjectName has indicator set");
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	offset += name_len;
	value_start = offset;

	/* then we have the  value's header */
	offset = get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
	value_offset = get_ber_length(tvb, offset, &value_len, &ind);

	if (! (!pc) ) {
		proto_item* pi = proto_tree_add_text(tree, tvb, seq_offset, seq_len,"the value must be in primitive encoding");
		pt = proto_item_add_subtree(pi,ett_decoding_error);
		expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "value not in primitive encoding");
		return dissect_unknown_ber(actx->pinfo, tvb, seq_offset, pt);
	}

	/* Now, we know where everithing is */



	/* we add the varbind tree root with a dummy label we'll fill later on */
	pi_varbind = proto_tree_add_text(tree,tvb,seq_offset,seq_len,"VarBind");
	pt_varbind = proto_item_add_subtree(pi_varbind,ett_varbind);
	*label = '\0';

	pi_name = proto_tree_add_item(pt_varbind,hf_snmp_objectname,tvb,name_offset,name_len,ENC_NA);
	pt_name = proto_item_add_subtree(pi_name,ett_name);

	/* fetch ObjectName and its relative oid_info */
	oid_bytes = ep_tvb_memdup(tvb, name_offset, name_len);
	oid_info = oid_get_from_encoded(oid_bytes, name_len, &subids, &oid_matched, &oid_left);

	add_oid_debug_subtree(oid_info,pt_name);

	if (!subids) {
		proto_item* pi;

		repr = oid_encoded2string(oid_bytes, name_len);
		pi = proto_tree_add_text(pt_name,tvb, 0, 0, "invalid oid: %s", repr);
		pt = proto_item_add_subtree(pi, ett_decoding_error);
		expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "invalid oid: %s", repr);
		return dissect_unknown_ber(actx->pinfo, tvb, name_offset, pt);
	}

	if (oid_matched+oid_left) {
		oid_string = oid_subid2string(subids,oid_matched+oid_left);
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
				pi = proto_tree_add_text(pt_varbind,tvb,0,0,"Wrong tag for Error Value: expected 0, 1, or 2 but got: %d",tag);
				pt = proto_item_add_subtree(pi,ett_decoding_error);
				expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "Wrong tag for SNMP VarBind error value");
				return dissect_unknown_ber(actx->pinfo, tvb, value_start, pt);
			}
		}

		pi = proto_tree_add_item(pt_varbind,hfid,tvb,value_offset,value_len,ENC_BIG_ENDIAN);
		expert_add_info_format(actx->pinfo, pi, PI_RESPONSE_CODE, PI_NOTE, "%s",note);
		g_strlcpy (label, note, ITEM_LABEL_LENGTH);
		goto set_label;
	}

	/* now we'll try to figure out which are the indexing sub-oids and whether the oid we know about is the one oid we have to use */
	switch (oid_info->kind) {
		case OID_KIND_SCALAR:
			if (oid_left  == 1) {
				/* OK: we got the instance sub-id */
				proto_tree_add_uint64(pt_name,hf_snmp_scalar_instance_index,tvb,name_offset,name_len,subids[oid_matched]);
				oid_info_is_ok = TRUE;
				goto indexing_done;
			} else if (oid_left  == 0) {
				if (ber_class == BER_CLASS_UNI && tag == BER_UNI_TAG_NULL) {
					/* unSpecified  does not require an instance sub-id add the new value and get off the way! */
					pi_value = proto_tree_add_item(pt_varbind,hf_snmp_unSpecified,tvb,value_offset,value_len,ENC_NA);
					goto set_label;
				} else {
					proto_item* pi = proto_tree_add_text(pt_name,tvb,0,0,"A scalar should have one instance sub-id this one has none");
					expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "No instance sub-id in scalar value");
					oid_info_is_ok = FALSE;
					goto indexing_done;
				}
			} else {
				proto_item* pi = proto_tree_add_text(pt_name,tvb,0,0,"A scalar should have only one instance sub-id this has: %d",oid_left);
				expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "Wrong number of instance sub-ids in scalar value");
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
							proto_item* pi = proto_tree_add_text(pt_name,tvb,0,0,"index sub-oid shorter than expected");
							expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "index sub-oid shorter than expected");
							oid_info_is_ok = FALSE;
							goto indexing_done;
						}

						switch(k->key_type) {
							case OID_KEY_TYPE_WRONG: {
								proto_item* pi = proto_tree_add_text(pt_name,tvb,0,0,"OID instaces not handled, if you want this implemented please contact the wireshark developers");
								expert_add_info_format(actx->pinfo, pi, PI_UNDECODED, PI_WARN, "Unimplemented instance index");
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
									proto_item* pi = proto_tree_add_text(pt_name,tvb,0,0,"an index sub-oid OID cannot be 0 bytes long!");
									expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "index sub-oid OID with len=0");
									oid_info_is_ok = FALSE;
									goto indexing_done;
								}

								if( key_len < suboid_len ) {
									proto_item* pi = proto_tree_add_text(pt_name,tvb,0,0,"index sub-oid should not be longer than remaining oid size");
									expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "index sub-oid longer than remaining oid size");
									oid_info_is_ok = FALSE;
									goto indexing_done;
								}

								suboid_buf_len = oid_subid2encoded(suboid_len, suboid, &suboid_buf);

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
									proto_item* pi = proto_tree_add_text(pt_name,tvb,0,0,"index string should not be longer than remaining oid size");
									expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "index string longer than remaining oid size");
									oid_info_is_ok = FALSE;
									goto indexing_done;
								}

								buf = ep_alloc(buf_len+1);
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
										guint32* ipv4_p = (void*)buf;
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
					proto_item* pi = proto_tree_add_text(pt_name,tvb,0,0,"We do not know how to handle this OID, if you want this implemented please contact the wireshark developers");
					expert_add_info_format(actx->pinfo, pi, PI_UNDECODED, PI_WARN, "Unimplemented instance index");
					oid_info_is_ok = FALSE;
					goto indexing_done;
				}
			} else {
				proto_item* pi = proto_tree_add_text(pt_name,tvb,0,0,"The COLUMS's parent is not a ROW. This is a BUG! please contact the wireshark developers.");
				expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_ERROR, "COLUMS's parent is not a ROW");
				oid_info_is_ok = FALSE;
				goto indexing_done;
			}
		default: {
/*			proto_item* pi = proto_tree_add_text(pt_name,tvb,0,0,"This kind OID should have no value");
			expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "This kind OID should have no value"); */
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
				min_len  = oid_info->value_type->min_len;

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
				unsigned int_val_offset = value_offset;
				unsigned i;

				max_len = 5; min_len = 1;
				if (value_len > (guint)max_len && value_len < (guint)min_len) {
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
				proto_tree_add_int64(pt_varbind, hf_snmp_integer32_value, tvb,value_offset,value_len, val);

				goto already_added;
			}
			case BER_CLASS_UNI|(BER_UNI_TAG_OCTETSTRING<<4):
				hfid = hf_snmp_octetstring_value;
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

		pi_value = proto_tree_add_item(pt_varbind,hfid,tvb,value_offset,value_len,ENC_BIG_ENDIAN);
		if (format_error != BER_NO_ERROR) {
			expert_add_info_format(actx->pinfo, pi_value, PI_UNDECODED, PI_NOTE, "Unresolved value, Missing MIB");
		}

already_added:
		oid_info_is_ok = FALSE;
	}

	pt_value = proto_item_add_subtree(pi_value,ett_value);

	if (value_len > 0 && oid_string) {
		tvbuff_t* sub_tvb = tvb_new_subset(tvb, value_offset, value_len, value_len);

		next_tvb_add_string(&var_list, sub_tvb, (snmp_var_in_tree) ? pt_value : NULL, value_sub_dissectors_table, oid_string);
	}


set_label:
	if (pi_value) proto_item_fill_label(PITEM_FINFO(pi_value), label);

	if (oid_info && oid_info->name) {
		if (oid_left >= 1) {
			repr  = ep_strdup_printf("%s.%s (%s)", oid_info->name,
						 oid_subid2string(&(subids[oid_matched]),oid_left),
						 oid_subid2string(subids,oid_matched+oid_left));
			info_oid = ep_strdup_printf("%s.%s", oid_info->name,
						    oid_subid2string(&(subids[oid_matched]),oid_left));
		} else {
			repr  = ep_strdup_printf("%s (%s)", oid_info->name,
						 oid_subid2string(subids,oid_matched));
			info_oid = oid_info->name;
		}
	} else if (oid_string) {
		repr  = ep_strdup(oid_string);
		info_oid = oid_string;
	} else {
		repr  = ep_strdup("[Bad OID]");
	}

	valstr = strstr(label,": ");
	valstr = valstr ? valstr+2 : label;

	proto_item_set_text(pi_varbind,"%s: %s",repr,valstr);

	if (display_oid && info_oid) {
	  col_append_fstr (actx->pinfo->cinfo, COL_INFO, " %s", info_oid);
	}

	switch (format_error) {
		case BER_WRONG_LENGTH: {
			proto_tree* pt = proto_item_add_subtree(pi_value,ett_decoding_error);
			proto_item* pi = proto_tree_add_text(pt,tvb,0,0,"Wrong value length: %u  expecting: %u <= len <= %u",
							     value_len, min_len, max_len == -1 ? 0xFFFFFF : max_len);
			pt = proto_item_add_subtree(pi,ett_decoding_error);
			expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "Wrong length for SNMP VarBind/value");
			return dissect_unknown_ber(actx->pinfo, tvb, value_start, pt);
		}
		case BER_WRONG_TAG: {
			proto_tree* pt = proto_item_add_subtree(pi_value,ett_decoding_error);
			proto_item* pi = proto_tree_add_text(pt,tvb,0,0,"Wrong class/tag for Value expected: %d,%d got: %d,%d",
							     oid_info->value_type->ber_class, oid_info->value_type->ber_tag,
							     ber_class, tag);
			pt = proto_item_add_subtree(pi,ett_decoding_error);
			expert_add_info_format(actx->pinfo, pi, PI_MALFORMED, PI_WARN, "Wrong class/tag for SNMP VarBind/value");
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
	{ 0,   	NULL }
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
dissect_snmp_engineid(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
    proto_item *item = NULL;
    guint8 conformance, format;
    guint32 enterpriseid, seconds;
    nstime_t ts;
    int len_remain = len;

    /* first bit: engine id conformance */
    if (len_remain<4) return offset;
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
	proto_tree_add_text(tree, tvb, offset, 8, "AgentID Trailer: 0x%s",
			    tvb_bytes_to_str(tvb, offset, 8));
	offset+=8;
	len_remain-=8;
      } else {
	proto_tree_add_text(tree, tvb, offset, len_remain, "<Data not conforming to RFC1910>");
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
	  proto_tree_add_item(tree, hf_snmp_engineid_text, tvb, offset, len_remain, ENC_ASCII|ENC_NA);
	  offset+=len_remain;
	  len_remain=0;
	}
	break;
      case 128:
	/* most common enterprise-specific format: (ucd|net)-snmp random */
	if ((enterpriseid==2021)||(enterpriseid==8072)) {
	  proto_item_append_text(item, (enterpriseid==2021) ? ": UCD-SNMP Random" : ": Net-SNMP Random");
	  /* demystify: 4B random, 4B epoch seconds */
	  if (len_remain==8) {
	    proto_tree_add_item(tree, hf_snmp_engineid_data, tvb, offset, 4, ENC_NA);
	    seconds = tvb_get_letohl(tvb, offset+4);
	    ts.secs = seconds;
	    ts.nsecs = 0;
	    proto_tree_add_time_format_value(tree, hf_snmp_engineid_time, tvb, offset+4, 4,
					     &ts, "%s",
					     abs_time_secs_to_str(seconds, ABSOLUTE_TIME_LOCAL, TRUE));
	    offset+=8;
	    len_remain=0;
	  }
	}
	break;
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
      proto_tree_add_text(tree, tvb, offset, len_remain, "<Data not conforming to RFC3411>");
      offset+=len_remain;
    }
    return offset;
}


static void set_ue_keys(snmp_ue_assoc_t* n ) {
	guint key_size = n->user.authModel->key_size;

	n->user.authKey.data = se_alloc(key_size);
	n->user.authKey.len = key_size;
	n->user.authModel->pass2key(n->user.authPassword.data,
				    n->user.authPassword.len,
				    n->engine.data,
				    n->engine.len,
				    n->user.authKey.data);

	n->user.privKey.data = se_alloc(key_size);
	n->user.privKey.len = key_size;
	n->user.authModel->pass2key(n->user.privPassword.data,
				    n->user.privPassword.len,
				    n->engine.data,
				    n->engine.len,
				    n->user.privKey.data);
}

static snmp_ue_assoc_t*
ue_se_dup(snmp_ue_assoc_t* o)
{
	snmp_ue_assoc_t* d = se_memdup(o,sizeof(snmp_ue_assoc_t));

	d->user.authModel = o->user.authModel;

	d->user.privProtocol = o->user.privProtocol;

	d->user.userName.data = se_memdup(o->user.userName.data,o->user.userName.len);
	d->user.userName.len = o->user.userName.len;

	d->user.authPassword.data = o->user.authPassword.data ? se_memdup(o->user.authPassword.data,o->user.authPassword.len) : NULL;
	d->user.authPassword.len = o->user.authPassword.len;

	d->user.privPassword.data = o->user.privPassword.data ? se_memdup(o->user.privPassword.data,o->user.privPassword.len) : NULL;
	d->user.privPassword.len = o->user.privPassword.len;

	d->engine.len = o->engine.len;

	if (d->engine.len) {
		d->engine.data = se_memdup(o->engine.data,o->engine.len);
		set_ue_keys(d);
	}

	return d;

}


#define CACHE_INSERT(c,a) if (c) { snmp_ue_assoc_t* t = c; c = a; c->next = t; } else { c = a; a->next = NULL; }

static void
renew_ue_cache(void)
{
	localized_ues = NULL;
	unlocalized_ues = NULL;

	if (num_ueas) {
		guint i;

		for(i = 0; i < num_ueas; i++) {
			snmp_ue_assoc_t* a = ue_se_dup(&(ueas[i]));

			if (a->engine.len) {
				CACHE_INSERT(localized_ues,a);

			} else {
				CACHE_INSERT(unlocalized_ues,a);
			}

		}
	}
}


static snmp_ue_assoc_t*
localize_ue( snmp_ue_assoc_t* o, const guint8* engine, guint engine_len )
{
	snmp_ue_assoc_t* n = se_memdup(o,sizeof(snmp_ue_assoc_t));

	n->engine.data = se_memdup(engine,engine_len);
	n->engine.len = engine_len;

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
get_user_assoc(tvbuff_t* engine_tvb, tvbuff_t* user_tvb)
{
	static snmp_ue_assoc_t* a;
	guint given_username_len;
	guint8* given_username;
	guint given_engine_len;
	guint8* given_engine;

	if ( ! (localized_ues || unlocalized_ues ) ) return NULL;

	if (! ( user_tvb && engine_tvb ) ) return NULL;

	given_username_len = tvb_ensure_length_remaining(user_tvb,0);
	given_username = ep_tvb_memdup(user_tvb,0,-1);
	given_engine_len = tvb_ensure_length_remaining(engine_tvb,0);
	given_engine = ep_tvb_memdup(engine_tvb,0,-1);

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
snmp_usm_auth_md5(snmp_usm_params_t* p, guint8** calc_auth_p, guint* calc_auth_len_p, gchar const** error)
{
	guint msg_len;
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


	auth_len = tvb_length_remaining(p->auth_tvb,0);

	if (auth_len != 12) {
		*error = "Authenticator length wrong";
		return FALSE;
	}

	msg_len = tvb_length_remaining(p->msg_tvb,0);
	msg = ep_tvb_memdup(p->msg_tvb,0,msg_len);


	auth = ep_tvb_memdup(p->auth_tvb,0,auth_len);

	start = p->auth_offset - p->start_offset;
	end = 	start + auth_len;

	/* fill the authenticator with zeros */
	for ( i = start ; i < end ; i++ ) {
		msg[i] = '\0';
	}

	calc_auth = ep_alloc(16);

	md5_hmac(msg, msg_len, key, key_len, calc_auth);

	if (calc_auth_p) *calc_auth_p = calc_auth;
	if (calc_auth_len_p) *calc_auth_len_p = 12;

	return ( memcmp(auth,calc_auth,12) != 0 ) ? FALSE : TRUE;
}


static gboolean
snmp_usm_auth_sha1(snmp_usm_params_t* p _U_, guint8** calc_auth_p, guint* calc_auth_len_p,  gchar const** error _U_)
{
	guint msg_len;
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


	auth_len = tvb_length_remaining(p->auth_tvb,0);


	if (auth_len != 12) {
		*error = "Authenticator length wrong";
		return FALSE;
	}

	msg_len = tvb_length_remaining(p->msg_tvb,0);
	msg = ep_tvb_memdup(p->msg_tvb,0,msg_len);

	auth = ep_tvb_memdup(p->auth_tvb,0,auth_len);

	start = p->auth_offset - p->start_offset;
	end = 	start + auth_len;

	/* fill the authenticator with zeros */
	for ( i = start ; i < end ; i++ ) {
		msg[i] = '\0';
	}

	calc_auth = ep_alloc(20);

	sha1_hmac(key, key_len, msg, msg_len, calc_auth);

	if (calc_auth_p) *calc_auth_p = calc_auth;
	if (calc_auth_len_p) *calc_auth_len_p = 12;

	return ( memcmp(auth,calc_auth,12) != 0 ) ? FALSE : TRUE;
}

static tvbuff_t*
snmp_usm_priv_des(snmp_usm_params_t* p _U_, tvbuff_t* encryptedData _U_, gchar const** error _U_)
{
#ifdef HAVE_LIBGCRYPT
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


	salt_len = tvb_length_remaining(p->priv_tvb,0);

	if (salt_len != 8)  {
		*error = "decryptionError: msgPrivacyParameters length != 8";
		return NULL;
	}

	salt = ep_tvb_memdup(p->priv_tvb,0,salt_len);

	/*
	 The resulting "salt" is XOR-ed with the pre-IV to obtain the IV.
	 */
	for (i=0; i<8; i++) {
		iv[i] = pre_iv[i] ^ salt[i];
	}

	cryptgrm_len = tvb_length_remaining(encryptedData,0);

	if (cryptgrm_len % 8) {
		*error = "decryptionError: the length of the encrypted data is not a mutiple of 8 octets";
		return NULL;
	}

	cryptgrm = ep_tvb_memdup(encryptedData,0,-1);

	cleartext = ep_alloc(cryptgrm_len);

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
	*error = (void*)gpg_strerror(err);
	if (hd) gcry_cipher_close(hd);
	return NULL;
#else
	*error = "libgcrypt not present, cannot decrypt";
	return NULL;
#endif
}

static tvbuff_t*
snmp_usm_priv_aes(snmp_usm_params_t* p _U_, tvbuff_t* encryptedData _U_, gchar const** error _U_)
{
#ifdef HAVE_LIBGCRYPT
	gcry_error_t err;
	gcry_cipher_hd_t hd = NULL;

	guint8* cleartext;
	guint8* aes_key = p->user_assoc->user.privKey.data; /* first 16 bytes */
	guint8 iv[16];
	gint priv_len;
	gint cryptgrm_len;
	guint8* cryptgrm;
	tvbuff_t* clear_tvb;

	priv_len = tvb_length_remaining(p->priv_tvb,0);

	if (priv_len != 8)  {
		*error = "decryptionError: msgPrivacyParameters length != 8";
		return NULL;
	}

	iv[0] = (p->boots & 0xff000000) >> 24;
	iv[1] = (p->boots & 0x00ff0000) >> 16;
	iv[2] = (p->boots & 0x0000ff00) >> 8;
	iv[3] = (p->boots & 0x000000ff);
	iv[4] = (p->time & 0xff000000) >> 24;
	iv[5] = (p->time & 0x00ff0000) >> 16;
	iv[6] = (p->time & 0x0000ff00) >> 8;
	iv[7] = (p->time & 0x000000ff);
	tvb_memcpy(p->priv_tvb,&(iv[8]),0,8);

	cryptgrm_len = tvb_length_remaining(encryptedData,0);
	cryptgrm = ep_tvb_memdup(encryptedData,0,-1);

	cleartext = ep_alloc(cryptgrm_len);

	err = gcry_cipher_open(&hd, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CFB, 0);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_setiv(hd, iv, 16);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_setkey(hd,aes_key,16);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	err = gcry_cipher_decrypt(hd, cleartext, cryptgrm_len, cryptgrm, cryptgrm_len);
	if (err != GPG_ERR_NO_ERROR) goto on_gcry_error;

	gcry_cipher_close(hd);

	clear_tvb = tvb_new_child_real_data(encryptedData, cleartext, cryptgrm_len, cryptgrm_len);

	return clear_tvb;

on_gcry_error:
	*error = (void*)gpg_strerror(err);
	if (hd) gcry_cipher_close(hd);
	return NULL;
#else
	*error = "libgcrypt not present, cannot decrypt";
	return NULL;
#endif
}


gboolean
check_ScopedPdu(tvbuff_t* tvb)
{
	int offset;
	gint8 class;
	gboolean pc;
	gint32 tag;
	int hoffset, eoffset;
	guint32 len;

	offset = get_ber_identifier(tvb, 0, &class, &pc, &tag);
	offset = get_ber_length(tvb, offset, NULL, NULL);

	if ( ! (((class!=BER_CLASS_APP) && (class!=BER_CLASS_PRI) )
			&& ( (!pc) || (class!=BER_CLASS_UNI) || (tag!=BER_UNI_TAG_ENUMERATED) )
			)) return FALSE;

	if((tvb_get_guint8(tvb, offset)==0)&&(tvb_get_guint8(tvb, offset+1)==0))
		return TRUE;

	hoffset = offset;

	offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
	offset = get_ber_length(tvb, offset, &len, NULL);
	eoffset = offset + len;

	if (eoffset <= hoffset) return FALSE;

	if ((class!=BER_CLASS_APP)&&(class!=BER_CLASS_PRI))
		if( (class!=BER_CLASS_UNI)
			||((tag<BER_UNI_TAG_NumericString)&&(tag!=BER_UNI_TAG_OCTETSTRING)&&(tag!=BER_UNI_TAG_UTF8String)) )
			return FALSE;

	return TRUE;

}


/*--- Included file: packet-snmp-fn.c ---*/
#line 1 "../../asn1/snmp/packet-snmp-fn.c"



static int
dissect_snmp_EnterpriseOID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 64 "../../asn1/snmp/snmp.cnf"
  const gchar* name;

  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &enterprise_oid);


  if (display_oid && enterprise_oid) {
    name = oid_resolved_from_string(enterprise_oid);
    if (name) {
      col_append_fstr (actx->pinfo->cinfo, COL_INFO, " %s", name);
    }
  }



  return offset;
}



static int
dissect_snmp_OCTET_STRING_SIZE_4(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_snmp_NetworkAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_snmp_OCTET_STRING_SIZE_4);

  return offset;
}



static int
dissect_snmp_INTEGER_0_4294967295(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_TimeTicks(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, TRUE, dissect_snmp_INTEGER_0_4294967295);

  return offset;
}



static int
dissect_snmp_Integer32(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_ObjectName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string snmp_Version_vals[] = {
  {   0, "version-1" },
  {   1, "v2c" },
  {   2, "v2u" },
  {   3, "snmpv3" },
  { 0, NULL }
};


static int
dissect_snmp_Version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_Community(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_snmp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string snmp_T_error_status_vals[] = {
  {   0, "noError" },
  {   1, "tooBig" },
  {   2, "noSuchName" },
  {   3, "badValue" },
  {   4, "readOnly" },
  {   5, "genErr" },
  {   6, "noAccess" },
  {   7, "wrongType" },
  {   8, "wrongLength" },
  {   9, "wrongEncoding" },
  {  10, "wrongValue" },
  {  11, "noCreation" },
  {  12, "inconsistentValue" },
  {  13, "resourceUnavailable" },
  {  14, "commitFailed" },
  {  15, "undoFailed" },
  {  16, "authorizationError" },
  {  17, "notWritable" },
  {  18, "inconsistentName" },
  { 0, NULL }
};


static int
dissect_snmp_T_error_status(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static const ber_sequence_t VarBindList_sequence_of[1] = {
  { &hf_snmp_VarBindList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_VarBind },
};

static int
dissect_snmp_VarBindList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      VarBindList_sequence_of, hf_index, ett_snmp_VarBindList);

  return offset;
}


static const ber_sequence_t PDU_sequence[] = {
  { &hf_snmp_request_id     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER },
  { &hf_snmp_error_status   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_error_status },
  { &hf_snmp_error_index    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER },
  { &hf_snmp_variable_bindings, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_VarBindList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PDU_sequence, hf_index, ett_snmp_PDU);

  return offset;
}



static int
dissect_snmp_GetRequest_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 0, TRUE, dissect_snmp_PDU);

  return offset;
}



static int
dissect_snmp_GetNextRequest_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 1, TRUE, dissect_snmp_PDU);

  return offset;
}



static int
dissect_snmp_GetResponse_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 2, TRUE, dissect_snmp_PDU);

  return offset;
}



static int
dissect_snmp_SetRequest_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 3, TRUE, dissect_snmp_PDU);

  return offset;
}


static const value_string snmp_GenericTrap_vals[] = {
  {   0, "coldStart" },
  {   1, "warmStart" },
  {   2, "linkDown" },
  {   3, "linkUp" },
  {   4, "authenticationFailure" },
  {   5, "egpNeighborLoss" },
  {   6, "enterpriseSpecific" },
  { 0, NULL }
};


static int
dissect_snmp_GenericTrap(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &generic_trap);

  return offset;
}



static int
dissect_snmp_SpecificTrap(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 48 "../../asn1/snmp/snmp.cnf"
  guint specific_trap;
  
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &specific_trap);


  if (generic_trap == 6) { /* enterprise specific */
    const gchar *specific_str = snmp_lookup_specific_trap (specific_trap);
    if (specific_str) {
      proto_item_append_text(actx->created_item, " (%s)", specific_str);
    }
  }


  return offset;
}


static const ber_sequence_t Trap_PDU_U_sequence[] = {
  { &hf_snmp_enterprise     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_snmp_EnterpriseOID },
  { &hf_snmp_agent_addr     , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_snmp_NetworkAddress },
  { &hf_snmp_generic_trap   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_GenericTrap },
  { &hf_snmp_specific_trap  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_SpecificTrap },
  { &hf_snmp_time_stamp     , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_snmp_TimeTicks },
  { &hf_snmp_variable_bindings, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_VarBindList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_Trap_PDU_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 40 "../../asn1/snmp/snmp.cnf"
  generic_trap = 0;
  enterprise_oid = NULL;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Trap_PDU_U_sequence, hf_index, ett_snmp_Trap_PDU_U);




  return offset;
}



static int
dissect_snmp_Trap_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 4, TRUE, dissect_snmp_Trap_PDU_U);

  return offset;
}



static int
dissect_snmp_INTEGER_0_2147483647(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t BulkPDU_sequence[] = {
  { &hf_snmp_bulkPDU_request_id, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_Integer32 },
  { &hf_snmp_non_repeaters  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER_0_2147483647 },
  { &hf_snmp_max_repetitions, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER_0_2147483647 },
  { &hf_snmp_variable_bindings, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_VarBindList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_BulkPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BulkPDU_sequence, hf_index, ett_snmp_BulkPDU);

  return offset;
}



static int
dissect_snmp_GetBulkRequest_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 5, TRUE, dissect_snmp_BulkPDU);

  return offset;
}



static int
dissect_snmp_InformRequest_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 6, TRUE, dissect_snmp_PDU);

  return offset;
}



static int
dissect_snmp_SNMPv2_Trap_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 7, TRUE, dissect_snmp_PDU);

  return offset;
}



static int
dissect_snmp_Report_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 8, TRUE, dissect_snmp_PDU);

  return offset;
}


static const value_string snmp_PDUs_vals[] = {
  {   0, "get-request" },
  {   1, "get-next-request" },
  {   2, "get-response" },
  {   3, "set-request" },
  {   4, "trap" },
  {   5, "getBulkRequest" },
  {   6, "informRequest" },
  {   7, "snmpV2-trap" },
  {   8, "report" },
  { 0, NULL }
};

static const ber_choice_t PDUs_choice[] = {
  {   0, &hf_snmp_get_request    , BER_CLASS_CON, 0, BER_FLAGS_NOOWNTAG, dissect_snmp_GetRequest_PDU },
  {   1, &hf_snmp_get_next_request, BER_CLASS_CON, 1, BER_FLAGS_NOOWNTAG, dissect_snmp_GetNextRequest_PDU },
  {   2, &hf_snmp_get_response   , BER_CLASS_CON, 2, BER_FLAGS_NOOWNTAG, dissect_snmp_GetResponse_PDU },
  {   3, &hf_snmp_set_request    , BER_CLASS_CON, 3, BER_FLAGS_NOOWNTAG, dissect_snmp_SetRequest_PDU },
  {   4, &hf_snmp_trap           , BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_snmp_Trap_PDU },
  {   5, &hf_snmp_getBulkRequest , BER_CLASS_CON, 5, BER_FLAGS_NOOWNTAG, dissect_snmp_GetBulkRequest_PDU },
  {   6, &hf_snmp_informRequest  , BER_CLASS_CON, 6, BER_FLAGS_NOOWNTAG, dissect_snmp_InformRequest_PDU },
  {   7, &hf_snmp_snmpV2_trap    , BER_CLASS_CON, 7, BER_FLAGS_NOOWNTAG, dissect_snmp_SNMPv2_Trap_PDU },
  {   8, &hf_snmp_report         , BER_CLASS_CON, 8, BER_FLAGS_NOOWNTAG, dissect_snmp_Report_PDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_PDUs(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 28 "../../asn1/snmp/snmp.cnf"
gint pdu_type=-1;

  col_clear(actx->pinfo->cinfo, COL_INFO);

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PDUs_choice, hf_index, ett_snmp_PDUs,
                                 &pdu_type);

  if( (pdu_type!=-1) && snmp_PDUs_vals[pdu_type].strptr ){
	col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s", snmp_PDUs_vals[pdu_type].strptr);
  }



  return offset;
}


static const ber_sequence_t Message_sequence[] = {
  { &hf_snmp_version        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_Version },
  { &hf_snmp_community      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_Community },
  { &hf_snmp_data           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_snmp_PDUs },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_Message(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Message_sequence, hf_index, ett_snmp_Message);

  return offset;
}



static int
dissect_snmp_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string snmp_T_datav2u_vals[] = {
  {   0, "plaintext" },
  {   1, "encrypted" },
  { 0, NULL }
};

static const ber_choice_t T_datav2u_choice[] = {
  {   0, &hf_snmp_v2u_plaintext  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_snmp_PDUs },
  {   1, &hf_snmp_encrypted      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_T_datav2u(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_datav2u_choice, hf_index, ett_snmp_T_datav2u,
                                 NULL);

  return offset;
}


static const ber_sequence_t Messagev2u_sequence[] = {
  { &hf_snmp_version        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_Version },
  { &hf_snmp_parameters     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_OCTET_STRING },
  { &hf_snmp_datav2u        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_snmp_T_datav2u },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_Messagev2u(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Messagev2u_sequence, hf_index, ett_snmp_Messagev2u);

  return offset;
}



static int
dissect_snmp_SnmpEngineID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 99 "../../asn1/snmp/snmp.cnf"
	tvbuff_t* param_tvb = NULL;

	offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &param_tvb);
	 if (param_tvb) {
		proto_tree* engine_tree = proto_item_add_subtree(actx->created_item,ett_engineid);
		dissect_snmp_engineid(engine_tree, param_tvb, 0, tvb_length_remaining(param_tvb,0));
	}



  return offset;
}



static int
dissect_snmp_T_msgAuthoritativeEngineID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 90 "../../asn1/snmp/snmp.cnf"

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &usm_p.engine_tvb);
	 if (usm_p.engine_tvb) {
		proto_tree* engine_tree = proto_item_add_subtree(actx->created_item,ett_engineid);
		dissect_snmp_engineid(engine_tree, usm_p.engine_tvb, 0, tvb_length_remaining(usm_p.engine_tvb,0));
	}



  return offset;
}



static int
dissect_snmp_T_msgAuthoritativeEngineBoots(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &usm_p.boots);

  return offset;
}



static int
dissect_snmp_T_msgAuthoritativeEngineTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &usm_p.time);

  return offset;
}



static int
dissect_snmp_T_msgUserName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &usm_p.user_tvb);

  return offset;
}



static int
dissect_snmp_T_msgAuthenticationParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 112 "../../asn1/snmp/snmp.cnf"
	offset = dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &usm_p.auth_tvb);
	if (usm_p.auth_tvb) {
		usm_p.auth_item = actx->created_item;
		usm_p.auth_offset = tvb_offset_from_real_beginning(usm_p.auth_tvb);
	}


  return offset;
}



static int
dissect_snmp_T_msgPrivacyParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &usm_p.priv_tvb);

  return offset;
}


static const ber_sequence_t UsmSecurityParameters_sequence[] = {
  { &hf_snmp_msgAuthoritativeEngineID, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgAuthoritativeEngineID },
  { &hf_snmp_msgAuthoritativeEngineBoots, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgAuthoritativeEngineBoots },
  { &hf_snmp_msgAuthoritativeEngineTime, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgAuthoritativeEngineTime },
  { &hf_snmp_msgUserName    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgUserName },
  { &hf_snmp_msgAuthenticationParameters, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgAuthenticationParameters },
  { &hf_snmp_msgPrivacyParameters, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgPrivacyParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_UsmSecurityParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UsmSecurityParameters_sequence, hf_index, ett_snmp_UsmSecurityParameters);

  return offset;
}



static int
dissect_snmp_INTEGER_484_2147483647(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_T_msgFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 227 "../../asn1/snmp/snmp.cnf"
	tvbuff_t *parameter_tvb = NULL;

   offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

 if (parameter_tvb){
	guint8 v3_flags = tvb_get_guint8(parameter_tvb, 0);
	proto_tree* flags_tree = proto_item_add_subtree(actx->created_item,ett_msgFlags);
	
	proto_tree_add_item(flags_tree, hf_snmp_v3_flags_report, parameter_tvb, 0, 1, FALSE);
	proto_tree_add_item(flags_tree, hf_snmp_v3_flags_crypt, parameter_tvb, 0, 1, FALSE);
	proto_tree_add_item(flags_tree, hf_snmp_v3_flags_auth, parameter_tvb, 0, 1, FALSE);
	
	usm_p.encrypted = v3_flags & TH_CRYPT ? TRUE : FALSE;
	usm_p.authenticated = v3_flags & TH_AUTH ? TRUE : FALSE;
  }




  return offset;
}



static int
dissect_snmp_T_msgSecurityModel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &MsgSecurityModel);

  return offset;
}


static const ber_sequence_t HeaderData_sequence[] = {
  { &hf_snmp_msgID          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER_0_2147483647 },
  { &hf_snmp_msgMaxSize     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER_484_2147483647 },
  { &hf_snmp_msgFlags       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgFlags },
  { &hf_snmp_msgSecurityModel, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgSecurityModel },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_HeaderData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HeaderData_sequence, hf_index, ett_snmp_HeaderData);

  return offset;
}



static int
dissect_snmp_T_msgSecurityParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 170 "../../asn1/snmp/snmp.cnf"

	switch(MsgSecurityModel){
		case SNMP_SEC_USM:	/* 3 */		
			offset = dissect_snmp_UsmSecurityParameters(FALSE, tvb, offset+2, actx, tree, -1);
			usm_p.user_assoc = get_user_assoc(usm_p.engine_tvb, usm_p.user_tvb);
			break;
		case SNMP_SEC_ANY:	/* 0 */
		case SNMP_SEC_V1:	/* 1 */
		case SNMP_SEC_V2C:	/* 2 */
		default:
			  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

			break;
	}



  return offset;
}


static const ber_sequence_t ScopedPDU_sequence[] = {
  { &hf_snmp_contextEngineID, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_SnmpEngineID },
  { &hf_snmp_contextName    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_OCTET_STRING },
  { &hf_snmp_data           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_snmp_PDUs },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_ScopedPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScopedPDU_sequence, hf_index, ett_snmp_ScopedPDU);

  return offset;
}



static int
dissect_snmp_T_encryptedPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 121 "../../asn1/snmp/snmp.cnf"
	tvbuff_t* crypt_tvb;
	offset = dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_snmp_encryptedPDU, &crypt_tvb);

	if( usm_p.encrypted && crypt_tvb
		&& usm_p.user_assoc
		&& usm_p.user_assoc->user.privProtocol ) {
		
		const gchar* error = NULL;
		proto_tree* encryptedpdu_tree = proto_item_add_subtree(actx->created_item,ett_encryptedPDU);
		tvbuff_t* cleartext_tvb = usm_p.user_assoc->user.privProtocol(&usm_p, crypt_tvb, &error );

		if (! cleartext_tvb) {
			proto_item* cause = proto_tree_add_text(encryptedpdu_tree, crypt_tvb, 0, -1,
				"Failed to decrypt encryptedPDU: %s", error);
			
			expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN,
				"Failed to decrypt encryptedPDU: %s", error);

			col_set_str(actx->pinfo->cinfo, COL_INFO, "encryptedPDU: Failed to decrypt");
				
			return offset;
		} else {
			proto_item* decrypted_item;
			proto_tree* decrypted_tree;

			if (! check_ScopedPdu(cleartext_tvb)) {
				proto_item* cause = proto_tree_add_text(encryptedpdu_tree, cleartext_tvb, 0, -1,
											"Decrypted data not formatted as expected, wrong key?");
				
				expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN,
									   "Decrypted data not formatted as expected");

				col_set_str(actx->pinfo->cinfo, COL_INFO, "encryptedPDU: Decrypted data not formatted as expected");
				
				return offset;
			}

			
            add_new_data_source(actx->pinfo, cleartext_tvb, "Decrypted ScopedPDU");
			
			decrypted_item = proto_tree_add_item(encryptedpdu_tree, hf_snmp_decryptedPDU,cleartext_tvb,0,-1,FALSE);
			decrypted_tree = proto_item_add_subtree(decrypted_item,ett_decrypted);
			dissect_snmp_ScopedPDU(FALSE, cleartext_tvb, 0, actx, decrypted_tree, -1);
		 }
	} else {
			col_set_str(actx->pinfo->cinfo, COL_INFO, "encryptedPDU: privKey Unknown");
	}



  return offset;
}


static const value_string snmp_ScopedPduData_vals[] = {
  {   0, "plaintext" },
  {   1, "encryptedPDU" },
  { 0, NULL }
};

static const ber_choice_t ScopedPduData_choice[] = {
  {   0, &hf_snmp_plaintext      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_ScopedPDU },
  {   1, &hf_snmp_encryptedPDU   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_encryptedPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_ScopedPduData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ScopedPduData_choice, hf_index, ett_snmp_ScopedPduData,
                                 NULL);

  return offset;
}


static const ber_sequence_t SNMPv3Message_sequence[] = {
  { &hf_snmp_msgVersion     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_Version },
  { &hf_snmp_msgGlobalData  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_snmp_HeaderData },
  { &hf_snmp_msgSecurityParameters, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_T_msgSecurityParameters },
  { &hf_snmp_msgData        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_snmp_ScopedPduData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_SNMPv3Message(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SNMPv3Message_sequence, hf_index, ett_snmp_SNMPv3Message);

#line 185 "../../asn1/snmp/snmp.cnf"

	if( usm_p.authenticated
		&& usm_p.user_assoc
		&& usm_p.user_assoc->user.authModel ) {
		const gchar* error = NULL;
		proto_item* authen_item;
		proto_tree* authen_tree = proto_item_add_subtree(usm_p.auth_item,ett_authParameters);
		guint8* calc_auth;
		guint calc_auth_len;
		
		usm_p.authOK = usm_p.user_assoc->user.authModel->authenticate( &usm_p, &calc_auth, &calc_auth_len, &error );

		if (error) {
			authen_item = proto_tree_add_text(authen_tree,tvb,0,0,"Error while verifying Message authenticity: %s", error);
			PROTO_ITEM_SET_GENERATED(authen_item);
			expert_add_info_format( actx->pinfo, authen_item, PI_MALFORMED, PI_ERROR, "Error while verifying Message authenticity: %s", error );
		} else {
			int severity;
			gchar* msg;			

			authen_item = proto_tree_add_boolean(authen_tree, hf_snmp_msgAuthentication, tvb, 0, 0, usm_p.authOK);
			PROTO_ITEM_SET_GENERATED(authen_item);
			
			if (usm_p.authOK) {
				msg = "SNMP Authentication OK";
				severity = PI_CHAT;
			} else {
				gchar* calc_auth_str = bytestring_to_str(calc_auth,calc_auth_len,' ');
				proto_item_append_text(authen_item, " calculated = %s", calc_auth_str);
				msg = "SNMP Authentication Error";
				severity = PI_WARN;
			}

			expert_add_info_format( actx->pinfo, authen_item, PI_CHECKSUM, severity, "%s", msg );
		}
	}


  return offset;
}


static const value_string snmp_T_smux_version_vals[] = {
  {   0, "version-1" },
  { 0, NULL }
};


static int
dissect_snmp_T_smux_version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_snmp_DisplayString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SimpleOpen_U_sequence[] = {
  { &hf_snmp_smux_version   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_smux_version },
  { &hf_snmp_identity       , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_snmp_OBJECT_IDENTIFIER },
  { &hf_snmp_description    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_DisplayString },
  { &hf_snmp_password       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_snmp_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_SimpleOpen_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SimpleOpen_U_sequence, hf_index, ett_snmp_SimpleOpen_U);

  return offset;
}



static int
dissect_snmp_SimpleOpen(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_snmp_SimpleOpen_U);

  return offset;
}


static const value_string snmp_OpenPDU_vals[] = {
  {   0, "smux-simple" },
  { 0, NULL }
};

static const ber_choice_t OpenPDU_choice[] = {
  {   0, &hf_snmp_smux_simple    , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_snmp_SimpleOpen },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_OpenPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OpenPDU_choice, hf_index, ett_snmp_OpenPDU,
                                 NULL);

  return offset;
}


static const value_string snmp_ClosePDU_U_vals[] = {
  {   0, "goingDown" },
  {   1, "unsupportedVersion" },
  {   2, "packetFormat" },
  {   3, "protocolError" },
  {   4, "internalError" },
  {   5, "authenticationFailure" },
  { 0, NULL }
};


static int
dissect_snmp_ClosePDU_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_ClosePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, TRUE, dissect_snmp_ClosePDU_U);

  return offset;
}



static int
dissect_snmp_INTEGER_M1_2147483647(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string snmp_T_operation_vals[] = {
  {   0, "delete" },
  {   1, "readOnly" },
  {   2, "readWrite" },
  { 0, NULL }
};


static int
dissect_snmp_T_operation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RReqPDU_U_sequence[] = {
  { &hf_snmp_subtree        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_snmp_ObjectName },
  { &hf_snmp_priority       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_INTEGER_M1_2147483647 },
  { &hf_snmp_operation      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_snmp_T_operation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_RReqPDU_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RReqPDU_U_sequence, hf_index, ett_snmp_RReqPDU_U);

  return offset;
}



static int
dissect_snmp_RReqPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, TRUE, dissect_snmp_RReqPDU_U);

  return offset;
}


static const value_string snmp_RRspPDU_U_vals[] = {
  {  -1, "failure" },
  { 0, NULL }
};


static int
dissect_snmp_RRspPDU_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_RRspPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, TRUE, dissect_snmp_RRspPDU_U);

  return offset;
}


static const value_string snmp_RegisterResponse_vals[] = {
  {   0, "rRspPDU" },
  {   1, "pDUs" },
  { 0, NULL }
};

static const ber_choice_t RegisterResponse_choice[] = {
  {   0, &hf_snmp_rRspPDU        , BER_CLASS_APP, 3, BER_FLAGS_NOOWNTAG, dissect_snmp_RRspPDU },
  {   1, &hf_snmp_pDUs           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_snmp_PDUs },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_RegisterResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RegisterResponse_choice, hf_index, ett_snmp_RegisterResponse,
                                 NULL);

  return offset;
}


static const value_string snmp_SOutPDU_U_vals[] = {
  {   0, "commit" },
  {   1, "rollback" },
  { 0, NULL }
};


static int
dissect_snmp_SOutPDU_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_snmp_SOutPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 4, TRUE, dissect_snmp_SOutPDU_U);

  return offset;
}


static const value_string snmp_SMUX_PDUs_vals[] = {
  {   0, "open" },
  {   1, "close" },
  {   2, "registerRequest" },
  {   3, "registerResponse" },
  {   4, "commitOrRollback" },
  { 0, NULL }
};

static const ber_choice_t SMUX_PDUs_choice[] = {
  {   0, &hf_snmp_open           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_snmp_OpenPDU },
  {   1, &hf_snmp_close          , BER_CLASS_APP, 1, BER_FLAGS_NOOWNTAG, dissect_snmp_ClosePDU },
  {   2, &hf_snmp_registerRequest, BER_CLASS_APP, 2, BER_FLAGS_NOOWNTAG, dissect_snmp_RReqPDU },
  {   3, &hf_snmp_registerResponse, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_snmp_RegisterResponse },
  {   4, &hf_snmp_commitOrRollback, BER_CLASS_APP, 4, BER_FLAGS_NOOWNTAG, dissect_snmp_SOutPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_snmp_SMUX_PDUs(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SMUX_PDUs_choice, hf_index, ett_snmp_SMUX_PDUs,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_SMUX_PDUs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_snmp_SMUX_PDUs(FALSE, tvb, 0, &asn1_ctx, tree, hf_snmp_SMUX_PDUs_PDU);
}


/*--- End of included file: packet-snmp-fn.c ---*/
#line 1496 "../../asn1/snmp/packet-snmp-template.c"


guint
dissect_snmp_pdu(tvbuff_t *tvb, int offset, packet_info *pinfo,
		 proto_tree *tree, int proto, gint ett, gboolean is_tcp)
{

	guint length_remaining;
	gint8 class;
	gboolean pc, ind = 0;
	gint32 tag;
	guint32 len;
	guint message_length;
	int start_offset = offset;
	guint32 version = 0;
	tvbuff_t	*next_tvb;

	proto_tree *snmp_tree = NULL;
	proto_item *item = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);


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
	usm_p.time = 0;
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
	length_remaining = tvb_ensure_length_remaining(tvb, offset);

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

			/*
			 * Return 0, which means "I didn't dissect anything
			 * because I don't have enough data - we need
			 * to desegment".
			 */
			return 0;
		}
	}

	/*
	 * OK, try to read the "Sequence Of" header; this gets the total
	 * length of the SNMP message.
	 */
	/* Set tree to 0 to not display internal BER fields if option used.*/
	offset = dissect_ber_identifier(pinfo, 0, tvb, offset, &class, &pc, &tag);
	/*Get the total octet length of the SNMP data*/
	offset = dissect_ber_length(pinfo, 0, tvb, offset, &len, &ind);
	message_length = len + 2;

	/*Get the SNMP version data*/
	offset = dissect_ber_integer(FALSE, &asn1_ctx, 0, tvb, offset, -1, &version);


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

	next_tvb_init(&var_list);

	col_set_str(pinfo->cinfo, COL_PROTOCOL,
	    proto_get_protocol_short_name(find_protocol_by_id(proto)));

	if (tree) {
		item = proto_tree_add_item(tree, proto, tvb, start_offset,
				           message_length, ENC_BIG_ENDIAN);
		snmp_tree = proto_item_add_subtree(item, ett);
	}

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
		proto_tree_add_text(snmp_tree, tvb, offset, -1,"Unknown version");
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
		next_tvb_call(&var_list, pinfo, tree, NULL, data_handle);
	}

	return offset;
}

static gint
dissect_snmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	conversation_t  *conversation;
	int offset;
	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;
	guint32 tmp_length;
	gboolean tmp_ind;

	/*
	 * See if this looks like SNMP or not. if not, return 0 so
	 * wireshark can try som other dissector instead.
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
	 * Losen the heuristic a bit to handle the case where data has intentionally
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
	if (pinfo->destport == UDP_PORT_SNMP) {
	  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
					   pinfo->srcport, 0, NO_PORT_B);
	  if( (conversation == NULL) || (conversation->dissector_handle!=snmp_handle) ) {
	    conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
					    pinfo->srcport, 0, NO_PORT2);
	    conversation_set_dissector(conversation, snmp_handle);
	  }
	}

	return dissect_snmp_pdu(tvb, 0, pinfo, tree, proto_snmp, ett_snmp, FALSE);
}

static void
dissect_snmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint message_len;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		message_len = dissect_snmp_pdu(tvb, 0, pinfo, tree,
					       proto_snmp, ett_snmp, TRUE);
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
}

static void
dissect_smux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *smux_tree = NULL;
	proto_item *item = NULL;

	next_tvb_init(&var_list);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMUX");

	if (tree) {
		item = proto_tree_add_item(tree, proto_smux, tvb, 0, -1, ENC_NA);
		smux_tree = proto_item_add_subtree(item, ett_smux);
	}

	dissect_SMUX_PDUs_PDU(tvb, pinfo, smux_tree);
}


/*
  MD5 Password to Key Algorithm
  from RFC 3414 A.2.1
*/
static void
snmp_usm_password_to_key_md5(const guint8 *password, guint passwordlen,
			     const guint8 *engineID, guint   engineLength,
			     guint8 *key)
{
	md5_state_t     MD;
	guint8     *cp, password_buf[64];
	guint32      password_index = 0;
	guint32      count = 0, i;
	guint8		key1[16];
	md5_init(&MD);   /* initialize MD5 */

	/**********************************************/
	/* Use while loop until we've done 1 Megabyte */
	/**********************************************/
	while (count < 1048576) {
		cp = password_buf;
		for (i = 0; i < 64; i++) {
			/*************************************************/
			/* Take the next octet of the password, wrapping */
			/* to the beginning of the password as necessary.*/
			/*************************************************/
			*cp++ = password[password_index++ % passwordlen];
		}
		md5_append(&MD, password_buf, 64);
		count += 64;
	}
	md5_finish(&MD, key1);          /* tell MD5 we're done */

	/*****************************************************/
	/* Now localize the key with the engineID and pass   */
	/* through MD5 to produce final key                  */
	/* We ignore invalid engineLengths here. More strict */
	/* checking is done in snmp_users_update_cb.         */
	/*****************************************************/

	md5_init(&MD);
	md5_append(&MD, key1, 16);
	md5_append(&MD, engineID, engineLength);
	md5_append(&MD, key1, 16);
	md5_finish(&MD, key);

	return;
}




/*
   SHA1 Password to Key Algorithm COPIED from RFC 3414 A.2.2
 */

static void
snmp_usm_password_to_key_sha1(const guint8 *password, guint passwordlen,
			      const guint8 *engineID, guint engineLength,
			      guint8 *key)
{
	sha1_context     SH;
	guint8     *cp, password_buf[64];
	guint32      password_index = 0;
	guint32      count = 0, i;

	sha1_starts(&SH);   /* initialize SHA */

	/**********************************************/
	/* Use while loop until we've done 1 Megabyte */
	/**********************************************/
	while (count < 1048576) {
		cp = password_buf;
		for (i = 0; i < 64; i++) {
			/*************************************************/
			/* Take the next octet of the password, wrapping */
			/* to the beginning of the password as necessary.*/
			/*************************************************/
			*cp++ = password[password_index++ % passwordlen];
		}
		sha1_update (&SH, password_buf, 64);
		count += 64;
	}
	sha1_finish(&SH, key);

	/*****************************************************/
	/* Now localize the key with the engineID and pass   */
	/* through SHA to produce final key                  */
	/* We ignore invalid engineLengths here. More strict */
	/* checking is done in snmp_users_update_cb.         */
	/*****************************************************/

	sha1_starts(&SH);
	sha1_update(&SH, key, 20);
	sha1_update(&SH, engineID, engineLength);
	sha1_update(&SH, key, 20);
	sha1_finish(&SH, key);
	return;
 }


static void
process_prefs(void)
{
}

static void*
snmp_users_copy_cb(void* dest, const void* orig, size_t len _U_)
{
	const snmp_ue_assoc_t* o = orig;
	snmp_ue_assoc_t* d = dest;

	d->auth_model = o->auth_model;
	d->user.authModel = auth_models[o->auth_model];

	d->priv_proto = o->priv_proto;
	d->user.privProtocol = priv_protos[o->priv_proto];

	d->user.userName.data = g_memdup(o->user.userName.data,o->user.userName.len);
	d->user.userName.len = o->user.userName.len;

	d->user.authPassword.data = o->user.authPassword.data ? g_memdup(o->user.authPassword.data,o->user.authPassword.len) : NULL;
	d->user.authPassword.len = o->user.authPassword.len;

	d->user.privPassword.data = o->user.privPassword.data ? g_memdup(o->user.privPassword.data,o->user.privPassword.len) : NULL;
	d->user.privPassword.len = o->user.privPassword.len;

	d->engine.len = o->engine.len;
	if (o->engine.data) {
		d->engine.data = g_memdup(o->engine.data,o->engine.len);
	}

	d->user.authKey.data = o->user.authKey.data ? g_memdup(o->user.authKey.data,o->user.authKey.len) : NULL;
	d->user.authKey.len = o->user.authKey.len;

	d->user.privKey.data = o->user.privKey.data ? g_memdup(o->user.privKey.data,o->user.privKey.len) : NULL;
	d->user.privKey.len = o->user.privKey.len;

	return d;
}

static void
snmp_users_free_cb(void* p)
{
	snmp_ue_assoc_t* ue = p;
	g_free(ue->user.userName.data);
	g_free(ue->user.authPassword.data);
	g_free(ue->user.privPassword.data);
	g_free(ue->user.authKey.data);
	g_free(ue->user.privKey.data);
	g_free(ue->engine.data);
}

static void
snmp_users_update_cb(void* p _U_, const char** err)
{
	snmp_ue_assoc_t* ue = p;
	GString* es = g_string_new("");
	unsigned i;

	*err = NULL;

	if (num_ueas == 0)
		/* Nothing to update */
		return;

	if (! ue->user.userName.len)
		g_string_append_printf(es,"no userName\n");

	for (i=0; i<num_ueas-1; i++) {
		snmp_ue_assoc_t* u = &(ueas[i]);

		/* RFC 3411 section 5 */
		if ((u->engine.len > 0) && (u->engine.len < 5 || u->engine.len > 32)) {
			g_string_append_printf(es, "Invalid engineId length (%u). Must be between 5 and 32 (10 and 64 hex digits)\n", u->engine.len);
		}


		if ( u->user.userName.len == ue->user.userName.len
			&& u->engine.len == ue->engine.len ) {

			if (u->engine.len > 0 && memcmp( u->engine.data,   ue->engine.data,  u->engine.len ) == 0) {
				if ( memcmp( u->user.userName.data, ue->user.userName.data, ue->user.userName.len ) == 0 ) {
					/* XXX: make a string for the engineId */
					g_string_append_printf(es,"Duplicate key (userName='%s')\n",ue->user.userName.data);
				}
			}

			if (u->engine.len == 0) {
				if ( memcmp( u->user.userName.data, ue->user.userName.data, ue->user.userName.len ) == 0 ) {
					g_string_append_printf(es,"Duplicate key (userName='%s' engineId=NONE)\n",ue->user.userName.data);
				}
			}
		}
	}

	if (es->len) {
		g_string_truncate(es,es->len-1);
		*err = ep_strdup(es->str);
	}

	g_string_free(es,TRUE);

	return;
}


UAT_LSTRING_CB_DEF(snmp_users,userName,snmp_ue_assoc_t,user.userName.data,user.userName.len)
UAT_LSTRING_CB_DEF(snmp_users,authPassword,snmp_ue_assoc_t,user.authPassword.data,user.authPassword.len)
UAT_LSTRING_CB_DEF(snmp_users,privPassword,snmp_ue_assoc_t,user.privPassword.data,user.privPassword.len)
UAT_BUFFER_CB_DEF(snmp_users,engine_id,snmp_ue_assoc_t,engine.data,engine.len)
UAT_VS_DEF(snmp_users,auth_model,snmp_ue_assoc_t,0,"MD5")
UAT_VS_DEF(snmp_users,priv_proto,snmp_ue_assoc_t,0,"DES")

static void *
snmp_specific_trap_copy_cb(void *dest, const void *orig, size_t len _U_)
{
	snmp_st_assoc_t *u = dest;
	const snmp_st_assoc_t *o = orig;

	u->enterprise = g_strdup(o->enterprise);
	u->trap = o->trap;
	u->desc = g_strdup(o->desc);

	return dest;
}

static void
snmp_specific_trap_free_cb(void *r)
{
	snmp_st_assoc_t *u = r;

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
		    "Engine Enterprise ID", "snmp.engineid.enterprise", FT_UINT32, BASE_DEC|BASE_EXT_STRING,
		    &sminmpec_values_ext, 0, NULL, HFILL }},
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
		    "Engine ID Data: Cisco type", "snmp.engineid.cisco.type", FT_UINT8, BASE_NONE,
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
		    "Value (OctetString)", "snmp.value.octets", FT_BYTES, BASE_NONE,
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



/*--- Included file: packet-snmp-hfarr.c ---*/
#line 1 "../../asn1/snmp/packet-snmp-hfarr.c"
    { &hf_snmp_SMUX_PDUs_PDU,
      { "SMUX-PDUs", "snmp.SMUX_PDUs",
        FT_UINT32, BASE_DEC, VALS(snmp_SMUX_PDUs_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_version,
      { "version", "snmp.version",
        FT_INT32, BASE_DEC, VALS(snmp_Version_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_community,
      { "community", "snmp.community",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_data,
      { "data", "snmp.data",
        FT_UINT32, BASE_DEC, VALS(snmp_PDUs_vals), 0,
        "PDUs", HFILL }},
    { &hf_snmp_parameters,
      { "parameters", "snmp.parameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_snmp_datav2u,
      { "datav2u", "snmp.datav2u",
        FT_UINT32, BASE_DEC, VALS(snmp_T_datav2u_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_v2u_plaintext,
      { "plaintext", "snmp.plaintext",
        FT_UINT32, BASE_DEC, VALS(snmp_PDUs_vals), 0,
        "PDUs", HFILL }},
    { &hf_snmp_encrypted,
      { "encrypted", "snmp.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_snmp_msgAuthoritativeEngineID,
      { "msgAuthoritativeEngineID", "snmp.msgAuthoritativeEngineID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgAuthoritativeEngineBoots,
      { "msgAuthoritativeEngineBoots", "snmp.msgAuthoritativeEngineBoots",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgAuthoritativeEngineTime,
      { "msgAuthoritativeEngineTime", "snmp.msgAuthoritativeEngineTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgUserName,
      { "msgUserName", "snmp.msgUserName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgAuthenticationParameters,
      { "msgAuthenticationParameters", "snmp.msgAuthenticationParameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgPrivacyParameters,
      { "msgPrivacyParameters", "snmp.msgPrivacyParameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgVersion,
      { "msgVersion", "snmp.msgVersion",
        FT_INT32, BASE_DEC, VALS(snmp_Version_vals), 0,
        "Version", HFILL }},
    { &hf_snmp_msgGlobalData,
      { "msgGlobalData", "snmp.msgGlobalData",
        FT_NONE, BASE_NONE, NULL, 0,
        "HeaderData", HFILL }},
    { &hf_snmp_msgSecurityParameters,
      { "msgSecurityParameters", "snmp.msgSecurityParameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgData,
      { "msgData", "snmp.msgData",
        FT_UINT32, BASE_DEC, VALS(snmp_ScopedPduData_vals), 0,
        "ScopedPduData", HFILL }},
    { &hf_snmp_msgID,
      { "msgID", "snmp.msgID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2147483647", HFILL }},
    { &hf_snmp_msgMaxSize,
      { "msgMaxSize", "snmp.msgMaxSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_484_2147483647", HFILL }},
    { &hf_snmp_msgFlags,
      { "msgFlags", "snmp.msgFlags",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_msgSecurityModel,
      { "msgSecurityModel", "snmp.msgSecurityModel",
        FT_UINT32, BASE_DEC, VALS(sec_models), 0,
        NULL, HFILL }},
    { &hf_snmp_plaintext,
      { "plaintext", "snmp.plaintext",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScopedPDU", HFILL }},
    { &hf_snmp_encryptedPDU,
      { "encryptedPDU", "snmp.encryptedPDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_contextEngineID,
      { "contextEngineID", "snmp.contextEngineID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SnmpEngineID", HFILL }},
    { &hf_snmp_contextName,
      { "contextName", "snmp.contextName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_snmp_get_request,
      { "get-request", "snmp.get_request",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetRequest_PDU", HFILL }},
    { &hf_snmp_get_next_request,
      { "get-next-request", "snmp.get_next_request",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetNextRequest_PDU", HFILL }},
    { &hf_snmp_get_response,
      { "get-response", "snmp.get_response",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetResponse_PDU", HFILL }},
    { &hf_snmp_set_request,
      { "set-request", "snmp.set_request",
        FT_NONE, BASE_NONE, NULL, 0,
        "SetRequest_PDU", HFILL }},
    { &hf_snmp_trap,
      { "trap", "snmp.trap",
        FT_NONE, BASE_NONE, NULL, 0,
        "Trap_PDU", HFILL }},
    { &hf_snmp_getBulkRequest,
      { "getBulkRequest", "snmp.getBulkRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetBulkRequest_PDU", HFILL }},
    { &hf_snmp_informRequest,
      { "informRequest", "snmp.informRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "InformRequest_PDU", HFILL }},
    { &hf_snmp_snmpV2_trap,
      { "snmpV2-trap", "snmp.snmpV2_trap",
        FT_NONE, BASE_NONE, NULL, 0,
        "SNMPv2_Trap_PDU", HFILL }},
    { &hf_snmp_report,
      { "report", "snmp.report",
        FT_NONE, BASE_NONE, NULL, 0,
        "Report_PDU", HFILL }},
    { &hf_snmp_request_id,
      { "request-id", "snmp.request_id",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_snmp_error_status,
      { "error-status", "snmp.error_status",
        FT_INT32, BASE_DEC, VALS(snmp_T_error_status_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_error_index,
      { "error-index", "snmp.error_index",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_snmp_variable_bindings,
      { "variable-bindings", "snmp.variable_bindings",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VarBindList", HFILL }},
    { &hf_snmp_bulkPDU_request_id,
      { "request-id", "snmp.request_id",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_snmp_non_repeaters,
      { "non-repeaters", "snmp.non_repeaters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2147483647", HFILL }},
    { &hf_snmp_max_repetitions,
      { "max-repetitions", "snmp.max_repetitions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2147483647", HFILL }},
    { &hf_snmp_enterprise,
      { "enterprise", "snmp.enterprise",
        FT_OID, BASE_NONE, NULL, 0,
        "EnterpriseOID", HFILL }},
    { &hf_snmp_agent_addr,
      { "agent-addr", "snmp.agent_addr",
        FT_IPv4, BASE_NONE, NULL, 0,
        "NetworkAddress", HFILL }},
    { &hf_snmp_generic_trap,
      { "generic-trap", "snmp.generic_trap",
        FT_INT32, BASE_DEC, VALS(snmp_GenericTrap_vals), 0,
        "GenericTrap", HFILL }},
    { &hf_snmp_specific_trap,
      { "specific-trap", "snmp.specific_trap",
        FT_INT32, BASE_DEC, NULL, 0,
        "SpecificTrap", HFILL }},
    { &hf_snmp_time_stamp,
      { "time-stamp", "snmp.time_stamp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeTicks", HFILL }},
    { &hf_snmp_name,
      { "name", "snmp.name",
        FT_OID, BASE_NONE, NULL, 0,
        "ObjectName", HFILL }},
    { &hf_snmp_valueType,
      { "valueType", "snmp.valueType",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_VarBindList_item,
      { "VarBind", "snmp.VarBind",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_snmp_open,
      { "open", "snmp.open",
        FT_UINT32, BASE_DEC, VALS(snmp_OpenPDU_vals), 0,
        "OpenPDU", HFILL }},
    { &hf_snmp_close,
      { "close", "snmp.close",
        FT_INT32, BASE_DEC, VALS(snmp_ClosePDU_U_vals), 0,
        "ClosePDU", HFILL }},
    { &hf_snmp_registerRequest,
      { "registerRequest", "snmp.registerRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "RReqPDU", HFILL }},
    { &hf_snmp_registerResponse,
      { "registerResponse", "snmp.registerResponse",
        FT_UINT32, BASE_DEC, VALS(snmp_RegisterResponse_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_commitOrRollback,
      { "commitOrRollback", "snmp.commitOrRollback",
        FT_INT32, BASE_DEC, VALS(snmp_SOutPDU_U_vals), 0,
        "SOutPDU", HFILL }},
    { &hf_snmp_rRspPDU,
      { "rRspPDU", "snmp.rRspPDU",
        FT_INT32, BASE_DEC, VALS(snmp_RRspPDU_U_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_pDUs,
      { "pDUs", "snmp.pDUs",
        FT_UINT32, BASE_DEC, VALS(snmp_PDUs_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_smux_simple,
      { "smux-simple", "snmp.smux_simple",
        FT_NONE, BASE_NONE, NULL, 0,
        "SimpleOpen", HFILL }},
    { &hf_snmp_smux_version,
      { "smux-version", "snmp.smux_version",
        FT_INT32, BASE_DEC, VALS(snmp_T_smux_version_vals), 0,
        NULL, HFILL }},
    { &hf_snmp_identity,
      { "identity", "snmp.identity",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_snmp_description,
      { "description", "snmp.description",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DisplayString", HFILL }},
    { &hf_snmp_password,
      { "password", "snmp.password",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_snmp_subtree,
      { "subtree", "snmp.subtree",
        FT_OID, BASE_NONE, NULL, 0,
        "ObjectName", HFILL }},
    { &hf_snmp_priority,
      { "priority", "snmp.priority",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1_2147483647", HFILL }},
    { &hf_snmp_operation,
      { "operation", "snmp.operation",
        FT_INT32, BASE_DEC, VALS(snmp_T_operation_vals), 0,
        NULL, HFILL }},

/*--- End of included file: packet-snmp-hfarr.c ---*/
#line 2148 "../../asn1/snmp/packet-snmp-template.c"
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

/*--- Included file: packet-snmp-ettarr.c ---*/
#line 1 "../../asn1/snmp/packet-snmp-ettarr.c"
    &ett_snmp_Message,
    &ett_snmp_Messagev2u,
    &ett_snmp_T_datav2u,
    &ett_snmp_UsmSecurityParameters,
    &ett_snmp_SNMPv3Message,
    &ett_snmp_HeaderData,
    &ett_snmp_ScopedPduData,
    &ett_snmp_ScopedPDU,
    &ett_snmp_PDUs,
    &ett_snmp_PDU,
    &ett_snmp_BulkPDU,
    &ett_snmp_Trap_PDU_U,
    &ett_snmp_VarBind,
    &ett_snmp_VarBindList,
    &ett_snmp_SMUX_PDUs,
    &ett_snmp_RegisterResponse,
    &ett_snmp_OpenPDU,
    &ett_snmp_SimpleOpen_U,
    &ett_snmp_RReqPDU_U,

/*--- End of included file: packet-snmp-ettarr.c ---*/
#line 2164 "../../asn1/snmp/packet-snmp-template.c"
  };
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
			      (void*)&ueas,
			      &num_ueas,
			      UAT_CAT_CRYPTO,
			      "ChSNMPUsersSection",
			      snmp_users_copy_cb,
			      snmp_users_update_cb,
			      snmp_users_free_cb,
			      renew_ue_cache,
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
                                      (void*) &specific_traps,
                                      &num_specific_traps,
                                      UAT_CAT_GENERAL,
                                      "ChSNMPEnterpriseSpecificTrapTypes",
                                      snmp_specific_trap_copy_cb,
                                      NULL,
                                      snmp_specific_trap_free_cb,
									  NULL,
                                      specific_traps_flds);

  /* Register protocol */
  proto_snmp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("snmp", dissect_snmp, proto_snmp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_snmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  /* Register configuration preferences */
  snmp_module = prefs_register_protocol(proto_snmp, process_prefs);
  prefs_register_bool_preference(snmp_module, "display_oid",
			"Show SNMP OID in info column",
			"Whether the SNMP OID should be shown in the info column",
			&display_oid);

  prefs_register_obsolete_preference(snmp_module, "mib_modules");
  prefs_register_obsolete_preference(snmp_module, "users_file");

  prefs_register_bool_preference(snmp_module, "desegment",
			"Reassemble SNMP-over-TCP messages\nspanning multiple TCP segments",
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

  value_sub_dissectors_table = register_dissector_table("snmp.variable_oid","SNMP Variable OID", FT_STRING, BASE_NONE);

  register_init_routine(renew_ue_cache);

  register_ber_syntax_dissector("SNMP", proto_snmp, dissect_snmp_tcp);
}


/*--- proto_reg_handoff_snmp ---------------------------------------*/
void proto_reg_handoff_snmp(void) {
	dissector_handle_t snmp_tcp_handle;

	snmp_handle = find_dissector("snmp");

	dissector_add_uint("udp.port", UDP_PORT_SNMP, snmp_handle);
	dissector_add_uint("udp.port", UDP_PORT_SNMP_TRAP, snmp_handle);
	dissector_add_uint("udp.port", UDP_PORT_SNMP_PATROL, snmp_handle);
	dissector_add_uint("ethertype", ETHERTYPE_SNMP, snmp_handle);
	dissector_add_uint("ipx.socket", IPX_SOCKET_SNMP_AGENT, snmp_handle);
	dissector_add_uint("ipx.socket", IPX_SOCKET_SNMP_SINK, snmp_handle);
	dissector_add_uint("hpext.dxsap", HPEXT_SNMP, snmp_handle);

	snmp_tcp_handle = create_dissector_handle(dissect_snmp_tcp, proto_snmp);
	dissector_add_uint("tcp.port", TCP_PORT_SNMP, snmp_tcp_handle);
	dissector_add_uint("tcp.port", TCP_PORT_SNMP_TRAP, snmp_tcp_handle);

	data_handle = find_dissector("data");

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
	static hf_register_info hf[] = {
		{ &hf_smux_version,
		{ "Version", "smux.version", FT_UINT8, BASE_DEC, NULL,
		    0x0, NULL, HFILL }},
		{ &hf_smux_pdutype,
		{ "PDU type", "smux.pdutype", FT_UINT8, BASE_DEC, VALS(smux_types),
		    0x0, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_smux,
	};

	proto_smux = proto_register_protocol("SNMP Multiplex Protocol",
	    "SMUX", "smux");
	proto_register_field_array(proto_smux, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_smux(void)
{
	dissector_handle_t smux_handle;

	smux_handle = create_dissector_handle(dissect_smux, proto_smux);
	dissector_add_uint("tcp.port", TCP_PORT_SMUX, smux_handle);
}
