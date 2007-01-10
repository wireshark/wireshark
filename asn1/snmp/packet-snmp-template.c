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
 * Copyright (C) 2007 Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/conversation.h>
#include "etypes.h"
#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include <epan/emem.h>
#include <epan/next_tvb.h>
#include "packet-ipx.h"
#include "packet-hpext.h"


#include "packet-ber.h"

#ifdef HAVE_NET_SNMP
# include <net-snmp/net-snmp-config.h>
# include <net-snmp/mib_api.h>
# include <net-snmp/library/default_store.h>
# include <net-snmp/config_api.h>

#ifdef _WIN32
# include <epan/filesystem.h>
#endif /* _WIN32 */

   /*
    * Define values "sprint_realloc_value()" expects.
    */
# define VALTYPE_INTEGER	ASN_INTEGER
# define VALTYPE_COUNTER	ASN_COUNTER
# define VALTYPE_GAUGE		ASN_GAUGE
# define VALTYPE_TIMETICKS	ASN_TIMETICKS
# define VALTYPE_STRING		ASN_OCTET_STR
# define VALTYPE_IPADDR		ASN_IPADDRESS
# define VALTYPE_OPAQUE		ASN_OPAQUE
# define VALTYPE_NSAP		ASN_NSAP
# define VALTYPE_OBJECTID	ASN_OBJECT_ID
# define VALTYPE_BITSTR		ASN_BIT_STR
# define VALTYPE_COUNTER64	ASN_COUNTER64

#endif /* HAVE_NET_SNMP */
#include "packet-snmp.h"
#include "format-oid.h"

#include <epan/sha1.h>
#include <epan/crypt/crypt-md5.h>
#include <epan/expert.h>
#include <epan/report_err.h>

#ifdef _WIN32
#include <winposixtype.h>
#endif /* _WIN32 */

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

/* Initialize the protocol and registered fields */
static int proto_snmp = -1;
static int proto_smux = -1;

/* Default MIB modules to load */
/*
 * XXX - According to Wes Hardaker, we shouldn't do this:
 *       http://www.ethereal.com/lists/ethereal-dev/200412/msg00222.html
 */
#ifdef _WIN32
# define DEF_MIB_MODULES "IP-MIB;IF-MIB;TCP-MIB;UDP-MIB;SNMPv2-MIB;RFC1213-MIB;UCD-SNMP-MIB"
# define IMPORT_SEPARATOR ":"
#else
# define DEF_MIB_MODULES "IP-MIB:IF-MIB:TCP-MIB:UDP-MIB:SNMPv2-MIB:RFC1213-MIB:UCD-SNMP-MIB"
# define IMPORT_SEPARATOR ";"
#endif /* _WIN32 */

static const gchar *mib_modules = DEF_MIB_MODULES;
static gboolean display_oid = TRUE;
static gboolean snmp_var_in_tree = TRUE;

static const gchar* ue_assocs_filename = "";
static const gchar* ue_assocs_filename_loaded = "";
static snmp_ue_assoc_t* ue_assocs = NULL;
static snmp_usm_params_t usm_p = {FALSE,FALSE,0,0,NULL,NULL,NULL,NULL,NULL,NULL,NULL};

/* Subdissector tables */
static dissector_table_t variable_oid_dissector_table;

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
static int hf_snmp_engineid_mac = -1;
static int hf_snmp_engineid_text = -1;
static int hf_snmp_engineid_time = -1;
static int hf_snmp_engineid_data = -1;
static int hf_snmp_counter64 = -1;
static int hf_snmp_decryptedPDU = -1;
static int hf_snmp_msgAuthentication = -1;

#include "packet-snmp-hf.c"

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

#include "packet-snmp-ett.c"


static const true_false_string auth_flags = {
	"OK",
	"Failed"
};

/* defined in net-SNMP; include/net-snmp/library/snmp.h */
#undef SNMP_MSG_GET
#undef SNMP_MSG_SET
#undef SNMP_MSG_GETNEXT
#undef SNMP_MSG_RESPONSE
#undef SNMP_MSG_TRAP
#undef SNMP_MSG_GETBULK
#undef SNMP_MSG_INFORM
#undef SNMP_MSG_TRAP2
#undef SNMP_MSG_REPORT
#undef SNMP_NOSUCHOBJECT
#undef SNMP_NOSUCHINSTANCE
#undef SNMP_ENDOFMIBVIEW

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

/* SNMP Tags */

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

/* SNMPv1 Types */

#define SNMP_NULL                0
#define SNMP_INTEGER             1    /* l  */
#define SNMP_OCTETSTR            2    /* c  */
#define SNMP_DISPLAYSTR          2    /* c  */
#define SNMP_OBJECTID            3    /* ul */
#define SNMP_IPADDR              4    /* uc */
#define SNMP_COUNTER             5    /* ul */
#define SNMP_GAUGE               6    /* ul */
#define SNMP_TIMETICKS           7    /* ul */
#define SNMP_OPAQUE              8    /* c  */

/* additional SNMPv2 Types */

#define SNMP_UINTEGER            5    /* ul */
#define SNMP_BITSTR              9    /* uc */
#define SNMP_NSAP               10    /* uc */
#define SNMP_COUNTER64          11    /* ul */
#define SNMP_NOSUCHOBJECT       12
#define SNMP_NOSUCHINSTANCE     13
#define SNMP_ENDOFMIBVIEW       14


typedef struct _SNMP_CNV SNMP_CNV;

struct _SNMP_CNV
{
  guint class;
  guint tag;
  gint  syntax;
  const gchar *name;
};

static SNMP_CNV SnmpCnv [] =
{
  {BER_CLASS_UNI, BER_UNI_TAG_NULL,			SNMP_NULL,      "NULL"},
  {BER_CLASS_UNI, BER_UNI_TAG_INTEGER,		SNMP_INTEGER,   "INTEGER"},
  {BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING,	SNMP_OCTETSTR,  "OCTET STRING"},
  {BER_CLASS_UNI, BER_UNI_TAG_OID,			SNMP_OBJECTID,  "OBJECTID"},
  {BER_CLASS_APP, SNMP_IPA,					SNMP_IPADDR,    "IPADDR"},
  {BER_CLASS_APP, SNMP_CNT,					SNMP_COUNTER,   "COUNTER"},  /* Counter32 */
  {BER_CLASS_APP, SNMP_GGE,					SNMP_GAUGE,     "GAUGE"},    /* Gauge32 == Unsigned32  */
  {BER_CLASS_APP, SNMP_TIT,					SNMP_TIMETICKS, "TIMETICKS"},
  {BER_CLASS_APP, SNMP_OPQ,					SNMP_OPAQUE,    "OPAQUE"},

/* SNMPv2 data types and errors */

  {BER_CLASS_UNI, BER_UNI_TAG_BITSTRING,	SNMP_BITSTR,         "BITSTR"},
  {BER_CLASS_APP, SNMP_C64,					SNMP_COUNTER64,      "COUNTER64"},
  {BER_CLASS_CON, SERR_NSO,					SNMP_NOSUCHOBJECT,   "NOSUCHOBJECT"},
  {BER_CLASS_CON, SERR_NSI,					SNMP_NOSUCHINSTANCE, "NOSUCHINSTANCE"},
  {BER_CLASS_CON, SERR_EOM,					SNMP_ENDOFMIBVIEW,   "ENDOFMIBVIEW"},
  {0,		0,         -1,                  NULL}
};

/*
 * NAME:        g_snmp_tag_cls2syntax
 * SYNOPSIS:    gboolean g_snmp_tag_cls2syntax
 *                  (
 *                      guint    tag,
 *                      guint    cls,
 *                      gushort *syntax
 *                  )
 * DESCRIPTION: Converts ASN1 tag and class to Syntax tag and name.
 *              See SnmpCnv for conversion.
 * RETURNS:     name on success, NULL on failure
 */

static const gchar *
snmp_tag_cls2syntax ( guint tag, guint cls, gushort *syntax)
{
    SNMP_CNV *cnv;

    cnv = SnmpCnv;
    while (cnv->syntax != -1)
    {
        if (cnv->tag == tag && cnv->class == cls)
        {
            *syntax = cnv->syntax;
            return cnv->name;
        }
        cnv++;
    }
    return NULL;
}

int oid_to_subid_buf(const guint8 *oid, gint oid_len, subid_t *buf, int buf_len) {
  int i, out_len;
  guint8 byte;
  guint32 value;
  gboolean is_first;

  value=0; out_len = 0; byte =0; is_first = TRUE;
  for (i=0; i<oid_len; i++){
    if (out_len >= buf_len)
      break;
    byte = oid[i];
    value = (value << 7) | (byte & 0x7F);
    if (byte & 0x80) {
      continue;
    }
    if (is_first) {
      if ( value<40 ){
        buf[0] = 0;
        buf[1] = value;
      }else if ( value < 80 ){
        buf[0] = 1;
        buf[1] = value - 40;
      }else {
        buf[0] = 2;
        buf[1] = value - 80;
      }
      out_len= out_len+2;
      is_first = FALSE;
    }else{
      buf[out_len++] = value;
    }
    value = 0;
  }

  return out_len;
}

gchar *
format_oid(subid_t *oid, guint oid_length)
{
	char *result;
	int result_len;
	int len;
	unsigned int i;
	char *buf;
#ifdef HAVE_NET_SNMP
	guchar *oid_string;
	size_t oid_string_len;
	size_t oid_out_len;
#endif

	result_len = oid_length * 22;

#ifdef HAVE_NET_SNMP
	/*
	 * Get the decoded form of the OID, and add its length to the
	 * length of the result string.
	 *
	 * XXX - check for "sprint_realloc_objid()" failure.
	 */
	oid_string_len = 1024;
	oid_string = ep_alloc(oid_string_len);
	*oid_string = '\0';
	oid_out_len = 0;
	/* We pass an ep allocated block here, NOT a malloced block
	 * so we MUST NOT allow reallocation, hence the fourth
	 * parameter MUST be 0/FALSE
	 */
	sprint_realloc_objid(&oid_string, &oid_string_len, &oid_out_len, FALSE,
	    oid, oid_length);
	result_len += strlen(oid_string) + 3;
#endif

	result = ep_alloc(result_len + 1);
	buf = result;
	len = g_snprintf(buf, result_len + 1 - (buf-result), "%lu", (unsigned long)oid[0]);
	buf += len;
	for (i = 1; i < oid_length;i++) {
		len = g_snprintf(buf, result_len + 1 - (buf-result), ".%lu", (unsigned long)oid[i]);
		buf += len;
	}

#ifdef HAVE_NET_SNMP
	/*
	 * Append the decoded form of the OID.
	 */
	g_snprintf(buf, result_len + 1 -(buf-result), " (%s)", oid_string);
#endif

	return result;
}

/* returns the decoded (can be NULL) and non_decoded OID strings */
void
new_format_oid(subid_t *oid, guint oid_length,
	       gchar **non_decoded, gchar **decoded)
{
	int non_decoded_len;
	int len;
	unsigned int i;
	char *buf;
#ifdef HAVE_NET_SNMP
	guchar *oid_string;
	size_t oid_string_len;
	size_t oid_out_len;
#endif

    if (oid == NULL || oid_length < 1) {
		*decoded = NULL;
		return;
	}

#ifdef HAVE_NET_SNMP
	/*
	 * Get the decoded form of the OID, and add its length to the
	 * length of the result string.
	 */

	/*
	 * XXX - if we convert this to ep_alloc(), make sure the fourth
	 * argument to sprint_realloc_objid() is FALSE.
	 */

	oid_string_len = 1024;
	oid_string = ep_alloc(oid_string_len);
	if (oid_string != NULL) {
		*oid_string = '\0';
		oid_out_len = 0;
		/* We pass an ep allocated block here, NOT a malloced block
		 * so we MUST NOT allow reallocation, hence the fourth
		 * parameter MUST be 0/FALSE
		 */
		sprint_realloc_objid(&oid_string, &oid_string_len, &oid_out_len, FALSE,
				     oid, oid_length);
	}
	*decoded = oid_string;
#else
	*decoded = NULL;
#endif

	non_decoded_len = oid_length * 22 + 1;
	*non_decoded = ep_alloc(non_decoded_len);
	buf = *non_decoded;
	len = g_snprintf(buf, non_decoded_len-(buf-*non_decoded), "%lu", (unsigned long)oid[0]);
	buf += len;
	for (i = 1; i < oid_length; i++) {
	  len = g_snprintf(buf, non_decoded_len-(buf-*non_decoded), ".%lu", (unsigned long)oid[i]);
	  buf += len;
	}
}

#ifdef HAVE_NET_SNMP
static gboolean
check_var_length(guint vb_length, guint required_length, guchar **errmsg)
{
	gchar *buf;
	static const char badlen_fmt[] = "Length is %u, should be %u";

	if (vb_length != required_length) {
		/* Enough room for the largest "Length is XXX,
		   should be XXX" message - 10 digits for each
		   XXX. */
		buf = ep_alloc(sizeof badlen_fmt + 10 + 10);
		if (buf != NULL) {
			g_snprintf(buf, sizeof badlen_fmt + 10 + 10,
			    badlen_fmt, vb_length, required_length);
		}
		*errmsg = buf;
		return FALSE;
	}
	return TRUE;	/* length is OK */
}

static gchar *
format_var(struct variable_list *variable, subid_t *variable_oid,
    guint variable_oid_length, gushort vb_type, guint val_len)
{
	guchar *buf;
	size_t buf_len;
	size_t out_len;

        if (variable_oid == NULL || variable_oid_length == 0)
                return NULL;

	switch (vb_type) {

	case SNMP_IPADDR:
		/* Length has to be 4 bytes. */
		if (!check_var_length(val_len, 4, &buf))
			return buf;	/* it's not 4 bytes */
		break;

#ifdef REMOVED
	/* not all counters are encoded as a full 64bit integer */
	case SNMP_COUNTER64:
		/* Length has to be 8 bytes. */
		if (!check_var_length(val_len, 8, &buf))
			return buf;	/* it's not 8 bytes */
		break;
#endif
	default:
		break;
	}

	variable->next_variable = NULL;
	variable->name = variable_oid;
	variable->name_length = variable_oid_length;
	switch (vb_type) {

	case SNMP_INTEGER:
		variable->type = VALTYPE_INTEGER;
		break;

	case SNMP_COUNTER:
		variable->type = VALTYPE_COUNTER;
		break;

	case SNMP_GAUGE:
		variable->type = VALTYPE_GAUGE;
		break;

	case SNMP_TIMETICKS:
		variable->type = VALTYPE_TIMETICKS;
		break;

	case SNMP_OCTETSTR:
		variable->type = VALTYPE_STRING;
		break;

	case SNMP_IPADDR:
		variable->type = VALTYPE_IPADDR;
		break;

	case SNMP_OPAQUE:
		variable->type = VALTYPE_OPAQUE;
		break;

	case SNMP_NSAP:
		variable->type = VALTYPE_NSAP;
		break;

	case SNMP_OBJECTID:
		variable->type = VALTYPE_OBJECTID;
		break;

	case SNMP_BITSTR:
		variable->type = VALTYPE_BITSTR;
		break;

	case SNMP_COUNTER64:
		variable->type = VALTYPE_COUNTER64;
		break;
	}
	variable->val_len = val_len;

	/*
	 * XXX - check for "sprint_realloc_objid()" failure.
	 */

	buf_len = 1024;
	buf = ep_alloc(buf_len);
	if (buf != NULL) {
		*buf = '\0';
		out_len = 0;
		/* We pass an ep allocated block here, NOT a malloced block
		 * so we MUST NOT allow reallocation, hence the fourth
		 * parameter MUST be 0/FALSE
		 */
		sprint_realloc_value(&buf, &buf_len, &out_len, FALSE,
		    variable_oid, variable_oid_length, variable);
	}
	return buf;
}
#endif


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
    conformance = ((tvb_get_guint8(tvb, offset)>>7) && 0x01);
    proto_tree_add_item(tree, hf_snmp_engineid_conform, tvb, offset, 1, FALSE);

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
	  proto_tree_add_item(tree, hf_snmp_engineid_ipv4, tvb, offset, 4, FALSE);
	  offset+=4;
	  len_remain=0;
	}
	break;
      case SNMP_ENGINEID_FORMAT_IPV6:
	/* 16-byte IPv6 address */
	if (len_remain==16) {
	  proto_tree_add_item(tree, hf_snmp_engineid_ipv6, tvb, offset, 16, FALSE);
	  offset+=16;
	  len_remain=0;
	}
	break;
      case SNMP_ENGINEID_FORMAT_MACADDRESS:
	/* 6-byte MAC address */
	if (len_remain==6) {
	  proto_tree_add_item(tree, hf_snmp_engineid_mac, tvb, offset, 6, FALSE);
	  offset+=6;
	  len_remain=0;
	}
	break;
      case SNMP_ENGINEID_FORMAT_TEXT:
	/* max. 27-byte string, administratively assigned */
	if (len_remain<=27) {
	  proto_tree_add_item(tree, hf_snmp_engineid_text, tvb, offset, len_remain, FALSE);
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
	    proto_tree_add_item(tree, hf_snmp_engineid_data, tvb, offset, 4, FALSE);
	    seconds = tvb_get_letohl(tvb, offset+4);
	    ts.secs = seconds;
	    proto_tree_add_time_format(tree, hf_snmp_engineid_time, tvb, offset+4, 4,
                                  &ts, "Engine ID Data: Creation Time: %s",
                                  abs_time_secs_to_str(seconds));
	    offset+=8;
	    len_remain=0;
	  }
	}
	break;
      case SNMP_ENGINEID_FORMAT_OCTETS:
      default:
	/* max. 27 bytes, administratively assigned or unknown format */
	if (len_remain<=27) {
	  proto_tree_add_item(tree, hf_snmp_engineid_data, tvb, offset, len_remain, FALSE);
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

/* This code is copied from the original SNMP dissector with minor changes to adapt it to use packet-ber.c routines
 * TODO:
 * - Rewrite it completly as OID as subid_t could be returned from dissect_ber_objectidentifier
 * - vb_type_name is known when calling this routine(?)
 * - All branches not needed(?)
 * ...
 */

static void
snmp_variable_decode(tvbuff_t *tvb, proto_tree *snmp_tree, packet_info *pinfo,tvbuff_t *oid_tvb,
					 int offset, guint *lengthp, tvbuff_t **out_tvb)
{
	int start, vb_value_start;
	guint length;
	guint vb_length;
	gushort vb_type;
	const gchar *vb_type_name;
	gint32 vb_integer_value;
	guint32 vb_uinteger_value;
	guint8 *vb_octet_string;
	const guint8 *oid_buf;
	subid_t *vb_oid;
	guint vb_oid_length;
	gchar *vb_display_string = NULL;
	subid_t *variable_oid = NULL;
	gint oid_len;
	guint variable_oid_length = 0;
	const guint8 *var_oid_buf;
#ifdef HAVE_NET_SNMP
	struct variable_list variable;
	long value;
#endif
	unsigned int i;
	gchar *buf;
	int len;
	gint8 class;
	gboolean pc, ind = 0;
	gint32 ber_tag;

	start = offset;
	/* parse the type of the object */
	offset = dissect_ber_identifier(pinfo, snmp_tree, tvb, start, &class, &pc, &ber_tag);
	offset = dissect_ber_length(pinfo, snmp_tree, tvb, offset, &vb_length, &ind);

	if(vb_length == 0){
		length = offset - start;
		*lengthp = length;
		return;
	}

	vb_value_start = offset;

	/* Convert the class, constructed flag, and tag to a type. */
	vb_type_name = snmp_tag_cls2syntax(ber_tag, class, &vb_type);

	if (vb_type_name == NULL) {
		/*
		 * Unsupported type.
		 * Dissect the value as an opaque string of octets.
		 */
		vb_type_name = "unsupported type";
		vb_type = SNMP_OPAQUE;
	}
	/* construct subid_t variable_oid from oid_tvb */
	if (oid_tvb){
		oid_len = tvb_length_remaining(oid_tvb,0);
		var_oid_buf = tvb_get_ptr(oid_tvb, 0, oid_len);
		variable_oid = ep_alloc((oid_len+1) * sizeof(gulong));
		variable_oid_length = oid_to_subid_buf(var_oid_buf, oid_len, variable_oid, ((oid_len+1) * sizeof(gulong)));
	}
	/* parse the value */
	switch (vb_type) {

	case SNMP_INTEGER:
		offset = dissect_ber_integer(FALSE, pinfo, NULL, tvb, start, -1, (void*)&(vb_integer_value));
		length = offset - vb_value_start;
		if (snmp_tree) {
#ifdef HAVE_NET_SNMP
			value = vb_integer_value;
			variable.val.integer = &value;
			vb_display_string = format_var(&variable,
			    variable_oid, variable_oid_length, vb_type,
			    vb_length);
#else
			vb_display_string = NULL;
#endif
			if (vb_display_string != NULL) {
				proto_tree_add_text(snmp_tree, tvb,
				    vb_value_start, length,
				    "Value: %s", vb_display_string);
			} else {
				proto_tree_add_text(snmp_tree,tvb,
				    vb_value_start, length,
				    "Value: %s: %d (%#x)", vb_type_name,
				    vb_integer_value, vb_integer_value);
			}
		}
		break;

	case SNMP_COUNTER:
	case SNMP_GAUGE:
	case SNMP_TIMETICKS:
		offset = dissect_ber_integer(FALSE, pinfo, NULL, tvb, start, -1, &vb_uinteger_value);
		length = offset - vb_value_start;
		if (snmp_tree) {
#ifdef HAVE_NET_SNMP
			value = vb_uinteger_value;
			variable.val.integer = &value;
			vb_display_string = format_var(&variable,
			    variable_oid, variable_oid_length, vb_type,
			    vb_length);
#else
			vb_display_string = NULL;
#endif
			if (vb_display_string != NULL) {
				proto_tree_add_text(snmp_tree, tvb,
				    vb_value_start, length,
				    "Value: %s", vb_display_string);
			} else {
				proto_tree_add_text(snmp_tree, tvb,
				    vb_value_start, length,
				    "Value: %s: %u (%#x)", vb_type_name,
				    vb_uinteger_value, vb_uinteger_value);
			}
		}
		break;
	case SNMP_COUNTER64:
		offset=dissect_ber_integer64(TRUE, pinfo, snmp_tree, tvb, offset, hf_snmp_counter64, NULL);
		break;
	case SNMP_OCTETSTR:
	case SNMP_IPADDR:
	case SNMP_OPAQUE:
	case SNMP_NSAP:
	case SNMP_BITSTR:
		offset = dissect_ber_octet_string(FALSE, pinfo, NULL, tvb, start, -1, out_tvb);
		vb_octet_string = ep_tvb_memdup(tvb, vb_value_start, vb_length);

		length = offset - vb_value_start;
		if (snmp_tree) {
#ifdef HAVE_NET_SNMP
			variable.val.string = vb_octet_string;
			vb_display_string = format_var(&variable,
			    variable_oid, variable_oid_length, vb_type,
			    vb_length);
#else
			vb_display_string = NULL;
#endif
			if (vb_display_string != NULL) {
				proto_tree_add_text(snmp_tree, tvb,
				    vb_value_start, length,
				    "Value: %s", vb_display_string);
			} else {
				/*
				 * If some characters are not printable,
				 * display the string as bytes.
				 */
				for (i = 0; i < vb_length; i++) {
					if (!(isprint(vb_octet_string[i])
					    || isspace(vb_octet_string[i])))
						break;
				}
				if (i < vb_length) {
					/*
					 * We stopped, due to a non-printable
					 * character, before we got to the end
					 * of the string.
					 */
					vb_display_string = ep_alloc(4*vb_length);
					buf = vb_display_string;
					len = g_snprintf(buf, 4*vb_length, "%03u", vb_octet_string[0]);
					buf += len;
					for (i = 1; i < vb_length; i++) {
						len = g_snprintf(buf, 4*vb_length-(buf-vb_display_string), ".%03u",
						    vb_octet_string[i]);
						buf += len;
					}
					proto_tree_add_text(snmp_tree, tvb, vb_value_start,
					    length,
					    "Value: %s: %s", vb_type_name,
					    vb_display_string);
				} else {
					proto_tree_add_text(snmp_tree, tvb, vb_value_start,
					    length,
					    "Value: %s: %s", vb_type_name,
					    SAFE_STRING(vb_octet_string, vb_length));
				}
			}
		}
		break;

	case SNMP_NULL:
		dissect_ber_null(FALSE, pinfo, NULL, tvb, start, -1);
		length = offset - vb_value_start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, tvb, vb_value_start, length,
			    "Value: %s", vb_type_name);
		}
		break;

	case SNMP_OBJECTID:
		/* XXX Redo this using dissect_ber_object_identifier when
		   it returns tvb or some other binary form of an OID */
		oid_buf = tvb_get_ptr(tvb, vb_value_start, vb_length);
		vb_oid = ep_alloc((vb_length+1) * sizeof(gulong));
		vb_oid_length = oid_to_subid_buf(oid_buf, vb_length, vb_oid, ((vb_length+1) * sizeof(gulong)));

		offset = offset + vb_length;
		length = offset - vb_value_start;
		if (snmp_tree) {
#ifdef HAVE_NET_SNMP
			variable.val.objid = vb_oid;
			vb_display_string = format_var(&variable,
			    variable_oid, variable_oid_length, vb_type,
			    vb_oid_length * sizeof (subid_t));
			if (vb_display_string != NULL) {
				proto_tree_add_text(snmp_tree, tvb,
				    vb_value_start, length,
				    "Value: %s", vb_display_string);
			} else {
				proto_tree_add_text(snmp_tree, tvb,
				    vb_value_start, length,
				    "Value: %s: [Out of memory]", vb_type_name);
			}
#else /* HAVE_NET_SNMP */
			vb_display_string = format_oid(vb_oid, vb_oid_length);
			if (vb_display_string != NULL) {
				proto_tree_add_text(snmp_tree, tvb,
				    vb_value_start, length,
				    "Value: %s: %s", vb_type_name,
				    vb_display_string);
			} else {
				proto_tree_add_text(snmp_tree, tvb,
				    vb_value_start, length,
				    "Value: %s: [Out of memory]", vb_type_name);
			}
#endif /* HAVE_NET_SNMP */
		}
		break;

	case SNMP_NOSUCHOBJECT:
		length = offset - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, tvb, offset, length,
			    "Value: %s: no such object", vb_type_name);
		}
		break;

	case SNMP_NOSUCHINSTANCE:
		length = offset - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, tvb, offset, length,
			    "Value: %s: no such instance", vb_type_name);
		}
		break;

	case SNMP_ENDOFMIBVIEW:
		length = offset - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, tvb, offset, length,
			    "Value: %s: end of mib view", vb_type_name);
		}
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
		return;
	}
	length = offset - start;
	*lengthp = length;
	return;
}






static snmp_ue_assoc_t* get_user_assoc(tvbuff_t* engine_tvb, tvbuff_t* user_tvb) {
	static snmp_ue_assoc_t* a;
	guint given_username_len;
	guint8* given_username;
	guint given_engine_len;
	guint8* given_engine;
	
	if ( ! ue_assocs ) return NULL;

	if (! ( user_tvb && engine_tvb ) ) return NULL;
	
	given_username_len = tvb_length_remaining(user_tvb,0);
	given_username = ep_tvb_memdup(user_tvb,0,-1);
	given_engine_len = tvb_length_remaining(engine_tvb,0);
	given_engine = ep_tvb_memdup(engine_tvb,0,-1);

	for(a = ue_assocs; a->user.userName.data; a++) {
		guint username_len = a->user.userName.len;
		
		if ( given_username_len == username_len
			 && memcmp(a->user.userName.data, given_username, given_username_len) == 0 ) {
			
			const guint8* engine_data = a->engine.data;
			guint engine_len = a->engine.len;
		
			if ( engine_data ) {
				if ( engine_len == given_engine_len
					 && memcmp(given_engine,engine_data,engine_len) == 0 ) {
					return a;
				}
			} else {
				return a;
			}
		}
	}
	
	return NULL;
}

#ifdef DEBUG_USM
#define DUMP_DATA(n,b,l) { unsigned i; printf("%s: ",n); for (i=0;i<(unsigned)l;i++) printf("%.2x",b[i]); printf("\n"); }
#define D(p) 	printf p
#else
#define DUMP_DATA(n,b,l)
#define D(p)
#endif

gboolean snmp_usm_auth_md5(snmp_usm_params_t* p, gchar const** error) {
	guint msg_len;
	guint8* msg;
	guint auth_len;
	guint8* auth;
	guint8* key;
	guint key_len;
	guint8 calc_auth[16];
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

	md5_hmac(msg, msg_len, key, key_len, calc_auth);
	
	return ( memcmp(auth,calc_auth,12) != 0 ) ? FALSE : TRUE;
}


gboolean snmp_usm_auth_sha1(snmp_usm_params_t* p _U_, gchar const** error _U_) {
	guint msg_len;
	guint8* msg;
	guint auth_len;
	guint8* auth;
	guint8* key;
	guint key_len;
	guint8 calc_auth[20];
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
	
	sha1_hmac(key, key_len, msg, msg_len, calc_auth);
	
	return ( memcmp(auth,calc_auth,12) != 0 ) ? FALSE : TRUE;
}

tvbuff_t* snmp_usm_priv_des(snmp_usm_params_t* p _U_, tvbuff_t* encryptedData _U_, gchar const** error _U_) {
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
		*error = "msgPrivacyParameters lenght != 8";
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
		*error = "the length of the encrypted data is noty a mutiple of 8";
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
	
	clear_tvb = tvb_new_real_data(cleartext, cryptgrm_len, cryptgrm_len);
	
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

tvbuff_t* snmp_usm_priv_aes(snmp_usm_params_t* p _U_, tvbuff_t* encryptedData _U_, gchar const** error _U_) {
#ifdef HAVE_LIBGCRYPT
	*error = "AES decryption Not Yet Implemented";
	return NULL;
#else
	*error = "libgcrypt not present, cannot decrypt";
	return NULL;
#endif
}






#include "packet-snmp-fn.c"


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

	proto_tree *snmp_tree = NULL;
	proto_item *item = NULL;

	usm_p.msg_tvb = tvb;
	usm_p.start_offset = offset_from_real_beginning(tvb,0) ;
	usm_p.engine_tvb = NULL;
	usm_p.user_tvb = NULL;
	usm_p.auth_item = NULL;
	usm_p.auth_tvb = NULL;
	usm_p.auth_offset = 0;
	usm_p.priv_tvb = NULL;
	usm_p.user_assoc = NULL;
	usm_p.authenticated = FALSE;
	usm_p.encrypted = FALSE;
	
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
		 * boundaries?  We requre at least 6 bytes for the
		 * header, which allows for a 4-byte length (ASN.1
		 * BER).
		 */
		if (length_remaining < 6) {
			pinfo->desegment_offset = offset;
			pinfo->desegment_len = 6 - length_remaining;

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
	/* Set tree to 0 to not display internakl BER fields if option used.*/
	offset = dissect_ber_identifier(pinfo, 0, tvb, offset, &class, &pc, &tag);
	offset = dissect_ber_length(pinfo, 0, tvb, offset, &len, &ind);

	message_length = len + 2;
	offset = dissect_ber_integer(FALSE, pinfo, 0, tvb, offset, -1, &version);


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

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
		col_set_str(pinfo->cinfo, COL_PROTOCOL,
		    proto_get_protocol_short_name(find_protocol_by_id(proto)));
	}

	if (tree) {
		item = proto_tree_add_item(tree, proto, tvb, offset,
		    message_length, FALSE);
		snmp_tree = proto_item_add_subtree(item, ett);
	}

	switch (version){
	case 0: /* v1 */
	case 1: /* v2c */
		offset = dissect_snmp_Message(FALSE , tvb, start_offset, pinfo, snmp_tree, -1);
		break;
	case 2: /* v2u */
		offset = dissect_snmp_Messagev2u(FALSE , tvb, start_offset, pinfo, snmp_tree, -1);
		break;
			/* v3 */
	case 3:
		offset = dissect_snmp_SNMPv3Message(FALSE , tvb, start_offset, pinfo, snmp_tree, -1);
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

	next_tvb_call(&var_list, pinfo, tree, NULL, data_handle);

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
	if((tmp_class!=BER_CLASS_UNI)||(tmp_tag!=BER_UNI_TAG_SEQUENCE)){
		return 0;
	}
	/* then comes a length which spans the rest of the tvb */
	offset = get_ber_length(NULL, tvb, offset, &tmp_length, &tmp_ind);
	if(tmp_length!=(guint32)tvb_reported_length_remaining(tvb, offset)){
		return 0;
	}
	/* then comes an INTEGER (version)*/
	offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);
	if((tmp_class!=BER_CLASS_UNI)||(tmp_tag!=BER_UNI_TAG_INTEGER)){
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
	  if( (conversation == NULL) || (conversation->dissector_handle!=snmp_handle) ){
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

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMUX");

	if (tree) {
		item = proto_tree_add_item(tree, proto_smux, tvb, 0, -1, FALSE);
		smux_tree = proto_item_add_subtree(item, ett_smux);
	}

	dissect_SMUX_PDUs_PDU(tvb, pinfo, tree);
}


/*
  MD5 Password to Key Algorithm
  from RFC 3414 A.2.1 
*/
void snmp_usm_password_to_key_md5(
								  guint8 *password,    /* IN */
								  guint   passwordlen, /* IN */
								  guint8 *engineID,    /* IN  - pointer to snmpEngineID  */
								  guint   engineLength,/* IN  - length of snmpEngineID */
								  guint8 *key)         /* OUT - pointer to caller 16-octet buffer */
								  
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
	/* May want to ensure that engineLength <= 32,       */
	/* otherwise need to use a buffer larger than 64     */
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

void snmp_usm_password_to_key_sha1(
						 guint8 *password,    /* IN */
						 guint   passwordlen, /* IN */
						 guint8 *engineID,    /* IN  - pointer to snmpEngineID  */
						 guint   engineLength,/* IN  - length of snmpEngineID */
						 guint8 *key)         /* OUT - pointer to caller 20-octet buffer */
						 {
	sha1_context     SH;
	guint8     *cp, password_buf[72];
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
	/* May want to ensure that engineLength <= 32,       */
	/* otherwise need to use a buffer larger than 72     */
	/*****************************************************/
	memcpy(password_buf, key, 20);
	memcpy(password_buf+20, engineID, engineLength);
	memcpy(password_buf+20+engineLength, key, 20);
	
	sha1_starts(&SH);
	sha1_update(&SH, password_buf, 40+engineLength);
	sha1_finish(&SH, key);
	return;
 }



static void destroy_ue_assocs(snmp_ue_assoc_t* assocs) {
	if (assocs) {
		snmp_ue_assoc_t* a;
		
		for(a = assocs; a->user.userName.data; a++) {
			g_free(a->user.userName.data);
			if (a->user.authKey.data) g_free(a->user.authKey.data);
			if (a->user.privKey.data) g_free(a->user.privKey.data);
			if (a->engine.data) g_free(a->engine.data);
		}
		
		g_free(ue_assocs);
	}
}

static void
process_prefs(void)
{
#ifdef HAVE_NET_SNMP
	gchar *tmp_mib_modules;
	static gboolean mibs_loaded = FALSE;

	if (mibs_loaded) {
		/*
		 * Unload the MIBs, as we'll be reloading them based on
		 * the current preference setting.
		 */
		shutdown_mib();	/* unload MIBs */
	}

	/*
	 * Cannot check if MIBS is already set, as it could be set by Wireshark.
	 *
	 * If we have a list of modules to load, put that list in MIBS,
	 * otherwise clear MIBS.
	 */
	if (mib_modules != NULL) {
		tmp_mib_modules = g_strconcat("MIBS=", mib_modules, NULL);
		/*
		 * Try to be clever and replace colons for semicolons under
		 * Windows.  Do the converse on non-Windows systems.  This
		 * handles cases where we've copied a preferences file
		 * between a non-Windows box and a Windows box or upgraded
		 * from an older version of Wireshark under Windows.
		 */
		g_strdelimit(tmp_mib_modules, IMPORT_SEPARATOR, ENV_SEPARATOR_CHAR);

#ifdef _WIN32
		_putenv(tmp_mib_modules);
#else
		putenv(tmp_mib_modules);
#endif /*_WIN32*/
	} else {
#ifdef _WIN32
		_putenv("MIBS");
#else
		putenv("MIBS");
#endif  /* _WIN32 */
	}

	/*
	 * Load the MIBs.
	 */
	register_mib_handlers();
	read_premib_configs();
	init_mib();
	read_configs();
	mibs_loaded = TRUE;
#endif /* HAVE_NET_SNMP */
	
	if ( g_str_equal(ue_assocs_filename_loaded,ue_assocs_filename) ) return;
	ue_assocs_filename_loaded = ue_assocs_filename;
	
	if (ue_assocs) destroy_ue_assocs(ue_assocs);
	
	if ( *ue_assocs_filename ) {
		gchar* err = load_snmp_users_file(ue_assocs_filename,&ue_assocs);
		if (err) report_failure("Error while loading SNMP's users file:\n%s",err);
	}
	
#ifdef DUMP_USMDATA
	{
		GString* s = g_string_new(">>");
		g_string_sprintfa(s,"File: %s\n",ue_assocs_filename);
		
#define DUMP(s,n,b,l) { unsigned i; g_string_sprintfa(s,"%s: ",n); for (i=0;i<l;i++) g_string_sprintfa(s,"%.2x",b[i]); g_string_sprintfa(s,"\n"); }
		if (ue_assocs) {
			snmp_ue_assoc_t* a;
			
			for(a = ue_assocs; a->user.userName.data; a++) {
				if (a->engine.data) DUMP(s,"engine",a->engine.data,a->engine.len);
				DUMP(s,"userName",a->user.userName.data,a->user.userName.len);
				DUMP(s,"authPassword",a->user.authPassword.data,a->user.authPassword.len);
				if (a->user.authKey.data) DUMP(s,"authKey",a->user.authKey.data,a->user.authKey.len);
				DUMP(s,"privPassword",a->user.privPassword.data,a->user.privPassword.len);
				if (a->user.privKey.data) DUMP(s,"privKey",a->user.privKey.data,a->user.privKey.len);
				g_string_sprintfa(s,"\n");
			}
			
		}
		
		report_failure("%s",s->str);
		g_string_free(s,TRUE);
	}
#endif
}
	
	
	
	/*--- proto_register_snmp -------------------------------------------*/
void proto_register_snmp(void) {	
#if defined(_WIN32) && defined(HAVE_NET_SNMP)
	char *mib_path;
	int mib_path_len;
#define MIB_PATH_APPEND "snmp\\mibs"
#endif
	gchar *tmp_mib_modules;
		
  /* List of fields */
  static hf_register_info hf[] = {
		{ &hf_snmp_v3_flags_auth,
		{ "Authenticated", "snmp.v3.flags.auth", FT_BOOLEAN, 8,
		    TFS(&flags_set_truth), TH_AUTH, "", HFILL }},
		{ &hf_snmp_v3_flags_crypt,
		{ "Encrypted", "snmp.v3.flags.crypt", FT_BOOLEAN, 8,
		    TFS(&flags_set_truth), TH_CRYPT, "", HFILL }},
		{ &hf_snmp_v3_flags_report,
		{ "Reportable", "snmp.v3.flags.report", FT_BOOLEAN, 8,
		    TFS(&flags_set_truth), TH_REPORT, "", HFILL }},
		{ &hf_snmp_engineid_conform, {
		    "Engine ID Conformance", "snmp.engineid.conform", FT_BOOLEAN, 8,
		    TFS(&tfs_snmp_engineid_conform), F_SNMP_ENGINEID_CONFORM, "Engine ID RFC3411 Conformance", HFILL }},
		{ &hf_snmp_engineid_enterprise, {
		    "Engine Enterprise ID", "snmp.engineid.enterprise", FT_UINT32, BASE_DEC,
		    VALS(sminmpec_values), 0, "Engine Enterprise ID", HFILL }},
		{ &hf_snmp_engineid_format, {
		    "Engine ID Format", "snmp.engineid.format", FT_UINT8, BASE_DEC,
		    VALS(snmp_engineid_format_vals), 0, "Engine ID Format", HFILL }},
		{ &hf_snmp_engineid_ipv4, {
		    "Engine ID Data: IPv4 address", "snmp.engineid.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0, "Engine ID Data: IPv4 address", HFILL }},
		{ &hf_snmp_engineid_ipv6, {
		    "Engine ID Data: IPv6 address", "snmp.engineid.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0, "Engine ID Data: IPv6 address", HFILL }},
		{ &hf_snmp_engineid_mac, {
		    "Engine ID Data: MAC address", "snmp.engineid.mac", FT_ETHER, BASE_NONE,
		    NULL, 0, "Engine ID Data: MAC address", HFILL }},
		{ &hf_snmp_engineid_text, {
		    "Engine ID Data: Text", "snmp.engineid.text", FT_STRING, BASE_NONE,
		    NULL, 0, "Engine ID Data: Text", HFILL }},
		{ &hf_snmp_engineid_time, {
		    "Engine ID Data: Time", "snmp.engineid.time", FT_ABSOLUTE_TIME, BASE_NONE,
		    NULL, 0, "Engine ID Data: Time", HFILL }},
		{ &hf_snmp_engineid_data, {
		    "Engine ID Data", "snmp.engineid.data", FT_BYTES, BASE_HEX,
		    NULL, 0, "Engine ID Data", HFILL }},
		{ &hf_snmp_counter64, {
		    "Value", "snmp.counter64", FT_INT64, BASE_DEC,
		    NULL, 0, "A counter64 value", HFILL }},
		  { &hf_snmp_msgAuthentication,
				{ "Authentication OK", "snmp.v3.authOK", FT_BOOLEAN, 8,
					TFS(&auth_flags), 0, "", HFILL }},
		  { &hf_snmp_decryptedPDU, {
					"Decrypted ScopedPDU", "snmp.decrypted_pdu", FT_BYTES, BASE_HEX,
					NULL, 0, "Decrypted PDU", HFILL }},
	  
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
	  
#include "packet-snmp-ettarr.c"
  };
	module_t *snmp_module;

#ifdef HAVE_NET_SNMP

#ifdef _WIN32
	/* Set MIBDIRS so that the SNMP library can find its mibs. */
	/* XXX - Should we set MIBS or MIBFILES as well? */
	mib_path_len=strlen(get_datafile_dir()) + strlen(MIB_PATH_APPEND) + 20;
	mib_path = ep_alloc (mib_path_len);
	g_snprintf (mib_path, mib_path_len, "MIBDIRS=%s\\%s", get_datafile_dir(), MIB_PATH_APPEND);
	/* Amazingly enough, Windows does not provide setenv(). */
	if (getenv("MIBDIRS") == NULL)
		_putenv(mib_path);

#endif	/* _WIN32 */

	/*
	 * Suppress warnings about unknown tokens - we aren't initializing
	 * Net-SNMP in its entirety, we're just initializing the
	 * MIB-handling part because that's all we're using, which
	 * means that entries in the configuration file for other
	 * pars of the library will not be handled, and we don't want
	 * the config file reading code to whine about that.
	 */
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_NO_TOKEN_WARNINGS, TRUE);
	netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
                           NETSNMP_DS_LIB_PRINT_SUFFIX_ONLY, 2);
#endif /* HAVE_NET_SNMP */


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

	/*
	 * Set the default value of "mib_modules".
	 *
	 * If the MIBS environment variable is set, make its value
	 * the value of "mib_modules", otherwise, set "mib_modules"
	 * to DEF_MIB_MODULES.
	 */
	tmp_mib_modules = getenv("MIBS");
	if (tmp_mib_modules != NULL)
		mib_modules = tmp_mib_modules;
	prefs_register_string_preference(snmp_module, "mib_modules",
	    "MIB modules to load",
	    "List of MIB modules to load (the list is set to environment variable MIBS if the variable is not already set)"
	    "The list must be separated by colons (:) on non-Windows systems and semicolons (;) on Windows systems",
	    &mib_modules);
	prefs_register_bool_preference(snmp_module, "desegment",
	    "Reassemble SNMP-over-TCP messages\nspanning multiple TCP segments",
	    "Whether the SNMP dissector should reassemble messages spanning multiple TCP segments."
	    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &snmp_desegment);

  prefs_register_bool_preference(snmp_module, "var_in_tree",
		"Display dissected variables inside SNMP tree",
		"ON - display dissected variables inside SNMP tree, OFF - display dissected variables in root tree after SNMP",
		&snmp_var_in_tree);

  prefs_register_string_preference(snmp_module, "users_file",
								   "USMuserTable",
								   "The filename of the user table used for authentication/decryption",
								   &ue_assocs_filename);
 	  
	variable_oid_dissector_table =
	    register_dissector_table("snmp.variable_oid",
	      "SNMP Variable OID", FT_STRING, BASE_NONE);
}


/*--- proto_reg_handoff_snmp ---------------------------------------*/
void proto_reg_handoff_snmp(void) {
	dissector_handle_t snmp_tcp_handle;

	snmp_handle = find_dissector("snmp");

	dissector_add("udp.port", UDP_PORT_SNMP, snmp_handle);
	dissector_add("udp.port", UDP_PORT_SNMP_TRAP, snmp_handle);
	dissector_add("ethertype", ETHERTYPE_SNMP, snmp_handle);
	dissector_add("ipx.socket", IPX_SOCKET_SNMP_AGENT, snmp_handle);
	dissector_add("ipx.socket", IPX_SOCKET_SNMP_SINK, snmp_handle);
	dissector_add("hpext.dxsap", HPEXT_SNMP, snmp_handle);

	snmp_tcp_handle = create_dissector_handle(dissect_snmp_tcp, proto_snmp);
	dissector_add("tcp.port", TCP_PORT_SNMP, snmp_tcp_handle);
	dissector_add("tcp.port", TCP_PORT_SNMP_TRAP, snmp_tcp_handle);

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
		    0x0, "", HFILL }},
		{ &hf_smux_pdutype,
		{ "PDU type", "smux.pdutype", FT_UINT8, BASE_DEC, VALS(smux_types),
		    0x0, "", HFILL }},
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
	dissector_add("tcp.port", TCP_PORT_SMUX, smux_handle);
}


