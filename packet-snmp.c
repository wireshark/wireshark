/* packet-snmp.c
 * Routines for SNMP (simple network management protocol)
 * D.Jorand (c) 1998
 *
 * See RFC 1157 for SNMPv1.
 *
 * See RFCs 1901, 1905, and 1906 for SNMPv2c.
 *
 * See RFCs 1905, 1906, 1909, and 1910 for SNMPv2u.
 *
 * $Id: packet-snmp.c,v 1.59 2001/01/30 07:16:28 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Didier Jorand
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#define MAX_STRING_LEN 2048	/* TBC */

#ifdef linux
#include <dlfcn.h>
#endif

#include <glib.h>

#include "packet.h"
#include "strutil.h"
#include "conversation.h"
#include "etypes.h"
#include "packet-ipx.h"

#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
 /*
  * UCD or CMU SNMP?
  */
# if defined(HAVE_UCD_SNMP_SNMP_H)
   /*
    * UCD SNMP.
    */
#  include <ucd-snmp/asn1.h>
#  include <ucd-snmp/snmp_api.h>
#  include <ucd-snmp/snmp_impl.h>
#  include <ucd-snmp/mib.h>

   /*
    * Sigh.  UCD SNMP 4.1.1 makes "snmp_set_suffix_only()" a macro
    * that calls "ds_set_int()" with the first two arguments
    * being DS_LIBRARY_ID and DS_LIB_PRINT_SUFFIX_ONLY; this means that,
    * when building with 4.1.1, we need to arrange that
    * <ucd-snmp/default_store.h> is included, to define those two values
    * and to declare "ds_int()".
    *
    * However:
    *
    *	1) we can't include it on earlier versions (at least not 3.6.2),
    *	   as it doesn't exist in those versions;
    *
    *	2) we don't want to include <ucd-snmp/ucd-snmp-includes.h>,
    *	   as that includes <ucd-snmp/snmp.h>, and that defines a whole
    *	   bunch of values that we also define ourselves.
    *
    * So we only include it if "snmp_set_suffix_only" is defined as
    * a macro.
    */
#  ifdef snmp_set_suffix_only
#   include <ucd-snmp/default_store.h>
#  endif

   /*
    * XXX - for now, we assume all versions of UCD SNMP have it.
    */
#  define HAVE_SPRINT_VALUE

   /*
    * Define values "sprint_value()" expects.
    */
#  define VALTYPE_INTEGER	ASN_INTEGER
#  define VALTYPE_COUNTER	ASN_COUNTER
#  define VALTYPE_GAUGE		ASN_GAUGE
#  define VALTYPE_TIMETICKS	ASN_TIMETICKS
#  define VALTYPE_STRING	ASN_OCTET_STR
#  define VALTYPE_IPADDR	ASN_IPADDRESS
#  define VALTYPE_OPAQUE	ASN_OPAQUE
#  define VALTYPE_NSAP		ASN_NSAP
#  define VALTYPE_OBJECTID	ASN_OBJECT_ID
#  define VALTYPE_BITSTR	ASN_BIT_STR
#  define VALTYPE_COUNTER64	ASN_COUNTER64
# elif defined(HAVE_SNMP_SNMP_H)
   /*
    * CMU SNMP.
    */
#  include <snmp/snmp.h>

   /*
    * Some older versions of CMU SNMP may lack these values (e.g., the
    * "libsnmp3.6" package for Debian, which is based on some old
    * CMU SNMP, perhaps 1.0); for now, we assume they also lack
    * "sprint_value()".
    */
#  ifdef SMI_INTEGER
#   define HAVE_SPRINT_VALUE
    /*
     * Define values "sprint_value()" expects.
     */
#   define VALTYPE_INTEGER	SMI_INTEGER
#   define VALTYPE_COUNTER	SMI_COUNTER32
#   define VALTYPE_GAUGE	SMI_GAUGE32
#   define VALTYPE_TIMETICKS	SMI_TIMETICKS
#   define VALTYPE_STRING	SMI_STRING
#   define VALTYPE_IPADDR	SMI_IPADDRESS
#   define VALTYPE_OPAQUE	SMI_OPAQUE
#   define VALTYPE_NSAP		SMI_STRING
#   define VALTYPE_OBJECTID	SMI_OBJID
#   define VALTYPE_BITSTR	ASN_BIT_STR
#   define VALTYPE_COUNTER64	SMI_COUNTER64
#  endif
  /*
   * Now undo all the definitions they "helpfully" gave us, so we don't get
   * complaints about redefining them.
   *
   * Why, oh why, is there no library that provides code to
   *
   *	1) read MIB files;
   *
   *	2) translate object IDs into names;
   *
   *	3) let you find out, for a given object ID, what the type, enum
   *	   values, display hint, etc. are;
   *
   * in a *simple* fashion, without assuming that your code is part of an
   * SNMP agent or client that wants a pile of definitions of PDU types,
   * etc.?  Is it just that 99 44/100% of the code that uses an SNMP library
   * *is* part of an agent or client, and really *does* need that stuff,
   * and *doesn't* need the interfaces we want?
   */
#  undef SNMP_ERR_NOERROR
#  undef SNMP_ERR_TOOBIG
#  undef SNMP_ERR_NOSUCHNAME
#  undef SNMP_ERR_BADVALUE
#  undef SNMP_ERR_READONLY
#  undef SNMP_ERR_NOACCESS
#  undef SNMP_ERR_WRONGTYPE
#  undef SNMP_ERR_WRONGLENGTH
#  undef SNMP_ERR_WRONGENCODING
#  undef SNMP_ERR_WRONGVALUE
#  undef SNMP_ERR_NOCREATION
#  undef SNMP_ERR_INCONSISTENTVALUE
#  undef SNMP_ERR_RESOURCEUNAVAILABLE
#  undef SNMP_ERR_COMMITFAILED
#  undef SNMP_ERR_UNDOFAILED
#  undef SNMP_ERR_AUTHORIZATIONERROR
#  undef SNMP_ERR_NOTWRITABLE
#  undef SNMP_ERR_INCONSISTENTNAME
#  undef SNMP_TRAP_COLDSTART
#  undef SNMP_TRAP_WARMSTART
#  undef SNMP_TRAP_LINKDOWN
#  undef SNMP_TRAP_LINKUP
#  undef SNMP_TRAP_EGPNEIGHBORLOSS
#  undef SNMP_TRAP_ENTERPRISESPECIFIC
# endif
#endif

#include "asn1.h"

#include "packet-snmp.h"

/* Null string of type "guchar[]". */
static const guchar nullstring[] = "";

/* Take a pointer that may be null and return a pointer that's not null
   by turning null pointers into pointers to the above null string. */
#define	SAFE_STRING(s)	(((s) != NULL) ? (s) : nullstring)

static int proto_snmp = -1;
static int proto_smux = -1;

static gint ett_snmp = -1;
static gint ett_smux = -1;
static gint ett_parameters = -1;
static gint ett_parameters_qos = -1;
static gint ett_global = -1;
static gint ett_flags = -1;
static gint ett_secur = -1;

static int hf_snmpv3_flags = -1;
static int hf_snmpv3_flags_auth = -1;
static int hf_snmpv3_flags_crypt = -1;
static int hf_snmpv3_flags_report = -1;

#define TH_AUTH   0x01
#define TH_CRYPT  0x02
#define TH_REPORT 0x04

static const true_false_string flags_set_truth = {
  "Set",
  "Not set"
};

#define UDP_PORT_SNMP		161
#define UDP_PORT_SNMP_TRAP	162
#define TCP_PORT_SMUX		199

/* Protocol version numbers */
#define SNMP_VERSION_1	0
#define SNMP_VERSION_2c	1
#define SNMP_VERSION_2u	2
#define SNMP_VERSION_3	3

static const value_string versions[] = {
	{ SNMP_VERSION_1,	"1" },
	{ SNMP_VERSION_2c,	"2C" },
	{ SNMP_VERSION_2u,	"2U" },
	{ SNMP_VERSION_3,	"3" },
	{ 0,			NULL },
};

/* PDU types */
#define SNMP_MSG_GET		0
#define SNMP_MSG_GETNEXT	1
#define SNMP_MSG_RESPONSE	2
#define SNMP_MSG_SET		3
#define SNMP_MSG_TRAP		4

#define SNMP_MSG_GETBULK	5
#define SNMP_MSG_INFORM		6
#define SNMP_MSG_TRAP2		7
#define SNMP_MSG_REPORT		8

static const value_string pdu_types[] = {
	{ SNMP_MSG_GET,		"GET" },
	{ SNMP_MSG_GETNEXT,	"GET-NEXT" },
	{ SNMP_MSG_SET,		"SET" },
	{ SNMP_MSG_RESPONSE,	"RESPONSE" },
	{ SNMP_MSG_TRAP, 	"TRAP-V1" },
	{ SNMP_MSG_GETBULK, 	"GETBULK" },
	{ SNMP_MSG_INFORM, 	"INFORM" },
	{ SNMP_MSG_TRAP2, 	"TRAP-V2" },
	{ SNMP_MSG_REPORT,	"REPORT" },
	{ 0,			NULL }
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

/* SMUX Closing causes */
#define SMUX_CLOSE_DOWN			0
#define SMUX_CLOSE_VERSION		1
#define SMUX_CLOSE_PACKET		2
#define SMUX_CLOSE_PROTOCOL		3
#define SMUX_CLOSE_INTERNAL		4
#define SMUX_CLOSE_NOAUTH		5

static const value_string smux_close[] = {
	{ SMUX_CLOSE_DOWN,	"Going down" },
	{ SMUX_CLOSE_VERSION,	"Unsupported Version" },
	{ SMUX_CLOSE_PACKET,	"Packet Format Error" },
	{ SMUX_CLOSE_PROTOCOL,	"Protocol Error" },
	{ SMUX_CLOSE_INTERNAL,	"Internal Error" },
	{ SMUX_CLOSE_NOAUTH,	"Unauthorized" },
	{ 0,			NULL }
};

/* SMUX Request codes */
#define SMUX_RREQ_DELETE		0
#define SMUX_RREQ_READONLY		1
#define SMUX_RREQ_READWRITE		2

static const value_string smux_rreq[] = {
	{ SMUX_RREQ_DELETE,	"Delete" },
	{ SMUX_RREQ_READONLY,	"Read Only" },
	{ SMUX_RREQ_READWRITE,	"Read Write" },
	{ 0,			NULL }
};

static const value_string smux_prio[] = {
	{ -1,				"Failure" },
	{ 0,				NULL }
};

/* SMUX SOut codes */
#define SMUX_SOUT_COMMIT		0
#define SMUX_SOUT_ROLLBACK		1

static const value_string smux_sout[] = {
	{ SMUX_SOUT_COMMIT,		"Commit" },
	{ SMUX_SOUT_ROLLBACK,		"Rollback" },
	{ 0,			        NULL }
};

/* Error status values */
#define SNMP_ERR_NOERROR		0
#define SNMP_ERR_TOOBIG			1
#define SNMP_ERR_NOSUCHNAME		2
#define SNMP_ERR_BADVALUE		3
#define SNMP_ERR_READONLY		4
#define SNMP_ERR_GENERROR		5

#define SNMP_ERR_NOACCESS		6
#define SNMP_ERR_WRONGTYPE		7
#define SNMP_ERR_WRONGLENGTH		8
#define SNMP_ERR_WRONGENCODING		9
#define SNMP_ERR_WRONGVALUE		10
#define SNMP_ERR_NOCREATION		11
#define SNMP_ERR_INCONSISTENTVALUE	12
#define SNMP_ERR_RESOURCEUNAVAILABLE	13
#define SNMP_ERR_COMMITFAILED		14
#define SNMP_ERR_UNDOFAILED		15
#define SNMP_ERR_AUTHORIZATIONERROR	16
#define SNMP_ERR_NOTWRITABLE		17
#define SNMP_ERR_INCONSISTENTNAME	18

static const value_string error_statuses[] = {
	{ SNMP_ERR_NOERROR,		"NO ERROR" },
	{ SNMP_ERR_TOOBIG,		"TOOBIG" },
	{ SNMP_ERR_NOSUCHNAME,		"NO SUCH NAME" },
	{ SNMP_ERR_BADVALUE,		"BAD VALUE" },
	{ SNMP_ERR_READONLY,		"READ ONLY" },
	{ SNMP_ERR_GENERROR,		"GENERIC ERROR" },
	{ SNMP_ERR_NOACCESS,		"NO ACCESS" },
	{ SNMP_ERR_WRONGTYPE,		"WRONG TYPE" },
	{ SNMP_ERR_WRONGLENGTH,		"WRONG LENGTH" },
	{ SNMP_ERR_WRONGENCODING,	"WRONG ENCODING" },
	{ SNMP_ERR_WRONGVALUE,		"WRONG VALUE" },
	{ SNMP_ERR_NOCREATION,		"NO CREATION" },
	{ SNMP_ERR_INCONSISTENTVALUE,	"INCONSISTENT VALUE" },
	{ SNMP_ERR_RESOURCEUNAVAILABLE,	"RESOURCE UNAVAILABLE" },
	{ SNMP_ERR_COMMITFAILED,	"COMMIT FAILED" },
	{ SNMP_ERR_UNDOFAILED,		"UNDO FAILED" },
	{ SNMP_ERR_AUTHORIZATIONERROR,	"AUTHORIZATION ERROR" },
	{ SNMP_ERR_NOTWRITABLE,		"NOT WRITABLE" },
	{ SNMP_ERR_INCONSISTENTNAME,	"INCONSISTENT NAME" },
	{ 0,				NULL }
};

/* General SNMP V1 Traps */

#define SNMP_TRAP_COLDSTART		0
#define SNMP_TRAP_WARMSTART		1
#define SNMP_TRAP_LINKDOWN		2
#define SNMP_TRAP_LINKUP		3
#define SNMP_TRAP_AUTHFAIL		4
#define SNMP_TRAP_EGPNEIGHBORLOSS	5
#define SNMP_TRAP_ENTERPRISESPECIFIC	6

static const value_string trap_types[] = {
	{ SNMP_TRAP_COLDSTART,		"COLD START" },
	{ SNMP_TRAP_WARMSTART,		"WARM START" },
	{ SNMP_TRAP_LINKDOWN,		"LINK DOWN" },
	{ SNMP_TRAP_LINKUP,		"LINK UP" },
	{ SNMP_TRAP_AUTHFAIL,		"AUTHENTICATION FAILED" },
	{ SNMP_TRAP_EGPNEIGHBORLOSS,	"EGP NEIGHBORLOSS" },
	{ SNMP_TRAP_ENTERPRISESPECIFIC,	"ENTERPRISE SPECIFIC" },
	{ 0,				NULL }
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
  gchar *name;
};

static SNMP_CNV SnmpCnv [] =
{
  {ASN1_UNI, ASN1_NUL, SNMP_NULL,      "NULL"},
  {ASN1_UNI, ASN1_INT, SNMP_INTEGER,   "INTEGER"},
  {ASN1_UNI, ASN1_OTS, SNMP_OCTETSTR,  "OCTET STRING"},
  {ASN1_UNI, ASN1_OJI, SNMP_OBJECTID,  "OBJECTID"},
  {ASN1_APL, SNMP_IPA, SNMP_IPADDR,    "IPADDR"},
  {ASN1_APL, SNMP_CNT, SNMP_COUNTER,   "COUNTER"},  /* Counter32 */
  {ASN1_APL, SNMP_GGE, SNMP_GAUGE,     "GAUGE"},    /* Gauge32 == Unsigned32  */
  {ASN1_APL, SNMP_TIT, SNMP_TIMETICKS, "TIMETICKS"},
  {ASN1_APL, SNMP_OPQ, SNMP_OPAQUE,    "OPAQUE"},

/* SNMPv2 data types and errors */

  {ASN1_UNI, ASN1_BTS, SNMP_BITSTR,         "BITSTR"},
  {ASN1_APL, SNMP_C64, SNMP_COUNTER64,      "COUNTER64"},
  {ASN1_CTX, SERR_NSO, SNMP_NOSUCHOBJECT,   "NOSUCHOBJECT"},
  {ASN1_CTX, SERR_NSI, SNMP_NOSUCHINSTANCE, "NOSUCHINSTANCE"},
  {ASN1_CTX, SERR_EOM, SNMP_ENDOFMIBVIEW,   "ENDOFMIBVIEW"},
  {0,       0,         -1,                  NULL}
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

static gchar *
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

static void
dissect_snmp_parse_error(const u_char *pd, int offset, frame_data *fd,
		   proto_tree *tree, const char *field_name, int ret)
{
	const gchar *errstr;

	if (check_col(fd, COL_INFO)) {
		switch (ret) {

		case ASN1_ERR_EMPTY:
			errstr = "Ran out of data";
			break;

		case ASN1_ERR_EOC_MISMATCH:
			errstr = "EOC mismatch";
			break;

		case ASN1_ERR_WRONG_TYPE:
			errstr = "Wrong type for that item";
			break;

		case ASN1_ERR_LENGTH_NOT_DEFINITE:
			errstr = "Length was indefinite";
			break;

		case ASN1_ERR_LENGTH_MISMATCH:
			errstr = "Length mismatch";
			break;

		case ASN1_ERR_WRONG_LENGTH_FOR_TYPE:
			errstr = "Wrong length for that item's type";
			break;

		default:
			errstr = "Unknown error";
			break;
		}
		col_add_fstr(fd, COL_INFO,
		    "ERROR: Couldn't parse %s: %s", field_name, errstr);
	}

	old_dissect_data(pd, offset, fd, tree);
}

static void
dissect_snmp_error(const u_char *pd, int offset, frame_data *fd,
		   proto_tree *tree, const char *message)
{
	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, message);

	old_dissect_data(pd, offset, fd, tree);
}

static gchar *
format_oid(subid_t *oid, guint oid_length)
{
	char *result;
	int result_len;
	int len, i;
	char *buf;

	result_len = oid_length * 22;
	result = g_malloc(result_len + 1);
	buf = result;
	len = sprintf(buf, "%lu", (unsigned long)oid[0]);
	buf += len;
	for (i = 1; i < oid_length;i++) {
		len = sprintf(buf, ".%lu", (unsigned long)oid[i]);
		buf += len;
	}
	return result;
}

#ifdef HAVE_SPRINT_VALUE
static gchar *
format_var(struct variable_list *variable, subid_t *variable_oid,
    guint variable_oid_length, gushort vb_type, guint vb_length)
{
	gchar *buf;

	switch (vb_type) {

	case SNMP_INTEGER:
	case SNMP_COUNTER:
	case SNMP_GAUGE:
	case SNMP_TIMETICKS:
		/* We don't know how long this will be, but let's guess it
		   fits within 128 characters; that should be enough for an
		   integral value plus some sort of type indication. */
		buf = g_malloc(128);
		break;

	case SNMP_OCTETSTR:
	case SNMP_IPADDR:
	case SNMP_OPAQUE:
	case SNMP_NSAP:
	case SNMP_BITSTR:
	case SNMP_COUNTER64:
		/* We don't know how long this will be, but let's guess it
		   fits within 128 characters plus 4 characters per octet. */
		buf = g_malloc(128 + 4*vb_length);
		break;

	case SNMP_OBJECTID:
		/* We don't know how long this will be, but let's guess it
		   fits within 128 characters plus 32 characters per subid
		   (10 digits plus period, or a subid name). */
		buf = g_malloc(1024 + 32*vb_length);
		break;

	default:
		/* Should not happen. */
		g_assert_not_reached();
		buf = NULL;
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
		vb_length *= sizeof (subid_t);	/* XXX - necessary? */
		break;

	case SNMP_BITSTR:
		variable->type = VALTYPE_BITSTR;
		break;

	case SNMP_COUNTER64:
		variable->type = VALTYPE_COUNTER64;
		break;
	}
	variable->val_len = vb_length;

	sprint_value(buf, variable_oid, variable_oid_length, variable);
	return buf;
}
#endif

static int
snmp_variable_decode(proto_tree *snmp_tree, subid_t *variable_oid,
    guint variable_oid_length, ASN1_SCK *asn1, int offset, guint *lengthp,
    gboolean unsafe)
{
	const guchar *start;
	guint length;
	gboolean def;
	guint vb_length;
	gushort vb_type;
	gchar *vb_type_name;
	int ret;
	guint cls, con, tag;

	gint32 vb_integer_value;
	guint32 vb_uinteger_value;

	guint8 *vb_octet_string;

	subid_t *vb_oid;
	guint vb_oid_length;

	gchar *vb_display_string;

#ifdef HAVE_SPRINT_VALUE
	struct variable_list variable;
#if defined(HAVE_UCD_SNMP_SNMP_H)
	long value;
#endif
#endif	/* HAVE_SPRINT_VALUE */
	int i;
	gchar *buf;
	int len;

	/* parse the type of the object */
	start = asn1->pointer;
	ret = asn1_header_decode (asn1, &cls, &con, &tag, &def, &vb_length);
	if (ret != ASN1_ERR_NOERROR)
		return ret;
	if (!def)
		return ASN1_ERR_LENGTH_NOT_DEFINITE;

	/* Convert the class, constructed flag, and tag to a type. */
	vb_type_name = snmp_tag_cls2syntax(tag, cls, &vb_type);
	if (vb_type_name == NULL) {
		/*
		 * Unsupported type.
		 * Dissect the value as an opaque string of octets.
		 */
		vb_type_name = "unsupported type";
		vb_type = SNMP_OPAQUE;
	}

	/* parse the value */
	switch (vb_type) {

	case SNMP_INTEGER:
		ret = asn1_int32_value_decode(asn1, vb_length,
		    &vb_integer_value);
		if (ret != ASN1_ERR_NOERROR)
			return ret;
		length = asn1->pointer - start;
		if (snmp_tree) {
#ifdef HAVE_SPRINT_VALUE
			if (!unsafe) {
#if defined(HAVE_UCD_SNMP_SNMP_H)
				value = vb_integer_value;
				variable.val.integer = &value;
#elif defined(HAVE_SNMP_SNMP_H)
				variable.val.integer = &vb_integer_value;
#endif
				vb_display_string = format_var(&variable,
				    variable_oid, variable_oid_length, vb_type,
				    vb_length);
				proto_tree_add_text(snmp_tree, NullTVB, offset,
				    length,
				    "Value: %s", vb_display_string);
				g_free(vb_display_string);
				break;	/* we added formatted version to the tree */
			}
#endif /* HAVE_SPRINT_VALUE */
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Value: %s: %d (%#x)", vb_type_name,
			    vb_integer_value, vb_integer_value);
		}
		break;

	case SNMP_COUNTER:
	case SNMP_GAUGE:
	case SNMP_TIMETICKS:
		ret = asn1_uint32_value_decode(asn1, vb_length,
		    &vb_uinteger_value);
		if (ret != ASN1_ERR_NOERROR)
			return ret;
		length = asn1->pointer - start;
		if (snmp_tree) {
#ifdef HAVE_SPRINT_VALUE
			if (!unsafe) {
#if defined(HAVE_UCD_SNMP_SNMP_H)
				value = vb_uinteger_value;
				variable.val.integer = &value;
#elif defined(HAVE_SNMP_SNMP_H)
				variable.val.integer = &vb_uinteger_value;
#endif
				vb_display_string = format_var(&variable,
				    variable_oid, variable_oid_length, vb_type,
				    vb_length);
				proto_tree_add_text(snmp_tree, NullTVB, offset,
				    length,
				    "Value: %s", vb_display_string);
				g_free(vb_display_string);
				break;	/* we added formatted version to the tree */
			}
#endif /* HAVE_SPRINT_VALUE */
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Value: %s: %u (%#x)", vb_type_name,
			    vb_uinteger_value, vb_uinteger_value);
		}
		break;

	case SNMP_OCTETSTR:
	case SNMP_IPADDR:
	case SNMP_OPAQUE:
	case SNMP_NSAP:
	case SNMP_BITSTR:
	case SNMP_COUNTER64:
		ret = asn1_string_value_decode (asn1, vb_length,
		    &vb_octet_string);
		if (ret != ASN1_ERR_NOERROR)
			return ret;
		length = asn1->pointer - start;
		if (snmp_tree) {
#ifdef HAVE_SPRINT_VALUE
			if (!unsafe) {
				variable.val.string = vb_octet_string;
				vb_display_string = format_var(&variable,
				    variable_oid, variable_oid_length, vb_type,
				    vb_length);
				proto_tree_add_text(snmp_tree, NullTVB, offset,
				    length,
				    "Value: %s", vb_display_string);
				g_free(vb_display_string);
				break;	/* we added formatted version to the tree */
			}
#endif /* HAVE_SPRINT_VALUE */
			/*
			 * If some characters are not printable, display
			 * the string as bytes.
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
				vb_display_string = g_malloc(4*vb_length);
				buf = &vb_display_string[0];
				len = sprintf(buf, "%03u", vb_octet_string[0]);
				buf += len;
				for (i = 1; i < vb_length; i++) {
					len = sprintf(buf, ".%03u",
					    vb_octet_string[i]);
					buf += len;
				}
				proto_tree_add_text(snmp_tree, NullTVB, offset, length,
				    "Value: %s: %s", vb_type_name,
				    vb_display_string);
				g_free(vb_display_string);
			} else {
				proto_tree_add_text(snmp_tree, NullTVB, offset, length,
				    "Value: %s: %.*s", vb_type_name,
				    (int)vb_length, vb_octet_string);
			}
		}
		g_free(vb_octet_string);
		break;

	case SNMP_NULL:
		ret = asn1_null_decode (asn1, vb_length);
		if (ret != ASN1_ERR_NOERROR)
			return ret;
		length = asn1->pointer - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Value: %s", vb_type_name);
		}
		break;

	case SNMP_OBJECTID:
		ret = asn1_oid_value_decode (asn1, vb_length, &vb_oid,
		    &vb_oid_length);
		if (ret != ASN1_ERR_NOERROR)
			return ret;
		length = asn1->pointer - start;
		if (snmp_tree) {
#ifdef HAVE_SPRINT_VALUE
			if (!unsafe) {
				variable.val.objid = vb_oid;
				vb_display_string = format_var(&variable,
				    variable_oid, variable_oid_length, vb_type,
				    vb_length);
				proto_tree_add_text(snmp_tree, NullTVB, offset,
				    length,
				    "Value: %s", vb_display_string);
				break;	/* we added formatted version to the tree */
			}
#endif /* HAVE_SPRINT_VALUE */
			vb_display_string = format_oid(vb_oid, vb_oid_length);
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Value: %s: %s", vb_type_name, vb_display_string);
			g_free(vb_display_string);
		}
		g_free(vb_oid);
		break;

	case SNMP_NOSUCHOBJECT:
		length = asn1->pointer - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Value: %s: no such object", vb_type_name);
		}
		break;

	case SNMP_NOSUCHINSTANCE:
		length = asn1->pointer - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Value: %s: no such instance", vb_type_name);
		}
		break;

	case SNMP_ENDOFMIBVIEW:
		length = asn1->pointer - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Value: %s: end of mib view", vb_type_name);
		}
		break;

	default:
		g_assert_not_reached();
		return ASN1_ERR_WRONG_TYPE;
	}
	*lengthp = length;
	return ASN1_ERR_NOERROR;
}

static void
dissect_common_pdu(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree, ASN1_SCK asn1, guint pdu_type, const guchar *start)
{
	gboolean def;
	guint length;
	guint sequence_length;

	guint32 request_id;

	guint32 error_status;

	guint32 error_index;

	char *pdu_type_string;

	subid_t *enterprise;
	guint enterprise_length;

	guint8 *agent_address;
	guint agent_address_length;

	guint32 trap_type;

	guint32 specific_type;

	guint timestamp;
	guint timestamp_length;

	gchar *oid_string;

	guint variable_bindings_length;

	int vb_index;
	guint variable_length;
	subid_t *variable_oid;
	guint variable_oid_length;
#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
	gchar vb_oid_string[MAX_STRING_LEN]; /* TBC */
#endif
	gboolean unsafe;

	int ret;
	guint cls, con, tag;

	pdu_type_string = val_to_str(pdu_type, pdu_types,
	    "Unknown PDU type %#x");
	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, pdu_type_string);
	length = asn1.pointer - start;
	if (tree) {
		proto_tree_add_text(tree, NullTVB, offset, length,
		    "PDU type: %s", pdu_type_string);
	}
	offset += length;

	/* get the fields in the PDU preceeding the variable-bindings sequence */
	switch (pdu_type) {

	case SNMP_MSG_GET:
	case SNMP_MSG_GETNEXT:
	case SNMP_MSG_RESPONSE:
	case SNMP_MSG_SET:
	case SNMP_MSG_GETBULK:
	case SNMP_MSG_INFORM:
	case SNMP_MSG_TRAP2:
	case SNMP_MSG_REPORT:
		/* request id */
		ret = asn1_uint32_decode (&asn1, &request_id, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "request ID", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Request Id: %#x", request_id);
		}
		offset += length;
		
		/* error status, or getbulk non-repeaters */
		ret = asn1_uint32_decode (&asn1, &error_status, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    (pdu_type == SNMP_MSG_GETBULK) ? "non-repeaters"
			    				   : "error status",
			    ret);
			return;
		}
		if (tree) {
			if (pdu_type == SNMP_MSG_GETBULK) {
				proto_tree_add_text(tree, NullTVB, offset,
				    length, "Non-repeaters: %u", error_status);
			} else {
				proto_tree_add_text(tree, NullTVB, offset,
				    length, "Error Status: %s",
				    val_to_str(error_status, error_statuses,
				      "Unknown (%d)"));
			}
		}
		offset += length;

		/* error index, or getbulk max-repetitions */
		ret = asn1_uint32_decode (&asn1, &error_index, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    (pdu_type == SNMP_MSG_GETBULK) ? "max repetitions"
			    				   : "error index",
			    ret);
			return;
		}
		if (tree) {
			if (pdu_type == SNMP_MSG_GETBULK) {
				proto_tree_add_text(tree, NullTVB, offset,
				    length, "Max repetitions: %u", error_index);
			} else {
				proto_tree_add_text(tree, NullTVB, offset,
				    length, "Error Index: %u", error_index);
			}
		}
		offset += length;
		break;

	case SNMP_MSG_TRAP:
		/* enterprise */
		ret = asn1_oid_decode (&asn1, &enterprise, &enterprise_length,
		    &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "enterprise OID", ret);
			return;
		}
		if (tree) {
			oid_string = format_oid(enterprise, enterprise_length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Enterprise: %s", oid_string);
			g_free(oid_string);
		}
		g_free(enterprise);
		offset += length;

		/* agent address */
		start = asn1.pointer;
		ret = asn1_header_decode (&asn1, &cls, &con, &tag,
		    &def, &agent_address_length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "agent address", ret);
			return;
		}
		if (!((cls == ASN1_APL && con == ASN1_PRI && tag == SNMP_IPA) ||
		    (cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_OTS))) {
			/* GXSNMP 0.0.15 says the latter is "needed for
			   Banyan" */
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "agent_address", ASN1_ERR_WRONG_TYPE);
			return;
		}
		if (agent_address_length != 4) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "agent_address", ASN1_ERR_WRONG_LENGTH_FOR_TYPE);
			return;
		}
		ret = asn1_string_value_decode (&asn1,
		    agent_address_length, &agent_address);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "agent address", ret);
			return;
		}
		length = asn1.pointer - start;
		if (tree) {
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Agent address: %s", ip_to_str(agent_address));
		}
		g_free(agent_address);
		offset += length;
		
	        /* generic trap type */
		ret = asn1_uint32_decode (&asn1, &trap_type, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "generic trap type", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Trap type: %s",
			    val_to_str(trap_type, trap_types, "Unknown (%u)"));
		}		
		offset += length;
		
	        /* specific trap type */
		ret = asn1_uint32_decode (&asn1, &specific_type, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "specific trap type", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Specific trap type: %u (%#x)",
			    specific_type, specific_type);
		}		
		offset += length;
		
	        /* timestamp */
		start = asn1.pointer;
		ret = asn1_header_decode (&asn1, &cls, &con, &tag,
		    &def, &timestamp_length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "timestamp", ret);
			return;
		}
		if (!((cls == ASN1_APL && con == ASN1_PRI && tag == SNMP_TIT) ||
		    (cls == ASN1_UNI && con == ASN1_PRI && tag == ASN1_INT))) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "timestamp", ASN1_ERR_WRONG_TYPE);
			return;
		}
		ret = asn1_uint32_value_decode(&asn1, timestamp_length,
		    &timestamp);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "timestamp", ret);
			return;
		}
		length = asn1.pointer - start;
		if (tree) {
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Timestamp: %u", timestamp);
		}		
		offset += length;
		break;
	}

	/* variable bindings */
	/* get header for variable-bindings sequence */
	ret = asn1_sequence_decode(&asn1, &variable_bindings_length, &length);
	if (ret != ASN1_ERR_NOERROR) {
		dissect_snmp_parse_error(pd, offset, fd, tree,
			"variable bindings header", ret);
		return;
	}
	offset += length;

	/* loop on variable bindings */
	vb_index = 0;
	while (variable_bindings_length > 0) {
		vb_index++;
		sequence_length = 0;

		/* parse type */
		ret = asn1_sequence_decode(&asn1, &variable_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
				"variable binding header", ret);
			return;
		}
		sequence_length += length;

		/* parse object identifier */
		ret = asn1_oid_decode (&asn1, &variable_oid,
		    &variable_oid_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "variable binding OID", ret);
			return;
		}
		sequence_length += length;

		unsafe = FALSE;
		if (tree) {
			oid_string = format_oid(variable_oid,
			    variable_oid_length);
			
#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
			sprint_objid(vb_oid_string, variable_oid,
			    variable_oid_length);
			proto_tree_add_text(tree, NullTVB, offset, sequence_length,
			    "Object identifier %d: %s (%s)", vb_index,
			    oid_string, vb_oid_string);
#ifdef HAVE_SNMP_SNMP_H
			/*
			 * CMU SNMP has a bug wherein "sprint_value()"
			 * calls "get_symbol()", passing it the
			 * OID supplied, to get an information about the
			 * variable, and blithely assumes that it will
			 * never get a null pointer back and dereferences
			 * the resulting pointer.
			 *
			 * Not true.  If there's nothing in the MIB
			 * about *any* of the components of the OID,
			 * it'll return a null pointer.
			 *
			 * So we have to check for that, and pass
			 * down to "snmp_variable_decode" a flag
			 * saying "don't pass this to 'sprint_value()'.
			 *
			 * We check for that by looking for a decoded
			 * OID string beginning with "." followed by a
			 * digit, meaning it couldn't even find any
			 * symbolic representation for the very
			 * beginning of the OID string.
			 */
			if (vb_oid_string[0] == '.' &&
			    isdigit((guchar)vb_oid_string[1]))
				unsafe = TRUE;
#endif /* HAVE_SNMP_SNMP_H */
#else /* defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H) */
			proto_tree_add_text(tree, NullTVB, offset, sequence_length,
			    "Object identifier %d: %s", vb_index,
			    oid_string);
#endif /* defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H) */
			g_free(oid_string);
		}
		offset += sequence_length;
		variable_bindings_length -= sequence_length;
				
		/* Parse the variable's value */
		ret = snmp_variable_decode(tree, variable_oid,
		    variable_oid_length, &asn1, offset, &length,
		    unsafe);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "variable", ret);
			return;
		}
		offset += length;
		variable_bindings_length -= length;
	}
}

static const value_string qos_vals[] = {
	{ 0x0,	"No authentication or privacy" },
	{ 0x1,	"Authentication, no privacy" },
	{ 0x2,	"Authentication and privacy" },
	{ 0x3,	"Authentication and privacy" },
	{ 0,	NULL },
};

static void
dissect_snmp2u_parameters(proto_tree *tree, int offset, int length,
    guchar *parameters, int parameters_length)
{
	proto_item *item;
	proto_tree *parameters_tree;
	proto_tree *qos_tree;
	guint8 model;
	guint8 qos;
	guint8 len;

	item = proto_tree_add_text(tree, NullTVB, offset, length,
	    "Parameters");
	parameters_tree = proto_item_add_subtree(item, ett_parameters);
	offset += length - parameters_length;

	if (parameters_length < 1)
		return;
	model = *parameters;
	proto_tree_add_text(parameters_tree, NullTVB, offset, 1,
	    "model: %u", model);
	offset += 1;
	parameters += 1;
	parameters_length -= 1;
	if (model != 1) {
		/* Unknown model. */
		proto_tree_add_text(parameters_tree, NullTVB, offset,
		    parameters_length, "parameters: %s",
		    bytes_to_str(parameters, parameters_length));
		return;
	}

	if (parameters_length < 1)
		return;
	qos = *parameters;
	item = proto_tree_add_text(parameters_tree, NullTVB, offset, 1,
	    "qoS: 0x%x", qos);
	qos_tree = proto_item_add_subtree(item, ett_parameters_qos);
	proto_tree_add_text(qos_tree, NullTVB, offset, 1, "%s",
	    decode_boolean_bitfield(qos, 0x04,
		8, "Generation of report PDU allowed",
		   "Generation of report PDU not allowed"));
	proto_tree_add_text(qos_tree, NullTVB, offset, 1, "%s",
	    decode_enumerated_bitfield(qos, 0x03,
		8, qos_vals, "%s"));
	offset += 1;
	parameters += 1;
	parameters_length -= 1;

	if (parameters_length < 12)
		return;
	proto_tree_add_text(parameters_tree, NullTVB, offset, 12,
	    "agentID: %s", bytes_to_str(parameters, 12));
	offset += 12;
	parameters += 12;
	parameters_length -= 12;

	if (parameters_length < 4)
		return;
	proto_tree_add_text(parameters_tree, NullTVB, offset, 4,
	    "agentBoots: %u", pntohl(parameters));
	offset += 4;
	parameters += 4;
	parameters_length -= 4;

	if (parameters_length < 4)
		return;
	proto_tree_add_text(parameters_tree, NullTVB, offset, 4,
	    "agentTime: %u", pntohl(parameters));
	offset += 4;
	parameters += 4;
	parameters_length -= 4;

	if (parameters_length < 2)
		return;
	proto_tree_add_text(parameters_tree, NullTVB, offset, 2,
	    "maxSize: %u", pntohs(parameters));
	offset += 2;
	parameters += 2;
	parameters_length -= 2;

	if (parameters_length < 1)
		return;
	len = *parameters;
	proto_tree_add_text(parameters_tree, NullTVB, offset, 1,
	    "userLen: %u", len);
	offset += 1;
	parameters += 1;
	parameters_length -= 1;

	if (parameters_length < len)
		return;
	proto_tree_add_text(parameters_tree, NullTVB, offset, len,
	    "userName: %.*s", len, parameters);
	offset += len;
	parameters += len;
	parameters_length -= len;

	if (parameters_length < 1)
		return;
	len = *parameters;
	proto_tree_add_text(parameters_tree, NullTVB, offset, 1,
	    "authLen: %u", len);
	offset += 1;
	parameters += 1;
	parameters_length -= 1;

	if (parameters_length < len)
		return;
	proto_tree_add_text(parameters_tree, NullTVB, offset, len,
	    "authDigest: %s", bytes_to_str(parameters, len));
	offset += len;
	parameters += len;
	parameters_length -= len;

	if (parameters_length < 1)
		return;
	proto_tree_add_text(parameters_tree, NullTVB, offset, parameters_length,
	    "contextSelector: %s", bytes_to_str(parameters, parameters_length));
}

void
dissect_snmp_pdu(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree, char *proto_name, int proto, gint ett)
{
	ASN1_SCK asn1;
	const guchar *start;
	gboolean def;
	gboolean encrypted;
	guint length;
	guint message_length;
	guint global_length;

	guint32 version;
	guint32 msgid;
	guint32 msgmax;
	guint32 msgsec;
	guint32 engineboots;
	guint32 enginetime;

	guchar *msgflags;
	guchar *community;
	guchar *secparm;
	guchar *cengineid;
	guchar *cname;
	guchar *cryptpdu;
	guchar *aengineid;
	guchar *username;
	guchar *authpar;
	guchar *privpar;
	int msgflags_length;
	int community_length;
	int secparm_length;
	int cengineid_length;
	int cname_length;
	int cryptpdu_length;
	int aengineid_length;
	int username_length;
	int authpar_length;
	int privpar_length;

	guint pdu_type;
	guint pdu_length;

	proto_tree *snmp_tree = NULL;
	proto_tree *global_tree = NULL;
	proto_tree *flags_tree = NULL;
	proto_tree *secur_tree = NULL;
	proto_item *item = NULL;
	int ret;
	guint cls, con, tag;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, proto_name);

	if (tree) {
		item = proto_tree_add_item(tree, proto, NullTVB, offset,
		    END_OF_FRAME, FALSE);
		snmp_tree = proto_item_add_subtree(item, ett);
	}

	/* NOTE: we have to parse the message piece by piece, since the
	 * capture length may be less than the message length: a 'global'
	 * parsing is likely to fail.
	 */
	/* parse the SNMP header */
	asn1_open(&asn1, &pd[offset], END_OF_FRAME);
	ret = asn1_sequence_decode(&asn1, &message_length, &length);
	if (ret != ASN1_ERR_NOERROR) {
		dissect_snmp_parse_error(pd, offset, fd, tree,
			"message header", ret);
		return;
	}
	offset += length;

	ret = asn1_uint32_decode (&asn1, &version, &length);
	if (ret != ASN1_ERR_NOERROR) {
		dissect_snmp_parse_error(pd, offset, fd, tree, "version number",
		    ret);
		return;
	}
	if (snmp_tree) {
		proto_tree_add_text(snmp_tree, NullTVB, offset, length,
		    "Version: %s",
		    val_to_str(version, versions, "Unknown version %#x"));
	}
	offset += length;


	switch (version) {
	case SNMP_VERSION_1:
	case SNMP_VERSION_2c:
		ret = asn1_octet_string_decode (&asn1, &community, 
		    &community_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree, 
			    "community", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Community: %.*s", community_length,
			    SAFE_STRING(community));
		}
		g_free(community);
		offset += length;
		break;
	case SNMP_VERSION_2u:
		ret = asn1_octet_string_decode (&asn1, &community, 
		    &community_length, &length);
		if (tree) {
			dissect_snmp2u_parameters(snmp_tree, offset, length,
			    community, community_length);
		}
		g_free(community);
		offset += length;
		break;
	case SNMP_VERSION_3:
		ret = asn1_sequence_decode(&asn1, &global_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
				"message global header", ret);
			return;
		}
		if (snmp_tree) {
			item = proto_tree_add_text(snmp_tree, NullTVB, offset,
			    global_length + length, "Message Global Header");
			global_tree = proto_item_add_subtree(item, ett_global);
			proto_tree_add_text(global_tree, NullTVB, offset,
		 	    length,
			    "Message Global Header Length: %d", global_length);
		}
		offset += length;
		ret = asn1_uint32_decode (&asn1, &msgid, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree, 
			    "message id", ret);
			return;
		}
		if (global_tree) {
			proto_tree_add_text(global_tree, NullTVB, offset,
			    length, "Message ID: %d", msgid);
		}
		offset += length;
		ret = asn1_uint32_decode (&asn1, &msgmax, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree, 
			    "message max size", ret);
			return;
		}
		if (global_tree) {
			proto_tree_add_text(global_tree, NullTVB, offset,
			    length, "Message Max Size: %d", msgmax);
		}
		offset += length;
		ret = asn1_octet_string_decode (&asn1, &msgflags, 
		    &msgflags_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree, 
			    "message flags", ret);
			return;
		}
		if (msgflags_length != 1) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "message flags wrong length", ret);
			g_free(msgflags);
			return;
		}
		if (global_tree) {
			item = proto_tree_add_uint_format(global_tree,
			    hf_snmpv3_flags, NullTVB, offset, length,
			    msgflags[0], "Flags: 0x%02x", msgflags[0]);
			flags_tree = proto_item_add_subtree(item, ett_flags);
			proto_tree_add_boolean(flags_tree, hf_snmpv3_flags_report,
			    NullTVB, offset, length, msgflags[0]);
			proto_tree_add_boolean(flags_tree, hf_snmpv3_flags_crypt,
			    NullTVB, offset, length, msgflags[0]);
			proto_tree_add_boolean(flags_tree, hf_snmpv3_flags_auth,
			    NullTVB, offset, length, msgflags[0]);
		}
		encrypted = msgflags[0] & TH_CRYPT;
		g_free(msgflags);
		offset += length;
		ret = asn1_uint32_decode (&asn1, &msgsec, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree, 
			    "message security model", ret);
			return;
		}
		if (global_tree) {
			proto_tree_add_text(global_tree, NullTVB, offset,
			    length, "Message Security Model: %s",
			    val_to_str(msgsec, sec_models,
			    "Unknown model %#x"));
		}
		offset += length;
		switch(msgsec) {
		case SNMP_SEC_USM:
			start = asn1.pointer;
			ret = asn1_header_decode (&asn1, &cls, &con, &tag,
			    &def, &secparm_length);
			length = asn1.pointer - start;
			if (cls != ASN1_UNI && con != ASN1_PRI && 
			    tag != ASN1_OTS) {
				dissect_snmp_parse_error(pd, offset, fd, tree, 
				    "Message Security Parameters",
				    ASN1_ERR_WRONG_TYPE);
				return;
			}
			if (snmp_tree) {
				item = proto_tree_add_text(snmp_tree, NullTVB,
				    offset, secparm_length + length,
				    "Message Security Parameters");
				secur_tree = proto_item_add_subtree(item,
				    ett_secur);
				proto_tree_add_text(secur_tree, NullTVB, offset,
			 	    length, 
				    "Message Security Parameters Length: %d",
				    secparm_length);
			}
			offset += length;
			ret = asn1_sequence_decode(&asn1, &secparm_length,
			    &length);
			if (ret != ASN1_ERR_NOERROR) {
				dissect_snmp_parse_error(pd, offset, fd, tree,
				    "USM sequence header", ret);
				return;
			}
			offset += length;
			ret = asn1_octet_string_decode (&asn1, &aengineid, 
			    &aengineid_length, &length);
			if (ret != ASN1_ERR_NOERROR) {
				dissect_snmp_parse_error(pd, offset, fd, tree, 
				    "authoritative engine id", ret);
				return;
			}
			if (secur_tree) {
				proto_tree_add_text(secur_tree, NullTVB, offset,
				    length, "Authoritative Engine ID: %s",
				    bytes_to_str(aengineid, aengineid_length));
			}
			g_free(aengineid);
			offset += length;
			ret = asn1_uint32_decode (&asn1, &engineboots, &length);
			if (ret != ASN1_ERR_NOERROR) {
				dissect_snmp_parse_error(pd, offset, fd, tree, 
				    "engine boots", ret);
				return;
			}
			if (secur_tree) {
				proto_tree_add_text(secur_tree, NullTVB,
				    offset, length, "Engine Boots: %d", 
				    engineboots);
			}
			offset += length;
			ret = asn1_uint32_decode (&asn1, &enginetime, &length);
			if (ret != ASN1_ERR_NOERROR) {
				dissect_snmp_parse_error(pd, offset, fd, tree, 
				    "engine time", ret);
				return;
			}
			if (secur_tree) {
				proto_tree_add_text(secur_tree, NullTVB,
				    offset, length, "Engine Time: %d", 
				    enginetime);
			}
			offset += length;
			ret = asn1_octet_string_decode (&asn1, &username, 
			    &username_length, &length);
			if (ret != ASN1_ERR_NOERROR) {
				dissect_snmp_parse_error(pd, offset, fd, tree, 
				    "user name", ret);
				return;
			}
			if (secur_tree) {
				proto_tree_add_text(secur_tree, NullTVB, offset,
				    length, "User Name: %.*s", 
				    username_length,
				    SAFE_STRING(username));
			}
			g_free(username);
			offset += length;
			ret = asn1_octet_string_decode (&asn1, &authpar, 
			    &authpar_length, &length);
			if (ret != ASN1_ERR_NOERROR) {
				dissect_snmp_parse_error(pd, offset, fd, tree, 
				    "authentication parameter", ret);
				return;
			}
			if (secur_tree) {
				proto_tree_add_text(secur_tree, NullTVB, offset,
				    length, "Authentication Parameter: %s",
				    bytes_to_str(authpar, authpar_length));
			}
			g_free(authpar);
			offset += length;
			ret = asn1_octet_string_decode (&asn1, &privpar, 
			    &privpar_length, &length);
			if (ret != ASN1_ERR_NOERROR) {
				dissect_snmp_parse_error(pd, offset, fd, tree, 
				    "privacy parameter", ret);
				return;
			}
			if (secur_tree) {
				proto_tree_add_text(secur_tree, NullTVB, offset,
				    length, "Privacy Parameter: %s",
				    bytes_to_str(privpar, privpar_length));
			}
			g_free(privpar);
			offset += length;
			break;
		default:
			ret = asn1_octet_string_decode (&asn1, 
			    &secparm, &secparm_length, &length);
			if (ret != ASN1_ERR_NOERROR) {
				dissect_snmp_parse_error(pd, offset, fd, tree, 
				    "Message Security Parameters", ret);
				return;
			}
			if (snmp_tree) {
				proto_tree_add_text(snmp_tree, NullTVB, offset,
				    length,
				    "Message Security Parameters Data"
				    " (%d bytes)", secparm_length);
			}
			g_free(secparm);
			offset += length;
			break;
		}
		/* PDU starts here */
		if (encrypted) {
			ret = asn1_octet_string_decode (&asn1, &cryptpdu,
			    &cryptpdu_length, &length);
			if (ret != ASN1_ERR_NOERROR) {
				dissect_snmp_parse_error(pd, offset, fd, tree, 
				    "encrypted PDU header", ret);
				return;
			}
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Encrypted PDU (%d bytes)", length);
			g_free(cryptpdu);
			if (check_col(fd, COL_INFO))
				col_set_str(fd, COL_INFO, "Encrypted PDU");
			return;
		}
		ret = asn1_sequence_decode(&asn1, &global_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
				"PDU header", ret);
			return;
		}
		offset += length;
		ret = asn1_octet_string_decode (&asn1, &cengineid, 
		    &cengineid_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree, 
			    "context engine id", ret);
			return;
		}
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Context Engine ID: %s",
			    bytes_to_str(cengineid, cengineid_length));
		}
		g_free(cengineid);
		offset += length;
		ret = asn1_octet_string_decode (&asn1, &cname, 
		    &cname_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree, 
			    "context name", ret);
			return;
		}
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, NullTVB, offset, length,
			    "Context Name: %.*s", cname_length,
			    SAFE_STRING(cname));
		}
		g_free(cname);
		offset += length;
		break;
	default:
		dissect_snmp_error(pd, offset, fd, tree,
		    "PDU for unknown version of SNMP");
		return;
	}

	start = asn1.pointer;
	ret = asn1_header_decode (&asn1, &cls, &con, &pdu_type, &def,
	    &pdu_length);
	if (ret != ASN1_ERR_NOERROR) {
		dissect_snmp_parse_error(pd, offset, fd, tree,
		    "PDU type", ret);
		return;
	}
	if (cls != ASN1_CTX || con != ASN1_CON) {
		dissect_snmp_parse_error(pd, offset, fd, tree,
		    "PDU type", ASN1_ERR_WRONG_TYPE);
		return;
	}
	dissect_common_pdu(pd, offset, fd, snmp_tree, asn1, pdu_type, start);
}

static void
dissect_smux_pdu(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree, int proto, gint ett)
{
	ASN1_SCK asn1;
	const guchar *start;
	gboolean def;
	guint length;

	guint pdu_type;
	char *pdu_type_string;
	guint pdu_length;

	guint32 version;
	guint32 cause;
	guint32 priority;
	guint32 operation;
	guint32 commit;

	guchar *password;
	int password_length;

	guchar *application;
	int application_length;

	subid_t *regid;
	guint regid_length;

	gchar *oid_string;

	proto_tree *smux_tree = NULL;
	proto_item *item = NULL;
	int ret;
	guint cls, con;

	if (check_col(fd, COL_PROTOCOL))
		col_set_str(fd, COL_PROTOCOL, "SMUX");

	if (tree) {
		item = proto_tree_add_item(tree, proto, NullTVB, offset,
		    END_OF_FRAME, FALSE);
		smux_tree = proto_item_add_subtree(item, ett);
	}

	/* NOTE: we have to parse the message piece by piece, since the
	 * capture length may be less than the message length: a 'global'
	 * parsing is likely to fail.
	 */
	/* parse the SNMP header */
	asn1_open(&asn1, &pd[offset], END_OF_FRAME);
	start = asn1.pointer;
	ret = asn1_header_decode (&asn1, &cls, &con, &pdu_type, &def,
	    &pdu_length);
	if (ret != ASN1_ERR_NOERROR) {
		dissect_snmp_parse_error(pd, offset, fd, tree,
		    "PDU type", ret);
		return;
	}

	/* Dissect SMUX here */
	if (cls == ASN1_APL && con == ASN1_CON && pdu_type == SMUX_MSG_OPEN) {
		pdu_type_string = val_to_str(pdu_type, smux_types,
		    "Unknown PDU type %#x");
		if (check_col(fd, COL_INFO))
			col_add_str(fd, COL_INFO, pdu_type_string);
		length = asn1.pointer - start;
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "PDU type: %s", pdu_type_string);
		}
		offset += length;
		ret = asn1_uint32_decode (&asn1, &version, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "version", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "Version: %d", version);
		}
		offset += length;

		ret = asn1_oid_decode (&asn1, &regid, &regid_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "registration OID", ret);
			return;
		}
		if (tree) {
			oid_string = format_oid(regid, regid_length);
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "Registration: %s", oid_string);
			g_free(oid_string);
		}
		g_free(regid);
		offset += length;

		ret = asn1_octet_string_decode (&asn1, &application, 
		    &application_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree, 
			    "application", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "Application: %.*s", application_length,
			     SAFE_STRING(application));
		}
		g_free(application);
		offset += length;

		ret = asn1_octet_string_decode (&asn1, &password, 
		    &password_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree, 
			    "password", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "Password: %.*s", password_length,
			    SAFE_STRING(password));
		}
		g_free(password);
		offset += length;
		return;
	}
	if (cls == ASN1_APL && con == ASN1_PRI && pdu_type == SMUX_MSG_CLOSE) {
		pdu_type_string = val_to_str(pdu_type, smux_types,
		    "Unknown PDU type %#x");
		if (check_col(fd, COL_INFO))
			col_add_str(fd, COL_INFO, pdu_type_string);
		length = asn1.pointer - start;
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "PDU type: %s", pdu_type_string);
		}
		offset += length;
		ret = asn1_uint32_value_decode (&asn1, pdu_length, &cause);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "cause", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset,
			    pdu_length, "Cause: %s",
			    val_to_str(cause, smux_close, 
				"Unknown cause %#x"));
		}
		offset += pdu_length;
		return;
	}
	if (cls == ASN1_APL && con == ASN1_CON && pdu_type == SMUX_MSG_RREQ) {
		pdu_type_string = val_to_str(pdu_type, smux_types,
		    "Unknown PDU type %#x");
		if (check_col(fd, COL_INFO))
			col_add_str(fd, COL_INFO, pdu_type_string);
		length = asn1.pointer - start;
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "PDU type: %s", pdu_type_string);
		}
		offset += length;
		ret = asn1_oid_decode (&asn1, &regid, &regid_length, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "registration subtree", ret);
			return;
		}
		if (tree) {
			oid_string = format_oid(regid, regid_length);
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "Registration: %s", oid_string);
			g_free(oid_string);
		}
		g_free(regid);
		offset += length;

		ret = asn1_uint32_decode (&asn1, &priority, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "priority", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "Priority: %d", priority);
		}
		offset += length;

		ret = asn1_uint32_decode (&asn1, &operation, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "operation", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "Operation: %s", 
			    val_to_str(operation, smux_rreq, 
				"Unknown operation %#x"));
		}
		offset += length;
		return;
	}
	if (cls == ASN1_APL && con == ASN1_PRI && pdu_type == SMUX_MSG_RRSP) {
		pdu_type_string = val_to_str(pdu_type, smux_types,
		    "Unknown PDU type %#x");
		if (check_col(fd, COL_INFO))
			col_add_str(fd, COL_INFO, pdu_type_string);
		length = asn1.pointer - start;
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "PDU type: %s", pdu_type_string);
		}
		offset += length;
		ret = asn1_uint32_value_decode (&asn1, pdu_length, &priority);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "priority", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset,
			    pdu_length, "%s",
			    val_to_str(priority, smux_prio, 
				"Priority: %#x"));
		}
		offset += pdu_length;
		return;
	}
	if (cls == ASN1_APL && con == ASN1_PRI && pdu_type == SMUX_MSG_SOUT) {
		pdu_type_string = val_to_str(pdu_type, smux_types,
		    "Unknown PDU type %#x");
		if (check_col(fd, COL_INFO))
			col_add_str(fd, COL_INFO, pdu_type_string);
		length = asn1.pointer - start;
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset, length,
			    "PDU type: %s", pdu_type_string);
		}
		offset += length;
		ret = asn1_uint32_value_decode (&asn1, pdu_length, &commit);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "commit", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(smux_tree, NullTVB, offset,
			    pdu_length, "%s",
			    val_to_str(commit, smux_sout, 
				"Unknown SOUT Value: %#x"));
		}
		offset += pdu_length;
		return;
	}
	if (cls != ASN1_CTX || con != ASN1_CON) {
		dissect_snmp_parse_error(pd, offset, fd, tree,
		    "PDU type", ASN1_ERR_WRONG_TYPE);
		return;
	}
	dissect_common_pdu(pd, offset, fd, smux_tree, asn1, pdu_type, start);
}

static void
dissect_snmp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
	conversation_t  *conversation;

	OLD_CHECK_DISPLAY_AS_DATA(proto_snmp, pd, offset, fd, tree);

	/*
	 * The first SNMP packet goes to the SNMP port; the second one
	 * may come from some *other* port, but goes back to the same
	 * IP address and port as the ones from which the first packet
	 * came; all subsequent packets presumably go between those two
	 * IP addresses and ports.
	 *
	 * If this packet went to the SNMP port, we check to see if
	 * there's already a conversation with the source IP address
	 * and port of this packet, the destination IP address of this
	 * packet, and any destination UDP port.  If not, we create
	 * one, with a wildcard UDP port, and give it the SNMP dissector
	 * as a dissector.
	 */
	if (pi.destport == UDP_PORT_SNMP) {
	  conversation = find_conversation(&pi.src, &pi.dst, PT_UDP,
					   pi.srcport, 0, NO_DST_PORT);
	  if (conversation == NULL) {
	    conversation = conversation_new(&pi.src, &pi.dst, PT_UDP,
					    pi.srcport, 0, NULL,
					    NO_DST_PORT);
	    old_conversation_set_dissector(conversation, dissect_snmp);
	  }
	}

	dissect_snmp_pdu(pd, offset, fd, tree, "SNMP", proto_snmp, ett_snmp);
}

static void
dissect_smux(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
	OLD_CHECK_DISPLAY_AS_DATA(proto_smux, pd, offset, fd, tree);
	dissect_smux_pdu(pd, offset, fd, tree, proto_smux, ett_smux);
}

void
proto_register_snmp(void)
{
#ifdef linux
	void *libsnmp_handle;
	int (*snmp_set_suffix_only_p)(int);
	int (*ds_set_int_p)(int, int, int);
#endif

        static hf_register_info hf[] = {
		{ &hf_snmpv3_flags,
		{ "SNMPv3 Flags", "snmpv3.flags", FT_UINT8, BASE_HEX, NULL,
		    0x0, "" }},
		{ &hf_snmpv3_flags_auth,
		{ "Authenticated", "snmpv3.flags.auth", FT_BOOLEAN, 8,
		    TFS(&flags_set_truth), TH_AUTH, "" }},
		{ &hf_snmpv3_flags_crypt,
		{ "Encrypted", "snmpv3.flags.crypt", FT_BOOLEAN, 8,
		    TFS(&flags_set_truth), TH_CRYPT, "" }},
		{ &hf_snmpv3_flags_report,
		{ "Reportable", "snmpv3.flags.report", FT_BOOLEAN, 8,
		    TFS(&flags_set_truth), TH_REPORT, "" }},
        };
	static gint *ett[] = {
		&ett_snmp,
		&ett_smux,
		&ett_parameters,
		&ett_parameters_qos,
		&ett_global,
		&ett_flags,
		&ett_secur,
	};

#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
	/* UCD or CMU SNMP */
	init_mib();
#ifdef HAVE_UCD_SNMP_SNMP_H
#ifdef linux
	/* As per the comment near the beginning of the file, UCD SNMP 4.1.1
	   changed "snmp_set_suffix_only()" from a function to a macro,
	   removing "snmp_set_suffix_only()" from the library; this means
	   that binaries that call "snmp_set_suffix_only()" and
	   that are linked against shared libraries from earlier versions
	   of the UCD SNMP library won't run with shared libraries from
	   4.1.1.

	   This is a problem on Red Hat Linux, as pre-6.2 releases
	   came with pre-4.1.1 UCD SNMP, while 6.2 comes the 4.1.1.
	   Versions of Ethereal built on pre-6.2 releases don't run
	   on 6.2, and the current Ethereal RPMs are built on pre-6.2
	   releases, causing problems when users running 6.2 download
	   them and try to use them.

	   Building the releases on 6.2 isn't necessarily the answer,
	   as "snmp_set_suffix_only()" expands to a call to "ds_set_int()"
	   with a second argument not supported by at least some pre-4.1.1
	   versions of the library - it appears that the 4.0.1 library,
	   at least, checks for invalid arguments and returns an error
	   rather than stomping random memory, but that means that you
	   won't get get OIDs displayed as module-name::sub-OID.

	   So we use a trick similar to one I've seen mentioned as
	   used in Windows applications to let you build binaries
	   that run on many different versions of Windows 9x and
	   Windows NT, that use features present on later versions
	   if run on those later versions, but that avoid calling,
	   when run on older versions, routines not present on those
	   older versions.

	   I.e., we load "libsnmp.so.0" with "dlopen()", and call
	   "dlsym()" to try to find "snmp_set_suffix_only()"; if we
	   don't find it, we make the appropriate call to
	   "ds_set_int()" instead.  (We load "libsnmp.so.0" rather
	   than "libsnmp.so" because, at least on RH 6.2, "libsnmp.so"
	   exists only if you've loaded the libsnmp development package,
	   which makes "libsnmp.so" a symlink to "libsnmp.so.0"; we
	   don't want to force users to install it or to make said
	   symlink by hand.)

	   We do this only on Linux, for now, as we've only seen the
	   problem on Red Hat; it may show up on other OSes that bundle
	   UCD SNMP, or on OSes where it's not bundled but for which
	   binary packages are built that link against a shared version
	   of the UCD SNMP library.  If we run into one of those, we
	   can do this under those OSes as well, *if* "dlopen()" makes
	   the run-time linker use the same search rules as it uses when
	   loading libraries with which the application is linked.

	   (Perhaps we could use the GLib wrappers for run-time linking,
	   *if* they're thin enough; however, as this code is currently
	   used only on Linux, we don't worry about that for now.) */

	libsnmp_handle = dlopen("libsnmp.so.0", RTLD_LAZY|RTLD_GLOBAL);
	if (libsnmp_handle == NULL) {
		/* We didn't find "libsnmp.so.0".

		   This could mean that there is no SNMP shared library
		   on this system, in which case we were linked statically,
		   in which case whatever call the following line of code
		   makes will presumably work, as we have the routine it
		   calls wired into our binary.  (If we were linked
		   dynamically with "-lsnmp", we would have failed to
		   start.)

		   It could also mean that there is an SNMP shared library
		   on this system, but it's called something other than
		   "libsnmp.so.0"; so far, we've seen the problem we're
		   working around only on systems where the SNMP shared
		   library is called "libsnmp.so.0", so we assume for now
		   that systems with shared SNMP libraries named something
		   other than "libsnmp.so.0" have an SNMP library that's
		   not 4.1.1. */
		snmp_set_suffix_only(2);
	} else {
		/* OK, we have it loaded.  Do we have
		   "snmp_set_suffix_only()"? */
		snmp_set_suffix_only_p = dlsym(libsnmp_handle,
		    "snmp_set_suffix_only");
		if (snmp_set_suffix_only_p != NULL) {
			/* Yes - call it. */
			(*snmp_set_suffix_only_p)(2);
		} else {
			/* No; do we have "ds_set_int()"? */
			ds_set_int_p = dlsym(libsnmp_handle, "ds_set_int");
			if (ds_set_int_p != NULL) {
				/* Yes - cal it with DS_LIBRARY_ID,
				   DS_LIB_PRINT_SUFFIX_ONLY, and 2 as
				   arguments.

				   We do *not* use DS_LIBRARY_ID or
				   DS_LIB_PRINT_SUFFIX_ONLY by name, so that
				   we don't require that Ethereal be built
				   with versions of UCD SNMP that include
				   that value; instead, we use their values
				   in UCD SNMP 4.1.1, which are 0 and 4,
				   respectively. */
				(*ds_set_int_p)(0, 4, 2);
			}
		}
		dlclose(libsnmp_handle);
	}
#else /* linux */
	snmp_set_suffix_only(2);
#endif /* linux */
#endif /* HAVE_UCD_SNMP_SNMP_H */
#endif /* defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H) */
        proto_snmp = proto_register_protocol("Simple Network Management Protocol",
	    "SNMP", "snmp");
        proto_smux = proto_register_protocol("SNMP Multiplex Protocol",
	    "SMUX", "smux");
        proto_register_field_array(proto_snmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_snmp(void)
{
	old_dissector_add("udp.port", UDP_PORT_SNMP, dissect_snmp,
	    proto_snmp);
	old_dissector_add("udp.port", UDP_PORT_SNMP_TRAP, dissect_snmp,
	    proto_snmp);
	old_dissector_add("tcp.port", TCP_PORT_SMUX, dissect_smux,
	    proto_smux);
	old_dissector_add("ethertype", ETHERTYPE_SNMP, dissect_snmp,
	    proto_snmp);
	old_dissector_add("ipx.socket", IPX_SOCKET_SNMP_AGENT, dissect_snmp,
	    proto_snmp);
	old_dissector_add("ipx.socket", IPX_SOCKET_SNMP_SINK, dissect_snmp,
	    proto_snmp);
}
