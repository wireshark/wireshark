/* packet-snmp.c
 * Routines for SNMP (simple network management protocol)
 * D.Jorand (c) 1998
 *
 * $Id: packet-snmp.c,v 1.23 2000/01/07 22:05:39 guy Exp $
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

#define MAX_STRING_LEN 1024	/* TBC */

#include <glib.h>

#include "packet.h"

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

static int proto_snmp = -1;

static gint ett_snmp = -1;

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

	dissect_data(pd, offset, fd, tree);
}

static void
dissect_snmp_error(const u_char *pd, int offset, frame_data *fd,
		   proto_tree *tree, const char *message)
{
	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, message);

	dissect_data(pd, offset, fd, tree);
}

static void
format_oid(gchar *buf, subid_t *oid, guint oid_length)
{
	int i;
	int len;

	len = sprintf(buf, "%lu", (unsigned long)oid[0]);
	buf += len;
	for (i = 1; i < oid_length;i++) {
		len = sprintf(buf, ".%lu", (unsigned long)oid[i]);
		buf += len;
	}
}

#ifdef HAVE_SPRINT_VALUE
static void
format_value(gchar *buf, struct variable_list *variable, subid_t *variable_oid,
    guint variable_oid_length, gushort vb_type, guint vb_length)
{
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
	variable->val_len = vb_length;
	sprint_value(buf, variable_oid, variable_oid_length, variable);
}
#endif

static int
snmp_variable_decode(proto_tree *snmp_tree, subid_t *variable_oid,
    guint variable_oid_length, ASN1_SCK *asn1, int offset, guint *lengthp)
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

	gchar vb_display_string[MAX_STRING_LEN]; /* TBC */

#ifdef HAVE_SPRINT_VALUE
	struct variable_list variable;
#if defined(HAVE_UCD_SNMP_SNMP_H)
	long value;
#endif
#else	/* HAVE_SPRINT_VALUE */
	int i;
	gchar *buf;
	int len;
#endif	/* HAVE_SPRINT_VALUE */

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
#if defined(HAVE_UCD_SNMP_SNMP_H)
			value = vb_integer_value;
			variable.val.integer = &value;
#elif defined(HAVE_SNMP_SNMP_H)
			variable.val.integer = &vb_integer_value;
#endif
			format_value(vb_display_string, &variable,
			    variable_oid, variable_oid_length, vb_type,
			    vb_length);
			proto_tree_add_text(snmp_tree, offset, length,
			    "Value: %s", vb_display_string);
#else
			proto_tree_add_text(snmp_tree, offset, length,
			    "Value: %s: %d (%#x)", vb_type_name,
			    vb_integer_value, vb_integer_value);
#endif
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
#if defined(HAVE_UCD_SNMP_SNMP_H)
			value = vb_uinteger_value;
			variable.val.integer = &value;
#elif defined(HAVE_SNMP_SNMP_H)
			variable.val.integer = &vb_uinteger_value;
#endif
			format_value(vb_display_string, &variable,
			    variable_oid, variable_oid_length, vb_type,
			    vb_length);
			proto_tree_add_text(snmp_tree, offset, length,
			    "Value: %s", vb_display_string);
#else
			proto_tree_add_text(snmp_tree, offset, length,
			    "Value: %s: %u (%#x)", vb_type_name,
			    vb_uinteger_value, vb_uinteger_value);
#endif
		}
		break;

	case SNMP_OCTETSTR:
	case SNMP_IPADDR:
	case SNMP_OPAQUE:
	case SNMP_NSAP:
	case SNMP_BITSTR:
	case SNMP_COUNTER64:
		ret = asn1_octet_string_value_decode (asn1, vb_length,
		    &vb_octet_string);
		if (ret != ASN1_ERR_NOERROR)
			return ret;
		length = asn1->pointer - start;
		if (snmp_tree) {
#ifdef HAVE_SPRINT_VALUE
			variable.val.string = vb_octet_string;
			format_value(vb_display_string, &variable,
			    variable_oid, variable_oid_length, vb_type,
			    vb_length);
			proto_tree_add_text(snmp_tree, offset, length,
			    "Value: %s", vb_display_string);
#else
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
				buf = &vb_display_string[0];
				len = sprintf(buf, "%03u", vb_octet_string[0]);
				buf += len;
				for (i = 1; i < vb_length; i++) {
					len = sprintf(buf, ".%03u",
					    vb_octet_string[i]);
					buf += len;
				}
				proto_tree_add_text(snmp_tree, offset, length,
				    "Value: %s: %s", vb_type_name,
				    vb_display_string);
			} else {
				proto_tree_add_text(snmp_tree, offset, length,
				    "Value: %s: %.*s", vb_type_name, vb_length,
				    vb_octet_string);
			}
#endif
		}
		g_free(vb_octet_string);
		break;

	case SNMP_NULL:
		ret = asn1_null_decode (asn1, vb_length);
		if (ret != ASN1_ERR_NOERROR)
			return ret;
		length = asn1->pointer - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, offset, length,
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
			variable.val.objid = vb_oid;
			format_value(vb_display_string, &variable,
			    variable_oid, variable_oid_length, vb_type,
			    vb_length*sizeof (subid_t));
			proto_tree_add_text(snmp_tree, offset, length,
			    "Value: %s", vb_display_string);
#else
			format_oid(vb_display_string, vb_oid, vb_oid_length);
			proto_tree_add_text(snmp_tree, offset, length,
			    "Value: %s: %s", vb_type_name, vb_display_string);
#endif
		}
		g_free(vb_oid);
		break;

	case SNMP_NOSUCHOBJECT:
		length = asn1->pointer - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, offset, length,
			    "Value: %s: no such object", vb_type_name);
		}
		break;

	case SNMP_NOSUCHINSTANCE:
		length = asn1->pointer - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, offset, length,
			    "Value: %s: no such instance", vb_type_name);
		}
		break;

	case SNMP_ENDOFMIBVIEW:
		length = asn1->pointer - start;
		if (snmp_tree) {
			proto_tree_add_text(snmp_tree, offset, length,
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

void
dissect_snmp_pdu(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree, char *proto_name, int proto, gint ett)
{
	ASN1_SCK asn1;
	const guchar *start;
	gboolean def;
	guint length;
	guint sequence_length;

	guint message_length;

	guint32 version;

	guchar *community;
	int community_length;

	guint pdu_type;
	char *pdu_type_string;
	guint pdu_length;

	guint32 request_id;

	guint32 error_status;

	guint32 error_index;

	subid_t *enterprise;
	guint enterprise_length;

	guint8 *agent_address;
	guint agent_address_length;

	guint32 trap_type;

	guint32 specific_type;

	guint timestamp;
	guint timestamp_length;

	gchar oid_string[MAX_STRING_LEN]; /* TBC */

	guint variable_bindings_length;

	int vb_index;
	guint variable_length;
	subid_t *variable_oid;
	guint variable_oid_length;
#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
	gchar vb_oid_string[MAX_STRING_LEN]; /* TBC */
#endif

	proto_tree *snmp_tree = NULL;
	proto_item *item = NULL;
	int ret;
	guint cls, con, tag;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, proto_name);

	if (tree) {
		item = proto_tree_add_item(tree, proto, offset, END_OF_FRAME, NULL);
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
	if (tree) {
		proto_tree_add_text(snmp_tree, offset, length,
		    "Version: %s",
		    val_to_str(version, versions, "Unknown version %#x"));
	}
	offset += length;

	ret = asn1_octet_string_decode (&asn1, &community, &community_length,
	    &length);
	if (ret != ASN1_ERR_NOERROR) {
		dissect_snmp_parse_error(pd, offset, fd, tree, "community",
		    ret);
		return;
	}
	if (tree) {
		proto_tree_add_text(snmp_tree, offset, length,
		    "Community: %.*s", community_length, community);
	}
	g_free(community);
	offset += length;

	switch (version) {

	case SNMP_VERSION_1:
	case SNMP_VERSION_2c:
	case SNMP_VERSION_2u:
	case SNMP_VERSION_3:
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
	pdu_type_string = val_to_str(pdu_type, pdu_types,
	    "Unknown PDU type %#x");
	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, pdu_type_string);
	length = asn1.pointer - start;
	if (tree) {
		proto_tree_add_text(snmp_tree, offset, length,
		    "PDU type: %s", pdu_type_string);
	}
	offset += length;

	/* get the fields in the PDU preceeding the variable-bindings sequence */
	switch (pdu_type) {

	case SNMP_MSG_GET:
	case SNMP_MSG_GETNEXT:
	case SNMP_MSG_RESPONSE:
	case SNMP_MSG_SET:
	/* XXX - are they like V1 non-trap PDUs? */
	case SNMP_MSG_GETBULK:
	case SNMP_MSG_INFORM:
		/* request id */
		ret = asn1_uint32_decode (&asn1, &request_id, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "request ID", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(snmp_tree, offset, length,
			    "Request Id: %#x", request_id);
		}
		offset += length;
		
		/* error status (getbulk non-repeaters) */
		ret = asn1_uint32_decode (&asn1, &error_status, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "error status", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(snmp_tree, offset, length,
			    "Error Status: %s",
			    val_to_str(error_status, error_statuses,
			      "Unknown (%d)"));
		}
		offset += length;

		/* error index (getbulk max-repetitions) */
		ret = asn1_uint32_decode (&asn1, &error_index, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "error index", ret);
			return;
		}
		if (tree) {
			proto_tree_add_text(snmp_tree, offset, length,
			    "Error Index: %u", error_index);
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
			format_oid(oid_string, enterprise, enterprise_length);
			proto_tree_add_text(snmp_tree, offset, length,
			    "Enterprise: %s", oid_string);
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
		ret = asn1_octet_string_value_decode (&asn1,
		    agent_address_length, &agent_address);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "agent address", ret);
			return;
		}
		length = asn1.pointer - start;
		if (tree) {
			proto_tree_add_text(snmp_tree, offset, agent_address_length,
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
			proto_tree_add_text(snmp_tree, offset, length,
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
			proto_tree_add_text(snmp_tree, offset, length,
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
			proto_tree_add_text(snmp_tree, offset, length,
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

		if (tree) {
			format_oid(oid_string, variable_oid,
			    variable_oid_length);
			
#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
			sprint_objid(vb_oid_string, variable_oid,
			    variable_oid_length);
			proto_tree_add_text(snmp_tree, offset, sequence_length,
			    "Object identifier %d: %s (%s)", vb_index,
			    oid_string, vb_oid_string);
#else
			
			proto_tree_add_text(snmp_tree, offset, sequence_length,
			    "Object identifier %d: %s", vb_index,
			    oid_string);
#endif
		}
		offset += sequence_length;
		variable_bindings_length -= sequence_length;
				
		/* Parse the variable's value */
		ret = snmp_variable_decode(snmp_tree, variable_oid,
		    variable_oid_length, &asn1, offset, &length);
		if (ret != ASN1_ERR_NOERROR) {
			dissect_snmp_parse_error(pd, offset, fd, tree,
			    "variable", ret);
			return;
		}
		offset += length;
		variable_bindings_length -= length;
	}
}

void
dissect_snmp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
	dissect_snmp_pdu(pd, offset, fd, tree, "SNMP", proto_snmp, ett_snmp);
}

void
proto_register_snmp(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "snmp.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_snmp,
	};

#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
	/* UCD or CMU SNMP */
	init_mib();
#ifdef HAVE_UCD_SNMP_SNMP_H
	snmp_set_full_objid(TRUE);
#endif
#endif
        proto_snmp = proto_register_protocol("Simple Network Management Protocol", "snmp");
 /*       proto_register_field_array(proto_snmp, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}
