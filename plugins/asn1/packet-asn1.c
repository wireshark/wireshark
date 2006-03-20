/******************************************************************************************************/
/* packet-asn1.c
 *
 * Copyright (c) 2003 by Matthijs Melchior <matthijs.melchior@xs4all.nl>
 *
 * $Id$
 *
 * A plugin for:
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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


/**************************************************************************
 * This plugin will dissect BER encoded ASN.1 messages in UDP packets or in
 * a TCP stream. It relies on ethereal to do defragmentation and re-assembly
 * to construct complete messages.
 *
 * To produce packet display with good annotations it needs to know about
 * the ASN.1 definition of the messages it reads. To this end, it can read
 * the 'type-table' output file of the ASN.1 to C compiler 'snacc'. The
 * version I have used came from: http://packages.debian.org/testing/devel/snacc.html
 * 
 * The type-table files produced by snacc are themselves ASN.1 BER encoded
 * data structures. Knowledge of the structure of that table, as specified
 * in the tbl.asn1 file in the snacc distribution, is hand coded in some
 * functions in this plugin.
 *
 * This also means that this dissector can show its own specification.
 * On a unix machine, do the following to see this in action:
 *  - cd /tmp
 *  - snacc -u /usr/include/snacc/asn1/asn-useful.asn1 -T tbl.tt /usr/include/snacc/asn1/tbl.asn1
 *  - od -Ax -tx1 tbl.tt | text2pcap -T 801,801 - tbl.tt.pcap
 *  - ethereal tbl.tt.pcap
 *      GUI: Edit->Preferences->Protocols->ASN1
 *             type table file: /tmp/tbl.tt
 *             PDU name: TBL
 *               [OK]
 *  you can now browse the tbl.tt definition.
 *
 */


/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "moduleinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/filesystem.h>
#include <epan/report_err.h>
#include <epan/emem.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/asn1.h>
#include <wiretap/file_util.h>

#ifdef DISSECTOR_WITH_GUI
#include <gtk/gtk.h>
#endif

#include <epan/ipproto.h>

/* Define version if we are not building ethereal statically */

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;
#endif

/* buffer lengths */
#define BUFLS 32
#define BUFLM 64
#define BUFLL 128

/* Define default ports */

#define TCP_PORT_ASN1 801
#define UDP_PORT_ASN1 801
#define SCTP_PORT_ASN1 801

void proto_reg_handoff_asn1(void);

/* Define the asn1 proto */

static int proto_asn1 = -1;

/* Define the tree for asn1*/

static int ett_asn1 = -1;

#define MAXPDU 64		/* max # PDU's in one packet */
static int ett_pdu[MAXPDU];

#define MAX_NEST 32		/* max nesting level for ASN.1 elements */
static int ett_seq[MAX_NEST];

/* 
 * Global variables associated with the preferences for asn1
 */

#ifdef JUST_ONE_PORT
static guint global_tcp_port_asn1 = TCP_PORT_ASN1;
static guint global_udp_port_asn1 = UDP_PORT_ASN1;
static guint global_sctp_port_asn1 = SCTP_PORT_ASN1;
static guint tcp_port_asn1 = TCP_PORT_ASN1;
static guint udp_port_asn1 = UDP_PORT_ASN1;
static guint sctp_port_asn1 = SCTP_PORT_ASN1;
#else
static range_t *global_tcp_ports_asn1;
static range_t *global_udp_ports_asn1;
static range_t *global_sctp_ports_asn1;

static range_t *tcp_ports_asn1;
static range_t *udp_ports_asn1;
static range_t *sctp_ports_asn1;
#endif /* JUST_ONE_PORT */

static gboolean asn1_desegment = TRUE;
static const char *asn1_filename = NULL;
static char *old_default_asn1_filename = NULL;
#define OLD_DEFAULT_ASN1FILE "asn1" G_DIR_SEPARATOR_S "default.tt"
#ifdef _WIN32
#define BAD_SEPARATOR_OLD_DEFAULT_ASN1FILE "asn1/default.tt"
static char *bad_separator_old_default_asn1_filename = NULL;
#endif
static char *current_asn1 = NULL;
static const char *asn1_pduname = NULL;
static char *current_pduname = NULL;
static gboolean asn1_debug = FALSE;
static guint first_pdu_offset = 0;
static gboolean asn1_message_win = FALSE;
static gboolean asn1_verbose = FALSE; /* change to TRUE for logging the startup phase */
static gboolean asn1_full = FALSE; /* show full names */
static guint type_recursion_level = 1; /* eliminate 1 level of references */
static char *asn1_logfile = NULL;

#define ASN1LOGFILE "ethereal.log"

/* PDU counter, for correlation between GUI display and log file in debug mode */
static int pcount = 0;

static tvbuff_t *asn1_desc;	/* the PDU description */
static GNode *asn1_nodes = 0;	/* GNode tree pointing to every asn1 data element */
static GNode *data_nodes = 0;	/* GNode tree describing the syntax data */
static GNode *PDUtree = 0;	/* GNode tree describing the expected PDU format */

static guint PDUerrcount = 0;   /* count of parse errors in one ASN.1 message */

#define NEL(x) (sizeof(x)/sizeof(*x)) /* # elements in static array */


static char pabbrev[] = "asn1";	/* field prefix */

static char fieldname[512];		/* for constructing full names */
static guint pabbrev_pdu_len;		/* length initial part of fieldname with 'abbrev.asn1pdu.' */

/*
 * Text strings describing the standard, universal, ASN.1 names.
 */

#define ASN1_EOI 4 /* this is in the class number space... */
#define ASN1_BEG 2 /* to be merged with constructed flag, first entry in sequence */

static const char tag_class[] = "UACPX";

static const char *asn1_cls[] = { "Universal", "Application", "Context", "Private" };

static const char *asn1_con[] = { "Primitive", "Constructed" };

static const char *asn1_tag[] = {
	/*  0 */ "EOC", 	    "Boolean",        "Integer",          "BitString",
	/*  4 */ "OctetString",     "Null",           "ObjectIdentifier", "ObjectDescriptor",
	/*  8 */ "External",        "Real",           "Enumerated",       "tag11",
	/* 12 */ "UTF8String",      "tag13",          "tag14",            "tag15",
	/* 16 */ "Sequence",        "Set",            "NumericString",    "PrintableString",
	/* 20 */ "TeletexString",   "VideotexString", "IA5String",        "UTCTime",
	/* 24 */ "GeneralTime",     "GraphicString",  "ISO646String",     "GeneralString",
	/* 28 */ "UniversalString", "tag29",          "BMPString",        "Long tag prefix"
/* TT61 == TELETEX */
/* ISO646 == VISIBLE*/
};

/* type names used in the output of the snacc ASN.1 compiler, the TBLTypeId enum */
static gboolean tbl_types_verified = FALSE;

typedef enum {	/* copied from .../snacc/c-lib/boot/tbl.h */
        TBL_BOOLEAN = 0,
        TBL_INTEGER = 1,
        TBL_BITSTRING = 2,
        TBL_OCTETSTRING = 3,
        TBL_NULL = 4,
        TBL_OID = 5,
        TBL_REAL = 6,
        TBL_ENUMERATED = 7,
	TBL__SIMPLE = 8,	/* values smaller than this can have a value */
        TBL_SEQUENCE = 8,
        TBL_SET = 9,
        TBL_SEQUENCEOF = 10,
        TBL_SETOF = 11,
        TBL_CHOICE = 12,
        TBL_TYPEREF = 13,

	TBL_SEQUENCEOF_start, 	/* to mark potential sequence-of repeat */
	TBL_TYPEREF_nopop,	/* typeref has been handled immediately */
	TBL_CHOICE_done,	/* choice is finished */
	TBL_reserved,		/* this sequence has been visited */
	TBL_CHOICE_immediate,	/* immediate choice, no next */

	TBL_INVALID		/* incorrect value for this enum */
} TBLTypeId;

/* Universal tags mapped to snacc ASN.1 table types */
static int asn1_uni_type[] = {
	/*  0 */ TBL_INVALID,	  TBL_BOOLEAN,	   TBL_INTEGER,     TBL_BITSTRING,
	/*  4 */ TBL_OCTETSTRING, TBL_NULL,	   TBL_OID,	    TBL_INVALID,
	/*  8 */ TBL_INVALID,	  TBL_REAL,	   TBL_ENUMERATED,  TBL_INVALID,
	/* 12 */ TBL_OCTETSTRING, TBL_INVALID, 	   TBL_INVALID,	    TBL_INVALID,
	/* 16 */ TBL_SEQUENCE, 	  TBL_SET,	   TBL_OCTETSTRING, TBL_OCTETSTRING,
	/* 20 */ TBL_OCTETSTRING, TBL_OCTETSTRING, TBL_OCTETSTRING, TBL_OCTETSTRING,
	/* 24 */ TBL_OCTETSTRING, TBL_OCTETSTRING, TBL_OCTETSTRING, TBL_OCTETSTRING,
	/* 28 */ TBL_OCTETSTRING, TBL_INVALID,	   TBL_OCTETSTRING, TBL_INVALID,
};


#define TBL_REPEAT		0x00010000 /* This type may be repeated, a flag in word TBLTypeId */
#define TBL_REPEAT_choice	0x00020000 /* repeating a choice */
#define TBL_CHOICE_made		0x00040000 /* This was a choice entry */
#define TBL_SEQUENCE_done	0x00080000 /* children have been processed */
#define TBL_CHOICE_repeat	0x00100000 /* a repeating choice */
#define TBL_REFERENCE		0x00200000 /* This entry is result of a typeref */
#define TBL_REFERENCE_pop	0x00400000 /* reference handled, do pop i.s.o. next */
#define TBL_SEQUENCE_choice	0x00800000 /* this sequence is a first of a repeating choice */
#define TBL_CONSTRUCTED		0x01000000 /* unexpectedly constructed entry */
#define TBL_TYPEmask		0x0000FFFF /* Mask just the type */


#define TBLTYPE(x) (tbl_types[x&TBL_TYPEmask])

/* text tables for debugging and GUI */
static const char *tbl_types[] = {
		       /*  0 */	"tbl-boolean",
		       /*  1 */	"tbl-integer",
		       /*  2 */	"tbl-bitstring",
		       /*  2 */	"tbl-octetstring",
		       /*  4 */	"tbl-null",
		       /*  5 */	"tbl-oid",
		       /*  6 */	"tbl-real",
		       /*  7 */	"tbl-enumerated",
		       /*  8 */	"tbl-sequence",
		       /*  9 */	"tbl-set",
		       /* 10 */	"tbl-sequenceof",
		       /* 11 */	"tbl-setof",
		       /* 12 */	"tbl-choice",
		       /* 13 */	"tbl-typeref",

		       /* 14 */ "tbl-sequenceof-start",
		       /* 15 */ "tbl-typeref-nopop",
		       /* 16 */ "tbl-choice-done",
		       /* 17 */ "tbl-reserved",
		       /* 18 */ "tbl-choice-immediate",

		       /* 19 */ "tbl-invalid",
};
static const char *tbl_types_asn1[] = {
		       /*  0 */	"BOOLEAN",
		       /*  1 */	"INTEGER",
		       /*  2 */	"BITSTRING",
		       /*  2 */	"OCTET STRING",
		       /*  4 */	"NULL",
		       /*  5 */	"OBJECT IDENTIFIER",
		       /*  6 */	"REAL",
		       /*  7 */	"ENUMERATED",
		       /*  8 */	"SEQUENCE",
		       /*  9 */	"SET",
		       /* 10 */	"SEQUENCE OF",
		       /* 11 */	"SET OF",
		       /* 12 */	"CHOICE",
		       /* 13 */	"TYPEREF",

		       /* 14 */ "start-SEQUENCE OF",
		       /* 15 */ "TYPEREF nopop",
		       /* 16 */ "CHOICE done",
		       /* 17 */ "Reserved",
		       /* 18 */	"CHOICE immediate",			
		       
		       /* 19 */ "INVALID entry",
};
/* conversion from snacc type to appropriate ethereal type */
static guint tbl_types_ethereal[] = {
		       /*  0 */	FT_BOOLEAN,	/* TBL_BOOLEAN */
		       /*  1 */	FT_UINT32,	/* TBL_INTEGER */
		       /*  2 */	FT_UINT32,	/* TBL_BITSTRING */
		       /*  2 */	FT_STRINGZ,	/* TBL_OCTETSTRING */
		       /*  4 */	FT_NONE,	/* TBL_NULL */
		       /*  5 */	FT_BYTES,	/* TBL_OID */
		       /*  6 */	FT_DOUBLE,	/* TBL_REAL */
		       /*  7 */	FT_UINT32,	/* TBL_ENUMERATED */
		       /*  8 */	FT_NONE,	/* TBL_SEQUENCE */
		       /*  9 */	FT_NONE,	/* TBL_SET */
		       /* 10 */	FT_NONE,	/* TBL_SEQUENCEOF */
		       /* 11 */	FT_NONE,	/* TBL_SETOF */
		       /* 12 */	FT_NONE,	/* TBL_CHOICE */
		       /* 13 */	FT_NONE,	/* TBL_TYPEREF */

		       /* 14 */ FT_NONE,	/* TBL_SEQUENCEOF_start */
		       /* 15 */ FT_NONE,	/* TBL_TYPEREF_nopop */
		       /* 16 */ FT_NONE,	/* TBL_CHOICE_done */
		       /* 17 */ FT_NONE,	/* TBL_reserved */
		       /* 18 */ FT_NONE,	/* TBL_CHOICE_immediate */

		       /* 19 */ FT_NONE,	/* TBL_INVALID */		
};

static const char *tbl_types_ethereal_txt[] = {
		       /*  0 */	"FT_BOOLEAN",	/* TBL_BOOLEAN */
		       /*  1 */	"FT_UINT32",	/* TBL_INTEGER */
		       /*  2 */	"FT_UINT32",	/* TBL_BITSTRING */
		       /*  2 */	"FT_STRINGZ",	/* TBL_OCTETSTRING */
		       /*  4 */	"FT_NONE",	/* TBL_NULL */
		       /*  5 */	"FT_BYTES",	/* TBL_OID */
		       /*  6 */	"FT_DOUBLE",	/* TBL_REAL */
		       /*  7 */	"FT_UINT32",	/* TBL_ENUMERATED */
		       /*  8 */	"FT_NONE",	/* TBL_SEQUENCE */
		       /*  9 */	"FT_NONE",	/* TBL_SET */
		       /* 10 */	"FT_NONE",	/* TBL_SEQUENCEOF */
		       /* 11 */	"FT_NONE",	/* TBL_SETOF */
		       /* 12 */	"FT_NONE",	/* TBL_CHOICE */
		       /* 13 */	"FT_NONE",	/* TBL_TYPEREF */

		       /* 14 */ "FT_NONE",	/* TBL_SEQUENCEOF_start */
		       /* 15 */ "FT_NONE",	/* TBL_TYPEREF_nopop */
		       /* 16 */ "FT_NONE",	/* TBL_CHOICE_done */
		       /* 17 */ "FT_NONE",	/* TBL_reserved */
		       /* 18 */ "FT_NONE",	/* TBL_CHOICE_immediate */

		       /* 19 */ "FT_NONE",	/* TBL_INVALID */		
};

typedef struct _PDUinfo PDUinfo;
struct _PDUinfo {
	guint type;
	const char *name;
	const char *typename;
	const char *fullname;
	guchar tclass;
	guint tag;
	guint flags;
	GNode *reference;
	gint typenum;
	gint basetype;		/* parent type */
	gint mytype;		/* original type number, typenum may have gone through a reference */
	gint value_id;		/* ethereal field id for the value in this PDU */
	gint type_id;		/* ethereal field id for the type of this PDU */
	hf_register_info value_hf; /* ethereal field info for this value */
};


/* bits in the flags collection */
#define PDU_OPTIONAL	 1
#define PDU_IMPLICIT	 2
#define PDU_NAMEDNUM 	 4
#define PDU_REFERENCE    8
#define PDU_TYPEDEF   0x10
#define PDU_ANONYMOUS 0x20
#define PDU_TYPETREE  0x40

#define PDU_CHOICE    0x08000000   /* manipulated by the PDUname routine */

static guint PDUinfo_initflags = 0;	/* default flags for newly allocated PDUinfo structs */

/* description of PDU properties as passed from the matching routine
 * to the decoder and GUI.
 */
typedef struct _PDUprops PDUprops;
struct _PDUprops {
	guint type;	/* value from enum TBLTypeId */
	const char *name;
	const char *typename;
	const char *fullname;
	guint flags;
	gpointer data;
	gint value_id;
	gint type_id;
};
/* flags defined in PDUprops.flags */
#define OUT_FLAG_type		1
#define OUT_FLAG_data		2
#define OUT_FLAG_typename	4
#define OUT_FLAG_dontshow	8
#define OUT_FLAG_noname	     0x10
#define OUT_FLAG_constructed 0x20

static PDUprops *getPDUprops(PDUprops *out, guint offset, guint class, guint tag, guint cons);
static const char *getPDUenum(PDUprops *props, guint offset, guint cls, guint tag, guint value);

static const char empty[] = "";		/* address of the empt string, avoids many tests for NULL */
#define MAX_OTSLEN 256		/* max printed size for an octet string */


#undef NEST			/* show nesting of asn.1 enties */

#ifdef NEST			/* only for debugging */
/* show nesting, only for debugging... */
#define MAXTAGS MAX_NEST
static struct {
	guchar cls;
	guchar tag;
} taglist[MAXTAGS];

static char *showtaglist(guint level)
{
	static char tagtxt[BUFLM];
	char *p = tagtxt;
	guint i;

#ifdef ALLTAGS
	for(i=0; i<= level; i++) {
		switch(taglist[i].cls) {
		case ASN1_UNI: *p++ = 'U'; break;
		case ASN1_APL: *p++ = 'A'; break;
		case ASN1_CTX: *p++ = 'C'; break;
		case ASN1_PRV: *p++ = 'P'; break;
		default:       *p++ = 'x'; break;
		}
		p += sprintf(p, "%d.", taglist[i].tag);
	}
#else /* only context tags */
        *p++ = 'C';
	for(i=0; i<= level; i++) {
		if (taglist[i].cls == ASN1_CTX) {
			p += sprintf(p, "%d.", taglist[i].tag);
		}
	}
#endif
	*--p = 0;		/* remove trailing '.' */
	return tagtxt;
}

static guint
get_context(guint level)
{
	guint ctx = 0;
	guint i;

	for(i=0; i<=level; i++) {
		if (taglist[i].cls == ASN1_CTX)
			ctx = (ctx << 8) | taglist[i].tag;
	}
	return ctx;
}
#endif /* NEST, only for debugging */


/* Convert a bit string to an ascii representation for printing
 * -- not thread safe ...
 */
static const char *showbits(guchar *val, guint count)
{
	static char str[BUFLM];
	guint i;
	char *p = str;

	if (count > 32)
		return "*too many bits*";

	if (val != 0) {
		for(i=0; i<count; i++) {
			if (i && ((i & 7) == 0)) *p++ = ' ';
			*p++ = (val[i>>3] & (0x80 >> (i & 7))) ? '1' : '0';
		}
	}
	*p = 0;
	return str;
}

/* get bitnames string for bits set */
static const char *
showbitnames(guchar *val, guint count, PDUprops *props, guint offset)
{
	static char str[BUFLL];
	guint i;
	char *p = str;

	if (props->flags & OUT_FLAG_noname)
		return empty;

	if (count > 32)
		return "*too many bits, no names...*";

	if (val != 0) {
		for(i=0; i<count; i++) {
			if (val[i>>3] & (0x80 >> (i & 7))) { /* bit i is set */
				p += sprintf(p,"%s,", getPDUenum(props, offset, 0, 0, i));
			}
		}
		if (p > str)
			--p;	/* remove terminating , */
	}
	*p = 0;
	return str;



}
/* Convert an oid to its conventional text representation
 * -- not thread safe...
 */
static char *showoid(subid_t *oid, guint len)
{
	static char str[BUFLM];
	guint i;
	char *p = str;

	if (oid != 0) {
		for(i=0; i<len; i++) {
			if (i) *p++ = '.';
			p += sprintf(p, "%lu", (unsigned long)oid[i]);
		}
	}
	*p = 0;
	return str;
}

/* show octetstring, if all ascii, show that, else hex [returnrd string must be freed by caller] */
static char *
showoctets(guchar *octets, guint len, guint hexlen) /* if len <= hexlen, always show hex */
{
	guint dohex = 0;
	guint i;
	char *str, *p;
	const char *endstr = empty;

	if (len == 0) {
		str = g_malloc(1);
		str[0] = 0;
	} else {
		for (i=0; i<len; i++) {
			if (!isprint(octets[i])) /* maybe isblank() as well ... */
				dohex++;
		}
		if (len > MAX_OTSLEN) { /* limit the maximum output.... */
			len = MAX_OTSLEN;
			endstr = "...."; /* this is 5 bytes !! */
		}
		if (dohex) {
			str = p = g_malloc(len*2 + 5);
			for (i=0; i<len; i++) {
				p += sprintf(p, "%2.2X", octets[i]);
			}
			strcpy(p, endstr);
		} else {
			if (len <= hexlen) { /* show both hex and ascii, assume hexlen < MAX_OTSLEN */
				str = p = g_malloc(len*3+2);
				for (i=0; i<len; i++) {
					p += sprintf(p, "%2.2X", octets[i]);
				}
				*p++ = ' '; /* insert space */
				strncpy(p, octets, len);
				p[len] = 0;
			} else {
				/* g_strdup_printf("%*s%s", len, octets, endstr) does not work ?? */
				str = g_malloc(len+5);
				strncpy(str, octets, len);
				strcpy(&str[len], endstr);
			}
		}
	}
	return str;
}

/* allow NULL pointers in strcmp, handle them as empty strings */
static int
g_strcmp(gconstpointer a, gconstpointer b)
{
	if (a == 0) a = empty;
	if (b == 0) b = empty;
	return strcmp(a, b);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */
/* WARNING   WARNING   WARNING   WARNING   WARNING   WARNING */
/*							     */
/* Most of the following routine is guesswork in order to    */
/* speed up resynchronisation if the dissector lost the      */
/* encoding due to incomplete captures, or a capture that    */
/* starts in the middle of a fragmented ip packet            */
/* If this poses to many problems, these settings can be     */
/* made part of the protocol settings in the user interface  */
/*************************************************************/

/* check length for a reasonable value, return a corrected value */
static int
checklength(int len, int def, int cls, int tag, char *lenstr, int strmax)
{
	int newlen = len;

	if ( ! def) {
		g_snprintf(lenstr, strmax, "indefinite");
		return len;
	}

	if (len < 0)		/* negative ..... */
		newlen = 4;

	if (cls != ASN1_UNI) {	/* don't know about the tags */
		if (len > 131071)
			newlen = 64;
	} else {
		switch (tag) {
		case ASN1_EOC:	/* End Of Contents    */
		case ASN1_NUL:	/* Null               */
			newlen = 0;
			break;
		case ASN1_BOL:	/* Boolean            */
			newlen = 1;
			break;
		case ASN1_INT:	/* Integer            */
		case ASN1_ENUM:	/* Enumerated         */
			if (len > 8)
				newlen = 4;
			break;
		case ASN1_BTS:	/* Bit String         */
			if (len > 8)
				newlen = 4;
			break;
		case ASN1_OTS:	/* Octet String       */
		case ASN1_NUMSTR: /* Numerical String   */
		case ASN1_PRNSTR: /* Printable String   */
		case ASN1_TEXSTR: /* Teletext String    */
		case ASN1_VIDSTR: /* Video String       */
		case ASN1_IA5STR: /* IA5 String         */
		case ASN1_GRASTR: /* Graphical String   */
		case ASN1_VISSTR: /* Visible String     */
		case ASN1_GENSTR: /* General String     */
		if (len > 65535)
			newlen = 32;
		break;
		case ASN1_OJI:		/* Object Identifier  */
		case ASN1_OJD:		/* Description	      */
		case ASN1_EXT:		/* External           */
			if (len > 64)
				newlen = 16;
			break;
		case ASN1_REAL:		/* Real               */
			if (len >16)
				newlen = 8;
			break;
		case ASN1_SEQ:		/* Sequence           */
		case ASN1_SET:		/* Set                */
			if (len > 65535)
				newlen = 64;
			break;
		case ASN1_UNITIM:	/* Universal Time     */
		case ASN1_GENTIM:	/* General Time       */
			if (len > 32)
				newlen = 15;
			break;

		default:
			if (len > 131071)
				newlen = 64;
			break;                                                  
		}
	}

	if (newlen != len) {
		/* a change was needed.... */
		g_snprintf(lenstr, strmax, "%d(changed from %d)", newlen, len);
	} else {
		g_snprintf(lenstr, strmax, "%d", len);
	}
	return newlen;
}

static guint decode_asn1_sequence(tvbuff_t *tvb, guint offset, guint len, proto_tree *pt, int level);
static void PDUreset(int count, int counr2);

static void 
dissect_asn1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  
  ASN1_SCK asn1;
  guint cls, con, tag, def, len, offset, reassembled;
  char lenstr[BUFLS];
  char tagstr[BUFLS];
  char headstr[BUFLL];
  char offstr[BUFLS];
  const char *name, *tname;
  volatile guint boffset;
  volatile int i = 0;		/* PDU counter */
  proto_tree * volatile ti = 0, * volatile ti2 = 0, *asn1_tree, *tree2;
  PDUprops props;
  static guint lastseq;

  pcount++;
  boffset = 0;

  reassembled = 1;		/* UDP is not a stream, and thus always reassembled .... */
  if (pinfo->ipproto == IP_PROTO_TCP) {	/* we have tcpinfo */
	  struct tcpinfo *info = (struct tcpinfo *)pinfo->private_data;
	  gint delta = info->seq - lastseq;
	  reassembled = info->is_reassembled;
	  lastseq = info->seq;

	  if (asn1_verbose)
		  g_message("dissect_asn1: tcp - seq=%u, delta=%d, reassembled=%d",
			    info->seq, delta, reassembled);
  } else {
	  if (asn1_verbose)
		  g_message("dissect_asn1: udp");
  }

  /* Set the protocol column */
  if(check_col(pinfo->cinfo, COL_PROTOCOL)){
    col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "ASN.1 %s", current_pduname);
  }
  
  if(check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);


  offstr[0] = 0;
  if ((first_pdu_offset > 0) && !reassembled) {
	  boffset = first_pdu_offset;
	  g_snprintf(offstr, sizeof(offstr), " at %d", boffset);
  }

  /* open BER decoding */
  asn1_open(&asn1, tvb, boffset);

  asn1_header_decode(&asn1, &cls, &con, &tag, &def, &len);

  asn1_close(&asn1, &offset);

  PDUreset(pcount, 0);		/* arguments are just for debugging */
  getPDUprops(&props, boffset, cls, tag, con);
  name = props.name;
  tname = props.typename;

  len = checklength(len, def, cls, tag, lenstr, sizeof(lenstr));

  if (asn1_debug) {

	  g_snprintf(tagstr, sizeof(tagstr), "%ctag%d", tag_class[cls], tag);

	  g_snprintf(headstr, sizeof(headstr), "first%s: (%s)%s %d %s, %s, %s, len=%s, off=%d, size=%d ",
		   offstr,
		   tname,
		   name,   
		   pcount,
		   asn1_cls[cls],
		   asn1_con[con],
		   ((cls == ASN1_UNI) && (tag < 32)) ? asn1_tag[tag] : tagstr,
		   lenstr,
		   boffset,
		   tvb_length(tvb)
		  );
  } else {
	  if (props.flags & OUT_FLAG_noname) {
		  g_snprintf(tagstr, sizeof(tagstr), "%ctag%d", tag_class[cls], tag);
		  name = ((cls == ASN1_UNI) && (tag < 32)) ? asn1_tag[tag] : tagstr;
	  }
	  g_snprintf(headstr, sizeof(headstr), "first pdu%s: (%s)%s ", offstr, tname, name );
  }

  /* Set the info column */
  if(check_col(pinfo->cinfo, COL_INFO)){
    col_add_str(pinfo->cinfo, COL_INFO, headstr );
  }

  /* 
   * If we have a non-null tree (ie we are building the proto_tree
   * instead of just filling out the columns ), then add a BER
   * tree node
   */

  /* ignore the tree here, must decode BER to know how to reassemble!! */
/* if(tree) { */

    TRY {			/* catch incomplete PDU's */

	ti = proto_tree_add_protocol_format(tree, proto_asn1, tvb, boffset,
					    def? (int) (offset - boffset + len) :  -1,
					    "ASN.1 %s", current_pduname);

	tree2 = proto_item_add_subtree(ti, ett_asn1);
	
	proto_tree_add_item_hidden(tree2, ((PDUinfo *)PDUtree->data)->value_id, tvb, boffset,
				   def? (int) (offset - boffset + len) :  -1, TRUE);

	offset = boffset; /* the first packet */
        while((i < MAXPDU) && (tvb_length_remaining(tvb, offset) > 0)) {
	    ti2 = 0;
	    boffset = offset;
	    /* open BER decoding */
	    asn1_open(&asn1, tvb, offset);
	    asn1_header_decode(&asn1, &cls, &con, &tag, &def, &len);
	    asn1_close(&asn1, &offset);

	    PDUreset(pcount, i+1);
	    getPDUprops(&props, boffset, cls, tag, con);
	    name = props.name;
	    tname = props.typename;
	    
	    if (!def)
		    len = tvb_length_remaining(tvb, offset);

	    len = checklength(len, def, cls, tag, lenstr, sizeof(lenstr));

	    if (asn1_debug) {

		    g_snprintf(tagstr, sizeof(tagstr), "%ctag%d", tag_class[cls], tag);

		    g_snprintf(headstr, sizeof(headstr), "%s, %s, %s, len=%s, off=%d, remaining=%d",
			     asn1_cls[cls],
			     asn1_con[con],
			     ((cls == ASN1_UNI) && (tag < 32)) ? asn1_tag[tag] : tagstr,
			     lenstr,
			     boffset,
			     tvb_length_remaining(tvb, offset) );

		    if (props.value_id == -1)
			    ti2 = proto_tree_add_text(tree2, tvb, boffset,
						      def? (int) (offset - boffset + len) :  -1,
						      "%s: (%s)%s %d-%d %s", current_pduname,
						      tname, name, pcount, i+1, headstr);
		    else {
			    ti2 = proto_tree_add_none_format(tree2, props.value_id, tvb, boffset,
						      def? (int) (offset - boffset + len) :  -1,
						      "%s: (%s)%s %d-%d %s ~", current_pduname,
						      tname, name, pcount, i+1, headstr);

			     if (props.type_id != -1)
			         proto_tree_add_item_hidden(tree2, props.type_id, tvb, boffset,
			     			      def? (int) (offset - boffset + len) :  -1, TRUE);
			     
	 	    }
	    } else {
		    if (props.flags & OUT_FLAG_noname) {
			    g_snprintf(tagstr, sizeof(tagstr), "%ctag%d", tag_class[cls], tag);
			    name = ((cls == ASN1_UNI) && (tag < 32)) ? asn1_tag[tag] : tagstr;
		    }
		    if (props.value_id == -1)
			    ti2 = proto_tree_add_text(tree2, tvb, boffset,
						      def? (int) (offset - boffset + len) :  -1,
						      "%s: (%s)%s", current_pduname, tname, name);
		    else {
			    ti2 = proto_tree_add_none_format(tree2, props.value_id, tvb, boffset,
						      def? (int) (offset - boffset + len) :  -1,
						      "%s: (%s)%s ~", current_pduname, tname, name);
			    if (props.type_id != -1)
			  	proto_tree_add_item_hidden(tree2, props.type_id, tvb, boffset,
			   			      def? (int) (offset - boffset + len) :  -1, TRUE);
		    }
	    }
	    asn1_tree = proto_item_add_subtree(ti2, ett_pdu[i]);

#ifdef NEST
	    taglist[0].cls = cls;
	    taglist[0].tag = tag;
#endif /* NEST */

	    if (!def) len++; /* make sure we get an exception if we run off the end! */

	    offset = decode_asn1_sequence(tvb, offset, len, asn1_tree, 1);

	    proto_item_set_len(ti2, offset - boffset); /* mark length for hex display */

	    i++; /* one more full message handled */
	
	    if (ti2 && PDUerrcount && asn1_debug) /* show error counts only when in debug mode.... */
		    proto_item_append_text(ti2," (%d error%s)", PDUerrcount, (PDUerrcount>1)?"s":empty);
	}
	if(check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, "[%d msg%s]", i, (i>1)?"s":empty);
	if (ti)
		proto_item_append_text(ti, ", %d msg%s", i, (i>1)?"s":empty);
    }
    CATCH(BoundsError) {
	    RETHROW;
    }
    CATCH(ReportedBoundsError) {
	    if(check_col(pinfo->cinfo, COL_INFO))
	  	    col_append_fstr(pinfo->cinfo, COL_INFO, "[%d+1 msg%s]", i, (i>0)?"s":empty);
	    if (ti)
		    proto_item_append_text(ti, ", %d+1 msg%s", i, (i>1)?"s":empty);
	    if (ti2)
		    proto_item_append_text(ti2, " (incomplete)");
	    if (asn1_desegment) {
		    pinfo->desegment_offset = boffset;
		    pinfo->desegment_len = 1;
		    if (asn1_verbose)
			    g_message("ReportedBoundsError: offset=%d len=%d can_desegment=%d",
				      boffset, 1, pinfo->can_desegment);
	    } else {
		    RETHROW;
	    }
    }
    ENDTRY;
/* } */
  if (asn1_verbose)
	g_message("dissect_asn1 finished: desegment_offset=%d desegment_len=%d can_desegment=%d",
		   pinfo->desegment_offset, pinfo->desegment_len, pinfo->can_desegment);
}

/* decode an ASN.1 sequence, until we have consumed the specified length */
static guint
decode_asn1_sequence(tvbuff_t *tvb, guint offset, guint tlen, proto_tree *pt, int level)
{
  ASN1_SCK asn1;
  guint ret, cls, con, tag, def, len, boffset, soffset, eos;
  guint value;
  const char *clsstr, *constr, *tagstr;
  char tagbuf[BUFLM];
  char lenbuf[BUFLM];
  char nnbuf[BUFLS];
  proto_tree *ti, *pt2;
  guchar *octets, *bits, unused;
  subid_t *oid;
  /* the debugging formats */
  static char textfmt_d[] = "off=%d: [%s %s %s] (%s)%s: %d%s";		/* decimal */
  static char textfmt_e[] = "off=%d: [%s %s %s] (%s)%s: %d:%s%s";	/* enum */
  static char textfmt_s[] = "off=%d: [%s %s %s] (%s)%s: '%s'%s";	/* octet string */
  static char textfmt_b[] = "off=%d: [%s %s %s] (%s)%s: %s:%s%s";	/* bit field */
  static char textfmt_c[] = "off=%d: [%s %s %s] (%s)%s%s%s";		/* constructed */
  static char matchind[] = " ~"; /* indication of possible match */
  const char *name, *ename, *tname;
  char *oname;
  PDUprops props;

  ti = 0;			/* suppress gcc warning */
  
  soffset = offset; /* where this sequence starts */
  eos = offset + tlen;
  while (offset < eos) {	/* while this entity has not ended... */
	  boffset = offset;
	  asn1_open(&asn1, tvb, offset);
	  ret = asn1_header_decode(&asn1, &cls, &con, &tag, &def, &len);
	  asn1_close(&asn1, &offset); /* mark current position */
	  if (ret != ASN1_ERR_NOERROR) {
		proto_tree_add_text(pt, tvb, offset, 1, "ASN1 ERROR: %s", asn1_err_to_str(ret) );
		break;
	  }

	  getPDUprops(&props, boffset, cls, tag, con);
	  name = props.name;
	  tname = props.typename;
	  if (asn1_full)
		  name = &props.fullname[pabbrev_pdu_len];	/* no abbrev.pduname */
	  if (asn1_debug) {	/* show both names */
		  sprintf(fieldname, "%s[%s]", props.name, props.fullname);
		  name = fieldname;
	  }

	  clsstr = asn1_cls[cls];
	  constr = asn1_con[con];
	  if ((cls == ASN1_UNI) && ( tag < 32 )) {
		  tagstr = asn1_tag[tag];
	  } else {
		  g_snprintf(tagbuf, sizeof(tagbuf), "%ctag%d", tag_class[cls], tag);
		  tagstr = tagbuf;
	  }

	  len = checklength(len, def, cls, tag, lenbuf, sizeof(lenbuf));

	  if (def) {
		  g_snprintf(nnbuf, sizeof(nnbuf), "NN%d", len);
	  } else {
		  strncpy(nnbuf, "NN-", sizeof(nnbuf));
		  		/* make sure we get an exception if we run off the end! */
		  len = tvb_length_remaining(tvb, offset) + 1;
	  }
	  if ( ( ! asn1_debug) && (props.flags & OUT_FLAG_noname) ) {
		  /* just give type name if we don't know any better */
		  tname = tagstr;
		  name = nnbuf; /* this is better than just empty.... */
	  }
  
#ifdef NEST
	  taglist[level].cls = cls;
	  taglist[level].tag = tag;
#endif /* NEST */

	  oname  = 0;
	  if (level >= MAX_NEST) { /* nesting too deep..., handle as general octet string */
		cls = ASN1_UNI;
		tag = ASN1_GENSTR;
		oname = g_malloc(strlen(name) + 32);
		sprintf(oname, "%s ** nesting cut off **", name);
		name = oname;
	  }
	  switch(cls) {
	    case ASN1_UNI:	/* fprintf(stderr, "Universal\n"); */
	      switch(tag) {
	        case ASN1_INT:
		      ret = asn1_int32_value_decode(&asn1, len, &value); /* read value */
		      asn1_close(&asn1, &offset); /* mark where we are now */
		      if (asn1_debug) {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_UINT32) )
				        /* unknown or unexpected: just text */
					proto_tree_add_text(pt, tvb, boffset,
							offset - boffset, textfmt_d, boffset,
							clsstr,	constr, tagstr,	tname, name, value,
							empty);
			      else {
					proto_tree_add_uint_format(pt, props.value_id, tvb, boffset,
						        offset - boffset, value, textfmt_d, boffset,
						       	clsstr,	constr, tagstr,	tname, name, value,
							matchind);
					if (props.type_id != -1)
						proto_tree_add_uint_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, value);
			      }
		      } else {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_UINT32) )
				        /* unknown or unexpected, just text */
					proto_tree_add_text(pt, tvb, boffset,
							offset - boffset,
							"(%s)%s: %d", tname, name, value);
			      else {
					proto_tree_add_uint_format(pt, props.value_id, tvb, boffset,
							offset - boffset, value,
							"(%s)%s: %d ~", tname, name, value);
					if (props.type_id != -1)
						proto_tree_add_uint_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, value);
			      }
		      }
		      break;

	        case ASN1_ENUM:
		      ret = asn1_int32_value_decode(&asn1, len, &value); /* read value */
		      asn1_close(&asn1, &offset); /* mark where we are now */
		      ename = getPDUenum(&props, boffset, cls, tag, value);
		      if (asn1_debug) {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_UINT32) )
				        /* unknown or unexpected, just text */
			      		proto_tree_add_text(pt, tvb, boffset,
							offset - boffset,
							textfmt_e, boffset, clsstr, constr, tagstr,
							tname, name, value, ename, empty);
			      else {
					proto_tree_add_uint_format(pt, props.value_id, tvb, boffset,
							offset - boffset, value,
							textfmt_e, boffset, clsstr, constr, tagstr,
							tname, name, value, ename, matchind);
					if (props.type_id != -1)
						proto_tree_add_uint_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, value);
			      }
		      } else {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_UINT32) )
				        /* unknown or unexpected, just text */
			      		proto_tree_add_text(pt, tvb, boffset,
							offset - boffset,
							"(%s)%s: %d:%s", tname, name, value, ename);
			      else {
					proto_tree_add_uint_format(pt, props.value_id, tvb, boffset,
							offset - boffset, value,
							"(%s)%s: %d:%s ~", tname, name, value, ename);
					if (props.type_id != -1)
						proto_tree_add_uint_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, value);
			      }
		      }
		      break;

	        case ASN1_BOL:
		      ret = asn1_bool_decode(&asn1, len, &value); /* read value */
		      asn1_close(&asn1, &offset); /* mark where we are now */
		      if (asn1_debug) {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_BOOLEAN) )
				        /* unknown or unexpected, just text */
			      		proto_tree_add_text(pt, tvb, boffset,
							offset - boffset,
							textfmt_s, boffset, clsstr, constr, tagstr,
							tname, name, value? "true" : "false", empty);
			      else {
					proto_tree_add_boolean_format(pt, props.value_id, tvb, boffset,
							offset - boffset, value != 0,
							textfmt_s, boffset, clsstr, constr, tagstr,
							tname, name, value? "true" : "false", matchind);
					if (props.type_id != -1)
						proto_tree_add_boolean_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, value != 0);
			      }
		      } else {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_BOOLEAN) )
				        /* unknown or unexpected, just text */
			      		proto_tree_add_text(pt, tvb, boffset,
							offset - boffset,
							"(%s)%s: %s", tname, name,
							value? "true" : "false");
			      else {
					proto_tree_add_boolean_format(pt, props.value_id, tvb, boffset,
							offset - boffset, value != 0,
							"(%s)%s: %s ~", tname, name,
							value? "true" : "false");
					if (props.type_id != -1)
						proto_tree_add_boolean_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, value != 0);
			      }
		      }
		      break;

		case ASN1_OTS:
		case ASN1_NUMSTR:
		case ASN1_PRNSTR:
		case ASN1_TEXSTR:
		case ASN1_IA5STR:
		case ASN1_GENSTR:
		case ASN1_UNITIM:
		case ASN1_GENTIM:
			/* read value, \0 terminated */
		      ret = asn1_string_value_decode(&asn1, len, &octets);
		      asn1_close(&asn1, &offset); /* mark where we are now */
		      ename = showoctets(octets, len, (tag == ASN1_OTS) ? 4 : 0 );
		      if (asn1_debug) {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_STRINGZ) )
				        /* unknown or unexpected, just text */
			      		proto_tree_add_text(pt, tvb, boffset,
							offset - boffset,
							textfmt_s, boffset, clsstr, constr, tagstr,
							tname, name, ename, empty);
			      else {
					proto_tree_add_string_format(pt, props.value_id, tvb, boffset,
							offset - boffset, octets, /* \0 termnated */
							textfmt_s, boffset, clsstr, constr, tagstr,
							tname, name, ename, matchind);
					if (props.type_id != -1)
						proto_tree_add_string_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, octets);
			      }
		      } else {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_STRINGZ) )
				        /* unknown or unexpected, just text */
			      		proto_tree_add_text(pt, tvb, boffset,
							offset - boffset,
							"(%s)%s: %s", tname, name, ename);
			      else {
					proto_tree_add_string_format(pt, props.value_id, tvb, boffset,
							offset - boffset, octets, /* \0 terminated */
							"(%s)%s: %s ~", tname, name, ename);
					if (props.type_id != -1)
						proto_tree_add_string_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, octets);
			      }
		      }
		      g_free(octets);
		      g_free(ename);
		      break;

		case ASN1_BTS:
		      ret = asn1_bits_decode(&asn1, len, &bits, &con, &unused); /* read value */
		      asn1_close(&asn1, &offset); /* mark where we are now */
		      ename = showbitnames(bits, (con*8)-unused, &props, offset);
		      if (asn1_debug) {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_UINT32) )
				        /* unknown or unexpected, just text */
					proto_tree_add_text(pt, tvb, boffset,
							offset - boffset,
							textfmt_b, boffset, clsstr, constr, tagstr,
							tname, name,
							showbits(bits, (con*8)-unused),	ename, empty);
			      else {
					proto_tree_add_uint_format(pt, props.value_id, tvb, boffset,
							offset - boffset, *bits, /* XXX length ? XXX */
							textfmt_b, boffset, clsstr, constr, tagstr,
							tname, name,
							showbits(bits, (con*8)-unused),ename, matchind);
					if (props.type_id != -1)
						proto_tree_add_uint_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, *bits);
			      }

		      } else {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_UINT32) )
				        /* unknown or unexpected, just text */
					proto_tree_add_text(pt, tvb, boffset,
							offset - boffset,
							"(%s)%s: %s:%s", tname, name,
							showbits(bits, (con*8)-unused), ename);
			      else {
					proto_tree_add_uint_format(pt, props.value_id, tvb, boffset,
							offset - boffset, *bits, /* XXX length ? XXX */
							"(%s)%s: %s:%s ~", tname, name,
							showbits(bits, (con*8)-unused), ename);
					if (props.type_id != -1)
						proto_tree_add_uint_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, *bits);
			      }
		      }
		      g_free(bits);
		      break;

		case ASN1_SET:
	        case ASN1_SEQ:
				/* show full sequence length */
		      if (asn1_debug) {
			      ename = empty;
			      if ( (props.flags & OUT_FLAG_dontshow) || asn1_full)
				      ename = ", noshow";
			      if ( (props.flags & OUT_FLAG_constructed))
				      ename = ", unexpected constructed";

			      if (props.value_id == -1)
				      ti = proto_tree_add_text(pt, tvb, boffset, offset - boffset + len,
							     textfmt_c, boffset, clsstr, constr, tagstr,
							     tname, name, ename, empty);
			      else {
				      ti = proto_tree_add_item(pt, props.value_id, tvb,
							      boffset, 1, TRUE);
				      /* change te text to to what I really want */
				      proto_item_set_text(ti, textfmt_c, boffset, clsstr, constr,
							     tagstr, tname, name, ename, matchind);
				      if (props.type_id != -1)
					      proto_tree_add_item_hidden(pt, props.type_id, tvb,
							      boffset, 1, TRUE);
			      }
		      } else {
			      if (props.value_id == -1) {
				      if ( (! asn1_full) && ((props.flags & OUT_FLAG_dontshow) == 0) )
					      ti = proto_tree_add_text(pt, tvb, boffset,
								       offset - boffset + len,
								       "(%s)%s", tname, name);
			      } else {
				      if ( (! asn1_full) && ((props.flags & OUT_FLAG_dontshow) == 0) )
					      ti = proto_tree_add_none_format(pt, props.value_id, tvb,
								       boffset, offset - boffset + len,
								       "(%s)%s ~", tname, name);
				      else {
					      /* don't care about the text */
					      ti = proto_tree_add_item_hidden(pt, props.value_id, tvb,
						    	  boffset, 1, TRUE);
				      }
				      if (props.type_id != -1)
					      proto_tree_add_item_hidden(pt, props.type_id, tvb,
						    	  boffset, 1, TRUE);
			      }
		      }
		      if (len == 0) return offset; /* don't recurse if offset isn't going to change */

		      if ( ( ! asn1_full) && (asn1_debug || ((props.flags & OUT_FLAG_dontshow) == 0)))
		      	      pt2 = proto_item_add_subtree(ti, ett_seq[level]);
		      else
			      pt2 = pt;

		      offset = decode_asn1_sequence(tvb, offset, len, pt2, level+1); /* recurse */

	      	      if ( ( ! asn1_full) && (asn1_debug || ((props.flags & OUT_FLAG_dontshow) == 0)))
			      proto_item_set_len(ti, offset - boffset);

		      break;

	        case ASN1_EOC:
		      if (asn1_debug) {	/* don't show if not debugging */
			      proto_tree_add_text(pt, tvb, boffset, offset - boffset, textfmt_d,
						  boffset, clsstr, constr, tagstr, tname, name,
						  offset - soffset, empty);
		      }
		      getPDUprops(&props, soffset, ASN1_EOI, 1, 0); /* mark end of this sequence */
		      return offset;
		      
		case ASN1_OJI:
		      ret = asn1_oid_value_decode(&asn1, len, &oid, &con);
		      asn1_close(&asn1, &offset); /* mark where we are now */
		      ename = showoid(oid, con);
		      if (asn1_debug) {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_BYTES) )
				      /* unknown or unexpected, just text */
				      proto_tree_add_text(pt, tvb, boffset, offset - boffset, textfmt_s,
							  boffset, clsstr, constr, tagstr, tname, name,
							  ename, empty);
			      else {
				      proto_tree_add_bytes_format(pt, props.value_id, tvb, boffset,
								 offset - boffset, ename,/* XXX length?*/
								 "(%s)%s: %s ~", tname, name, ename);
					if (props.type_id != -1)
						proto_tree_add_bytes_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, ename);
			      }
		      } else {
			      if ( (props.value_id == -1) ||
				   (tbl_types_ethereal[props.type] != FT_BYTES) )
				        /* unknown or unexpected, just text */
					proto_tree_add_text(pt, tvb, boffset,
							offset - boffset,
							"(%s)%s: %s", tname, name, ename);
			      else {
					proto_tree_add_bytes_format(pt, props.value_id, tvb, boffset,
							offset - boffset, ename, /* XXX length ? */
							"(%s)%s: %s ~", tname, name, ename);
					if (props.type_id != -1)
						proto_tree_add_bytes_hidden(pt, props.type_id, tvb,
								boffset, offset - boffset, ename);
			      }
		      }
		      g_free(oid);
		      break;

		case ASN1_NUL:
		      if (asn1_debug) {
			      proto_tree_add_text(pt, tvb, boffset, offset - boffset + len, textfmt_s,
						  boffset, clsstr, constr, tagstr, tname, name,
						  "[NULL]", empty);
		      } else {
			      proto_tree_add_text(pt, tvb, boffset, offset - boffset + len,
						  "(%s)%s: [NULL]", tname, name);
		      }
		      offset += len; /* skip value ... */
		      break;

		case ASN1_OJD:
		case ASN1_EXT:
		case ASN1_REAL:
		case ASN1_VIDSTR:
		case ASN1_GRASTR:
		case ASN1_VISSTR:
		      
	        default:
		      if (asn1_debug) {
			      ti = proto_tree_add_text(pt, tvb, boffset, offset - boffset + len,
						       textfmt_s, boffset, clsstr, constr, tagstr,
						       tname, name, lenbuf, empty);
		      } else {
			      ti = proto_tree_add_text(pt, tvb, boffset, offset - boffset + len,
						       "(%s)%s: %s bytes", tname, name, lenbuf);
		      }
		      proto_item_append_text(ti, " *"); /* indicate default is used */
		      offset += len; /* skip value ... */
		      break;
	      };	
	      break;

	    case ASN1_CTX:		/* fprintf(stderr, "Context\n"); */
	    case ASN1_APL:		/* fprintf(stderr, "Application\n"); */
	    case ASN1_PRV:		/* fprintf(stderr, "Private\n"); */

		  if (def && !con) {
			if (props.value_id == -1) /* type unknown, handle as string */
				goto dostring;
			switch(props.type) {
				/* this is via the asn1 description, don't trust the length */
			case TBL_INTEGER:
				if (len > 4)
					goto dostring;
				ret = asn1_int32_value_decode(&asn1, len, &value); /* read value */
				asn1_close(&asn1, &offset); /* mark where we are now */
				if (asn1_debug) {
					if ( (props.value_id == -1) ||
					     (tbl_types_ethereal[props.type] != FT_UINT32) )
						/* unknown or unexpected, just text */
						proto_tree_add_text(pt, tvb,
							    boffset, offset - boffset,
							    textfmt_d, boffset, clsstr, constr,
							    tagstr, tname, name, value, empty);
					else {
						proto_tree_add_uint_format(pt, props.value_id, tvb,
							    boffset, offset - boffset, value,
							    textfmt_d, boffset, clsstr, constr,
							    tagstr, tname, name, value, matchind);
						if (props.type_id != -1)
							proto_tree_add_uint_hidden(pt, props.type_id,
								tvb, boffset, offset - boffset, value);
					}
				} else {
					if ( (props.value_id == -1) ||
					     (tbl_types_ethereal[props.type] != FT_UINT32) )
						/* unknown or unexpected, just text */
						proto_tree_add_text(pt, tvb,
							    boffset, offset - boffset,
							    "(%s)%s: %d", tname, name, value);
					else {
						proto_tree_add_uint_format(pt, props.value_id, tvb,
							    boffset, offset - boffset, value,
							    "(%s)%s: %d ~", tname, name, value);
						if (props.type_id != -1)
							proto_tree_add_uint_hidden(pt, props.type_id,
								tvb, boffset, offset - boffset, value);
					}
				}
				break;

			case TBL_ENUMERATED:
				if (len > 4)
					goto dostring;
				ret = asn1_int32_value_decode(&asn1, len, &value); /* read value */
		 		asn1_close(&asn1, &offset); /* mark where we are now */
				ename = getPDUenum(&props, boffset, cls, tag, value);
				if (asn1_debug) {
					if ( (props.value_id == -1) ||
					     (tbl_types_ethereal[props.type] != FT_UINT32) )
						/* unknown or unexpected, just text */
						proto_tree_add_text(pt, tvb,
							   boffset, offset - boffset,
							   textfmt_e, boffset, clsstr, constr,
							   tagstr, tname, name, value, ename, empty);
					else {
						proto_tree_add_uint_format(pt, props.value_id, tvb,
							   boffset, offset - boffset, value,
							   textfmt_e, boffset, clsstr, constr,
							   tagstr, tname, name, value, ename, matchind);
						if (props.type_id != -1)
							proto_tree_add_uint_hidden(pt, props.type_id,
								tvb, boffset, offset - boffset, value);
					}
				} else {
					if ( (props.value_id == -1) ||
					     (tbl_types_ethereal[props.type] != FT_UINT32) )
						/* unknown or unexpected, just text */
						proto_tree_add_text(pt, tvb,
							   boffset, offset - boffset,
							   "(%s)%s: %d:%s", tname, name, value, ename);
					else {
						proto_tree_add_uint_format(pt, props.value_id, tvb,
							  boffset, offset - boffset, value,
							  "(%s)%s: %d:%s ~", tname, name, value, ename);
						if (props.type_id != -1)
							proto_tree_add_uint_hidden(pt, props.type_id,
								tvb, boffset, offset - boffset, value);
					}
				}
				break;
			case TBL_BITSTRING:
				if (len > (1+4)) /* max 32 bits ...?.. */
					goto dostring;
								/* read value */
				ret = asn1_bits_decode(&asn1, len, &bits, &con, &unused);
				asn1_close(&asn1, &offset); /* mark where we are now */
				ename = showbitnames(bits, (con*8)-unused, &props, offset);
				if (asn1_debug) {
					if ( (props.value_id == -1) ||
					     (tbl_types_ethereal[props.type] != FT_UINT32) )
						/* unknown or unexpected, just text */
						proto_tree_add_text(pt, tvb,
							    boffset, offset - boffset,
							    textfmt_b, boffset, clsstr, constr,
							    tagstr, tname, name,
							    showbits(bits, (con*8)-unused), ename,
							    empty);
					else {
						proto_tree_add_uint_format(pt, props.value_id, tvb,
							    boffset, offset - boffset, *bits,
							    textfmt_b, boffset, clsstr, constr,
							    tagstr, tname, name,
							    showbits(bits, (con*8)-unused), ename,
							    matchind);
						if (props.type_id != -1)
							proto_tree_add_uint_hidden(pt, props.type_id,
								 tvb, boffset, offset - boffset, *bits);
					}
				} else {
					if ( (props.value_id == -1) ||
					     (tbl_types_ethereal[props.type] != FT_UINT32) )
						/* unknown or unexpected, just text */
						proto_tree_add_text(pt, tvb, boffset, offset - boffset,
							    "(%s)%s: %s:%s", tname, name,
							    showbits(bits, (con*8)-unused), ename);
					else {
						proto_tree_add_uint_format(pt, props.value_id, tvb,
							    boffset, offset - boffset, *bits,
							    "(%s)%s: %s:%s ~", tname, name,
							    showbits(bits, (con*8)-unused), ename);
						if (props.type_id != -1)
							proto_tree_add_uint_hidden(pt, props.type_id,
								tvb, boffset, offset - boffset, *bits);
					}
				}
				g_free(bits);
				break;
			case TBL_BOOLEAN:
				if (len > 1)
					goto dostring;
				ret = asn1_bool_decode(&asn1, len, &value); /* read value */
				asn1_close(&asn1, &offset); /* mark where we are now */
				if (asn1_debug) {
					if ( (props.value_id == -1) ||
					     (tbl_types_ethereal[props.type] != FT_BOOLEAN) )
						/* unknown or unexpected, just text */
						proto_tree_add_text(pt, tvb,
							    boffset, offset - boffset,
							    textfmt_s, boffset, clsstr, constr,
							    tagstr, tname, name,
							    value? "true" : "false", empty);
					else {
						proto_tree_add_boolean_format(pt, props.value_id,  tvb,
							    boffset, offset - boffset, value != 0,
							    textfmt_s, boffset, clsstr, constr,
							    tagstr, tname, name,
							    value? "true" : "false", matchind);
						if (props.type_id != -1)
							proto_tree_add_boolean_hidden(pt, props.type_id,
							  tvb, boffset, offset - boffset, value != 0);
					}
				} else {
					if ( (props.value_id == -1) ||
					     (tbl_types_ethereal[props.type] != FT_BOOLEAN) )
						/* unknown or unexpected, just text */
						proto_tree_add_text(pt, tvb,
							    boffset, offset - boffset,
							    "(%s)%s: %s", tname, name,
							    value? "true" : "false");
					else {
						proto_tree_add_boolean_format(pt, props.value_id, tvb,
							    boffset, offset - boffset, value != 0,
							    "(%s)%s: %s ~", tname, name,
							    value? "true" : "false");
						if (props.type_id != -1)
							proto_tree_add_boolean_hidden(pt, props.type_id,
							  tvb, boffset, offset - boffset, value != 0);
					}
				}
				break;
			case TBL_NULL:
				if (len > 0)
					goto dostring;
				if (asn1_debug) {
					proto_tree_add_text(pt, tvb, boffset, offset - boffset + len,
							    textfmt_s, boffset, clsstr, constr,
							    tagstr, tname, name, "[NULL]", empty);
				} else {
					proto_tree_add_text(pt, tvb, boffset, offset - boffset + len,
						            "(%s)%s: [NULL]", tname, name);
				}
				offset += len; /* skip value ... */
				break;
			default:
			dostring:
			        props.value_id = -1; /* unlikely this is correct, dont use it */
				/* fallthrough */
			case TBL_OCTETSTRING:
				/* defined length, not constructed, must be a string.... */
				ret = asn1_string_value_decode(&asn1, len, &octets); /* read value */
				asn1_close(&asn1, &offset); /* mark where we are now */
				ename = showoctets(octets, len, 2); /* convert octets to printable */
				if (asn1_debug) {
					if ( (props.value_id == -1) ||
					     (tbl_types_ethereal[props.type] != FT_STRINGZ) )
						/* unknown or unexpected, just text */
						proto_tree_add_text(pt, tvb,
							    boffset, offset - boffset,
							    textfmt_s, boffset, clsstr, constr,
							    tagstr, tname, name, ename, empty);
					else {
						proto_tree_add_string_format(pt, props.value_id, tvb,
							    boffset, offset - boffset, octets, /* XXX */
							    textfmt_s, boffset, clsstr, constr,
							    tagstr, tname, name, ename, matchind);
						if (props.type_id != -1)
							proto_tree_add_string_hidden(pt, props.type_id,
								tvb, boffset, offset - boffset, octets);
					}
				} else {
					if ( (props.value_id == -1) ||
					     (tbl_types_ethereal[props.type] != FT_STRINGZ) )
						/* unknown or unexpected, just text */
						proto_tree_add_text(pt, tvb, boffset, offset - boffset,
							    "(%s)%s: %s", tname, name, ename);
					else {
						proto_tree_add_string_format(pt, props.value_id, tvb,
							    boffset, offset - boffset, octets, /* XXX */
							    "(%s)%s: %s ~", tname, name, ename);
						if (props.type_id != -1)
							proto_tree_add_string_hidden(pt, props.type_id,
								tvb, boffset, offset - boffset, octets);
					}
				}
				g_free(octets);
				g_free(ename);
			  	break;
			}
		  } else {
			/* indefinite length or constructed.... must be a sequence .... */
			/* show full sequence length */
			if (asn1_debug) {
			     	ename = empty;
			      	if ( (props.flags & OUT_FLAG_dontshow) || asn1_full)
					ename = ", noshow";
			      	if ( (props.flags & OUT_FLAG_constructed))
					ename = ", unexpected constructed";
				
				if (props.value_id == -1)
				      ti = proto_tree_add_text(pt, tvb, boffset, offset - boffset + len,
								 textfmt_c, boffset, clsstr, constr,
								 tagstr, tname, name, ename, empty);
				else {
				      ti = proto_tree_add_item(pt, props.value_id, tvb,
							      boffset, 1, TRUE);
				      /* change te text to to what I really want */
				      if (ti) {
					proto_item_set_text(ti, textfmt_c, boffset, clsstr, constr,
							     tagstr, tname, name, ename, matchind);
					if (props.type_id != -1)
					      proto_tree_add_item_hidden(pt, props.type_id, tvb,
							      boffset, 1, TRUE);
				      } else {
					ti = proto_tree_add_text(pt, tvb, boffset,
								 offset - boffset + len,
								 textfmt_c, boffset, clsstr, constr,
								 tagstr, tname, name, ename, empty);
				      }
				}
			} else {
				if (props.value_id == -1) {
					if ( ( ! asn1_full) && ((props.flags & OUT_FLAG_dontshow) == 0))
						ti = proto_tree_add_text(pt, tvb, boffset,
							 offset - boffset + len, "(%s)%s", tname, name);
				} else {
					if ( ( ! asn1_full) && ((props.flags & OUT_FLAG_dontshow) == 0))
						ti = proto_tree_add_none_format(pt, props.value_id, tvb,
							       	boffset, 1,
						       		"(%s)%s ~", tname, name);
					else {
						/* don't care about the text */
						ti = proto_tree_add_item_hidden(pt, props.value_id,
						             tvb,  boffset, 1, TRUE);
					}
					if (props.type_id != -1)
						proto_tree_add_item_hidden(pt, props.type_id,
						             tvb,  boffset, 1, TRUE);
				}
			}

			if (len == 0) return offset; /* don't recurse if offset isn't going to change */

			if ( ( ! asn1_full) && (asn1_debug || ((props.flags & OUT_FLAG_dontshow) == 0)))
				pt2 = proto_item_add_subtree(ti, ett_seq[level]);
			else
				pt2 = pt;
	
			offset = decode_asn1_sequence(tvb, offset, len, pt2, level+1); /* recurse */

			if ( ( ! asn1_full) && (asn1_debug || ((props.flags & OUT_FLAG_dontshow) == 0)))
				proto_item_set_len(ti, offset - boffset);
		  }
	      break;

	    default:   		/* fprintf(stderr, "Other\n"); */
		  if (asn1_debug) {
			  ti = proto_tree_add_text(pt, tvb, boffset, offset - boffset + len,
					           textfmt_s, boffset, clsstr, constr, tagstr,
						   tname, name, lenbuf, empty);
		  } else {
			  ti = proto_tree_add_text(pt, tvb, boffset, offset - boffset + len,
					  	   "(%s)%s: %s bytes %s data", tname, name,
						   lenbuf, clsstr);
		  }
		  proto_item_append_text(ti, " *"); /* indicate default is used */
		  offset += len; /* skip value ... */
		  break;
	  }
	  g_free(oname); /* XXX, memory management ? */
  }
  /* proto_tree_add_text(pt, tvb, offset, 1, "Marker: offset=%d", offset); */

  getPDUprops(&props, soffset, ASN1_EOI, 0, 0); /* mark end of this sequence */
  
  return offset;
}
#define READSYNTAX
#ifdef READSYNTAX

/************************************************************************************************/
/*  search throug the ASN.1 description for appropriate names 					*/
/************************************************************************************************/

guint lev_limit = G_MAXINT;

int icount = 0;			/* item counter */

static guint
parse_tt3(tvbuff_t *tvb, guint offset, guint size, guint level, GNode *ptr)
{
	ASN1_SCK asn1;
	guint eos, ret, cls, con, tag, def, len, value;
	guchar *octets, *bits, unused;
	subid_t *oid;
	const char *clsstr, *constr, *tagstr;
	char tagbuf[BUFLM];
	char lenbuf[BUFLM];
	GNode *cur_node = 0;

	eos = offset + size;

	if (level > lev_limit)
		return eos;

	while(offset < eos) {
		if (ptr)	/* build pointer tree to all asn1 enteties */
			cur_node = g_node_append_data(ptr, GUINT_TO_POINTER(offset));

		asn1_open(&asn1, tvb, offset);
		ret = asn1_header_decode(&asn1, &cls, &con, &tag, &def, &len);
		asn1_close(&asn1, &offset); /* mark where we are */
		icount++;
		clsstr = asn1_cls[cls];
		constr = asn1_con[con];
		if ((cls == ASN1_UNI) && ( tag < 32 )) {
			tagstr = asn1_tag[tag];
		} else {
			g_snprintf(tagbuf, sizeof(tagbuf), "tag%d", tag);
			tagstr = tagbuf;
		}
		if (def) {
			g_snprintf(lenbuf, sizeof(lenbuf), "%d", len);
		} else {
			strncpy(lenbuf, "indefinite", sizeof(lenbuf));
			len = tvb_length_remaining(tvb, offset);
		}

		switch(cls) {
		case ASN1_UNI:	/* fprintf(stderr, "Universal\n"); */
			switch(tag) {
			case ASN1_INT:
			case ASN1_ENUM:
				ret = asn1_int32_value_decode(&asn1, len, &value); /* read value */
				asn1_close(&asn1, &offset); /* mark where we are */
				break;

			case ASN1_BOL:
				ret = asn1_bool_decode(&asn1, len, &value); /* read value */
				asn1_close(&asn1, &offset); /* mark where we are */
				break;

			case ASN1_OTS:
			case ASN1_NUMSTR:
			case ASN1_PRNSTR:
			case ASN1_TEXSTR:
			case ASN1_IA5STR:
			case ASN1_GENSTR:
			case ASN1_UNITIM:
			case ASN1_GENTIM:
				ret = asn1_string_value_decode(&asn1, len, &octets); /* read value */
				asn1_close(&asn1, &offset); /* mark where we are */
				g_free(octets);
				break;

			case ASN1_BTS:
				ret = asn1_bits_decode(&asn1, len, &bits, &con, &unused);
				asn1_close(&asn1, &offset); /* mark where we are */
				g_free(bits);
				break;

			case ASN1_SET:
			case ASN1_SEQ:
				if (len == 0) /* don't recurse if offset isn't going to change */
					return offset;

				offset = parse_tt3(tvb, offset, len, level+1, cur_node); /* recurse */
				break;

			case ASN1_EOC:
				return offset;
		      
			case ASN1_OJI:
				ret = asn1_oid_value_decode(&asn1, len, &oid, &con);
				asn1_close(&asn1, &offset); /* mark where we are */
				g_free(oid);
				break;

			case ASN1_NUL:
				offset += len;
				break;

			case ASN1_OJD:
			case ASN1_EXT:
			case ASN1_REAL:
			case ASN1_VIDSTR:
			case ASN1_GRASTR:
			case ASN1_VISSTR:
		      
			default:
				if (asn1_verbose) g_message("%d skip1 %d", offset, len);
				offset += len; /* skip value ... */
				break;
			};	
			break;

		case ASN1_CTX:		/* fprintf(stderr, "Context\n"); */
			tagstr = tagbuf;
			g_snprintf(tagbuf, sizeof(tagbuf), "TAG%d", tag);
			if (def && !con) {
				/* defined length, not constructed, must be a string.... */
				asn1_string_value_decode(&asn1, len, &octets); /* read value */
				asn1_close(&asn1, &offset); /* mark where we are */
				g_free(octets);
			} else {
				/* indefinite length or constructed.... must be a sequence .... */
				if (len == 0) /* don't recurse if offset isn't going to change */
					return offset;

				offset = parse_tt3(tvb, offset, len, level+1, cur_node); /* recurse */
			}
			break;

		default:		/* fprintf(stderr, "Other\n"); */
			if (asn1_verbose) g_message("%d skip2 %d", offset, len);
			offset += len; /* skip value ... */
			break;
		}
	}
	return offset;
}

static void showGNodes(GNode *p, int n);

#if 0
static gboolean
myLeaf(GNode *node, gpointer data)
{
	ASN1_SCK asn1;
	guint ret, cls, con, tag, def, len;
	char *clsstr, *constr, *tagstr;
	char tagbuf[BUFLM];
	char lenbuf[BUFLM];

	(void) data;			/* make a reference */
	asn1_open(&asn1, asn1_desc, (int)node->data);

	ret = asn1_header_decode(&asn1, &cls, &con, &tag, &def, &len);

	clsstr = asn1_cls[cls];
	constr = asn1_con[con];
	if ((cls == ASN1_UNI) && ( tag < 32 )) {
		tagstr = asn1_tag[tag];
	} else {
		g_snprintf(tagbuf, sizeof(tagbuf), "tag%d", tag);
		tagstr = tagbuf;
	}
	if (def) {
		g_snprintf(lenbuf, sizeof(lenbuf), "%d", len);
	} else {
		strncpy(lenbuf, "indefinite", sizeof(lenbuf));
	}

	if (asn1_verbose)
		g_message("off=%d: [%s %s %s] len=%s", (int)node->data, clsstr, constr, tagstr, lenbuf);

	return FALSE;
}

static void
list_modules(void)
{
	if (asn1_verbose) g_message("build GNode tree:");
	showGNodes(g_node_first_child(asn1_nodes), 0);
	if (asn1_verbose) g_message("end of tree: %d nodes, %d deep, %d leafs, %d branches",
		  g_node_n_nodes(asn1_nodes, G_TRAVERSE_ALL),
		  g_node_max_height (asn1_nodes),
		  g_node_n_nodes(asn1_nodes, G_TRAVERSE_LEAFS),
		  g_node_n_nodes(asn1_nodes, G_TRAVERSE_NON_LEAFS) );

	g_node_traverse(g_node_first_child(asn1_nodes), G_PRE_ORDER, G_TRAVERSE_LEAFS, -1, myLeaf, 0);

}
#endif

static void
tt_build_tree(void)		/* build a GNode tree with all offset's to ASN.1 entities */
{
	if (asn1_nodes)
		g_node_destroy(asn1_nodes);
	asn1_nodes = g_node_new(0);
	icount = 0;
	parse_tt3(asn1_desc, 0, tvb_length(asn1_desc), 0, asn1_nodes);
}


/*****************************************************************************************************/

static guint anonCount;  /* for naming anonymous types */

typedef struct _TBLModule 	TBLModule;
typedef struct _TBLTypeDef	TBLTypeDef;
typedef struct _TBLTag		TBLTag;
typedef struct _TBLType		TBLType;
typedef struct _TBLTypeRef	TBLTypeRef;
typedef struct _TBLNamedNumber	TBLNamedNumber;
typedef struct _TBLRange	TBLRange;

enum _tbl_t {
	TBLTYPE_Module,
	TBLTYPE_TypeDef,
	TBLTYPE_Tag,
	TBLTYPE_Type,
	TBLTYPE_TypeRef,
	TBLTYPE_NamedNumber,
	TBLTYPE_Range
};
typedef enum _tbl_t tbl_t;
/* text for 'tbl_t' type for debugging */
static const char *data_types[] = {
			"Module",
			"TypeDef",
			"Tag",
			"Type",
			"TypeRef",
			"NamedNumber",
			"Range",
};

enum _TBLTypeContent_t {
	TBLTYPETYPE_None,
	TBLTYPETYPE_Primitive,
	TBLTYPETYPE_Elements,
	TBLTYPETYPE_TypeRef
};
typedef enum _TBLTypeContent_t TBLTypeContent_t;

struct _TBLNamedNumber {
	tbl_t	type;
	guchar	*name;
	guint	value;
};

struct _TBLRange {
	tbl_t	type;
	guint	from;
	guint	to;
};

struct _TBLTypeRef {
	tbl_t	type;
	guint	typeDefId;
	gboolean implicit;
};

struct _TBLTag {
	tbl_t	type;
	guint	tclass;
	guint	code;
};

struct _TBLType {
	tbl_t	type;
	guint	typeId;
	gboolean	optional;
	TBLTypeContent_t content;
	guchar	*fieldName;
	gboolean anonymous;
	gboolean constraint;
};

struct _TBLTypeDef {
	tbl_t	type;
	guint	typeDefId;
	guchar	*typeName;
	guchar	isPdu;
};

struct _TBLModule {
	tbl_t	type;
	guchar 	*name;
	subid_t *id;
	guint 	isUseful;
};

struct _TT {
	guint	totalNumModules;
	guint	totalNumTypeDefs;
	guint	totalNumTypes;
	guint 	totalNumTags;
	guint	totalNumStrings;
	guint	totalLenStrings;
} TT;

#define CHECKP(p) {if (p==0){g_warning("pointer==0, line %d **********", __LINE__);return;}}

static guint
get_asn1_int(guint want_tag, guint offset)
{
	ASN1_SCK asn1;
	guint ret, cls, con, tag, def, len;
	guint value;

	/* g_message("%d get_asn1_int", offset); */

	asn1_open(&asn1, asn1_desc, offset);

	ret = asn1_header_decode(&asn1, &cls, &con, &tag, &def, &len);
	if (ret == ASN1_ERR_NOERROR) {
			 /* do not check class, both Unversal and Context are OK */
		if (con == ASN1_PRI && tag == want_tag)	{
			if (def) {
				asn1_uint32_value_decode(&asn1, len, &value);
				return value;
			} else
				ret = ASN1_ERR_LENGTH_NOT_DEFINITE;
		} else
			ret = ASN1_ERR_WRONG_TYPE;
	}
	g_warning("ASN.1 int mismatch at offset %d, %s", offset, asn1_err_to_str(ret));

	return 0;
}

static subid_t *			/* with prepended length ..... */
get_asn1_oid(guint want_tag, guint offset)
{
	ASN1_SCK asn1;
	guint ret, cls, con, tag, def, len;
	subid_t *oid;

	/* g_message("%d get_asn1_oid", offset); */

	asn1_open(&asn1, asn1_desc, offset);

	ret = asn1_header_decode(&asn1, &cls, &con, &tag, &def, &len);
	if (ret == ASN1_ERR_NOERROR) {
			/* do not check class, both Unversal and Context are OK */
		if ((con == ASN1_PRI) && (tag == want_tag))	{
			if (def) {
				asn1_oid_value_decode(&asn1, len, &oid, &con);
				oid = g_realloc(oid, con + sizeof(guint)); /* prepend the length */
				memmove(&oid[1], oid, con*sizeof(guint));
				oid[0] = con;
				return oid;
			} else
				ret = ASN1_ERR_LENGTH_NOT_DEFINITE;
		} else
			ret = ASN1_ERR_WRONG_TYPE;
	}
	g_warning("ASN.1 oid mismatch at offset %d, %s", offset, asn1_err_to_str(ret));

	return 0;
}

static guchar *			/* 0 terminated string */
get_asn1_string(guint want_tag, guint offset)
{
	ASN1_SCK asn1;
	guint ret, cls, con, tag, def, len;
	guchar *octets;

	/* g_message("%d get_asn1_string", offset); */

	asn1_open(&asn1, asn1_desc, offset);

	ret = asn1_header_decode(&asn1, &cls, &con, &tag, &def, &len);
	if (ret == ASN1_ERR_NOERROR) {
			/* do not check class, both Unversal and Context are OK */
		if ((con == ASN1_PRI) && (tag == want_tag))	{
			if (def) {
				asn1_string_value_decode(&asn1, len, &octets);
				octets = g_realloc(octets, len+1); /* need space for sentinel */
				octets[len] = 0;
				return octets;
			} else
				ret = ASN1_ERR_LENGTH_NOT_DEFINITE;
		} else
			ret = ASN1_ERR_WRONG_TYPE;
	}
	g_warning("ASN.1 string mismatch at offset %d, %s", offset, asn1_err_to_str(ret));

	return 0;
}

static guint
get_asn1_uint(guint offset)
{
	ASN1_SCK asn1;
	guint ret, len, value;	

	/* g_message( "%d get_asn1_uint", offset); */

	asn1_open(&asn1, asn1_desc, offset);

	ret = asn1_uint32_decode(&asn1, &value, &len);

	if (ret != ASN1_ERR_NOERROR) {
		g_warning("ASN.1 uint mismatch at offset %d, %s", offset, asn1_err_to_str(ret));
		value = 0;
	}
	return value;
}

static gboolean
check_tag(guint want_tag, guint offset)
{
	ASN1_SCK asn1;
	guint ret, cls, con, tag, def, len;

	asn1_open(&asn1, asn1_desc, offset);

	ret = asn1_header_decode(&asn1, &cls, &con, &tag, &def, &len);
	if (ret == ASN1_ERR_NOERROR) {
		ret = (tag == want_tag) ? TRUE : FALSE;
		/* g_message("%d check tag %d, %s", offset, want_tag, ret? "true" : "false"); */
		return ret;
	}
	g_warning("ASN.1 check_tag at offset %d, %s", offset, asn1_err_to_str(ret));

	return FALSE;
}

#if 0
static gboolean
constructed(guint offset)
{
	ASN1_SCK asn1;
	guint ret, cls, con, tag, def, len;

	/* g_message("%d constructed?", offset); */

	asn1_open(&asn1, asn1_desc, offset);

	ret = asn1_header_decode(&asn1, &cls, &con, &tag, &def, &len);
	if (ret == ASN1_ERR_NOERROR) {
		if (con) {
			return TRUE;
		}
		return FALSE;
	}
	/* g_warning("ASN.1 constructed? at offset %d, %s", offset, asn1_err_to_str(ret)); */

	return FALSE;
}
#endif

static void
define_constraint(GNode *p, GNode *q)
{
	TBLRange *range = g_malloc(sizeof(TBLRange));
	g_node_append_data(q, range);
	
	range->type = TBLTYPE_Range;
	
	/* g_message("define_constraint %p, %p", p, q); */

	p = g_node_first_child(p);
	
	range->from = get_asn1_int(0, GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);

	range->to = get_asn1_int(1, GPOINTER_TO_UINT(p->data));

}

static void
define_namednumber(GNode *p, GNode *q)
{
	TBLNamedNumber *num = g_malloc(sizeof(TBLNamedNumber));
	g_node_append_data(q, num);
	
	num->type = TBLTYPE_NamedNumber;
	
	/* g_message("define_namednumber %p, %p", p, q); */
	
	p = g_node_first_child(p);
	
	num->name = get_asn1_string(0, GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);

	num->value = get_asn1_int(1, GPOINTER_TO_UINT(p->data));
}

static void
define_typeref(GNode *p, GNode *q)
{
	TBLTypeRef *ref = g_malloc(sizeof(TBLTypeRef));
	g_node_append_data(q, ref);
	
	ref->type = TBLTYPE_TypeRef;
	
	/* g_message("define_typeref %p, %p", p, q); */

	p = g_node_first_child(p);

	ref->typeDefId = get_asn1_uint(GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);

	ref->implicit = get_asn1_int(ASN1_BOL, GPOINTER_TO_UINT(p->data));
}

static void
define_tag(GNode *p, GNode *q)
{
	TBLTag *type = g_malloc(sizeof(TBLTag));
	g_node_append_data(q, type);

	type->type = TBLTYPE_Tag;

	/* g_message("define_tag %p, %p", p, q); */

	p = g_node_first_child(p);
	
	type->tclass = get_asn1_int(ASN1_ENUM, GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);

	type->code = get_asn1_int(ASN1_INT, GPOINTER_TO_UINT(p->data));
	
}

static void
define_type(GNode *p, GNode *q)
{
	GNode *r;
	TBLType *type = g_malloc(sizeof(TBLType));

	GNode *t = g_node_append_data(q, type);

	type->type = TBLTYPE_Type;

	/* g_message("define_type %p, %p", p, q); */

	type->typeId = get_asn1_int(0, GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);

	type->optional = get_asn1_int(1, GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);

	if (check_tag(2, GPOINTER_TO_UINT(p->data))) { /* optional, need empty node if not there ?*/
		r = g_node_first_child(p);
		while (r) {
			define_tag(r, t);
			r = g_node_next_sibling(r);
		}
		p = g_node_next_sibling(p);
	}

	if (!check_tag(3, GPOINTER_TO_UINT(p->data))) {
		g_warning("expect tag 3, ERROR");
	}
	r = g_node_first_child(p);
		/* a choice ... */
	type->content = TBLTYPETYPE_None;
	if (check_tag(0, GPOINTER_TO_UINT(r->data))) type->content = TBLTYPETYPE_Primitive;
	if (check_tag(1, GPOINTER_TO_UINT(r->data))) type->content = TBLTYPETYPE_Elements;
	if (check_tag(2, GPOINTER_TO_UINT(r->data))) type->content = TBLTYPETYPE_TypeRef;
	switch(type->content) {
		case TBLTYPETYPE_Primitive:
			break;
		case TBLTYPETYPE_Elements:
			r = g_node_first_child(r);
			while (r) {
				define_type(g_node_first_child(r), t);
				r = g_node_next_sibling(r);
			}
			break;			
		case TBLTYPETYPE_TypeRef:
			define_typeref(r, t);
			break;
		case TBLTYPETYPE_None:
			g_warning("expected a contents choice, error");
			break;
	}
	p = g_node_next_sibling(p);

	type->fieldName = 0;
	type->anonymous = FALSE;
	if (p && check_tag(4, GPOINTER_TO_UINT(p->data))) {
		type->fieldName = get_asn1_string(4, GPOINTER_TO_UINT(p->data));
		p = g_node_next_sibling(p);
	} else {
		type->anonymous = TRUE;
	}

	type->constraint = FALSE;
	if (p && check_tag(5, GPOINTER_TO_UINT(p->data))) {
		type->constraint = TRUE;
		define_constraint(p, t);
		p = g_node_next_sibling(p);
	}
	
	if (p && check_tag(6, GPOINTER_TO_UINT(p->data))) {
		r =  g_node_first_child(p);
		while(r) {
			define_namednumber(r, t);
			r = g_node_next_sibling(r);
		}
	}
}

static void
define_typedef(GNode *p, GNode *q)
{
	TBLTypeDef *type_def = g_malloc(sizeof(TBLTypeDef));

	GNode *t = g_node_append_data(q, type_def);

	/* g_message("define_typedef %p, %p", p, q); */
	
	type_def->type = TBLTYPE_TypeDef;

	p = g_node_first_child(p);
	
	type_def->typeDefId = get_asn1_uint(GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);
	
	type_def->typeName = get_asn1_string(ASN1_PRNSTR, GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);
	
	define_type(g_node_first_child(p), t);
	p = g_node_next_sibling(p);
	
	type_def->isPdu = (p != 0);  /* true if it exists, value ignored */
}

static void
define_module(GNode *p, GNode *q)
{
	TBLModule *module = g_malloc(sizeof(TBLModule));

	GNode *m = g_node_append_data(q, module);
	
	/* g_message("define_module %p %p", p, q); */

	module->type = TBLTYPE_Module;
	
	p = g_node_first_child(p);
	
	module->name = get_asn1_string(0, GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);
	
	module->id = 0;
	if (check_tag(1, GPOINTER_TO_UINT(p->data))) { /* optional */ 
		module->id = get_asn1_oid(1, GPOINTER_TO_UINT(p->data));
		p = g_node_next_sibling(p);
	}
	
	module->isUseful = get_asn1_int(2, GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);

	p = g_node_first_child(p);
	while (p) {
		define_typedef(p, m);
		p = g_node_next_sibling(p);
	}
}

typedef struct _SearchDef SearchDef;
struct _SearchDef {
	const char *key;
	GNode *here;
};

static gboolean
is_typedef(GNode *node, gpointer data)
{
	TBLTypeDef *d = (TBLTypeDef *)node->data;
	SearchDef *s = (SearchDef *)data;

	if (d == 0) return FALSE;
	if (d->type != TBLTYPE_TypeDef) return FALSE;
	if (strcmp(s->key, d->typeName) == 0) {
		s->here = node;
		return TRUE;
	}
	return FALSE;
}

typedef struct _TypeRef TypeRef;
struct _TypeRef {
	GNode *type;
	char *name;
	guchar defclass;
	guint deftag;
	GNode *pdu;		/* location in PDU descriptor tree */
	guint level;		/* recursion counter */
	GNode *typetree;
	GPtrArray *refs;	/* pointers to PDUinfo structures teferencing this entry */
};

typedef struct _NameDefs NameDefs;
struct _NameDefs {
	guint max;
	guint used;
	TypeRef *info;
};
#define ALLOC_INCR 4
#define CLASSREF (ASN1_PRV+1)

static gboolean
is_named(GNode *node, gpointer data)
{
	TBLNamedNumber *num = (TBLNamedNumber *)node->data;
	NameDefs *n = (NameDefs *)data;
	guint oldmax;

	if (num == 0) return FALSE;
	if (num->type != TBLTYPE_NamedNumber) return FALSE;

	if (num->value >= n->max) { /* need larger array */
		oldmax = n->max;
		n->max = num->value + ALLOC_INCR;
		n->info = g_realloc(n->info, n->max * sizeof(TypeRef));
		memset(&n->info[oldmax], 0, (n->max - oldmax) * sizeof(TypeRef));
	}
	if (num->value > n->used)  /* track max used value, there may be holes... */
		n->used = num->value;
	
	n->info[num->value].name = num->name;

	return FALSE;
}

static gboolean
index_typedef(GNode *node, gpointer data)
{
	TBLTypeDef *d = (TBLTypeDef *)node->data;
	NameDefs *n = (NameDefs *)data;
	TypeRef *t;
	TBLTag *tag;
	guint oldmax;

	if (d == 0) return FALSE;
	if (d->type != TBLTYPE_TypeDef) return FALSE;
	
	if (d->typeDefId >= n->max) { /* need larger array */
		oldmax = n->max;
		n->max = d->typeDefId + ALLOC_INCR;
		n->info = g_realloc(n->info, n->max * sizeof(TypeRef));
		memset(&n->info[oldmax], 0, (n->max - oldmax) * sizeof(TypeRef));
	}
	if (d->typeDefId > n->used)  /* track max used value, there may be holes... */
		n->used = d->typeDefId;

	t = &(n->info[d->typeDefId]);
	t->name = d->typeName;
	t->type = node;
	t->refs = g_ptr_array_new();	/* collect references here */
	node = g_node_first_child(node); /* the real type */
	tag = (TBLTag *)node->data;
	if ((tag->type == TBLTYPE_Type) && (((TBLType *)tag)->typeId == TBL_CHOICE)) {
		/* no reasonable default... ! */
		t->defclass = 3; /* Private .... */
		t->deftag= 9999; /* a random value */
	} else {
		node = g_node_first_child(node); /* the default tag */
		tag = (TBLTag *)node->data;
		switch(tag->type) {
		case TBLTYPE_Tag:
			t->defclass = tag->tclass;
			t->deftag = tag->code;
			break;
		case TBLTYPE_TypeRef: /* take values from another one, may not be defined yet... */
			t->defclass = CLASSREF; /* invalid class.. */
			t->deftag = ((TBLTypeRef *)tag)->typeDefId;
			break;
		default:
			g_warning("***** index_typedef: expecting a tag or typeref, found %s *****",
					data_types[tag->type]);
			t->defclass = 3; /* Private .... */
			t->deftag= 9998; /* another random value */
			break;
		}
	}
	
	return FALSE;
}

static TypeRef *typeDef_names = 0;
static guint numTypedefs = 0;

static gboolean
free_node_data(GNode *node, gpointer data _U_)
{
	g_free(node->data);
	return FALSE;
}

static void
get_values(void)		/* collect values from ASN.1 tree */
				/* coded according to the tbl.asn1 description of snacc output */ 
{				/* This routine does not leave references to the tvbuff or */
				/* to the asn1_nodes, both can be freed by the caller of this.*/
	GNode *p;
	SearchDef sd;
	NameDefs nd;
	guint i;
	char X;
	const char *t, *s, *E;
	static char missing[] = "  **missing**  ";

	if (asn1_verbose) g_message("interpreting tree");
	typeDef_names = 0;  /* just forget allocated any data .... */
	
	if (data_nodes) {
		g_node_traverse(data_nodes, G_POST_ORDER, G_TRAVERSE_ALL, -1,
		    free_node_data, NULL);
		g_node_destroy(data_nodes);
	}
			
	data_nodes = g_node_new(0);

	p = g_node_first_child(asn1_nodes); /* top of the data tree */
	
	p = g_node_first_child(p);
	TT.totalNumModules = get_asn1_uint(GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);
	TT.totalNumTypeDefs = get_asn1_uint(GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);
	TT.totalNumTypes = get_asn1_uint(GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);
	TT.totalNumTags = get_asn1_uint(GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);
	TT.totalNumStrings = get_asn1_uint(GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);
	TT.totalLenStrings = get_asn1_uint(GPOINTER_TO_UINT(p->data));
	p = g_node_next_sibling(p);

	p = g_node_first_child(p);
	while (p) {
		define_module(p, data_nodes);
		p = g_node_next_sibling(p);
	}
	
	/* g_message("finished with tree"); */

	if (!tbl_types_verified) { /* verify snacc TBLTypeId contents */
		sd.key = "TBLTypeId";
		sd.here = 0;
		g_node_traverse(data_nodes, G_PRE_ORDER, G_TRAVERSE_ALL, -1, is_typedef, (gpointer)&sd);
		if (asn1_verbose) g_message("%s %sfound, %p", sd.key, sd.here?empty:"not ", sd.here);
		if (sd.here) {
			nd.max = 8;
			nd.used = 0;
			nd.info = g_malloc0(nd.max * sizeof(TypeRef));
			g_node_traverse(sd.here, G_PRE_ORDER, G_TRAVERSE_ALL, -1, is_named,
						(gpointer)&nd);
			if (asn1_verbose) g_message("tbltypenames: max=%d, info=%p", nd.max, nd.info);
			E = empty;
			for (i=0; i<=nd.used; i++) { /* we have entries in addition to snacc's */
				X = 'X';
				t = TBLTYPE(i);
				s = nd.info[i].name;
				if (s == 0) s = missing;
				if (g_strcmp(t, s) == 0) { /* OK ! */
					X = ' ';
					t = empty;
				} else {
					E = ", X  with errors  X";
				}
				if (asn1_verbose) g_message(" %c %2d %s %s", X, i, s, t);
			}
			if (asn1_verbose) g_message("OK, TBLTypeId's index verified%s", E);
		}
		tbl_types_verified = TRUE;
	}
	/* build table with typedef names */
	nd.max = 8;
	nd.used = 0;
	nd.info = g_malloc0(nd.max * sizeof(TypeRef));
	g_node_traverse(data_nodes, G_PRE_ORDER, G_TRAVERSE_ALL, -1, index_typedef, (gpointer)&nd);
	if (asn1_verbose) g_message("tbltypedefs: max=%d, info=%p", nd.max, nd.info);

	for (i=0; i<=nd.used; i++) { /* show what we have in the index now */
		TypeRef *ref = &(nd.info[i]);
		t = ref->name;
		if (t == 0) {
			t = ref->name = missing;
			if (asn1_verbose) g_message("  %3d %s", i, t);
		} else {
			if (asn1_verbose) g_message("  %3d %s, %c%d", i, t,
						    tag_class[ref->defclass], ref->deftag);
		}
		if (ref->pdu) { /* should be 0 */
			if (asn1_verbose) g_message("* %3d %s pdu=%p", i, t, ref->pdu);
		}
	}
	typeDef_names = nd.info;
	numTypedefs = i;
	if (asn1_verbose) g_message("OK, %d TBLTypeDef's index set up", numTypedefs);

}

static void
showGNode(GNode *p, int n)
{
	if (p == 0) return;
	n *=2; /* 2 spaces per level */
	if (p->data) { /* show value ... */
		/* g_message("show %p, type %d", p, ((TBLTag *)p->data)->type); */
		switch (((TBLTag *)p->data)->type) {
		case TBLTYPE_Module: {
			TBLModule *m = (TBLModule *)p->data;
			if (asn1_verbose)
				g_message("%*smodule %s%s", n, empty, m->name,
						m->isUseful ? ", useful" : empty);
			};
			break;
		case TBLTYPE_TypeDef: {
			TBLTypeDef *t = (TBLTypeDef *)p->data;
			if (asn1_verbose)
				g_message("%*stypedef %d %s%s", n, empty, t->typeDefId, t->typeName,
						t->isPdu ? ", isPDU" : empty);
			};
			break;
		case TBLTYPE_Type: {
			TBLType *t = (TBLType *)p->data;
			const char *fn, *s = empty;
			if (t->fieldName)
				s = t->fieldName;
			/* typeId is a value from enum TBLTypeId */
			fn = TBLTYPE(t->typeId);
			if (asn1_verbose) g_message("%*stype %d[%s]%s [%s]", n, empty, t->typeId, fn,
					t->optional ? " opt" : empty, s );
			};
		        break;
		case TBLTYPE_Tag: {
			TBLTag *t = (TBLTag *)p->data;
			const char *s = empty;
			if ((t->tclass == ASN1_UNI) && (t->code < 32))
				s = asn1_tag[t->code];
			if (asn1_verbose) g_message("%*stag %c%d[%s]", n, empty,
						    tag_class[t->tclass], t->code, s);
			};
		        break;
		case TBLTYPE_NamedNumber: {
			TBLNamedNumber *nn = (TBLNamedNumber *)p->data;
			if (asn1_verbose) g_message("%*snamednumber %2d %s", n, empty,
						    nn->value, nn->name);
			};
		        break;
		case TBLTYPE_Range: {
			TBLRange *r = (TBLRange *)p->data;
			if (asn1_verbose) g_message("%*srange %d .. %d", n, empty,
						    r->from, r->to );
			};
			break;
		case TBLTYPE_TypeRef: {
			TBLTypeRef *r = (TBLTypeRef *)p->data;
			const char *s = empty;
			if (typeDef_names)
				s = typeDef_names[r->typeDefId].name;
			if (asn1_verbose) g_message("%*styperef %d[%s]%s", n, empty,
						  r->typeDefId, s, r->implicit ? ", implicit" : empty );
			};
			break;
		default: {
			TBLTag *x = (TBLTag *)p->data;
			if (asn1_verbose) g_message("%*s--default-- type=%d", n, empty, x->type);
		        };
			break;
		}
	} else {	/* just show tree */
		if (asn1_verbose)
			g_message("%*snode=%p, data=%p, next=%p, prev=%p, parent=%p, child=%p",
				  n, empty, p, p->data, p->next, p->prev, p->parent, p->children);
	}
}

static void
showGNodes(GNode *p, int n)
{
	if (p == 0) return;
	showGNode(p, n);
	showGNodes(p->children, n+1);
	showGNodes(p->next, n);
}

static void showGenv(GNode *p, int n, int m)
{
	int i;

	if (p == 0) return;
	if (n > m) {
		if (asn1_verbose) g_message("%*s.....", n*2, empty);
		return;
	}

	for(i=0; p && (i < 3); p = p->next, i++) {
		showGNode(p, n);
		showGenv(p->children, n+1, m);
	}
	if (p && asn1_verbose) g_message("%*s.....", n*2, empty);

}

static void
debug_dump_TT(void)		/* dump contents of TT struct, for debugging */
{
	if (asn1_verbose)
		g_message("modules=%d, defs=%d, types=%d, tags=%d, strings=%d, lenstrings=%d",
			TT.totalNumModules,
			TT.totalNumTypeDefs,
			TT.totalNumTypes,
			TT.totalNumTags,
			TT.totalNumStrings,
			TT.totalLenStrings);
}

static void
my_log_handler(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
static FILE* logf = 0;
static char eol[] = "\r\n";

	(void) log_domain; (void) log_level; (void) user_data; /* make references */

	if (logf == NULL && asn1_logfile) {
		logf = eth_fopen(asn1_logfile, "w");
	}
	if (logf) {
	fputs(message, logf);
	fputs(eol, logf);
        fflush(logf);   /* debugging ... */
        }
}

static void
read_asn1_type_table(const char *filename)
{
	FILE *f;
	guint size;
	guchar *data;
	struct stat stat;

	if ((filename == 0) || (strlen(filename) == 0))
		return;		/* no filename provided */

	f = eth_fopen(filename, "rb");
	if (f == 0) {
		/*
		 * Ignore "file not found" errors if it's the old default
		 * ASN.1 file name, as we never shipped such a file.
		 * Also, on Win32, ignore the earlier default, which
		 * had a "/" rather than a "\" as the last pathname
		 * separator.
		 */
		if ((strcmp(filename, old_default_asn1_filename) != 0
#ifdef _WIN32
		    && strcmp(filename, bad_separator_old_default_asn1_filename) != 0
#endif
		    ) || errno != ENOENT)
			report_open_failure(filename, errno, FALSE);
		return;
	}
	fstat(fileno(f), &stat);
	size = (int)stat.st_size;
	if (size == 0) {
		if (asn1_verbose) g_message("file %s is empty, ignored", filename);
		fclose(f);
		return;
	}
	if (asn1_verbose) g_message("reading %d bytes from %s", size, filename);
	
	data = g_malloc(size);
	if (fread(data, size, 1, f) < 1) {
		g_warning("error reading %s, %s", filename, strerror(errno));
	}
	fclose(f);

	if (asn1_verbose) {
	  /* ***** from the time when logging was just in a console... *****
	   * g_message("******* Type ^S and change console buffer size to 9999 and type ^Q *******\n"
	   * 		"  Sleep 5 sec...");
	   * Sleep(5 * 1000);
	   */

		static guint mylogh = 0;
		
		g_message("logging to file %s", asn1_logfile);

		if (mylogh == 0) {
			mylogh = g_log_set_handler (NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
						    | G_LOG_FLAG_RECURSION, my_log_handler, NULL);
		}
	}

	asn1_desc = tvb_new_real_data(data, size, size);

	tt_build_tree();
	if (asn1_verbose) g_message("read %d items from %s", icount, filename);	

#if 0
	list_modules();
#endif

	get_values();

	g_node_destroy(asn1_nodes);	asn1_nodes = 0;
#ifndef _WIN32		/* tvb_free not yet exported to plugins... */
	tvb_free(asn1_desc);
#endif
					asn1_desc = 0;
	g_free(data);			data = 0;

	showGNodes(data_nodes, 0);

	debug_dump_TT();  
}


#define CHECKTYPE(p,x) {if (((TBLTag *)(p)->data)->type != (x)) \
        g_warning("**** unexpected type %s, want %s, at line %d", \
			data_types[((TBLTag *)p->data)->type], data_types[(x)], __LINE__);}


static void
save_reference(PDUinfo *p)
{
	gint i = p->mytype;

	if (i == -1)
		i = p->basetype;
	
	g_ptr_array_add(typeDef_names[i].refs, (gpointer)p);
}

static void
tbl_type(guint n, GNode *pdu, GNode *list, guint fullindex);



	/* evaluate typeref, pointer to current pdu node and typedef */
static void
tbl_typeref(guint n, GNode *pdu, GNode *tree, guint fullindex)
{
	GNode *q;
	PDUinfo *p = (PDUinfo *)pdu->data, *p1;
	guint nvals;
	value_string *v;

	if (n > 40) {  /* don't believe this....! ...... stop recursion ...... */
		g_warning("****tbl_typeref: n>40, return [recursion too deep] ****************");
		return;
	}
	
	CHECKTYPE(tree, TBLTYPE_TypeDef);

	if (asn1_verbose) g_message("%*s+tbl_typeref %s [%s, tag %c%d]", n*2, empty,
				    p->name, TBLTYPE(p->type), tag_class[p->tclass], p->tag);

	p->typenum = ((TBLTypeDef *)tree->data)->typeDefId; /* name of current type */
	p->flags |= PDU_TYPEDEF;

	tree = g_node_first_child(tree);		/* move to its underlying type */
	CHECKTYPE(tree, TBLTYPE_Type);
	p->type = ((TBLType *)tree->data)->typeId;

	q = g_node_first_child(tree);		/* the tag of this type entry ... is optional... */
	if (((TBLTag *)q->data)->type == TBLTYPE_Tag) {
		if ((p->flags & PDU_IMPLICIT) == 0) { /* not implicit, use this tag */
			guint xcls, xtag;
			xcls = p->tclass;
			xtag = p->tag;
				/* XXX -- hack -- hack -- hack -- hack -- hack --
				 * only change tag when class+tag == EOC,
				 * or class is a reference,
				 * or new class is not universal.
				 */
			if ( ((xcls|xtag) == 0) || (xcls == CLASSREF) ||
					(((TBLTag *)q->data)->tclass != ASN1_UNI) ) {
				p->tclass = ((TBLTag *)q->data)->tclass;
				p->tag = ((TBLTag *)q->data)->code;
				if (asn1_verbose)
					g_message("%*s*change typeref tag from %c%d to %c%d",
						  n*2, empty,
						  tag_class[xcls],
						  xtag,
						  tag_class[p->tclass],
						  p->tag);
			} else {
				if (asn1_verbose)
					g_message("%*sNOT changing tag from %c%d to %c%d",
						  n*2, empty,
						  tag_class[xcls],
						  xtag,
						  tag_class[((TBLTag *)q->data)->tclass],
						  ((TBLTag *)q->data)->code);
		
			}
		}
	} else {
		char ss[128];

		ss[0] = 0;
		if (p->tclass==CLASSREF)
			g_snprintf(ss, 128, ", CLASSREF %d", p->tag);
		if (asn1_verbose) g_message("%*sno typeref tag%s", n*2, empty, ss);
		
		if (p->tclass==CLASSREF) {
			TypeRef *tr;
			int i = p->basetype;
			/* CLASSREF....., get it defined using type of the reference */

			/* p->basetype may be -1 .... ? XXX */
			if (i == -1)
				i = p->tag;
			tr = &typeDef_names[i];
			if (asn1_verbose)
				g_message("%*s*refer2 to type#%d %s, %p", n*2, empty,
					  p->tag, tr->name, tr->pdu);

			tbl_typeref(n+1, pdu, tr->type, fullindex);
		
			return;
		}
	}

	if (asn1_verbose)
		g_message("%*sinclude typedef %d %s %s [%p:%s, tag %c%d]", n*2, empty, p->typenum,
			  p->name, p->typename, p, TBLTYPE(p->type), tag_class[p->tclass], p->tag);

	switch(p->type) {
	case TBL_BITSTRING:
	case TBL_ENUMERATED:
		/* names do not have a fullname */
		if (asn1_verbose) g_message("%*s*collection T %s", n*2, empty, p->name);
			/* read the enumeration [save min-max somewhere ?] */
		p->value_hf.hfinfo.type = tbl_types_ethereal[p->type]; /* XXX change field type... */
		
		proto_register_field_array(proto_asn1, &(p->value_hf) , 1);

		save_reference(p);
		
		if (asn1_verbose)
			g_message("regtype1: %3d %3d [%3d] F%2.2x (%s)%s %s %s -> id=%d",
				  p->mytype, p->typenum, p->basetype, p->flags, p->typename,
				  p->name, p->fullname,
				  tbl_types_ethereal_txt[p->type], p->value_id);
		p1 = p;
		nvals = 0;
		while((q = g_node_next_sibling(q))) {
			CHECKTYPE(q, TBLTYPE_NamedNumber);
			p = g_malloc0(sizeof(PDUinfo));
			nvals++;
			p->type = TBL_ENUMERATED;
			p->name = (((TBLNamedNumber *)q->data)->name);
			p->tag = (((TBLNamedNumber *)q->data)->value);
			p->flags = PDU_NAMEDNUM;
			if (asn1_verbose) g_message("%*s  %3d %s", n*2, empty, p->tag, p->name);
			g_node_append_data(pdu, p);
		}
		
		/* list all enum values in the field structure for matching */
		p1->value_hf.hfinfo.strings = v = g_malloc0((nvals+1) * sizeof(value_string));
		q = g_node_first_child(pdu);
		nvals = 0;
		while(q) {
			p = (PDUinfo *)q->data;
			v[nvals].value = p->tag;
			v[nvals].strptr = p->name;
/* g_message("enumval2:  %d %s %d %s %s", nvals, p1->name, p->tag, p->name, tbl_types_asn1[p1->type]); */
			nvals++;
			q = g_node_next_sibling(q);
		}
		/* last entry is already initialized to { 0, NULL } */
		
		break;

	case TBL_CHOICE:
		if (p->value_id == -1) { /* not yet registered ..... */
			p->value_hf.hfinfo.type = tbl_types_ethereal[p->type];
			proto_register_field_array(proto_asn1, &(p->value_hf) , 1);

			save_reference(p);
		
			if (asn1_verbose)
				g_message("regtype2: %3d %3d [%3d] F%2.2x (%s)%s %s %s -> id=%d",
					  p->mytype, p->typenum, p->basetype, p->flags, p->typename,
					  p->name, p->fullname,
					  tbl_types_ethereal_txt[p->type], p->value_id);
		}
		tbl_type(n, pdu, q, fullindex);
		break;

	default:
		if (p->value_id == -1) { /* not yet registered ..... */
			p->value_hf.hfinfo.type = tbl_types_ethereal[p->type];
			proto_register_field_array(proto_asn1, &(p->value_hf) , 1);

			save_reference(p);			

			if (asn1_verbose)
				g_message("regtype3: %3d %3d [%3d] F%2.2x (%s)%s %s %s -> id=%d",
					  p->mytype, p->typenum, p->basetype, p->flags, p->typename,
					  p->name, p->fullname,
					  tbl_types_ethereal_txt[p->type], p->value_id);
		}
		tbl_type(n, pdu, g_node_next_sibling(q), fullindex);
	}
}

static void
tbl_type(guint n, GNode *pdu, GNode *list, guint fullindex) /* indent, pdu, source type node list */
{
	GNode *q, *pdu1;
	PDUinfo *p, *p1;
	guint ni;
	guint nvals;
	value_string *v;

	if (n > 40) {  /* don't believe this....! ...... stop recursion ...... */
		g_warning("****tbl_type: n>40, return [recursion too deep] ****************");
		return;
	}

	/* showGenv(list, n, n+1); */

	ni = fullindex;
	pdu1 = pdu;		/* save start location for append */
	while (list) {		/* handle all entries */
		if (asn1_verbose)
			g_message("%*s+handle a %s, list=%p", n*2, empty,
				  data_types[((TBLTag *)list->data)->type], list);

		if (((TBLTag *)list->data)->type == TBLTYPE_Range) { /* ignore this ..... */
			list = g_node_next_sibling(list);
			if (asn1_verbose) g_message("%*s*skip range", n*2, empty);
			if (list == 0)
				break;
		}

		/******* change to positive comparation, but leave comment for reference
		 * if (((TBLTag *)list->data)->type != TBLTYPE_TypeRef) { 
		 *	CHECKTYPE(list, TBLTYPE_Type);
		 */

                if (((TBLTag *)list->data)->type == TBLTYPE_Type) { 
			CHECKTYPE(list, TBLTYPE_Type);

			p = g_malloc0(sizeof(PDUinfo));
			pdu = g_node_append_data(pdu1, p);

			p->type = ((TBLType *)list->data)->typeId;
			p->typename = tbl_types_asn1[p->type]; /* the default type */
			p->typenum = -1;
			p->mytype = -1;
			p->basetype = ((PDUinfo *)pdu1->data)->typenum;
			p->flags = PDUinfo_initflags;
			p->flags |= (((TBLType *)list->data)->anonymous ? PDU_ANONYMOUS : 0);
			p->flags |= (((TBLType *)list->data)->optional ? PDU_OPTIONAL : 0);
	
			if (((TBLType *)list->data)->fieldName == 0) { /* no name assigned */
				/* assign an anonymous name [XXX refer to parent typename...] */
				((TBLType *)list->data)->fieldName =
							g_strdup_printf("anon%d", anonCount++);
			}
			p->name = ((TBLType *)list->data)->fieldName;
			
			ni = fullindex;
			ni += snprintf(&fieldname[ni], sizeof(fieldname) - ni, ".%s", p->name);
			p->fullname = g_strdup(fieldname);
			
			/* initialize field info */
			p->value_id = -1;
			p->type_id = -1;
			p->value_hf.p_id = &(p->value_id);
			p->value_hf.hfinfo.name = p->fullname;
			p->value_hf.hfinfo.abbrev = p->fullname;
			p->value_hf.hfinfo.type = tbl_types_ethereal[p->type];
			p->value_hf.hfinfo.display = BASE_DEC;
			p->value_hf.hfinfo.blurb = p->fullname;
			/* all the other fields are already 0 ! */

			if (p->type < TBL__SIMPLE) {
				/* only register fields with a value here, postpone others */
				proto_register_field_array(proto_asn1, &(p->value_hf) , 1);

				save_reference(p);

				if (asn1_verbose)
					g_message("register: %3d %3d [%3d] F%2.2x (%s)%s %s %s -> id=%d",
						  p->mytype, p->typenum, p->basetype, p->flags,
						  p->typename, p->name, p->fullname,
						  tbl_types_ethereal_txt[p->type], p->value_id);
			}
			
			q = g_node_first_child(list);
		} else {
			p = (PDUinfo *)pdu->data;
			q = list;
		}


		if (asn1_verbose) g_message("%*s*switch %s %s", n*2, empty, p->name, TBLTYPE(p->type));
		
		switch (p->type) {
		case TBL_BOOLEAN:
		case TBL_INTEGER:
		case TBL_OCTETSTRING:
		case TBL_NULL:
		case TBL_OID:
		case TBL_REAL:
			CHECKTYPE(q, TBLTYPE_Tag);
			p->tclass = ((TBLTag *)q->data)->tclass;
			p->tag = ((TBLTag *)q->data)->code;
			break;
			
		case TBL_BITSTRING:
		case TBL_ENUMERATED:
			CHECKTYPE(q, TBLTYPE_Tag);
			p->tclass = ((TBLTag *)q->data)->tclass;
			p->tag = ((TBLTag *)q->data)->code;
			if (asn1_verbose) g_message("%*s*collection %s", n*2, empty, p->name);
				/* read the enumeration [save min-max somewhere ?] */
			nvals = 0;
			p1 = p;
			while((q = g_node_next_sibling(q))) {
				CHECKTYPE(q, TBLTYPE_NamedNumber);
				p = g_malloc0(sizeof(PDUinfo));
				nvals++;
				p->type = TBL_ENUMERATED;
				p->name = (((TBLNamedNumber *)q->data)->name);
				p->tag = (((TBLNamedNumber *)q->data)->value);
				p->flags = PDU_NAMEDNUM;
				if (asn1_verbose) g_message("%*s  %3d %s", n*2, empty, p->tag, p->name);
				g_node_append_data(pdu, p);
			}

			/* list all enum values in the field structure for matching */
			p1->value_hf.hfinfo.strings = v = g_malloc0((nvals+1) * sizeof(value_string));
			q = g_node_first_child(pdu);
			nvals = 0;
			while(q) {
				p = (PDUinfo *)q->data;
				v[nvals].value = p->tag;
				v[nvals].strptr = p->name;
			/* g_message("enumval1:  %d %s %d %s", nvals, p1->name, p->tag, p->name); */
				nvals++;
				q = g_node_next_sibling(q);
			}
			/* last entry is already initialized to { 0, NULL } */
			
			break;

		case TBL_SEQUENCE:
		case TBL_SET:
		case TBL_SEQUENCEOF:
		case TBL_SETOF:
		case TBL_CHOICE:
			CHECKTYPE(q, TBLTYPE_Tag);
			q = g_node_first_child(list);
			tbl_type(n+1, pdu, q, ni);
			break;
			
		case TBL_TYPEREF: {	/* may have a tag ... */
			TypeRef *tr;
			guint i;
			if(!q){
				break;
			}
			if ( ((TBLTag *)q->data)->type == TBLTYPE_Tag) {
				if ((p->flags & PDU_IMPLICIT) == 0) { /* not implicit, use this tag */
					p->tclass = ((TBLTag *)q->data)->tclass;
					p->tag = ((TBLTag *)q->data)->code;
					if (asn1_verbose)
						g_message("%*s*insert type tag %c%d", n*2, empty,
							  tag_class[p->tclass], p->tag);
				}
				q = g_node_next_sibling(q);				
			} else { /* use default tag for this type */
				tr = &typeDef_names[((TBLTypeRef *)q->data)->typeDefId];
				if ((((p->flags & PDU_IMPLICIT) == 0) && (tr->defclass != ASN1_UNI)) ||
				    				((p->tclass | p->tag) == 0 )) {
					/* not implicit, use this tag */
					p->tclass = tr->defclass;
					p->tag = tr->deftag;
					if (asn1_verbose) g_message("%*s*set tag %c%d", n*2, empty,
								    tag_class[p->tclass], p->tag);
				}
			}
			CHECKTYPE(q, TBLTYPE_TypeRef);
			i = ((TBLTypeRef *)q->data)->typeDefId;
			p->mytype = i;
			tr = &typeDef_names[i];
			if (asn1_verbose)
				g_message("%*s*type#%d %s, %p", n*2, empty, i, tr->name, tr->pdu);
			p->typename = tr->name;

			if (tr->defclass == CLASSREF) {
				if (tr->pdu == 0)
					tr->pdu = pdu;	/* remember this reference */
				i = tr->deftag;
				tr =  &typeDef_names[i];
				if (asn1_verbose)
					g_message("%*s*refer to type#%d %s, %p", n*2, empty,
						  i, tr->name, tr->pdu);
			}
			/* evaluate reference if not done before or when below recursion limit */
			if ((tr->pdu == 0) || (tr->level < type_recursion_level)) {
				tr->level++;
				if (tr->pdu == 0) {
					tr->pdu = pdu; /* save for references we leave */
				}
				p->flags |= ((TBLTypeRef *)q->data)->implicit? PDU_IMPLICIT : 0;
				if (asn1_verbose)
					g_message("%*s*typeref %s > %s%s at %p", n*2, empty,
						  p->name, 
						  ((TBLTypeRef *)q->data)->implicit?"implicit ":empty,
						  tr->name,
						  pdu);
				tbl_typeref(n+1, pdu, tr->type, ni);
				tr->level--;
			} else {
				if (asn1_verbose)
					g_message("%*s*typeref %s > %s already at %p", n*2, empty,
						  p->name, tr->name, tr->pdu);
				p->flags |= PDU_REFERENCE;
				p->reference = tr->pdu;
			}
			};
			break;
		default:
			g_warning("**** unknown tbl-type %d at line %d", p->type, __LINE__);
			break;
		}

		if (asn1_verbose)
			g_message("%*sinclude type %s %s [%p:%s, tag %c%d]",
				  n*2, empty, p->name, p->typename, p, TBLTYPE(p->type),
				  tag_class[p->tclass], p->tag);

		if (p->value_id == -1) { /* not registered before, do it now */
			proto_register_field_array(proto_asn1, &(p->value_hf) , 1);

			save_reference(p);
			
			if (asn1_verbose)
				g_message("regist-2: %3d %3d [%3d] F%2.2x (%s)%s %s %s -> id=%d",
					  p->mytype, p->typenum, p->basetype, p->flags, p->typename,
					  p->name, p->fullname,
					  tbl_types_ethereal_txt[p->type], p->value_id);
			}
		list = g_node_next_sibling(list);
	}
}

static void
PDUtext(char *txt, PDUinfo *info) /* say everything we know about this entry */
{
	PDUinfo *rinfo;
	const char *tt, *nn, *tn, *fn, *oo, *ii, *an, *tr, *ty;

	if (info) {
		tt = TBLTYPE(info->type);
		nn = info->name;
		tn = info->typename;
		fn = info->fullname;
		if (info->flags & PDU_NAMEDNUM)
			txt += sprintf(txt, "name: %2d %s", info->tag, nn);
		else {
			if (info->flags & PDU_TYPEDEF)
				txt += sprintf(txt, "def %d: ", info->typenum);
			else
				txt += sprintf(txt, "  ");
			ty = (info->flags & PDU_TYPETREE) ? "typ" : "val";
			txt += sprintf(txt, "%s %s (%s)%s [%s] tag %c%d hf=%d tf=%d",ty,tt, tn, nn, fn,
				     tag_class[info->tclass], info->tag, info->value_id, info->type_id);
			txt += sprintf(txt, ", mt=%d, bt=%d", info->mytype, info->basetype);
			oo = (info->flags & PDU_OPTIONAL) ?  ", optional"  : empty;
			ii = (info->flags & PDU_IMPLICIT) ?  ", implicit"  : empty;
			nn = (info->flags & PDU_NAMEDNUM) ?  ", namednum"  : empty;
			an = (info->flags & PDU_ANONYMOUS) ? ", anonymous" : empty;
			txt += sprintf(txt, "%s%s%s%s", oo, ii, nn, an);
			if (info->flags & PDU_REFERENCE) {
				rinfo = (PDUinfo *)((GNode *)(info->reference))->data;
				tt = TBLTYPE(rinfo->type);
				nn = rinfo->name;
				tn = rinfo->typename;
				fn = rinfo->fullname;
				txt += sprintf(txt, ", reference to %s (%s)%s [%s]", tt, tn, nn, fn);
				if (rinfo->flags & PDU_TYPEDEF)
					txt += sprintf(txt, " T%d", rinfo->typenum);
				txt += sprintf(txt, " tag %c%d", tag_class[rinfo->tclass], rinfo->tag);
				oo = (rinfo->flags & PDU_OPTIONAL) ?  ", optional"  : empty;
				ii = (rinfo->flags & PDU_IMPLICIT) ?  ", implicit"  : empty;
				nn = (rinfo->flags & PDU_NAMEDNUM) ?  ", namednum"  : empty;
				tn = (rinfo->flags & PDU_REFERENCE) ? ", reference" : empty;
				tt = (rinfo->flags & PDU_TYPEDEF) ?   ", typedef"   : empty;
				an = (rinfo->flags & PDU_ANONYMOUS) ? ", anonymous" : empty;
				tr = (rinfo->flags & PDU_TYPETREE) ?  ", typetree"  : empty;
				txt += sprintf(txt, "%s%s%s%s%s%s%s", oo, ii, nn, tn, tt, an, tr);
			}
		}
	} else {
		strcpy(txt, "no info available");
	}

	return;
}


static void
showPDUtree(GNode *p, int n)
{
	PDUinfo *info;
	char text[400];

	while (p != 0) {
		info = (PDUinfo *)p->data;

		PDUtext(text, info);

		if (asn1_verbose) g_message("%*s%s", n*2, empty, text);

		showPDUtree(g_node_first_child(p), n+1);

		p = g_node_next_sibling(p);
	}

	return;
}

static gboolean
build_pdu_tree(const char *pduname)
{
	SearchDef sd;
	guint pdudef, i, tcount;
	guint sav_len;
	PDUinfo *info;

	if (asn1_verbose) g_message("build msg tree from '%s' for '%s'", current_asn1, pduname);

	if (!data_nodes) {
		if (asn1_verbose) g_message("no data nodes");
		return FALSE;
	}
	sd.key = pduname;
	sd.here = 0;
	g_node_traverse(data_nodes, G_PRE_ORDER, G_TRAVERSE_ALL, -1, is_typedef, (gpointer)&sd);
	if (sd.here) {
		pdudef = ((TBLTypeDef *)(sd.here->data))->typeDefId;
		if (asn1_verbose) g_message("%s found, %p, typedef %d", sd.key, sd.here, pdudef);
	} else {
		if (asn1_verbose) g_message("%s not found, ignored", sd.key);
		return FALSE;
	}

	/* If there's an existing PDU tree, free it */
	if (PDUtree) {
		g_node_traverse(PDUtree, G_POST_ORDER, G_TRAVERSE_ALL, -1,
		    free_node_data, NULL);
		g_node_destroy(PDUtree);
	}

	/* initialize the PDU tree, hand craft the root entry */

	info = g_malloc0(sizeof(PDUinfo));
	info->name = pduname;
	info->typename = pduname;
	info->type = TBL_SEQUENCEOF;
	info->fullname = g_strdup_printf("%s.%s", pabbrev, pduname);
	info->flags = PDUinfo_initflags = 0;
	info->value_id = -1;
	info->type_id = -1;
	info->basetype = -1;
	info->mytype = pdudef;

	info->value_hf.p_id = &(info->value_id);
	info->value_hf.hfinfo.name = info->fullname;
	info->value_hf.hfinfo.abbrev = info->fullname;
	info->value_hf.hfinfo.type = tbl_types_ethereal[info->type];
	info->value_hf.hfinfo.display = BASE_DEC;
	info->value_hf.hfinfo.blurb = info->fullname;

	anonCount = 0; /* anonymous types counter */
	
	PDUtree = g_node_new(info);
	pabbrev_pdu_len = sprintf(fieldname, "%s.%s.", pabbrev, pduname);
	sav_len = pabbrev_pdu_len;

	/* Now build the tree for this top level PDU */
	if (asn1_verbose)
		g_message("******** Define main type %d, %s", pdudef, pduname);
	tbl_typeref(0, PDUtree, sd.here, pabbrev_pdu_len-1);	/* strip initial . for new names */

	if (asn1_verbose)
		g_message("%d anonymous types", anonCount);

	/* Now make all types used available for matching */
	if (asn1_verbose)
		g_message("Define the types that are actually referenced through the top level PDU");
	for (i=0, tcount=0; i<numTypedefs; i++) {
		TypeRef *tr = &(typeDef_names[i]);

		if (tr->pdu) {	/* ignore if not used in main pdu */
			tcount++;
			if (i == pdudef)
				g_warning("pdu %d %s defined twice, TopLevel & type", pdudef, pduname);
			if (asn1_verbose)
				g_message("******** Define type %d, %s", i, tr->name);

			/* .... do definition ..... */
			info = g_malloc0(sizeof(PDUinfo));
			info->name = tr->name;
			info->typename = tr->name;
			info->tclass = tr->defclass;
			info->tag = tr->deftag;
			info->type = TBL_TYPEREF;
			info->fullname = g_strdup_printf("%s.--.%s", pabbrev, tr->name);
			info->flags = PDUinfo_initflags = PDU_TYPETREE;
			info->value_id = -1;
			info->type_id = -1;
			info->basetype = -1;
			info->mytype = i;

			info->value_hf.p_id = &(info->value_id);
			info->value_hf.hfinfo.name = info->fullname;
			info->value_hf.hfinfo.abbrev = info->fullname;
			info->value_hf.hfinfo.type = tbl_types_ethereal[info->type];
			info->value_hf.hfinfo.display = BASE_DEC;
			info->value_hf.hfinfo.blurb = info->fullname;
			
			tr->typetree = g_node_new(info);
			pabbrev_pdu_len = sprintf(fieldname, "%s.--.%s.", pabbrev, tr->name);
			tbl_typeref(0, tr->typetree, tr->type, pabbrev_pdu_len-1);
		}
	}
	if (asn1_verbose)
		g_message("%d types used", tcount);

	pabbrev_pdu_len = sav_len;

	/* and show the result */
	if (asn1_verbose)
		g_message("Type index:");
	for (i=0; i<numTypedefs; i++) {
		TypeRef *tr = &(typeDef_names[i]);
		guint j, k;
		gint defid;
		PDUinfo *p, *q;
		char text[400];
		
		if (tr->pdu == 0) /* skip if not used */
			continue;

		if (asn1_verbose)
			g_message("  %3d %s, %c%d, refs: %d",
				  i, tr->name, tag_class[tr->defclass], tr->deftag,
				  g_ptr_array_len(tr->refs));

		/* get defining node for this type */
		defid = -1;
		if (tr->typetree) {
			p = (PDUinfo *)(tr->typetree->data);
			defid = p->value_id;
			if (asn1_verbose)
				g_message("      -- defining id=%d", defid);
		}
		for(j=0; j < g_ptr_array_len(tr->refs); j++) {	/* show refs, and set type_id */
			p = (PDUinfo *)g_ptr_array_index(tr->refs, j);
			if (p->mytype == (gint)i)
				p->type_id = defid;	/* normal reference */
			else {
				if ((p->flags & PDU_TYPETREE) == 0) {
					/* we have a primitive value, find its real type */
					for(k=0; k < g_ptr_array_len(tr->refs); k++) {
							/* look at all refs */
						q = (PDUinfo *)g_ptr_array_index(tr->refs, k);
						if ((q->flags & PDU_TYPETREE) == 0)
							continue; /* only type trees are interresting */
						if (q->type != p->type)
							continue; /* must be same types */
						if (strcmp(q->name, p->name) == 0) {
							/* OK, take the first we find, not entirely
							 * correct, it may be from a different
							 * base-base type...... XXX */
							p->type_id = q->value_id;
							break;
						}	
					}
				}
			}

			if (asn1_verbose) {
				PDUtext(text, p);
				g_message("      %s", text);
			}
		}
	}
	
	if (asn1_verbose)
		g_message("The resulting PDU tree:");
	showPDUtree(PDUtree, 0);

	return TRUE;
}


#ifdef DISSECTOR_WITH_GUI
/* This cannot work in tethereal.... don't include for now */
#if GTK_MAJOR_VERSION >= 2
#define SHOWPDU	/* this needs GTK2 */
#endif
#endif /* DISSECTOR_WITH_GUI */
#ifdef SHOWPDU

static GtkWidget *window = NULL;

/* the columns in the tree view */
enum
{
   TITLE_COLUMN,		/* text in this row */
   DEF_COLUMN,			/* definition in this row, if any */
   REF_COLUMN,			/* referennce from this column, if any */
   VALUE_COLUMN,		/* indicate this is a value */
   NAME_COLUMN,			/* name of this row */
   N_COLUMNS
};

static FILE *namelist = 0;

static void
build_tree_view(GtkTreeStore *store, GNode *p, GtkTreeIter *iter)
{
	GtkTreeIter iter2;
	PDUinfo *info, *rinfo;
	gint def, ref;
	guchar *pb;

	char text[400];

	while (p != 0) {
		info = (PDUinfo *)p->data;

		gtk_tree_store_append (store, &iter2, iter);  /* Acquire iterator */

		PDUtext(text, info);

		def = ref = -1;
		if (info->flags & PDU_TYPEDEF)
			def = info->typenum;

		if (info->flags & PDU_REFERENCE) {
			rinfo = (PDUinfo *)((GNode *)(info->reference))->data;
			ref = rinfo->typenum;
		}
		pb = GTK_STOCK_CANCEL;
		if (G_NODE_IS_LEAF(p)) {
			if (info->flags & PDU_NAMEDNUM)
				pb = GTK_STOCK_BOLD;
			else {
				pb = GTK_STOCK_YES;
				if (namelist)
					fprintf(namelist, "%16s %s\n",
						&(TBLTYPE(info->type)[4]), info->fullname);
			}
		} else {
			switch (info->type) {
			case TBL_ENUMERATED:
			case TBL_BITSTRING:
				pb = GTK_STOCK_ADD;
				if (namelist)
					fprintf(namelist, "%16s %s\n",
						&(TBLTYPE(info->type)[4]), info->fullname);
				break;
			default:
				break;
			}
		}

		gtk_tree_store_set (store, &iter2,
				    TITLE_COLUMN, text,
				    DEF_COLUMN, def,
				    REF_COLUMN, ref,
				    VALUE_COLUMN, pb,
				    NAME_COLUMN, info->fullname,
				    -1);

		build_tree_view(store, g_node_first_child(p), &iter2);

		p = g_node_next_sibling(p);
	}

	return;
}


struct DefFind {
	gint def;
	GtkTreePath *path;
};

#define PATHSTACKMAX 10
static GtkTreePath *pathstack[PATHSTACKMAX];
static gint pathstackp = 0;

static void add_path(GtkTreePath *p)
{
	if (pathstackp >= PATHSTACKMAX) { /* shift old contents */
		gtk_tree_path_free(pathstack[0]); /* we forget about this one */
		memmove(&pathstack[0], &pathstack[1], (PATHSTACKMAX-1)*sizeof(GtkTreePath *));
		pathstackp--;
	}
	pathstack[pathstackp++] = p;
}

static GtkTreePath *pop_path(void)
{
	if (pathstackp > 0)
		return pathstack[--pathstackp];
	return 0;
}

static gboolean
find_definition(GtkTreeModel *model, GtkTreePath *path, GtkTreeIter *iter, gpointer data)
{
	gint def;

	struct DefFind *df = (struct DefFind *)data;

	gtk_tree_model_get (model, iter, DEF_COLUMN, &def, -1);

	if (def == df->def) {
		df->path = gtk_tree_path_copy (path);
		return TRUE;
	}
	return FALSE;

}

static void
my_signal_handler(GtkTreeView *treeview, GtkTreePath *spath, GtkTreeViewColumn *arg2, gpointer model)
{
	GtkTreeIter iter;
	GtkTreePath *path, *path2;
	gchar *text, *oldpath, *newpath;
	gint def, ref;
	struct DefFind df;

	(void) arg2;

	path = gtk_tree_path_copy (spath);

	gtk_tree_model_get_iter (model, &iter, path);
	gtk_tree_model_get (model, &iter, TITLE_COLUMN, &text, DEF_COLUMN, &def, REF_COLUMN, &ref, -1);

	oldpath = gtk_tree_path_to_string(path);
	path2 = gtk_tree_path_copy (path);

	add_path(gtk_tree_path_copy(path));

	if (ref != -1) {	/* this is a reference, find matching definition */
		df.def = ref;
		df.path = 0;
		gtk_tree_model_foreach (model, find_definition, &df);
		if (df.path) {
			gtk_tree_path_free(path);
			path = df.path;
		}
	} else {		/* just move to the next entry, if it exists */
		gtk_tree_path_next(path2);

		if (gtk_tree_model_get_iter (model, &iter, path2)) {
			gtk_tree_path_free(path);
			path = path2;	/* OK */
		} else {
			if (gtk_tree_path_get_depth (path) > 1)
				gtk_tree_path_up (path);
		}
	}

	if (path != path2)
		gtk_tree_path_free (path2);

	gtk_tree_view_expand_to_path (treeview, path);
	gtk_tree_view_expand_row (treeview, path, FALSE);

	gtk_tree_view_scroll_to_cell (treeview, path, NULL, TRUE, 0.2, 0.0);

	gtk_tree_view_set_cursor (treeview, path, NULL, FALSE);

	newpath = gtk_tree_path_to_string(path);

	if (asn1_debug)
		g_message("my_signal_handler: treeview=%p, moveing from %s to %s",
			  treeview, oldpath, newpath);

	g_free(text);
	g_free(oldpath);
	g_free(newpath);
	/* if (df.path) */
	/*	gtk_tree_path_free(df.path); */
}


static void
menuitem_cb (gpointer             callback_data,
             guint                callback_action,
             GtkWidget           *widget)
{
  GtkWidget *dialog;
  GtkTreeModel *model;
  GtkTreeView *treeview = gtk_item_factory_popup_data_from_widget(widget);
  GtkTreeSelection *selection;
  GtkTreeIter iter;
  gchar *text, *name;
  gint def, ref;
  GtkTreePath *path;
  gchar *oldpath, *newpath;
  GtkTreeViewColumn *focus_column;

  selection = gtk_tree_view_get_selection(treeview);

  model = gtk_tree_view_get_model(treeview);
  gtk_tree_view_get_cursor (treeview, &path, &focus_column);

  if (gtk_tree_model_get_iter (model, &iter, path)) {

	  gtk_tree_model_get (model, &iter, TITLE_COLUMN, &text, DEF_COLUMN, &def, REF_COLUMN, &ref,
			      NAME_COLUMN, &name, -1);
	  oldpath = gtk_tree_path_to_string(path);
	  newpath = empty;

	  switch (callback_action) {
	  case 0:		/* Select */
		  gtk_tree_selection_select_path (selection, path);
		  break;
	  case 1:		/* back */
		  path = pop_path();
		  if (path) {
			  gtk_tree_view_expand_to_path (treeview, path);
			  gtk_tree_view_expand_row (treeview, path, FALSE);

			  gtk_tree_view_scroll_to_cell (treeview, path, NULL, TRUE, 0.2, 0.0);

			  gtk_tree_view_set_cursor (treeview, path, NULL, FALSE);

			  newpath = gtk_tree_path_to_string(path);

			  gtk_tree_path_free(path);
		  } else
			  newpath = g_strdup("** no path **");
		  if (asn1_debug)
			  g_message("menueitem_cb: treeview=%p, moveing from %s to %s",
				    treeview, oldpath, newpath);
		  break;

	  case 2:		/* Find */
		  /* get all non anonymous names to the root */

	  default:
		  dialog = gtk_message_dialog_new (GTK_WINDOW (callback_data),
						   GTK_DIALOG_DESTROY_WITH_PARENT,
						   GTK_MESSAGE_INFO,
						   GTK_BUTTONS_CLOSE,
				"You selected the menu item: \"%s\" [%d]\n%s\npath=%s, %s\nname='%s'",
						   gtk_item_factory_path_from_widget (widget),
						   callback_action, text, oldpath, newpath, name);

		  /* Close dialog on user response */
		  g_signal_connect (dialog,
				    "response",
				    G_CALLBACK (gtk_widget_destroy),
				    NULL);
  
		  gtk_widget_show (dialog);
		  break;
	  }
	  g_free(text);
	  g_free(name);
	  if (newpath != empty)
		  g_free(newpath);
	  g_free(oldpath);
  } else
	  g_message("menuitem_cb: no iterator...");
}

static GtkItemFactoryEntry menu_items[] = {
  { "/Select",  NULL,         menuitem_cb, 0, NULL, 0 },
  { "/Back",	"<control>B", menuitem_cb, 1, NULL, 0 },
  { "/Find",	"<control>F", menuitem_cb, 2, NULL, 0 },
  { "/Save",	"<control>S", menuitem_cb, 3, NULL, 0 },
};

static gint button_press_callback( GtkWidget      *widget, 
                                   GdkEventButton *event,
                                   gpointer        data )
{
	GtkTreeView *treeview = GTK_TREE_VIEW(widget);

	/* g_message("button_press_callback, widget=%p, button=%d, type=%d, x=%g, y=%g, x_root=%g,"
	 *   " y_root=%g", widget, event->button, event->type, event->x, event->y, event->x_root,
	 *                 event->y_root );
	 */
	if (event->button == 3) {
		gtk_item_factory_popup_with_data ((GtkItemFactory *)data, treeview, NULL,
                                             event->x_root,
                                             event->y_root,
                                             event->button,
                                             event->time);
		return TRUE;
	}
	return FALSE;		/* continue handling this event */
}


static void
create_message_window(void)
{
	GtkCellRenderer *renderer;
	GtkTreeStore *model;
	GtkWidget *vbox;
	GtkWidget *sw;
	GtkWidget *treeview;
	gchar *text;
	GtkItemFactory *item_factory;
	GtkAccelGroup *accel_group;
	gint nmenu_items = sizeof (menu_items) / sizeof (menu_items[0]);

    if ( ! window) {
	    
	/* create window, etc */
	window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title (GTK_WINDOW (window), current_pduname);
	g_signal_connect (window, "destroy",
			  G_CALLBACK (gtk_widget_destroyed), &window);

	vbox = gtk_vbox_new (FALSE, 8);
	gtk_container_set_border_width (GTK_CONTAINER (vbox), 4);
	gtk_container_add (GTK_CONTAINER (window), vbox);

	text = g_strdup_printf("ASN.1 message structure from %s, %s", current_asn1, current_pduname);

	gtk_box_pack_start (GTK_BOX (vbox),
			    gtk_label_new (text),
			    FALSE, FALSE, 0);
	g_free(text);

	sw = gtk_scrolled_window_new (NULL, NULL);
	gtk_scrolled_window_set_shadow_type (GTK_SCROLLED_WINDOW (sw),
					     GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy (GTK_SCROLLED_WINDOW (sw),
					GTK_POLICY_AUTOMATIC,
					GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start (GTK_BOX (vbox), sw, TRUE, TRUE, 0);

	model = gtk_tree_store_new(N_COLUMNS, G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT,
				   G_TYPE_STRING, G_TYPE_STRING);

	namelist = eth_fopen("namelist.txt", "w");
	build_tree_view(model, PDUtree, NULL);
	fclose(namelist);
	namelist = 0;

	/* create tree view */
	treeview = gtk_tree_view_new_with_model (GTK_TREE_MODEL (model));
	g_object_unref (model);
	gtk_tree_view_set_rules_hint (GTK_TREE_VIEW (treeview), TRUE);
	gtk_tree_selection_set_mode (gtk_tree_view_get_selection (GTK_TREE_VIEW (treeview)),
				     GTK_SELECTION_MULTIPLE);

	renderer = gtk_cell_renderer_text_new ();

#if 0 /* testing pango attributes */
{
	PangoAttribute* bg;
	PangoAttrList* attr;

	attr = pango_attr_list_new();
	bg = pango_attr_background_new(50000,55000,50000);
	bg->start_index = 0;
	bg->end_index = 10000;
	pango_attr_list_insert(attr, bg);

	g_object_set(renderer, "attributes", attr, NULL);
}
#endif /* testing pango attributes */

	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW(treeview),
						     TITLE_COLUMN, "asn1 entities", renderer,
						     "text", TITLE_COLUMN, NULL );
	
	/* renderer = gtk_cell_renderer_text_new ();
	 * gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW(treeview),
	 *					     DEF_COLUMN, "type definition", renderer,
	 *					     "text", DEF_COLUMN, NULL );
	 *
	 * renderer = gtk_cell_renderer_text_new ();
	 * gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW(treeview),
	 * 					     REF_COLUMN, "reference", renderer,
	 *					     "text", REF_COLUMN, NULL );
	 */
	renderer = gtk_cell_renderer_pixbuf_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW(treeview),
						     VALUE_COLUMN, "value", renderer,
						     "stock_id", VALUE_COLUMN, NULL );

	renderer = gtk_cell_renderer_text_new ();
	gtk_tree_view_insert_column_with_attributes (GTK_TREE_VIEW(treeview),
						     NAME_COLUMN, "fieldname", renderer,
						     "text", NAME_COLUMN, NULL );

	gtk_container_add (GTK_CONTAINER (sw), treeview);

	/* gtk_tree_view_set_headers_visible (GTK_TREE_VIEW(treeview), FALSE); */

	/* create menu */

	accel_group = gtk_accel_group_new ();

	/* This function initializes the item factory.
	 * Param 1: The type of menu - can be GTK_TYPE_MENU_BAR, GTK_TYPE_MENU,
	 *          or GTK_TYPE_OPTION_MENU.
	 * Param 2: The path of the menu.
	 * Param 3: A pointer to a gtk_accel_group.  The item factory sets up
	 *          the accelerator table while generating menus.
	 */

	item_factory = gtk_item_factory_new (GTK_TYPE_MENU, "<menu>", accel_group);
	
	/* This function generates the menu items. Pass the item factory,
	   the number of items in the array, the array itself, and any
	   callback data for the the menu items. */
	gtk_item_factory_create_items (item_factory, nmenu_items, menu_items, NULL);

	/* Attach the new accelerator group to the window. */
	gtk_window_add_accel_group (GTK_WINDOW (window), accel_group);


	/* expand all rows after the treeview widget has been realized */
	g_signal_connect (treeview, "realize",
			  G_CALLBACK (gtk_tree_view_expand_all), NULL);
	g_signal_connect (treeview, "row-activated",
			  G_CALLBACK (my_signal_handler), (gpointer)model);

	g_signal_connect (treeview, "button_press_event",
			  G_CALLBACK (button_press_callback), item_factory);

	/* g_signal_connect_swapped (treeview, "event",
	 *			 	 G_CALLBACK (button_press_handler), 
	 *				menu);
	 */
	gtk_window_set_default_size (GTK_WINDOW (window), 650, 400);
    }

    if (!GTK_WIDGET_VISIBLE (window))
	    gtk_widget_show_all (window);
    else
	    {
		    gtk_widget_destroy (window);
		    window = NULL;
	    }
}
#endif /* SHOWPDU */

/************************************************************************************************
 *    routines to find names to go with the decoded data stream	 				*
 ************************************************************************************************/
typedef struct _statestack statestack;
static struct _statestack {
	GNode *node;
	guint type;
	guint offset;
	const char *name;
} PDUstate[1024];
static gint PDUstatec = 0;

#define PUSHNODE(x)   { PDUstate[PDUstatec++] = (x); }
#define STORENODE(x)  { PDUstate[PDUstatec-1] = (x); }
#define POPSTATE      PDUstate[--PDUstatec]
#define GETSTATE      PDUstate[PDUstatec-1]
#define GETNAME	      (((PDUinfo *)pos.node->data)->name)
#define TYPENAME      (((PDUinfo *)pos.node->data)->typename)
#define GETTYPE	      (((PDUinfo *)pos.node->data)->type & TBL_TYPEmask)
#define GETFLAGS      (((PDUinfo *)pos.node->data)->flags)
#define GETINFO	      ((PDUinfo *)pos.node->data)
#define NEXT	      {pos.node = g_node_next_sibling(pos.node);pos.type=0;}
#define CHILD	      {pos.node = g_node_first_child(pos.node);pos.type=0;}
#define MATCH	      ((class == info->tclass) && (tag == info->tag))
#define ISOPTIONAL    (info && (info->flags & PDU_OPTIONAL))
#define ISIMPLICIT    (info && (info->flags & PDU_IMPLICIT))
#define ISREFERENCE   (info && (info->flags & PDU_REFERENCE))
#define ISCHOICE      (info && (info->flags & PDU_CHOICE))
#define ISANONYMOUS   (info && (info->flags & PDU_ANONYMOUS))

#undef CHECKP
#define CHECKP(p) {if ((p==0)||(PDUstatec<0)){g_warning("pointer==0, line %d **********", __LINE__);\
				pos.node=0;PUSHNODE(pos);return ret;}}


static void
showstack(statestack *pos, char *txt, int n)
{
	char buf[1024];
	const char *name, *type, *stype;
	const char *rep, *chs, *done, *ref, *pop, *chr, *rch, *sch, *con;
	int i, j;
	GNode *g;
	statestack *p;
	guint typef;

	if ( ! asn1_verbose)
		return;
	
	if (n>PDUstatec)
		n = PDUstatec;
	if (n<0) {
		g_message("==underflow");
		return;
	}
	rep = chs = done = ref = pop = chr = rch = sch = con = empty;

	g = pos->node;
	if (g) {
		name = ((PDUinfo *)g->data)->name;
		type = TBLTYPE(((PDUinfo *)g->data)->type);
	} else {
		name = "node<null>";
		type = "?";
	}
	typef = pos->type;
	stype = TBLTYPE(typef);
	if (typef & TBL_REPEAT)		rep  = "[repeat]";
	if (typef & TBL_CHOICE_made)	chs  = "[choice]";
	if (typef & TBL_SEQUENCE_done)	done = "[done]";
	if (typef & TBL_REFERENCE)	ref  = "[ref]";
	if (typef & TBL_REFERENCE_pop)	pop  = "[ref-pop]";
	if (typef & TBL_CHOICE_repeat)  chr  = "[chs-rep]";
	if (typef & TBL_REPEAT_choice)  rch  = "[rep-chs]";
	if (typef & TBL_SEQUENCE_choice)sch  = "[seq-chs]";
	if (typef & TBL_CONSTRUCTED)    con  = "[constr]";

	i = sprintf(buf, "%s sp=%d,pos=%p,%s%s%s%s%s%s%s%s%s%s:%s,%d", txt, PDUstatec,
		    pos->node, stype, rep, chs, done, ref, pop, chr, rch, sch, con,
		    pos->name, pos->offset);

	for(j=1, n--; n>0; j++, n--) {
		p = &PDUstate[PDUstatec-j];
		typef = p->type;
		stype = TBLTYPE(typef);
		rep  = (typef & TBL_REPEAT)         ? "[repeat]"  : empty;
		chs  = (typef & TBL_CHOICE_made)    ? "[choice]"  : empty;
		done = (typef & TBL_SEQUENCE_done)  ? "[done]"    : empty;
		ref  = (typef & TBL_REFERENCE)      ? "[ref]"     : empty;
		pop  = (typef & TBL_REFERENCE_pop)  ? "[ref-pop]" : empty;
		chr  = (typef & TBL_CHOICE_repeat)  ? "[chs-rep]" : empty;
		rch  = (typef & TBL_REPEAT_choice)  ? "[rep-chs]" : empty;
	        sch  = (typef & TBL_SEQUENCE_choice)? "[seq-chs]" : empty;
		con  = (typef & TBL_CONSTRUCTED)    ? "[constr]"  : empty;

		i += sprintf(&buf[i], "| sp=%d,st=%p,%s%s%s%s%s%s%s%s%s%s:%s,%d", PDUstatec-j,
			p->node, stype, rep, chs, done, ref, pop, chr, rch, sch, con,
			p->name, p->offset);
	}
	g_message(buf);
}

static void
showrefNode(GNode *node, int n)
{
	const char *name = empty, *type = empty, *tname = empty;
	int cls = 0, tag = 0;
	PDUinfo *info;
	GNode *ref = 0;

	if (n > 10) {
		g_message("%*sstop, nesting too deep", 2*n, empty);
		return;
	}
	if (node->data) {
		info = (PDUinfo *)(node->data);
		type = TBLTYPE(info->type);
		name = info->name;
		tname = info->typename;
		ref  = info->reference;
		cls = info->tclass;
		tag = info->tag;
	}
	g_message("%*sreference '(%s)%s:%s' at %p: data=%p, reference=%p, %c%d",
		 2*n, empty, tname, type, name, node, node->data,
		  ref, tag_class[cls], tag);

	if (ref)
		showrefNode(ref, n+1);
}

static void
showNode(GNode *node, int n, int m)
{
	const char *name = empty, *type = empty;
	GNode *ref = 0;

	if (n > m)
		return;

	if (node->data) {
		type = TBLTYPE(((PDUinfo *)(node->data))->type);
		name = ((PDUinfo *)(node->data))->name;
		ref  = ((PDUinfo *)(node->data))->reference;
	}
	g_message("%*snode '%s:%s' at %p: data=%p, next=%p, prev=%p, parent=%p, child=%p",
		 2*n, empty, type, name, node, node->data, node->next, node->prev,
		 					node->parent, node->children);

	if (m > 10) {
		g_message("%*sstop, nesting too deep", 2*n, empty);
		return;
	}

	if (ref) showrefNode(ref, n+2);

	if (node->children) showNode(node->children, n+1, m);
	if (node->next) showNode(node->next, n, m);
}

static void
PDUreset(int count, int count2)
{
	statestack pos;

	if (asn1_verbose) g_message("PDUreset %d-%d", count, count2);

	PDUstatec = 0; /* stackpointer */
	PDUerrcount = 0; /* error counter per asn.1 message */
	
	pos.node = 0; /* sentinel */
	pos.name = "sentinel";
	pos.type = TBL_SEQUENCEOF;
	pos.offset = 0;
	PUSHNODE(pos);

	if (PDUtree) {
		pos.node = PDUtree; /* root of the tree */
		pos.name = GETNAME;
		pos.type = GETTYPE | TBL_REPEAT;
		pos.offset = 0;
		PUSHNODE(pos);
	}
}

static GNode *			/* find GNode for a choice element, 0 if none */
makechoice(GNode *p, guint class, guint tag)
{
	GNode *q;
	PDUinfo *info;

	p = g_node_first_child(p); /* the list of choices */
	info = 0;		/* avoid gcc warning */

	while (p) {
		info = ((PDUinfo *)p->data);

		if (info->type == TBL_CHOICE) {
			if (asn1_verbose)
				g_message("    using sub choice (%s)%s", info->typename, info->name);
			
			q = makechoice(p, class, tag);
			if (q) { /* found it */
				p = q;
				info = ((PDUinfo *)p->data);
				break;
			} /* continue with this level */

		} else {
			if (asn1_verbose)
				g_message("    have %c%d, found %c%d, %s", tag_class[class], tag,
					    tag_class[info->tclass], info->tag, info->name);

			if ((class == info->tclass) && (tag == info->tag))
				break;	/* found it */
		}

		p = g_node_next_sibling(p);
	}
	if (asn1_verbose) {
		if (p) g_message("    OK, '%s:(%s)%s' chosen", tbl_types[info->type], info->typename,
				 info->name);
		else   g_message("    ...no matching choice...");
	}
	return p;
}

		/* offset is for debugging only, a reference to output on screen */
static PDUprops *
getPDUprops(PDUprops *out, guint offset, guint class, guint tag, guint cons)
{
	statestack pos, pos2, save_pos;
	PDUinfo *info;
	const char *ret, *tmp;
	int typeflags = 0, donext = 0, pushed = 0, cons_handled = 0;
	static char namestr[64]; /* enough ? */
	static char posstr[40];
	static char noname[] = "*noname*";
	static PDUprops constructed_save; /* for unexpectedly constructed enteties */

	if (PDUstatec > 0) 	/* don't read from below the stack */
		pos = POPSTATE;
	/* pos refers to the last asn1 node handled */
	
	/* a very simple, too simple??, way to handle constructed entities */
	if ((PDUstatec > 0) && (pos.type & TBL_CONSTRUCTED)) {
	       		/* unexpectedly constructed, return same info as last time */
		sprintf(posstr, "==off=%d %c%d%c", offset, tag_class[class], tag, cons?'c':'p');
		showstack(&pos, posstr, 3);
		pos.offset = offset;
		pos.type &= ~TBL_CONSTRUCTED; /* remove the flag */
		PUSHNODE(pos);	/* push extra, to match with a EOI operation */
		PUSHNODE(pos);	/* restore the stack */
		*out = constructed_save;
		if (asn1_verbose)
			g_message("  return for constructed %s (%s)%s",
				  TBLTYPE(out->type), out->typename, out->name);
		return out;
	}

	save_pos = pos; /* may need it again */

	out->type = 0;
	out->name = 0;
	out->typename = "*error*";
	out->fullname = 0;
	out->flags = 0;
	out->data = 0;
	out->value_id = -1;
	out->type_id = -1;

	if (PDUstatec <= 0) {
		if (PDUstatec > -10) {
			if (asn1_verbose)
				g_message(">>off=%d stack underflow, return", offset);
		}
		if (PDUstatec == -10) {
			if (asn1_verbose)
				g_message(">>off=%d stack underflow, return, no more messages", offset);
		}
		out->name = "*underflow*";
		out->flags |= OUT_FLAG_noname;
		PDUerrcount++;
		return out;
	}
	sprintf(posstr, "==off=%d %c%d%c", offset, tag_class[class], tag, cons?'c':'p');

	showstack(&pos, posstr, 3);

	ret = noname;

	if (class == ASN1_EOI) { /* end of this input sequence */
		
		if (pos.type & TBL_REFERENCE_pop) { /* reference finished, return to caller */
			if (asn1_verbose) g_message("    EOI: reference pop");
			pos = POPSTATE;
		} else
		switch(pos.type & TBL_TYPEmask) {
		case TBL_TYPEREF:
			if (asn1_verbose) g_message("    EOI: pop typeref");
			pos = POPSTATE;	/* remove typeref */
			break;
		case TBL_CHOICE_done:
			if (asn1_verbose) g_message("    EOI: mark choice");
			pos = POPSTATE;
			pos.type |= TBL_CHOICE_made; /* poropagate this up the stack */
			PUSHNODE(pos);
			break;
		default:
			break;
		}


		pos = POPSTATE;	/* this is pushed back on the stack later */
		if (pos.node == 0) {
			if (asn1_verbose) g_message("  EOI, pos.node == 0");
			out->name = "*no-name-EOI*";
			out->flags |= OUT_FLAG_noname;
			PDUerrcount++;
			return out;
		}

		info = GETINFO;
		ret = info->name;
		tmp = TBLTYPE(info->type);
		if (offset != pos.offset) {
			if (asn1_verbose)
				g_message("  *EOI %s:%s mismatch, EOIoffset=%d, stack=%d",
					  tmp, ret, offset, pos.offset);
			while ((offset < pos.offset) && (PDUstatec > 0)) {
				pos = POPSTATE;
				if (asn1_verbose)
					g_message("  EOI extra pop, EOIoffset=%d, stack=%d",
						  offset, pos.offset);
			}
			if (offset != pos.offset)
				PDUerrcount++; /* only count if still unequal */
		} else {
			if (asn1_verbose) g_message("  EOI %s:%s OK, offset=%d", tmp, ret, offset);
		}
	} else {
		/* EOC is only present for indefinite length sequences, etc. end of sequence is always
		 * indicated by the synthetic EOI call. */
		if ((class == ASN1_UNI) && (tag == ASN1_EOC)) { /* explicit EOC never has a name */
			PUSHNODE(pos); /* restore stack */
			ret = "explicit-EOC";
			if (asn1_verbose) g_message("  return '%s', ignore", ret);
			out->name = ret;
			out->typename = "ASN1";
			return out;
		}

		/* find appropriate node for this tag */

		if (pos.node == 0) {
			if (asn1_verbose) g_message("  pos.node == 0");
			out->name = "*no-name*";
			out->flags |= OUT_FLAG_noname;
			PDUerrcount++;
			return out;
		}

		/* showNode(pos.node, 3, 4); */

		switch (pos.type & TBL_TYPEmask) {
		case TBL_SEQUENCE: /* avoid finishing a choice when we have to do a sequence first */
		case TBL_SET:
			break;
		default:
			if (pos.type & TBL_CHOICE_made) {
				if (asn1_verbose) g_message("    finish choice");
				donext = 1;
			}
			break;
		}

		info = GETINFO;

		if (pos.type & TBL_REPEAT) { /* start of a repeat */
			switch(pos.type & TBL_TYPEmask) { /* type of previous node */
			case TBL_CHOICE:
				if (asn1_verbose) g_message("    repeating choice"); /* ignore repeat */
				break;
			default:
				if (asn1_verbose) g_message("    seqof: repeat start");
				/* decide how to continue, CHILD for next instance of sequence
				 * or NEXT for end of repeated sequence.
				 * use the tag to make a descision */
				if (asn1_verbose) g_message("    seqof: first got %c%d, found %c%d",
							tag_class[class], tag,
							tag_class[info->tclass], info->tag);
				if ( MATCH ) {
					/* This is the start of repeating */
					PUSHNODE(pos);
					ret = GETNAME;
					if (asn1_verbose) g_message("  return for repeat '%s'", ret);
					out->type = (pos.type & TBL_TYPEmask);
					out->typename = info->typename;
					out->name = ret;
					out->value_id = info->value_id;
					out->type_id = info->type_id;
					if (ISANONYMOUS) {
						if (asn1_verbose) g_message("    anonymous: dontshow");
						if (asn1_debug)
							out->flags |= OUT_FLAG_dontshow;
						else
							out->name = empty;
					}
					return out;
				} else {
					/* find out where to go .... */
					pos2 = pos;
					CHILD;	/* assume sequence is repeated */
					if (pos.node) {
						info = GETINFO;	/* needed for MATCH to look ahead */
						if (asn1_verbose)
						    g_message("    seqof: child: got %c%d, found %c%d",
							      tag_class[class], tag,
							      tag_class[info->tclass], info->tag);
					}
					if (pos2.type & TBL_CHOICE_repeat) {
						pos = POPSTATE;
						if (asn1_verbose)
							g_message("    repeating a choice, %s",
								  GETNAME);
						pos.type = TBL_CHOICE_immediate;
					} else {
						if ( pos.node && ! MATCH) { /* no, repeat ends, */
							donext = 1;	/* move on */
							if (asn1_verbose)
							  g_message("    seqof: no repeat, force next");
						}
						/* following code will take the child again */
						pos = pos2;
					}
				}
				break;
			}
		} else 	if (pos.type & TBL_REFERENCE_pop) { /* reference finished, return to caller */
			if (asn1_verbose) g_message("    reference pop, donext");
			pos = POPSTATE;
			donext = 1;
		} else if (pos.type & TBL_SEQUENCE_done) { /* Children have been processed */
			if (pos.type & TBL_SEQUENCE_choice) {
				pos = POPSTATE;	/* expect to find a repeat here */
			} else {
				donext = 1;
				if (asn1_verbose) g_message("    sequence done, donext");
			}
		}

		if (pos.type & TBL_REFERENCE) {
			if (asn1_verbose) g_message("    reference change ref -> pop");
			pos.type ^= (TBL_REFERENCE | TBL_REFERENCE_pop);
		}

		pos.offset = offset;

		ret = pos.name;	/* for the debug messages */
		
		if (donext) {
			if (asn1_verbose) g_message("    donext");
			NEXT;
		} else {
			switch(pos.type & TBL_TYPEmask) { /* type of previous node */
			case TBL_SETOF:		/* ?? */
			case TBL_SEQUENCEOF:
				if ((pos.type & TBL_REPEAT) == 0) { /* start repeating */
					pos.type |= TBL_REPEAT;
					PUSHNODE(pos);
					CHILD;
					pushed++;
						/* remember this is the start of a repeat cycle */
					typeflags |= TBL_REPEAT;
					if (asn1_verbose)
						g_message("    seqof: set repeat mark [push,child]");
				} else {
					if (asn1_verbose)
						g_message("    seqof: end of reapeat loop [next]");
					NEXT;
				}
				break;
			case TBL_SET: 		/* ?? */
			case TBL_SEQUENCE:
				pos.type |= TBL_SEQUENCE_done;
				PUSHNODE(pos);
				CHILD;
				pushed++;
				if (asn1_verbose) g_message("    seq [push,child]");
				break;
			case TBL_CHOICE:
						/* no more choice */
				pos.type = (TBL_CHOICE_done | (pos.type & ~TBL_TYPEmask));
				PUSHNODE(pos);

				pos.type = 0; /* clear all type flags */
				if (asn1_verbose)
					g_message("    choice [push], %c%d, %s",
						  tag_class[info->tclass], info->tag, GETNAME);
				pos.node = makechoice(pos.node, class, tag);
				if (pos.node == 0) {
					pos = POPSTATE;
					out->flags |= OUT_FLAG_noname;
					PDUerrcount++;
				}
				info = GETINFO;

				ret = GETNAME;
				if (asn1_verbose)
					g_message("    '%s' %c%d will be used",
						  ret, tag_class[info->tclass], info->tag);
				break;
			case TBL_CHOICE_done:
				NEXT;
				break;
			case TBL_TYPEREF:
				pos = POPSTATE;
				NEXT;
				if (asn1_verbose) g_message("    typeref [pop,next]");
				break;
			case TBL_ENUMERATED:
			case TBL_BITSTRING:
				/* skip named numbers now, call to PDUenum() will retrieve a name */
				NEXT;
				break;
			case TBL_CHOICE_immediate:
				if (asn1_verbose) g_message("    immediate choice [no next]");
				/* nothing */
				break;
			default:
				NEXT;
				break;
			}
		}

		if (pos.node == 0) {
			ret = "*no-name-2*";
			if (asn1_verbose) g_message("  return '%s'", ret);
			out->name = ret;
			out->flags |= OUT_FLAG_noname;
			PDUerrcount++;
			return out;
		}
		ret = pos.name = GETNAME;
		pos.type = GETTYPE  | (pos.type & ~TBL_TYPEmask);
		info = GETINFO;
		
		/* pos now points to the prospective current node, go check it ********************/
		if (asn1_verbose) g_message("  candidate %s '%s'%s%s, %c%d", TBLTYPE(pos.type), ret,
				(ISOPTIONAL)?", optional":empty,
				(ISIMPLICIT)?", implicit":empty,
				tag_class[info->tclass], info->tag );
		
		if (ISOPTIONAL) { /* must check the tag */
			while(! MATCH) {   /* check optional here again...? */
				if (asn1_verbose)
					g_message("    got %c%d, found %c%d", tag_class[class], tag,
							tag_class[info->tclass], info->tag);
				NEXT;
				if (pos.node == 0) {
					ret = "------";
					if (cons) {
						pos = save_pos; /* reset for next time */
						pos.type |= TBL_SEQUENCE_done;
						PUSHNODE(pos);
						pos.type &= ~TBL_SEQUENCE_done;
						cons_handled = 1;
						out->flags |= OUT_FLAG_dontshow;
						if (asn1_verbose)
			g_message("    end of optional list, constructed, expect value next time");
					} else {
						PDUerrcount++;
						out->flags |= OUT_FLAG_noname;
						if (asn1_verbose)
							g_message("    *end of optional list...");
						info = 0; /* this is not valid any more... */
					}
					break;  /* end of list */
				}
				info = GETINFO;
				if (asn1_verbose) g_message("  optional, %s", GETNAME);
			}
			if (pos.node && ! cons_handled) {
				ret = pos.name = GETNAME;
				pos.type = GETTYPE;
			}
			/* pos now refers to node with name we want, optional nodes skipped */
		}
		
		if (pos.type == TBL_CHOICE) { /* may be an immediate choice */
			pos2 = pos; /* save current state */
			if ( ! MATCH) {
				if (! pushed) {
					if (asn1_verbose)
						g_message("    already pushed, skip next push");
					PUSHNODE(pos);
					typeflags &= ~TBL_CHOICE_made;
				}

				if (asn1_verbose)
					g_message("    immediate choice [push], %c%d, %s",
						  tag_class[info->tclass], info->tag, GETNAME);
				if (pos.node) {
					pos.node = makechoice(pos.node, class, tag);
				}
				if (pos.node == 0) {
					pos = POPSTATE;
					PDUerrcount++;
				}
				info = GETINFO;
				pos.type = GETTYPE;
				out->type = (pos.type & TBL_TYPEmask);
				out->flags |= OUT_FLAG_type;

				sprintf(namestr, "%s!%s", ret, GETNAME);
				ret = namestr;
				if (asn1_verbose)
					g_message("    %s:%s will be used", TBLTYPE(pos.type), ret);
				if (typeflags & TBL_REPEAT) {
					pos2.type |= TBL_REPEAT | TBL_REPEAT_choice;
					PUSHNODE(pos2);
					pos.type |= TBL_SEQUENCE_choice;
					PUSHNODE(pos);
					if (asn1_verbose)
						g_message("  return from immediate choice [%s] '%s'",
								TBLTYPE(pos.type), ret);

					out->data = pos.node; /* for access to named numbers... */

					out->type = (pos.type & TBL_TYPEmask);
					out->name = ret;
					if (info) {
						out->typename = info->typename;
						out->fullname = info->fullname;
						out->value_id = info->value_id;
						out->type_id = info->type_id;
					}

					return out;
				} else {
					typeflags |= TBL_CHOICE_made;
				}
			} else {
				if (asn1_verbose) g_message("    matching choice '%s'", ret);
			}
			if ( ! cons ) { /* ISIMPLICIT was not OK for all */
				pos = pos2; /* reset for continuation */
			}
		}
		if (asn1_verbose) {
			if (info)
				g_message("  using: %s '%s'%s%s, %c%d", TBLTYPE(pos.type), ret,
					  (ISOPTIONAL)?", optional":empty,
					  (ISIMPLICIT)?", implicit":empty,
					  tag_class[info->tclass], info->tag );
			else
				g_message("  using: unknown '%s'", ret);
		}
		
		/* must follow references now */
		if (pos.type == TBL_TYPEREF) {
			out->typename = info->typename;
			out->type_id = info->typenum;
			out->flags |= OUT_FLAG_typename;
			pos2 = pos;
			PUSHNODE(pos);	/* remember where we were */
			if (asn1_verbose) g_message("   typeref [push]");
			typeflags |= TBL_REFERENCE;
			if (info->reference == 0) { /* resolved ref to universal type.... */
				/* showNode(pos.node, 3, 4); */
				pos.type = GETTYPE; /* the resulting type */
				info = GETINFO;
				tmp = "inknown tag";
				if ((info->tclass == ASN1_UNI) && (info->tag < 31)) {
					tmp = asn1_tag[info->tag];
					pos.type = asn1_uni_type[info->tag]; /* get univsrsal type */
				}
				if (asn1_verbose)
					g_message("  indirect typeref to %s:%s, %s [%c%d]",
						  TBLTYPE(pos.type), info->typename, tmp,
						  tag_class[info->tclass], info->tag );
			} else {
				out->fullname = info->fullname;
				donext = (ISANONYMOUS);	/* refereing entity has no name ? */
				pos.node = info->reference;
				pos.type = GETTYPE;
				info = GETINFO;
				if (asn1_verbose)
					g_message("  typeref %s %s", TBLTYPE(pos.type), GETNAME);
			/* keep name from before going through the reference, unless anonymous */
				if (donext) /* refering entity has no name */
					ret = GETNAME; /* a better name */

				/* handle choice here ? !!mm!! */

				out->type = (pos.type & TBL_TYPEmask);
				out->flags |= OUT_FLAG_type;
				/* showNode(pos.node, 3, 4); */
				/* ret = GETNAME;*/

				out->data = pos.node;
				out->flags |= OUT_FLAG_data;
				if (asn1_verbose)
					g_message("  typeref set named number list node %p", pos.node);

				if ( ! cons) {
					pos = POPSTATE;
					pos.type = TBL_TYPEREF_nopop;
					if (asn1_verbose) g_message("    typeref pop");
				} else if ((pos.type == TBL_ENUMERATED) || (pos.type == TBL_BITSTRING)){
						/* do not enter the named-number list */
					pos = POPSTATE;
					pos.type = TBL_TYPEREF_nopop;
					if (asn1_verbose) g_message("    typeref [pop]");
				} else {
					typeflags |= TBL_REFERENCE;
				}
			}
		}

		if (cons && ! cons_handled) {	/* This entity is constructed, expected ? */
			switch(pos.type) {
			case TBL_BOOLEAN: /* these are not expected to be constructed */
			case TBL_INTEGER:
			case TBL_OCTETSTRING:
			case TBL_NULL:
			case TBL_OID:
			case TBL_REAL:
			case TBL_ENUMERATED:
			case TBL_TYPEREF:
				typeflags |= TBL_CONSTRUCTED;
					/* this entry has no extra info, next is the same */
				out->flags |= (OUT_FLAG_dontshow | OUT_FLAG_constructed);
				if (asn1_verbose) g_message("    dontshow and set constructed flag");
				break;
			default: /* others, such as sequences, are expected to be constructed */
				break;
			}
		}
	}

	if (ISANONYMOUS) {
		if (asn1_verbose) g_message("    anonymous: dontshow");
		if (asn1_debug) /* this entry has no extra info, next is the same */
			out->flags |= OUT_FLAG_dontshow;
		else
			out->name = empty; /* show it, but no name */
	}

	if (out->name != empty)
		out->name = ret;

	if ( ! (out->flags & OUT_FLAG_data))
		out->data = pos.node; /* for access to named numbers... */

	pos.type |= typeflags;
	PUSHNODE(pos);

	if ( ! (out->flags & OUT_FLAG_type))
		out->type = pos.type;

	out->type &= TBL_TYPEmask;

	if (ret == noname) {
		PDUerrcount++;
		out->flags |= OUT_FLAG_noname;
	}
	
	if (info && ((out->flags & OUT_FLAG_typename) == 0)) {
		out->typename = info->typename;
		out->type_id = info->typenum;
	}

	if (info && (out->value_id == -1)) {
		out->value_id = info->value_id;
		out->type_id = info->type_id;
	}

	if ((out->fullname == 0) && info)
		out->fullname = info->fullname;

	if (typeflags & TBL_CONSTRUCTED)
		constructed_save = *out;

	if (asn1_verbose)
		g_message("  return [%s] '%s' vid=%d, tid=%d", TBLTYPE(out->type), out->name,
						out->value_id, out->type_id);

	return out;
}

static const char *
getPDUenum(PDUprops *props, guint offset, guint cls, guint tag, guint value)
{
	GNode *list;
	PDUinfo *info;
	const char *ret, *name;
	static char unnamed[] = "*unnamed*";
	
	(void) cls; (void) tag;		/* make a reference */

	if (props->flags & OUT_FLAG_noname)
		return empty;

	ret = unnamed;
	list = (GNode *)props->data;
	
	if (list == 0) {
		if (asn1_verbose) g_message("--off=%d named number list not initialized", offset);
		PDUerrcount++;
		return "*list-still-0*";
	}
	
	if ((PDUinfo *)list->data)
		name = ((PDUinfo *)list->data)->name;
	else
		name = ret;

	for(list = g_node_first_child(list); list; list = g_node_next_sibling(list)) {
		info = (PDUinfo *)list->data;
		if (value == info->tag) {
			ret = info->name;
			break;
		}
	}
	if (ret == unnamed)
		PDUerrcount++;
	
	if (asn1_verbose)
		g_message("--off=%d namednumber %d=%s from list %s", offset, value, ret, name);
	return ret;
}

#endif /* READSYNTAX */

void 
proto_register_asn1(void) {

  static const enum_val_t type_recursion_opts[] = {
	  { "0", "0", 0 },
	  { "1", "1", 1 },
	  { "2", "2", 2 },
	  { "3", "3", 3 },
	  { "4", "4", 4 },
	  { "4", "5", 5 },
	  { "6", "6", 6 },
	  { "7", "7", 7 },
	  { "8", "8", 8 },
	  { "9", "9", 9 },
	  { NULL, NULL, -1},
  };

  static gint *ett[1+MAX_NEST+MAXPDU];

  char tmpstr[64];

  module_t *asn1_module;
  int i, j;

  asn1_logfile = get_tempfile_path(ASN1LOGFILE);

  current_asn1 = g_strdup("");
  asn1_filename = g_strdup(current_asn1);

  current_pduname = g_strdup("ASN1");
  asn1_pduname = g_strdup(current_pduname);

  proto_asn1 = proto_register_protocol("ASN.1 decoding",
				       "ASN1", pabbrev);
  
  ett[0] = &ett_asn1;
  for (i=0, j=1; i<MAX_NEST; i++, j++) {
	  ett[j] = &ett_seq[i];
	  ett_seq[i] = -1;
  }
  for(i=0; i<MAXPDU; i++, j++) {
	  ett[j] = &ett_pdu[i];
	  ett_pdu[i] = -1;
  }

  proto_register_subtree_array(ett, array_length(ett));

  asn1_module = prefs_register_protocol(proto_asn1,
					proto_reg_handoff_asn1);
#ifdef JUST_ONE_PORT
  prefs_register_uint_preference(asn1_module, "tcp_port",
				 "ASN.1 TCP Port",
				 "The TCP port on which "
				 "ASN.1 messages will be read",
				 10, &global_tcp_port_asn1);
  prefs_register_uint_preference(asn1_module, "udp_port",
				 "ASN.1 UDP Port",
				 "The UDP port on which "
				 "ASN.1 messages will be read",
				 10, &global_udp_port_asn1);
  prefs_register_uint_preference(asn1_module, "sctp_port",
				 "ASN.1 SCTP Port",
				 "The SCTP port on which "
				 "ASN.1 messages will be read",
				 10, &global_sctp_port_asn1);
#else
  g_snprintf(tmpstr, sizeof(tmpstr), "%u", TCP_PORT_ASN1);
  range_convert_str(&global_tcp_ports_asn1, tmpstr, 65535);
  
  g_snprintf(tmpstr, sizeof(tmpstr), "%u", UDP_PORT_ASN1);
  range_convert_str(&global_udp_ports_asn1, tmpstr, 65535);
  
  g_snprintf(tmpstr, sizeof(tmpstr), "%u", SCTP_PORT_ASN1);
  range_convert_str(&global_sctp_ports_asn1, tmpstr, 65535);
  
  prefs_register_range_preference(asn1_module, "tcp_ports",
				 "ASN.1 TCP Ports",
				 "The TCP ports on which "
				 "ASN.1 messages will be read",
				 &global_tcp_ports_asn1, 65535);
  prefs_register_range_preference(asn1_module, "udp_ports",
				 "ASN.1 UDP Ports",
				 "The UDP ports on which "
				 "ASN.1 messages will be read",
				 &global_udp_ports_asn1, 65535);
  prefs_register_range_preference(asn1_module, "sctp_ports",
				 "ASN.1 SCTP Ports",
				 "The SCTP ports on which "
				 "ASN.1 messages will be read",
				 &global_sctp_ports_asn1, 65535);
#endif /* JUST_ONE_PORT */

  prefs_register_bool_preference(asn1_module, "desegment_messages",
				 "Desegment TCP",
				 "Desegment ASN.1 messages that span TCP segments",
				 &asn1_desegment);

  old_default_asn1_filename = get_datafile_path(OLD_DEFAULT_ASN1FILE);
#ifdef _WIN32
  bad_separator_old_default_asn1_filename = get_datafile_path(BAD_SEPARATOR_OLD_DEFAULT_ASN1FILE);
#endif

  prefs_register_string_preference(asn1_module, "file",
				   "ASN.1 type table file",
				   "Compiled ASN.1 description of ASN.1 types",
				   &asn1_filename);
  prefs_register_string_preference(asn1_module, "pdu_name",
				   "ASN.1 PDU name",
				   "Name of top level PDU",
				   &asn1_pduname);
  prefs_register_uint_preference(asn1_module, "first_pdu_offset",
				 "Offset to first PDU in first tcp packet",
				 "Offset for non-reassembled packets, "
				 "wrong if this happens on other than the first packet!",
				 10, &first_pdu_offset);
  prefs_register_bool_preference(asn1_module, "flat",
				 "Show full names",
				 "Show full names for all values",
				 &asn1_full);
  prefs_register_enum_preference(asn1_module, "type_recursion",
				 "Eliminate references to level",
				 "Allow this recursion level for eliminated type references",
				 &type_recursion_level,
				 type_recursion_opts, FALSE);
  prefs_register_bool_preference(asn1_module, "debug",
				 "ASN.1 debug mode",
				 "Extra output useful for debuging",
				 &asn1_debug);
#if 0
  prefs_register_bool_preference(asn1_module, "message_win",
				 "Show ASN.1 tree",
				 "show full message description",
				 &asn1_message_win);
#else
  prefs_register_obsolete_preference(asn1_module, "message_win");
#endif
  prefs_register_bool_preference(asn1_module, "verbose_log",
				 "Write very verbose log",
				 "log to file $TMP/" ASN1LOGFILE,
				 &asn1_verbose);
}

/* The registration hand-off routing */

static dissector_handle_t asn1_handle;

static void
register_tcp_port(guint32 port)
{
  dissector_add("tcp.port", port, asn1_handle);
}

static void
unregister_tcp_port(guint32 port)
{
  dissector_delete("tcp.port", port, asn1_handle);
}

static void
register_udp_port(guint32 port)
{
  dissector_add("udp.port", port, asn1_handle);
}

static void
unregister_udp_port(guint32 port)
{
  dissector_delete("udp.port", port, asn1_handle);
}

static void
register_sctp_port(guint32 port)
{
  dissector_add("sctp.port", port, asn1_handle);
}

static void
unregister_sctp_port(guint32 port)
{
  dissector_delete("sctp.port", port, asn1_handle);
}

void
proto_reg_handoff_asn1(void) {
  static int asn1_initialized = FALSE;
#ifndef JUST_ONE_PORT
  char *tcp_ports_asn1_string, *udp_ports_asn1_string, *sctp_ports_asn1_string;
#endif

  pcount = 0;

#ifdef JUST_ONE_PORT
  if (asn1_verbose) g_message("prefs change: tcpport=%u, udpport=%u, sctpport=%u, desegnment=%d, "
		"asn1file=%s, pduname=%s, first_offset=%d, debug=%d, msg_win=%d, verbose=%d",
  	  global_tcp_port_asn1, global_udp_port_asn1, global_sctp_port_asn1, asn1_desegment,
	  asn1_filename, asn1_pduname, first_pdu_offset, asn1_debug, asn1_message_win, asn1_verbose);
#else
  if (asn1_verbose) {
    tcp_ports_asn1_string = range_convert_range(global_tcp_ports_asn1);
    udp_ports_asn1_string = range_convert_range(global_udp_ports_asn1);
    sctp_ports_asn1_string = range_convert_range(global_sctp_ports_asn1);
    g_message("prefs change: tcpports=%s, udpports=%s, sctpports=%s, desegnment=%d, "
		"asn1file=%s, pduname=%s, first_offset=%d, debug=%d, msg_win=%d, verbose=%d",
  	  tcp_ports_asn1_string, udp_ports_asn1_string, sctp_ports_asn1_string, asn1_desegment,
	  asn1_filename, asn1_pduname, first_pdu_offset, asn1_debug, asn1_message_win, asn1_verbose);
  }
#endif /* JUST_ONE_PORT */

  if(!asn1_initialized) {
    asn1_handle = create_dissector_handle(dissect_asn1,proto_asn1);
    asn1_initialized = TRUE;
  } else {	/* clean up ports and their lists */
#ifdef JUST_ONE_PORT
    unregister_tcp_port(tcp_port_asn1);
    unregister_udp_port(udp_port_asn1);
    unregister_sctp_port(sctp_port_asn1);
#else
    if (tcp_ports_asn1 != NULL) {
      range_foreach(tcp_ports_asn1, unregister_tcp_port);
      g_free(tcp_ports_asn1);
    }

    if (udp_ports_asn1 != NULL) {
      range_foreach(udp_ports_asn1, unregister_udp_port);
      g_free(udp_ports_asn1);
    }
    
    if (sctp_ports_asn1 != NULL) {
      range_foreach(sctp_ports_asn1, unregister_sctp_port);
      g_free(sctp_ports_asn1);
    }
#endif /* JUST_ONE_PORT */
  }

  if (strcmp(asn1_filename, current_asn1) != 0) {
	  /* new definitions, parse the file if we have one */
	  /* !!! should be postponed until we really need it !!! */
#ifdef READSYNTAX
	  read_asn1_type_table(asn1_filename);
#endif /* READSYNTAX */
	  g_free(current_asn1);
	  current_asn1 = g_strdup(asn1_filename);
  }
  if (!PDUtree ||	/* no tree built yet for PDU type */
      strcmp(asn1_pduname, current_pduname) != 0) { /* new PDU type, build tree for it */
	  if (build_pdu_tree(asn1_pduname)) {
		  g_free(current_pduname);
		  current_pduname = g_strdup(asn1_pduname);
	  }
  }
#ifdef SHOWPDU
  if (asn1_message_win) {	/* show what we are prepared to recognize */
	  if (window) {
		  gtk_widget_destroy (window);
		  window = NULL;
	  }
	  create_message_window();
  }
#endif /* SHOWPDU */

  /* If we now have a PDU tree, register for the port or ports we have */
  if (PDUtree) {
#ifdef JUST_ONE_PORT
    tcp_port_asn1 = global_tcp_port_asn1;
    udp_port_asn1 = global_udp_port_asn1;
    sctp_port_asn1 = global_sctp_port_asn1;

    register_tcp_port(tcp_port_asn1);
    register_udp_port(udp_port_asn1);
    register_sctp_port(sctp_port_asn1);
#else
    tcp_ports_asn1 = range_copy(global_tcp_ports_asn1);
    udp_ports_asn1 = range_copy(global_udp_ports_asn1);
    sctp_ports_asn1 = range_copy(global_sctp_ports_asn1);

    range_foreach(tcp_ports_asn1, register_tcp_port);
    range_foreach(udp_ports_asn1, register_udp_port);
    range_foreach(sctp_ports_asn1, register_sctp_port);
  }
#endif /* JUST_ONE_PORT */
}

/* Start the functions we need for the plugin stuff */

#ifndef ENABLE_STATIC

G_MODULE_EXPORT void
plugin_register(void)
{
  /* register the new protocol, protocol fields, and subtrees */
  if (proto_asn1 == -1) { /* execute protocol initialization only once */
    proto_register_asn1();
  }
}

G_MODULE_EXPORT void
plugin_reg_handoff(void){
  proto_reg_handoff_asn1();
}

#endif

/* End the functions we need for plugin stuff */
