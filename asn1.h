/* asn1.h
 * Definitions for ASN.1 BER dissection
 *
 * $Id: asn1.h,v 1.4 2000/12/24 09:10:11 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 *
 * Based on "g_asn1.h" from:
 *
 * GXSNMP -- An snmp mangament application
 * Copyright (C) 1998 Gregory McLean & Jochen Friedrich
 * Beholder RMON ethernet network monitor,Copyright (C) 1993 DNPAP group
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
#ifndef __ASN1_H__
#define __ASN1_H__

#define ASN1_UNI       0     /* Universal   */
#define ASN1_APL       1     /* Application */
#define ASN1_CTX       2     /* Context     */
#define ASN1_PRV       3     /* Private     */

                             /* Tag                */
#define ASN1_EOC       0     /* End Of Contents    */
#define ASN1_BOL       1     /* Boolean            */
#define ASN1_INT       2     /* Integer            */
#define ASN1_BTS       3     /* Bit String         */
#define ASN1_OTS       4     /* Octet String       */
#define ASN1_NUL       5     /* Null               */
#define ASN1_OJI       6     /* Object Identifier  */
#define ASN1_OJD       7     /* Object Description */
#define ASN1_EXT       8     /* External           */
#define ASN1_REAL      9     /* Real               */
#define ASN1_ENUM      10    /* Enumerated         */
#define ASN1_SEQ       16    /* Sequence           */
#define ASN1_SET       17    /* Set                */
#define ASN1_NUMSTR    18    /* Numerical String   */
#define ASN1_PRNSTR    19    /* Printable String   */
#define ASN1_TEXSTR    20    /* Teletext String    */
#define ASN1_VIDSTR    21    /* Video String       */
#define ASN1_IA5STR    22    /* IA5 String         */
#define ASN1_UNITIM    23    /* Universal Time     */
#define ASN1_GENTIM    24    /* General Time       */
#define ASN1_GRASTR    25    /* Graphical String   */
#define ASN1_VISSTR    26    /* Visible String     */
#define ASN1_GENSTR    27    /* General String     */

                             /* Primitive / Constructed */
#define ASN1_PRI     0       /* Primitive               */
#define ASN1_CON     1       /* Constructed             */

/*
 * Oh, this is hellish.
 *
 * The CMU SNMP library defines an OID as a sequence of "u_int"s,
 * unless EIGHTBIT_SUBIDS is defined, in which case it defines
 * an OID as a sequence of "u_char"s.  None of its header files
 * define EIGHTBIT_SUBIDS, and if a program defines it, that's
 * not going to change the library to treat OIDs as sequences
 * of "u_chars", so I'll assume that it'll be "u_int"s.
 *
 * The UCD SNMP library does the same, except it defines an OID
 * as a sequence of "u_long"s, by default.
 *
 * "libsmi" defines it as a sequence of "unsigned int"s.
 *
 * I don't want to oblige all users of ASN.1 to include the SNMP
 * library header files, so I'll assume none of the SNMP libraries
 * will rudely surprise me by changing the definition; if they
 * do, there will be compiler warnings, so we'll at least be able
 * to catch it.
 *
 * This requires that, if you're going to use "asn1_subid_decode()",
 * "asn1_oid_value_decode()", or "asn1_oid_decode()", you include
 * "config.h", to get the right #defines defined, so that we properly
 * typedef "subid_t".
 */
#if defined(HAVE_UCD_SNMP_SNMP_H)
typedef u_long	subid_t;	/* UCD SNMP */
#else
typedef u_int	subid_t;	/* CMU SNMP, libsmi, or nothing */
#endif

#define ASN1_ERR_NOERROR		0	/* no error */
#define ASN1_ERR_EMPTY			1	/* ran out of data */
#define ASN1_ERR_EOC_MISMATCH		2
#define ASN1_ERR_WRONG_TYPE		3	/* type not right */
#define ASN1_ERR_LENGTH_NOT_DEFINITE	4	/* length should be definite */
#define ASN1_ERR_LENGTH_MISMATCH	5
#define ASN1_ERR_WRONG_LENGTH_FOR_TYPE	6	/* length wrong for type */

typedef struct _ASN1_SCK ASN1_SCK;

struct _ASN1_SCK
{                           /* ASN1 socket                         */
    const guchar *pointer;  /* Octet just encoded or to be decoded */
    const guchar *begin;    /* First octet                         */
    const guchar *end;      /* Octet after last octet              */
};

void asn1_open (ASN1_SCK *asn1, const guchar *buf, guint len);
void asn1_close (ASN1_SCK *asn1, const guchar **buf, guint *len);
int asn1_octet_decode (ASN1_SCK *asn1, guchar *ch);
int asn1_tag_decode (ASN1_SCK *asn1, guint *tag);
int asn1_id_decode (ASN1_SCK *asn1, guint *cls, guint *con, guint *tag);
int asn1_length_decode (ASN1_SCK *asn1, gboolean *def, guint *len);
int asn1_header_decode(ASN1_SCK *asn1, guint *cls, guint *con, guint *tag,
			gboolean *defp, guint *lenp);
int asn1_eoc (ASN1_SCK *asn1, const guchar *eoc);
int asn1_eoc_decode (ASN1_SCK *asn1, const guchar *eoc);
int asn1_null_decode (ASN1_SCK *asn1, int enc_len);
int asn1_bool_decode (ASN1_SCK *asn1, int enc_len, gboolean *bool);
int asn1_int32_value_decode (ASN1_SCK *asn1, int enc_len, gint32 *integer);
int asn1_int32_decode (ASN1_SCK *asn1, gint32 *integer, guint *nbytes);
int asn1_uint32_value_decode (ASN1_SCK *asn1, int enc_len, guint *integer);
int asn1_uint32_decode (ASN1_SCK *asn1, guint32 *integer, guint *nbytes);
int asn1_bits_decode (ASN1_SCK *asn1, const guchar *eoc, guchar **bits, 
                             guint *len, guchar *unused);
int asn1_string_value_decode (ASN1_SCK *asn1, int enc_len,
			guchar **octets);
int asn1_string_decode (ASN1_SCK *asn1, guchar **octets, guint *str_len,
			guint *nbytes, guint expected_tag);
int asn1_octet_string_decode (ASN1_SCK *asn1, guchar **octets, guint *str_len,
			guint *nbytes);
int asn1_subid_decode (ASN1_SCK *asn1, subid_t *subid);
int asn1_oid_value_decode (ASN1_SCK *asn1, int enc_len, subid_t **oid,
			guint *len);
int asn1_oid_decode ( ASN1_SCK *asn1, subid_t **oid, guint *len, guint *nbytes);
int asn1_sequence_decode ( ASN1_SCK *asn1, guint *seq_len, guint *nbytes);
#endif
