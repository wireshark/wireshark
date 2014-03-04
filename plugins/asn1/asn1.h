/* asn1.h
 * Definitions for ASN.1 BER dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#ifndef __ASN1_H__
#define __ASN1_H__

#define ASN1_UNI       0     /* Universal   */
#define ASN1_APL       1     /* Application */
#define ASN1_CTX       2     /* Context     */
#define ASN1_PRV       3     /* Private     */

#define BER_CLASS_UNI	0
#define BER_CLASS_APP	1
#define BER_CLASS_CON	2
#define BER_CLASS_PRI	3
#define BER_CLASS_ANY   99			/* dont check class nor tag */

#define BER_UNI_TAG_EOC					0	/* 'end-of-content' */
#define BER_UNI_TAG_BOOLEAN				1
#define BER_UNI_TAG_INTEGER				2
#define BER_UNI_TAG_BITSTRING		    3
#define BER_UNI_TAG_OCTETSTRING		    4
#define BER_UNI_TAG_NULL				5
#define BER_UNI_TAG_OID					6	/* OBJECT IDENTIFIER */
#define BER_UNI_TAG_ObjectDescriptor	7
#define BER_UNI_TAG_EXTERNAL			8
#define BER_UNI_TAG_REAL				9
#define BER_UNI_TAG_ENUMERATED		    10
#define BER_UNI_TAG_EMBEDDED_PDV	    11
#define BER_UNI_TAG_UTF8String		    12
#define BER_UNI_TAG_RELATIVE_OID	    13
/* UNIVERSAL 14-15
 * Reserved for future editions of this
 * Recommendation | International Standard
 */
#define BER_UNI_TAG_SEQUENCE		    16	/* SEQUENCE, SEQUENCE OF */
#define BER_UNI_TAG_SET					17	/* SET, SET OF */
/* UNIVERSAL 18-22 Character string types */
#define BER_UNI_TAG_NumericString	    18
#define BER_UNI_TAG_PrintableString	    19
#define BER_UNI_TAG_TeletexString	    20  /* TeletextString, T61String */
#define BER_UNI_TAG_VideotexString	    21
#define BER_UNI_TAG_IA5String		    22
/* UNIVERSAL 23-24 Time types */
#define BER_UNI_TAG_UTCTime				23
#define BER_UNI_TAG_GeneralizedTime	    24
/* UNIVERSAL 25-30 Character string types */
#define BER_UNI_TAG_GraphicString	    25
#define BER_UNI_TAG_VisibleString	    26  /* VisibleString, ISO64String */
#define BER_UNI_TAG_GeneralString	    27
#define BER_UNI_TAG_UniversalString	    28
#define BER_UNI_TAG_CHARACTERSTRING	    29
#define BER_UNI_TAG_BMPString		    30
/* UNIVERSAL 31- ...
 * Reserved for addenda to this Recommendation | International Standard
 */
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


#define ASN1_ERR_NOERROR		0	/* no error */
#define ASN1_ERR_EOC_MISMATCH		1
#define ASN1_ERR_WRONG_TYPE		2	/* type not right */
#define ASN1_ERR_LENGTH_NOT_DEFINITE	3	/* length should be definite */
#define ASN1_ERR_LENGTH_MISMATCH	4
#define ASN1_ERR_WRONG_LENGTH_FOR_TYPE	5	/* length wrong for type */

typedef struct _ASN1_SCK ASN1_SCK;

struct _ASN1_SCK
{                           /* ASN1 socket                         */
    tvbuff_t *tvb;          /* Tvbuff whence the data comes        */
    int offset;             /* Current offset in tvbuff            */
};

extern void asn1_open (ASN1_SCK *asn1, tvbuff_t *tvb, int offset);
extern void asn1_close (ASN1_SCK *asn1, int *offset);
extern int asn1_octet_decode (ASN1_SCK *asn1, guchar *ch);
extern int asn1_tag_decode (ASN1_SCK *asn1, guint *tag);
extern int asn1_id_decode (ASN1_SCK *asn1, guint *cls, guint *con, guint *tag);
extern int asn1_id_decode1 (ASN1_SCK *asn1, guint *tag);
extern int asn1_length_decode (ASN1_SCK *asn1, gboolean *def, guint *len);
extern int asn1_header_decode(ASN1_SCK *asn1, guint *cls, guint *con,
			      guint *tag, gboolean *defp, guint *lenp);
extern int asn1_eoc (ASN1_SCK *asn1, int eoc);
extern int asn1_eoc_decode (ASN1_SCK *asn1, int eoc);
extern int asn1_null_decode (ASN1_SCK *asn1, int enc_len);
extern int asn1_bool_decode (ASN1_SCK *asn1, int enc_len, gboolean *boolean);
extern int asn1_int32_value_decode (ASN1_SCK *asn1, int enc_len,
				    gint32 *integer);
extern int asn1_int32_decode (ASN1_SCK *asn1, gint32 *integer, guint *nbytes);
extern int asn1_uint32_value_decode (ASN1_SCK *asn1, int enc_len,
				     guint32 *integer);
extern int asn1_uint32_decode (ASN1_SCK *asn1, guint32 *integer, guint *nbytes);
extern int asn1_bits_decode (ASN1_SCK *asn1, int enc_len, guchar **bits,
			     guint *len, guchar *unused);
extern int asn1_string_value_decode (ASN1_SCK *asn1, int enc_len,
				     guchar **octets);
extern int asn1_string_decode (ASN1_SCK *asn1, guchar **octets, guint *str_len,
			       guint *nbytes, guint expected_tag);
extern int asn1_octet_string_decode (ASN1_SCK *asn1, guchar **octets,
				     guint *str_len, guint *nbytes);
extern int asn1_subid_decode (ASN1_SCK *asn1, subid_t *subid);
extern int asn1_oid_value_decode (ASN1_SCK *asn1, int enc_len, subid_t **oid,
				  guint *len);
extern int asn1_oid_decode (ASN1_SCK *asn1, subid_t **oid, guint *len,
			    guint *nbytes);
extern int asn1_sequence_decode (ASN1_SCK *asn1, guint *seq_len, guint *nbytes);

extern const char *asn1_err_to_str (int err);

#endif
