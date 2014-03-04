/* asn1.c
 * Routines for ASN.1 BER dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * Based on "g_asn1.c" from:
 *
 * GXSNMP -- An snmp mangament application
 * Copyright (C) 1998 Gregory McLean & Jochen Friedrich
 * Beholder RMON ethernet network monitor, Copyright (C) 1993 DNPAP group
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
 */

/*
 * MODULE INFORMATION
 * ------------------
 *     FILE     NAME:       g_asn1.c
 *     SYSTEM   NAME:       ASN1 Basic Encoding
 *     ORIGINAL AUTHOR(S):  Dirk Wisse
 *     VERSION  NUMBER:     1
 *     CREATION DATE:       1990/11/22
 *
 * DESCRIPTION: ASN1 Basic Encoding Rules.
 *
 *              To decode this we must do:
 *
 *              asn1_open (asn1, tvb, offset);
 *              asn1_header_decode (asn1, &end_of_seq, cls, con, tag, def, len);
 *              asn1_header_decode (asn1, &end_of_octs, cls, con, tag, def, len);
 *              asn1_octets_decode (asn1, end_of_octs, str, len);
 *              asn1_header_decode (asn1, &end_of_int, cls, con, tag);
 *              asn1_int_decode (asn1, end_of_int, &integer);
 *              asn1_eoc_decode (asn1, end_of_seq);
 *              asn1_close (asn1, &offset);
 *
 *              For indefinite encoding end_of_seq and &end_of_seq in the
 *              example above should be replaced by NULL.
 *              For indefinite decoding nothing has to be changed.
 *              This can be very useful if you want to decode both
 *              definite and indefinite encodings.
 */

#include "config.h"

#include <glib.h>

#define subid_t guint32 /* ugly hack to get it to compile this symbol should be suppressed! */

#include <epan/tvbuff.h>
#include <plugins/asn1/asn1.h>
#include <epan/emem.h>

void proto_register_asn1(void);
/*
 * NAME:        asn1_open                                   [API]
 * SYNOPSIS:    void asn1_open
 *                  (
 *                      ASN1_SCK *asn1,
 *                      tvbuff_t *tvb,
 *                      int       offset
 *                  )
 * DESCRIPTION: Opens an ASN1 socket.
 *              Parameters:
 *              asn1:   pointer to ASN1 socket.
 *              tvb:    Tvbuff for encoding.
 *              offset: Current offset in tvbuff.
 *              Encoding starts at the end of the buffer, and
 *              proceeds to the beginning.
 * RETURNS:     void
 */

void
asn1_open(ASN1_SCK *asn1, tvbuff_t *tvb, int offset)
{
    asn1->tvb = tvb;
    asn1->offset = offset;
}

/*
 * NAME:        asn1_close                                  [API]
 * SYNOPSIS:    void asn1_close
 *                  (
 *                      ASN1_SCK   *asn1,
 *                      int        *offset
 *                  )
 * DESCRIPTION: Closes an ASN1 socket.
 *              Parameters:
 *              asn1:   pointer to ASN1 socket.
 *              offset: pointer to variable into which current offset is
 *              to be put.
 * RETURNS:     void
 */

void
asn1_close(ASN1_SCK *asn1, int *offset)
{
    *offset = asn1->offset;
}

/*
 * NAME:        asn1_octet_decode
 * SYNOPSIS:    int asn1_octet_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      guchar   *ch
 *                  )
 * DESCRIPTION: Decodes an octet.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_octet_decode(ASN1_SCK *asn1, guchar *ch)
{
    *ch = tvb_get_guint8(asn1->tvb, asn1->offset);
    asn1->offset++;
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_tag_get
 * SYNOPSIS:    int asn1_tag_get
 *                  (
 *                      ASN1_SCK *asn1,
 *                      guint    *tag
 *                  )
 * DESCRIPTION: Decodes a tag number, combining it with existing tag bits.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
static int
asn1_tag_get(ASN1_SCK *asn1, guint *tag)
{
    int    ret;
    guchar ch;

    do {
	ret = asn1_octet_decode (asn1, &ch);
	if (ret != ASN1_ERR_NOERROR)
	    return ret;
        *tag <<= 7;
        *tag |= ch & 0x7F;
    } while ((ch & 0x80) == 0x80);
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_tag_decode
 * SYNOPSIS:    int asn1_tag_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      guint    *tag
 *                  )
 * DESCRIPTION: Decodes a tag number.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_tag_decode(ASN1_SCK *asn1, guint *tag)
{
    *tag = 0;
    return asn1_tag_get(asn1, tag);
}

/*
 * NAME:        asn1_id_decode
 * SYNOPSIS:    int asn1_id_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      guint    *cls,
 *                      guint    *con,
 *                      guint    *tag
 *                  )
 * DESCRIPTION: Decodes an identifier.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_id_decode(ASN1_SCK *asn1, guint *cls, guint *con, guint *tag)
{
    int    ret;
    guchar ch;

    *tag = 0;
    ret = asn1_octet_decode (asn1, &ch);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    *cls = (ch & 0xC0) >> 6;
    *con = (ch & 0x20) >> 5;
    *tag = (ch & 0x1F);
    if (*tag == 0x1F) {
        ret = asn1_tag_decode (asn1, tag);
        if (ret != ASN1_ERR_NOERROR)
            return ret;
    }
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_id_decode1
 * SYNOPSIS:    int asn1_id_decode1
 *                  (
 *                      ASN1_SCK *asn1,
 *                      guint    *tag
 *                  )
 * DESCRIPTION: Decodes an identifier.
 *		Like asn1_id_decode() except that the Class and Constructor
 *		bits are returned in the tag.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_id_decode1(ASN1_SCK *asn1, guint *tag)
{
    int    ret;
    guchar ch;

    *tag = 0;
    ret = asn1_octet_decode (asn1, &ch);
    if (ret != ASN1_ERR_NOERROR)
        return ret;

    *tag = ch;
    if ((*tag & 0x1F) == 0x1F) { /* high-tag-number format */
	*tag = ch >> 5;	/* leave just the Class and Constructor bits */
        ret = asn1_tag_get (asn1, tag);
        if (ret != ASN1_ERR_NOERROR)
            return ret;
    }
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_length_decode
 * SYNOPSIS:    int asn1_length_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      gboolean *def,
 *                      guint    *len
 *                  )
 * DESCRIPTION: Decodes an ASN1 length.
 *              Parameters:
 *              asn1: pointer to ASN1 socket.
 *              def: Boolean - TRUE if length definite, FALSE if not
 *              len: length, if length is definite
 * DESCRIPTION: Decodes a definite or indefinite length.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_length_decode(ASN1_SCK *asn1, gboolean *def, guint *len)
{
    int    ret;
    guchar ch, cnt;

    ret = asn1_octet_decode (asn1, &ch);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    if (ch == 0x80)
        *def = FALSE;		/* indefinite length */
    else {
        *def = TRUE;		/* definite length */
        if (ch < 0x80)
            *len = ch;
        else {
            cnt = (guchar) (ch & 0x7F);
            *len = 0;
            while (cnt > 0) {
                ret = asn1_octet_decode (asn1, &ch);
                if (ret != ASN1_ERR_NOERROR)
                    return ret;
                *len <<= 8;
                *len |= ch;
                cnt--;
            }
        }
    }
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_header_decode                                [API]
 * SYNOPSIS:    int asn1_header_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      guint    *cls,
 *                      guint    *con,
 *                      guint    *tag
 *                      gboolean *defp,
 *                      guint    *lenp
 *                  )
 * DESCRIPTION: Decodes an ASN1 header.
 *              Parameters:
 *              asn1: pointer to ASN1 socket.
 *              cls:  Class (see asn1.h)
 *              con:  Primitive, Constructed (ASN1_PRI, ASN1_CON)
 *              tag:  Tag (see asn1.h)
 *              defp: Boolean - TRUE if length definite, FALSE if not
 *              lenp: length, if length is definite
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_header_decode(ASN1_SCK *asn1, guint *cls, guint *con, guint *tag,
			gboolean *defp, guint *lenp)
{
    int   ret;
    guint len = 0;
    gboolean def;

    ret = asn1_id_decode (asn1, cls, con, tag);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    ret = asn1_length_decode (asn1, &def, &len);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    *defp = def;
    *lenp = len;
    return ASN1_ERR_NOERROR;
}


/*
 * NAME:        asn1_eoc                                   [API]
 * SYNOPSIS:    gboolean asn1_eoc
 *                  (
 *                      ASN1_SCK *asn1,
 *                      int       eoc
 *                  )
 * DESCRIPTION: Checks if decoding is at End Of Contents.
 *              Parameters:
 *              asn1: pointer to ASN1 socket.
 *              eoc: offset of end of encoding, or -1 if indefinite.
 * RETURNS:     gboolean success
 */
gboolean
asn1_eoc ( ASN1_SCK *asn1, int eoc)
{
    if (eoc == -1)
        return (tvb_get_guint8(asn1->tvb, asn1->offset) == 0x00
		&& tvb_get_guint8(asn1->tvb, asn1->offset + 1) == 0x00);
    else
        return (asn1->offset >= eoc);
}

/*
 * NAME:        asn1_eoc_decode                                [API]
 * SYNOPSIS:    int asn1_eoc_decode
 *                  (
 *                      ASN1_SCK  *asn1,
 *                      int       eoc
 *                  )
 * DESCRIPTION: Decodes End Of Contents.
 *              Parameters:
 *              asn1: pointer to ASN1 socket.
 *              eoc: offset of end of encoding, or -1 if indefinite.
 *              If eoc is -1 it decodes an ASN1 End Of
 *              Contents (0x00 0x00), so it has to be an
 *              indefinite length encoding. If eoc is a non-negative
 *              integer, it probably was filled by asn1_header_decode,
 *              and should refer to the octet after the last of the encoding.
 *              It is checked if this offset refers to the octet to be
 *              decoded. This only takes place in decoding a
 *              definite length encoding.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_eoc_decode (ASN1_SCK *asn1, int eoc)
{
    int    ret;
    guchar ch;

    if (eoc == -1) {
        ret = asn1_octet_decode (asn1, &ch);
        if (ret != ASN1_ERR_NOERROR)
	    return ret;
      if (ch != 0x00)
	return ASN1_ERR_EOC_MISMATCH;
      ret = asn1_octet_decode (asn1, &ch);
      if (ret != ASN1_ERR_NOERROR)
	return ret;
      if (ch != 0x00)
	return ASN1_ERR_EOC_MISMATCH;
      return ASN1_ERR_NOERROR;
  } else {
      if (asn1->offset != eoc)
	return ASN1_ERR_LENGTH_MISMATCH;
      return ASN1_ERR_NOERROR;
    }
}

/*
 * NAME:        asn1_null_decode                                [API]
 * SYNOPSIS:    int asn1_null_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      int      enc_len
 *                  )
 * DESCRIPTION: Decodes Null.
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              enc_len: length of encoding of value.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_null_decode ( ASN1_SCK *asn1, int enc_len)
{
    int start_off = asn1->offset;

    asn1->offset += enc_len;
    /*
     * Check for integer overflows.
     * XXX - ASN1_ERR_LENGTH_MISMATCH seemed like the most appropriate
     *       error from the ones available.  Should we make a new one?
     */
    if (asn1->offset < 0 || asn1->offset < start_off)
        return ASN1_ERR_LENGTH_MISMATCH;

    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_bool_decode                                [API]
 * SYNOPSIS:    int asn1_bool_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      int      enc_len,
 *                      gboolean *boolean
 *                  )
 * DESCRIPTION: Decodes Boolean.
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              enc_len: length of encoding of value.
 *              bool:    False, True (0, !0).
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_bool_decode ( ASN1_SCK *asn1, int enc_len, gboolean *boolean)
{
    int    ret;
    guchar ch;

    if (enc_len != 1)
      return ASN1_ERR_LENGTH_MISMATCH;
    ret = asn1_octet_decode (asn1, &ch);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    *boolean = ch ? TRUE : FALSE;
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_int32_value_decode                                [API]
 * SYNOPSIS:    int asn1_int32_value_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      int      enc_len,
 *                      gint32   *integer
 *                  )
 * DESCRIPTION: Decodes value portion of Integer (which must be no more
 *              than 32 bits).
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              enc_len: length of encoding of value.
 *              integer: Integer.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_int32_value_decode ( ASN1_SCK *asn1, int enc_len, gint32 *integer)
{
    int          ret;
    int          eoc;
    guchar       ch;
    guint        len;

    eoc = asn1->offset + enc_len;
    ret = asn1_octet_decode (asn1, &ch);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    *integer = (gint) ch;
    len = 1;
    while (asn1->offset < eoc) {
        if (++len > sizeof (gint32))
	    return ASN1_ERR_WRONG_LENGTH_FOR_TYPE;
        ret = asn1_octet_decode (asn1, &ch);
        if (ret != ASN1_ERR_NOERROR)
            return ret;
        *integer <<= 8;
        *integer |= ch;
    }
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_int32_decode                                [API]
 * SYNOPSIS:    int asn1_int32_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      gint32   *integer,
 *                      guint    *nbytes,
 *                  )
 * DESCRIPTION: Decodes Integer (which must be no more than 32 bits).
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              integer: Integer.
 *              nbytes:  number of bytes used to encode it.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_int32_decode ( ASN1_SCK *asn1, gint32 *integer, guint *nbytes)
{
    int          ret;
    int          start;
    guint        cls;
    guint        con;
    guint        tag;
    gboolean     def;
    guint        enc_len;

    start = asn1->offset;
    ret = asn1_header_decode (asn1, &cls, &con, &tag, &def, &enc_len);
    if (ret != ASN1_ERR_NOERROR)
	goto done;
    if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_INT) {
	ret = ASN1_ERR_WRONG_TYPE;
	goto done;
    }
    if (!def) {
    	ret = ASN1_ERR_LENGTH_NOT_DEFINITE;
    	goto done;
    }
    ret = asn1_int32_value_decode (asn1, enc_len, integer);

done:
    *nbytes = asn1->offset - start;
    return ret;
}

/*
 * NAME:        asn1_uint32_value_decode                             [API]
 * SYNOPSIS:    int asn1_uint32_value_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      int      enc_len,
 *                      guint32  *integer
 *                  )
 * DESCRIPTION: Decodes value part of Unsigned Integer (which must be no
 *              more than 32 bits).
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              enc_len: length of encoding of value.
 *              integer: Integer.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_uint32_value_decode ( ASN1_SCK *asn1, int enc_len, guint32 *integer)
{
    int          ret;
    int          eoc;
    guchar       ch;
    guint        len;

    eoc = asn1->offset + enc_len;
    ret = asn1_octet_decode (asn1, &ch);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    *integer = ch;
    if (ch == 0)
	len = 0;
    else
	len = 1;
    while (asn1->offset < eoc) {
        if (++len > sizeof (guint32))
	    return ASN1_ERR_WRONG_LENGTH_FOR_TYPE;
        ret = asn1_octet_decode (asn1, &ch);
        if (ret != ASN1_ERR_NOERROR)
            return ret;
        *integer <<= 8;
        *integer |= ch;
    }
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_uint32_decode                             [API]
 * SYNOPSIS:    int asn1_uint32_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      guint32  *integer,
 *                      guint    *nbytes,
 *                  )
 * DESCRIPTION: Decodes Unsigned Integer (which must be no more than 32 bits).
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              integer: Integer.
 *              nbytes:  number of bytes used to encode it.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_uint32_decode ( ASN1_SCK *asn1, guint32 *integer, guint *nbytes)
{
    int          ret;
    int          start;
    guint        cls;
    guint        con;
    guint        tag;
    gboolean     def;
    guint        enc_len;

    start = asn1->offset;
    ret = asn1_header_decode (asn1, &cls, &con, &tag, &def, &enc_len);
    if (ret != ASN1_ERR_NOERROR)
	goto done;
    if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_INT) {
	ret = ASN1_ERR_WRONG_TYPE;
	goto done;
    }
    if (!def) {
    	ret = ASN1_ERR_LENGTH_NOT_DEFINITE;
    	goto done;
    }
    ret = asn1_uint32_value_decode (asn1, enc_len, integer);

done:
    *nbytes = asn1->offset - start;
    return ret;
}

/*
 * NAME:        asn1_bits_decode                                [API]
 * SYNOPSIS:    int asn1_bits_decode
 *                  (
 *                      ASN1_SCK  *asn1,
 *                      int        eoc,
 *                      guchar    *bits,
 *                      guint      size,
 *                      guint      len,
 *                      guchar     unused
 *                  )
 * DESCRIPTION: Decodes Bit String.
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              enc_len: length of value.
 *              bits:    pointer to variable we set to point to strring
 *              len:     Size of Bit String in characters.
 *              unused:  Number of unused bits in last character.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_bits_decode ( ASN1_SCK *asn1, int enc_len, guchar **bits,
		     guint *len, guchar *unused)
{
    int ret;
    int eoc;
    guchar *ptr;

    eoc = asn1->offset + enc_len;
    *bits = NULL;
    ret = asn1_octet_decode (asn1, unused);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    *len = 0;

    /*
     * First, make sure the entire string is in the tvbuff, and throw
     * an exception if it isn't.  If the length is bogus, this should
     * keep us from trying to allocate an immensely large buffer.
     * (It won't help if the length is *valid* but immensely large,
     * but that's another matter; in any case, that would happen only
     * if we had an immensely large tvbuff....)
     */
    if (enc_len != 0) {
        tvb_ensure_bytes_exist(asn1->tvb, asn1->offset, enc_len);
        *bits = (guchar *)g_malloc (enc_len);
    } else {
	/*
	 * If the length is 0, we allocate a 1-byte buffer, as
	 * "g_malloc()" returns NULL if passed 0 as an argument,
	 * and our caller expects us to return a pointer to a
	 * buffer.
	 */
	*bits = (guchar *)g_malloc (1);
    }

    ptr = *bits;
    while (asn1->offset < eoc) {
        ret = asn1_octet_decode (asn1, (guchar *)ptr++);
        if (ret != ASN1_ERR_NOERROR) {
            g_free(*bits);
            *bits = NULL;
	    return ret;
	}
    }
    *len = (guint) (ptr - *bits);
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_string_value_decode                       [API]
 * SYNOPSIS:    int asn1_string_value_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      int      enc_len,
 *                      guchar   **octets
 *                  )
 * DESCRIPTION: Decodes value portion of string (Octet String, various
 *              character string types)
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              enc_len: length of encoding of value.
 *              octets:  pointer to variable we set to point to string,
 *			 which is '\0' terminated for ease of use as C-string
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_string_value_decode ( ASN1_SCK *asn1, int enc_len, guchar **octets)
{
    int          ret;
    int          eoc;
    guchar       *ptr;

    /*
     * First, make sure the entire string is in the tvbuff, and throw
     * an exception if it isn't.  If the length is bogus, this should
     * keep us from trying to allocate an immensely large buffer.
     * (It won't help if the length is *valid* but immensely large,
     * but that's another matter; in any case, that would happen only
     * if we had an immensely large tvbuff....)
     */
    if (enc_len != 0)
	tvb_ensure_bytes_exist(asn1->tvb, asn1->offset, enc_len);
    *octets = (guchar *)g_malloc (enc_len+1);

    eoc = asn1->offset + enc_len;
    ptr = *octets;
    while (asn1->offset < eoc) {
	ret = asn1_octet_decode (asn1, (guchar *)ptr++);
	if (ret != ASN1_ERR_NOERROR) {
	    g_free(*octets);
	    *octets = NULL;
	    return ret;
	}
    }
    *(guchar *)ptr = '\0';
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_string_decode                             [API]
 * SYNOPSIS:    int asn1_string_decode
 *                  (
 *                      ASN1_SCK  *asn1,
 *                      guchar    **octets,
 *                      guint     *str_len,
 *                      guint     *nbytes,
 *                      guint     expected_tag
 *                  )
 * DESCRIPTION: Decodes string (Octet String, various character string
 *              types)
 *              Parameters:
 *              asn1:         pointer to ASN1 socket.
 *              octets:       pointer to variable we set to point to string.
 *              str_len:      length of octet_string.
 *              nbytes:       number of bytes used to encode.
 *              expected_tag: tag expected for this type of string.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_string_decode ( ASN1_SCK *asn1, guchar **octets, guint *str_len,
			guint *nbytes, guint expected_tag)
{
    int          ret;
    int          start;
    guint          enc_len;
    guint        cls;
    guint        con;
    guint        tag;
    gboolean     def;

    start = asn1->offset;
    ret = asn1_header_decode (asn1, &cls, &con, &tag, &def, &enc_len);
    if (ret != ASN1_ERR_NOERROR)
	goto done;
    if (cls != ASN1_UNI || con != ASN1_PRI || tag != expected_tag) {
    	/* XXX - handle the constructed encoding? */
	ret = ASN1_ERR_WRONG_TYPE;
	goto done;
    }
    if (!def) {
    	ret = ASN1_ERR_LENGTH_NOT_DEFINITE;
    	goto done;
    }

    ret = asn1_string_value_decode (asn1, enc_len, octets);
    *str_len = enc_len;

done:
    *nbytes = asn1->offset - start;
    return ret;
}

/*
 * NAME:        asn1_octet_string_decode                             [API]
 * SYNOPSIS:    int asn1_octet_string_decode
 *                  (
 *                      ASN1_SCK  *asn1,
 *                      guchar    **octets,
 *                      guint     *str_len,
 *                      guint     *nbytes,
 *                  )
 * DESCRIPTION: Decodes Octet String.
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              octets:  pointer to variable we set to point to string.
 *              str_len: length of octet_string.
 *              nbytes:  number of bytes used to encode.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_octet_string_decode ( ASN1_SCK *asn1, guchar **octets, guint *str_len,
			guint *nbytes)
{
    return asn1_string_decode(asn1, octets, str_len, nbytes, ASN1_OTS);
}

/*
 * NAME:        asn1_subid_decode
 * SYNOPSIS:    int asn1_subid_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      subid_t  *subid
 *                  )
 * DESCRIPTION: Decodes Sub Identifier.
 *              Parameters:
 *              asn1:  pointer to ASN1 socket.
 *              subid: Sub Identifier.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_subid_decode ( ASN1_SCK *asn1, subid_t *subid)
{
    int    ret;
    guchar ch;

    *subid = 0;
    do {
        ret = asn1_octet_decode(asn1, &ch);
        if (ret != ASN1_ERR_NOERROR)
            return ret;
        *subid <<= 7;
        *subid |= ch & 0x7F;
    } while ((ch & 0x80) == 0x80);
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_oid_value_decode                                [API]
 * SYNOPSIS:    int asn1_oid_value_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      int      enc_len,
 *                      subid_t  **oid,
 *                      guint    *len
 *                  )
 * DESCRIPTION: Decodes value portion of Object Identifier.
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              enc_len: length of encoding of value.
 *              oid:     pointer to variable we set to Object Identifier.
 *              len:     Length of Object Identifier in gulongs.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_oid_value_decode ( ASN1_SCK *asn1, int enc_len, subid_t **oid, guint *len)
{
    int          ret;
    int          eoc;
    subid_t      subid;
    guint        size;
    subid_t      *optr;

    /*
     * First, make sure the entire string is in the tvbuff, and throw
     * an exception if it isn't.  If the length is bogus, this should
     * keep us from trying to allocate an immensely large buffer.
     * (It won't help if the length is *valid* but immensely large,
     * but that's another matter; in any case, that would happen only
     * if we had an immensely large tvbuff....)
     */
    if (enc_len < 1) {
	*oid = NULL;
	return ASN1_ERR_LENGTH_MISMATCH;
    }
    tvb_ensure_bytes_exist(asn1->tvb, asn1->offset, enc_len);

    eoc = asn1->offset + enc_len;

    size = enc_len + 1;
    *oid = (guint32 *)g_malloc(size * sizeof(gulong));
    optr = *oid;

    ret = asn1_subid_decode (asn1, &subid);
    if (ret != ASN1_ERR_NOERROR) {
	g_free(*oid);
	*oid = NULL;
	return ret;
    }
    if (subid < 40) {
	optr[0] = 0;
	optr[1] = subid;
    } else if (subid < 80) {
	optr[0] = 1;
	optr[1] = subid - 40;
    } else {
	optr[0] = 2;
	optr[1] = subid - 80;
    }
    *len = 2;
    optr += 2;
    while (asn1->offset < eoc) {
	if (++(*len) > size) {
            g_free(*oid);
            *oid = NULL;
	    return ASN1_ERR_WRONG_LENGTH_FOR_TYPE;
	}
	ret = asn1_subid_decode (asn1, optr++);
	if (ret != ASN1_ERR_NOERROR) {
            g_free(*oid);
            *oid = NULL;
	    return ret;
	}
    }
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_oid_decode                                [API]
 * SYNOPSIS:    int asn1_oid_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      subid_t  **oid,
 *                      guint    *len,
 *                      guint    *nbytes
 *                  )
 * DESCRIPTION: Decodes Object Identifier.
 *              Parameters:
 *              asn1:   pointer to ASN1 socket.
 *              oid:    pointer to variable we set to Object Identifier.
 *              len:    Length of Object Identifier in gulongs.
 *              nbytes: number of bytes used to encode.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_oid_decode ( ASN1_SCK *asn1, subid_t **oid, guint *len, guint *nbytes)
{
    int          ret;
    int          start;
    guint        cls;
    guint        con;
    guint        tag;
    gboolean     def;
    guint        enc_len;

    start = asn1->offset;
    ret = asn1_header_decode (asn1, &cls, &con, &tag, &def, &enc_len);
    if (ret != ASN1_ERR_NOERROR)
	goto done;
    if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_OJI) {
	ret = ASN1_ERR_WRONG_TYPE;
	goto done;
    }
    if (!def) {
    	ret = ASN1_ERR_LENGTH_NOT_DEFINITE;
    	goto done;
    }

    ret = asn1_oid_value_decode (asn1, enc_len, oid, len);

done:
    *nbytes = asn1->offset - start;
    return ret;
}

/*
 * NAME:        asn1_sequence_decode                             [API]
 * SYNOPSIS:    int asn1_sequence_decode
 *                  (
 *                      ASN1_SCK  *asn1,
 *                      guint     *seq_len,
 *                      guint     *nbytes
 *                  )
 * DESCRIPTION: Decodes header for SEQUENCE.
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              seq_len: length of sequence.
 *              nbytes:  number of bytes used to encode header.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_sequence_decode ( ASN1_SCK *asn1, guint *seq_len, guint *nbytes)
{
    int          ret;
    int          start;
    guint        cls;
    guint        con;
    guint        tag;
    gboolean     def;

    start = asn1->offset;
    ret = asn1_header_decode(asn1, &cls, &con, &tag,
	    &def, seq_len);
    if (ret != ASN1_ERR_NOERROR)
	goto done;
    if (cls != ASN1_UNI || con != ASN1_CON || tag != ASN1_SEQ) {
	ret = ASN1_ERR_WRONG_TYPE;
	goto done;
    }
    if (!def) {
    	/* XXX - might some sequences have an indefinite length? */
    	ret = ASN1_ERR_LENGTH_NOT_DEFINITE;
    	goto done;
    }
    ret = ASN1_ERR_NOERROR;

done:
    *nbytes = asn1->offset - start;
    return ret;
}

/*
 * NAME:        asn1_err_to_str                             [API]
 * SYNOPSIS:    const char *asn1_err_to_str
 *                  (
 *                      int     err
 *                  )
 * DESCRIPTION: Returns the string corresponding to an ASN.1 library error.
 *              Parameters:
 *              err: the error code
 * RETURNS:     string for the error
 */
const char *
asn1_err_to_str(int err)
{
    const char   *errstr;
    char         errstrbuf[14+1+1+11+1+1];	/* "Unknown error (%d)\0" */

    switch (err) {

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
	g_snprintf(errstrbuf, sizeof errstrbuf, "Unknown error (%d)", err);
	errstr = ep_strdup(errstrbuf);
	break;
    }
    return errstr;
}
