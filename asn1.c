/* asn1.c
 * Routines for ASN.1 BER dissection
 *
 * $Id: asn1.c,v 1.5 2000/06/26 00:08:48 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
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
 *              asn1_open (asn1, buf_start, buf_len);
 *              asn1_header_decode (asn1, &end_of_seq, cls, con, tag, def, len);
 *              asn1_header_decode (asn1, &end_of_octs, cls, con, tag, def, len);
 *              asn1_octets_decode (asn1, end_of_octs, str, len);
 *              asn1_header_decode (asn1, &end_of_int, cls, con, tag);
 *              asn1_int_decode (asn1, end_of_int, &integer);
 *              asn1_eoc_decode (asn1, end_of_seq);
 *              asn1_close (asn1, &buf_start, &buf_len);
 *              
 *              For indefinite encoding end_of_seq and &end_of_seq in the
 *              example above should be replaced by NULL.
 *              For indefinite decoding nothing has to be changed.
 *              This can be very useful if you want to decode both
 *              definite and indefinite encodings.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include <glib.h>
#include "asn1.h"

/*
 * NAME:        asn1_open                                   [API]
 * SYNOPSIS:    void asn1_open
 *                  (
 *                      ASN1_SCK     *asn1,
 *                      const guchar *buf,
 *                      guint        len,
 *                  )
 * DESCRIPTION: Opens an ASN1 socket.
 *              Parameters:
 *              asn1: pointer to ASN1 socket.
 *              buf:  Character buffer for encoding.
 *              len:  Length of character buffer.
 *              Encoding starts at the end of the buffer, and
 *              proceeds to the beginning.
 * RETURNS:     void
 */

void
asn1_open(ASN1_SCK *asn1, const guchar *buf, guint len)
{
    asn1->begin = buf;
    asn1->end = buf + len;
    asn1->pointer = buf;
}

/*
 * NAME:        asn1_close                                  [API]
 * SYNOPSIS:    void asn1_close
 *                  (
 *                      ASN1_SCK   *asn1,
 *                      guchar    **buf,
 *                      guint      *len
 *                  )
 * DESCRIPTION: Closes an ASN1 socket.
 *              Parameters:
 *              asn1: pointer to ASN1 socket.
 *              buf: pointer to beginning of encoding.
 *              len: Length of encoding.
 * RETURNS:     void
 */

void 
asn1_close(ASN1_SCK *asn1, const guchar **buf, guint *len)
{
    *buf   = asn1->pointer;
    *len   = asn1->end - asn1->pointer;
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
    if (asn1->pointer >= asn1->end)
	return ASN1_ERR_EMPTY;
    *ch = *(asn1->pointer)++;
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_tag_decode
 * SYNOPSIS:    int asn1_tag_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      guint    *tag
 *                  )
 * DESCRIPTION: Decodes a tag.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_tag_decode(ASN1_SCK *asn1, guint *tag)
{
    int    ret;
    guchar ch;

    *tag = 0;
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
    guint def, len;

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
 *                      guchar   *eoc
 *                  )
 * DESCRIPTION: Checks if decoding is at End Of Contents.
 *              Parameters:
 *              asn1: pointer to ASN1 socket.
 *              eoc: pointer to end of encoding or 0 if
 *                   indefinite.
 * RETURNS:     gboolean success
 */
gboolean
asn1_eoc ( ASN1_SCK *asn1, const guchar *eoc)
{
    if (eoc == 0)
        return (asn1->pointer [0] == 0x00 && asn1->pointer [1] == 0x00);
    else
        return (asn1->pointer >= eoc);
}

/*
 * NAME:        asn1_eoc_decode                                [API]
 * SYNOPSIS:    int asn1_eoc_decode
 *                  (
 *                      ASN1_SCK  *asn1,
 *                      guchar    *eoc
 *                  )
 * DESCRIPTION: Decodes End Of Contents.
 *              Parameters:
 *              asn1: pointer to ASN1 socket.
 *              eoc: pointer to end of encoding or 0 if
 *                   indefinite.
 *              If eoc is 0 it decodes an ASN1 End Of
 *              Contents (0x00 0x00), so it has to be an
 *              indefinite length encoding. If eoc is a
 *              character pointer, it probably was filled by
 *              asn1_header_decode, and should point to the octet
 *              after the last of the encoding. It is checked
 *              if this pointer points to the octet to be
 *              decoded. This only takes place in decoding a
 *              definite length encoding.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_eoc_decode (ASN1_SCK *asn1, const guchar *eoc)
{
    int    ret;
    guchar ch;
    
    if (eoc == 0) {
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
      if (asn1->pointer != eoc)
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
    asn1->pointer += enc_len;
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_bool_decode                                [API]
 * SYNOPSIS:    int asn1_bool_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      int      enc_len,
 *                      gboolean *bool
 *                  )
 * DESCRIPTION: Decodes Boolean.
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              enc_len: length of encoding of value.
 *              bool:    False, True (0, !0).
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_bool_decode ( ASN1_SCK *asn1, int enc_len, gboolean *bool)
{
    int    ret;
    guchar ch;

    if (enc_len != 1)
      return ASN1_ERR_LENGTH_MISMATCH;
    ret = asn1_octet_decode (asn1, &ch);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    *bool = ch ? TRUE : FALSE;
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
    const guchar *eoc;
    guchar       ch;
    guint        len;

    eoc = asn1->pointer + enc_len;
    ret = asn1_octet_decode (asn1, &ch);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    *integer = (gint) ch;
    len = 1;
    while (asn1->pointer < eoc) {
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
    const guchar *start;
    guint        cls;
    guint        con;
    guint        tag;
    gboolean     def;
    guint        enc_len;

    start = asn1->pointer;
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
    *nbytes = asn1->pointer - start;
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
asn1_uint32_value_decode ( ASN1_SCK *asn1, int enc_len, guint *integer)
{
    int          ret;
    const guchar *eoc;
    guchar       ch;
    guint        len;

    eoc = asn1->pointer + enc_len;
    ret = asn1_octet_decode (asn1, &ch);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    *integer = ch;
    if (ch == 0)
	len = 0;
    else
	len = 1;
    while (asn1->pointer < eoc) {
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
    const guchar *start;
    guint        cls;
    guint        con;
    guint        tag;
    gboolean     def;
    guint        enc_len;

    start = asn1->pointer;
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
    *nbytes = asn1->pointer - start;
    return ret;
}

/*
 * NAME:        asn1_bits_decode                                [API]
 * SYNOPSIS:    int asn1_bits_decode
 *                  (
 *                      ASN1_SCK  *asn1,
 *                      guchar    *eoc,
 *                      guchar    *bits,
 *                      guint      size,
 *                      guint      len,
 *                      guchar     unused
 *                  )
 * DESCRIPTION: Decodes Bit String.
 *              Parameters:
 *              asn1:   pointer to ASN1 socket.
 *              eoc:    pointer to end of encoding or 0 if
 *                      indefinite.
 *              bits:   pointer to begin of Bit String.
 *              size:   Size of Bit String in characters.
 *              len:    Length of Bit String in characters.
 *              unused: Number of unused bits in last character.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_bits_decode ( ASN1_SCK *asn1, const guchar *eoc, guchar **bits,
		     guint *len, guchar *unused)

{
    int ret;

    *bits = NULL;
    ret = asn1_octet_decode (asn1, unused);
    if (ret != ASN1_ERR_NOERROR)
        return ret;
    *len = 0;
    *bits = g_malloc(eoc - asn1->pointer);
    while (asn1->pointer < eoc) {
        ret = asn1_octet_decode (asn1, (guchar *)bits++);
        if (ret != ASN1_ERR_NOERROR) {
            g_free(*bits);
            *bits = NULL;
	    return ret;
          }
    }
    return ASN1_ERR_NOERROR;
}

/*
 * NAME:        asn1_octet_string_value_decode                       [API]
 * SYNOPSIS:    int asn1_octet_string_value_decode
 *                  (
 *                      ASN1_SCK *asn1,
 *                      int      enc_len,
 *                      guchar   **octets
 *                  )
 * DESCRIPTION: Decodes value portion of Octet String.
 *              Parameters:
 *              asn1:    pointer to ASN1 socket.
 *              enc_len: length of encoding of value.
 *              octets:  pointer to variable we set to point to string.
 * RETURNS:     ASN1_ERR value (ASN1_ERR_NOERROR on success)
 */
int
asn1_octet_string_value_decode ( ASN1_SCK *asn1, int enc_len, guchar **octets)
{
    int          ret;
    const guchar *eoc;
    guchar       *ptr;

    eoc = asn1->pointer + enc_len;
    *octets = g_malloc (enc_len);
    ptr = *octets;
    while (asn1->pointer < eoc) {
	ret = asn1_octet_decode (asn1, (guchar *)ptr++);
	if (ret != ASN1_ERR_NOERROR) {
	    g_free(*octets);
	    *octets = NULL;
	    return ret;
	}
    }
    return ASN1_ERR_NOERROR;
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
    int          ret;
    const guchar *start;
    int          enc_len;
    guint        cls;
    guint        con;
    guint        tag;
    gboolean     def;

    start = asn1->pointer;
    ret = asn1_header_decode (asn1, &cls, &con, &tag, &def, &enc_len);
    if (ret != ASN1_ERR_NOERROR)
	goto done;
    if (cls != ASN1_UNI || con != ASN1_PRI || tag != ASN1_OTS) {
    	/* XXX - handle the constructed encoding? */
	ret = ASN1_ERR_WRONG_TYPE;
	goto done;
    }
    if (!def) {
    	ret = ASN1_ERR_LENGTH_NOT_DEFINITE;
    	goto done;
    }

    ret = asn1_octet_string_value_decode (asn1, enc_len, octets);
    *str_len = enc_len;

done:
    *nbytes = asn1->pointer - start;
    return ret;
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
    const guchar *eoc;
    subid_t      subid;
    guint        size;
    subid_t      *optr;

    eoc = asn1->pointer + enc_len;
    size = enc_len + 1;
    *oid = g_malloc(size * sizeof(gulong));
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
    while (asn1->pointer < eoc) {
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
    const guchar *start;
    guint        cls;
    guint        con;
    guint        tag;
    gboolean     def;
    guint        enc_len;

    start = asn1->pointer;
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
    *nbytes = asn1->pointer - start;
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
    const guchar *start;
    guint        cls;
    guint        con;
    guint        tag;
    gboolean     def;

    start = asn1->pointer;
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
    *nbytes = asn1->pointer - start;
    return ret;
}
