/* charsets.h
 * Routines for handling character sets
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __CHARSETS_H__
#define __CHARSETS_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Translation tables that map the upper 128 code points in single-byte
 * "extended ASCII" character encodings to Unicode code points in the
 * Basic Multilingual Plane.
 */

/* Table for windows-1250 */
extern const gunichar2 charset_table_cp1250[0x80];
/* Table for windows-1251 */
extern const gunichar2 charset_table_cp1251[0x80];
/* Table for windows-1252 */
extern const gunichar2 charset_table_cp1252[0x80];

/* Tables for ISO-8859-X */
extern const gunichar2 charset_table_iso_8859_2[0x80];
extern const gunichar2 charset_table_iso_8859_3[0x80];
extern const gunichar2 charset_table_iso_8859_4[0x80];
extern const gunichar2 charset_table_iso_8859_5[0x80];
extern const gunichar2 charset_table_iso_8859_6[0x80];
extern const gunichar2 charset_table_iso_8859_7[0x80];
extern const gunichar2 charset_table_iso_8859_8[0x80];
extern const gunichar2 charset_table_iso_8859_9[0x80];
extern const gunichar2 charset_table_iso_8859_10[0x80];
extern const gunichar2 charset_table_iso_8859_11[0x80];
extern const gunichar2 charset_table_iso_8859_13[0x80];
extern const gunichar2 charset_table_iso_8859_14[0x80];
extern const gunichar2 charset_table_iso_8859_15[0x80];
extern const gunichar2 charset_table_iso_8859_16[0x80];

/* Tables for Mac character sets */
extern const gunichar2 charset_table_mac_roman[0x80];

/* Tables for DOS code pages */
extern const gunichar2 charset_table_cp437[0x80];
extern const gunichar2 charset_table_cp855[0x80];
extern const gunichar2 charset_table_cp866[0x80];

/*
 * Translation tables that map the lower 128 code points in single-byte
 * ISO 646-based character encodings to Unicode code points in the
 * Basic Multilingual Plane.
 */
extern const gunichar2 charset_table_iso_646_basic[0x80];

/* Tables for EBCDIC code pages */
extern const gunichar2 charset_table_ebcdic[256];
extern const gunichar2 charset_table_ebcdic_cp037[256];

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as an ASCII string, with all bytes
 * with the high-order bit set being invalid, and return a pointer to a
 * UTF-8 string, allocated using the wmem scope.
 *
 * Octets with the highest bit set will be converted to the Unicode
 * REPLACEMENT CHARACTER.
 */
WS_DLL_PUBLIC guint8 *
get_ascii_string(wmem_allocator_t *scope, const guint8 *ptr, gint length);

/*
 * Given a wmem scope, a pointer, a length, and a translation table,
 * treat the string of bytes referred to by the pointer and length as a
 * string encoded using one octet per character, with octets with the
 * high-order bit clear being mapped by the translation table to 2-byte
 * Unicode Basic Multilingual Plane characters (including REPLACEMENT
 * CHARACTER) and octets with the high-order bit set being mapped to
 * REPLACEMENT CHARACTER, and return a pointer to a UTF-8 string,
 * allocated using the wmem scope.
 */
WS_DLL_PUBLIC guint8 *
get_iso_646_string(wmem_allocator_t *scope, const guint8 *ptr, gint length, const gunichar2 table[0x80]);

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as an ISO 8859/1 string, and
 * return a pointer to a UTF-8 string, allocated using the wmem scope.
 */
WS_DLL_PUBLIC guint8 *
get_8859_1_string(wmem_allocator_t *scope, const guint8 *ptr, gint length);

/*
 * Given a wmem scope, a pointer, a length, and a translation table with
 * 128 entries, treat the string of bytes referred to by the pointer and
 * length as a string encoded using one octet per character, with octets
 * with the high-order bit clear being ASCII and octets with the high-order
 * bit set being mapped by the translation table to 2-byte Unicode Basic
 * Multilingual Plane characters (including REPLACEMENT CHARACTER), and
 * return a pointer to a UTF-8 string, allocated using the wmem scope.
 */
WS_DLL_PUBLIC guint8 *
get_unichar2_string(wmem_allocator_t *scope, const guint8 *ptr, gint length, const gunichar2 table[0x80]);

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UCS-2 encoded string
 * containing characters from the Basic Multilingual Plane (plane 0) of
 * Unicode, and return a pointer to a UTF-8 string, allocated with the
 * wmem scope.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN.
 *
 * Specify length in bytes.
 *
 * XXX - should map lead and trail surrogate values to REPLACEMENT
 * CHARACTERs (0xFFFD)?
 * XXX - if there are an odd number of bytes, should put a
 * REPLACEMENT CHARACTER at the end.
 */
WS_DLL_PUBLIC guint8 *
get_ucs_2_string(wmem_allocator_t *scope, const guint8 *ptr, gint length, const guint encoding);

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UTF-16 encoded string, and
 * return a pointer to a UTF-8 string, allocated with the wmem scope.
 *
 * See RFC 2781 section 2.2.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN.
 *
 * Specify length in bytes.
 *
 * XXX - should map surrogate errors to REPLACEMENT CHARACTERs (0xFFFD).
 * XXX - should map code points > 10FFFF to REPLACEMENT CHARACTERs.
 * XXX - if there are an odd number of bytes, should put a
 * REPLACEMENT CHARACTER at the end.
 */
WS_DLL_PUBLIC guint8 *
get_utf_16_string(wmem_allocator_t *scope, const guint8 *ptr, gint length, const guint encoding);

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UCS-4 encoded string, and
 * return a pointer to a UTF-8 string, allocated with the wmem scope.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN
 *
 * Specify length in bytes
 *
 * XXX - should map lead and trail surrogate values to a "substitute"
 * UTF-8 character?
 * XXX - should map code points > 10FFFF to REPLACEMENT CHARACTERs.
 * XXX - if the number of bytes isn't a multiple of 4, should put a
 * REPLACEMENT CHARACTER at the end.
 */
WS_DLL_PUBLIC guint8 *
get_ucs_4_string(wmem_allocator_t *scope, const guint8 *ptr, gint length, const guint encoding);

WS_DLL_PUBLIC guint8 *
get_ts_23_038_7bits_string(wmem_allocator_t *scope, const guint8 *ptr,
        const gint bit_offset, gint no_of_chars);

WS_DLL_PUBLIC guint8 *
get_ascii_7bits_string(wmem_allocator_t *scope, const guint8 *ptr,
        const gint bit_offset, gint no_of_chars);

/*
 * Given a wmem scope, a pointer, a length, and a translation table with
 * 256 entries, treat the string of bytes referred to by the pointer and
 * length as a string encoded using one octet per character, with octets
 * being mapped by the translation table to 2-byte Unicode Basic Multilingual
 * Plane characters (including REPLACEMENT CHARACTER), and return a
 * pointer to a UTF-8 string, allocated using the wmem scope.
 */
WS_DLL_PUBLIC guint8 *
get_nonascii_unichar2_string(wmem_allocator_t *scope, const guint8 *ptr, gint length, const gunichar2 table[256]);

WS_DLL_PUBLIC guint8 *
get_t61_string(wmem_allocator_t *scope, const guint8 *ptr, gint length);

#if 0
void ASCII_to_EBCDIC(guint8 *buf, guint bytes);
guint8 ASCII_to_EBCDIC1(guint8 c);
#endif
WS_DLL_PUBLIC
void EBCDIC_to_ASCII(guint8 *buf, guint bytes);
WS_DLL_PUBLIC
guint8 EBCDIC_to_ASCII1(guint8 c);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __CHARSETS_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
