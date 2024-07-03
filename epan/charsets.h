/** @file
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
extern const gunichar2 charset_table_ebcdic_cp500[256];

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as an ASCII string, with all bytes
 * with the high-order bit set being invalid, and return a pointer to a
 * UTF-8 string, allocated using the wmem scope.
 *
 * Octets with the highest bit set will be converted to the Unicode
 * REPLACEMENT CHARACTER.
 */
WS_DLL_PUBLIC uint8_t *
get_ascii_string(wmem_allocator_t *scope, const uint8_t *ptr, int length);

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UTF-8 string, and return a
 * pointer to a UTF-8 string, allocated using the wmem scope, with all
 * ill-formed sequences replaced with the Unicode REPLACEMENT CHARACTER
 * according to the recommended "best practices" given in the Unicode
 * Standard and specified by W3C/WHATWG.
 */
WS_DLL_PUBLIC uint8_t *
get_utf_8_string(wmem_allocator_t *scope, const uint8_t *ptr, int length);

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
WS_DLL_PUBLIC uint8_t *
get_iso_646_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, const gunichar2 table[0x80]);

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as an ISO 8859/1 string, and
 * return a pointer to a UTF-8 string, allocated using the wmem scope.
 */
WS_DLL_PUBLIC uint8_t *
get_8859_1_string(wmem_allocator_t *scope, const uint8_t *ptr, int length);

/*
 * Given a wmem scope, a pointer, a length, and a translation table with
 * 128 entries, treat the string of bytes referred to by the pointer and
 * length as a string encoded using one octet per character, with octets
 * with the high-order bit clear being ASCII and octets with the high-order
 * bit set being mapped by the translation table to 2-byte Unicode Basic
 * Multilingual Plane characters (including REPLACEMENT CHARACTER), and
 * return a pointer to a UTF-8 string, allocated using the wmem scope.
 */
WS_DLL_PUBLIC uint8_t *
get_unichar2_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, const gunichar2 table[0x80]);

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UCS-2 encoded string
 * containing characters from the Basic Multilingual Plane (plane 0) of
 * Unicode, and return a pointer to a UTF-8 string, allocated with the
 * wmem scope.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN,
 * possibly ORed with ENC_BOM.
 *
 * Specify length in bytes.
 */
WS_DLL_PUBLIC uint8_t *
get_ucs_2_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, unsigned encoding);

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UTF-16 encoded string, and
 * return a pointer to a UTF-8 string, allocated with the wmem scope.
 *
 * See RFC 2781 section 2.2.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN,
 * possibly ORed with ENC_BOM.
 *
 * Specify length in bytes.
 */
WS_DLL_PUBLIC uint8_t *
get_utf_16_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, unsigned encoding);

/*
 * Given a wmem scope, a pointer, and a length, treat the string of bytes
 * referred to by the pointer and length as a UCS-4 encoded string, and
 * return a pointer to a UTF-8 string, allocated with the wmem scope.
 *
 * Encoding parameter should be ENC_BIG_ENDIAN or ENC_LITTLE_ENDIAN,
 * possibly ORed with ENC_BOM.
 *
 * Specify length in bytes.
 */
WS_DLL_PUBLIC uint8_t *
get_ucs_4_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, unsigned encoding);

WS_DLL_PUBLIC uint8_t *
get_ts_23_038_7bits_string_packed(wmem_allocator_t *scope, const uint8_t *ptr,
        const int bit_offset, int no_of_chars);

WS_DLL_PUBLIC uint8_t *
get_ts_23_038_7bits_string_unpacked(wmem_allocator_t *scope, const uint8_t *ptr,
        int length);

WS_DLL_PUBLIC uint8_t *
get_etsi_ts_102_221_annex_a_string(wmem_allocator_t *scope, const uint8_t *ptr,
        int length);

WS_DLL_PUBLIC uint8_t *
get_ascii_7bits_string(wmem_allocator_t *scope, const uint8_t *ptr,
        const int bit_offset, int no_of_chars);

/*
 * Given a wmem scope, a pointer, a length, and a translation table with
 * 256 entries, treat the string of bytes referred to by the pointer and
 * length as a string encoded using one octet per character, with octets
 * being mapped by the translation table to 2-byte Unicode Basic Multilingual
 * Plane characters (including REPLACEMENT CHARACTER), and return a
 * pointer to a UTF-8 string, allocated using the wmem scope.
 */
WS_DLL_PUBLIC uint8_t *
get_nonascii_unichar2_string(wmem_allocator_t *scope, const uint8_t *ptr, int length, const gunichar2 table[256]);

/*
 * Given a wmem scope, a pointer, and a length, treat the bytes referred to
 * by the pointer and length as a GB18030 encoded string, and return a pointer
 * to a UTF-8 string, allocated using the wmem scope, converted having
 * substituted REPLACEMENT CHARACTER according to the Unicode Standard
 * 5.22 U+FFFD Substitution for Conversion.
 * ( https://www.unicode.org/versions/Unicode13.0.0/ch05.pdf )
 *
 * As expected, this will also decode GBK and GB2312 strings.
 */
WS_DLL_PUBLIC uint8_t *
get_gb18030_string(wmem_allocator_t *scope, const uint8_t *ptr, int length);

/*
 * Given a wmem scope, a pointer, and a length, treat the bytes referred to
 * by the pointer and length as a EUC-KR encoded string, and return a pointer
 * to a UTF-8 string, allocated using the wmem scope, converted having
 * substituted REPLACEMENT CHARACTER according to the Unicode Standard
 * 5.22 U+FFFD Substitution for Conversion.
 * ( https://www.unicode.org/versions/Unicode13.0.0/ch05.pdf )
 */
WS_DLL_PUBLIC uint8_t *
get_euc_kr_string(wmem_allocator_t *scope, const uint8_t *ptr, int length);

WS_DLL_PUBLIC uint8_t *
get_t61_string(wmem_allocator_t *scope, const uint8_t *ptr, int length);

WS_DLL_PUBLIC uint8_t *
get_dect_standard_8bits_string(wmem_allocator_t *scope, const uint8_t *ptr, int length);
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
