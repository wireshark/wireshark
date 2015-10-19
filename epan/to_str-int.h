/* to_str-int.h
 * Definitions for utilities to convert various other types to strings.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __TO_STR_INT_H__
#define __TO_STR_INT_H__

#include <glib.h>

/**
 * word_to_hex_punct()
 *
 * Output guint16 hex represetation to 'out', and return pointer after last character.
 * Each byte will be separated with punct character (cannot be NUL).
 * It always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 5 bytes in the buffer.
 */
char *word_to_hex_punct(char *out, guint16 word, char punct);

/**
 * word_to_hex_npad()
 *
 * Output guint16 hex represetation to 'out', and return pointer after last character.
 * Value is not padded.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 4 bytes in the buffer.
 */
char *word_to_hex_npad(char *out, guint16 word);

/**
 * dword_to_hex_punct()
 *
 * Output guint32 hex represetation to 'out', and return pointer after last character.
 * Each byte will be separated with punct character (cannot be NUL).
 * It always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 11 bytes in the buffer.
 */
char *dword_to_hex_punct(char *out, guint32 dword, char punct);

/**
 * qword_to_hex()
 *
 * Output guint64 hex represetation to 'out', and return pointer after last character.
 * It always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 16 bytes in the buffer.
 */
char *qword_to_hex(char *out, guint64 qword);

/**
 * qword_to_hex_punct()
 *
 * Output guint64 hex represetation to 'out', and return pointer after last character.
 * Each byte will be separated with punct character (cannot be NUL).
 * It always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 22 bytes in the buffer.
 */
char *qword_to_hex_punct(char *out, guint64 qword, char punct);

/**
 * bytes_to_hexstr_punct()
 *
 * Output hex represetation of guint8 ad array, and return pointer after last character.
 * Each byte will be separated with punct character (cannot be NUL).
 * It always output full representation (padded with 0).
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least len * 3 - 1 bytes in the buffer.
 */
char *bytes_to_hexstr_punct(char *out, const guint8 *ad, guint32 len, char punct);

/**
 * oct_to_str_back()
 *
 * Output guint32 octal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 12 bytes in the buffer.
 */
char *oct_to_str_back(char *ptr, guint32 value);

/**
 * oct64_to_str_back()
 *
 * Output guint64 octal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 12 bytes in the buffer.
 */
char *oct64_to_str_back(char *ptr, guint64 value);

/**
 * hex_to_str_back()
 *
 * Output guint32 hex representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 * This routine will output for sure (can output more) 'len' decimal characters (number padded with '0').
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 2 + MAX(8, len) bytes in the buffer.
 */
char *hex_to_str_back(char *ptr, int len, guint32 value);

/**
 * hex64_to_str_back()
 *
 * Output guint64 hex representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 * This routine will output for sure (can output more) 'len' decimal characters (number padded with '0').
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 2 + MAX(16, len) bytes in the buffer.
 */
char *hex64_to_str_back(char *ptr, int len, guint64 value);

/**
 * uint64_str_back()
 *
 * Output guint64 decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 20 bytes in the buffer.
 */
char *uint64_to_str_back(char *ptr, guint64 value);

/**
 * uint_to_str_back_len()
 *
 * Output guint32 decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 * This routine will output for sure (can output more) 'len' decimal characters (number padded with '0').
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least MAX(10, len) bytes in the buffer.
 */
char *uint_to_str_back_len(char *ptr, guint32 value, int len);

/**
 * uint64_to_str_back_len()
 *
 * Output guint64 decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 * This routine will output for sure (can output more) 'len' decimal characters (number padded with '0').
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least MAX(20, len) bytes in the buffer.
 */
char *uint64_to_str_back_len(char *ptr, guint64 value, int len);

/**
 * int_to_str_back()
 *
 * Output gint32 decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 11 bytes in the buffer.
 */
char *int_to_str_back(char *ptr, gint32 value);

/**
 * int64_to_str_back()
 *
 * Output gint64 decimal representation backward (last character will be written on ptr - 1),
 * and return pointer to first character.
 *
 * String is not NUL terminated by this routine.
 * There needs to be at least 21 bytes in the buffer.
 */
char *int64_to_str_back(char *ptr, gint64 value);

#endif /* __TO_STR_INT_H__ */
