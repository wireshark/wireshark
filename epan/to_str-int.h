/* to_str-int.h
 * Definitions for utilities to convert various other types to strings.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#endif /* __TO_STR_INT_H__ */
