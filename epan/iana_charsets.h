/* iana_charsets.h
 *
 * Declarations for IANA-registered character sets
 *
 *    http://www.iana.org/assignments/character-sets/character-sets.xhtml
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __IANA_CHARSETS_H__
#define __IANA_CHARSETS_H__

/* Map a MIBenum code for a charset to a Wireshark string encoding. */
WS_DLL_PUBLIC guint mibenum_charset_to_encoding (guint charset);

/* value_string_ext table of names for MIBenum codes */
WS_DLL_PUBLIC value_string_ext mibenum_vals_character_sets_ext;

#endif /* iana_charsets.h */
