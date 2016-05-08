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

#ifndef __IANA_CHARSETS_H__
#define __IANA_CHARSETS_H__

/* Map a MIBenum code for a charset to a Wireshark string encoding. */
WS_DLL_PUBLIC guint mibenum_charset_to_encoding (guint charset);

/* value_string_ext table of names for MIBenum codes */
WS_DLL_PUBLIC value_string_ext mibenum_vals_character_sets_ext;

#endif /* iana_charsets.h */
