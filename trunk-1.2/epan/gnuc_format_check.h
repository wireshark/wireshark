/* gnuc_format_check.h
 * Definitions of macro to conditionally do GCC format checks
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __GNUC_FORMAT_CHECK_H__
#define __GNUC_FORMAT_CHECK_H__

/** GNUC has the ability to check format strings that follow the syntax used in printf and others.
 Hide the differences between different compilers in this GNUC_FORMAT_CHECK macro.
 @param archetype one of: printf, scanf, strftime or strfmon
 @param string_index specifies which argument is the format string argument (starting from 1)
 @param first_to_check is the number of the first argument to check against the format string */
#if __GNUC__ >= 2
	#define GNUC_FORMAT_CHECK(archetype, string_index, first_to_check) __attribute__((format (archetype, string_index, first_to_check)))
#else
	#define GNUC_FORMAT_CHECK(archetype, string_index, first_to_check)
#endif

#endif /* gnuc-format-check.h */
