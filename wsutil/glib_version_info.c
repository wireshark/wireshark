/* glib_version_info.c
 * Routines to report GLib version information
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

#include "config.h"

#include <glib.h>

#include <wsutil/glib_version_info.h>

/*
 * Get the GLib version, and append it to the GString
 */
void
get_glib_version_info(GString *str)
{
	/* GLIB */
	g_string_append(str, "with ");
	g_string_append_printf(str,
#ifdef GLIB_MAJOR_VERSION
	    "GLib %d.%d.%d", GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION,
	    GLIB_MICRO_VERSION);
#else
	    "GLib (version unknown)");
#endif
}
