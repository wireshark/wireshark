/* mem_info.c
 * Routines to report version information about how much memory the
 * machine on which we're running has
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

#ifdef _WIN32
#include <windows.h>
#endif

#include <glib.h>

#include <wsutil/mem_info.h>

void
get_mem_info(GString *str _U_)
{
#ifdef _WIN32
	MEMORYSTATUSEX statex;

	statex.dwLength = sizeof (statex);

	if (GlobalMemoryStatusEx(&statex))
		g_string_append_printf(str, ", with ""%" G_GINT64_MODIFIER "d" "MB of physical memory.\n", statex.ullTotalPhys/(1024*1024));
#endif
}
