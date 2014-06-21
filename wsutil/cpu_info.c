/* cpu_info.c
 * Routines to report information about the CPU on which we're running
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

#include <string.h>

#include <glib.h>

#include <wsutil/ws_cpuid.h>

#include <wsutil/cpu_info.h>

/*
 * Get the CPU info, and append it to the GString
 */
void
get_cpu_info(GString *str _U_)
{
	guint32 CPUInfo[4];
	char CPUBrandString[0x40];
	unsigned nExIds;

	/* http://msdn.microsoft.com/en-us/library/hskdteyh(v=vs.100).aspx */

	/* Calling __cpuid with 0x80000000 as the InfoType argument*/
	/* gets the number of valid extended IDs.*/
	if (!ws_cpuid(CPUInfo, 0x80000000))
		return;
	nExIds = CPUInfo[0];

	if( nExIds<0x80000005)
		return;
	memset(CPUBrandString, 0, sizeof(CPUBrandString));

	/* Interpret CPU brand string.*/
	ws_cpuid(CPUInfo, 0x80000002);
	memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
	ws_cpuid(CPUInfo, 0x80000003);
	memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
	ws_cpuid(CPUInfo, 0x80000004);
	memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));

	g_string_append_printf(str, "\n%s", CPUBrandString);

	if (ws_cpuid_sse42())
		g_string_append(str, " (with SSE4.2)");
}
