/* 
 * app_mem_usage.c
 *
 * $Id: get_app_mem_usage.c 50885 2013-07-25 04:40:37Z etxrab $
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

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif /*  _WIN32 */

#include "app_mem_usage.h"

gsize
get_total_mem_used_by_app(void)
{
#if defined(_WIN32)
   HANDLE pHandle;
   PROCESS_MEMORY_COUNTERS pmc;
   SIZE_T workingSize = 0;

   pHandle = GetCurrentProcess();

   if (GetProcessMemoryInfo(pHandle, &pmc, sizeof(pmc))){
      workingSize = pmc.WorkingSetSize;

	  workingSize = workingSize / 1024;
    }

    CloseHandle(pHandle);

	if(workingSize == 0){
		return -1;
	}else{
		return (int)workingSize;
	}
#else
	return 0;
#endif /* (_WIN32) */
}
