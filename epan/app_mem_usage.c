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

#define MAX_COMPONENTS 16

#if defined(_WIN32)
static gsize
win32_get_total_mem_used_by_app(void)
{
   HANDLE pHandle;
   PROCESS_MEMORY_COUNTERS pmc;
   SIZE_T workingSize = 0;

   pHandle = GetCurrentProcess();

   if (GetProcessMemoryInfo(pHandle, &pmc, sizeof(pmc))){
      workingSize = pmc.WorkingSetSize;
    }

    CloseHandle(pHandle);

	if(workingSize == 0){
		return -1;
	}else{
		return (int)workingSize;
	}
}

#define get_total_mem_used_by_app win32_get_total_mem_used_by_app

#endif /* (_WIN32) */


#ifdef get_total_mem_used_by_app
static const ws_mem_usage_t total_usage = { "Total", get_total_mem_used_by_app, NULL };
#endif

#ifdef get_rss_mem_used_by_app
static const ws_mem_usage_t rss_usage = { "RSS", get_rss_mem_used_by_app, NULL };
#endif

static const ws_mem_usage_t *memory_components[MAX_COMPONENTS] = { 
#ifdef get_total_mem_used_by_app
	&total_usage,
#endif
#ifdef get_rss_mem_used_by_app
	&rss_usage,
#endif
};

static guint memory_register_num = 0
#ifdef get_total_mem_used_by_app
	+ 1
#endif
#ifdef get_rss_mem_used_by_app
	+ 1
#endif
	;

/* public API */

void
memory_usage_component_register(const ws_mem_usage_t *component)
{
	if (memory_register_num >= MAX_COMPONENTS)
		return;

	memory_components[memory_register_num++] = component;
}

const char *
memory_usage_get(guint index, gsize *value)
{
	if (index >= memory_register_num)
		return NULL;

	if (value)
		*value = memory_components[index]->fetch();

	return memory_components[index]->name;
}

void
memory_usage_gc(void)
{
	guint i;

	for (i = 0; i < memory_register_num; i++) {
		if (memory_components[i]->gc)
			memory_components[i]->gc();
	}
}

