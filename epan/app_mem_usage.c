/*
 * app_mem_usage.c
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

#if defined(__linux__)
 #define _XOPEN_SOURCE 500
#endif

#include "config.h"

#include <stdio.h>

#include <glib.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif /*  _WIN32 */

#if defined(__linux__)
# include <sys/types.h>
# include <sys/stat.h>
# include <unistd.h>
# include <fcntl.h>
#endif

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

#if defined(__linux__)

static gboolean
linux_get_memory(gsize *ptotal, gsize *prss)
{
	static int fd = -1;
	static intptr_t pagesize = 0;

	char buf[128];
	unsigned long total, rss;
	ssize_t ret;

	if (!pagesize)
		pagesize = sysconf(_SC_PAGESIZE);

	if (pagesize == -1)
		return FALSE;

	if (fd < 0) {
		char path[64];

		g_snprintf(path, sizeof(path), "/proc/%d/statm", getpid());

		fd = open(path, O_RDONLY);

		/* XXX, fallback to some other /proc file ? */
	}

	if (fd < 0)
		return FALSE;

	ret = pread(fd, buf, sizeof(buf)-1, 0);
	if (ret <= 0)
		return FALSE;

	buf[ret] = '\0';

	if (sscanf(buf, "%lu %lu", &total, &rss) != 2)
		return FALSE;

	if (ptotal)
		*ptotal = pagesize * (gsize) total;
	if (prss)
		*prss = pagesize * (gsize) rss;

	return TRUE;
}

static gsize
linux_get_total_mem_used_by_app(void)
{
	gsize total;

	if (!linux_get_memory(&total, NULL))
		total = 0;

	return total;
}

static gsize
linux_get_rss_mem_used_by_app(void)
{
	gsize rss;

	if (!linux_get_memory(NULL, &rss))
		rss = 0;

	return rss;
}

#define get_total_mem_used_by_app linux_get_total_mem_used_by_app

#define get_rss_mem_used_by_app linux_get_rss_mem_used_by_app

#endif

/* XXX, BSD 4.3: getrusage() -> ru_ixrss ? */

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

