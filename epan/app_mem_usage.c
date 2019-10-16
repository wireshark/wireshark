/*
 * app_mem_usage.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include "wsutil/file_util.h"
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

static const ws_mem_usage_t total_usage = { "Total", win32_get_total_mem_used_by_app, NULL };

static const ws_mem_usage_t *memory_components[MAX_COMPONENTS] = {
	&total_usage,
};

static guint memory_register_num = 1;

#elif defined(__linux__)

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

		fd = ws_open(path, O_RDONLY);

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

static const ws_mem_usage_t total_usage = { "Total", linux_get_total_mem_used_by_app, NULL };
static const ws_mem_usage_t rss_usage = { "RSS", linux_get_rss_mem_used_by_app, NULL };

static const ws_mem_usage_t *memory_components[MAX_COMPONENTS] = {
	&total_usage,
	&rss_usage,
};

static guint memory_register_num = 2;

#else

/*
 * macOS: task_info()?
 *
 * *BSD: getrusage() -> ru_ixrss ?  Note that there are three
 * current-RSS components in struct rusage, but those date
 * back to the days when you had just text, data, and stack,
 * and kernels might not even bother supplying them.
 */

static const ws_mem_usage_t *memory_components[MAX_COMPONENTS];

static guint memory_register_num = 0;

#endif

/* public API */

void
memory_usage_component_register(const ws_mem_usage_t *component)
{
	if (memory_register_num >= MAX_COMPONENTS)
		return;

	memory_components[memory_register_num++] = component;
}

const char *
memory_usage_get(guint idx, gsize *value)
{
	if (idx >= memory_register_num)
		return NULL;

	if (value)
		*value = memory_components[idx]->fetch();

	return memory_components[idx]->name;
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


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
