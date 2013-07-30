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

/* code copied from ekg2, GPL-2 */
#include "config.h"

#include <glib.h>

#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

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
	char *temp;
	FILE *file = NULL;
	int rozmiar = 0, unmres;
	struct utsname sys;

	unmres = uname(&sys);

	temp = g_strdup_printf("/proc/%d/status", getpid());

	if ( (unmres != -1 && !strcmp(sys.sysname, "FreeBSD")) || (file = fopen(temp,"rb")) ) {
		g_free(temp);
		{
#ifdef __linux__
			char buf[1024];
			char *p = NULL;
			size_t rd = 0;

			rd = fread(buf, 1, 1024, file);
			fclose(file);
			if (rd == 0)
			{
				return -1;
			}
			p = strstr(buf, "VmSize");
			if (p) {
				sscanf(p, "VmSize:     %d kB", &rozmiar);
			} else {
				return -1;
			}
#elif __sun
			size_t rd = 0;
			pstatus_t proc_stat;
			rd = fread(&proc_stat, sizeof(proc_stat), 1, file);
			fclose(file);
			if (rd == 0)
			{
				return -1;
			}
			rozmiar = proc_stat.pr_brksize + proc_stat.pr_stksize;
#elif __FreeBSD__ /* link with -lkvm */
			char errbuf[_POSIX2_LINE_MAX];
			int nentries = -1;
			struct kinfo_proc *kp;
			static kvm_t	  *kd;

			if (!(kd = kvm_openfiles(NULL /* "/dev/null" */, "/dev/null", NULL, /* O_RDONLY */0, errbuf))) {
				return -1;
			}
			kp = kvm_getprocs(kd, KERN_PROC_PID, getpid(), &nentries);
			if (!kp || nentries != 1) {
				return -1; 
			}
#ifdef HAVE_STRUCT_KINFO_PROC_KI_SIZE
			rozmiar = (u_long) kp->ki_size/1024; /* freebsd5 */
#else
			rozmiar = kp->kp_eproc.e_vm.vm_map.size/1024; /* freebsd4 */
#endif /* HAVE_STRUCT_KINFO_PROC_KI_SIZE */
#else
			/* no /proc mounted */
			return -1;
#endif
		}
	} else {
		return -1;
	}
	return rozmiar;
#endif /* (_WIN32) */
}
