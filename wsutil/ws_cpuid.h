/* ws_cpuid.h
 * Get the CPU info
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

/*
 * Get CPU info on platforms where the cpuid instruction can be used skip 32 bit versions for GCC
 * 	http://www.intel.com/content/dam/www/public/us/en/documents/application-notes/processor-identification-cpuid-instruction-note.pdf
 * the ws_cpuid() routine will return 0 in CPUInfo[0] if cpuinfo isn't available.
 */

#if defined(_MSC_VER)     /* MSVC */
static void
ws_cpuid(guint32 *CPUInfo, guint32 selector)
{
	__cpuid((int *) CPUInfo, selector);
}

#elif defined(__GNUC__)  /* GCC/clang */

#if defined(__x86_64__)
static inline void
ws_cpuid(guint32 *CPUInfo, int selector)
{
	__asm__ __volatile__("cpuid"
						: "=a" (CPUInfo[0]),
							"=b" (CPUInfo[1]),
							"=c" (CPUInfo[2]),
							"=d" (CPUInfo[3])
						: "a"(selector));
}
#else /* (__i386__) */

static void
ws_cpuid(guint32 *CPUInfo, int selector _U_)
{
	/* TODO: need a test if older proccesors have the cpuid instruction */
	CPUInfo[0] = 0;
}
#endif

#else /* Other compilers */

static void
ws_cpuid(guint32 *CPUInfo, int selector _U_)
{
	CPUInfo[0] = 0;
}
#endif
