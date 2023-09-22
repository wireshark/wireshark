/** @file
 * Get the CPU info on x86 processors that support it
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Get CPU info on platforms where the x86 cpuid instruction can be used.
 *
 * Skip 32-bit versions for GCC and Clang, as older IA-32 processors don't
 * have cpuid.
 *
 * Intel has documented the CPUID instruction in the "Intel(r) 64 and IA-32
 * Architectures Developer's Manual" at
 *
 * https://www.intel.com/content/www/us/en/architecture-and-technology/64-ia-32-architectures-software-developer-vol-2a-manual.html
 *
 * The ws_cpuid() routine will return 0 if cpuinfo isn't available, including
 * on non-x86 platforms and on 32-bit x86 platforms with GCC and Clang, as
 * well as non-MSVC and non-GCC-or-Clang platforms.
 *
 * The "selector" argument to ws_cpuid() is the "initial EAX value" for the
 * instruction.  The initial ECX value is 0.
 *
 * The "CPUInfo" argument points to 4 32-bit values into which the
 * resulting values of EAX, EBX, ECX, and EDX are store, in order.
 */

#include "ws_attributes.h"

#include <inttypes.h>
#include <stdbool.h>

#if defined(_MSC_VER)     /* MSVC */

/*
 * XXX - do the same IA-32 (which doesn't have CPUID prior to some versions
 * of the 80486 and all versions of the 80586^Woriginal Pentium) vs.
 * x86-64 (which always has CPUID) stuff that we do with GCC/Clang?
 *
 * You will probably not be happy running current versions of Wireshark
 * on an 80386 or 80486 machine, and we're dropping support for IA-32
 * on Windows anyway, so the answer is probably "no".
 */
#if defined(_M_IX86) || defined(_M_X64)
static bool
ws_cpuid(uint32_t *CPUInfo, uint32_t selector)
{
	/* https://docs.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex */

	CPUInfo[0] = CPUInfo[1] = CPUInfo[2] = CPUInfo[3] = 0;
	__cpuid((int *) CPUInfo, selector);
	/* XXX, how to check if it's supported on MSVC? just in case clear all flags above */
	return true;
}
#else /* not x86 */
static bool
ws_cpuid(uint32_t *CPUInfo _U_, int selector _U_)
{
	/* Not x86, so no cpuid instruction */
	return false;
}
#endif

#elif defined(__GNUC__)  /* GCC/clang */

#if defined(__x86_64__)
static inline bool
ws_cpuid(uint32_t *CPUInfo, int selector)
{
	__asm__ __volatile__("cpuid"
						: "=a" (CPUInfo[0]),
							"=b" (CPUInfo[1]),
							"=c" (CPUInfo[2]),
							"=d" (CPUInfo[3])
						: "a" (selector),
							"c" (0));
	return true;
}
#elif defined(__i386__)
static bool
ws_cpuid(uint32_t *CPUInfo _U_, int selector _U_)
{
	/*
	 * TODO: need a test if older processors have the cpuid instruction.
	 *
	 * The correct way to test for this, according to the Intel64/IA-32
	 * documentation from Intel, in section 17.1 "USING THE CPUID
	 * INSTRUCTION", is to try to change the ID bit (bit 21) in
	 * EFLAGS.  If it can be changed, the machine supports CPUID,
	 * otherwise it doesn't.
	 *
	 * Some 486's, and all subsequent processors, support CPUID.
	 *
	 * For those who are curious, the way you distinguish between
	 * an 80386 and an 80486 is to try to set the flag in EFLAGS
	 * that causes unaligned accesses to fault - that's bit 18.
	 * However, if the SMAP bit is set in CR4, that bit controls
	 * whether explicit supervisor-mode access to user-mode pages
	 * are allowed, so that should presumably only be done in a
	 * very controlled environment, such as the system boot process.
	 *
	 * So, if you want to find out what type of CPU the system has,
	 * it's probably best to ask the OS, if it supplies the result
	 * of any CPU type testing it's done.
	 */
	return false;
}
#else /* not x86 */
static bool
ws_cpuid(uint32_t *CPUInfo _U_, int selector _U_)
{
	/* Not x86, so no cpuid instruction */
	return false;
}
#endif

#else /* Other compilers */

static bool
ws_cpuid(uint32_t *CPUInfo _U_, int selector _U_)
{
	return false;
}
#endif

static int
ws_cpuid_sse42(void)
{
	uint32_t CPUInfo[4];

	if (!ws_cpuid(CPUInfo, 1))
		return 0;

	/* in ECX bit 20 toggled on */
	return (CPUInfo[2] & (1 << 20));
}
