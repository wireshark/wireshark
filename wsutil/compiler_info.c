/* compiler_info.c
 * Routines to report information about the compiler used to compile
 * Wireshark
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

#include <wsutil/compiler_info.h>

/*
 * Get compiler information, and append it to the GString.
 */
void
get_compiler_info(GString *str)
{
	/*
	 * See https://sourceforge.net/apps/mediawiki/predef/index.php?title=Compilers
	 * information on various defined strings.
	 *
	 * GCC's __VERSION__ is a nice text string for humans to
	 * read.  The page at sourceforge.net largely describes
	 * numeric #defines that encode the version; if the compiler
	 * doesn't also offer a nice printable string, we try prettifying
	 * the number somehow.
	 */
#if defined(__GNUC__) && defined(__VERSION__)
	/*
	 * Clang and llvm-gcc also define __GNUC__ and __VERSION__;
	 * distinguish between them.
	 */
#if defined(__clang__)
	g_string_append_printf(str, "\n\nBuilt using clang %s.\n", __VERSION__);
#elif defined(__llvm__)
	g_string_append_printf(str, "\n\nBuilt using llvm-gcc %s.\n", __VERSION__);
#else /* boring old GCC */
	g_string_append_printf(str, "\n\nBuilt using gcc %s.\n", __VERSION__);
#endif /* llvm */
#elif defined(__HP_aCC)
	g_string_append_printf(str, "\n\nBuilt using HP aCC %d.\n", __HP_aCC);
#elif defined(__xlC__)
	g_string_append_printf(str, "\n\nBuilt using IBM XL C %d.%d\n",
	    (__xlC__ >> 8) & 0xFF, __xlC__ & 0xFF);
#ifdef __IBMC__
	if ((__IBMC__ % 10) != 0)
		g_string_append_printf(str, " patch %d", __IBMC__ % 10);
#endif /* __IBMC__ */
	g_string_append_printf(str, "\n");
#elif defined(__INTEL_COMPILER)
	g_string_append_printf(str, "\n\nBuilt using Intel C %d.%d",
	    __INTEL_COMPILER / 100, (__INTEL_COMPILER / 10) % 10);
	if ((__INTEL_COMPILER % 10) != 0)
		g_string_append_printf(str, " patch %d", __INTEL_COMPILER % 10);
#ifdef __INTEL_COMPILER_BUILD_DATE
	g_string_sprinta(str, ", compiler built %04d-%02d-%02d",
	    __INTEL_COMPILER_BUILD_DATE / 10000,
	    (__INTEL_COMPILER_BUILD_DATE / 100) % 100,
	    __INTEL_COMPILER_BUILD_DATE % 100);
#endif /* __INTEL_COMPILER_BUILD_DATE */
	g_string_append_printf(str, "\n");
#elif defined(_MSC_FULL_VER)
# if _MSC_FULL_VER > 99999999
	g_string_append_printf(str, "\n\nBuilt using Microsoft Visual C++ %d.%d",
			       (_MSC_FULL_VER / 10000000) - 6,
			       (_MSC_FULL_VER / 100000) % 100);
#  if (_MSC_FULL_VER % 100000) != 0
	g_string_append_printf(str, " build %d",
			       _MSC_FULL_VER % 100000);
#  endif
# else
	g_string_append_printf(str, "\n\nBuilt using Microsoft Visual C++ %d.%d",
			       (_MSC_FULL_VER / 1000000) - 6,
			       (_MSC_FULL_VER / 10000) % 100);
#  if (_MSC_FULL_VER % 10000) != 0
	g_string_append_printf(str, " build %d",
			       _MSC_FULL_VER % 10000);
#  endif
# endif
	g_string_append_printf(str, "\n");
#elif defined(_MSC_VER)
	/* _MSC_FULL_VER not defined, but _MSC_VER defined */
	g_string_append_printf(str, "\n\nBuilt using Microsoft Visual C++ %d.%d\n",
	    (_MSC_VER / 100) - 6, _MSC_VER % 100);
#elif defined(__SUNPRO_C)
	g_string_append_printf(str, "\n\nBuilt using Sun C %d.%d",
	    (__SUNPRO_C >> 8) & 0xF, (__SUNPRO_C >> 4) & 0xF);
	if ((__SUNPRO_C & 0xF) != 0)
		g_string_append_printf(str, " patch %d", __SUNPRO_C & 0xF);
	g_string_append_printf(str, "\n");
#endif
}
