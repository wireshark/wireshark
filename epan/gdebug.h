/* gdebug.h
 *
 * Useful macro for use during development.
 *
 * $Id: gdebug.h,v 1.2 2001/02/01 20:31:17 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2001 Gerald Combs
 *
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef GDEBUG_H
#define GDEBUG_H

#ifdef __GNUC__

/* The last "%s" in g_log() is for the empty-string arg that
 * g_debug() always passes. */
#define _g_debug(format, args...) \
	g_log(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, \
			"%s():%s +%d: " format "%s", \
			G_GNUC_PRETTY_FUNCTION, __FILE__, __LINE__, ##args) ;

/* Always pass a empty-string argument to _g_debug() so that g_debug will always
 * have at least 2 arguments. If user passes 1 arg to g_debug() (i.e., only
 * a format string), _g_debug() will still work. */
#define g_debug(args...) \
	_g_debug(args, "")


#else

#include <stdio.h>
#include <stdarg.h>

static void
g_debug(const char* format, ...)
{
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

#endif /* __GNUC__ */

#endif /* GDEBUG_H */
