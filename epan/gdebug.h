/* $Id: gdebug.h,v 1.1 2001/02/01 20:21:16 gram Exp $ */

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
