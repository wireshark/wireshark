/*
 * $Id: snprintf.h,v 1.6 2001/07/22 10:25:48 guy Exp $
 */

#ifndef __ETHEREAL_SNPRINTF_H__
#define __ETHEREAL_SNPRINTF_H__

#if defined(HAVE_STDARG_H)
# include <stdarg.h>
#else
# include <varargs.h>
#endif

extern int vsnprintf(char *string, size_t length, const char * format,
  va_list args);

#if __GNUC__ >= 2
extern int snprintf(char *string, size_t length, const char * format, ...)
	__attribute__((format (printf, 3, 4)));
#else
extern int snprintf(char *string, size_t length, const char * format, ...);
#endif

#endif
