/*
 * $Id: snprintf.h,v 1.7 2002/07/19 12:59:21 girlich Exp $
 */

#ifndef __ETHEREAL_SNPRINTF_H__
#define __ETHEREAL_SNPRINTF_H__

#if defined(HAVE_STDARG_H)
# include <stdarg.h>
#else
# include <varargs.h>
#endif

/* for size_t */
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
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
