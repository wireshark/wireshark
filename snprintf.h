/*
 * $Id: snprintf.h,v 1.4 2000/08/11 22:00:49 guy Exp $
 */

#ifndef __ETHEREAL_SNPRINTF_H__
#define __ETHEREAL_SNPRINTF_H__

#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
# include <stdarg.h>
#else
# include <varargs.h>
#endif

extern int vsnprintf(char *string, size_t length, const char * format,
  va_list args);

#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
extern int snprintf(char *string, size_t length, const char * format, ...);
#else
extern int snprintf(char *string, size_t length, const char * format,
  int va_alist);
#endif

#endif
