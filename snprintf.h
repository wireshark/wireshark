extern int vsnprintf(char *string, size_t length, const char * format,
  va_list args);

#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
extern int snprintf(char *string, size_t length, const char * format, ...);
#else
extern int snprintf(char *string, size_t length, const char * format,
  int va_alist);
#endif
