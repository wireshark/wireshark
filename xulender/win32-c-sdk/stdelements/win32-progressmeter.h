#ifndef __WIN32_PROGRESSMETER_H__
#define __WIN32_PROGRESSMETER_H__


win32_element_t * win32_progressmeter_new(HWND);

/*
 * Determines whether a progressmeter is smooth or chunky (the Windows
 * default) or not.
 */
void win32_progressmeter_set_smooth(HWND hwnd, gboolean smooth);

#endif /* win32-progressmeter.h */
