#ifndef __WIN32_DESCRIPTION_H__
#define __WIN32_DESCRIPTION_H__


win32_element_t * win32_description_new(HWND, LPCSTR);
void win32_description_apply_styles(win32_element_t *description);

#endif /* win32-description.h */
