#ifndef __WIN32_STATUSBARPANEL_H__
#define __WIN32_STATUSBARPANEL_H__


win32_element_t * win32_statusbarpanel_new(HWND, LPCSTR);
void win32_statusbarpanel_apply_styles(win32_element_t *statusbarpanel);

void win32_statusbarpanel_push(win32_element_t *statusbarpanel, gchar *ctx, gchar *msg);

void win32_statusbarpanel_pop(win32_element_t *statusbarpanel, gchar *ctx);

#endif /* win32-statusbarpanel.h */
