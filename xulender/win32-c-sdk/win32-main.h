#ifndef __WIN32_MAIN_H__
#define __WIN32_MAIN_H__

void filter_apply_cb();
void filter_clear_cb();
void set_last_open_dir(char *dirname);
void font_apply();
extern gboolean main_do_quit(void);
HICON get_ethereal_icon_small(HWND hwnd);
HICON get_ethereal_icon_large(HWND hwnd);

#endif /* win32-main.h */
