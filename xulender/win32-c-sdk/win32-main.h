#ifndef __WIN32_MAIN_H__
#define __WIN32_MAIN_H__

void filter_apply_cb();
void filter_clear_cb();
void set_last_open_dir(char *dirname);
extern gboolean main_do_quit(void);
/** Show or hide the main window widgets, user changed it's preferences. */
extern void main_widgets_show_or_hide(void);
HICON get_ethereal_icon_small(HWND hwnd);
HICON get_ethereal_icon_large(HWND hwnd);

#endif /* win32-main.h */
