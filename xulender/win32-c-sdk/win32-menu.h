#ifndef __WIN32_MENU_H__
#define __WIN32_MENU_H__

void menus_init(HWND hw_mainwin);
void open_menu_recent_capture_file(HWND hw_mainwin, guint menu_id);
void clear_menu_recent(HWND hw_mainwin);
void menu_name_resolution_changed(HWND hw_mainwin);
void menu_toggle_name_resolution(HWND hw_mainwin, guint menu_id);
void set_menus_for_capture_in_progress(gboolean capture_in_progress);
void menu_update_view_items();
void menu_toggle_timestamps(ts_type ts_t);
#ifdef HAVE_LIBPCAP
void menu_toggle_auto_scroll();
#endif

#endif /* win32-menu.h */
