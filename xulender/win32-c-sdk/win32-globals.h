#ifndef __WIN32_GLOBALS_H__
#define __WIN32_GLOBALS_H__

/* Our main instance variable */
extern HWND g_hw_mainwin;
extern HWND g_hw_capture_info_dlg;

extern HFONT g_fixed_font;

extern gchar *ethereal_path;

#define ETHEREAL_BYTEVIEW_TREEVIEW   "_ethereal_byteview_treeview"
#define ETHEREAL_TREEVIEW_BYTEVIEW   "_ethereal_treeview_byteview"


/* XXX - This needs to be moved to a better place. */
#define ID_COMBOBOX 5003
#define ID_GROUPBOX 5004

#endif /* win32-globals.h */
