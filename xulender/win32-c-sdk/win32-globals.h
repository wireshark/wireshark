#ifndef __WIN32_GLOBALS_H__
#define __WIN32_GLOBALS_H__

/* Our main instance variable */
extern HWND g_hw_mainwin;
extern HWND g_hw_capture_dlg;
extern HWND g_hw_capture_info_dlg;

extern HFONT m_r_font, m_b_font;

extern gchar *ethereal_path;

static COLORREF cust_colors[16];

#define ETHEREAL_BYTEVIEW_TREEVIEW   "_ethereal_byteview_treeview"
#define ETHEREAL_TREEVIEW_BYTEVIEW   "_ethereal_treeview_byteview"


/* XXX - This needs to be moved to a better place. */
#define ID_GROUPBOX 5004
/* This MUST match the resource ID of the toolbar in image/win32-toolbar.res */
#define IDR_MAIN_TOOLBAR 5020
#define IDM_RECENT_FILE_START 5050

#endif /* win32-globals.h */
