
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>


#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"
#include "about-dlg.h"

#include "about-dialog.h"

extern GString *comp_info_str, *runtime_info_str;

void
about_dialog_init(HWND hw_parent) {
    win32_element_t *about_dlg = win32_identifier_get_str("about-dialog");
    HWND             hw_about;
    win32_element_t *about_vbox;
    win32_element_t *descr;
    int              i = 0;
    GString         *line;

    if (! about_dlg) {
	hw_about = about_dialog_dialog_create(hw_parent);
	about_dlg = (win32_element_t *) GetWindowLong(hw_about, GWL_USERDATA);
	about_vbox = win32_identifier_get_str("about-dlg.vbox");
	win32_element_assert(about_vbox);

	descr = win32_description_new(about_vbox->h_wnd, "Ethereal - Network Protocol Analyzer\n");
	win32_box_add(about_vbox, descr, i++);

	line = g_string_new("Version " VERSION
#ifdef CVSVERSION
	    " (" CVSVERSION ")"
#endif
	    " (C) 1998-2004 Gerald Combs <gerald@ethereal.com>\n");

	descr = win32_description_new(about_vbox->h_wnd, line->str);
	win32_box_add(about_vbox, descr, i++);

	g_string_printf(line, "%s\n", comp_info_str->str);
	descr = win32_description_new(about_vbox->h_wnd, line->str);
	win32_box_add(about_vbox, descr, i++);

	g_string_printf(line, "%s\n", runtime_info_str->str);
	descr = win32_description_new(about_vbox->h_wnd, line->str);
	win32_box_add(about_vbox, descr, i++);

	g_string_printf(line, "%s\n", "Ethereal is Open Source Software released under the GNU General Public License.");
	descr = win32_description_new(about_vbox->h_wnd, line->str);
	win32_box_add(about_vbox, descr, i++);

	g_string_printf(line, "%s\n", "Check the man page and http://www.ethereal.com for more information.");
	descr = win32_description_new(about_vbox->h_wnd, line->str);
	win32_box_add(about_vbox, descr, i++);

    }
    about_dialog_dialog_show(about_dlg->h_wnd);
}

BOOL CALLBACK
about_dialog_dlg_proc(HWND hw_about, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;

    switch( msg ) {
	case WM_INITDIALOG:
	    about_dialog_handle_wm_initdialog(hw_about);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_about, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    return 0;
	    break;
	case WM_COMMAND:
	    return 0;
	    break;
	case WM_CLOSE:
	    about_dialog_dialog_hide(hw_about);
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}

void
about_dialog_hide(win32_element_t *ok_el) {
    win32_element_t *about_el = win32_identifier_get_str("about-dialog");

    win32_element_assert(about_el);
    about_dialog_dialog_hide(about_el->h_wnd);
}

