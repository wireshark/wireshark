
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>

#include "alert_box.h"
#include "epan/strutil.h"

#include "simple_dialog.h"

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"
#include "goto-util.h"

#include "goto-packet-dialog.h"


win32_element_t *
goto_dialog_init(HWND hw_mainwin) {
    win32_element_t *goto_dlg = win32_identifier_get_str("goto-packet-dialog");
    win32_element_t *fnumber_tb;
    HWND             hw_goto;

    if (! goto_dlg) {
	hw_goto = goto_packet_dialog_dialog_create(hw_mainwin);
	goto_dlg = (win32_element_t *) GetWindowLong(hw_goto, GWL_USERDATA);
    }

    fnumber_tb = win32_identifier_get_str("goto-packet.number");
    win32_element_assert(fnumber_tb);

    win32_textbox_set_text(fnumber_tb, "");

    goto_packet_dialog_dialog_show(goto_dlg->h_wnd);

    return goto_dlg;
}

BOOL CALLBACK
goto_packet_dialog_dlg_proc(HWND hw_goto, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;

    switch(msg) {
	case WM_INITDIALOG:
	    goto_packet_dialog_handle_wm_initdialog(hw_goto);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_goto, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    return 0;
	    break;
	case WM_COMMAND:
	    return 0;
	    break;
	case WM_CLOSE:
	    goto_packet_dialog_dialog_hide(hw_goto);
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}


/* oncommand procedures */

/* Command sent by element type <button>, id "goto-packet.go" */
/* Guts copied from gtk/goto_dlg.c */
void
goto_dlg_go (win32_element_t *go_btn) {
    win32_element_t *goto_dlg = win32_identifier_get_str("goto-packet-dialog");
    win32_element_t *fnumber_tb = win32_identifier_get_str("goto-packet.number");
    gchar           *fnumber_text, *p;
    guint            fnumber;

    win32_element_assert(goto_dlg);
    win32_element_assert(fnumber_tb);

    fnumber_text = win32_textbox_get_text(fnumber_tb);
    fnumber = strtoul(fnumber_text, &p, 10);
    if (p == fnumber_text || *p != '\0') {
	/* Illegal number.
	   XXX - what about negative numbers (which "strtoul()" allows)?
	   Can we hack up signal handlers for the widget to make it
	   reject attempts to type in characters other than digits? */
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"The packet number you entered isn't a valid number.");
	return;
    }

    if (goto_frame(&cfile, fnumber)) {
	/* We succeeded in going to that frame; we're done. */
	win32_element_destroy(goto_dlg, TRUE);
    }
}

/* Command sent by element type <button>, id "goto-packet.cancel" */
void
goto_dlg_cancel (win32_element_t *cancel_btn) {
    win32_element_t *goto_dlg = win32_identifier_get_str("goto-packet-dialog");

    win32_element_assert(goto_dlg);

    win32_element_destroy(goto_dlg, TRUE);
}


/*
 * Private functions
 */
