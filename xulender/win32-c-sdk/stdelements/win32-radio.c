
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "glib.h"

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"

#define ATTACHED_DATA_ID "_win32_radio_attached_data"

/*
 * Create a radio control.
 */

win32_element_t *
win32_radio_new(HWND hw_parent, LPCSTR label, gboolean group_start) {
    win32_element_t *radio;
    SIZE             sz;
    DWORD            wstyle = WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON;

    g_assert(hw_parent != NULL);

    if (group_start)
	wstyle |= WS_GROUP;

    radio = win32_element_new(NULL);

    radio->h_wnd = CreateWindow(
	"BUTTON",
	label,
	wstyle,
	0, 0, 0, 0,
	hw_parent,
	(HMENU) NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    SendMessage(radio->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    win32_get_text_size(radio->h_wnd, label, &sz);
    /* XXX - Surely we can do better than this. */
    sz.cx += DIALOG2PIXELX(15);
    sz.cy = DIALOG2PIXELY(14);
    MoveWindow(radio->h_wnd, 0, 0, sz.cx, sz.cy, TRUE);

    radio->minwidth = sz.cx;
    radio->minheight = sz.cy;

    ShowWindow(radio->h_wnd, SW_SHOW);
    UpdateWindow(radio->h_wnd);

    /* Attach the radio address to our HWND. */
    SetWindowLong(radio->h_wnd, GWL_USERDATA, (LONG) radio);

    return radio;
}

/*
 * Get the state of a radio
 */
gboolean
win32_radio_get_state(win32_element_t *rd_el) {
    int state;

    win32_element_assert(rd_el);

    state = SendMessage(rd_el->h_wnd, BM_GETCHECK, 0, 0);
    return state == BST_CHECKED ? TRUE : FALSE;
}

/*
 * Set the state of a radio
 */
void
win32_radio_set_state(win32_element_t *rd_el, gboolean state) {
    win32_element_assert(rd_el);

    SendMessage(rd_el->h_wnd, BM_SETCHECK,
	state ? (WPARAM) BST_CHECKED : (WPARAM) BST_UNCHECKED, 0);
}

/*
 * Attach a gboolean pointer to a radio.  This is meant to be used
 * in conjunction with win32_radio_toggle_attached_data(), below.
 */
void
win32_radio_attach_data(win32_element_t *rd_el, gboolean *toggle_val) {
    win32_element_assert(rd_el);

    win32_element_set_data(rd_el, ATTACHED_DATA_ID, toggle_val);

    SendMessage(rd_el->h_wnd, BM_SETCHECK,
	*toggle_val ? (WPARAM) BST_CHECKED : (WPARAM) BST_UNCHECKED, 0);
}

/*
 * Toggle the variable pointed to by ATTACHED_DATA_ID.  An assertion is
 * thrown if nothing is associated to ATTACHED_DATA_ID.
 */
void
win32_radio_toggle_attached_data(win32_element_t *rd_el) {
    gboolean *toggle_val;

    win32_element_assert(rd_el);
    toggle_val = win32_element_get_data(rd_el, ATTACHED_DATA_ID);
    g_assert(toggle_val != NULL);

    if (SendMessage(rd_el->h_wnd, BM_GETCHECK, 0, 0) == BST_CHECKED)
	*toggle_val = TRUE;
    else
	*toggle_val = FALSE;
}
