
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

#define ATTACHED_DATA_ID "_win32_checkbox_attached_data"

/*
 * Create a Checkbox control.
 */

win32_element_t *
win32_checkbox_new(HWND hw_parent, LPCSTR label) {
    win32_element_t *checkbox;
    SIZE sz;

    g_assert(hw_parent != NULL);

    checkbox = win32_element_new(NULL);

    checkbox->h_wnd = CreateWindow(
	"BUTTON",
	label,
	WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
	0, 0, 0, 0,
	hw_parent,
	(HMENU) NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    SendMessage(checkbox->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    win32_get_text_size(checkbox->h_wnd, label, &sz);
    /* XXX - Surely we can do better than this. */
    sz.cx += DIALOG2PIXELX(15);
    sz.cy = DIALOG2PIXELY(14);
    MoveWindow(checkbox->h_wnd, 0, 0, sz.cx, sz.cy, TRUE);

    checkbox->minwidth = sz.cx;
    checkbox->minheight = sz.cy;

    ShowWindow(checkbox->h_wnd, SW_SHOW);
    UpdateWindow(checkbox->h_wnd);

    /* Attach the checkbox address to our HWND. */
    SetWindowLong(checkbox->h_wnd, GWL_USERDATA, (LONG) checkbox);

    return checkbox;
}

/*
 * Get the state of a checkbox
 */
gboolean
win32_checkbox_get_state(win32_element_t *cb_el) {
    int state;

    win32_element_assert(cb_el);

    state = SendMessage(cb_el->h_wnd, BM_GETCHECK, 0, 0);
    return state == BST_CHECKED ? TRUE : FALSE;
}

/*
 * Set the state of a checkbox
 */
void
win32_checkbox_set_state(win32_element_t *cb_el, gboolean state) {
    win32_element_assert(cb_el);

    SendMessage(cb_el->h_wnd, BM_SETCHECK,
	state ? (WPARAM) BST_CHECKED : (WPARAM) BST_UNCHECKED, 0);
}

/*
 * Attach a gboolean pointer to a checkbox.  This is meant to be used
 * in conjunction with win32_checkbox_toggle_attached_data(), below.
 */
void
win32_checkbox_attach_data(win32_element_t *cb_el, gboolean *toggle_val) {
    win32_element_assert(cb_el);

    win32_element_set_data(cb_el, ATTACHED_DATA_ID, toggle_val);

    SendMessage(cb_el->h_wnd, BM_SETCHECK,
	*toggle_val ? (WPARAM) BST_CHECKED : (WPARAM) BST_UNCHECKED, 0);
}

/*
 * Toggle the variable pointed to by ATTACHED_DATA_ID.  An assertion is
 * thrown if nothing is associated to ATTACHED_DATA_ID.
 */
void
win32_checkbox_toggle_attached_data(win32_element_t *cb_el) {
    gboolean *toggle_val;

    win32_element_assert(cb_el);
    toggle_val = win32_element_get_data(cb_el, ATTACHED_DATA_ID);
    g_assert(toggle_val != NULL);

    if (SendMessage(cb_el->h_wnd, BM_GETCHECK, 0, 0) == BST_CHECKED)
	*toggle_val = TRUE;
    else
	*toggle_val = FALSE;
}
