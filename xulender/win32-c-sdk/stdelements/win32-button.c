
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"

/*
 * Create a Button control.
 */

win32_element_t *
win32_button_new(HWND hw_parent, LPCSTR label) {
    win32_element_t *button;
    SIZE sz;

    g_assert(hw_parent != NULL);

    button = win32_element_new(NULL);

    button->h_wnd = CreateWindow(
	"BUTTON",
	label,
	WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
	0, 0, 0, 0,
	hw_parent,
	(HMENU) NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    SendMessage(button->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    win32_get_text_size(button->h_wnd, label, &sz);
    /* XXX - Surely we can do better than this. */
    sz.cx += DIALOG2PIXELX(12);
    sz.cy = DIALOG2PIXELY(14);
    MoveWindow(button->h_wnd, 0, 0, sz.cx, sz.cy, TRUE);

    button->minwidth = sz.cx;
    button->minheight = sz.cy;

    ShowWindow(button->h_wnd, SW_SHOW);
    UpdateWindow(button->h_wnd);

    /* Attach the button address to our HWND. */
    SetWindowLong(button->h_wnd, GWL_USERDATA, (LONG) button);

    return button;
}
