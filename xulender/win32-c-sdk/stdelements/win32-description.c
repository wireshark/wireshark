
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
 * Create a <description> element, implemented as a static control.
 */

/*
 * XXX - Instead of setting the window text, we should handle WM_PAINT
 * ourselves, so that we can dynamically support different text alignments,
 * center the text vertically, etc.
 */

win32_element_t *
win32_description_new(HWND hw_parent, LPCSTR text) {
    win32_element_t *description;
    SIZE             sz;

    g_assert(hw_parent != NULL);

    description = win32_element_new(NULL);

    description->h_wnd = CreateWindow(
	"STATIC",
	text,
	WS_CHILD | WS_VISIBLE,
	0, 0, 10, 10,
	hw_parent,
	NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    SendMessage(description->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    win32_get_text_size(description->h_wnd, text, &sz);
    sz.cx += 4;
    sz.cy += 2;

    MoveWindow(description->h_wnd, 0, 0, sz.cx, sz.cy, TRUE);

    description->minwidth = sz.cx;
    description->minheight = sz.cy;

    ShowWindow(description->h_wnd, SW_SHOW);
    UpdateWindow(description->h_wnd);

    /* Attach the description address to our HWND. */
    SetWindowLong(description->h_wnd, GWL_USERDATA, (LONG) description);

    return description;
}

void
win32_description_apply_styles(win32_element_t *description) {
    LONG wstyle;

    win32_element_assert(description);
    wstyle = GetWindowLong(description->h_wnd, GWL_STYLE);

    /* XXX - Handle JUSTIFY */
    switch (description->text_align) {
	case CSS_TEXT_ALIGN_RIGHT:
	    wstyle |= SS_RIGHT;
	    break;
	case CSS_TEXT_ALIGN_CENTER:
	    wstyle |= SS_CENTER;
	    break;
	default:
	    wstyle |= SS_LEFT;
	    break;
    }
    SetWindowLong(description->h_wnd, GWL_STYLE, wstyle);
}