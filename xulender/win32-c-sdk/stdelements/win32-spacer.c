
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
 * Create a <spacer> element, implemented as a static control.
 */

win32_element_t *
win32_spacer_new(HWND hw_parent) {
    win32_element_t *spacer;

    g_assert(hw_parent != NULL);

    spacer = win32_element_new(NULL);

    spacer->h_wnd = CreateWindow(
	"STATIC",
	"",
	WS_CHILD | WS_VISIBLE,
	0, 0, 0, 0,
	hw_parent,
	NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);


    ShowWindow(spacer->h_wnd, SW_SHOW);
    UpdateWindow(spacer->h_wnd);

    /* Attach the spacer address to our HWND. */
    SetWindowLong(spacer->h_wnd, GWL_USERDATA, (LONG) spacer);

    return spacer;
}
