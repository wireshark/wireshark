
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
 * Create a progressmeter / Progress Bar control.
 */

win32_element_t *
win32_progressmeter_new(HWND hw_parent) {
    win32_element_t *progressmeter;

    g_assert(hw_parent != NULL);

    progressmeter = win32_element_new(NULL);

    progressmeter->h_wnd = CreateWindowEx(
	0, PROGRESS_CLASS,
	NULL,
	WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
	0, 0, 120, 20,
	hw_parent,
	(HMENU) NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    SendMessage(progressmeter->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    progressmeter->minwidth = 120;
    progressmeter->minheight = 20;

    ShowWindow(progressmeter->h_wnd, SW_SHOW);
    UpdateWindow(progressmeter->h_wnd);

    /* Attach the progressmeter address to our HWND. */
    SetWindowLong(progressmeter->h_wnd, GWL_USERDATA, (LONG) progressmeter);

    return progressmeter;
}

/*
 * XXX - Apparently you can only set PBS_SMOOTH at control creation time.
 * This means that win32_progressmeter_set_smooth() below doesn't work.
 */

void
win32_progressmeter_set_smooth(HWND hwnd, gboolean smooth) {
    LONG pm_style;

    pm_style = GetWindowLong(hwnd, GWL_STYLE);
    if (smooth)
	pm_style |= PBS_SMOOTH;
    else
	pm_style &= ~PBS_SMOOTH;
    SetWindowLong(hwnd, GWL_STYLE, pm_style);
}
