
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

static LRESULT CALLBACK win32_toolbar_wnd_proc(HWND hw_toolbar, UINT msg, WPARAM w_param, LPARAM l_param);

/* XXX - This may force us to require IE 5.
 * http://msdn.microsoft.com/library/default.asp?url=/library/en-us/shellcc/platform/commctls/toolbar/structures/tbbutton.asp?frame=true&hidetoc=true
 * I can't find any other way of making a text-only button, however.
 */
#ifndef I_IMAGENONE
# define I_IMAGENONE -2
#endif

/* Structures */


/*
 * Create a <toolbar> using the Windows toolbar control.
 */

win32_element_t *
win32_toolbar_new(HWND hw_parent) {
    win32_element_t *toolbar;
    RECT             wr;

    g_assert(hw_parent != NULL);

    toolbar = win32_element_new(NULL);

    toolbar->h_wnd = CreateWindowEx(
	0,
	TOOLBARCLASSNAME,
	NULL,
	WS_CHILD,
	0, 0, 0, 0,
	hw_parent,
	NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

//    SendMessage(toolbar->h_wnd, WM_SETFONT,
//	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    /* Initialize our button struct size */
    SendMessage(toolbar->h_wnd, TB_BUTTONSTRUCTSIZE, (WPARAM) sizeof(TBBUTTON), 0);

    GetWindowRect(toolbar->h_wnd, &wr);
    toolbar->minheight = wr.bottom - wr.top;

    ShowWindow(toolbar->h_wnd, SW_SHOW);
    UpdateWindow(toolbar->h_wnd);

    /* Attach the box address to our HWND. */
    SetWindowLong(toolbar->h_wnd, GWL_USERDATA, (LONG) toolbar);

    return toolbar;
}

void
win32_toolbar_add_button(win32_element_t *toolbar, gint id, gchar *label) {
    TBBUTTON  tbb;

    win32_element_assert(toolbar);

    ZeroMemory(&tbb, sizeof(tbb));
    tbb.iBitmap = 0;
    tbb.idCommand = id;
    tbb.fsState = TBSTATE_ENABLED;
    tbb.fsStyle = TBSTYLE_BUTTON;
    if (label) {
	tbb.iBitmap = I_IMAGENONE;
	tbb.fsStyle |= TBSTYLE_LIST;
	tbb.iString = (int) label;
    }

    SendMessage(toolbar->h_wnd, TB_ADDBUTTONS, (WPARAM) 1, (LPARAM) &tbb);
}

void
win32_toolbar_add_separator(win32_element_t *toolbar) {
    TBBUTTON tbb;

    win32_element_assert(toolbar);

    ZeroMemory(&tbb, sizeof(tbb));
    tbb.fsState = TBSTATE_ENABLED;
    tbb.fsStyle = TBSTYLE_SEP;

    SendMessage(toolbar->h_wnd, TB_ADDBUTTONS, (WPARAM) 1, (LPARAM) &tbb);
}


/*
 * Private routines
 */

