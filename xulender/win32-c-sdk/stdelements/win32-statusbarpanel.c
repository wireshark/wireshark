
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

#define WIN32_STATUSBAR_MSG_STACK "_win32_statusbar_msg_stack"

/*
 * Create a <statusbarpanel> element, implemented as a static control with
 * an inset border.
 */

win32_element_t *
win32_statusbarpanel_new(HWND hw_parent, LPCSTR text) {
    win32_element_t *statusbarpanel;
    SIZE             sz;
    RECT             wr, cr;

    g_assert(hw_parent != NULL);

    statusbarpanel = win32_element_new(NULL);

    statusbarpanel->h_wnd = CreateWindowEx(
	WS_EX_CLIENTEDGE,
	"STATIC",
	text,
	WS_CHILD | WS_VISIBLE,
	0, 0, 10, 10,
	hw_parent,
	NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    SendMessage(statusbarpanel->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    GetWindowRect(statusbarpanel->h_wnd, &wr);
    GetClientRect(statusbarpanel->h_wnd, &cr);
    win32_get_text_size(statusbarpanel->h_wnd, text, &sz);
    sz.cx += 4;
    sz.cy += (wr.bottom - wr.top) - (cr.bottom - cr.top) + 2;

    MoveWindow(statusbarpanel->h_wnd, 0, 0, sz.cx, sz.cy, TRUE);

    statusbarpanel->minwidth = sz.cx;
    statusbarpanel->minheight = sz.cy;

    ShowWindow(statusbarpanel->h_wnd, SW_SHOW);
    UpdateWindow(statusbarpanel->h_wnd);

    /* Attach the statusbarpanel address to our HWND. */
    SetWindowLong(statusbarpanel->h_wnd, GWL_USERDATA, (LONG) statusbarpanel);

    return statusbarpanel;
}

void
win32_statusbarpanel_apply_styles(win32_element_t *statusbarpanel) {
    LONG wstyle;

    win32_element_assert(statusbarpanel);
    wstyle = GetWindowLong(statusbarpanel->h_wnd, GWL_STYLE);

    /* XXX - Handle JUSTIFY */
    switch (statusbarpanel->text_align) {
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
    SetWindowLong(statusbarpanel->h_wnd, GWL_STYLE, wstyle);
}

/*
 * We implement _push() and _pop() routines, similar to their gtk_statusbar
 * counterparts.
 * XXX - Implement context IDs.
 */

void
win32_statusbarpanel_push(win32_element_t *statusbarpanel, gchar *msg) {
    GSList *msg_stack;
    gchar  *push_msg;
    gint    len;

    win32_element_assert(statusbarpanel);

    msg_stack = (GSList *) win32_element_get_data(statusbarpanel,
	    WIN32_STATUSBAR_MSG_STACK);

    len = GetWindowTextLength(statusbarpanel->h_wnd) + 1;

    push_msg = g_malloc(len);
    GetWindowText(statusbarpanel->h_wnd, push_msg, len);

    msg_stack = g_slist_prepend(msg_stack, push_msg);
    win32_element_set_data(statusbarpanel, WIN32_STATUSBAR_MSG_STACK, msg_stack);

    SetWindowText(statusbarpanel->h_wnd, msg);
}

void
win32_statusbarpanel_pop(win32_element_t *statusbarpanel) {
    GSList *msg_stack;
    gchar  *pop_msg;

    win32_element_assert(statusbarpanel);

    msg_stack = (GSList *) win32_element_get_data(statusbarpanel,
	    WIN32_STATUSBAR_MSG_STACK);

    if (msg_stack == NULL)
	return;

    pop_msg = (gchar *) msg_stack->data;

    msg_stack = g_slist_remove(msg_stack, pop_msg);
    win32_element_set_data(statusbarpanel, WIN32_STATUSBAR_MSG_STACK, msg_stack);

    SetWindowText(statusbarpanel->h_wnd, pop_msg);
    g_free(pop_msg);
}