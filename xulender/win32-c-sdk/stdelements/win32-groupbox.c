
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

static void win32_groupbox_destroy(win32_element_t *groupbox, gboolean destroy_window);
static LRESULT CALLBACK win32_groupbox_wnd_proc(HWND hw_groupbox, UINT msg, WPARAM w_param, LPARAM l_param);
static LRESULT CALLBACK win32_container_wnd_proc(HWND hw_container, UINT msg, WPARAM w_param, LPARAM l_param);

/* Structures */

typedef struct _groupbox_data_t {
    HWND container;
    gint pad_top;
    gint pad_bottom;
    gint pad_left;
    gint pad_right;
} groupbox_data_t;

static WNDPROC g_groupbox_wnd_proc = NULL;

#define WIN32_GROUPBOX_DATA "_win32_groupbox_data"

#define WIN32_GROUPBOX_PANE "GroupboxPane"

/*
 * XXX - BS_GROUPBOX windows are horrible about eating system messages.
 * In order to work around this, win32-c-sdk.py adds a <vbox> to any
 * <groupbox> it creates.  We fix the issue here at some point.
 */

/*
 * Create a Button control with a BS_GROUPBOX style.
 */

win32_element_t *
win32_groupbox_new(HWND hw_parent) {
    win32_element_t *groupbox;
    WNDCLASS         wc;
    groupbox_data_t *gd;
    SIZE             sz;

    g_assert(hw_parent != NULL);

    groupbox = win32_element_new(NULL);

    /* Groupboxes are actually buttons with the BS_GROUPBOX style
     * applied.  One has to wonder what the path from button to
     * groupbox was within Microsoft.
     */
    groupbox->h_wnd = CreateWindow(
	"BUTTON",
	"",
	WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
	0, 0, 0, 0,
	hw_parent,
	(HMENU) ID_GROUPBOX,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    SendMessage(groupbox->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    ShowWindow(groupbox->h_wnd, SW_SHOW);
    UpdateWindow(groupbox->h_wnd);

    groupbox->orient = BOX_ORIENT_VERTICAL;
    groupbox->type = BOX_GROUPBOX;
    groupbox->destroy = win32_groupbox_destroy;

    /* Attach the box address to our HWND. */
    SetWindowLong(groupbox->h_wnd, GWL_USERDATA, (LONG) groupbox);

    win32_get_text_size(groupbox->h_wnd, "ABC123xyz", &sz);
    gd = g_malloc(sizeof(groupbox_data_t));
    gd->pad_top = sz.cy + 1;
    gd->pad_bottom = 2;
    gd->pad_left = 2;
    gd->pad_right = 2;
    /*
     * The groupbox (which is really a button) control is bad about eating
     * events that it encounters.  We swap out the wndprocs in order to
     * properly handle events.
     */
    if (g_groupbox_wnd_proc == NULL) {
	g_groupbox_wnd_proc = (WNDPROC) GetWindowLong(groupbox->h_wnd, GWL_WNDPROC);
    }
    SetWindowLong(groupbox->h_wnd, GWL_WNDPROC, (LONG) win32_groupbox_wnd_proc);
    win32_element_set_data(groupbox, WIN32_GROUPBOX_DATA, gd);

    /* Create our container sub-window */
    wc.lpszClassName = WIN32_GROUPBOX_PANE;
    wc.lpfnWndProc = win32_container_wnd_proc;
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    wc.hIcon = NULL;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH) (COLOR_3DFACE+1);
    wc.lpszMenuName = NULL;

    RegisterClass(&wc);

    gd->container = CreateWindowEx(
	0,
	WIN32_GROUPBOX_PANE,
	WIN32_GROUPBOX_PANE,
	WS_CHILD | WS_VISIBLE,
	0, 0, 0, 0,
	groupbox->h_wnd,
	NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	NULL);

    ShowWindow(gd->container, SW_SHOW);
    UpdateWindow(gd->container);

    return groupbox;
}

/*
 * Move a child from the BS_GROUPBOX window to the container window.
 */
void
win32_groupbox_reparent(win32_element_t *groupbox, win32_element_t *groupbox_el) {
    groupbox_data_t *gd;

    win32_element_assert(groupbox);
    win32_element_assert(groupbox_el);

    gd = (groupbox_data_t *) win32_element_get_data(groupbox, WIN32_GROUPBOX_DATA);

    SetParent(groupbox_el->h_wnd, gd->container);

}

void
win32_groupbox_set_title(win32_element_t *box, char *title) {
    SetWindowText(box->h_wnd, title);
}

/*
 * Return the extra width needed for padding.
 */
gint
win32_groupbox_extra_width(win32_element_t *groupbox) {
    groupbox_data_t *gd;

    win32_element_assert(groupbox);
    gd = (groupbox_data_t *) win32_element_get_data(groupbox, WIN32_GROUPBOX_DATA);

    return gd->pad_left + gd->pad_right;
}

/*
 * Return the extra height needed for padding.
 */
gint
win32_groupbox_extra_height(win32_element_t *groupbox) {
    groupbox_data_t *gd;

    win32_element_assert(groupbox);
    gd = (groupbox_data_t *) win32_element_get_data(groupbox, WIN32_GROUPBOX_DATA);

    return gd->pad_top + gd->pad_bottom;
}

static LRESULT CALLBACK
win32_groupbox_wnd_proc(HWND hw_groupbox, UINT msg, WPARAM w_param, LPARAM l_param) {
    win32_element_t *groupbox;
    groupbox_data_t *gd;
    RECT             cr;
    POINT            pt;

    groupbox = (win32_element_t *) GetWindowLong(hw_groupbox, GWL_USERDATA);

    switch (msg) {
	case WM_SIZE:
	    win32_element_assert(groupbox);
	    gd = (groupbox_data_t *) win32_element_get_data(groupbox, WIN32_GROUPBOX_DATA);
	    GetWindowRect(hw_groupbox, &cr);
	    pt.x = 0; pt.y = 0;
	    ScreenToClient(hw_groupbox, &pt);
	    OffsetRect(&cr, pt.x, pt.y);
	    cr.top += gd->pad_top;
	    cr.left += gd->pad_left;
	    cr.bottom -= gd->pad_bottom;
	    cr.right -= gd->pad_right;
	    MoveWindow(gd->container, cr.left, cr.top, cr.right - cr.left, cr.bottom - cr.top, TRUE);
	    break;
	default:
	    return(CallWindowProc(g_groupbox_wnd_proc, hw_groupbox, msg, w_param, l_param));
    }
    return(CallWindowProc(g_groupbox_wnd_proc, hw_groupbox, msg, w_param, l_param));
}

/*
 * Private routines
 */

static void
win32_groupbox_destroy(win32_element_t *groupbox, gboolean destroy_window) {
    groupbox_data_t *gd;

    win32_element_assert(groupbox);

    gd = (groupbox_data_t *) win32_element_get_data(groupbox, WIN32_GROUPBOX_DATA);
    DestroyWindow(gd->container);
    g_free(gd);
}

static LRESULT CALLBACK
win32_container_wnd_proc(HWND hw_container, UINT msg, WPARAM w_param, LPARAM l_param) {

    switch (msg) {
	case WM_COMMAND:
	    win32_element_handle_wm_command(msg, w_param, l_param);
	    break;
	default:
	    return(DefWindowProc(hw_container, msg, w_param, l_param));
    }
    return 0;
}

