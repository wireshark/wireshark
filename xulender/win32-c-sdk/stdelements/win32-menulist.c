
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

static void win32_menulist_size_adjust(win32_element_t *ml_el, gchar *text);

/*
 * Create a menulist control.
 */

win32_element_t *
win32_menulist_new(HWND hw_parent) {
    win32_element_t *menulist;

    g_assert(hw_parent != NULL);

    menulist = win32_element_new(NULL);

    menulist->h_wnd = CreateWindow(
	"COMBOBOX",
	"MenuList",
	WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
	0, 0, 0, 0,
	hw_parent,
	(HMENU) ID_MENULIST,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    /* Attach the menulist address to our HWND. */
    SetWindowLong(menulist->h_wnd, GWL_USERDATA, (LONG) menulist);

    SendMessage(menulist->h_wnd, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    win32_menulist_size_adjust(menulist, "ABCabc");

    ShowWindow(menulist->h_wnd, SW_SHOW);
    UpdateWindow(menulist->h_wnd);

    return menulist;
}

/*
 * Public functions
 */

/*
 * Add a menu item
 */
void
win32_menulist_add(win32_element_t *ml_el, gchar *item, gboolean selected) {
    int  sel;
    SIZE sz;

    win32_element_assert(ml_el);

    sel = SendMessage(ml_el->h_wnd, CB_ADDSTRING, 0, (LPARAM) (LPCTSTR) item);
    if (selected)
	win32_menulist_set_selection(ml_el, sel);

    win32_get_text_size(ml_el->h_wnd, item, &sz);
    if (sz.cx > ml_el->minwidth)
	win32_menulist_size_adjust(ml_el, item);
}

/*
 * Set the current selection
 */
void
win32_menulist_set_selection(win32_element_t *ml_el, int sel) {
    win32_element_assert(ml_el);

    SendMessage(ml_el->h_wnd, CB_SETCURSEL, (WPARAM) sel, 0);

    if (ml_el->oncommand != NULL) ml_el->oncommand(ml_el);
}

/*
 * Get the current selection
 */
int
win32_menulist_get_selection(win32_element_t *ml_el) {
    int ret;

    win32_element_assert(ml_el);

    ret = SendMessage(ml_el->h_wnd, CB_GETCURSEL, 0, 0);
    if (ret == CB_ERR) {
	return -1;
    }
    return ret;
} 

/*
 * Get the item string.  Returns NULL if the item is invalid.  Result
 * must be freed.
 */
gchar * win32_menulist_get_string(win32_element_t *ml_el, gint item) {
    int    len;
    gchar *str;

    win32_element_assert(ml_el);

    len = SendMessage(ml_el->h_wnd, CB_GETLBTEXTLEN, (WPARAM) item, 0);
    if (len == CB_ERR) {
	return NULL;
    }
    str = g_malloc(len);
    len = SendMessage(ml_el->h_wnd, CB_GETLBTEXT, (WPARAM) item, (LPARAM) (LPCSTR) str);
    if (len == CB_ERR) {
	g_free(str);
	return NULL;
    }
    return str;
}


/*
 * Given a string, finds its selection index.  Returns -1 if not found.
 */
int win32_menulist_find_string(win32_element_t *ml_el, gchar *str) {
    LRESULT res;

    win32_element_assert(ml_el);

    if (str == NULL) {
	return -1;
    }

    res = SendMessage(ml_el->h_wnd, CB_FINDSTRINGEXACT, (WPARAM) -1, (LPARAM) str);
    if (res == CB_ERR) {
	return -1;
    }
    return res;
}

/*
 * Private functions
 */

static void
win32_menulist_size_adjust(win32_element_t *ml_el, gchar *text) {
    SIZE     sz;
    LONG     width, height;
    RECT     mr;
    POINT    pt;
    gboolean changed = FALSE;

    win32_element_assert(ml_el);

    GetWindowRect(ml_el->h_wnd, &mr);
    height = mr.bottom - mr.top;

    /* XXX - There doesn't appear to be a way to get the width of the drop
     * down tab, so we currently guess. */
    win32_get_text_size(ml_el->h_wnd, text, &sz);
    width = sz.cx + DIALOG2PIXELX(22);
    if (width > ml_el->minwidth) {
	ml_el->minwidth = width;
	changed = TRUE;
    }
    if (height > ml_el->minheight) {
	ml_el->minheight = height;
	changed = TRUE;
    }

    if (changed) {
	pt.x = mr.left;
	pt.y = mr.top;
	ScreenToClient(GetParent(ml_el->h_wnd), &pt);
	MoveWindow(ml_el->h_wnd, pt.x, pt.y, width, height, TRUE);
    }
}
