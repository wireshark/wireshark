
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
static LRESULT CALLBACK win32_menulist_wnd_proc(HWND hw_listbox, UINT msg, WPARAM w_param, LPARAM l_param);

static WNDPROC g_menulist_wnd_proc = NULL;

#define WIN32_MENULIST_EDIT_BRUSH "_win32_menulist_edit_brush"
#define WIN32_MENULIST_EDIT_COLOR "_win32_menulist_edit_color"

/*
 * Create a menulist control.
 */

win32_element_t *
win32_menulist_new(HWND hw_parent, gboolean editable) {
    win32_element_t *menulist;
    LONG style = editable ? CBS_DROPDOWN : CBS_DROPDOWNLIST;

    g_assert(hw_parent != NULL);

    menulist = win32_element_new(NULL);

    menulist->h_wnd = CreateWindow(
	"COMBOBOX",
	"MenuList",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_AUTOHSCROLL | style,
	0, 0, 0, 0,
	hw_parent,
	(HMENU) ID_MENULIST,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPSTR) NULL);

    /* Attach the menulist address to our HWND. */
    SetWindowLong(menulist->h_wnd, GWL_USERDATA, (LONG) menulist);

    /*
     * Comboboxes use a standard (and not "rich") edit control, which doesn't
     * respond to EM_SETBKGNDCOLOR messages.  We fake this capability by
     * - Dropping in our own wndproc
     * - Having the wndproc catch EM_SETBKGNDCOLOR
     * - Having the wndproc catch WM_CTLCOLOREDIT
     */
    if (g_menulist_wnd_proc == NULL) {
        g_menulist_wnd_proc = (WNDPROC) GetWindowLong(menulist->h_wnd, GWL_WNDPROC);
    }
    SetWindowLong(menulist->h_wnd, GWL_WNDPROC, (LONG) win32_menulist_wnd_proc);

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
int
win32_menulist_add(win32_element_t *ml_el, gchar *item, gboolean selected) {
    LRESULT sel;
    SIZE sz;

    win32_element_assert(ml_el);

    sel = SendMessage(ml_el->h_wnd, CB_ADDSTRING, 0, (LPARAM) (LPCTSTR) item);
    if (sel < 0) {
	return -1;
    }

    if (selected)
	win32_menulist_set_selection(ml_el, sel);

    win32_get_text_size(ml_el->h_wnd, item, &sz);
    if (sz.cx > ml_el->minwidth)
	win32_menulist_size_adjust(ml_el, item);

    return sel;
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
 * Set the data for a given item.
 */
void win32_menulist_set_data(win32_element_t *ml_el, int item, gpointer data) {

    win32_element_assert(ml_el);

    SendMessage(ml_el->h_wnd, CB_SETITEMDATA, (WPARAM) item, (LPARAM) data);
}

/*
 * Get the data for a given item.  Returns NULL on failure.
 */
gpointer win32_menulist_get_data(win32_element_t *ml_el, int item) {
    LRESULT ret;

    win32_element_assert(ml_el);

    ret = SendMessage(ml_el->h_wnd, CB_GETITEMDATA, (WPARAM) item, 0);

    if (ret == CB_ERR)
	return NULL;

    return (gpointer) ret;
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

/*
 */
static LRESULT CALLBACK
win32_menulist_wnd_proc(HWND hw_menulist, UINT msg, WPARAM w_param, LPARAM l_param) {
    win32_element_t *menulist = (win32_element_t *) GetWindowLong(hw_menulist, GWL_USERDATA);
    HBRUSH           editbrush;
    COLORREF         color;
    HDC              hdc;

    switch(msg) {
	case WM_CTLCOLOREDIT:
	    win32_element_assert(menulist);

	    hdc = (HDC) w_param;
	    editbrush = win32_element_get_data(menulist, WIN32_MENULIST_EDIT_BRUSH);
	    color = (COLORREF) win32_element_get_data(menulist, WIN32_MENULIST_EDIT_COLOR);

	    if (editbrush) {
		SelectObject(hdc, editbrush);
		SetBkColor(hdc, color);
		return (LONG) editbrush;
	    }
	    break;
	case EM_SETBKGNDCOLOR:
	    editbrush = win32_element_get_data(menulist, WIN32_MENULIST_EDIT_BRUSH);
	    if (editbrush)
		DeleteObject(editbrush);

	    if (w_param)
		color = GetSysColor( (int) l_param);
	    else
		color = (COLORREF) l_param;

	    editbrush = CreateSolidBrush(color);

	    win32_element_set_data(menulist, WIN32_MENULIST_EDIT_BRUSH, editbrush);
	    win32_element_set_data(menulist, WIN32_MENULIST_EDIT_COLOR, (gpointer) color);
	    break;
	default:
	    break;
    }
    return(CallWindowProc(g_menulist_wnd_proc, hw_menulist, msg, w_param, l_param));
}