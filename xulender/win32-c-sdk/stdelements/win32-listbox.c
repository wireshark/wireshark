/*
 *
 * XXX - The XULPlanet docs say that list columns can be separated by splitters
 *       to make them adjustable.  Do we implement this?
 *
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP
#include <pcap.h>
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "color.h"

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"

static void win32_listbox_destroy(win32_element_t *listbox, gboolean destroy_window);
static LRESULT CALLBACK win32_listbox_wnd_proc(HWND hw_listbox, UINT msg, WPARAM w_param, LPARAM l_param);
void win32_listbox_resize(HWND hw_listbox);
void win32_listbox_sort(win32_element_t *listbox);

/* Structures */

typedef struct _listbox_data_t {
    HWND     listview;
    gint     num_cols;
    gint     cur_col;
    gint     cur_item;
    gint     last_col_min_width;
    void     (*onselect)();
    void     (*ondoubleclick)();
} listbox_data_t;

typedef struct _listrow_data_t {
    gchar    *id; /* XXX - We only store IDs for the entire row.  Do we need to handle individual cells? */
    gpointer *data;
    color_t  *fg;
    color_t  *bg;
} listrow_data_t;

#define EWC_LISTBOX_PANE "ListboxPane"
#define WIN32_LISTBOX_DATA "_win32_listbox_data"
#define MAX_ITEM_TEXT 256

#ifndef ListView_SetCheckState
# define ListView_SetCheckState(hwndLV, i, fCheck) \
    ListView_SetItemState(hwndLV, i, INDEXTOSTATEIMAGEMASK((fCheck)+1), LVIS_STATEIMAGEMASK)
#endif

#ifndef ListView_GetCheckState
# define ListView_GetCheckState(hwndLV, i) \
  ((((UINT)(SNDMSG((hwndLV), LVM_GETITEMSTATE, (WPARAM)(i), LVIS_STATEIMAGEMASK))) >> 12) -1)
#endif


/*
 * Public routines
 */

/*
 * Creates a listview control
 */

win32_element_t *
win32_listbox_new(HWND hw_parent, gboolean show_header) {
    win32_element_t *listbox;
    WNDCLASS         wc;

    wc.lpszClassName = EWC_LISTBOX_PANE;
    wc.lpfnWndProc = win32_listbox_wnd_proc;
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    wc.hIcon = NULL;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH) (COLOR_WINDOWFRAME+1);
    wc.lpszMenuName = NULL;

    RegisterClass(&wc);

    g_assert(hw_parent != NULL);

    listbox = win32_element_new(NULL);
    /* This is kind of cheesy, but we need to pass "show_header"
     * to the window proc somehow so we overload "minwidth". */
    listbox->minwidth = show_header;
    listbox->destroy = win32_listbox_destroy;

    CreateWindowEx(
	0,
	EWC_LISTBOX_PANE,
	EWC_LISTBOX_PANE,
	WS_CHILD | WS_VISIBLE | CS_DBLCLKS,
	0, 0, 0, 50,
	hw_parent,
	NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPVOID) listbox);

    ShowWindow(listbox->h_wnd, SW_SHOW);
    UpdateWindow(listbox->h_wnd);

    SetWindowLong(listbox->h_wnd, GWL_USERDATA, (LONG) listbox);

    return listbox;
}

void
win32_listbox_clear(win32_element_t *listbox) {
    listbox_data_t *ld;
    int             i;
    LVITEM          item;
    listrow_data_t *lr;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    ld->cur_col = 0;
    ld->cur_item = 0;
    ld->last_col_min_width = 0;

    i = ListView_GetNextItem(ld->listview, -1, LVNI_ALL);
    while (i >= 0) {
	ZeroMemory(&item, sizeof(item));
	item.mask = LVIF_PARAM;
	item.iItem = i;
	item.iSubItem = 0;
	if (ListView_GetItem(ld->listview, &item)) {
	    lr = (listrow_data_t *) item.lParam;
	    if (lr) {
		if (lr->fg)
		    g_free(lr->fg);
		if (lr->bg)
		    g_free(lr->bg);
		g_free(lr);
	    }
	}
	i = ListView_GetNextItem(ld->listview, i, LVNI_ALL);
    }
    SendMessage(ld->listview, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(ld->listview);
    SendMessage(ld->listview, WM_SETREDRAW, TRUE, 0);
    for (i = 0; i < ld->num_cols; i++) {
	ListView_SetColumnWidth(ld->listview, i, 0);
    }
}

void
win32_listbox_add_column(win32_element_t *listbox, gchar *id, gchar *label) {
    listbox_data_t *ld;
    LVCOLUMN        col;
    HWND            header;
    HDITEM          hdi;
    SIZE            sz;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);
    header = ListView_GetHeader(ld->listview);

    win32_get_text_size(header, label, &sz);
    sz.cx += DIALOG2PIXELX(12);
    if (sz.cx > ld->last_col_min_width)
	ld->last_col_min_width = sz.cx;

    ZeroMemory(&col, sizeof(col));
    col.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_WIDTH;
    if (label != NULL)
	col.mask |= LVCF_TEXT;
    col.pszText = label;
    col.cchTextMax = lstrlen(label);
    col.fmt = LVCFMT_LEFT;
    col.cx = sz.cx;
    ListView_InsertColumn(ld->listview, ld->num_cols, &col);

    ZeroMemory(&hdi, sizeof(hdi));
    hdi.mask = HDI_LPARAM;
    hdi.lParam = (LPARAM) g_strdup(id);
    Header_SetItem(header, ld->num_cols, &hdi);

    ld->num_cols++;
}

gint
win32_listbox_add_item(win32_element_t *listbox, gint row, gchar *id, gchar *text) {
    listbox_data_t   *ld;
    LVITEM            item;
    listrow_data_t   *lr;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    lr = g_malloc(sizeof(listrow_data_t));
    lr->id = g_strdup(id);
    lr->data = NULL;
    lr->fg = NULL;
    lr->bg = NULL;

    if (ld->num_cols < 1) {
	win32_listbox_add_column(listbox, NULL, NULL);
    }
    ld->cur_col = 0;

    ZeroMemory(&item, sizeof(item));
    item.mask = TVIF_PARAM;
    item.lParam = (LPARAM) lr;
    if (row < 0) {
	item.iItem = ld->cur_item + 1;
    } else {
	item.iItem = row;
    }
    item.iSubItem = 0;

    ld->cur_item = ListView_InsertItem(ld->listview, &item);

    if (text != NULL)
	win32_listbox_add_cell(listbox, id, text);

    return ld->cur_item;
}

void
win32_listbox_delete_item(win32_element_t *listbox, gint row) {
    listbox_data_t *ld;
    LVITEM          item;
    listrow_data_t *lr;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    ZeroMemory(&item, sizeof(item));
    item.mask = LVIF_PARAM;
    item.iItem = row;
    item.iSubItem = 0;
    if (ListView_GetItem(ld->listview, &item)) {
	lr = (listrow_data_t *) item.lParam;
	if (lr)
	    g_free(lr);
    }

    ListView_DeleteItem(ld->listview, row);
}

void
win32_listbox_add_cell(win32_element_t *listbox, gchar *id, gchar *text) {
    listbox_data_t *ld;
    int             col_width, text_width;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);
    g_assert(ld->cur_item >= 0);

    ListView_SetItemText(ld->listview, ld->cur_item, ld->cur_col, text);

    col_width = ListView_GetColumnWidth(ld->listview, ld->cur_col);
    text_width = ListView_GetStringWidth(ld->listview, text);
    text_width += DIALOG2PIXELX(8);
    if (ld->cur_col == ld->num_cols - 1 && text_width > ld->last_col_min_width) {
	ld->last_col_min_width = text_width;
    }
    if (text_width > col_width) {
	ListView_SetColumnWidth(ld->listview, ld->cur_col, text_width);
    }

    win32_listbox_resize(listbox->h_wnd);
    ld->cur_col++;

    /* XXX - Sorting at every insert isn't very scalable */
    if (listbox->sortdirection != EL_SORT_NATURAL) {
	win32_listbox_sort(listbox);
    }
}

/*
 * Set the text in a particular row/column.
 */
void
win32_listbox_set_text(win32_element_t *listbox, gint row, gint column, gchar *text) {
    listbox_data_t   *ld;
    LVITEM            item;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    ZeroMemory(&item, sizeof(item));
    item.mask = LVIF_TEXT;
    item.iItem = row;
    item.iSubItem = column;
    item.pszText = text;
    item.cchTextMax = lstrlen(text);

    ListView_SetItem(ld->listview, &item);
}

/*
 * Get the text in a particular row/column.
 */
gchar *
win32_listbox_get_text(win32_element_t *listbox, gint row, gint column) {
    listbox_data_t *ld;
    static gchar    text[MAX_ITEM_TEXT];

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    text[0] = '\0';
    ListView_GetItemText(ld->listview, row, column, text, MAX_ITEM_TEXT);
    if (text[0] == '\0') {
	return NULL;
    }
    return g_strdup(text);
}

/*
 * Associate a data pointer with a row.
 */
void
win32_listbox_set_row_data(win32_element_t *listbox, gint row, gpointer data) {
    listbox_data_t   *ld;
    LVITEM            item;
    listrow_data_t   *lr;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    ZeroMemory(&item, sizeof(item));
    item.mask = TVIF_PARAM;
    item.iItem = row;
    item.iSubItem = 0;

    if (ListView_GetItem(ld->listview, &item)) {
	lr = (listrow_data_t *) item.lParam;
	g_assert(lr != NULL);
	lr->data = data;
    }
}

/*
 * Set the foreground and background colors for a row.  Either color may be
 * NULL, in which case the system default color is used.
 */
void
win32_listbox_set_row_colors(win32_element_t *listbox, gint row, color_t *fg, color_t *bg) {
    listbox_data_t   *ld;
    LVITEM            item;
    listrow_data_t   *lr;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    ZeroMemory(&item, sizeof(item));
    item.mask = TVIF_PARAM;
    item.iItem = row;
    item.iSubItem = 0;

    if (ListView_GetItem(ld->listview, &item)) {
	lr = (listrow_data_t *) item.lParam;
	g_assert(lr != NULL);
	if (lr->fg)
	    g_free(lr->fg);
	if (lr->bg)
	    g_free(lr->bg);
	lr->fg = g_memdup(fg, sizeof(*lr->fg));
	lr->bg = g_memdup(bg, sizeof(*lr->bg));
    }
}

gpointer
win32_listbox_enable_checkboxes(win32_element_t *listbox, gboolean enable) {
    listbox_data_t *ld;
    DWORD style;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);
    
    style = ListView_GetExtendedListViewStyle(ld->listview);
    if (enable)
	style |= LVS_EX_CHECKBOXES;
    else
	style &= ~LVS_EX_CHECKBOXES;

    ListView_SetExtendedListViewStyle(ld->listview, style);
}

void win32_listbox_set_row_checked(win32_element_t *listbox, gint row, gboolean checked) {
    listbox_data_t *ld;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);
    
    ListView_SetCheckState(ld->listview, row, checked);
}

gboolean win32_listbox_get_row_checked(win32_element_t *listbox, gint row) {
    listbox_data_t *ld;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);
    
    return ListView_GetCheckState(ld->listview, row);
}

/*
 * Fetch the data pointer associated with a row.
 */
gpointer
win32_listbox_get_row_data(win32_element_t *listbox, gint row) {
    listbox_data_t   *ld;
    LVITEM            item;
    listrow_data_t   *lr;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    ZeroMemory(&item, sizeof(item));
    item.mask = TVIF_PARAM;
    item.iItem = row;
    item.iSubItem = 0;

    if (ListView_GetItem(ld->listview, &item)) {
	lr = (listrow_data_t *) item.lParam;
	g_assert(lr != NULL);
	return lr->data;
    } else {
	return NULL;
    }
}

/*
 * Set the selected row in a listbox.
 */
void win32_listbox_set_selected(win32_element_t *listbox, gint row) {
    listbox_data_t *ld;
    gint            sel_row = row;

    if (row < 0) {
	sel_row = 0;
    }

    if (row >= win32_listbox_get_row_count(listbox)) {
	sel_row = win32_listbox_get_row_count(listbox) - 1;
    }

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    ListView_SetItemState(ld->listview, -1, 0, LVIS_SELECTED);
    ListView_SetItemState(ld->listview, sel_row, LVIS_SELECTED, LVIS_SELECTED);
}

/*
 * Fetch the selected row in a listbox.
 */
gint win32_listbox_get_selected(win32_element_t *listbox) {
    listbox_data_t *ld;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    return ListView_GetNextItem(ld->listview, -1, LVNI_SELECTED);
}

/*
 * Return the row containing "text" in the specified column.  Return -1
 * otherwise.
 */
gint
win32_listbox_find_text(win32_element_t *listbox, gint column, gchar *text) {
    listbox_data_t *ld;
    LVFINDINFO      lvfi;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    lvfi.flags = LVFI_STRING;
    lvfi.psz   = text;
    return ListView_FindItem(ld->listview, -1, &lvfi);
}

/*
 * Return the number of rows in the listbox.
 */
gint win32_listbox_get_row_count(win32_element_t *listbox) {
    listbox_data_t *ld;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    return ListView_GetItemCount(ld->listview);
}

void
win32_listbox_minimum_size(win32_element_t *listbox) {
    listbox_data_t *ld;
    HWND            header;
    RECT            ir;
    LVCOLUMN        col;
    int             i, oldwidth, oldheight;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);
    header = ListView_GetHeader(ld->listview);

    oldwidth  = listbox->minwidth;
    oldheight = listbox->minheight;

    listbox->minwidth = 8;  /* XXX - Just a guess. */
    listbox->minheight = 0;

    /* XXX - We need to check more than just the first column. */

    if (Header_GetItemRect(header, 0, &ir)) {
	listbox->minheight += ir.bottom - ir.top;
    }

    if (listbox->minheight < 1) {
	listbox->minheight = 50;
    }

    for (i = 0; i < ld->num_cols; i++) {
	ZeroMemory(&col, sizeof(col));
	col.mask = LVCF_WIDTH;
	ListView_GetColumn(ld->listview, i, &col);
	listbox->minwidth += col.cx;
    }
}

void
win32_listbox_set_onselect(win32_element_t *listbox, void (*selfunc)()) {
    listbox_data_t *ld;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    ld->onselect = selfunc;
}

void
win32_listbox_set_ondoubleclick(win32_element_t *listbox, void (*dclickfunc)()) {
    listbox_data_t *ld;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    ld->ondoubleclick = dclickfunc;
}


/*
 * Private routines
 */

static void
win32_listbox_destroy(win32_element_t *listbox, gboolean destroy_window) {
    listbox_data_t *ld;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    win32_listbox_clear(listbox);

    DestroyWindow(ld->listview);

    g_free(ld);
}

void win32_listbox_resize(HWND hw_listbox) {
    win32_element_t *listbox = (win32_element_t *) GetWindowLong(hw_listbox, GWL_USERDATA);
    listbox_data_t  *ld;
    int              available_width, i;
    RECT             cr;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    GetClientRect(listbox->h_wnd, &cr);
    MoveWindow(ld->listview, 0, 0, cr.right - cr.left, cr.bottom - cr.top, TRUE);
    GetClientRect(ld->listview, &cr);

    available_width = cr.right - cr.left;
    for (i = 0; i < ld->num_cols - 1; i++) {
	available_width -= ListView_GetColumnWidth(ld->listview, i);
    }
    if (available_width > ld->last_col_min_width || ld->num_cols == 1) {
	ListView_SetColumnWidth(ld->listview, ld->num_cols - 1, available_width);
    }
}

static int CALLBACK
win32_listbox_sort_compare(LPARAM l_param1, LPARAM l_param2, LPARAM l_param_sort) {
    win32_element_t *listbox = (win32_element_t *) l_param_sort;
    listbox_data_t  *ld;
    int              idx, res;
    LVFINDINFO       lvfi;
    gchar            text1[MAX_ITEM_TEXT] = "", text2[MAX_ITEM_TEXT] = "";

    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    lvfi.flags = LVFI_PARAM;
    lvfi.lParam = l_param1;
    idx = ListView_FindItem(ld->listview, -1, &lvfi);
    if (idx >= 0) {
	ListView_GetItemText(ld->listview, idx, 0, text1, MAX_ITEM_TEXT);
    }

    lvfi.flags = LVFI_PARAM;
    lvfi.lParam = l_param2;
    idx = ListView_FindItem(ld->listview, -1, &lvfi);
    if (idx >= 0) {
	ListView_GetItemText(ld->listview, idx, 0, text2, MAX_ITEM_TEXT);
    }

    res = lstrcmp(text1, text2);
    if (listbox->sortdirection == EL_SORT_DESCENDING) {
	res *= -1;
    }
    return res;
}

void win32_listbox_sort(win32_element_t *listbox) {
    listbox_data_t *ld;

    win32_element_assert(listbox);
    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);

    ListView_SortItems(ld->listview, win32_listbox_sort_compare, (LPARAM) listbox);
}


static LRESULT CALLBACK
win32_listbox_wnd_proc(HWND hw_listbox, UINT msg, WPARAM w_param, LPARAM l_param) {
    win32_element_t *listbox;
    listbox_data_t  *ld;
    LPCREATESTRUCT   cs = (LPCREATESTRUCT) l_param;
    LPNMHDR          nmh;
    LPNMLISTVIEW     nmlv;
    NMLVCUSTOMDRAW  *lvcdparam;
    LONG             extra_style = LVS_NOCOLUMNHEADER;
    listrow_data_t  *lr;

    switch (msg) {
	case WM_CREATE:
	    /* Attach the treeview address to our HWND. */
	    listbox = (win32_element_t *) cs->lpCreateParams;
	    g_assert(listbox != NULL);
	    listbox->h_wnd = hw_listbox;
	    SetWindowLong(hw_listbox, GWL_USERDATA, (LONG) listbox);

            if (listbox->minwidth) {
		extra_style = 0;
	    }

	    ld = g_malloc(sizeof(listbox_data_t));

	    ld->listview = CreateWindowEx(
		WS_EX_CLIENTEDGE,
		WC_LISTVIEW,
		"",
		WS_CHILD | WS_VISIBLE |
		    LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | extra_style,
		0, 0, 0, 50,
		hw_listbox,
		NULL,
		(HINSTANCE) GetWindowLong(hw_listbox, GWL_HINSTANCE),
		NULL);

	    ld->num_cols = 0;
	    ld->cur_col = 0;
	    ld->cur_item = 0;
	    ld->last_col_min_width = 0;
	    ld->onselect = NULL;
	    ld->ondoubleclick = NULL;
	    win32_element_set_data(listbox, WIN32_LISTBOX_DATA, ld);

	    ListView_SetExtendedListViewStyle(ld->listview, LVS_EX_FULLROWSELECT);

	    listbox->minwidth = 0;
	    listbox->minheight = 50;

	    break;
	case WM_SIZE:
	    win32_listbox_resize(hw_listbox);
	    break;
	case WM_NOTIFY:
	    nmh = (LPNMHDR) l_param;
	    switch (nmh->code) {
		case LVN_ITEMCHANGED:
		    listbox = (win32_element_t *) GetWindowLong(hw_listbox, GWL_USERDATA);
		    win32_element_assert(listbox);
		    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);
		    g_assert(ld != NULL);
		    nmlv = (LPNMLISTVIEW) l_param;

		    if (ld->onselect) {
			ld->onselect(listbox, nmlv);
		    }
		    break;
		case NM_CUSTOMDRAW: /* Apply colors to each item */
		    lvcdparam = (NMLVCUSTOMDRAW *) l_param;
		    switch (lvcdparam->nmcd.dwDrawStage) {
			case CDDS_PREPAINT:
			    return CDRF_NOTIFYITEMDRAW;
			    break;
			case CDDS_ITEMPREPAINT:
			    lr = (listrow_data_t *) lvcdparam->nmcd.lItemlParam;
			    if (lr != NULL && lr->fg != NULL && lr->bg != NULL) {
				lvcdparam->clrText = COLOR_T2COLORREF(lr->fg);
				lvcdparam->clrTextBk = COLOR_T2COLORREF(lr->bg);
				return CDRF_NEWFONT;
			    }
			    return CDRF_DODEFAULT;
			    break;
		    }
		    break;
		case NM_DBLCLK:
		    listbox = (win32_element_t *) GetWindowLong(hw_listbox, GWL_USERDATA);
		    win32_element_assert(listbox);
		    ld = (listbox_data_t *) win32_element_get_data(listbox, WIN32_LISTBOX_DATA);
		    g_assert(ld != NULL);
		    nmlv = (LPNMLISTVIEW) l_param;
		    if (ld->ondoubleclick) {
			ld->ondoubleclick(listbox, nmlv);
		    }
		    break;
		default:
		    break;
	    }
	    break;
	default:
	    return(DefWindowProc(hw_listbox, msg, w_param, l_param));
    }
    return(DefWindowProc(hw_listbox, msg, w_param, l_param));
}
