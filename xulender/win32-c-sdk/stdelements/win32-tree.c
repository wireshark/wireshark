/*
 * Tree element.  We need to do the following:
 * - Provide columns and column headers
 * - Hide column headers (what do we do if one is hidden, and others aren't?)
 *   There's an HDS_HIDDEN style, BTW.
 * - Custom-draw tree items, so that we get columns right
 * -
 *
 * XXX - The XULPlanet docs say that tree columns can be separated by splitters
 *       to make them adjustable.  Do we implement this?
 *
 * Windows doesn't have a multi-column tree control, so we have to
 * make a custom control using a "tree view" inside a "header".
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

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"

#include "win32-tree.h"

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/epan_dissect.h>

/* Structures */

typedef struct _tree_el_data_t {
    HWND header;
    HWND treeview;
    gboolean hideheader;
    GList *item_stack;
    HTREEITEM cur_item;
    gboolean open_item;
    void (*onselect)();
} tree_el_data_t;

static void win32_tree_destroy(win32_element_t *tree, gboolean destroy_window);
static LRESULT CALLBACK win32_tree_wnd_proc(HWND, UINT, WPARAM, LPARAM);
static void win32_tree_resize(HWND hw_tree);
static LRESULT win32_tree_notify(HWND, LPARAM, capture_file *);

#define EWC_TREE_PANE "TreePane"
#define WIN32_TREE_DATA "_win32_tree_data"

/*
 * Public routines
 */

/*
 * Creates a tree (header + treeview) control
 */

win32_element_t *
win32_tree_new(HWND hw_parent) {
    win32_element_t *tree;
    WNDCLASS wc;

    wc.lpszClassName = EWC_TREE_PANE;
    wc.lpfnWndProc = win32_tree_wnd_proc;
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

    tree = win32_element_new(NULL);

    CreateWindowEx(
	WS_EX_CLIENTEDGE,
	EWC_TREE_PANE,
	EWC_TREE_PANE,
	WS_CHILD | WS_VISIBLE,
	0, 0, 0, 0,
	hw_parent,
	NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	(LPVOID) tree);

    ShowWindow(tree->h_wnd, SW_SHOW);
    UpdateWindow(tree->h_wnd);

    return tree;
}

void
win32_tree_clear(HWND hw_tree) {
    win32_element_t *tree = (win32_element_t *) GetWindowLong(hw_tree, GWL_USERDATA);
    tree_el_data_t  *td;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);

    SendMessage(td->treeview, WM_SETREDRAW, FALSE, 0);
    /* Row and cell data is freed in the wnd_proc */
    TreeView_DeleteAllItems(td->treeview);
    SendMessage(td->treeview, WM_SETREDRAW, TRUE, 0);
}

void
win32_tree_add_column(win32_element_t *tree, gchar *id, gchar *label,
	gboolean primary, gboolean hideheader) {
    tree_el_data_t *td;
    int             count;
    LONG            h_style;
    HDITEM          hdi;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);

    /* XXX - XUL specifies "hideheader" in individual tree column headers.
     * This doesn't make sense e.g. what if you had alternating hidden and
     * visible headers?  If we encounter a hidden column header, we hide
     * the entire thing. */
    if (hideheader) {
	td->hideheader = TRUE;
	h_style = GetWindowLong(td->header, GWL_STYLE);
	h_style |= HDS_HIDDEN;
	SetWindowLong(td->header, GWL_STYLE, h_style);
    }

    hdi.mask = HDI_TEXT | HDI_FORMAT;
    hdi.pszText = label;
    hdi.cchTextMax = lstrlen(label);
    hdi.fmt = HDF_LEFT | HDF_STRING;
    hdi.lParam = (LPARAM) g_strdup(id);
    count = SendMessage(td->header, HDM_GETITEMCOUNT, 0, 0);
    SendMessage(td->header, HDM_INSERTITEM, (WPARAM) count, (LPARAM) &hdi);
}

/*
 * XXX - tree_push() and tree_pop() are lame attempts to get around unused
 * variable warnings in the automatically generated code.
 */
void
win32_tree_push(win32_element_t *tree) {
    tree_el_data_t *td;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);

    td->item_stack = g_list_prepend(td->item_stack, td->cur_item);
}

void
win32_tree_pop(win32_element_t *tree) {
    tree_el_data_t *td;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);

    td->item_stack = g_list_first(td->item_stack);
    g_assert(td->item_stack != NULL);
    td->cur_item = (HTREEITEM) td->item_stack->data;
    td->item_stack = g_list_remove(td->item_stack, td->cur_item);

    /* The treeitem has to have children in order for this to work, apparently. */
    if (td->open_item) {
	SendMessage(td->treeview, TVM_EXPAND, (WPARAM) (UINT) TVE_EXPAND,
	    (LPARAM) (HTREEITEM) td->cur_item);
	td->open_item = FALSE;
    }
}

void
win32_tree_flag_open_item(win32_element_t *tree) {
    tree_el_data_t *td;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);
    td->open_item = TRUE;
}

void
win32_tree_add_row(win32_element_t *tree, gchar *id) {
    tree_el_data_t    *td;
    tree_row          *row;
    TVITEM             tv_node;
    TVINSERTSTRUCT     tv_is;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);

    row = g_malloc(sizeof(tree_row));
    row->id = g_strdup(id);
    row->cells = NULL;

    ZeroMemory(&tv_node, sizeof(tv_node));
    ZeroMemory(&tv_is, sizeof(tv_is));
    tv_node.mask = TVIF_PARAM;
    tv_node.lParam = (LONG) row;

    td->item_stack = g_list_first(td->item_stack);
    if (td->item_stack != NULL)
	tv_is.hParent = (HTREEITEM) td->cur_item;
    else
	tv_is.hParent = TVI_ROOT;
    tv_is.hInsertAfter = TVI_LAST;
    tv_is.item = tv_node;

    td->cur_item = (HTREEITEM) SendMessage(td->treeview, TVM_INSERTITEM, 0,
	(LPARAM) (LPTVINSERTSTRUCT) &tv_is);
}

void
win32_tree_add_cell(win32_element_t *tree, gchar *id, gchar *text) {
    tree_el_data_t *td;
    tree_row       *row;
    tree_cell      *cell;
    TVITEM          tvi;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);
    g_assert(td->cur_item != NULL);

    cell = g_malloc(sizeof(tree_cell));
    cell->id = g_strdup(id);
    cell->text = g_strdup(text);

    ZeroMemory(&tvi, sizeof(tvi));
    tvi.mask = TVIF_PARAM;
    tvi.hItem = td->cur_item;
    TreeView_GetItem(td->treeview, &tvi);
    row = (tree_row *) tvi.lParam;
    row->cells = g_list_append(row->cells, cell);
}

void
win32_tree_minimum_size(win32_element_t *tree) {
    tree_el_data_t *td;
    RECT            tvir, hir;
    SIZE            sz;
    HTREEITEM       item;
    TVITEM          tvi;
    tree_row       *row;
    tree_cell      *cell;
    gint            width;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);

    tree->minwidth = 0;
    tree->minheight = 0;

    /* XXX - We need to check more than just the first column. */

    Header_GetItemRect(td->header, 0, &hir);
    /* XXX - This returns an abnormal width.  We'll comment it out for now. */
//    tree->minwidth += hir.right - hir.left;
    tree->minheight += hir.bottom - hir.top;

    item = TreeView_GetFirstVisible(td->treeview);

    while (item) {
	tvi.mask = TVIF_PARAM;
	tvi.hItem = item;
	TreeView_GetItem(td->treeview, &tvi);
	row = (tree_row *) tvi.lParam;
	row->cells = g_list_first(row->cells);
	g_assert(row->cells != NULL);
	cell = row->cells->data;
	g_assert (cell != NULL);

	win32_get_text_size(td->treeview, (LPCSTR) cell->text, &sz);

	TreeView_GetItemRect(td->treeview, item, &tvir, TRUE);

	width = tvir.left + sz.cx + DIALOG2PIXELY(22);
	if (width > tree->minwidth) {
	    tree->minwidth = width;
	}
	item = TreeView_GetNextVisible(td->treeview, item);
	if (item)
	    tree->minheight += TreeView_GetItemHeight(td->treeview);
    }
}

void
win32_tree_set_onselect(win32_element_t *tree, void (*selfunc)()) {
    tree_el_data_t *td;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);

    td->onselect = selfunc;
}

/*
 * Private routines
 */

static void
win32_tree_destroy(win32_element_t *tree, gboolean destroy_window) {
    tree_el_data_t *td;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);

    DestroyWindow(td->header);
    DestroyWindow(td->treeview);
    g_free(td);
}

static LRESULT CALLBACK
win32_tree_wnd_proc(HWND hw_tree, UINT msg, WPARAM w_param, LPARAM l_param) {
    win32_element_t *tree;
    tree_el_data_t  *td;
    tree_row        *row;
    tree_cell       *cell;
    HINSTANCE        h_instance = (HINSTANCE) GetWindowLong(hw_tree, GWL_HINSTANCE);
    LPCREATESTRUCT   cs = (LPCREATESTRUCT) l_param;
    RECT             pr;
    HDLAYOUT         hdl;
    WINDOWPOS        hdl_wpos;
    LPNMTVCUSTOMDRAW tvcdparam;
    LPNMHDR          lpnmh;
    HTREEITEM        item;
    TVITEM           tvi;
    TVHITTESTINFO    tvht;
    DWORD            mpos;
    gint             tv_width;
    LPNMTREEVIEW     tv_sel;
    GList           *cells;

    switch (msg) {
	case WM_CREATE:
	    /* Attach the treeview address to our HWND. */
	    tree = (win32_element_t *) cs->lpCreateParams;
	    g_assert(tree != NULL);
	    tree->h_wnd = hw_tree;
	    SetWindowLong(hw_tree, GWL_USERDATA, (LONG) tree);

	    td = g_malloc(sizeof(tree_el_data_t));

	    td->header = CreateWindowEx(
		0,
		WC_HEADER,
		"",
		WS_CHILD | WS_TABSTOP | WS_VISIBLE | HDS_HOTTRACK,
		0, 0, 0, 0,
		hw_tree,
		(HMENU) 0,
		h_instance,
		NULL);
	    td->treeview = CreateWindowEx(
		0,
		WC_TREEVIEW,
		"",
		WS_CHILD | WS_TABSTOP | WS_VISIBLE |
			TVS_DISABLEDRAGDROP | TVS_HASBUTTONS |
			TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
		0, 0, 0, 0,
		hw_tree,
		(HMENU) 0,
		h_instance,
		NULL);
	    td->hideheader = FALSE;
	    td->item_stack = NULL;
	    td->cur_item = NULL;
	    td->open_item = FALSE;
	    td->onselect = NULL;
	    win32_element_set_data(tree, WIN32_TREE_DATA, td);

	    GetClientRect(hw_tree, &pr);
	    hdl.prc = &pr;
	    hdl.pwpos = &hdl_wpos;
	    SendMessage(td->header, HDM_LAYOUT, 0, (LONG) &hdl);
	    tree->minwidth = 100;
	    tree->minheight = hdl_wpos.cy * 3;

	    break;
	case WM_SIZE:
	    win32_tree_resize (hw_tree);
	    break;
	case WM_NOTIFY:
	    lpnmh = (LPNMHDR) l_param;
	    switch (lpnmh->code) {
		case NM_CUSTOMDRAW: /* We have to draw each column by hand. */
		    tvcdparam = (LPNMTVCUSTOMDRAW) l_param;

		    switch (tvcdparam->nmcd.dwDrawStage) {
			case CDDS_PREPAINT:
			    return CDRF_NOTIFYITEMDRAW;
			    break;
			case CDDS_ITEMPREPAINT:
			    return CDRF_DODEFAULT | CDRF_NOTIFYPOSTPAINT;
			case CDDS_ITEMPOSTPAINT:
			    /* Bail if we're updating an empty area */
			    if (IsRectEmpty(&(tvcdparam->nmcd.rc))) {
				return CDRF_DODEFAULT;
			    }
			    /* Get our cell text list */
			    item = (HTREEITEM) tvcdparam->nmcd.dwItemSpec;
			    tvi.mask = TVIF_PARAM;
			    tvi.hItem = item;
			    SendMessage(lpnmh->hwndFrom, TVM_GETITEM, 0, (LPARAM) (LPTVITEM) &tvi);
			    row = (tree_row *) tvi.lParam;
			    row->cells = g_list_first(row->cells);
			    /* XXX - We should probably throw an assertion if our list length != the # of columns */
			    if (row->cells != NULL) {
				cell = (tree_cell *) row->cells->data;
				g_assert(cell != NULL);
				/* XXX - We actually need to loop over all of the items in the GList. */
				GetClientRect(lpnmh->hwndFrom, &pr);
				tv_width = pr.right;

				TreeView_GetItemRect(lpnmh->hwndFrom, item, &pr, TRUE);
				pr.right = tv_width;
				FillRect(tvcdparam->nmcd.hdc, &pr, (HBRUSH) COLOR_WINDOW + 1);
				FillRect(tvcdparam->nmcd.hdc, &pr, CreateSolidBrush(tvcdparam->clrTextBk));
				if (tvcdparam->nmcd.uItemState & CDIS_FOCUS) {
				    DrawFocusRect(tvcdparam->nmcd.hdc, &pr);
				}
				pr.top++; pr.bottom--; pr.left += 2; pr.right -= 2;
				SetBkColor(tvcdparam->nmcd.hdc, tvcdparam->clrTextBk);
				SetTextColor(tvcdparam->nmcd.hdc, tvcdparam->clrText);
				DrawText(tvcdparam->nmcd.hdc, cell->text, -1, &pr, DT_NOPREFIX | DT_END_ELLIPSIS);
			    }

			    return CDRF_DODEFAULT;
			    break;
			default:
			    return CDRF_DODEFAULT;
			    break;
		    }
		    break;
		case NM_CLICK:
		    /* Since we're drawing our own labels, the TreeView provides
		     * a selection area that's only a couple of pixels wide.  We
		     * catch clicks to the right of each TreeItem here, and make
		     * selections as needed.
		     */
		    mpos = GetMessagePos();
		    tvht.pt.x = GET_X_LPARAM(mpos);
		    tvht.pt.y = GET_Y_LPARAM(mpos);
		    ScreenToClient(lpnmh->hwndFrom, &(tvht.pt));
		    item = TreeView_HitTest(lpnmh->hwndFrom, &tvht);
		    if (item != NULL && tvht.flags & TVHT_ONITEMRIGHT) {
			TreeView_SelectItem(lpnmh->hwndFrom, item);
		    }
		    break;
		case TVN_SELCHANGED:
		    tv_sel = (LPNMTREEVIEW) l_param;
		    tree = (win32_element_t *) GetWindowLong(hw_tree, GWL_USERDATA);
		    win32_element_assert(tree);
		    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);
		    g_assert(td != NULL);

		    if (td->onselect) {
			td->onselect(tree, tv_sel);
		    }
		    break;
		case TVN_DELETEITEM:
		    tv_sel = (LPNMTREEVIEW) l_param;

		    row = (tree_row *) tv_sel->itemOld.lParam;
		    cells = g_list_first(row->cells);
		    while (cells) {
			g_free(cells->data);
			cells = g_list_next(cells);
		    }
		    g_list_free(g_list_first(row->cells));
		    g_free(row);
		    break;
		default:
		    break;
	    }
	    break;
	    return(DefWindowProc(hw_tree, msg, w_param, l_param));
	default:
	    return(DefWindowProc(hw_tree, msg, w_param, l_param));
    }
    return 0;
}

static void
win32_tree_resize(HWND hw_tree) {
    win32_element_t *tree = (win32_element_t *) GetWindowLong(hw_tree, GWL_USERDATA);
    tree_el_data_t  *td;
    RECT             pr;
    HDLAYOUT         hdl;
    WINDOWPOS        hdl_wpos;

    win32_element_assert(tree);
    td = (tree_el_data_t *) win32_element_get_data(tree, WIN32_TREE_DATA);

    GetClientRect(hw_tree, &pr);

    hdl.prc = &pr;
    hdl.pwpos = &hdl_wpos;
    SendMessage(td->header, HDM_LAYOUT, 0, (LONG) &hdl);

    SetWindowPos(td->header, hdl_wpos.hwndInsertAfter, hdl_wpos.x, hdl_wpos.y,
	hdl_wpos.cx, hdl_wpos.cy, hdl_wpos.flags | SWP_SHOWWINDOW);
    MoveWindow(td->treeview, pr.left, pr.top, pr.right - pr.left,
	pr.bottom - pr.top, TRUE);
}
