

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

#include "ethereal-treeview.h"
#include "ethereal-byteview.h"

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/epan_dissect.h>
#include "menu.h"

/* Structures */

typedef struct _treeview_data_t {
    HWND             tv_ctrl;
    win32_element_t *byteview;
} treeview_data_t;

typedef struct _add_node_t {
    HWND      tv_ctrl;
    HTREEITEM node;
} add_node_t;

static void ethereal_treeview_resize(HWND hw_treeview);
static LRESULT CALLBACK ethereal_treeview_wnd_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT ethereal_treeview_notify(HWND, LPARAM, capture_file *);
static HTREEITEM ethereal_treeview_find_lparam(HWND tv_ctrl, HTREEITEM last_ti, LPARAM lp_data);

#define EWC_TREE_PANE          "TreeViewPane"
#define ETHEREAL_TREEVIEW_DATA "_ethereal_treeview_data"

/*
 * Creates a TreeView control
 */

win32_element_t *
ethereal_treeview_new(HWND hw_parent) {
    win32_element_t *treeview;
    HINSTANCE        h_instance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    WNDCLASS         wc;

    wc.lpszClassName = EWC_TREE_PANE;
    wc.lpfnWndProc = ethereal_treeview_wnd_proc;
    wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    wc.cbClsExtra = 0;
    wc.cbWndExtra = 0;
    wc.hInstance = h_instance;
    wc.hIcon = NULL;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH) (COLOR_WINDOWFRAME+1);
    wc.lpszMenuName = NULL;

    RegisterClass(&wc);

    g_assert(hw_parent != NULL);

    treeview = win32_element_new(NULL);

    treeview->h_wnd = CreateWindow(
	EWC_TREE_PANE,
	EWC_TREE_PANE,
	WS_CHILD | WS_VISIBLE,
	0, 0, 0, 0,
	hw_parent,
	NULL,
	h_instance,
	treeview);

    ShowWindow(treeview->h_wnd, SW_SHOW);
    UpdateWindow(treeview->h_wnd);

    ethereal_treeview_resize(treeview->h_wnd);

    return treeview;
}

void
ethereal_treeview_clear(win32_element_t *treeview) {
    treeview_data_t *td;

    win32_element_assert(treeview);
    td = (treeview_data_t *) win32_element_get_data(treeview, ETHEREAL_TREEVIEW_DATA);

    /* We must first clear the current selection */
    TreeView_SelectItem(td->tv_ctrl, NULL);
    SendMessage(td->tv_ctrl, WM_SETREDRAW, FALSE, 0);
    TreeView_DeleteAllItems(td->tv_ctrl);
    SendMessage(td->tv_ctrl, WM_SETREDRAW, TRUE, 0);
}

static void
ethereal_treeview_add_node(proto_node *node, gpointer data)
{
    add_node_t      info;
    add_node_t     *parent_info = (add_node_t *) data;
    HTREEITEM       parent;
    field_info     *fi = PITEM_FINFO(node);
    TVITEM          tv_node;
    TVINSERTSTRUCT  tv_is;
    gchar           label_str[ITEM_LABEL_LENGTH];
    gchar          *label_ptr;
    gboolean        is_leaf, is_expanded;

    if (PROTO_ITEM_IS_HIDDEN(node))
	return;

    /* was a free format label produced? */
    if (fi->rep) {
	label_ptr = fi->rep->representation;
    } else { /* no, make a generic label */
	label_ptr = label_str;
	proto_item_fill_label(fi, label_str);
    }

    if (node->first_child != NULL) {
	is_leaf = FALSE;
	g_assert(fi->tree_type >= 0 && fi->tree_type < num_tree_types);
	if (tree_is_expanded[fi->tree_type]) {
	    is_expanded = TRUE;
	} else {
	    is_expanded = FALSE;
	}
    } else {
	is_leaf = TRUE;
	is_expanded = FALSE;
    }

    if(PROTO_ITEM_IS_GENERATED(node)) {
	label_ptr = g_strdup_printf("[%s]", label_ptr);
    }

    info.tv_ctrl = parent_info->tv_ctrl;
    ZeroMemory(&tv_node, sizeof(tv_node));
    ZeroMemory(&tv_is, sizeof(tv_is));

    /* Load our node data */
    tv_node.mask = TVIF_TEXT | TVIF_PARAM;
    tv_node.pszText = label_ptr;
    tv_node.cchTextMax = lstrlen(label_ptr);
    tv_node.lParam = (LPARAM) fi;

    /* Prep the node for insertion */
    tv_is.hParent = parent_info->node;
    tv_is.hInsertAfter = TVI_LAST;
    tv_is.item = tv_node;

    /* Insert the node */
    parent = TreeView_InsertItem(info.tv_ctrl, &tv_is);

    if(PROTO_ITEM_IS_GENERATED(node)) {
	g_free(label_ptr);
    }

    if (!is_leaf) { /* Our node contains more items to add. */
	info.node = parent;
	proto_tree_children_foreach(node, ethereal_treeview_add_node, &info);

	if (is_expanded) {
	    ZeroMemory(&tv_node, sizeof(tv_node));
	    tv_node.mask = TVIF_STATE;
	    tv_node.state = TVIS_EXPANDED;
	    tv_node.stateMask = TVIS_EXPANDED;
	    TreeView_SetItem(info.tv_ctrl, info.node);
	}
    }
}

void
ethereal_treeview_draw(win32_element_t *treeview, proto_tree *tree, win32_element_t *byteview) {
    treeview_data_t *td;
    add_node_t       node_data;

    win32_element_assert(treeview);
    td = (treeview_data_t *) win32_element_get_data(treeview, ETHEREAL_TREEVIEW_DATA);
    td->byteview = byteview;

    ethereal_treeview_clear(treeview);
    node_data.tv_ctrl = td->tv_ctrl;
    node_data.node = NULL;

    proto_tree_children_foreach(tree, ethereal_treeview_add_node, &node_data);
}

HTREEITEM
ethereal_treeview_find_finfo(win32_element_t *treeview, field_info *fi) {
    treeview_data_t *td;

    win32_element_assert(treeview);
    td = (treeview_data_t *) win32_element_get_data(treeview, ETHEREAL_TREEVIEW_DATA);

    return ethereal_treeview_find_lparam(td->tv_ctrl, NULL, (LPARAM) fi);
}

void
ethereal_treeview_select(win32_element_t *treeview, HTREEITEM hti) {
    treeview_data_t *td;

    win32_element_assert(treeview);
    td = (treeview_data_t *) win32_element_get_data(treeview, ETHEREAL_TREEVIEW_DATA);

    TreeView_Select(td->tv_ctrl, hti, TVGN_FIRSTVISIBLE);
    TreeView_Select(td->tv_ctrl, hti, TVGN_CARET);
}

/*
 * Private routines
 */
static void
ethereal_treeview_resize(HWND hw_treeview) {
    win32_element_t *treeview = (win32_element_t *) GetWindowLong(hw_treeview, GWL_USERDATA);
    treeview_data_t *td;
    RECT             pr;

    win32_element_assert(treeview);
    td = (treeview_data_t *) win32_element_get_data(treeview, ETHEREAL_TREEVIEW_DATA);

    GetClientRect(hw_treeview, &pr);
    MoveWindow(td->tv_ctrl, pr.left, pr.top, pr.right - pr.left,
	pr.bottom - pr.top, TRUE);
}

static LRESULT CALLBACK
ethereal_treeview_wnd_proc(HWND hw_treeview, UINT msg,
	WPARAM w_param, LPARAM l_param) {
    win32_element_t *treeview;
    treeview_data_t *td;
    LPCREATESTRUCT   cs = (LPCREATESTRUCT) l_param;

    switch (msg) {
	case WM_CREATE:
	    /* Attach the treeview address to our HWND. */
	    treeview = (win32_element_t *) cs->lpCreateParams;
	    g_assert(treeview != NULL);
	    treeview->h_wnd = hw_treeview;
	    SetWindowLong(hw_treeview, GWL_USERDATA, (LONG) treeview);

	    td = g_malloc(sizeof(treeview_data_t));

	    td->tv_ctrl = CreateWindowEx(
		WS_EX_CLIENTEDGE,
		WC_TREEVIEW,
		"",
		WS_CHILD | WS_TABSTOP | WS_VISIBLE |
			TVS_DISABLEDRAGDROP | TVS_FULLROWSELECT | TVS_HASBUTTONS |
			TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
		0, 0, 0, 0,
		hw_treeview,
		(HMENU) ID_TREE_VIEW,
		(HINSTANCE) GetWindowLong(hw_treeview, GWL_HINSTANCE),
		NULL);
	    td->byteview = NULL;
	    win32_element_set_data(treeview, ETHEREAL_TREEVIEW_DATA, td);
	    break;
	case WM_SIZE:
	    ethereal_treeview_resize (hw_treeview);
	    break;
	case WM_NOTIFY:
	    return ethereal_treeview_notify(hw_treeview, l_param, &cfile);
	    break;
	default:
	    return(DefWindowProc(hw_treeview, msg, w_param, l_param));
    }
    return 0;
}

static LRESULT
ethereal_treeview_notify(HWND hw_treeview, LPARAM l_param, capture_file *cfile) {
    win32_element_t *treeview = (win32_element_t *) GetWindowLong(hw_treeview, GWL_USERDATA);
    treeview_data_t *td;
    LPNMHDR          lpnmh = (LPNMHDR) l_param;
    LPNMTREEVIEW     tv_sel;
    field_info      *finfo = NULL;
    const guint8    *byte_data = NULL;
    guint            byte_len;

    win32_element_assert(treeview);
    td = (treeview_data_t *) win32_element_get_data(treeview, ETHEREAL_TREEVIEW_DATA);

    switch(lpnmh->code) {
	case TVN_SELCHANGED:
	    /* Bah.  For some reason, we crash if we select a
	     * packet, then click on a tree view label.  Forcing
	     * the focus to the treeview window seems to fix this.
	     */
	    SetFocus(td->tv_ctrl);
	    tv_sel = (LPNMTREEVIEW) l_param;

	    if (!TreeView_GetSelection(td->tv_ctrl)) {
		// Clear the byte view
		unselect_field(cfile);
		packet_hex_print(td->byteview, byte_data, cfile->current_frame,
			NULL, 0);
		break;
	    }
	    if (tv_sel)
		finfo = (field_info *) tv_sel->itemNew.lParam;
	    if (! finfo) return 0;

	    set_notebook_page(td->byteview, finfo->ds_tvb);

	    byte_data = get_byteview_data_and_length(td->byteview, &byte_len);
	    g_assert(byte_data != NULL);

	    cfile->finfo_selected = finfo;
	    set_menus_for_selected_tree_row(cfile);

	    packet_hex_print(td->byteview, byte_data, cfile->current_frame,
		    finfo, byte_len);

	    // XXX - Push data to the statusbar
	    // XXX - Get our bv HWND and data ptr info

	    break;
	default:
	    break;
    }
    return 0;
}

/* Find a TreeView item by its lParam value */
/* XXX - We could eliminate this by adding a generic pointer to the
 * proto_node or field_info structs, which we could use to store an
 * HTREEITEM pointer.
 */
static HTREEITEM
ethereal_treeview_find_lparam(HWND tv_ctrl, HTREEITEM last_ti, LPARAM lp_data) {
    TVITEM    tvi;
    HTREEITEM hti, ret;

    if (last_ti == NULL) { /* Start at the root */
	hti = TreeView_GetRoot(tv_ctrl);
	if (hti == NULL) return NULL;
	return ethereal_treeview_find_lparam(tv_ctrl, hti, lp_data);
    }

    ZeroMemory(&tvi, sizeof(tvi));
    tvi.mask = TVIF_PARAM;
    tvi.hItem = last_ti;

    if (TreeView_GetItem(tv_ctrl, &tvi)) {
	if (tvi.lParam == lp_data) {
	    return tvi.hItem;
	}
    }

    hti = TreeView_GetChild(tv_ctrl, last_ti);
    if (hti != NULL) {
	ret = ethereal_treeview_find_lparam(tv_ctrl, hti, lp_data);
	if (ret != NULL) return ret;
    }

    hti = TreeView_GetNextSibling(tv_ctrl, last_ti);
    if (hti != NULL) {
	ret = ethereal_treeview_find_lparam(tv_ctrl, hti, lp_data);
	if (ret != NULL) return ret;
    }

    return NULL;
}

