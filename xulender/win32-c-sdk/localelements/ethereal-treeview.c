

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
#include "statusbar.h"

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
static void ethereal_treeview_expand_item(HWND tv_ctrl, HTREEITEM last_ti, gboolean expand);

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

void
ethereal_treeview_collapse_all(win32_element_t *treeview) {
    treeview_data_t *td;
    HTREEITEM        hti;

    win32_element_assert(treeview);
    td = (treeview_data_t *) win32_element_get_data(treeview, ETHEREAL_TREEVIEW_DATA);

    ethereal_treeview_expand_item(td->tv_ctrl, NULL, FALSE);

    hti = TreeView_GetSelection(td->tv_ctrl);
    if (hti)
	TreeView_EnsureVisible(td->tv_ctrl, hti);
}

void
ethereal_treeview_expand_all(win32_element_t *treeview) {
    treeview_data_t *td;
    HTREEITEM        hti;

    win32_element_assert(treeview);
    td = (treeview_data_t *) win32_element_get_data(treeview, ETHEREAL_TREEVIEW_DATA);

    ethereal_treeview_expand_item(td->tv_ctrl, NULL, TRUE);

    hti = TreeView_GetSelection(td->tv_ctrl);
    if (hti)
	TreeView_EnsureVisible(td->tv_ctrl, hti);
}

void
ethereal_treeview_expand_tree(win32_element_t *treeview) {
    treeview_data_t *td;
    HTREEITEM        hti;

    win32_element_assert(treeview);
    td = (treeview_data_t *) win32_element_get_data(treeview, ETHEREAL_TREEVIEW_DATA);

    hti = TreeView_GetSelection(td->tv_ctrl);

    if (!hti)
	return;

    TreeView_Expand(td->tv_ctrl, hti, TVE_EXPAND);

    hti = TreeView_GetChild(td->tv_ctrl, hti);

    if (hti)
	ethereal_treeview_expand_item(td->tv_ctrl, hti, TRUE);

    hti = TreeView_GetSelection(td->tv_ctrl);
    if (hti)
	TreeView_EnsureVisible(td->tv_ctrl, hti);
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
    gchar           *help_str = NULL;
    gchar            len_str[2+10+1+5+1]; /* ", {N} bytes\0",
                                             N < 4294967296 */
    gboolean         has_blurb = FALSE;
    guint            length = 0, byte_len;

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

	    /* Copied directly from gtk/main.c:tree_view_selection_changed_cb() */
	    if (finfo->hfinfo) {
		if (finfo->hfinfo->blurb != NULL &&
		    finfo->hfinfo->blurb[0] != '\0') {
		    has_blurb = TRUE;
		    length = strlen(finfo->hfinfo->blurb);
		} else {
		    length = strlen(finfo->hfinfo->name);
		}
		if (finfo->length == 0) {
		    len_str[0] = '\0';
		} else if (finfo->length == 1) {
		    strcpy (len_str, ", 1 byte");
		} else {
		    g_snprintf (len_str, sizeof len_str, ", %d bytes", finfo->length);
		}
		statusbar_pop_field_msg();      /* get rid of current help msg */
		if (length) {
		    help_str = g_strdup_printf("%s (%s)%s",
			    (has_blurb) ? finfo->hfinfo->blurb : finfo->hfinfo->name,
			    finfo->hfinfo->abbrev, len_str);
		    statusbar_push_field_msg(help_str);
		    g_free(help_str);
		} else {
		    /*
		     * Don't show anything if the field name is zero-length;
		     * the pseudo-field for "proto_tree_add_text()" is such
		     * a field, and we don't want "Text (text)" showing up
		     * on the status line if you've selected such a field.
		     *
		     * XXX - there are zero-length fields for which we *do*
		     * want to show the field name.
		     *
		     * XXX - perhaps the name and abbrev field should be null
		     * pointers rather than null strings for that pseudo-field,
		     * but we'd have to add checks for null pointers in some
		     * places if we did that.
		     *
		     * Or perhaps protocol tree items added with
		     * "proto_tree_add_text()" should have -1 as the field index,
		     * with no pseudo-field being used, but that might also
		     * require special checks for -1 to be added.
		     */
		    statusbar_push_field_msg("");
		}
	    }

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

/* Expand collapse the item and any children */
static void
ethereal_treeview_expand_item(HWND tv_ctrl, HTREEITEM last_ti, gboolean expand) {
    HTREEITEM hti;
    UINT      flag = expand ? TVE_EXPAND : TVE_COLLAPSE;

    if (last_ti == NULL) { /* Start at the root */
	hti = TreeView_GetRoot(tv_ctrl);
	if (hti == NULL) return;
	ethereal_treeview_expand_item(tv_ctrl, hti, expand);
    }

    TreeView_Expand(tv_ctrl, last_ti, flag);

    hti = TreeView_GetChild(tv_ctrl, last_ti);
    if (hti != NULL) {
	ethereal_treeview_expand_item(tv_ctrl, hti, expand);
    }

    hti = TreeView_GetNextSibling(tv_ctrl, last_ti);
    if (hti != NULL) {
	ethereal_treeview_expand_item(tv_ctrl, hti, expand);
    }
}

