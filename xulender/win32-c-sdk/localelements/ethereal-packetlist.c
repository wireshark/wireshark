/*
 * Packet list control (widget) MUST:
 * - Have unlimited length
 * - Tie into packet list glist?
 * - Set fg & bg colors
 * - Allow column resizing
 *
 * It SHOULD
 * - Allow column names and data types to be changed on the fly
 * - Allow multiple selects?
 * - Allow columns to be moved around
 */

/*
 * Some of the stuff used here, e.g. LVS_EX_FULLROWSELECT requires commctrl.dll
 * version 4.70, which ships with IE 3.x according to
 * http://msdn.microsoft.com/library/default.asp?url=/library/en-us/shellcc/platform/shell/programmersguide/versions.asp
 * Therefore, we require IE 3.x or greater.  This is probably a safe
 * requirement.  :)
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

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/epan_dissect.h>
#include <epan/column.h>
#include <epan/column-utils.h>
#include <epan/prefs.h>
#include "color.h"
#include "color_filters.h"

#include "win32-c-sdk.h"
#include "win32-globals.h"
#include "win32-util.h"

#include "ethereal-packetlist.h"
#include "ui_util.h"
#include "win32-file-dlg.h"
#include "win32-statusbar.h"

typedef struct _packet_list_item {
    gchar   **text;
    gpointer  data;
    color_t  *fg;
    color_t  *bg;
} packet_list_item;

/* Globals */
GList *packet_list, *first, *last = NULL;
gint rows;
HWND g_hw_packetlist = NULL, g_hw_packetlist_pane;

static LRESULT CALLBACK ethereal_packetlist_wnd_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT ethereal_packetlist_notify(HWND, LPARAM, capture_file *);

#define EWC_LIST_PANE "PacketListPane"


/*
 * Creates a ListView control using the LVS_OWNERDATA flag
 */

win32_element_t *
ethereal_packetlist_new(HWND hw_parent) {
    HINSTANCE        h_instance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    win32_element_t *packetlist;
    WNDCLASS         wc;

    /* XXX - Is this really needed?  We're just using the enclosing pane
     * to draw an inset. */
    ZeroMemory(&wc, sizeof(wc));
    wc.lpszClassName = EWC_LIST_PANE;
    wc.lpfnWndProc = ethereal_packetlist_wnd_proc;
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

    packetlist = win32_element_new(NULL);

    packetlist->h_wnd = CreateWindow(
	EWC_LIST_PANE,
	EWC_LIST_PANE,
	WS_CHILD | WS_VISIBLE,
	0, 0, 0, 0,
	hw_parent,
	NULL,
	h_instance,
	(LPSTR) NULL);

    ShowWindow(packetlist->h_wnd, SW_SHOW);
    UpdateWindow(packetlist->h_wnd);

    ethereal_packetlist_resize(packetlist->h_wnd, hw_parent);

    /* Attach the packetlist address to our HWND. */
    SetWindowLong(packetlist->h_wnd, GWL_USERDATA, (LONG) packetlist);

    g_hw_packetlist_pane = packetlist->h_wnd;
    return packetlist;
}

/* XXX Add a "destroy" routine */

static LRESULT CALLBACK
ethereal_packetlist_wnd_proc(HWND hw_packetlist_pane, UINT msg,
	WPARAM w_param, LPARAM l_param) {
    LV_COLUMN col;
    int       i;
    LRESULT   ret;
    SIZE      sz;

    switch (msg) {
	case WM_CREATE:
	    /* Build the column format array */
	    /* XXX - this is duplicated in gtk/main.c _and_ tethereal.c */
	    col_setup(&cfile.cinfo, prefs.num_cols);
	    for (i = 0; i < cfile.cinfo.num_cols; i++) {
		cfile.cinfo.col_fmt[i] = get_column_format(i);
		cfile.cinfo.col_title[i] = g_strdup(get_column_title(i));
		cfile.cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) *
		    NUM_COL_FMTS);
		get_column_format_matches(cfile.cinfo.fmt_matx[i], cfile.cinfo.col_fmt[i]);
		cfile.cinfo.col_data[i] = NULL;
		if (cfile.cinfo.col_fmt[i] == COL_INFO)
		    cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
		else
		    cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
		cfile.cinfo.col_fence[i] = 0;
		cfile.cinfo.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
		cfile.cinfo.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
	    }
	    for (i = 0; i < cfile.cinfo.num_cols; i++) {
		int j;

		for (j = 0; j < NUM_COL_FMTS; j++) {
		    if (!cfile.cinfo.fmt_matx[i][j])
			continue;

		    if (cfile.cinfo.col_first[j] == -1)
			cfile.cinfo.col_first[j] = i;
		    cfile.cinfo.col_last[j] = i;
		}
	    }

	    g_hw_packetlist = CreateWindowEx(
		WS_EX_CLIENTEDGE,
		WC_LISTVIEW,
		"",
		WS_CHILD | WS_TABSTOP | WS_VISIBLE | LVS_OWNERDATA | LVS_REPORT |
		    LVS_SHOWSELALWAYS | LVS_SINGLESEL,
		0, 0, 0, 0,
		hw_packetlist_pane,
		(HMENU) ID_PACKET_LIST,
		(HINSTANCE) GetWindowLong(hw_packetlist_pane, GWL_HINSTANCE),
		NULL);

	    /* XXX set extra styles, e.g. LVS_EX_HEADERDRAGDROP? */
	    ListView_SetExtendedListViewStyle(g_hw_packetlist, LVS_EX_FULLROWSELECT);

	    /* XXX - Set width and justification */
	    col.mask = LVCF_FMT | LVCF_SUBITEM | LVCF_TEXT | LVCF_WIDTH;
	    col.fmt = LVCFMT_LEFT;
	    for (i = 0; i < cfile.cinfo.num_cols; i++) {
		win32_get_text_size(g_hw_packetlist,
			get_column_longest_string(get_column_format(i)), &sz);
		col.cx = sz.cx + 20; // Arbitrary padding value
		col.pszText = cfile.cinfo.col_title[i];
		ListView_InsertColumn(g_hw_packetlist, i, &col);
	    }

	    packet_list = first = last = NULL;
	    rows = -1;
	    break;
	case WM_SIZE:
	    ethereal_packetlist_resize (g_hw_packetlist, g_hw_packetlist_pane);
	    break;
	case WM_NOTIFY:
	    ret = ethereal_packetlist_notify(g_hw_packetlist, l_param, &cfile);
	    if (ret)
		return ret;
	    break;
	default:
	    break;
    }
    return(DefWindowProc(hw_packetlist_pane, msg, w_param, l_param));
}

void
ethereal_packetlist_resize(HWND hw_packetlist, HWND hw_parent) {
    RECT pr;

    GetClientRect(hw_parent, &pr);
    MoveWindow(g_hw_packetlist, pr.left, pr.top, pr.right - pr.left,
	pr.bottom - pr.top, TRUE);
}

void
ethereal_packetlist_clear(HWND hw_packetlist) {
    packet_list_item *pli;
    int i;

    ListView_DeleteAllItems(g_hw_packetlist);
    packet_list = first;
    while (packet_list) {
	pli = (packet_list_item *) packet_list->data;
	for (i = 0; i < prefs.num_cols; i++) {
	    g_free(pli->text[i]);
	    pli->text[i] = NULL;
	}
	g_free(pli->text);
	pli->text = NULL;
	if (pli->fg)
	    g_free(pli->fg);
	if (pli->bg)
	    g_free(pli->bg);
	pli->fg = NULL;
	pli->bg = NULL;
	g_free(pli);
	pli = NULL;
	packet_list = g_list_next(packet_list);
    }
    packet_list = first;
    g_list_free(packet_list);
    packet_list = first = last = NULL;
    rows = -1;
}

void
ethereal_packetlist_init(capture_file *cfile) {
    ListView_SetItemCount(g_hw_packetlist, rows + 1);
}

static LRESULT
ethereal_packetlist_notify(HWND hw_packetlist, LPARAM l_param, capture_file *cfile) {
    LPNMHDR lpnmh = (LPNMHDR) l_param;
    NMLVCUSTOMDRAW *lvcdparam;
    LV_DISPINFO *lpdi;
    packet_list_item *pli;
    int col_num = 0, sel_item;

    switch(lpnmh->code) {
	case LVN_GETDISPINFO:
	    lpdi = (LV_DISPINFO *)l_param;

	    if ((lpdi->item.mask & LVIF_TEXT) == 0)
		break;

	    if (lpdi->item.iSubItem) {	/* Our column number isn't zero. */
		col_num = lpdi->item.iSubItem;
	    }
	    g_assert (packet_list != NULL && cfile->count != 0);
	    pli = g_list_nth_data(first, lpdi->item.iItem);
	    lstrcpyn(lpdi->item.pszText, pli->text[col_num], lpdi->item.cchTextMax);
	    break;
	case LVN_ITEMCHANGED:
	    sel_item = ListView_GetNextItem(hw_packetlist, -1, LVNI_SELECTED);
	    if (sel_item >= 0) {
		select_packet(cfile, sel_item);
	    }
	    break;
	case LVN_DELETEALLITEMS:
	    /*
	     * XXX - Should we move packet list deletion here?  Calling
	     * ListView_DeleteAllItems() (in ethereal_packetlist_clear())
	     * triggers this message.
	     */
	    break;
	case NM_CUSTOMDRAW: /* Apply colors to each item */
	    lvcdparam = (NMLVCUSTOMDRAW *) l_param;
	    switch (lvcdparam->nmcd.dwDrawStage) {
		case CDDS_PREPAINT:
		    return CDRF_NOTIFYITEMDRAW;
		    break;
		case CDDS_ITEMPREPAINT:
		    pli = g_list_nth_data(first, lvcdparam->nmcd.dwItemSpec);
		    if (pli != NULL && pli->fg != NULL && pli->bg != NULL) {
			lvcdparam->clrText = COLOR_T2COLORREF(pli->fg);
			lvcdparam->clrTextBk = COLOR_T2COLORREF(pli->bg);
			return CDRF_NEWFONT;
		    }
		    return CDRF_DODEFAULT;
		    break;
	    }
	    break;
    }
    return 0;
}

/* mark packets */
static void
set_frame_mark(gboolean set, frame_data *frame, gint row) {

    if (row == -1)
	return;

    if (set) {
	mark_frame(&cfile, frame);
	packet_list_set_colors(row, &prefs.gui_marked_fg, &prefs.gui_marked_bg);
    } else {
	color_filter_t *cfilter = frame->color_filter;

	unmark_frame(&cfile, frame);
	/* Restore the color from the matching color filter if any */
	if (cfilter) { /* The packet matches a color filter */
	    packet_list_set_colors(row, &cfilter->fg_color, &cfilter->bg_color);
	} else { /* No color filter match */
	    packet_list_set_colors(row, NULL, NULL);
	}
    }

    RedrawWindow(g_hw_packetlist, NULL, NULL, RDW_INVALIDATE);
}

/* call this after last set_frame_mark is done */
static void
mark_frames_ready(void) {
    file_set_save_marked_sensitive();
    packets_bar_update();
}

void
mark_current_frame() {

    if (cfile.current_frame) {
	/* XXX hum, should better have a "cfile->current_row" here ... */
	set_frame_mark(!cfile.current_frame->flags.marked, cfile.current_frame,
		packet_list_find_row_from_data(cfile.current_frame));
	mark_frames_ready();
    }
}

void
mark_all_frames(gboolean set) {
    frame_data *fdata;

    /* XXX: we might need a progressbar here */
    cfile.marked_count = 0;
    for (fdata = cfile.plist; fdata != NULL; fdata = fdata->next) {
	set_frame_mark(set, fdata, packet_list_find_row_from_data(fdata));
    }
    mark_frames_ready();
}

void
update_marked_frames(void) {
    frame_data *fdata;

    if (cfile.plist == NULL) return;

    /* XXX: we might need a progressbar here */
    /* XXX: This (along with mark_all_frames()) could be optimized quite
     *      a bit if we had a better packet list iterator. */
    for (fdata = cfile.plist; fdata != NULL; fdata = fdata->next) {
	if (fdata->flags.marked)
	    set_frame_mark(TRUE, fdata, g_list_index(first, fdata));
    }
    mark_frames_ready();
}

/* These are defined in ui_util.h */

void
packet_list_clear(void) {
    ethereal_packetlist_clear(g_hw_packetlist);
}

void
packet_list_freeze(void) {
//    ListView_SetItemCount(g_hw_packetlist, 0);
}

void
packet_list_thaw(void) {
    ListView_SetItemCount(g_hw_packetlist, rows + 1);
    packets_bar_update();
}

void packet_list_select_row(gint row) {
    ListView_SetItemState(g_hw_packetlist, row, LVIS_SELECTED, LVIS_SELECTED);
    ListView_EnsureVisible(g_hw_packetlist, row, FALSE);
}

void packet_list_moveto_end(void) {
}

gint
packet_list_append(gchar *text[], gpointer data) {
    packet_list_item *pli;
    int i;

    pli = g_malloc(sizeof(packet_list_item));
    pli->text = g_malloc(sizeof(gchar *) * prefs.num_cols);
    for (i = 0; i < prefs.num_cols; i++) {
	pli->text[i] = g_strdup(text[i]);
    }
    pli->data = data;
    pli->fg = NULL;
    pli->bg = NULL;

    packet_list = g_list_append(last, pli);
    last = g_list_last(packet_list);
    if (first == NULL)
	first = g_list_first(packet_list);
    rows++;

    /* XXX - ...and so is this. */
    return rows;
}

void
packet_list_set_colors(gint row, color_t *fg, color_t *bg) {
    packet_list_item *pli;

    pli = g_list_nth_data(first, row);
    if (pli == NULL)
	return;

    if (pli->fg)
	g_free(pli->fg);
    if (pli->bg)
	g_free(pli->bg);
    pli->fg = g_memdup(fg, sizeof(*pli->fg));
    pli->bg = g_memdup(bg, sizeof(*pli->bg));
}

gint
packet_list_find_row_from_data_compare_func(gconstpointer list_data, gconstpointer compare_data) {
    if (((packet_list_item *) list_data)->data == compare_data)
	return 0;
    return 1;
}

gint packet_list_find_row_from_data(gpointer data) {
    GList *entry;
    entry = g_list_find_custom(first, data, packet_list_find_row_from_data_compare_func);
    if (entry)
	return g_list_position(first, entry);
    return 0;
}

void
packet_list_set_text(gint row, gint column, const gchar *text) {
    packet_list_item *pli;

    pli = g_list_nth_data(first, row);
    if (pli->text[column])
	g_free(pli->text[column]);
    pli->text[column] = g_strdup(text);
}

void
packet_list_set_cls_time_width(gint column) {
}

gpointer
packet_list_get_row_data(gint row) {
    gpointer pdata;
    pdata = g_list_nth_data(first, row);
    return ((packet_list_item *) pdata)->data;
}

void
packet_list_set_selected_row(gint row) {
    packet_list_select_row(row);
}


