

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
#include <tchar.h>
#include <richedit.h>

#include "win32-c-sdk.h"

#include "win32-globals.h"

#include "ethereal-byteview.h"
#include "ethereal-treeview.h"

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/epan_dissect.h>
#include <epan/packet.h>
#include "util.h"

static LRESULT CALLBACK ethereal_byteview_wnd_proc(HWND, UINT, WPARAM, LPARAM);
static void ethereal_byteview_show_hide(HWND tab);
static void ethereal_byteview_empty(win32_element_t *byteview);
static void ethereal_byteview_resize(HWND hw_byteview);
static LRESULT ethereal_byteview_notify(HWND, LPARAM, capture_file *);
static void add_byte_tab(HWND tab, const char *name, tvbuff_t *tvb,
	int encoding, win32_element_t *treeview);
static void packet_hex_print_common(HWND hw_bv, const guint8 *pd, int len,
	int bstart, int bend);
static void byteview_select(win32_element_t *byteview, HWND edit, LONG selpt);

typedef struct _byteview_data_t {
    HWND        tab;		/* Notebook/tab control */
    proto_tree *tree;		/* Associated protocol tree */
    gboolean    in_hex_print;	/* Are we in the middle of printing? */
} byteview_data_t;

typedef struct _byte_tab_data_t {
    tvbuff_t        *tvb;
    win32_element_t *treeview;
    int              encoding;
} byte_tab_data_t;

#define EWC_BYTE_PANE          "ByteViewPane"
#define EWC_BYTE_TEXT          "ByteViewTextArea"
#define ETHEREAL_BYTEVIEW_DATA "_ethereal_byteview_data"


/*
 * Copied from gtk/proto_draw.c.
 */
#define BYTE_VIEW_WIDTH    16
#define BYTE_VIEW_SEP       8

#define MAX_OFFSET_LEN	 8	/* max length of hex offset of bytes */
#define BYTES_PER_LINE	16	/* max byte values in a line */
#define HEX_DUMP_LEN	(BYTES_PER_LINE*3 + 1)
				/* max number of characters hex dump takes -
				   2 digits plus trailing blank
				   plus separator between first and
				   second 8 digits */
#define DATA_DUMP_LEN	(HEX_DUMP_LEN + 2 + BYTES_PER_LINE)
				/* number of characters those bytes take;
				   3 characters per byte of hex dump,
				   2 blanks separating hex from ASCII,
				   1 character per byte of ASCII dump */
#define MAX_LINE_LEN	(MAX_OFFSET_LEN + 2 + DATA_DUMP_LEN)
				/* number of characters per line;
				   offset, 2 blanks separating offset
				   from data dump, data dump */

/*
 * Creates a ByteView control
 */

win32_element_t *
ethereal_byteview_new(HWND hw_parent) {
    HINSTANCE        h_instance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    win32_element_t *byteview;
    byteview_data_t *bd;
    WNDCLASS         wc;

    wc.lpszClassName = EWC_BYTE_PANE;
    wc.lpfnWndProc = ethereal_byteview_wnd_proc;
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

    byteview = win32_element_new(NULL);

    byteview->h_wnd = CreateWindow(
	EWC_BYTE_PANE,
	EWC_BYTE_PANE,
	WS_CHILD | WS_VISIBLE,
	0, 0, 0, 0,
	hw_parent,
	NULL,
	h_instance,
	(LPSTR) NULL);
    ShowWindow(byteview->h_wnd, SW_SHOW);
    UpdateWindow(byteview->h_wnd);

    /* Attach the byteview address to our HWND. */
    SetWindowLong(byteview->h_wnd, GWL_USERDATA, (LONG) byteview);
    SendMessage(byteview->h_wnd, WM_SETFONT, (WPARAM) m_r_font, FALSE);

    bd = g_malloc(sizeof(byteview_data_t));
    win32_element_set_data(byteview, ETHEREAL_BYTEVIEW_DATA, bd);
    bd->tree = NULL;

    /*
     * XXX - According to
     * http://msdn.microsoft.com/library/default.asp?url=/library/en-us/shellcc/platform/commctls/tab/styles.asp
     * TCS_BOTTOM isn't supported in ComCtl32.dll version 6.  Yay.
     */
    bd->tab = CreateWindowEx(
	0,
	WC_TABCONTROL,
	"",
	WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_CLIPSIBLINGS /* | TCS_BOTTOM */,
	0, 0, 50, 25,
	byteview->h_wnd,
	NULL,
	h_instance,
	(LPSTR) NULL);

    SendMessage(bd->tab, WM_SETFONT,
	(WPARAM) GetStockObject(DEFAULT_GUI_FONT), TRUE);

    ShowWindow(bd->tab, SW_HIDE);
    UpdateWindow(bd->tab);

    ethereal_byteview_empty(byteview);
    add_byte_tab(bd->tab, "", NULL, CHAR_ASCII, NULL);
    ethereal_byteview_resize(byteview->h_wnd);

    return byteview;
}

/* XXX Add a "destroy" routine */

static LRESULT CALLBACK
ethereal_byteview_wnd_proc(HWND hw_byteview, UINT msg,
	WPARAM w_param, LPARAM l_param) {
    win32_element_t *byteview;
    byteview_data_t *bd;
    int              count, i;
    TCITEM           tci;
    HWND             edit;
    LPNMHDR          lpnmh;
    SELCHANGE       *selchg;

    switch (msg) {
	case WM_CREATE:
	    break;
	case WM_SIZE:
	    if (GetWindowLong(hw_byteview, GWL_USERDATA) != 0) {
		ethereal_byteview_resize (hw_byteview);
	    }
	    break;
	case WM_NOTIFY:
	    lpnmh = (LPNMHDR) l_param;
	    switch (lpnmh->code) {
		case NM_CLICK:
		    ethereal_byteview_show_hide(lpnmh->hwndFrom);
		    ethereal_byteview_resize(hw_byteview);
		    break;
		case EN_SELCHANGE:
		    selchg = (SELCHANGE *) l_param;
		    byteview = (win32_element_t *) GetWindowLong(hw_byteview, GWL_USERDATA);
		    win32_element_assert(byteview);
		    bd = win32_element_get_data(byteview, ETHEREAL_BYTEVIEW_DATA);
		    if (bd && bd->in_hex_print) break;

		    byteview_select(byteview, lpnmh->hwndFrom, selchg->chrg.cpMin);
		default:
		    break;
	    }
	    break;
	case WM_SETFONT:
	    byteview = (win32_element_t *) GetWindowLong(hw_byteview, GWL_USERDATA);
	    win32_element_assert(byteview);
	    bd = win32_element_get_data(byteview, ETHEREAL_BYTEVIEW_DATA);

	    if (bd) {
		count = TabCtrl_GetItemCount(bd->tab);
		for (i = 0; i < count; i++) {
		    ZeroMemory(&tci, sizeof(tci));
		    tci.mask = TCIF_PARAM;
		    TabCtrl_GetItem(bd->tab, i, &tci);
		    edit = (HWND) tci.lParam;
		    if (edit == NULL) continue;
		    SendMessage(edit, WM_SETFONT, w_param, l_param);
		}
	    }

	    break;
	default:
	    return (DefWindowProc(hw_byteview, msg, w_param, l_param));
    }
    return (DefWindowProc(hw_byteview, msg, w_param, l_param));
}

static void
ethereal_byteview_resize(HWND hw_byteview) {
    win32_element_t *byteview;
    byteview_data_t *bd;
    RECT             pr;
    int              item;
    TCITEM           tci;
    HWND             edit;

    byteview = (win32_element_t *) GetWindowLong(hw_byteview, GWL_USERDATA);
    win32_element_assert(byteview);
    bd = win32_element_get_data(byteview, ETHEREAL_BYTEVIEW_DATA);

    GetClientRect(hw_byteview, &pr);

    item = TabCtrl_GetItemCount(bd->tab);
    if (item < 1) return;

    /* If we have one item, the first item is the only visible window.
       Otherwise, we size the tab control, then the current window */
    if (item > 1) {
	MoveWindow(bd->tab, pr.left, pr.top, pr.right - pr.left,
	    pr.bottom - pr.top, TRUE);
	TabCtrl_AdjustRect(bd->tab, FALSE, &pr);
    }

    item = TabCtrl_GetCurSel(bd->tab);
    ZeroMemory(&tci, sizeof(tci));
    tci.mask = TCIF_PARAM;
    TabCtrl_GetItem(bd->tab, item, &tci);
    edit = (HWND) tci.lParam;
    if (edit == NULL) return;
    MoveWindow(edit, pr.left, pr.top, pr.right - pr.left,
	pr.bottom - pr.top, TRUE);
}

static void
ethereal_byteview_show_hide(HWND tab) {
    HWND   edit;
    TCITEM tci;
    int    count, i, cur_sel;

    cur_sel = TabCtrl_GetCurSel(tab);
    count = TabCtrl_GetItemCount(tab);
    if (count > 1) {
	ShowWindow(tab, SW_SHOW);
    } else {
	ShowWindow(tab, SW_HIDE);
    }

    for (i = 0; i < count; i++) {
	ZeroMemory(&tci, sizeof(tci));
	tci.mask = TCIF_PARAM;
	TabCtrl_GetItem(tab, i, &tci);
	edit = (HWND) tci.lParam;
	if (edit == NULL) continue;
	if (i == cur_sel) {
	    ShowWindow(edit, SW_SHOW);
	} else {
	    ShowWindow(edit, SW_HIDE);
	    UpdateWindow(edit);
	}
    }
}

static void
ethereal_byteview_empty(win32_element_t *byteview) {
    byteview_data_t *bd;
    byte_tab_data_t *btd;
    TCITEM           tci;
    int              count, i;
    HWND             edit;

    win32_element_assert(byteview);
    bd = win32_element_get_data(byteview, ETHEREAL_BYTEVIEW_DATA);

    count = TabCtrl_GetItemCount(bd->tab);
    for (i = 0; i < count; i++) {
	ZeroMemory(&tci, sizeof(tci));
	tci.mask = TCIF_PARAM;
	TabCtrl_GetItem(bd->tab, i, &tci);
	edit = (HWND) tci.lParam;
	if (edit == NULL) continue;
	btd = (byte_tab_data_t *) GetWindowLong(edit, GWL_USERDATA);
	g_free(btd);
	DestroyWindow(edit);
    }
    TabCtrl_DeleteAllItems(bd->tab);
    ShowWindow(bd->tab, SW_HIDE);
}

/*
 * Get the data and length for a byte view, given the byte view page.
 * Return the pointer, or NULL on error, and set "*data_len" to the length.
 */
/*
 * Copied from gtk/proto_draw.c.
 * XXX - Maybe this should be an epan/tvbuff routine?
 */
const guint8 *
get_byteview_data_and_length(win32_element_t *byteview, guint *data_len)
{
    byteview_data_t *bd;
    byte_tab_data_t *btd;
    const guint8    *data_ptr;
    int              cur_sel;
    TCITEM           tci;
    HWND             edit;

    win32_element_assert(byteview);
    bd = win32_element_get_data(byteview, ETHEREAL_BYTEVIEW_DATA);

    cur_sel = TabCtrl_GetCurSel(bd->tab);
    if (cur_sel < 0) return NULL;

    ZeroMemory(&tci, sizeof(tci));
    tci.mask = TCIF_PARAM;
    TabCtrl_GetItem(bd->tab, cur_sel, &tci);
    edit = (HWND) tci.lParam;
    if (edit == NULL) return NULL;

    btd = (byte_tab_data_t *) GetWindowLong(edit, GWL_USERDATA);

    if (btd->tvb == NULL) return NULL;

    data_ptr = tvb_get_ptr(btd->tvb, 0, -1);
    *data_len = tvb_length(btd->tvb);
    return data_ptr;
}

/*
 * Create byte views in the main window.  Defined in ui_util.h.
 * Many bits copied from gtk/proto_draw.c.
 */
/* XXX - Add selection */
// proto_draw.c:add_byte_tab() does this:
// - Add a tab to the notebook widget
// - Create a scrolled window/text widget and add it to the notebook
// - Disable editing, word wrap and line wrap in the text widget
// - Show tabs if there is more than one notebook page
// proto_draw.c:byte_view_realize_cb() does this:
// - Gets the tvb data and length
// - Calls packet_hex_print on the textarea

/* Corresponds to add_byte_views() in gtk/proto_draw.c */
void
ethereal_byteview_add(epan_dissect_t *edt, win32_element_t *byteview, win32_element_t *treeview) {
    byteview_data_t *bd;
    GSList          *src_le = edt->pi.data_src;
    data_source     *src;

    win32_element_assert(byteview);
    bd = win32_element_get_data(byteview, ETHEREAL_BYTEVIEW_DATA);
    bd->tree = edt->tree;

    ethereal_byteview_empty(byteview);

    for (src_le = edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
	src = src_le->data;
	add_byte_tab(bd->tab, src->name, src->tvb, edt->pi.fd->flags.encoding, treeview);
    }

    /*
     * Initially select the first byte view.
     */
    TabCtrl_SetCurFocus(bd->tab, 0);
    ethereal_byteview_show_hide(bd->tab);
}

void set_notebook_page(win32_element_t *byteview, tvbuff_t *tvb) {
    byteview_data_t *bd;
    byte_tab_data_t *btd;
    int              count, i;
    TCITEM           tci;
    HWND             edit;

    win32_element_assert(byteview);
    bd = win32_element_get_data(byteview, ETHEREAL_BYTEVIEW_DATA);

    count = TabCtrl_GetItemCount(bd->tab);
    for (i = 0; i < count; i++) {
	ZeroMemory(&tci, sizeof(tci));
	tci.mask = TCIF_PARAM;
	TabCtrl_GetItem(bd->tab, i, &tci);
	edit = (HWND) tci.lParam;
	if (edit == NULL) continue;
	btd = (byte_tab_data_t *) GetWindowLong(edit, GWL_USERDATA);
	if (btd->tvb == tvb) {
	    TabCtrl_SetCurSel(bd->tab, count);
	}
    }
}

void
packet_hex_print(win32_element_t *byteview, const guint8 *pd, frame_data *fd,
	field_info *finfo, guint len) {
    byteview_data_t *bd;
    int              cur_sel, bstart, bend = -1, blen;
    TCITEM           tci;
    HWND             edit;

    win32_element_assert(byteview);
    bd = win32_element_get_data(byteview, ETHEREAL_BYTEVIEW_DATA);

    cur_sel = TabCtrl_GetCurSel(bd->tab);
    if (cur_sel < 0) return;

    ZeroMemory(&tci, sizeof(tci));
    tci.mask = TCIF_PARAM;
    TabCtrl_GetItem(bd->tab, cur_sel, &tci);
    edit = (HWND) tci.lParam;
    if (edit == NULL) return;

    if (finfo != NULL) {
	bstart = finfo->start;
	blen = finfo->length;
    } else {
	bstart = -1;
	blen = -1;
    }
    if (bstart >= 0 && blen >= 0) {
	bend = bstart + blen;
    }

    bd->in_hex_print = TRUE;
    packet_hex_print_common(edit, pd, len, bstart, bend);
    bd->in_hex_print = FALSE;
}

void
ethereal_byteview_clear(win32_element_t *byteview) {
    byteview_data_t *bd;

    win32_element_assert(byteview);
    bd = win32_element_get_data(byteview, ETHEREAL_BYTEVIEW_DATA);

    ethereal_byteview_empty(byteview);

    add_byte_tab(bd->tab, "", NULL, CHAR_ASCII, NULL);
}



/*
 * Private routines
 */

static void
add_byte_tab(HWND tab, const char *name, tvbuff_t *tvb,
	int encoding, win32_element_t *treeview) {
    byte_tab_data_t *btd;
    int              count;
    const guint8    *pd = NULL;
    int              len = 0;
    TCITEM           tci;
    HWND             edit, hw_parent = GetParent(tab);

    if (tvb) {
	len = tvb_length(tvb);
	pd = tvb_get_ptr(tvb, 0, -1);
    }
    count = TabCtrl_GetItemCount(tab);

    btd = g_malloc(sizeof(byte_tab_data_t));
    btd->tvb = tvb;
    btd->treeview  = treeview;
    btd->encoding  = encoding;

    edit = CreateWindowEx(
	WS_EX_CLIENTEDGE,
	RICHEDIT_CLASS,
	"",
	WS_CHILD | WS_TABSTOP | WS_VISIBLE | WS_HSCROLL | WS_VSCROLL |
	    ES_AUTOHSCROLL | ES_AUTOVSCROLL | ES_MULTILINE |
	    ES_NOHIDESEL | ES_READONLY /* | ES_SUNKEN */,
	0, 0, 0, 0,
	hw_parent,
	NULL,
	(HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE),
	NULL);
    SendMessage(edit, WM_SETFONT, (WPARAM) m_r_font, FALSE);
    SetWindowLong(edit, GWL_USERDATA, (LONG) btd);

    ZeroMemory(&tci, sizeof(tci));
    tci.mask = TCIF_TEXT | TCIF_PARAM;
    tci.pszText = name;
    tci.cchTextMax = lstrlen(name);
    tci.lParam = (LPARAM) edit;

    TabCtrl_InsertItem(tab, count, &tci);
    ethereal_byteview_show_hide(tab);

    if (pd) {
	packet_hex_print_common(edit, pd, len, 0, 0);
    }
    ethereal_byteview_resize(GetParent(tab));
}


static void
packet_hex_print_common(HWND edit, const guint8 *pd, int len, int bstart,
	int bend) {
    byte_tab_data_t *btd;
    int              i = 0, j, k, cur;
    unsigned int     use_digits;
    TCHAR            line[MAX_LINE_LEN + 2];
    gboolean         reverse, newreverse;
    static           guchar hexchars[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    guchar           c = '\0';
    CHARFORMAT2      normal_fmt, hilite_fmt;
    COLORREF         fg, bg;

    btd = (byte_tab_data_t *) GetWindowLong(edit, GWL_USERDATA);

    /*
     * How many of the leading digits of the offset will we supply?
     * We always supply at least 4 digits, but if the maximum offset
     * won't fit in 4 digits, we use as many digits as will be needed.
     */
    if (((len - 1) & 0xF0000000) != 0)
	use_digits = 8;	/* need all 8 digits */
    else if (((len - 1) & 0x0F000000) != 0)
	use_digits = 7;	/* need 7 digits */
    else if (((len - 1) & 0x00F00000) != 0)
	use_digits = 6;	/* need 6 digits */
    else if (((len - 1) & 0x000F0000) != 0)
	use_digits = 5;	/* need 5 digits */
    else
	use_digits = 4;	/* we'll supply 4 digits */

    SendMessage(edit, WM_SETTEXT, (WPARAM) 0, (LPARAM) "");
    fg = GetSysColor(COLOR_WINDOWTEXT);
    bg = GetSysColor(COLOR_WINDOW);

    ZeroMemory(&normal_fmt, sizeof(normal_fmt));
    normal_fmt.cbSize = sizeof(normal_fmt);
    normal_fmt.dwMask = CFM_COLOR| CFM_BACKCOLOR;
    normal_fmt.crTextColor = fg;
    normal_fmt.crBackColor = bg;

    /* XXX - Add "bold". */
    ZeroMemory(&hilite_fmt, sizeof(hilite_fmt));
    hilite_fmt.cbSize = sizeof(hilite_fmt);
    hilite_fmt.dwMask = CFM_COLOR| CFM_BACKCOLOR;
    hilite_fmt.crTextColor = bg;
    hilite_fmt.crBackColor = fg;

    SendMessage(edit, EM_SETEVENTMASK, (WPARAM) 0, (LPARAM) (DWORD) ENM_NONE);

    while (i < len) {
	/* Print the line number */
	j = use_digits;
	cur = 0;
	do {
	    j--;
	    c = (i >> (j*4)) & 0xF;
	    line[cur++] = hexchars[c];
	} while (j != 0);
	line[cur++] = ' ';
	line[cur++] = ' ';
	line[cur] = '\0';

	SendMessage(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &normal_fmt);
	SendMessage(edit, EM_REPLACESEL, FALSE, (LPARAM)(LPCTSTR) line);

	reverse = i >= bstart && i < bend;
	j       = i;
	k       = i + BYTE_VIEW_WIDTH;
	cur     = 0;
	/* Do we start in reverse? */
	if (reverse)
	    SendMessage(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &hilite_fmt);
	/* Print the hex bit */
	while (i < k) {
	    if (i < len) {
		line[cur++] = hexchars[(pd[i] & 0xf0) >> 4];
		line[cur++] = hexchars[pd[i] & 0x0f];
	    } else {
		line[cur++] = ' '; line[cur++] = ' ';
	    }
	    i++;
	    newreverse = i >= bstart && i < bend;
	    /* Have we gone from reverse to plain? */
	    if (reverse && (reverse != newreverse)) {
		line[cur] = '\0';
		SendMessage(edit, EM_REPLACESEL, FALSE, (LPARAM)(LPCTSTR) line);
		SendMessage(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &normal_fmt);
		cur = 0;
	    }

	    /* Inter byte space if not at end of line */
	    if (i < k) {
		line[cur++] = ' ';
		/* insert a space every BYTE_VIEW_SEP bytes */
		if( ( i % BYTE_VIEW_SEP ) == 0 ) {
		    line[cur++] = ' ';
		}
	    }
	    /* Have we gone from plain to reversed? */
	    if (!reverse && (reverse != newreverse)) {
		line[cur] = '\0';
		SendMessage(edit, EM_REPLACESEL, FALSE, (LPARAM)(LPCTSTR) line);
		SendMessage(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &hilite_fmt);
		cur = 0;
	    }
	    reverse = newreverse;
	}
	line[cur] = '\0';
	SendMessage(edit, EM_REPLACESEL, FALSE, (LPARAM)(LPCTSTR) line);
	SendMessage(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &normal_fmt);
	cur = 0;
	line[cur++] = ' '; line[cur++] = ' '; line[cur++] = ' ';
	line[cur] = '\0';
	SendMessage(edit, EM_REPLACESEL, FALSE, (LPARAM)(LPCTSTR) line);
	cur = 0;

	/* Print the ASCII bit */
	i = j;
	/* Do we start in reverse? */
	reverse = i >= bstart && i < bend;
	if (reverse)
	    SendMessage(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &hilite_fmt);
	while (i < k) {
		if (i < len) {
		    if (btd->encoding == CHAR_ASCII) {
		    c = pd[i];
		} else if (btd->encoding == CHAR_EBCDIC) {
		    c = EBCDIC_to_ASCII1(pd[i]);
		} else {
		    g_assert_not_reached();
		}
		line[cur++] = isprint(c) ? c : '.';
	    } else {
		line[cur++] = ' ';
	    }
	    i++;

	    newreverse = i >= bstart && i < bend;
	    /* Have we gone from reverse to plain? */
	    if (reverse && (reverse != newreverse)) {
		line[cur] = '\0';
		SendMessage(edit, EM_REPLACESEL, FALSE, (LPARAM)(LPCTSTR) line);
		SendMessage(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &normal_fmt);
		cur = 0;
	    }
	    if (i < k) {
		/* insert a space every BYTE_VIEW_SEP bytes */
		if( ( i % BYTE_VIEW_SEP ) == 0 ) {
		    line[cur++] = ' ';
		}
	    }
	    /* Have we gone from plain to reversed? */
	    if (!reverse && (reverse != newreverse)) {
		line[cur] = '\0';
		SendMessage(edit, EM_REPLACESEL, FALSE, (LPARAM)(LPCTSTR) line);
		SendMessage(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &hilite_fmt);
		cur = 0;
	    }
	    reverse = newreverse;
	}
	line[cur++] = '\r';
	line[cur++] = '\n';
	line[cur]   = '\0';
	SendMessage(edit, EM_REPLACESEL, FALSE, (LPARAM)(LPCTSTR) line);
    }

    /* Lop off the last CR/LF */
    i = GetWindowTextLength (edit);
    SendMessage(edit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM) &normal_fmt);
    SendMessage(edit, EM_SETEVENTMASK, (WPARAM) 0, (LPARAM) (DWORD) ENM_SELCHANGE);
    SendMessage(edit, EM_SETSEL, (WPARAM) i - 5, (LPARAM) i);
    SendMessage(edit, EM_REPLACESEL, FALSE, (LPARAM)(LPCTSTR) "");
    SendMessage(edit, EM_SETSEL, (WPARAM) 0, (LPARAM) 0);

}

/* Which byte the offset is referring to. Associates
 * whitespace with the preceding digits. */
static int
byte_num(int offset, int start_point)
{
    return (offset - start_point) / 3;
}

static void
byteview_select(win32_element_t *byteview, HWND edit, LONG selpt) {
    byte_tab_data_t *btd;
    byteview_data_t *bd;
    int              line_len = (int) SendMessage(edit, EM_LINELENGTH, 0, 0) + 1;
    int              row = (int) SendMessage(edit, EM_EXLINEFROMCHAR, 0, (LPARAM) (DWORD) selpt);
    int              column = selpt % line_len;
    int              ndigits, byte = 0;
    int              digits_start_1, digits_end_1, digits_start_2, digits_end_2;
    int              text_start_1, text_end_1, text_start_2, text_end_2;
    field_info      *finfo;
    HTREEITEM        hti;

    win32_element_assert(byteview);
    bd = win32_element_get_data(byteview, ETHEREAL_BYTEVIEW_DATA);

    if (bd->tree == NULL) return;
    if (bd->in_hex_print) return;

    btd = (byte_tab_data_t *) GetWindowLong(edit, GWL_USERDATA);

    /*
     * Get the number of digits of offset being displayed, and
     * compute the columns of various parts of the display.
     */
    ndigits = MAX_LINE_LEN - line_len + 2;

    /*
     * The column of the first hex digit in the first half.
     * That starts after "ndigits" digits of offset and two
     * separating blanks.
     */
    digits_start_1 = ndigits + 2;

    /*
     * The column of the last hex digit in the first half.
     * There are BYTES_PER_LINE/2 bytes displayed in the first
     * half; there are 2 characters per byte, plus a separating
     * blank after all but the last byte's characters.
     *
     * Then subtract 1 to get the last column of the first half
     * rather than the first column after the first half.
     */
    digits_end_1 = digits_start_1 + (BYTES_PER_LINE/2)*2 +
	(BYTES_PER_LINE/2 - 1) - 1;

    /*
     * The column of the first hex digit in the second half.
     * Add back the 1 to get the first column after the first
     * half, and then add 2 for the 2 separating blanks between
     * the halves.
     */
    digits_start_2 = digits_end_1 + 3;

    /*
     * The column of the last hex digit in the second half.
     * Add the same value we used to get "digits_end_1" from
     * "digits_start_1".
     */
    digits_end_2 = digits_start_2 + (BYTES_PER_LINE/2)*2 +
        (BYTES_PER_LINE/2 - 1) - 1;

    /*
     * The column of the first "text dump" character in the first half.
     * Add back the 1 to get the first column after the second
     * half's hex dump, and then add 3 for the 3 separating blanks
     * between the hex and text dummp.
     */
    text_start_1 = digits_end_2 + 4;

    /*
     * The column of the last "text dump" character in the first half.
     * There are BYTES_PER_LINE/2 bytes displayed in the first
     * half; there is 1 character per byte.
     *
     * Then subtract 1 to get the last column of the first half
     * rather than the first column after the first half.
     */
    text_end_1 = text_start_1 + BYTES_PER_LINE/2 - 1;

    /*
     * The column of the first "text dump" character in the second half.
     * Add back the 1 to get the first column after the first half,
     * and then add 1 for the separating blank between the halves.
     */
    text_start_2 = text_end_1 + 2;

    /*
     * The column of the last "text dump" character in second half.
     * Add the same value we used to get "text_end_1" from
     * "text_start_1".
     */
    text_end_2 = text_start_2 + BYTES_PER_LINE/2 - 1;

    /* Given the column and row, determine which byte offset
     * the user clicked on. */
    if (column >= digits_start_1 && column <= digits_end_1) {
	byte = byte_num(column, digits_start_1);
	if (byte == -1) {
	    return;
	}
    }
    else if (column >= digits_start_2 && column <= digits_end_2) {
	byte = byte_num(column, digits_start_2);
	if (byte == -1) {
	    return;
	}
	byte += 8;
    }
    else if (column >= text_start_1 && column <= text_end_1) {
	byte = column - text_start_1;
    }
    else if (column >= text_start_2 && column <= text_end_2) {
	byte = 8 + column - text_start_2;
    }
    else {
	/* The user didn't select a hex digit or
	 * text-dump character. */
	return;
    }

    /* Add the number of bytes from the previous rows. */
    byte += row * 16;

    finfo = proto_find_field_from_offset(bd->tree, byte, btd->tvb);

    if (finfo == NULL) return;

    hti = ethereal_treeview_find_finfo(btd->treeview, finfo);

    ethereal_treeview_select(btd->treeview, hti);
}
