
/*
 * Splitter code taken from an example by J Brown at
 * http://www.catch22.org.uk/.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <windows.h>

#include <glib.h>

#include "win32-c-sdk.h"

#include "win32-globals.h"

/*
 * Box and splitter WndProcs
 */
static LRESULT CALLBACK win32_box_wnd_proc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK win32_splitter_wnd_proc(HWND, UINT, WPARAM, LPARAM);

/*
 * Given a box, return its contents' cumulative "flex" value.
 */
static gfloat win32_box_flex_total(win32_element_t *box);

/*
 * Given a box, return its contents' cumulative static width/height.
 */
static gint win32_box_static_dim(win32_element_t *box);

/*
 * Given a box, return its contents' cumulative flexible width/height.
 */
gint win32_box_flexible_dim(win32_element_t *box);


static LRESULT win32_splitter_lbutton_down(HWND, UINT, WPARAM, LPARAM);
static LRESULT win32_splitter_lbutton_up(HWND, UINT, WPARAM, LPARAM);
static LRESULT win32_splitter_mouse_move(HWND, UINT, WPARAM, LPARAM);

#define EWC_BOX_PANE "BoxPane"
#define EWC_SPLITTER_H "SplitterHorizontal"
#define EWC_SPLITTER_V "SplitterVertical"
#define BOX_SPLITTER_GAP 4	/* Splitter size in pixels */

/* Globals */
/* XXX - These could probably be moved to win32_element_t */
static int  y_old = -4, y_orig, x_old = -4, x_orig;
static BOOL splitter_drag_mode = FALSE;
static win32_element_t *cur_splitter = NULL;


/* Box packing routines.  We follow the XUL box packing model.
 *
 *     http://www.mozilla.org/projects/xul/xul.html
 *     http://www.xulplanet.com/references/elemref/ref_XULElement.html
 */

/*
 * Box packing rules:
 *
 * - By default, horizontal boxes grow left-to-right.  Vertical boxes
 *   grow top-to-bottom.
 * - By default, sizing is intrinsic (elements are shrunk to their minimum
 *   natural size).
 * - By default, horizontal boxes stretch their children to the same height.
 *   Likewise for vertical boxes.
 * - The default flex value is 0.0.
 * -
 *
 */

/*
 * To do:
 * - Find a way to tell a control that it's next to a splitter (and that it
 *   needs an inset 3d border).  This may not be such a big deal for Ethereal.
 *   The only things we're splitting (so far) are custom controls; we can
 *   force their insettedness.
 */


win32_element_t *
win32_box_new(HWND hw_box, HWND hw_parent, win32_box_orient_t orientation) {
    win32_element_t *box;
    HINSTANCE        h_instance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    WNDCLASS         wc;

    box = win32_element_new(hw_box);

    if (box->h_wnd == NULL) {	/* We have to create our own window */
	g_assert(hw_parent != NULL);

	/* XXX - Should we move this into its own init routine? */
	if (! GetClassInfo(h_instance, EWC_BOX_PANE, &wc)) {
	    wc.lpszClassName = EWC_BOX_PANE;
	    wc.lpfnWndProc = win32_box_wnd_proc;
	    wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
	    wc.cbClsExtra = 0;
	    wc.cbWndExtra = 0;
	    wc.hInstance = h_instance;
	    wc.hIcon = NULL;
	    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	    wc.hbrBackground = (HBRUSH) (COLOR_3DFACE+1);
	    wc.lpszMenuName = NULL;

	    RegisterClass(&wc);
	}

	box->h_wnd = CreateWindow(
	    EWC_BOX_PANE,
	    EWC_BOX_PANE,
	    WS_CHILD | WS_VISIBLE,
	    0, 0, 0, 0,
	    hw_parent,
	    NULL,
	    h_instance,
	    (LPSTR) NULL);

	ShowWindow(box->h_wnd, SW_SHOW);
	UpdateWindow(box->h_wnd);
    }

    box->orient = orientation;

    /* Attach the box address to our HWND. */
    SetWindowLong(box->h_wnd, GWL_USERDATA, (LONG) box);

    return box;
}


win32_element_t *
win32_hbox_new(HWND hw_box, HWND hw_parent) {
    return win32_box_new(hw_box, hw_parent, BOX_ORIENT_HORIZONTAL);
}

win32_element_t *
win32_vbox_new(HWND hw_box, HWND hw_parent) {
    return win32_box_new(hw_box, hw_parent, BOX_ORIENT_VERTICAL);
}

void
win32_box_add(win32_element_t *box, win32_element_t *box_el, int pos) {
    win32_element_assert(box);
    win32_element_assert(box_el);

    if (box->type == BOX_GRID)
	win32_grid_add(box, box_el);
    else
	box->contents = g_list_insert(box->contents, box_el, pos);

    if (box->type == BOX_DECK) {
	if (g_list_index(box->contents, box_el) != (gint) win32_deck_get_selectedindex(box))
	    ShowWindow(box_el->h_wnd, SW_HIDE);
    }

    if (box->type == BOX_GROUPBOX) {
	win32_groupbox_reparent(box, box_el);
    }
}

win32_element_t *
win32_box_add_hwnd(win32_element_t *box, HWND h_wnd, int pos) {
    win32_element_t *box_el;
    RECT wr;

    box_el = win32_element_new(h_wnd);
    SetWindowLong(h_wnd, GWL_USERDATA, (LONG) box_el);
    GetWindowRect(h_wnd, &wr);

    box_el->id = NULL;
    box_el->type = BOX_WINDOW;
    box_el->h_wnd = h_wnd;
    box_el->dir = BOX_DIR_RTL;
    box_el->crop = BOX_CROP_NONE;
    box_el->flex = 0.0;
    box_el->flexgroup = 1;

    box_el->minwidth = wr.right - wr.left;
    box_el->minheight = wr.bottom - wr.top;
    box_el->maxwidth = -1;
    box_el->maxheight = -1;

    box_el->oncommand = NULL;

    win32_box_add(box, box_el, pos);

    return box_el;
}

win32_element_t *
win32_box_add_splitter(win32_element_t *box, int pos, win32_box_orient_t orientation) {
    win32_element_t *splitter;
    HINSTANCE        h_instance;
    WNDCLASS         wc;
    LPCSTR           name;
    gboolean         horizontal = FALSE;

    win32_element_assert(box);
    g_assert(pos != 0);
    g_assert(box->type == BOX_BOX);

    if (box->orient == BOX_ORIENT_HORIZONTAL) {
	horizontal = TRUE;
    }

    splitter = win32_element_new(NULL);
    splitter->type = BOX_SPLITTER;
    splitter->orient = box->orient;

    h_instance = (HINSTANCE) GetWindowLong(box->h_wnd, GWL_HINSTANCE);

    if (horizontal) {
	name = EWC_SPLITTER_H;
	wc.hCursor = LoadCursor(NULL, IDC_SIZEWE);
    } else {
	name = EWC_SPLITTER_V;
	wc.hCursor = LoadCursor(NULL, IDC_SIZENS);
    }
    if (! GetClassInfo(h_instance, name, &wc)) {
	wc.lpszClassName = name;
	wc.style = CS_HREDRAW | CS_VREDRAW | CS_PARENTDC;
	wc.lpfnWndProc = win32_splitter_wnd_proc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = h_instance;
	wc.hIcon = NULL;
	wc.hbrBackground = (HBRUSH) (COLOR_3DFACE+1);
	wc.lpszMenuName = NULL;

	RegisterClass(&wc);
    }

    splitter->h_wnd = CreateWindowEx(
	WS_EX_WINDOWEDGE,
	name,
	name,
	WS_CHILD | WS_VISIBLE,
	0, 0, 0, 0,
	box->h_wnd,
	NULL,
	h_instance,
	(LPSTR) NULL);

    ShowWindow(splitter->h_wnd, SW_SHOW);
    UpdateWindow(splitter->h_wnd);

    /* Attach the box address to our HWND. */
    SetWindowLong(splitter->h_wnd, GWL_USERDATA, (LONG) splitter);

    win32_box_add(box, splitter, pos);

    /* Sizes must be specified _after_ win32_box_add(). */
    /* XXX - Do splitters care about direction and cropping? */
    splitter->dir = BOX_DIR_LTR;
    splitter->crop = BOX_CROP_NONE;
    splitter->flex = 0.0;
    splitter->flexgroup = 0;

    if (horizontal) {
	splitter->minwidth  = BOX_SPLITTER_GAP - 1;
	splitter->maxwidth  = BOX_SPLITTER_GAP - 1;
	splitter->minheight = 0;
    } else {
	splitter->minheight = BOX_SPLITTER_GAP - 1;
	splitter->maxheight = BOX_SPLITTER_GAP - 1;
	splitter->minwidth  = 0;
    }

    return splitter;
}

/*
 * Resize an element.  If set_width or set_height are -1, the width or
 * height is shrunk to its intrinsic value.
 */
void
win32_element_resize (win32_element_t *el, int set_width, int set_height) {
    int x, y, width, height;
    int flex_dim, static_dim;
    win32_element_t *cur_el, *last_flexible_el = NULL;
    GList *contents;
    gfloat total_flex;
    gboolean force_max = FALSE, horizontal;
    RECT wr, cr;

    win32_element_assert(el);

    if (set_width < 0 && set_height < 0)
	force_max = TRUE;

    if (set_width < 0) {
	set_width = win32_element_intrinsic_width(el);
    }
    if (set_height < 0)
	set_height = win32_element_intrinsic_height(el);

    GetWindowRect(el->h_wnd, &wr);
    GetClientRect(el->h_wnd, &cr);
    if (GetParent(el->h_wnd) != NULL) { /* We're a client window. */
	SetWindowPos(el->h_wnd, HWND_TOP, 0, 0,
		set_width - el->margin_left - el->margin_right,
		set_height - el->margin_top - el->margin_bottom,
		SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOMOVE);
    } else if (force_max) {
	MoveWindow(el->h_wnd, wr.left, wr.top,
	    set_width + (wr.right - wr.left) - (cr.right - cr.left),
	    set_height + (wr.bottom - wr.top) - (cr.bottom - cr.top),
	    TRUE);
    }

    if (el->type == BOX_GRID) { /* Hand off sizing chores to the grid */
	win32_grid_resize_contents(el, set_width, set_height);
	return;
    } else if (el->type == BOX_DECK) { /* Hand off sizing chores to the deck */
	win32_deck_resize_contents(el, set_width, set_height);
	return;
    }

    if (el->contents == NULL) /* We're done. */
	return;

    /* Otherwise, we have a box.  Proceed through its contents. */

    /* Shave off the groupbox frame */
    /* XXX - Maybe we should have "frame_" dimensions that elements can
     * set to indicate frame thickness */
    if (el->type == BOX_GROUPBOX) {
	set_width -= win32_groupbox_extra_width(el);
	set_height -= win32_groupbox_extra_height(el);
    }
    x = el->padding_left;
    y = el->padding_top;
    width = set_width - el->padding_left - el->padding_right - el->margin_left - el->margin_right;
    height = set_height - el->padding_top - el->padding_bottom - el->margin_top - el->margin_bottom;
    total_flex = win32_box_flex_total(el);
    static_dim = win32_box_static_dim(el);

    if (el->orient == BOX_ORIENT_HORIZONTAL) {
	horizontal = TRUE;
	flex_dim = set_width - static_dim - x - el->padding_right;
    } else {
	horizontal = FALSE;
	flex_dim = set_height - static_dim - y - el->padding_bottom;
    }

    for (contents = g_list_first(el->contents); contents != NULL; contents = g_list_next(contents)) {
	cur_el = (win32_element_t *) contents->data;
	if (cur_el->flex > 0.0 && win32_element_is_visible(cur_el)) {
	    last_flexible_el = cur_el;
	}
    }

    for (contents = g_list_first(el->contents); contents != NULL; contents = g_list_next(contents)) {
	cur_el = (win32_element_t *) contents->data;
	if (! win32_element_is_visible(cur_el)) {
	    continue;
	}
	if (horizontal) { /* Trundle along in the y direction */
	    if (cur_el->flex > 0.0 && total_flex > 0) {
		if (cur_el != last_flexible_el) {
		    width = (int) (cur_el->flex * flex_dim / total_flex);
		    flex_dim -= width;
		    total_flex -= cur_el->flex;
		} else {	/* We're the last flexible item.  Take up the remaining flex space. */
		    width = flex_dim;
		}
	    } else {
		width = win32_element_intrinsic_width(cur_el);
	    }
	} else { /* Vertical */
	    if (cur_el->flex > 0.0 && total_flex > 0) {
		if (cur_el != last_flexible_el) {
		    height = (int) (cur_el->flex * flex_dim / total_flex);
		    flex_dim -= height;
		    total_flex -= cur_el->flex;
		} else {	/* We're the last flexible item.  Take up the remaining flex space. */
		    height = flex_dim;
		}

	    } else {
		height = win32_element_intrinsic_height(cur_el);
	    }
	}
	win32_element_resize(cur_el, width, height);
	win32_element_move(cur_el, x, y);

	if (horizontal) {
	    x += width;
	} else {
	    y += height;
	}
    }
}

/*
 * Move the given box to the given coordiantes.  Coordinates are
 * relative to the screen for top-level windows and relative to
 * the parent for child windows.
 */
 void
 win32_element_move (win32_element_t *el, int x, int y) {
    RECT wr;

    win32_element_assert(el);
    GetWindowRect(el->h_wnd, &wr);
    MoveWindow(el->h_wnd, x + el->margin_left, y + el->margin_top, wr.right - wr.left, wr.bottom - wr.top, TRUE);
}


/*
 * Private routines
 */

static LRESULT CALLBACK
win32_box_wnd_proc(HWND hw_box, UINT msg, WPARAM w_param, LPARAM l_param) {

    switch (msg) {
//		case WM_CREATE:
//			break;
//		case WM_SIZE:
//			break;
//		case WM_NOTIFY:
//			break;
	/*
	 * This is a little counter-intuitive.  WM_LBUTTONDOWN events are
	 * caught by splitter windows (below), which are children of hw_box.
	 * WM_MOUSEMOVE and WM_LBUTTONUP events are handled by hw_box itself.
	 */
	case WM_LBUTTONUP:
	    if (splitter_drag_mode) {
		win32_splitter_lbutton_up(hw_box, msg, w_param, l_param);
		return 0;
	    }
	    break;
	case WM_MOUSEMOVE:
	    if (splitter_drag_mode) {
		win32_splitter_mouse_move(hw_box, msg, w_param, l_param);
		return 0;
	    }
	    break;
	case WM_COMMAND:
	    win32_element_handle_wm_command(msg, w_param, l_param);
	    break;
	default:
	    return(DefWindowProc(hw_box, msg, w_param, l_param));
	    break;
    }
    return 0;
}

static LRESULT CALLBACK
win32_splitter_wnd_proc(HWND hw_splitter, UINT msg, WPARAM w_param, LPARAM l_param) {

    switch (msg) {
	case WM_LBUTTONDOWN:
	    win32_splitter_lbutton_down(hw_splitter, msg, w_param, l_param);
	    return 0;
	default:
	    return(DefWindowProc(hw_splitter, msg, w_param, l_param));
    }
    return 0;
}


/*
 * Given a box, return its contents' cumulative "flex" value.
 */
static gfloat
win32_box_flex_total(win32_element_t *box) {
    gfloat total = 0.0;
    win32_element_t *cur_el;
    GList *contents;

    win32_element_assert(box);
    g_assert(box->type == BOX_BOX || box->type == BOX_GROUPBOX);

    for (contents = g_list_first(box->contents); contents != NULL; contents = g_list_next(contents)) {
	cur_el = (win32_element_t *) contents->data;
	if (win32_element_is_visible(cur_el))
	    total += cur_el->flex;
    }
    return total;
}

/*
 * Given a box, return its contents' cumulative static (non-flexible) width/height.
 */
static gint
win32_box_static_dim(win32_element_t *box) {
    gint             total = 0, intrinsic_dim = 0;
    win32_element_t *cur_el;
    GList           *contents;

    win32_element_assert(box);
    g_assert(box->type == BOX_BOX || box->type == BOX_GROUPBOX);

    /*
     * XXX - The intrinsic width is accumulated because we might run into
     * a situation where a box is sized before its minimum width has been
     * set.  This may not be the best place to do this.
     */
    for (contents = g_list_first(box->contents); contents != NULL; contents = g_list_next(contents)) {
	cur_el = (win32_element_t *) contents->data;
	if (cur_el->flex == 0.0) {
	    if (box->orient == BOX_ORIENT_HORIZONTAL) {
		total += win32_element_get_width(cur_el);
		intrinsic_dim += win32_element_intrinsic_width(cur_el);
	    } else {
		total += win32_element_get_height(cur_el);
		intrinsic_dim += win32_element_intrinsic_height(cur_el);
	    }
	}
    }

    if (intrinsic_dim > total)
	return intrinsic_dim;

    return total;
}

/*
 * Given a box, return its contents' cumulative flexible width/height.
 */
static gint
win32_box_flexible_dim(win32_element_t *box) {
    gint total = 0;
    win32_element_t *cur_el;
    GList *contents;

    win32_element_assert(box);
    g_assert(box->type == BOX_BOX || box->type == BOX_GROUPBOX);

    for (contents = g_list_first(box->contents); contents != NULL; contents = g_list_next(contents)) {
	cur_el = (win32_element_t *) contents->data;
	if (! win32_element_is_visible(cur_el))
	    continue;
	if (cur_el->flex > 0.0) {
	    if (box->orient == BOX_ORIENT_HORIZONTAL) {
		total += win32_element_get_width(cur_el);
	    } else {
		total += win32_element_get_height(cur_el);
	    }
	}
    }
    return total;
}



/*
 * Splitter routines
 */

/* XXX - The min/max x/y value should be bounded to match
 * win32_splitter_lbutton_up()'s behavior. */
static void
win32_splitter_xor_bar(HDC hdc, int x1, int y1, int width, int height)
{
    static WORD dot_pattern[8] =
    {
	0x00aa, 0x0055, 0x00aa, 0x0055,
	0x00aa, 0x0055, 0x00aa, 0x0055
    };

    HBITMAP hbm;
    HBRUSH  hbr, hbr_old;

    hbm = CreateBitmap(8, 8, 1, 1, dot_pattern);
    hbr = CreatePatternBrush(hbm);

    SetBrushOrgEx(hdc, x1, y1, 0);
    hbr_old = (HBRUSH)SelectObject(hdc, hbr);

    PatBlt(hdc, x1, y1, width, height, PATINVERT);

    SelectObject(hdc, hbr_old);

    DeleteObject(hbr);
    DeleteObject(hbm);
}

/* XXX - Handle vertical splitter bars */
static LRESULT
win32_splitter_lbutton_down(HWND hwnd, UINT i_msg, WPARAM w_param, LPARAM l_param)
{
    HWND hw_parent = GetParent(hwnd);
    POINT pt;
    HDC hdc;
    RECT rect;
    win32_element_t *box;
    win32_element_t *cur_el;
    GList *contents;
    int dim = 0;

    /* Find the box we're attached to */
    box = (win32_element_t *) GetWindowLong(hw_parent, GWL_USERDATA);
    win32_element_assert (box);

    /* Find our splitter's box element */
    cur_splitter = NULL;
    contents = g_list_first(box->contents);
    while (contents != NULL) {
	cur_el = (win32_element_t *) contents->data;
	if (cur_el->type == BOX_SPLITTER && cur_el->h_wnd == hwnd) {
	    cur_splitter = cur_el;
	    break;
	}
	dim += win32_element_get_height(cur_el);
	contents = g_list_next(contents);
    }
    win32_element_assert(cur_splitter);

    pt.x = (short)LOWORD(l_param);  // horizontal position of cursor
    pt.y = (short)HIWORD(l_param);

    GetWindowRect(hw_parent, &rect);

    //convert the mouse coordinates relative to the top-left of
    //the window
    ClientToScreen(hwnd, &pt);
    pt.x -= rect.left;
    pt.y -= rect.top;

    //same for the window coordinates - make them relative to 0,0
    OffsetRect(&rect, -rect.left, -rect.top);

    if(pt.y < 0) pt.y = 0;
    /* XXX - Find our splitter and use its width/height */
    if(pt.y > rect.bottom-4)
    {
	pt.y = rect.bottom-4;
    }

    splitter_drag_mode = TRUE;

    SetCapture(hw_parent);

    hdc = GetWindowDC(hw_parent);
    if (cur_splitter->orient == BOX_ORIENT_HORIZONTAL) {
	win32_splitter_xor_bar(hdc, pt.x - 2, 1, BOX_SPLITTER_GAP, rect.bottom - 2);
    } else {
	win32_splitter_xor_bar(hdc, 1, pt.y - 2, rect.right - 2, BOX_SPLITTER_GAP);
    }
    ReleaseDC(hw_parent, hdc);

    y_old = y_orig = pt.y;
    x_old = x_orig = pt.x;

    return 0;
}

/* XXX - Handle vertical splitter bars */
static LRESULT
win32_splitter_lbutton_up(HWND hwnd, UINT i_msg, WPARAM w_param, LPARAM l_param)
{
    HDC hdc;
    RECT rect;
    POINT pt;
    win32_element_t *box;
    win32_element_t *cur_el, *prev_el = NULL, *next_el = NULL;
    GList *contents, *tmp_item;
    gint tot_dynamic = 0;
    int dim = 0;
    gboolean horizontal = FALSE;

    pt.x = (short)LOWORD(l_param);  // horizontal position of cursor
    pt.y = (short)HIWORD(l_param);

    if(splitter_drag_mode == FALSE)
	return 0;

    if (cur_splitter == NULL)
	return 0;

    if (cur_splitter->orient == BOX_ORIENT_HORIZONTAL)
	horizontal = TRUE;

    GetWindowRect(hwnd, &rect);

    ClientToScreen(hwnd, &pt);
    pt.x -= rect.left;
    pt.y -= rect.top;

    OffsetRect(&rect, -rect.left, -rect.top);

    if(pt.y < 0)
	pt.y = 0;
    if(pt.y > rect.bottom - BOX_SPLITTER_GAP)
	pt.y = rect.bottom - BOX_SPLITTER_GAP;

    if(pt.x < 0)
	pt.x = 0;
    if(pt.x > rect.right - BOX_SPLITTER_GAP)
	pt.x = rect.right - BOX_SPLITTER_GAP;

    hdc = GetWindowDC(hwnd);
    if (horizontal) {
	win32_splitter_xor_bar(hdc, pt.x - 2, 1, BOX_SPLITTER_GAP, rect.bottom - 2);
    } else {
	win32_splitter_xor_bar(hdc, 1, pt.y - 2, rect.right - 2, BOX_SPLITTER_GAP);
    }

    ReleaseDC(hwnd, hdc);

    y_old = pt.y;
    x_old = pt.x;

    splitter_drag_mode = FALSE;

    /* Find the box we're attached to */
    box = (win32_element_t *) GetWindowLong(hwnd, GWL_USERDATA);
    win32_element_assert(box);

    /* Reposition our element */
    if (cur_splitter != NULL) {
	/* Search for the previous and next items that are visible and aren't
	   splitters, and latch on to them. */
	contents = g_list_find(box->contents, (gpointer) cur_splitter);
	for (tmp_item = g_list_previous(contents); tmp_item != NULL; tmp_item = g_list_previous(tmp_item)) {
	    prev_el = (win32_element_t *) tmp_item->data;
	    if (win32_element_is_visible(prev_el) && prev_el->type != BOX_SPLITTER)
		break;
	    prev_el = NULL;
	}
	for (tmp_item = g_list_next(contents); tmp_item != NULL; tmp_item = g_list_next(tmp_item)) {
	    next_el = (win32_element_t *) tmp_item->data;
	    if (win32_element_is_visible(next_el) && next_el->type != BOX_SPLITTER)
		break;
	    next_el = NULL;
	}

	tot_dynamic = win32_box_flexible_dim(box);

	contents = g_list_first(box->contents);
	while (contents != NULL) {
	    cur_el = (win32_element_t *) contents->data;
	    if (cur_el == cur_splitter && prev_el != NULL && next_el != NULL) {
		/* "dim" is located at the bottom of prev_item / top
		 * of cur_splitter. */

		/* Stay within the bounds of the previous and next items */
		if (horizontal) {
		    if (x_old <= dim - win32_element_get_width(prev_el))
			x_old = dim - win32_element_get_width(prev_el) + 1;
		    if (x_old >= dim + win32_element_get_width(next_el) - win32_element_get_width(cur_el))
			x_old = dim + win32_element_get_width(next_el) - 1;

		    win32_element_set_width(prev_el, win32_element_get_width(prev_el) + x_old - dim);
		    win32_element_set_width(next_el, win32_element_get_width(next_el) + dim - x_old);
		} else {
		    if (y_old <= dim - win32_element_get_height(prev_el))
			y_old = dim - win32_element_get_height(prev_el) + 1;
		    if (y_old >= dim + win32_element_get_height(next_el) - win32_element_get_height(cur_el))
			y_old = dim + win32_element_get_height(next_el) - 1;

		    win32_element_set_height(prev_el, win32_element_get_height(prev_el) + y_old - dim);
		    win32_element_set_height(next_el, win32_element_get_height(next_el) + dim - y_old);
		}

	    }

	    if (horizontal) {
		dim += win32_element_get_width(cur_el);
	    } else {
		dim += win32_element_get_height(cur_el);
	    }
	    contents = g_list_next(contents);
	}

	/* Make another pass through the box contents, adjusting
	 * each flex value */
	contents = g_list_first(box->contents);
	while (contents != NULL) {
	    cur_el = (win32_element_t *) contents->data;
	    if (cur_el->flex > 0.0 && win32_element_is_visible(cur_el)) {
		if (horizontal) {
		    cur_el->flex = (float) (win32_element_get_width(cur_el) * 100.0 / tot_dynamic);
		} else {
		    cur_el->flex = (float) (win32_element_get_height(cur_el) * 100.0 / tot_dynamic);
		}
	    }
	    contents = g_list_next(contents);
	}
    }

    if (tot_dynamic) {
	win32_element_resize(box, rect.right - rect.left, rect.bottom - rect.top);
    }

    ReleaseCapture();

    return 0;
}

static LRESULT
win32_splitter_mouse_move(HWND hwnd, UINT i_msg, WPARAM w_param, LPARAM l_param)
{
    HDC      hdc;
    RECT     rect;
    POINT    pt;
    gboolean horizontal = FALSE;

    if (splitter_drag_mode == FALSE)
	return 0;

    if (cur_splitter == NULL)
	return 0;

    if (cur_splitter->orient == BOX_ORIENT_HORIZONTAL)
	horizontal = TRUE;

    pt.x = (short)LOWORD(l_param);  // horizontal position of cursor
    pt.y = (short)HIWORD(l_param);

    GetWindowRect(hwnd, &rect);

    ClientToScreen(hwnd, &pt);
    pt.x -= rect.left;
    pt.y -= rect.top;

    OffsetRect(&rect, -rect.left, -rect.top);

    if(pt.y < 0)
	pt.y = 0;
    if(pt.y > rect.bottom - BOX_SPLITTER_GAP)
	pt.y = rect.bottom - BOX_SPLITTER_GAP;

    if(pt.x < 0)
	pt.x = 0;
    if(pt.x > rect.right - BOX_SPLITTER_GAP)
	pt.x = rect.right - BOX_SPLITTER_GAP;

    if (horizontal && pt.x != x_old && w_param & MK_LBUTTON) {
	hdc = GetWindowDC(hwnd);
	win32_splitter_xor_bar(hdc, x_old - 2, 1, BOX_SPLITTER_GAP, rect.bottom - 2);
	win32_splitter_xor_bar(hdc, pt.x - 2, 1, BOX_SPLITTER_GAP, rect.bottom - 2);

	ReleaseDC(hwnd, hdc);

	x_old = pt.x;
    } else if (!horizontal && pt.y != y_old && w_param & MK_LBUTTON) {
	hdc = GetWindowDC(hwnd);
	win32_splitter_xor_bar(hdc, 1, y_old - 2, rect.right - 2, BOX_SPLITTER_GAP);
	win32_splitter_xor_bar(hdc, 1, pt.y - 2, rect.right - 2, BOX_SPLITTER_GAP);

	ReleaseDC(hwnd, hdc);

	y_old = pt.y;
    }

    return 0;
}
