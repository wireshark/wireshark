

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <windows.h>

#include <glib.h>

#include "win32-c-sdk.h"

#include "win32-globals.h"

static GData *g_identifier_list = NULL;

/*
 * Routines for managing the global identifier list.
 */

void
win32_identifier_init(void) {
	if (! g_identifier_list)
		g_datalist_init(&g_identifier_list);
}

void
win32_identifier_set_str(const gchar* id, gpointer data) {
	g_datalist_set_data(&g_identifier_list, id, data);
}

gpointer
win32_identifier_get_str(const gchar *id) {
	return (g_datalist_get_data(&g_identifier_list, id));
}

void
win32_identifier_remove_str(const gchar *id) {
	g_datalist_remove_data(&g_identifier_list, id);
}


win32_element_t *
win32_element_new(HWND hw_box) {
    win32_element_t *box;

    box = g_malloc(sizeof(win32_element_t));

    ZeroMemory(box, sizeof(win32_element_t));
    box->type = BOX_BOX;
    box->contents = NULL;
    g_datalist_init(&box->object_data);
    box->rows = NULL;
    box->columns = NULL;

    box->h_wnd = hw_box;

    box->id = NULL;
    box->dir = BOX_DIR_LTR;
    box->crop = BOX_CROP_NONE;
    box->flex = 0.0;
    box->flexgroup = 0;

    box->orient = BOX_ORIENT_HORIZONTAL;
    box->align = BOX_ALIGN_STRETCH;
    box->pack = BOX_PACK_START;

    box->padding_top = 0;
    box->padding_bottom = 0;
    box->padding_left = 0;
    box->padding_right = 0;

    box->text_align = CSS_TEXT_ALIGN_LEFT;

    box->maxheight = -1;
    box->maxwidth = -1;
    box->minheight = 0;
    box->minwidth = 0;

    box->frame_top = 0;
    box->frame_bottom = 0;
    box->frame_left = 0;
    box->frame_right = 0;

    box->onchange = NULL;
    box->oncommand = NULL;
    box->oninput = NULL;

    box->sortdirection = EL_SORT_NATURAL;

    return box;
}

void
win32_element_destroy(win32_element_t *el, gboolean destroy_window) {
    win32_element_t *cur_el;
    GList           *contents;

    win32_element_assert(el);

    contents = g_list_first(el->contents);
    while (contents) {
	cur_el = (win32_element_t *) contents->data;
	win32_element_destroy(cur_el, FALSE);
	contents = g_list_next(contents);
    }
    g_list_free(g_list_first(contents));

    if (el->id) {
	win32_identifier_remove_str(el->id);
    }

    if (el->destroy) {
	el->destroy(el);
    }

    if (el->object_data) {
	g_datalist_clear(&el->object_data);
    }

    if (destroy_window && el->h_wnd) {
	DestroyWindow(el->h_wnd);
    }

    g_free(el);
}

/*
 * Checks that an element is valid, and throws an assertion if it isn't.
 */
void
win32_element_assert(win32_element_t *el) {
    win32_element_t *hw_el;
#if 1
    if (el == NULL) G_BREAKPOINT();
#else
    g_assert(el != NULL);
#endif

#if 1
    if (el->h_wnd == NULL) G_BREAKPOINT();
#else
    g_assert(el->h_wnd != NULL);
#endif

    hw_el = (win32_element_t *) GetWindowLong(el->h_wnd, GWL_USERDATA);
#if 1
    if (el != hw_el) G_BREAKPOINT();
#else
    g_assert(el == hw_el);
#endif
}

/*
 * Checks that an HWND has an associated element, and that it is valid.
 */
void
win32_element_hwnd_assert(HWND hwnd) {
    win32_element_t *hw_el;

    g_assert(hwnd != NULL);
    hw_el = (win32_element_t *) GetWindowLong(hwnd, GWL_USERDATA);
    win32_element_assert(hw_el);
}

void
win32_element_set_id(win32_element_t *el, gchar *id) {
    win32_element_assert(el);

    el->id = g_strdup(id);
    win32_identifier_set_str(el->id, el);
}

/*
 * Given an element, return the width of its h_wnd.
 */
LONG
win32_element_get_width(win32_element_t *el) {

    g_assert(el != NULL);

    return win32_element_hwnd_get_width(el->h_wnd);
}

/*
 * Given an element's hwnd, return its width.
 */
LONG
win32_element_hwnd_get_width(HWND hwnd) {
    RECT wr;

    win32_element_hwnd_assert(hwnd);
    GetWindowRect(hwnd, &wr);
    return wr.right - wr.left;
}

/*
 * Given an element, return the height of its h_wnd.
 */
LONG
win32_element_get_height(win32_element_t *el) {
    g_assert(el != NULL);

    return win32_element_hwnd_get_height(el->h_wnd);
}

/*
 * Given an element's hwnd, return its height.
 */
LONG
win32_element_hwnd_get_height(HWND hwnd) {
    RECT wr;

    win32_element_hwnd_assert(hwnd);
    GetWindowRect(hwnd, &wr);
    return wr.bottom - wr.top;
}

/*
 * Given an element, set the width of its h_wnd.
 */
void
win32_element_set_width(win32_element_t *el, int width) {
    g_assert(el != NULL);

    win32_element_hwnd_set_width(el->h_wnd, width);
}

/*
 * Set the width of an element's h_wnd
 */
void
win32_element_hwnd_set_width(HWND hwnd, int width) {
    RECT wr;

    win32_element_hwnd_assert(hwnd);
    GetWindowRect(hwnd, &wr);
    SetWindowPos(hwnd, HWND_TOP, 0, 0, width, wr.bottom - wr.top,
	SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOMOVE);
}

/*
 * Given an element, set the height of its h_wnd.
 */
void win32_element_set_height(win32_element_t *el, int height) {
    g_assert(el != NULL);

    win32_element_hwnd_set_height(el->h_wnd, height);
}

/*
 * Set the height of an element's h_wnd
 */
void win32_element_hwnd_set_height(HWND hwnd, int height) {
    RECT wr;

    win32_element_hwnd_assert(hwnd);
    GetWindowRect(hwnd, &wr);
    SetWindowPos(hwnd, HWND_TOP, 0, 0, wr.right - wr.left, height,
	SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOMOVE);
}

/*
 * Find an element's intrinsic (minimum) width.
 */
gint
win32_element_intrinsic_width(win32_element_t *el) {
    gint width, min_width = 0, extra = 0;
    win32_element_t *cur_el;
    GList *contents;

    win32_element_assert(el);

    if (el->type == BOX_GRID)
	return win32_grid_intrinsic_width(el);

    if (el->type == BOX_DECK)
	return win32_deck_intrinsic_width(el);

    if (el->type == BOX_GROUPBOX)
	extra = win32_groupbox_extra_width(el);

    if (el->contents == NULL) {
	min_width = el->minwidth;
    } else {
	contents = g_list_first(el->contents);
	while (contents) {
	    cur_el = (win32_element_t *) contents->data;
	    width = win32_element_intrinsic_width(cur_el);
	    if (el->orient == BOX_ORIENT_HORIZONTAL) {
		min_width += width;
	    } else {
		if (width > min_width)
		    min_width = width;
	    }
	    contents = g_list_next(contents);
	}
	min_width += el->frame_left + el->frame_right;
    }
    return min_width + extra;
}

/*
 * Find an element's intrinsic (minimum) height.
 */
gint
win32_element_intrinsic_height(win32_element_t *el) {
    gint height, min_height = 0, extra = 0;
    win32_element_t *cur_el;
    GList *contents;

    win32_element_assert(el);

    if (el->type == BOX_GRID)
	return win32_grid_intrinsic_height(el);

    if (el->type == BOX_DECK)
	return win32_deck_intrinsic_height(el);

    if (el->type == BOX_GROUPBOX)
	extra = win32_groupbox_extra_height(el);

    if (el->contents == NULL) {
	min_height = el->minheight;
    } else {
	contents = g_list_first(el->contents);
	while (contents) {
	    cur_el = (win32_element_t *) contents->data;
	    height = win32_element_intrinsic_height(cur_el);
	    if (el->orient == BOX_ORIENT_VERTICAL) {
		min_height += height;
	    } else {
		if (height > min_height)
		    min_height = height;
	    }
	    contents = g_list_next(contents);
	}
	min_height += el->frame_top + el->frame_bottom;
    }
    return min_height + extra;
}


void
win32_element_set_data(win32_element_t *el, gchar *id, gpointer data) {
    g_datalist_set_data(&el->object_data, id, data);
}

void
win32_element_hwnd_set_data(HWND hwnd, gchar *id, gpointer data) {
    win32_element_t *el = (win32_element_t *) GetWindowLong(hwnd, GWL_USERDATA);

    g_assert(el != NULL);
    g_datalist_set_data(&el->object_data, id, data);
}

gpointer
win32_element_get_data(win32_element_t *el, gchar *id) {
    return (g_datalist_get_data(&el->object_data, id));
}

gpointer
win32_element_hwnd_get_data(HWND hwnd, gchar *id) {
    win32_element_t *el = (win32_element_t *) GetWindowLong(hwnd, GWL_USERDATA);

    g_assert(el != NULL);
    return (g_datalist_get_data(&el->object_data, id));
}

gboolean
win32_element_get_enabled(win32_element_t *el) {
    LONG el_style;

    win32_element_assert(el);
    el_style = GetWindowLong(el->h_wnd, GWL_STYLE);
    return el_style | WS_DISABLED ? FALSE : TRUE;
}

void
win32_element_set_enabled(win32_element_t *el, gboolean enabled) {

    win32_element_assert(el);
    EnableWindow(el->h_wnd, enabled);
}

void win32_element_handle_wm_command(UINT msg, WPARAM w_param, LPARAM l_param) {
    win32_element_t *el;
    RECT dcrect;

    /* onCommand commands */
    if (HIWORD(w_param) == BN_CLICKED && l_param != NULL) {
	el = (win32_element_t *) GetWindowLong((HWND) l_param, GWL_USERDATA);
	win32_element_assert(el);
	if (el->oncommand != NULL) el->oncommand(el);
    /* Resize our combobox dropdown boxes */
    /* XXX - Get the number of items in the list and size accordingly */
    } else if (HIWORD(w_param) == CBN_DROPDOWN && (
	    (int) LOWORD(w_param) == ID_COMBOBOX ||
	    (int) LOWORD(w_param) == ID_MENULIST )) {
	GetWindowRect((HWND) l_param,  &dcrect);
	SetWindowPos((HWND) l_param, HWND_TOP, 0, 0, dcrect.right - dcrect.left, 150,
	    SWP_NOACTIVATE | SWP_NOZORDER | SWP_NOMOVE);
    /* onInput commands */
    } else if (HIWORD(w_param) == EN_UPDATE && (int) LOWORD(w_param) == ID_TEXTBOX) {
	el = (win32_element_t *) GetWindowLong((HWND) l_param, GWL_USERDATA);
	win32_element_assert(el);
	if (el->oninput != NULL) el->oninput(el);
    } else if (HIWORD(w_param) == CBN_SELCHANGE && (int) LOWORD(w_param) == ID_MENULIST) {
	el = (win32_element_t *) GetWindowLong((HWND) l_param, GWL_USERDATA);
	win32_element_assert(el);
	if (el->oncommand != NULL) el->oncommand(el);
    }
}

