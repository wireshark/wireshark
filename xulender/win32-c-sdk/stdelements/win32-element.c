

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
win32_element_new(HWND hw_el) {
    win32_element_t *el;

    el = g_malloc(sizeof(win32_element_t));

    ZeroMemory(el, sizeof(win32_element_t));
    el->type = BOX_BOX;
    el->contents = NULL;
    g_datalist_init(&el->object_data);
    el->rows = NULL;
    el->columns = NULL;

    el->h_wnd = hw_el;

    el->id = NULL;
    el->dir = BOX_DIR_LTR;
    el->crop = BOX_CROP_NONE;
    el->flex = 0.0;
    el->flexgroup = 0;

    el->orient = BOX_ORIENT_HORIZONTAL;
    el->align = BOX_ALIGN_STRETCH;
    el->pack = BOX_PACK_START;

    el->margin_top = 0;
    el->margin_bottom = 0;
    el->margin_left = 0;
    el->margin_right = 0;

    el->padding_top = 0;
    el->padding_bottom = 0;
    el->padding_left = 0;
    el->padding_right = 0;

    el->text_align = CSS_TEXT_ALIGN_LEFT;

    el->maxheight = -1;
    el->maxwidth = -1;
    el->minheight = 0;
    el->minwidth = 0;

    el->onchange = NULL;
    el->oncommand = NULL;
    el->oninput = NULL;

    el->sortdirection = EL_SORT_NATURAL;

    return el;
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

    win32_element_assert(el);

    return win32_element_hwnd_get_width(el->h_wnd);
}

/*
 * Given an element's hwnd, return its width.
 */
LONG
win32_element_hwnd_get_width(HWND hwnd) {
    win32_element_t *el;
    RECT wr;

    win32_element_hwnd_assert(hwnd);
    el = (win32_element_t *) GetWindowLong(hwnd, GWL_USERDATA);

    if (! IsWindowVisible(hwnd))
	return 0;

    GetWindowRect(hwnd, &wr);
    return (wr.right - wr.left) + el->margin_left + el->margin_right;
}

/*
 * Given an element, return the height of its h_wnd.
 */
LONG
win32_element_get_height(win32_element_t *el) {

    win32_element_assert(el);

    return win32_element_hwnd_get_height(el->h_wnd);
}

/*
 * Given an element's hwnd, return its height.
 */
LONG
win32_element_hwnd_get_height(HWND hwnd) {
    win32_element_t *el;
    RECT wr;

    win32_element_hwnd_assert(hwnd);
    el = (win32_element_t *) GetWindowLong(hwnd, GWL_USERDATA);

    if (! IsWindowVisible(hwnd))
	return 0;

    GetWindowRect(hwnd, &wr);
    return (wr.bottom - wr.top) + el->margin_top + el->margin_bottom;
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

    if (! win32_element_is_visible(el))
	return 0;

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
	min_width += el->padding_left + el->padding_right;
    }
    min_width += el->margin_left + el->margin_right;
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

    if (! win32_element_is_visible(el))
	return 0;

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
	min_height += el->padding_top + el->padding_bottom;
    }
    min_height += el->margin_top + el->margin_bottom;
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

win32_element_t *
win32_element_find_child(win32_element_t *el, gchar *id) {
    win32_element_t *cur_el, *retval;
    GList           *contents;

    if (el->id && strcmp(el->id, id) == 0)
	return el;

    if (el->contents) { /* We have a "normal" box */
	for (contents = g_list_first(el->contents); contents != NULL; contents = g_list_next(contents)) {
	    cur_el = (win32_element_t *) contents->data;
	    retval = win32_element_find_child(cur_el, id);
	    if (retval)
		return retval;
	}
    }

    if (el->type == BOX_GRID) { /* Hand off to the grid */
	retval = win32_grid_find_child(el, id);
	if (retval)
	    return retval;
    }

    return NULL;
}

win32_element_t *
win32_element_find_in_window(win32_element_t *el, gchar *id) {
    HWND             hw_parent, hw_top;
    win32_element_t *el_top;

    win32_element_assert(el);
    hw_top = el->h_wnd;

    while (hw_parent = GetParent(hw_top))
	hw_top = hw_parent;

    if (hw_top == NULL)
	return NULL;

    el_top = (win32_element_t *) GetWindowLong(hw_top, GWL_USERDATA);
    if (el_top == NULL)
	return NULL;

    return win32_element_find_child(el_top, id);
}

gboolean
win32_element_is_visible(win32_element_t *el) {
    win32_element_assert(el);

    if (IsWindowVisible(el->h_wnd))
	return TRUE;

    return FALSE;
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
    } else if (HIWORD(w_param) == CBN_DROPDOWN && (int) LOWORD(w_param) == ID_MENULIST ) {
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
	if (el->onchange != NULL) el->onchange(el);
    } else if (HIWORD(w_param) == CBN_EDITCHANGE && (int) LOWORD(w_param) == ID_MENULIST) {
	el = (win32_element_t *) GetWindowLong((HWND) l_param, GWL_USERDATA);
	win32_element_assert(el);
	if (el->oninput != NULL) el->oninput(el);
    }
}

