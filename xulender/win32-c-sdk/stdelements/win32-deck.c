
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <windows.h>

#include <glib.h>

#include "win32-c-sdk.h"

#include "win32-globals.h"


/*
 * Deck elements.
 *
 * http://www.mozilla.org/projects/xul/layout.html
 * http://www.xulplanet.com/tutorials/xultu/stacks.html
 *
 */

 /*
  * Structures
  */

typedef struct _deck_data_t {
    guint selectedindex;
    win32_element_t *selectedpanel;
} deck_data_t;

#define EWC_DECK_PANE "DeckPane"
#define WIN32_DECK_DATA "_win32_deck_data"

static void win32_deck_destroy(win32_element_t *deck, gboolean destroy_window);
static LRESULT CALLBACK win32_deck_wnd_proc(HWND, UINT, WPARAM, LPARAM);

win32_element_t *
win32_deck_new(HWND hw_parent) {
    win32_element_t *deck;
    HINSTANCE        h_instance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    deck_data_t     *dd;
    WNDCLASS         wc;

    g_assert(hw_parent != NULL);

    deck = win32_element_new(NULL);

    if (! GetClassInfo(h_instance, EWC_DECK_PANE, &wc)) {
	wc.lpszClassName = EWC_DECK_PANE;
	wc.lpfnWndProc = win32_deck_wnd_proc;
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

    deck->h_wnd = CreateWindow(
	EWC_DECK_PANE,
	EWC_DECK_PANE,
	WS_CHILD | WS_VISIBLE,
	0, 0, 0, 0,
	hw_parent,
	NULL,
	h_instance,
	(LPSTR) NULL);

    ShowWindow(deck->h_wnd, SW_SHOW);
    UpdateWindow(deck->h_wnd);



    deck->type = BOX_DECK;
    deck->destroy = win32_deck_destroy;

    dd = g_malloc(sizeof(deck_data_t));
    dd->selectedindex = 0;
    dd->selectedpanel = NULL;

    /* Attach the deck address to our HWND. */
    SetWindowLong(deck->h_wnd, GWL_USERDATA, (LONG) deck);
    win32_element_set_data(deck, WIN32_DECK_DATA, dd);

    return deck;
}


/*
 * Resize the contents of the deck.  This is meant to be called from
 * win32_element_resize() after the deck's HWND has been resized; therefore
 * we only handle the deck's contents and not the deck's HWND.
 */
/* XXX - Add flex support */
void
win32_deck_resize_contents(win32_element_t *deck, int set_width, int set_height) {
    int              width, height;
    win32_element_t *cur_el;
    GList           *contents;

    win32_element_assert(deck);

    width = set_width - deck->padding_left - deck->padding_right
	    - deck->margin_left - deck->margin_right;
    if (width < 0) width = 0;
    height = set_height  - deck->padding_bottom - deck->padding_top
	    - deck->margin_top - deck->margin_bottom;
    if (height < 0) height = 0;
    contents = g_list_first(deck->contents);
    while (contents != NULL) {
	cur_el = (win32_element_t *) contents->data;
	win32_element_resize(cur_el, width, height);
	win32_element_move(cur_el, cur_el->margin_left, cur_el->margin_top);
	contents = g_list_next(contents);
    }
}

/*
 * Find a deck's intrinsic (minimum) width.
 */
gint
win32_deck_intrinsic_width(win32_element_t *deck) {
    gint             width, min_width = 0;
    GList           *contents;
    win32_element_t *cur_el;

    win32_element_assert(deck);

    if (deck->contents == NULL)
	return deck->minwidth + deck->padding_left + deck->padding_right +
		deck->margin_left + deck->margin_right;

    contents = g_list_first(deck->contents);
    while (contents) {
	cur_el = (win32_element_t *) contents->data;
	width = win32_element_intrinsic_width(cur_el);
	if (width > min_width)
	    min_width = width;
	contents = g_list_next(contents);
    }

    min_width += deck->padding_left + deck->padding_right;
    min_width += deck->margin_left + deck->margin_right;
    return min_width;
}

/*
 * Find a deck's intrinsic (minimum) height.
 */
gint
win32_deck_intrinsic_height(win32_element_t *deck) {
    gint             height, min_height = 0;
    GList           *contents;
    win32_element_t *cur_el;

    win32_element_assert(deck);

    if (deck->contents == NULL)
	return deck->minheight + deck->padding_top + deck->padding_bottom
		+ deck->margin_top + deck->margin_bottom;

    contents = g_list_first(deck->contents);
    while (contents) {
	cur_el = (win32_element_t *) contents->data;
	height = win32_element_intrinsic_height(cur_el);
	if (height > min_height)
	    min_height = height;
	contents = g_list_next(contents);
    }

    min_height += deck->padding_top + deck->padding_bottom;
    min_height += deck->margin_top + deck->margin_bottom;
    return min_height;
}

/*
 * Set a deck's selected (visible) element given its index number
 * (starting at 0).
 */
void
win32_deck_set_selectedindex(win32_element_t *deck, guint index) {
    GList           *contents;
    deck_data_t     *dd;
    win32_element_t *cur_el;
    guint             count = 0;

    win32_element_assert(deck);
    dd = (deck_data_t *) win32_element_get_data(deck, WIN32_DECK_DATA);

    contents = g_list_first(deck->contents);
    while (contents) {
	cur_el = (win32_element_t *) contents->data;
	if (count == index) {
	    ShowWindow(cur_el->h_wnd, SW_SHOW);
	    dd->selectedindex = count;
	    dd->selectedpanel = cur_el;
	} else {
	    ShowWindow(cur_el->h_wnd, SW_HIDE);
	}
	count++;
	contents = g_list_next(contents);
    }
}

/*
 * Set a deck's selected (visible) element given a pointer to the element.
 */
void
win32_deck_set_selectedpanel(win32_element_t *deck, win32_element_t *panel) {
    GList           *contents;
    deck_data_t     *dd;
    win32_element_t *cur_el;
    gint             count = 0, width, height;

    win32_element_assert(deck);
    dd = (deck_data_t *) win32_element_get_data(deck, WIN32_DECK_DATA);

    contents = g_list_first(deck->contents);
    while (contents) {
	cur_el = (win32_element_t *) contents->data;
	if (cur_el == panel) {
	    ShowWindow(cur_el->h_wnd, SW_SHOW);
	    width = win32_element_get_width(cur_el);
	    height = win32_element_get_height(cur_el);
	    win32_element_resize(cur_el, width, height);
	    dd->selectedindex = count;
	    dd->selectedpanel = cur_el;
	} else {
	    ShowWindow(cur_el->h_wnd, SW_HIDE);
	}
	count++;
	contents = g_list_next(contents);
    }
}

/*
 * Fetch a deck's selected (visible) element index, starting from 0.
 */
guint win32_deck_get_selectedindex(win32_element_t *deck) {
    deck_data_t *dd;

    win32_element_assert(deck);
    dd = (deck_data_t *) win32_element_get_data(deck, WIN32_DECK_DATA);

    return dd->selectedindex;
}

/*
 * Fetch the pointer to a deck's selected (visible) element.
 */
win32_element_t * win32_deck_get_selectedpanel(win32_element_t *deck) {
    deck_data_t *dd;

    win32_element_assert(deck);
    dd = (deck_data_t *) win32_element_get_data(deck, WIN32_DECK_DATA);

    return dd->selectedpanel;
}


/*
 * Private routines
 */

static void
win32_deck_destroy(win32_element_t *deck, gboolean destroy_window) {
    deck_data_t *dd;

    win32_element_assert(deck);

    dd = (deck_data_t *) win32_element_get_data(deck, WIN32_DECK_DATA);
    g_free(dd);

    /* Deck contents are destroyed by win32_element_destory() */
}

static LRESULT CALLBACK
win32_deck_wnd_proc(HWND hw_deck, UINT msg, WPARAM w_param, LPARAM l_param) {

    switch (msg) {
	case WM_COMMAND:
	    win32_element_handle_wm_command(msg, w_param, l_param);
	    break;
	default:
	    return(DefWindowProc(hw_deck, msg, w_param, l_param));
    }
    return 0;
}
