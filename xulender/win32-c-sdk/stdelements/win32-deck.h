#ifndef __WIN32_DECK_H__
#define __WIN32_DECK_H__

/*
 * Create a new deck element.
 */
win32_element_t * win32_deck_new(HWND hw_parent);

/*
 * Resize the contents of the deck.
 */
void win32_deck_resize_contents(win32_element_t *deck, int set_width, int set_height);

/*
 * Find a deck's intrinsic (minimum) width.
 */
gint win32_deck_intrinsic_width(win32_element_t *deck);

/*
 * Find a deck's intrinsic (minimum) height.
 */
gint win32_deck_intrinsic_height(win32_element_t *deck);

/*
 * Set a deck's selected (visible) element given its index number
 * (starting at 0).
 */
void win32_deck_set_selectedindex(win32_element_t *deck, guint index);

/*
 * Set a deck's selected (visible) element given a pointer to the element.
 */
void win32_deck_set_selectedpanel(win32_element_t *deck, win32_element_t *panel);

/*
 * Fetch a deck's selected (visible) element index, starting from 0.
 */
guint win32_deck_get_selectedindex(win32_element_t *deck);

/*
 * Fetch the pointer to a deck's selected (visible) element.
 * NOTE: If the selected panel hasn't been set by calling
 * win32_deck_set_selectedindex() or win32_deck_set_selectedpanel()
 * the return value will be NULL.
 */
win32_element_t * win32_deck_get_selectedpanel(win32_element_t *deck);

#endif /* win32-deck.h */
