#ifndef __WIN32_MENULIST_H__
#define __WIN32_MENULIST_H__

#define ID_MENULIST 5005

win32_element_t * win32_menulist_new(HWND);

/*
 * Add an item to the menu.
 */
void win32_menulist_add(win32_element_t *ml_el, gchar *item, gboolean selected);

/*
 * Set the current selection (starting from zero).  Runs the element's
 * oncommand() function afterward, if present.
 */
void win32_menulist_set_selection(win32_element_t *ml_el, int sel);

/*
 * Get the current selection (starts from zero).  Returns -1 if there is
 * no selection.
 */
int win32_menulist_get_selection(win32_element_t *ml_el);

/*
 * Get the item string.  Returns NULL if the item is invalid.  Returned
 * data must be freed.
 */
gchar * win32_menulist_get_string(win32_element_t *ml_el, gint item);

/*
 * Given a string, finds its selection index.  Returns -1 if not found.
 */
int win32_menulist_find_string(win32_element_t *ml_el, gchar *str);

#endif /* win32-menulist.h */
