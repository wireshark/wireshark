#ifndef __WIN32_TOOLBAR_H__
#define __WIN32_TOOLBAR_H__


/*
 * Create a new toolbar.
 */
win32_element_t * win32_toolbar_new(HWND);

/*
 * Add a button to a toolbar, with "label" specifying the label string.
 * If "label" is NULL, an empty button will be created.
 */
void win32_toolbar_add_button(win32_element_t *toolbar, gint id, gchar *label);

/*
 * Add a separator to a toolbar.
 */
void win32_toolbar_add_separator(win32_element_t *toolbar);

#endif /* win32-toolbar.h */
