#ifndef __WIN32_LISTBOX_H__
#define __WIN32_LISTBOX_H__

/*
 * Create a listbox element.
 */
win32_element_t * win32_listbox_new(HWND hw_parent, gboolean show_header);

/*
 * Add a column "label" should be NULL for <listcol> and non-NULL for
 * <listheader>. 
 */
void win32_listbox_add_column(win32_element_t *listbox, gchar *id, gchar *label);

/*
 * Add a listbox item (row).
 */
gint win32_listbox_add_item(win32_element_t *listbox, gint row, gchar *id, gchar *text);

/*
 * Delete a listbox item (row).
 */
void win32_listbox_delete_item(win32_element_t *listbox, gint row);

/*
 * Add a cell to a listbox item.
 */
void win32_listbox_add_cell(win32_element_t *listbox, gchar *id, gchar *text);

/*
 * Set the text in a particular row/column.
 */
void win32_listbox_set_text(win32_element_t *listbox, gint row, gint column, gchar *text);
/*
 * Get the text in a particular row/column.  Return NULL if not found.
 * A non-null return value must be g_free()d by the caller.
 */
gchar * win32_listbox_get_text(win32_element_t *listbox, gint row, gint column);

/*
 * Associate a data pointer with a row.
 */
void win32_listbox_set_row_data(win32_element_t *listbox, gint row, gpointer data);

/*
 * Set the foreground and background colors for a row.  Either color may be
 * NULL, in which case the system default color is used.
 */
void win32_listbox_set_row_colors(win32_element_t *listbox, gint row, color_t *fg, color_t *bg);

/*
 * Enable checkboxes for the listbox (first column only).
 */
gpointer win32_listbox_enable_checkboxes(win32_element_t *listbox, gboolean enable);

/*
 * Check/uncheck a row.
 */
void win32_listbox_set_row_checked(win32_element_t *listbox, gint row, gboolean checked);

/*
 * Check/uncheck a row.
 */
gboolean win32_listbox_get_row_checked(win32_element_t *listbox, gint row);

/*
 * Fetch the data pointer associated with a row.
 */
gpointer win32_listbox_get_row_data(win32_element_t *listbox, gint row);

/*
 * Set the selected row in a listbox.
 */
void win32_listbox_set_selected(win32_element_t *listbox, gint row);

/*
 * Fetch the selected row in a listbox.
 */
gint win32_listbox_get_selected(win32_element_t *listbox);

/*
 * Find the listbox's minimum size.
 */
void win32_listbox_minimum_size(win32_element_t *listbox);

/*
 * Set the selection callback for a listbox.
 */
void win32_listbox_set_onselect(win32_element_t *listbox, void (*selfunc)());

/*
 * Set the doubleclick callback for a listbox.
 */
void win32_listbox_set_ondoubleclick(win32_element_t *listbox, void (*dclickfunc)());

/*
 * Return the row containing "text" in the specified column.  Return -1
 * otherwise.
 */
gint win32_listbox_find_text(win32_element_t *listbox, gint column, gchar *text);

/*
 * Return the number of rows in the listbox.
 */
gint win32_listbox_get_row_count(win32_element_t *listbox);

/*
 * Clear all items from the listbox.
 */
void win32_listbox_clear(win32_element_t *listbox);

#endif /* win32-listbox.h */
