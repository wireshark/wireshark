#ifndef __WIN32_TEXTBOX_H__
#define __WIN32_TEXTBOX_H__

#include <richedit.h>

#define ID_TEXTBOX 5006

win32_element_t *win32_textbox_new(HWND hw_parent, gboolean multiline);

/*
 * Set the text in a textbox.
 */
void win32_textbox_set_text(win32_element_t *textbox, gchar *text);

/*
 * Get the text in a textbox.  The result is a freshly-allocated string
 * which must be g_free()d by the caller.
 */
gchar * win32_textbox_get_text(win32_element_t *textbox);

/*
 * Set the number of rows displayed.
 */
void win32_textbox_set_row_count(win32_element_t *textbox, gint rows);

/*
 * Get the current character formatting.  If get_sel is TRUE, gets
 * the formatting of the current selection.  Otherwise the default
 * format is used.
 */
void win32_textbox_get_char_format(win32_element_t *textbox, CHARFORMAT *char_fmt, gboolean get_sel);

/*
 * Insert text at the specified position.  If pos is -1, the text is appended.
 * If char_fmt is NULL, the default formatting is used.
 */
void win32_textbox_insert(win32_element_t *textbox, gchar *text, gint pos, CHARFORMAT *char_fmt);

#endif /* win32-textbox.h */
