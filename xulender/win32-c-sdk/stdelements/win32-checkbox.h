#ifndef __WIN32_CHECKBOX_H__
#define __WIN32_CHECKBOX_H__


win32_element_t *win32_checkbox_new(HWND, LPCSTR);

/*
 * Get the state of a checkbox
 */
gboolean win32_checkbox_get_state(win32_element_t *cb_el);

/*
 * Set the state of a checkbox
 */
void win32_checkbox_set_state(win32_element_t *cb_el, gboolean state);

/*
 * Attach a gboolean pointer to a checkbox.  This is meant to be used
 * in conjunction with win32_checkbox_toggle_attached_data(), below.
 */
void win32_checkbox_attach_data(win32_element_t *cb_el, gboolean *toggle_val);

/*
 * Toggle the gboolean associated with a checkbox.  Suitable for
 * use as an oncommand() routine.
 */
void win32_checkbox_toggle_attached_data(win32_element_t *cb_el);

#endif /* win32-checkbox.h */
