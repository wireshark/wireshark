#ifndef __WIN32_RADIO_H__
#define __WIN32_RADIO_H__


win32_element_t *win32_radio_new(HWND, LPCSTR, gboolean);

/*
 * Get the state of a radio
 */
gboolean win32_radio_get_state(win32_element_t *rd_el);

/*
 * Set the state of a radio
 */
void win32_radio_set_state(win32_element_t *rd_el, gboolean state);

/*
 * Attach a gboolean pointer to a radio.  This is meant to be used
 * in conjunction with win32_radio_toggle_attached_data(), below.
 */
void win32_radio_attach_data(win32_element_t *rd_el, gboolean *toggle_val);

/*
 * Toggle the gboolean associated with a radio.  Suitable for
 * use as an oncommand() routine.
 */
void win32_radio_toggle_attached_data(win32_element_t *rd_el);

#endif /* win32-radio.h */
