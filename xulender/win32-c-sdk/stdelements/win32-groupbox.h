#ifndef __WIN32_GROUPBOX_H__
#define __WIN32_GROUPBOX_H__


win32_element_t * win32_groupbox_new(HWND);
/*
 * Move a child from the BS_GROUPBOX window to the container window.
 */
void win32_groupbox_reparent(win32_element_t *groupbox, win32_element_t *groupbox_el);

void win32_groupbox_set_title(win32_element_t *gb, char *title);
/*
 * Return the extra width needed for padding.
 */
gint win32_groupbox_extra_width(win32_element_t *groupbox);
/*
 * Return the extra height needed for padding.
 */
gint win32_groupbox_extra_height(win32_element_t *groupbox);


#endif /* win32-groupbox.h */
