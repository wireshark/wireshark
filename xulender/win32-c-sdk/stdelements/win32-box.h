#ifndef __WIN32_BOX_H__
#define __WIN32_BOX_H__

/*
 * Creates a XUL element struct and returns its address.
 * If hw_box is NULL, a new window is created with hw_parent as the parent.
 * if hw_box is not NULL, (e.g. it's a newly-created window or dialog)
 * that window is associated with the box and hw_parent is ignored.
 *
 * "orient" can be one of BOX_ORIENT HORIZONTAL or BOX_ORIENT_VERTICAL.
 * The box address is saved in its hw_box's GWL_USERDATA attribute.
 */
win32_element_t * win32_box_new(HWND hw_box, HWND hw_parent, win32_box_orient_t orient);

/*
 * Creates a horizontally-oriented "box" struct and returns its address.
 * If hw_box is NULL, a new window is created with hw_parent as the parent.
 * if hw_box is not NULL, that window is associated with the box and hw_parent
 * is ignored.
 */
win32_element_t * win32_hbox_new(HWND hw_box, HWND hw_parent);

/*
 * Creates a vertically-oriented "box" struct and returns its address.
 * If hw_box is NULL, a new window is created with hw_parent as the parent.
 * if hw_box is not NULL, that window is associated with the box and hw_parent
 * is ignored.
 */
win32_element_t * win32_vbox_new(HWND hw_box, HWND hw_parent);

/* Add a user-created box element */
void win32_box_add(win32_element_t *box, win32_element_t *element, int pos);

/* Given an HWND, create a box element and add it to the given box */
/* Changes the box element size values */
win32_element_t * win32_box_add_hwnd(win32_element_t *box, HWND h_wnd, int pos);

/* Add a splitter to a box */
/* Changes the box element size values */
win32_element_t * win32_box_add_splitter(win32_element_t *box, int pos, win32_box_orient_t orientation);

/*
 * Resize the contents of the given box to fit inside the given window.
 * If width is -1, the box is constrained to its minumum width.  Otherwise
 * the box width is set to the given width.  Likewise for the height.
 */
void win32_element_resize (win32_element_t *el, int width, int height);


/*
 * Move the given box to the given screen coordiantes.  Coordinates are
 * relative to the screen for top-level windows and relative to the parent
 * for child windows.
 */
void win32_element_move (win32_element_t *el, int x, int y);

#endif /* win32-box.h */
