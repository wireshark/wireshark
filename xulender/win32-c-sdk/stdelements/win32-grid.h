#ifndef __WIN32_GRID_H__
#define __WIN32_GRID_H__

/*
 * Create a new grid element.
 */
win32_element_t * win32_grid_new(HWND hw_parent);

/*
 * Add a column
 */
void win32_grid_add_column(win32_element_t *grid, gfloat flex, gint flexgroup);

/*
 * Add a row
 */
void win32_grid_add_row(win32_element_t *grid, gfloat flex, gint flexgroup);

/*
 * Add an arbitrary element to the most recently-added row.
 */
void win32_grid_add(win32_element_t *grid, win32_element_t *grid_el);

/*
 * Resize the contents of the grid.
 */
void win32_grid_resize_contents(win32_element_t *grid, int set_width, int set_height);

/*
 * Find a grid's intrinsic (minimum) width
 */
gint win32_grid_intrinsic_width(win32_element_t *grid);

/*
 * Find a grid's intrinsic (minimum) height
 */
gint win32_grid_intrinsic_height(win32_element_t *grid);

/*
 * Find a child element by its ID.
 */
win32_element_t * win32_grid_find_child(win32_element_t *grid, gchar *id);


#endif /* win32-grid.h */
