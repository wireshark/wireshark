
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <windows.h>

#include <glib.h>

#include "win32-c-sdk.h"

#include "win32-globals.h"


/*
 * Grid elements.
 *
 * http://www.mozilla.org/projects/xul/layout.html
 * http://www.xulplanet.com/tutorials/xultu/grids.html
 *
 * The Mozilla documentation says that column lines may contain
 * elements, while the XUL Planet page says that only rows may
 * contain elements.  The Mozilla model seems a little silly;
 * with it you can have two elements occupying the same table
 * cell -- one in the "row" plane and one in the "column" plane.
 * To make things easier and cleaner we're going with the XUL
 * Planet specification.  Columns will only be used for layout
 * hints, e.g. "flex" and "flex-group".
 */

#define EWC_GRID_PANE "GridPane"

static void win32_grid_destroy(win32_element_t *grid, gboolean destroy_window);
static LRESULT CALLBACK win32_grid_wnd_proc(HWND, UINT, WPARAM, LPARAM);
static gint win32_grid_column_intrinsic_width(win32_element_t *grid, guint col);
static gint win32_grid_row_intrinsic_height(win32_element_t *grid, guint row);

typedef struct _win32_grid_column_t {
    gfloat flex;
    gint flexgroup;
    gint width;
} win32_grid_column_t;

typedef struct _win32_grid_row_t {
    gfloat flex;
    gint flexgroup;
    gint height;
    GList *contents;
} win32_grid_row_t;


win32_element_t *
win32_grid_new(HWND hw_parent) {
    win32_element_t *grid;
    HINSTANCE        h_instance = (HINSTANCE) GetWindowLong(hw_parent, GWL_HINSTANCE);
    WNDCLASS         wc;

    g_assert(hw_parent != NULL);

    grid = win32_element_new(NULL);

    if (! GetClassInfo(h_instance, EWC_GRID_PANE, &wc)) {
	wc.lpszClassName = EWC_GRID_PANE;
	wc.lpfnWndProc = win32_grid_wnd_proc;
	wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = h_instance;
	wc.hIcon = NULL;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = (HBRUSH) (COLOR_3DFACE+1);
	wc.lpszMenuName = NULL;

	RegisterClass(&wc);
    }

    grid->h_wnd = CreateWindow(
	EWC_GRID_PANE,
	EWC_GRID_PANE,
	WS_CHILD | WS_VISIBLE,
	0, 0, 0, 0,
	hw_parent,
	NULL,
	h_instance,
	(LPSTR) NULL);

    ShowWindow(grid->h_wnd, SW_SHOW);
    UpdateWindow(grid->h_wnd);

    grid->type = BOX_GRID;
    grid->rows = g_ptr_array_new();
    grid->columns = g_ptr_array_new();
    grid->destroy = win32_grid_destroy;

    /* Attach the grid address to our HWND. */
    SetWindowLong(grid->h_wnd, GWL_USERDATA, (LONG) grid);

    return grid;
}

void
win32_grid_add_column(win32_element_t *grid, gfloat flex, gint flexgroup) {
    win32_grid_column_t *column;

    win32_element_assert(grid);
    g_assert(grid->type == BOX_GRID);
    g_assert(grid->columns != NULL);

    column = g_malloc(sizeof(win32_grid_column_t));
    column->flex = flex;
    column->flexgroup = flexgroup;

    g_ptr_array_add(grid->columns, column);
}

void
win32_grid_add_row(win32_element_t *grid, gfloat flex, gint flexgroup) {
    win32_grid_row_t *row;

    win32_element_assert(grid);
    g_assert(grid->type == BOX_GRID);
    g_assert(grid->rows != NULL);

    row = g_malloc(sizeof(win32_grid_row_t));
    row->flex = flex;
    row->flexgroup = flexgroup;
    row->contents = NULL;

    g_ptr_array_add(grid->rows, row);
}

/*
 * Add an abitrary element to a grid.
 */
void
win32_grid_add(win32_element_t *grid, win32_element_t *grid_el) {
    win32_grid_row_t *row_data;

    win32_element_assert(grid);
    g_assert(grid->type == BOX_GRID);
    g_assert(grid->rows != NULL);
    g_assert(grid->rows->len > 0);
    g_assert(grid->columns != NULL);
    win32_element_assert(grid_el);

    row_data = g_ptr_array_index(grid->rows, grid->rows->len - 1);
    g_assert(g_list_length(row_data->contents) < grid->columns->len);
    row_data->contents = g_list_append(row_data->contents, grid_el);
}

/*
 * Resize the contents of the grid.  This is meant to be called from
 * win32_element_resize() after the grid's HWND has been resized; therefore
 * we only handle the grid's contents and not the grid's HWND.
 */
void
win32_grid_resize_contents(win32_element_t *grid, int set_width, int set_height) {
    int                  x, y, fixed_dim = 0, flex_dim;
    win32_element_t     *cur_el;
    guint                cur_row, cur_col;
    gfloat               total_flex = 0;
    win32_grid_row_t    *row_data;
    win32_grid_column_t *col_data;

    win32_element_assert(grid);
    if (grid->rows == NULL || grid->columns == NULL) {
	return;
    }

    /* Pass 1: Collect our flex/fixed width values */
    for (cur_col = 0; cur_col < grid->columns->len; cur_col++) {
	col_data = g_ptr_array_index(grid->columns, cur_col);
	col_data->width = win32_grid_column_intrinsic_width(grid, cur_col);
	total_flex += col_data->flex;
	if (col_data->flex == 0.0) {
	    fixed_dim += col_data->width;
	}
    }

    flex_dim = set_width - fixed_dim;

    /* Pass 2: Adjust our flexible column widths */
    for (cur_col = 0; cur_col < grid->columns->len; cur_col++) {
	col_data = g_ptr_array_index(grid->columns, cur_col);
	if (col_data->flex > 0.0 && total_flex > 0.0) {
	    col_data->width = (int) (col_data->flex * flex_dim / total_flex);
	}
    }

    /* Pass 3: Collect our flex/fixed height values */
    fixed_dim = 0;
    total_flex = 0.0;
    for (cur_row = 0; cur_row < grid->rows->len; cur_row++) {
	row_data = g_ptr_array_index(grid->rows, cur_row);
	row_data->height = win32_grid_row_intrinsic_height(grid, cur_row);
	total_flex += row_data->flex;
	if (row_data->flex == 0.0) {
	    fixed_dim += row_data->height;
	}
    }


    flex_dim = set_height - fixed_dim;
    y = grid->padding_top;
    /* Pass 4: Adjust our flexible row heights and resize each cell */
    for (cur_row = 0; cur_row < grid->rows->len; cur_row++) {
	row_data = g_ptr_array_index(grid->rows, cur_row);
	if (row_data->flex > 0.0 && total_flex > 0.0) {
	    row_data->height = (int) (row_data->flex * flex_dim / total_flex);
	}
	x = grid->padding_left;
	for (cur_col = 0; cur_col < grid->columns->len; cur_col++) {
	    col_data = g_ptr_array_index(grid->columns, cur_col);
	    cur_el = (win32_element_t *) g_list_nth_data(row_data->contents, cur_col);
	    if (cur_el != NULL) {
		win32_element_resize(cur_el, col_data->width, row_data->height);
		win32_element_move(cur_el, x, y);
	    }
	    x += col_data->width;
	}
	y += row_data->height;
    }
}


/*
 * Find a grid's intrinsic (minimum) width.  We do this by finding each
 * column's intrinsic width, then returning the total.
 */
gint
win32_grid_intrinsic_width(win32_element_t *grid) {
    gint tot_width = 0;
    guint cur_col;

    win32_element_assert(grid);
    if (grid->rows == NULL || grid->columns == NULL) {
	return 0;
    }

    for (cur_col = 0; cur_col < grid->columns->len; cur_col++) {
	tot_width += win32_grid_column_intrinsic_width(grid, cur_col);
    }
    return tot_width + grid->padding_left + grid->padding_right;
    return tot_width + grid->margin_left + grid->margin_right;
}



/*
 * Find a grid's intrinsic (minimum) height.
 */
gint
win32_grid_intrinsic_height(win32_element_t *grid) {
    gint tot_height = 0;
    guint cur_row;

    win32_element_assert(grid);
    if (grid->rows == NULL || grid->columns == NULL) {
	return 0;
    }

    for (cur_row = 0; cur_row < grid->rows->len; cur_row++) {
	tot_height += win32_grid_row_intrinsic_height(grid, cur_row);
    }
    return tot_height + grid->padding_top + grid->padding_bottom;
    return tot_height + grid->margin_top + grid->margin_bottom;
}

/*
 * Find a child element by its ID.
 */
win32_element_t *
win32_grid_find_child(win32_element_t *grid, gchar *id) {
    win32_element_t *cur_el, *retval;
    guint cur_row;
    win32_grid_row_t *row_data;
    GList *contents;

    win32_element_assert(grid);

    if (strcmp(grid->id, id) == 0)
	return grid;

    for (cur_row = 0; cur_row < grid->rows->len; cur_row++) {
	row_data = g_ptr_array_index(grid->rows, cur_row);
	for (contents = g_list_first(row_data->contents); contents != NULL; contents = g_list_next(contents)) {
	    cur_el = (win32_element_t *) contents->data;
	    retval = win32_grid_find_child(cur_el, id);
	    if (retval)
		return retval;
	}
    }
    return NULL;
}


/*
 * Private routines
 */

static void
win32_grid_destroy(win32_element_t *grid, gboolean destroy_window) {
    win32_element_t  *cur_el;
    win32_grid_row_t *row_data;
    GList *contents;
    guint cur_row;

    win32_element_assert(grid);

    for (cur_row = 0; cur_row < grid->rows->len; cur_row++) {
	row_data = g_ptr_array_index(grid->rows, cur_row);
	contents = g_list_first(row_data->contents);
	while (contents != NULL) {
	    cur_el = (win32_element_t *) contents->data;
	    win32_element_destroy(cur_el, FALSE);
	    contents = g_list_next(contents);
	}
	g_list_free(g_list_first(contents));
    }
    g_ptr_array_free(grid->rows, TRUE);
    g_ptr_array_free(grid->columns, TRUE);
}

static LRESULT CALLBACK
win32_grid_wnd_proc(HWND hw_grid, UINT msg, WPARAM w_param, LPARAM l_param) {

    switch (msg) {
	case WM_COMMAND:
	    win32_element_handle_wm_command(msg, w_param, l_param);
	    break;
	default:
	    return(DefWindowProc(hw_grid, msg, w_param, l_param));
    }
    return 0;
}

/*
 * Find a grid column's intrinsic (minimum) width.
 */
static gint
win32_grid_column_intrinsic_width(win32_element_t *grid, guint col) {
    gint col_width, el_width;
    win32_element_t *cur_el;
    guint cur_row;
    win32_grid_row_t *row_data;
    GList *contents;

    win32_element_assert(grid);
    if (grid->rows == NULL || grid->columns == NULL || grid->columns->len < col) {
	return 0;
    }

    col_width = 0;
    for (cur_row = 0; cur_row < grid->rows->len; cur_row++) {
	row_data = g_ptr_array_index(grid->rows, cur_row);
	contents = g_list_first(row_data->contents);
	g_assert(g_list_length(contents) == grid->columns->len);
	cur_el = (win32_element_t *) g_list_nth_data(contents, col);
	if (cur_el != NULL) {
	    el_width = win32_element_intrinsic_width(cur_el);
	    if (el_width > col_width)
		col_width = el_width;
	}
    }
    return col_width;
}

/*
 * Find a grid row's intrinsic (minimum) height.
 */
static gint
win32_grid_row_intrinsic_height(win32_element_t *grid, guint row) {
    gint row_height, el_height;
    win32_element_t *cur_el;
    guint cur_col;
    win32_grid_row_t *row_data;
    GList *contents;

    win32_element_assert(grid);
    if (grid->rows == NULL || grid->columns == NULL || grid->rows->len < row) {
	return 0;
    }
    row_data = g_ptr_array_index(grid->rows, row);
    contents = g_list_first(row_data->contents);
    g_assert(g_list_length(contents) == grid->columns->len);

    row_height = 0;
    for (cur_col = 0; cur_col < grid->columns->len; cur_col++) {
	cur_el = (win32_element_t *) g_list_nth_data(contents, cur_col);
	if (cur_el != NULL) {
	    el_height = win32_element_intrinsic_height(cur_el);
	    if (el_height > row_height)
		row_height = el_height;
	}
    }
    return row_height;
}

