#ifndef __WIN32_TREE_H__
#define __WIN32_TREE_H__

typedef struct _tree_row {
    gchar *id;
    GList *cells;
} tree_row;

typedef struct _tree_cell {
    gchar *id;
    gchar *text;
} tree_cell;

/*
 * Create a tree element.
 */
win32_element_t * win32_tree_new(HWND hw_parent);

/*
 * Add a column.
 */
void win32_tree_add_column(win32_element_t *tree, gchar *id, gchar *label,
    gboolean primary, gboolean hideheader);

/*
 * "Push" the current treeitem so that children can be placed underneath
 * it.
 */
void win32_tree_push(win32_element_t *tree);

/*
 * "Pop" the current treeitem.
 */
void win32_tree_pop(win32_element_t *tree);

/*
 * Specifies that the next item added should be open/expanded.
 */
void win32_tree_flag_open_item(win32_element_t *tree);

/*
 * Add a tree row.
 */
void win32_tree_add_row(win32_element_t *tree, gchar *id);

/*
 * Add a cell to a tree row.
 */
void win32_tree_add_cell(win32_element_t *tree, gchar *id, gchar *text);

/*
 * Find the tree's minimum size.
 */
void win32_tree_minimum_size(win32_element_t *tree);

/*
 * Set the selection callback for a tree.
 */
void win32_tree_set_onselect(win32_element_t *tree, void (*selfunc)());

/*
 * Clear all items from the tree.
 */
void win32_tree_clear();

#endif /* win32-tree.h */
