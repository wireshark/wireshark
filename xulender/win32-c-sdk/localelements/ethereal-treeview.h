#ifndef __ETHEREAL_TREEVIEW_H__
#define __ETHEREAL_TREEVIEW_H__

#define ID_TREE_VIEW 5001

win32_element_t * ethereal_treeview_new(HWND hw_parent);
void ethereal_treeview_clear(win32_element_t* treeview);
void ethereal_treeview_delete(HWND hw_treeview);
HTREEITEM ethereal_treeview_find_finfo(win32_element_t *treeview, field_info *fi);
void ethereal_treeview_select(win32_element_t *treeview, HTREEITEM hti);
void ethereal_treeview_show_tree(capture_file *cfile);
void ethereal_treeview_draw(win32_element_t *treeview, proto_tree *tree, win32_element_t *byteview);
void ethereal_treeview_collapse_all(win32_element_t *treeview);
void ethereal_treeview_expand_all(win32_element_t *treeview);
void ethereal_treeview_expand_tree(win32_element_t *treeview);

#endif /* ethereal-treeview.h */
