
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "color.h"
#include "color_filters.h"
#include "simple_dialog.h"

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"
#include "color-util.h"

#include "coloring-rules-dialog.h"
#include "win32-file-dlg.h"

static void add_filter_to_list(gpointer filter_arg, gpointer listbox_arg);
static void move_this_row(win32_element_t *listbox, gint row, gint offset);

void
coloring_rules_dialog_init(HWND hw_parent) {
    win32_element_t *cr_dlg = win32_identifier_get_str("coloring-rules-dialog");
    HWND             hw_cr;
    win32_element_t *listbox;

    if (! cr_dlg) {
	hw_cr = coloring_rules_dialog_dialog_create(hw_parent);
	cr_dlg = (win32_element_t *) GetWindowLong(hw_cr, GWL_USERDATA);
    }

    listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");
    win32_element_assert(listbox);

    win32_listbox_clear(listbox);
    g_slist_foreach(filter_list, add_filter_to_list, listbox);

    coloring_rules_list_select(listbox, NULL);

    coloring_rules_dialog_dialog_show(cr_dlg->h_wnd);
}

BOOL CALLBACK
coloring_rules_dialog_dlg_proc(HWND hw_cr, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;

    switch(msg) {
	case WM_INITDIALOG:
	    coloring_rules_dialog_handle_wm_initdialog(hw_cr);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_cr, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    win32_element_resize(dlg_box, -1, -1);
	    return 0;
	    break;
	case WM_COMMAND:
	    return 0;
	    break;
	case WM_CLOSE:
	    coloring_rules_dialog_dialog_hide(hw_cr);
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}


/* oncommand procedures */

/* Command sent by <listbox> id "coloring-rules.filter.filterlist" */
void coloring_rules_list_select (win32_element_t *listbox, LPNMLISTVIEW nmlv) {
    win32_element_t *cur_el;
    gint             row;
    gboolean         enable_up = FALSE, enable_down = FALSE;
    gboolean         enable_mod = FALSE;

    win32_element_assert(listbox);

    row = win32_listbox_get_selected(listbox);

    if (row > 0)
	enable_up = TRUE;

    cur_el = win32_identifier_get_str("coloring-rules.order.up");
    win32_element_assert(cur_el);
    win32_element_set_enabled(cur_el, enable_up);

    if (row > -1 && row < win32_listbox_get_row_count(listbox) - 1)
	enable_down = TRUE;

    cur_el = win32_identifier_get_str("coloring-rules.order.down");
    win32_element_assert(cur_el);
    win32_element_set_enabled(cur_el, enable_down);

    if (row > -1)
	enable_mod = TRUE;

    cur_el = win32_identifier_get_str("coloring-rules.edit.edit");
    win32_element_assert(cur_el);
    win32_element_set_enabled(cur_el, enable_mod);

    cur_el = win32_identifier_get_str("coloring-rules.edit.delete");
    win32_element_assert(cur_el);
    win32_element_set_enabled(cur_el, enable_mod);
}


/* Command sent by element type <button>, id "coloring-rules.edit.new" */
void coloring_rules_new (win32_element_t *btn_el) {
}

/* Command sent by element type <button>, id "coloring-rules.edit.edit" */
void coloring_rules_edit (win32_element_t *btn_el) {
}

/* Command sent by element type <button>, id "coloring-rules.edit.delete" */
void coloring_rules_delete (win32_element_t *btn_el) {
    win32_element_t *listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");
    color_filter_t  *colorf;
    gint             row;

    win32_element_assert(listbox);

    row = win32_listbox_get_selected(listbox);

    if (row < 0)
	return;

    colorf = win32_listbox_get_row_data(listbox, row);

    if (colorf == NULL)
	return;

    win32_listbox_delete_item(listbox, row);
    remove_color_filter(colorf);
}




/* Command sent by element type <button>, id "coloring-rules.manage.export" */
void coloring_rules_export (win32_element_t *btn_el) {
    win32_element_t *cr_dlg = win32_identifier_get_str("coloring-rules-dialog");

    win32_element_assert(cr_dlg);

    win32_export_color_file(cr_dlg->h_wnd);
}

/* Command sent by element type <button>, id "coloring-rules.manage.import" */
void coloring_rules_import (win32_element_t *btn_el) {
    win32_element_t *cr_dlg = win32_identifier_get_str("coloring-rules-dialog");
    win32_element_t *listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");

    win32_element_assert(cr_dlg);
    win32_element_assert(listbox);

    win32_import_color_file(cr_dlg->h_wnd);

    win32_listbox_clear(listbox);
    g_slist_foreach(filter_list, add_filter_to_list, listbox);
    coloring_rules_list_select(listbox, NULL);

}

/* Command sent by element type <button>, id "coloring-rules.manage.clear" */
void coloring_rules_clear (win32_element_t *btn_el) {
    win32_element_t *listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");
    color_filter_t  *colorf;

    win32_element_assert(listbox);

    while (filter_list) {
	colorf = filter_list->data;
	remove_color_filter(colorf);
    }

    win32_listbox_clear(listbox);

    if (!revert_filters())
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "Could not delete filter file: %s", strerror(errno));

    /* colorize list */
    colorize_packets(&cfile);

    coloring_rules_close(NULL);
}


/* Command sent by element type <button>, id "coloring-rules.order.up" */
void coloring_rules_up (win32_element_t *btn_el) {
    win32_element_t *listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");
    gint row;

    win32_element_assert(listbox);

    row = win32_listbox_get_selected(listbox);
    if (row < 0)
	return;

    move_this_row(listbox, row, -1);
}

/* Command sent by element type <button>, id "coloring-rules.order.down" */
void coloring_rules_down (win32_element_t *btn_el) {
    win32_element_t *listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");
    gint row;

    win32_element_assert(listbox);

    row = win32_listbox_get_selected(listbox);
    if (row < 0)
	return;

    move_this_row(listbox, row, 1);
}


/* Command sent by element type <button>, id "coloring-rules.ok" */
void coloring_rules_ok (win32_element_t *btn_el) {
    colorize_packets(&cfile);

    coloring_rules_close(NULL);
}

/* Command sent by element type <button>, id "coloring-rules.apply" */
void coloring_rules_apply (win32_element_t *btn_el) {
    colorize_packets(&cfile);
}

/* Command sent by element type <button>, id "coloring-rules.save" */
void coloring_rules_save (win32_element_t *btn_el) {
    if (!write_filters())
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "Could not open filter file: %s", strerror(errno));
}

/* Command sent by element type <button>, id "coloring-rules.close" */
void coloring_rules_close (win32_element_t *btn_el) {
    win32_element_t *cr_dlg = win32_identifier_get_str("coloring-rules-dialog");

    win32_element_assert(cr_dlg);

    coloring_rules_dialog_dialog_hide(cr_dlg->h_wnd);
}



/*
 * Private functions
 */

static void
add_filter_to_list(gpointer filter_arg, gpointer listbox_arg)
{
    color_filter_t  *colorf = filter_arg;
    win32_element_t *listbox = listbox_arg;
    gint             row;

    row = win32_listbox_add_item(listbox, -1, NULL, colorf->filter_name);
    win32_listbox_add_cell(listbox, NULL, colorf->filter_text);
    win32_listbox_set_row_data(listbox, row, colorf);
    win32_listbox_set_row_colors(listbox, row, &colorf->fg_color, &colorf->bg_color);
}

static void
move_this_row(win32_element_t *listbox, gint row, gint offset) {
    color_filter_t  *colorf;
    gint             new_pos = row + offset;

    if (row < 0 || row > win32_listbox_get_row_count(listbox))
	return;

    if (new_pos < 0 || new_pos > win32_listbox_get_row_count(listbox))
	return;

    colorf = win32_listbox_get_row_data(listbox, row);
    win32_listbox_delete_item(listbox, row);
    new_pos = win32_listbox_add_item(listbox, new_pos, NULL, colorf->filter_name);
    win32_listbox_add_cell(listbox, NULL, colorf->filter_text);
    win32_listbox_set_row_data(listbox, new_pos, colorf);
    win32_listbox_set_row_colors(listbox, new_pos, &colorf->fg_color, &colorf->bg_color);
    win32_listbox_set_selected(listbox, new_pos);
}