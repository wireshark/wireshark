
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
#include "edit-color-filter-dialog.h"
#include "win32-file-dlg.h"

static void add_filter_to_list(gpointer filter_arg, gpointer listbox_arg);
static void move_this_row(win32_element_t *listbox, gint row, gint offset);
static void edit_color_filter_dialog_init(HWND hw_parent, color_filter_t *colorf);
static void create_new_color_filter(char *filter);

static gboolean delete_last = FALSE;

/*
 * Called from color_filters.c
 */
/* XXX - Should we do anything here? */
void
color_add_filter_cb (color_filter_t *colorf, gpointer arg) {
}


/*
 * Coloring rules dialog
 */

void
coloring_rules_dialog_init(HWND hw_parent) {
    win32_element_t *cr_dlg = win32_identifier_get_str("coloring-rules-dialog");
    HWND             hw_cr;
    win32_element_t *listbox;
    SIZE             sz;

    if (! cr_dlg) {
	hw_cr = coloring_rules_dialog_dialog_create(hw_parent);
	cr_dlg = (win32_element_t *) GetWindowLong(hw_cr, GWL_USERDATA);
    }

    listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");
    win32_element_assert(listbox);

    win32_listbox_clear(listbox);
    g_slist_foreach(filter_list, add_filter_to_list, listbox);

    coloring_rules_list_select(listbox, NULL);

    win32_get_text_size(listbox->h_wnd, "A long filter string", &sz);
    listbox->minwidth = sz.cx * 3;
    listbox->minheight = sz.cy * 10;

    coloring_rules_dialog_dialog_show(cr_dlg->h_wnd);
}

BOOL CALLBACK
coloring_rules_dialog_dlg_proc(HWND hw_cr, UINT msg, WPARAM w_param, LPARAM l_param) {
    win32_element_t *dlg_box;

    switch(msg) {
	case WM_INITDIALOG:
	    coloring_rules_dialog_handle_wm_initdialog(hw_cr);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_cr, GWL_USERDATA);
	    win32_element_assert (dlg_box);
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

    delete_last = TRUE;
    create_new_color_filter("filter");
}

/* Command sent by element type <button>, id "coloring-rules.edit.edit" */
void coloring_rules_edit (win32_element_t *btn_el) {
    win32_element_t *cr_dlg = win32_identifier_get_str("coloring-rules-dialog");
    win32_element_t *listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");
    color_filter_t  *colorf;
    gint             row;

    win32_element_assert(cr_dlg);
    win32_element_assert(listbox);

    row = win32_listbox_get_selected(listbox);
    g_assert(row != -1);

    colorf = win32_listbox_get_row_data(listbox, row);
    g_assert(colorf != NULL);

    delete_last = FALSE;
    edit_color_filter_dialog_init(cr_dlg->h_wnd, colorf);
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
    gint             btn;

    win32_element_assert(listbox);

    /* ask user, if he/she is really sure */
    btn = (gint) simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTN_CLEAR | ESD_BTN_CANCEL,
	    "Remove all your personal color settings?\n\n"
	    "This will revert the color settings to global defaults.\n\n"
	    "Are you really sure?");

    if (btn != ESD_BTN_CLEAR)
	return;


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
 * Edit color filter dialog
 */

static void
edit_color_filter_dialog_init(HWND hw_parent, color_filter_t *colorf) {
    win32_element_t *cf_dlg = win32_identifier_get_str("edit-color-filter-dialog");
    win32_element_t *cur_el;
    HWND             hw_cf;
    CHARFORMAT2       char_fmt;

    if (! cf_dlg) {
	hw_cf = edit_color_filter_dialog_dialog_create(hw_parent);
	cf_dlg = (win32_element_t *) GetWindowLong(hw_cf, GWL_USERDATA);
    }

    cur_el = win32_identifier_get_str("edit-color-filter.name");
    win32_element_assert(cur_el);
    if (colorf->filter_name)
	SetWindowText(cur_el->h_wnd, colorf->filter_name);
    else
	SetWindowText(cur_el->h_wnd, "");

    ZeroMemory(&char_fmt, sizeof(char_fmt));
    char_fmt.cbSize = sizeof(char_fmt);
    char_fmt.dwMask = CFM_COLOR | CFM_BACKCOLOR;
    char_fmt.crTextColor = COLOR_T2COLORREF(&colorf->fg_color);
    char_fmt.crBackColor = COLOR_T2COLORREF(&colorf->bg_color);
    SendMessage(cur_el->h_wnd, EM_SETCHARFORMAT, (WPARAM) SCF_ALL, (LPARAM) &char_fmt);

    cur_el = win32_identifier_get_str("edit-color-filter.filter");
    win32_element_assert(cur_el);
    if (colorf->filter_text)
	SetWindowText(cur_el->h_wnd, colorf->filter_text);
    else
	SetWindowText(cur_el->h_wnd, "");

    EnableWindow(hw_parent, FALSE);
    coloring_rules_dialog_dialog_show(cf_dlg->h_wnd);
}

BOOL CALLBACK
edit_color_filter_dialog_dlg_proc(HWND hw_cf, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;

    switch(msg) {
	case WM_INITDIALOG:
	    edit_color_filter_dialog_handle_wm_initdialog(hw_cf);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_cf, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    return 0;
	    break;
	case WM_COMMAND:
	    return 0;
	    break;
	case WM_CLOSE:
	    edit_color_cancel(NULL);
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}

/* oncommand procedures */

/* Command sent by element type <button>, id "edit-color-filter.expression" */
void edit_color_expression (win32_element_t *btn_el) {
}

/* Command sent by element type <button>, id "edit-color-filter.foreground" */
void edit_color_foreground (win32_element_t *btn_el) {
    win32_element_t *name_te = win32_identifier_get_str("edit-color-filter.name");
    CHARFORMAT2      char_fmt;
    CHOOSECOLOR      cc;

    win32_element_assert(name_te);

    ZeroMemory(&char_fmt, sizeof(char_fmt));
    char_fmt.cbSize = sizeof(char_fmt);
    char_fmt.dwMask = CFM_COLOR;
    SendMessage(name_te->h_wnd, EM_GETCHARFORMAT, 0, (LPARAM) &char_fmt);

    ZeroMemory(&cc, sizeof(cc));
    cc.lStructSize = sizeof(cc);
    cc.Flags = CC_FULLOPEN | CC_RGBINIT;
    cc.rgbResult = char_fmt.crTextColor;
    cc.lpCustColors = cust_colors;
    if (ChooseColor(&cc)) {
	ZeroMemory(&char_fmt, sizeof(char_fmt));
	char_fmt.cbSize = sizeof(char_fmt);
	char_fmt.dwMask = CFM_COLOR;
	char_fmt.crTextColor = cc.rgbResult;
	SendMessage(name_te->h_wnd, EM_SETCHARFORMAT, (WPARAM) SCF_ALL, (LPARAM) &char_fmt);
    }
}

/* Command sent by element type <button>, id "edit-color-filter.background" */
void edit_color_background (win32_element_t *btn_el) {
    win32_element_t *name_te = win32_identifier_get_str("edit-color-filter.name");
    CHARFORMAT2      char_fmt;
    CHOOSECOLOR      cc;

    win32_element_assert(name_te);

    ZeroMemory(&char_fmt, sizeof(char_fmt));
    char_fmt.cbSize = sizeof(char_fmt);
    char_fmt.dwMask = CFM_BACKCOLOR;
    SendMessage(name_te->h_wnd, EM_GETCHARFORMAT, 0, (LPARAM) &char_fmt);

    ZeroMemory(&cc, sizeof(cc));
    cc.lStructSize = sizeof(cc);
    cc.Flags = CC_FULLOPEN | CC_RGBINIT;
    cc.rgbResult = char_fmt.crBackColor;
    cc.lpCustColors = cust_colors;
    if (ChooseColor(&cc)) {
	ZeroMemory(&char_fmt, sizeof(char_fmt));
	char_fmt.cbSize = sizeof(char_fmt);
	char_fmt.dwMask = CFM_BACKCOLOR;
	char_fmt.crBackColor = cc.rgbResult;
	SendMessage(name_te->h_wnd, EM_SETCHARFORMAT, (WPARAM) SCF_ALL, (LPARAM) &char_fmt);
    }
}

/* Command sent by element type <button>, id "edit-color-filter.ok" */
void edit_color_ok (win32_element_t *btn_el) {
    win32_element_t *cf_dlg = win32_identifier_get_str("edit-color-filter-dialog");
    win32_element_t *listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");
    win32_element_t *cur_el;
    color_filter_t  *colorf;
    dfilter_t       *compiled_filter;
    gint             row, textlen;
    CHARFORMAT2      char_fmt;
    gchar           *filter_name, *filter_text;

    win32_element_assert(cf_dlg);
    win32_element_assert(listbox);

    row = win32_listbox_get_selected(listbox);
    g_assert(row > 0);

    colorf = win32_listbox_get_row_data(listbox, row);
    g_assert(colorf != NULL);

    cur_el = win32_identifier_get_str("edit-color-filter.name");
    win32_element_assert(cur_el);

    textlen = GetWindowTextLength(cur_el->h_wnd) + 1;
    filter_name = g_malloc(textlen);
    GetWindowText(cur_el->h_wnd, filter_name, textlen);

    ZeroMemory(&char_fmt, sizeof(char_fmt));
    char_fmt.cbSize = sizeof(char_fmt);
    char_fmt.dwMask = CFM_COLOR | CFM_BACKCOLOR;
    SendMessage(cur_el->h_wnd, EM_GETCHARFORMAT, 0, (LPARAM) &char_fmt);

    cur_el = win32_identifier_get_str("edit-color-filter.filter");
    win32_element_assert(cur_el);

    textlen = GetWindowTextLength(cur_el->h_wnd) + 1;
    filter_text = g_malloc(textlen);
    GetWindowText(cur_el->h_wnd, filter_text, textlen);

    if(strchr(filter_name,'@') || strchr(filter_text,'@')) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Filter names and strings must not"
		" use the '@' character. Filter unchanged.");
	g_free(filter_name);
	g_free(filter_text);
	return;
    }

    if(!dfilter_compile(filter_text, &compiled_filter)) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "Filter \"%s\" did not compile correctly.\n"
	    " Please try again. Filter unchanged.\n%s\n", filter_name,
	    dfilter_error_msg);
	g_free(filter_name);
	g_free(filter_text);
	return;
    }

    if (colorf->filter_name)
	g_free(colorf->filter_name);
    colorf->filter_name = filter_name;

    if (colorf->filter_text)
	g_free(colorf->filter_text);
    colorf->filter_text = filter_text;

    colorref2color_t(char_fmt.crBackColor, &colorf->bg_color);
    colorref2color_t(char_fmt.crTextColor, &colorf->fg_color);

    if(colorf->c_colorfilter != NULL)
	dfilter_free(colorf->c_colorfilter);
    colorf->c_colorfilter = compiled_filter;

    win32_listbox_set_text(listbox, row, 0, colorf->filter_name);
    win32_listbox_set_text(listbox, row, 1, colorf->filter_text);
    win32_listbox_set_row_colors(listbox, row, &colorf->fg_color, &colorf->bg_color);

    RedrawWindow(listbox->h_wnd, NULL, NULL, RDW_INVALIDATE);
    edit_color_filter_dialog_dialog_hide(cf_dlg->h_wnd);
}

/* Command sent by element type <button>, id "edit-color-filter.cancel" */
void edit_color_cancel (win32_element_t *btn_el) {
    win32_element_t *cf_dlg = win32_identifier_get_str("edit-color-filter-dialog");
    win32_element_t *listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");
    color_filter_t  *colorf;
    gint             row;

    win32_element_assert(cf_dlg);

    if (delete_last) {
	win32_element_assert(listbox);

	row = win32_listbox_get_row_count(listbox) - 1;
	g_assert(row > 0);

	colorf = win32_listbox_get_row_data(listbox, row);
	g_assert(colorf != NULL);

	win32_listbox_delete_item(listbox, row);
	remove_color_filter(colorf);
    }

    edit_color_filter_dialog_dialog_hide(cf_dlg->h_wnd);
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

/* Create a new filter in the list, and pop up an "Edit color filter"
   dialog box to edit it. */
static void
create_new_color_filter(char *filter) {
    win32_element_t *cr_dlg = win32_identifier_get_str("coloring-rules-dialog");
    win32_element_t *listbox = win32_identifier_get_str("coloring-rules.filter.filterlist");
    color_filter_t  *colorf;
    color_t          bg_color, fg_color;
    gint             row;

    win32_element_assert(cr_dlg);
    win32_element_assert(listbox);

    colorref2color_t(GetSysColor(COLOR_WINDOW), &bg_color);
    colorref2color_t(GetSysColor(COLOR_WINDOWTEXT), &fg_color);

    colorf = new_color_filter("name", filter, &bg_color, &fg_color);

    add_filter_to_list(colorf, listbox);

    row = win32_listbox_get_row_count(listbox) - 1;
    g_assert(row > 0);
    win32_listbox_set_selected(listbox, row);

    edit_color_filter_dialog_init(cr_dlg->h_wnd, colorf);
}
