
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include "alert_box.h"
#include "epan/filesystem.h"
#include "epan/strutil.h"
#include "filters.h"

#include "simple_dialog.h"

#include "win32-c-sdk.h"

#include "win32-globals.h"
#include "win32-util.h"
#include "filter-util.h"

#include "filter-dialog.h"

typedef struct _filter_cb_data {
    GList           *fl;
    win32_element_t *dlg;
} filter_cb_data;

static win32_element_t * filter_dialog_new(win32_element_t *btn_el,
	win32_element_t *parent_filter_tb, filter_list_type_t list,
	construct_args_t *construct_args);
static void filter_dlg_destroy(win32_element_t *dlg, gboolean destroy_window);
static void filter_apply (win32_element_t *btn_el, gboolean destroy);

static gboolean in_tb_update = FALSE;

#define FILTER_DIALOG_DATA          "filter_dialog_data"
#define E_FILT_DIALOG_PTR_KEY       "filter_dialog_ptr"
#define E_FILT_BUTTON_PTR_KEY       "filter_button_ptr"
#define E_FILT_DBLACTIVATE_KEY      "filter_dblactivate"
#define E_FILT_PARENT_FILTER_TE_KEY "filter_parent_filter_te"
#define E_FILT_CONSTRUCT_ARGS_KEY   "filter_construct_args"
#define E_FILT_LIST_TYPE            "filter_list_type"

/* Much of this was taken from gtk/filter_dlg.c */

/* Create a filter dialog for constructing a capture filter.

   This is to be used as a callback for a button next to a text entry box,
   which, when clicked, pops up this dialog to allow you to construct a
   display filter by browsing the list of saved filters (the dialog
   for constructing expressions assumes display filter syntax, not
   capture filter syntax).  The "OK" button sets the text entry box to the
   constructed filter and activates that text entry box (which should have
   no effect in the main capture dialog); this dialog is then dismissed. */
void
capture_filter_construct(win32_element_t *btn_el, win32_element_t *parent_filter_tb)
{
#ifdef HAVE_LIBPCAP
    win32_element_t *filter_browse_dlg;
    /* No Apply button, and "OK" just sets our text widget, it doesn't
       activate it (i.e., it doesn't cause us to try to open the file). */
    static construct_args_t args = {
	"Ethereal: Capture Filter",
	FALSE,
	FALSE
    };

    /* Has a filter dialog box already been opened for that button? */
    filter_browse_dlg = win32_element_get_data(btn_el, E_FILT_DIALOG_PTR_KEY);

    if (filter_browse_dlg != NULL) {
	/* Yes.  Just re-activate that dialog box. */
	SetActiveWindow(filter_browse_dlg->h_wnd);
	return;
    }

    /* Now create a new dialog, without an "Add Expression..." button. */
    filter_browse_dlg = filter_dialog_new(btn_el, parent_filter_tb,
	CFILTER_LIST, &args);
#endif
}

/* Create a filter dialog for constructing a display filter.

   This is to be used as a callback for a button next to a text entry box,
   which, when clicked, pops up this dialog to allow you to construct a
   display filter by browsing the list of saved filters and/or by adding
   test expressions constructed with another dialog.  The "OK" button
   sets the text entry box to the constructed filter and activates that
   text entry box, causing the filter to be used; this dialog is then
   dismissed.

   If "wants_apply_button" is non-null, we add an "Apply" button that
   acts like "OK" but doesn't dismiss this dialog. */
void
display_filter_construct(win32_element_t *btn_el, win32_element_t *parent_filter_el, gpointer construct_args_ptr)
{
    construct_args_t *construct_args = construct_args_ptr;
    win32_element_t *filter_browse_dlg;

    /* Has a filter dialog box already been opened for the button? */
    filter_browse_dlg = win32_element_get_data(btn_el, E_FILT_DIALOG_PTR_KEY);

    if (filter_browse_dlg != NULL) {
	/* Yes.  Just re-activate that dialog box. */
	SetActiveWindow(filter_browse_dlg->h_wnd);
	return;
    }

    /* Now create a new dialog, possibly with an "Apply" button, and
       definitely with an "Add Expression..." button. */
    filter_browse_dlg = filter_dialog_new(btn_el, parent_filter_el,
	DFILTER_LIST, construct_args);
}

/* Should be called when a button that creates filters is destroyed; it
   destroys any filter dialog created by that button. */
void
filter_button_destroy(win32_element_t *btn_el)
{
    win32_element_t *filter_dlg;

    /* Is there a filter edit/selection dialog associated with this
       button? */
    filter_dlg = win32_element_get_data(btn_el, E_FILT_DIALOG_PTR_KEY);

    if (filter_dlg != NULL) {
	/* Yes.  Break the association, and destroy the dialog. */
	win32_element_set_data(btn_el, E_FILT_DIALOG_PTR_KEY, NULL);
	win32_element_destroy(filter_dlg, TRUE);
    }
}


#ifdef HAVE_LIBPCAP
static win32_element_t *global_cfilter_dlg = NULL;

/* Create a filter dialog for editing capture filters; this is to be used
   as a callback for menu items, toolbars, etc.. */
void
cfilter_dialog() {
    /* No Apply button, and there's no text widget to set, much less
       activate, on "OK". */
    static construct_args_t args = {
	"Ethereal: Capture Filter",
	FALSE,
	FALSE
    };

    /* Has a filter dialog box already been opened for editing
       capture filters? */
    if (global_cfilter_dlg != NULL) {
	/* Yes.  Just reactivate it. */
	SetActiveWindow(global_cfilter_dlg->h_wnd);
	return;
    }

    /*
     * No.  Create one; we didn't pop this up as a result of pressing
     * a button next to some text entry field, so don't associate it
     * with a text entry field or button.
     */
    global_cfilter_dlg = filter_dialog_new(NULL, NULL, CFILTER_LIST, &args);
}
#endif

/* Create a filter dialog for editing display filters; this is to be used
   as a callback for menu items, toolbars, etc.. */
void
dfilter_dialog() {
        static construct_args_t args = {
                "Ethereal: Display Filter",
                TRUE,
                TRUE
        };

    display_filter_construct(win32_element_hwnd_get_data(g_hw_mainwin, E_FILT_BT_PTR_KEY), NULL, &args);
}

/* List of capture filter dialogs, so that if the list of filters changes
  (the model, if you will), we can update all of their lists displaying
   the filters (the views). */
static GList *cfilter_dialogs;

/* List of display filter dialogs, so that if the list of filters changes
  (the model, if you will), we can update all of their lists displaying
   the filters (the views). */
static GList *dfilter_dialogs;

static void
remember_filter_dialog(win32_element_t *main_w, GList **filter_dialogs)
{
    *filter_dialogs = g_list_append(*filter_dialogs, main_w);
}

/* Remove a filter dialog from the specified list of filter_dialogs. */
static void
forget_filter_dialog(win32_element_t *main_w, filter_list_type_t list)
{
    switch (list) {

    case CFILTER_LIST:
	cfilter_dialogs = g_list_remove(cfilter_dialogs, main_w);
	break;

    case DFILTER_LIST:
	dfilter_dialogs = g_list_remove(dfilter_dialogs, main_w);
	break;

    default:
	g_assert_not_reached();
	break;
    }
}

/* Get the dialog list corresponding to a particular filter list. */
static GList *
get_filter_dialog_list(filter_list_type_t list)
{
    switch (list) {

    case CFILTER_LIST:
	return cfilter_dialogs;

    case DFILTER_LIST:
	return dfilter_dialogs;

    default:
	g_assert_not_reached();
	return NULL;
    }
}

static win32_element_t *
filter_dialog_new(win32_element_t *btn_el, win32_element_t *parent_filter_tb,
	filter_list_type_t list, construct_args_t *construct_args) {
    win32_element_t *filter_dlg;
    HWND             hw_filter, parent = g_hw_mainwin;
    win32_element_t *filter_l, *expr_btn, *apply_btn, *ok_btn;
    SIZE             sz;

    GList      *fl_entry;
    filter_def *filt;
    static filter_list_type_t cfilter_list_type = CFILTER_LIST;
    static filter_list_type_t dfilter_list_type = DFILTER_LIST;
    filter_list_type_t *filter_list_type_p;
    GList       **filter_dialogs;
    const gchar *filter_te_str = NULL;
    gint row;

    /* Get a pointer to a static variable holding the type of filter on
       which we're working, so we can pass that pointer to callback
       routines. */
    switch (list) {
	case CFILTER_LIST:
	    filter_dialogs = &cfilter_dialogs;
	    filter_list_type_p = &cfilter_list_type;
	    break;
	case DFILTER_LIST:
	    filter_dialogs = &dfilter_dialogs;
	    filter_list_type_p = &dfilter_list_type;
	    break;
	default:
	    g_assert_not_reached();
	    filter_dialogs = NULL;
	    filter_list_type_p = NULL;
	    break;
    }

    if (btn_el) parent = btn_el->h_wnd;
    hw_filter = filter_dialog_dialog_create(parent);
    filter_dlg = (win32_element_t *) GetWindowLong(hw_filter, GWL_USERDATA);
    SetWindowText(hw_filter, construct_args->title);
    filter_dlg->destroy = filter_dlg_destroy;
    win32_element_set_data(filter_dlg, E_FILT_BUTTON_PTR_KEY, btn_el);
    win32_element_set_data(filter_dlg, E_FILT_LIST_TYPE, (gpointer) list);
    win32_element_set_data(filter_dlg, E_FILT_CONSTRUCT_ARGS_KEY, construct_args);

    /* Make sure everything is set up */
    if (parent_filter_tb)
	filter_te_str = win32_textbox_get_text(parent_filter_tb);

    filter_l = win32_element_find_child(filter_dlg, "filter-dialog.filter.filterlist");
    win32_element_assert(filter_l);
    win32_element_set_data(filter_l, E_FILT_PARENT_FILTER_TE_KEY, parent_filter_tb);
    win32_element_set_data(filter_l, E_FILT_DBLACTIVATE_KEY,
	    construct_args->activate_on_ok ? "" : NULL);

    win32_get_text_size(filter_l->h_wnd, "A long filter name", &sz);
    filter_l->minwidth = sz.cx * 2;
    filter_l->minheight = sz.cy * 15;

    fl_entry = get_filter_list_first(list);
    while (fl_entry != NULL) {
	filt = (filter_def *) fl_entry->data;

	row = win32_listbox_add_item(filter_l, -1, NULL, filt->name);
	win32_listbox_set_row_data(filter_l, row, fl_entry);

	if (filter_te_str && filt->strval) {
	    if (strcmp(filter_te_str, filt->strval) == 0) {
		win32_listbox_set_selected(filter_l, row);
	    }
	}
	fl_entry = fl_entry->next;
    }

    /* Unlike the GTK code, we have to go in and hide the expression, apply, and OK buttons. */
    if (list != DFILTER_LIST) {
	expr_btn = win32_element_find_child(filter_dlg, "filter-dialog.expression");
	ShowWindow(expr_btn->h_wnd, SW_HIDE);
    }

    apply_btn = win32_element_find_child(filter_dlg, "filter-dialog.apply");
    ok_btn = win32_element_find_child(filter_dlg, "filter-dialog.ok");

    if (parent_filter_tb != NULL) {
        if (!construct_args->wants_apply_button) {
	    ShowWindow(apply_btn->h_wnd, SW_HIDE);
	}
    } else {
	if (construct_args->wants_apply_button) {
	    ShowWindow(ok_btn->h_wnd, SW_HIDE);
	} else {
	    ShowWindow(apply_btn->h_wnd, SW_HIDE);
	    ShowWindow(ok_btn->h_wnd, SW_HIDE);
	}
    }

    // Remove the oncommands for any disabled buttons
    // Make the OK button the default

    remember_filter_dialog(filter_dlg, filter_dialogs);

    filter_dialog_dialog_show(filter_dlg->h_wnd);

    return filter_dlg;
}

BOOL CALLBACK
filter_dialog_dlg_proc(HWND hw_cf, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;

    switch(msg) {
	case WM_INITDIALOG:
	    filter_dialog_handle_wm_initdialog(hw_cf);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_cf, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    return 0;
	    break;
	case WM_COMMAND:
	    return 0;
	    break;
	case WM_CLOSE:
	    dlg_box = (win32_element_t *) GetWindowLong(hw_cf, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    win32_element_destroy(dlg_box, TRUE);
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}


/* Command sent by <listbox> id "filter-dialog.filter.filterlist" */
void filter_dialog_list_select (win32_element_t *listbox, LPNMLISTVIEW nmlv) {
    win32_element_t *filter_tb = win32_element_find_in_window(listbox, "filter-dialog.filter");
    win32_element_t *name_tb = win32_element_find_in_window(listbox, "filter-dialog.name");
    win32_element_t *del_bt = win32_element_find_in_window(listbox, "filter-dialog.edit.delete");
    GList           *flp;
    filter_def      *filt;
    gchar           *name = NULL, *strval = NULL;
    gboolean         enabled = FALSE;

    win32_element_assert(filter_tb);
    win32_element_assert(name_tb);
    win32_element_assert(del_bt);

    flp = win32_listbox_get_row_data(listbox, nmlv->iItem);

    if (flp && win32_listbox_get_selected(listbox) >= 0) {
	filt    = (filter_def *) flp->data;
	name    = g_strdup(filt->name);
	strval  = g_strdup(filt->strval);
	enabled = TRUE;

	if (! in_tb_update) {
	    win32_textbox_set_text(name_tb, name);
	    win32_textbox_set_text(filter_tb, strval);
	}
    } else {
	win32_textbox_set_text(name_tb, "");
	win32_textbox_set_text(filter_tb, "");
    }


    win32_element_set_enabled(del_bt, enabled);

    if (name) g_free(name);
    if (strval) g_free(strval);
}

/* Command sent by element type <button>, id "filter-dialog.close" */
void filter_dialog_close (win32_element_t *btn_el) {
    win32_element_t *dlg = win32_element_find_in_window(btn_el, "filter-dialog");

    win32_element_destroy(dlg, TRUE);
}

static void
delete_filter_cb(gpointer data, gpointer user_data) {
    win32_element_t      *dlg = data;
    win32_element_t      *filter_l = win32_element_find_child(dlg, "filter-dialog.filter.filterlist");
    gint                  pos = (gint) user_data;

    win32_listbox_delete_item(filter_l, pos);
}

/* Command sent by element type <button>, id "filter-dialog.edit.delete" */
void filter_dialog_delete_filter (win32_element_t *btn_el) {
    win32_element_t   *dlg = win32_element_find_in_window(btn_el, "filter-dialog");
    win32_element_t   *filter_l;
    filter_list_type_t list;
    GList             *fl_entry = NULL;
    gint               pos;

    win32_element_assert(dlg);

    filter_l = win32_element_find_child(dlg, "filter-dialog.filter.filterlist");
    win32_element_assert(filter_l);

    list = (filter_list_type_t) win32_element_get_data(dlg, E_FILT_LIST_TYPE);

    pos = win32_listbox_get_selected(filter_l);

    if (pos >= 0) {
	fl_entry = win32_listbox_get_row_data(filter_l, pos);

	if (fl_entry) {
	    /* Remove the entry from the filter list. */
	    remove_from_filter_list(list, fl_entry);

	    /* Update all the filter list widgets, not just the one in
	       the dialog box in which we clicked on "Delete". */
	    g_list_foreach(get_filter_dialog_list(list), delete_filter_cb, (gpointer) pos);
	}
    }
}

/* Command sent by element type <button>, id "filter-dialog.expression" */
void filter_dialog_expression (win32_element_t *btn_el) {
}

/* Command sent by element type <button>, id "filter-dialog.help" */
void filter_dialog_help (win32_element_t *btn_el) {
}

/* Structure containing arguments to be passed to "new_filter_cb()".

   "active_filter_l" is the list in the dialog box in which "New" or
   "Copy" was clicked; in that dialog box, but not in any other dialog
   box, we select the newly created list item.

   "nflp" is the GList member in the model (filter list) for the new
   filter. */
/* XXX - Copied from gtk/filter_dlg.c */
typedef struct {
    win32_element_t *active_filter_l;
    GList           *nflp;
} new_filter_cb_args_t;

static void
new_filter_cb(gpointer data, gpointer user_data) {
    win32_element_t      *dlg = data;
    win32_element_t      *filter_l = win32_element_find_child(dlg, "filter-dialog.filter.filterlist");
    new_filter_cb_args_t *args = user_data;
    filter_def           *nfilt = args->nflp->data;
    gint                  row;

    win32_element_assert(filter_l);

    row = win32_listbox_add_item(filter_l, -1, NULL, nfilt->name);
    win32_listbox_set_row_data(filter_l, row, args->nflp);
    win32_listbox_set_selected(filter_l, row);
}

/* Command sent by element type <button>, id "filter-dialog.edit.new" */
void filter_dialog_new_filter (win32_element_t *btn_el) {
    win32_element_t     *dlg = win32_element_find_in_window(btn_el, "filter-dialog");
    win32_element_t     *filter_l, *filter_tb, *name_tb;
    gchar               *name = NULL, *strval = NULL;
    filter_list_type_t   list;
    GList               *fl_entry;
    new_filter_cb_args_t args;

    win32_element_assert(dlg);

    filter_l = win32_element_find_child(dlg, "filter-dialog.filter.filterlist");
    win32_element_assert(filter_l);

    filter_tb = win32_element_find_in_window(filter_l, "filter-dialog.filter");
    win32_element_assert(filter_tb);

    name_tb = win32_element_find_in_window(filter_l, "filter-dialog.name");
    win32_element_assert(name_tb);

    list = (filter_list_type_t) win32_element_get_data(dlg, E_FILT_LIST_TYPE);

    name = win32_textbox_get_text(name_tb);
    strval = win32_textbox_get_text(filter_tb);

    if (name == NULL || name[0] == '\0') {
	g_free(name);
	name = g_strdup("new");
    }
    if (strval == NULL || strval[0] == '\0') {
	g_free(strval);
	strval = g_strdup("new");
    }

    /* Add a new entry to the filter list. */
    fl_entry = add_to_filter_list(list, name, strval);
    if (name) g_free(name);
    if (strval) g_free(strval);

    /* Update all the filter list widgets, not just the one in
       the dialog box in which we clicked on "Copy". */
    args.active_filter_l = filter_l;
    args.nflp = fl_entry;
    g_list_foreach(get_filter_dialog_list(list), new_filter_cb, &args);
}


/* Command sent by element type <button>, id "filter_dialog.apply" */
void filter_dialog_apply (win32_element_t *btn_el) {
    filter_apply(btn_el, FALSE);
}

/* Command sent by element type <button>, id "filter_dialog.ok" */
void filter_dialog_ok (win32_element_t *btn_el) {
    filter_apply(btn_el, TRUE);
}

/* Command sent by element type <button>, id "filter_dialog.save" */
void filter_dialog_save (win32_element_t *btn_el) {
    win32_element_t   *dlg = win32_element_find_in_window(btn_el, "filter-dialog");
    filter_list_type_t list;
    char              *pf_dir_path;
    char              *f_path;
    int                f_save_errno;
    char              *filter_type;

    win32_element_assert(dlg);

    list = (filter_list_type_t) win32_element_get_data(dlg, E_FILT_LIST_TYPE);

    /* Create the directory that holds personal configuration files,
       if necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "Can't create directory\n\"%s\"\nfor filter files: %s.",
	    pf_dir_path, strerror(errno));
	g_free(pf_dir_path);
	return;
    }

    save_filter_list(list, &f_path, &f_save_errno);
    if (f_path != NULL) {
	/* We had an error saving the filter. */
	switch (list) {
	    case CFILTER_LIST:
		filter_type = "capture";
		break;
	    case DFILTER_LIST:
		filter_type = "display";
		break;
	    default:
		g_assert_not_reached();
		filter_type = NULL;
		break;
	}
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
	    "Could not save to your %s filter file\n\"%s\": %s.",
	    filter_type, f_path, strerror(f_save_errno));
	g_free(f_path);
    }
}

/* Command sent by <listbox> id "filter-dialog.filter.filterlist" */
void filter_dialog_list_dclick (win32_element_t *listbox, LPNMLISTVIEW nmlv) {
    win32_element_t *parent_filter_tb = win32_element_get_data(listbox, E_FILT_PARENT_FILTER_TE_KEY);
    GList           *flp;
    filter_def      *filt;

    /*
     * Do we have a text entry widget associated with this dialog
     * box, and is one of the filters in the list selected?
     */
    if (parent_filter_tb != NULL && nmlv->iItem >= 0) {
	/*
	 * Yes.  Is there a filter definition for that filter?
	 */
	flp = win32_listbox_get_row_data(listbox, nmlv->iItem);
	if (flp != NULL) {
	    filt = (filter_def *) flp->data;
	    SetWindowText(parent_filter_tb->h_wnd, filt->strval);
	    /*
	     * Are we supposed to cause the filter we
	     * put there to be applied?
	     */
	    if (win32_element_get_data(listbox, E_FILT_PARENT_FILTER_TE_KEY) != NULL) {
		if (parent_filter_tb->oncommand) {
		    parent_filter_tb->oncommand(parent_filter_tb);
		}
	    }
	}
    }
    filter_dialog_close(listbox);
}


static void
chg_filter_cb(gpointer data, gpointer user_data) {
    win32_element_t *dlg = data;
    win32_element_t *filter_l = win32_element_find_child(dlg, "filter-dialog.filter.filterlist");
    gint             count, i;
    GList           *flp;
    filter_def      *filt;

    win32_element_assert(filter_l);

    count = win32_listbox_get_row_count(filter_l);

    for (i = 0; i < count; i++) {
	flp = win32_listbox_get_row_data(filter_l, i);
	if (flp) {
	    filt = flp->data;
	    if (filt) {
		in_tb_update = TRUE;
		win32_listbox_set_text(filter_l, i, 0, filt->name);
		in_tb_update = FALSE;
	    }
	}
    }
}

/* Command sent by element type <textbox>, id "filter-dialog.filter" */
void filter_dialog_name_changed (win32_element_t *name_tb) {
    win32_element_t   *dlg = win32_element_find_in_window(name_tb, "filter-dialog");
    win32_element_t   *filter_l, *filter_tb;
    GList             *flp;
    filter_def        *filt;
    gchar             *name = NULL, *strval = NULL;
    gint               sel;
    filter_list_type_t list;

    win32_element_assert(dlg);

    filter_l = win32_element_find_child(dlg, "filter-dialog.filter.filterlist");
    win32_element_assert(filter_l);

    filter_tb = win32_element_find_in_window(filter_l, "filter-dialog.filter");
    win32_element_assert(filter_tb);

    list = (filter_list_type_t) win32_element_get_data(dlg, E_FILT_LIST_TYPE);

    name = win32_textbox_get_text(name_tb);
    strval = win32_textbox_get_text(filter_tb);

    sel = win32_listbox_get_selected(filter_l);
    flp = win32_listbox_get_row_data(filter_l, sel);

    if (flp && sel >= 0) {
	filt = (filter_def *) flp->data;
	if (strcmp(filt->name, name) != 0) {
	    g_free(filt->name);
	    g_free(filt->strval);
	    filt->name   = g_strdup(name);
	    filt->strval = g_strdup(strval);
	    /* Update all the filter list widgets, not just the one in
	       the dialog box in which we clicked on "Copy". */
	    g_list_foreach(get_filter_dialog_list(list), chg_filter_cb, NULL);
	}
    }
    g_free(name);
    g_free(strval);
}

/* Command sent by element type <textbox>, id "filter-dialog.filter" */
void filter_dialog_filter_changed (win32_element_t *filter_tb) {
    win32_element_t   *dlg = win32_element_find_in_window(filter_tb, "filter-dialog");
    filter_list_type_t list;

    win32_element_assert(dlg);

    list = (filter_list_type_t) win32_element_get_data(dlg, E_FILT_LIST_TYPE);

    /* XXX - We should probably update all of the other open display filter
       dialogs, like we do with the other callbacks. */
    if (DFILTER_LIST == list) {
	/* colorize filter string entry */
	filter_tb_syntax_check(filter_tb->h_wnd, NULL);
    }

}

/* XXX - The only reason for the "filter_text" parameter is to be able to feed
 * in the "real" filter string in the case of a CBN_SELCHANGE notification message.
 */
void
filter_tb_syntax_check(HWND hwnd, gchar *filter_text) {
    gchar     *strval = NULL;
    gint       len;
    dfilter_t *dfp;

    /* If filter_text is non-NULL, use it.  Otherwise, grab the text from
     * the window */
    if (filter_text) {
	strval = g_strdup(filter_text);
	len = lstrlen(filter_text);
    } else {
	len = GetWindowTextLength(hwnd);
	if (len > 0) {
	    len++;
	    strval = g_malloc(len);
	    GetWindowText(hwnd, strval, len);
	}
    }

    if (len == 0) {
	/* Default window background */
	SendMessage(hwnd, EM_SETBKGNDCOLOR, (WPARAM) 1, COLOR_WINDOW);
	return;
    } else if (dfilter_compile(strval, &dfp)) {	/* colorize filter string entry */
	if (dfp != NULL)
	    dfilter_free(dfp);
	/* Valid (light green) */
	SendMessage(hwnd, EM_SETBKGNDCOLOR, 0, 0x00afffaf);
    } else {
	/* Invalid (light red) */
	SendMessage(hwnd, EM_SETBKGNDCOLOR, 0, 0x00afafff);
    }

    if (strval) g_free(strval);
}

/*
 * Private functions
 */

static void
filter_apply(win32_element_t *btn_el, gboolean destroy) {
    win32_element_t  *dlg = win32_element_find_in_window(btn_el, "filter-dialog");
    win32_element_t  *filter_l, *parent_filter_tb, *filter_tb;
    construct_args_t *construct_args;
    gchar            *filter_string;

    win32_element_assert(dlg);

    filter_l = win32_element_find_child(dlg, "filter-dialog.filter.filterlist");
    win32_element_assert(filter_l);

    construct_args = win32_element_get_data(dlg, E_FILT_CONSTRUCT_ARGS_KEY);
    parent_filter_tb = win32_element_get_data(filter_l, E_FILT_PARENT_FILTER_TE_KEY);

    if (parent_filter_tb != NULL) {
	/*
	 * We have a text entry widget associated with this dialog
	 * box; put the filter in our text entry widget into that
	 * text entry widget.
	 */
	filter_tb = win32_element_find_child(dlg, "filter-dialog.filter");
	win32_element_assert(filter_tb);

	filter_string = win32_textbox_get_text(filter_tb);
	SetWindowText(parent_filter_tb->h_wnd, filter_string);
	g_free(filter_string);
    }

    if (destroy) {
	win32_element_destroy(dlg, TRUE);
    }

    if (parent_filter_tb != NULL && parent_filter_tb->oncommand != NULL) {
	/*
	 * We have a text entry widget associated with this dialog
	 * box; activate that widget to cause the filter we put
	 * there to be applied if we're supposed to do so.
	 *
	 * We do this after dismissing the filter dialog box,
	 * as activating the widget the dialog box to which
	 * it belongs to be dismissed, and that may cause it
	 * to destroy our dialog box if the filter succeeds.
	 * This means that our subsequent attempt to destroy
	 * it will fail.
	 *
	 * We don't know whether it'll destroy our dialog box,
	 * so we can't rely on it to do so.  Instead, we
	 * destroy it ourselves, which will clear the
	 * E_FILT_DIALOG_PTR_KEY pointer for their dialog box,
	 * meaning they won't think it has one and won't try
	 * to destroy it.
	 */
	parent_filter_tb->oncommand(parent_filter_tb);
    }
}


static void
filter_dlg_destroy(win32_element_t *dlg, gboolean destroy_window) {
    filter_list_type_t list;
    win32_element_t   *btn_el;

    win32_element_assert(dlg);

    btn_el = win32_element_get_data(dlg, E_FILT_BUTTON_PTR_KEY);
    list = (filter_list_type_t) win32_element_get_data(dlg, E_FILT_LIST_TYPE);

    /* Get the button that requested that we be popped up, if any.
       (It should arrange to destroy us if it's destroyed, so
       that we don't get a pointer to a non-existent window here.) */
    if (btn_el != NULL) {
	win32_element_set_data(btn_el, E_FILT_DIALOG_PTR_KEY, NULL);
    } else {
	switch (list) {
#ifdef HAVE_LIBPCAP
	    case CFILTER_LIST:
		g_assert(dlg == global_cfilter_dlg);
		global_cfilter_dlg = NULL;
		break;
#endif
	    default:
		g_assert_not_reached();
		break;
	}
    }
    forget_filter_dialog(dlg, list);
}
