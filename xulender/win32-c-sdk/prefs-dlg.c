
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "globals.h"
#include "glib.h"
#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>

#include <pcap.h>
#include "pcap-util.h"

#include <epan/column.h>
#include <epan/filesystem.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include "print.h"
#include "epan/addr_resolv.h"
#include "capture-wpcap.h"
#include "simple_dialog.h"

#include "win32-c-sdk.h"
#include "ethereal-win32.h"

#include "win32-globals.h"
#include "win32-menu.h"
#include "win32-util.h"

#include "color.h"
#include "color_filters.h"
#include "capture_combo_utils.h"
#include "font-util.h"

#include "preferences-dialog.h"

/* XXX - We should split this file into column_prefs.c, stream_prefs.c, etc.
 * like GTK version. */
static void gui_prefs_init(win32_element_t *prefs_dlg);
static void column_prefs_init(win32_element_t *prefs_dlg);
static void font_prefs_init(win32_element_t *prefs_dlg);
static void color_prefs_init(win32_element_t *prefs_dlg);
static void capture_prefs_init(win32_element_t *prefs_dlg);
static void printer_prefs_init(win32_element_t *prefs_dlg);
static void nameres_prefs_init(win32_element_t *prefs_dlg);
static void protocol_prefs_init(win32_element_t *prefs_dlg);
static int CALLBACK font_style_enum_proc(ENUMLOGFONTEX *lpelfe, NEWTEXTMETRICEX *lpntme,
    int font_type, LPARAM l_param);
static int CALLBACK font_size_enum_proc(ENUMLOGFONTEX *lpelfe, NEWTEXTMETRICEX *lpntme,
    int font_type, LPARAM l_param);
static void show_font_selection();
static void set_sample_colors();
static void prefs_main_fetch_all(gboolean *must_redissect);
static void prefs_main_apply_all();
static void toggle_column_buttons(int cur_sel);
static guint module_prefs_revert(module_t *module, gpointer user_data);

typedef struct _module_data_t {
    win32_element_t *tree;
    win32_element_t *deck;
} module_data_t;

typedef struct _menulist_val_map {
    gchar *name;
    gint  *val;
} menulist_val_map;

typedef struct _checkbox_val_map {
    gchar    *name;
    gboolean *val;
} checkbox_val_map;

typedef struct _radio_val_t {
    gchar *name;
    gint   val;
} radio_val_t;

typedef struct _textbox_val_map {
    gchar  *name;
    gchar **val;
} textbox_val_map;

typedef struct _spinner_val_map {
    gchar    *name;
    gint     *val;
    gint      low;
    gint      high;
} spinner_val_map;

/* From gtk/stream_prefs.c */
#define SAMPLE_MARKED_TEXT "Sample marked packet text\n"
#define SAMPLE_CLIENT_TEXT "Sample TCP stream client text\n"
#define SAMPLE_SERVER_TEXT "Sample TCP stream server text\n"
#define MFG_IDX 0
#define MBG_IDX 1
#define CFG_IDX 2
#define CBG_IDX 3
#define SFG_IDX 4
#define SBG_IDX 5
#define MAX_IDX 6 /* set this to the number of IDX values */

#define NAMRES_MAX_CONCURRENCY 100000

static color_t  tcolors[MAX_IDX];
static HFONT    old_r_font = NULL;
static gboolean font_changed;
static e_prefs  saved_prefs, tmp_prefs;

static menulist_val_map gui_ml_map[] = {
    { "prefs.gui_plist_sel_browse",             &tmp_prefs.gui_plist_sel_browse },
    { "prefs.gui_ptree_sel_browse",             &tmp_prefs.gui_ptree_sel_browse },
    { "prefs.gui_hex_dump_highlight_style",     &tmp_prefs.gui_hex_dump_highlight_style },
    { "prefs.gui_toolbar_main_style",           &tmp_prefs.gui_toolbar_main_style },
    { "prefs.filter_toolbar_show_in_statusbar", &tmp_prefs.filter_toolbar_show_in_statusbar },
    { "prefs.gui_console_open",                 &tmp_prefs.gui_console_open },
    { NULL,                                     NULL }
};

static checkbox_val_map gui_cb_map[] = {
    { "prefs.gui_geometry_save_position",  &tmp_prefs.gui_geometry_save_position },
    { "prefs.gui_geometry_save_size",      &tmp_prefs.gui_geometry_save_size },
    { "prefs.gui_geometry_save_maximized", &tmp_prefs.gui_geometry_save_maximized },
    { NULL,                                NULL }
};

static radio_val_t gui_fs_radio_vals[] = {
    { "prefs.gui_fo_style_last_opened", FO_STYLE_LAST_OPENED, },
    { "prefs.gui_fo_style_specified",   FO_STYLE_SPECIFIED,   },
    { NULL,                             0 }
};

static textbox_val_map gui_tb_map[] = {
    { "prefs.gui_fileopen_dir", &tmp_prefs.gui_fileopen_dir },
    { NULL,                     NULL }
};

static spinner_val_map gui_sp_map[] = {
    { "prefs.gui_recent_files_count_max", &tmp_prefs.gui_recent_files_count_max, 0, 50 },
    { NULL,                               NULL,                              0, 0}
};

static checkbox_val_map capture_cb_map[] = {
    { "prefs.capture_prom_mode",   &tmp_prefs.capture_prom_mode },
    { "prefs.capture_real_time",   &tmp_prefs.capture_real_time },
    { "prefs.capture_auto_scroll", &tmp_prefs.capture_auto_scroll },
    { "prefs.capture_show_info",   &tmp_prefs.capture_show_info },
    { NULL,                        NULL }
};

static radio_val_t print_format_radio_vals[] = {
    { "prefs.pr_format_plain", PR_FMT_TEXT, },
    { "prefs.pr_format_ps",    PR_FMT_PS,   },
    { NULL,                    0 }
};

static radio_val_t print_dest_radio_vals[] = {
    { "prefs.pr_dest_printer", PR_DEST_CMD,  },
    { "prefs.pr_dest_file",    PR_DEST_FILE, },
    { NULL,                    0 }
};


/* Create the dialog (if needed), initialize its controls, and display it */
void
prefs_dialog_init(HWND parent) {
    HWND             hw_prefs;
    win32_element_t *prefs_dlg = win32_identifier_get_str("preferences-dialog");

    if (! prefs_dlg) {
	hw_prefs = preferences_dialog_dialog_create(parent);
	prefs_dlg = (win32_element_t *) GetWindowLong(hw_prefs, GWL_USERDATA);

	copy_prefs(&saved_prefs, &prefs);

	/* XXX - We use tmp_prefs so that we can feed a const to the various
	 * gui_*_map structs above.  Is there a way we can use "prefs" directly?
	 */
	copy_prefs(&tmp_prefs, &prefs);

	/* Load our prefs */
	gui_prefs_init(prefs_dlg);
	column_prefs_init(prefs_dlg);
	font_prefs_init(prefs_dlg);
	color_prefs_init(prefs_dlg);
	capture_prefs_init(prefs_dlg);
	printer_prefs_init(prefs_dlg);
	nameres_prefs_init(prefs_dlg);
	protocol_prefs_init(prefs_dlg);
    } else {
	win32_element_assert(prefs_dlg);
	hw_prefs = prefs_dlg->h_wnd;
    }
    preferences_dialog_dialog_show(hw_prefs);
}

/* Command sent by element type <button>, id "prefs-dialog.ok" */
void
prefs_dialog_ok (win32_element_t *ok_el) {
    win32_element_t *pd_el = win32_identifier_get_str("preferences-dialog");
    gboolean must_redissect = FALSE;

    prefs_main_fetch_all(&must_redissect);

    prefs_main_apply_all();

    win32_element_assert(pd_el);
    win32_element_destroy(pd_el, TRUE);

    if (must_redissect) {
	redissect_packets(&cfile);
    }
}

/* Command sent by element type <button>, id "prefs-dialog.apply" */
void
prefs_dialog_apply (win32_element_t *apply_el) {
    gboolean must_redissect = FALSE;

    prefs_main_fetch_all(&must_redissect);

    prefs_main_apply_all();

    if (must_redissect) {
	/* Redissect all the packets, and re-evaluate the display filter. */
	redissect_packets(&cfile);
    }
}

/* Command sent by element type <button>, id "prefs-dialog.save" */
void
prefs_dialog_save (win32_element_t *save_el) {
    gboolean must_redissect = FALSE;
    int      err;
    char    *pf_dir_path, *pf_path;

    prefs_main_fetch_all(&must_redissect);

    /* Create the directory that holds personal configuration files, if
       necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Can't create directory\n\"%s\"\nfor preferences file: %s.", pf_dir_path,
		strerror(errno));
	g_free(pf_dir_path);
    } else {
	/* Write the preferencs out. */
	err = write_prefs(&pf_path);
	if (err != 0) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Can't open preferences file\n\"%s\": %s.", pf_path,
		    strerror(err));
	    g_free(pf_path);
	}
    }

    /* Now apply those preferences.
       XXX - should we do this?  The user didn't click "OK" or "Apply".
       However:

          1) by saving the preferences they presumably indicate that they
             like them;

          2) the next time they fire Ethereal up, those preferences will
             apply;

          3) we'd have to buffer "must_redissect" so that if they do
             "Apply" after this, we know we have to redissect;

          4) we did apply the protocol preferences, at least, in the past. */
    prefs_main_apply_all();

    if (must_redissect) {
	/* Redissect all the packets, and re-evaluate the display filter. */
	redissect_packets(&cfile);
    }
}

/* Command sent by element type <button>, id "prefs-dialog.cancel" */
void
prefs_dialog_cancel (win32_element_t *cancel_el) {
    win32_element_t *pd_el = win32_identifier_get_str("preferences-dialog");
    gboolean         must_redissect = FALSE;

    win32_element_assert(pd_el);

    /* Free up the current preferences and copy the saved preferences to the
       current preferences. */
    free_prefs(&prefs);
    copy_prefs(&prefs, &saved_prefs);

    /* Now revert the registered preferences. */
    prefs_modules_foreach(module_prefs_revert, &must_redissect);

    /* Now apply the reverted-to preferences. */
    prefs_main_apply_all();

    win32_element_destroy(pd_el, TRUE);

    if (must_redissect) {
	/* Redissect all the packets, and re-evaluate the display filter. */
	redissect_packets(&cfile);
    }
}

#define PREFS_DLG_ID_PREFIX "prefs-dialog."
void
prefs_tree_select (win32_element_t *tree_el, NMTREEVIEW *tv_sel) {
    tree_row        *row;
    gchar           *panel_id;
    win32_element_t *deck, *panel;
    gint             offset = strlen(PREFS_DLG_ID_PREFIX);

    win32_element_assert(tree_el);

    deck = win32_identifier_get_str("prefs-dialog.deck");
    win32_element_assert(deck);

    row = (tree_row *) tv_sel->itemNew.lParam;
    g_assert(row != NULL);
    g_assert(row->id != NULL);
    panel_id = g_strdup(row->id);
    g_assert(strlen(panel_id) > offset + strlen("tree."));

    memcpy(panel_id + offset, "deck", 4);
    panel = win32_identifier_get_str(panel_id);

    if (panel != NULL) {
	win32_deck_set_selectedpanel(deck, panel);
    }
    g_free(panel_id);
}

void
prefs_col_list_select(win32_element_t *listbox, LPNMLISTVIEW nmlv) {
    win32_element_t *col_tb, *col_ml;
    int              sel_item;
    fmt_data        *cfmt;
    gboolean         enabled = FALSE;

    col_tb = win32_identifier_get_str("prefs-dialog.cols.title");
    win32_element_assert(col_tb);

    col_ml = win32_identifier_get_str("prefs-dialog.cols.format");
    win32_element_assert(col_ml);

    sel_item = ListView_GetNextItem(nmlv->hdr.hwndFrom, -1, LVNI_SELECTED);
    toggle_column_buttons(sel_item);

    cfmt = (fmt_data *) win32_listbox_get_row_data(listbox, sel_item);
    if (sel_item >= 0 && nmlv->uNewState & LVIS_SELECTED && cfmt != NULL) {
	win32_textbox_set_text(col_tb, cfmt->title);
	sel_item = get_column_format_from_str(cfmt->fmt);
	win32_menulist_set_selection(col_ml, sel_item);
	enabled = TRUE;
    }
}

void
prefs_font_name_list_select(win32_element_t *listbox, LPNMLISTVIEW nmlv) {
    win32_element_t *name_tb, *style_lb, *size_lb;
    int              sel_name, row = 0;
    LVITEM           item;
    gchar            font_name[LF_FULLFACESIZE];
    LOGFONT          lfinfo;
    HDC              hdc;
    gpointer         row_data;

    name_tb = win32_identifier_get_str("prefs-dialog.font.tb.name");
    win32_element_assert(name_tb);

    style_lb = win32_identifier_get_str("prefs-dialog.font.lb.style");
    win32_element_assert(style_lb);

    size_lb = win32_identifier_get_str("prefs-dialog.font.lb.size");
    win32_element_assert(size_lb);

    sel_name = ListView_GetNextItem(nmlv->hdr.hwndFrom, -1, LVNI_SELECTED);
    if (sel_name >= 0 && nmlv->uNewState & LVIS_SELECTED) {
	ZeroMemory(&item, sizeof(item));
	item.mask = LVIF_TEXT;
	item.iItem = sel_name;
	item.iSubItem = 0;
	item.pszText = font_name;
	item.cchTextMax = LF_FULLFACESIZE;
	ListView_GetItem(nmlv->hdr.hwndFrom, &item);
	win32_textbox_set_text(name_tb, font_name);

        ZeroMemory(&lfinfo, sizeof(lfinfo));
	lfinfo.lfCharSet        = ANSI_CHARSET;  /* XXX - Do we need to be this restrictive? */
	lstrcpyn(lfinfo.lfFaceName, font_name, LF_FACESIZE);
	lfinfo.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;

	if (style_lb != NULL) {
	    for (row = 0; row < win32_listbox_get_row_count(style_lb); row++) {
		row_data = win32_listbox_get_row_data(style_lb, row);
		if (row_data) {
		    g_free(row_data);
		}
	    }
	    win32_listbox_clear(style_lb);
	}
	if (size_lb != NULL) {
	    win32_listbox_clear(size_lb);
	}
	hdc = GetDC(listbox->h_wnd);
	EnumFontFamiliesEx(hdc, &lfinfo, (FONTENUMPROC) font_style_enum_proc,
	    (LONG) style_lb, 0);
	EnumFontFamiliesEx(hdc, &lfinfo, (FONTENUMPROC) font_size_enum_proc,
	    (LONG) size_lb, 0);
	ReleaseDC(listbox->h_wnd, hdc);
    } else {
	win32_textbox_set_text(name_tb, "");
    }
    if (win32_listbox_get_selected(style_lb) < 0)
	win32_listbox_set_selected(style_lb, 0);
    if (win32_listbox_get_selected(size_lb) < 0)
	win32_listbox_set_selected(size_lb, 0);

    show_font_selection();
}

void
prefs_font_style_list_select(win32_element_t *listbox, LPNMLISTVIEW nmlv) {
    win32_element_t *style_tb = win32_identifier_get_str("prefs-dialog.font.tb.style");
    int              sel_item;
    LVITEM           item;
    gchar            font_style[LF_FACESIZE];

    win32_element_assert(style_tb);

    sel_item = ListView_GetNextItem(nmlv->hdr.hwndFrom, -1, LVNI_SELECTED);
    if (sel_item >= 0 && nmlv->uNewState & LVIS_SELECTED) {
	ZeroMemory(&item, sizeof(item));
	item.mask = LVIF_TEXT;
	item.iItem = sel_item;
	item.iSubItem = 0;
	item.pszText = font_style;
	item.cchTextMax = LF_FACESIZE;
	ListView_GetItem(nmlv->hdr.hwndFrom, &item);
	win32_textbox_set_text(style_tb, font_style);
    } else {
	win32_textbox_set_text(style_tb, "");
    }

    show_font_selection();
}

void
prefs_font_size_list_select(win32_element_t *listbox, LPNMLISTVIEW nmlv) {
    win32_element_t *size_tb = win32_identifier_get_str("prefs-dialog.font.tb.size");
    int              sel_item;
    LVITEM           item;
    gchar            font_size[LF_FACESIZE];

    win32_element_assert(size_tb);

    sel_item = ListView_GetNextItem(nmlv->hdr.hwndFrom, -1, LVNI_SELECTED);
    if (sel_item >= 0 && nmlv->uNewState & LVIS_SELECTED) {
	ZeroMemory(&item, sizeof(item));
	item.mask = LVIF_TEXT;
	item.iItem = sel_item;
	item.iSubItem = 0;
	item.pszText = font_size;
	item.cchTextMax = LF_FACESIZE;
	ListView_GetItem(nmlv->hdr.hwndFrom, &item);
	win32_textbox_set_text(size_tb, font_size);
    } else {
	win32_textbox_set_text(size_tb, "");
    }

    show_font_selection();
}

/* Command sent by element type <button>, id "prefs-dialog.color.set" */
void
prefs_dialog_set_color (win32_element_t *set_el) {
    win32_element_t *color_ml;
    CHOOSECOLOR      cc;
    int              cur_sel;

    color_ml = win32_identifier_get_str("prefs-dialog.color.select");
    win32_element_assert(color_ml);

    cur_sel = win32_menulist_get_selection(color_ml);
    g_assert(cur_sel >= 0 && cur_sel < MAX_IDX);

    ZeroMemory(&cc, sizeof(cc));
    cc.lStructSize = sizeof(cc);
    cc.Flags = CC_FULLOPEN | CC_RGBINIT;
    cc.rgbResult = COLOR_T2COLORREF(&tcolors[cur_sel]);
    cc.lpCustColors = cust_colors;
    if (ChooseColor(&cc)) {
	colorref2color_t(cc.rgbResult, &tcolors[cur_sel]);
	set_sample_colors();
    }
}

/* Command sent by element type <radio>, id "prefs.gui_fo_style_last_opened" */
/* Command sent by element type <radio>, id "prefs.gui_fo_style_specified" */
void
prefs_fileopen_style (win32_element_t *rd_el) {
    win32_element_t *cur_el, *text_el;

    cur_el = win32_identifier_get_str("prefs.gui_fo_style_specified");
    win32_element_assert(cur_el);

    text_el = win32_identifier_get_str("prefs.gui_fileopen_dir");
    win32_element_assert(text_el);

    if (win32_radio_get_state(cur_el)) {
	win32_element_set_enabled(text_el, TRUE);
    } else {
	win32_element_set_enabled(text_el, FALSE);
    }
}

/* Command sent by element type <button>, id "prefs-dialog.cols.new" */
void prefs_dialog_new_column (win32_element_t *button) {
    win32_element_t  *listbox, *textbox, *menulist;
    fmt_data         *cfmt;
    gchar            *title = "New Column";
    gint              row;

    win32_element_assert(button);


    listbox = win32_identifier_get_str("prefs-dialog.cols.list");
    win32_element_assert(listbox);

    textbox = win32_identifier_get_str("prefs-dialog.cols.title");
    win32_element_assert(textbox);

    menulist = win32_identifier_get_str("prefs-dialog.cols.format");
    win32_element_assert(menulist);

    cfmt = g_malloc(sizeof(fmt_data));
    cfmt->title = g_strdup(title);
    cfmt->fmt = g_strdup(col_format_to_string(0));
    prefs.col_list = g_list_append(prefs.col_list, cfmt);

    row = win32_listbox_add_item(listbox, -1, NULL, "");
    win32_listbox_add_cell(listbox, NULL, "");
    win32_listbox_set_row_data(listbox, row, cfmt);
    win32_listbox_set_selected(listbox, row);

    win32_textbox_set_text(textbox, cfmt->title);
    win32_menulist_set_selection(menulist, 0);
}

/* Command sent by element type <button>, id "prefs-dialog.cols.delete" */
void prefs_dialog_delete_column (win32_element_t *button) {
    win32_element_t *listbox;
    int              row;
    fmt_data        *cfmt;

    listbox = win32_identifier_get_str("prefs-dialog.cols.list");
    win32_element_assert(listbox);

    win32_element_assert(button);

    row = win32_listbox_get_selected(listbox);
    if (row < 0  || row >= win32_listbox_get_row_count(listbox)) {
	return;
    }
    cfmt = (fmt_data *) win32_listbox_get_row_data(listbox, row);

    prefs.col_list = g_list_remove(prefs.col_list, cfmt);
    g_free(cfmt->title);
    g_free(cfmt->fmt);
    g_free(cfmt);
    win32_listbox_delete_item(listbox, row);
}

/* Command sent by element type <button>, id "prefs-dialog.cols.up" */
/* Command sent by element type <button>, id "prefs-dialog.cols.down" */
void prefs_dialog_move_column (win32_element_t *button) {
    win32_element_t *listbox, *textbox, *menulist;
    int              row, inc = 1;
    fmt_data        *cfmt;

    listbox = win32_identifier_get_str("prefs-dialog.cols.list");
    win32_element_assert(listbox);

    textbox = win32_identifier_get_str("prefs-dialog.cols.title");
    win32_element_assert(textbox);

    menulist = win32_identifier_get_str("prefs-dialog.cols.format");
    win32_element_assert(menulist);

    win32_element_assert(button);
    if (button->id && strcmp(button->id, "prefs-dialog.cols.up") == 0) {
	inc = -1;
    }

    row = win32_listbox_get_selected(listbox);
    if (row < 0 || row >= win32_listbox_get_row_count(listbox)) {
	return;
    }
    if (row < 1 && inc == -1) {
	return;
    }
    if (row >= win32_listbox_get_row_count(listbox) - 1 && inc == 1) {
	return;
    }
    cfmt = (fmt_data *) win32_listbox_get_row_data(listbox, row);

    prefs.col_list = g_list_remove(prefs.col_list, cfmt);
    prefs.col_list = g_list_insert(prefs.col_list, cfmt, row + inc);
    win32_listbox_delete_item(listbox, row);
    row += inc;
    win32_listbox_add_item(listbox, row, NULL, "");
    win32_listbox_add_cell(listbox, NULL, "");
    win32_listbox_set_row_data(listbox, row, cfmt);
    win32_listbox_set_selected(listbox, row);

    win32_textbox_set_text(textbox, cfmt->title);
    win32_menulist_set_selection(menulist, 0);
}

/* Command sent by element type <textbox>, id "prefs-dialog.cols.title" */
void
prefs_dialog_set_column_title  (win32_element_t *textbox) {
    win32_element_t *listbox;
    gchar           *title;
    int              row;
    fmt_data        *cfmt;

    listbox = win32_identifier_get_str("prefs-dialog.cols.list");
    win32_element_assert(listbox);

    win32_element_assert(textbox);

    row = win32_listbox_get_selected(listbox);
    if (row < 0 || row >= win32_listbox_get_row_count(listbox)) {
	return;
    }
    cfmt = (fmt_data *) win32_listbox_get_row_data(listbox, row);
    title = win32_textbox_get_text(textbox);

    win32_listbox_set_text(listbox, row, 0, title);
    g_free(cfmt->title);
    cfmt->title = g_strdup(title);
}

/* Command sent by element type <menulist>, id "prefs-dialog.cols.format" */
void prefs_dialog_set_column_format  (win32_element_t *menulist) {
    win32_element_t *listbox;
    gchar           *format;
    int              row, sel;
    fmt_data        *cfmt;


    listbox = win32_identifier_get_str("prefs-dialog.cols.list");
    win32_element_assert(listbox);

    win32_element_assert(menulist);

    row = win32_listbox_get_selected(listbox);
    if (row < 0 || row >= win32_listbox_get_row_count(listbox)) {
	return;
    }
    cfmt = (fmt_data *) win32_listbox_get_row_data(listbox, row);
    sel = win32_menulist_get_selection(menulist);
    g_free(cfmt->fmt);
    cfmt->fmt = g_strdup(col_format_to_string(sel));
    format = col_format_desc(sel);
    win32_listbox_set_text(listbox, row, 1, format);
}

BOOL CALLBACK
preferences_dialog_dlg_proc(HWND hw_prefs, UINT msg, WPARAM w_param, LPARAM l_param)
{
    win32_element_t *dlg_box;

    switch( msg ) {
	case WM_INITDIALOG:
	    preferences_dialog_handle_wm_initdialog(hw_prefs);
	    dlg_box = (win32_element_t *) GetWindowLong(hw_prefs, GWL_USERDATA);
	    win32_element_assert (dlg_box);
	    return 0;
	    break;
	case WM_COMMAND:
	    g_warning("w_param: %04x", LOWORD(w_param));
	    return 0;
	    break;
	case WM_CLOSE:
	    prefs_dialog_cancel(NULL);
	    return 1;
	    break;
	default:
	    return 0;
    }
    return 0;
}

/*
 * Private routines
 */

static void
gui_prefs_fetch() {
    win32_element_t  *cur_el;
    int               i;

    /* Fetch our menulist values */
    i = 0;
    while (gui_ml_map[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_ml_map[i].name);
	win32_element_assert(cur_el);
	*gui_ml_map[i].val = win32_menulist_get_selection(cur_el);
	i++;
    }

    /* Fetch our checkbox values */
    i = 0;
    while (gui_cb_map[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_cb_map[i].name);
	win32_element_assert(cur_el);
	*gui_cb_map[i].val = win32_checkbox_get_state(cur_el);
	i++;
    }

    /* Fetch our textbox values */
    i = 0;
    while (gui_tb_map[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_tb_map[i].name);
	win32_element_assert(cur_el);
	if (*gui_tb_map[i].val != NULL) {
	    g_free(*gui_tb_map[i].val);
	}
	*gui_tb_map[i].val = win32_textbox_get_text(cur_el);
	i++;
    }

    /* Fetch our spinner values */
    i = 0;
    while (gui_sp_map[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_sp_map[i].name);
	win32_element_assert(cur_el);
	*gui_sp_map[i].val = ethereal_spinner_get_pos(cur_el);
	i++;
    }

    /* File open radio buttons / file open style */
    i = 0;
    while (gui_fs_radio_vals[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_fs_radio_vals[i].name);
	if (win32_radio_get_state(cur_el)) {
	    prefs.gui_fileopen_style = gui_fs_radio_vals[i].val;
	}
	i++;
    }
}

static void
font_prefs_fetch() {
    win32_element_t *style_lb, *size_lb;
    LOGFONT         *lfinfo;
    int              row;
    gchar           *font_style, *font_size;

    style_lb = win32_identifier_get_str("prefs-dialog.font.lb.style");
    win32_element_assert(style_lb);

    size_lb = win32_identifier_get_str("prefs-dialog.font.lb.size");
    win32_element_assert(size_lb);

    row = win32_listbox_get_selected(style_lb);
    if (row < 0 || row >= win32_listbox_get_row_count(style_lb)) {
	return;
    }
    lfinfo = win32_listbox_get_row_data(style_lb, row);
    font_style = win32_listbox_get_text(style_lb, row, 0);
    if (font_style == NULL) {
	return;
    }
    if (g_ascii_strcasecmp(font_style, "Regular") == 0 || g_ascii_strcasecmp(font_style, "Normal") == 0) {
	g_free(font_style);
	font_style = NULL;
    }

    row = win32_listbox_get_selected(size_lb);
    if (row < 0 || row >= win32_listbox_get_row_count(size_lb)) {
	return;
    }
    lfinfo->lfHeight = (int) win32_listbox_get_row_data(size_lb, row);
    font_size = win32_listbox_get_text(size_lb, row, 0);
    if (font_size == NULL) {
	g_free(font_style);
	return;
    }

    old_r_font = m_r_font;
    m_r_font = CreateFontIndirect(lfinfo);
    DeleteObject(old_r_font);

    if (tmp_prefs.gui_font_name2)
	g_free(tmp_prefs.gui_font_name2);
    if (font_style) {
	tmp_prefs.gui_font_name2 = g_strdup_printf("%s %s %s", lfinfo->lfFaceName,
		font_style, font_size);
    } else {
	tmp_prefs.gui_font_name2 = g_strdup_printf("%s %s", lfinfo->lfFaceName,
		font_size);
    }

    if (g_ascii_strcasecmp(prefs.gui_font_name2, tmp_prefs.gui_font_name2))
	font_changed = TRUE;
    g_free(font_style);
    g_free(font_size);
}

static void
column_prefs_fetch() {
    /* XXX - Column prefs are changed by the new/delete/up/down callbacks,
     * just as they are in the GTK+ code.  Should they be changed here instead?
     */
}

static void
stream_prefs_fetch() {
    CopyMemory(&prefs.gui_marked_fg, &tcolors[MFG_IDX], sizeof(color_t));
    CopyMemory(&prefs.gui_marked_bg, &tcolors[MBG_IDX], sizeof(color_t));
    CopyMemory(&prefs.st_client_fg,  &tcolors[CFG_IDX], sizeof(color_t));
    CopyMemory(&prefs.st_client_bg,  &tcolors[CBG_IDX], sizeof(color_t));
    CopyMemory(&prefs.st_server_fg,  &tcolors[SFG_IDX], sizeof(color_t));
    CopyMemory(&prefs.st_server_bg,  &tcolors[SBG_IDX], sizeof(color_t));
}

static void
capture_prefs_fetch() {
    win32_element_t *iflist_ml, *cur_el;
    gchar           *if_text;
    int              sel_item, i;

    iflist_ml = win32_identifier_get_str("prefs-dialog.capture.iflist");
    win32_element_assert(iflist_ml);

    /* Fetch the capture device */
    if (prefs.capture_device != NULL) {
	g_free(prefs.capture_device);
	prefs.capture_device = NULL;
    }

    sel_item = win32_menulist_get_selection(iflist_ml);
    if_text = win32_menulist_get_string(iflist_ml, sel_item);
    if (if_text != NULL) {
	prefs.capture_device = if_text;
    }

    /* Fetch in our checkbox values */
    i = 0;
    while (capture_cb_map[i].name != NULL) {
	cur_el = win32_identifier_get_str(capture_cb_map[i].name);
	win32_element_assert(cur_el);
	*capture_cb_map[i].val = win32_checkbox_get_state(cur_el);
	i++;
    }
    /* ...then invert show_info */
    tmp_prefs.capture_show_info = ! tmp_prefs.capture_show_info;
}

static void
printer_prefs_fetch () {
    win32_element_t *cur_el;
    int              i;

    /* File open radio buttons / file open style */
    i = 0;
    while (gui_fs_radio_vals[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_fs_radio_vals[i].name);
	if (win32_radio_get_state(cur_el)) {
	    prefs.gui_fileopen_style = gui_fs_radio_vals[i].val;
	}
	i++;
    }


    /* Print format radio buttons */
    i = 0;
    while (print_format_radio_vals[i].name != NULL) {
	cur_el = win32_identifier_get_str(print_format_radio_vals[i].name);
	if (win32_radio_get_state(cur_el)) {
	    prefs.pr_format = print_format_radio_vals[i].val;
	}
	i++;
    }

    /* Print destination radio buttons */
    i = 0;
    while (print_dest_radio_vals[i].name != NULL) {
	cur_el = win32_identifier_get_str(print_dest_radio_vals[i].name);
	if (win32_radio_get_state(cur_el)) {
	    prefs.pr_dest = print_dest_radio_vals[i].val;
	}
	i++;
    }

    cur_el = win32_identifier_get_str("prefs.pr_file");
    win32_element_assert(cur_el);

    if (prefs.pr_file != NULL) {
	g_free(prefs.pr_file);
	prefs.pr_file = NULL;
    }
    prefs.pr_file = g_strdup(win32_textbox_get_text(cur_el));
}

static void
nameres_prefs_fetch() {
    win32_element_t *cur_el;

    prefs.name_resolve = RESOLV_NONE;
    /* Fetch our checkbox values */
    cur_el = win32_identifier_get_str("prefs.name_resolve_mac");
    win32_element_assert(cur_el);
    if (win32_checkbox_get_state(cur_el))
	prefs.name_resolve |= RESOLV_MAC;

    cur_el = win32_identifier_get_str("prefs.name_resolve_network");
    win32_element_assert(cur_el);
    if (win32_checkbox_get_state(cur_el))
	prefs.name_resolve |= RESOLV_NETWORK;

    cur_el = win32_identifier_get_str("prefs.name_resolve_transport");
    win32_element_assert(cur_el);
    if (win32_checkbox_get_state(cur_el))
	prefs.name_resolve |= RESOLV_TRANSPORT;

    cur_el = win32_identifier_get_str("prefs.name_resolve_concurrent");
    win32_element_assert(cur_el);
    if (win32_checkbox_get_state(cur_el))
	prefs.name_resolve |= RESOLV_CONCURRENT;

    /* Fetch the spinbutton value */
    cur_el = win32_identifier_get_str("prefs.name_resolve_concurrency");
    win32_element_assert(cur_el);
    prefs.name_resolve_concurrency = ethereal_spinner_get_pos(cur_el);
}

gint
fetch_preference_radio_buttons_val(GSList *rb_group, const enum_val_t *enumvals) {
    win32_element_t  *radio;
    const enum_val_t *enum_valp;
    GSList           *rb_entry = rb_group;

    for (enum_valp = enumvals; enum_valp->name != NULL; enum_valp++) {
	radio = (win32_element_t *) rb_entry->data;
	win32_element_assert(radio);
	if (win32_radio_get_state(radio)) {
	    break;
	}
	rb_entry = g_slist_next(rb_entry);
    }

    return enum_valp->value;
}

static guint
pref_fetch(pref_t *pref, gpointer user_data)
{
    win32_element_t *cur_el = (win32_element_t *) pref->control;
    gchar *str_val;
    char *p;
    guint uval;
    gboolean bval;
    gint enumval, i;
    gboolean *pref_changed_p = user_data;

    /* Fetch the value of the preference, and set the appropriate variable
     to it. */
    switch (pref->type) {

	case PREF_UINT:
	    win32_element_assert(cur_el);
	    str_val = win32_textbox_get_text(cur_el);
	    uval = strtoul(str_val, &p, pref->info.base);
#if 0
	    if (p == value || *p != '\0')
		return PREFS_SET_SYNTAX_ERR;      /* number was bad */
#endif
	    if (*pref->varp.uint != uval) {
	      *pref_changed_p = TRUE;
	      *pref->varp.uint = uval;
	    }
	    g_free(str_val);
	    break;

	case PREF_BOOL:
	    win32_element_assert(cur_el);
	    bval = win32_checkbox_get_state(cur_el);
	    if (*pref->varp.boolp != bval) {
		*pref_changed_p = TRUE;
		*pref->varp.boolp = bval;
	    }
	    break;

	case PREF_ENUM:
	    if (pref->info.enum_info.radio_buttons) {
		enumval = fetch_preference_radio_buttons_val((GSList *) pref->control,
		    pref->info.enum_info.enumvals);
	    } else {
		win32_element_assert(cur_el);
		i = win32_menulist_get_selection(cur_el);
		enumval = pref->info.enum_info.enumvals[i].value;
	    }

	    if (*pref->varp.enump != enumval) {
		*pref_changed_p = TRUE;
		*pref->varp.enump = enumval;
	    }
	    break;

	case PREF_STRING:
	    win32_element_assert(cur_el);
	    str_val = win32_textbox_get_text(cur_el);
	    if (strcmp(*pref->varp.string, str_val) != 0) {
		*pref_changed_p = TRUE;
		g_free(*pref->varp.string);
		*pref->varp.string = str_val;
	    }
	    break;

	case PREF_OBSOLETE:
	    g_assert_not_reached();
	    break;
    }
    return 0;
}

static guint
module_prefs_fetch(module_t *module, gpointer user_data) {
    gboolean *must_redissect_p = user_data;

    /* For all preferences in this module, fetch its value from this
     module's notebook page.  Find out whether any of them changed. */
    module->prefs_changed = FALSE;        /* assume none of them changed */
    prefs_pref_foreach(module, pref_fetch, &module->prefs_changed);

    /* If any of them changed, indicate that we must redissect and refilter
     the current capture (if we have one), as the preference change
     could cause packets to be dissected differently. */
    if (module->prefs_changed)
	*must_redissect_p = TRUE;

    return 0;     /* keep fetching module preferences */
}

/* fetch all pref values from all pages */
static void
prefs_main_fetch_all(gboolean *must_redissect)
{
    /* Fetch the preferences (i.e., make sure all the values set in all of
       the preferences panes have been copied to "prefs" and the registered
       preferences). */
    gui_prefs_fetch();
//    layout_prefs_fetch();
    column_prefs_fetch();
    font_prefs_fetch();
    stream_prefs_fetch();

#ifdef HAVE_LIBPCAP
    /* Is WPcap loaded? */
    if (has_wpcap) {
	capture_prefs_fetch();
    }
#endif /* HAVE_LIBPCAP */
    printer_prefs_fetch();
    nameres_prefs_fetch();

    prefs_modules_foreach(module_prefs_fetch, must_redissect);

    free_prefs(&prefs);
    copy_prefs(&prefs, &tmp_prefs);
}

static void
gui_prefs_apply() {

    /* user immediately wants to see a console */
    if (prefs.gui_console_open == console_open_always) {
//        create_console();
    }

    if (font_changed) {
	user_font_apply();
    }

//    redraw_hex_dump_all();

    /* Redraw the help window(s). */
//    supported_redraw();
//    help_redraw();

    /* XXX: redraw the toolbar only, if style changed */
//    toolbar_redraw_all();

//    set_scrollbar_placement_all();
//    set_plist_sel_browse(prefs.gui_plist_sel_browse);
//    set_ptree_sel_browse_all(prefs.gui_ptree_sel_browse);
//    set_tree_styles_all();
//    main_widgets_rearrange();

}

static void
column_prefs_apply() {
}

void
stream_prefs_apply()
{
//    follow_redraw_all();

//    update_marked_frames();
}

static void
capture_prefs_apply() {
}

static void
printer_prefs_apply() {
}

static void
nameres_prefs_apply()
{
    /*
     * XXX - force a regeneration of the protocol list if this has
     * changed?
     */
    g_resolv_flags = prefs.name_resolve;
    menu_name_resolution_changed(g_hw_mainwin);
}

/* apply all pref values to the real world */
static void
prefs_main_apply_all()
{
    /* Now apply those preferences. */
    gui_prefs_apply();
//  layout_prefs_apply();
  column_prefs_apply();
  stream_prefs_apply();

#ifdef HAVE_LIBPCAP
  /* Is WPcap loaded? */
    if (has_wpcap) {
	capture_prefs_apply();
    }
#endif /* HAVE_LIBPCAP */
    printer_prefs_apply();
    nameres_prefs_apply();

    prefs_apply_all();
}

static void
gui_prefs_init(win32_element_t *prefs_dlg) {
    win32_element_t  *cur_el;
    int               i;

    /* Fill in our menulist values */
    i = 0;
    while (gui_ml_map[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_ml_map[i].name);
	win32_element_assert(cur_el);
	win32_menulist_set_selection(cur_el, *gui_ml_map[i].val);
	i++;
    }

    /* Fill in our checkbox values */
    i = 0;
    while (gui_cb_map[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_cb_map[i].name);
	win32_element_assert(cur_el);
	win32_checkbox_set_state(cur_el, *gui_cb_map[i].val);
	i++;
    }

    /* Fill in our textbox values */
    i = 0;
    while (gui_tb_map[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_tb_map[i].name);
	win32_element_assert(cur_el);
	if (*gui_tb_map[i].val != NULL) {
	    win32_textbox_set_text(cur_el, *gui_tb_map[i].val);
	}
	i++;
    }

    /* Fill in our spinner values */
    i = 0;
    while (gui_sp_map[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_sp_map[i].name);
	win32_element_assert(cur_el);
	ethereal_spinner_set_range(cur_el, gui_sp_map[i].low, gui_sp_map[i].high);
	ethereal_spinner_set_pos(cur_el, *gui_sp_map[i].val);
	i++;
    }

    /* File open radio buttons */
    i = 0;
    while (gui_fs_radio_vals[i].name != NULL) {
	cur_el = win32_identifier_get_str(gui_fs_radio_vals[i].name);
	if (gui_fs_radio_vals[i].val == (gint) prefs.gui_fileopen_style) {
	    win32_radio_set_state(cur_el, TRUE);
	    prefs_fileopen_style(cur_el);
	} else {
	    win32_radio_set_state(cur_el, FALSE);
	}
	i++;
    }
}

static void
column_prefs_init(win32_element_t *prefs_dlg) {
    win32_element_t  *col_lb, *col_ml;
    GList            *clp = NULL;
    fmt_data         *cfmt;
    gint             row, i;
    gchar            *title, *descr;

    col_lb = win32_identifier_get_str("prefs-dialog.cols.list");
    win32_element_assert(col_lb);

    clp = g_list_first(prefs.col_list);
    while (clp) {
	cfmt = (fmt_data *) clp->data;
	title = cfmt->title;
	descr = col_format_desc(get_column_format_from_str(cfmt->fmt));
	row = win32_listbox_add_item(col_lb, -1, NULL, title);
	win32_listbox_add_cell(col_lb, NULL, descr);
	win32_listbox_set_row_data(col_lb, row, cfmt);

	clp = clp->next;
    }

    col_ml = win32_identifier_get_str("prefs-dialog.cols.format");
    win32_element_assert(col_ml);

    for (i = 0; i < NUM_COL_FMTS; i++) {
	win32_menulist_add(col_ml, col_format_desc(i), FALSE);
    }
}

static int CALLBACK
font_name_enum_proc(ENUMLOGFONTEX *lpelfe, NEWTEXTMETRICEX *lpntme,
    int font_type, LPARAM l_param) {
    win32_element_t *name_lb = (win32_element_t *) l_param;

    if (name_lb == NULL) {
	return 1;
    }
    /*
     * A Bugzilla response from Tor Lillqvist about an unrelated issue included
     * a reference to
     *     http://groups.google.com/groups?hl=en&lr=&ie=UTF-8&c2coff=1&th=bb8eaff9d1d51576&rnum=1
     * which indicates that any text face name that begins with an '@' is a simulated,
     * rotated font generated by Windows, and can be ignored in our case.  I can't find
     * any reference on MSDN that confirms this.
     */
    if (lpelfe->elfLogFont.lfFaceName[0] == '@') {
	return 1;
    }

    /* Filter out duplicates */
    if (win32_listbox_find_text(name_lb, 0, lpelfe->elfLogFont.lfFaceName) >= 0) {
	return 1;
    }

    /* Fixed pitched only.  XXX - Is this too restrictive? */
    if (lpelfe->elfLogFont.lfPitchAndFamily & FIXED_PITCH) {
	win32_listbox_add_item(name_lb, -1, NULL, lpelfe->elfLogFont.lfFaceName);
    }


    return 1;
}

static int CALLBACK
font_style_enum_proc(ENUMLOGFONTEX *lpelfe, NEWTEXTMETRICEX *lpntme,
	int font_type, LPARAM l_param) {
    win32_element_t *style_lb = (win32_element_t *) l_param;
    LOGFONT         *lfdata, cur_lf;
    int              row, objsz;

    ZeroMemory(&cur_lf, sizeof(cur_lf));
    objsz = GetObject(user_font_get_regular(), sizeof(cur_lf), &cur_lf);

    if (font_type & TRUETYPE_FONTTYPE) {
	row = win32_listbox_add_item(style_lb, -1, NULL, lpelfe->elfStyle);
	lfdata = g_memdup(&(lpelfe->elfLogFont), sizeof(LOGFONT));
	win32_listbox_set_row_data(style_lb, row, lfdata);

	if (objsz && lpelfe->elfLogFont.lfWeight == cur_lf.lfWeight &&
		lpelfe->elfLogFont.lfItalic == cur_lf.lfItalic) {
	    win32_listbox_set_selected(style_lb, row);
	}
    } else if (win32_listbox_get_row_count(style_lb) == 0) {
	row = win32_listbox_add_item(style_lb, -1, NULL, "Regular");
	lfdata = g_memdup(&(lpelfe->elfLogFont), sizeof(LOGFONT));
	lfdata->lfWeight = FW_REGULAR;
	lfdata->lfItalic = FALSE;
	win32_listbox_set_row_data(style_lb, row, lfdata);

	if (objsz && cur_lf.lfWeight == FW_NORMAL && ! cur_lf.lfItalic) {
	    win32_listbox_set_selected(style_lb, row);
	}

	row = win32_listbox_add_item(style_lb, -1, NULL, "Bold");
	lfdata = g_memdup(&(lpelfe->elfLogFont), sizeof(LOGFONT));
	lfdata->lfWeight = FW_BOLD;
	lfdata->lfItalic = FALSE;
	win32_listbox_set_row_data(style_lb, row, lfdata);

	if (objsz && cur_lf.lfWeight == FW_BOLD && ! cur_lf.lfItalic) {
	    win32_listbox_set_selected(style_lb, row);
	}

	row = win32_listbox_add_item(style_lb, -1, NULL, "Bold Italic");
	lfdata = g_memdup(&(lpelfe->elfLogFont), sizeof(LOGFONT));
	lfdata->lfWeight = FW_BOLD;
	lfdata->lfItalic = TRUE;
	win32_listbox_set_row_data(style_lb, row, lfdata);

	if (objsz && cur_lf.lfWeight == FW_BOLD && cur_lf.lfItalic) {
	    win32_listbox_set_selected(style_lb, row);
	}

	row = win32_listbox_add_item(style_lb, -1, NULL, "Italic");
	lfdata = g_memdup(&(lpelfe->elfLogFont), sizeof(LOGFONT));
	lfdata->lfWeight = FW_REGULAR;
	lfdata->lfItalic = TRUE;
	win32_listbox_set_row_data(style_lb, row, lfdata);

	if (objsz && cur_lf.lfWeight == FW_NORMAL && cur_lf.lfItalic) {
	    win32_listbox_set_selected(style_lb, row);
	}
    }

    return 1;
}

static int CALLBACK
font_size_enum_proc(ENUMLOGFONTEX *lpelfe, NEWTEXTMETRICEX *lpntme,
	int font_type, LPARAM l_param) {
    win32_element_t *size_lb = (win32_element_t *) l_param;
    TEXTMETRIC      *lptm = (TEXTMETRIC *) lpntme;
    int              i, row, rawsz, pointsz, objsz;
    HDC              hdc;
    LOGFONT          cur_lf;

    static int       tt_size[] = { 8, 9, 10, 11, 12, 14, 16, 18, 20,
	22, 24, 26, 28, 36 };
    gchar size_str[LF_FACESIZE];

    ZeroMemory(&cur_lf, sizeof(cur_lf));
    objsz = GetObject(user_font_get_regular(), sizeof(cur_lf), &cur_lf);

    if (font_type & TRUETYPE_FONTTYPE) {
	if (win32_listbox_get_row_count(size_lb) == 0) {
	    for (i = 0; i < sizeof(tt_size) / sizeof(int); i++) {
		g_snprintf(size_str, LF_FACESIZE, "%d", tt_size[i]);
		row = win32_listbox_add_item(size_lb, -1, NULL, size_str);

		hdc = GetDC(size_lb->h_wnd);
		rawsz = - MulDiv(tt_size[i], GetDeviceCaps(hdc, LOGPIXELSY), 72);
		ReleaseDC(size_lb->h_wnd, hdc);

		win32_listbox_set_row_data(size_lb, row, (gpointer) rawsz);

		if (objsz && cur_lf.lfHeight == rawsz) {
		    win32_listbox_set_selected(size_lb, row);
		}
	    }
	}
    } else {
	hdc = GetDC(size_lb->h_wnd);
	rawsz = lptm->tmHeight - lptm->tmInternalLeading;
	pointsz = MulDiv(rawsz, 72, GetDeviceCaps(hdc, LOGPIXELSY));
	ReleaseDC(size_lb->h_wnd, hdc);
	g_snprintf(size_str, LF_FACESIZE, "%d", pointsz);
	row = win32_listbox_add_item(size_lb, -1, NULL, size_str);
	win32_listbox_set_row_data(size_lb, row, (gpointer) rawsz);

	if (objsz && cur_lf.lfHeight == rawsz) {
	    win32_listbox_set_selected(size_lb, row);
	}
    }

    return 1;
}

static void
font_prefs_init(win32_element_t *prefs_dlg) {
    win32_element_t *name_lb, *sample_tb;
    LOGFONT          lfinfo, cur_lf;
    HFONT            hfont;
    HDC              hdc;
    gint             item;

    name_lb = win32_identifier_get_str("prefs-dialog.font.lb.name");
    win32_element_assert(name_lb);

    sample_tb = win32_identifier_get_str("prefs-dialog.font.tb.sample");
    win32_element_assert(sample_tb);

    /* Pre-load the sample textbox with the current font so that we can
     * call DeleteObject() on it later */
    ZeroMemory(&cur_lf, sizeof(cur_lf));
    if (GetObject(user_font_get_regular(), sizeof(cur_lf), &cur_lf)) {
	hfont = CreateFontIndirect(&cur_lf);
	SendMessage(sample_tb->h_wnd, WM_SETFONT, (WPARAM) hfont, (LPARAM) TRUE);
    }

    ZeroMemory(&lfinfo, sizeof(lfinfo));
    lfinfo.lfCharSet        = ANSI_CHARSET;  /* XXX - Do we need to be this restrictive? */
    lfinfo.lfFaceName[0]    = '\0';
    lfinfo.lfPitchAndFamily = FIXED_PITCH | FF_DONTCARE;

    hdc = GetDC(prefs_dlg->h_wnd);
    EnumFontFamiliesEx(hdc, &lfinfo, (FONTENUMPROC) font_name_enum_proc,
	(LONG) name_lb, 0);
    ReleaseDC(prefs_dlg->h_wnd, hdc);

    item = win32_listbox_find_text(name_lb, 0, cur_lf.lfFaceName);
    if (item < 0) item = 0;
    win32_listbox_set_selected(name_lb, item);

    font_changed = FALSE;
}

static void
show_font_selection() {
    win32_element_t *style_lb, *size_lb, *sample_tb;
    LOGFONT         *lfinfo;
    int              row;
    HDC              hdc;
    HFONT            hfont, old_font;

    style_lb = win32_identifier_get_str("prefs-dialog.font.lb.style");
    win32_element_assert(style_lb);

    size_lb = win32_identifier_get_str("prefs-dialog.font.lb.size");
    win32_element_assert(size_lb);

    sample_tb = win32_identifier_get_str("prefs-dialog.font.tb.sample");
    win32_element_assert(sample_tb);

    row = win32_listbox_get_selected(style_lb);
    if (row < 0 || row >= win32_listbox_get_row_count(style_lb)) {
	return;
    }

    lfinfo = win32_listbox_get_row_data(style_lb, row);

    row = win32_listbox_get_selected(size_lb);
    if (row < 0 || row >= win32_listbox_get_row_count(size_lb)) {
	return;
    }

    lfinfo->lfHeight = (int) win32_listbox_get_row_data(size_lb, row);

    old_font = (HFONT) SendMessage(sample_tb->h_wnd, WM_GETFONT, 0, 0);
    hdc = GetDC(size_lb->h_wnd);
    hfont = CreateFontIndirect(lfinfo);
    SelectObject(hdc, hfont);
    ReleaseDC(size_lb->h_wnd, hdc);

    SendMessage(sample_tb->h_wnd, WM_SETFONT, (WPARAM) hfont, (LPARAM) TRUE);
    DeleteObject(old_font);
}

static void
set_sample_colors() {
    win32_element_t *sample_tb;
    CHARFORMAT2      char_fmt;

    sample_tb = win32_identifier_get_str("prefs-dialog.color.sample");
    win32_element_assert(sample_tb);

    ZeroMemory(&char_fmt, sizeof(char_fmt));
    char_fmt.cbSize = sizeof(char_fmt);
    char_fmt.dwMask = CFM_COLOR | CFM_BACKCOLOR;

    win32_textbox_set_text(sample_tb, "");

    char_fmt.crTextColor = COLOR_T2COLORREF(&tcolors[MFG_IDX]);
    char_fmt.crBackColor = COLOR_T2COLORREF(&tcolors[MBG_IDX]);
    win32_textbox_insert(sample_tb, SAMPLE_MARKED_TEXT, -1,
	(CHARFORMAT *) &char_fmt);

    char_fmt.crTextColor = COLOR_T2COLORREF(&tcolors[CFG_IDX]);
    char_fmt.crBackColor = COLOR_T2COLORREF(&tcolors[CBG_IDX]);
    win32_textbox_insert(sample_tb, SAMPLE_CLIENT_TEXT, -1,
	(CHARFORMAT *) &char_fmt);

    char_fmt.crTextColor = COLOR_T2COLORREF(&tcolors[SFG_IDX]);
    char_fmt.crBackColor = COLOR_T2COLORREF(&tcolors[SBG_IDX]);
    win32_textbox_insert(sample_tb, SAMPLE_SERVER_TEXT, -1,
	(CHARFORMAT *) &char_fmt);
}

static void
color_prefs_init(win32_element_t *prefs_dlg) {
    win32_element_t *color_ml;

    color_ml = win32_identifier_get_str("prefs-dialog.color.select");
    win32_element_assert(color_ml);

    win32_menulist_set_selection(color_ml, 0);

    CopyMemory(&tcolors[MFG_IDX], &prefs.gui_marked_fg, sizeof(color_t));
    CopyMemory(&tcolors[MBG_IDX], &prefs.gui_marked_bg, sizeof(color_t));
    CopyMemory(&tcolors[CFG_IDX], &prefs.st_client_fg,  sizeof(color_t));
    CopyMemory(&tcolors[CBG_IDX], &prefs.st_client_bg,  sizeof(color_t));
    CopyMemory(&tcolors[SFG_IDX], &prefs.st_server_fg,  sizeof(color_t));
    CopyMemory(&tcolors[SBG_IDX], &prefs.st_server_bg,  sizeof(color_t));

    set_sample_colors();
}

static void
capture_prefs_init(win32_element_t *prefs_dlg) {
    win32_element_t *iflist_ml, *cur_el;
    GList           *if_list, *combo_list, *cl_item;
    int              err, idx = 0, i;
    char             err_str[PCAP_ERRBUF_SIZE];

    iflist_ml = win32_identifier_get_str("prefs-dialog.capture.iflist");
    win32_element_assert(iflist_ml);

    if_list = get_interface_list(&err, err_str);
    combo_list = build_capture_combo_list(if_list, FALSE);
    free_interface_list(if_list);

    cl_item = g_list_first(combo_list);
    while(cl_item != NULL) {
	win32_menulist_add(iflist_ml, cl_item->data, FALSE);
	cl_item = g_list_next(cl_item);
    }
    if (combo_list != NULL) {
	free_capture_combo_list(combo_list);
    }
    if (prefs.capture_device != NULL) {
	idx = win32_menulist_find_string(iflist_ml, prefs.capture_device);
	if (idx < 0) {
	    idx = 0;
	}
    }
    win32_menulist_set_selection(iflist_ml, idx);
    /* XXX - This is a hack to get around the super-long interface names */
    iflist_ml->minwidth = 50;

    /* Fill in our checkbox values */
    i = 0;
    /* First, invert show_info */
    tmp_prefs.capture_show_info = ! tmp_prefs.capture_show_info;
    while (capture_cb_map[i].name != NULL) {
	cur_el = win32_identifier_get_str(capture_cb_map[i].name);
	win32_element_assert(cur_el);
	win32_checkbox_set_state(cur_el, *capture_cb_map[i].val);
	i++;
    }
}

static void
printer_prefs_init(win32_element_t *prefs_dlg) {
    win32_element_t *cur_el;
    int              i;

    /* Print format radio buttons */
    i = 0;
    while (print_format_radio_vals[i].name != NULL) {
	cur_el = win32_identifier_get_str(print_format_radio_vals[i].name);
	if (print_format_radio_vals[i].val == prefs.pr_format) {
	    win32_radio_set_state(cur_el, TRUE);
	} else {
	    win32_radio_set_state(cur_el, FALSE);
	}
	i++;
    }

    /* Print destination radio buttons */
    i = 0;
    while (print_dest_radio_vals[i].name != NULL) {
	cur_el = win32_identifier_get_str(print_dest_radio_vals[i].name);
	if (print_dest_radio_vals[i].val == prefs.pr_dest) {
	    win32_radio_set_state(cur_el, TRUE);
	} else {
	    win32_radio_set_state(cur_el, FALSE);
	}
	i++;
    }

    cur_el = win32_identifier_get_str("prefs.pr_file");
    win32_element_assert(cur_el);

    if (prefs.pr_file != NULL) {
	win32_textbox_set_text(cur_el, prefs.pr_file);
    }
}

static void
nameres_prefs_init(win32_element_t *prefs_dlg) {
    win32_element_t *cur_el;

    /* Fill in our checkbox values */
    cur_el = win32_identifier_get_str("prefs.name_resolve_mac");
    win32_element_assert(cur_el);
    win32_checkbox_set_state(cur_el, prefs.name_resolve & RESOLV_MAC);

    cur_el = win32_identifier_get_str("prefs.name_resolve_network");
    win32_element_assert(cur_el);
    win32_checkbox_set_state(cur_el, prefs.name_resolve & RESOLV_NETWORK);

    cur_el = win32_identifier_get_str("prefs.name_resolve_transport");
    win32_element_assert(cur_el);
    win32_checkbox_set_state(cur_el, prefs.name_resolve & RESOLV_TRANSPORT);

    cur_el = win32_identifier_get_str("prefs.name_resolve_concurrent");
    win32_element_assert(cur_el);
    win32_checkbox_set_state(cur_el, prefs.name_resolve & RESOLV_CONCURRENT);

    cur_el = win32_identifier_get_str("prefs.name_resolve_concurrency");
    win32_element_assert(cur_el);
    ethereal_spinner_set_range(cur_el, 0, NAMRES_MAX_CONCURRENCY);
    ethereal_spinner_set_pos(cur_el, prefs.name_resolve_concurrency);
}

/* XXX - Most of the protocol (module) prefs code was taken from
 * gtk/prefs_dlg.c
 */

win32_element_t *
create_preference_entry(win32_element_t *grid, const gchar *label_text,
	const gchar *tooltip_text, char *value) {
    win32_element_t *label, *entry;

    win32_element_assert(grid);

    win32_grid_add_row(grid, 0.0, 0);

    label = win32_description_new(grid->h_wnd, label_text);
    label->text_align = CSS_TEXT_ALIGN_RIGHT;
    win32_description_apply_styles(label);
    win32_box_add(grid, label, -1);

    entry = win32_textbox_new(grid->h_wnd, FALSE);
    win32_box_add(grid, entry, -1);
    win32_textbox_set_text(entry, value);

    return entry;
}

win32_element_t *
create_preference_check_button(win32_element_t *grid, const gchar *label_text,
	const gchar *tooltip_text, gboolean active) {
    win32_element_t *label, *checkbox;

    win32_element_assert(grid);

    win32_grid_add_row(grid, 0.0, 0);

    label = win32_description_new(grid->h_wnd, label_text);
    label->text_align = CSS_TEXT_ALIGN_RIGHT;
    win32_description_apply_styles(label);
    win32_box_add(grid, label, -1);

    checkbox = win32_checkbox_new(grid->h_wnd, "");
    win32_box_add(grid, checkbox, -1);
    win32_checkbox_set_state(checkbox, active);

    return checkbox;
}

GSList *
create_preference_radio_buttons(win32_element_t *grid, const gchar *label_text,
	const gchar *tooltip_text, const enum_val_t *enumvals, gint current_val) {
    win32_element_t  *label, *hbox, *radio;
    const enum_val_t *enum_valp;
    gboolean          start_group = TRUE;
    GSList           *rb_group = NULL;

    win32_element_assert(grid);

    win32_grid_add_row(grid, 0.0, 0);

    label = win32_description_new(grid->h_wnd, label_text);
    label->text_align = CSS_TEXT_ALIGN_RIGHT;
    win32_description_apply_styles(label);
    win32_box_add(grid, label, -1);

    hbox = win32_hbox_new(NULL, grid->h_wnd);
    win32_box_add(grid, hbox, -1);

    for (enum_valp = enumvals; enum_valp->name != NULL; enum_valp++) {
	radio = win32_radio_new(grid->h_wnd, enum_valp->description, start_group);
	win32_box_add(hbox, radio, -1);
	if (enum_valp->value == current_val) {
	    win32_radio_set_state(radio, TRUE);
	}
	start_group = FALSE;
	rb_group = g_slist_append(rb_group, radio);
    }

    return rb_group;
}

win32_element_t *
create_preference_option_menu(win32_element_t *grid, const gchar *label_text,
	const gchar *tooltip_text, const enum_val_t *enumvals, gint current_val) {
    win32_element_t  *label, *menulist;
    const enum_val_t *enum_valp;
    gboolean          selected;

    win32_element_assert(grid);

    win32_grid_add_row(grid, 0.0, 0);

    label = win32_description_new(grid->h_wnd, label_text);
    label->text_align = CSS_TEXT_ALIGN_RIGHT;
    win32_description_apply_styles(label);
    win32_box_add(grid, label, -1);

    menulist = win32_menulist_new(grid->h_wnd, FALSE);
    win32_box_add(grid, menulist, -1);

    for (enum_valp = enumvals; enum_valp->name != NULL; enum_valp++) {
	selected = FALSE;
	if (enum_valp->value == current_val) {
	    selected = TRUE;
	}
	win32_menulist_add(menulist, enum_valp->description, selected);
    }
    return menulist;
}

#define UINT_STRLEN (10 + 1)
static guint
pref_show(pref_t *pref, gpointer user_data) {
    win32_element_t *grid = user_data;
    GString         *label_string = g_string_new(pref->title);
    char             uint_str[UINT_STRLEN];

    win32_element_assert(grid);

    g_string_append(label_string, ":");

    switch (pref->type) {
	case PREF_UINT:
	    pref->saved_val.uint = *pref->varp.uint;

	    switch (pref->info.base) {

		case 10:
		    g_snprintf(uint_str, UINT_STRLEN, "%u", pref->saved_val.uint);
		    break;

		case 8:
		    g_snprintf(uint_str, UINT_STRLEN, "%o", pref->saved_val.uint);
		    break;

		case 16:
		    g_snprintf(uint_str, UINT_STRLEN, "%x", pref->saved_val.uint);
		    break;
	    }
	    pref->control = create_preference_entry(grid, label_string->str,
		    pref->description, uint_str);
	    break;

	case PREF_BOOL:
	    pref->saved_val.boolval = *pref->varp.boolp;
	    pref->control = create_preference_check_button(grid, label_string->str,
		    pref->description, pref->saved_val.boolval);
	    break;

	case PREF_ENUM:
	    pref->saved_val.enumval = *pref->varp.enump;
	    if (pref->info.enum_info.radio_buttons) {
		/* Show it as radio buttons. */
		pref->control = create_preference_radio_buttons(grid,
		    label_string->str, pref->description,
		    pref->info.enum_info.enumvals,
		    pref->saved_val.enumval);
	    } else {
		/* Show it as an option menu. */
		pref->control = create_preference_option_menu(grid,
		    label_string->str, pref->description,
		    pref->info.enum_info.enumvals,
		    pref->saved_val.enumval);
	    }
	    break;

	case PREF_STRING:
	    if (pref->saved_val.string != NULL)
		g_free(pref->saved_val.string);
	    pref->saved_val.string = g_strdup(*pref->varp.string);
	    pref->control = create_preference_entry(grid, label_string->str,
		pref->description, pref->saved_val.string);
	    break;

	case PREF_OBSOLETE:
	    g_assert_not_reached();
	    break;
    }
    g_string_free(label_string, TRUE);
    return 0;
}
static guint
pref_exists(pref_t *pref _U_, gpointer user_data _U_) {
    return 1;
}

#define MAX_TREE_NODE_NAME_LEN 96
static guint
module_prefs_show(module_t *module, gpointer user_data) {
    win32_element_t *groupbox, *grid;
    module_data_t   *md = user_data;
    gchar            id[MAX_TREE_NODE_NAME_LEN];

    g_assert(md != NULL);

    /*
     * Is this module a subtree, with modules underneath it?
     */
    if (!module->is_subtree) {
	/*
	 * No.
	 * Does it have any preferences (other than possibly obsolete ones)?
	 */
	if (prefs_pref_foreach(module, pref_exists, md) == 0) {
	    /*
	     * No.  Don't put the module into the preferences window.
	     * XXX - we should do the same for subtrees; if a subtree has
	     * nothing under it that will be displayed, don't put it into
	     * the window.
	     */
	    return 0;
	}
    }

    win32_tree_push(md->tree);
    g_snprintf(id, MAX_TREE_NODE_NAME_LEN, "prefs-dialog.tree.protocols.%s",
	module->title);
    win32_tree_add_row(md->tree, id);
    win32_tree_add_cell(md->tree, "", (gchar *) module->title);

    if (module->is_subtree) {
	prefs_module_list_foreach(module->prefs, module_prefs_show, md);
    } else {
	/* Create our <groupbox> */
	g_snprintf(id, MAX_TREE_NODE_NAME_LEN, "prefs-dialog.deck.protocols.%s",
	    module->title);
	groupbox = win32_groupbox_new(md->deck->h_wnd);
	win32_box_add(md->deck, groupbox, -1);
	win32_element_set_id(groupbox, id);
	win32_groupbox_set_title(groupbox, (gchar *) module->title);

	/* Create a <grid> with two columns */
	grid = win32_grid_new(groupbox->h_wnd);
	win32_box_add(groupbox, grid, -1);
	win32_grid_add_column(grid, 0.0, 0);
	win32_grid_add_column(grid, 1.0, 0);

	/* Add items for each of the preferences */
	prefs_pref_foreach(module, pref_show, grid);
    }

    win32_tree_pop(md->tree);
    return 0;
}

static void
protocol_prefs_init(win32_element_t *prefs_dlg) {
    module_data_t    md;

    md.tree = win32_identifier_get_str("prefs-dialog.tree");
    win32_element_assert(md.tree);

    md.deck = win32_identifier_get_str("prefs-dialog.deck");
    win32_element_assert(md.deck);

    prefs_module_list_foreach(NULL, module_prefs_show, &md);
}

#define NUM_COL_BUTTONS 3
static void
toggle_column_buttons(int cur_sel) {
    win32_element_t *col_lb, *delete_bt, *up_bt, *down_bt, *title_tb, *format_ml;
    int              rows;
    gboolean         ena_delete = FALSE, ena_up = FALSE, ena_down = FALSE;
    gboolean         ena_title = FALSE, ena_format = FALSE;

    col_lb = win32_identifier_get_str("prefs-dialog.cols.list");
    win32_element_assert(col_lb);

    delete_bt = win32_identifier_get_str("prefs-dialog.cols.delete");
    win32_element_assert(delete_bt);

    up_bt = win32_identifier_get_str("prefs-dialog.cols.up");
    win32_element_assert(up_bt);

    down_bt = win32_identifier_get_str("prefs-dialog.cols.down");
    win32_element_assert(down_bt);

    title_tb = win32_identifier_get_str("prefs-dialog.cols.title");
    win32_element_assert(title_tb);

    format_ml = win32_identifier_get_str("prefs-dialog.cols.format");
    win32_element_assert(format_ml);

    rows = win32_listbox_get_row_count(col_lb);

    if (cur_sel >= 0) {
	ena_delete = TRUE;
	ena_title = TRUE;
	ena_format = TRUE;
	if (cur_sel > 0) {
	    ena_up = TRUE;
	}
	if (cur_sel < rows - 1) {
	    ena_down = TRUE;
	}
    }
    win32_element_set_enabled(delete_bt, ena_delete);
    win32_element_set_enabled(up_bt, ena_up);
    win32_element_set_enabled(down_bt, ena_down);
    win32_element_set_enabled(title_tb, ena_title);
    win32_element_set_enabled(format_ml, ena_format);
}

static guint
pref_revert(pref_t *pref, gpointer user_data)
{
    gboolean *pref_changed_p = user_data;

    /* Revert the preference to its saved value. */
    switch (pref->type) {

	case PREF_UINT:
	    if (*pref->varp.uint != pref->saved_val.uint) {
		*pref_changed_p = TRUE;
		*pref->varp.uint = pref->saved_val.uint;
	    }
	    break;

	case PREF_BOOL:
	    if (*pref->varp.boolp != pref->saved_val.boolval) {
		*pref_changed_p = TRUE;
		*pref->varp.boolp = pref->saved_val.boolval;
	    }
	    break;

	case PREF_ENUM:
	    if (*pref->varp.enump != pref->saved_val.enumval) {
		*pref_changed_p = TRUE;
		*pref->varp.enump = pref->saved_val.enumval;
	    }
	    break;

	case PREF_STRING:
	    if (strcmp(*pref->varp.string, pref->saved_val.string) != 0) {
		*pref_changed_p = TRUE;
		g_free(*pref->varp.string);
		*pref->varp.string = g_strdup(pref->saved_val.string);
	    }
	    break;

	case PREF_OBSOLETE:
	    g_assert_not_reached();
	    break;
    }
    return 0;
}

static guint
module_prefs_revert(module_t *module, gpointer user_data)
{
    gboolean *must_redissect_p = user_data;

    /* For all preferences in this module, revert its value to the value
       it had when we popped up the Preferences dialog.  Find out whether
       this changes any of them. */
    module->prefs_changed = FALSE;        /* assume none of them changed */
    prefs_pref_foreach(module, pref_revert, &module->prefs_changed);

    /* If any of them changed, indicate that we must redissect and refilter
       the current capture (if we have one), as the preference change
       could cause packets to be dissected differently. */
    if (module->prefs_changed)
	*must_redissect_p = TRUE;
    return 0;     /* keep processing modules */
}
