/* gui_prefs.c
 * Dialog box for GUI preferences
 *
 * $Id: gui_prefs.c,v 1.46 2003/11/19 00:10:25 ulfl Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gtk/gtk.h>

#include <string.h>

#include "color.h"
#include "color_utils.h"
#include "globals.h"
#include "gui_prefs.h"
#include "gtkglobals.h"
#include "follow_dlg.h"
#include "help_dlg.h"
#include "supported_protos_dlg.h"
#include "prefs.h"
#include "prefs_dlg.h"
#include "ui_util.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "proto_draw.h"
#include "main.h"
#include "compat_macros.h"
#include "toolbar.h"

static void font_browse_cb(GtkWidget *w, gpointer data);
static void font_browse_ok_cb(GtkWidget *w, GtkFontSelectionDialog *fs);
static void font_browse_destroy(GtkWidget *win, gpointer data);
static gint fetch_enum_value(gpointer control, const enum_val_t *enumvals);
static void color_browse_cb(GtkWidget *w, gpointer data);
static void update_text_color(GtkWidget *w, gpointer data);
static void update_current_color(GtkWidget *w, gpointer data);
static void color_ok_cb(GtkWidget *w, gpointer data);
static void color_cancel_cb(GtkWidget *w, gpointer data);
static gboolean color_delete_cb(GtkWidget *prefs_w, gpointer dummy);
static void color_destroy_cb(GtkWidget *w, gpointer data);
static void fetch_colors(void);
static gint fileopen_dir_changed_cb(GtkWidget *myentry _U_, GdkEvent *event, gpointer parent_w);
static void fileopen_selected_cb(GtkWidget *mybutton_rb _U_, gpointer parent_w);

#define SCROLLBAR_PLACEMENT_KEY		"scrollbar_placement"
#define PLIST_SEL_BROWSE_KEY		"plist_sel_browse"
#define PTREE_SEL_BROWSE_KEY		"ptree_sel_browse"
#if GTK_MAJOR_VERSION < 2
#define PTREE_LINE_STYLE_KEY		"ptree_line_style"
#define PTREE_EXPANDER_STYLE_KEY	"ptree_expander_style"
#else
#define ALTERN_COLORS_KEY               "altern_colors"
#endif
#define HEX_DUMP_HIGHLIGHT_STYLE_KEY	"hex_dump_highlight_style"
#define GEOMETRY_POSITION_KEY		"geometry_position"
#define GEOMETRY_SIZE_KEY		"geometry_size"

#define FONT_DIALOG_PTR_KEY	"font_dialog_ptr"
#define FONT_CALLER_PTR_KEY	"font_caller_ptr"
#define COLOR_DIALOG_PTR_KEY	"color_dialog_ptr"
#define COLOR_CALLER_PTR_KEY	"color_caller_ptr"
#define COLOR_SAMPLE_PTR_KEY	"color_sample_ptr"
#define COLOR_SELECTION_PTR_KEY	"color_selection_ptr"

#define GUI_FILEOPEN_KEY	"fileopen_behavior"
#define GUI_FILEOPEN_DIR_KEY	"fileopen_directory"

#define GUI_TOOLBAR_STYLE_KEY	"toolbar_style"

static const enum_val_t scrollbar_placement_vals[] = {
	{ "Left",  FALSE },
	{ "Right", TRUE },
	{ NULL,    0 }
};

static const enum_val_t selection_mode_vals[] = {
	{ "Selects", FALSE },
	{ "Browses", TRUE },
	{ NULL,      0 }
};

#if GTK_MAJOR_VERSION < 2
static const enum_val_t line_style_vals[] = {
	{ "None",   0 },
	{ "Solid",  1 },
	{ "Dotted", 2 },
	{ "Tabbed", 3 },
	{ NULL,     0 }
};

static const enum_val_t expander_style_vals[] = {
	{ "None",     0 },
	{ "Square",   1 },
	{ "Triangle", 2 },
	{ "Circular", 3 },
	{ NULL,       0 }
};
#else
static const enum_val_t altern_colors_vals[] = {
	{ "No",  FALSE },
	{ "Yes",  TRUE },
	{ NULL,      0 }
};
#endif

static const enum_val_t highlight_style_vals[] = {
  	{ "Bold",     FALSE },
  	{ "Inverse",  TRUE },
	{ NULL,       0 }
};

static const enum_val_t toolbar_style_vals[] = {
  	{ "Icons only",     TB_STYLE_ICONS },
  	{ "Text only",      TB_STYLE_TEXT },
  	{ "Icons & Text",   TB_STYLE_BOTH },
	{ NULL,             0 }
};

static const enum_val_t gui_fileopen_vals[] = {
        { "Remember last directory", FO_STYLE_LAST_OPENED },
        { "Always start in directory:", FO_STYLE_SPECIFIED },
        { NULL,    0 }
};

/* Set to FALSE initially; set to TRUE if the user ever hits "OK" on
   the "Colors..." dialog, so that we know that they (probably) changed
   colors, and therefore that the "apply" function needs to recolor
   any marked packets. */
static gboolean colors_changed;

/* Set to FALSE initially; set to TRUE if the user ever hits "OK" on
   the "Font..." dialog, so that we know that they (probably) changed
   the font, and therefore that the "apply" function needs to take care
   of that */
static gboolean font_changed;

/* Font name from the font dialog box; if "font_changed" is TRUE, this
   has been set to the name of the font the user selected. */
static gchar *new_font_name;

#if GTK_MAJOR_VERSION < 2
#define GUI_TABLE_ROWS 10
#else
#define GUI_TABLE_ROWS 9
#endif

GtkWidget*
gui_prefs_show(void)
{
	GtkWidget *main_tb, *main_vb, *hbox, *font_bt, *color_bt;
	GtkWidget *scrollbar_om, *plist_browse_om;
	GtkWidget *ptree_browse_om, *highlight_style_om;
        GtkWidget *fileopen_rb, *fileopen_dir_te, *toolbar_style_om;
	GtkWidget *save_position_cb, *save_size_cb;
#if GTK_MAJOR_VERSION < 2
	GtkWidget *expander_style_om, *line_style_om;
#else
        GtkWidget *altern_colors_om;
#endif
        int        pos = 0;

	/* The colors or font haven't been changed yet. */
	colors_changed = FALSE;
	font_changed = FALSE;

	/* Main vertical box */
	main_vb = gtk_vbox_new(FALSE, 7);
	gtk_container_border_width( GTK_CONTAINER(main_vb), 5 );

	/* Main horizontal box  */
	/* XXX - Is therea a better way to center the table? */
	hbox = gtk_hbox_new(FALSE, 7);
	gtk_box_pack_start (GTK_BOX(main_vb), hbox, TRUE, FALSE, 0);

	/* Main table */
	main_tb = gtk_table_new(GUI_TABLE_ROWS, 3, FALSE);
	gtk_box_pack_start( GTK_BOX(hbox), main_tb, TRUE, FALSE, 0 );
	gtk_table_set_row_spacings( GTK_TABLE(main_tb), 10 );
	gtk_table_set_col_spacings( GTK_TABLE(main_tb), 15 );
	gtk_table_set_col_spacing( GTK_TABLE(main_tb), 1, 50 );

	/* Scrollbar placement */
	scrollbar_om = create_preference_option_menu(main_tb, pos++,
	    "Vertical scrollbar placement:", NULL, scrollbar_placement_vals,
	    prefs.gui_scrollbar_on_right);
	OBJECT_SET_DATA(main_vb, SCROLLBAR_PLACEMENT_KEY, scrollbar_om);

	/* Packet list selection browseable */
	plist_browse_om = create_preference_option_menu(main_tb, pos++,
	    "Packet list selection mode:", NULL, selection_mode_vals,
	    prefs.gui_plist_sel_browse);
	OBJECT_SET_DATA(main_vb, PLIST_SEL_BROWSE_KEY, plist_browse_om);

	/* Proto tree selection browseable */
	ptree_browse_om = create_preference_option_menu(main_tb, pos++,
	    "Protocol tree selection mode:", NULL, selection_mode_vals,
	    prefs.gui_ptree_sel_browse);
	OBJECT_SET_DATA(main_vb, PTREE_SEL_BROWSE_KEY, ptree_browse_om);

#if GTK_MAJOR_VERSION < 2
	/* Tree line style */
	line_style_om = create_preference_option_menu(main_tb, pos++,
	    "Tree line style:", NULL, line_style_vals,
	    prefs.gui_ptree_line_style);
	OBJECT_SET_DATA(main_vb, PTREE_LINE_STYLE_KEY, line_style_om);

	/* Tree expander style */
	expander_style_om = create_preference_option_menu(main_tb, pos++,
	    "Tree expander style:", NULL, expander_style_vals,
	    prefs.gui_ptree_expander_style);
	OBJECT_SET_DATA(main_vb, PTREE_EXPANDER_STYLE_KEY, expander_style_om);
#else
        /* Alternating row colors in list and tree views */
	altern_colors_om = create_preference_option_menu(main_tb, pos++,
	    "Alternating row colors in lists and trees:", NULL,
            altern_colors_vals, prefs.gui_altern_colors);
	OBJECT_SET_DATA(main_vb, ALTERN_COLORS_KEY, altern_colors_om);
#endif

	/* Hex Dump highlight style */
	highlight_style_om = create_preference_option_menu(main_tb, pos++,
	    "Hex display highlight style:", NULL, highlight_style_vals,
	    prefs.gui_hex_dump_highlight_style);
	OBJECT_SET_DATA(main_vb, HEX_DUMP_HIGHLIGHT_STYLE_KEY,
                        highlight_style_om);

	/* Toolbar prefs */
	toolbar_style_om = create_preference_option_menu(main_tb, pos++,
	    "Toolbar style:", NULL, toolbar_style_vals,
	    prefs.gui_toolbar_main_style);
	OBJECT_SET_DATA(main_vb, GUI_TOOLBAR_STYLE_KEY,
                        toolbar_style_om);

	/* Geometry prefs */
	save_position_cb = create_preference_check_button(main_tb, pos++,
            "Save window position:", NULL, prefs.gui_geometry_save_position);
	OBJECT_SET_DATA(main_vb, GEOMETRY_POSITION_KEY, save_position_cb);

	save_size_cb = create_preference_check_button(main_tb, pos++,
	    "Save window size:", NULL, prefs.gui_geometry_save_size);
	OBJECT_SET_DATA(main_vb, GEOMETRY_SIZE_KEY, save_size_cb);

	/* Allow user to select where they want the File Open dialog to open to
	 * by default */
	fileopen_rb = create_preference_radio_buttons(main_tb, pos++,
	    "File Open dialog behavior:", NULL, gui_fileopen_vals,
	    prefs.gui_fileopen_style);
        
	/* Directory to default File Open dialog to */
	fileopen_dir_te = create_preference_entry(main_tb, pos++, "Directory:",
	    NULL, prefs.gui_fileopen_dir);
	OBJECT_SET_DATA(main_vb, GUI_FILEOPEN_KEY, fileopen_rb);
        OBJECT_SET_DATA(main_vb, GUI_FILEOPEN_DIR_KEY, fileopen_dir_te);
	SIGNAL_CONNECT(fileopen_rb, "clicked", fileopen_selected_cb, main_vb);
        SIGNAL_CONNECT(fileopen_dir_te, "focus-out-event",
                       fileopen_dir_changed_cb, main_vb);

	/* "Font..." button - click to open a font selection dialog box. */
#if GTK_MAJOR_VERSION < 2
	font_bt = gtk_button_new_with_label("Font...");
#else
        font_bt = gtk_button_new_from_stock(GTK_STOCK_SELECT_FONT);
#endif
	SIGNAL_CONNECT(font_bt, "clicked", font_browse_cb, NULL);
	gtk_table_attach_defaults( GTK_TABLE(main_tb), font_bt, 2, 3, 0, 1 );

	/* "Colors..." button - click to open a color selection dialog box. */
#if GTK_MAJOR_VERSION < 2
	color_bt = gtk_button_new_with_label("Colors...");
#else
        color_bt = gtk_button_new_from_stock(GTK_STOCK_SELECT_COLOR);
#endif
	SIGNAL_CONNECT(color_bt, "clicked", color_browse_cb, NULL);
	gtk_table_attach_defaults( GTK_TABLE(main_tb), color_bt, 2, 3, 1, 2 );

        fileopen_selected_cb(NULL, main_vb);        

	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}

/* Create a font dialog for browsing. */
static void
font_browse_cb(GtkWidget *w, gpointer data _U_)
{
	GtkWidget *caller = gtk_widget_get_toplevel(w);
	GtkWidget *font_browse_w;
#if GTK_MAJOR_VERSION < 2
	static gchar *fixedwidths[] = { "c", "m", NULL };
#endif

	/* Has a font dialog box already been opened for that top-level
	   widget? */
	font_browse_w = OBJECT_GET_DATA(caller, FONT_DIALOG_PTR_KEY);

	if (font_browse_w != NULL) {
		/* Yes.  Just re-activate that dialog box. */
		reactivate_window(font_browse_w);
		return;
	}

	/* Now create a new dialog. */
	font_browse_w = gtk_font_selection_dialog_new("Ethereal: Select Font");
	gtk_window_set_transient_for(GTK_WINDOW(font_browse_w),
	    GTK_WINDOW(top_level));

	/* Call a handler when we're destroyed, so we can inform
	   our caller, if any, that we've been destroyed. */
	SIGNAL_CONNECT(font_browse_w, "destroy", font_browse_destroy, NULL);

#if GTK_MAJOR_VERSION < 2
	/* Set its filter to show only fixed_width fonts. */
	gtk_font_selection_dialog_set_filter(
	    GTK_FONT_SELECTION_DIALOG(font_browse_w),
	    GTK_FONT_FILTER_BASE, /* user can't change the filter */
	    GTK_FONT_ALL,	  /* bitmap or scalable are fine */
	    NULL,		  /* all foundries are OK */
	    NULL,		  /* all weights are OK (XXX - normal only?) */
	    NULL,		  /* all slants are OK (XXX - Roman only?) */
	    NULL,		  /* all setwidths are OK */
	    fixedwidths,	  /* ONLY fixed-width fonts */
	    NULL);	/* all charsets are OK (XXX - ISO 8859/1 only?) */
#endif

	/* Set the font to the current font.
	   XXX - GTK+ 1.2.8, and probably earlier versions, have a bug
	   wherein that doesn't necessarily cause that font to be
	   selected in the dialog box.  I've sent to the GTK+ folk
	   a fix; hopefully, it'll show up in 1.2.9 if, as, and when
	   they put out a 1.2.9 release. */
	gtk_font_selection_dialog_set_font_name(
	    GTK_FONT_SELECTION_DIALOG(font_browse_w), prefs.gui_font_name);

	/* Set the FONT_CALLER_PTR_KEY for the new dialog to point to
	   our caller. */
	OBJECT_SET_DATA(font_browse_w, FONT_CALLER_PTR_KEY, caller);

	/* Set the FONT_DIALOG_PTR_KEY for the caller to point to us */
	OBJECT_SET_DATA(caller, FONT_DIALOG_PTR_KEY, font_browse_w);

	/* Connect the ok_button to font_browse_ok_cb function and pass along a
	   pointer to the font selection box widget */
	SIGNAL_CONNECT(GTK_FONT_SELECTION_DIALOG(font_browse_w)->ok_button,
                       "clicked", font_browse_ok_cb, font_browse_w);

	/* Connect the cancel_button to destroy the widget */
	SIGNAL_CONNECT_OBJECT(
            GTK_FONT_SELECTION_DIALOG(font_browse_w)->cancel_button, "clicked",
            gtk_widget_destroy, font_browse_w);

	/* Catch the "key_press_event" signal in the window, so that we can
	   catch the ESC key being pressed and act as if the "Cancel" button
	   had been selected. */
	dlg_set_cancel(font_browse_w,
                       GTK_FONT_SELECTION_DIALOG(font_browse_w)->cancel_button);

	gtk_widget_show(font_browse_w);
}

static void
font_browse_ok_cb(GtkWidget *w _U_, GtkFontSelectionDialog *fs)
{
	gchar   *font_name;
#if GTK_MAJOR_VERSION < 2
        gchar   *bold_font_name;
	GdkFont *new_r_font, *new_b_font;
#else
        PangoFontDescription *new_r_font, *new_b_font;
#endif

	font_name = g_strdup(gtk_font_selection_dialog_get_font_name(
	      GTK_FONT_SELECTION_DIALOG(fs)));
	if (font_name == NULL) {
		/* No font was selected; let the user know, but don't
		   tear down the font selection dialog, so they can
		   try again. */
		simple_dialog(ESD_TYPE_CRIT | ESD_TYPE_MODAL, NULL,
		   "You have not selected a font.");
		return;
	}

#if GTK_MAJOR_VERSION < 2
	/* Get the name that the boldface version of that font would have. */
	bold_font_name = boldify(font_name);

	/* Now load those fonts, just to make sure we can. */
	new_r_font = gdk_font_load(font_name);
#else
        new_r_font = pango_font_description_from_string(font_name);
#endif
	if (new_r_font == NULL) {
		/* Oops, that font didn't work.
		   Tell the user, but don't tear down the font selection
		   dialog, so that they can try again. */
		simple_dialog(ESD_TYPE_CRIT | ESD_TYPE_MODAL, NULL,
		   "The font you selected cannot be loaded.");

		g_free(font_name);
#if GTK_MAJOR_VERSION < 2
		g_free(bold_font_name);
#endif
		return;
	}

#if GTK_MAJOR_VERSION < 2
	new_b_font = gdk_font_load(bold_font_name);
#else
        new_b_font = pango_font_description_copy(new_r_font);
        pango_font_description_set_weight(new_b_font,
                                          PANGO_WEIGHT_BOLD);
#endif
	if (new_b_font == NULL) {
		/* Oops, that font didn't work.
		   Tell the user, but don't tear down the font selection
		   dialog, so that they can try again. */
		simple_dialog(ESD_TYPE_CRIT | ESD_TYPE_MODAL, NULL,
		   "The font you selected doesn't have a boldface version.");

		g_free(font_name);
#if GTK_MAJOR_VERSION < 2
		g_free(bold_font_name);
		gdk_font_unref(new_r_font);
#else
                pango_font_description_free(new_r_font);
#endif
		return;
	}

	font_changed = TRUE;
	new_font_name = font_name;

	gtk_widget_hide(GTK_WIDGET(fs));
	gtk_widget_destroy(GTK_WIDGET(fs));
}

static void
font_browse_destroy(GtkWidget *win, gpointer data _U_)
{
	GtkWidget *caller;

	/* Get the widget that requested that we be popped up, if any.
	   (It should arrange to destroy us if it's destroyed, so
	   that we don't get a pointer to a non-existent window here.) */
	caller = OBJECT_GET_DATA(win, FONT_CALLER_PTR_KEY);

	if (caller != NULL) {
		/* Tell it we no longer exist. */
		OBJECT_SET_DATA(caller, FONT_DIALOG_PTR_KEY, NULL);
	}

	/* Now nuke this window. */
	gtk_grab_remove(GTK_WIDGET(win));
	gtk_widget_destroy(GTK_WIDGET(win));
}

static gint
fetch_enum_value(gpointer control, const enum_val_t *enumvals)
{
	return fetch_preference_option_menu_val(GTK_WIDGET(control), enumvals);
}

void
gui_prefs_fetch(GtkWidget *w)
{
	prefs.gui_scrollbar_on_right = fetch_enum_value(
	    OBJECT_GET_DATA(w, SCROLLBAR_PLACEMENT_KEY),
            scrollbar_placement_vals);
	prefs.gui_plist_sel_browse = fetch_enum_value(
	    OBJECT_GET_DATA(w, PLIST_SEL_BROWSE_KEY), selection_mode_vals);
	prefs.gui_ptree_sel_browse = fetch_enum_value(
	    OBJECT_GET_DATA(w, PTREE_SEL_BROWSE_KEY), selection_mode_vals);
#if GTK_MAJOR_VERSION < 2
	prefs.gui_ptree_line_style = fetch_enum_value(
	    OBJECT_GET_DATA(w, PTREE_LINE_STYLE_KEY), line_style_vals);
	prefs.gui_ptree_expander_style = fetch_enum_value(
	    OBJECT_GET_DATA(w, PTREE_EXPANDER_STYLE_KEY), expander_style_vals);
#else
        prefs.gui_altern_colors = fetch_enum_value(
	    OBJECT_GET_DATA(w, ALTERN_COLORS_KEY), altern_colors_vals);
#endif
	prefs.gui_hex_dump_highlight_style = fetch_enum_value(
	    OBJECT_GET_DATA(w, HEX_DUMP_HIGHLIGHT_STYLE_KEY),
            highlight_style_vals);
	prefs.gui_toolbar_main_style = fetch_enum_value(
	    OBJECT_GET_DATA(w, GUI_TOOLBAR_STYLE_KEY),
            toolbar_style_vals);	
	prefs.gui_geometry_save_position =
	    gtk_toggle_button_get_active(OBJECT_GET_DATA(w,
	    	GEOMETRY_POSITION_KEY));
	prefs.gui_geometry_save_size =
	    gtk_toggle_button_get_active(OBJECT_GET_DATA(w, GEOMETRY_SIZE_KEY));
        prefs.gui_fileopen_style = fetch_preference_radio_buttons_val(
            OBJECT_GET_DATA(w, GUI_FILEOPEN_KEY), gui_fileopen_vals);
            
        if (prefs.gui_fileopen_dir != NULL)
                g_free(prefs.gui_fileopen_dir);
        prefs.gui_fileopen_dir = g_strdup(gtk_entry_get_text(
                GTK_ENTRY(OBJECT_GET_DATA(w, GUI_FILEOPEN_DIR_KEY))));

	if (font_changed) {
		if (prefs.gui_font_name != NULL)
			g_free(prefs.gui_font_name);
		prefs.gui_font_name = g_strdup(new_font_name);
	}

	if (colors_changed)
		fetch_colors();
}

void
gui_prefs_apply(GtkWidget *w _U_)
{
#if GTK_MAJOR_VERSION < 2
	GdkFont *new_r_font, *new_b_font;
	char *bold_font_name;
	GdkFont *old_r_font = NULL, *old_b_font = NULL;
#else
        PangoFontDescription *new_r_font, *new_b_font;
	PangoFontDescription *old_r_font = NULL, *old_b_font = NULL;
#endif

	if (font_changed) {
		/* XXX - what if the world changed out from under
		   us, so that one or both of these fonts cannot
		   be loaded? */
#if GTK_MAJOR_VERSION < 2
		new_r_font = gdk_font_load(prefs.gui_font_name);
		bold_font_name = boldify(prefs.gui_font_name);
		new_b_font = gdk_font_load(bold_font_name);
#else
                new_r_font = pango_font_description_from_string(prefs.gui_font_name);
		new_b_font = pango_font_description_copy(new_r_font);
                pango_font_description_set_weight(new_b_font,
                                                  PANGO_WEIGHT_BOLD);
#endif
		set_plist_font(new_r_font);
		set_ptree_font_all(new_r_font);
		old_r_font = m_r_font;
		old_b_font = m_b_font;
		set_fonts(new_r_font, new_b_font);
#if GTK_MAJOR_VERSION < 2
		g_free(bold_font_name);
#endif
	}

	/* Redraw the hex dump windows, in case either the font or the
	   highlight style changed. */
	redraw_hex_dump_all();

	/* Redraw the help window(s). */
	supported_redraw();
	help_redraw();

	/* Redraw the "Follow TCP Stream" windows, in case either the font
	   or the colors to use changed. */
	follow_redraw_all();

	/* XXX: redraw the toolbar only, if style changed */
	toolbar_redraw_all();
	
	set_scrollbar_placement_all();
	set_plist_sel_browse(prefs.gui_plist_sel_browse);
	set_ptree_sel_browse_all(prefs.gui_ptree_sel_browse);
	set_tree_styles_all();
	if (colors_changed)
		update_marked_frames();

	/* We're no longer using the old fonts; unreference them. */
#if GTK_MAJOR_VERSION < 2
	if (old_r_font != NULL)
		gdk_font_unref(old_r_font);
	if (old_b_font != NULL)
		gdk_font_unref(old_b_font);
#else
        if (old_r_font != NULL)
		pango_font_description_free(old_r_font);
	if (old_b_font != NULL)
		pango_font_description_free(old_b_font);
#endif
}

void
gui_prefs_destroy(GtkWidget *w)
{
	GtkWidget *caller = gtk_widget_get_toplevel(w);
	GtkWidget *fs;

	/* Is there a font selection dialog associated with this
	   Preferences dialog? */
	fs = OBJECT_GET_DATA(caller, FONT_DIALOG_PTR_KEY);

	if (fs != NULL) {
		/* Yes.  Destroy it. */
		gtk_widget_destroy(fs);
	}

	/* Is there a color selection dialog associated with this
	   Preferences dialog? */
	fs = OBJECT_GET_DATA(caller, COLOR_DIALOG_PTR_KEY);

	if (fs != NULL) {
		/* Yes.  Destroy it. */
		gtk_widget_destroy(fs);
	}

	/* Free up any saved font name. */
	if (new_font_name != NULL) {
		g_free(new_font_name);
		new_font_name = NULL;
	}
}

/* color selection part */

#define MAX_HANDLED_COL		2

typedef struct {
  GdkColor color;
  char    *label;
} color_info_t;

static color_info_t color_info[MAX_HANDLED_COL] = {
#define MFG_IDX			0
  { {0.0, 0.0, 0.0, 0.0},      	"Marked frame foreground" },
#define MBG_IDX			1
  { {0.0, 0.0, 0.0, 0.0},	"Marked frame background" }
};

#define SAMPLE_MARKED_TEXT	"Sample marked frame text\n"

#define CS_RED			0
#define CS_GREEN		1
#define CS_BLUE			2
#define CS_OPACITY		3

static GdkColor *curcolor = NULL;

static gint
fileopen_dir_changed_cb(GtkWidget *fileopen_entry _U_, GdkEvent *event _U_, gpointer parent_w)
{
    GtkWidget	*fileopen_dir_te;
    char *lastchar;
    gint fileopen_dir_te_length;
    
    fileopen_dir_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, GUI_FILEOPEN_DIR_KEY);
    fileopen_dir_te_length = strlen(gtk_entry_get_text (GTK_ENTRY(fileopen_entry)));
    if (fileopen_dir_te_length == 0) return FALSE;
    lastchar = gtk_editable_get_chars(GTK_EDITABLE(fileopen_entry), fileopen_dir_te_length-1, -1);
    if (strcmp(lastchar, G_DIR_SEPARATOR_S) != 0)
        gtk_entry_append_text(GTK_ENTRY(fileopen_entry), G_DIR_SEPARATOR_S);
    return(FALSE);
}

static void
fileopen_selected_cb(GtkWidget *mybutton_rb _U_, gpointer parent_w)
{
    GtkWidget	*fileopen_rb, *fileopen_dir_te;
    
    fileopen_rb = (GtkWidget *)OBJECT_GET_DATA(parent_w, GUI_FILEOPEN_KEY);
    fileopen_dir_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, GUI_FILEOPEN_DIR_KEY);
    
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(fileopen_rb)))
    {
        gtk_widget_set_sensitive(GTK_WIDGET(fileopen_dir_te), TRUE);
    }
    else
    {
        gtk_widget_set_sensitive(GTK_WIDGET(fileopen_dir_te), FALSE);
    }
    return;
}

static void
color_browse_cb(GtkWidget *w, gpointer data _U_)
{

  GtkWidget *main_vb, *main_tb, *label, *optmenu, *menu, *menuitem;
  GtkWidget *sample, *colorsel, *bbox, *cancel_bt, *ok_bt, *color_w;
  int        i;
  GtkWidget *caller = gtk_widget_get_toplevel(w);
#if GTK_MAJOR_VERSION < 2
  gdouble    scolor[4];
  int        width, height;
#else
  GtkTextBuffer *buffer;
  GtkTextIter    iter;
#endif

  /* Has a color dialog box already been opened for that top-level
     widget? */
  color_w = OBJECT_GET_DATA(caller, COLOR_DIALOG_PTR_KEY);

  if (color_w != NULL) {
    /* Yes.  Just re-activate that dialog box. */
    reactivate_window(color_w);
    return;
  }

  color_t_to_gdkcolor(&color_info[MFG_IDX].color, &prefs.gui_marked_fg);
  color_t_to_gdkcolor(&color_info[MBG_IDX].color, &prefs.gui_marked_bg);
  curcolor = &color_info[MFG_IDX].color;
#if GTK_MAJOR_VERSION < 2
  scolor[CS_RED]     = (gdouble) (curcolor->red)   / 65535.0;
  scolor[CS_GREEN]   = (gdouble) (curcolor->green) / 65535.0;
  scolor[CS_BLUE]    = (gdouble) (curcolor->blue)  / 65535.0;
  scolor[CS_OPACITY] = 1.0;
#endif

  /* Now create a new dialog.
     You can't put your own extra widgets into a color selection
     dialog, as you can with a file selection dialog, so we have to
     construct our own dialog and put a color selection widget
     into it. */
  color_w = dlg_window_new("Ethereal: Select Color");

  SIGNAL_CONNECT(color_w, "delete_event", color_delete_cb, NULL);

  /* Call a handler when we're destroyed, so we can inform our caller,
     if any, that we've been destroyed. */
  SIGNAL_CONNECT(color_w, "destroy", color_destroy_cb, NULL);

  main_vb = gtk_vbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add (GTK_CONTAINER (color_w), main_vb);
  main_tb = gtk_table_new(3, 3, FALSE);
  gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
  gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
  gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
  gtk_widget_show(main_tb);
  label = gtk_label_new("Set:");
  gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, 0, 1);
  gtk_widget_show(label);

  colorsel = gtk_color_selection_new();
  optmenu = gtk_option_menu_new();
  menu = gtk_menu_new();
  for (i = 0; i < MAX_HANDLED_COL; i++){
    menuitem = gtk_menu_item_new_with_label(color_info[i].label);
    OBJECT_SET_DATA(menuitem, COLOR_SELECTION_PTR_KEY, colorsel);
    SIGNAL_CONNECT(menuitem, "activate", update_current_color,
                   &color_info[i].color);
    gtk_widget_show(menuitem);
    gtk_menu_append(GTK_MENU (menu), menuitem);
  }
  gtk_option_menu_set_menu (GTK_OPTION_MENU (optmenu), menu);
  gtk_table_attach_defaults(GTK_TABLE(main_tb), optmenu, 1, 2, 0, 1);
  gtk_widget_show(optmenu);

#if GTK_MAJOR_VERSION < 2
  sample = gtk_text_new(FALSE, FALSE);
  height = sample->style->font->ascent + sample->style->font->descent;
  width = gdk_string_width(sample->style->font, SAMPLE_MARKED_TEXT);
  WIDGET_SET_SIZE(GTK_WIDGET(sample), width, height);
  gtk_text_set_editable(GTK_TEXT(sample), FALSE);
  gtk_text_insert(GTK_TEXT(sample), NULL,
		  &color_info[MFG_IDX].color,
		  &color_info[MBG_IDX].color,
		  SAMPLE_MARKED_TEXT, -1);
#else
  sample = gtk_text_view_new();
  buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(sample));
  gtk_text_view_set_editable(GTK_TEXT_VIEW(sample), FALSE);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(sample), FALSE);
  gtk_text_buffer_create_tag(buffer, "color", "foreground-gdk",
                             &color_info[MFG_IDX].color, "background-gdk",
                             &color_info[MBG_IDX].color, NULL);
  gtk_text_buffer_get_start_iter(buffer, &iter);
  gtk_text_buffer_insert_with_tags_by_name(buffer, &iter, SAMPLE_MARKED_TEXT,
                                           -1, "color", NULL);
#endif
  gtk_table_attach_defaults(GTK_TABLE(main_tb), sample, 2, 3, 0, 2);
  gtk_widget_show(sample);
#if GTK_MAJOR_VERSION < 2
  gtk_color_selection_set_color(GTK_COLOR_SELECTION(colorsel),
				&scolor[CS_RED]);
#else
  gtk_color_selection_set_current_color(GTK_COLOR_SELECTION(colorsel),
                                        curcolor);
#endif
  gtk_table_attach_defaults(GTK_TABLE(main_tb), colorsel, 0, 3, 2, 3);
  OBJECT_SET_DATA(colorsel, COLOR_SAMPLE_PTR_KEY, sample);
  SIGNAL_CONNECT(colorsel, "color-changed", update_text_color, NULL);
  gtk_widget_show(colorsel);
  gtk_widget_show(main_vb);

  OBJECT_SET_DATA(color_w, COLOR_CALLER_PTR_KEY, caller);
  OBJECT_SET_DATA(caller, COLOR_DIALOG_PTR_KEY, color_w);

  /* Ok, Cancel Buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);
  gtk_widget_show(bbox);

#if GTK_MAJOR_VERSION < 2
  ok_bt = gtk_button_new_with_label ("OK");
#else
  ok_bt = gtk_button_new_from_stock(GTK_STOCK_OK);
#endif
  SIGNAL_CONNECT(ok_bt, "clicked", color_ok_cb, color_w);
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);
#if GTK_MAJOR_VERSION < 2
  cancel_bt = gtk_button_new_with_label ("Cancel");
#else
  cancel_bt = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
#endif
  SIGNAL_CONNECT_OBJECT(cancel_bt, "clicked", gtk_widget_destroy, color_w);
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start(GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);
  dlg_set_cancel(color_w, cancel_bt);

  gtk_widget_show(color_w);
}

static void
update_text_color(GtkWidget *w, gpointer data _U_) {
  GtkWidget     *sample = OBJECT_GET_DATA(w, COLOR_SAMPLE_PTR_KEY);
#if GTK_MAJOR_VERSION < 2
  gdouble        scolor[4];

  gtk_color_selection_get_color(GTK_COLOR_SELECTION(w), &scolor[CS_RED]);

  curcolor->red   = (gushort) (scolor[CS_RED]   * 65535.0);
  curcolor->green = (gushort) (scolor[CS_GREEN] * 65535.0);
  curcolor->blue  = (gushort) (scolor[CS_BLUE]  * 65535.0);
#else
  GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(sample));
  GtkTextTag    *tag;

  gtk_color_selection_get_current_color(GTK_COLOR_SELECTION(w), curcolor);
#endif

#if GTK_MAJOR_VERSION < 2
  gtk_text_freeze(GTK_TEXT(sample));
  gtk_text_set_point(GTK_TEXT(sample), 0);
  gtk_text_forward_delete(GTK_TEXT(sample),
                          gtk_text_get_length(GTK_TEXT(sample)));
  gtk_text_insert(GTK_TEXT(sample), NULL,
		  &color_info[MFG_IDX].color,
		  &color_info[MBG_IDX].color,
		  SAMPLE_MARKED_TEXT, -1);
  gtk_text_thaw(GTK_TEXT(sample));
#else
  tag = gtk_text_tag_table_lookup(gtk_text_buffer_get_tag_table(buffer),
                                  "color");
  g_object_set(tag, "foreground-gdk", &color_info[MFG_IDX].color,
               "background-gdk", &color_info[MBG_IDX].color, NULL);
#endif
}

static void
update_current_color(GtkWidget *w, gpointer data)
{
  GtkColorSelection *colorsel;
#if GTK_MAJOR_VERSION < 2
  gdouble            scolor[4];

  colorsel = GTK_COLOR_SELECTION(OBJECT_GET_DATA(w, COLOR_SELECTION_PTR_KEY));
  curcolor = (GdkColor *)data;
  scolor[CS_RED]     = (gdouble) (curcolor->red)   / 65535.0;
  scolor[CS_GREEN]   = (gdouble) (curcolor->green) / 65535.0;
  scolor[CS_BLUE]    = (gdouble) (curcolor->blue)  / 65535.0;
  scolor[CS_OPACITY] = 1.0;

  gtk_color_selection_set_color(colorsel, &scolor[CS_RED]);
#else
  colorsel = GTK_COLOR_SELECTION(g_object_get_data(G_OBJECT(w),
                                                   COLOR_SELECTION_PTR_KEY));
  curcolor = (GdkColor *)data;
  gtk_color_selection_set_current_color(colorsel, curcolor);
#endif
}

static void
color_ok_cb(GtkWidget *w _U_, gpointer data)
{
  /* We assume the user actually changed a color here. */
  colors_changed = TRUE;

  gtk_widget_hide(GTK_WIDGET(data));
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void
color_cancel_cb(GtkWidget *w _U_, gpointer data)
{
  /* Revert the colors to the current preference settings. */
  color_t_to_gdkcolor(&color_info[MFG_IDX].color, &prefs.gui_marked_fg);
  color_t_to_gdkcolor(&color_info[MBG_IDX].color, &prefs.gui_marked_bg);
  gtk_widget_hide(GTK_WIDGET(data));
  gtk_widget_destroy(GTK_WIDGET(data));
}

/* Treat this as a cancel, by calling "color_cancel_cb()".
   XXX - that'll destroy the Select Color dialog; will that upset
   a higher-level handler that says "OK, we've been asked to delete
   this, so destroy it"? */
static gboolean
color_delete_cb(GtkWidget *prefs_w _U_, gpointer dummy _U_)
{
  color_cancel_cb(NULL, NULL);
  return FALSE;
}

static void
color_destroy_cb(GtkWidget *w, gpointer data _U_)
{
  GtkWidget *caller = OBJECT_GET_DATA(w, COLOR_CALLER_PTR_KEY);
  if (caller != NULL) {
    OBJECT_SET_DATA(caller, COLOR_DIALOG_PTR_KEY, NULL);
  }
  gtk_grab_remove(GTK_WIDGET(w));
  gtk_widget_destroy(GTK_WIDGET(w));
}

static void
fetch_colors(void)
{
  gdkcolor_to_color_t(&prefs.gui_marked_fg, &color_info[MFG_IDX].color);
  gdkcolor_to_color_t(&prefs.gui_marked_bg, &color_info[MBG_IDX].color);
}
