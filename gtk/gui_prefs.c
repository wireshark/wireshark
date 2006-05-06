/* gui_prefs.c
 * Dialog box for GUI preferences
 *
 * $Id$
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

#include "globals.h"
#include "gui_prefs.h"
#include "gtkglobals.h"
#include "help_dlg.h"
#include "supported_protos_dlg.h"
#include <epan/prefs.h>
#include "prefs_dlg.h"
#include "gui_utils.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "proto_draw.h"
#include "main.h"
#include "compat_macros.h"
#include "font_utils.h"
#include "packet_list.h"
#include "toolbar.h"
#include "recent.h"
#include "webbrowser.h"


static gint fetch_enum_value(gpointer control, const enum_val_t *enumvals);
static gint fileopen_dir_changed_cb(GtkWidget *myentry _U_, GdkEvent *event, gpointer parent_w);
static gint fileopen_preview_changed_cb(GtkWidget *myentry _U_, GdkEvent *event, gpointer parent_w);
static void fileopen_selected_cb(GtkWidget *mybutton_rb _U_, gpointer parent_w);
static gint recent_files_count_changed_cb(GtkWidget *recent_files_entry _U_, 
					  GdkEvent *event _U_, gpointer parent_w);
#define PLIST_SEL_BROWSE_KEY		"plist_sel_browse"
#define PTREE_SEL_BROWSE_KEY		"ptree_sel_browse"
#define GEOMETRY_POSITION_KEY		"geometry_position"
#define GEOMETRY_SIZE_KEY		"geometry_size"
#define GEOMETRY_MAXIMIZED_KEY		"geometry_maximized"

#define GUI_CONSOLE_OPEN_KEY "console_open"
#define GUI_FILEOPEN_KEY	"fileopen_behavior"
#define GUI_FILEOPEN_PREVIEW_KEY "fileopen_preview_timeout"
#define GUI_RECENT_FILES_COUNT_KEY "recent_files_count"
#define GUI_FILEOPEN_DIR_KEY	"fileopen_directory"
#define GUI_ASK_UNSAVED_KEY     "ask_unsaved"
#define GUI_WEBBROWSER_KEY	    "webbrowser"
#define GUI_FIND_WRAP_KEY       "find_wrap"

static const enum_val_t scrollbar_placement_vals[] = {
	{ "FALSE", "Left", FALSE },
	{ "TRUE",  "Right", TRUE },
	{ NULL,    NULL,    0 }
};

static const enum_val_t selection_mode_vals[] = {
	{ "FALSE", "Selects", FALSE },
	{ "TRUE",  "Browses", TRUE },
	{ NULL,    NULL,      0 }
};

#if GTK_MAJOR_VERSION < 2
static const enum_val_t line_style_vals[] = {
	{ "NONE",   "None",   0 },
	{ "SOLID",  "Solid",  1 },
	{ "DOTTED", "Dotted", 2 },
	{ "TABBED", "Tabbed", 3 },
	{ NULL,     NULL,     0 }
};

static const enum_val_t expander_style_vals[] = {
	{ "NONE",     "None",     0 },
	{ "SQUARE",   "Square",   1 },
	{ "TRIANGLE", "Triangle", 2 },
	{ "CIRCULAR", "Circular", 3 },
	{ NULL,       NULL,       0 }
};
#else
static const enum_val_t altern_colors_vals[] = {
	{ "FALSE", "No",  FALSE },
	{ "TRUE",  "Yes", TRUE },
	{ NULL,    NULL,  0 }
};
#endif

static const enum_val_t filter_toolbar_placement_vals[] = {
	{ "FALSE", "Below the main toolbar", FALSE },
	{ "TRUE",  "Insert into statusbar",  TRUE },
	{ NULL,    NULL,                     0 }
};

static const enum_val_t highlight_style_vals[] = {
  	{ "FALSE", "Bold",     FALSE },
  	{ "TRUE",  "Inverse",  TRUE },
	{ NULL,    NULL,       0 }
};


static const enum_val_t toolbar_style_vals[] = {
  	{ "ICONS", "Icons only",     TB_STYLE_ICONS },
  	{ "TEXT",  "Text only",      TB_STYLE_TEXT },
  	{ "BOTH",  "Icons & Text",   TB_STYLE_BOTH },
	{ NULL,    NULL,             0 }
};

#ifdef _WIN32
static const enum_val_t gui_console_open_vals[] = {
	{ "NEVER",     "Never",                      console_open_never },
	{ "AUTOMATIC", "Automatic (advanced user)",  console_open_auto },
	{ "ALWAYS",    "Always (debugging)",         console_open_always },
	{ NULL,        NULL,                         0 }
};
#endif

static const enum_val_t gui_fileopen_vals[] = {
	{ "LAST_OPENED", "Remember last directory", FO_STYLE_LAST_OPENED },
	{ "SPECIFIED",   "Always start in:",        FO_STYLE_SPECIFIED },
	{ NULL,          NULL,                      0 }
};

/* Set to FALSE initially; set to TRUE if the user ever hits "OK" on
   the "Font..." dialog, so that we know that they (probably) changed
   the font, and therefore that the "apply" function needs to take care
   of that */
static gboolean font_changed;

/* Font name from the font dialog box; if "font_changed" is TRUE, this
   has been set to the name of the font the user selected. */
static gchar *new_font_name;

static GtkWidget *font_browse_w;

/* Used to contain the string from the Recent Files Count Max pref item */
static char recent_files_count_max_str[128] = "";

/* Used to contain the string from the Open File preview timeout pref item */
static char open_file_preview_str[128] = "";

#if GTK_MAJOR_VERSION < 2
#define GUI_TABLE_ROWS 5
#else
#define GUI_TABLE_ROWS 4
#endif

GtkWidget*
gui_prefs_show(void)
{
	GtkWidget *main_tb, *main_vb;
	GtkWidget *plist_browse_om;
	GtkWidget *ptree_browse_om;
#ifdef _WIN32
	GtkWidget *console_open_om;
#endif
	GtkWidget *fileopen_rb, *fileopen_dir_te, *fileopen_preview_te;
	GtkWidget *recent_files_count_max_te, *ask_unsaved_cb, *find_wrap_cb;
	GtkWidget *webbrowser_te;
	GtkWidget *save_position_cb, *save_size_cb, *save_maximized_cb;

	GtkTooltips *tooltips = gtk_tooltips_new();

	int        pos = 0;
	char       current_val_str[128];

	/* The font haven't been changed yet. */
	font_changed = FALSE;

	/* Main vertical box */
	main_vb = gtk_vbox_new(FALSE, 7);
	gtk_container_border_width( GTK_CONTAINER(main_vb), 5 );

        /* Main table */
        main_tb = gtk_table_new(GUI_TABLE_ROWS, 2, FALSE);
        gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
        gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
        gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);

	/* Packet list selection browseable */
	plist_browse_om = create_preference_option_menu(main_tb, pos++,
	    "Packet list selection mode:", NULL, selection_mode_vals,
	    prefs.gui_plist_sel_browse);
	gtk_tooltips_set_tip(tooltips, plist_browse_om, "Choose to browse "
		"or select a packet for detailed dissection.", NULL);
	OBJECT_SET_DATA(main_vb, PLIST_SEL_BROWSE_KEY, plist_browse_om);

	/* Proto tree selection browseable */
	ptree_browse_om = create_preference_option_menu(main_tb, pos++,
	    "Protocol tree selection mode:", NULL, selection_mode_vals,
	    prefs.gui_ptree_sel_browse);
	gtk_tooltips_set_tip(tooltips, ptree_browse_om, "Choose to browse "
		"or select.", NULL);
	OBJECT_SET_DATA(main_vb, PTREE_SEL_BROWSE_KEY, ptree_browse_om);

	/* Geometry prefs */
	save_position_cb = create_preference_check_button(main_tb, pos++,
	    "Save window position:", NULL, prefs.gui_geometry_save_position);
	gtk_tooltips_set_tip(tooltips, save_position_cb, "Whether to save the "
		"position of the main window.", NULL);
	OBJECT_SET_DATA(main_vb, GEOMETRY_POSITION_KEY, save_position_cb);

	save_size_cb = create_preference_check_button(main_tb, pos++,
	    "Save window size:", NULL, prefs.gui_geometry_save_size);
	gtk_tooltips_set_tip(tooltips, save_size_cb, "Whether to save the "
		"size of the main window.", NULL);
	OBJECT_SET_DATA(main_vb, GEOMETRY_SIZE_KEY, save_size_cb);

	save_maximized_cb = create_preference_check_button(main_tb, pos++,
	    "Save maximized state:", NULL, prefs.gui_geometry_save_maximized);
	gtk_tooltips_set_tip(tooltips, save_maximized_cb, "Whether to save the "
		"maximed state of the main window.", NULL);
	OBJECT_SET_DATA(main_vb, GEOMETRY_MAXIMIZED_KEY, save_maximized_cb);

#ifdef _WIN32
	/* How the console window should be opened */
	console_open_om = create_preference_option_menu(main_tb, pos++,
		"Open a console window", NULL, gui_console_open_vals, 
		prefs.gui_console_open);
	gtk_tooltips_set_tip(tooltips, console_open_om, "Whether to open a console window "
		"(Automatic will open a console if messages appear).", NULL);
	OBJECT_SET_DATA(main_vb, GUI_CONSOLE_OPEN_KEY, console_open_om);
#endif

	/* Allow user to select where they want the File Open dialog to open to
	 * by default */
	fileopen_rb = create_preference_radio_buttons(main_tb, pos++,
	    "\"File Open\" dialog behavior:", 
        "Which directory the \"File Open\" dialog should start with.", gui_fileopen_vals,
	    prefs.gui_fileopen_style);

	/* Directory to default File Open dialog to */
	fileopen_dir_te = create_preference_entry(main_tb, pos++, 
        "Directory:", NULL, prefs.gui_fileopen_dir);
	gtk_tooltips_set_tip(tooltips, fileopen_dir_te,
		"The \"File Open\" dialog defaults always to this directory.", NULL);
	OBJECT_SET_DATA(main_vb, GUI_FILEOPEN_KEY, fileopen_rb);
	OBJECT_SET_DATA(main_vb, GUI_FILEOPEN_DIR_KEY, fileopen_dir_te);
	SIGNAL_CONNECT(fileopen_rb, "clicked", fileopen_selected_cb, main_vb);
	SIGNAL_CONNECT(fileopen_dir_te, "focus-out-event",
	    fileopen_dir_changed_cb, main_vb);

	/* File Open dialog preview timeout */
	fileopen_preview_te = create_preference_entry(main_tb, pos++,
	    "\"File Open\" preview timeout:", "Timeout, until preview gives up scanning the capture file content.", open_file_preview_str);
	g_snprintf(current_val_str, 128, "%d", prefs.gui_fileopen_preview);
	gtk_entry_set_text(GTK_ENTRY(fileopen_preview_te), current_val_str);
	gtk_tooltips_set_tip(tooltips, fileopen_preview_te, 
        "Reading preview data in the \"File Open\" dialog will be stopped after given seconds.", NULL);
	OBJECT_SET_DATA(main_vb, GUI_FILEOPEN_PREVIEW_KEY, fileopen_preview_te);
	SIGNAL_CONNECT(fileopen_preview_te, "focus_out_event", fileopen_preview_changed_cb, main_vb);

	/* Number of entries in the recent_files list ... */
	recent_files_count_max_te = create_preference_entry(main_tb, pos++,
	    "\"Open Recent\" max. list entries:", "Maximum number of recent files", recent_files_count_max_str);
	g_snprintf(current_val_str, 128, "%d", prefs.gui_recent_files_count_max);
	gtk_entry_set_text(GTK_ENTRY(recent_files_count_max_te), current_val_str);
	gtk_tooltips_set_tip(tooltips, recent_files_count_max_te, 
        "Maximum number of entries in the \"File/Open Recent\" list.", NULL);
	OBJECT_SET_DATA(main_vb, GUI_RECENT_FILES_COUNT_KEY, recent_files_count_max_te);
	SIGNAL_CONNECT(recent_files_count_max_te, "focus_out_event", recent_files_count_changed_cb, main_vb);

	fileopen_selected_cb(NULL, main_vb);

	/* ask for unsaved capture files? */
	ask_unsaved_cb = create_preference_check_button(main_tb, pos++,
	    "Ask for unsaved capture files:", NULL, prefs.gui_ask_unsaved);
	gtk_tooltips_set_tip(tooltips, ask_unsaved_cb, "Whether a dialog should "
		"pop up in case of an unsaved capture file.", NULL);
	OBJECT_SET_DATA(main_vb, GUI_ASK_UNSAVED_KEY, ask_unsaved_cb);

	/* do we want to wrap when searching for data? */
	find_wrap_cb = create_preference_check_button(main_tb, pos++,
	    "Wrap to end/beginning of file during a find:", NULL, prefs.gui_find_wrap);
	gtk_tooltips_set_tip(tooltips, find_wrap_cb, "Whether a search should "
		"wrap in a capture file.", NULL);
	OBJECT_SET_DATA(main_vb, GUI_FIND_WRAP_KEY, find_wrap_cb);

	/* Webbrowser */
	if (browser_needs_pref()) {
	    webbrowser_te = create_preference_entry(main_tb, pos++, 
            "Web browser command:", NULL, prefs.gui_webbrowser);
	    gtk_entry_set_text(GTK_ENTRY(webbrowser_te), prefs.gui_webbrowser);
	    gtk_tooltips_set_tip(tooltips, webbrowser_te, "Command line to "
	        "desired browser.", NULL);
	    OBJECT_SET_DATA(main_vb, GUI_WEBBROWSER_KEY, webbrowser_te);
	}

	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}


/* Create a font widget for browsing. */
GtkWidget *
gui_font_prefs_show(void)
{
	/* Create the font selection widget. */
	font_browse_w = (GtkWidget *) gtk_font_selection_new();
	gtk_widget_show(font_browse_w);

	return font_browse_w;
}


static gboolean
font_fetch(void)
{
	gchar   *font_name;

	font_name = g_strdup(gtk_font_selection_get_font_name(
	      GTK_FONT_SELECTION(font_browse_w)));
	if (font_name == NULL) {
		/* No font was selected; let the user know, but don't
		   tear down the font selection dialog, so they can
		   try again. */
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		   "You have not selected a font.");
		return FALSE;
	}

	if (!user_font_test(font_name)) {
		/* The font isn't usable; "user_font_test()" has already
		   told the user why.  Don't tear down the font selection
		   dialog. */
		g_free(font_name);
		return FALSE;
	}
	new_font_name = font_name;
	return TRUE;
}


static gint
fetch_enum_value(gpointer control, const enum_val_t *enumvals)
{
	return fetch_preference_option_menu_val(GTK_WIDGET(control), enumvals);
}

void
gui_prefs_fetch(GtkWidget *w)
{
	prefs.gui_plist_sel_browse = fetch_enum_value(
	    OBJECT_GET_DATA(w, PLIST_SEL_BROWSE_KEY), selection_mode_vals);
	prefs.gui_ptree_sel_browse = fetch_enum_value(
	    OBJECT_GET_DATA(w, PTREE_SEL_BROWSE_KEY), selection_mode_vals);
	prefs.gui_geometry_save_position =
	    gtk_toggle_button_get_active(OBJECT_GET_DATA(w, GEOMETRY_POSITION_KEY));
	prefs.gui_geometry_save_size =
	    gtk_toggle_button_get_active(OBJECT_GET_DATA(w, GEOMETRY_SIZE_KEY));
	prefs.gui_geometry_save_maximized =
	    gtk_toggle_button_get_active(OBJECT_GET_DATA(w, GEOMETRY_MAXIMIZED_KEY));
#ifdef _WIN32
	prefs.gui_console_open = fetch_enum_value(
	    OBJECT_GET_DATA(w, GUI_CONSOLE_OPEN_KEY), gui_console_open_vals);
#endif
	prefs.gui_fileopen_style = fetch_preference_radio_buttons_val(
	    OBJECT_GET_DATA(w, GUI_FILEOPEN_KEY), gui_fileopen_vals);
	
	if (prefs.gui_fileopen_dir != NULL)
		g_free(prefs.gui_fileopen_dir);
	prefs.gui_fileopen_dir = g_strdup(gtk_entry_get_text(
		GTK_ENTRY(OBJECT_GET_DATA(w, GUI_FILEOPEN_DIR_KEY))));

    prefs.gui_ask_unsaved = 
	    gtk_toggle_button_get_active(OBJECT_GET_DATA(w, GUI_ASK_UNSAVED_KEY));

    prefs.gui_find_wrap = 
	    gtk_toggle_button_get_active(OBJECT_GET_DATA(w, GUI_FIND_WRAP_KEY));

    if (browser_needs_pref()) {
		g_free(prefs.gui_webbrowser);
	    prefs.gui_webbrowser = g_strdup(gtk_entry_get_text(
		    GTK_ENTRY(OBJECT_GET_DATA(w, GUI_WEBBROWSER_KEY))));
    }
	/*
	 * XXX - we need to have a way to fetch the preferences into
	 * local storage and only set the permanent preferences if there
	 * weren't any errors in those fetches, as there are several
	 * places where there *can* be a bad preference value.
	 */
	if (font_fetch()) {
		if (strcmp(new_font_name, prefs.PREFS_GUI_FONT_NAME) != 0) {
			font_changed = TRUE;
			if (prefs.PREFS_GUI_FONT_NAME != NULL)
				g_free(prefs.PREFS_GUI_FONT_NAME);
			prefs.PREFS_GUI_FONT_NAME = g_strdup(new_font_name);
		}
	}
}



void
gui_prefs_apply(GtkWidget *w _U_)
{

#ifdef _WIN32
    /* user immediately wants to see a console */
    if (prefs.gui_console_open == console_open_always) {
        create_console();
    }
#endif

	if (font_changed) {
		/* This redraws the hex dump windows. */
		switch (user_font_apply()) {

		case FA_SUCCESS:
			break;

		case FA_FONT_NOT_RESIZEABLE:
			/* "user_font_apply()" popped up an alert box. */
			/* turn off zooming - font can't be resized */
			recent.gui_zoom_level = 0;
			break;

		case FA_FONT_NOT_AVAILABLE:
			/* We assume this means that the specified size
			   isn't available. */
			simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			    "That font isn't available at the specified zoom level;\n"
			    "turning zooming off.");
			recent.gui_zoom_level = 0;
			break;
		}
	} else {
		/* Redraw the hex dump windows, in case the
		   highlight style changed.
		   XXX - do it only if the highlight style *did* change. */
		redraw_hex_dump_all();
	}

	/* Redraw the help window(s). */
	supported_redraw();
	help_redraw();

	/* XXX: redraw the toolbar only, if style changed */
	toolbar_redraw_all();
	
	set_scrollbar_placement_all();
	packet_list_set_sel_browse(prefs.gui_plist_sel_browse);
	set_ptree_sel_browse_all(prefs.gui_ptree_sel_browse);
	set_tree_styles_all();
	main_widgets_rearrange();
}

void
gui_prefs_destroy(GtkWidget *w _U_)
{
	/* Free up any saved font name. */
	if (new_font_name != NULL) {
		g_free(new_font_name);
		new_font_name = NULL;
	}
}


static gint
recent_files_count_changed_cb(GtkWidget *recent_files_entry _U_, 
			      GdkEvent *event _U_, gpointer parent_w)
{
    GtkWidget	*recent_files_count_te;
    guint newval;
    
    recent_files_count_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, GUI_RECENT_FILES_COUNT_KEY);

    /*
     * Now, just convert the string to a number and store it in the prefs
     * filed ...
     */

    newval = strtol(gtk_entry_get_text (GTK_ENTRY(recent_files_count_te)), NULL, 10);

    if (newval > 0) {
      prefs.gui_recent_files_count_max = newval;
    }

    /* We really should pop up a nasty dialog box if newval <= 0 */

    return FALSE;
}

static gint
fileopen_preview_changed_cb(GtkWidget *recent_files_entry _U_, 
			      GdkEvent *event _U_, gpointer parent_w)
{
    GtkWidget	*fileopen_preview_te;
    guint newval;
    
    fileopen_preview_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, GUI_FILEOPEN_PREVIEW_KEY);

    /*
     * Now, just convert the string to a number and store it in the prefs
     * filed ...
     */

    newval = strtol(gtk_entry_get_text (GTK_ENTRY(fileopen_preview_te)), NULL, 10);

    if (newval > 0) {
      prefs.gui_fileopen_preview = newval;
    }

    /* We really should pop up a nasty dialog box if newval <= 0 */

    return FALSE;
}

static gint
fileopen_dir_changed_cb(GtkWidget *fileopen_entry _U_, GdkEvent *event _U_, gpointer parent_w)
{
    GtkWidget	*fileopen_dir_te;
    char *lastchar;
    gint fileopen_dir_te_length;
    
    fileopen_dir_te = (GtkWidget *)OBJECT_GET_DATA(parent_w, GUI_FILEOPEN_DIR_KEY);
    fileopen_dir_te_length = strlen(gtk_entry_get_text (GTK_ENTRY(fileopen_entry)));
    if (fileopen_dir_te_length == 0)
    	return FALSE;
    lastchar = gtk_editable_get_chars(GTK_EDITABLE(fileopen_entry), fileopen_dir_te_length-1, -1);
    if (strcmp(lastchar, G_DIR_SEPARATOR_S) != 0)
	gtk_entry_append_text(GTK_ENTRY(fileopen_entry), G_DIR_SEPARATOR_S);
    return FALSE;
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

