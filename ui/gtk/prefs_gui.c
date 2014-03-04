/* gui_prefs.c
 * Dialog box for GUI preferences
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "cfile.h"

#include "ui/recent.h"

#include "ui/gtk/prefs_gui.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/supported_protos_dlg.h"
#include "ui/gtk/prefs_dlg.h"
#include "ui/gtk/main_titlebar.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/main.h"
#include "ui/gtk/packet_list.h"
#include "ui/gtk/packet_panes.h"
#include "ui/gtk/main_toolbar.h"
#include "ui/gtk/font_utils.h"
#include "ui/gtk/webbrowser.h"
#include "ui/gtk/main_welcome.h"


static gint fetch_enum_value(gpointer control, const enum_val_t *enumvals);
static gboolean fileopen_dir_changed_cb(GtkWidget *myentry, GdkEvent *event _U_, gpointer parent_w _U_);
static gboolean fileopen_preview_changed_cb(GtkWidget *myentry _U_, GdkEvent *event, gpointer parent_w);
static void fileopen_selected_cb(GtkWidget *mybutton_rb _U_, gpointer parent_w);
static gboolean recent_files_count_changed_cb(GtkWidget *recent_files_entry _U_,
					      GdkEvent *event _U_, gpointer parent_w);
static gboolean recent_df_entries_changed_cb(GtkWidget *recent_df_entry _U_,
					     GdkEvent *event _U_, gpointer parent_w);
static gint scroll_percent_changed_cb(GtkWidget *recent_df_entry _U_,
					  GdkEvent *event _U_, gpointer parent_w);
#define GEOMETRY_POSITION_KEY		"geometry_position"
#define GEOMETRY_SIZE_KEY		"geometry_size"
#define GEOMETRY_MAXIMIZED_KEY		"geometry_maximized"

#if defined(HAVE_IGE_MAC_INTEGRATION) || defined(HAVE_GTKOSXAPPLICATION)
#define MACOSX_STYLE_KEY		"macosx_style"
#endif

#ifdef _WIN32
#define GUI_CONSOLE_OPEN_KEY		"console_open"
#define ENABLE_UPDATE_KEY		"enable_update"
#endif

#define GUI_FILEOPEN_KEY		"fileopen_behavior"
#define GUI_FILEOPEN_PREVIEW_KEY	"fileopen_preview_timeout"
#define GUI_RECENT_FILES_COUNT_KEY	"recent_files_count"
#define GUI_RECENT_DF_ENTRIES_KEY	"recent_display_filter_entries"
#define GUI_FILEOPEN_DIR_KEY		"fileopen_directory"
#define GUI_ASK_UNSAVED_KEY		"ask_unsaved"
#define GUI_WEBBROWSER_KEY		"webbrowser"
#define GUI_FIND_WRAP_KEY		"find_wrap"
#define GUI_USE_PREF_SAVE_KEY		"use_pref_save"
#define GUI_SHOW_VERSION_KEY		"show_version"
#define GUI_EXPERT_EYECANDY_KEY		"expert_eyecandy"
#define GUI_AUTO_SCROLL_KEY		"auto_scroll_on_expand"
#define GUI_SCROLL_PERCENT_KEY		"scroll_percent_on_expand"
#define GUI_PACKET_EDITOR		"packet_editor"

static const enum_val_t filter_toolbar_placement_vals[] _U_ = {
	{ "FALSE", "Below the main toolbar", FALSE },
	{ "TRUE",  "Insert into statusbar",  TRUE },
	{ NULL,    NULL,                     0 }
};

static const enum_val_t highlight_style_vals[] _U_ = {
	{ "FALSE", "Bold",     FALSE },
 	{ "TRUE",  "Inverse",  TRUE },
	{ NULL,    NULL,       0 }
};


static const enum_val_t toolbar_style_vals[] _U_ = {
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

static const enum_val_t gui_version_placement_vals[] = {
	{ "WELCOME",  "Welcome only",               version_welcome_only },
	{ "TITLE",    "Title only",                 version_title_only },
	{ "BOTH",     "Both",                       version_both },
	{ "NEITHER",  "Neither",                    version_neither },
	{ NULL,        NULL,                         0 }
};

static const enum_val_t gui_fileopen_vals[] = {
	{ "LAST_OPENED", "Remember last directory", FO_STYLE_LAST_OPENED },
	{ "SPECIFIED",   "Always start in:",        FO_STYLE_SPECIFIED },
	{ NULL,          NULL,                      0 }
};

/* Used to contain the string from the Recent Files Count Max pref item */
static char recent_files_count_max_str[128] = "";

/* Used to contain the string from the Recent Display Filter Max Entries pref item */
static char recent_df_entries_max_str[128] = "";

/* Used to contain the string from the Open File preview timeout pref item */
static char open_file_preview_str[128] = "";

/* Used to contain the string from the Auto Scroll Percentage pref item */
static char scroll_percent_preview_str[128] = "";

GtkWidget*
gui_prefs_show(void)
{
	GtkWidget *main_grid, *main_vb;
#ifdef _WIN32
	GtkWidget *console_open_om, *enable_update_cb;
#endif
	GtkWidget *fileopen_rb, *fileopen_dir_te, *fileopen_preview_te;
	GtkWidget *recent_files_count_max_te, *recent_df_entries_max_te, *ask_unsaved_cb, *find_wrap_cb;
	GtkWidget *use_pref_save_cb;
	GtkWidget *show_version_om;
	GtkWidget *auto_scroll_cb, *scroll_percent_te;
	GtkWidget *webbrowser_te;
	GtkWidget *save_position_cb, *save_size_cb, *save_maximized_cb;
#if defined(HAVE_IGE_MAC_INTEGRATION) || defined(HAVE_GTKOSXAPPLICATION)
	GtkWidget *macosx_style_cb;
#endif
	GtkWidget *expert_info_eyecandy_cb;
	GtkWidget *packet_editor_cb;

	int        pos = 0;
	char       current_val_str[128];

	/* The columns haven't been changed yet */
	cfile.columns_changed = FALSE;

	/* Main vertical box */
	main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 7, FALSE);
	gtk_container_set_border_width( GTK_CONTAINER(main_vb), 5 );

	/* Main grid */
	main_grid = ws_gtk_grid_new();
	gtk_box_pack_start(GTK_BOX(main_vb), main_grid, FALSE, FALSE, 0);
#if GTK_CHECK_VERSION(3,0,0)
        gtk_widget_set_vexpand(GTK_WIDGET(main_grid), FALSE); /* Ignore VEXPAND requests from children */
#endif
	ws_gtk_grid_set_row_spacing(GTK_GRID(main_grid), 10);
	ws_gtk_grid_set_column_spacing(GTK_GRID(main_grid), 15);

	/* Geometry prefs */
	save_position_cb = create_preference_check_button(main_grid, pos++,
	    "Save window position:",
	    "Save the position of the main window.",
	    prefs.gui_geometry_save_position);
	g_object_set_data(G_OBJECT(main_vb), GEOMETRY_POSITION_KEY, save_position_cb);

	save_size_cb = create_preference_check_button(main_grid, pos++,
	    "Save window size:",
	    "Save the size of the main window.",
	    prefs.gui_geometry_save_size);
	g_object_set_data(G_OBJECT(main_vb), GEOMETRY_SIZE_KEY, save_size_cb);

	save_maximized_cb = create_preference_check_button(main_grid, pos++,
	    "Save maximized state:",
	    "Save the maximized state of the main window.",
	    prefs.gui_geometry_save_maximized);
	g_object_set_data(G_OBJECT(main_vb), GEOMETRY_MAXIMIZED_KEY, save_maximized_cb);

#ifdef _WIN32
	enable_update_cb = create_preference_check_button(main_grid, pos++,
	    "Check for updates:",
	    "Periodically check for new versions of Wireshark.",
	    prefs.gui_update_enabled);
	g_object_set_data(G_OBJECT(main_vb), ENABLE_UPDATE_KEY, enable_update_cb);
#endif

#if defined(HAVE_IGE_MAC_INTEGRATION) || defined(HAVE_GTKOSXAPPLICATION)
	macosx_style_cb = create_preference_check_button(main_grid, pos++,
	    "Mac OS X style",
	    "Create a Mac OS X look and feel. Checking this box will move the "
	    "menu bar to the top of the screen instead of the top of the Wireshark window. "
	    "Requires a restart of Wireshark to take effect.",
	    prefs.gui_macosx_style);
	g_object_set_data(G_OBJECT(main_vb), MACOSX_STYLE_KEY, macosx_style_cb);
#endif

#ifdef _WIN32
	/* How the console window should be opened */
	console_open_om = create_preference_option_menu(main_grid, pos++,
	    "Open a console window",
	    "Whether to open a console window "
	    "(Automatic will open a console if messages appear).",
	    gui_console_open_vals, prefs.gui_console_open);
	g_object_set_data(G_OBJECT(main_vb), GUI_CONSOLE_OPEN_KEY, console_open_om);
#endif

	/* Allow user to select where they want the File Open dialog to open to
	 * by default */
	fileopen_rb = create_preference_radio_buttons(main_grid, pos++,
	    "\"File Open\" dialog behavior:",
	    "Which directory the \"File Open\" dialog should start with.",
	    gui_fileopen_vals, prefs.gui_fileopen_style);

	/* Directory to default File Open dialog to */
	fileopen_dir_te = create_preference_entry(main_grid, pos++,
	    "Directory:",
	    "The \"File Open\" dialog defaults always to this directory.",
	    prefs.gui_fileopen_dir);
	g_object_set_data(G_OBJECT(main_vb), GUI_FILEOPEN_KEY, fileopen_rb);
	g_object_set_data(G_OBJECT(main_vb), GUI_FILEOPEN_DIR_KEY, fileopen_dir_te);
	g_signal_connect(fileopen_rb, "clicked", G_CALLBACK(fileopen_selected_cb), main_vb);
	g_signal_connect(fileopen_dir_te, "focus-out-event",
	    G_CALLBACK(fileopen_dir_changed_cb), main_vb);

	/* File Open dialog preview timeout */
	fileopen_preview_te = create_preference_entry(main_grid, pos++,
	    "\"File Open\" preview timeout:",
	    "Reading preview data in the \"File Open\" dialog will be stopped after given seconds.",
	    open_file_preview_str);
	g_snprintf(current_val_str, sizeof(current_val_str), "%d", prefs.gui_fileopen_preview);
	gtk_entry_set_text(GTK_ENTRY(fileopen_preview_te), current_val_str);
	g_object_set_data(G_OBJECT(main_vb), GUI_FILEOPEN_PREVIEW_KEY, fileopen_preview_te);
	g_signal_connect(fileopen_preview_te, "focus_out_event", G_CALLBACK(fileopen_preview_changed_cb), main_vb);

	/* Number of recent entries in the display filter list ... */
	recent_df_entries_max_te = create_preference_entry(main_grid, pos++,
	    "Maximum recent filters:",
	    "Maximum number of recent entries in filter display list.",
	    recent_df_entries_max_str);
	g_snprintf(current_val_str, sizeof(current_val_str), "%d", prefs.gui_recent_df_entries_max);
	gtk_entry_set_text(GTK_ENTRY(recent_df_entries_max_te), current_val_str);
	g_object_set_data(G_OBJECT(main_vb), GUI_RECENT_DF_ENTRIES_KEY, recent_df_entries_max_te);
	g_signal_connect(recent_df_entries_max_te, "focus_out_event", G_CALLBACK(recent_df_entries_changed_cb), main_vb);

	/* Number of entries in the recent_files list ... */
	recent_files_count_max_te = create_preference_entry(main_grid, pos++,
	    "Maximum recent files:",
	    "Maximum number of entries in the \"File/Open Recent\" list.",
	    recent_files_count_max_str);
	g_snprintf(current_val_str, sizeof(current_val_str), "%d", prefs.gui_recent_files_count_max);
	gtk_entry_set_text(GTK_ENTRY(recent_files_count_max_te), current_val_str);
	g_object_set_data(G_OBJECT(main_vb), GUI_RECENT_FILES_COUNT_KEY, recent_files_count_max_te);
	g_signal_connect(recent_files_count_max_te, "focus_out_event", G_CALLBACK(recent_files_count_changed_cb), main_vb);

	fileopen_selected_cb(NULL, main_vb);

	/* ask for unsaved capture files? */
	ask_unsaved_cb = create_preference_check_button(main_grid, pos++,
	    "Confirm unsaved capture files:",
	    "Whether a dialog should pop up in case of an unsaved capture file.",
	    prefs.gui_ask_unsaved);
	g_object_set_data(G_OBJECT(main_vb), GUI_ASK_UNSAVED_KEY, ask_unsaved_cb);

	/* do we want to wrap when searching for data? */
	find_wrap_cb = create_preference_check_button(main_grid, pos++,
	    "Wrap to end/beginning of file during a find:",
	    "Whether a search should wrap in a capture file.",
	    prefs.gui_find_wrap);
	g_object_set_data(G_OBJECT(main_vb), GUI_FIND_WRAP_KEY, find_wrap_cb);

	/* show an explicit Save button for settings dialogs (preferences and alike)? */
	use_pref_save_cb = create_preference_check_button(main_grid, pos++,
	    "Settings dialogs show a save button:",
	    "Whether the various settings dialogs (e.g. Preferences) should "
	    "use an explicit save button - for advanced users.",
	    prefs.gui_use_pref_save);
	g_object_set_data(G_OBJECT(main_vb), GUI_USE_PREF_SAVE_KEY, use_pref_save_cb);

	/* Show version in welcome and/or title screen */
	show_version_om = create_preference_option_menu(main_grid, pos++,
	    "Welcome screen and title bar shows version",
	    "Whether version should be shown in the start page and/or main screen's title bar.",
	    gui_version_placement_vals, prefs.gui_version_placement);
	g_object_set_data(G_OBJECT(main_vb), GUI_SHOW_VERSION_KEY, show_version_om);

	/* Whether to auto scroll when expanding items */
	auto_scroll_cb = create_preference_check_button(main_grid, pos++,
		"Auto scroll on expansion:",
	    "Whether the details view should be automatically scrolled up when expanding an item.",
	    prefs.gui_auto_scroll_on_expand );
	g_object_set_data(G_OBJECT(main_vb), GUI_AUTO_SCROLL_KEY, auto_scroll_cb);

	/* Where to auto scroll to when expanding items */
	scroll_percent_te = create_preference_entry(main_grid, pos++,
		"Auto scroll percentage:",
	    "Where to scroll the expanded item to within the view e.g. 0% = top of view, 50% = center of view.",
	    scroll_percent_preview_str);
	g_snprintf(current_val_str, sizeof(current_val_str), "%d", prefs.gui_auto_scroll_percentage);
	gtk_entry_set_text(GTK_ENTRY(scroll_percent_te), current_val_str);
	g_object_set_data(G_OBJECT(main_vb), GUI_SCROLL_PERCENT_KEY, scroll_percent_te);
	g_signal_connect(scroll_percent_te, "focus_out_event", G_CALLBACK(scroll_percent_changed_cb), main_vb);

	/* Webbrowser */
	if (browser_needs_pref()) {
	    webbrowser_te = create_preference_entry(main_grid, pos++,
						    "Web browser command:",
						    "Command line to desired browser.",
						    prefs.gui_webbrowser);
	    gtk_entry_set_text(GTK_ENTRY(webbrowser_te), prefs.gui_webbrowser);
	    g_object_set_data(G_OBJECT(main_vb), GUI_WEBBROWSER_KEY, webbrowser_te);
	}

	/* Enable Expert Infos Dialog Tab Label "eye-candy" */
	expert_info_eyecandy_cb = create_preference_check_button(main_grid, pos++,
	    "Display icons in the Expert Infos dialog tab labels:",
	    "Whether icon images should be displayed in the Expert Infos dialog tab labels.",
	    prefs.gui_expert_composite_eyecandy );
	g_object_set_data(G_OBJECT(main_vb), GUI_EXPERT_EYECANDY_KEY, expert_info_eyecandy_cb);

	/* Enable Experimental Packet Editor */
	packet_editor_cb = create_preference_check_button(main_grid, pos++,
	    "Enable Packet Editor (Experimental):",
	    "Activate Packet Editor (Experimental)",
	    prefs.gui_packet_editor);
	g_object_set_data(G_OBJECT(main_vb), GUI_PACKET_EDITOR, packet_editor_cb);

	/* Show 'em what we got */
	gtk_widget_show_all(main_vb);

	return(main_vb);
}


static gint
fetch_enum_value(gpointer control, const enum_val_t *enumvals)
{
	return fetch_preference_option_menu_val(GTK_WIDGET(control), enumvals);
}

void
gui_prefs_fetch(GtkWidget *w)
{
	prefs.gui_geometry_save_position =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), GEOMETRY_POSITION_KEY));
	prefs.gui_geometry_save_size =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), GEOMETRY_SIZE_KEY));
	prefs.gui_geometry_save_maximized =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), GEOMETRY_MAXIMIZED_KEY));

#ifdef _WIN32
	prefs.gui_update_enabled =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), ENABLE_UPDATE_KEY));
#endif

#if defined(HAVE_IGE_MAC_INTEGRATION) || defined(HAVE_GTKOSXAPPLICATION)
	prefs.gui_macosx_style =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), MACOSX_STYLE_KEY));
#endif

#ifdef _WIN32
	prefs.gui_console_open = fetch_enum_value(
		g_object_get_data(G_OBJECT(w), GUI_CONSOLE_OPEN_KEY), gui_console_open_vals);
#endif
	prefs.gui_fileopen_style = fetch_preference_radio_buttons_val(
		(GtkWidget *)g_object_get_data(G_OBJECT(w), GUI_FILEOPEN_KEY), gui_fileopen_vals);

	g_free(prefs.gui_fileopen_dir);
	prefs.gui_fileopen_dir = g_strdup(gtk_entry_get_text(
						  GTK_ENTRY(g_object_get_data(G_OBJECT(w), GUI_FILEOPEN_DIR_KEY))));

	prefs.gui_ask_unsaved =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), GUI_ASK_UNSAVED_KEY));

	prefs.gui_find_wrap =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), GUI_FIND_WRAP_KEY));

	prefs.gui_use_pref_save =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), GUI_USE_PREF_SAVE_KEY));

	prefs.gui_version_placement = (version_info_e)
		fetch_enum_value(g_object_get_data(G_OBJECT(w), GUI_SHOW_VERSION_KEY), gui_version_placement_vals);

	prefs.gui_auto_scroll_on_expand =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), GUI_AUTO_SCROLL_KEY));

	if (browser_needs_pref()) {
		g_free(prefs.gui_webbrowser);
		prefs.gui_webbrowser = g_strdup(gtk_entry_get_text(
							GTK_ENTRY(g_object_get_data(G_OBJECT(w), GUI_WEBBROWSER_KEY))));
	}

	prefs.gui_expert_composite_eyecandy =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), GUI_EXPERT_EYECANDY_KEY));

	prefs.gui_packet_editor =
		gtk_toggle_button_get_active((GtkToggleButton *)g_object_get_data(G_OBJECT(w), GUI_PACKET_EDITOR));
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

	/* Redisplay the main window's title */
	main_titlebar_update();

	/* Redisplay the default welcome header message in case the "show
	 * version" option was changed. */
	welcome_header_set_message(NULL);

	/* Redraw the help window(s). */
	supported_redraw();
	help_redraw();

	/* XXX: redraw the toolbar only, if style changed */
	toolbar_redraw_all();

	set_tree_styles_all();
	main_widgets_rearrange();
}

void
gui_prefs_destroy(GtkWidget *w _U_)
{
}

static gboolean
recent_df_entries_changed_cb(GtkWidget *recent_df_entry _U_,
			      GdkEvent *event _U_, gpointer parent_w)
{
	GtkWidget	*recent_df_entries_count_te;
	guint newval;

	recent_df_entries_count_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), GUI_RECENT_DF_ENTRIES_KEY);

	/*
	 * Now, just convert the string to a number and store it in the prefs
	 * filed ...
	 */

	newval = (guint)strtol(gtk_entry_get_text (GTK_ENTRY(recent_df_entries_count_te)), NULL, 10);

	if (newval > 0) {
		prefs.gui_recent_df_entries_max = newval;
	}

	/* We really should pop up a nasty dialog box if newval <= 0 */

	return FALSE;
}

static gboolean
recent_files_count_changed_cb(GtkWidget *recent_files_entry _U_,
			      GdkEvent *event _U_, gpointer parent_w)
{
	GtkWidget	*recent_files_count_te;
	guint newval;

	recent_files_count_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), GUI_RECENT_FILES_COUNT_KEY);

	/*
	 * Now, just convert the string to a number and store it in the prefs
	 * filed ...
	 */

	newval = (guint)strtol(gtk_entry_get_text (GTK_ENTRY(recent_files_count_te)), NULL, 10);

	if (newval > 0) {
		prefs.gui_recent_files_count_max = newval;
	}

	/* We really should pop up a nasty dialog box if newval <= 0 */

	return FALSE;
}

static gboolean
fileopen_preview_changed_cb(GtkWidget *recent_files_entry _U_,
			      GdkEvent *event _U_, gpointer parent_w)
{
	GtkWidget	*fileopen_preview_te;
	guint newval;

	fileopen_preview_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), GUI_FILEOPEN_PREVIEW_KEY);

	/*
	 * Now, just convert the string to a number and store it in the prefs
	 * filed ...
	 */

	newval = (guint)strtol(gtk_entry_get_text (GTK_ENTRY(fileopen_preview_te)), NULL, 10);

	if (newval > 0) {
		prefs.gui_fileopen_preview = newval;
	}

	/* We really should pop up a nasty dialog box if newval <= 0 */

	return FALSE;
}

static gboolean
fileopen_dir_changed_cb(GtkWidget *fileopen_dir_te, GdkEvent *event _U_, gpointer parent_w _U_)
{
	char *lastchar;
	gint fileopen_dir_te_length;

	fileopen_dir_te_length = (gint) strlen(gtk_entry_get_text (GTK_ENTRY(fileopen_dir_te)));
	if (fileopen_dir_te_length == 0)
		return FALSE;
	lastchar = gtk_editable_get_chars(GTK_EDITABLE(fileopen_dir_te), fileopen_dir_te_length-1, -1);
	if (strcmp(lastchar, G_DIR_SEPARATOR_S) != 0){
		gtk_editable_insert_text(GTK_EDITABLE(fileopen_dir_te), G_DIR_SEPARATOR_S,
					 1, /* new_text_length */
					 &fileopen_dir_te_length); /* *position */
	}
	return FALSE;
}

static void
fileopen_selected_cb(GtkWidget *mybutton_rb _U_, gpointer parent_w)
{
	GtkWidget	*fileopen_rb, *fileopen_dir_te;

	fileopen_rb = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), GUI_FILEOPEN_KEY);
	fileopen_dir_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), GUI_FILEOPEN_DIR_KEY);

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

static gboolean
scroll_percent_changed_cb(GtkWidget *recent_files_entry _U_,
			  GdkEvent *event _U_, gpointer parent_w)
{
	GtkWidget *scroll_percent_te;
	guint newval;

	scroll_percent_te = (GtkWidget*)g_object_get_data(G_OBJECT(parent_w), GUI_SCROLL_PERCENT_KEY);

	/*
	 * Now, just convert the string to a number and store it in the prefs field ...
	 */

	newval = (guint)strtol(gtk_entry_get_text(GTK_ENTRY(scroll_percent_te)), NULL, 10);

	if (newval <= 100) {
		prefs.gui_auto_scroll_percentage = newval;
	}

	if (newval <= 100) {
		prefs.gui_auto_scroll_percentage = newval;
	}

	/* We really should pop up a dialog box is newval < 0 or > 100 */
	return FALSE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
