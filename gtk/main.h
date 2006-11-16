/* main.h
 * Global defines, etc.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __MAIN_H__
#define __MAIN_H__

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "globals.h"

/** @defgroup main_window_group Main window
 * The main window has the following submodules:
   @dot
  digraph main_dependencies {
      node [shape=record, fontname=Helvetica, fontsize=10];
      main [ label="main window" URL="\ref main.h"];
      menu [ label="menubar" URL="\ref menu.h"];
      toolbar [ label="toolbar" URL="\ref toolbar.h"];
      packet_list [ label="packet list pane" URL="\ref packet_list.h"];
      proto_draw [ label="packet details & bytes panes" URL="\ref proto_draw.h"];
      recent [ label="recent user settings" URL="\ref recent.h"];
      main -> menu [ arrowhead="open", style="solid" ];
      main -> toolbar [ arrowhead="open", style="solid" ];
      main -> packet_list [ arrowhead="open", style="solid" ];
      main -> proto_draw [ arrowhead="open", style="solid" ];
      main -> recent [ arrowhead="open", style="solid" ];
  }
  @enddot
 */

/** @file
 *  The main window, filter toolbar, program start/stop and a lot of other things
 *  @ingroup main_window_group
 *  @ingroup windows_group
 */

/** Global compile time version string */
extern GString *comp_info_str;
/** Global runtime version string */
extern GString *runtime_info_str;

extern GtkWidget* airpcap_tb;

/** Global capture options type. */
typedef struct capture_options_tag * p_capture_options_t;
/** Pointer to global capture options. */
extern p_capture_options_t capture_opts;

extern void protect_thread_critical_region(void);
extern void unprotect_thread_critical_region(void);

void
airpcap_toolbar_encryption_cb(GtkWidget *entry, gpointer user_data);

/** User requested "Zoom In" by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void view_zoom_in_cb(GtkWidget *widget, gpointer data);

/** User requested "Zoom Out" by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void view_zoom_out_cb(GtkWidget *widget, gpointer data);

/** User requested "Zoom 100%" by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void view_zoom_100_cb(GtkWidget *widget, gpointer data);

/** User requested "Protocol Info" by ptree context menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void selected_ptree_info_cb(GtkWidget *widget, gpointer data);

/** User requested "Filter Reference" by ptree context menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void selected_ptree_ref_cb(GtkWidget *widget, gpointer data);

/** "Apply as Filter" / "Prepare a Filter" action type. */
typedef enum {
    MATCH_SELECTED_REPLACE, /**< "Selected" */
    MATCH_SELECTED_AND,     /**< "and Selected" */
    MATCH_SELECTED_OR,      /**< "or Selected" */
    MATCH_SELECTED_NOT,     /**< "Not Selected" */
    MATCH_SELECTED_AND_NOT, /**< "and not Selected" */
    MATCH_SELECTED_OR_NOT   /**< "or not Selected" */
} MATCH_SELECTED_E;

/** mask MATCH_SELECTED_E values (internally used) */
#define MATCH_SELECTED_MASK         0x0ff

/** "bitwise or" this with MATCH_SELECTED_E value for instant apply instead of prepare only */
#define MATCH_SELECTED_APPLY_NOW    0x100

/** User highlited item in details window and then right clicked and selected the copy option 
 *
 * @param widget parent widget
 * @param data parent widget
 */
extern void copy_selected_plist_cb(GtkWidget *w _U_, gpointer data);

/** User requested one of "Apply as Filter" or "Prepare a Filter" functions 
 *  by menu or context menu of protocol tree.
 *
 * @param widget parent widget
 * @param data parent widget
 * @param action the function to use
 */
extern void match_selected_ptree_cb(GtkWidget *widget, gpointer data, MATCH_SELECTED_E action);

/** User requested one of "Apply as Filter" or "Prepare a Filter" functions
 *  by context menu of packet list.
 *
 * @param widget parent widget (unused)
 * @param data parent widget
 * @param action the function to use
 */
extern void match_selected_plist_cb(GtkWidget *widget, gpointer data, MATCH_SELECTED_E action);

/** User requested "Quit" by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void file_quit_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested "Print" by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void file_print_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested "Print" by packet list context menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void file_print_selected_cmd_cb(GtkWidget *widget _U_, gpointer data _U_);

/** User requested "Export as Plain Text" by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void export_text_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested "Export as Postscript" by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void export_ps_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested "Export as PSML" by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void export_psml_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested "Export as PDML" by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void export_pdml_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested "Export as CSV" by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void export_csv_cmd_cb(GtkWidget *widget, gpointer data);

/** User requested "Expand Tree" by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void expand_tree_cb(GtkWidget *widget, gpointer data);

/** User requested "Expand All" by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void expand_all_cb(GtkWidget *widget, gpointer data);

/** User requested "Collapse All" by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void collapse_all_cb(GtkWidget *widget, gpointer data);

/** User requested "Resolve Name" by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
extern void resolve_name_cb(GtkWidget *widget, gpointer data);

/** Action to take for reftime_frame_cb() */
typedef enum {
    REFTIME_TOGGLE,     /**< toggle ref frame */
    REFTIME_FIND_NEXT,  /**< find next ref frame */
    REFTIME_FIND_PREV   /**< find previous ref frame */
} REFTIME_ACTION_E;

/** User requested one of the "Time Reference" functions by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 * @param action the function to use
 */
extern void reftime_frame_cb(GtkWidget *widget, gpointer data, REFTIME_ACTION_E action);

/** User requested the "Find Next Mark" function by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 * @param action unused
 */
extern void find_next_mark_cb(GtkWidget *widget, gpointer data, int action);

/** User requested the "Find Previous Mark" function by menu.
 *
 * @param widget parent widget (unused)
 * @param data unused
 * @param action unused
 */
extern void find_prev_mark_cb(GtkWidget *widget, gpointer data, int action);

/** Add a display filter coming from the user's recent file to the dfilter combo box.
 *
 * @param dftext the filter string
 */
extern gboolean dfilter_combo_add_recent(gchar *dftext);

/** Empty out the combobox entry field */
extern void dfilter_combo_add_empty(void);

/** Write all non empty display filters (until maximum count) 
 *  of the combo box GList to the user's recent file.
 *
 * @param rf the recent file
 */
extern void dfilter_recent_combo_write_all(FILE *rf);

/** Quit the program.
 *
 * @return TRUE, if a file read is in progress
 */
extern gboolean main_do_quit(void);

/** Rearrange the main window widgets, user changed it's preferences. */
extern void main_widgets_rearrange(void);

/** Show or hide the main window widgets, user changed it's preferences. */
extern void main_widgets_show_or_hide(void);

/** Apply a new filter string. 
 *  Call cf_filter_packets() and add this filter string to the recent filter list.
 *
 * @param cf the capture file
 * @param dftext the new filter string
 * @param force force the refiltering, even if filter string doesn't changed
 * @return TRUE, if the filtering succeeded
 */
extern gboolean main_filter_packets(capture_file *cf, const gchar *dftext,
    gboolean force);

/** Init the drag-n-drop functionality.
 *
 * @param w the target widget for this dnd operations
 */
extern void dnd_init(GtkWidget *w);

/** Open a new file coming from drag and drop.
 * @param cf_names_freeme the selection data reported from GTK
 */
extern void dnd_open_file_cmd(gchar *cf_names_freeme);

/** Update the packets statusbar to the current values. */
extern void packets_bar_update(void);

#ifdef _WIN32
/** Win32 only: Create a console. Beware: cannot be closed again. */
extern void create_console(void);
#endif

/* Fill in capture options with values from the preferences */
extern void prefs_to_capture_opts(void);

#endif /* __MAIN_H__ */
