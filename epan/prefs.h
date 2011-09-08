/* prefs.h
 * Definitions for preference handling routines
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

#ifndef __PREFS_H__
#define __PREFS_H__

#include <glib.h>

#include "color.h"

#include <epan/params.h>
#include <epan/range.h>

#define PR_DEST_CMD  0
#define PR_DEST_FILE 1

#define DEF_WIDTH 750
#define DEF_HEIGHT 550

#define MAX_VAL_LEN  1024

#define RTP_PLAYER_DEFAULT_VISIBLE 4
#define TAP_UPDATE_DEFAULT_INTERVAL 3000

/*
 * Convert a string listing name resolution types to a bitmask of
 * those types.
 *
 * Set "*name_resolve" to the bitmask, and return '\0', on success;
 * return the bad character in the string on error.
 */
char string_to_name_resolve(char *string, guint32 *name_resolve);

/*
 * Modes for the starting directory in File Open dialogs.
 */
#define FO_STYLE_LAST_OPENED	0	/* start in last directory we looked at */
#define FO_STYLE_SPECIFIED	1	/* start in specified directory */

/*
 * Toolbar styles.
 */
#define TB_STYLE_ICONS		0
#define TB_STYLE_TEXT		1
#define TB_STYLE_BOTH		2

/*
 * Types of layout of summary/details/hex panes.
 */
typedef enum {
    layout_unused,  /* entry currently unused */
    layout_type_5,
    layout_type_2,
    layout_type_1,
    layout_type_4,
    layout_type_3,
    layout_type_6,
    layout_type_max
} layout_type_e;

/*
 * Types of pane.
 */
typedef enum {
    layout_pane_content_none,
    layout_pane_content_plist,
    layout_pane_content_pdetails,
    layout_pane_content_pbytes
} layout_pane_content_e;

/*
 * open console behaviour (win32 only)
 */
typedef enum {
    console_open_never,
    console_open_auto,
    console_open_always
} console_open_e;


typedef struct _e_prefs {
  gint     pr_format;
  gint     pr_dest;
  gchar   *pr_file;
  gchar   *pr_cmd;
  GList   *col_list;
  gint     num_cols;
  color_t  st_client_fg, st_client_bg, st_server_fg, st_server_bg;
  gboolean gui_scrollbar_on_right;
  gboolean gui_plist_sel_browse;
  gboolean gui_ptree_sel_browse;
  gboolean gui_altern_colors;
  gboolean gui_expert_composite_eyecandy;
  gboolean filter_toolbar_show_in_statusbar;
  gint     gui_ptree_line_style;
  gint     gui_ptree_expander_style;
  gboolean gui_hex_dump_highlight_style;
  gint     gui_toolbar_main_style;
  gint     gui_toolbar_filter_style;
  gchar   *gui_font_name;
  color_t  gui_marked_fg;
  color_t  gui_marked_bg;
  color_t  gui_ignored_fg;
  color_t  gui_ignored_bg;
  gchar   *gui_colorized_fg;
  gchar   *gui_colorized_bg;
  gboolean gui_geometry_save_position;
  gboolean gui_geometry_save_size;
  gboolean gui_geometry_save_maximized;
  gboolean gui_macosx_style;
  console_open_e gui_console_open;
  guint    gui_recent_df_entries_max;
  guint    gui_recent_files_count_max;
  guint    gui_fileopen_style;
  gchar	   *gui_fileopen_dir;
  guint    gui_fileopen_preview;
  gboolean gui_ask_unsaved;
  gboolean gui_find_wrap;
  gboolean gui_use_pref_save;
  gchar   *gui_webbrowser;
  gchar   *gui_window_title;
  gchar   *gui_start_title;
  gboolean gui_version_in_start_page;
  gboolean gui_auto_scroll_on_expand;
  guint    gui_auto_scroll_percentage;
  layout_type_e gui_layout_type;
  layout_pane_content_e gui_layout_content_1;
  layout_pane_content_e gui_layout_content_2;
  layout_pane_content_e gui_layout_content_3;
  gint     console_log_level;
  guint32  name_resolve;
  gint     name_resolve_concurrency;
  gboolean load_smi_modules;
  gboolean suppress_smi_errors;
  gchar   *capture_device;
  gchar   *capture_devices_linktypes;
  gchar   *capture_devices_descr;
  gchar   *capture_devices_hide;
  gchar   *capture_devices_monitor_mode;
  gboolean capture_prom_mode;
  gboolean capture_pcap_ng;
  gboolean capture_real_time;
  gboolean capture_auto_scroll;
  gboolean capture_show_info;
  gboolean capture_syntax_check_filter;
  guint    rtp_player_max_visible;
  guint    tap_update_interval;
  gboolean display_hidden_proto_items;
  gpointer filter_expressions;	/* Actually points to &head */
} e_prefs;

WS_VAR_IMPORT e_prefs prefs;

/*
 * Routines to let modules that have preference settings register
 * themselves by name, and to let them register preference settings
 * by name.
 */
struct pref_module;

typedef struct pref_module module_t;

/** Sets up memory used by proto routines. Called at program startup */
extern void prefs_init(void);

/** Reset preferences to default values.  Called at profile change */
extern void prefs_reset(void);

/** Frees memory used by proto routines. Called at program shutdown */
extern void prefs_cleanup(void);

/*
 * Register a module that will have preferences.
 * Specify the module under which to register it or NULL to register it
 * at the top level, the name used for the module in the preferences file,
 * the title used in the tab for it in a preferences dialog box, and a
 * routine to call back when we apply the preferences.
 *
 * This should not be used for dissector preferences;
 * "prefs_register_protocol()" should be used for that, so that the
 * preferences go under the "Protocols" subtree, and so that the
 * name is the protocol name specified at the "proto_register_protocol()"
 * call so that the "Protocol Properties..." menu item works.
 */
extern module_t *prefs_register_module(module_t *parent, const char *name,
    const char *title, const char *description, void (*apply_cb)(void));

/*
 * Register a subtree that will have modules under it.
 * Specify the module under which to register it or NULL to register it
 * at the top level and the title used in the tab for it in a preferences
 * dialog box.
 */
extern module_t *prefs_register_subtree(module_t *parent, const char *title,
    const char *description);

/*
 * Register that a protocol has preferences.
 */
extern module_t *prefs_register_protocol(int id, void (*apply_cb)(void));

/*
 * Register that a protocol has preferences and group it under a single
 * subtree
 */
#define PREFERENCE_GROUPING
extern module_t *prefs_register_protocol_subtree(const char *subtree, int id,
						 void (*apply_cb)(void));

/*
 * Register that a protocol used to have preferences but no longer does,
 * by creating an "obsolete" module for it.
 */
extern module_t *prefs_register_protocol_obsolete(int id);

/*
 * Callback function for module list scanners.
 */
typedef guint (*module_cb)(module_t *module, gpointer user_data);

/*
 * Returns TRUE if module has any submodules
 */
extern gboolean prefs_module_has_submodules(module_t *module);

/*
 * Call a callback function, with a specified argument, for each module
 * in the list of all modules.  (This list does not include subtrees.)
 *
 * Ignores "obsolete" modules; their sole purpose is to allow old
 * preferences for dissectors that no longer have preferences to be
 * silently ignored in preference files.
 */
extern guint prefs_modules_foreach(module_cb callback, gpointer user_data);

/*
 * Call a callback function, with a specified argument, for each submodule
 * of specified modules.  If the module is NULL, goes through the top-level
 * list in the display tree of modules.
 *
 * Ignores "obsolete" modules; their sole purpose is to allow old
 * preferences for dissectors that no longer have preferences to be
 * silently ignored in preference files.  Does not ignore subtrees,
 * as this can be used when walking the display tree of modules.
 */
extern guint prefs_modules_foreach_submodules(module_t *module, module_cb callback, gpointer user_data);

/*
 * Call the "apply" callback function for each module if any of its
 * preferences have changed, and then clear the flag saying its
 * preferences have changed, as the module has been notified of that
 * fact.
 */
extern void prefs_apply_all(void);

/*
 * Call the "apply" callback function for a specific module if any of
 * its preferences have changed, and then clear the flag saying its
 * preferences have changed, as the module has been notified of that
 * fact.
 */
extern void prefs_apply(module_t *module);


struct preference;

typedef struct preference pref_t;

/*
 * Returns TRUE if the given protocol has registered preferences.
 */
extern gboolean prefs_is_registered_protocol(const char *name);

/*
 * Returns the module title of a registered protocol (or NULL if unknown).
 */
extern const char *prefs_get_title_by_name(const char *name);

/** Given a module name, return a pointer to its pref_module struct,
 * or NULL if it's not found.
 *
 * @param name The preference module name.  Usually the same as the protocol
 * name, e.g. "tcp".
 * @return A pointer to the corresponding preference module, or NULL if it
 * wasn't found.
 */
extern module_t *prefs_find_module(const char *name);

/** Given a module name, and a preference name return a pointer to the given
 * module's given preference or NULL if it's not found.
 *
 * @param module The preference module name.  Usually the same as the protocol
 * name, e.g. "tcp".
 * @param pref The preference name, e.g. "desegment".
 * @return A pointer to the corresponding preference, or NULL if it
 * wasn't found.
 */
extern pref_t *prefs_find_preference(module_t * module, const char *pref);

/*
 * Register a preference with an unsigned integral value.
 */
extern void prefs_register_uint_preference(module_t *module, const char *name,
    const char *title, const char *description, guint base, guint *var);

/*
 * Register a preference with an Boolean value.
 * Note that the name must be in lowercase letters only (underscore allowed).
 */
extern void prefs_register_bool_preference(module_t *module, const char *name,
    const char *title, const char *description, gboolean *var);

/*
 * Register a preference with an enumerated value.
 */
extern void prefs_register_enum_preference(module_t *module, const char *name,
    const char *title, const char *description, gint *var,
    const enum_val_t *enumvals, gboolean radio_buttons);

/*
 * Register a preference with a character-string value.
 */
extern void prefs_register_string_preference(module_t *module, const char *name,
    const char *title, const char *description, const char **var);

/*
 * Register a preference with a ranged value.
 */
extern void prefs_register_range_preference(module_t *module, const char *name,
    const char *title, const char *description, range_t **var,
    guint32 max_value);

/*
 * Register a static text 'preference'. It can be used to add some info/explanation.
 */
extern void prefs_register_static_text_preference(module_t *module, const char *name,
    const char *title, const char *description);

/*
 * Register a uat 'preference'. It adds a button that opens the uat's window in the
 * preferences tab of the module.
 */
extern void prefs_register_uat_preference(module_t *module,
										  const char *name,
										  const char* title,
										  const char *description,
										  void* uat);

/*
 * Register a preference that used to be supported but no longer is.
 */
extern void prefs_register_obsolete_preference(module_t *module,
    const char *name);


typedef guint (*pref_cb)(pref_t *pref, gpointer user_data);

/*
 * Call a callback function, with a specified argument, for each preference
 * in a given module.
 *
 * If any of the callbacks return a non-zero value, stop and return that
 * value, otherwise return 0.
 */
extern guint prefs_pref_foreach(module_t *module, pref_cb callback,
    gpointer user_data);

/* Parse through a list of comma-separated, possibly quoted strings.
 *  Return a list of the string data.
 */
extern GList *prefs_get_string_list(gchar *str);

/* Clear the given list of string data. */
extern void prefs_clear_string_list(GList *sl);

/*
 * Register all non-dissector modules' preferences.
 */
extern void prefs_register_modules(void);

/* Read the preferences file, fill in "prefs", and return a pointer to it.

   If we got an error (other than "it doesn't exist") trying to read
   the global preferences file, stuff the errno into "*gpf_errno_return"
   on an open error and into "*gpf_read_errno_return" on a read error,
   stuff a pointer to the path of the file into "*gpf_path_return", and
   return NULL.

   If we got an error (other than "it doesn't exist") trying to read
   the user's preferences file, stuff the errno into "*pf_errno_return"
   on an open error and into "*pf_read_errno_return" on a read error,
   stuff a pointer to the path of the file into "*pf_path_return", and
   return NULL. */
extern e_prefs *read_prefs(int *, int *, char **, int *, int *, char **);

/* Write out "prefs" to the user's preferences file, and return 0.

   If we got an error, stuff a pointer to the path of the preferences file
   into "*pf_path_return", and return the errno. */
extern int write_prefs(char **);

/* Copy a set of preferences. */
extern void copy_prefs(e_prefs *dest, e_prefs *src);

/* Free a set of preferences. */
extern void free_prefs(e_prefs *pr);

/*
 * Given a string of the form "<pref name>:<pref value>", as might appear
 * as an argument to a "-o" option, parse it and set the preference in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 *
 * XXX - should supply, for syntax errors, a detailed explanation of
 * the syntax error.
 */
typedef enum {
    PREFS_SET_OK,		/* succeeded */
    PREFS_SET_SYNTAX_ERR,	/* syntax error in string */
    PREFS_SET_NO_SUCH_PREF,	/* no such preference */
    PREFS_SET_OBSOLETE		/* preference used to exist but no longer does */
} prefs_set_pref_e;

extern prefs_set_pref_e prefs_set_pref(char *prefarg);

/*
 * Get or set a preference's obsolete status. These can be used to make a
 * preference obsolete after startup so that we can fetch its value but
 * keep it from showing up in the prefrences dialog.
 */
extern gboolean prefs_get_preference_obsolete(pref_t *pref);
extern prefs_set_pref_e prefs_set_preference_obsolete(pref_t *pref);


/*
 * Returns TRUE if the given device is hidden
 */
extern gboolean prefs_is_capture_device_hidden(const char *name);

/*
 * Returns TRUE if the given device should capture in monitor mode by default
 */
extern gboolean prefs_capture_device_monitor_mode(const char *name);

#endif /* prefs.h */
