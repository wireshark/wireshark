/** @file prefs.h
 * Definitions for preference handling routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PREFS_H__
#define __PREFS_H__

#include <glib.h>

#include <epan/params.h>
#include <epan/range.h>

#include <wsutil/color.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define DEF_WIDTH 750
#define DEF_HEIGHT 550

#define MAX_VAL_LEN  1024

#define TAP_UPDATE_DEFAULT_INTERVAL 3000
#define ST_DEF_BURSTRES 5
#define ST_DEF_BURSTLEN 100
#define ST_MAX_BURSTRES 600000 /* somewhat arbirary limit of 10 minutes */
#define ST_MAX_BURSTBUCKETS 100 /* somewhat arbirary limit - more buckets degrade performance */
#define DEF_GUI_DECIMAL_PLACES1 2
#define DEF_GUI_DECIMAL_PLACES2 4
#define DEF_GUI_DECIMAL_PLACES3 6

struct epan_uat;
struct _e_addr_resolve;

/**
 * Convert a string listing name resolution types to a bitmask of
 * those types.
 *
 * Set "*name_resolve" to the bitmask, and return '\0', on success;
 * return the bad character in the string on error.
 *
 * @param string a list of name resolution types
 * @param name_resolve the bitmap of names to resolve to set
 * @return '\0' on success, the bad character in the string on error
 */
WS_DLL_PUBLIC
char string_to_name_resolve(const char *string, struct _e_addr_resolve *name_resolve);

/*
 * Modes for the starting directory in File Open dialogs.
 */
#define FO_STYLE_LAST_OPENED    0 /* start in last directory we looked at */
#define FO_STYLE_SPECIFIED      1 /* start in specified directory */

/*
 * Toolbar styles.
 */
#define TB_STYLE_ICONS          0
#define TB_STYLE_TEXT           1
#define TB_STYLE_BOTH           2

/*
 * Color styles.
 */
#define COLOR_STYLE_DEFAULT     0
#define COLOR_STYLE_FLAT        1
#define COLOR_STYLE_GRADIENT    2

#define COLOR_STYLE_ALPHA       0.25

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
    layout_pane_content_pbytes,
    layout_pane_content_pdiagram,
} layout_pane_content_e;

/*
 * open console behaviour (win32 only)
 */
typedef enum {
    console_open_never,
    console_open_auto,
    console_open_always
} console_open_e;

/*
 * Places version information will show up
 */
typedef enum {
    version_welcome_only,
    version_title_only,
    version_both,
    version_neither
} version_info_e;

typedef enum {
    pref_default,
    pref_stashed,
    pref_current
} pref_source_t;

typedef enum {
    ELIDE_LEFT,
    ELIDE_RIGHT,
    ELIDE_MIDDLE,
    ELIDE_NONE
} elide_mode_e;


/*
 * Update channel.
 */
typedef enum {
    UPDATE_CHANNEL_DEVELOPMENT,
    UPDATE_CHANNEL_STABLE
} software_update_channel_e;

typedef struct _e_prefs {
  GList       *col_list;
  gint         num_cols;
  color_t      st_client_fg, st_client_bg, st_server_fg, st_server_bg;
  color_t      gui_text_valid, gui_text_invalid, gui_text_deprecated;
  gboolean     restore_filter_after_following_stream;
  gint         gui_toolbar_main_style;
  gchar       *gui_qt_font_name;
  color_t      gui_active_fg;
  color_t      gui_active_bg;
  gint         gui_active_style;
  color_t      gui_inactive_fg;
  color_t      gui_inactive_bg;
  gint         gui_inactive_style;
  color_t      gui_marked_fg;
  color_t      gui_marked_bg;
  color_t      gui_ignored_fg;
  color_t      gui_ignored_bg;
  gchar       *gui_colorized_fg;
  gchar       *gui_colorized_bg;
  gboolean     gui_geometry_save_position;
  gboolean     gui_geometry_save_size;
  gboolean     gui_geometry_save_maximized;
  console_open_e gui_console_open;
  guint        gui_recent_df_entries_max;
  guint        gui_recent_files_count_max;
  guint        gui_fileopen_style;
  gchar       *gui_fileopen_dir;
  guint        gui_fileopen_preview;
  gboolean     gui_ask_unsaved;
  gboolean     gui_autocomplete_filter;
  gboolean     gui_find_wrap;
  gchar       *gui_window_title;
  gchar       *gui_prepend_window_title;
  gchar       *gui_start_title;
  version_info_e gui_version_placement;
  guint        gui_max_export_objects;
  guint        gui_max_tree_items;
  guint        gui_max_tree_depth;
  layout_type_e gui_layout_type;
  layout_pane_content_e gui_layout_content_1;
  layout_pane_content_e gui_layout_content_2;
  layout_pane_content_e gui_layout_content_3;
  gchar       *gui_interfaces_hide_types;
  gboolean     gui_interfaces_show_hidden;
  gboolean     gui_interfaces_remote_display;
  gboolean     gui_io_graph_automatic_update;
  gboolean     gui_packet_details_show_byteview;
  gchar       *capture_device;
  gchar       *capture_devices_linktypes;
  gchar       *capture_devices_descr;
  gchar       *capture_devices_hide;
  gchar       *capture_devices_monitor_mode;
  gchar       *capture_devices_buffersize;
  gchar       *capture_devices_snaplen;
  gchar       *capture_devices_pmode;
  gchar       *capture_devices_filter; /* XXX - Mostly unused. Deprecate? */
  gboolean     capture_prom_mode;
  gboolean     capture_pcap_ng;
  gboolean     capture_real_time;
  gboolean     capture_auto_scroll; /* XXX - Move to recent */
  gboolean     capture_no_interface_load;
  gboolean     capture_no_extcap;
  gboolean     capture_show_info;
  GList       *capture_columns;
  guint        tap_update_interval;
  gboolean     display_hidden_proto_items;
  gboolean     display_byte_fields_with_spaces;
  gboolean     enable_incomplete_dissectors_check;
  gboolean     incomplete_dissectors_check_debug;
  gboolean     strict_conversation_tracking_heuristics;
  gboolean     filter_expressions_old;  /* TRUE if old filter expressions preferences were loaded. */
  gboolean     gui_update_enabled;
  software_update_channel_e gui_update_channel;
  gint         gui_update_interval;
  gchar       *saved_at_version;
  gboolean     unknown_prefs; /* unknown or obsolete pref(s) */
  gboolean     unknown_colorfilters; /* Warn when saving unknown or obsolete color filters. */
  gboolean     gui_qt_packet_list_separator;
  gboolean     gui_qt_packet_header_column_definition;
  gboolean     gui_qt_packet_list_hover_style; /* Enable/Disable mouse-over colorization */
  gboolean     gui_qt_show_selected_packet;
  gboolean     gui_qt_show_file_load_time;
  elide_mode_e gui_packet_list_elide_mode;
  gboolean     gui_packet_list_show_related;
  gboolean     gui_packet_list_show_minimap;
  gboolean     gui_packet_list_sortable;
  gint         gui_decimal_places1; /* Used for type 1 calculations */
  gint         gui_decimal_places2; /* Used for type 2 calculations */
  gint         gui_decimal_places3; /* Used for type 3 calculations */
  gboolean     gui_rtp_player_use_disk1;
  gboolean     gui_rtp_player_use_disk2;
  gboolean     st_enable_burstinfo;
  gboolean     st_burst_showcount;
  gint         st_burst_resolution;
  gint         st_burst_windowlen;
  gboolean     st_sort_casesensitve;
  gboolean     st_sort_rng_fixorder;
  gboolean     st_sort_rng_nameonly;
  gint         st_sort_defcolflag;
  gboolean     st_sort_defdescending;
  gboolean     st_sort_showfullname;
  gboolean     extcap_save_on_start;
} e_prefs;

WS_DLL_PUBLIC e_prefs prefs;

/*
 * Routines to let modules that have preference settings register
 * themselves by name, and to let them register preference settings
 * by name.
 */
struct pref_module;

struct pref_custom_cbs;

typedef struct pref_module module_t;

/** Sets up memory used by proto routines. Called at program startup */
void prefs_init(void);

/** Reset preferences to default values.  Called at profile change */
WS_DLL_PUBLIC void prefs_reset(void);

/** Frees memory used by proto routines. Called at program shutdown */
void prefs_cleanup(void);

/** Store whether the current UI theme is dark so that we can adjust colors
* @param is_dark set to TRUE if the UI's theme is dark
*/
WS_DLL_PUBLIC void prefs_set_gui_theme_is_dark(gboolean is_dark);

/**
 * Register that a protocol has preferences.
 * @param id the value returned by "proto_register_protocol()" when
 *                the protocol was registered.
 * @param apply_cb callback routine that is called when preferences are
 *                      applied. It may be NULL, which inhibits the callback.
 * @return a preferences module which can be used to register a user 'preference'
 */
WS_DLL_PUBLIC module_t *prefs_register_protocol(int id, void (*apply_cb)(void));

/**
 * Register an alias for a preference module.
 * @param name the preference module's alias. Only ASCII letters, numbers,
 *                  underscores, hyphens, and dots may appear in the name
 * @param module the module to create an alias for
 */
WS_DLL_PUBLIC void prefs_register_module_alias(const char *name, module_t *module);

/**
 * Deregister preferences from a protocol.
 * @param id the value returned by "proto_register_protocol()" when
 *                the protocol was registered.
 */
void prefs_deregister_protocol(int id);

/**
 * Register that a statistical tap has preferences.
 *
 * @param name the name for the tap to use on the command line with "-o"
 *             and in preference files.
 * @param title is a short human-readable name for the tap.
 * @param description is a longer human-readable description of the tap.
 * @param apply_cb routine to call back after we apply the preferences
 * @return a preferences module which can be used to register a user 'preference'
 */
WS_DLL_PUBLIC module_t *prefs_register_stat(const char *name, const char *title,
    const char *description, void (*apply_cb)(void));

/**
 * Register that a codec has preferences.
 *
 * @param name is a name for the codec to use on the command line with "-o"
 *             and in preference files.
 * @param title is a short human-readable name for the codec.
 * @param description is a longer human-readable description of the codec.
 * @param apply_cb routine to call back after we apply the preferences
 * @return a preferences module which can be used to register a user 'preference'
 */
WS_DLL_PUBLIC module_t *prefs_register_codec(const char *name, const char *title,
    const char *description, void (*apply_cb)(void));

/**
 * Register that a protocol has preferences and group it under a single
 * subtree
 * @param subtree the tree node name for grouping preferences
 *                the protocol was registered.
 * @param id the value returned by "proto_register_protocol()" when
 *                the protocol was registered.
 * @param apply_cb Callback routine that is called when preferences are
 *                      applied. It may be NULL, which inhibits the callback.
 * @return a preferences module which can be used to register a user 'preference'
 */
WS_DLL_PUBLIC module_t *prefs_register_protocol_subtree(const char *subtree, int id,
    void (*apply_cb)(void));

/**
 * Register that a protocol used to have preferences but no longer does,
 * by creating an "obsolete" module for it.
 * @param id the value returned by "proto_register_protocol()" when
 *                the protocol was registered.
 * @return a preferences module which can be used to register a user 'preference'
 */
WS_DLL_PUBLIC module_t *prefs_register_protocol_obsolete(int id);

/**
 * Callback function for module list scanners.
 */
typedef guint (*module_cb)(module_t *module, gpointer user_data);

/**
 * Returns TRUE if a preferences module has any submodules
 * @param module a preferences module which can be used to register a user 'preference'
 * @return TRUE if a preferences module has any submodules, otherwise FALSE
 */
WS_DLL_PUBLIC gboolean prefs_module_has_submodules(module_t *module);

/**
 * Call a callback function, with a specified argument, for each module
 * in the list of all modules.  (This list does not include subtrees.)
 *
 * Ignores "obsolete" modules; their sole purpose is to allow old
 * preferences for dissectors that no longer have preferences to be
 * silently ignored in preference files.
 *
 * @param callback the callback to call
 * @param user_data additional data to pass to the callback
 */
WS_DLL_PUBLIC guint prefs_modules_foreach(module_cb callback, gpointer user_data);

/**
 * Call a callback function, with a specified argument, for each submodule
 * of a specified module. If the module is NULL, goes through the top-level
 * list in the display tree of modules.
 *
 * Ignores "obsolete" modules; their sole purpose is to allow old
 * preferences for dissectors that no longer have preferences to be
 * silently ignored in preference files.  Does not ignore subtrees,
 * as this can be used when walking the display tree of modules.
 *
 * @param module the top-level module to walk through the submodules,
 *               or NULL for the top-level list in the display tree of modules
 * @param callback the callback to call
 * @param user_data additional data to pass to the callback
 */
WS_DLL_PUBLIC guint prefs_modules_foreach_submodules(module_t *module, module_cb callback, gpointer user_data);

/**
 * Call the "apply" callback function for each module if any of its
 * preferences have changed, and then clear the flag saying its
 * preferences have changed, as the module has been notified of that
 * fact.
 */
WS_DLL_PUBLIC void prefs_apply_all(void);

/**
 * Call the "apply" callback function for a specific module if any of
 * its preferences have changed, and then clear the flag saying its
 * preferences have changed, as the module has been notified of that
 * fact.
 * @param module the module to call the 'apply' callback function for
 */
WS_DLL_PUBLIC void prefs_apply(module_t *module);


struct preference;

typedef struct preference pref_t;

/**
 * Returns TRUE if the provided protocol has registered preferences.
 * @param name the name of the protocol to look up
 * @return TRUE if the given protocol has registered preferences, otherwise FALSE
 */
WS_DLL_PUBLIC gboolean prefs_is_registered_protocol(const char *name);

/**
 * Returns the module title of a registered protocol (or NULL if unknown).
 * @param name the name of the protocol to look up
 * @return the module title of a registered protocol, otherwise NULL
 */
WS_DLL_PUBLIC const char *prefs_get_title_by_name(const char *name);

/** Given a module name, return a pointer to its pref_module struct,
 * or NULL if it's not found.
 *
 * @param name The preference module name.  Usually the same as the protocol
 * name, e.g. "tcp".
 * @return A pointer to the corresponding preference module, or NULL if it
 * wasn't found.
 */
WS_DLL_PUBLIC module_t *prefs_find_module(const char *name);

/** Given a module and a preference name, return a pointer to the given
 * module's given preference or NULL if it's not found.
 *
 * @param module The preference module name.  Usually the same as the protocol
 * name, e.g. "tcp".
 * @param pref The preference name, e.g. "desegment".
 * @return A pointer to the corresponding preference, or NULL if it
 * wasn't found.
 */
WS_DLL_PUBLIC pref_t *prefs_find_preference(module_t * module, const char *pref);

/**
 * Register a preference with an unsigned integral value.
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title the title in the preferences dialog
 * @param description the description included in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param base the base the unsigned integer is expected to be in. See strtoul(3)
 * @param var pointer to the storage location that is updated when the
 *                    field is changed in the preference dialog box
 */
WS_DLL_PUBLIC void prefs_register_uint_preference(module_t *module, const char *name,
    const char *title, const char *description, guint base, guint *var);

/*
 * prefs_register_ callers must conform to the following:
 *
 * Names must be in lowercase letters only (underscore allowed).
 * Titles and descriptions must be valid UTF-8 or NULL.
 * Titles must be short (less than 80 characters)
 * Titles must not contain newlines.
 */

/**
 * Register a preference with an Boolean value.
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param var pointer to the storage location that is updated when the
 *                    field is changed in the preference dialog box
 */
WS_DLL_PUBLIC void prefs_register_bool_preference(module_t *module, const char *name,
    const char *title, const char *description, gboolean *var);

/**
 * Register a preference with an enumerated value.
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param var pointer to the storage location that is updated when the
 *                    field is changed in the preference dialog box
 * @param enumvals a null-terminated array of enum_val_t structures
 * @param radio_buttons TRUE if the field is to be displayed in the
 *                  preferences dialog as a set of radio buttons,
 *                  FALSE if it is to be displayed as an option menu
 */
WS_DLL_PUBLIC void prefs_register_enum_preference(module_t *module, const char *name,
    const char *title, const char *description, gint *var,
    const enum_val_t *enumvals, gboolean radio_buttons);

/**
 * Register a preference with a character-string value.
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param var pointer to the storage location that is updated when the
 *                    field is changed in the preference dialog box. Note that
 *          with string preferences the given pointer is overwritten
 *          with a pointer to a new copy of the string during the
 *          preference registration. The passed-in string may be
 *          freed, but you must keep another pointer to the string
 *          in order to free it
 */
WS_DLL_PUBLIC void prefs_register_string_preference(module_t *module, const char *name,
    const char *title, const char *description, const char **var);

/**
 * Register a preference with a file name (string) value.
 *
 * File name preferences are basically like string preferences
 * except that the GUI gives the user the ability to browse for the
 * file.
 *
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param var pointer to the storage location that is updated when the
 *                    field is changed in the preference dialog box. Note that
 *          the given pointer is overwritten
 *          with a pointer to a new copy of the string during the
 *          preference registration. The passed-in string may be
 *          freed, but you must keep another pointer to the string
 *          in order to free it
 * @param for_writing TRUE to display a Save dialog, FALSE to display an Open dialog.
 */
WS_DLL_PUBLIC void prefs_register_filename_preference(module_t *module, const char *name,
    const char *title, const char *description, const char **var, gboolean for_writing);

/**
 * Register a preference with a directory name (string) value.
 * Directory name preferences are basically like string preferences
 * except that the GUI gives the user the ability to browse for a
 * directory.
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param var pointer to the storage location that is updated when the
 *                    field is changed in the preference dialog box. Note that
 *          the given pointer is overwritten
 *          with a pointer to a new copy of the string during the
 *          preference registration. The passed-in string may be
 *          freed, but you must keep another pointer to the string
 *          in order to free it
 */
WS_DLL_PUBLIC void prefs_register_directory_preference(module_t *module, const char *name,
    const char *title, const char *description, const char **var);

/**
 * Register a preference with a ranged value.
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param var pointer to the storage location that is updated when the
 *                    field is changed in the preference dialog box.
 * @param max_value the maximum allowed value for a range (0 is the minimum)
 */
WS_DLL_PUBLIC void prefs_register_range_preference(module_t *module, const char *name,
    const char *title, const char *description, range_t **var,
    guint32 max_value);

/**
 * Register a static text 'preference'. It can be used to add some info/explanation.
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 */
WS_DLL_PUBLIC void prefs_register_static_text_preference(module_t *module, const char *name,
    const char *title, const char *description);

/**
 * Register a uat (User Accessible Table) 'preference'. It adds a button that opens the uat's window in the
 * preferences tab of the module.
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param uat the uat object that will be updated when the
 *                    field is changed in the preference dialog box
 */
WS_DLL_PUBLIC void prefs_register_uat_preference(module_t *module,
    const char *name, const char* title, const char *description,  struct epan_uat* uat);

/**
 * Register a uat 'preference' for QT only. It adds a button that opens the uat's window in the
 * preferences tab of the module.
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param uat the uat object that will be updated when the
 *                    field is changed in the preference dialog box
 */
WS_DLL_PUBLIC void prefs_register_uat_preference_qt(module_t *module,
    const char *name, const char* title, const char *description,  struct epan_uat* uat);


/**
 * Register a color preference.  Currently does not have any "GUI Dialog" support
 * so the color data needs to be managed independently.  Currently used by the
 * "GUI preferences" to aid in reading/writing the preferences file, but the
 * "data" is still managed by the specific "GUI preferences" dialog.
 *
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param color the color object that will be updated when the
 *                    field is changed in the preference dialog box
 */
void prefs_register_color_preference(module_t *module, const char *name,
    const char *title, const char *description, color_t *color);

/**
 * Register a custom preference.  Currently does not have any "GUI Dialog" support
 * so data needs to be managed independently.  Currently used by the
 * "GUI preferences" to aid in reading/writing the preferences file, but the
 * "data" is still managed by the specific "GUI preferences" dialog.
 *
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param custom_cbs a structure with the custom preference's callbacks
 * @param custom_data currently unused
 */
void prefs_register_custom_preference(module_t *module, const char *name,
    const char *title, const char *description, struct pref_custom_cbs* custom_cbs,
    void** custom_data);

/**
 * Register a (internal) "Decode As" preference with a ranged value.
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title Field's title in the preferences dialog
 * @param description description to include in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param var pointer to the storage location that is updated when the
 *                    field is changed in the preference dialog box.
 * @param max_value the maximum allowed value for a range (0 is the minimum)
 */
void prefs_register_decode_as_range_preference(module_t *module, const char *name,
    const char *title, const char *description, range_t **var,
    guint32 max_value);

/**
 * Register a preference with an password (password is never stored).
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 * @param title the title in the preferences dialog
 * @param description the description included in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param var pointer to the storage location that is updated when the
 *                    field is changed in the preference dialog box
 */
WS_DLL_PUBLIC void prefs_register_password_preference(module_t *module, const char *name,
    const char *title, const char *description, const char **var);

/**
 * Register a preference that used to be supported but no longer is.
 *
 * Note that a warning will pop up if you've saved such preference to the
 * preference file and you subsequently take the code out. The way to make
 * a preference obsolete is to register it with prefs_register_obsolete_preference()
 *
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 */
WS_DLL_PUBLIC void prefs_register_obsolete_preference(module_t *module,
    const char *name);

/**
 * Mark a preference that affects fields change. This works for bool, enum,
 * int, string (containing filename), range preferences. UAT is not included,
 * because you can specified UAT_AFFECTS_FIELDS at uat_new().
  *
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param name the preference's identifier. This is appended to the name of the
 *             protocol, with a "." between them, to create a unique identifier.
 *             The identifier should not include the protocol name, as the name in
 *             the preference file will already have it. Make sure that
 *             only lower-case ASCII letters, numbers, underscores and
 *             dots appear in the preference name.
 */
WS_DLL_PUBLIC void prefs_set_preference_effect_fields(module_t *module,
    const char *name);


typedef guint (*pref_cb)(pref_t *pref, gpointer user_data);

/**
 * Call a callback function, with a specified argument, for each preference
 * in a given module.
 *
 * If any of the callbacks return a non-zero value, stop and return that
 * value, otherwise return 0.
 *
 * @param module the preferences module returned by prefs_register_protocol() or
 *               prefs_register_protocol_subtree()
 * @param callback the callback to call
 * @param user_data additional data to pass to the callback
 * @return If any of the callbacks return a non-zero value, stop and return that
 *         value, otherwise return 0.
 */
WS_DLL_PUBLIC guint prefs_pref_foreach(module_t *module, pref_cb callback,
    gpointer user_data);

/**
 * Parse through a list of comma-separated, possibly quoted strings.
 * Return a list of the string data.
 *
 * Commas, whitespace, and the quotes surrounding entries are removed.
 * Quotes and backslashes escaped with a backslash (\") will remain.
 *
 * @param str a list of comma-separated, possibly quoted strings
 * @return a list of the string data, or NULL if there's an error
 */
WS_DLL_PUBLIC GList *prefs_get_string_list(const gchar *str);

/**
 * Clear the given list of string data.
 * @param sl the GList to clear
 */
WS_DLL_PUBLIC void prefs_clear_string_list(GList *sl);

/** Fetch a short preference type name, e.g. "Integer".
 *
 * @param pref A preference.
 *
 * @return The preference type name. May be NULL.
 */
WS_DLL_PUBLIC
const char *prefs_pref_type_name(pref_t *pref);

/** Fetch a long description of the preference type
 *
 * @param pref A preference.
 *
 * @return A description of the preference type including allowed
 * values for enums. The description may include newlines. Must be
 * g_free()d.
 */
WS_DLL_PUBLIC
char *prefs_pref_type_description(pref_t *pref);

/** Fetch a string representation of the preference.
 *
 * @param pref A preference.
 * @param source Which value of the preference to return, see pref_source_t.
 *
 * @return A string representation of the preference. Must be g_free()d.
 */
WS_DLL_PUBLIC
char *prefs_pref_to_str(pref_t *pref, pref_source_t source);

/**
 * Read the preferences file, fill in "prefs", and return a pointer to it.
 * If we got an error (other than "it doesn't exist") we report it through
 * the UI.
 *
 * This is called by epan_load_settings(); programs should call that
 * rather than individually calling the routines it calls.
 *
 * @return a pointer to the filled in prefs object
*/
extern e_prefs *read_prefs(void);

/**
 * Write out "prefs" to the user's preferences file, and return 0.
 *
 * If we got an error, stuff a pointer to the path of the preferences file
 * into "*pf_path_return", and return the errno.
 *
 * @param pf_path_return The path to write preferences to or NULL for stdout
 * @return 0 if success, otherwise errno
*/
WS_DLL_PUBLIC int write_prefs(char **pf_path_return);

/**
 * Result of setting a preference.
 */
typedef enum {
    PREFS_SET_OK,               /* succeeded */
    PREFS_SET_SYNTAX_ERR,       /* syntax error in string */
    PREFS_SET_NO_SUCH_PREF,     /* no such preference */
    PREFS_SET_OBSOLETE          /* preference used to exist but no longer does */
} prefs_set_pref_e;

/**
 * Given a string of the form "<pref name>:<pref value>", as might appear
 * as an argument to a "-o" option, parse it and set the preference in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 *
 * For syntax errors (return value PREFS_SET_SYNTAX_ERR), details (when
 * available) are written into "errmsg" which must be freed with g_free.
 *
 * @param prefarg a string of the form "<pref name>:<pref value>"
 * @param errmsg storage for syntax error details
 * @return the result from attempting to set the preference
 */
WS_DLL_PUBLIC prefs_set_pref_e prefs_set_pref(char *prefarg, char **errmsg);

/**
 * Get or set a preference's obsolete status. These can be used to make a
 * preference obsolete after startup so that we can fetch its value but
 * keep it from showing up in the prefrences dialog.
 *
 * @param pref A preference.
 * @return TRUE if the preference is obsolete, otherwise FALSE
 */
gboolean prefs_get_preference_obsolete(pref_t *pref);

/**
 * Make a preference obsolete
 *
 * @param pref a preference.
 * @return the result from attempting to set the preference
 */
prefs_set_pref_e prefs_set_preference_obsolete(pref_t *pref);

/**
 * Get current preference uint value. This allows the preference structure
 * to remain hidden from those that doesn't really need it
 *
 * @param module_name the preference module name. Usually the same as the protocol
 *                    name, e.g. "tcp".
 * @param pref_name the preference name, e.g. "desegment".
 * @return the preference's value
 */
WS_DLL_PUBLIC guint prefs_get_uint_value(const char *module_name, const char* pref_name);

/**
 * Get the current range preference value (maintained by pref, so it doesn't need to be freed). This allows the
 * preference structure to remain hidden from those that doesn't really need it.
 *
 * @param module_name the preference module name. Usually the same as the protocol
 *                    name, e.g. "tcp".
 * @param pref_name the preference name, e.g. "desegment".
 * @return the preference's value
 */
WS_DLL_PUBLIC range_t* prefs_get_range_value(const char *module_name, const char* pref_name);

/**
 * Returns TRUE if the specified capture device is hidden
 * @param name the name of the capture device
 * @return TRUE if the specified capture device is hidden, otherwise FALSE
 */
WS_DLL_PUBLIC gboolean prefs_is_capture_device_hidden(const char *name);

/**
 * Returns TRUE if the given device should capture in monitor mode by default
 * @param name the name of the capture device
 * @return TRUE if the specified capture device should capture in monitor mode by default, otherwise FALSE
 */
WS_DLL_PUBLIC gboolean prefs_capture_device_monitor_mode(const char *name);

/**
 * Returns TRUE if the user has marked this column as visible
 *
 * @param column the name of the column
 * @return TRUE if this column as visible, otherwise FALSE
 */
WS_DLL_PUBLIC gboolean prefs_capture_options_dialog_column_is_visible(const gchar *column);

/**
 * Returns TRUE if the layout pane content is enabled
 *
 * @param layout_pane_content the layout pane content to check
 * @return TRUE if the layout pane content is enabled, otherwise FALSE
 */
WS_DLL_PUBLIC gboolean prefs_has_layout_pane_content (layout_pane_content_e layout_pane_content);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* prefs.h */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
