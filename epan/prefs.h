/** @file prefs.h
 * Definitions for preference handling routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
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
#define ST_MAX_BURSTRES 600000 /* somewhat arbitrary limit of 10 minutes */
#define ST_MAX_BURSTBUCKETS 100 /* somewhat arbitrary limit - more buckets degrade performance */
#define DEF_GUI_DECIMAL_PLACES1 2
#define DEF_GUI_DECIMAL_PLACES2 4
#define DEF_GUI_DECIMAL_PLACES3 6

#define CONV_DEINT_KEY_CAPFILE    0x01 /* unused yet */
#define CONV_DEINT_KEY_INTERFACE  0x02
#define CONV_DEINT_KEY_MAC        0x04
#define CONV_DEINT_KEY_VLAN       0x08

/* Bitmask of flags for the effect of a preference in Wireshark */
#define PREF_EFFECT_DISSECTION        (1u << 0)
#define PREF_EFFECT_CAPTURE           (1u << 1)
#define PREF_EFFECT_GUI_LAYOUT        (1u << 2)
#define PREF_EFFECT_FIELDS            (1u << 3)
#define PREF_EFFECT_GUI               (1u << 4)
#define PREF_EFFECT_GUI_COLOR         (1u << 5)
#define PREF_EFFECT_AGGREGATION       (1u << 6)

/* Default update interval in milliseconds */
#define DEFAULT_UPDATE_INTERVAL 100

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
#define FO_STYLE_CWD            2 /* start in current working directory at startup */

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

#define COLOR_SCHEME_DEFAULT    0
#define COLOR_SCHEME_LIGHT      1
#define COLOR_SCHEME_DARK       2

/**
 * @brief Arrangement type of the summary, details, and hex panes in the main window.
 */
typedef enum {
    layout_unused,    /**< Layout slot is currently unused */
    layout_type_5,    /**< Pane arrangement type 5 */
    layout_type_2,    /**< Pane arrangement type 2 */
    layout_type_1,    /**< Pane arrangement type 1 */
    layout_type_4,    /**< Pane arrangement type 4 */
    layout_type_3,    /**< Pane arrangement type 3 */
    layout_type_6,    /**< Pane arrangement type 6 */
    layout_type_max   /**< Sentinel: one past the last valid layout type */
} layout_type_e;


/**
 * @brief Content assigned to a single layout pane in the main window.
 */
typedef enum {
    layout_pane_content_none,     /**< Pane is empty / not displayed */
    layout_pane_content_plist,    /**< Pane shows the packet list */
    layout_pane_content_pdetails, /**< Pane shows the packet details tree */
    layout_pane_content_pbytes,   /**< Pane shows the packet bytes (hex dump) */
    layout_pane_content_pdiagram, /**< Pane shows the packet diagram */
} layout_pane_content_e;


/**
 * @brief Controls where version information is displayed in the GUI.
 */
typedef enum {
    version_welcome_only, /**< Version shown on the welcome splash screen only */
    version_title_only,   /**< Version shown in the window title bar only */
    version_both,         /**< Version shown in both the welcome screen and title bar */
    version_neither       /**< Version not shown anywhere */
} version_info_e;


/**
 * @brief Orientation of a splitter divider between panes.
 */
typedef enum {
    layout_vertical,   /**< Panes are split vertically (side by side) */
    layout_horizontal  /**< Panes are split horizontally (stacked) */
} splitter_layout_e;


/**
 * @brief Selects which copy of a preference value is used as the active source.
 */
typedef enum {
    pref_default, /**< The compiled-in default value */
    pref_stashed, /**< A temporarily stashed value (e.g., before applying changes) */
    pref_current  /**< The currently active/applied value */
} pref_source_t;


/**
 * @brief Controls which end of a text string is elided when it is too long to display.
 */
typedef enum {
    ELIDE_LEFT,   /**< Elide (truncate with ellipsis) from the left end */
    ELIDE_RIGHT,  /**< Elide from the right end */
    ELIDE_MIDDLE, /**< Elide from the middle */
    ELIDE_NONE    /**< Do not elide; display the full string */
} elide_mode_e;


/**
 * @brief Output format for copying packet list rows to the clipboard.
 */
typedef enum {
    COPY_FORMAT_TEXT, /**< Plain text format */
    COPY_FORMAT_CSV,  /**< Comma-separated values (CSV) format */
    COPY_FORMAT_YAML, /**< YAML format */
    COPY_FORMAT_HTML  /**< HTML format */
} copy_format_e;


/**
 * @brief Controls whether absolute timestamps are rendered as ASCII in tree and column views.
 */
typedef enum {
    ABS_TIME_ASCII_NEVER,  /**< Never render absolute timestamps as ASCII strings */
    ABS_TIME_ASCII_TREE,   /**< Render ASCII timestamps in the packet details tree only */
    ABS_TIME_ASCII_COLUMN, /**< Render ASCII timestamps in packet list columns only */
    ABS_TIME_ASCII_ALWAYS, /**< Always render absolute timestamps as ASCII strings */
} abs_time_format_e;


/**
 * @brief Automatic software update channel selection.
 */
typedef enum {
    UPDATE_CHANNEL_DEVELOPMENT, /**< Receive development/pre-release update builds */
    UPDATE_CHANNEL_STABLE       /**< Receive stable release update builds only */
} software_update_channel_e;


/**
 * @brief Multi-color stripe display mode for the packet list scrollbar and rows.
 */
typedef enum {
    PACKET_LIST_MULTI_COLOR_MODE_OFF         = 0, /**< Multi-color display disabled */
    PACKET_LIST_MULTI_COLOR_MODE_SCROLLBAR_ONLY,  /**< Color stripes shown in scrollbar only; no row striping */
    PACKET_LIST_MULTI_COLOR_MODE_FULL,            /**< Full color stripes in both rows and scrollbar */
    PACKET_LIST_MULTI_COLOR_MODE_SHIFT_RIGHT      /**< Color stripes shifted right by a configurable percentage in rows and scrollbar */
} gui_packet_list_multi_color_mode_e;


/**
 * @brief Visual style of the separator between adjacent color stripes in the packet list.
 */
typedef enum {
    PACKET_LIST_MULTI_COLOR_SEPARATOR_VERTICAL  = 0, /**< Straight vertical separator between stripes */
    PACKET_LIST_MULTI_COLOR_SEPARATOR_DIAGONAL,      /**< Diagonal (candy-cane) separator between stripes */
    PACKET_LIST_MULTI_COLOR_SEPARATOR_BUBBLE         /**< Bubble / half-moon separator between stripes */
} gui_packet_list_multi_color_separator_e;


/**
 * @brief Global Wireshark preferences structure holding all persistent configuration settings.
 */
typedef struct _e_prefs {
    GList        *col_list;                  /**< Ordered list of packet list column definitions */
    unsigned      num_cols;                  /**< Number of entries in @ref col_list */

    /* Statistics stream colors */
    color_t       st_client_fg;              /**< Foreground color for client-side stream data in statistics */
    color_t       st_client_bg;              /**< Background color for client-side stream data in statistics */
    color_t       st_server_fg;              /**< Foreground color for server-side stream data in statistics */
    color_t       st_server_bg;              /**< Background color for server-side stream data in statistics */

    /* Display filter bar colors */
    color_t       gui_filter_valid_fg;       /**< Foreground color for a syntactically valid filter expression */
    color_t       gui_filter_invalid_fg;     /**< Foreground color for a syntactically invalid filter expression */
    color_t       gui_filter_deprecated_fg;  /**< Foreground color for a deprecated filter expression */
    color_t       gui_filter_valid_bg;       /**< Background color for a syntactically valid filter expression */
    color_t       gui_filter_invalid_bg;     /**< Background color for a syntactically invalid filter expression */
    color_t       gui_filter_deprecated_bg;  /**< Background color for a deprecated filter expression */

    bool          restore_filter_after_following_stream; /**< If true, restore the previous display filter after closing a stream follow dialog */

    /* GUI appearance */
    int           gui_toolbar_main_style;    /**< Style of the main toolbar (icon size/text) */
    char         *gui_font_name;             /**< Name and size of the font used in the packet list and details pane */
    int           gui_color_scheme;          /**< Active color scheme index */

    /* Selected-row (active) colors */
    color_t       gui_active_fg;             /**< Foreground color for the active/selected row in a focused widget */
    color_t       gui_active_bg;             /**< Background color for the active/selected row in a focused widget */
    int           gui_active_style;          /**< Style flags for the active row */

    /* Inactive-selection colors */
    color_t       gui_inactive_fg;           /**< Foreground color for a selected row in an unfocused widget */
    color_t       gui_inactive_bg;           /**< Background color for a selected row in an unfocused widget */
    int           gui_inactive_style;        /**< Style flags for an inactive selected row */

    /* Marked-packet colors */
    color_t       gui_marked_fg;             /**< Foreground color for manually marked packets */
    color_t       gui_marked_bg;             /**< Background color for manually marked packets */

    /* Ignored-packet colors */
    color_t       gui_ignored_fg;            /**< Foreground color for ignored packets */
    color_t       gui_ignored_bg;            /**< Background color for ignored packets */

    /* Colorized column colors */
    char         *gui_colorized_fg;          /**< Comma-separated list of foreground colors for the 10 colorized column slots */
    char         *gui_colorized_bg;          /**< Comma-separated list of background colors for the 10 colorized column slots */

    /* Window geometry */
    bool          gui_geometry_save_position;   /**< If true, save and restore the main window position */
    bool          gui_geometry_save_size;        /**< If true, save and restore the main window size */
    bool          gui_geometry_save_maximized;   /**< If true, save and restore the maximized state of the main window */

    /* Recent entries */
    unsigned      gui_recent_df_entries_max;    /**< Maximum number of recent display filter entries to retain */
    unsigned      gui_recent_files_count_max;   /**< Maximum number of recently opened files to retain */

    /* File open dialog */
    unsigned      gui_fileopen_style;           /**< File open dialog style (last directory vs. fixed directory) */
    char         *gui_fileopen_dir;             /**< Fixed directory used when gui_fileopen_style is set to fixed */
    unsigned      gui_fileopen_preview;         /**< Number of bytes to preview when browsing capture files */

    char         *gui_tlskeylog_command;         /**< Shell command executed to retrieve a TLS key log file path */

    /* Dialog behavior */
    bool          gui_ask_unsaved;              /**< If true, prompt before discarding unsaved changes */
    bool          gui_autocomplete_filter;      /**< If true, enable autocomplete in the display filter bar */
    bool          gui_find_wrap;                /**< If true, wrap around when reaching the end of search results */

    /* Window title */
    char         *gui_window_title;             /**< Custom suffix appended to the main window title */
    char         *gui_prepend_window_title;     /**< Custom prefix prepended to the main window title */
    char         *gui_start_title;              /**< Title shown on the welcome screen */
    version_info_e gui_version_placement;       /**< Controls where version information appears in the GUI */

    /* Export/tree limits */
    unsigned      gui_max_export_objects;       /**< Maximum number of objects to show in the Export Objects dialog */
    unsigned      gui_max_tree_items;           /**< Maximum number of items to display in the packet details tree */
    unsigned      gui_max_tree_depth;           /**< Maximum depth to expand in the packet details tree */

    bool          gui_welcome_page_show_recent; /**< If true, show recent files on the welcome page */

    /* Layout */
    layout_type_e         gui_layout_type;       /**< Arrangement of the summary/details/bytes panes */
    layout_pane_content_e gui_layout_content_1;  /**< Content assigned to layout pane 1 */
    layout_pane_content_e gui_layout_content_2;  /**< Content assigned to layout pane 2 */
    layout_pane_content_e gui_layout_content_3;  /**< Content assigned to layout pane 3 */
    splitter_layout_e     gui_packet_dialog_layout; /**< Splitter orientation in the packet detail dialog */

    /* Interface filtering */
    char         *gui_interfaces_hide_types;     /**< Comma-separated list of interface type IDs to hide in the interface list */
    bool          gui_interfaces_show_hidden;    /**< If true, show interfaces that would otherwise be hidden */
    bool          gui_interfaces_remote_display; /**< If true, display remote capture interfaces */

    /* I/O graph */
    bool          gui_io_graph_automatic_update; /**< If true, automatically update the I/O graph while capturing */
    bool          gui_io_graph_enable_legend;    /**< If true, display the legend on the I/O graph */

    /* Plot */
    bool          gui_plot_automatic_update;     /**< If true, automatically update plot views while capturing */
    bool          gui_plot_enable_legend;        /**< If true, display the legend on plot views */
    bool          gui_plot_enable_auto_scroll;   /**< If true, auto-scroll plot views to follow new data */

    bool          gui_packet_details_show_byteview; /**< If true, show the byte view panel alongside packet details */

    /* Capture device settings */
    char         *capture_device;               /**< Name of the default capture interface */
    char         *capture_devices_linktypes;    /**< Per-interface link-type selections (name:linktype pairs) */
    char         *capture_devices_descr;        /**< Per-interface user-defined descriptions (name:descr pairs) */
    char         *capture_devices_hide;         /**< Comma-separated list of interface names to hide */
    char         *capture_devices_monitor_mode; /**< Per-interface monitor mode settings (name:0/1 pairs) */
    char         *capture_devices_buffersize;   /**< Per-interface kernel capture buffer sizes in MB (name:size pairs) */
    char         *capture_devices_snaplen;      /**< Per-interface snapshot lengths in bytes (name:snaplen pairs) */
    char         *capture_devices_pmode;        /**< Per-interface promiscuous mode settings (name:0/1 pairs) */
    char         *capture_devices_filter;       /**< Per-interface default capture filters; mostly unused, may be deprecated */

    /* Capture behavior */
    bool          capture_prom_mode;            /**< If true, capture in promiscuous mode by default */
    bool          capture_monitor_mode;         /**< If true, capture in monitor (RFMON) mode by default */
    bool          capture_pcap_ng;              /**< If true, save captures in pcapng format instead of pcap */
    bool          capture_real_time;            /**< If true, update the packet list in real time during capture */
    unsigned      capture_update_interval;      /**< Interval in milliseconds between packet list updates during capture */

    /* Aggregation */
    GList        *aggregation_fields;           /**< List of field names used for packet aggregation */
    int           aggregation_fields_num;       /**< Number of entries in @ref aggregation_fields */

    /* Capture startup */
    bool          capture_no_interface_load;    /**< If true, skip loading the interface list at startup */
    bool          capture_no_extcap;            /**< If true, disable extcap interface discovery */
    bool          capture_show_info;            /**< If true, show the capture information dialog during live capture */
    GList        *capture_columns;              /**< Ordered list of columns shown in the capture interfaces dialog */

    /* Update intervals */
    unsigned      tap_update_interval;          /**< Interval in milliseconds between tap/statistics view updates */

    /* Dissection display options */
    bool          display_hidden_proto_items;          /**< If true, show protocol fields marked as hidden in the details tree */
    bool          display_byte_fields_with_spaces;     /**< If true, insert spaces between bytes in byte-array field display */
    abs_time_format_e display_abs_time_ascii;          /**< Controls ASCII rendering of absolute timestamps */

    /* Dissector checking */
    bool          enable_incomplete_dissectors_check;  /**< If true, warn when a dissector does not consume all available data */
    bool          incomplete_dissectors_check_debug;   /**< If true, emit debug output for incomplete dissector checks */
    bool          strict_conversation_tracking_heuristics; /**< If true, apply stricter heuristics for conversation tracking */
    int           conversation_deinterlacing_key;      /**< Key bitmask controlling conversation deinterlacing behavior */

    /* Duplicate frame detection */
    bool          ignore_dup_frames;                   /**< If true, suppress display of duplicate frames */
    unsigned      ignore_dup_frames_cache_entries;     /**< Number of frames to cache for duplicate detection */

    /* Migration flags */
    bool          filter_expressions_old;   /**< True if legacy filter expression preferences were loaded from disk */
    bool          cols_hide_new;            /**< True if the new index-based gui.column.hide preference was loaded */

    /* Auto-update */
    bool          gui_update_enabled;                  /**< If true, automatic update checks are enabled */
    software_update_channel_e gui_update_channel;      /**< Update channel (stable or development) */
    unsigned      gui_update_interval;                 /**< Interval in seconds between automatic update checks */
    unsigned      gui_debounce_timer;                  /**< Debounce interval in milliseconds for UI events */

    char         *saved_at_version;         /**< Wireshark version string that last wrote the preferences file */

    /* Packet list display options */
    bool          gui_packet_list_separator;             /**< If true, draw a separator line between rows in the packet list */
    bool          gui_packet_header_column_definition;   /**< If true, show column type descriptions in packet list header tooltips */
    bool          gui_packet_list_hover_style;           /**< If true, apply hover colorization to packet list rows */
    bool          gui_show_selected_packet;              /**< If true, highlight the selected packet in all views */
    bool          gui_show_file_load_time;               /**< If true, display the file load time in the status bar */
    elide_mode_e  gui_packet_list_elide_mode;            /**< Which end of long column text is elided */
    copy_format_e gui_packet_list_copy_format_options_for_keyboard_shortcut; /**< Format used when copying rows via keyboard shortcut */
    bool          gui_packet_list_copy_text_with_aligned_columns; /**< If true, align columns with spaces when copying as text */
    bool          gui_packet_list_show_related;          /**< If true, highlight related packets in the packet list */
    bool          gui_packet_list_show_minimap;          /**< If true, show the color minimap alongside the packet list scrollbar */
    bool          gui_packet_list_sortable;              /**< If true, allow the packet list to be sorted by clicking column headers */
    unsigned      gui_packet_list_cached_rows_max;       /**< Maximum number of packet list rows to keep in the display cache */

    /* Multi-color stripe settings */
    gui_packet_list_multi_color_mode_e      gui_packet_list_multi_color_mode;            /**< Multi-color stripe display mode */
    unsigned                                gui_packet_list_multi_color_shift_percent;   /**< Primary color width percentage (75–95) for SHIFT_RIGHT mode */
    bool                                    gui_packet_list_multi_color_details;         /**< If true, show all matching color rules in the packet details tree */
    gui_packet_list_multi_color_separator_e gui_packet_list_multi_color_separator;       /**< Separator style between adjacent color stripes */

    /* Decimal places for statistics calculations */
    unsigned      gui_decimal_places1;      /**< Number of decimal places for type-1 statistic calculations */
    unsigned      gui_decimal_places2;      /**< Number of decimal places for type-2 statistic calculations */
    unsigned      gui_decimal_places3;      /**< Number of decimal places for type-3 statistic calculations */

    /* RTP player */
    bool          gui_rtp_player_use_disk1; /**< If true, buffer RTP audio stream 1 to disk instead of memory */
    bool          gui_rtp_player_use_disk2; /**< If true, buffer RTP audio stream 2 to disk instead of memory */

    /* Flow graph */
    unsigned      flow_graph_max_export_items; /**< Maximum number of items to include in a flow graph export */

    /* Statistics burst detection */
    bool          st_enable_burstinfo;      /**< If true, compute and display burst information in statistics */
    bool          st_burst_showcount;       /**< If true, show burst packet count instead of burst rate */
    unsigned      st_burst_resolution;      /**< Resolution of burst detection in milliseconds */
    unsigned      st_burst_windowlen;       /**< Sliding window length for burst detection in milliseconds */

    /* Statistics sorting */
    bool          st_sort_casesensitve;     /**< If true, perform case-sensitive sorting in statistics trees */
    bool          st_sort_rng_fixorder;     /**< If true, fix the order of range-based statistics columns */
    bool          st_sort_rng_nameonly;     /**< If true, sort range-based statistics by name only */
    int           st_sort_defcolflag;       /**< Default column flag used for initial statistics sort */
    bool          st_sort_defdescending;    /**< If true, sort statistics in descending order by default */
    bool          st_sort_showfullname;     /**< If true, display the full protocol name in statistics trees */
    int           st_format;               /**< Output format selector for statistics text export */

    bool          conv_machine_readable;   /**< If true, output conversation statistics in machine-readable format */
    bool          extcap_save_on_start;    /**< If true, automatically save extcap capture options at session start */
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

/**
 * @brief Initialize preferences system
 *
 * @param col_fmt Array of column format strings
 * @param num_cols Number of columns in the display
 */
void prefs_init(const char** col_fmt, int num_cols);

/** Reset preferences to default values.  Called at profile change */

/**
 * @brief Resets preferences to their default values.
 *
 * @param app_env_var_prefix Prefix for the application environment variables.
 * @param col_fmt Array of column format strings.
 * @param num_cols Number of columns in the format array.
 */
WS_DLL_PUBLIC void prefs_reset(const char* app_env_var_prefix, const char** col_fmt, int num_cols);

/** Frees memory used by proto routines. Called at program shutdown */

/**
 * @brief Clean up preferences.
 */
void prefs_cleanup(void);

/** Store whether the current UI theme is dark so that we can adjust colors
* @param is_dark set to true if the UI's theme is dark
*/
WS_DLL_PUBLIC void prefs_set_gui_theme_is_dark(bool is_dark);

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
 * @brief Register an alias for a preference module.
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
 * @brief Register a module that will have preferences.
 * Specify the module under which to register it, the name used for the
 * module in the preferences file, the title used in the tab for it
 * in a preferences dialog box, and a routine to call back when the
 * preferences are applied.
 *
 * @param pref_tree "Parent" preference tree under which to register this module.
 * @param master_pref_tree List of all preference modules.
 * @param name is a name for the module to use on the command line with "-o"
 *             and in preference files.
 * @param title the module title in the preferences UI
 * @param description the description included in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param help The help string associated with the module, or NULL
 * @param apply_cb Callback routine that is called when preferences are
 *                      applied. It may be NULL, which inhibits the callback.
 * @return a preferences module which can be used to register a user 'preference'
 */
WS_DLL_PUBLIC module_t*
prefs_register_module(wmem_tree_t* pref_tree, wmem_tree_t* master_pref_tree, const char* name, const char* title,
    const char* description, const char* help, void (*apply_cb)(void),
    const bool use_gui);

/**
 * Callback function for module list scanners.
 */
typedef unsigned (*module_cb)(module_t *module, void *user_data);

/**
 * Returns true if a preferences module has any submodules
 * @param module a preferences module which can be used to register a user 'preference'
 * @return true if a preferences module has any submodules, otherwise false
 */
WS_DLL_PUBLIC bool prefs_module_has_submodules(module_t *module);

/**
 * Call a callback function, with a specified argument, for each module
 * in the list of all modules.  (This list does not include subtrees.)
 *
 * Ignores "obsolete" modules; their sole purpose is to allow old
 * preferences for dissectors that no longer have preferences to be
 * silently ignored in preference files.
 *
 * @param module module to act on
 * @param callback the callback to call
 * @param user_data additional data to pass to the callback
 */
WS_DLL_PUBLIC unsigned prefs_modules_foreach(const wmem_tree_t* module, module_cb callback, void *user_data);

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
 * @param module module to walk through
 * @param callback the callback to call
 * @param user_data additional data to pass to the callback
 */
WS_DLL_PUBLIC unsigned prefs_modules_foreach_submodules(const wmem_tree_t* module, module_cb callback, void *user_data);

/**
 * Call a callback function, with a specified argument, for all modules.
 *
 * Ignores "obsolete" modules; their sole purpose is to allow old
 * preferences for dissectors that no longer have preferences to be
 * silently ignored in preference files.  Does not ignore subtrees,
 * as this can be used when walking the display tree of modules.
 *
 * @param callback the callback to call
 * @param user_data additional data to pass to the callback
 */
WS_DLL_PUBLIC unsigned prefs_modules_for_all_modules(module_cb callback, void* user_data);

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
 * Returns true if the provided protocol has registered preferences.
 * @param name the name of the protocol to look up
 * @return true if the given protocol has registered preferences, otherwise false
 */
WS_DLL_PUBLIC bool prefs_is_registered_protocol(const char *name);

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
    const char *title, const char *description, unsigned base, unsigned *var);

/**
 * Register a preference with an integer value.
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
WS_DLL_PUBLIC void prefs_register_int_preference(module_t* module, const char* name,
    const char* title, const char* description, int* var);

/**
* Register a preference with a float (double) value.
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
* @param num_decimal the number of decimal places to display for a value
* @param var pointer to the storage location that is updated when the
*                    field is changed in the preference dialog box
*/
WS_DLL_PUBLIC void prefs_register_float_preference(module_t* module, const char* name,
    const char* title, const char* description, unsigned num_decimal, double* var);

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
    const char *title, const char *description, bool *var);

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
 * @param radio_buttons true if the field is to be displayed in the
 *                  preferences dialog as a set of radio buttons,
 *                  false if it is to be displayed as an option menu
 */
WS_DLL_PUBLIC void prefs_register_enum_preference(module_t *module, const char *name,
    const char *title, const char *description, int *var,
    const enum_val_t *enumvals, bool radio_buttons);

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
 * @param for_writing true to display a Save dialog, false to display an Open dialog.
 */
WS_DLL_PUBLIC void prefs_register_filename_preference(module_t *module, const char *name,
    const char *title, const char *description, const char **var, bool for_writing);

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
 * Register a preference with a comma-delimited string values.
 *
 * This is currently not support in the UI for dissector use
 * (internal UI preferences only)
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
 *          with a pointer to a new copy of the list during the
 *          preference registration. The passed-in string may be
 *          freed, but you must keep another pointer to the string
 *          in order to free it
 */
WS_DLL_PUBLIC void prefs_register_list_string_preference(module_t* module, const char* name,
    const char* title, const char* description, wmem_list_t** var);

/**
 * Register a preference that has multiple string values
 * This looks like multiple instances of the same preference in the file
 *
 * This is currently not support in the UI for dissector use
 * (internal UI preferences only)
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
 *          with a pointer to a new copy of the list during the
 *          preference registration. The passed-in string may be
 *          freed, but you must keep another pointer to the string
 *          in order to free it
 */
WS_DLL_PUBLIC void prefs_register_multiple_string_preference(module_t* module, const char* name,
    const char* title, const char* description, wmem_list_t** var);

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
    uint32_t max_value);

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
 * @param dissector_table the name of the dissector table
 * @param dissector_description the handle description
 */
void prefs_register_decode_as_range_preference(module_t *module, const char *name,
    const char *title, const char *description, range_t **var,
    uint32_t max_value, const char *dissector_table, const char *dissector_description);

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
 * Register a preference with a dissector name.
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
WS_DLL_PUBLIC void prefs_register_dissector_preference(module_t *module, const char *name,
    const char *title, const char *description, const char **var);

/**
 * @brief Register a preference that used to be supported but no longer is.
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
 * @brief Register a preference with an enumerated value.
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
 * @param radio_buttons true if the field is to be displayed in the
 *                  preferences dialog as a set of radio buttons,
 *                  false if it is to be displayed as an option menu
 */
WS_DLL_PUBLIC void prefs_register_custom_preference_TCP_Analysis(module_t *module, const char *name,
    const char *title, const char *description, int *var,
    const enum_val_t *enumvals, bool radio_buttons);

/**
 * @brief Mark a preference that affects fields change.
 *
 * This works for bool, enum,
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

/**
 * @brief Set the effect flags for a preference in a given module.
 *
 * @param module The module containing the preference.
 * @param name The name of the preference to set.
 * @param flags The effect flags to set.
 */
WS_DLL_PUBLIC void prefs_set_preference_effect(module_t* module,
    const char* name, unsigned flags);

typedef unsigned (*pref_cb)(pref_t *pref, void *user_data);

/**
 * @brief Call a callback function, with a specified argument, for each preference
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
WS_DLL_PUBLIC unsigned prefs_pref_foreach(module_t *module, pref_cb callback,
    void *user_data);

/**
 * @brief Parse through a list of comma-separated, possibly quoted strings.
 * Return a list of the string data.
 *
 * Commas, whitespace, and the quotes surrounding entries are removed.
 * Quotes and backslashes escaped with a backslash (\") will remain.
 *
 * @param str a list of comma-separated, possibly quoted strings
 * @return a list of the string data, or NULL if there's an error
 */
WS_DLL_PUBLIC GList *prefs_get_string_list(const char *str);

/**
 * @brief Clear the given list of string data.
 * @param sl the GList to clear
 */
WS_DLL_PUBLIC void prefs_clear_string_list(GList *sl);

/**
 * @brief Fetch a short preference type name, e.g. "Integer".
 *
 * @param pref A preference.
 *
 * @return The preference type name. May be NULL.
 */
WS_DLL_PUBLIC
const char *prefs_pref_type_name(pref_t *pref);

/**
 * @brief Fetch a long description of the preference type
 *
 * @param pref A preference.
 *
 * @return A description of the preference type including allowed
 * values for enums. The description may include newlines. Must be
 * g_free()d.
 */
WS_DLL_PUBLIC
char *prefs_pref_type_description(pref_t *pref);

/**
 * @brief Fetch a string representation of the preference.
 *
 * @param pref A preference.
 * @param source Which value of the preference to return, see pref_source_t.
 *
 * @return A string representation of the preference. Must be g_free()d.
 */
WS_DLL_PUBLIC
char *prefs_pref_to_str(pref_t *pref, pref_source_t source);

/**
 * @brief Fetch the number of preferences in a module that are not UATs.
 *
 * @param module A preference module.
 *
 * @return The number of non-UAT preferences in the module.
 */
WS_DLL_PUBLIC
int prefs_num_non_uat(module_t* module);


/**
 * @brief Fetch whether a preference is marked obsolete.
 *
 * @param pref A preference.
 *
 * @return A boolean indication the obsolescence of the preference.
 */
WS_DLL_PUBLIC
bool prefs_is_preference_obsolete(pref_t *pref);

/**
 * @brief Read the preferences file, fill in "prefs", and return a pointer to it.
 *
 * If we got an error (other than "it doesn't exist") we report it through
 * the UI.
 *
 * This is called by epan_load_settings(); programs should call that
 * rather than individually calling the routines it calls.
 *
 * @param app_env_var_prefix The prefix for the application environment variable used to get the global configuration directory.
 * @return a pointer to the filled in prefs object
*/
extern e_prefs *read_prefs(const char* app_env_var_prefix);

/**
 * @brief Write out "prefs" to the user's preferences file, and return 0.
 *
 * If we got an error, stuff a pointer to the path of the preferences file
 * into "*pf_path_return", and return the errno.
 *
 * @param app_env_var_prefix The prefix for the application environment variable used to get the global configuration directory.
 * @param pf_path_return The path to write preferences to or NULL for stdout
 * @return 0 if success, otherwise errno
*/
WS_DLL_PUBLIC int write_prefs(const char* app_env_var_prefix, char **pf_path_return);

/**
 * @brief Callback function for writing individual preferences.
 *
 * @param data A preference pointer of type pref_t*
 * @param user_data write_pref_arg_t* pointer
 */
WS_DLL_PUBLIC void pref_write_individual(void* data, void* user_data);

/**
 * @brief Callback function for freeing individual preferences.
 *
 * @param data A preference pointer of type pref_t*
 * @param user_data unused
 */
WS_DLL_PUBLIC void pref_free_individual(void* data, void* user_data);

/**
 * @brief Result of setting a preference.
 */
typedef enum {
    PREFS_SET_OK,               /**< succeeded */
    PREFS_SET_SYNTAX_ERR,       /**< syntax error in string */
    PREFS_SET_NO_SUCH_PREF,     /**< no such preference */
    PREFS_SET_OBSOLETE          /**< preference used to exist but no longer does */
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
 * @brief Checks if the specified capture device is hidden
 *
 * @param name the name of the capture device
 * @return true if the specified capture device is hidden, otherwise false
 */
WS_DLL_PUBLIC bool prefs_is_capture_device_hidden(const char *name);

/**
 * @brief Returns true if the given device should capture in monitor mode by default
 *
 * @param name the name of the capture device
 * @return true if the specified capture device should capture in monitor mode by default, otherwise false
 */
WS_DLL_PUBLIC bool prefs_capture_device_monitor_mode(const char *name);

/**
 * @brief Returns true if the user has marked this column as visible
 *
 * @param column the name of the column
 * @return true if this column as visible, otherwise false
 */
WS_DLL_PUBLIC bool prefs_capture_options_dialog_column_is_visible(const char *column);

/**
 * @brief Returns true if the layout pane content is enabled
 *
 * @param layout_pane_content the layout pane content to check
 * @return true if the layout pane content is enabled, otherwise false
 */
WS_DLL_PUBLIC bool prefs_has_layout_pane_content (layout_pane_content_e layout_pane_content);

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
