/** @file
 *
 * Definitions for recent "preference" handling routines
 * Copyright 2004, Ulf Lamping <ulf.lamping@web.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __RECENT_H__
#define __RECENT_H__

#include <glib.h>

#include <stdio.h>
#include "epan/timestamp.h"
#include "ui/ws_ui_util.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 *  Recent user interface settings.
 *  @ingroup main_window_group
 */

/** ???. */
#define RECENT_KEY_CAPTURE_FILE         "recent.capture_file"

/** ???. */
#define RECENT_KEY_DISPLAY_FILTER       "recent.display_filter"

#define RECENT_KEY_COL_WIDTH            "column.width"

#define RECENT_KEY_CAPTURE_FILTER       "recent.capture_filter"

#define RECENT_KEY_REMOTE_HOST          "recent.remote_host"

/**
 * @brief Stores the display width and alignment for a single column.
 */
typedef struct _col_width_data {
    int  fmt;     /**< Column format, used for consistency check. */
    int  width;   /**< Column width in characters. */
    char xalign;  /**< Horizontal alignment specifier (e.g., 'l' = left, 'r' = right, 'c' = center). */
} col_width_data;

/** Defines used in col_width_data.xalign */
#define COLUMN_XALIGN_DEFAULT  0
#define COLUMN_XALIGN_LEFT    'L'
#define COLUMN_XALIGN_CENTER  'C'
#define COLUMN_XALIGN_RIGHT   'R'

/**
 * @brief Numeric base used to render byte values in the Packet Bytes pane.
 */
typedef enum {
    BYTES_HEX, /**< Display bytes as hexadecimal (base 16) */
    BYTES_BITS, /**< Display bytes as binary (base 2) */
    BYTES_DEC,  /**< Display bytes as decimal (base 10) */
    BYTES_OCT   /**< Display bytes as octal (base 8) */
} bytes_view_type;


/**
 * @brief Character encoding used to render the ASCII side-panel in the Packet Bytes pane.
 */
typedef enum {
    BYTES_ENC_FROM_PACKET, /**< Use the encoding recorded in the frame's ::frame_data packet_char_enc field */
    BYTES_ENC_ASCII,       /**< Always render characters using ASCII */
    BYTES_ENC_EBCDIC       /**< Always render characters using EBCDIC */
} bytes_encoding_type;


/**
 * @brief Selects which packet pane the Find Packet search operates on.
 */
typedef enum {
    SEARCH_IN_PACKET_LIST,    /**< Search within the summary strings visible in the packet list */
    SEARCH_IN_PACKET_DETAILS, /**< Search within the decoded field tree in the packet details pane */
    SEARCH_IN_PACKET_BYTES    /**< Search within the raw bytes in the packet bytes pane */
} search_in_type;


/**
 * @brief Controls whether string searches match narrow (single-byte), wide (two-byte), or both character encodings.
 */
typedef enum {
    SEARCH_CHAR_SET_NARROW_AND_WIDE, /**< Match both narrow (ASCII/single-byte) and wide (UTF-16/two-byte) strings */
    SEARCH_CHAR_SET_NARROW,          /**< Match narrow (ASCII/single-byte) strings only */
    SEARCH_CHAR_SET_WIDE             /**< Match wide (UTF-16/two-byte) strings only */
} search_char_set_type;


/**
 * @brief Specifies the matching method used by the Find Packet dialog.
 */
typedef enum {
    SEARCH_TYPE_DISPLAY_FILTER, /**< Match packets using a display filter expression */
    SEARCH_TYPE_HEX_VALUE,      /**< Match packets containing a specific hex byte sequence */
    SEARCH_TYPE_STRING,         /**< Match packets containing a plain text string */
    SEARCH_TYPE_REGEX           /**< Match packets whose content matches a regular expression */
} search_type_type;


/**
 * @brief Selects the presentation format for payload data in the Follow Stream and Show Packet Bytes dialogs.
 */
typedef enum {
    SHOW_ASCII,         /**< Render payload as printable ASCII text */
    SHOW_ASCII_CONTROL, /**< Render payload as ASCII with visible representations of control characters */
    SHOW_CARRAY,        /**< Render payload as a C-style byte array literal */
    SHOW_EBCDIC,        /**< Render payload decoded from EBCDIC to ASCII */
    SHOW_HEXDUMP,       /**< Render payload as an annotated hex dump */
    SHOW_HTML,          /**< Render payload as HTML in an embedded web view */
    SHOW_IMAGE,         /**< Render payload as an image */
    SHOW_JSON,          /**< Render payload as pretty-printed JSON */
    SHOW_RAW,           /**< Render payload as raw bytes with no interpretation */
    SHOW_RUSTARRAY,     /**< Render payload as a Rust-style byte array literal */
    SHOW_CODEC,         /**< Render payload decoded with a text codec; maps to UTF-8 in the combo box (other codecs generated at runtime) */
    SHOW_YAML           /**< Render payload as YAML */
} bytes_show_type;


/**
 * @brief Controls display of inter-segment timing deltas in the Follow Stream dialog.
 */
typedef enum {
    FOLLOW_DELTA_NONE, /**< Do not show timing deltas */
    FOLLOW_DELTA_TURN, /**< Show elapsed time at each direction change (turn) */
    FOLLOW_DELTA_ALL   /**< Show elapsed time between every segment */
} follow_delta_type;


/**
 * @brief Secondary decode transformation applied to raw bytes before display in the Show Packet Bytes dialog.
 */
typedef enum {
    DecodeAsNone,             /**< No secondary decoding; display raw bytes */
    DecodeAsBASE64,           /**< Decode bytes as Base64-encoded data */
    DecodeAsCompressed,       /**< Decompress bytes using zlib/DEFLATE */
    DecodeAsHexDigits,        /**< Interpret bytes as an ASCII hex-digit string and decode to binary */
    DecodeAsPercentEncoding,  /**< Decode percent-encoded (URL-encoded) byte sequences */
    DecodeAsQuotedPrintable,  /**< Decode Quoted-Printable encoded data */
    DecodeAsROT13             /**< Apply ROT13 substitution cipher to the bytes */
} bytes_decode_type;


/**
 * @brief Persisted GUI state and preferences restored across Wireshark sessions.
 */
typedef struct recent_settings_tag {

    /* --- Toolbar and pane visibility --- */
    bool main_toolbar_show;          /**< True if the main toolbar is visible */
    bool filter_toolbar_show;        /**< True if the display filter toolbar is visible */
    bool wireless_toolbar_show;      /**< True if the wireless toolbar is visible */
    bool packet_list_show;           /**< True if the packet list pane is visible */
    bool tree_view_show;             /**< True if the packet details tree pane is visible */
    bool byte_view_show;             /**< True if the packet bytes pane is visible */
    bool packet_diagram_show;        /**< True if the packet diagram pane is visible */
    bool statusbar_show;             /**< True if the status bar is visible */

    /* --- Packet list behaviour --- */
    bool packet_list_colorize;       /**< True if coloring rules are applied to the packet list */
    bool capture_auto_scroll;        /**< True if the packet list auto-scrolls during live capture */
    bool aggregation_view;           /**< True if the aggregation (combined) view is active */

    /* --- Time display --- */
    ts_type         gui_time_format;    /**< Timestamp display format (see ::ts_type) */
    int             gui_time_precision; /**< Number of fractional seconds digits shown in timestamps */
    ts_seconds_type gui_seconds_format; /**< Format used for the seconds portion of timestamps (see ::ts_seconds_type) */

    /* --- Zoom and bytes display --- */
    int                 gui_zoom_level;                    /**< Font zoom level applied to the packet list and details panes */
    bytes_view_type     gui_bytes_view;                    /**< Numeric base used to render bytes in the bytes pane */
    bytes_encoding_type gui_bytes_encoding;                /**< Character encoding used for the ASCII column of the bytes pane */
    bool                gui_packet_diagram_field_values;   /**< True if field values are shown inside the packet diagram */
    bool                gui_allow_hover_selection;         /**< True if hovering over the packet list selects the packet under the cursor */

    /* --- Find Packet settings --- */
    search_in_type       gui_search_in;              /**< Pane searched by the Find Packet dialog */
    search_char_set_type gui_search_char_set;         /**< Character width(s) matched during string searches */
    bool                 gui_search_case_sensitive;   /**< True if string/regex searches are case-sensitive */
    bool                 gui_search_reverse_dir;      /**< True if searches proceed backwards through the packet list */
    bool                 gui_search_multiple_occurs;  /**< True if all occurrences within a packet are highlighted */
    search_type_type     gui_search_type;             /**< Matching method used by the Find Packet dialog */

    /* --- Follow Stream settings --- */
    bytes_show_type   gui_follow_show;    /**< Presentation format used in the Follow Stream dialog */
    follow_delta_type gui_follow_delta;   /**< Inter-segment timing delta mode for the Follow Stream dialog */

    /* --- Show Packet Bytes settings --- */
    bytes_decode_type gui_show_bytes_decode; /**< Secondary decode transformation applied in the Show Packet Bytes dialog */
    bytes_show_type   gui_show_bytes_show;   /**< Presentation format used in the Show Packet Bytes dialog */

    /* --- Main window geometry --- */
    int  gui_geometry_main_x;          /**< Saved X position of the main window */
    int  gui_geometry_main_y;          /**< Saved Y position of the main window */
    int  gui_geometry_main_width;      /**< Saved width of the main window in pixels */
    int  gui_geometry_main_height;     /**< Saved height of the main window in pixels */
    bool gui_geometry_main_maximized;  /**< True if the main window was maximized when last closed */
    bool gui_geometry_leftalign_actions; /**< True if toolbar actions are left-aligned */

    /* --- Splitter positions --- */
    int   gui_geometry_main_upper_pane;      /**< Saved pixel height of the upper splitter pane */
    int   gui_geometry_main_lower_pane;      /**< Saved pixel height of the lower splitter pane */
    char *gui_geometry_main;                 /**< Serialised main window geometry string */
    char *gui_geometry_main_master_split;    /**< Serialised master splitter state */
    char *gui_geometry_main_extra_split;     /**< Serialised extra splitter state */

    /* --- Privilege and system warnings --- */
    bool privs_warn_if_elevated;   /**< True if a warning is shown when running with elevated privileges */
    bool sys_warn_if_no_capture;   /**< True if a warning is shown when capture support is unavailable */

    /* --- Column and dialog tab state --- */
    GList *col_width_list;              /**< Saved column widths for the packet list */
    GList *conversation_tabs;           /**< Names of enabled tabs in the Conversations dialog */
    GList *conversation_tabs_columns;   /**< Saved column configurations for Conversations dialog tabs */
    GList *endpoint_tabs;               /**< Names of enabled tabs in the Endpoints dialog */
    GList *endpoint_tabs_columns;       /**< Saved column configurations for Endpoints dialog tabs */

    /* --- Miscellaneous --- */
    int   gui_profile_switch_check_count;  /**< Number of packets or events checked per automatic profile switch evaluation */
    char *gui_fileopen_remembered_dir;     /**< Last directory visited in the File Open dialog */
    bool  gui_rlc_use_pdus_from_mac;       /**< True if the RLC dissector should source PDUs from the MAC layer */
    GList *custom_colors;                  /**< User-defined custom colours for the colour picker */
    GList *gui_additional_toolbars;        /**< Names of additional plugin toolbars that are shown */
    GList *interface_toolbars;             /**< State of interface-specific extcap toolbars */

    /* --- TCP Stream Graph dialog --- */
    bool   gui_tsgd_throughput_show;   /**< True if the throughput series is shown in the TCP Stream Graph dialog */
    bool   gui_tsgd_goodput_show;      /**< True if the goodput series is shown in the TCP Stream Graph dialog */
    double gui_tsgd_ma_window_size;    /**< Moving average window size used in the TCP Stream Graph dialog */

    /* --- Welcome page sidebar / banner slides --- */
    bool     gui_welcome_page_sidebar_learn_visible;       /**< True if the Learn sidebar panel is expanded on the welcome page */
    bool     gui_welcome_page_sidebar_tips_visible;        /**< True if the Tips/News sidebar panel is expanded on the welcome page */
    bool     gui_welcome_page_sidebar_tips_events;         /**< True if event slides are shown in the banner */
    bool     gui_welcome_page_sidebar_tips_sponsorship;    /**< True if sponsorship slides are shown in the banner */
    bool     gui_welcome_page_sidebar_tips_tips;           /**< True if tip slides are shown in the banner */
    bool     gui_welcome_page_sidebar_tips_auto_advance;   /**< True if the banner auto-advances through slides */
    unsigned gui_welcome_page_sidebar_tips_interval;       /**< Auto-advance interval for banner slides in milliseconds */

    /**
     * Internal name of the active theme (directory name under
     * `resources/themes/`, e.g. "default", "inverted").  NULL or empty
     * is treated as "default".  Lives in recent_common so the choice is
     * global and persists across profile switches, mirroring the
     * welcome-page sidebar settings.
     */
    char       *gui_theme_name;

    /**
     * Active appearance mode (COLOR_SCHEME_DEFAULT / _LIGHT / _DARK).
     * Lives in recent_common so the choice is global and persists across
     * profile switches, mirroring gui_theme_name.  Was formerly the
     * per-profile preference gui.color_scheme.
     */
    int      gui_color_scheme;
    bool     gui_welcome_page_sidebar_tips_slides_test;    /**< True if test/debug slides are included in the banner rotation */

} recent_settings_t;

/** Global recent settings. */
extern recent_settings_t recent;

/**
 * @brief Initialize recent settings module (done at startup).
 */
extern void recent_init(void);

/**
 * @brief Cleans up recent settings and frees allocated memory.
 *
 * Cleanup/Frees recent settings (done at shutdown)
 */
extern void recent_cleanup(void);

/**
 * @brief Write recent_common settings file.
 *
 * @return true if succeeded, false if failed
 */
extern bool write_recent(void);

/**
 * @brief Write profile recent settings file.
 *
 * @return true if succeeded, false if failed
 */
extern bool write_profile_recent(void);

/**
 * @brief Read recent settings file (static part).
 *
 * @param rf_path_return path to recent file if function failed
 * @param rf_errno_return if failed
 * @return true if succeeded, false if failed (check parameters for reason).
 */
extern bool recent_read_static(char **rf_path_return, int *rf_errno_return);

/**
 * @brief Read profile recent settings file (static part).
 *
 * @param rf_path_return path to recent file if function failed
 * @param rf_errno_return if failed
 * @return true if succeeded, false if failed (check parameters for reason).
 */
extern bool recent_read_profile_static(char **rf_path_return, int *rf_errno_return);

/**
 * @brief Read recent settings file (dynamic part).
 *
 * @param rf_path_return path to recent file if function failed
 * @param rf_errno_return if failed
 * @return true if succeeded, false if failed (check parameters for reason).
 */
extern bool recent_read_dynamic(char **rf_path_return, int *rf_errno_return);

/**
 * @brief Given a -o command line string, parse it and set the recent value in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 *
 * @param prefarg a string of the form "<recent name>:<recent value>", as might appear
 * as an argument to a "-o" command line option
 * @return PREFS_SET_OK or PREFS_SET_SYNTAX_ERR
 */
extern int recent_set_arg(char *prefarg);

/**
 * @brief Free the recent settings list of column width information
 *
 * @param rs the recent settings (currently a global)
 */
extern void recent_free_column_width_info(recent_settings_t *rs);

/**
 * @brief Insert an entry in the recent column width setting for
 * the given column, which should have been just added to
 * the column list preference. (This keeps them in sync.)
 *
 * @param col column number
 */
extern void recent_insert_column(int col);

/**
 * @brief Remove an entry in the recent column width setting for
 * the given column, which should have been just removed to
 * the column list preference. (This keeps them in sync.)
 *
 * @param col column number
 */
extern void recent_remove_column(int col);

/**
 * @brief Set the column width for the given column
 *
 * @param col column number
 * @param format column format
 */
extern void recent_set_column_format(int col, int format);

/**
 * @brief Get the column width for the given column
 *
 * @param col column number
 */
extern int recent_get_column_width(int col);

/**
 * @brief Set the column width for the given column
 *
 * @param col column number
 * @param width column width
 */
extern void recent_set_column_width(int col, int width);

/**
 * @brief Get the column xalign for the given column
 *
 * @param col column number
 */
extern char recent_get_column_xalign(int col);

/**
 * @brief Set the column xalign for the given column
 *
 * @param col column number
 * @param xalign column alignment
 */
extern void recent_set_column_xalign(int col, char xalign);

/**
 * @brief save the window and its current geometry into the geometry hashtable.
 *
 * @param name The name of the window.
 * @param geom Pointer to the window_geometry_t structure containing the geometry data.
 *
 * @note This deep copies the window_geometry_t struct (including the qt_geom
 * member) and does NOT take ownership of the original.
 */
extern void window_geom_save(const char *name, window_geometry_t *geom);

/**
 * @brief Load the desired geometry for this window from the geometry hashtable.
 *
 * @param name The name of the window.
 * @param geom Pointer to the window_geometry_t structure to be filled with the geometry data.
 * @return bool True if the geometry was successfully loaded, false otherwise.
 */
extern bool window_geom_load(const char *name, window_geometry_t *geom);

/**
 * @brief Save the splitter state for a given interface.
 *
 * @param name Interface name; NULL refers to the global list.
 * @param splitter_state The state of the splitter.
 */
extern void window_splitter_save(const char *name, const char *splitter_state);

/**
 * @brief Load the splitter state for a given interface.
 *
 * @param name Interface name; NULL refers to the global list.
 * @return const char* The state of the splitter, or NULL if not found.
 */
extern const char * window_splitter_load(const char *name);

/**
 * @brief Returns a list of recent capture filters.
 *
 * @param ifname interface name; NULL refers to the global list.
 * @return A GList containing the recent capture filters, or NULL if none are available.
 */
extern GList *recent_get_cfilter_list(const char *ifname);

/**
 * @brief Add a capture filter to the global recent capture filter list or
 * the recent capture filter list for an interface.
 *
 * @param ifname interface name; NULL refers to the global list.
 * @param s text of capture filter
 */
extern void recent_add_cfilter(const char *ifname, const char *s);

/**
 * @brief Get the value of an entry for a remote host from the remote host list.
 *
 * @param host host name for the remote host.
 * @return pointer to the entry for the remote host.
 */
extern struct remote_host *recent_get_remote_host(const char *host);

/**
 * @brief Get the number of entries of the remote host list.
 *
 * @return number of entries in the list.
 */
extern int recent_get_remote_host_list_size(void);

/**
 * @brief Iterate over all items in the remote host list, calling a
 * function for each member
 *
 * @param func function to be called
 * @param user_data argument to pass as user data to the function
 */
extern void recent_remote_host_list_foreach(GFunc func, void *user_data);

/**
 * @brief Free all entries of the remote host list.
 */
extern void recent_free_remote_host_list(void);

/**
 * @brief Add an entry to the remote_host_list.
 *
 * @param host Key of the entry
 * @param rh Value of the entry
 */
extern void recent_add_remote_host(char *host, struct remote_host *rh);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* recent.h */
