/* recent.c
 * Recent "preference" handling routines
 * Copyright 2004, Ulf Lamping <ulf.lamping@web.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <wireshark.h>

#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_PCAP_REMOTE
#include <capture_opts.h>
#endif
#include <wsutil/filesystem.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/column.h>
#include <epan/value_string.h>

#include "ui/util.h"
#include "ui/recent.h"
#include "ui/recent_utils.h"
#include "ui/packet_list_utils.h"
#include "ui/simple_dialog.h"

#include <wsutil/file_util.h>
#include <wsutil/strtoi.h>

#define RECENT_KEY_MAIN_TOOLBAR_SHOW            "gui.toolbar_main_show"
#define RECENT_KEY_FILTER_TOOLBAR_SHOW          "gui.filter_toolbar_show"
#define RECENT_KEY_WIRELESS_TOOLBAR_SHOW        "gui.wireless_toolbar_show"
#define RECENT_KEY_PACKET_LIST_SHOW             "gui.packet_list_show"
#define RECENT_KEY_TREE_VIEW_SHOW               "gui.tree_view_show"
#define RECENT_KEY_BYTE_VIEW_SHOW               "gui.byte_view_show"
#define RECENT_KEY_PACKET_DIAGRAM_SHOW          "gui.packet_diagram_show"
#define RECENT_KEY_STATUSBAR_SHOW               "gui.statusbar_show"
#define RECENT_KEY_PACKET_LIST_COLORIZE         "gui.packet_list_colorize"
#define RECENT_KEY_CAPTURE_AUTO_SCROLL          "capture.auto_scroll"
#define RECENT_GUI_TIME_FORMAT                  "gui.time_format"
#define RECENT_GUI_TIME_PRECISION               "gui.time_precision"
#define RECENT_GUI_SECONDS_FORMAT               "gui.seconds_format"
#define RECENT_GUI_ZOOM_LEVEL                   "gui.zoom_level"
#define RECENT_GUI_BYTES_VIEW                   "gui.bytes_view"
#define RECENT_GUI_BYTES_ENCODING               "gui.bytes_encoding"
#define RECENT_GUI_ALLOW_HOVER_SELECTION        "gui.allow_hover_selection"
#define RECENT_GUI_PACKET_DIAGRAM_FIELD_VALUES  "gui.packet_diagram_field_values"
#define RECENT_GUI_GEOMETRY_MAIN_X              "gui.geometry_main_x"
#define RECENT_GUI_GEOMETRY_MAIN_Y              "gui.geometry_main_y"
#define RECENT_GUI_GEOMETRY_MAIN_WIDTH          "gui.geometry_main_width"
#define RECENT_GUI_GEOMETRY_MAIN_HEIGHT         "gui.geometry_main_height"
#define RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED      "gui.geometry_main_maximized"
#define RECENT_GUI_GEOMETRY_MAIN                "gui.geometry_main"
#define RECENT_GUI_GEOMETRY_LEFTALIGN_ACTIONS   "gui.geometry_leftalign_actions"
#define RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE     "gui.geometry_main_upper_pane"
#define RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE     "gui.geometry_main_lower_pane"
#define RECENT_GUI_GEOMETRY_MAIN_MASTER_SPLIT   "gui.geometry_main_master_split"
#define RECENT_GUI_GEOMETRY_MAIN_EXTRA_SPLIT    "gui.geometry_main_extra_split"
#define RECENT_LAST_USED_PROFILE                "gui.last_used_profile"
#define RECENT_PROFILE_SWITCH_CHECK_COUNT       "gui.profile_switch_check_count"
#define RECENT_GUI_FILEOPEN_REMEMBERED_DIR      "gui.fileopen_remembered_dir"
#define RECENT_GUI_CONVERSATION_TABS            "gui.conversation_tabs"
#define RECENT_GUI_CONVERSATION_TABS_COLUMNS    "gui.conversation_tabs_columns"
#define RECENT_GUI_ENDPOINT_TABS                "gui.endpoint_tabs"
#define RECENT_GUI_ENDPOINT_TABS_COLUMNS        "gui.endpoint_tabs_columns"
#define RECENT_GUI_RLC_PDUS_FROM_MAC_FRAMES     "gui.rlc_pdus_from_mac_frames"
#define RECENT_GUI_CUSTOM_COLORS                "gui.custom_colors"
#define RECENT_GUI_TOOLBAR_SHOW                 "gui.additional_toolbar_show"
#define RECENT_GUI_INTERFACE_TOOLBAR_SHOW       "gui.interface_toolbar_show"
#define RECENT_GUI_SEARCH_IN                    "gui.search_in"
#define RECENT_GUI_SEARCH_CHAR_SET              "gui.search_char_set"
#define RECENT_GUI_SEARCH_CASE_SENSITIVE        "gui.search_case_sensitive"
#define RECENT_GUI_SEARCH_REVERSE_DIR           "gui.search_reverse_dir"
#define RECENT_GUI_SEARCH_MULTIPLE_OCCURS       "gui.search_multiple_occurs"
#define RECENT_GUI_SEARCH_TYPE                  "gui.search_type"
#define RECENT_GUI_FOLLOW_SHOW                  "gui.follow_show"
#define RECENT_GUI_FOLLOW_DELTA                 "gui.follow_delta"
#define RECENT_GUI_SHOW_BYTES_DECODE            "gui.show_bytes_decode"
#define RECENT_GUI_SHOW_BYTES_SHOW              "gui.show_bytes_show"

#define RECENT_GUI_GEOMETRY                   "gui.geom."

#define RECENT_KEY_PRIVS_WARN_IF_ELEVATED     "privs.warn_if_elevated"
#define RECENT_KEY_SYS_WARN_IF_NO_CAPTURE     "sys.warn_if_no_capture"

#define RECENT_FILE_NAME "recent"
#define RECENT_COMMON_FILE_NAME "recent_common"

recent_settings_t recent;

static const value_string ts_type_values[] = {
    { TS_RELATIVE,             "RELATIVE"           },
    { TS_ABSOLUTE,             "ABSOLUTE"           },
    { TS_ABSOLUTE_WITH_YMD,    "ABSOLUTE_WITH_YMD"  },
    { TS_ABSOLUTE_WITH_YDOY,   "ABSOLUTE_WITH_YDOY" },
    { TS_ABSOLUTE_WITH_YMD,    "ABSOLUTE_WITH_DATE" },  /* Backward compatibility */
    { TS_DELTA,                "DELTA"              },
    { TS_DELTA_DIS,            "DELTA_DIS"          },
    { TS_EPOCH,                "EPOCH"              },
    { TS_UTC,                  "UTC"                },
    { TS_UTC_WITH_YMD,         "UTC_WITH_YMD"       },
    { TS_UTC_WITH_YDOY,        "UTC_WITH_YDOY"      },
    { TS_UTC_WITH_YMD,         "UTC_WITH_DATE"      },  /* Backward compatibility */
    { 0, NULL }
};

/*
 * NOTE: all values other than TS_PREC_AUTO are the number of digits
 * of precision.
 *
 * We continue to use the old names for values where they may have
 * been written to the recent file by previous releases.  For other
 * values, we just write it out numerically.
 */
static const value_string ts_precision_values[] = {
    { TS_PREC_AUTO,            "AUTO" },
    { TS_PREC_FIXED_SEC,       "SEC"  },
    { TS_PREC_FIXED_100_MSEC,  "DSEC" },
    { TS_PREC_FIXED_10_MSEC,   "CSEC" },
    { TS_PREC_FIXED_MSEC,      "MSEC" },
    { TS_PREC_FIXED_USEC,      "USEC" },
    { TS_PREC_FIXED_NSEC,      "NSEC" },
    { 0, NULL }
};

static const value_string ts_seconds_values[] = {
    { TS_SECONDS_DEFAULT,      "SECONDS"      },
    { TS_SECONDS_HOUR_MIN_SEC, "HOUR_MIN_SEC" },
    { 0, NULL }
};

static const value_string bytes_view_type_values[] = {
    { BYTES_HEX,    "HEX"  },
    { BYTES_BITS,   "BITS" },
    { BYTES_DEC,    "DEC" },
    { BYTES_OCT,    "OCT" },
    { 0, NULL }
};

static const value_string bytes_encoding_type_values[] = {
    { BYTES_ENC_FROM_PACKET,    "FROM_PACKET"  },
    { BYTES_ENC_ASCII,          "ASCII"  },
    { BYTES_ENC_EBCDIC,         "EBCDIC"  },
    { 0, NULL }
};

static const value_string search_in_values[] = {
    { SEARCH_IN_PACKET_LIST,    "PACKET_LIST" },
    { SEARCH_IN_PACKET_DETAILS, "PACKET_DETAILS" },
    { SEARCH_IN_PACKET_BYTES,   "PACKET_BYTES" },
    { 0, NULL }
};

static const value_string search_char_set_values[] = {
    { SEARCH_CHAR_SET_NARROW_AND_WIDE, "NARROW_AND_WIDE" },
    { SEARCH_CHAR_SET_NARROW,          "NARROW" },
    { SEARCH_CHAR_SET_WIDE,            "WIDE" },
    { 0, NULL }
};

static const value_string search_type_values[] = {
    { SEARCH_TYPE_DISPLAY_FILTER, "DISPLAY_FILTER" },
    { SEARCH_TYPE_HEX_VALUE,      "HEX_VALUE" },
    { SEARCH_TYPE_STRING,         "STRING" },
    { SEARCH_TYPE_REGEX,          "REGEX" },
    { 0, NULL }
};

static const value_string bytes_show_values[] = {
    { SHOW_ASCII,         "ASCII" },
    { SHOW_ASCII_CONTROL, "ASCII_CONTROL" },
    { SHOW_CARRAY,        "C_ARRAYS" },
    { SHOW_EBCDIC,        "EBCDIC" },
    { SHOW_HEXDUMP,       "HEX_DUMP" },
    { SHOW_HTML,          "HTML" },
    { SHOW_IMAGE,         "IMAGE" },
    { SHOW_JSON,          "JSON" },
    { SHOW_RAW,           "RAW" },
    { SHOW_RUSTARRAY,     "RUST_ARRAY" },
    { SHOW_CODEC,         "UTF-8" },
    // Other codecs are generated at runtime
    { SHOW_YAML,          "YAML"},
    { 0, NULL }
};

static const value_string follow_delta_values[] = {
    { FOLLOW_DELTA_NONE,    "NONE" },
    { FOLLOW_DELTA_TURN,    "TURN" },
    { FOLLOW_DELTA_ALL,     "ALL" },
    { 0, NULL }
};

static const value_string show_bytes_decode_values[] = {
    { DecodeAsNone,            "NONE" },
    { DecodeAsBASE64,          "BASE64" },
    { DecodeAsCompressed,      "COMPRESSED" },
    { DecodeAsHexDigits,       "HEX_DIGITS" },
    { DecodeAsPercentEncoding, "PERCENT_ENCODING" },
    { DecodeAsQuotedPrintable, "QUOTED_PRINTABLE" },
    { DecodeAsROT13,           "ROT13"},
    { 0, NULL }
};

static void
free_col_width_data(void *data)
{
    col_width_data *cfmt = (col_width_data *)data;
    g_free(cfmt);
}

void
recent_free_column_width_info(recent_settings_t *rs)
{
    g_list_free_full(rs->col_width_list, free_col_width_data);
    rs->col_width_list = NULL;
}

/** Write the geometry values of a single window to the recent file.
 *
 * @param key unused
 * @param value the geometry values
 * @param rfh recent file handle (FILE)
 */
static void
write_recent_geom(void *key _U_, void *value, void *rfh)
{
    window_geometry_t *geom = (window_geometry_t *)value;
    FILE *rf = (FILE *)rfh;

    fprintf(rf, "\n# Geometry and maximized state of %s window.\n", geom->key);
    fprintf(rf, "# Decimal integers.\n");
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.x: %d\n", geom->key, geom->x);
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.y: %d\n", geom->key, geom->y);
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.width: %d\n", geom->key,
            geom->width);
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.height: %d\n", geom->key,
            geom->height);

    fprintf(rf, "# true or false (case-insensitive).\n");
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.maximized: %s\n", geom->key,
            geom->maximized == true ? "true" : "false");

    fprintf(rf, "# Qt Geometry State (hex byte string).\n");
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.qt_geometry: %s\n", geom->key,
            geom->qt_geom);
}

/* the geometry hashtable for all known window classes,
 * the window name is the key, and the geometry struct is the value */
static GHashTable *window_geom_hash;

static GHashTable *window_splitter_hash;

void
window_geom_free(void *data)
{
    window_geometry_t *geom = (window_geometry_t*)data;
    g_free(geom->key);
    g_free(geom->qt_geom);
    g_free(geom);
}

/* save the window and its current geometry into the geometry hashtable */
void
window_geom_save(const char *name, window_geometry_t *geom)
{
    char *key;
    window_geometry_t *work;

    /* init hashtable, if not already done */
    if (!window_geom_hash) {
        window_geom_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, window_geom_free);
    }

    /* g_malloc and insert the new one */
    work = g_new(window_geometry_t, 1);
    *work = *geom;
    key = g_strdup(name);
    work->key = key;
    g_hash_table_replace(window_geom_hash, key, work);
}

/* load the desired geometry for this window from the geometry hashtable */
bool
window_geom_load(const char        *name,
                 window_geometry_t *geom)
{
    window_geometry_t *p;

    /* init hashtable, if not already done */
    if (!window_geom_hash) {
        window_geom_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, window_geom_free);
    }

    p = (window_geometry_t *)g_hash_table_lookup(window_geom_hash, name);
    if (p) {
        *geom = *p;
        return true;
    } else {
        return false;
    }
}

/* save the window and its splitter state into the splitter hashtable */
void
window_splitter_save(const char *name, const char *splitter_state)
{
    /* init hashtable, if not already done */
    if (!window_splitter_hash) {
        window_splitter_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    }

    g_hash_table_replace(window_splitter_hash, g_strdup(name), g_strdup(splitter_state));
}

/* save the window and its splitter state into the geometry hashtable */
const char*
window_splitter_load(const char *name)
{
    /* init hashtable, if not already done */
    if (!window_splitter_hash) {
        return NULL;
    }

    return g_hash_table_lookup(window_splitter_hash, name);
}


/* parse values of particular types */
static void
parse_recent_boolean(const char *val_str, bool *valuep)
{
    if (g_ascii_strcasecmp(val_str, "true") == 0) {
        *valuep = true;
    }
    else {
        *valuep = false;
    }
}

/** Read in a single geometry key value pair from the recent file.
 *
 * @param name the geom_name of the window
 * @param key the subkey of this pair (e.g. "x")
 * @param value the new value (e.g. "123")
 */
static void
window_geom_recent_read_pair(const char *name,
                             const char *key,
                             const char *value)
{
    window_geometry_t geom;

    if (strcmp(key, "splitter") == 0) {
        window_splitter_save(name, value);
        return;
    }

    /* find window geometry maybe already in hashtable */
    if (!window_geom_load(name, &geom)) {
        /* not in table, init geom with "basic" values */
        geom.key        = NULL;    /* Will be set in window_geom_save() */
        geom.set_pos    = false;
        geom.x          = -1;
        geom.y          = -1;
        geom.set_size   = false;
        geom.width      = -1;
        geom.height     = -1;
        geom.qt_geom    = NULL;
    }

    if (strcmp(key, "x") == 0) {
        geom.x = (int)strtol(value, NULL, 10);
        geom.set_pos = true;
    } else if (strcmp(key, "y") == 0) {
        geom.y = (int)strtol(value, NULL, 10);
        geom.set_pos = true;
    } else if (strcmp(key, "width") == 0) {
        geom.width = (int)strtol(value, NULL, 10);
        geom.set_size = true;
    } else if (strcmp(key, "height") == 0) {
        geom.height = (int)strtol(value, NULL, 10);
        geom.set_size = true;
    } else if (strcmp(key, "maximized") == 0) {
        parse_recent_boolean(value, &geom.maximized);
        geom.set_maximized = true;
    } else if (strcmp(key, "qt_geometry") == 0) {
        geom.qt_geom = g_strdup(value);
    } else {
        /*
         * Silently ignore the bogus key.  We shouldn't abort here,
         * as this could be due to a corrupt recent file.
         *
         * XXX - should we print a message about this?
         */
        return;
    }

    /* save / replace geometry in hashtable */
    window_geom_save(name, &geom);
}

/** Write all geometry values of all windows to the recent file.
 * Will call write_recent_geom() for every existing window type.
 *
 * @param rf recent file handle from caller
 */
static void
window_geom_recent_write_all(FILE *rf)
{
    /* init hashtable, if not already done */
    if (!window_geom_hash) {
        window_geom_hash = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, window_geom_free);
    }

    g_hash_table_foreach(window_geom_hash, write_recent_geom, rf);
}

/** Write all known window splitter states to the recent file.
 *
 * @param rf recent file handle from caller
 */
static void
window_splitter_recent_write_all(FILE *rf)
{
    /* init hashtable, if not already done */
    if (!window_splitter_hash) {
        return;
    }

    GHashTableIter iter;
    void *key, *value;
    g_hash_table_iter_init(&iter, window_splitter_hash);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        fprintf(rf, "\n# Splitter state of %s window.\n", (char*)key);
        fprintf(rf, "# Qt Splitter state (hex byte string).\n");
        fprintf(rf, RECENT_GUI_GEOMETRY "%s.splitter: %s\n", (char*)key,
                (char*)value);
    }
}

/* Global list of recent capture filters. */
static GList *recent_cfilter_list;

/*
 * Per-interface lists of recent capture filters; stored in a hash
 * table indexed by interface name.
 */
static GHashTable *per_interface_cfilter_lists_hash;

/* XXX: use a preference for this setting! */
/* N.B.: If we use a pref, we will read the recent_common file
 * before the pref, so don't truncate the list when reading
 * (see the similar #16782 for the recent files.)
 */
static unsigned cfilter_combo_max_recent = 20;

/**
 * Returns a list of recent capture filters.
 *
 * @param ifname interface name; NULL refers to the global list.
 */
GList *
recent_get_cfilter_list(const char *ifname)
{
    if (ifname == NULL)
        return recent_cfilter_list;
    if (per_interface_cfilter_lists_hash == NULL) {
        /* No such lists exist. */
        return NULL;
    }
    return (GList *)g_hash_table_lookup(per_interface_cfilter_lists_hash, ifname);
}

/**
 * Add a capture filter to the global recent capture filter list or
 * the recent capture filter list for an interface.
 *
 * @param ifname interface name; NULL refers to the global list.
 * @param s text of capture filter
 */
void
recent_add_cfilter(const char *ifname, const char *s)
{
    GList     *cfilter_list;
    GList     *li;
    char      *li_filter, *newfilter = NULL;

    /* Don't add empty filters to the list. */
    if (s[0] == '\0')
        return;

    if (ifname == NULL)
        cfilter_list = recent_cfilter_list;
    else {
        /* If we don't yet have a hash table for per-interface recent
           capture filter lists, create one.  Have it free the new key
           if we're updating an entry rather than creating it below. */
        if (per_interface_cfilter_lists_hash == NULL)
            per_interface_cfilter_lists_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        cfilter_list = (GList *)g_hash_table_lookup(per_interface_cfilter_lists_hash, ifname);
    }

    li = g_list_first(cfilter_list);
    while (li) {
        /* If the filter is already in the list, remove the old one and
         * append the new one at the latest position (at g_list_append() below) */
        li_filter = (char *)li->data;
        if (strcmp(s, li_filter) == 0) {
            /* No need to copy the string, we're just moving it. */
            newfilter = li_filter;
            cfilter_list = g_list_remove(cfilter_list, li->data);
            break;
        }
        li = li->next;
    }
    if (newfilter == NULL) {
        /* The filter wasn't already in the list; make a copy to add. */
        newfilter = g_strdup(s);
    }
    cfilter_list = g_list_prepend(cfilter_list, newfilter);

    if (ifname == NULL)
        recent_cfilter_list = cfilter_list;
    else
        g_hash_table_insert(per_interface_cfilter_lists_hash, g_strdup(ifname), cfilter_list);
}

#ifdef HAVE_PCAP_REMOTE
/* XXX: use a preference for this setting! */
/* N.B.: If we use a pref, we will read the recent_common file
 * before the pref, so don't truncate the list when reading
 * (see the similar #16782 for the recent files.)
 */
static unsigned remote_host_max_recent = 20;
static GList *remote_host_list;

int recent_get_remote_host_list_size(void)
{
    if (remote_host_list == NULL) {
        /* No entries exist. */
        return 0;
    }
    return g_list_length(remote_host_list);
}

static void
free_remote_host(void *value)
{
    struct remote_host* rh = (struct remote_host*)value;

    g_free(rh->r_host);
    g_free(rh->remote_port);
    g_free(rh->auth_username);
    g_free(rh->auth_password);

}

static int
remote_host_compare(const void *a, const void *b)
{
    const struct remote_host* rh_a = (const struct remote_host*)a;
    const struct remote_host* rh_b = (const struct remote_host*)b;

    /* We assume only one entry per host (the GUI assumes that too.) */
    return g_strcmp0(rh_a->r_host, rh_b->r_host);
}

static void
remote_host_reverse(void)
{
    if (remote_host_list) {
        remote_host_list = g_list_reverse(remote_host_list);
    }
}

void recent_add_remote_host(char *host _U_, struct remote_host *rh)
{
    GList* li = NULL;
    if (remote_host_list) {
        li = g_list_find_custom(remote_host_list, rh, remote_host_compare);
        if (li != NULL) {
            free_remote_host(li->data);
            remote_host_list = g_list_delete_link(remote_host_list, li);
        }
    }
    remote_host_list = g_list_prepend(remote_host_list, rh);
}

void
recent_remote_host_list_foreach(GFunc func, void *user_data)
{
    if (remote_host_list != NULL) {
        g_list_foreach(remote_host_list, func, user_data);
    }
}

static void
recent_print_remote_host(void *value, void *user)
{
    FILE *rf = (FILE *)user;
    struct remote_host_info *ri = (struct remote_host_info *)value;

    fprintf (rf, RECENT_KEY_REMOTE_HOST ": %s,%s,%d\n", ri->remote_host, ri->remote_port, ri->auth_type);
}

/**
 * Write the contents of the remote_host_list to the 'recent' file.
 *
 * @param rf File to write to.
 */
static void
capture_remote_combo_recent_write_all(FILE *rf)
{
    unsigned max_count = 0;
    GList   *li = g_list_first(remote_host_list);

    /* write all non empty remote capture hosts to the recent file (until max count) */
    while (li && (max_count++ <= remote_host_max_recent)) {
        recent_print_remote_host(li->data, rf);
        li = li->next;
    }
}


void recent_free_remote_host_list(void)
{
    g_list_free_full(remote_host_list, free_remote_host);
    remote_host_list = NULL;
}

struct remote_host *
recent_get_remote_host(const char *host)
{
    if (host == NULL)
        return NULL;
    for (GList* li = g_list_first(remote_host_list); li != NULL; li = li->next) {
        struct remote_host *rh = (struct remote_host*)li->data;
        if (g_strcmp0(host, rh->r_host) == 0) {
            return rh;
        }
    }
    return NULL;
}

/**
 * Fill the remote_host_list with the entries stored in the 'recent' file.
 *
 * @param s String to be filled from the 'recent' file.
 * @return True, if the list was written successfully, False otherwise.
 */
static bool
capture_remote_combo_add_recent(const char *s)
{
    GList *vals = prefs_get_string_list (s);
    GList *valp = vals;
    capture_auth auth_type;
    char  *p;
    struct remote_host *rh;

    if (valp == NULL)
        return false;

    /* First value is the host */
    if (recent_get_remote_host(valp->data)) {
        /* Don't add it, it's already in the list (shouldn't happen). */
        return false; // Should this be true or false?
    }
    rh = (struct remote_host *) g_malloc (sizeof (*rh));

    /* First value is the host */
    rh->r_host = (char *)g_strdup ((const char *)valp->data);
    if (strlen(rh->r_host) == 0) {
        /* Empty remote host */
        g_free(rh->r_host);
        g_free(rh);
        return false;
    }
    rh->auth_type = CAPTURE_AUTH_NULL;
    valp = valp->next;

    if (valp) {
        /* Found value 2, this is the port number */
        if (!strcmp((const char*)valp->data, "0")) {
            /* Port 0 isn't valid, so leave port blank */
            rh->remote_port = (char *)g_strdup ("");
        } else {
            rh->remote_port = (char *)g_strdup ((const char *)valp->data);
        }
        valp = valp->next;
    } else {
        /* Did not find a port number */
        rh->remote_port = g_strdup ("");
    }

    if (valp) {
        /* Found value 3, this is the authentication type */
        auth_type = (capture_auth)strtol((const char *)valp->data, &p, 0);
        if (p != valp->data && *p == '\0') {
            rh->auth_type = auth_type;
        }
    }

    /* Do not store username and password */
    rh->auth_username = g_strdup ("");
    rh->auth_password = g_strdup ("");

    prefs_clear_string_list(vals);

    remote_host_list = g_list_prepend(remote_host_list, rh);
    return true;
}
#endif

static void
cfilter_recent_write_all_list(FILE *rf, const char *ifname, GList *cfilter_list)
{
    unsigned   max_count = 0;
    GList     *li;

    /* write all non empty capture filter strings to the recent file (until max count) */
    li = g_list_first(cfilter_list);
    while (li && (max_count++ <= cfilter_combo_max_recent) ) {
        if (li->data && strlen((const char *)li->data)) {
            if (ifname == NULL)
                fprintf (rf, RECENT_KEY_CAPTURE_FILTER ": %s\n", (char *)li->data);
            else
                fprintf (rf, RECENT_KEY_CAPTURE_FILTER ".%s: %s\n", ifname, (char *)li->data);
        }
        li = li->next;
    }
}

static void
cfilter_recent_write_all_hash_callback(void *key, void *value, void *user_data)
{
    cfilter_recent_write_all_list((FILE *)user_data, (const char *)key, (GList *)value);
}

/** Write all capture filter values to the recent file.
 *
 * @param rf recent file handle from caller
 */
static void
cfilter_recent_write_all(FILE *rf)
{
    /* Write out the global list. */
    cfilter_recent_write_all_list(rf, NULL, recent_cfilter_list);

    /* Write out all the per-interface lists. */
    if (per_interface_cfilter_lists_hash != NULL) {
        g_hash_table_foreach(per_interface_cfilter_lists_hash, cfilter_recent_write_all_hash_callback, (void *)rf);
    }
}

/** Reverse the order of all the capture filter lists after
 *  reading recent_common (we want the latest first).
 *  Note this is O(N), whereas appendng N items to a GList is O(N^2),
 *  since it doesn't have a pointer to the end like a GQueue.
 */
static void
cfilter_recent_reverse_all(void)
{
    recent_cfilter_list = g_list_reverse(recent_cfilter_list);

    /* Reverse all the per-interface lists. */
    if (per_interface_cfilter_lists_hash != NULL) {
        GHashTableIter iter;
        void *key, *value;
        g_hash_table_iter_init(&iter, per_interface_cfilter_lists_hash);
        GList *li;
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            li = (GList *)value;
            li = g_list_reverse(li);
            /* per_interface_cfilter_lists_hash was created without a
             * value_destroy_func, so this is fine.
             */
            g_hash_table_iter_replace(&iter, li);
        }
    }
}

/* Write out recent settings of particular types. */
static void
write_recent_boolean(FILE *rf, const char *description, const char *name,
                     bool value)
{
    fprintf(rf, "\n# %s.\n", description);
    fprintf(rf, "# true or false (case-insensitive).\n");
    fprintf(rf, "%s: %s\n", name, value == true ? "true" : "false");
}

static void
write_recent_enum(FILE *rf, const char *description, const char *name,
                  const value_string *values, unsigned value)
{
    const char *if_invalid = NULL;
    const value_string *valp;
    const char *str_value;

    fprintf(rf, "\n# %s.\n", description);
    fprintf(rf, "# One of: ");
    valp = values;
    while (valp->strptr != NULL) {
        if (if_invalid == NULL)
            if_invalid = valp->strptr;
        fprintf(rf, "%s", valp->strptr);
        valp++;
        if (valp->strptr != NULL)
            fprintf(rf, ", ");
    }
    fprintf(rf, "\n");
    str_value = try_val_to_str(value, values);
    if (str_value != NULL)
        fprintf(rf, "%s: %s\n", name, str_value);
    else
        fprintf(rf, "%s: %s\n", name, if_invalid != NULL ? if_invalid : "Unknown");
}

/* Attempt to write out "recent common" to the user's recent_common file.
   If we got an error report it with a dialog box and return false,
   otherwise return true. */
bool
write_recent(void)
{
    char        *pf_dir_path;
    char        *rf_path;
    FILE        *rf;
    char        *string_list;

    /* To do:
     * - Split output lines longer than MAX_VAL_LEN
     * - Create a function for the preference directory check/creation
     *   so that duplication can be avoided with filter.c
     */

    /* Create the directory that holds personal configuration files, if
       necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Can't create directory\n\"%s\"\nfor recent file: %s.", pf_dir_path,
                g_strerror(errno));
        g_free(pf_dir_path);
        return false;
    }

    rf_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, false);
    if ((rf = ws_fopen(rf_path, "w")) == NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Can't open recent file\n\"%s\": %s.", rf_path,
                g_strerror(errno));
        g_free(rf_path);
        return false;
    }
    g_free(rf_path);

    fprintf(rf, "# Common recent settings file for %s " VERSION ".\n"
            "#\n"
            "# This file is regenerated each time %s is quit\n"
            "# and when changing configuration profile.\n"
            "# So be careful, if you want to make manual changes here.\n"
            "\n"
            "######## Recent capture files (latest last), cannot be altered through command line ########\n"
            "\n",
            get_configuration_namespace(), get_configuration_namespace());


    menu_recent_file_write_all(rf);

    fputs("\n"
            "######## Recent capture filters (latest first), cannot be altered through command line ########\n"
            "\n", rf);

    cfilter_recent_write_all(rf);

    fputs("\n"
            "######## Recent display filters (latest last), cannot be altered through command line ########\n"
            "\n", rf);

    dfilter_recent_combo_write_all(rf);

#ifdef HAVE_PCAP_REMOTE
    fputs("\n"
            "######## Recent remote hosts (latest first), cannot be altered through command line ########\n"
            "\n", rf);

    capture_remote_combo_recent_write_all(rf);
#endif

    fprintf(rf, "\n# Main window geometry.\n");
    fprintf(rf, "# Decimal numbers.\n");
    fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_X ": %d\n", recent.gui_geometry_main_x);
    fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_Y ": %d\n", recent.gui_geometry_main_y);
    fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_WIDTH ": %d\n",
            recent.gui_geometry_main_width);
    fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_HEIGHT ": %d\n",
            recent.gui_geometry_main_height);

    write_recent_boolean(rf, "Main window maximized",
            RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED,
            recent.gui_geometry_main_maximized);

    if (recent.gui_geometry_main != NULL) {
        fprintf(rf, "\n# Main window geometry state.\n");
        fprintf(rf, "# Hex byte string.\n");
        fprintf(rf, RECENT_GUI_GEOMETRY_MAIN ": %s\n",
                recent.gui_geometry_main);
    }

    write_recent_boolean(rf, "Leftalign Action Buttons",
            RECENT_GUI_GEOMETRY_LEFTALIGN_ACTIONS,
            recent.gui_geometry_leftalign_actions);

    fprintf(rf, "\n# Last used Configuration Profile.\n");
    fprintf(rf, RECENT_LAST_USED_PROFILE ": %s\n", get_profile_name());

    fprintf(rf, "\n# Number of packets or events to check for automatic profile switching.\n");
    fprintf(rf, "# Decimal number. Zero disables switching.\n");
    const char * def_prefix = recent.gui_profile_switch_check_count == 1000 ? "#" : "";
    fprintf(rf, "%s" RECENT_PROFILE_SWITCH_CHECK_COUNT ": %d\n", def_prefix,
            recent.gui_profile_switch_check_count);

    write_recent_boolean(rf, "Warn if running with elevated permissions (e.g. as root)",
            RECENT_KEY_PRIVS_WARN_IF_ELEVATED,
            recent.privs_warn_if_elevated);

    write_recent_boolean(rf, "Warn if Wireshark is unable to capture",
            RECENT_KEY_SYS_WARN_IF_NO_CAPTURE,
            recent.sys_warn_if_no_capture);

    write_recent_enum(rf, "Find packet search in", RECENT_GUI_SEARCH_IN, search_in_values,
                      recent.gui_search_in);
    write_recent_enum(rf, "Find packet character set", RECENT_GUI_SEARCH_CHAR_SET, search_char_set_values,
                      recent.gui_search_char_set);
    write_recent_boolean(rf, "Find packet case sensitive search",
                         RECENT_GUI_SEARCH_CASE_SENSITIVE,
                         recent.gui_search_case_sensitive);
    write_recent_boolean(rf, "Find packet search reverse direction",
                         RECENT_GUI_SEARCH_REVERSE_DIR,
                         recent.gui_search_reverse_dir);
    write_recent_boolean(rf, "Find packet search multiple occurrences",
                         RECENT_GUI_SEARCH_MULTIPLE_OCCURS,
                         recent.gui_search_multiple_occurs);
    write_recent_enum(rf, "Find packet search type", RECENT_GUI_SEARCH_TYPE, search_type_values,
                      recent.gui_search_type);

    window_geom_recent_write_all(rf);

    fprintf(rf, "\n# Custom colors.\n");
    fprintf(rf, "# List of custom colors selected in Qt color picker.\n");
    string_list = join_string_list(recent.custom_colors);
    fprintf(rf, RECENT_GUI_CUSTOM_COLORS ": %s\n", string_list);
    g_free(string_list);

    fclose(rf);

    /* XXX - catch I/O errors (e.g. "ran out of disk space") and return
       an error indication, or maybe write to a new recent file and
       rename that file on top of the old one only if there are not I/O
       errors. */
    return true;
}


/* Attempt to Write out profile "recent" to the user's profile recent file.
   If we got an error report it with a dialog box and return false,
   otherwise return true. */
bool
write_profile_recent(void)
{
    char        *pf_dir_path;
    char        *rf_path;
    char        *string_list;
    FILE        *rf;

    /* To do:
     * - Split output lines longer than MAX_VAL_LEN
     * - Create a function for the preference directory check/creation
     *   so that duplication can be avoided with filter.c
     */

    /* Create the directory that holds personal configuration files, if
       necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Can't create directory\n\"%s\"\nfor recent file: %s.", pf_dir_path,
                g_strerror(errno));
        g_free(pf_dir_path);
        return false;
    }

    rf_path = get_persconffile_path(RECENT_FILE_NAME, true);
    if ((rf = ws_fopen(rf_path, "w")) == NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Can't open recent file\n\"%s\": %s.", rf_path,
                g_strerror(errno));
        g_free(rf_path);
        return false;
    }
    g_free(rf_path);

    fprintf(rf, "# Recent settings file for %s " VERSION ".\n"
            "#\n"
            "# This file is regenerated each time %s is quit\n"
            "# and when changing configuration profile.\n"
            "# So be careful, if you want to make manual changes here.\n"
            "\n",
            get_configuration_namespace(), get_configuration_namespace());

    write_recent_boolean(rf, "Main Toolbar show (hide)",
            RECENT_KEY_MAIN_TOOLBAR_SHOW,
            recent.main_toolbar_show);

    write_recent_boolean(rf, "Filter Toolbar show (hide)",
            RECENT_KEY_FILTER_TOOLBAR_SHOW,
            recent.filter_toolbar_show);

    write_recent_boolean(rf, "Wireless Settings Toolbar show (hide)",
            RECENT_KEY_WIRELESS_TOOLBAR_SHOW,
            recent.wireless_toolbar_show);

    write_recent_boolean(rf, "Packet list show (hide)",
            RECENT_KEY_PACKET_LIST_SHOW,
            recent.packet_list_show);

    write_recent_boolean(rf, "Tree view show (hide)",
            RECENT_KEY_TREE_VIEW_SHOW,
            recent.tree_view_show);

    write_recent_boolean(rf, "Byte view show (hide)",
            RECENT_KEY_BYTE_VIEW_SHOW,
            recent.byte_view_show);

    write_recent_boolean(rf, "Packet diagram show (hide)",
            RECENT_KEY_PACKET_DIAGRAM_SHOW,
            recent.packet_diagram_show);

    write_recent_boolean(rf, "Statusbar show (hide)",
            RECENT_KEY_STATUSBAR_SHOW,
            recent.statusbar_show);

    write_recent_boolean(rf, "Packet list colorize (hide)",
            RECENT_KEY_PACKET_LIST_COLORIZE,
            recent.packet_list_colorize);

    write_recent_boolean(rf, "Auto scroll packet list when capturing",
            RECENT_KEY_CAPTURE_AUTO_SCROLL,
            recent.capture_auto_scroll);

    write_recent_enum(rf, "Timestamp display format",
            RECENT_GUI_TIME_FORMAT, ts_type_values,
            recent.gui_time_format);

    /*
     * The value of this item is either TS_PREC_AUTO, which is a
     * negative number meaning "pick the display precision based
     * on the time stamp precision of the packet", or is a numerical
     * value giving the number of decimal places to display, from 0
     * to WS_TSPREC_MAX.
     *
     * It used to be that not all values between 0 and 9 (the maximum
     * precision back then) were supported, and that names were
     * written out to the recent file.
     *
     * For backwards compatibility with those older versions of
     * Wireshark, write out the names for those values, and the
     * raw number for other values.
     */
    {
        const char *if_invalid = NULL;
        const value_string *valp;
        const char *str_value;

        fprintf(rf, "\n# %s.\n", "Timestamp display precision");
        fprintf(rf, "# One of: ");
        valp = ts_precision_values;
        while (valp->strptr != NULL) {
            if (if_invalid == NULL)
                if_invalid = valp->strptr;
            fprintf(rf, "%s", valp->strptr);
            valp++;
            if (valp->strptr != NULL)
                fprintf(rf, ", ");
        }
        fprintf(rf, ", or a number between 0 and %d\n", WS_TSPREC_MAX);

        str_value = try_val_to_str(recent.gui_time_precision, ts_precision_values);
        if (str_value != NULL)
            fprintf(rf, "%s: %s\n", RECENT_GUI_TIME_PRECISION, str_value);
        else {
            if (recent.gui_time_precision >= 0 && recent.gui_time_precision < WS_TSPREC_MAX)
                fprintf(rf, "%s: %d\n", RECENT_GUI_TIME_PRECISION, recent.gui_time_precision);
            else
                fprintf(rf, "%s: %s\n", RECENT_GUI_TIME_PRECISION, if_invalid != NULL ? if_invalid : "Unknown");
        }
    }

    write_recent_enum(rf, "Seconds display format",
            RECENT_GUI_SECONDS_FORMAT, ts_seconds_values,
            recent.gui_seconds_format);

    fprintf(rf, "\n# Zoom level.\n");
    fprintf(rf, "# A decimal number.\n");
    fprintf(rf, RECENT_GUI_ZOOM_LEVEL ": %d\n",
            recent.gui_zoom_level);

    write_recent_enum(rf, "Bytes view display type",
            RECENT_GUI_BYTES_VIEW, bytes_view_type_values,
            recent.gui_bytes_view);

    write_recent_enum(rf, "Bytes view text encoding",
            RECENT_GUI_BYTES_ENCODING, bytes_encoding_type_values,
            recent.gui_bytes_encoding);

    write_recent_boolean(rf, "Packet diagram field values show (hide)",
            RECENT_GUI_PACKET_DIAGRAM_FIELD_VALUES,
            recent.gui_packet_diagram_field_values);

    write_recent_boolean(rf, "Allow hover selection in byte view",
            RECENT_GUI_ALLOW_HOVER_SELECTION,
            recent.gui_allow_hover_selection);

    write_recent_enum(rf, "Follow stream show as",
            RECENT_GUI_FOLLOW_SHOW, bytes_show_values,
            recent.gui_follow_show);

    write_recent_enum(rf, "Follow stream delta times",
                      RECENT_GUI_FOLLOW_DELTA, follow_delta_values,
                      recent.gui_follow_delta);

    write_recent_enum(rf, "Show packet bytes decode as",
            RECENT_GUI_SHOW_BYTES_DECODE, show_bytes_decode_values,
            recent.gui_show_bytes_decode);

    write_recent_enum(rf, "Show packet bytes show as",
            RECENT_GUI_SHOW_BYTES_SHOW, bytes_show_values,
            recent.gui_show_bytes_show);

    fprintf(rf, "\n# Main window upper (or leftmost) pane size.\n");
    fprintf(rf, "# Decimal number.\n");
    if (recent.gui_geometry_main_upper_pane != 0) {
        fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE ": %d\n",
                recent.gui_geometry_main_upper_pane);
    }
    fprintf(rf, "\n# Main window middle pane size.\n");
    fprintf(rf, "# Decimal number.\n");
    if (recent.gui_geometry_main_lower_pane != 0) {
        fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE ": %d\n",
                recent.gui_geometry_main_lower_pane);
    }

    if (recent.gui_geometry_main_master_split != NULL) {
        fprintf(rf, "\n# Main window master splitter state.\n");
        fprintf(rf, "# Hex byte string.\n");
        fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_MASTER_SPLIT ": %s\n",
                recent.gui_geometry_main_master_split);
    }

    if (recent.gui_geometry_main_extra_split != NULL) {
        fprintf(rf, "\n# Main window extra splitter state.\n");
        fprintf(rf, "# Hex byte string.\n");
        fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_EXTRA_SPLIT ": %s\n",
                recent.gui_geometry_main_extra_split);
    }

    window_splitter_recent_write_all(rf);

    fprintf(rf, "\n# Packet list column pixel widths.\n");
    fprintf(rf, "# Each pair of strings consists of a column format and its pixel width.\n");
    packet_list_recent_write_all(rf);

    fprintf(rf, "\n# Open conversation dialog tabs.\n");
    fprintf(rf, "# List of conversation names, e.g. \"TCP\", \"IPv6\".\n");
    string_list = join_string_list(recent.conversation_tabs);
    fprintf(rf, RECENT_GUI_CONVERSATION_TABS ": %s\n", string_list);
    g_free(string_list);

    fprintf(rf, "\n# Conversation dialog tabs columns.\n");
    fprintf(rf, "# List of conversation columns numbers.\n");
    string_list = join_string_list(recent.conversation_tabs_columns);
    fprintf(rf, RECENT_GUI_CONVERSATION_TABS_COLUMNS ": %s\n", string_list);
    g_free(string_list);

    fprintf(rf, "\n# Open endpoint dialog tabs.\n");
    fprintf(rf, "# List of endpoint names, e.g. \"TCP\", \"IPv6\".\n");
    string_list = join_string_list(recent.endpoint_tabs);
    fprintf(rf, RECENT_GUI_ENDPOINT_TABS ": %s\n", string_list);
    g_free(string_list);

    fprintf(rf, "\n# Endpoint dialog tabs columns.\n");
    fprintf(rf, "# List of endpoint columns numbers.\n");
    string_list = join_string_list(recent.endpoint_tabs_columns);
    fprintf(rf, RECENT_GUI_ENDPOINT_TABS_COLUMNS ": %s\n", string_list);
    g_free(string_list);

    write_recent_boolean(rf, "For RLC stats, whether to use RLC PDUs found inside MAC frames",
            RECENT_GUI_RLC_PDUS_FROM_MAC_FRAMES,
            recent.gui_rlc_use_pdus_from_mac);

    if (get_last_open_dir() != NULL) {
        fprintf(rf, "\n# Last directory navigated to in File Open dialog.\n");
        fprintf(rf, RECENT_GUI_FILEOPEN_REMEMBERED_DIR ": %s\n", get_last_open_dir());
    }

    fprintf(rf, "\n# Additional Toolbars shown\n");
    fprintf(rf, "# List of additional toolbars to show.\n");
    string_list = join_string_list(recent.gui_additional_toolbars);
    fprintf(rf, RECENT_GUI_TOOLBAR_SHOW ": %s\n", string_list);
    g_free(string_list);

    fprintf(rf, "\n# Interface Toolbars show.\n");
    fprintf(rf, "# List of interface toolbars to show.\n");
    string_list = join_string_list(recent.interface_toolbars);
    fprintf(rf, RECENT_GUI_INTERFACE_TOOLBAR_SHOW ": %s\n", string_list);
    g_free(string_list);

    fclose(rf);

    /* XXX - catch I/O errors (e.g. "ran out of disk space") and return
       an error indication, or maybe write to a new recent file and
       rename that file on top of the old one only if there are not I/O
       errors. */
    return true;
}

/* set one user's recent common file key/value pair */
static prefs_set_pref_e
read_set_recent_common_pair_static(char *key, const char *value,
                                   void *private_data _U_,
                                   bool return_range_errors _U_)
{
    long num;
    char *p;

    if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED) == 0) {
        parse_recent_boolean(value, &recent.gui_geometry_main_maximized);
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_LEFTALIGN_ACTIONS) == 0) {
        parse_recent_boolean(value, &recent.gui_geometry_leftalign_actions);
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_X) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        recent.gui_geometry_main_x = (int)num;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_Y) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        recent.gui_geometry_main_y = (int)num;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_WIDTH) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_main_width = (int)num;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_HEIGHT) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_main_height = (int)num;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN) == 0) {
        g_free(recent.gui_geometry_main);
        recent.gui_geometry_main = g_strdup(value);
    } else if (strcmp(key, RECENT_LAST_USED_PROFILE) == 0) {
        if ((strcmp(value, DEFAULT_PROFILE) != 0) && profile_exists (value, false)) {
            set_profile_name (value);
        }
    } else if (strcmp(key, RECENT_PROFILE_SWITCH_CHECK_COUNT) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_profile_switch_check_count = (int)num;
    } else if (strncmp(key, RECENT_GUI_GEOMETRY, sizeof(RECENT_GUI_GEOMETRY)-1) == 0) {
        /* now have something like "gui.geom.main.x", split it into win and sub_key */
        char *win = &key[sizeof(RECENT_GUI_GEOMETRY)-1];
        char *sub_key = strchr(win, '.');
        if (sub_key) {
            *sub_key = '\0';
            sub_key++;
            window_geom_recent_read_pair(win, sub_key, value);
        }
    } else if (strcmp(key, RECENT_KEY_PRIVS_WARN_IF_ELEVATED) == 0) {
        parse_recent_boolean(value, &recent.privs_warn_if_elevated);
    } else if (strcmp(key, RECENT_KEY_SYS_WARN_IF_NO_CAPTURE) == 0) {
        parse_recent_boolean(value, &recent.sys_warn_if_no_capture);
    } else if (strcmp(key, RECENT_GUI_SEARCH_IN) == 0) {
        recent.gui_search_in = (search_in_type)str_to_val(value, search_in_values, SEARCH_IN_PACKET_LIST);
    } else if (strcmp(key, RECENT_GUI_SEARCH_CHAR_SET) == 0) {
        recent.gui_search_char_set = (search_char_set_type)str_to_val(value, search_char_set_values, SEARCH_CHAR_SET_NARROW_AND_WIDE);
    } else if (strcmp(key, RECENT_GUI_SEARCH_CASE_SENSITIVE) == 0) {
        parse_recent_boolean(value, &recent.gui_search_case_sensitive);
    } else if (strcmp(key, RECENT_GUI_SEARCH_REVERSE_DIR) == 0) {
        parse_recent_boolean(value, &recent.gui_search_reverse_dir);
    } else if (strcmp(key, RECENT_GUI_SEARCH_MULTIPLE_OCCURS) == 0) {
        parse_recent_boolean(value, &recent.gui_search_multiple_occurs);
    } else if (strcmp(key, RECENT_GUI_SEARCH_TYPE) == 0) {
        recent.gui_search_type = (search_type_type)str_to_val(value, search_type_values, SEARCH_TYPE_DISPLAY_FILTER);
    } else if (strcmp(key, RECENT_GUI_CUSTOM_COLORS) == 0) {
        recent.custom_colors = prefs_get_string_list(value);
    }

    return PREFS_SET_OK;
}

/* set one user's recent file key/value pair */
static prefs_set_pref_e
read_set_recent_pair_static(char *key, const char *value,
                            void *private_data _U_,
                            bool return_range_errors _U_)
{
    long num;
    int32_t num_int32;
    char *p;
    GList *col_l, *col_l_elt;
    col_width_data *cfmt;

    if (strcmp(key, RECENT_KEY_MAIN_TOOLBAR_SHOW) == 0) {
        parse_recent_boolean(value, &recent.main_toolbar_show);
    } else if (strcmp(key, RECENT_KEY_FILTER_TOOLBAR_SHOW) == 0) {
        parse_recent_boolean(value, &recent.filter_toolbar_show);
        /* check both the old and the new keyword */
    } else if (strcmp(key, RECENT_KEY_WIRELESS_TOOLBAR_SHOW) == 0 || (strcmp(key, "gui.airpcap_toolbar_show") == 0)) {
        parse_recent_boolean(value, &recent.wireless_toolbar_show);
    } else if (strcmp(key, RECENT_KEY_PACKET_LIST_SHOW) == 0) {
        parse_recent_boolean(value, &recent.packet_list_show);
    } else if (strcmp(key, RECENT_KEY_TREE_VIEW_SHOW) == 0) {
        parse_recent_boolean(value, &recent.tree_view_show);
    } else if (strcmp(key, RECENT_KEY_BYTE_VIEW_SHOW) == 0) {
        parse_recent_boolean(value, &recent.byte_view_show);
    } else if (strcmp(key, RECENT_KEY_PACKET_DIAGRAM_SHOW) == 0) {
        parse_recent_boolean(value, &recent.packet_diagram_show);
    } else if (strcmp(key, RECENT_KEY_STATUSBAR_SHOW) == 0) {
        parse_recent_boolean(value, &recent.statusbar_show);
    } else if (strcmp(key, RECENT_KEY_PACKET_LIST_COLORIZE) == 0) {
        parse_recent_boolean(value, &recent.packet_list_colorize);
    } else if (strcmp(key, RECENT_KEY_CAPTURE_AUTO_SCROLL) == 0) {
        parse_recent_boolean(value, &recent.capture_auto_scroll);
    } else if (strcmp(key, RECENT_GUI_TIME_FORMAT) == 0) {
        recent.gui_time_format = (ts_type)str_to_val(value, ts_type_values,
            is_packet_configuration_namespace() ? TS_RELATIVE : TS_ABSOLUTE);
    } else if (strcmp(key, RECENT_GUI_TIME_PRECISION) == 0) {
        /*
         * The value of this item is either TS_PREC_AUTO, which is a
         * negative number meaning "pick the display precision based
         * on the time stamp precision of the packet", or is a numerical
         * value giving the number of decimal places to display, from 0
         * to WS_TSPREC_MAX.
         *
         * It used to be that not all values between 0 and 9 (the maximum
         * precision back then) were supported, and that names were
         * written out to the recent file.
         *
         * If the string value is a valid number in that range, use
         * that number, otherwise look it up in the table of names,
         * and, if that fails, set it to TS_PREC_AUTO.
         */
        if (ws_strtoi32(value, NULL, &num_int32) && num_int32 >= 0 &&
            num_int32 <= WS_TSPREC_MAX) {
            recent.gui_time_precision = num_int32;
        } else {
            recent.gui_time_precision =
                (ts_precision)str_to_val(value, ts_precision_values, TS_PREC_AUTO);
        }
    } else if (strcmp(key, RECENT_GUI_SECONDS_FORMAT) == 0) {
        recent.gui_seconds_format =
            (ts_seconds_type)str_to_val(value, ts_seconds_values, TS_SECONDS_DEFAULT);
    } else if (strcmp(key, RECENT_GUI_ZOOM_LEVEL) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        recent.gui_zoom_level = (int)num;
    } else if (strcmp(key, RECENT_GUI_BYTES_VIEW) == 0) {
        recent.gui_bytes_view =
            (bytes_view_type)str_to_val(value, bytes_view_type_values, BYTES_HEX);
    } else if (strcmp(key, RECENT_GUI_BYTES_ENCODING) == 0) {
        recent.gui_bytes_encoding =
            (bytes_encoding_type)str_to_val(value, bytes_encoding_type_values, BYTES_ENC_FROM_PACKET);
    } else if (strcmp(key, RECENT_GUI_PACKET_DIAGRAM_FIELD_VALUES) == 0) {
        parse_recent_boolean(value, &recent.gui_packet_diagram_field_values);
    } else if (strcmp(key, RECENT_GUI_ALLOW_HOVER_SELECTION) == 0) {
        parse_recent_boolean(value, &recent.gui_allow_hover_selection);
    } else if (strcmp(key, RECENT_GUI_FOLLOW_SHOW) == 0) {
        recent.gui_follow_show = (bytes_show_type)str_to_val(value, bytes_show_values, SHOW_ASCII);
    } else if (strcmp(key, RECENT_GUI_FOLLOW_DELTA) == 0) {
        recent.gui_follow_delta = (follow_delta_type)str_to_val(value, follow_delta_values, FOLLOW_DELTA_NONE);
    } else if (strcmp(key, RECENT_GUI_SHOW_BYTES_DECODE) == 0) {
        recent.gui_show_bytes_decode = (bytes_decode_type)str_to_val(value, show_bytes_decode_values, DecodeAsNone);
    } else if (strcmp(key, RECENT_GUI_SHOW_BYTES_SHOW) == 0) {
        recent.gui_show_bytes_show = (bytes_show_type)str_to_val(value, bytes_show_values, SHOW_ASCII);
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_main_upper_pane = (int)num;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_main_lower_pane = (int)num;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_MASTER_SPLIT) == 0) {
        g_free(recent.gui_geometry_main_master_split);
        recent.gui_geometry_main_master_split = g_strdup(value);
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_EXTRA_SPLIT) == 0) {
        g_free(recent.gui_geometry_main_extra_split);
        recent.gui_geometry_main_extra_split = g_strdup(value);
    } else if (strncmp(key, RECENT_GUI_GEOMETRY, sizeof(RECENT_GUI_GEOMETRY)-1) == 0) {
        /* now have something like "gui.geom.win.sub_key", split it into win and sub_key */
        char *win = &key[sizeof(RECENT_GUI_GEOMETRY)-1];
        char *sub_key = strchr(win, '.');
        if (sub_key) {
            *sub_key = '\0';
            sub_key++;
            window_geom_recent_read_pair(win, sub_key, value);
        }
    } else if (strcmp(key, RECENT_GUI_CONVERSATION_TABS) == 0) {
        g_list_free_full(recent.conversation_tabs, g_free);
        recent.conversation_tabs = prefs_get_string_list(value);
    } else if (strcmp(key, RECENT_GUI_CONVERSATION_TABS_COLUMNS) == 0) {
        g_list_free_full(recent.conversation_tabs_columns, g_free);
        recent.conversation_tabs_columns = prefs_get_string_list(value);
    } else if (strcmp(key, RECENT_GUI_ENDPOINT_TABS) == 0) {
        g_list_free_full(recent.endpoint_tabs, g_free);
        recent.endpoint_tabs = prefs_get_string_list(value);
    } else if (strcmp(key, RECENT_GUI_ENDPOINT_TABS_COLUMNS) == 0) {
        g_list_free_full(recent.endpoint_tabs_columns, g_free);
        recent.endpoint_tabs_columns = prefs_get_string_list(value);
    } else if (strcmp(key, RECENT_GUI_RLC_PDUS_FROM_MAC_FRAMES) == 0) {
        parse_recent_boolean(value, &recent.gui_rlc_use_pdus_from_mac);
    } else if (strcmp(key, RECENT_KEY_COL_WIDTH) == 0) {
        col_l = prefs_get_string_list(value);
        if (col_l == NULL)
            return PREFS_SET_SYNTAX_ERR;
        if ((g_list_length(col_l) % 2) != 0) {
            /* A title didn't have a matching width.  */
            prefs_clear_string_list(col_l);
            return PREFS_SET_SYNTAX_ERR;
        }
        recent_free_column_width_info(&recent);
        recent.col_width_list = NULL;
        col_l_elt = g_list_first(col_l);
        while (col_l_elt) {
            cfmt = g_new(col_width_data, 1);
            /* Skip the column format, we don't use it anymore because the
             * column indices are in sync and the key since 4.4. Format is
             * still written for backwards compatibility.
             */
            col_l_elt      = col_l_elt->next;
            cfmt->width    = (int)strtol((const char *)col_l_elt->data, &p, 0);
            if (p == col_l_elt->data || (*p != '\0' && *p != ':')) {
                g_free(cfmt);
                return PREFS_SET_SYNTAX_ERR;    /* number was bad */
            }

            if (*p == ':') {
                cfmt->xalign = *(++p);
            } else {
                cfmt->xalign = COLUMN_XALIGN_DEFAULT;
            }

            col_l_elt      = col_l_elt->next;
            recent.col_width_list = g_list_append(recent.col_width_list, cfmt);
        }
        prefs_clear_string_list(col_l);
    } else if (strcmp(key, RECENT_GUI_FILEOPEN_REMEMBERED_DIR) == 0) {
        g_free(recent.gui_fileopen_remembered_dir);
        recent.gui_fileopen_remembered_dir = g_strdup(value);
    } else if (strcmp(key, RECENT_GUI_TOOLBAR_SHOW) == 0) {
        recent.gui_additional_toolbars = prefs_get_string_list(value);
    } else if (strcmp(key, RECENT_GUI_INTERFACE_TOOLBAR_SHOW) == 0) {
        recent.interface_toolbars = prefs_get_string_list(value);
    } else {
        return PREFS_SET_NO_SUCH_PREF;
    }

    return PREFS_SET_OK;
}


/* set one user's recent file key/value pair */
static prefs_set_pref_e
read_set_recent_pair_dynamic(char *key, const char *value,
                             void *private_data _U_,
                             bool return_range_errors _U_)
{
    if (!g_utf8_validate(value, -1, NULL)) {
        return PREFS_SET_SYNTAX_ERR;
    }
    if (strcmp(key, RECENT_KEY_CAPTURE_FILE) == 0) {
        add_menu_recent_capture_file(value, true);
    } else if (strcmp(key, RECENT_KEY_DISPLAY_FILTER) == 0) {
        dfilter_combo_add_recent(value);
    } else if (strcmp(key, RECENT_KEY_CAPTURE_FILTER) == 0) {
        recent_add_cfilter(NULL, value);
    } else if (g_str_has_prefix(key, RECENT_KEY_CAPTURE_FILTER ".")) {
        /* strrchr() can't fail - string has a prefix that ends with a "." */
        recent_add_cfilter(strrchr(key, '.') + 1, value);
#ifdef HAVE_PCAP_REMOTE
    } else if (strcmp(key, RECENT_KEY_REMOTE_HOST) == 0) {
        capture_remote_combo_add_recent(value);
#endif
    }

    return PREFS_SET_OK;
}


/*
 * Given a string of the form "<recent name>:<recent value>", as might appear
 * as an argument to a "-o" option, parse it and set the recent value in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
int
recent_set_arg(char *prefarg)
{
    char *p, *colonp;
    int ret;

    colonp = strchr(prefarg, ':');
    if (colonp == NULL)
        return PREFS_SET_SYNTAX_ERR;

    p = colonp;
    *p++ = '\0';

    /*
     * Skip over any white space (there probably won't be any, but
     * as we allow it in the preferences file, we might as well
     * allow it here).
     */
    while (g_ascii_isspace(*p))
        p++;
    if (*p == '\0') {
        /*
         * Put the colon back, so if our caller uses, in an
         * error message, the string they passed us, the message
         * looks correct.
         */
        *colonp = ':';
        return PREFS_SET_SYNTAX_ERR;
    }

    ret = read_set_recent_pair_static(prefarg, p, NULL, true);
    *colonp = ':';     /* put the colon back */
    return ret;
}


/* opens the user's recent common file and read the first part */
bool
recent_read_static(char **rf_path_return, int *rf_errno_return)
{
    char       *rf_path;
    FILE       *rf;

    /* set defaults */
    recent.gui_geometry_main_x        =        20;
    recent.gui_geometry_main_y        =        20;
    recent.gui_geometry_main_width    = DEF_WIDTH;
    recent.gui_geometry_main_height   = DEF_HEIGHT;
    recent.gui_geometry_main_maximized=     false;

    recent.gui_geometry_leftalign_actions = false;

    recent.privs_warn_if_elevated = true;
    recent.sys_warn_if_no_capture = true;

    recent.col_width_list = NULL;
    recent.gui_geometry_main = NULL;
    recent.gui_geometry_main_master_split = NULL;
    recent.gui_geometry_main_extra_split = NULL;
    recent.gui_profile_switch_check_count = 1000;
    recent.gui_fileopen_remembered_dir = NULL;

    /* Construct the pathname of the user's recent common file. */
    rf_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, false);

    /* Read the user's recent common file, if it exists. */
    *rf_path_return = NULL;
    if ((rf = ws_fopen(rf_path, "r")) != NULL) {
        /* We succeeded in opening it; read it. */
        read_prefs_file(rf_path, rf, read_set_recent_common_pair_static, NULL);

        fclose(rf);
    } else {
        /* We failed to open it.  If we failed for some reason other than
           "it doesn't exist", return the errno and the pathname, so our
           caller can report the error. */
        if (errno != ENOENT) {
            *rf_errno_return = errno;
            *rf_path_return = rf_path;
            return false;
        }
    }
    g_free(rf_path);
    return true;
}



/* opens the user's recent file and read the first part */
bool
recent_read_profile_static(char **rf_path_return, int *rf_errno_return)
{
    char       *rf_path, *rf_common_path;
    FILE       *rf;

    /* set defaults */
    recent.main_toolbar_show         = true;
    recent.filter_toolbar_show       = true;
    recent.wireless_toolbar_show     = false;
    recent.packet_list_show          = true;
    recent.tree_view_show            = true;
    recent.byte_view_show            = true;
    recent.packet_diagram_show       = true;
    recent.statusbar_show            = true;
    recent.packet_list_colorize      = true;
    recent.capture_auto_scroll       = true;
    recent.gui_time_format           = TS_RELATIVE;
    recent.gui_time_precision        = TS_PREC_AUTO;
    recent.gui_seconds_format        = TS_SECONDS_DEFAULT;
    recent.gui_zoom_level            = 0;
    recent.gui_bytes_view            = BYTES_HEX;
    recent.gui_bytes_encoding        = BYTES_ENC_FROM_PACKET;
    recent.gui_allow_hover_selection = true;
    recent.gui_follow_show           = SHOW_ASCII;
    recent.gui_follow_delta          = FOLLOW_DELTA_NONE;
    recent.gui_show_bytes_decode     = DecodeAsNone;
    recent.gui_show_bytes_show       = SHOW_ASCII;

    /* pane size of zero will autodetect */
    recent.gui_geometry_main_upper_pane   = 0;
    recent.gui_geometry_main_lower_pane   = 0;

    if (recent.gui_geometry_main) {
        g_free(recent.gui_geometry_main);
        recent.gui_geometry_main = NULL;
    }

    if (recent.gui_geometry_main_master_split) {
        g_free(recent.gui_geometry_main_master_split);
        recent.gui_geometry_main_master_split = NULL;
    }
    if (recent.gui_geometry_main_extra_split) {
        g_free(recent.gui_geometry_main_extra_split);
        recent.gui_geometry_main_extra_split = NULL;
    }

    if (recent.col_width_list) {
        recent_free_column_width_info(&recent);
    }

    if (recent.gui_fileopen_remembered_dir) {
        g_free (recent.gui_fileopen_remembered_dir);
        recent.gui_fileopen_remembered_dir = NULL;
    }

    if (recent.gui_additional_toolbars) {
        g_list_free_full (recent.gui_additional_toolbars, g_free);
        recent.gui_additional_toolbars = NULL;
    }

    if (recent.interface_toolbars) {
        g_list_free_full (recent.interface_toolbars, g_free);
        recent.interface_toolbars = NULL;
    }

    /* Construct the pathname of the user's profile recent file. */
    rf_path = get_persconffile_path(RECENT_FILE_NAME, true);

    /* Read the user's recent file, if it exists. */
    *rf_path_return = NULL;
    if ((rf = ws_fopen(rf_path, "r")) != NULL) {
        /* We succeeded in opening it; read it. */
        read_prefs_file(rf_path, rf, read_set_recent_pair_static, NULL);
        fclose(rf);

        /* XXX: The following code doesn't actually do anything since
         *  the "recent common file" always exists. Presumably the
         *  "if (!file_exists())" should actually be "if (file_exists())".
         *  However, I've left the code as is because this
         *  behaviour has existed for quite some time and I don't
         *  know what's supposed to happen at this point.
         *  ToDo: Determine if the "recent common file" should be read at this point
         */
        rf_common_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, false);
        if (!file_exists(rf_common_path)) {
            /* Read older common settings from recent file */
            rf = ws_fopen(rf_path, "r");
            read_prefs_file(rf_path, rf, read_set_recent_common_pair_static, NULL);
            fclose(rf);
        }
        g_free(rf_common_path);
    } else {
        /* We failed to open it.  If we failed for some reason other than
           "it doesn't exist", return the errno and the pathname, so our
           caller can report the error. */
        if (errno != ENOENT) {
            *rf_errno_return = errno;
            *rf_path_return = rf_path;
            return false;
        }
    }
    g_free(rf_path);
    return true;
}

/* opens the user's recent file and read it out */
bool
recent_read_dynamic(char **rf_path_return, int *rf_errno_return)
{
    char       *rf_path;
    FILE       *rf;


    /* Construct the pathname of the user's recent common file. */
    rf_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, false);
    if (!file_exists (rf_path)) {
        /* Recent common file does not exist, read from default recent */
        g_free (rf_path);
        rf_path = get_persconffile_path(RECENT_FILE_NAME, false);
    }

    /* Read the user's recent file, if it exists. */
    *rf_path_return = NULL;
    if ((rf = ws_fopen(rf_path, "r")) != NULL) {
        /* We succeeded in opening it; read it. */
        read_prefs_file(rf_path, rf, read_set_recent_pair_dynamic, NULL);
#if 0
        /* set dfilter combobox to have an empty line */
        dfilter_combo_add_empty();
#endif
        /* We prepend new capture filters, so reverse them after adding
         * all to keep the latest first.
         */
        cfilter_recent_reverse_all();
#ifdef HAVE_PCAP_REMOTE
        remote_host_reverse();
#endif
        fclose(rf);
    } else {
        /* We failed to open it.  If we failed for some reason other than
           "it doesn't exist", return the errno and the pathname, so our
           caller can report the error. */
        if (errno != ENOENT) {
            *rf_errno_return = errno;
            *rf_path_return = rf_path;
            return false;
        }
    }
    g_free(rf_path);
    return true;
}

void
recent_insert_column(int col)
{
    col_width_data *col_w;

    col_w = g_new(col_width_data, 1);
    col_w->width = -1;
    col_w->xalign = COLUMN_XALIGN_DEFAULT;
    recent.col_width_list = g_list_insert(recent.col_width_list, col_w, col);
}

void
recent_remove_column(int col)
{
    GList *col_l = g_list_nth(recent.col_width_list, col);
    col_width_data *col_w;

    if (!col_l) return;

    col_w = (col_width_data*)col_l->data;

    if (col_w) {
        free_col_width_data(col_w);
    }

    recent.col_width_list = g_list_delete_link(recent.col_width_list, col_l);
}

int
recent_get_column_width(int col)
{
    col_width_data *col_w;

    col_w = g_list_nth_data(recent.col_width_list, col);
    if (col_w) {
        return col_w->width;
    } else {
        /* Make sure the recent column list isn't out of sync with the
         * number of columns (e.g., for a brand new profile.)
         */
        for (unsigned colnr = g_list_length(recent.col_width_list); colnr < g_list_length(prefs.col_list); colnr++) {
            recent_insert_column(colnr);
        }
    }

    return -1;
}

void
recent_set_column_width(int col, int width)
{
    col_width_data *col_w;

    col_w = g_list_nth_data(recent.col_width_list, col);
    if (col_w) {
        col_w->width = width;
    } else {
        /* Make sure the recent column list isn't out of sync with the
         * number of columns (e.g., for a brand new profile.)
         */
        for (unsigned colnr = g_list_length(recent.col_width_list); colnr < g_list_length(prefs.col_list); colnr++) {
            recent_insert_column(colnr);
        }
        col_w = g_list_nth_data(recent.col_width_list, col);
        if (col_w) {
            col_w->width = width;
        }
    }
}

char
recent_get_column_xalign(int col)
{
    col_width_data *col_w;

    col_w = g_list_nth_data(recent.col_width_list, col);
    if (col_w) {
        return col_w->xalign;
    } else {
        /* Make sure the recent column list isn't out of sync with the
         * number of columns (e.g., for a brand new profile.)
         */
        for (unsigned colnr = g_list_length(recent.col_width_list); colnr < g_list_length(prefs.col_list); colnr++) {
            recent_insert_column(colnr);
        }
    }

    return COLUMN_XALIGN_DEFAULT;
}

void
recent_set_column_xalign(int col, char xalign)
{
    col_width_data *col_w;

    col_w = g_list_nth_data(recent.col_width_list, col);
    if (col_w) {
        col_w->xalign = xalign;
    } else {
        /* Make sure the recent column list isn't out of sync with the
         * number of columns (e.g., for a brand new profile.)
         */
        for (unsigned colnr = g_list_length(recent.col_width_list); colnr < g_list_length(prefs.col_list); colnr++) {
            recent_insert_column(colnr);
        }
        col_w = g_list_nth_data(recent.col_width_list, col);
        if (col_w) {
            col_w->xalign = xalign;
        }
    }
}

void
recent_init(void)
{
    memset(&recent, 0, sizeof(recent_settings_t));
}

void
recent_cleanup(void)
{
    recent_free_column_width_info(&recent);
    g_free(recent.gui_geometry_main);
    g_free(recent.gui_geometry_main_master_split);
    g_free(recent.gui_geometry_main_extra_split);
    g_free(recent.gui_fileopen_remembered_dir);
    g_list_free_full(recent.gui_additional_toolbars, g_free);
    g_list_free_full(recent.interface_toolbars, g_free);
    prefs_clear_string_list(recent.conversation_tabs);
    prefs_clear_string_list(recent.conversation_tabs_columns);
    prefs_clear_string_list(recent.endpoint_tabs);
    prefs_clear_string_list(recent.endpoint_tabs_columns);
    prefs_clear_string_list(recent.custom_colors);
}
