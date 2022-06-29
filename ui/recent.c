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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "capture_opts.h"
#include <wsutil/filesystem.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/column.h>
#include <epan/value_string.h>

#include "ui/last_open_dir.h"
#include "ui/recent.h"
#include "ui/recent_utils.h"
#include "ui/packet_list_utils.h"
#include "ui/simple_dialog.h"

#include <wsutil/file_util.h>

#define RECENT_KEY_MAIN_TOOLBAR_SHOW            "gui.toolbar_main_show"
#define RECENT_KEY_FILTER_TOOLBAR_SHOW          "gui.filter_toolbar_show"
#define RECENT_KEY_WIRELESS_TOOLBAR_SHOW        "gui.wireless_toolbar_show"
#define RECENT_KEY_PACKET_LIST_SHOW             "gui.packet_list_show"
#define RECENT_KEY_TREE_VIEW_SHOW               "gui.tree_view_show"
#define RECENT_KEY_BYTE_VIEW_SHOW               "gui.byte_view_show"
#define RECENT_KEY_PACKET_DIAGRAM_SHOW          "gui.packet_diagram_show"
#define RECENT_KEY_STATUSBAR_SHOW               "gui.statusbar_show"
#define RECENT_KEY_PACKET_LIST_COLORIZE         "gui.packet_list_colorize"
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
#define RECENT_GUI_GEOMETRY_LEFTALIGN_ACTIONS   "gui.geometry_leftalign_actions"
#define RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE     "gui.geometry_main_upper_pane"
#define RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE     "gui.geometry_main_lower_pane"
#define RECENT_GUI_GEOMETRY_STATUS_PANE_LEFT    "gui.geometry_status_pane"
#define RECENT_GUI_GEOMETRY_STATUS_PANE_RIGHT   "gui.geometry_status_pane_right"
#define RECENT_GUI_GEOMETRY_WLAN_STATS_PANE     "gui.geometry_status_wlan_stats_pane"
#define RECENT_LAST_USED_PROFILE                "gui.last_used_profile"
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
#define RECENT_GUI_SEARCH_TYPE                  "gui.search_type"

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
    { TS_ABSOLUTE_WITH_YMD,    "ABSOLUTE_WITH_DATE" },  /* Backward compability */
    { TS_DELTA,                "DELTA"              },
    { TS_DELTA_DIS,            "DELTA_DIS"          },
    { TS_EPOCH,                "EPOCH"              },
    { TS_UTC,                  "UTC"                },
    { TS_UTC_WITH_YMD,         "UTC_WITH_YMD"       },
    { TS_UTC_WITH_YDOY,        "UTC_WITH_YDOY"      },
    { TS_UTC_WITH_YMD,         "UTC_WITH_DATE"      },  /* Backward compability */
    { 0, NULL }
};

static const value_string ts_precision_values[] = {
    { TS_PREC_AUTO,            "AUTO" },
    { TS_PREC_FIXED_SEC,       "SEC"  },
    { TS_PREC_FIXED_DSEC,      "DSEC" },
    { TS_PREC_FIXED_CSEC,      "CSEC" },
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

static void
free_col_width_data(gpointer data, gpointer user_data _U_)
{
    col_width_data *cfmt = (col_width_data *)data;
    g_free(cfmt->cfield);
    g_free(cfmt);
}

static void
free_col_width_info(recent_settings_t *rs)
{
    g_list_foreach(rs->col_width_list, free_col_width_data, NULL);
    g_list_free(rs->col_width_list);
    rs->col_width_list = NULL;
}

/** Write the geometry values of a single window to the recent file.
 *
 * @param key unused
 * @param value the geometry values
 * @param rfh recent file handle (FILE)
 */
static void
write_recent_geom(gpointer key _U_, gpointer value, gpointer rfh)
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

    fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.maximized: %s\n", geom->key,
            geom->maximized == TRUE ? "TRUE" : "FALSE");

}

/* the geometry hashtable for all known window classes,
 * the window name is the key, and the geometry struct is the value */
static GHashTable *window_geom_hash = NULL;

/* save the window and its current geometry into the geometry hashtable */
void
window_geom_save(const gchar *name, window_geometry_t *geom)
{
    gchar *key;
    window_geometry_t *work;

    /* init hashtable, if not already done */
    if (!window_geom_hash) {
        window_geom_hash = g_hash_table_new(g_str_hash, g_str_equal);
    }
    /* if we have an old one, remove and free it first */
    work = (window_geometry_t *)g_hash_table_lookup(window_geom_hash, name);
    if (work) {
        g_hash_table_remove(window_geom_hash, name);
        g_free(work->key);
        g_free(work);
    }

    /* g_malloc and insert the new one */
    work = g_new(window_geometry_t, 1);
    *work = *geom;
    key = g_strdup(name);
    work->key = key;
    g_hash_table_insert(window_geom_hash, key, work);
}

/* load the desired geometry for this window from the geometry hashtable */
gboolean
window_geom_load(const gchar       *name,
                 window_geometry_t *geom)
{
    window_geometry_t *p;

    /* init hashtable, if not already done */
    if (!window_geom_hash) {
        window_geom_hash = g_hash_table_new(g_str_hash, g_str_equal);
    }

    p = (window_geometry_t *)g_hash_table_lookup(window_geom_hash, name);
    if (p) {
        *geom = *p;
        return TRUE;
    } else {
        return FALSE;
    }
}

/* parse values of particular types */
static void
parse_recent_boolean(const gchar *val_str, gboolean *valuep)
{
    if (g_ascii_strcasecmp(val_str, "true") == 0) {
        *valuep = TRUE;
    }
    else {
        *valuep = FALSE;
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

    /* find window geometry maybe already in hashtable */
    if (!window_geom_load(name, &geom)) {
        /* not in table, init geom with "basic" values */
        geom.key        = NULL;    /* Will be set in window_geom_save() */
        geom.set_pos    = FALSE;
        geom.x          = -1;
        geom.y          = -1;
        geom.set_size   = FALSE;
        geom.width      = -1;
        geom.height     = -1;
    }

    if (strcmp(key, "x") == 0) {
        geom.x = (gint)strtol(value, NULL, 10);
        geom.set_pos = TRUE;
    } else if (strcmp(key, "y") == 0) {
        geom.y = (gint)strtol(value, NULL, 10);
        geom.set_pos = TRUE;
    } else if (strcmp(key, "width") == 0) {
        geom.width = (gint)strtol(value, NULL, 10);
        geom.set_size = TRUE;
    } else if (strcmp(key, "height") == 0) {
        geom.height = (gint)strtol(value, NULL, 10);
        geom.set_size = TRUE;
    } else if (strcmp(key, "maximized") == 0) {
        parse_recent_boolean(value, &geom.maximized);
        geom.set_maximized = TRUE;
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
        window_geom_hash = g_hash_table_new(g_str_hash, g_str_equal);
    }

    g_hash_table_foreach(window_geom_hash, write_recent_geom, rf);
}

/* Global list of recent capture filters. */
static GList *recent_cfilter_list;

/*
 * Per-interface lists of recent capture filters; stored in a hash
 * table indexed by interface name.
 */
static GHashTable *per_interface_cfilter_lists_hash;

/* XXX: use a preference for this setting! */
static guint cfilter_combo_max_recent = 20;

/**
 * Returns a list of recent capture filters.
 *
 * @param ifname interface name; NULL refers to the global list.
 */
GList *
recent_get_cfilter_list(const gchar *ifname)
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
recent_add_cfilter(const gchar *ifname, const gchar *s)
{
    GList     *cfilter_list;
    GList     *li;
    gchar     *li_filter, *newfilter = NULL;

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
    cfilter_list = g_list_append(cfilter_list, newfilter);

    if (ifname == NULL)
        recent_cfilter_list = cfilter_list;
    else
        g_hash_table_insert(per_interface_cfilter_lists_hash, g_strdup(ifname), cfilter_list);
}

#ifdef HAVE_PCAP_REMOTE
static GHashTable *remote_host_list=NULL;

int recent_get_remote_host_list_size(void)
{
    if (remote_host_list == NULL) {
        /* No entries exist. */
        return 0;
    }
    return g_hash_table_size (remote_host_list);
}

void recent_add_remote_host(gchar *host, struct remote_host *rh)
{
    if (remote_host_list == NULL) {
        remote_host_list = g_hash_table_new (g_str_hash, g_str_equal);
    }
    g_hash_table_insert (remote_host_list, g_strdup(host), rh);
}

static gboolean
free_remote_host (gpointer key _U_, gpointer value, gpointer user _U_)
{
    struct remote_host *rh = (struct remote_host *) value;

    g_free (rh->r_host);
    g_free (rh->remote_port);
    g_free (rh->auth_username);
    g_free (rh->auth_password);

    return TRUE;
}

void
recent_remote_host_list_foreach(GHFunc func, gpointer user_data)
{
    if (remote_host_list != NULL) {
        g_hash_table_foreach(remote_host_list, func, user_data);
    }
}

static void
recent_print_remote_host (gpointer key _U_, gpointer value, gpointer user)
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
    if (remote_host_list && g_hash_table_size (remote_host_list) > 0) {
        /* Write all remote interfaces to the recent file */
        g_hash_table_foreach (remote_host_list, recent_print_remote_host, rf);
    }
}


void recent_free_remote_host_list(void)
{
    g_hash_table_foreach_remove(remote_host_list, free_remote_host, NULL);
}

struct remote_host *
recent_get_remote_host(const gchar *host)
{
    if (host == NULL)
        return NULL;
    if (remote_host_list == NULL) {
        /* No such host exist. */
        return NULL;
    }
    return (struct remote_host *)g_hash_table_lookup(remote_host_list, host);
}

/**
 * Fill the remote_host_list with the entries stored in the 'recent' file.
 *
 * @param s String to be filled from the 'recent' file.
 * @return True, if the list was written successfully, False otherwise.
 */
static gboolean
capture_remote_combo_add_recent(const gchar *s)
{
    GList *vals = prefs_get_string_list (s);
    GList *valp = vals;
    capture_auth auth_type;
    char  *p;
    struct remote_host *rh;

    if (valp == NULL)
        return FALSE;

    if (remote_host_list == NULL) {
        remote_host_list = g_hash_table_new (g_str_hash, g_str_equal);
    }

    rh =(struct remote_host *) g_malloc (sizeof (*rh));

    /* First value is the host */
    rh->r_host = (gchar *)g_strdup ((const gchar *)valp->data);
    if (strlen(rh->r_host) == 0) {
        /* Empty remote host */
        g_free(rh->r_host);
        g_free(rh);
        return FALSE;
    }
    rh->auth_type = CAPTURE_AUTH_NULL;
    valp = valp->next;

    if (valp) {
        /* Found value 2, this is the port number */
        if (!strcmp((const char*)valp->data, "0")) {
            /* Port 0 isn't valid, so leave port blank */
            rh->remote_port = (gchar *)g_strdup ("");
        } else {
            rh->remote_port = (gchar *)g_strdup ((const gchar *)valp->data);
        }
        valp = valp->next;
    } else {
        /* Did not find a port number */
        rh->remote_port = g_strdup ("");
    }

    if (valp) {
        /* Found value 3, this is the authentication type */
        auth_type = (capture_auth)strtol((const gchar *)valp->data, &p, 0);
        if (p != valp->data && *p == '\0') {
            rh->auth_type = auth_type;
        }
    }

    /* Do not store username and password */
    rh->auth_username = g_strdup ("");
    rh->auth_password = g_strdup ("");

    prefs_clear_string_list(vals);

    g_hash_table_insert (remote_host_list, g_strdup(rh->r_host), rh);

    return TRUE;
}
#endif

static void
cfilter_recent_write_all_list(FILE *rf, const gchar *ifname, GList *cfilter_list)
{
    guint      max_count = 0;
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
cfilter_recent_write_all_hash_callback(gpointer key, gpointer value, gpointer user_data)
{
    cfilter_recent_write_all_list((FILE *)user_data, (const gchar *)key, (GList *)value);
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
        g_hash_table_foreach(per_interface_cfilter_lists_hash, cfilter_recent_write_all_hash_callback, (gpointer)rf);
    }
}

/* Write out recent settings of particular types. */
static void
write_recent_boolean(FILE *rf, const char *description, const char *name,
                     gboolean value)
{
    fprintf(rf, "\n# %s.\n", description);
    fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
    fprintf(rf, "%s: %s\n", name, value == TRUE ? "TRUE" : "FALSE");
}

static void
write_recent_enum(FILE *rf, const char *description, const char *name,
                  const value_string *values, guint value)
{
    const char *if_invalid = NULL;
    const value_string *valp;
    const gchar *str_value;

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
   If we got an error report it with a dialog box and return FALSE,
   otherwise return TRUE. */
gboolean
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
        return FALSE;
    }

    rf_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, FALSE);
    if ((rf = ws_fopen(rf_path, "w")) == NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Can't open recent file\n\"%s\": %s.", rf_path,
                g_strerror(errno));
        g_free(rf_path);
        return FALSE;
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
            "######## Recent capture filters (latest last), cannot be altered through command line ########\n"
            "\n", rf);

    cfilter_recent_write_all(rf);

    fputs("\n"
            "######## Recent display filters (latest last), cannot be altered through command line ########\n"
            "\n", rf);

    dfilter_recent_combo_write_all(rf);

#ifdef HAVE_PCAP_REMOTE
    fputs("\n"
            "######## Recent remote hosts, cannot be altered through command line ########\n"
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

    write_recent_boolean(rf, "Leftalign Action Buttons",
            RECENT_GUI_GEOMETRY_LEFTALIGN_ACTIONS,
            recent.gui_geometry_leftalign_actions);

    fprintf(rf, "\n# Statusbar left pane size.\n");
    fprintf(rf, "# Decimal number.\n");
    if (recent.gui_geometry_status_pane_left != 0) {
        fprintf(rf, RECENT_GUI_GEOMETRY_STATUS_PANE_LEFT ": %d\n",
                recent.gui_geometry_status_pane_left);
    }
    fprintf(rf, "\n# Statusbar middle pane size.\n");
    fprintf(rf, "# Decimal number.\n");
    if (recent.gui_geometry_status_pane_right != 0) {
        fprintf(rf, RECENT_GUI_GEOMETRY_STATUS_PANE_RIGHT ": %d\n",
                recent.gui_geometry_status_pane_right);
    }

    fprintf(rf, "\n# Last used Configuration Profile.\n");
    fprintf(rf, RECENT_LAST_USED_PROFILE ": %s\n", get_profile_name());

    fprintf(rf, "\n# WLAN statistics upper pane size.\n");
    fprintf(rf, "# Decimal number.\n");
    fprintf(rf, RECENT_GUI_GEOMETRY_WLAN_STATS_PANE ": %d\n",
            recent.gui_geometry_wlan_stats_pane);

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
    return TRUE;
}


/* Attempt to Write out profile "recent" to the user's profile recent file.
   If we got an error report it with a dialog box and return FALSE,
   otherwise return TRUE. */
gboolean
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
        return FALSE;
    }

    rf_path = get_persconffile_path(RECENT_FILE_NAME, TRUE);
    if ((rf = ws_fopen(rf_path, "w")) == NULL) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Can't open recent file\n\"%s\": %s.", rf_path,
                g_strerror(errno));
        g_free(rf_path);
        return FALSE;
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

    write_recent_enum(rf, "Timestamp display format",
            RECENT_GUI_TIME_FORMAT, ts_type_values,
            recent.gui_time_format);

    write_recent_enum(rf, "Timestamp display precision",
            RECENT_GUI_TIME_PRECISION, ts_precision_values,
            recent.gui_time_precision);

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
    return TRUE;
}

/* set one user's recent common file key/value pair */
static prefs_set_pref_e
read_set_recent_common_pair_static(gchar *key, const gchar *value,
                                   void *private_data _U_,
                                   gboolean return_range_errors _U_)
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
        recent.gui_geometry_main_x = (gint)num;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_Y) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        recent.gui_geometry_main_y = (gint)num;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_WIDTH) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_main_width = (gint)num;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_HEIGHT) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_main_height = (gint)num;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_STATUS_PANE_RIGHT) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_status_pane_right = (gint)num;
        recent.has_gui_geometry_status_pane = TRUE;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_STATUS_PANE_LEFT) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_status_pane_left = (gint)num;
        recent.has_gui_geometry_status_pane = TRUE;
    } else if (strcmp(key, RECENT_LAST_USED_PROFILE) == 0) {
        if ((strcmp(value, DEFAULT_PROFILE) != 0) && profile_exists (value, FALSE)) {
            set_profile_name (value);
        }
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_WLAN_STATS_PANE) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_wlan_stats_pane = (gint)num;
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
    } else if (strcmp(key, RECENT_GUI_SEARCH_TYPE) == 0) {
        recent.gui_search_type = (search_type_type)str_to_val(value, search_type_values, SEARCH_TYPE_DISPLAY_FILTER);
    } else if (strcmp(key, RECENT_GUI_CUSTOM_COLORS) == 0) {
        recent.custom_colors = prefs_get_string_list(value);
    }

    return PREFS_SET_OK;
}

/* set one user's recent file key/value pair */
static prefs_set_pref_e
read_set_recent_pair_static(gchar *key, const gchar *value,
                            void *private_data _U_,
                            gboolean return_range_errors _U_)
{
    long num;
    char *p;
    GList *col_l, *col_l_elt;
    col_width_data *cfmt;
    const gchar *cust_format = col_format_to_string(COL_CUSTOM);
    int cust_format_len = (int) strlen(cust_format);

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
    } else if (strcmp(key, RECENT_GUI_TIME_FORMAT) == 0) {
        recent.gui_time_format =
            (ts_type)str_to_val(value, ts_type_values, TS_RELATIVE);
    } else if (strcmp(key, RECENT_GUI_TIME_PRECISION) == 0) {
        recent.gui_time_precision =
            (ts_precision)str_to_val(value, ts_precision_values, TS_PREC_AUTO);
    } else if (strcmp(key, RECENT_GUI_SECONDS_FORMAT) == 0) {
        recent.gui_seconds_format =
            (ts_seconds_type)str_to_val(value, ts_seconds_values, TS_SECONDS_DEFAULT);
    } else if (strcmp(key, RECENT_GUI_ZOOM_LEVEL) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        recent.gui_zoom_level = (gint)num;
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
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED) == 0) {
        parse_recent_boolean(value, &recent.gui_geometry_main_maximized);
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_main_upper_pane = (gint)num;
        recent.has_gui_geometry_main_upper_pane = TRUE;
    } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE) == 0) {
        num = strtol(value, &p, 0);
        if (p == value || *p != '\0')
            return PREFS_SET_SYNTAX_ERR;      /* number was bad */
        if (num <= 0)
            return PREFS_SET_SYNTAX_ERR;      /* number must be positive */
        recent.gui_geometry_main_lower_pane = (gint)num;
        recent.has_gui_geometry_main_lower_pane = TRUE;
    } else if (strcmp(key, RECENT_GUI_CONVERSATION_TABS) == 0) {
        recent.conversation_tabs = prefs_get_string_list(value);
    } else if (strcmp(key, RECENT_GUI_CONVERSATION_TABS_COLUMNS) == 0) {
        recent.conversation_tabs_columns = prefs_get_string_list(value);
    } else if (strcmp(key, RECENT_GUI_ENDPOINT_TABS) == 0) {
        recent.endpoint_tabs = prefs_get_string_list(value);
    } else if (strcmp(key, RECENT_GUI_ENDPOINT_TABS_COLUMNS) == 0) {
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
        /* Check to make sure all column formats are valid.  */
        col_l_elt = g_list_first(col_l);
        while (col_l_elt) {
            /* Make sure the format isn't empty.  */
            if (strcmp((const char *)col_l_elt->data, "") == 0) {
                /* It is.  */
                prefs_clear_string_list(col_l);
                return PREFS_SET_SYNTAX_ERR;
            }

            /* Check the format.  */
            if (strncmp((const char *)col_l_elt->data, cust_format, cust_format_len) != 0) {
                if (get_column_format_from_str((const gchar *)col_l_elt->data) == -1) {
                    /* It's not a valid column format.  */
                    prefs_clear_string_list(col_l);
                    return PREFS_SET_SYNTAX_ERR;
                }
            }

            /* Go past the format.  */
            col_l_elt = col_l_elt->next;

            /* Go past the width.  */
            col_l_elt = col_l_elt->next;
        }
        free_col_width_info(&recent);
        recent.col_width_list = NULL;
        col_l_elt = g_list_first(col_l);
        while (col_l_elt) {
            gchar *fmt = g_strdup((const gchar *)col_l_elt->data);
            cfmt = g_new(col_width_data, 1);
            if (strncmp(fmt, cust_format, cust_format_len) != 0) {
                cfmt->cfmt   = get_column_format_from_str(fmt);
                cfmt->cfield = NULL;
            } else {
                cfmt->cfmt   = COL_CUSTOM;
                cfmt->cfield = g_strdup(&fmt[cust_format_len+1]);  /* add 1 for ':' */
            }
            g_free (fmt);
            if (cfmt->cfmt == -1) {
                g_free(cfmt->cfield);
                g_free(cfmt);
                return PREFS_SET_SYNTAX_ERR;   /* string was bad */
            }

            col_l_elt      = col_l_elt->next;
            cfmt->width    = (gint)strtol((const char *)col_l_elt->data, &p, 0);
            if (p == col_l_elt->data || (*p != '\0' && *p != ':')) {
                g_free(cfmt->cfield);
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
    }

    return PREFS_SET_OK;
}


/* set one user's recent file key/value pair */
static prefs_set_pref_e
read_set_recent_pair_dynamic(gchar *key, const gchar *value,
                             void *private_data _U_,
                             gboolean return_range_errors _U_)
{
    if (!g_utf8_validate(value, -1, NULL)) {
        return PREFS_SET_SYNTAX_ERR;
    }
    if (strcmp(key, RECENT_KEY_CAPTURE_FILE) == 0) {
        add_menu_recent_capture_file(value);
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
    gchar *p, *colonp;
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

    ret = read_set_recent_pair_static(prefarg, p, NULL, TRUE);
    *colonp = ':';     /* put the colon back */
    return ret;
}


/* opens the user's recent common file and read the first part */
gboolean
recent_read_static(char **rf_path_return, int *rf_errno_return)
{
    char       *rf_path;
    FILE       *rf;

    /* set defaults */
    recent.gui_geometry_main_x        =        20;
    recent.gui_geometry_main_y        =        20;
    recent.gui_geometry_main_width    = DEF_WIDTH;
    recent.gui_geometry_main_height   = DEF_HEIGHT;
    recent.gui_geometry_main_maximized=     FALSE;

    recent.gui_geometry_leftalign_actions = FALSE;

    recent.gui_geometry_status_pane_left  = (DEF_WIDTH/3);
    recent.gui_geometry_status_pane_right = (DEF_WIDTH/3);
    recent.gui_geometry_wlan_stats_pane   = 200;

    recent.privs_warn_if_elevated = TRUE;
    recent.sys_warn_if_no_capture = TRUE;

    recent.col_width_list = NULL;
    recent.gui_fileopen_remembered_dir = NULL;

    /* Construct the pathname of the user's recent common file. */
    rf_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, FALSE);

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
            return FALSE;
        }
    }
    g_free(rf_path);
    return TRUE;
}



/* opens the user's recent file and read the first part */
gboolean
recent_read_profile_static(char **rf_path_return, int *rf_errno_return)
{
    char       *rf_path, *rf_common_path;
    FILE       *rf;

    /* set defaults */
    recent.main_toolbar_show         = TRUE;
    recent.filter_toolbar_show       = TRUE;
    recent.wireless_toolbar_show     = FALSE;
    recent.packet_list_show          = TRUE;
    recent.tree_view_show            = TRUE;
    recent.byte_view_show            = TRUE;
    recent.packet_diagram_show       = TRUE;
    recent.statusbar_show            = TRUE;
    recent.packet_list_colorize      = TRUE;
    recent.gui_time_format           = TS_RELATIVE;
    recent.gui_time_precision        = TS_PREC_AUTO;
    recent.gui_seconds_format        = TS_SECONDS_DEFAULT;
    recent.gui_zoom_level            = 0;
    recent.gui_bytes_view            = BYTES_HEX;
    recent.gui_bytes_encoding        = BYTES_ENC_FROM_PACKET;
    recent.gui_allow_hover_selection = TRUE;

    /* pane size of zero will autodetect */
    recent.gui_geometry_main_upper_pane   = 0;
    recent.gui_geometry_main_lower_pane   = 0;

    recent.has_gui_geometry_main_upper_pane = TRUE;
    recent.has_gui_geometry_main_lower_pane = TRUE;
    recent.has_gui_geometry_status_pane     = TRUE;

    if (recent.col_width_list) {
        free_col_width_info(&recent);
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
    rf_path = get_persconffile_path(RECENT_FILE_NAME, TRUE);

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
        rf_common_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, FALSE);
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
            return FALSE;
        }
    }
    g_free(rf_path);
    return TRUE;
}

/* opens the user's recent file and read it out */
gboolean
recent_read_dynamic(char **rf_path_return, int *rf_errno_return)
{
    char       *rf_path;
    FILE       *rf;


    /* Construct the pathname of the user's recent common file. */
    rf_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, FALSE);
    if (!file_exists (rf_path)) {
        /* Recent common file does not exist, read from default recent */
        g_free (rf_path);
        rf_path = get_persconffile_path(RECENT_FILE_NAME, FALSE);
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
        fclose(rf);
    } else {
        /* We failed to open it.  If we failed for some reason other than
           "it doesn't exist", return the errno and the pathname, so our
           caller can report the error. */
        if (errno != ENOENT) {
            *rf_errno_return = errno;
            *rf_path_return = rf_path;
            return FALSE;
        }
    }
    g_free(rf_path);
    return TRUE;
}

gint
recent_get_column_width(gint col)
{
    GList *col_l;
    col_width_data *col_w;
    gint cfmt;
    const gchar *cfield = NULL;

    cfmt = get_column_format(col);
    if (cfmt == COL_CUSTOM) {
        cfield = get_column_custom_fields(col);
    }

    col_l = g_list_first(recent.col_width_list);
    while (col_l) {
        col_w = (col_width_data *) col_l->data;
        if (col_w->cfmt == cfmt) {
            if (cfmt != COL_CUSTOM) {
                return col_w->width;
            } else if (cfield && strcmp (cfield, col_w->cfield) == 0) {
                return col_w->width;
            }
        }
        col_l = col_l->next;
    }

    return -1;
}

void
recent_set_column_width(gint col, gint width)
{
    GList *col_l;
    col_width_data *col_w;
    gint cfmt;
    const gchar *cfield = NULL;
    gboolean found = FALSE;

    cfmt = get_column_format(col);
    if (cfmt == COL_CUSTOM) {
        cfield = get_column_custom_fields(col);
    }

    col_l = g_list_first(recent.col_width_list);
    while (col_l) {
        col_w = (col_width_data *) col_l->data;
        if (col_w->cfmt == cfmt) {
            if (cfmt != COL_CUSTOM || strcmp (cfield, col_w->cfield) == 0) {
                col_w->width = width;
                found = TRUE;
                break;
            }
        }
        col_l = col_l->next;
    }

    if (!found) {
        col_w = g_new(col_width_data, 1);
        col_w->cfmt = cfmt;
        col_w->cfield = g_strdup(cfield);
        col_w->width = width;
        col_w->xalign = COLUMN_XALIGN_DEFAULT;
        recent.col_width_list = g_list_append(recent.col_width_list, col_w);
    }
}

gchar
recent_get_column_xalign(gint col)
{
    GList *col_l;
    col_width_data *col_w;
    gint cfmt;
    const gchar *cfield = NULL;

    cfmt = get_column_format(col);
    if (cfmt == COL_CUSTOM) {
        cfield = get_column_custom_fields(col);
    }

    col_l = g_list_first(recent.col_width_list);
    while (col_l) {
        col_w = (col_width_data *) col_l->data;
        if (col_w->cfmt == cfmt) {
            if (cfmt != COL_CUSTOM) {
                return col_w->xalign;
            } else if (cfield && strcmp (cfield, col_w->cfield) == 0) {
                return col_w->xalign;
            }
        }
        col_l = col_l->next;
    }

    return 0;
}

void
recent_set_column_xalign(gint col, gchar xalign)
{
    GList *col_l;
    col_width_data *col_w;
    gint cfmt;
    const gchar *cfield = NULL;
    gboolean found = FALSE;

    cfmt = get_column_format(col);
    if (cfmt == COL_CUSTOM) {
        cfield = get_column_custom_fields(col);
    }

    col_l = g_list_first(recent.col_width_list);
    while (col_l) {
        col_w = (col_width_data *) col_l->data;
        if (col_w->cfmt == cfmt) {
            if (cfmt != COL_CUSTOM || strcmp (cfield, col_w->cfield) == 0) {
                col_w->xalign = xalign;
                found = TRUE;
                break;
            }
        }
        col_l = col_l->next;
    }

    if (!found) {
        col_w = g_new(col_width_data, 1);
        col_w->cfmt = cfmt;
        col_w->cfield = g_strdup(cfield);
        col_w->width = 40;
        col_w->xalign = xalign;
        recent.col_width_list = g_list_append(recent.col_width_list, col_w);
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
    free_col_width_info(&recent);
    g_free(recent.gui_fileopen_remembered_dir);
    g_list_free_full(recent.gui_additional_toolbars, g_free);
    g_list_free_full(recent.interface_toolbars, g_free);
    prefs_clear_string_list(recent.conversation_tabs);
    prefs_clear_string_list(recent.conversation_tabs_columns);
    prefs_clear_string_list(recent.endpoint_tabs);
    prefs_clear_string_list(recent.endpoint_tabs_columns);
    prefs_clear_string_list(recent.custom_colors);
}
