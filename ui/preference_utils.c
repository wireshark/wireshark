/* preference_utils.c
 * Routines for handling preferences
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>

#include <epan/column.h>
#include <wsutil/filesystem.h>
#include <wsutil/wslog.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/uat-int.h>
#include <ui/recent.h>

#ifdef HAVE_LIBPCAP
#include "capture_opts.h"
#include "ui/capture_globals.h"
#endif

#include "ui/preference_utils.h"
#include "ui/simple_dialog.h"

#ifdef HAVE_LIBPCAP
gboolean auto_scroll_live;
#endif

/* Fill in capture options with values from the preferences */
void
prefs_to_capture_opts(void)
{
#ifdef HAVE_LIBPCAP
    /* Set promiscuous mode from the preferences setting. */
    /* the same applies to other preferences settings as well. */
    global_capture_opts.default_options.promisc_mode = prefs.capture_prom_mode;
    global_capture_opts.use_pcapng                   = prefs.capture_pcap_ng;
    global_capture_opts.show_info                    = prefs.capture_show_info;
    global_capture_opts.real_time_mode               = prefs.capture_real_time;
    auto_scroll_live                                 = prefs.capture_auto_scroll;
#endif /* HAVE_LIBPCAP */
}

void
prefs_main_write(void)
{
    int   err;
    char *pf_dir_path;
    char *pf_path;

    /* Create the directory that holds personal configuration files, if
       necessary.  */
    if (create_persconffile_dir(&pf_dir_path) == -1) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                "Can't create directory\n\"%s\"\nfor preferences file: %s.", pf_dir_path,
                g_strerror(errno));
        g_free(pf_dir_path);
    } else {
        /* Write the preferences out. */
        err = write_prefs(&pf_path);
        if (err != 0) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
                    "Can't open preferences file\n\"%s\": %s.", pf_path,
                    g_strerror(err));
            g_free(pf_path);
        }
        /* Write recent and recent_common files out to ensure sync with prefs. */
        write_profile_recent();
        write_recent();
    }
}

static unsigned int
prefs_store_ext_helper(const char * module_name, const char *pref_name, const char *pref_value)
{
    module_t * module = NULL;
    pref_t * pref = NULL;
    unsigned int pref_changed = 0;

    if ( !prefs_is_registered_protocol(module_name))
        return 0;

    module = prefs_find_module(module_name);
    if ( !module )
        return 0;

    pref = prefs_find_preference(module, pref_name);

    if (!pref)
        return 0;

    if (prefs_get_type(pref) == PREF_STRING )
    {
        pref_changed |= prefs_set_string_value(pref, pref_value, pref_stashed);
        if ( !pref_changed || prefs_get_string_value(pref, pref_stashed) != 0 )
            pref_changed |= prefs_set_string_value(pref, pref_value, pref_current);
    } else if (prefs_get_type(pref) == PREF_PASSWORD )
    {
        pref_changed |= prefs_set_password_value(pref, pref_value, pref_stashed);
        if ( !pref_changed || prefs_get_password_value(pref, pref_stashed) != 0 )
            pref_changed |= prefs_set_password_value(pref, pref_value, pref_current);
    }

    return pref_changed;
}

unsigned int
prefs_store_ext(const char * module_name, const char *pref_name, const char *pref_value)
{
    unsigned int changed_flags = prefs_store_ext_helper(module_name, pref_name, pref_value);
    if ( changed_flags )
    {
        prefs_main_write();
        prefs_apply_all();
        prefs_to_capture_opts();
        return changed_flags;
    }

    return 0;
}

gboolean
prefs_store_ext_multiple(const char * module, GHashTable * pref_values)
{
    gboolean pref_changed = FALSE;
    GList * keys = NULL;

    if ( !prefs_is_registered_protocol(module))
        return pref_changed;

    keys = g_hash_table_get_keys(pref_values);
    if ( !keys )
        return pref_changed;

    for ( GList * key = keys; key != NULL; key = g_list_next(key) )
    {
        gchar * pref_name = (gchar *)key->data;
        gchar * pref_value = (gchar *) g_hash_table_lookup(pref_values, key->data);

        if ( pref_name && pref_value )
        {
            if ( prefs_store_ext_helper(module, pref_name, pref_value) )
                pref_changed = TRUE;
        }
    }
    g_list_free(keys);

    if ( pref_changed )
    {
        prefs_main_write();
        prefs_apply_all();
        prefs_to_capture_opts();
    }

    return TRUE;
}

gint
column_prefs_add_custom(gint fmt, const gchar *title, const gchar *custom_fields, gint position)
{
    GList *clp;
    fmt_data *cfmt, *last_cfmt;
    gint colnr;

    cfmt = g_new(fmt_data, 1);
    /*
     * Because a single underscore is interpreted as a signal that the next character
     * is going to be marked as accelerator for this header (i.e. is going to be
     * shown underlined), escape it be inserting a second consecutive underscore.
     */
    cfmt->title = g_strdup(title);
    cfmt->fmt = fmt;
    cfmt->custom_fields = g_strdup(custom_fields);
    cfmt->custom_occurrence = 0;
    cfmt->resolved = TRUE;

    colnr = g_list_length(prefs.col_list);

    if (custom_fields) {
        cfmt->visible = TRUE;
        clp = g_list_last(prefs.col_list);
        last_cfmt = (fmt_data *) clp->data;
        if (position > 0 && position <= colnr) {
            /* Custom fields may be added at any position, depending on the given argument */
            prefs.col_list = g_list_insert(prefs.col_list, cfmt, position);
        } else if (last_cfmt->fmt == COL_INFO) {
            /* Last column is COL_INFO, add custom column before this */
            colnr -= 1;
            prefs.col_list = g_list_insert(prefs.col_list, cfmt, colnr);
        } else {
            prefs.col_list = g_list_append(prefs.col_list, cfmt);
        }
    } else {
        cfmt->visible = FALSE;  /* Will be set to TRUE in visible_toggled() when added to list */
        prefs.col_list = g_list_append(prefs.col_list, cfmt);
    }

    return colnr;
}

gint
column_prefs_has_custom(const gchar *custom_field)
{
    GList *clp;
    fmt_data *cfmt;
    gint colnr = -1;

    for (gint i = 0; i < prefs.num_cols; i++) {
        clp = g_list_nth(prefs.col_list, i);
        if (clp == NULL) /* Sanity check, invalid column requested */
            continue;

        cfmt = (fmt_data *) clp->data;
        if (cfmt->fmt == COL_CUSTOM && strcmp(custom_field, cfmt->custom_fields) == 0) {
            colnr = i;
            break;
        }
    }

    return colnr;
}

gboolean
column_prefs_custom_resolve(const gchar* custom_field)
{
    gchar **fields;
    header_field_info *hfi;
    bool resolve = false;

    fields = g_regex_split_simple(COL_CUSTOM_PRIME_REGEX, custom_field,
                                  (GRegexCompileFlags) (G_REGEX_ANCHORED | G_REGEX_RAW),
                                  G_REGEX_MATCH_ANCHORED);

    for (guint i = 0; i < g_strv_length(fields); i++) {
        if (fields[i] && *fields[i]) {
            hfi = proto_registrar_get_byname(fields[i]);
            if (hfi && ((hfi->type == FT_OID) || (hfi->type == FT_REL_OID) || (hfi->type == FT_BOOLEAN) ||
                    ((hfi->strings != NULL) &&
                     (IS_FT_INT(hfi->type) || IS_FT_UINT(hfi->type)))))
                {
                    resolve = TRUE;
                    break;
                }
        }
    }

    g_strfreev(fields);

    return resolve;
}

void
column_prefs_remove_link(GList *col_link)
{
    fmt_data *cfmt;

    if (!col_link || !col_link->data) return;

    cfmt = (fmt_data *) col_link->data;

    g_free(cfmt->title);
    g_free(cfmt->custom_fields);
    g_free(cfmt);
    prefs.col_list = g_list_remove_link(prefs.col_list, col_link);
}

void
column_prefs_remove_nth(gint col)
{
    column_prefs_remove_link(g_list_nth(prefs.col_list, col));
}

void save_migrated_uat(const char *uat_name, gboolean *old_pref)
{
    char *err = NULL;

    if (!uat_save(uat_get_table_by_name(uat_name), &err)) {
        ws_warning("Unable to save %s: %s", uat_name, err);
        g_free(err);
        return;
    }

    // Ensure that any old preferences are removed after successful migration.
    if (*old_pref) {
        *old_pref = FALSE;
        prefs_main_write();
    }
}
