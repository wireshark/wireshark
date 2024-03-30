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

/* Fill in capture options with values from the preferences */
void
prefs_to_capture_opts(void)
{
#ifdef HAVE_LIBPCAP
    /* Set promiscuous mode from the preferences setting. */
    /* the same applies to other preferences settings as well. */
    global_capture_opts.default_options.promisc_mode = prefs.capture_prom_mode;
    global_capture_opts.default_options.monitor_mode = prefs.capture_monitor_mode;
    global_capture_opts.use_pcapng                   = prefs.capture_pcap_ng;
    global_capture_opts.show_info                    = prefs.capture_show_info;
    global_capture_opts.real_time_mode               = prefs.capture_real_time;
    global_capture_opts.update_interval              = prefs.capture_update_interval;
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

    if (prefs_get_type(pref) == PREF_STRING || prefs_get_type(pref) == PREF_DISSECTOR)
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

bool
prefs_store_ext_multiple(const char * module, GHashTable * pref_values)
{
    bool pref_changed = false;
    GList * keys = NULL;

    if ( !prefs_is_registered_protocol(module))
        return pref_changed;

    keys = g_hash_table_get_keys(pref_values);
    if ( !keys )
        return pref_changed;

    for ( GList * key = keys; key != NULL; key = g_list_next(key) )
    {
        char * pref_name = (char *)key->data;
        char * pref_value = (char *) g_hash_table_lookup(pref_values, key->data);

        if ( pref_name && pref_value )
        {
            if ( prefs_store_ext_helper(module, pref_name, pref_value) )
                pref_changed = true;
        }
    }
    g_list_free(keys);

    if ( pref_changed )
    {
        prefs_main_write();
        prefs_apply_all();
        prefs_to_capture_opts();
    }

    return true;
}

int
column_prefs_add_custom(int fmt, const char *title, const char *custom_fields, int position)
{
    GList *clp;
    fmt_data *cfmt, *last_cfmt;
    int colnr;

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
    cfmt->resolved = true;

    colnr = g_list_length(prefs.col_list);

    if (custom_fields) {
        cfmt->visible = true;
        clp = g_list_last(prefs.col_list);
        last_cfmt = (fmt_data *) clp->data;
        if (position > 0 && position <= colnr) {
            /* Custom fields may be added at any position, depending on the given argument */
            colnr = position;
            prefs.col_list = g_list_insert(prefs.col_list, cfmt, colnr);
        } else if (last_cfmt->fmt == COL_INFO) {
            /* Last column is COL_INFO, add custom column before this */
            colnr -= 1;
            prefs.col_list = g_list_insert(prefs.col_list, cfmt, colnr);
        } else {
            prefs.col_list = g_list_append(prefs.col_list, cfmt);
        }
    } else {
        cfmt->visible = false;  /* Will be set to true in visible_toggled() when added to list */
        prefs.col_list = g_list_append(prefs.col_list, cfmt);
    }
    recent_insert_column(colnr);

    return colnr;
}

int
column_prefs_has_custom(const char *custom_field)
{
    GList *clp;
    fmt_data *cfmt;
    int colnr = -1;

    for (int i = 0; i < prefs.num_cols; i++) {
        clp = g_list_nth(prefs.col_list, i);
        if (clp == NULL) /* Sanity check, invalid column requested */
            continue;

        cfmt = (fmt_data *) clp->data;
        if (cfmt->fmt == COL_CUSTOM && cfmt->custom_occurrence == 0 && strcmp(custom_field, cfmt->custom_fields) == 0) {
            colnr = i;
            break;
        }
    }

    return colnr;
}

bool
column_prefs_custom_resolve(const char* custom_field)
{
    char **fields;
    header_field_info *hfi;
    bool resolve = false;

    fields = g_regex_split_simple(COL_CUSTOM_PRIME_REGEX, custom_field,
                                  (GRegexCompileFlags) (G_REGEX_RAW),
                                  0);

    for (unsigned i = 0; i < g_strv_length(fields); i++) {
        if (fields[i] && *fields[i]) {
            hfi = proto_registrar_get_byname(fields[i]);
            if (hfi && ((hfi->type == FT_OID) || (hfi->type == FT_REL_OID) || (hfi->type == FT_ETHER) || (hfi->type == FT_IPv4) || (hfi->type == FT_IPv6) || (hfi->type == FT_FCWWN) || (hfi->type == FT_BOOLEAN) ||
                    ((hfi->strings != NULL) &&
                     (FT_IS_INT(hfi->type) || FT_IS_UINT(hfi->type)))))
                {
                    resolve = true;
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
    g_list_free_1(col_link);
}

void
column_prefs_remove_nth(int col)
{
    column_prefs_remove_link(g_list_nth(prefs.col_list, col));
    recent_remove_column(col);
}

void save_migrated_uat(const char *uat_name, bool *old_pref)
{
    char *err = NULL;

    if (!uat_save(uat_get_table_by_name(uat_name), &err)) {
        ws_warning("Unable to save %s: %s", uat_name, err);
        g_free(err);
        return;
    }

    // Ensure that any old preferences are removed after successful migration.
    if (*old_pref) {
        *old_pref = false;
        prefs_main_write();
    }
}
