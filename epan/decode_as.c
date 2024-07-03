/* decode_as.c
 * Routines for dissector Decode As handlers
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include "decode_as.h"
#include "packet.h"
#include "prefs.h"
#include "prefs-int.h"
#include "wsutil/file_util.h"
#include "wsutil/filesystem.h"
#include "epan/dissectors/packet-dcerpc.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <wsutil/ws_assert.h>

GList *decode_as_list;

void register_decode_as(decode_as_t* reg)
{
    dissector_table_t decode_table;

    /* Ensure valid functions */
    ws_assert(reg->populate_list);
    ws_assert(reg->reset_value);
    ws_assert(reg->change_value);

    decode_table = find_dissector_table(reg->table_name);
    if (decode_table != NULL)
    {
        dissector_table_allow_decode_as(decode_table);
    }

    decode_as_list = g_list_prepend(decode_as_list, reg);
}

static void next_proto_prompt(packet_info *pinfo _U_, char *result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Next level protocol as");
}

static void *next_proto_value(packet_info *pinfo _U_)
{
    return 0;
}

static build_valid_func next_proto_values[] = { next_proto_value };
static decode_as_value_t next_proto_da_values =
                        { next_proto_prompt, 1, next_proto_values };

dissector_table_t register_decode_as_next_proto(int proto, const char *table_name, const char *ui_name, build_label_func label_func)
{
    decode_as_t *da;

    dissector_table_t dt = register_dissector_table(table_name, ui_name, proto, FT_NONE, BASE_NONE);

    da = wmem_new0(wmem_epan_scope(), decode_as_t);
    da->name = wmem_strdup(wmem_epan_scope(), proto_get_protocol_filter_name(proto));
    da->table_name = wmem_strdup(wmem_epan_scope(), table_name);
    da->num_items = 1;
    if (label_func == NULL)
    {
        da->values = &next_proto_da_values;
    }
    else
    {
        da->values = wmem_new(wmem_epan_scope(), decode_as_value_t);
        da->values->label_func = label_func;
        da->values->num_values = 1;
        da->values->build_values = next_proto_values;
    }
    da->populate_list = decode_as_default_populate_list;
    da->reset_value = decode_as_default_reset;
    da->change_value = decode_as_default_change;

    register_decode_as(da);
    return dt;
}

struct decode_as_default_populate
{
    decode_as_add_to_list_func add_to_list;
    void *ui_element;
};

static void
decode_proto_add_to_list (const char *table_name, void *value, void *user_data)
{
    struct decode_as_default_populate* populate = (struct decode_as_default_populate*)user_data;
    const char      *dissector_description;
    int        i;
    dissector_handle_t handle;


    handle = (dissector_handle_t)value;
    dissector_description = dissector_handle_get_description(handle);

    i = dissector_handle_get_protocol_index(handle);
    if (i >= 0 && !proto_is_protocol_enabled(find_protocol_by_id(i)))
        return;

    populate->add_to_list(table_name, dissector_description, value, populate->ui_element);
}

void decode_as_default_populate_list(const char *table_name, decode_as_add_to_list_func add_to_list, void *ui_element)
{
    struct decode_as_default_populate populate;

    populate.add_to_list = add_to_list;
    populate.ui_element = ui_element;

    dissector_table_foreach_handle(table_name, decode_proto_add_to_list, &populate);
}

bool decode_as_default_reset(const char *name, const void *pattern)
{
    switch (get_dissector_table_selector_type(name)) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        dissector_reset_uint(name, GPOINTER_TO_UINT(pattern));
        return true;
    case FT_NONE:
        dissector_reset_payload(name);
        return true;
    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
    case FT_STRINGZTRUNC:
        dissector_reset_string(name, (!pattern)?"":(const char *) pattern);
        return true;
    default:
        return false;
    };

    return true;
}

bool decode_as_default_change(const char *name, const void *pattern, const void *handle, const char *list_name _U_)
{
    const dissector_handle_t dissector = (const dissector_handle_t)handle;
    switch (get_dissector_table_selector_type(name)) {
    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        dissector_change_uint(name, GPOINTER_TO_UINT(pattern), dissector);
        return true;
    case FT_NONE:
        dissector_change_payload(name, dissector);
        return true;
    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
    case FT_STRINGZTRUNC:
        dissector_change_string(name, (!pattern)?"":(const char *) pattern, dissector);
        return true;
    default:
        return false;
    };

    return true;
}

/* Some useful utilities for Decode As */

/*
 * A list of dissectors that need to be reset.
 */
static GSList *dissector_reset_list;

/*
 * A callback function to parse each "decode as" entry in the file and apply the change
 */
static prefs_set_pref_e
read_set_decode_as_entries(char *key, const char *value,
                           void *user_data,
                           bool return_range_errors _U_)
{
    char *values[4] = {NULL, NULL, NULL, NULL};
    char delimiter[4] = {',', ',', ',','\0'};
    char *pch;
    unsigned i, j;
    GHashTable* processed_entries = (GHashTable*)user_data;
    dissector_table_t sub_dissectors;
    prefs_set_pref_e retval = PREFS_SET_OK;
    bool is_valid = false;

    if (strcmp(key, DECODE_AS_ENTRY) == 0) {
        /* Parse csv into table, selector, initial, current */
        for (i = 0; i < 4; i++) {
            pch = strchr(value, delimiter[i]);
            if (pch == NULL) {
                for (j = 0; j < i; j++) {
                    g_free(values[j]);
                }
                return PREFS_SET_SYNTAX_ERR;
            }
            values[i] = g_strndup(value, pch - value);
            value = pch + 1;
        }
        sub_dissectors = find_dissector_table(values[0]);
        if (sub_dissectors != NULL) {
            dissector_handle_t handle;
            ftenum_t selector_type;
            pref_t* pref_value;
            module_t *module;
            const char* proto_name;

            selector_type = dissector_table_get_type(sub_dissectors);

            handle = dissector_table_get_dissector_handle(sub_dissectors, values[3]);
            if (handle != NULL || g_ascii_strcasecmp(values[3], DECODE_AS_NONE) == 0) {
                is_valid = true;
            }

            if (is_valid) {
                if (FT_IS_STRING(selector_type)) {
                    dissector_change_string(values[0], values[1], handle);
                } else {
                    char *p;
                    long long_value;

                    long_value = strtol(values[1], &p, 0);
                    if (p == values[0] || *p != '\0' || long_value < 0 ||
                          (unsigned long)long_value > UINT_MAX) {
                        retval = PREFS_SET_SYNTAX_ERR;
                        is_valid = false;
                    } else {
                        dissector_change_uint(values[0], (unsigned)long_value, handle);
                    }

                    /* Now apply the value data back to dissector table preference */
                    if (handle != NULL) {
                        proto_name = proto_get_protocol_filter_name(dissector_handle_get_protocol_index(handle));
                        module = prefs_find_module(proto_name);
                        // values[0] is the dissector table
                        char *pref_name = ws_strdup_printf("%s%s", values[0], dissector_handle_get_pref_suffix(handle));
                        pref_value = prefs_find_preference(module, pref_name);
                        g_free(pref_name);
                        if (pref_value != NULL) {
                            bool replace = false;
                            if (g_hash_table_lookup(processed_entries, proto_name) == NULL) {
                                /* First decode as entry for this protocol, ranges may be replaced */
                                replace = true;

                                /* Remember we've processed this protocol */
                                g_hash_table_insert(processed_entries, (void *)proto_name, (void *)proto_name);
                            }

                            prefs_add_decode_as_value(pref_value, (unsigned)long_value, replace);
                            module->prefs_changed_flags |= prefs_get_effect_flags(pref_value);
                        }
                    }
                }
            }
            if (is_valid) {
                decode_build_reset_list(values[0], selector_type, values[1], NULL, NULL);
            }
        } else {
            retval = PREFS_SET_SYNTAX_ERR;
        }

    } else {
        retval = PREFS_SET_NO_SUCH_PREF;
    }

    for (i = 0; i < 4; i++) {
        g_free(values[i]);
    }
    return retval;
}

void
load_decode_as_entries(void)
{
    char   *daf_path;
    FILE   *daf;

    decode_clear_all();

    daf_path = get_persconffile_path(DECODE_AS_ENTRIES_FILE_NAME, true);
    if ((daf = ws_fopen(daf_path, "r")) != NULL) {
        /* Store saved entries for better range processing */
        GHashTable* processed_entries = g_hash_table_new(g_str_hash, g_str_equal);
        read_prefs_file(daf_path, daf, read_set_decode_as_entries, processed_entries);
        g_hash_table_destroy(processed_entries);
        fclose(daf);
    }
    g_free(daf_path);
}


/* Make a sorted list of the entries as we are fetching them from a hash table. Then write it out from the sorted list */
static void
decode_as_write_entry (const char *table_name, ftenum_t selector_type,
                       void *key, void *value, void *user_data)
{
    GList **decode_as_rows_list = (GList **)user_data;
    dissector_handle_t current, initial;
    const char *current_dissector_name, *initial_dissector_name, *decode_as_row;

    current = dtbl_entry_get_handle((dtbl_entry_t *)value);
    if (current == NULL)
        current_dissector_name = DECODE_AS_NONE;
    else
        current_dissector_name = dissector_handle_get_description(current);
    initial = dtbl_entry_get_initial_handle((dtbl_entry_t *)value);
    if (initial == NULL)
        initial_dissector_name = DECODE_AS_NONE;
    else
        initial_dissector_name = dissector_handle_get_description(initial);

    switch (selector_type) {

    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        /*
         * XXX - write these in decimal, regardless of the base of
         * the dissector table's selector, as older versions of
         * Wireshark used atoi() when reading this file, and
         * failed to handle hex or octal numbers.
         *
         * That will be fixed in future 1.10 and 1.12 releases,
         * but pre-1.10 releases are at end-of-life and won't
         * be fixed.
         */
        decode_as_row = ws_strdup_printf(
            DECODE_AS_ENTRY ": %s,%u,%s,%s\n",
            table_name, GPOINTER_TO_UINT(key), initial_dissector_name,
            current_dissector_name);
        break;
    case FT_NONE:
        /*
         * XXX - Just put a placeholder for the key value.  Currently
         * FT_NONE dissector table uses a single uint value for
         * a placeholder
         */
        decode_as_row = ws_strdup_printf(
            DECODE_AS_ENTRY ": %s,0,%s,%s\n",
            table_name, initial_dissector_name,
            current_dissector_name);
        break;

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
    case FT_STRINGZTRUNC:
        decode_as_row = ws_strdup_printf(
            DECODE_AS_ENTRY ": %s,%s,%s,%s\n",
            table_name, (char *)key, initial_dissector_name,
            current_dissector_name);
        break;

    default:
        ws_assert_not_reached();
        break;
    }

    /* Do we need a better sort function ???*/
    *decode_as_rows_list = g_list_insert_sorted (*decode_as_rows_list, (void *)decode_as_row,
        (GCompareFunc)g_ascii_strcasecmp);

}

/* Print the sorted rows to File */
static void
decode_as_print_rows(void *data, void *user_data)
{
    FILE *da_file = (FILE *)user_data;
    const char *decode_as_row = (const char *)data;

    fprintf(da_file, "%s",decode_as_row);

}
int
save_decode_as_entries(char** err)
{
    char *pf_dir_path;
    char *daf_path;
    FILE *da_file;
    GList *decode_as_rows_list = NULL;

    if (create_persconffile_dir(&pf_dir_path) == -1) {
        *err = ws_strdup_printf("Can't create directory\n\"%s\"\nfor recent file: %s.",
                                pf_dir_path, g_strerror(errno));
        g_free(pf_dir_path);
        return -1;
    }

    daf_path = get_persconffile_path(DECODE_AS_ENTRIES_FILE_NAME, true);
    if ((da_file = ws_fopen(daf_path, "w")) == NULL) {
        *err = ws_strdup_printf("Can't open decode_as_entries file\n\"%s\": %s.",
                                daf_path, g_strerror(errno));
        g_free(daf_path);
        return -1;
    }

    fprintf(da_file, "# \"Decode As\" entries file for %s " VERSION ".\n"
        "#\n"
        "# This file is regenerated each time \"Decode As\" preferences\n"
        "# are saved within %s. Making manual changes should be safe,\n"
        "# however.\n",
        get_configuration_namespace(), get_configuration_namespace());

    dissector_all_tables_foreach_changed(decode_as_write_entry, &decode_as_rows_list);

    g_list_foreach(decode_as_rows_list, decode_as_print_rows, da_file);

    fclose(da_file);
    g_free(daf_path);
    g_list_free_full(decode_as_rows_list, g_free);

    return 0;
}

/*
 * Data structure for tracking which dissector need to be reset.  This
 * structure is necessary as a hash table entry cannot be removed
 * while a g_hash_table_foreach walk is in progress.
 */
typedef struct dissector_delete_item {
    /* The name of the dissector table */
    char *ddi_table_name;
    /* The type of the selector in that dissector table */
    ftenum_t ddi_selector_type;
    /* The selector in the dissector table */
    union {
        unsigned   sel_uint;
        char    *sel_string;
    } ddi_selector;
} dissector_delete_item_t;

void
decode_build_reset_list (const char *table_name, ftenum_t selector_type,
                         void *key, void *value _U_,
                         void *user_data _U_)
{
    dissector_delete_item_t *item;

    item = g_new(dissector_delete_item_t,1);
    item->ddi_table_name = g_strdup(table_name);
    item->ddi_selector_type = selector_type;
    switch (selector_type) {

    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        item->ddi_selector.sel_uint = GPOINTER_TO_UINT(key);
        break;

    case FT_NONE:
        /* Not really needed, but prevents the assert */
        item->ddi_selector.sel_uint = 0;
        break;

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
    case FT_STRINGZTRUNC:
        item->ddi_selector.sel_string = g_strdup((char *)key);
        break;

    default:
        ws_assert_not_reached();
    }
    dissector_reset_list = g_slist_prepend(dissector_reset_list, item);
}

/* clear all settings */
void
decode_clear_all(void)
{
    dissector_delete_item_t *item;
    GSList *tmp;

    dissector_all_tables_foreach_changed(decode_build_reset_list, NULL);

    for (tmp = dissector_reset_list; tmp; tmp = g_slist_next(tmp)) {
        item = (dissector_delete_item_t *)tmp->data;
        switch (item->ddi_selector_type) {

        case FT_UINT8:
        case FT_UINT16:
        case FT_UINT24:
        case FT_UINT32:
            dissector_reset_uint(item->ddi_table_name,
                                 item->ddi_selector.sel_uint);
            break;

        case FT_NONE:
            dissector_reset_payload(item->ddi_table_name);
            break;

        case FT_STRING:
        case FT_STRINGZ:
        case FT_UINT_STRING:
        case FT_STRINGZPAD:
        case FT_STRINGZTRUNC:
            dissector_reset_string(item->ddi_table_name,
                                   item->ddi_selector.sel_string);
            g_free(item->ddi_selector.sel_string);
            break;

        default:
            ws_assert_not_reached();
        }
        g_free(item->ddi_table_name);
        g_free(item);
    }
    g_slist_free(dissector_reset_list);
    dissector_reset_list = NULL;

    decode_dcerpc_reset_all();
}

void
decode_cleanup(void)
{
    g_list_free(decode_as_list);
    decode_as_list = NULL;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
