/* decode_as_utils.c
 *
 * Routines to modify dissector tables on the fly.
 *
 * By David Hampton <dhampton@mac.com>
 * Copyright 2001 David Hampton
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <stdlib.h>

#include <errno.h>

#include "epan/decode_as.h"
#include "epan/packet.h"
#include "epan/prefs.h"
#include "epan/prefs-int.h"

#include "ui/decode_as_utils.h"
#include "ui/simple_dialog.h"

#include "wsutil/file_util.h"
#include "wsutil/filesystem.h"
#include "ui/cmdarg_err.h"
#include "version_info.h"

/* XXX - We might want to switch this to a UAT */

static const char* prev_display_dissector_name = NULL;

/*
* For a dissector table, print on the stream described by output,
* its short name (which is what's used in the "-d" option) and its
* descriptive name.
*/
static void
display_dissector_table_names(const char *table_name, const char *ui_name,
gpointer output)
{
    if ((prev_display_dissector_name == NULL) ||
        (strcmp(prev_display_dissector_name, table_name) != 0)) {
        fprintf((FILE *)output, "\t%s (%s)\n", table_name, ui_name);
        prev_display_dissector_name = table_name;
    }
}

/*
* For a dissector handle, print on the stream described by output,
* the filter name (which is what's used in the "-d" option) and the full
* name for the protocol that corresponds to this handle.
*/
static void
display_dissector_names(const gchar *table _U_, gpointer handle, gpointer output)
{
    int          proto_id;
    const gchar *proto_filter_name;
    const gchar *proto_ui_name;

    proto_id = dissector_handle_get_protocol_index((dissector_handle_t)handle);

    if (proto_id != -1) {
        proto_filter_name = proto_get_protocol_filter_name(proto_id);
        proto_ui_name = proto_get_protocol_name(proto_id);
        g_assert(proto_filter_name != NULL);
        g_assert(proto_ui_name != NULL);

        if ((prev_display_dissector_name == NULL) ||
            (strcmp(prev_display_dissector_name, proto_filter_name) != 0)) {
            fprintf((FILE *)output, "\t%s (%s)\n",
                proto_filter_name,
                proto_ui_name);
            prev_display_dissector_name = proto_filter_name;
        }
    }
}

/*
* Allow dissector key names to be sorted alphabetically
*/

static gint
compare_dissector_key_name(gconstpointer dissector_a, gconstpointer dissector_b)
{
    return strcmp((const char*)dissector_a, (const char*)dissector_b);
}

/*
* Print all layer type names supported.
* We send the output to the stream described by the handle output.
*/
static void
fprint_all_layer_types(FILE *output)

{
    prev_display_dissector_name = NULL;
    dissector_all_tables_foreach_table(display_dissector_table_names, (gpointer)output, (GCompareFunc)compare_dissector_key_name);
}

/*
* Print all protocol names supported for a specific layer type.
* table_name contains the layer type name in which the search is performed.
* We send the output to the stream described by the handle output.
*/
static void
fprint_all_protocols_for_layer_types(FILE *output, gchar *table_name)

{
    prev_display_dissector_name = NULL;
    dissector_table_foreach_handle(table_name,
        display_dissector_names,
        (gpointer)output);
}

/*
* The protocol_name_search structure is used by find_protocol_name_func()
* to pass parameters and store results
*/
struct protocol_name_search{
    const char         *searched_name;  /* Protocol filter name we are looking for */
    dissector_handle_t  matched_handle; /* Handle for a dissector whose protocol has the specified filter name */
    guint               nb_match;       /* How many dissectors matched searched_name */
};
typedef struct protocol_name_search *protocol_name_search_t;

/*
* This function parses all dissectors associated with a table to find the
* one whose protocol has the specified filter name.  It is called
* as a reference function in a call to dissector_table_foreach_handle.
* The name we are looking for, as well as the results, are stored in the
* protocol_name_search struct pointed to by user_data.
* If called using dissector_table_foreach_handle, we actually parse the
* whole list of dissectors.
*/
static void
find_protocol_name_func(const gchar *table _U_, gpointer handle, gpointer user_data)

{
    int                     proto_id;
    const gchar            *protocol_filter_name;
    protocol_name_search_t  search_info;

    g_assert(handle);

    search_info = (protocol_name_search_t)user_data;

    proto_id = dissector_handle_get_protocol_index((dissector_handle_t)handle);
    if (proto_id != -1) {
        protocol_filter_name = proto_get_protocol_filter_name(proto_id);
        g_assert(protocol_filter_name != NULL);
        if (strcmp(protocol_filter_name, search_info->searched_name) == 0) {
            /* Found a match */
            if (search_info->nb_match == 0) {
                /* Record this handle only if this is the first match */
                search_info->matched_handle = (dissector_handle_t)handle; /* Record the handle for this matching dissector */
            }
            search_info->nb_match++;
        }
    }
}

/*
* The function below parses the command-line parameters for the decode as
* feature (a string pointer by cl_param).
* It checks the format of the command-line, searches for a matching table
* and dissector.  If a table/dissector match is not found, we display a
* summary of the available tables/dissectors (on stderr) and return FALSE.
* If everything is fine, we get the "Decode as" preference activated,
* then we return TRUE.
*/
gboolean decode_as_command_option(const gchar *cl_param)
{
    gchar                        *table_name;
    guint32                       selector = 0, selector2 = 0;
    gchar                        *decoded_param;
    gchar                        *remaining_param;
    gchar                        *selector_str = NULL;
    gchar                        *dissector_str;
    dissector_handle_t            dissector_matching;
    dissector_table_t             table_matching;
    ftenum_t                      dissector_table_selector_type;
    struct protocol_name_search   user_protocol_name;
    guint64                       i;
    char                          op = '\0';

    /* The following code will allocate and copy the command-line options in a string pointed by decoded_param */

    g_assert(cl_param);
    decoded_param = g_strdup(cl_param);
    g_assert(decoded_param);


    /* The lines below will parse this string (modifying it) to extract all
    necessary information.  Note that decoded_param is still needed since
    strings are not copied - we just save pointers. */

    /* This section extracts a layer type (table_name) from decoded_param */
    table_name = decoded_param; /* Layer type string starts from beginning */

    remaining_param = strchr(table_name, '=');
    if (remaining_param == NULL) {
        /* Dissector tables of type FT_NONE aren't required to specify a value, so for now
           just check for comma */
        remaining_param = strchr(table_name, ',');
        if (remaining_param == NULL) {
            cmdarg_err("Parameter \"%s\" doesn't follow the template \"%s\"", cl_param, DECODE_AS_ARG_TEMPLATE);
        } else {
            *remaining_param = '\0'; /* Terminate the layer type string (table_name) where ',' was detected */
        }
        /* If the argument does not follow the template, carry on anyway to check
        if the table name is at least correct.  If remaining_param is NULL,
        we'll exit anyway further down */
    }
    else {
        *remaining_param = '\0'; /* Terminate the layer type string (table_name) where '=' was detected */
    }

    /* Remove leading and trailing spaces from the table name */
    while (table_name[0] == ' ')
        table_name++;
    while (table_name[strlen(table_name) - 1] == ' ')
        table_name[strlen(table_name) - 1] = '\0'; /* Note: if empty string, while loop will eventually exit */

    /* The following part searches a table matching with the layer type specified */
    table_matching = NULL;

    /* Look for the requested table */
    if (!(*(table_name))) { /* Is the table name empty, if so, don't even search for anything, display a message */
        cmdarg_err("No layer type specified"); /* Note, we don't exit here, but table_matching will remain NULL, so we exit below */
    }
    else {
        table_matching = find_dissector_table(table_name);
        if (!table_matching) {
            cmdarg_err("Unknown layer type -- %s", table_name); /* Note, we don't exit here, but table_matching will remain NULL, so we exit below */
        }
    }

    if (!table_matching) {
        /* Display a list of supported layer types to help the user, if the
        specified layer type was not found */
        cmdarg_err("Valid layer types are:");
        fprint_all_layer_types(stderr);
    }
    if (remaining_param == NULL || !table_matching) {
        /* Exit if the layer type was not found, or if no '=' separator was found
        (see above) */
        g_free(decoded_param);
        return FALSE;
    }

    dissector_table_selector_type = get_dissector_table_selector_type(table_name);

    if (dissector_table_selector_type != FT_NONE) {
        if (*(remaining_param + 1) != '=') { /* Check for "==" and not only '=' */
                cmdarg_err("WARNING: -d requires \"==\" instead of \"=\". Option will be treated as \"%s==%s\"", table_name, remaining_param + 1);
        }
        else {
            remaining_param++; /* Move to the second '=' */
            *remaining_param = '\0'; /* Remove the second '=' */
        }
        remaining_param++; /* Position after the layer type string */


        /* This section extracts a selector value (selector_str) from decoded_param */

        selector_str = remaining_param; /* Next part starts with the selector number */

        remaining_param = strchr(selector_str, ',');
        if (remaining_param == NULL) {
            cmdarg_err("Parameter \"%s\" doesn't follow the template \"%s\"", cl_param, DECODE_AS_ARG_TEMPLATE);
            /* If the argument does not follow the template, carry on anyway to check
            if the selector value is at least correct.  If remaining_param is NULL,
            we'll exit anyway further down */
        }
        else {
            *remaining_param = '\0'; /* Terminate the selector number string (selector_str) where ',' was detected */
        }
    }

    switch (dissector_table_selector_type) {

    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
    {
        /* The selector for this table is an unsigned number.  Parse it as such.
        Skip leading spaces for backwards compatibility (previously sscanf was used). */
        gchar *str = selector_str;
        gchar *end;
        guint64 val;

        while (g_ascii_isspace(*str)) {
            str++;
        }

        val = g_ascii_strtoull(str, &end, 0);
        if (str == end || val > G_MAXUINT32) {
            cmdarg_err("Invalid selector number \"%s\"", selector_str);
            g_free(decoded_param);
            return FALSE;
        }
        selector = (guint32) val;

        if (*end == '\0') {
            /* not a range, but a single (valid) value */
            op = '\0';
            selector2 = 0;
        } else if (*end == ':' || *end == '-') {
            /* range value such as "8888:3" or "8888-8890" */
            op = *end;
            str = end + 1;

            val = g_ascii_strtoull(str, &end, 0);
            if (str == end || val > G_MAXUINT32 || *end != '\0') {
                cmdarg_err("Invalid selector numeric range \"%s\"", selector_str);
                g_free(decoded_param);
                return FALSE;
            }
            selector2 = (guint32) val;

            if (op == ':') {
                if ((selector2 == 0) || ((guint64)selector + selector2 - 1) > G_MAXUINT32) {
                    cmdarg_err("Invalid selector numeric range \"%s\"", selector_str);
                    g_free(decoded_param);
                    return FALSE;
                }
            }
            else if (selector2 < selector) {
                /* We could swap them for the user, but maybe it's better to call
                * this out as an error in case it's not what was intended? */
                cmdarg_err("Invalid selector numeric range \"%s\"", selector_str);
                g_free(decoded_param);
                return FALSE;
            }
        } else {
            /* neither a valid single value, nor a range. */
            cmdarg_err("Invalid selector number \"%s\"", selector_str);
            g_free(decoded_param);
            return FALSE;
        }
        break;
    }

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
        /* The selector for this table is a string. */
        break;

    case FT_NONE:
        /* There is no selector for this table */
        break;

    default:
        /* There are currently no dissector tables with any types other
        than the ones listed above. */
        g_assert_not_reached();
    }

    if (remaining_param == NULL) {
        /* Exit if no ',' separator was found (see above) */
        cmdarg_err("Valid protocols for layer type \"%s\" are:", table_name);
        fprint_all_protocols_for_layer_types(stderr, table_name);
        g_free(decoded_param);
        return FALSE;
    }

    remaining_param++; /* Position after the selector number string */

    /* This section extracts a protocol filter name (dissector_str) from decoded_param */

    dissector_str = remaining_param; /* All the rest of the string is the dissector (decode as protocol) name */

    /* Remove leading and trailing spaces from the dissector name */
    while (dissector_str[0] == ' ')
        dissector_str++;
    while (dissector_str[strlen(dissector_str) - 1] == ' ')
        dissector_str[strlen(dissector_str) - 1] = '\0'; /* Note: if empty string, while loop will eventually exit */

    dissector_matching = NULL;

    /* We now have a pointer to the handle for the requested table inside the variable table_matching */
    if (!(*dissector_str)) { /* Is the dissector name empty, if so, don't even search for a matching dissector and display all dissectors found for the selected table */
        cmdarg_err("No protocol name specified"); /* Note, we don't exit here, but dissector_matching will remain NULL, so we exit below */
    }
    else {
        header_field_info *hfi = proto_registrar_get_byalias(dissector_str);

        user_protocol_name.nb_match = 0;
        if (hfi) {
            user_protocol_name.searched_name = hfi->abbrev;
        } else {
            user_protocol_name.searched_name = dissector_str;
        }
        user_protocol_name.matched_handle = NULL;

        dissector_table_foreach_handle(table_name, find_protocol_name_func, &user_protocol_name); /* Go and perform the search for this dissector in the this table's dissectors' names and shortnames */

        if (user_protocol_name.nb_match != 0) {
            dissector_matching = user_protocol_name.matched_handle;
            if (user_protocol_name.nb_match > 1) {
                cmdarg_err("WARNING: Protocol \"%s\" matched %u dissectors, first one will be used", dissector_str, user_protocol_name.nb_match);
            }
        }
        else {
            /* OK, check whether the problem is that there isn't any such
            protocol, or that there is but it's not specified as a protocol
            that's valid for that dissector table.
            Note, we don't exit here, but dissector_matching will remain NULL,
            so we exit below */
            if (proto_get_id_by_filter_name(dissector_str) == -1) {
                /* No such protocol */
                cmdarg_err("Unknown protocol -- \"%s\"", dissector_str);
            }
            else {
                cmdarg_err("Protocol \"%s\" isn't valid for layer type \"%s\"",
                    dissector_str, table_name);
            }
        }
    }

    if (!dissector_matching) {
        cmdarg_err("Valid protocols for layer type \"%s\" are:", table_name);
        fprint_all_protocols_for_layer_types(stderr, table_name);
        g_free(decoded_param);
        return FALSE;
    }

    /* This is the end of the code that parses the command-line options.
    All information is now stored in the variables:
    table_name
    selector
    dissector_matching
    The above variables that are strings are still pointing to areas within
    decoded_parm.  decoded_parm thus still needs to be kept allocated in
    until we stop needing these variables
    decoded_param will be deallocated at each exit point of this function */


    /* We now have a pointer to the handle for the requested dissector
    (requested protocol) inside the variable dissector_matching */
    switch (dissector_table_selector_type) {

    case FT_UINT8:
    case FT_UINT16:
    case FT_UINT24:
    case FT_UINT32:
        /* The selector for this table is an unsigned number. */
        if (op == '\0') {
            dissector_change_uint(table_name, selector, dissector_matching);
        }
        else if (op == ':') {
            for (i = selector; i < (guint64)selector + selector2; i++) {
                dissector_change_uint(table_name, (guint32)i, dissector_matching);
            }
        }
        else { /* op == '-' */
            for (i = selector; i <= selector2; i++) {
                dissector_change_uint(table_name, (guint32)i, dissector_matching);
            }
        }
        break;

    case FT_STRING:
    case FT_STRINGZ:
    case FT_UINT_STRING:
    case FT_STRINGZPAD:
        /* The selector for this table is a string. */
        dissector_change_string(table_name, selector_str, dissector_matching);
        break;

    case FT_NONE:
        /* Just directly set the dissector found. */
        dissector_change_payload(table_name, dissector_matching);
        break;

    default:
        /* There are currently no dissector tables with any types other
        than the ones listed above. */
        g_assert_not_reached();
    }
    g_free(decoded_param); /* "Decode As" rule has been successfully added */
    return TRUE;
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
