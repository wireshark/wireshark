/* prefs.c
 * Routines for handling preferences
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>

#include <stdio.h>
#include <epan/filesystem.h>
#include <epan/address.h>
#include <epan/addr_resolv.h>
#include <epan/oids.h>
#ifdef HAVE_GEOIP
#include <epan/geoip_db.h>
#endif
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/strutil.h>
#include <epan/column.h>
#include "print.h"
#include <wsutil/file_util.h>

#include <epan/prefs-int.h>
#include <epan/uat-int.h>

#include "epan/filter_expressions.h"

/* Internal functions */
static module_t *find_subtree(module_t *parent, const char *tilte);
static module_t *prefs_register_module_or_subtree(module_t *parent,
    const char *name, const char *title, const char *description, gboolean is_subtree,
    void (*apply_cb)(void), gboolean use_gui);
static prefs_set_pref_e set_pref(gchar*, gchar*, void *, gboolean);
static void write_string_list(FILE *, GList *, gboolean is_default);
static void free_col_info(GList *);
static void pre_init_prefs(void);
static gboolean prefs_is_column_visible(const gchar *cols_hidden, fmt_data *cfmt);
static gboolean parse_column_format(fmt_data *cfmt, const char *fmt);
static void try_convert_to_custom_column(gpointer *el_data);


#define PF_NAME		"preferences"
#define OLD_GPF_NAME	"wireshark.conf"	/* old name for global preferences file */

static gboolean prefs_initialized = FALSE;
static gboolean prefs_pre_initialized = FALSE;
static gchar *gpf_path = NULL;
static gchar *cols_hidden_list = NULL;

/*
 * XXX - variables to allow us to attempt to interpret the first
 * "mgcp.{tcp,udp}.port" in a preferences file as
 * "mgcp.{tcp,udp}.gateway_port" and the second as
 * "mgcp.{tcp,udp}.callagent_port".
 */
static int mgcp_tcp_port_count;
static int mgcp_udp_port_count;

e_prefs prefs;

static enum_val_t gui_ptree_line_style[] = {
		{"NONE", "NONE", 0},
		{"SOLID", "SOLID", 1},
		{"DOTTED", "DOTTED", 2},
		{"TABBED", "TABBED", 3},
		{NULL, NULL, -1}
	};

static enum_val_t gui_ptree_expander_style[] = {
		{"NONE", "NONE", 0},
		{"SQUARE", "SQUARE", 1},
		{"TRIANGLE", "TRIANGLE", 2},
		{"CIRCULAR", "CIRCULAR", 3},
		{NULL, NULL, -1}
	};

static enum_val_t gui_hex_dump_highlight_style[] = {
		{"BOLD", "BOLD", 0},
		{"INVERSE", "INVERSE", 1},
		{NULL, NULL, -1}
	};

static enum_val_t gui_console_open_type[] = {
		{"NEVER", "NEVER", console_open_never},
		{"AUTOMATIC", "AUTOMATIC", console_open_auto},
		{"ALWAYS", "ALWAYS", console_open_always},
		{NULL, NULL, -1}
	};

static enum_val_t gui_version_placement_type[] = {
		{"WELCOME", "WELCOME", version_welcome_only},
		{"TITLE", "TITLE", version_title_only},
		{"BOTH", "BOTH", version_both},
		{"NEITHER", "NEITHER", version_neither},
		{NULL, NULL, -1}
	};

static enum_val_t gui_fileopen_style[] = {
		{"LAST_OPENED", "LAST_OPENED", 0},
		{"SPECIFIED", "SPECIFIED", 1},
		{NULL, NULL, -1}
	};

/* GTK knows of two ways representing "both", vertical and horizontal aligned.
 * as this may not work on other guis, we use only "both" in general here */
static enum_val_t gui_toolbar_style[] = {
		{"ICONS", "ICONS", 0},
		{"TEXT", "TEXT", 1},
		{"BOTH", "BOTH", 2},
		{NULL, NULL, -1}
	};

static enum_val_t gui_layout_content[] = {
		{"NONE", "NONE", 0},
		{"PLIST", "PLIST", 1},
		{"PDETAILS", "PDETAILS", 2},
		{"PBYTES", "PBYTES", 3},
		{NULL, NULL, -1}
	};

/*
 * List of all modules with preference settings.
 */
static emem_tree_t *prefs_modules = NULL;

/*
 * List of all modules that should show up at the top level of the
 * tree in the preference dialog box.
 */
static emem_tree_t *prefs_top_level_modules = NULL;

/** Sets up memory used by proto routines. Called at program startup */
void
prefs_init(void)
{
    prefs_modules = pe_tree_create(EMEM_TREE_TYPE_RED_BLACK, "prefs_modules");
    prefs_top_level_modules = pe_tree_create(EMEM_TREE_TYPE_RED_BLACK, "prefs_top_level_modules");
}

static void
free_pref(gpointer data, gpointer user_data _U_)
{
    pref_t *pref = data;

    switch (pref->type) {
    case PREF_OBSOLETE:
    case PREF_BOOL:
    case PREF_ENUM:
    case PREF_UINT:
    case PREF_STATIC_TEXT:
    case PREF_UAT:
    case PREF_COLOR:
        break;
    case PREF_STRING:
    case PREF_FILENAME:
        g_free((char *)*pref->varp.string);
        *pref->varp.string = NULL;
        g_free(pref->default_val.string);
        break;
    case PREF_RANGE:
        g_free(*pref->varp.range);
        *pref->varp.range = NULL;
        g_free(pref->default_val.range);
        break;
    case PREF_CUSTOM:
        pref->custom_cbs.free_cb(pref);
        break;
    }

    g_free(pref);
}

static guint
free_module_prefs(module_t *module, gpointer data _U_)
{
    g_list_foreach(module->prefs, free_pref, NULL);
    g_list_free(module->prefs);
    module->prefs = NULL;
    module->numprefs = 0;
    /*  We don't free the actual module: its submodules pointer points to
        a pe_tree and the module itself is stored in a pe_tree
     */

    return 0;
}

/** Frees memory used by proto routines. Called at program shutdown */
void
prefs_cleanup(void)
{
    /*  This isn't strictly necessary since we're exiting anyway, but let's
     *  do what clean up we can.
     */
    prefs_modules_foreach(free_module_prefs, NULL);
}

/*
 * Register a module that will have preferences.
 * Specify the module under which to register it or NULL to register it
 * at the top level, the name used for the module in the preferences file,
 * the title used in the tab for it in a preferences dialog box, and a
 * routine to call back when we apply the preferences.
 */
module_t *
prefs_register_module(module_t *parent, const char *name, const char *title,
                      const char *description, void (*apply_cb)(void),
                      const gboolean use_gui)
{
    return prefs_register_module_or_subtree(parent, name, title, description,
                                            FALSE, apply_cb, use_gui);
}

/*
 * Register a subtree that will have modules under it.
 * Specify the module under which to register it or NULL to register it
 * at the top level and the title used in the tab for it in a preferences
 * dialog box.
 */
module_t *
prefs_register_subtree(module_t *parent, const char *title, const char *description,
                       void (*apply_cb)(void))
{
    return prefs_register_module_or_subtree(parent, NULL, title, description,
                                            TRUE, apply_cb,
                                            parent ? parent->use_gui : FALSE);
}

static module_t *
prefs_register_module_or_subtree(module_t *parent, const char *name,
                                 const char *title, const char *description,
                                 gboolean is_subtree, void (*apply_cb)(void),
                                 gboolean use_gui)
{
    module_t *module;
    const char *p;
    guchar c;

    /* this module may have been created as a subtree item previously */
    if((module = find_subtree(parent, title))) {
        /* the module is currently a subtree */
        module->name = name;
        module->apply_cb = apply_cb;
        module->description = description;

        if (prefs_find_module(name) == NULL) {
            pe_tree_insert_string(prefs_modules, name, module,
                                  EMEM_TREE_STRING_NOCASE);
        }

        return module;
    }

    module = g_malloc(sizeof (module_t));
    module->name = name;
    module->title = title;
    module->description = description;
    module->apply_cb = apply_cb;
    module->prefs = NULL;    /* no preferences, to start */
    module->parent = parent;
    module->submodules = NULL;    /* no submodules, to start */
    module->numprefs = 0;
    module->prefs_changed = FALSE;
    module->obsolete = FALSE;
    module->use_gui = use_gui;

    /*
     * Do we have a module name?
     */
    if (name != NULL) {
        /*
         * Yes.
         * Make sure that only lower-case ASCII letters, numbers,
         * underscores, hyphens, and dots appear in the name.
         *
         * Crash if there is, as that's an error in the code;
         * you can make the title a nice string with capitalization,
         * white space, punctuation, etc., but the name can be used
         * on the command line, and shouldn't require quoting,
         * shifting, etc.
         */
        for (p = name; (c = *p) != '\0'; p++)
            g_assert(isascii(c) &&
                (islower(c) || isdigit(c) || c == '_' ||
                 c == '-' || c == '.'));

        /*
         * Make sure there's not already a module with that
         * name.  Crash if there is, as that's an error in the
         * code, and the code has to be fixed not to register
         * more than one module with the same name.
         *
         * We search the list of all modules; the subtree stuff
         * doesn't require preferences in subtrees to have names
         * that reflect the subtree they're in (that would require
         * protocol preferences to have a bogus "protocol.", or
         * something such as that, to be added to all their names).
         */
        g_assert(prefs_find_module(name) == NULL);

        /*
         * Insert this module in the list of all modules.
         */
        pe_tree_insert_string(prefs_modules, name, module, EMEM_TREE_STRING_NOCASE);
    } else {
        /*
         * This has no name, just a title; check to make sure it's a
         * subtree, and crash if it's not.
         */
        g_assert(is_subtree);
    }

    /*
     * Insert this module into the appropriate place in the display
     * tree.
     */
    if (parent == NULL) {
        /*
         * It goes at the top.
         */
        pe_tree_insert_string(prefs_top_level_modules, title, module, EMEM_TREE_STRING_NOCASE);
    } else {
        /*
         * It goes into the list for this module.
         */

        if (parent->submodules == NULL)
            parent->submodules = pe_tree_create(EMEM_TREE_TYPE_RED_BLACK, "prefs_submodules");

        pe_tree_insert_string(parent->submodules, title, module, EMEM_TREE_STRING_NOCASE);
    }

    return module;
}

/*
 * Register that a protocol has preferences.
 */
module_t *protocols_module = NULL;

module_t *
prefs_register_protocol(int id, void (*apply_cb)(void))
{
    protocol_t *protocol;

    /*
     * Have we yet created the "Protocols" subtree?
     */
    if (protocols_module == NULL) {
        /*
         * No.  Register Protocols subtree as well as any preferences
         * for non-dissector modules.
         */
        prefs_register_modules();
    }
    protocol = find_protocol_by_id(id);
    return prefs_register_module(protocols_module,
                                 proto_get_protocol_filter_name(id),
                                 proto_get_protocol_short_name(protocol),
                                 proto_get_protocol_name(id), apply_cb, TRUE);
}

module_t *
prefs_register_protocol_subtree(const char *subtree, int id, void (*apply_cb)(void))
{
    protocol_t *protocol;
    module_t   *subtree_module;
    module_t   *new_module;
    char       *sep = NULL, *ptr = NULL;

    /*
     * Have we yet created the "Protocols" subtree?
     * XXX - can we just do this by registering Protocols/{subtree}?
     * If not, why not?
     */
    if (protocols_module == NULL) {
        /*
         * No.  Register Protocols subtree as well as any preferences
         * for non-dissector modules.
         */
        prefs_register_modules();
    }

    subtree_module = protocols_module;

    if(subtree) {
        /* take a copy of the buffer */
        ptr = g_strdup(subtree);

        while(ptr && *ptr) {

            if((sep = strchr(ptr, '/')))
                *sep++ = '\0';

            if(!(new_module = find_subtree(subtree_module, ptr))) {
                /*
                 * There's no such module; create it, with the description
                 * being the name (if it's later registered explicitly
                 * with a description, that will override it).
                 */
                new_module = prefs_register_subtree(subtree_module, ptr, ptr, NULL);
            }

            subtree_module = new_module;
            ptr = sep;

        }
    }

    protocol = find_protocol_by_id(id);
    return prefs_register_module(subtree_module,
                                 proto_get_protocol_filter_name(id),
                                 proto_get_protocol_short_name(protocol),
                                 proto_get_protocol_name(id), apply_cb, TRUE);
}


/*
 * Register that a protocol used to have preferences but no longer does,
 * by creating an "obsolete" module for it.
 */
module_t *
prefs_register_protocol_obsolete(int id)
{
    module_t *module;
    protocol_t *protocol;

    /*
     * Have we yet created the "Protocols" subtree?
     */
    if (protocols_module == NULL) {
        /*
         * No.  Register Protocols subtree as well as any preferences
         * for non-dissector modules.
         */
        prefs_register_modules();
    }
    protocol = find_protocol_by_id(id);
    module = prefs_register_module(protocols_module,
                                   proto_get_protocol_filter_name(id),
                                   proto_get_protocol_short_name(protocol),
                                   proto_get_protocol_name(id), NULL, TRUE);
    module->obsolete = TRUE;
    return module;
}

/*
 * Register that a statistical tap has preferences.
 *
 * "name" is a name for the tap to use on the command line with "-o"
 * and in preference files.
 *
 * "title" is a short human-readable name for the tap.
 *
 * "description" is a longer human-readable description of the tap.
 */
module_t *stats_module = NULL;

module_t *
prefs_register_stat(const char *name, const char *title,
                    const char *description, void (*apply_cb)(void))
{
    /*
     * Have we yet created the "Statistics" subtree?
     */
    if (stats_module == NULL) {
        /*
         * No.  Register Statistics subtree as well as any preferences
         * for non-dissector modules.
         */
         prefs_register_modules();
    }

    return prefs_register_module(stats_module, name, title, description,
                                 apply_cb, TRUE);
}

module_t *
prefs_find_module(const char *name)
{
    return pe_tree_lookup_string(prefs_modules, name, EMEM_TREE_STRING_NOCASE);
}

static module_t *
find_subtree(module_t *parent, const char *name)
{
    return pe_tree_lookup_string(parent ? parent->submodules : prefs_top_level_modules, name, EMEM_TREE_STRING_NOCASE);
}

/*
 * Call a callback function, with a specified argument, for each module
 * in a list of modules.  If the list is NULL, searches the top-level
 * list in the display tree of modules.  If any callback returns a
 * non-zero value, we stop and return that value, otherwise we
 * return 0.
 *
 * Ignores "obsolete" modules; their sole purpose is to allow old
 * preferences for dissectors that no longer have preferences to be
 * silently ignored in preference files.  Does not ignore subtrees,
 * as this can be used when walking the display tree of modules.
 */

typedef struct {
    module_cb callback;
    gpointer user_data;
    guint ret;
} call_foreach_t;

static gboolean
call_foreach_cb(void *value, void *data)
{
    module_t *module = (module_t*)value;
    call_foreach_t *call_data = (call_foreach_t*)data;

    if (!module->obsolete) {
        call_data->ret = (*call_data->callback)(module, call_data->user_data);
    }
    return (call_data->ret != 0);
}

static guint
prefs_module_list_foreach(emem_tree_t *module_list, module_cb callback,
                          gpointer user_data)
{
    call_foreach_t call_data;

    if (module_list == NULL)
        module_list = prefs_top_level_modules;

    call_data.callback = callback;
    call_data.user_data = user_data;
    call_data.ret = 0;
    pe_tree_foreach(module_list, call_foreach_cb, &call_data);
    return call_data.ret;
}

/*
 * Returns TRUE if module has any submodules
 */
gboolean
prefs_module_has_submodules(module_t *module)
{
    if (module->submodules == NULL) {
        return FALSE;
    }

    if (module->submodules->tree == NULL) {
        return FALSE;
    }

    return TRUE;
}

/*
 * Call a callback function, with a specified argument, for each module
 * in the list of all modules.  (This list does not include subtrees.)
 *
 * Ignores "obsolete" modules; their sole purpose is to allow old
 * preferences for dissectors that no longer have preferences to be
 * silently ignored in preference files.
 */
guint
prefs_modules_foreach(module_cb callback, gpointer user_data)
{
    return prefs_module_list_foreach(prefs_modules, callback, user_data);
}

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
guint
prefs_modules_foreach_submodules(module_t *module, module_cb callback,
                                 gpointer user_data)
{
    return prefs_module_list_foreach((module)?module->submodules:prefs_top_level_modules, callback, user_data);
}

static gboolean
call_apply_cb(void *value, void *data _U_)
{
    module_t *module = value;

    if (module->obsolete)
        return FALSE;
    if (module->prefs_changed) {
        if (module->apply_cb != NULL)
            (*module->apply_cb)();
        module->prefs_changed = FALSE;
    }
    return FALSE;
}

/*
 * Call the "apply" callback function for each module if any of its
 * preferences have changed, and then clear the flag saying its
 * preferences have changed, as the module has been notified of that
 * fact.
 */
void
prefs_apply_all(void)
{
    pe_tree_foreach(prefs_modules, call_apply_cb, NULL);
}

/*
 * Call the "apply" callback function for a specific module if any of
 * its preferences have changed, and then clear the flag saying its
 * preferences have changed, as the module has been notified of that
 * fact.
 */
void
prefs_apply(module_t *module)
{
    if (module && module->prefs_changed)
        call_apply_cb(module, NULL);
}

/*
 * Register a preference in a module's list of preferences.
 * If it has a title, give it an ordinal number; otherwise, it's a
 * preference that won't show up in the UI, so it shouldn't get an
 * ordinal number (the ordinal should be the ordinal in the set of
 * *visible* preferences).
 */
static pref_t *
register_preference(module_t *module, const char *name, const char *title,
                    const char *description, pref_type_t type)
{
    pref_t *preference;
    const gchar *p;

    preference = g_malloc(sizeof (pref_t));
    preference->name = name;
    preference->title = title;
    preference->description = description;
    preference->type = type;
    if (title != NULL)
        preference->ordinal = module->numprefs;
    else
        preference->ordinal = -1;    /* no ordinal for you */

    /*
     * Make sure that only lower-case ASCII letters, numbers,
     * underscores, and dots appear in the preference name.
     *
     * Crash if there is, as that's an error in the code;
     * you can make the title and description nice strings
     * with capitalization, white space, punctuation, etc.,
     * but the name can be used on the command line,
     * and shouldn't require quoting, shifting, etc.
     */
    for (p = name; *p != '\0'; p++)
        if (!(isascii((guchar)*p) &&
            (islower((guchar)*p) || isdigit((guchar)*p) || *p == '_' || *p == '.')))
            g_error("Preference %s.%s contains invalid characters", module->name, name);

    /*
     * Make sure there's not already a preference with that
     * name.  Crash if there is, as that's an error in the
     * code, and the code has to be fixed not to register
     * more than one preference with the same name.
     */
    if (prefs_find_preference(module, name) != NULL)
        g_error("Preference %s has already been registered", name);

    if ((type != PREF_OBSOLETE) &&
        /* Don't compare if its a subtree */
        (module->name != NULL)) {
        /*
         * Make sure the preference name doesn't begin with the
         * module name, as that's redundant and Just Silly.
         */
        if(!((strncmp(name, module->name, strlen(module->name)) != 0) ||
            (((name[strlen(module->name)]) != '.') && ((name[strlen(module->name)]) != '_'))))
            g_error("Preference %s begins with the module name", name);
    }

    /*
     * There isn't already one with that name, so add the
     * preference.
     */
    module->prefs = g_list_append(module->prefs, preference);
    if (title != NULL)
        module->numprefs++;

    return preference;
}

/*
 * Find a preference in a module's list of preferences, given the module
 * and the preference's name.
 */
typedef struct {
    GList *list_entry;
    const char *name;
} find_pref_arg_t;

static gint
preference_match(gconstpointer a, gconstpointer b)
{
    const pref_t *pref = a;
    const char *name = b;

    return strcmp(name, pref->name);
}

static gboolean module_find_pref_cb(void *value, void *data)
{
    find_pref_arg_t* arg = (find_pref_arg_t*)data;
    GList *list_entry;
    module_t *module = value;

    if (module == NULL)
        return FALSE;

    list_entry = g_list_find_custom(module->prefs, arg->name,
        preference_match);

    if (list_entry == NULL)
        return FALSE;

    arg->list_entry = list_entry;
    return TRUE;
}

struct preference *
prefs_find_preference(module_t *module, const char *name)
{
    find_pref_arg_t arg;
    GList *list_entry;

    if (module == NULL)
        return NULL;    /* invalid parameters */

    list_entry = g_list_find_custom(module->prefs, name,
        preference_match);

    if (list_entry == NULL)
    {
        arg.list_entry = NULL;
        if (module->submodules != NULL)
        {
            arg.name = name;
            pe_tree_foreach(module->submodules, module_find_pref_cb, &arg);
        }

        list_entry = arg.list_entry;
    }

    if (list_entry == NULL)
    {
        return NULL;    /* no such preference */
    }

    return (struct preference *) list_entry->data;
}

/*
 * Returns TRUE if the given protocol has registered preferences
 */
gboolean
prefs_is_registered_protocol(const char *name)
{
    module_t *m = prefs_find_module(name);

    return (m != NULL && !m->obsolete);
}

/*
 * Returns the module title of a registered protocol
 */
const char *
prefs_get_title_by_name(const char *name)
{
    module_t *m = prefs_find_module(name);

    return (m != NULL && !m->obsolete) ? m->title : NULL;
}

/*
 * Register a preference with an unsigned integral value.
 */
void
prefs_register_uint_preference(module_t *module, const char *name,
                               const char *title, const char *description,
                               guint base, guint *var)
{
    pref_t *preference;

    preference = register_preference(module, name, title, description,
                                     PREF_UINT);
    preference->varp.uint = var;
    preference->default_val.uint = *var;
    g_assert(base > 0 && base != 1 && base < 37);
    preference->info.base = base;
}

/*
 * Register a "custom" preference with a unsigned integral value.
 * XXX - This should be temporary until we can find a better way
 * to do "custom" preferences
 */
static void
prefs_register_uint_custom_preference(module_t *module, const char *name,
                               const char *title, const char *description,
                               struct pref_custom_cbs* custom_cbs, guint *var)
{
    pref_t *preference;

    preference = register_preference(module, name, title, description,
                                     PREF_CUSTOM);

    preference->custom_cbs = *custom_cbs;
    preference->varp.uint = var;
    preference->default_val.uint = *var;
}

/*
 * Register a preference with an Boolean value.
 */
void
prefs_register_bool_preference(module_t *module, const char *name,
                               const char *title, const char *description,
                               gboolean *var)
{
    pref_t *preference;

    preference = register_preference(module, name, title, description,
                                     PREF_BOOL);
    preference->varp.boolp = var;
    preference->default_val.boolval = *var;
}

/*
 * Register a preference with an enumerated value.
 */
void
prefs_register_enum_preference(module_t *module, const char *name,
                               const char *title, const char *description,
                               gint *var, const enum_val_t *enumvals,
                               gboolean radio_buttons)
{
    pref_t *preference;

    preference = register_preference(module, name, title, description,
                                     PREF_ENUM);
    preference->varp.enump = var;
    preference->default_val.enumval = *var;
    preference->info.enum_info.enumvals = enumvals;
    preference->info.enum_info.radio_buttons = radio_buttons;
}

static pref_t*
register_string_like_preference(module_t *module, const char *name,
                                const char *title, const char *description,
                                const char **var, pref_type_t type)
{
    pref_t *preference;
    char *varcopy;

    preference = register_preference(module, name, title, description,
                                     type);

    /*
     * String preference values should be non-null (as you can't
     * keep them null after using the preferences GUI, you can at best
     * have them be null strings) and freeable (as we free them
     * if we change them).
     *
     * If the value is a null pointer, make it a copy of a null
     * string, otherwise make it a copy of the value.
     */
    if (*var == NULL) {
        *var = g_strdup("");
        varcopy = g_strdup("");
    } else {
        *var = g_strdup(*var);
        varcopy = g_strdup(*var);
    }
    preference->varp.string = var;
    preference->default_val.string = varcopy;
    preference->saved_val.string = NULL;

    return preference;
}

/*
 * Register a preference with a character-string value.
 */
void
prefs_register_string_preference(module_t *module, const char *name,
                                 const char *title, const char *description,
                                 const char **var)
{
    register_string_like_preference(module, name, title, description, var,
                                    PREF_STRING);
}

/*
 * Register a "custom" preference with a character-string value.
 * XXX - This should be temporary until we can find a better way
 * to do "custom" preferences
 */
static
void prefs_register_string_custom_preference(module_t *module, const char *name,
                                 const char *title, const char *description,
                                 struct pref_custom_cbs* custom_cbs, const char **var)
{
    pref_t *preference;

    preference = register_string_like_preference(module, name, title, description, var,
                                    PREF_CUSTOM);

    preference->custom_cbs = *custom_cbs;
}


/*
 * Register a preference with a file name (string) value.
 */
void
prefs_register_filename_preference(module_t *module, const char *name,
                                   const char *title, const char *description,
                                   const char **var)
{
    register_string_like_preference(module, name, title, description, var,
                                    PREF_FILENAME);
}

/*
 * Register a preference with a ranged value.
 */
void
prefs_register_range_preference(module_t *module, const char *name,
                                const char *title, const char *description,
                                range_t **var, guint32 max_value)
{
    pref_t *preference;

    preference = register_preference(module, name, title, description,
                                     PREF_RANGE);
    preference->info.max_value = max_value;


    /*
     * Range preference values should be non-null (as you can't
     * keep them null after using the preferences GUI, you can at best
     * have them be empty ranges) and freeable (as we free them
     * if we change them).
     *
     * If the value is a null pointer, make it an empty range.
     */
    if (*var == NULL)
        *var = range_empty();
    preference->varp.range = var;
    preference->default_val.range = range_copy(*var);
    preference->saved_val.range = NULL;
}

/*
 * Register a static text 'preference'.  It can be used to add explanatory
 * text inline with other preferences in the GUI.
 * Note: Static preferences are not saved to the preferences file.
 */
void
prefs_register_static_text_preference(module_t *module, const char *name,
                                      const char *title,
                                      const char *description)
{
    register_preference(module, name, title, description, PREF_STATIC_TEXT);
}

/*
 * Register a uat 'preference'. It adds a button that opens the uat's window in the
 * preferences tab of the module.
 */
extern void
prefs_register_uat_preference(module_t *module, const char *name,
                              const char *title, const char *description,
                              void* uat)
{

    pref_t* preference = register_preference(module, name, title, description, PREF_UAT);

    preference->varp.uat = uat;
}

/*
 * Register a color preference.
 */
void prefs_register_color_preference(module_t *module, const char *name,
    const char *title, const char *description, color_t *color)
{
    pref_t* preference = register_preference(module, name, title, description, PREF_COLOR);

    preference->varp.color = color;
    preference->default_val.color = *color;
}

/*
 * Register a "custom" preference with a list.
 * XXX - This should be temporary until we can find a better way
 * to do "custom" preferences
 */
typedef void (*pref_custom_list_init_cb) (pref_t* pref, GList** value);

static
void prefs_register_list_custom_preference(module_t *module, const char *name,
    const char *title, const char *description, struct pref_custom_cbs* custom_cbs,
    pref_custom_list_init_cb init_cb, GList** list)
{
    pref_t* preference = register_preference(module, name, title, description, PREF_CUSTOM);

    preference->custom_cbs = *custom_cbs;
    init_cb(preference, list);
}

/*
 * Register a custom preference.
 */
void prefs_register_custom_preference(module_t *module, const char *name,
    const char *title, const char *description, struct pref_custom_cbs* custom_cbs,
    void** custom_data _U_)
{
    pref_t* preference = register_preference(module, name, title, description, PREF_CUSTOM);

    preference->custom_cbs = *custom_cbs;
    /* XXX - wait until we can handle void** pointers
    preference->custom_cbs.init_cb(preference, custom_data);
    */
}

/*
 * Register a preference that used to be supported but no longer is.
 */
void
prefs_register_obsolete_preference(module_t *module, const char *name)
{
    register_preference(module, name, NULL, NULL, PREF_OBSOLETE);
}

/*
 * Check to see if a preference is obsolete.
 */
extern gboolean
prefs_get_preference_obsolete(pref_t *pref)
{
    if (pref) {
        return pref->type == PREF_OBSOLETE ? TRUE : FALSE;
    }
    return TRUE;
}

/*
 * Make a preference obsolete.
 */
extern prefs_set_pref_e
prefs_set_preference_obsolete(pref_t *pref)
{
    if (pref) {
        pref->type = PREF_OBSOLETE;
        return PREFS_SET_OK;
    }
    return PREFS_SET_NO_SUCH_PREF;
}

/* Return the value assigned to the given uint preference. */
guint prefs_get_uint_preference(pref_t *pref)
{
    if (pref && pref->type == PREF_UINT)
        return *pref->varp.uint;
    return 0;
}

/*
 * Call a callback function, with a specified argument, for each preference
 * in a given module.
 *
 * If any of the callbacks return a non-zero value, stop and return that
 * value, otherwise return 0.
 */
guint
prefs_pref_foreach(module_t *module, pref_cb callback, gpointer user_data)
{
    GList *elem;
    pref_t *pref;
    guint ret;

    for (elem = g_list_first(module->prefs); elem != NULL; elem = g_list_next(elem)) {
        pref = elem->data;
        if (pref->type == PREF_OBSOLETE) {
            /*
             * This preference is no longer supported; it's
             * not a real preference, so we don't call the
             * callback for it (i.e., we treat it as if it
             * weren't found in the list of preferences,
             * and we weren't called in the first place).
             */
            continue;
        }

        ret = (*callback)(pref, user_data);
        if (ret != 0)
            return ret;
    }
    return 0;
}

static const enum_val_t print_format_vals[] = {
    { "text",       "Plain Text", PR_FMT_TEXT },
    { "postscript", "Postscript", PR_FMT_PS },
    { NULL,         NULL,         0 }
};

static const enum_val_t print_dest_vals[] = {
#ifdef _WIN32
    /* "PR_DEST_CMD" means "to printer" on Windows */
    { "command", "Printer", PR_DEST_CMD },
#else
    { "command", "Command", PR_DEST_CMD },
#endif
    { "file",    "File",    PR_DEST_FILE },
    { NULL,      NULL,      0 }
};

static void stats_callback(void)
{
    /* Test for a sane tap update interval */
    if (prefs.tap_update_interval < 100 || prefs.tap_update_interval > 10000) {
            prefs.tap_update_interval = TAP_UPDATE_DEFAULT_INTERVAL;
    }

#ifdef HAVE_LIBPORTAUDIO
    /* Test for a sane max channels entry */
    if (prefs.rtp_player_max_visible < 1 || prefs.rtp_player_max_visible > 10)
            prefs.rtp_player_max_visible = RTP_PLAYER_DEFAULT_VISIBLE;
#endif

}

static void gui_callback(void)
{
    /* Ensure there is at least one file count */
    if (prefs.gui_recent_files_count_max == 0)
      prefs.gui_recent_files_count_max = 10;

    /* Ensure there is at least one display filter entry */
    if (prefs.gui_recent_df_entries_max == 0)
      prefs.gui_recent_df_entries_max = 10;
}

static void gui_layout_callback(void)
{
    if (prefs.gui_layout_type == layout_unused ||
        prefs.gui_layout_type >= layout_type_max) {
      /* XXX - report an error?  It's not a syntax error - we'd need to
         add a way of reporting a *semantic* error. */
      prefs.gui_layout_type = layout_type_5;
    }
}

/******************************************************
 * All custom preference function callbacks
 ******************************************************/
static void custom_pref_no_cb(pref_t* pref _U_) {}


/*
 * Console log level custom preference functions
 */
static void console_log_level_reset_cb(pref_t* pref)
{
    *pref->varp.uint = pref->default_val.uint;
}

static prefs_set_pref_e console_log_level_set_cb(pref_t* pref, gchar* value, gboolean* changed)
{
    guint    uval;

    uval = strtoul(value, NULL, 10);

    if (*pref->varp.uint != uval) {
        *changed = TRUE;
        *pref->varp.uint = uval;
    }

    if (*pref->varp.uint & (G_LOG_LEVEL_INFO|G_LOG_LEVEL_DEBUG)) {
      /*
       * GLib >= 2.32 drops INFO and DEBUG messages by default. Tell
       * it not to do that.
       */
       g_setenv("G_MESSAGES_DEBUG", "all", TRUE);
    }

    return PREFS_SET_OK;
}

static void console_log_level_write_cb(pref_t* pref, write_pref_arg_t* arg)
{
    const char *prefix = (arg->module->name != NULL) ? arg->module->name : arg->module->parent->name;

    fprintf(arg->pf, "# (debugging only, not in the Preferences dialog)\n");
    fprintf(arg->pf, "# A bitmask of glib log levels:\n"
          "# G_LOG_LEVEL_ERROR    = 4\n"
          "# G_LOG_LEVEL_CRITICAL = 8\n"
          "# G_LOG_LEVEL_WARNING  = 16\n"
          "# G_LOG_LEVEL_MESSAGE  = 32\n"
          "# G_LOG_LEVEL_INFO     = 64\n"
          "# G_LOG_LEVEL_DEBUG    = 128\n");

    if (*pref->varp.uint == pref->default_val.uint)
        fprintf(arg->pf, "#");
    fprintf(arg->pf, "%s.%s: %u\n", prefix,
                pref->name, *pref->varp.uint);
}

/*
 * Column hidden custom preference functions
 */
#define PRS_COL_HIDDEN                   "column.hidden"
#define PRS_COL_FMT                      "column.format"
#define PRS_COL_NUM                      "column.number"
static module_t *gui_column_module = NULL;

static void column_hidden_free_cb(pref_t* pref)
{
    g_free((char *)*pref->varp.string);
    *pref->varp.string = NULL;
    g_free(pref->default_val.string);
}

static void column_hidden_reset_cb(pref_t* pref)
{
    g_free((void *)*pref->varp.string);
    *pref->varp.string = g_strdup(pref->default_val.string);
}

static prefs_set_pref_e column_hidden_set_cb(pref_t* pref, gchar* value, gboolean* changed)
{
    GList       *clp;
    fmt_data    *cfmt;
    pref_t  *format_pref;

    if (*pref->varp.string && (strcmp(*pref->varp.string, value) != 0)) {
        *changed = TRUE;
        g_free((void *)*pref->varp.string);
        *pref->varp.string = g_strdup(value);
    }

    /*
     * Set the "visible" flag for the existing columns; we need to
     * do this if we set PRS_COL_HIDDEN but don't set PRS_COL_FMT
     * after setting it (which might be the case if, for example, we
     * set PRS_COL_HIDDEN on the command line).
     */
    format_pref = prefs_find_preference(gui_column_module, PRS_COL_FMT);
    for (clp = *format_pref->varp.list; clp != NULL; clp = clp->next) {
      cfmt = (fmt_data *)clp->data;
      cfmt->visible = prefs_is_column_visible(*pref->varp.string, cfmt);
    }

    return PREFS_SET_OK;
}

static void column_hidden_write_cb(pref_t* pref, write_pref_arg_t* arg)
{
  GString     *cols_hidden = g_string_new ("");
  GList       *clp, *col_l;
  fmt_data    *cfmt;
  const char *prefix = (arg->module->name != NULL) ? arg->module->name : arg->module->parent->name;
  pref_t  *format_pref;

  format_pref = prefs_find_preference(gui_column_module, PRS_COL_FMT);
  clp = *format_pref->varp.list;
  col_l = NULL;
  while (clp) {
    gchar *prefs_fmt;
    cfmt = (fmt_data *) clp->data;
    col_l = g_list_append(col_l, g_strdup(cfmt->title));
    if ((cfmt->fmt == COL_CUSTOM) && (cfmt->custom_field)) {
      prefs_fmt = g_strdup_printf("%s:%s:%d:%c",
                                  col_format_to_string(cfmt->fmt),
                                  cfmt->custom_field,
                                  cfmt->custom_occurrence,
                                  cfmt->resolved ? 'R' : 'U');
    } else {
      prefs_fmt = g_strdup(col_format_to_string(cfmt->fmt));
    }
    col_l = g_list_append(col_l, prefs_fmt);
    if (!cfmt->visible) {
      if (cols_hidden->len) {
	     g_string_append (cols_hidden, ",");
      }
      g_string_append (cols_hidden, prefs_fmt);
    }
    clp = clp->next;
  }
  fprintf (arg->pf, "\n# Packet list hidden columns.\n");
  fprintf (arg->pf, "# List all columns to hide in the packet list.\n");
  if (strcmp(cols_hidden->str, pref->default_val.string) == 0)
    fprintf(arg->pf, "#");
  fprintf (arg->pf, "%s.%s: %s\n", prefix, pref->name, cols_hidden->str);
  /* This frees the list of strings, but not the strings to which it
     refers; they are free'ed in write_string_list(). */
  g_string_free (cols_hidden, TRUE);
  g_list_free(col_l);
}

/* Number of columns "preference".  This is only used internally and is not written to the
 * preference file
 */
static void column_num_reset_cb(pref_t* pref)
{
    *pref->varp.uint = pref->default_val.uint;
}

static prefs_set_pref_e column_num_set_cb(pref_t* pref _U_, gchar* value _U_, gboolean* changed _U_)
{
    /* Don't write this to the preferences file */
    return PREFS_SET_OK;
}

static void column_num_write_cb(pref_t* pref _U_, write_pref_arg_t* arg _U_) {}

/*
 * Column format custom preference functions
 */
static void column_format_init_cb(pref_t* pref, GList** value)
{
    fmt_data *src_cfmt, *dest_cfmt;
    GList *entry;

    pref->varp.list = value;

    pref->default_val.list = NULL;
    for (entry = *pref->varp.list; entry != NULL; entry = g_list_next(entry)) {
        src_cfmt = entry->data;
        dest_cfmt = (fmt_data *) g_malloc(sizeof(fmt_data));
        dest_cfmt->title = g_strdup(src_cfmt->title);
        dest_cfmt->fmt = src_cfmt->fmt;
        if (src_cfmt->custom_field) {
            dest_cfmt->custom_field = g_strdup(src_cfmt->custom_field);
            dest_cfmt->custom_occurrence = src_cfmt->custom_occurrence;
        } else {
            dest_cfmt->custom_field = NULL;
            dest_cfmt->custom_occurrence = 0;
        }
        dest_cfmt->visible = src_cfmt->visible;
        dest_cfmt->resolved = src_cfmt->resolved;
        pref->default_val.list = g_list_append(pref->default_val.list, dest_cfmt);
    }
}

static void column_format_free_cb(pref_t* pref)
{
    free_col_info(*pref->varp.list);
    free_col_info(pref->default_val.list);
}

static void column_format_reset_cb(pref_t* pref)
{
    fmt_data *src_cfmt, *dest_cfmt;
    GList *entry;
    pref_t  *col_num_pref;

    free_col_info(*pref->varp.list);
    *pref->varp.list = NULL;

    for (entry = pref->default_val.list; entry != NULL; entry = g_list_next(entry)) {
        src_cfmt = entry->data;
        dest_cfmt = (fmt_data *) g_malloc(sizeof(fmt_data));
        dest_cfmt->title = g_strdup(src_cfmt->title);
        dest_cfmt->fmt = src_cfmt->fmt;
        if (src_cfmt->custom_field) {
            dest_cfmt->custom_field = g_strdup(src_cfmt->custom_field);
            dest_cfmt->custom_occurrence = src_cfmt->custom_occurrence;
        } else {
            dest_cfmt->custom_field = NULL;
            dest_cfmt->custom_occurrence = 0;
        }
        dest_cfmt->visible = src_cfmt->visible;
        dest_cfmt->resolved = src_cfmt->resolved;
        *pref->varp.list = g_list_append(*pref->varp.list, dest_cfmt);
    }

    col_num_pref = prefs_find_preference(gui_column_module, PRS_COL_NUM);
    column_num_reset_cb(col_num_pref);
}

static prefs_set_pref_e column_format_set_cb(pref_t* pref, gchar* value, gboolean* changed _U_)
{
    GList    *col_l, *col_l_elt;
    fmt_data *cfmt;
    gint     llen;
    pref_t   *hidden_pref, *col_num_pref;

    col_l = prefs_get_string_list(value);
    if (col_l == NULL)
      return PREFS_SET_SYNTAX_ERR;
    if ((g_list_length(col_l) % 2) != 0) {
      /* A title didn't have a matching format.  */
      prefs_clear_string_list(col_l);
      return PREFS_SET_SYNTAX_ERR;
    }
    /* Check to make sure all column formats are valid.  */
    col_l_elt = g_list_first(col_l);
    while(col_l_elt) {
      fmt_data cfmt_check;

      /* Go past the title.  */
      col_l_elt = col_l_elt->next;

      /* Parse the format to see if it's valid.  */
      if (!parse_column_format(&cfmt_check, col_l_elt->data)) {
        /* It's not a valid column format.  */
        prefs_clear_string_list(col_l);
        return PREFS_SET_SYNTAX_ERR;
      }
      if (cfmt_check.fmt != COL_CUSTOM) {
        /* Some predefined columns have been migrated to use custom colums.
         * We'll convert these silently here */
        try_convert_to_custom_column(&col_l_elt->data);
      } else {
        /* We don't need the custom column field on this pass. */
        g_free(cfmt_check.custom_field);
      }

      /* Go past the format.  */
      col_l_elt = col_l_elt->next;
    }

    /* They're all valid; process them. */
    free_col_info(*pref->varp.list);
    *pref->varp.list = NULL;
    hidden_pref = prefs_find_preference(gui_column_module, PRS_COL_HIDDEN);
    col_num_pref = prefs_find_preference(gui_column_module, PRS_COL_NUM);
    llen             = g_list_length(col_l);
    *col_num_pref->varp.uint = llen / 2;
    col_l_elt = g_list_first(col_l);
    while(col_l_elt) {
      cfmt = (fmt_data *) g_malloc(sizeof(fmt_data));
      cfmt->title    = g_strdup(col_l_elt->data);
      col_l_elt      = col_l_elt->next;
      parse_column_format(cfmt, col_l_elt->data);
      cfmt->visible   = prefs_is_column_visible((gchar*)(*hidden_pref->varp.string), cfmt);
      col_l_elt      = col_l_elt->next;
      *pref->varp.list = g_list_append(*pref->varp.list, cfmt);
    }

    prefs_clear_string_list(col_l);
    column_hidden_free_cb(hidden_pref);
    return PREFS_SET_OK;
}

static void column_format_write_cb(pref_t* pref, write_pref_arg_t* arg)
{
  GList       *clp = *pref->varp.list, *col_l,
              *pref_col = g_list_first(clp),
              *def_col = g_list_first(pref->default_val.list);
  fmt_data    *cfmt, *def_cfmt;
  gchar       *prefs_fmt;
  gboolean    is_default = TRUE;
  pref_t      *col_num_pref;
  const char *prefix = (arg->module->name != NULL) ? arg->module->name : arg->module->parent->name;

  /* See if the column data has changed from the default */
  col_num_pref = prefs_find_preference(gui_column_module, PRS_COL_NUM);
  if (*col_num_pref->varp.uint != col_num_pref->default_val.uint) {
     is_default = FALSE;
  } else {
      while (pref_col && def_col) {
          cfmt = (fmt_data *) pref_col->data;
          def_cfmt = (fmt_data *) def_col->data;
          if ((strcmp(cfmt->title, def_cfmt->title) != 0) ||
              (cfmt->fmt != def_cfmt->fmt) ||
              (((cfmt->fmt == COL_CUSTOM) && (cfmt->custom_field)) &&
                 ((strcmp(cfmt->custom_field, def_cfmt->custom_field) != 0) ||
                 (cfmt->resolved != def_cfmt->resolved)))) {
             is_default = FALSE;
             break;
          }

          pref_col = pref_col->next;
          def_col = def_col->next;
      }
  }

  /* Now write the current columns */
  col_l = NULL;
  while (clp) {
    cfmt = (fmt_data *) clp->data;
    col_l = g_list_append(col_l, g_strdup(cfmt->title));
    if ((cfmt->fmt == COL_CUSTOM) && (cfmt->custom_field)) {
      prefs_fmt = g_strdup_printf("%s:%s:%d:%c",
                                  col_format_to_string(cfmt->fmt),
                                  cfmt->custom_field,
                                  cfmt->custom_occurrence,
                                  cfmt->resolved ? 'R' : 'U');
    } else {
      prefs_fmt = g_strdup(col_format_to_string(cfmt->fmt));
    }
    col_l = g_list_append(col_l, prefs_fmt);
    clp = clp->next;
  }

  fprintf (arg->pf, "\n# Packet list column format.\n");
  fprintf (arg->pf, "# Each pair of strings consists of a column title and its format.\n");
  if (is_default)
     fprintf(arg->pf, "#");
  fprintf(arg->pf, "%s.%s: ", prefix, pref->name);
  write_string_list(arg->pf, col_l, is_default);
  fprintf(arg->pf, "\n");
  /* This frees the list of strings, but not the strings to which it
     refers; they are free'ed in write_string_list(). */
  g_list_free(col_l);
}

/*
 * Capture column custom preference functions
 */
static void capture_column_init_cb(pref_t* pref, GList** value)
{
    GList   *list = *value,
            *list_copy = NULL;
    gchar   *col;

    pref->varp.list = value;
    /* Copy the current list */
    while (list) {
        col = (gchar *)list->data;
        list_copy = g_list_append(list_copy, g_strdup(col));
        list = list->next;
    }

    pref->default_val.list = list_copy;
}

static void capture_column_free_cb(pref_t* pref)
{
    GList   *list = *pref->varp.list;
    gchar    *col_name;

    while (list != NULL) {
        col_name = list->data;

        g_free(col_name);
        list = g_list_remove_link(list, list);
    }
    g_list_free(list);

    list = pref->default_val.list;
    while (list != NULL) {
        col_name = list->data;

        g_free(col_name);
        list = g_list_remove_link(list, list);
    }
    g_list_free(list);
}

static void capture_column_reset_cb(pref_t* pref)
{
    GList   *list_copy = *pref->varp.list,
            *list = pref->default_val.list;
    gchar    *col_name;

    /* Clear the list before it's copied */
    while (list_copy != NULL) {
        col_name = list_copy->data;

        g_free(col_name);
        list_copy = g_list_remove_link(list_copy, list_copy);
    }

    while (list) {
        col_name = (gchar *)list->data;
        list_copy = g_list_append(list_copy, g_strdup(col_name));
        list = list->next;
    }
}

static prefs_set_pref_e capture_column_set_cb(pref_t* pref, gchar* value, gboolean* changed _U_)
{
    GList    *col_l, *col_l_elt;
    gchar    *col_name;

    col_l = prefs_get_string_list(value);
    if (col_l == NULL)
      return PREFS_SET_SYNTAX_ERR;

    g_list_free(*pref->varp.list);
    *pref->varp.list = NULL;

    col_l_elt = g_list_first(col_l);
    while(col_l_elt) {
      col_name = (gchar *)col_l_elt->data;
      *pref->varp.list = g_list_append(*pref->varp.list, col_name);
      col_l_elt = col_l_elt->next;
    }

    return PREFS_SET_OK;
}

static void capture_column_write_cb(pref_t* pref, write_pref_arg_t* arg)
{
  GList       *clp = *pref->varp.list,
              *col_l = NULL,
              *pref_col = g_list_first(clp),
              *def_col = g_list_first(pref->default_val.list);
  gchar *col, *def_col_str;
  gboolean is_default = TRUE;
  const char *prefix = (arg->module->name != NULL) ? arg->module->name : arg->module->parent->name;

  /* See if the column data has changed from the default */
  while (pref_col && def_col) {
      col = (gchar *)pref_col->data;
      def_col_str = (gchar *) def_col->data;
      if (strcmp(col, def_col_str) != 0) {
         is_default = FALSE;
         break;
      }

      pref_col = pref_col->next;
      def_col = def_col->next;
  }

  /* Ensure the same column count */
  if (((pref_col == NULL) && (def_col != NULL)) ||
      ((pref_col != NULL) && (def_col == NULL)))
     is_default = FALSE;

  while (clp) {
    col = (gchar *) clp->data;
    col_l = g_list_append(col_l, g_strdup(col));
    clp = clp->next;
  }

  fprintf(arg->pf, "\n# Capture options dialog column list.\n");
  fprintf(arg->pf, "# List of columns to be displayed.\n");
  fprintf(arg->pf, "# Possible values: INTERFACE,LINK,PMODE,SNAPLEN,MONITOR,BUFFER,FILTER\n");
  if (is_default)
     fprintf(arg->pf, "#");
  fprintf(arg->pf, "%s.%s: ", prefix, pref->name);
  write_string_list(arg->pf, col_l, is_default);
  fprintf(arg->pf, "\n");
  /* This frees the list of strings, but not the strings to which it
     refers; they are free'ed in write_string_list(). */
  g_list_free(col_l);

}


static void colorized_frame_free_cb(pref_t* pref)
{
    g_free((char *)*pref->varp.string);
    *pref->varp.string = NULL;
    g_free(pref->default_val.string);
}

static void colorized_frame_reset_cb(pref_t* pref)
{
    g_free((void *)*pref->varp.string);
    *pref->varp.string = g_strdup(pref->default_val.string);
}

static prefs_set_pref_e colorized_frame_set_cb(pref_t* pref, gchar* value, gboolean* changed)
{
    if (strcmp(*pref->varp.string, value) != 0) {
        *changed = TRUE;
        g_free((void *)*pref->varp.string);
        *pref->varp.string = g_strdup(value);
    }

    return PREFS_SET_OK;
}

static void colorized_frame_write_cb(pref_t* pref _U_, write_pref_arg_t* arg _U_)
{
   /* Don't write the colors of the 10 easy-access-colorfilters to the preferences
    * file until the colors can be changed in the GUI. Currently this is not really
    * possible since the STOCK-icons for these colors are hardcoded.
    *
    * XXX Find a way to change the colors of the STOCK-icons on the fly and then
    *     add these 10 colors to the list of colors that can be changed through
    *     the preferences.
    *
    */
}

/*
 * Register all non-dissector modules' preferences.
 */
static module_t *gui_module = NULL;
static module_t *gui_color_module = NULL;
static module_t *nameres_module = NULL;

void
prefs_register_modules(void)
{
    module_t *printing, *capture_module, *console_module,
        *gui_layout_module, *gui_font_module;
    struct pref_custom_cbs custom_cbs;

    if (protocols_module != NULL) {
        /* Already setup preferences */
        return;
    }

    /* Ensure the "global" preferences have been initialized so the
     * preference API has the proper default values to work from
     */
    pre_init_prefs();

    /* GUI
     * These are "simple" GUI preferences that can be read/written using the
     * preference module API.  These preferences still use their own
     * configuration screens for access, but this cuts down on the
     * preference "string compare list" in set_pref()
     */
    gui_module = prefs_register_module(NULL, "gui", "User Interface",
        "User Interface", &gui_callback, FALSE);

    prefs_register_bool_preference(gui_module, "scrollbar_on_right",
                                   "Vertical scrollbars on right side",
                                   "Vertical scrollbars should be on right side?",
                                   &prefs.gui_scrollbar_on_right);

    prefs_register_bool_preference(gui_module, "packet_list_sel_browse",
                                   "Packet-list selection bar browse",
                                   "Packet-list selection bar can be used to browse w/o selecting?",
                                   &prefs.gui_plist_sel_browse);

    prefs_register_bool_preference(gui_module, "protocol_tree_sel_browse",
                                   "Protocol-tree selection bar browse",
                                   "Protocol-tree selection bar can be used to browse w/o selecting?",
                                   &prefs.gui_ptree_sel_browse);

    prefs_register_bool_preference(gui_module, "tree_view_altern_colors",
                                   "Alternating colors in TreeViews",
                                   "Alternating colors in TreeViews?",
                                   &prefs.gui_altern_colors);

    prefs_register_bool_preference(gui_module, "expert_composite_eyecandy",
                                   "Display Icons on Expert Composite Dialog Tabs",
                                   "Display Icons on Expert Composite Dialog Tabs?",
                                   &prefs.gui_expert_composite_eyecandy);

    prefs_register_bool_preference(gui_module, "filter_toolbar_show_in_statusbar",
                                   "Place filter toolbar inside the statusbar",
                                   "Place filter toolbar inside the statusbar?",
                                   &prefs.filter_toolbar_show_in_statusbar);

    prefs_register_enum_preference(gui_module, "protocol_tree_line_style",
                       "Protocol-tree line style",
                       "Protocol-tree line style",
                       &prefs.gui_ptree_line_style, gui_ptree_line_style, FALSE);

    prefs_register_enum_preference(gui_module, "protocol_tree_expander_style",
                       "Protocol-tree expander style",
                       "Protocol-tree expander style",
                       &prefs.gui_ptree_expander_style, gui_ptree_expander_style, FALSE);

    prefs_register_enum_preference(gui_module, "hex_dump_highlight_style",
                       "Hex dump highlight style",
                       "Hex dump highlight style",
                       &prefs.gui_hex_dump_highlight_style, gui_hex_dump_highlight_style, FALSE);

    gui_column_module = prefs_register_subtree(gui_module, "Columns", "Columns", NULL);

    custom_cbs.free_cb = column_hidden_free_cb;
    custom_cbs.reset_cb = column_hidden_reset_cb;
    custom_cbs.set_cb = column_hidden_set_cb;
    custom_cbs.write_cb = column_hidden_write_cb;
    prefs_register_string_custom_preference(gui_column_module, PRS_COL_HIDDEN, "Packet list hidden columns",
        "List all columns to hide in the packet list", &custom_cbs, (const char **)&cols_hidden_list);

    custom_cbs.free_cb = column_format_free_cb;
    custom_cbs.reset_cb = column_format_reset_cb;
    custom_cbs.set_cb = column_format_set_cb;
    custom_cbs.write_cb = column_format_write_cb;

    prefs_register_list_custom_preference(gui_column_module, PRS_COL_FMT, "Packet list column format",
        "Each pair of strings consists of a column title and its format", &custom_cbs,
        column_format_init_cb, &prefs.col_list);

    /* Number of columns.  This is only used internally and is not written to the
     * preference file
     */
    custom_cbs.free_cb = custom_pref_no_cb;
    custom_cbs.reset_cb = column_num_reset_cb;
    custom_cbs.set_cb = column_num_set_cb;
    custom_cbs.write_cb = column_num_write_cb;
    prefs_register_uint_custom_preference(gui_column_module, PRS_COL_NUM, "Number of columns",
        "Number of columns in col_list", &custom_cbs, &prefs.num_cols);

    /* User Interface : Font */
    gui_font_module = prefs_register_subtree(gui_module, "Font", "Font", NULL);

    prefs_register_obsolete_preference(gui_font_module, "font_name");

    prefs_register_string_preference(gui_font_module, "gtk2.font_name", "Font name",
        "Font name for packet list, protocol tree, and hex dump panes.", (const char**)(&prefs.gui_font_name));

    /* User Interface : Colors */
    gui_color_module = prefs_register_subtree(gui_module, "Colors", "Colors", NULL);

    prefs_register_color_preference(gui_color_module, "marked_frame.fg", "Color preferences for a marked frame",
        "Color preferences for a marked frame", &prefs.gui_marked_fg);

    prefs_register_color_preference(gui_color_module, "marked_frame.bg", "Color preferences for a marked frame",
        "Color preferences for a marked frame", &prefs.gui_marked_bg);

    prefs_register_color_preference(gui_color_module, "ignored_frame.fg", "Color preferences for a ignored frame",
        "Color preferences for a ignored frame", &prefs.gui_ignored_fg);

    prefs_register_color_preference(gui_color_module, "ignored_frame.bg", "Color preferences for a ignored frame",
        "Color preferences for a ignored frame", &prefs.gui_ignored_bg);

    prefs_register_color_preference(gui_color_module, "stream.client.fg", "TCP stream window color preference",
        "TCP stream window color preference", &prefs.st_client_fg);

    prefs_register_color_preference(gui_color_module, "stream.client.bg", "TCP stream window color preference",
        "TCP stream window color preference", &prefs.st_client_bg);

    prefs_register_color_preference(gui_color_module, "stream.server.fg", "TCP stream window color preference",
        "TCP stream window color preference", &prefs.st_server_fg);

    prefs_register_color_preference(gui_color_module, "stream.server.bg", "TCP stream window color preference",
        "TCP stream window color preference", &prefs.st_server_bg);

    custom_cbs.free_cb = colorized_frame_free_cb;
    custom_cbs.reset_cb = colorized_frame_reset_cb;
    custom_cbs.set_cb = colorized_frame_set_cb;
    custom_cbs.write_cb = colorized_frame_write_cb;
    prefs_register_string_custom_preference(gui_column_module, "colorized_frame.fg", "Colorized Foreground",
        "Filter Colorized Foreground", &custom_cbs, (const char **)&prefs.gui_colorized_fg);

    custom_cbs.free_cb = colorized_frame_free_cb;
    custom_cbs.reset_cb = colorized_frame_reset_cb;
    custom_cbs.set_cb = colorized_frame_set_cb;
    custom_cbs.write_cb = colorized_frame_write_cb;
    prefs_register_string_custom_preference(gui_column_module, "colorized_frame.bg", "Colorized Background",
        "Filter Colorized Background", &custom_cbs, (const char **)&prefs.gui_colorized_bg);

    prefs_register_enum_preference(gui_module, "console_open",
                       "Open a console window",
                       "Open a console window (WIN32 only)",
                       (gint*)(void*)(&prefs.gui_console_open), gui_console_open_type, FALSE);

    prefs_register_enum_preference(gui_module, "fileopen.style",
                       "Where to start the File Open dialog box",
                       "Where to start the File Open dialog box",
                       &prefs.gui_fileopen_style, gui_fileopen_style, FALSE);

    prefs_register_uint_preference(gui_module, "recent_files_count.max",
                                   "The max. number of items in the open recent files list",
                                   "The max. number of items in the open recent files list",
                                   10,
                                   &prefs.gui_recent_files_count_max);

    prefs_register_uint_preference(gui_module, "recent_display_filter_entries.max",
                                   "The max. number of entries in the display filter list",
                                   "The max. number of entries in the display filter list",
                                   10,
                                   &prefs.gui_recent_df_entries_max);

    prefs_register_string_preference(gui_module, "fileopen.dir", "Start Directory",
        "Directory to start in when opening File Open dialog.", (const char**)(&prefs.gui_fileopen_dir));

    prefs_register_obsolete_preference(gui_module, "fileopen.remembered_dir");

    prefs_register_uint_preference(gui_module, "fileopen.preview",
                                   "The preview timeout in the File Open dialog",
                                   "The preview timeout in the File Open dialog",
                                   10,
                                   &prefs.gui_fileopen_preview);

    prefs_register_bool_preference(gui_module, "ask_unsaved",
                                   "Ask to save unsaved capture files",
                                   "Ask to save unsaved capture files?",
                                   &prefs.gui_ask_unsaved);

    prefs_register_bool_preference(gui_module, "find_wrap",
                                   "Wrap to beginning/end of file during search",
                                   "Wrap to beginning/end of file during search?",
                                   &prefs.gui_find_wrap);

    prefs_register_bool_preference(gui_module, "use_pref_save",
                                   "Settings dialogs use a save button",
                                   "Settings dialogs use a save button?",
                                   &prefs.gui_use_pref_save);

    prefs_register_bool_preference(gui_module, "geometry.save.position",
                                   "Save window position at exit",
                                   "Save window position at exit?",
                                   &prefs.gui_geometry_save_position);

    prefs_register_bool_preference(gui_module, "geometry.save.size",
                                   "Save window size at exit",
                                   "Save window size at exit?",
                                   &prefs.gui_geometry_save_size);

    prefs_register_bool_preference(gui_module, "geometry.save.maximized",
                                   "Save window maximized state at exit",
                                   "Save window maximized state at exit?",
                                   &prefs.gui_geometry_save_maximized);

    prefs_register_bool_preference(gui_module, "macosx_style",
                                   "Use Mac OS X style",
                                   "Use Mac OS X style (Mac OS X with native GTK only)?",
                                   &prefs.gui_macosx_style);

    prefs_register_obsolete_preference(gui_module, "geometry.main.x");
    prefs_register_obsolete_preference(gui_module, "geometry.main.y");
    prefs_register_obsolete_preference(gui_module, "geometry.main.width");
    prefs_register_obsolete_preference(gui_module, "geometry.main.height");
    prefs_register_obsolete_preference(gui_module, "toolbar_main_show");

    prefs_register_enum_preference(gui_module, "toolbar_main_style",
                       "Main Toolbar style",
                       "Main Toolbar style",
                       &prefs.gui_toolbar_main_style, gui_toolbar_style, FALSE);

    prefs_register_enum_preference(gui_module, "toolbar_filter_style",
                       "Filter Toolbar style",
                       "Filter Toolbar style",
                       &prefs.gui_toolbar_filter_style, gui_toolbar_style, FALSE);

    prefs_register_string_preference(gui_module, "webbrowser", "The path to the webbrowser",
        "The path to the webbrowser (Ex: mozilla)", (const char**)(&prefs.gui_webbrowser));

    prefs_register_string_preference(gui_module, "window_title", "Custom window title",
        "Custom window title. (Appended to existing titles.)", (const char**)(&prefs.gui_window_title));

    prefs_register_string_preference(gui_module, "start_title", "Custom start page title",
        "Custom start page title", (const char**)(&prefs.gui_start_title));

    prefs_register_enum_preference(gui_module, "version_placement",
                       "Show version in the start page and/or main screen's title bar",
                       "Show version in the start page and/or main screen's title bar",
                       (gint*)(void*)(&prefs.gui_version_placement), gui_version_placement_type, FALSE);

    prefs_register_bool_preference(gui_module, "auto_scroll_on_expand",
                                   "Automatically scroll the recently expanded item",
                                   "Automatically scroll the recently expanded item",
                                   &prefs.gui_auto_scroll_on_expand);

    prefs_register_uint_preference(gui_module, "auto_scroll_percentage",
                                   "The percentage down the view the recently expanded item should be scrolled",
                                   "The percentage down the view the recently expanded item should be scrolled",
                                   10,
                                   &prefs.gui_auto_scroll_percentage);

    /* User Interface : Layout */
    gui_layout_module = prefs_register_subtree(gui_module, "Layout", "Layout", gui_layout_callback);

    prefs_register_uint_preference(gui_layout_module, "layout_type",
                                   "Layout type",
                                   "Layout type (1-6)",
                                   10,
                                   (guint*)(void*)(&prefs.gui_layout_type));

    prefs_register_enum_preference(gui_layout_module, "layout_content_1",
                       "Layout content of the pane 1",
                       "Layout content of the pane 1",
                       (gint*)(void*)(&prefs.gui_layout_content_1), gui_layout_content, FALSE);

    prefs_register_enum_preference(gui_layout_module, "layout_content_2",
                       "Layout content of the pane 2",
                       "Layout content of the pane 2",
                       (gint*)(void*)(&prefs.gui_layout_content_2), gui_layout_content, FALSE);

    prefs_register_enum_preference(gui_layout_module, "layout_content_3",
                       "Layout content of the pane 3",
                       "Layout content of the pane 3",
                       (gint*)(void*)(&prefs.gui_layout_content_3), gui_layout_content, FALSE);

    /* Console
     * These are preferences that can be read/written using the
     * preference module API.  These preferences still use their own
     * configuration screens for access, but this cuts down on the
     * preference "string compare list" in set_pref()
     */
    console_module = prefs_register_module(NULL, "console", "Console",
        "CONSOLE", NULL, FALSE);

    custom_cbs.free_cb = custom_pref_no_cb;
    custom_cbs.reset_cb = console_log_level_reset_cb;
    custom_cbs.set_cb = console_log_level_set_cb;
    custom_cbs.write_cb = console_log_level_write_cb;
    prefs_register_uint_custom_preference(console_module, "log.level", "logging level",
        "A bitmask of glib log levels", &custom_cbs, &prefs.console_log_level);

    /* Capture
     * These are preferences that can be read/written using the
     * preference module API.  These preferences still use their own
     * configuration screens for access, but this cuts down on the
     * preference "string compare list" in set_pref()
     */
    capture_module = prefs_register_module(NULL, "capture", "Capture",
        "CAPTURE", NULL, FALSE);

    prefs_register_string_preference(capture_module, "device", "Default capture device",
        "Default capture device", (const char**)(&prefs.capture_device));

    prefs_register_string_preference(capture_module, "devices_linktypes", "Interface link-layer header type",
        "Interface link-layer header types (Ex: en0(1),en1(143),...)",
        (const char**)(&prefs.capture_devices_linktypes));

    prefs_register_string_preference(capture_module, "devices_descr", "Interface descriptions",
        "Interface descriptions (Ex: eth0(eth0 descr),eth1(eth1 descr),...)",
        (const char**)(&prefs.capture_devices_descr));

    prefs_register_string_preference(capture_module, "devices_hide", "Hide interface",
        "Hide interface? (Ex: eth0,eth3,...)", (const char**)(&prefs.capture_devices_hide));

    prefs_register_string_preference(capture_module, "devices_monitor_mode", "Capture in monitor mode",
        "By default, capture in monitor mode on interface? (Ex: eth0,eth3,...)",
        (const char**)(&prefs.capture_devices_monitor_mode));

    prefs_register_bool_preference(capture_module, "prom_mode", "Capture in promiscuous mode",
        "Capture in promiscuous mode?", &prefs.capture_prom_mode);

    prefs_register_bool_preference(capture_module, "pcap_ng", "Capture in Pcap-NG format",
        "Capture in Pcap-NG format?", &prefs.capture_pcap_ng);

    prefs_register_bool_preference(capture_module, "real_time_update", "Update packet list in real time during capture",
        "Update packet list in real time during capture?", &prefs.capture_real_time);

    prefs_register_bool_preference(capture_module, "auto_scroll", "Scroll packet list during capture",
        "Scroll packet list during capture?", &prefs.capture_auto_scroll);

    prefs_register_bool_preference(capture_module, "show_info", "Show capture info dialog while capturing",
        "Show capture info dialog while capturing?", &prefs.capture_show_info);

    prefs_register_obsolete_preference(capture_module, "syntax_check_filter");

    custom_cbs.free_cb = capture_column_free_cb;
    custom_cbs.reset_cb = capture_column_reset_cb;
    custom_cbs.set_cb = capture_column_set_cb;
    custom_cbs.write_cb = capture_column_write_cb;
    prefs_register_list_custom_preference(capture_module, "columns", "Capture options dialog column list",
        "List of columns to be displayed", &custom_cbs, capture_column_init_cb, &prefs.capture_columns);

    /* Name Resolution */
    nameres_module = prefs_register_module(NULL, "nameres", "Name Resolution",
        "Name Resolution", NULL, TRUE);
    addr_resolve_pref_init(nameres_module);
    oid_pref_init(nameres_module);
#ifdef HAVE_GEOIP
    geoip_db_pref_init(nameres_module);
#endif

    /* Printing */
    printing = prefs_register_module(NULL, "print", "Printing",
        "Printing", NULL, TRUE);

    prefs_register_enum_preference(printing, "format",
                                   "Format", "Can be one of \"text\" or \"postscript\"",
                                   &prefs.pr_format, print_format_vals, TRUE);

    prefs_register_enum_preference(printing, "destination",
                                   "Print to", "Can be one of \"command\" or \"file\"",
                                   &prefs.pr_dest, print_dest_vals, TRUE);

#ifndef _WIN32
    prefs_register_string_preference(printing, "command", "Command",
        "Output gets piped to this command when the destination is set to \"command\"", (const char**)(&prefs.pr_cmd));
#endif

    prefs_register_filename_preference(printing, "file", "File",
        "This is the file that gets written to when the destination is set to \"file\"", (const char**)(&prefs.pr_file));


    /* Statistics */
    stats_module = prefs_register_module(NULL, "statistics", "Statistics",
        "Statistics", &stats_callback, TRUE);

    prefs_register_uint_preference(stats_module, "update_interval",
                                   "Tap update interval in ms",
                                   "Determines time between tap updates",
                                   10,
                                   &prefs.tap_update_interval);

#ifdef HAVE_LIBPORTAUDIO
    prefs_register_uint_preference(stats_module, "rtp_player_max_visible",
                                   "Max visible channels in RTP Player",
                                   "Determines maximum height of RTP Player window",
                                   10,
                                   &prefs.rtp_player_max_visible);
#endif


    /* Protocols */
    protocols_module = prefs_register_module(NULL, "protocols", "Protocols",
                                             "Protocols", NULL, TRUE);

    prefs_register_bool_preference(protocols_module, "display_hidden_proto_items",
                                   "Display hidden protocol items",
                                   "Display all hidden protocol items in the packet list.",
                                   &prefs.display_hidden_proto_items);

    /* Obsolete preferences
     * These "modules" were reorganized/renamed to correspond to their GUI
     * configuration screen within the preferences dialog
     */

    /* taps is now part of the stats module */
    prefs_register_module(NULL, "taps", "TAPS", "TAPS", NULL, FALSE);
    /* packet_list is now part of the protocol (parent) module */
    prefs_register_module(NULL, "packet_list", "PACKET_LIST", "PACKET_LIST", NULL, FALSE);
    /* stream is now part of the gui module */
    prefs_register_module(NULL, "stream", "STREAM", "STREAM", NULL, FALSE);

}

/* Parse through a list of comma-separated, possibly quoted strings.
   Return a list of the string data. */
GList *
prefs_get_string_list(gchar *str)
{
  enum { PRE_STRING, IN_QUOT, NOT_IN_QUOT };

  gint      state = PRE_STRING, i = 0, j = 0;
  gboolean  backslash = FALSE;
  guchar    cur_c;
  gchar    *slstr = NULL;
  GList    *sl = NULL;

  /* Allocate a buffer for the first string.   */
  slstr = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
  j = 0;

  for (;;) {
    cur_c = str[i];
    if (cur_c == '\0') {
      /* It's the end of the input, so it's the end of the string we
         were working on, and there's no more input. */
      if (state == IN_QUOT || backslash) {
        /* We were in the middle of a quoted string or backslash escape,
           and ran out of characters; that's an error.  */
        g_free(slstr);
        prefs_clear_string_list(sl);
        return NULL;
      }
      slstr[j] = '\0';
      sl = g_list_append(sl, slstr);
      break;
    }
    if (cur_c == '"' && ! backslash) {
      switch (state) {
        case PRE_STRING:
          /* We hadn't yet started processing a string; this starts the
             string, and we're now quoting.  */
          state = IN_QUOT;
          break;
        case IN_QUOT:
          /* We're in the middle of a quoted string, and we saw a quotation
             mark; we're no longer quoting.   */
          state = NOT_IN_QUOT;
          break;
        case NOT_IN_QUOT:
          /* We're working on a string, but haven't seen a quote; we're
             now quoting.  */
          state = IN_QUOT;
          break;
        default:
          break;
      }
    } else if (cur_c == '\\' && ! backslash) {
      /* We saw a backslash, and the previous character wasn't a
         backslash; escape the next character.

         This also means we've started a new string. */
      backslash = TRUE;
      if (state == PRE_STRING)
        state = NOT_IN_QUOT;
    } else if (cur_c == ',' && state != IN_QUOT && ! backslash) {
      /* We saw a comma, and we're not in the middle of a quoted string
         and it wasn't preceded by a backslash; it's the end of
         the string we were working on...  */
      slstr[j] = '\0';
      sl = g_list_append(sl, slstr);

      /* ...and the beginning of a new string.  */
      state = PRE_STRING;
      slstr = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
      j = 0;
    } else if (!isspace(cur_c) || state != PRE_STRING) {
      /* Either this isn't a white-space character, or we've started a
         string (i.e., already seen a non-white-space character for that
         string and put it into the string).

         The character is to be put into the string; do so if there's
         room.  */
      if (j < COL_MAX_LEN) {
        slstr[j] = cur_c;
        j++;
      }

      /* If it was backslash-escaped, we're done with the backslash escape.  */
      backslash = FALSE;
    }
    i++;
  }
  return(sl);
}

static void
write_string_list(FILE *f, GList *sl, gboolean is_default)
{
  char          pref_str[8];
  GList        *clp = g_list_first(sl);
  gchar        *str;
  int           cur_len = 0;
  gchar        *quoted_str;
  size_t        str_len;
  gchar        *strp, *quoted_strp, c;
  guint         item_count = 0;
  gboolean      first = TRUE;

  while (clp) {
    item_count++;
    str = clp->data;

    /* Allocate a buffer big enough to hold the entire string, with each
       character quoted (that's the worst case).  */
    str_len = strlen(str);
    quoted_str = g_malloc(str_len*2 + 1);

    /* Now quote any " or \ characters in it. */
    strp = str;
    quoted_strp = quoted_str;
    while ((c = *strp++) != '\0') {
      if (c == '"' || c == '\\') {
        /* It has to be backslash-quoted.  */
        *quoted_strp++ = '\\';
      }
      *quoted_strp++ = c;
    }
    *quoted_strp = '\0';

    {
      cur_len = 0;
      if (!first) {
        pref_str[cur_len] = ','; cur_len++;
      }

      if (item_count % 2) {
        /* Wrap the line.  */
        pref_str[cur_len] = '\n'; cur_len++;
        if (is_default) {
          pref_str[cur_len] = '#'; cur_len++;
        }
        pref_str[cur_len] = '\t'; cur_len++;
      } else {
        pref_str[cur_len] = ' '; cur_len++;
      }
      pref_str[cur_len] = '\0';
      fprintf(f, "%s\"%s\"", pref_str, quoted_str);
      first = FALSE;
    }
    g_free(quoted_str);
    g_free(str);
    clp = clp->next;
  }
}

void
prefs_clear_string_list(GList *sl)
{
  GList *l = sl;

  while (l) {
    g_free(l->data);
    l = g_list_remove_link(l, l);
  }
}

/*
 * Takes a string, a pointer to an array of "enum_val_t"s, and a default gint
 * value.
 * The array must be terminated by an entry with a null "name" string.
 *
 * If the string matches a "name" string in an entry, the value from that
 * entry is returned.
 *
 * Otherwise, if a string matches a "desctiption" string in an entry, the
 * value from that entry is returned; we do that for backwards compatibility,
 * as we used to have only a "name" string that was used both for command-line
 * and configuration-file values and in the GUI (which meant either that
 * the GUI had what might be somewhat cryptic values to select from or that
 * the "-o" flag took long strings, often with spaces in them).
 *
 * Otherwise, the default value that was passed as the third argument is
 * returned.
 */
static gint
find_val_for_string(const char *needle, const enum_val_t *haystack,
                    gint default_value)
{
    int i;

    for (i = 0; haystack[i].name != NULL; i++) {
        if (g_ascii_strcasecmp(needle, haystack[i].name) == 0) {
            return haystack[i].value;
        }
    }
    for (i = 0; haystack[i].name != NULL; i++) {
        if (g_ascii_strcasecmp(needle, haystack[i].description) == 0) {
            return haystack[i].value;
        }
    }
    return default_value;
}

/* Preferences file format:
 * - Configuration directives start at the beginning of the line, and
 *   are terminated with a colon.
 * - Directives can be continued on the next line by preceding them with
 *   whitespace.
 *
 * Example:

# This is a comment line
print.command: lpr
print.file: /a/very/long/path/
            to/wireshark-out.ps
 *
 */

#define DEF_NUM_COLS    7

/*
 * Parse a column format, filling in the relevant fields of a fmt_data.
 */
static gboolean
parse_column_format(fmt_data *cfmt, const char *fmt)
{
  const gchar *cust_format = col_format_to_string(COL_CUSTOM);
  size_t cust_format_len = strlen(cust_format);
  gchar **cust_format_info;
  char *p;
  int col_fmt;
  gchar *col_custom_field;
  long col_custom_occurrence;
  gboolean col_resolved;

  /*
   * Is this a custom column?
   */
  if ((strlen(fmt) > cust_format_len) && (fmt[cust_format_len] == ':') &&
      strncmp(fmt, cust_format, cust_format_len) == 0) {
    /* Yes. */
    col_fmt = COL_CUSTOM;
    cust_format_info = g_strsplit(&fmt[cust_format_len+1],":",3); /* add 1 for ':' */
    col_custom_field = g_strdup(cust_format_info[0]);
    if (col_custom_field && cust_format_info[1]) {
      col_custom_occurrence = strtol(cust_format_info[1], &p, 10);
      if (p == cust_format_info[1] || *p != '\0') {
        /* Not a valid number. */
        g_free(col_custom_field);
        g_strfreev(cust_format_info);
        return FALSE;
      }
    } else {
      col_custom_occurrence = 0;
    }
    if (col_custom_field && cust_format_info[1] && cust_format_info[2]) {
      col_resolved = (cust_format_info[2][0] == 'U') ? FALSE : TRUE;
    } else {
      col_resolved = TRUE;
    }
    g_strfreev(cust_format_info);
  } else {
    col_fmt = get_column_format_from_str(fmt);
    if (col_fmt == -1)
      return FALSE;
    col_custom_field = NULL;
    col_custom_occurrence = 0;
    col_resolved = TRUE;
  }

  cfmt->fmt = col_fmt;
  cfmt->custom_field = col_custom_field;
  cfmt->custom_occurrence = (int)col_custom_occurrence;
  cfmt->resolved = col_resolved;
  return TRUE;
}

/* Initialize non-dissector preferences to wired-in default values.
 * (The dissector preferences are assumed to be set to those values
 * by the dissectors.)
 * They may be overridden by the global preferences file or the
 *  user's preferences file.
 */
static void
init_prefs(void)
{
  if (prefs_initialized)
    return;

  uat_load_all();

  pre_init_prefs();

  filter_expression_init(TRUE);

  prefs_initialized = TRUE;
}

/* Initialize non-dissector preferences used by the "register preference" API
 * to default values so the default values can be used when registered
 */
static void
pre_init_prefs(void)
{
  int         i;
  gchar       *col_name;
  fmt_data    *cfmt;
  static const gchar *col_fmt[DEF_NUM_COLS*2] = {
                            "No.",      "%m", "Time",        "%t",
                            "Source",   "%s", "Destination", "%d",
                            "Protocol", "%p", "Length",      "%L",
                            "Info",     "%i"};
#if defined(HAVE_PCAP_CREATE)
  static gint num_capture_cols = 7;
  static const gchar *capture_cols[7] = {
                                "INTERFACE",
                                "LINK",
                                "PMODE",
                                "SNAPLEN",
                                "MONITOR",
                                "BUFFER",
                                "FILTER"};
#elif defined(_WIN32) && !defined (HAVE_PCAP_CREATE)
  static gint num_capture_cols = 6;
  static const gchar *capture_cols[6] = {
                                "INTERFACE",
                                "LINK",
                                "PMODE",
                                "SNAPLEN",
                                "BUFFER",
                                "FILTER"};
#else
  static gint num_capture_cols = 5;
  static const gchar *capture_cols[5] = {
                                "INTERFACE",
                                "LINK",
                                "PMODE",
                                "SNAPLEN",
                                "FILTER"};
#endif

  if (prefs_pre_initialized)
     return;

  prefs.pr_format  = PR_FMT_TEXT;
  prefs.pr_dest    = PR_DEST_CMD;
  prefs.pr_file    = g_strdup("wireshark.out");
  prefs.pr_cmd     = g_strdup("lpr");

  prefs.gui_scrollbar_on_right = TRUE;
  prefs.gui_plist_sel_browse = FALSE;
  prefs.gui_ptree_sel_browse = FALSE;
  prefs.gui_altern_colors = FALSE;
  prefs.gui_expert_composite_eyecandy = FALSE;
  prefs.gui_ptree_line_style = 0;
  prefs.gui_ptree_expander_style = 1;
  prefs.gui_hex_dump_highlight_style = 1;
  prefs.filter_toolbar_show_in_statusbar = FALSE;
  prefs.gui_toolbar_main_style = TB_STYLE_ICONS;
  prefs.gui_toolbar_filter_style = TB_STYLE_TEXT;
#ifdef _WIN32
  prefs.gui_font_name = g_strdup("Lucida Console 10");
#else
  /*
   * XXX - for now, we make the initial font name a pattern that matches
   * only ISO 8859/1 fonts, so that we don't match 2-byte fonts such
   * as ISO 10646 fonts.
   *
   * Users in locales using other one-byte fonts will have to choose
   * a different font from the preferences dialog - or put the font
   * selection in the global preferences file to make that font the
   * default for all users who don't explicitly specify a different
   * font.
   *
   * Making this a font set rather than a font has two problems:
   *
   *	1) as far as I know, you can't select font sets with the
   *	   font selection dialog;
   *
   *  2) if you use a font set, the text to be drawn must be a
   *	   multi-byte string in the appropriate locale, but
   *	   Wireshark does *NOT* guarantee that's the case - in
   *	   the hex-dump window, each character in the text portion
   *	   of the display must be a *single* byte, and in the
   *	   packet-list and protocol-tree windows, text extracted
   *	   from the packet is not necessarily in the right format.
   *
   * "Doing this right" may, for the packet-list and protocol-tree
   * windows, require that dissectors know what the locale is
   * *AND* know what locale and text representation is used in
   * the packets they're dissecting, and may be impossible in
   * the hex-dump window (except by punting and displaying only
   * ASCII characters).
   *
   * GTK+ 2.0 may simplify part of the problem, as it will, as I
   * understand it, use UTF-8-encoded Unicode as its internal
   * character set; however, we'd still have to know whatever
   * character set and encoding is used in the packet (which
   * may differ for different protocols, e.g. SMB might use
   * PC code pages for some strings and Unicode for others, whilst
   * NFS might use some UNIX character set encoding, e.g. ISO 8859/x,
   * or one of the EUC character sets for Asian languages, or one
   * of the other multi-byte character sets, or UTF-8, or...).
   *
   * I.e., as far as I can tell, "internationalizing" the packet-list,
   * protocol-tree, and hex-dump windows involves a lot more than, say,
   * just using font sets rather than fonts.
   */
  /* XXX - the above comment was about the GTK1 font stuff, just remove this comment now */
  /* XXX- is this the correct default font name for GTK2 none win32? */
  prefs.gui_font_name = g_strdup("Monospace 10");
#endif
  prefs.gui_marked_fg.pixel        =     65535;
  prefs.gui_marked_fg.red          =     65535;
  prefs.gui_marked_fg.green        =     65535;
  prefs.gui_marked_fg.blue         =     65535;
  prefs.gui_marked_bg.pixel        =         0;
  prefs.gui_marked_bg.red          =         0;
  prefs.gui_marked_bg.green        =         0;
  prefs.gui_marked_bg.blue         =         0;
  prefs.gui_ignored_fg.pixel       =     32767;
  prefs.gui_ignored_fg.red         =     32767;
  prefs.gui_ignored_fg.green       =     32767;
  prefs.gui_ignored_fg.blue        =     32767;
  prefs.gui_ignored_bg.pixel       =     65535;
  prefs.gui_ignored_bg.red         =     65535;
  prefs.gui_ignored_bg.green       =     65535;
  prefs.gui_ignored_bg.blue        =     65535;
  prefs.gui_colorized_fg           = g_strdup("000000,000000,000000,000000,000000,000000,000000,000000,000000,000000");
  prefs.gui_colorized_bg           = g_strdup("ffc0c0,ffc0ff,e0c0e0,c0c0ff,c0e0e0,c0ffff,c0ffc0,ffffc0,e0e0c0,e0e0e0");
  prefs.st_client_fg.pixel         =     0;
  prefs.st_client_fg.red           = 32767;
  prefs.st_client_fg.green         =     0;
  prefs.st_client_fg.blue          =     0;
  prefs.st_client_bg.pixel         =     0;
  prefs.st_client_bg.red           = 64507;
  prefs.st_client_bg.green         = 60909;
  prefs.st_client_bg.blue          = 60909;
  prefs.st_server_fg.pixel         =     0;
  prefs.st_server_fg.red           =     0;
  prefs.st_server_fg.green         =     0;
  prefs.st_server_fg.blue          = 32767;
  prefs.st_server_bg.pixel         =     0;
  prefs.st_server_bg.red           = 60909;
  prefs.st_server_bg.green         = 60909;
  prefs.st_server_bg.blue          = 64507;
  prefs.gui_geometry_save_position = TRUE;
  prefs.gui_geometry_save_size     = TRUE;
  prefs.gui_geometry_save_maximized= TRUE;
  prefs.gui_macosx_style           = TRUE;
  prefs.gui_console_open           = console_open_never;
  prefs.gui_fileopen_style         = FO_STYLE_LAST_OPENED;
  prefs.gui_recent_df_entries_max  = 10;
  prefs.gui_recent_files_count_max = 10;
  prefs.gui_fileopen_dir           = g_strdup(get_persdatafile_dir());
  prefs.gui_fileopen_preview       = 3;
  prefs.gui_ask_unsaved            = TRUE;
  prefs.gui_find_wrap              = TRUE;
  prefs.gui_use_pref_save          = FALSE;
  prefs.gui_webbrowser             = g_strdup(HTML_VIEWER " %s");
  prefs.gui_window_title           = g_strdup("");
  prefs.gui_start_title            = g_strdup("The World's Most Popular Network Protocol Analyzer");
  prefs.gui_version_placement      = version_both;
  prefs.gui_auto_scroll_on_expand  = FALSE;
  prefs.gui_auto_scroll_percentage = 0;
  prefs.gui_layout_type            = layout_type_5;
  prefs.gui_layout_content_1       = layout_pane_content_plist;
  prefs.gui_layout_content_2       = layout_pane_content_pdetails;
  prefs.gui_layout_content_3       = layout_pane_content_pbytes;

  prefs.col_list = NULL;
  for (i = 0; i < DEF_NUM_COLS; i++) {
    cfmt = (fmt_data *) g_malloc(sizeof(fmt_data));
    cfmt->title = g_strdup(col_fmt[i * 2]);
    parse_column_format(cfmt, col_fmt[(i * 2) + 1]);
    cfmt->visible = TRUE;
    cfmt->resolved = TRUE;
    cfmt->custom_field = NULL;
    cfmt->custom_occurrence = 0;
    prefs.col_list = g_list_append(prefs.col_list, cfmt);
  }
  prefs.num_cols  = DEF_NUM_COLS;

/* set the default values for the capture dialog box */
  prefs.capture_prom_mode             = TRUE;
#ifdef PCAP_NG_DEFAULT
  prefs.capture_pcap_ng               = TRUE;
#else
  prefs.capture_pcap_ng               = FALSE;
#endif
  prefs.capture_real_time             = TRUE;
  prefs.capture_auto_scroll           = TRUE;
  prefs.capture_show_info             = FALSE;

  prefs.capture_columns               = NULL;
  for (i = 0; i < num_capture_cols; i++) {
    col_name = g_strdup(capture_cols[i]);
    prefs.capture_columns = g_list_append(prefs.capture_columns, col_name);
  }

  prefs.console_log_level          =
      G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR;

/* set the default values for the tap/statistics dialog box */
  prefs.tap_update_interval    = TAP_UPDATE_DEFAULT_INTERVAL;
  prefs.rtp_player_max_visible = RTP_PLAYER_DEFAULT_VISIBLE;

  prefs.display_hidden_proto_items = FALSE;

  prefs_pre_initialized = TRUE;
}

/*
 * Reset a single dissector preference.
 */
static void
reset_pref(gpointer data, gpointer user_data _U_)
{
    pref_t *pref = data;

    switch (pref->type) {

    case PREF_UINT:
        *pref->varp.uint = pref->default_val.uint;
        break;

    case PREF_BOOL:
        *pref->varp.boolp = pref->default_val.boolval;
        break;

    case PREF_ENUM:
        /*
         * For now, we save the "description" value, so that if we
         * save the preferences older versions of Wireshark can at
         * least read preferences that they supported; we support
         * either the short name or the description when reading
         * the preferences file or a "-o" option.
         */
        *pref->varp.enump = pref->default_val.enumval;
        break;

    case PREF_STRING:
    case PREF_FILENAME:
        g_free((void *)*pref->varp.string);
        *pref->varp.string = g_strdup(pref->default_val.string);
        break;

    case PREF_RANGE:
        g_free(*pref->varp.range);
        *pref->varp.range = range_copy(pref->default_val.range);
        break;

    case PREF_STATIC_TEXT:
    case PREF_UAT:
        /* Nothing to do */
        break;

    case PREF_COLOR:
        *pref->varp.color = pref->default_val.color;
        break;

    case PREF_CUSTOM:
        pref->custom_cbs.reset_cb(pref);
        break;

    case PREF_OBSOLETE:
        /*
         * This preference is no longer supported; it's not a
         * real preference, so we don't reset it (i.e., we
         * treat it as if it weren't found in the list of
         * preferences, and we weren't called in the first place).
         */
        break;
    }
}

typedef struct {
    module_t *module;
} reset_pref_arg_t;

/*
 * Reset all preferences for a module.
 */
static gboolean
reset_module_prefs(void *value, void *data _U_)
{
    reset_pref_arg_t arg;

    arg.module = value;
    g_list_foreach(arg.module->prefs, reset_pref, &arg);
    return FALSE;
}

/* Reset preferences */
void
prefs_reset(void)
{
  prefs_initialized = FALSE;

  /*
   * Unload all UAT preferences.
   */
  uat_unload_all();

  /*
   * Unload any loaded MIBs.
   */
  oids_cleanup();

  /*
   * Reset the non-dissector preferences.
   */
  init_prefs();

  /*
   * Reset the non-UAT dissector preferences.
   */
  pe_tree_foreach(prefs_modules, reset_module_prefs, NULL);
}

/* Read the preferences file, fill in "prefs", and return a pointer to it.

   If we got an error (other than "it doesn't exist") trying to read
   the global preferences file, stuff the errno into "*gpf_errno_return"
   and a pointer to the path of the file into "*gpf_path_return", and
   return NULL.

   If we got an error (other than "it doesn't exist") trying to read
   the user's preferences file, stuff the errno into "*pf_errno_return"
   and a pointer to the path of the file into "*pf_path_return", and
   return NULL. */
e_prefs *
read_prefs(int *gpf_errno_return, int *gpf_read_errno_return,
           char **gpf_path_return, int *pf_errno_return,
           int *pf_read_errno_return, char **pf_path_return)
{
  int         err;
  char        *pf_path;
  FILE        *pf;

  /* clean up libsmi structures before reading prefs */
  oids_cleanup();

  init_prefs();

  /*
   * If we don't already have the pathname of the global preferences
   * file, construct it.  Then, in either case, try to open the file.
   */
  if (gpf_path == NULL) {
    /*
     * We don't have the path; try the new path first, and, if that
     * file doesn't exist, try the old path.
     */
    gpf_path = get_datafile_path(PF_NAME);
    if ((pf = ws_fopen(gpf_path, "r")) == NULL && errno == ENOENT) {
      /*
       * It doesn't exist by the new name; try the old name.
       */
      g_free(gpf_path);
      gpf_path = get_datafile_path(OLD_GPF_NAME);
      pf = ws_fopen(gpf_path, "r");
    }
  } else {
    /*
     * We have the path; try it.
     */
    pf = ws_fopen(gpf_path, "r");
  }

  /*
   * If we were able to open the file, read it.
   * XXX - if it failed for a reason other than "it doesn't exist",
   * report the error.
   */
  *gpf_path_return = NULL;
  if (pf != NULL) {
    /*
     * Start out the counters of "mgcp.{tcp,udp}.port" entries we've
     * seen.
     */
    mgcp_tcp_port_count = 0;
    mgcp_udp_port_count = 0;

    /* We succeeded in opening it; read it. */
    err = read_prefs_file(gpf_path, pf, set_pref, NULL);
    if (err != 0) {
      /* We had an error reading the file; return the errno and the
         pathname, so our caller can report the error. */
      *gpf_errno_return = 0;
      *gpf_read_errno_return = err;
      *gpf_path_return = gpf_path;
    }
    fclose(pf);
  } else {
    /* We failed to open it.  If we failed for some reason other than
       "it doesn't exist", return the errno and the pathname, so our
       caller can report the error. */
    if (errno != ENOENT) {
      *gpf_errno_return = errno;
      *gpf_read_errno_return = 0;
      *gpf_path_return = gpf_path;
    }
  }

  /* Construct the pathname of the user's preferences file. */
  pf_path = get_persconffile_path(PF_NAME, TRUE, FALSE);

  /* Read the user's preferences file, if it exists. */
  *pf_path_return = NULL;
  if ((pf = ws_fopen(pf_path, "r")) != NULL) {
    /*
     * Start out the counters of "mgcp.{tcp,udp}.port" entries we've
     * seen.
     */
    mgcp_tcp_port_count = 0;
    mgcp_udp_port_count = 0;

    /* We succeeded in opening it; read it. */
    err = read_prefs_file(pf_path, pf, set_pref, NULL);
    if (err != 0) {
      /* We had an error reading the file; return the errno and the
         pathname, so our caller can report the error. */
      *pf_errno_return = 0;
      *pf_read_errno_return = err;
      *pf_path_return = pf_path;
    } else
      g_free(pf_path);
    fclose(pf);
  } else {
    /* We failed to open it.  If we failed for some reason other than
       "it doesn't exist", return the errno and the pathname, so our
       caller can report the error. */
    if (errno != ENOENT) {
      *pf_errno_return = errno;
      *pf_read_errno_return = 0;
      *pf_path_return = pf_path;
    } else
      g_free(pf_path);
  }

  /* load SMI modules if needed */
  oids_init();

  return &prefs;
}

/* read the preferences file (or similiar) and call the callback
 * function to set each key/value pair found */
int
read_prefs_file(const char *pf_path, FILE *pf,
                pref_set_pair_cb pref_set_pair_fct, void *private_data)
{
  enum { START, IN_VAR, PRE_VAL, IN_VAL, IN_SKIP };
  int       got_c, state = START;
  GString  *cur_val;
  GString  *cur_var;
  gboolean  got_val = FALSE;
  gint      fline = 1, pline = 1;
  gchar     hint[] = "(applying your preferences once should remove this warning)";

  cur_val = g_string_new("");
  cur_var = g_string_new("");

  while ((got_c = getc(pf)) != EOF) {
    if (got_c == '\n') {
      state = START;
      fline++;
      continue;
    }

    switch (state) {
      case START:
        if (isalnum(got_c)) {
          if (cur_var->len > 0) {
            if (got_val) {
              /*  Convert the string to a range.  Since we're reading the
               *  preferences file, silently lower values in excess of the
               *  range's maximum.
               */
              switch (pref_set_pair_fct(cur_var->str, cur_val->str, private_data, FALSE)) {

              case PREFS_SET_OK:
                break;

              case PREFS_SET_SYNTAX_ERR:
                g_warning ("%s line %d: Syntax error in preference %s %s", pf_path, pline, cur_var->str, hint);
                break;

              case PREFS_SET_NO_SUCH_PREF:
                g_warning ("%s line %d: No such preference \"%s\" %s", pf_path,
                                pline, cur_var->str, hint);
                break;

              case PREFS_SET_OBSOLETE:
                /* We silently ignore attempts to set these; it's
                   probably not the user's fault that it's in there -
                   they may have saved preferences with a release that
                   supported them. */
                break;
              }
            } else {
              g_warning ("%s line %d: Incomplete preference %s", pf_path, pline, hint);
            }
          }
          state      = IN_VAR;
          got_val    = FALSE;
          g_string_truncate(cur_var, 0);
          g_string_append_c(cur_var, (gchar) got_c);
          pline = fline;
        } else if (isspace(got_c) && cur_var->len > 0 && got_val) {
          state = PRE_VAL;
        } else if (got_c == '#') {
          state = IN_SKIP;
        } else {
          g_warning ("%s line %d: Malformed line %s", pf_path, fline, hint);
        }
        break;
      case IN_VAR:
        if (got_c != ':') {
          g_string_append_c(cur_var, (gchar) got_c);
        } else {
          state   = PRE_VAL;
          g_string_truncate(cur_val, 0);
          got_val = TRUE;
        }
        break;
      case PRE_VAL:
        if (!isspace(got_c)) {
          state = IN_VAL;
          g_string_append_c(cur_val, (gchar) got_c);
        }
        break;
      case IN_VAL:
        g_string_append_c(cur_val, (gchar) got_c);
        break;
    }
  }
  if (cur_var->len > 0) {
    if (got_val) {
      /*  Convert the string to a range.  Since we're reading the
       *  preferences file, silently lower values in excess of the
       *  range's maximum.
       */
      switch (pref_set_pair_fct(cur_var->str, cur_val->str, private_data, FALSE)) {

      case PREFS_SET_OK:
        break;

      case PREFS_SET_SYNTAX_ERR:
        g_warning ("%s line %d: Syntax error in preference %s %s", pf_path, pline, cur_var->str, hint);
        break;

      case PREFS_SET_NO_SUCH_PREF:
        g_warning ("%s line %d: No such preference \"%s\" %s", pf_path,
                        pline, cur_var->str, hint);
        break;

      case PREFS_SET_OBSOLETE:
        /* We silently ignore attempts to set these; it's probably not
           the user's fault that it's in there - they may have saved
           preferences with a release that supported it. */
        break;
      }
    } else {
      g_warning ("%s line %d: Incomplete preference %s", pf_path, pline, hint);
    }
  }

  g_string_free(cur_val, TRUE);
  g_string_free(cur_var, TRUE);

  if (ferror(pf))
    return errno;
  else
    return 0;
}

/*
 * If we were handed a preference starting with "uat:", try to turn it into
 * a valid uat entry.
 */
static gboolean
prefs_set_uat_pref(char *uat_entry) {
    gchar *p, *colonp;
    uat_t *uat;
    gchar *err;

    colonp = strchr(uat_entry, ':');
    if (colonp == NULL)
        return FALSE;

    p = colonp;
    *p++ = '\0';

    /*
     * Skip over any white space (there probably won't be any, but
     * as we allow it in the preferences file, we might as well
     * allow it here).
     */
    while (isspace((guchar)*p))
        p++;
    if (*p == '\0') {
        /*
         * Put the colon back, so if our caller uses, in an
         * error message, the string they passed us, the message
         * looks correct.
         */
        *colonp = ':';
        return FALSE;
    }

    uat = uat_find(uat_entry);
    *colonp = ':';
    if (uat == NULL) {
        return FALSE;
    }

    if (uat_load_str(uat, p, &err)) {
        return TRUE;
    }
    return FALSE;
}

/*
 * Given a string of the form "<pref name>:<pref value>", as might appear
 * as an argument to a "-o" option, parse it and set the preference in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
prefs_set_pref_e
prefs_set_pref(char *prefarg)
{
    gchar *p, *colonp;
    prefs_set_pref_e ret;

    /*
     * Set the counters of "mgcp.{tcp,udp}.port" entries we've
     * seen to values that keep us from trying to interpret tham
     * as "mgcp.{tcp,udp}.gateway_port" or "mgcp.{tcp,udp}.callagent_port",
     * as, from the command line, we have no way of guessing which
     * the user had in mind.
     */
    mgcp_tcp_port_count = -1;
    mgcp_udp_port_count = -1;

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
    while (isspace((guchar)*p))
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
    if (strcmp(prefarg, "uat")) {
        ret = set_pref(prefarg, p, NULL, TRUE);
    } else {
        ret = prefs_set_uat_pref(p) ? PREFS_SET_OK : PREFS_SET_SYNTAX_ERR;
    }
    *colonp = ':';    /* put the colon back */
    return ret;
}

/*
 * Returns TRUE if the given device is hidden
 */
gboolean
prefs_is_capture_device_hidden(const char *name)
{
    gchar *tok, *devices;
    size_t len;

    if (prefs.capture_devices_hide && name) {
        devices = g_strdup (prefs.capture_devices_hide);
        len = strlen (name);
        for (tok = strtok (devices, ","); tok; tok = strtok(NULL, ",")) {
            if (strlen (tok) == len && strcmp (name, tok) == 0) {
                g_free (devices);
                return TRUE;
            }
        }
        g_free (devices);
    }

    return FALSE;
}

/*
 * Returns TRUE if the given column is visible (not hidden)
 */
static gboolean
prefs_is_column_visible(const gchar *cols_hidden, fmt_data *cfmt)
{
    gchar *tok, *cols;
    fmt_data cfmt_hidden;

    /*
     * Do we have a list of hidden columns?
     */
    if (cols_hidden) {
        /*
         * Yes - check the column against each of the ones in the
         * list.
         */
        cols = g_strdup(cols_hidden);
        for (tok = strtok(cols, ","); tok; tok = strtok(NULL, ",")) {
            tok = g_strstrip(tok);

            /*
             * Parse this column format.
             */
            if (!parse_column_format(&cfmt_hidden, tok)) {
                /*
                 * It's not valid; ignore it.
                 */
                continue;
            }

            /*
             * Does it match the column?
             */
            if (cfmt->fmt != cfmt_hidden.fmt) {
                /* No. */
                g_free(cfmt_hidden.custom_field);
                continue;
            }
            if (cfmt->fmt == COL_CUSTOM) {
                /*
                 * A custom column has to have the
                 * same custom field and occurrence.
                 */
                if (strcmp(cfmt->custom_field,
                           cfmt_hidden.custom_field) != 0) {
                    /* Different fields. */
                    g_free(cfmt_hidden.custom_field);
                    continue;
                }
                if (cfmt->custom_occurrence != cfmt_hidden.custom_occurrence) {
                    /* Different occurrences. */
                    g_free(cfmt_hidden.custom_field);
                    continue;
                }
            }

            /*
             * OK, they match, so it's one of the hidden fields,
             * hence not visible.
             */
            g_free(cfmt_hidden.custom_field);
            g_free(cols);
            return FALSE;
        }
        g_free(cols);
    }

    /*
     * No - either there are no hidden columns or this isn't one
     * of them - so it is visible.
     */
    return TRUE;
}

/*
 * Returns TRUE if the given device should capture in monitor mode by default
 */
gboolean
prefs_capture_device_monitor_mode(const char *name)
{
    gchar *tok, *devices;
    size_t len;

    if (prefs.capture_devices_monitor_mode && name) {
        devices = g_strdup (prefs.capture_devices_monitor_mode);
        len = strlen (name);
        for (tok = strtok (devices, ","); tok; tok = strtok(NULL, ",")) {
            if (strlen (tok) == len && strcmp (name, tok) == 0) {
                g_free (devices);
                return TRUE;
            }
        }
        g_free (devices);
    }

    return FALSE;
}

/*
 * Returns TRUE if the user has marked this column as visible
 */
gboolean
prefs_capture_options_dialog_column_is_visible(const gchar *column)
{
    GList *curr;
    gchar *col;

    for (curr = g_list_first(prefs.capture_columns); curr; curr = g_list_next(curr)) {
        col = (gchar *)curr->data;
        if (col && (g_ascii_strcasecmp(col, column) == 0)) {
            return TRUE;
        }
    }
    return FALSE;
}

#define PRS_GUI_FILTER_LABEL             "gui.filter_expressions.label"
#define PRS_GUI_FILTER_EXPR              "gui.filter_expressions.expr"
#define PRS_GUI_FILTER_ENABLED           "gui.filter_expressions.enabled"

#define RED_COMPONENT(x)   (guint16) (((((x) >> 16) & 0xff) * 65535 / 255))
#define GREEN_COMPONENT(x) (guint16) (((((x) >>  8) & 0xff) * 65535 / 255))
#define BLUE_COMPONENT(x)  (guint16) ( (((x)        & 0xff) * 65535 / 255))

char
string_to_name_resolve(char *string, e_addr_resolve *name_resolve)
{
  char c;

  memset(name_resolve, 0, sizeof(e_addr_resolve));
  while ((c = *string++) != '\0') {
      switch (c) {
      case 'm':
          name_resolve->mac_name = TRUE;
          break;
      case 'n':
          name_resolve->network_name = TRUE;
          break;
      case 'N':
          name_resolve->use_external_net_name_resolver = TRUE;
          break;
      case 't':
          name_resolve->transport_name = TRUE;
          break;
      case 'C':
          name_resolve->concurrent_dns = TRUE;
          break;
      default:
          /*
           * Unrecognized letter.
           */
          return c;
      }
  }
  return '\0';
}


static void
try_convert_to_custom_column(gpointer *el_data)
{
    /* Array of columns that have been migrated to custom columns */
    struct {
        gint el;
        gchar *col_expr;
    } migrated_columns[] = {
        { COL_COS_VALUE, "vlan.priority" },
        { COL_CIRCUIT_ID, "iax2.call" },
        { COL_BSSGP_TLLI, "bssgp.tlli" },
        { COL_HPUX_SUBSYS, "nettl.subsys" },
        { COL_HPUX_DEVID, "nettl.devid" },
        { COL_FR_DLCI, "fr.dlci" },
        { COL_REL_CONV_TIME, "tcp.time_relative" },
        { COL_DELTA_CONV_TIME, "tcp.time_delta" },
        { COL_OXID, "fc.ox_id" },
        { COL_RXID, "fc.rx_id" },
        { COL_SRCIDX, "mdshdr.srcidx" },
        { COL_DSTIDX, "mdshdr.dstidx" },
        { COL_DCE_CTX, "dcerpc.cn_ctx_id" }
    };

    guint haystack_idx;
    const gchar *haystack_fmt;

    gchar **fmt = (gchar **) el_data;

    for (haystack_idx = 0;
         haystack_idx < G_N_ELEMENTS(migrated_columns);
         ++haystack_idx) {

        haystack_fmt = col_format_to_string(migrated_columns[haystack_idx].el);
        if (strcmp(haystack_fmt, *fmt) == 0) {
            gchar *cust_col = g_strdup_printf("%%Cus:%s:0",
                                migrated_columns[haystack_idx].col_expr);

            g_free(*fmt);
            *fmt = cust_col;
        }
    }
}

static prefs_set_pref_e
set_pref(gchar *pref_name, gchar *value, void *private_data _U_,
         gboolean return_range_errors)
{
  unsigned long int cval;
  guint    uval;
  gboolean bval;
  gint     enum_val;
  char     *p;
  gchar    *dotp, *last_dotp;
  static gchar *filter_label = NULL;
  static gboolean filter_enabled = FALSE;
  gchar    *filter_expr = NULL;
  module_t *module;
  pref_t   *pref;
  gboolean had_a_dot;

  if (strcmp(pref_name, PRS_GUI_FILTER_LABEL) == 0) {
    filter_label = g_strdup(value);
  } else if (strcmp(pref_name, PRS_GUI_FILTER_ENABLED) == 0) {
    filter_enabled = (strcmp(value, "TRUE") == 0) ? TRUE : FALSE;
  } else if (strcmp(pref_name, PRS_GUI_FILTER_EXPR) == 0) {
    filter_expr = g_strdup(value);
    filter_expression_new(filter_label, filter_expr, filter_enabled);
    g_free(filter_label);
    g_free(filter_expr);
  } else if (strcmp(pref_name, "gui.version_in_start_page") == 0) {
    /* Convert deprecated value to closest current equivalent */
    if (g_ascii_strcasecmp(value, "true") == 0) {
	    prefs.gui_version_placement = version_both;
    } else {
	    prefs.gui_version_placement = version_neither;
    }
/* handle the deprecated name resolution options */
  } else if (strcmp(pref_name, "name_resolve") == 0 ||
	     strcmp(pref_name, "capture.name_resolve") == 0) {
    /*
     * "TRUE" and "FALSE", for backwards compatibility, are synonyms for
     * RESOLV_ALL and RESOLV_NONE.
     *
     * Otherwise, we treat it as a list of name types we want to resolve.
     */
     if (g_ascii_strcasecmp(value, "true") == 0) {
        gbl_resolv_flags.mac_name = TRUE;
        gbl_resolv_flags.network_name = TRUE;
        gbl_resolv_flags.transport_name = TRUE;
        gbl_resolv_flags.concurrent_dns = TRUE;
     }
     else if (g_ascii_strcasecmp(value, "false") == 0) {
        gbl_resolv_flags.mac_name = FALSE;
        gbl_resolv_flags.network_name = FALSE;
        gbl_resolv_flags.transport_name = FALSE;
        gbl_resolv_flags.concurrent_dns = FALSE;
     }
     else {
        /* start out with none set */
        gbl_resolv_flags.mac_name = FALSE;
        gbl_resolv_flags.network_name = FALSE;
        gbl_resolv_flags.transport_name = FALSE;
        gbl_resolv_flags.concurrent_dns = FALSE;
        if (string_to_name_resolve(value, &gbl_resolv_flags) != '\0')
           return PREFS_SET_SYNTAX_ERR;
     }
  } else {
    /* Handle deprecated "global" options that don't have a module
     * associated with them
     */
    if ((strcmp(pref_name, "name_resolve_concurrency") == 0) ||
        (strcmp(pref_name, "name_resolve_load_smi_modules") == 0)  ||
        (strcmp(pref_name, "name_resolve_suppress_smi_errors") == 0)) {
        module = nameres_module;
        dotp = pref_name;
    } else {
      /* To which module does this preference belong? */
      module = NULL;
      last_dotp = pref_name;
      had_a_dot = FALSE;
      while (!module) {
        dotp = strchr(last_dotp, '.');
        if (dotp == NULL) {
            if (had_a_dot) {
              /* no such module */
              return PREFS_SET_NO_SUCH_PREF;
            }
            else {
              /* no ".", so no module/name separator */
              return PREFS_SET_SYNTAX_ERR;
            }
        }
        else {
            had_a_dot = TRUE;
        }
        *dotp = '\0';		/* separate module and preference name */
        module = prefs_find_module(pref_name);

        /*
         * XXX - "Diameter" rather than "diameter" was used in earlier
         * versions of Wireshark; if we didn't find the module, and its name
         * was "Diameter", look for "diameter" instead.
         *
         * In addition, the BEEP protocol used to be the BXXP protocol,
         * so if we didn't find the module, and its name was "bxxp",
         * look for "beep" instead.
         *
         * Also, the preferences for GTP v0 and v1 were combined under
         * a single "gtp" heading, and the preferences for SMPP were
         * moved to "smpp-gsm-sms" and then moved to "gsm-sms-ud".
         * However, SMPP now has its own preferences, so we just map
         * "smpp-gsm-sms" to "gsm-sms-ud", and then handle SMPP below.
         *
         * We also renamed "dcp" to "dccp", "x.25" to "x25", "x411" to "p1"
         * and "nsip" to "gprs_ns".
         *
         * The SynOptics Network Management Protocol (SONMP) is now known by
         * its modern name, the Nortel Discovery Protocol (NDP).
         *
         */
        if (module == NULL) {
          if (strcmp(pref_name, "column") == 0)
            module = gui_column_module;
          else if (strcmp(pref_name, "Diameter") == 0)
            module = prefs_find_module("diameter");
          else if (strcmp(pref_name, "bxxp") == 0)
            module = prefs_find_module("beep");
          else if (strcmp(pref_name, "gtpv0") == 0 ||
                   strcmp(pref_name, "gtpv1") == 0)
            module = prefs_find_module("gtp");
          else if (strcmp(pref_name, "smpp-gsm-sms") == 0)
            module = prefs_find_module("gsm-sms-ud");
          else if (strcmp(pref_name, "dcp") == 0)
            module = prefs_find_module("dccp");
          else if (strcmp(pref_name, "x.25") == 0)
            module = prefs_find_module("x25");
          else if (strcmp(pref_name, "x411") == 0)
            module = prefs_find_module("p1");
          else if (strcmp(pref_name, "nsip") == 0)
            module = prefs_find_module("gprs-ns");
          else if (strcmp(pref_name, "sonmp") == 0)
            module = prefs_find_module("ndp");
          else if (strcmp(pref_name, "etheric") == 0 ||
                   strcmp(pref_name, "isup_thin") == 0)
            /* This protocols was removed 7. July 2009 */
            return PREFS_SET_OBSOLETE;
        }
        *dotp = '.';                /* put the preference string back */
        dotp++;                        /* skip past separator to preference name */
        last_dotp = dotp;
      }
    }

    pref = prefs_find_preference(module, dotp);

    if (pref == NULL) {
      /* "gui" prefix was added to column preferences for better organization
       * within the preferences file
       */
      if ((strcmp(pref_name, PRS_COL_HIDDEN) == 0) ||
          (strcmp(pref_name, PRS_COL_FMT) == 0)) {
         pref = prefs_find_preference(module, pref_name);
      }
      else if (strcmp(module->name, "mgcp") == 0) {
        /*
         * XXX - "mgcp.display raw text toggle" and "mgcp.display dissect tree"
         * rather than "mgcp.display_raw_text" and "mgcp.display_dissect_tree"
         * were used in earlier versions of Wireshark; if we didn't find the
         * preference, it was an MGCP preference, and its name was
         * "display raw text toggle" or "display dissect tree", look for
         * "display_raw_text" or "display_dissect_tree" instead.
         *
         * "mgcp.tcp.port" and "mgcp.udp.port" are harder to handle, as both
         * the gateway and callagent ports were given those names; we interpret
         * the first as "mgcp.{tcp,udp}.gateway_port" and the second as
         * "mgcp.{tcp,udp}.callagent_port", as that's the order in which
         * they were registered by the MCCP dissector and thus that's the
         * order in which they were written to the preferences file.  (If
         * we're not reading the preferences file, but are handling stuff
         * from a "-o" command-line option, we have no clue which the user
         * had in mind - they should have used "mgcp.{tcp,udp}.gateway_port"
         * or "mgcp.{tcp,udp}.callagent_port" instead.)
         */
        if (strcmp(dotp, "display raw text toggle") == 0)
          pref = prefs_find_preference(module, "display_raw_text");
        else if (strcmp(dotp, "display dissect tree") == 0)
          pref = prefs_find_preference(module, "display_dissect_tree");
        else if (strcmp(dotp, "tcp.port") == 0) {
          mgcp_tcp_port_count++;
          if (mgcp_tcp_port_count == 1) {
            /* It's the first one */
            pref = prefs_find_preference(module, "tcp.gateway_port");
          } else if (mgcp_tcp_port_count == 2) {
            /* It's the second one */
            pref = prefs_find_preference(module, "tcp.callagent_port");
          }
          /* Otherwise it's from the command line, and we don't bother
             mapping it. */
        } else if (strcmp(dotp, "udp.port") == 0) {
          mgcp_udp_port_count++;
          if (mgcp_udp_port_count == 1) {
            /* It's the first one */
            pref = prefs_find_preference(module, "udp.gateway_port");
          } else if (mgcp_udp_port_count == 2) {
            /* It's the second one */
            pref = prefs_find_preference(module, "udp.callagent_port");
          }
          /* Otherwise it's from the command line, and we don't bother
             mapping it. */
        }
      } else if (strcmp(module->name, "smb") == 0) {
        /* Handle old names for SMB preferences. */
        if (strcmp(dotp, "smb.trans.reassembly") == 0)
          pref = prefs_find_preference(module, "trans_reassembly");
        else if (strcmp(dotp, "smb.dcerpc.reassembly") == 0)
          pref = prefs_find_preference(module, "dcerpc_reassembly");
      } else if (strcmp(module->name, "ndmp") == 0) {
        /* Handle old names for NDMP preferences. */
        if (strcmp(dotp, "ndmp.desegment") == 0)
          pref = prefs_find_preference(module, "desegment");
      } else if (strcmp(module->name, "diameter") == 0) {
        /* Handle old names for Diameter preferences. */
        if (strcmp(dotp, "diameter.desegment") == 0)
          pref = prefs_find_preference(module, "desegment");
      } else if (strcmp(module->name, "pcli") == 0) {
        /* Handle old names for PCLI preferences. */
        if (strcmp(dotp, "pcli.udp_port") == 0)
          pref = prefs_find_preference(module, "udp_port");
      } else if (strcmp(module->name, "artnet") == 0) {
        /* Handle old names for ARTNET preferences. */
        if (strcmp(dotp, "artnet.udp_port") == 0)
          pref = prefs_find_preference(module, "udp_port");
      } else if (strcmp(module->name, "mapi") == 0) {
        /* Handle old names for MAPI preferences. */
        if (strcmp(dotp, "mapi_decrypt") == 0)
          pref = prefs_find_preference(module, "decrypt");
      } else if (strcmp(module->name, "fc") == 0) {
        /* Handle old names for Fibre Channel preferences. */
        if (strcmp(dotp, "reassemble_fc") == 0)
          pref = prefs_find_preference(module, "reassemble");
        else if (strcmp(dotp, "fc_max_frame_size") == 0)
          pref = prefs_find_preference(module, "max_frame_size");
      } else if (strcmp(module->name, "fcip") == 0) {
        /* Handle old names for Fibre Channel-over-IP preferences. */
        if (strcmp(dotp, "desegment_fcip_messages") == 0)
          pref = prefs_find_preference(module, "desegment");
        else if (strcmp(dotp, "fcip_port") == 0)
          pref = prefs_find_preference(module, "target_port");
      } else if (strcmp(module->name, "gtp") == 0) {
        /* Handle old names for GTP preferences. */
        if (strcmp(dotp, "gtpv0_port") == 0)
          pref = prefs_find_preference(module, "v0_port");
        else if (strcmp(dotp, "gtpv1c_port") == 0)
          pref = prefs_find_preference(module, "v1c_port");
        else if (strcmp(dotp, "gtpv1u_port") == 0)
          pref = prefs_find_preference(module, "v1u_port");
        else if (strcmp(dotp, "gtp_dissect_tpdu") == 0)
          pref = prefs_find_preference(module, "dissect_tpdu");
        else if (strcmp(dotp, "gtpv0_dissect_cdr_as") == 0)
          pref = prefs_find_preference(module, "v0_dissect_cdr_as");
        else if (strcmp(dotp, "gtpv0_check_etsi") == 0)
          pref = prefs_find_preference(module, "v0_check_etsi");
        else if (strcmp(dotp, "gtpv1_check_etsi") == 0)
          pref = prefs_find_preference(module, "v1_check_etsi");
      } else if (strcmp(module->name, "ip") == 0) {
        /* Handle old names for IP preferences. */
        if (strcmp(dotp, "ip_summary_in_tree") == 0)
          pref = prefs_find_preference(module, "summary_in_tree");
      } else if (strcmp(module->name, "iscsi") == 0) {
        /* Handle old names for iSCSI preferences. */
        if (strcmp(dotp, "iscsi_port") == 0)
          pref = prefs_find_preference(module, "target_port");
      } else if (strcmp(module->name, "lmp") == 0) {
        /* Handle old names for LMP preferences. */
        if (strcmp(dotp, "lmp_version") == 0)
          pref = prefs_find_preference(module, "version");
      } else if (strcmp(module->name, "mtp3") == 0) {
        /* Handle old names for MTP3 preferences. */
        if (strcmp(dotp, "mtp3_standard") == 0)
          pref = prefs_find_preference(module, "standard");
        else if (strcmp(dotp, "net_addr_format") == 0)
          pref = prefs_find_preference(module, "addr_format");
      } else if (strcmp(module->name, "nlm") == 0) {
        /* Handle old names for NLM preferences. */
        if (strcmp(dotp, "nlm_msg_res_matching") == 0)
          pref = prefs_find_preference(module, "msg_res_matching");
      } else if (strcmp(module->name, "ppp") == 0) {
        /* Handle old names for PPP preferences. */
        if (strcmp(dotp, "ppp_fcs") == 0)
          pref = prefs_find_preference(module, "fcs_type");
        else if (strcmp(dotp, "ppp_vj") == 0)
          pref = prefs_find_preference(module, "decompress_vj");
      } else if (strcmp(module->name, "rsvp") == 0) {
        /* Handle old names for RSVP preferences. */
        if (strcmp(dotp, "rsvp_process_bundle") == 0)
          pref = prefs_find_preference(module, "process_bundle");
      } else if (strcmp(module->name, "tcp") == 0) {
        /* Handle old names for TCP preferences. */
        if (strcmp(dotp, "tcp_summary_in_tree") == 0)
          pref = prefs_find_preference(module, "summary_in_tree");
        else if (strcmp(dotp, "tcp_analyze_sequence_numbers") == 0)
          pref = prefs_find_preference(module, "analyze_sequence_numbers");
        else if (strcmp(dotp, "tcp_relative_sequence_numbers") == 0)
          pref = prefs_find_preference(module, "relative_sequence_numbers");
      } else if (strcmp(module->name, "udp") == 0) {
        /* Handle old names for UDP preferences. */
        if (strcmp(dotp, "udp_summary_in_tree") == 0)
          pref = prefs_find_preference(module, "summary_in_tree");
      } else if (strcmp(module->name, "ndps") == 0) {
        /* Handle old names for NDPS preferences. */
        if (strcmp(dotp, "desegment_ndps") == 0)
          pref = prefs_find_preference(module, "desegment_tcp");
      } else if (strcmp(module->name, "http") == 0) {
        /* Handle old names for HTTP preferences. */
        if (strcmp(dotp, "desegment_http_headers") == 0)
          pref = prefs_find_preference(module, "desegment_headers");
        else if (strcmp(dotp, "desegment_http_body") == 0)
          pref = prefs_find_preference(module, "desegment_body");
      } else if (strcmp(module->name, "smpp") == 0) {
        /* Handle preferences that moved from SMPP. */
        module_t *new_module = prefs_find_module("gsm-sms-ud");
        if(new_module){
          if (strcmp(dotp, "port_number_udh_means_wsp") == 0)
            pref = prefs_find_preference(new_module, "port_number_udh_means_wsp");
          else if (strcmp(dotp, "try_dissect_1st_fragment") == 0)
            pref = prefs_find_preference(new_module, "try_dissect_1st_fragment");
        }
      } else if (strcmp(module->name, "asn1") == 0) {
        /* Handle old generic ASN.1 preferences (it's not really a
           rename, as the new preferences support multiple ports,
           but we might as well copy them over). */
        if (strcmp(dotp, "tcp_port") == 0)
          pref = prefs_find_preference(module, "tcp_ports");
        else if (strcmp(dotp, "udp_port") == 0)
          pref = prefs_find_preference(module, "udp_ports");
        else if (strcmp(dotp, "sctp_port") == 0)
          pref = prefs_find_preference(module, "sctp_ports");
      } else if (strcmp(module->name, "llcgprs") == 0) {
        if (strcmp(dotp, "ignore_cipher_bit") == 0)
          pref = prefs_find_preference(module, "autodetect_cipher_bit");
      } else if (strcmp(module->name, "erf") == 0) {
        if (strcmp(dotp, "erfeth") == 0) {
          /* Handle the old "erfeth" preference; map it to the new
             "ethfcs" preference, and map the values to those for
             the new preference. */
          pref = prefs_find_preference(module, "ethfcs");
          if (strcmp(value, "ethfcs") == 0 || strcmp(value, "Ethernet with FCS") == 0)
            value = "TRUE";
          else if (strcmp(value, "eth") == 0 || strcmp(value, "Ethernet") == 0)
            value = "FALSE";
          else if (strcmp(value, "raw") == 0 || strcmp(value, "Raw data") == 0)
            value = "TRUE";
        } else if (strcmp(dotp, "erfatm") == 0) {
          /* Handle the old "erfatm" preference; map it to the new
             "aal5_type" preference, and map the values to those for
             the new preference. */
          pref = prefs_find_preference(module, "aal5_type");
          if (strcmp(value, "atm") == 0 || strcmp(value, "ATM") == 0)
            value = "guess";
          else if (strcmp(value, "llc") == 0 || strcmp(value, "LLC") == 0)
            value = "llc";
          else if (strcmp(value, "raw") == 0 || strcmp(value, "Raw data") == 0)
            value = "guess";
        } else if (strcmp(dotp, "erfhdlc") == 0) {
          /* Handle the old "erfhdlc" preference; map it to the new
             "hdlc_type" preference, and map the values to those for
             the new preference. */
          pref = prefs_find_preference(module, "hdlc_type");
          if (strcmp(value, "chdlc") == 0 || strcmp(value, "Cisco HDLC") == 0)
            value = "chdlc";
          else if (strcmp(value, "ppp") == 0 || strcmp(value, "PPP serial") == 0)
            value = "ppp";
          else if (strcmp(value, "fr") == 0 || strcmp(value, "Frame Relay") == 0)
            value = "frelay";
          else if (strcmp(value, "mtp2") == 0 || strcmp(value, "SS7 MTP2") == 0)
            value = "mtp2";
          else if (strcmp(value, "raw") == 0 || strcmp(value, "Raw data") == 0)
            value = "guess";
        }
      } else if (strcmp(module->name, "eth") == 0) {
        /* "eth.qinq_ethertype" has been changed(restored) to "vlan.qinq.ethertype" */
        if (strcmp(dotp, "qinq_ethertype") == 0) {
          module_t *new_module = prefs_find_module("vlan");
          if(new_module) {
            pref = prefs_find_preference(new_module, "qinq_ethertype");
            module = new_module;
          }
        }
      } else if (strcmp(module->name, "taps") == 0) {
          /* taps preferences moved to stats module */
          if (strcmp(dotp, "update_interval") == 0 || strcmp(value, "rtp_player_max_visible") == 0)
            pref = prefs_find_preference(stats_module, dotp);
      } else if (strcmp(module->name, "packet_list") == 0) {
          /* packet_list preferences moved to protocol module */
          if (strcmp(dotp, "display_hidden_proto_items") == 0)
            pref = prefs_find_preference(protocols_module, dotp);
      } else if (strcmp(module->name, "stream") == 0) {
          /* stream preferences moved to gui color module */
          if ((strcmp(dotp, "stream.client.fg") == 0) || (strcmp(value, "stream.client.bg") == 0) ||
              (strcmp(dotp, "stream.server.fg") == 0) || (strcmp(value, "stream.server.bg") == 0))
            pref = prefs_find_preference(gui_color_module, pref_name);
      } else if (strcmp(module->name, "nameres") == 0) {
          if (strcmp(pref_name, "name_resolve_concurrency") == 0) {
            pref = prefs_find_preference(nameres_module, pref_name);
          } else if (strcmp(pref_name, "name_resolve_load_smi_modules") == 0) {
            pref = prefs_find_preference(nameres_module, "load_smi_modules");
          } else if (strcmp(pref_name, "name_resolve_suppress_smi_errors") == 0) {
            pref = prefs_find_preference(nameres_module, "suppress_smi_errors");
          }
      }
    }
    if (pref == NULL)
      return PREFS_SET_NO_SUCH_PREF;        /* no such preference */

    switch (pref->type) {

    case PREF_UINT:
      uval = strtoul(value, &p, pref->info.base);
      if (p == value || *p != '\0')
        return PREFS_SET_SYNTAX_ERR;        /* number was bad */
      if (*pref->varp.uint != uval) {
        module->prefs_changed = TRUE;
        *pref->varp.uint = uval;
      }
      break;

    case PREF_BOOL:
      /* XXX - give an error if it's neither "true" nor "false"? */
      if (g_ascii_strcasecmp(value, "true") == 0)
        bval = TRUE;
      else
        bval = FALSE;
      if (*pref->varp.boolp != bval) {
        module->prefs_changed = TRUE;
        *pref->varp.boolp = bval;
      }
      break;

    case PREF_ENUM:
      /* XXX - give an error if it doesn't match? */
      enum_val = find_val_for_string(value, pref->info.enum_info.enumvals,
                                     *pref->varp.enump);
      if (*pref->varp.enump != enum_val) {
        module->prefs_changed = TRUE;
        *pref->varp.enump = enum_val;
      }
      break;

    case PREF_STRING:
    case PREF_FILENAME:
      if (strcmp(*pref->varp.string, value) != 0) {
        module->prefs_changed = TRUE;
        g_free((void *)*pref->varp.string);
        *pref->varp.string = g_strdup(value);
      }
      break;

    case PREF_RANGE:
    {
      range_t *newrange;

      if (range_convert_str_work(&newrange, value, pref->info.max_value,
                                 return_range_errors) != CVT_NO_ERROR) {
        return PREFS_SET_SYNTAX_ERR;        /* number was bad */
      }

      if (!ranges_are_equal(*pref->varp.range, newrange)) {
        module->prefs_changed = TRUE;
        g_free(*pref->varp.range);
        *pref->varp.range = newrange;
      } else {
        g_free (newrange);
      }
      break;
    }

    case PREF_COLOR:
    {
      cval = strtoul(value, NULL, 16);
      pref->varp.color->pixel = 0;
      if ((pref->varp.color->red != RED_COMPONENT(cval)) ||
          (pref->varp.color->green != GREEN_COMPONENT(cval)) ||
          (pref->varp.color->blue != BLUE_COMPONENT(cval))) {
          module->prefs_changed = TRUE;
          pref->varp.color->red   = RED_COMPONENT(cval);
          pref->varp.color->green = GREEN_COMPONENT(cval);
          pref->varp.color->blue  = BLUE_COMPONENT(cval);
      }
      break;
    }

    case PREF_CUSTOM:
        return pref->custom_cbs.set_cb(pref, value, &module->prefs_changed);

    case PREF_STATIC_TEXT:
    case PREF_UAT:
    {
      break;
    }

    case PREF_OBSOLETE:
      return PREFS_SET_OBSOLETE;        /* no such preference any more */
    }
  }

  return PREFS_SET_OK;
}

typedef struct {
    FILE     *pf;
    gboolean is_gui_module;
} write_gui_pref_arg_t;

/*
 * Write out a single dissector preference.
 */
static void
write_pref(gpointer data, gpointer user_data)
{
    pref_t *pref = data;
    write_pref_arg_t *arg = user_data;
    const enum_val_t *enum_valp;
    const char *val_string, *prefix;
    gchar **desc_lines;
    int i;

    switch (pref->type) {
    case PREF_OBSOLETE:
        /*
         * This preference is no longer supported; it's not a
         * real preference, so we don't write it out (i.e., we
         * treat it as if it weren't found in the list of
         * preferences, and we weren't called in the first place).
         */
        return;

    case PREF_STATIC_TEXT:
    case PREF_UAT:
	/* Nothing to do; don't bother printing the description */
        return;
    default:
	break;
    }

    /*
     * The prefix will either be the module name or the parent
     * name if its a subtree
     */
    prefix = (arg->module->name != NULL) ? arg->module->name : arg->module->parent->name;

    /*
     * Make multiple line descriptions appear as
     * multiple commented lines in prefs file.
     */
    if (pref->type != PREF_CUSTOM) {
        if (pref->description &&
                (g_ascii_strncasecmp(pref->description,"", 2) != 0)) {
            desc_lines = g_strsplit(pref->description,"\n",0);
            for (i = 0; desc_lines[i] != NULL; ++i) {
                fprintf(arg->pf, "\n# %s", desc_lines[i]);
            }
            fprintf(arg->pf, "\n");
            g_strfreev(desc_lines);
        } else {
            fprintf(arg->pf, "\n# No description\n");
        }
    }

    switch (pref->type) {

    case PREF_UINT:
        switch (pref->info.base) {

        case 10:
            fprintf(arg->pf, "# A decimal number.\n");
            if (pref->default_val.uint == *pref->varp.uint)
                fprintf(arg->pf, "#");
            fprintf(arg->pf, "%s.%s: %u\n", prefix,
                pref->name, *pref->varp.uint);
            break;

        case 8:
            fprintf(arg->pf, "# An octal number.\n");
            if (pref->default_val.uint == *pref->varp.uint)
                fprintf(arg->pf, "#");
            fprintf(arg->pf, "%s.%s: %#o\n", prefix,
                pref->name, *pref->varp.uint);
            break;

        case 16:
            fprintf(arg->pf, "# A hexadecimal number.\n");
            if (pref->default_val.uint == *pref->varp.uint)
                fprintf(arg->pf, "#");
            fprintf(arg->pf, "%s.%s: %#x\n", prefix,
                pref->name, *pref->varp.uint);
            break;
        }
        break;

    case PREF_BOOL:
        fprintf(arg->pf, "# TRUE or FALSE (case-insensitive).\n");
        if (pref->default_val.boolval == *pref->varp.boolp)
            fprintf(arg->pf, "#");
        fprintf(arg->pf, "%s.%s: %s\n", prefix, pref->name,
            *pref->varp.boolp ? "TRUE" : "FALSE");
        break;

    case PREF_ENUM:
        /*
         * For now, we save the "description" value, so that if we
         * save the preferences older versions of Wireshark can at
         * least read preferences that they supported; we support
         * either the short name or the description when reading
         * the preferences file or a "-o" option.
         */
        fprintf(arg->pf, "# One of: ");
        enum_valp = pref->info.enum_info.enumvals;
        val_string = NULL;
        while (enum_valp->name != NULL) {
            if (enum_valp->value == *pref->varp.enump)
                val_string = enum_valp->description;
            fprintf(arg->pf, "%s", enum_valp->description);
            enum_valp++;
            if (enum_valp->name == NULL)
                fprintf(arg->pf, "\n");
            else
                fprintf(arg->pf, ", ");
        }
        fprintf(arg->pf, "# (case-insensitive).\n");
        if (pref->default_val.enumval == *pref->varp.enump)
            fprintf(arg->pf, "#");
        fprintf(arg->pf, "%s.%s: %s\n", prefix,
            pref->name, val_string);
        break;

    case PREF_STRING:
    case PREF_FILENAME:
        fprintf(arg->pf, "# A string.\n");
        if (!(strcmp(pref->default_val.string, *pref->varp.string)))
            fprintf(arg->pf, "#");
        fprintf(arg->pf, "%s.%s: %s\n", prefix, pref->name,
            *pref->varp.string);
        break;

    case PREF_RANGE:
    {
        char *range_string_p;

        range_string_p = range_convert_range(*pref->varp.range);
        fprintf(arg->pf, "# A string denoting an positive integer range (e.g., \"1-20,30-40\").\n");
        if ((ranges_are_equal(pref->default_val.range, *pref->varp.range)))
            fprintf(arg->pf, "#");
        fprintf(arg->pf, "%s.%s: %s\n", prefix, pref->name,
            range_string_p);
        break;
    }

    case PREF_COLOR:
    {
        fprintf (arg->pf, "# Each value is a six digit hexadecimal color value in the form rrggbb.\n");
        if ((pref->default_val.color.red == pref->varp.color->red) &&
            (pref->default_val.color.green == pref->varp.color->green) &&
            (pref->default_val.color.blue == pref->varp.color->blue))
            fprintf(arg->pf, "#");
        fprintf (arg->pf, "%s.%s: %02x%02x%02x\n", prefix, pref->name,
                   (pref->varp.color->red * 255 / 65535),
                   (pref->varp.color->green * 255 / 65535),
                   (pref->varp.color->blue * 255 / 65535));
        break;
    }

    case PREF_CUSTOM:
        pref->custom_cbs.write_cb(pref, arg);
        break;

    case PREF_OBSOLETE:
    case PREF_STATIC_TEXT:
    case PREF_UAT:
        g_assert_not_reached();
        break;
    }
}

/*
 * Write out all preferences for a module.
 */
static guint
write_module_prefs(module_t *module, gpointer user_data)
{
    write_gui_pref_arg_t *gui_pref_arg = (write_gui_pref_arg_t*)user_data;
    write_pref_arg_t arg;

    /* The GUI module needs to be explicitly called out so it
       can be written out of order */
    if ((module == gui_module) && (gui_pref_arg->is_gui_module != TRUE))
        return 0;

    /* Write a header for the main modules and GUI sub-modules */
    if (((module->parent == NULL) || (module->parent == gui_module)) &&
        ((prefs_module_has_submodules(module)) ||
         (module->numprefs > 0) ||
         (module->name == NULL))) {
         if ((module->name == NULL) && (module->parent != NULL)) {
            fprintf(gui_pref_arg->pf, "\n####### %s: %s ########\n", module->parent->title, module->title);
         } else {
            fprintf(gui_pref_arg->pf, "\n####### %s ########\n", module->title);
         }
    }

    arg.module = module;
    arg.pf = gui_pref_arg->pf;
    g_list_foreach(arg.module->prefs, write_pref, &arg);

    if(prefs_module_has_submodules(module))
        return prefs_modules_foreach_submodules(module, write_module_prefs, user_data);

    return 0;
}

/* Write out "prefs" to the user's preferences file, and return 0.

   If the preferences file path is NULL, write to stdout.

   If we got an error, stuff a pointer to the path of the preferences file
   into "*pf_path_return", and return the errno. */
int
write_prefs(char **pf_path_return)
{
  char        *pf_path;
  FILE        *pf;
  write_gui_pref_arg_t write_gui_pref_info;

  /* Needed for "-G defaultprefs" */
  init_prefs();

  /* To do:
   * - Split output lines longer than MAX_VAL_LEN
   * - Create a function for the preference directory check/creation
   *   so that duplication can be avoided with filter.c
   */

  if (pf_path_return != NULL) {
    pf_path = get_persconffile_path(PF_NAME, TRUE, TRUE);
    if ((pf = ws_fopen(pf_path, "w")) == NULL) {
      *pf_path_return = pf_path;
      return errno;
    }
  } else {
    pf = stdout;
  }

  fputs("# Configuration file for Wireshark " VERSION ".\n"
        "#\n"
        "# This file is regenerated each time preferences are saved within\n"
        "# Wireshark.  Making manual changes should be safe, however.\n"
        "# Preferences that have been commented out have not been\n"
        "# changed from their default value.\n", pf);

  /*
   * For "backwards compatibility" the GUI module is written first as its
   * at the top of the file.  This is followed by all modules that can't
   * fit into the preferences read/write API.  Finally the remaining modules
   * are written in alphabetical order (including of course the protocol preferences)
   */
  write_gui_pref_info.pf = pf;
  write_gui_pref_info.is_gui_module = TRUE;

  write_module_prefs(gui_module, &write_gui_pref_info);

  {
    struct filter_expression *fe = *(struct filter_expression **)prefs.filter_expressions;

    if (fe != NULL)
      fprintf(pf, "\n####### Filter Expressions ########\n");

    while (fe != NULL) {
      if (fe->deleted == FALSE) {
        fprintf(pf, "%s: %s\n", PRS_GUI_FILTER_LABEL, fe->label);
        fprintf(pf, "%s: %s\n", PRS_GUI_FILTER_ENABLED,
        fe->enabled == TRUE ? "TRUE" : "FALSE");
        fprintf(pf, "%s: %s\n", PRS_GUI_FILTER_EXPR, fe->expression);
      }
      fe = fe->next;
    }
  }

  write_gui_pref_info.is_gui_module = FALSE;
  prefs_modules_foreach_submodules(NULL, write_module_prefs, &write_gui_pref_info);

  fclose(pf);

  /* XXX - catch I/O errors (e.g. "ran out of disk space") and return
     an error indication, or maybe write to a new preferences file and
     rename that file on top of the old one only if there are not I/O
     errors. */
  return 0;
}

/** The col_list is only partly managed by the custom preference API
 * because its data is shared between multiple preferences, so
 * it's freed here
 */
static void
free_col_info(GList * list)
{
  fmt_data *cfmt;

  while (list != NULL) {
    cfmt = list->data;

    g_free(cfmt->title);
    g_free(cfmt->custom_field);
    g_free(cfmt);
    list = g_list_remove_link(list, list);
  }
  g_list_free(list);
  list = NULL;
}
