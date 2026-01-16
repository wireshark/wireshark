/* ui_prefs.c
 * Routines for UI preferences
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "ui/ui_prefs.h"
#include "ui/init.h"

#include <wsutil/wslog.h>
#include <wsutil/strtoi.h>

static wmem_tree_t* ui_prefs_modules;

static wmem_tree_t* ui_prefs_top_level_modules;

typedef struct ui_deprecated_data {
    module_t* module;
    ui_pref_deprecated_cb deprecated_cb;
} ui_deprecated_data_t;

static wmem_list_t* ui_prefs_deprecated = NULL;

void ui_prefs_init(void)
{
    ui_prefs_modules = wmem_tree_new(wmem_ui_scope());
    ui_prefs_top_level_modules = wmem_tree_new(wmem_ui_scope());
    ui_prefs_deprecated = wmem_list_new(wmem_ui_scope());
}

void ui_prefs_cleanup(void)
{
    wmem_tree_destroy(ui_prefs_modules, true, true);
    wmem_tree_destroy(ui_prefs_top_level_modules, true, true);
    wmem_destroy_list(ui_prefs_deprecated);
}

module_t*
ui_prefs_register_module(const char* name, const char* title,
    const char* description, const char* help,
    void (*apply_cb)(void), ui_pref_deprecated_cb depr_callback)
{
    module_t* module = prefs_register_module(ui_prefs_top_level_modules, ui_prefs_modules, name, title, description, help, apply_cb, false);
    if ((module != NULL) && (depr_callback != NULL))
    {
        ui_deprecated_data_t* data = wmem_new(wmem_ui_scope(), ui_deprecated_data_t);
        data->module = module;
        data->deprecated_cb = depr_callback;
        wmem_list_append(ui_prefs_deprecated, data);
    }

    return module;
}

/* XXX - Currently duplicated from prefs.c to not confuse dissectors
(because they don't need to ever call this) */
static unsigned
free_module_prefs(module_t* module, void* data _U_)
{
    if (module->prefs) {
        g_list_foreach(module->prefs, pref_free_individual, NULL);
        g_list_free(module->prefs);
    }
    module->prefs = NULL;
    module->numprefs = 0;
    if (module->submodules) {
        prefs_module_list_foreach(module->submodules, free_module_prefs, NULL, false);
    }
    /*  We don't free the actual module: its submodules pointer points to
        a wmem_tree and the module itself is stored in a wmem_tree
     */

    return 0;
}

void
ui_prefs_deregister_module(module_t* module)
{
    //Sanity check
    if (module == NULL)
        return;

    /* Remove this module from the list of all modules */
    module_t* removed_module = (module_t*)wmem_tree_remove_string(ui_prefs_modules, module->name, WMEM_TREE_STRING_NOCASE);
    if (!removed_module)
        return;

    wmem_tree_remove_string(ui_prefs_top_level_modules, module->title, WMEM_TREE_STRING_NOCASE);
    free_module_prefs(removed_module, NULL);
    wmem_free(removed_module->scope, removed_module);
}

unsigned
ui_prefs_write_module(module_t* module, void* user_data)
{
    ui_prefs_write_pref_arg_t* module_arg = (ui_prefs_write_pref_arg_t*)user_data;
    write_pref_arg_t pref_arg;

    /* Write a header for the main modules */
    if ( (module->parent == NULL) &&
        ((prefs_module_has_submodules(module)) ||
            (prefs_num_non_uat(module) > 0) ||
            (module->name == NULL)))
    {
        if ((module->name == NULL) && (module->parent != NULL))
        {
            fprintf(module_arg->pf, "\n####### %s: %s ########\n", module->parent->title, module->title);
        }
        else
        {
            fprintf(module_arg->pf, "\n####### %s ########\n", module->title);
        }
    }

    pref_arg.module = module;
    pref_arg.pf = module_arg->pf;
    g_list_foreach(pref_arg.module->prefs, pref_write_individual, &pref_arg);

    if (prefs_module_has_submodules(module))
        return prefs_modules_foreach_submodules(module->submodules, ui_prefs_write_module, user_data);

    return 0;
}

prefs_set_pref_e
ui_prefs_read_pref(char* pref_name, const char* value, void* private_data _U_, bool return_range_errors)
{
    unsigned cval;
    unsigned uval;
    bool     bval;
    int      ival;
    double   fval;
    char* dotp, * last_dotp;
    module_t* module = NULL;
    pref_t* pref = NULL;
    bool converted_pref = false;

    /* To which module does this preference belong? */
    last_dotp = pref_name;
    while (!module) {
        dotp = strchr(last_dotp, '.');
        if (dotp == NULL)
    {
            /* Either there's no such module, or no module was specified. */
            break;
        }
        *dotp = '\0'; /* separate module and preference name */
        module = (module_t*)wmem_tree_lookup_string(ui_prefs_modules, pref_name, WMEM_TREE_STRING_NOCASE);


        *dotp = '.';                /* put the preference string back */
        dotp++;                     /* skip past separator to preference name */
        last_dotp = dotp;
    }

    if (module == NULL)
    {
        /* Check any deprecated settings */
        wmem_list_frame_t* lf = wmem_list_head(ui_prefs_deprecated);

        while (lf != NULL)
        {
            ui_deprecated_data_t* data = (ui_deprecated_data_t*)wmem_list_frame_data(lf);
            pref = data->deprecated_cb(data->module, pref_name);
            if (pref != NULL)
            {
                /* Found preference */
                module = data->module;
                converted_pref = true;
                break;
            }
            lf = wmem_list_frame_next(lf);
        }
    }
    else
    {
        /* The pref is located in the module or a submodule.
         * Assume module, then search for a submodule holding the pref.
         */
        pref = prefs_find_preference(module, dotp);
    }

    if (pref == NULL)
        return PREFS_SET_NO_SUCH_PREF;    /* no such preference */

    if (prefs_is_preference_obsolete(pref))
        return PREFS_SET_OBSOLETE;        /* no such preference any more */

    if (converted_pref) {
        ws_warning("Preference \"%s\" has been converted to \"%s.%s\"\n"
            "Save your preferences to make this change permanent.",
            pref_name, module->name ? module->name : module->parent->name, prefs_get_name(pref));
    }

    switch (prefs_get_type(pref)) {

    case PREF_UINT:
        if (!ws_basestrtou32(value, NULL, &uval, prefs_get_uint_base(pref)))
            return PREFS_SET_SYNTAX_ERR;        /* number was bad */
        module->prefs_changed_flags |= prefs_set_uint_value(pref, uval, pref_current);
        break;
    case PREF_INT:
        if (!ws_strtoi32(value, NULL, &ival))
            return PREFS_SET_SYNTAX_ERR;        /* number was bad */
        module->prefs_changed_flags |= prefs_set_int_value(pref, ival, pref_current);
        break;
    case PREF_FLOAT:
        fval = g_ascii_strtod(value, NULL);
        if (errno == ERANGE)
            return PREFS_SET_SYNTAX_ERR;        /* number was bad */
        module->prefs_changed_flags |= prefs_set_float_value(pref, fval, pref_current);
        break;
    case PREF_BOOL:
        /* XXX - give an error if it's neither "true" nor "false"? */
        if (g_ascii_strcasecmp(value, "true") == 0)
            bval = true;
        else
            bval = false;
        module->prefs_changed_flags |= prefs_set_bool_value(pref, bval, pref_current);
        break;

    case PREF_ENUM:
        /* XXX - give an error if it doesn't match? */
        module->prefs_changed_flags |= prefs_set_enum_string_value(pref, value, pref_current);
        break;

    case PREF_STRING:
    case PREF_SAVE_FILENAME:
    case PREF_OPEN_FILENAME:
    case PREF_DIRNAME:
        module->prefs_changed_flags |= prefs_set_string_value(pref, value, pref_current);
        break;

    case PREF_PASSWORD:
        /* Read value is every time empty */
        module->prefs_changed_flags |= prefs_set_string_value(pref, "", pref_current);
        break;

    case PREF_RANGE:
    {
        if (!prefs_set_range_value_work(pref, value, return_range_errors,
            &module->prefs_changed_flags))
            return PREFS_SET_SYNTAX_ERR;        /* number was bad */
        break;
    }

    case PREF_COLOR:
    {
        if (!ws_hexstrtou32(value, NULL, &cval))
            return PREFS_SET_SYNTAX_ERR;        /* number was bad */

        color_t color_value;
        color_value.red = RED_COMPONENT(cval);
        color_value.green = GREEN_COMPONENT(cval);
        color_value.blue = BLUE_COMPONENT(cval);
        module->prefs_changed_flags |= prefs_set_color_value(pref, color_value, pref_current);
        break;
    }

    case PREF_CUSTOM:
        module->prefs_changed_flags |= prefs_set_custom_value(pref, value, pref_current);
        break;

    case PREF_STATIC_TEXT:
    case PREF_UAT:
    case PREF_DISSECTOR:
    case PREF_DECODE_AS_RANGE:
    case PREF_PROTO_TCP_SNDAMB_ENUM:
        //Not supported preferences types in UI
        break;
    }

    return PREFS_SET_OK;
}
