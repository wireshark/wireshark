/** @file
 *
 * Routines for UI preferences
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UI_PREFERENCES_H__
#define __UI_PREFERENCES_H__

#include <epan/prefs.h>
#include <epan/prefs-int.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Initialize the UI preferences component */
void ui_prefs_init(void);

/* Cleanup the UI preferences component */
void ui_prefs_cleanup(void);

typedef pref_t* (*ui_pref_deprecated_cb)(module_t* module, const char* name);

/*
 * Register a UI component that will have preferences.
 * Specify the module under which to register it, the name used for the
 * module in the preferences file, the title used in the tab for it
 * in a preferences dialog box, and a routine to call back when the
 * preferences are applied.
 *
 * @param name is a name for the module to use on the command line with "-o"
 *             and in preference files.
 * @param title the module title in the preferences UI
 * @param description the description included in the preferences file
 *                    and shown as tooltip in the GUI, or NULL
 * @param help The help string associated with the module, or NULL
 * @param apply_cb Callback routine that is called when preferences are
 *                      applied. It may be NULL, which inhibits the callback.
 * @param depr_callback Optional Callback routine that is called when a preference
 *                      name string isn't found when reading a preference file.
 *                      It may be NULL.
 * @return a preferences module which can be used to register a user 'preference'
 */
module_t*
ui_prefs_register_module(const char* name, const char* title,
                         const char* description, const char* help,
                         void (*apply_cb)(void), ui_pref_deprecated_cb depr_callback);

/*
 * Unregister a UI component that will have preferences.  Done when the component
 * is removed
 *
 * @param module Module to deregister
 */
void
ui_prefs_deregister_module(module_t* module);

typedef struct {
    FILE* pf;
} ui_prefs_write_pref_arg_t;

/*
 * Write out all preferences for a UI module.
 *
 * @param module Module containing preferences
 * @param user_data ui_prefs_write_pref_arg_t pointer
 */
unsigned
ui_prefs_write_module(module_t* module, void* user_data);


prefs_set_pref_e
ui_prefs_read_pref(char* pref_name, const char* value, void* private_data, bool return_range_errors);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_PREFERENCES_H__ */
